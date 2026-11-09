//! Connecting, signing in and opening channels.

use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use russh::MethodKind;
use russh::client::{self, AuthResult, Handle, KeyboardInteractiveAuthResponse};
use russh::keys::agent::client::AgentClient;
use russh::keys::{PrivateKey, PrivateKeyWithHashAlg, load_secret_key};
use russh::{Channel, ChannelStream, Disconnect};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use zeroize::Zeroizing;

use crate::SshError;
use crate::chain::Reporter;
use crate::host_key::{HostKeyCheck, HostKeyPolicy};
use crate::prompt::{KeyboardInteractive, KeyboardPrompt, PromptLine};
use crate::proxy;

/// Refused rounds of keyboard-interactive before giving up, three attempts
/// as servers usually allow.
const KEYBOARD_ROUNDS: u32 = 3;

/// Requests and steps of one keyboard-interactive sign-in at most, so a
/// server that never ends it cannot keep the client (or the user) busy.
const KEYBOARD_STEPS: u32 = 16;

/// How to sign in.
#[derive(Clone)]
pub enum Identity {
    /// Private key file in OpenSSH format, with the passphrase if it is
    /// encrypted.
    File {
        path: PathBuf,
        passphrase: Option<Zeroizing<String>>,
    },
    /// The SSH agent (`SSH_AUTH_SOCK`, on Windows the OpenSSH named pipe).
    Agent,
    /// A key held in memory, for example loaded from the Keychain.
    Key(Arc<PrivateKey>),
    /// A password. russh copies it into a plain `String` while signing in;
    /// only this copy here is wiped on drop.
    Password(Zeroizing<String>),
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::File { path, passphrase } => f
                .debug_struct("File")
                .field("path", path)
                .field("passphrase", &passphrase.as_ref().map(|_| ".."))
                .finish(),
            Self::Agent => f.write_str("Agent"),
            Self::Key(_) => f.write_str("Key(..)"),
            Self::Password(_) => f.write_str("Password(..)"),
        }
    }
}

/// Where to connect, as whom, and which host keys to trust.
#[derive(Debug, Clone)]
pub struct SshTarget {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub identity: Identity,
    pub host_key: HostKeyPolicy,
    /// Lets this server use the local SSH agent through shells opened on the
    /// session. Off by default; in a [`crate::Route`] it only ever applies to
    /// the target, never to a jump.
    pub agent_forward: bool,
    /// Answers questions of the server during sign-in, for example a
    /// one-time code after the key. Asked only if the server accepted
    /// [`SshTarget::identity`] as a partial success and still wants
    /// keyboard-interactive; a refused identity is never followed by a
    /// question. `None` ends there in [`SshError::AuthFailed`].
    pub keyboard_interactive: Option<Arc<dyn KeyboardInteractive>>,
}

impl SshTarget {
    /// `user@host:port`, as errors and hop events name the host.
    pub fn label(&self) -> String {
        format!("{}@{}:{}", self.user, self.host, self.port)
    }
}

/// One signed-in SSH connection. Channels are opened on it as needed.
pub struct Session {
    handle: Handle<HostKeyCheck>,
    agent_forward: bool,
    /// The sign-in asked the user something.
    asked: bool,
    /// `keep_open` of the last answer during sign-in.
    keep_open: Option<Duration>,
}

/// Transport settings of a single connection: keepalive every 15 s.
fn default_config() -> Arc<client::Config> {
    Arc::new(client::Config {
        inactivity_timeout: None,
        keepalive_interval: Some(Duration::from_secs(15)),
        nodelay: true,
        ..Default::default()
    })
}

impl Session {
    /// Connects, checks the host key and signs in.
    ///
    /// A refused host key ends in [`SshError::UnknownHostKey`] or
    /// [`SshError::HostKeyChanged`], refused credentials in
    /// [`SshError::AuthFailed`].
    pub async fn connect(target: &SshTarget) -> Result<Self, SshError> {
        let stream = Self::open_tcp(target).await?;
        Self::start(target, stream, default_config(), None).await
    }

    /// Connects to `target` through `jump` (ProxyJump): a `direct-tcpip`
    /// channel on `jump` carries the new connection, without a local port.
    /// `target.host` is resolved by the jump, and the host key is checked
    /// under that name. Errors as with [`Session::connect`].
    pub async fn connect_via(jump: &Session, target: &SshTarget) -> Result<Self, SshError> {
        let stream = jump.open_via(target).await?;
        Self::start(target, stream, default_config(), None).await
    }

    /// Connects to `target` over a local command (ProxyCommand): its stdin
    /// and stdout carry the connection, for servers reachable only through a
    /// helper such as `cloudflared` or AWS SSM. `%h`, `%p`, `%r` and `%%` in
    /// `command` are replaced by host, port, user and `%`; the command runs
    /// through `/bin/sh` on Unix and `cmd.exe` on Windows. Dropping the
    /// session kills the command. No time limit of its own, as with
    /// [`Session::connect`].
    ///
    /// An unknown placeholder, or a host or user with characters that are
    /// unsafe in a command line, ends in [`SshError::ProxyCommand`] before
    /// anything starts; so does a command that ends before the sign-in, with
    /// its exit status and the last of its error output. Other errors as with
    /// [`Session::connect`].
    pub async fn connect_command(command: &str, target: &SshTarget) -> Result<Self, SshError> {
        Self::start_command(command, target, default_config(), None).await
    }

    /// Starts `command` for `target` and runs SSH over it.
    pub(crate) async fn start_command(
        command: &str,
        target: &SshTarget,
        config: Arc<client::Config>,
        reporter: Option<Reporter>,
    ) -> Result<Self, SshError> {
        let expanded = proxy::expand(command, target)?;
        let (stream, exit) = proxy::spawn(&expanded)?;
        match Self::start(target, stream, config, reporter).await {
            Ok(session) => Ok(session),
            Err(error) => Err(exit.explain(error).await),
        }
    }

    /// The TCP connection to `target`.
    pub(crate) async fn open_tcp(target: &SshTarget) -> Result<TcpStream, SshError> {
        let socket = TcpStream::connect((target.host.as_str(), target.port)).await?;
        // Only latency suffers if this fails.
        socket.set_nodelay(true).ok();
        Ok(socket)
    }

    /// A `direct-tcpip` channel from this session to `target`, as a stream.
    pub(crate) async fn open_via(
        &self,
        target: &SshTarget,
    ) -> Result<ChannelStream<client::Msg>, SshError> {
        Ok(self
            .direct_tcpip(&target.host, target.port)
            .await?
            .into_stream())
    }

    /// Runs SSH on `stream`: key exchange, host key check, sign-in.
    pub(crate) async fn start<S>(
        target: &SshTarget,
        stream: S,
        config: Arc<client::Config>,
        reporter: Option<Reporter>,
    ) -> Result<Self, SshError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (check, refusal) =
            HostKeyCheck::new(&target.host, target.port, target.host_key.clone());
        let check = check.with_agent_forward(target.agent_forward);
        let reporter_ref = reporter.clone();
        let stream = Watched {
            inner: stream,
            reporter,
        };
        let mut handle = match client::connect_stream(config, stream, check).await {
            Ok(handle) => handle,
            Err(err) => {
                let refused = refusal.lock().ok().and_then(|mut r| r.take());
                return Err(refused.unwrap_or(SshError::Ssh(err)));
            }
        };

        let user = target.user.as_str();
        let first = match &target.identity {
            Identity::File { path, passphrase } => {
                let key = load_secret_key(path, passphrase.as_ref().map(|p| p.as_str()))
                    .map_err(|e| SshError::Key(e.to_string()))?;
                authenticate_with_key(&mut handle, user, Arc::new(key)).await?
            }
            Identity::Agent => authenticate_with_agent(&mut handle, user).await?,
            Identity::Key(key) => authenticate_with_key(&mut handle, user, Arc::clone(key)).await?,
            Identity::Password(password) => {
                handle
                    .authenticate_password(user, password.as_str())
                    .await?
            }
        };
        let failed = || SshError::AuthFailed(format!("{}@{}", target.user, target.host));
        let mut asked = Asked::default();
        match first {
            AuthResult::Success => {}
            AuthResult::Failure {
                remaining_methods,
                partial_success,
            } => {
                // Only a server that accepted the credentials and wants more
                // asks; a refused key or password stays a refusal.
                let prompter = target
                    .keyboard_interactive
                    .as_ref()
                    .filter(|_| {
                        partial_success
                            && remaining_methods.contains(&MethodKind::KeyboardInteractive)
                    })
                    .ok_or_else(failed)?;
                let signed_in = authenticate_keyboard_interactive(
                    &mut handle,
                    target,
                    prompter.as_ref(),
                    reporter_ref.as_ref(),
                    &mut asked,
                )
                .await?;
                if !signed_in {
                    return Err(failed());
                }
            }
        }
        Ok(Self {
            handle,
            agent_forward: target.agent_forward,
            asked: asked.asked,
            keep_open: asked.keep_open,
        })
    }

    /// How long a pool keeps this connection open once nobody uses it: what
    /// the last answer during sign-in asked for, `grace` if the sign-in asked
    /// without saying, otherwise not at all.
    pub(crate) fn linger(&self, grace: Duration) -> Duration {
        match (self.asked, self.keep_open) {
            (true, Some(keep_open)) => keep_open,
            (true, None) => grace,
            (false, _) => Duration::ZERO,
        }
    }

    /// Whether shells on this session forward the local SSH agent.
    pub fn agent_forward(&self) -> bool {
        self.agent_forward
    }

    /// A plain session channel, for example to run a command.
    pub async fn channel_session(&self) -> Result<Channel<client::Msg>, SshError> {
        Ok(self.handle.channel_open_session().await?)
    }

    /// A `direct-tcpip` channel to `host:port`, as seen from the server.
    pub async fn direct_tcpip(
        &self,
        host: &str,
        port: u16,
    ) -> Result<Channel<client::Msg>, SshError> {
        Ok(self
            .handle
            .channel_open_direct_tcpip(host, u32::from(port), "127.0.0.1", 0)
            .await?)
    }

    /// A `direct-streamlocal@openssh.com` channel to a Unix socket on the
    /// server.
    pub async fn direct_streamlocal(
        &self,
        socket_path: &str,
    ) -> Result<Channel<client::Msg>, SshError> {
        Ok(self
            .handle
            .channel_open_direct_streamlocal(socket_path)
            .await?)
    }

    /// Whether the connection is gone.
    pub fn is_closed(&self) -> bool {
        self.handle.is_closed()
    }

    /// Closes the connection. On a [`crate::Lease`] that closes it for every
    /// user of the pooled connection; drop the lease instead.
    pub async fn disconnect(&self) -> Result<(), SshError> {
        Ok(self
            .handle
            .disconnect(Disconnect::ByApplication, "", "")
            .await?)
    }
}

/// The transport of a session. russh drops it whenever the connection ends,
/// also where it skips `Handler::disconnected` (a failed shutdown of a
/// channel below), so the drop reports the end.
struct Watched<S> {
    inner: S,
    reporter: Option<Reporter>,
}

impl<S> Drop for Watched<S> {
    fn drop(&mut self) {
        if let Some(reporter) = &self.reporter {
            reporter.closed();
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Watched<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Watched<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

async fn authenticate_with_key(
    handle: &mut Handle<HostKeyCheck>,
    user: &str,
    key: Arc<PrivateKey>,
) -> Result<AuthResult, SshError> {
    let hash = handle.best_supported_rsa_hash().await?.flatten();
    Ok(handle
        .authenticate_publickey(user, PrivateKeyWithHashAlg::new(key, hash))
        .await?)
}

/// Tries every key of the agent. The result is the first success, else the
/// first key the server accepted as a partial success (it then wants more,
/// for example a one-time code), else the last refusal.
async fn authenticate_with_agent(
    handle: &mut Handle<HostKeyCheck>,
    user: &str,
) -> Result<AuthResult, SshError> {
    #[cfg(unix)]
    let agent = AgentClient::connect_env().await;
    // Windows OpenSSH runs its agent on a fixed named pipe.
    #[cfg(windows)]
    let agent = AgentClient::connect_named_pipe(r"\\.\pipe\openssh-ssh-agent").await;
    let mut agent = agent.map_err(|e| SshError::Key(e.to_string()))?;
    let identities = agent
        .request_identities()
        .await
        .map_err(|e| SshError::Key(e.to_string()))?;
    let hash = handle.best_supported_rsa_hash().await?.flatten();
    let mut last = AuthResult::Failure {
        remaining_methods: russh::MethodSet::empty(),
        partial_success: false,
    };
    for identity in identities {
        let key = identity.public_key().into_owned();
        let result = handle
            .authenticate_publickey_with(user, key, hash, &mut agent)
            .await
            .map_err(|e| SshError::Key(e.to_string()))?;
        match result {
            AuthResult::Success
            | AuthResult::Failure {
                partial_success: true,
                ..
            } => return Ok(result),
            AuthResult::Failure { .. } => last = result,
        }
    }
    Ok(last)
}

/// What the user was asked during sign-in.
#[derive(Default)]
struct Asked {
    asked: bool,
    keep_open: Option<Duration>,
}

/// Signs in by keyboard-interactive, asking `prompter` for every request
/// with questions; up to [`KEYBOARD_ROUNDS`] attempts while the server keeps
/// refusing and offering the method again. A partial success (one of
/// several keyboard-interactive steps passed) starts the next step within
/// the same attempt. `Ok(false)` is a refusal, a cancelled question ends in
/// [`SshError::Cancelled`].
async fn authenticate_keyboard_interactive(
    handle: &mut Handle<HostKeyCheck>,
    target: &SshTarget,
    prompter: &dyn KeyboardInteractive,
    reporter: Option<&Reporter>,
    asked: &mut Asked,
) -> Result<bool, SshError> {
    let (route, index) = match reporter {
        Some(reporter) => (reporter.route(), reporter.index()),
        None => (vec![target.label()], 0),
    };
    let mut attempt = 1;
    let mut steps = 0;
    while attempt <= KEYBOARD_ROUNDS {
        let mut reply = handle
            .authenticate_keyboard_interactive_start(target.user.as_str(), None)
            .await?;
        loop {
            steps += 1;
            if steps > KEYBOARD_STEPS {
                return Ok(false);
            }
            match reply {
                KeyboardInteractiveAuthResponse::Success => return Ok(true),
                KeyboardInteractiveAuthResponse::Failure {
                    remaining_methods,
                    partial_success,
                } => {
                    if !remaining_methods.contains(&MethodKind::KeyboardInteractive) {
                        return Ok(false);
                    }
                    if !partial_success {
                        attempt += 1;
                    }
                    break;
                }
                KeyboardInteractiveAuthResponse::InfoRequest {
                    name,
                    instructions,
                    prompts,
                } => {
                    if prompts.is_empty() {
                        reply = handle
                            .authenticate_keyboard_interactive_respond(Vec::new())
                            .await?;
                        continue;
                    }
                    let expected = prompts.len();
                    let prompt = KeyboardPrompt {
                        route: route.clone(),
                        index,
                        name,
                        instructions,
                        prompts: prompts
                            .into_iter()
                            .map(|p| PromptLine {
                                text: p.prompt,
                                echo: p.echo,
                            })
                            .collect(),
                        attempt,
                    };
                    let answer = {
                        // The time the user takes is no part of the limit.
                        let _pause = reporter.map(Reporter::awaiting_input);
                        prompter.ask(prompt).await
                    };
                    let Some(answer) = answer else {
                        return Err(SshError::Cancelled(target.label()));
                    };
                    if answer.responses.len() != expected {
                        return Ok(false);
                    }
                    asked.asked = true;
                    asked.keep_open = answer.keep_open;
                    let responses = answer
                        .responses
                        .iter()
                        .map(|r| r.as_str().to_owned())
                        .collect();
                    reply = handle
                        .authenticate_keyboard_interactive_respond(responses)
                        .await?;
                }
            }
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_hides_secrets() {
        let password = Identity::Password(Zeroizing::new("geheim-123".into()));
        let file = Identity::File {
            path: "/k".into(),
            passphrase: Some(Zeroizing::new("geheim-456".into())),
        };
        let target = SshTarget {
            host: "h".into(),
            port: 22,
            user: "u".into(),
            identity: password.clone(),
            host_key: HostKeyPolicy::Pinned(None),
            agent_forward: false,
            keyboard_interactive: None,
        };
        for text in [
            format!("{password:?}"),
            format!("{file:?}"),
            format!("{target:?}"),
        ] {
            assert!(!text.contains("geheim"), "{text}");
        }
    }
}
