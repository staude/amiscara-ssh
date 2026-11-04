//! Connecting, signing in and opening channels.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use russh::client::{self, AuthResult, Handle};
use russh::keys::agent::client::AgentClient;
use russh::keys::{PrivateKey, PrivateKeyWithHashAlg, load_secret_key};
use russh::{Channel, Disconnect};
use zeroize::Zeroizing;

use crate::SshError;
use crate::host_key::{HostKeyCheck, HostKeyPolicy};

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
}

/// One signed-in SSH connection. Channels are opened on it as needed.
pub struct Session {
    handle: Handle<HostKeyCheck>,
}

impl Session {
    /// Connects, checks the host key and signs in.
    ///
    /// A refused host key ends in [`SshError::UnknownHostKey`] or
    /// [`SshError::HostKeyChanged`], refused credentials in
    /// [`SshError::AuthFailed`].
    pub async fn connect(target: &SshTarget) -> Result<Self, SshError> {
        let config = Arc::new(client::Config {
            inactivity_timeout: None,
            keepalive_interval: Some(Duration::from_secs(15)),
            nodelay: true,
            ..Default::default()
        });
        let (check, refusal) =
            HostKeyCheck::new(&target.host, target.port, target.host_key.clone());
        let mut handle =
            match client::connect(config, (target.host.as_str(), target.port), check).await {
                Ok(handle) => handle,
                Err(err) => {
                    let refused = refusal.lock().ok().and_then(|mut r| r.take());
                    return Err(refused.unwrap_or(SshError::Ssh(err)));
                }
            };

        let user = target.user.as_str();
        let authenticated = match &target.identity {
            Identity::File { path, passphrase } => {
                let key = load_secret_key(path, passphrase.as_ref().map(|p| p.as_str()))
                    .map_err(|e| SshError::Key(e.to_string()))?;
                authenticate_with_key(&mut handle, user, Arc::new(key)).await?
            }
            Identity::Agent => authenticate_with_agent(&mut handle, user).await?,
            Identity::Key(key) => authenticate_with_key(&mut handle, user, Arc::clone(key)).await?,
            Identity::Password(password) => {
                let result = handle
                    .authenticate_password(user, password.as_str())
                    .await?;
                matches!(result, AuthResult::Success)
            }
        };
        if !authenticated {
            return Err(SshError::AuthFailed(format!(
                "{}@{}",
                target.user, target.host
            )));
        }
        Ok(Self { handle })
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

    /// Closes the connection.
    pub async fn disconnect(&self) -> Result<(), SshError> {
        Ok(self
            .handle
            .disconnect(Disconnect::ByApplication, "", "")
            .await?)
    }
}

async fn authenticate_with_key(
    handle: &mut Handle<HostKeyCheck>,
    user: &str,
    key: Arc<PrivateKey>,
) -> Result<bool, SshError> {
    let hash = handle.best_supported_rsa_hash().await?.flatten();
    let result = handle
        .authenticate_publickey(user, PrivateKeyWithHashAlg::new(key, hash))
        .await?;
    Ok(matches!(result, AuthResult::Success))
}

async fn authenticate_with_agent(
    handle: &mut Handle<HostKeyCheck>,
    user: &str,
) -> Result<bool, SshError> {
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
    for identity in identities {
        let key = identity.public_key().into_owned();
        let result = handle
            .authenticate_publickey_with(user, key, hash, &mut agent)
            .await
            .map_err(|e| SshError::Key(e.to_string()))?;
        if matches!(result, AuthResult::Success) {
            return Ok(true);
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
