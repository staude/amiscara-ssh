//! ProxyCommand: a local command whose stdin and stdout carry the
//! connection, for servers only reachable through a helper program.

use std::pin::Pin;
use std::process::{ExitStatus, Stdio};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, Join, ReadBuf};
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};
use tokio::sync::{oneshot, watch};

use crate::{SshError, SshTarget};

/// Bytes of the command's error output kept for the error message.
const STDERR_TAIL: usize = 2048;

/// How long a failed sign-in waits for the command to end, before the
/// failure counts as one of SSH rather than of the command.
const EXIT_WAIT: Duration = Duration::from_secs(2);

/// Replaces `%h` (host), `%p` (port), `%r` (user) and `%%` in `command`.
///
/// Host and user are set into a command line without quoting, so they may
/// only hold ASCII letters, digits and `. - _ : @`, and may not start with
/// `-` (it would turn into an option of the command). Anything else, an
/// unknown placeholder and an empty command are refused before anything
/// starts.
pub(crate) fn expand(command: &str, target: &SshTarget) -> Result<String, SshError> {
    if command.trim().is_empty() {
        return Err(SshError::ProxyCommand("the command is empty".into()));
    }
    let mut expanded = String::with_capacity(command.len());
    let mut chars = command.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            expanded.push(c);
            continue;
        }
        match chars.next() {
            Some('h') => expanded.push_str(safe("host", &target.host)?),
            Some('p') => expanded.push_str(&target.port.to_string()),
            Some('r') => expanded.push_str(safe("user", &target.user)?),
            Some('%') => expanded.push('%'),
            Some(other) => {
                return Err(SshError::ProxyCommand(format!(
                    "unknown placeholder %{other}"
                )));
            }
            None => {
                return Err(SshError::ProxyCommand(
                    "the command ends in a single %".into(),
                ));
            }
        }
    }
    Ok(expanded)
}

/// `value` if it can go into a command line as it is.
fn safe<'a>(what: &str, value: &'a str) -> Result<&'a str, SshError> {
    let allowed = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '@');
    if value.is_empty() || value.starts_with('-') || !value.chars().all(allowed) {
        return Err(SshError::ProxyCommand(format!(
            "the {what} {value:?} holds characters not allowed in a command"
        )));
    }
    Ok(value)
}

/// How the command ended.
#[derive(Debug, Clone)]
enum Ended {
    /// By itself, with the last of its error output.
    Exited { status: ExitStatus, stderr: String },
    /// Killed because the connection was dropped.
    Killed,
}

/// Starts `expanded` through the shell of the system: `/bin/sh -c "exec …"`
/// on Unix, `cmd.exe /C …` on Windows. The returned stream reads its stdout
/// and writes its stdin; dropping the stream kills the command.
pub(crate) fn spawn(expanded: &str) -> Result<(CommandStream, CommandExit), SshError> {
    let mut command = shell(expanded);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn()?;
    let (Some(stdin), Some(stdout), Some(stderr)) =
        (child.stdin.take(), child.stdout.take(), child.stderr.take())
    else {
        return Err(SshError::ProxyCommand(
            "the command's stdin, stdout or stderr is missing".into(),
        ));
    };
    let tail = Arc::new(Mutex::new(Vec::new()));
    let stderr_task = tokio::spawn(read_stderr(stderr, Arc::clone(&tail)));
    let (kill, killed) = oneshot::channel();
    let (ended_tx, ended) = watch::channel(None);
    tokio::spawn(watch_child(child, killed, stderr_task, tail, ended_tx));
    Ok((
        CommandStream {
            io: tokio::io::join(stdout, stdin),
            _kill: kill,
        },
        CommandExit { ended },
    ))
}

#[cfg(unix)]
fn shell(expanded: &str) -> Command {
    let mut command = Command::new("/bin/sh");
    // `exec`, so the command itself is the child and gets the kill.
    command.arg("-c").arg(format!("exec {expanded}"));
    command
}

#[cfg(windows)]
fn shell(expanded: &str) -> Command {
    /// No console window pops up for the command.
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let mut command = Command::new("cmd.exe");
    command
        .arg("/C")
        .raw_arg(expanded)
        .creation_flags(CREATE_NO_WINDOW);
    command
}

/// Reads the error output for as long as there is any, so the command never
/// blocks on a full pipe, and keeps the last [`STDERR_TAIL`] bytes.
async fn read_stderr(mut stderr: ChildStderr, tail: Arc<Mutex<Vec<u8>>>) {
    let mut buf = [0u8; 1024];
    loop {
        match stderr.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                let mut tail = tail.lock().unwrap_or_else(PoisonError::into_inner);
                tail.extend_from_slice(&buf[..n]);
                if tail.len() > STDERR_TAIL {
                    let cut = tail.len() - STDERR_TAIL;
                    tail.drain(..cut);
                }
            }
        }
    }
}

/// Waits for the command to end, or kills it once the stream is dropped,
/// and reaps it either way, so no zombie stays behind.
async fn watch_child(
    mut child: Child,
    killed: oneshot::Receiver<()>,
    stderr_task: tokio::task::JoinHandle<()>,
    tail: Arc<Mutex<Vec<u8>>>,
    ended: watch::Sender<Option<Ended>>,
) {
    let status = tokio::select! {
        biased;
        status = child.wait() => status.ok(),
        // The sender never sends: dropping it is the signal. A command that
        // ended by itself just before still counts as ended.
        _ = killed => child.try_wait().ok().flatten(),
    };
    let Some(status) = status else {
        // Already gone is fine.
        child.kill().await.ok();
        ended.send_replace(Some(Ended::Killed));
        return;
    };
    // The rest of the error output, unless something else holds the pipe.
    tokio::time::timeout(Duration::from_millis(500), stderr_task)
        .await
        .ok();
    let stderr = {
        let tail = tail.lock().unwrap_or_else(PoisonError::into_inner);
        String::from_utf8_lossy(&tail).trim().to_owned()
    };
    ended.send_replace(Some(Ended::Exited { status, stderr }));
}

/// The end of a started command, to explain a failed sign-in.
pub(crate) struct CommandExit {
    ended: watch::Receiver<Option<Ended>>,
}

impl CommandExit {
    /// `error` of a sign-in over the command, or [`SshError::ProxyCommand`]
    /// with exit status and error output if the command ended by itself.
    /// Host key and sign-in decisions stay as they are: the command did its
    /// job there.
    pub(crate) async fn explain(mut self, error: SshError) -> SshError {
        if !matches!(error, SshError::Io(_) | SshError::Ssh(_)) {
            return error;
        }
        let ended = tokio::time::timeout(EXIT_WAIT, self.ended.wait_for(Option::is_some)).await;
        let Ok(Ok(ended)) = ended else {
            return error;
        };
        match ended.clone() {
            Some(Ended::Exited { status, stderr }) if stderr.is_empty() => {
                SshError::ProxyCommand(format!("ended with {status}"))
            }
            Some(Ended::Exited { status, stderr }) => {
                SshError::ProxyCommand(format!("ended with {status}: {stderr}"))
            }
            Some(Ended::Killed) | None => error,
        }
    }
}

/// stdout and stdin of a running command as one stream. Dropping it kills
/// the command.
pub(crate) struct CommandStream {
    io: Join<ChildStdout, ChildStdin>,
    /// Dropped with the stream, which tells [`watch_child`] to kill.
    _kill: oneshot::Sender<()>,
}

impl AsyncRead for CommandStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for CommandStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HostKeyPolicy, Identity};

    fn target(host: &str, user: &str) -> SshTarget {
        SshTarget {
            host: host.into(),
            port: 2222,
            user: user.into(),
            identity: Identity::Agent,
            host_key: HostKeyPolicy::Pinned(None),
            agent_forward: false,
            keyboard_interactive: None,
        }
    }

    fn refused(command: &str, target: &SshTarget) -> String {
        match expand(command, target) {
            Err(SshError::ProxyCommand(reason)) => reason,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn placeholders_are_replaced() -> Result<(), SshError> {
        let t = target("db.example.org", "deploy");
        assert_eq!(expand("nc %h %p", &t)?, "nc db.example.org 2222");
        assert_eq!(expand("ssm %r@%h", &t)?, "ssm deploy@db.example.org");
        assert_eq!(expand("echo 100%%", &t)?, "echo 100%");
        assert_eq!(expand("echo %%h", &t)?, "echo %h");
        assert_eq!(expand("plain", &t)?, "plain");
        Ok(())
    }

    #[test]
    fn unknown_placeholders_are_refused() {
        let t = target("h", "u");
        assert!(refused("nc %x %p", &t).contains("%x"));
        assert!(refused("nc %h %", &t).contains('%'));
        refused("", &t);
        refused("   ", &t);
    }

    #[test]
    fn unsafe_values_are_refused() {
        assert!(refused("nc %h %p", &target("a;b", "u")).contains("host"));
        assert!(refused("ssm %r", &target("h", "a b")).contains("user"));
        refused("nc %h %p", &target("$(id)", "u"));
        refused("nc %h %p", &target("-oProxyCommand=x", "u"));
        refused("nc %h %p", &target("", "u"));
        // Not used, not checked.
        assert_eq!(
            expand("nc %h %p", &target("h", "a b")).ok().as_deref(),
            Some("nc h 2222")
        );
    }
}
