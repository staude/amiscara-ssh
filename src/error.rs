//! Errors of the crate.

/// Everything that can go wrong while connecting or talking to a server.
///
/// Texts never contain a password or passphrase.
#[derive(Debug, thiserror::Error)]
pub enum SshError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Ssh(#[from] russh::Error),
    /// A key could not be generated, read or decrypted, or the SSH agent
    /// is not reachable.
    #[error("ssh key error: {0}")]
    Key(String),
    /// The server refused every offered credential. Holds `user@host`.
    #[error("ssh authentication failed for {0}")]
    AuthFailed(String),
    /// The server presented a key nobody has trusted yet. Show the
    /// fingerprint, ask, and pin `key` on consent.
    #[error("unknown host key for {host}: {fingerprint}")]
    UnknownHostKey {
        host: String,
        key: String,
        fingerprint: String,
    },
    /// The server presented a different key than the trusted one.
    #[error("host key for {host} changed, it is now {fingerprint}")]
    HostKeyChanged {
        host: String,
        key: String,
        fingerprint: String,
    },
    /// The server refused a channel request, for example a PTY or a shell.
    #[error("server refused {0}")]
    Refused(String),
    /// Connecting and signing in to this host (`user@host:port`) took too
    /// long.
    #[error("timed out connecting to {0}")]
    Timeout(String),
    /// The server offers no SFTP, refused the subsystem, or the SFTP
    /// protocol did not start. Holds the reason.
    #[error("sftp unavailable: {0}")]
    SftpUnavailable(String),
    /// The user cancelled the sign-in to this host (`user@host:port`), for
    /// example by answering a [`crate::KeyboardPrompt`] with `None`.
    #[error("sign-in to {0} was cancelled")]
    Cancelled(String),
    /// The ProxyCommand was refused before it started (unknown placeholder,
    /// host or user not fit for a command line) or ended before the
    /// sign-in, then with its exit status and the last of its error output.
    /// Never holds the command itself, it may carry an access token; parts
    /// of the command that the error output repeats are replaced, as far as
    /// they can be recognised.
    #[error("proxy command: {0}")]
    ProxyCommand(String),
    /// A hop of a [`crate::Route`] failed: `index` counts from the first jump
    /// (0), the target is the last index; `hop` is `user@host:port`.
    #[error("hop {index} ({hop}): {source}")]
    Hop {
        index: usize,
        hop: String,
        source: Box<SshError>,
    },
}

impl SshError {
    /// Errors that a retry cannot fix without a decision by the user.
    pub fn needs_user(&self) -> bool {
        if let Self::Hop { source, .. } = self {
            return source.needs_user();
        }
        matches!(
            self,
            Self::UnknownHostKey { .. }
                | Self::HostKeyChanged { .. }
                | Self::AuthFailed(_)
                | Self::Key(_)
                | Self::Cancelled(_)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_decisions_need_the_user() {
        assert!(SshError::AuthFailed("a@b".into()).needs_user());
        assert!(SshError::Key("x".into()).needs_user());
        assert!(
            SshError::HostKeyChanged {
                host: "h".into(),
                key: "k".into(),
                fingerprint: "f".into(),
            }
            .needs_user()
        );
        assert!(SshError::Cancelled("u@h:22".into()).needs_user());
        assert!(!SshError::Refused("pty".into()).needs_user());
        assert!(!SshError::Io(std::io::Error::other("x")).needs_user());
        assert!(!SshError::Timeout("u@h:22".into()).needs_user());
        assert!(!SshError::SftpUnavailable("refused".into()).needs_user());
        assert!(!SshError::ProxyCommand("ended with exit status: 1".into()).needs_user());
        let hop = |source| SshError::Hop {
            index: 1,
            hop: "u@jump:22".into(),
            source: Box::new(source),
        };
        assert!(hop(SshError::AuthFailed("u@jump".into())).needs_user());
        assert!(!hop(SshError::Timeout("u@jump:22".into())).needs_user());
        assert!(hop(SshError::Cancelled("u@jump:22".into())).needs_user());
    }
}
