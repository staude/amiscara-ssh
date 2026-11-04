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
}

impl SshError {
    /// Errors that a retry cannot fix without a decision by the user.
    pub fn needs_user(&self) -> bool {
        matches!(
            self,
            Self::UnknownHostKey { .. }
                | Self::HostKeyChanged { .. }
                | Self::AuthFailed(_)
                | Self::Key(_)
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
        assert!(!SshError::Refused("pty".into()).needs_user());
        assert!(!SshError::Io(std::io::Error::other("x")).needs_user());
    }
}
