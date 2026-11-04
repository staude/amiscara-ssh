//! Host key checks: an OpenSSH `known_hosts` file with trust on first use,
//! or one pinned key.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use russh::client;
use russh::keys::{HashAlg, PublicKey, PublicKeyOrCertificate, known_hosts};

use crate::SshError;

/// Which host keys a connection trusts.
#[derive(Debug, Clone)]
pub enum HostKeyPolicy {
    /// An OpenSSH `known_hosts` file. With `accept_new`, unknown keys are
    /// recorded (trust on first use); changed keys are always refused.
    KnownHostsFile { path: PathBuf, accept_new: bool },
    /// Exactly this key, as an OpenSSH public key line. `None` trusts
    /// nothing yet, so the first contact ends in [`SshError::UnknownHostKey`].
    Pinned(Option<String>),
}

/// The russh handler of a connection: checks the server key against the
/// policy and keeps the reason of a refusal for [`crate::Session::connect`].
pub(crate) struct HostKeyCheck {
    host: String,
    port: u16,
    policy: HostKeyPolicy,
    refusal: Arc<Mutex<Option<SshError>>>,
}

impl HostKeyCheck {
    pub(crate) fn new(
        host: &str,
        port: u16,
        policy: HostKeyPolicy,
    ) -> (Self, Arc<Mutex<Option<SshError>>>) {
        let refusal = Arc::new(Mutex::new(None));
        let check = Self {
            host: host.to_owned(),
            port,
            policy,
            refusal: Arc::clone(&refusal),
        };
        (check, refusal)
    }

    fn refuse(&self, error: SshError) -> Result<bool, russh::Error> {
        if let Ok(mut refusal) = self.refusal.lock() {
            *refusal = Some(error);
        }
        Ok(false)
    }

    fn check(&self, server_key: &PublicKeyOrCertificate) -> Result<bool, russh::Error> {
        // Host certificates are not supported yet; only plain host keys.
        if server_key.certificate().is_some() {
            return Ok(false);
        }
        let server_public_key = server_key.public_key();
        let presented = || {
            (
                server_public_key.to_openssh().unwrap_or_default(),
                server_public_key.fingerprint(HashAlg::Sha256).to_string(),
            )
        };
        let unknown = || {
            let (key, fingerprint) = presented();
            SshError::UnknownHostKey {
                host: self.host.clone(),
                key,
                fingerprint,
            }
        };
        let changed = || {
            let (key, fingerprint) = presented();
            SshError::HostKeyChanged {
                host: self.host.clone(),
                key,
                fingerprint,
            }
        };
        match &self.policy {
            HostKeyPolicy::Pinned(None) => self.refuse(unknown()),
            HostKeyPolicy::Pinned(Some(line)) => match PublicKey::from_openssh(line) {
                Ok(pinned) if pinned.key_data() == server_public_key.key_data() => Ok(true),
                _ => self.refuse(changed()),
            },
            HostKeyPolicy::KnownHostsFile { path, accept_new } => {
                match known_hosts::check_known_hosts_path(
                    &self.host,
                    self.port,
                    &server_public_key,
                    path,
                ) {
                    Ok(true) => Ok(true),
                    Ok(false) if *accept_new => {
                        known_hosts::learn_known_hosts_path(
                            &self.host,
                            self.port,
                            &server_public_key,
                            path,
                        )
                        .map_err(|e| russh::Error::IO(std::io::Error::other(e.to_string())))?;
                        Ok(true)
                    }
                    Ok(false) => self.refuse(unknown()),
                    Err(russh::keys::Error::KeyChanged { .. }) => self.refuse(changed()),
                    Err(_) => self.refuse(unknown()),
                }
            }
        }
    }
}

impl client::Handler for HostKeyCheck {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        self.check(server_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{generate_ed25519, parse_public};

    fn server_key() -> Result<(PublicKeyOrCertificate, String), SshError> {
        // Host keys come without a comment; russh compares it too.
        let generated = generate_ed25519("")?;
        let public = parse_public(&generated.public_openssh)?;
        Ok((public.into(), generated.public_openssh))
    }

    fn refusal(refusal: &Arc<Mutex<Option<SshError>>>) -> Option<SshError> {
        refusal.lock().ok().and_then(|mut r| r.take())
    }

    #[test]
    fn pinned_key_is_trusted_and_others_are_changed() -> Result<(), Box<dyn std::error::Error>> {
        let (key, line) = server_key()?;
        let (check, _) = HostKeyCheck::new("h", 22, HostKeyPolicy::Pinned(Some(line)));
        assert!(check.check(&key)?);

        let (other, _) = server_key()?;
        assert!(!check.check(&other)?);
        assert!(matches!(
            refusal(&check.refusal),
            Some(SshError::HostKeyChanged { .. })
        ));

        let (garbage, _) = HostKeyCheck::new("h", 22, HostKeyPolicy::Pinned(Some("x".into())));
        assert!(!garbage.check(&key)?);
        assert!(matches!(
            refusal(&garbage.refusal),
            Some(SshError::HostKeyChanged { .. })
        ));
        Ok(())
    }

    #[test]
    fn nothing_pinned_is_unknown() -> Result<(), Box<dyn std::error::Error>> {
        let (key, line) = server_key()?;
        let (check, _) = HostKeyCheck::new("h", 22, HostKeyPolicy::Pinned(None));
        assert!(!check.check(&key)?);
        match refusal(&check.refusal) {
            Some(SshError::UnknownHostKey {
                host,
                key,
                fingerprint,
            }) => {
                assert_eq!(host, "h");
                assert!(line.starts_with(&key));
                assert!(fingerprint.starts_with("SHA256:"));
            }
            other => panic!("expected UnknownHostKey, got {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn known_hosts_learns_once_then_refuses_changes() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("known_hosts");
        let (key, _) = server_key()?;

        let strict = HostKeyPolicy::KnownHostsFile {
            path: path.clone(),
            accept_new: false,
        };
        let (check, _) = HostKeyCheck::new("h", 2222, strict.clone());
        assert!(!check.check(&key)?);
        assert!(matches!(
            refusal(&check.refusal),
            Some(SshError::UnknownHostKey { .. })
        ));

        let tofu = HostKeyPolicy::KnownHostsFile {
            path: path.clone(),
            accept_new: true,
        };
        let (check, _) = HostKeyCheck::new("h", 2222, tofu);
        assert!(check.check(&key)?);
        let recorded = std::fs::read_to_string(&path)?;
        assert!(
            recorded
                .lines()
                .any(|line| line.starts_with("[h]:2222 ssh-ed25519 "))
        );

        let (check, _) = HostKeyCheck::new("h", 2222, strict);
        assert!(check.check(&key)?);
        let (other, _) = server_key()?;
        assert!(!check.check(&other)?);
        assert!(matches!(
            refusal(&check.refusal),
            Some(SshError::HostKeyChanged { .. })
        ));
        Ok(())
    }
}
