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
    /// An OpenSSH `known_hosts` file. With `accept_new`, the key of a host
    /// without any entry is recorded (trust on first use). A host recorded
    /// only with other key types counts as unknown, never as learned; a
    /// different key of the same type is always refused as changed.
    KnownHostsFile { path: PathBuf, accept_new: bool },
    /// Exactly this key, as an OpenSSH public key line. `None` trusts
    /// nothing yet, so the first contact ends in [`SshError::UnknownHostKey`].
    Pinned(Option<String>),
}

/// Records `key` (an OpenSSH public key line, as in
/// [`SshError::UnknownHostKey`]) for `host:port` in a `known_hosts` file,
/// for example after the user confirmed the fingerprint. The next
/// connection with [`HostKeyPolicy::KnownHostsFile`] then trusts this key,
/// without `accept_new`.
///
/// Only for unknown keys: if the file already holds another key of the same
/// type for the host, this ends in [`SshError::HostKeyChanged`] and writes
/// nothing, since the old key would stay trusted next to the new one.
pub fn trust_host_key(
    path: &std::path::Path,
    host: &str,
    port: u16,
    key: &str,
) -> Result<(), SshError> {
    let key = crate::keys::parse_public(key)?;
    let host = host_entry(host)?;
    let recorded = recorded_keys(path, &host, port)?;
    if recorded.iter().any(|(_, k)| k.key_data() == key.key_data()) {
        return Ok(());
    }
    if recorded
        .iter()
        .any(|(_, k)| k.algorithm() == key.algorithm())
    {
        return Err(SshError::HostKeyChanged {
            host,
            key: key.to_openssh().unwrap_or_default(),
            fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
        });
    }
    learn(path, &host, port, &key)
}

/// The host as `known_hosts` stores it: lower case, as OpenSSH writes it.
/// Characters that would split or widen the entry are refused.
fn host_entry(host: &str) -> Result<String, SshError> {
    let refused = |c: char| c.is_whitespace() || c.is_control() || ",*?!|#@".contains(c);
    if host.is_empty() || host.chars().any(refused) {
        return Err(SshError::Key(format!(
            "invalid host for known_hosts: {host:?}"
        )));
    }
    Ok(host.to_ascii_lowercase())
}

/// Keys recorded for `host:port`. A missing file holds none; a file that
/// exists but cannot be read is an error, not an empty list.
fn recorded_keys(
    path: &std::path::Path,
    host: &str,
    port: u16,
) -> Result<Vec<(usize, PublicKey)>, SshError> {
    if path.exists() {
        std::fs::File::open(path)?;
    }
    // russh finds hashed entries and plain ones written exactly like this.
    let mut keys = known_hosts::known_host_keys_path(host, port, path).map_err(|err| {
        SshError::Io(std::io::Error::other(format!(
            "known_hosts {}: {err}",
            path.display()
        )))
    })?;
    // Plain entries in another casing (by hand or by older tools) count
    // too, or TOFU would learn a second key next to them.
    let wanted = if port == 22 {
        host.to_owned()
    } else {
        format!("[{host}]:{port}")
    };
    if let Ok(text) = std::fs::read_to_string(path) {
        for (index, line) in text.lines().enumerate() {
            let mut fields = line.split_whitespace();
            let (Some(names), Some(kind), Some(blob)) =
                (fields.next(), fields.next(), fields.next())
            else {
                continue;
            };
            let named = names
                .split(',')
                .any(|name| name != wanted && name.eq_ignore_ascii_case(&wanted));
            if named && let Ok(key) = PublicKey::from_openssh(&format!("{kind} {blob}")) {
                keys.push((index + 1, key));
            }
        }
    }
    Ok(keys)
}

fn learn(path: &std::path::Path, host: &str, port: u16, key: &PublicKey) -> Result<(), SshError> {
    known_hosts::learn_known_hosts_path(host, port, key, path)
        .map_err(|e| SshError::Io(std::io::Error::other(e.to_string())))
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
                // An unreadable file or a bad host is no decision for the
                // user; report it instead of asking again and again.
                let host = match host_entry(&self.host) {
                    Ok(host) => host,
                    Err(err) => return self.refuse(err),
                };
                let recorded = match recorded_keys(path, &host, self.port) {
                    Ok(recorded) => recorded,
                    Err(err) => return self.refuse(err),
                };
                if recorded
                    .iter()
                    .any(|(_, key)| key.key_data() == server_public_key.key_data())
                {
                    return Ok(true);
                }
                if recorded
                    .iter()
                    .any(|(_, key)| key.algorithm() == server_public_key.algorithm())
                {
                    return self.refuse(changed());
                }
                // Learn only for a host without any entry. A host known with
                // another key type now showing a new type could be someone
                // in the middle, so the user decides.
                if *accept_new && recorded.is_empty() {
                    return match learn(path, &host, self.port, &server_public_key) {
                        Ok(()) => Ok(true),
                        Err(err) => self.refuse(err),
                    };
                }
                self.refuse(unknown())
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

    #[test]
    fn other_key_type_is_not_learned() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("known_hosts");
        std::fs::write(
            &path,
            "[h]:2222 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=\n",
        )?;
        let (key, line) = server_key()?;
        let tofu = HostKeyPolicy::KnownHostsFile {
            path: path.clone(),
            accept_new: true,
        };
        let (check, _) = HostKeyCheck::new("h", 2222, tofu.clone());
        assert!(!check.check(&key)?);
        assert!(matches!(
            refusal(&check.refusal),
            Some(SshError::UnknownHostKey { .. })
        ));
        assert!(!std::fs::read_to_string(&path)?.contains("ssh-ed25519"));

        trust_host_key(&path, "h", 2222, &line)?;
        let (check, _) = HostKeyCheck::new("h", 2222, tofu);
        assert!(check.check(&key)?);
        Ok(())
    }

    #[test]
    fn trust_refuses_a_second_key_of_the_same_type() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("known_hosts");
        let (_, first) = server_key()?;
        let (_, second) = server_key()?;
        trust_host_key(&path, "Host.Example", 22, &first)?;
        trust_host_key(&path, "host.example", 22, &first)?;
        let written = std::fs::read_to_string(&path)?;
        assert_eq!(written.matches("host.example ssh-ed25519 ").count(), 1);
        assert!(matches!(
            trust_host_key(&path, "host.example", 22, &second),
            Err(SshError::HostKeyChanged { .. })
        ));
        assert_eq!(std::fs::read_to_string(&path)?, written);
        Ok(())
    }

    #[test]
    fn host_names_are_lower_case_and_plain() {
        assert!(matches!(
            host_entry("Server.Example").as_deref(),
            Ok("server.example")
        ));
        for bad in ["", "a,b", "a b", "a\nb", "*.example"] {
            assert!(host_entry(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn upper_case_host_matches_recorded_entry() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("known_hosts");
        let (key, line) = server_key()?;
        trust_host_key(&path, "server.example", 22, &line)?;
        let (other, _) = server_key()?;
        let tofu = HostKeyPolicy::KnownHostsFile {
            path: path.clone(),
            accept_new: true,
        };
        let (check, _) = HostKeyCheck::new("Server.Example", 22, tofu);
        assert!(check.check(&key)?);
        assert!(!check.check(&other)?);
        assert!(matches!(
            refusal(&check.refusal),
            Some(SshError::HostKeyChanged { .. })
        ));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_file_is_an_error_not_unknown() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("known_hosts");
        std::fs::write(&path, "")?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o200))?;
        if std::fs::File::open(&path).is_ok() {
            return Ok(()); // running as root, permissions do not apply
        }
        let (key, _) = server_key()?;
        let tofu = HostKeyPolicy::KnownHostsFile {
            path: path.clone(),
            accept_new: true,
        };
        let (check, _) = HostKeyCheck::new("h", 22, tofu);
        assert!(!check.check(&key)?);
        assert!(matches!(refusal(&check.refusal), Some(SshError::Io(_))));
        Ok(())
    }

    #[test]
    fn entry_in_other_casing_blocks_tofu() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("known_hosts");
        let (key, line) = server_key()?;
        std::fs::write(&path, format!("[Server.Example]:2222 {line}\n"))?;
        let tofu = HostKeyPolicy::KnownHostsFile {
            path: path.clone(),
            accept_new: true,
        };
        let (check, _) = HostKeyCheck::new("server.example", 2222, tofu);
        assert!(check.check(&key)?);
        let (other, _) = server_key()?;
        assert!(!check.check(&other)?);
        assert!(matches!(
            refusal(&check.refusal),
            Some(SshError::HostKeyChanged { .. })
        ));
        assert_eq!(std::fs::read_to_string(&path)?.lines().count(), 1);
        Ok(())
    }
}
