//! Client keys: generate, load from text, describe.

use russh::keys::ssh_key::LineEnding;
use russh::keys::ssh_key::rand_core::UnwrapErr;
use russh::keys::{Algorithm, HashAlg, PrivateKey, PublicKey};
use ssh_key::getrandom::SysRng;

use crate::SshError;

/// A freshly generated key in OpenSSH text form.
#[derive(Clone)]
pub struct GeneratedKey {
    /// Unencrypted OpenSSH private key. Store it somewhere safe, e.g. the Keychain.
    pub private_openssh: String,
    /// One `authorized_keys` style line: `ssh-ed25519 AAAA... comment`.
    pub public_openssh: String,
    /// `SHA256:...`
    pub fingerprint: String,
}

/// Generates an ed25519 key pair.
pub fn generate_ed25519(comment: &str) -> Result<GeneratedKey, SshError> {
    let mut rng = UnwrapErr(SysRng);
    let mut key = PrivateKey::random(&mut rng, Algorithm::Ed25519).map_err(key_error)?;
    key.set_comment(comment);
    describe(&key)
}

/// Parses an unencrypted OpenSSH private key.
pub fn parse_private(private_openssh: &str) -> Result<PrivateKey, SshError> {
    PrivateKey::from_openssh(private_openssh).map_err(key_error)
}

/// Parses one OpenSSH public key line (`ssh-ed25519 AAAA... comment`).
/// Anything spanning more than one line is refused.
pub fn parse_public(public_openssh: &str) -> Result<PublicKey, SshError> {
    if public_openssh.contains(['\n', '\r']) {
        return Err(SshError::Key("public key must be a single line".into()));
    }
    PublicKey::from_openssh(public_openssh).map_err(key_error)
}

/// `SHA256:...` of a public key, as `ssh-keygen -lf` prints it.
pub fn fingerprint(key: &PublicKey) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
}

/// Text forms of an existing key.
pub fn describe(key: &PrivateKey) -> Result<GeneratedKey, SshError> {
    let public = key.public_key();
    Ok(GeneratedKey {
        private_openssh: key
            .to_openssh(LineEnding::LF)
            .map_err(key_error)?
            .to_string(),
        public_openssh: public.to_openssh().map_err(key_error)?,
        fingerprint: public.fingerprint(HashAlg::Sha256).to_string(),
    })
}

fn key_error(err: impl std::fmt::Display) -> SshError {
    SshError::Key(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_key_round_trips() -> Result<(), SshError> {
        let generated = generate_ed25519("amiscara-ssh-test")?;
        assert!(generated.public_openssh.starts_with("ssh-ed25519 "));
        assert!(generated.public_openssh.ends_with(" amiscara-ssh-test"));
        assert!(generated.fingerprint.starts_with("SHA256:"));
        let parsed = parse_private(&generated.private_openssh)?;
        assert_eq!(describe(&parsed)?.fingerprint, generated.fingerprint);
        Ok(())
    }

    #[test]
    fn public_key_must_be_one_valid_line() -> Result<(), SshError> {
        let generated = generate_ed25519("one-line")?;
        assert!(parse_public(&generated.public_openssh).is_ok());
        let injected = format!("{}\nssh-ed25519 AAAA other", generated.public_openssh);
        assert!(parse_public(&injected).is_err());
        assert!(parse_public("command=\"sh\" ssh-ed25519 AAAA").is_err());
        Ok(())
    }
}
