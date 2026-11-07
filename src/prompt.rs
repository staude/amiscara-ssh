//! Sign-in by keyboard-interactive: one-time codes and other questions of a
//! server, answered by the app.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use zeroize::Zeroizing;

/// A question of a server during sign-in by keyboard-interactive, for
/// example the one-time code of a bastion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyboardPrompt {
    /// `user@host:port` of every hop of the route being set up, the target
    /// last. Without a route (a plain [`crate::Session::connect`]) only the
    /// asking host.
    pub route: Vec<String>,
    /// Index of the asking hop in `route`.
    pub index: usize,
    /// Name of the request as the server sends it, often empty.
    pub name: String,
    /// Instructions of the server, often empty.
    pub instructions: String,
    /// The questions, in the order the answers are expected.
    pub prompts: Vec<PromptLine>,
    /// Attempt of this sign-in, from 1; 2 and 3 follow a refused answer.
    pub attempt: u32,
}

/// One question of a [`KeyboardPrompt`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptLine {
    /// The text the server shows, for example `Verification code: `.
    pub text: String,
    /// Whether the answer may be shown while typing; false for codes and
    /// passwords.
    pub echo: bool,
}

/// The answer of the app to a [`KeyboardPrompt`].
///
/// russh copies the responses into plain `String`s while sending them; only
/// the copies here are wiped on drop.
#[derive(Clone)]
pub struct KeyboardAnswer {
    /// One response per [`PromptLine`], in the same order.
    pub responses: Vec<Zeroizing<String>>,
    /// How long a [`crate::SessionPool`] keeps the connection to this hop
    /// open after its last user is gone, so the next session within that
    /// time needs no new code. `None` keeps it for
    /// [`crate::PoolConfig::code_grace`]. The answer to the last question of
    /// a sign-in counts.
    pub keep_open: Option<Duration>,
}

impl std::fmt::Debug for KeyboardAnswer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyboardAnswer")
            .field("responses", &self.responses.len())
            .field("keep_open", &self.keep_open)
            .finish()
    }
}

/// What [`KeyboardInteractive::ask`] returns: the answer, or `None` if the
/// user cancelled.
pub type PromptFuture = Pin<Box<dyn Future<Output = Option<KeyboardAnswer>> + Send>>;

/// Answers the questions of a server during sign-in, see
/// [`crate::SshTarget::keyboard_interactive`]. Called for the hop that asks,
/// once per request with questions. The time until the answer does not count
/// towards [`crate::PoolConfig::connect_timeout`].
pub trait KeyboardInteractive: Send + Sync + std::fmt::Debug {
    fn ask(&self, prompt: KeyboardPrompt) -> PromptFuture;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_hides_answers() {
        let answer = KeyboardAnswer {
            responses: vec![Zeroizing::new("123456".into())],
            keep_open: Some(Duration::from_secs(5)),
        };
        let text = format!("{answer:?}");
        assert!(!text.contains("123456"), "{text}");
    }
}
