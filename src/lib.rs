//! Shared SSH client of the Amiscara apps, built on russh.
//!
//! [`Session::connect`] opens a connection to an [`SshTarget`], checks the
//! host key against a [`HostKeyPolicy`] (an OpenSSH `known_hosts` file with
//! trust on first use, one pinned key, or a [`HostKeyVerifier`] that lets
//! the app decide during the handshake) and signs in with an [`Identity`]:
//! key file, SSH agent, key in memory or password. On the session,
//! [`Session::open_shell`] starts a shell with a PTY, and `direct-tcpip` and
//! `direct-streamlocal` channels reach ports and sockets on the server.
//! [`keys`] generates, reads and describes client keys.
//!
//! Jump hosts: [`Session::connect_via`] reaches a server through a
//! `direct-tcpip` channel on another session, without a local port. A
//! [`Route`] chains any number of jumps; a [`SessionPool`] sets it up hop by
//! hop, keeps one connection per jump for every session behind it, closes it
//! when the last [`Lease`] is gone and reports each hop as a [`HopEvent`]
//! (connecting, connected with latency, reused, failed with a
//! [`HopFailure`], closed). Agent forwarding is off unless the target turns
//! it on with [`SshTarget::agent_forward`], and never reaches a jump.
//!
//! One-time codes: a server that asks questions during sign-in, for example
//! a bastion that wants a code after the key, is answered by the
//! [`KeyboardInteractive`] of its [`SshTarget`] via keyboard-interactive.
//! The app gets a [`KeyboardPrompt`] naming the asking hop and the route
//! and returns a [`KeyboardAnswer`], or `None` to cancel
//! ([`SshError::Cancelled`]). A pool keeps such a hop open after its last
//! lease ([`KeyboardAnswer::keep_open`], [`PoolConfig::code_grace`]), so the
//! next session needs no new code; [`SessionPool::close_idle`] closes it
//! early.
//!
//! ProxyCommand: [`Session::connect_command`] runs a local command, for
//! example `cloudflared access ssh --hostname %h`, and speaks SSH over its
//! stdin and stdout; in a [`Route`] [`Route::proxy_command`] does the same for
//! the first hop. `%h`, `%p`, `%r` and `%%` are replaced as in OpenSSH, a
//! host or user that is unsafe in a command line is refused. If the command
//! ends before the sign-in, [`SshError::ProxyCommand`] names its exit status
//! and the last of its error output; dropping the connection kills it.
//!
//! Files: [`Session::open_sftp`] starts the `sftp` subsystem on a session,
//! also one behind jumps, and returns a [`russh_sftp::client::SftpSession`].
//! The crate re-exports [`russh_sftp`], so apps use the same version.
//!
//! The crate started as the general SSH part of `herdr-transport` in
//! Amiscara Agents; everything specific to an app stays in the app.

mod chain;
mod client;
mod error;
mod host_key;
pub mod keys;
mod prompt;
mod proxy;
mod sftp;
mod shell;

pub use chain::{HopEvent, HopFailure, HopState, Lease, PoolConfig, Route, SessionPool};
pub use client::{Identity, Session, SshTarget};
pub use error::SshError;
pub use host_key::{HostKeyPolicy, HostKeyVerdict, HostKeyVerifier, trust_host_key};
pub use prompt::{KeyboardAnswer, KeyboardInteractive, KeyboardPrompt, PromptFuture, PromptLine};
pub use shell::{PtySize, Shell, ShellEvent, ShellReader, ShellWriter};

pub use russh::client::Msg;
pub use russh::keys::{PrivateKey, PublicKey};
pub use russh::{Channel, ChannelMsg};
pub use russh_sftp;
pub use zeroize::Zeroizing;
