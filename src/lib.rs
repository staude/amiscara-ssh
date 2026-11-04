//! Shared SSH client of the Amiscara apps, built on russh.
//!
//! [`Session::connect`] opens a connection to an [`SshTarget`], checks the
//! host key against a [`HostKeyPolicy`] (an OpenSSH `known_hosts` file with
//! trust on first use, or one pinned key) and signs in with an [`Identity`]:
//! key file, SSH agent, key in memory or password. On the session,
//! [`Session::open_shell`] starts a shell with a PTY, and `direct-tcpip` and
//! `direct-streamlocal` channels reach ports and sockets on the server.
//! [`keys`] generates, reads and describes client keys.
//!
//! The crate started as the general SSH part of `herdr-transport` in
//! Amiscara Agents; everything specific to an app stays in the app.

mod client;
mod error;
mod host_key;
pub mod keys;
mod shell;

pub use client::{Identity, Session, SshTarget};
pub use error::SshError;
pub use host_key::HostKeyPolicy;
pub use shell::{PtySize, Shell, ShellEvent, ShellReader, ShellWriter};

pub use russh::client::Msg;
pub use russh::keys::{PrivateKey, PublicKey};
pub use russh::{Channel, ChannelMsg};
pub use zeroize::Zeroizing;
