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
mod sftp;
mod shell;

pub use chain::{HopEvent, HopFailure, HopState, Lease, PoolConfig, Route, SessionPool};
pub use client::{Identity, Session, SshTarget};
pub use error::SshError;
pub use host_key::{HostKeyPolicy, HostKeyVerdict, HostKeyVerifier, trust_host_key};
pub use shell::{PtySize, Shell, ShellEvent, ShellReader, ShellWriter};

pub use russh::client::Msg;
pub use russh::keys::{PrivateKey, PublicKey};
pub use russh::{Channel, ChannelMsg};
pub use russh_sftp;
pub use zeroize::Zeroizing;
