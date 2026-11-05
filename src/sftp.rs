//! The SFTP subsystem on a session.

use russh::ChannelMsg;
use russh_sftp::client::SftpSession;

use crate::{Session, SshError};

impl Session {
    /// Opens the `sftp` subsystem on a new session channel and starts the
    /// protocol on it. The returned [`SftpSession`] works like `std::fs`
    /// (read directories, open, create, rename, remove, metadata).
    ///
    /// The SFTP session only borrows the channel: keep this [`Session`] (or
    /// its [`crate::Lease`]) alive as long as the SFTP session is used, or
    /// the connection below it may close.
    ///
    /// A server without SFTP, or one that refuses the subsystem or the
    /// protocol start, ends in [`SshError::SftpUnavailable`].
    pub async fn open_sftp(&self) -> Result<SftpSession, SshError> {
        let mut channel = self.channel_session().await?;
        channel.request_subsystem(true, "sftp").await?;
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Success) => break,
                Some(ChannelMsg::Failure) => {
                    return Err(SshError::SftpUnavailable(
                        "server refused the sftp subsystem".into(),
                    ));
                }
                // Window adjustments and the like before the answer.
                Some(_) => {}
                None => {
                    return Err(SshError::SftpUnavailable(
                        "channel closed before the sftp subsystem started".into(),
                    ));
                }
            }
        }
        SftpSession::new(channel.into_stream())
            .await
            .map_err(|e| SshError::SftpUnavailable(e.to_string()))
    }
}
