//! An interactive shell with a pseudo terminal.

use std::collections::VecDeque;

use russh::client;
use russh::{Channel, ChannelMsg, ChannelReadHalf, ChannelWriteHalf};

use crate::{Session, SshError};

/// Size of the terminal in character cells.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtySize {
    pub cols: u16,
    pub rows: u16,
}

/// What a shell sends back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellEvent {
    /// Bytes for the terminal, from stdout or stderr.
    Output(Vec<u8>),
    /// The shell ended with this exit status.
    Exit(u32),
    /// The shell was ended by this signal (e.g. `KILL`).
    Signal(String),
}

/// A running shell. [`Shell::split`] separates reading and writing, so one
/// task can wait for output while another one sends input.
pub struct Shell {
    read: ShellReader,
    write: ShellWriter,
}

/// The sending half of a [`Shell`].
pub struct ShellWriter {
    write: ChannelWriteHalf<client::Msg>,
}

impl Session {
    /// Opens a shell with a PTY of type `term` (e.g. `xterm-256color`).
    pub async fn open_shell(&self, term: &str, size: PtySize) -> Result<Shell, SshError> {
        let mut channel = self.channel_session().await?;
        let mut pending = VecDeque::new();
        channel
            .request_pty(
                true,
                term,
                u32::from(size.cols),
                u32::from(size.rows),
                0,
                0,
                &[],
            )
            .await?;
        wait_for_reply(&mut channel, "a pty", &mut pending).await?;
        channel.request_shell(true).await?;
        wait_for_reply(&mut channel, "a shell", &mut pending).await?;
        let (read, write) = channel.split();
        Ok(Shell {
            read: ShellReader { read, pending },
            write: ShellWriter { write },
        })
    }
}

/// Waits for the answer to a request sent with `want_reply`. Output that
/// arrives before it is kept for [`Shell::next`].
async fn wait_for_reply(
    channel: &mut Channel<client::Msg>,
    what: &str,
    pending: &mut VecDeque<ShellEvent>,
) -> Result<(), SshError> {
    loop {
        match channel.wait().await {
            Some(ChannelMsg::Success) => return Ok(()),
            Some(ChannelMsg::Failure) => return Err(SshError::Refused(what.into())),
            Some(msg) => {
                if let Some(event) = event(msg) {
                    pending.push_back(event);
                }
            }
            None => return Err(SshError::Refused(format!("{what}, channel closed"))),
        }
    }
}

fn event(msg: ChannelMsg) -> Option<ShellEvent> {
    match msg {
        ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } => {
            Some(ShellEvent::Output(data.to_vec()))
        }
        ChannelMsg::ExitStatus { exit_status } => Some(ShellEvent::Exit(exit_status)),
        ChannelMsg::ExitSignal { signal_name, .. } => Some(ShellEvent::Signal(match signal_name {
            russh::Sig::Custom(name) => name,
            known => format!("{known:?}"),
        })),
        _ => None,
    }
}

impl Shell {
    /// Sends input, for example typed keys.
    pub async fn write(&self, data: &[u8]) -> Result<(), SshError> {
        self.write.write(data).await
    }

    /// Tells the server the new terminal size.
    pub async fn resize(&self, size: PtySize) -> Result<(), SshError> {
        self.write.resize(size).await
    }

    /// The next output or the exit status. `None` once the channel is closed.
    pub async fn next(&mut self) -> Option<ShellEvent> {
        self.read.next().await
    }

    /// Splits into receiving and sending half, each for a task of its own.
    pub fn split(self) -> (ShellReader, ShellWriter) {
        (self.read, self.write)
    }

    /// Closes the channel.
    pub async fn close(&self) -> Result<(), SshError> {
        self.write.close().await
    }
}

/// The receiving half of a [`Shell`] after [`Shell::split`].
pub struct ShellReader {
    read: ChannelReadHalf,
    pending: VecDeque<ShellEvent>,
}

impl ShellReader {
    /// As [`Shell::next`].
    pub async fn next(&mut self) -> Option<ShellEvent> {
        if let Some(event) = self.pending.pop_front() {
            return Some(event);
        }
        loop {
            match self.read.wait().await? {
                ChannelMsg::Close => return None,
                msg => {
                    if let Some(event) = event(msg) {
                        return Some(event);
                    }
                }
            }
        }
    }
}

impl ShellWriter {
    /// As [`Shell::write`].
    pub async fn write(&self, data: &[u8]) -> Result<(), SshError> {
        Ok(self.write.data(data).await?)
    }

    /// As [`Shell::resize`].
    pub async fn resize(&self, size: PtySize) -> Result<(), SshError> {
        Ok(self
            .write
            .window_change(u32::from(size.cols), u32::from(size.rows), 0, 0)
            .await?)
    }

    /// As [`Shell::close`].
    pub async fn close(&self) -> Result<(), SshError> {
        Ok(self.write.close().await?)
    }
}
