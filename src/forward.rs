//! Local port forwarding over a [`Route`]: a local TCP port whose
//! connections reach `host:port` as seen from the target of the route.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};

use crate::{HopFailure, Lease, Route, SessionPool, SshError};

/// State of a [`LocalForward`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ForwardStatus {
    /// Connections being forwarded right now.
    pub active: usize,
    /// Why the last connection could not be forwarded; cleared by the next
    /// one that could.
    pub error: Option<HopFailure>,
}

/// A local port forwarded over a route of a [`SessionPool`]. It holds a
/// [`Lease`] on the route while it lives, so the jumps stay open. Dropping it
/// stops listening, ends every forwarded connection and gives the lease
/// back.
pub struct LocalForward {
    local: SocketAddr,
    status: watch::Receiver<ForwardStatus>,
    task: JoinHandle<()>,
}

impl std::fmt::Debug for LocalForward {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalForward")
            .field("local", &self.local)
            .field("status", &*self.status.borrow())
            .finish_non_exhaustive()
    }
}

impl LocalForward {
    /// The address it listens on, with the real port if it was bound to
    /// port 0.
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Follows the state: active connections and the last error.
    pub fn status(&self) -> watch::Receiver<ForwardStatus> {
        self.status.clone()
    }
}

impl Drop for LocalForward {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl SessionPool {
    /// Listens on `bind` and forwards every connection to `host:port`, as
    /// seen from the target of `route`, over a `direct-tcpip` channel.
    ///
    /// The port is bound first: taken, it ends in [`SshError::PortInUse`]
    /// before anything connects. Then the route is set up as with
    /// [`SessionPool::connect`], its errors unchanged. Must be called in a
    /// Tokio runtime; the forwarding runs in tasks of it.
    ///
    /// If the connection has ended when a client connects, the route is set
    /// up once more for that client. A connection that cannot be forwarded
    /// is closed and its error kept in [`ForwardStatus::error`]; the port
    /// keeps listening.
    pub async fn forward_local(
        &self,
        route: Route,
        bind: SocketAddr,
        host: String,
        port: u16,
    ) -> Result<LocalForward, SshError> {
        let listener = TcpListener::bind(bind).await.map_err(|error| {
            if error.kind() == std::io::ErrorKind::AddrInUse {
                SshError::PortInUse(bind)
            } else {
                SshError::Io(error)
            }
        })?;
        let local = listener.local_addr()?;
        let lease = self.connect(&route).await?;
        let (status, receiver) = watch::channel(ForwardStatus::default());
        let forwarder = Forwarder {
            pool: self.clone(),
            route,
            host,
            port,
            lease: Arc::new(lease),
            status: Arc::new(status),
        };
        let task = tokio::spawn(forwarder.run(listener));
        Ok(LocalForward {
            local,
            status: receiver,
            task,
        })
    }
}

struct Forwarder {
    pool: SessionPool,
    route: Route,
    host: String,
    port: u16,
    lease: Arc<Lease>,
    status: Arc<watch::Sender<ForwardStatus>>,
}

impl Forwarder {
    /// Accepts until dropped. The connections run in `tasks`, so they end
    /// with it.
    async fn run(mut self, listener: TcpListener) {
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    // A failed accept (for example too many open files)
                    // concerns only that client.
                    if let Ok((stream, _)) = accepted {
                        let lease = self.current().await;
                        let status = Arc::clone(&self.status);
                        let (host, port) = (self.host.clone(), self.port);
                        tasks.spawn(forward(stream, lease, host, port, status));
                    }
                }
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
    }

    /// The lease to use for a new client: the current one, or once a new one
    /// if its connection has ended.
    async fn current(&mut self) -> Result<Arc<Lease>, SshError> {
        if !self.lease.is_closed() {
            return Ok(Arc::clone(&self.lease));
        }
        let lease = Arc::new(self.pool.connect(&self.route).await?);
        self.lease = Arc::clone(&lease);
        Ok(lease)
    }
}

/// Counts a forwarded connection while it lives.
struct Active(Arc<watch::Sender<ForwardStatus>>);

impl Drop for Active {
    fn drop(&mut self) {
        self.0
            .send_modify(|status| status.active = status.active.saturating_sub(1));
    }
}

async fn forward(
    mut stream: TcpStream,
    lease: Result<Arc<Lease>, SshError>,
    host: String,
    port: u16,
    status: Arc<watch::Sender<ForwardStatus>>,
) {
    let channel = match lease {
        Ok(lease) => lease.direct_tcpip(&host, port).await.map(|c| (c, lease)),
        Err(error) => Err(error),
    };
    let (channel, _lease) = match channel {
        Ok(opened) => opened,
        Err(error) => {
            status.send_modify(|status| status.error = Some(HopFailure::from(&error)));
            // Dropping the stream closes it.
            return;
        }
    };
    status.send_modify(|status| {
        status.active += 1;
        status.error = None;
    });
    let _active = Active(Arc::clone(&status));
    // Shutting down the channel side sends EOF, so the far end learns that
    // the client is done and the copy ends once both sides are. An error of
    // either side ends the connection; there is nobody to tell.
    let mut channel = channel.into_stream();
    tokio::io::copy_bidirectional(&mut stream, &mut channel)
        .await
        .ok();
}
