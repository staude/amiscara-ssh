//! Local port forwarding over a [`Route`]: a local TCP port whose
//! connections reach `host:port` as seen from the target of the route.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::{Mutex, watch};
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
        let listener = listen(bind).map_err(|error| {
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
            lease: Arc::new(Mutex::new(Arc::new(lease))),
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
    /// The lease new clients use; replaced once its connection has ended.
    lease: Arc<Mutex<Arc<Lease>>>,
    status: Arc<watch::Sender<ForwardStatus>>,
}

/// Wait after a failed accept, which may fail again at once (for example out of file
/// descriptors).
const ACCEPT_PAUSE: Duration = Duration::from_millis(100);

/// Binds `addr` and listens, with `SO_REUSEADDR` on Unix like [`TcpListener::bind`], so a port
/// is free again at once after a forward ends, also with connections in `TIME_WAIT`. On macOS
/// and the BSDs that option also lets a socket bind `127.0.0.1:port` while another program
/// listens on `0.0.0.0:port`, and clients of that program would silently land in the forward.
/// There a specific address first checks that the wildcard address of its family is free on
/// that port. Linux and Windows refuse such a bind by themselves.
fn listen(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let socket = |ip: IpAddr| match ip {
        IpAddr::V4(_) => TcpSocket::new_v4(),
        IpAddr::V6(_) => TcpSocket::new_v6(),
    };
    #[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
    if addr.port() != 0 && !addr.ip().is_unspecified() {
        let wildcard = match addr.ip() {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        };
        let probe = socket(wildcard)?;
        // Without it a connection of an earlier forward in `TIME_WAIT` would count as taken.
        probe.set_reuseaddr(true)?;
        probe.bind(SocketAddr::new(wildcard, addr.port()))?;
        drop(probe);
    }
    let listener = socket(addr.ip())?;
    #[cfg(unix)]
    listener.set_reuseaddr(true)?;
    listener.bind(addr)?;
    listener.listen(1024)
}

impl Forwarder {
    /// Accepts until dropped. The connections run in `tasks`, so they end
    /// with it.
    async fn run(self, listener: TcpListener) {
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    match accepted {
                        Ok((stream, _)) => {
                            let current = Current {
                                pool: self.pool.clone(),
                                route: self.route.clone(),
                                lease: Arc::clone(&self.lease),
                            };
                            let status = Arc::clone(&self.status);
                            let (host, port) = (self.host.clone(), self.port);
                            tasks.spawn(forward(stream, current, host, port, status));
                        }
                        // A failed accept (for example too many open files) concerns only
                        // that client; the pause keeps a lasting one from spinning.
                        Err(_) => tokio::time::sleep(ACCEPT_PAUSE).await,
                    }
                }
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
    }
}

/// What a client task needs to find its lease.
struct Current {
    pool: SessionPool,
    route: Route,
    lease: Arc<Mutex<Arc<Lease>>>,
}

impl Current {
    /// The lease to use for a new client: the current one, or once a new one if its
    /// connection has ended. Runs in the task of the client, so accepting goes on meanwhile;
    /// clients arriving during the set-up wait for it and use the new lease, or try once more
    /// themselves if it failed.
    async fn get(self) -> Result<Arc<Lease>, SshError> {
        let mut lease = self.lease.lock().await;
        if lease.is_closed() {
            *lease = Arc::new(self.pool.connect(&self.route).await?);
        }
        Ok(Arc::clone(&lease))
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
    current: Current,
    host: String,
    port: u16,
    status: Arc<watch::Sender<ForwardStatus>>,
) {
    let channel = match current.get().await {
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
