//! Jump host chains: a [`Route`] over any number of jumps, and a
//! [`SessionPool`] with one shared connection per jump.

use std::collections::HashMap;
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use russh::client;
use tokio::sync::{OwnedMutexGuard, broadcast};

use crate::{Session, SshError, SshTarget};

/// The way to a server: first the jumps in order, then the target. Each hop
/// signs in with its own user and credentials and is checked against its own
/// host key policy. A hop's `host` is resolved by the hop before it, so the
/// host key of `jump` is looked up as `jump`, not under an address.
#[derive(Debug, Clone)]
pub struct Route {
    pub jumps: Vec<SshTarget>,
    pub target: SshTarget,
}

impl Route {
    /// A route without jumps.
    pub fn direct(target: SshTarget) -> Self {
        Self {
            jumps: Vec::new(),
            target,
        }
    }

    /// `user@host:port` of every hop, the target last.
    pub fn labels(&self) -> Vec<String> {
        self.hops().map(SshTarget::label).collect()
    }

    fn hops(&self) -> impl Iterator<Item = &SshTarget> {
        self.jumps.iter().chain(std::iter::once(&self.target))
    }
}

/// Settings of a [`SessionPool`].
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Limit per hop, from opening the transport up to the end of sign-in.
    pub connect_timeout: Duration,
    /// Keepalive on every hop, so a hanging jump is noticed.
    pub keepalive_interval: Duration,
    /// Unanswered keepalives after which a hop counts as gone.
    pub keepalive_max: usize,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            keepalive_interval: Duration::from_secs(5),
            keepalive_max: 3,
        }
    }
}

/// What happened to one hop of a route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HopEvent {
    /// `user@host:port` of every hop of the route that caused the event (for
    /// [`HopState::Closed`] the route that built the connection).
    pub route: Vec<String>,
    /// Index of the hop in `route`; the target is the last one.
    pub index: usize,
    pub state: HopState,
}

/// State of a hop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HopState {
    /// A new connection to the hop is being set up.
    Connecting,
    /// The hop is signed in. `latency` is the time from opening the
    /// transport to the end of sign-in, measured once.
    Connected { latency: Duration },
    /// The pool already held a live connection to the hop.
    Reused,
    /// The hop failed; the route was not set up.
    Failed(HopFailure),
    /// The connection to the hop has ended.
    Closed,
}

/// Why a hop failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HopFailure {
    /// No TCP connection to the first hop.
    Unreachable,
    /// The hop before refused the `direct-tcpip` channel to this hop, for
    /// example because it cannot resolve or reach it.
    ChannelRefused,
    /// Connecting and signing in took longer than
    /// [`PoolConfig::connect_timeout`].
    Timeout,
    /// The host key is not trusted yet.
    HostKeyUnknown,
    /// The host key differs from the trusted one.
    HostKeyChanged,
    /// The hop refused every credential.
    AuthFailed,
    /// The connection ended while setting up.
    Closed,
    /// Anything else, for example an unreadable key file.
    Other,
}

impl From<&SshError> for HopFailure {
    fn from(error: &SshError) -> Self {
        match error {
            SshError::Hop { source, .. } => Self::from(source.as_ref()),
            SshError::Timeout(_) => Self::Timeout,
            SshError::UnknownHostKey { .. } => Self::HostKeyUnknown,
            SshError::HostKeyChanged { .. } => Self::HostKeyChanged,
            SshError::AuthFailed(_) => Self::AuthFailed,
            SshError::Ssh(russh::Error::ChannelOpenFailure(_)) => Self::ChannelRefused,
            SshError::Ssh(
                russh::Error::Disconnect
                | russh::Error::HUP
                | russh::Error::SendError
                | russh::Error::KeepaliveTimeout
                | russh::Error::InactivityTimeout,
            ) => Self::Closed,
            SshError::Io(_)
            | SshError::Ssh(_)
            | SshError::Key(_)
            | SshError::Refused(_)
            | SshError::SftpUnavailable(_) => Self::Other,
        }
    }
}

/// Reports [`HopState::Closed`] once for a connection that made it into
/// the pool (or out as a fresh one); a failed set-up stays silent.
#[derive(Clone)]
pub(crate) struct Reporter {
    events: broadcast::Sender<HopEvent>,
    route: Arc<[String]>,
    index: usize,
    armed: Arc<AtomicBool>,
}

impl Reporter {
    fn arm(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }

    pub(crate) fn closed(&self) {
        if self.armed.swap(false, Ordering::SeqCst) {
            // Nobody listening is fine.
            self.events
                .send(HopEvent {
                    route: self.route.to_vec(),
                    index: self.index,
                    state: HopState::Closed,
                })
                .ok();
        }
    }
}

/// One hop of a pool key. The agent setting belongs to it, so a target with
/// agent forwarding never shares a connection with one without.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct HopKey {
    host: String,
    port: u16,
    user: String,
    agent_forward: bool,
}

impl HopKey {
    fn of(hop: &SshTarget) -> Self {
        Self {
            host: hop.host.to_ascii_lowercase(),
            port: hop.port,
            user: hop.user.clone(),
            agent_forward: hop.agent_forward,
        }
    }
}

/// The way up to and including a hop. The same server behind two different
/// jumps is two connections.
type Key = Vec<HopKey>;

/// A pool entry, identified by key and generation.
type Slot = (Key, u64);

struct Entry {
    generation: u64,
    session: Arc<Session>,
    /// Live leases on this entry plus connections built on top of it.
    users: usize,
    parent: Option<Slot>,
}

#[derive(Default)]
struct Entries {
    map: HashMap<Key, Entry>,
    next_generation: u64,
}

impl Entries {
    /// Drops one use of `slot`. An entry nobody uses any more leaves the
    /// pool, and so does its parent once it has no other user; their
    /// sessions go to `closing`, the deepest first.
    fn release(&mut self, slot: Slot, closing: &mut Vec<Arc<Session>>) {
        let mut next = Some(slot);
        while let Some((key, generation)) = next.take() {
            let Some(entry) = self.map.get_mut(&key) else {
                return;
            };
            if entry.generation != generation {
                return;
            }
            entry.users = entry.users.saturating_sub(1);
            if entry.users > 0 {
                return;
            }
            if let Some(entry) = self.map.remove(&key) {
                closing.push(entry.session);
                next = entry.parent;
            }
        }
    }

    /// The live entry at `key` on top of `parent`, with one more user.
    fn reuse(&mut self, key: &Key, parent: Option<&Slot>) -> Option<(u64, Arc<Session>)> {
        let entry = self.map.get_mut(key)?;
        if entry.session.is_closed() || entry.parent.as_ref() != parent {
            return None;
        }
        entry.users += 1;
        Some((entry.generation, Arc::clone(&entry.session)))
    }

    /// Puts `session` at `key` with one user, on top of `parent`. What was at
    /// `key` or behind it is gone: it ran over a dead connection.
    fn insert(
        &mut self,
        key: Key,
        session: Arc<Session>,
        parent: Option<Slot>,
        closing: &mut Vec<Arc<Session>>,
    ) -> u64 {
        let stale: Vec<Key> = self
            .map
            .keys()
            .filter(|k| k.starts_with(&key))
            .cloned()
            .collect();
        for stale_key in stale {
            if let Some(entry) = self.map.remove(&stale_key) {
                closing.push(entry.session);
                // Entries behind it pointed into the removed part; only the
                // entry at `key` held a use of something still in the pool.
                if stale_key.len() == key.len()
                    && let Some(old_parent) = entry.parent
                {
                    self.release(old_parent, closing);
                }
            }
        }
        if let Some((parent_key, parent_generation)) = &parent
            && let Some(entry) = self.map.get_mut(parent_key)
            && entry.generation == *parent_generation
        {
            entry.users += 1;
        }
        let generation = self.next_generation;
        self.next_generation += 1;
        self.map.insert(
            key,
            Entry {
                generation,
                session,
                users: 1,
                parent,
            },
        );
        generation
    }
}

struct Shared {
    entries: Mutex<Entries>,
    locks: Mutex<HashMap<Key, Arc<tokio::sync::Mutex<()>>>>,
    events: broadcast::Sender<HopEvent>,
    config: Arc<client::Config>,
    connect_timeout: Duration,
}

impl Shared {
    fn entries(&self) -> MutexGuard<'_, Entries> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn release(&self, slot: Option<Slot>) {
        let Some(slot) = slot else {
            return;
        };
        let mut closing = Vec::new();
        self.entries().release(slot, &mut closing);
        close_later(closing);
    }

    fn emit(&self, route: &Arc<[String]>, index: usize, state: HopState) {
        self.events
            .send(HopEvent {
                route: route.to_vec(),
                index,
                state,
            })
            .ok();
    }

    /// Waits for the set-up lock of `key`.
    async fn lock(self: &Arc<Self>, key: &Key) -> OwnedMutexGuard<()> {
        let lock = {
            let mut locks = self.locks.lock().unwrap_or_else(PoisonError::into_inner);
            Arc::clone(locks.entry(key.clone()).or_default())
        };
        lock.lock_owned().await
    }
}

/// The use a set-up holds on the deepest hop so far. Given back on drop, so
/// a cancelled `connect` (dropped future, timeout of the caller) leaves
/// nothing behind in the pool.
struct Hold {
    shared: Arc<Shared>,
    slot: Option<Slot>,
}

impl Drop for Hold {
    fn drop(&mut self) {
        self.shared.release(self.slot.take());
    }
}

/// Set-up lock of the hop being built, released and cleaned up on drop.
struct Locked {
    shared: Arc<Shared>,
    keys: Vec<Key>,
    guards: Vec<OwnedMutexGuard<()>>,
}

impl Drop for Locked {
    fn drop(&mut self) {
        self.guards.clear();
        let mut locks = self
            .shared
            .locks
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        for key in &self.keys {
            if locks
                .get(key)
                .is_some_and(|lock| Arc::strong_count(lock) == 1)
            {
                locks.remove(key);
            }
        }
    }
}

/// Disconnects sessions in order, in the background; without a runtime they
/// are only dropped, which ends them too.
fn close_later(sessions: Vec<Arc<Session>>) {
    if sessions.is_empty() {
        return;
    }
    if let Ok(runtime) = tokio::runtime::Handle::try_current() {
        runtime.spawn(async move {
            for session in sessions {
                // Already gone is fine.
                session.disconnect().await.ok();
            }
        });
    }
}

/// Connections over jump chains, with one shared connection per jump.
///
/// Every hop is keyed by the way up to it (host, port and user of each hop
/// so far, for the target also `agent_forward`), so the same server behind
/// two jumps is two connections. Credentials and host key policy are not
/// part of the key: a live connection is reused as it was signed in and
/// checked, a changed policy only applies to the next new connection. A
/// connection stays in the pool while a [`Lease`] or a connection behind it
/// uses it; once the last one is gone, it is closed. Dead connections are
/// replaced on the next [`SessionPool::connect`], together with everything
/// behind them, while the live hops before them are kept.
#[derive(Clone)]
pub struct SessionPool {
    shared: Arc<Shared>,
}

impl SessionPool {
    pub fn new(config: PoolConfig) -> Self {
        let (events, _) = broadcast::channel(64);
        let client = client::Config {
            inactivity_timeout: None,
            keepalive_interval: Some(config.keepalive_interval),
            keepalive_max: config.keepalive_max,
            nodelay: true,
            ..Default::default()
        };
        Self {
            shared: Arc::new(Shared {
                entries: Mutex::new(Entries::default()),
                locks: Mutex::new(HashMap::new()),
                events,
                config: Arc::new(client),
                connect_timeout: config.connect_timeout,
            }),
        }
    }

    /// Events of every hop of every route of this pool. A receiver that falls
    /// more than 64 events behind loses the oldest.
    pub fn subscribe(&self) -> broadcast::Receiver<HopEvent> {
        self.shared.events.subscribe()
    }

    /// A session on the target of `route`, shared with every other lease on
    /// the same route. Jumps never forward the agent, whatever their
    /// `agent_forward` says.
    ///
    /// A failing hop ends in [`SshError::Hop`] with its index, and nothing
    /// set up for this call stays in the pool.
    pub async fn connect(&self, route: &Route) -> Result<Lease, SshError> {
        self.open(route, false).await
    }

    /// As [`SessionPool::connect`], but with a new connection to the target
    /// that no one else shares, for servers that want one per session. The
    /// jumps still come from the pool.
    pub async fn connect_fresh(&self, route: &Route) -> Result<Lease, SshError> {
        self.open(route, true).await
    }

    async fn open(&self, route: &Route, fresh: bool) -> Result<Lease, SshError> {
        let shared = &self.shared;
        let labels: Arc<[String]> = route.labels().into();
        let mut hops: Vec<SshTarget> = route.jumps.clone();
        for jump in &mut hops {
            jump.agent_forward = false;
        }
        hops.push(route.target.clone());
        let last = hops.len() - 1;

        let mut locked = Locked {
            shared: Arc::clone(shared),
            keys: Vec::new(),
            guards: Vec::new(),
        };
        let mut key: Key = Vec::new();
        let mut hold = Hold {
            shared: Arc::clone(shared),
            slot: None,
        };
        let mut below: Option<Arc<Session>> = None;

        for (index, hop) in hops.iter().enumerate() {
            key.push(HopKey::of(hop));
            let pooled = !(fresh && index == last);
            // Only one lock at a time: a route through the same bastion does
            // not wait while this one signs in further down.
            locked.guards.clear();
            if pooled {
                // The lock of this hop keeps two calls from building it twice.
                locked.guards.push(shared.lock(&key).await);
                locked.keys.push(key.clone());
                let reused = shared.entries().reuse(&key, hold.slot.as_ref());
                if let Some((generation, session)) = reused {
                    shared.emit(&labels, index, HopState::Reused);
                    shared.release(hold.slot.replace((key.clone(), generation)));
                    below = Some(session);
                    continue;
                }
            }

            shared.emit(&labels, index, HopState::Connecting);
            let reporter = Reporter {
                events: shared.events.clone(),
                route: Arc::clone(&labels),
                index,
                armed: Arc::new(AtomicBool::new(false)),
            };
            let built = self.build(hop, below.as_deref(), reporter.clone()).await;
            let (session, latency) = match built {
                Ok(built) => built,
                Err((error, failure)) => {
                    shared.emit(&labels, index, HopState::Failed(failure));
                    drop(hold);
                    return Err(SshError::Hop {
                        index,
                        hop: labels[index].clone(),
                        source: Box::new(error),
                    });
                }
            };
            let session = Arc::new(session);
            shared.emit(&labels, index, HopState::Connected { latency });
            reporter.arm();
            if session.is_closed() {
                // Ended before the reporter was armed; report it now.
                reporter.closed();
            }
            if !pooled {
                // Fresh target: keeps the use of the last jump until it ends.
                return Ok(Lease {
                    session,
                    hold: hold.slot.take(),
                    own: true,
                    shared: Arc::clone(shared),
                });
            }
            let mut closing = Vec::new();
            let generation = shared.entries().insert(
                key.clone(),
                Arc::clone(&session),
                hold.slot.clone(),
                &mut closing,
            );
            close_later(closing);
            shared.release(hold.slot.replace((key.clone(), generation)));
            below = Some(session);
        }
        drop(locked);

        match below {
            Some(session) => Ok(Lease {
                session,
                hold: hold.slot.take(),
                own: false,
                shared: Arc::clone(shared),
            }),
            // A route always has a target, so the loop ran at least once.
            None => Err(SshError::Refused("an empty route".into())),
        }
    }

    /// Opens the transport to `hop` (TCP, or a channel on `below`) and signs
    /// in, within the time limit.
    async fn build(
        &self,
        hop: &SshTarget,
        below: Option<&Session>,
        reporter: Reporter,
    ) -> Result<(Session, Duration), (SshError, HopFailure)> {
        let started = Instant::now();
        let config = Arc::clone(&self.shared.config);
        let set_up = async {
            let session = match below {
                None => {
                    let stream = Session::open_tcp(hop)
                        .await
                        .map_err(|e| (e, HopFailure::Unreachable))?;
                    Session::start(hop, stream, config, Some(reporter)).await
                }
                Some(jump) => {
                    let stream = jump.open_via(hop).await.map_err(|e| {
                        let failure = if jump.is_closed() {
                            HopFailure::Closed
                        } else {
                            HopFailure::ChannelRefused
                        };
                        (e, failure)
                    })?;
                    Session::start(hop, stream, config, Some(reporter)).await
                }
            };
            session.map_err(|e| {
                let failure = HopFailure::from(&e);
                (e, failure)
            })
        };
        match tokio::time::timeout(self.shared.connect_timeout, set_up).await {
            Ok(Ok(session)) => Ok((session, started.elapsed())),
            Ok(Err(failed)) => Err(failed),
            Err(_) => Err((SshError::Timeout(hop.label()), HopFailure::Timeout)),
        }
    }
}

/// A session from a [`SessionPool`]. Dropping it gives the connection back;
/// the pool closes what nobody uses any more.
///
/// Close a lease by dropping it, not with [`Session::disconnect`]: that ends
/// the shared connection for every other lease on it and for everything
/// behind it.
pub struct Lease {
    session: Arc<Session>,
    hold: Option<Slot>,
    /// A fresh connection only this lease uses.
    own: bool,
    shared: Arc<Shared>,
}

impl Deref for Lease {
    type Target = Session;

    fn deref(&self) -> &Session {
        &self.session
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        let mut closing = Vec::new();
        if self.own {
            closing.push(Arc::clone(&self.session));
        }
        if let Some(slot) = self.hold.take() {
            self.shared.entries().release(slot, &mut closing);
        }
        close_later(closing);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(names: &[&str]) -> Key {
        names
            .iter()
            .map(|name| HopKey {
                host: (*name).into(),
                port: 22,
                user: "u".into(),
                agent_forward: false,
            })
            .collect()
    }

    #[test]
    fn failures_follow_the_error() {
        let hop = SshError::Hop {
            index: 1,
            hop: "u@jump:22".into(),
            source: Box::new(SshError::HostKeyChanged {
                host: "jump".into(),
                key: "k".into(),
                fingerprint: "f".into(),
            }),
        };
        assert_eq!(HopFailure::from(&hop), HopFailure::HostKeyChanged);
        assert_eq!(
            HopFailure::from(&SshError::Timeout("u@h:22".into())),
            HopFailure::Timeout
        );
        assert_eq!(
            HopFailure::from(&SshError::Ssh(russh::Error::ChannelOpenFailure(
                russh::ChannelOpenFailure::ConnectFailed
            ))),
            HopFailure::ChannelRefused
        );
        assert_eq!(
            HopFailure::from(&SshError::AuthFailed("u@h".into())),
            HopFailure::AuthFailed
        );
        assert_eq!(
            HopFailure::from(&SshError::Ssh(russh::Error::Disconnect)),
            HopFailure::Closed
        );
    }

    #[test]
    fn labels_name_every_hop() {
        let hop = |host: &str| SshTarget {
            host: host.into(),
            port: 22,
            user: "u".into(),
            identity: crate::Identity::Agent,
            host_key: crate::HostKeyPolicy::Pinned(None),
            agent_forward: false,
        };
        let route = Route {
            jumps: vec![hop("bastion"), hop("jump")],
            target: hop("target"),
        };
        assert_eq!(
            route.labels(),
            vec!["u@bastion:22", "u@jump:22", "u@target:22"]
        );
        assert_eq!(Route::direct(hop("h")).labels(), vec!["u@h:22"]);
    }

    #[test]
    fn keys_are_ways_not_hosts() {
        let behind_a = key(&["a", "x"]);
        let behind_b = key(&["b", "x"]);
        assert_ne!(behind_a, behind_b);
        assert!(behind_a.starts_with(&key(&["a"])));
        assert!(!behind_b.starts_with(&key(&["a"])));
    }
}
