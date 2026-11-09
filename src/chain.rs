//! Jump host chains: a [`Route`] over any number of jumps, and a
//! [`SessionPool`] with one shared connection per jump.

use std::collections::HashMap;
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::{Duration, Instant};

use russh::client;
use tokio::sync::{OwnedMutexGuard, broadcast, watch};

use crate::{Session, SshError, SshTarget};

/// The way to a server: first the jumps in order, then the target. Each hop
/// signs in with its own user and credentials and is checked against its own
/// host key policy. A hop's `host` is resolved by the hop before it, so the
/// host key of `jump` is looked up as `jump`, not under an address.
#[derive(Clone)]
pub struct Route {
    pub jumps: Vec<SshTarget>,
    pub target: SshTarget,
    /// ProxyCommand for the first hop (the first jump, or the target of a
    /// route without jumps): its stdin and stdout carry the connection
    /// instead of TCP, as with [`Session::connect_command`]. Its set-up may
    /// take up to [`PoolConfig::proxy_connect_timeout`], for helpers that
    /// first wait for a sign-in in the browser. `Debug` hides it, it may
    /// carry an access token.
    pub proxy_command: Option<String>,
}

impl std::fmt::Debug for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Route")
            .field("jumps", &self.jumps)
            .field("target", &self.target)
            .field("proxy_command", &self.proxy_command.as_ref().map(|_| ".."))
            .finish()
    }
}

impl Route {
    /// A route without jumps, over TCP.
    pub fn direct(target: SshTarget) -> Self {
        Self {
            jumps: Vec::new(),
            target,
            proxy_command: None,
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
    /// How long a hop that asked a question during sign-in (for example a
    /// one-time code) stays open after its last user is gone, unless the
    /// answer said otherwise ([`crate::KeyboardAnswer::keep_open`]). So a
    /// quick retry, for example after confirming a host key further down,
    /// needs no second code. Hops that asked nothing close at once.
    pub code_grace: Duration,
    /// Limit for a first hop over [`Route::proxy_command`], instead of
    /// `connect_timeout`: a helper like `cloudflared` may first wait for a
    /// sign-in in the browser.
    pub proxy_connect_timeout: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            keepalive_interval: Duration::from_secs(5),
            keepalive_max: 3,
            code_grace: Duration::from_secs(60),
            proxy_connect_timeout: Duration::from_secs(120),
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
    /// The hop asked a question during sign-in, for example a one-time
    /// code, and waits for the answer of
    /// [`crate::KeyboardInteractive::ask`].
    AwaitingInput,
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
    /// The user cancelled a question of the hop during sign-in.
    Cancelled,
    /// The connection ended while setting up.
    Closed,
    /// The ProxyCommand of the first hop was refused, did not start or
    /// ended before the sign-in.
    ProxyCommand,
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
            SshError::Cancelled(_) => Self::Cancelled,
            SshError::ProxyCommand(_) => Self::ProxyCommand,
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

/// Time the set-up of a hop spent waiting for the user.
#[derive(Debug, Clone, Copy, Default)]
struct Pause {
    since: Option<Instant>,
    total: Duration,
}

impl Pause {
    /// Paused time so far, the running pause included.
    fn elapsed(&self) -> Duration {
        self.total + self.since.map_or(Duration::ZERO, |since| since.elapsed())
    }
}

/// A running pause of the set-up limit; ends on drop, also when the
/// question is cancelled.
pub(crate) struct Paused(Arc<watch::Sender<Pause>>);

impl Drop for Paused {
    fn drop(&mut self) {
        self.0.send_modify(|pause| {
            if let Some(since) = pause.since.take() {
                pause.total += since.elapsed();
            }
        });
    }
}

/// Reports what happens to one hop while it is set up and
/// [`HopState::Closed`] once for a connection that made it into the pool
/// (or out as a fresh one); a failed set-up stays silent on close.
#[derive(Clone)]
pub(crate) struct Reporter {
    events: broadcast::Sender<HopEvent>,
    route: Arc<[String]>,
    index: usize,
    armed: Arc<AtomicBool>,
    pause: Arc<watch::Sender<Pause>>,
}

impl Reporter {
    pub(crate) fn route(&self) -> Vec<String> {
        self.route.to_vec()
    }

    pub(crate) fn index(&self) -> usize {
        self.index
    }

    /// Reports [`HopState::AwaitingInput`] and pauses the set-up limit
    /// until the returned guard is dropped.
    pub(crate) fn awaiting_input(&self) -> Paused {
        self.pause.send_modify(|pause| {
            pause.since.get_or_insert_with(Instant::now);
        });
        self.events
            .send(HopEvent {
                route: self.route.to_vec(),
                index: self.index,
                state: HopState::AwaitingInput,
            })
            .ok();
        Paused(Arc::clone(&self.pause))
    }

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
/// agent forwarding never shares a connection with one without; so does the
/// ProxyCommand (unexpanded, only on the first hop), so the way over a
/// command and the way over TCP are two connections.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct HopKey {
    host: String,
    port: u16,
    user: String,
    agent_forward: bool,
    proxy: Option<String>,
}

impl HopKey {
    fn of(hop: &SshTarget, proxy: Option<&str>) -> Self {
        Self {
            host: hop.host.to_ascii_lowercase(),
            port: hop.port,
            user: hop.user.clone(),
            agent_forward: hop.agent_forward,
            proxy: proxy.map(str::to_owned),
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
    /// How long the entry stays in the pool once `users` is 0.
    keep_open: Duration,
    /// Set while the entry waits unused; only the timer with this token may
    /// close it.
    idle: Option<u64>,
}

/// An unused entry that stays open until the timer with `token` runs out.
struct Linger {
    slot: Slot,
    token: u64,
    after: Duration,
}

/// What a change of the pool leaves to do once its lock is released.
#[derive(Default)]
struct Effects {
    closing: Vec<Arc<Session>>,
    lingering: Vec<Linger>,
}

#[derive(Default)]
struct Entries {
    map: HashMap<Key, Entry>,
    next_generation: u64,
}

impl Entries {
    /// Drops one use of `slot`. An entry nobody uses any more leaves the
    /// pool, and so does its parent once it has no other user; their
    /// sessions go to `closing`, the deepest first. An entry with
    /// `keep_open` stays instead, together with the use of its parent, and
    /// goes to `lingering`.
    fn release(&mut self, slot: Slot, effects: &mut Effects) {
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
            if !entry.keep_open.is_zero() && !entry.session.is_closed() {
                let token = self.next_generation;
                self.next_generation += 1;
                entry.idle = Some(token);
                effects.lingering.push(Linger {
                    slot: (key, generation),
                    token,
                    after: entry.keep_open,
                });
                return;
            }
            if let Some(entry) = self.map.remove(&key) {
                effects.closing.push(entry.session);
                next = entry.parent;
            }
        }
    }

    /// The time of a lingering entry ran out: if it is still unused and
    /// waits for this timer, it leaves the pool and gives its parent back.
    fn expire(&mut self, linger: &Linger, effects: &mut Effects) {
        let (key, generation) = &linger.slot;
        let Some(entry) = self.map.get(key) else {
            return;
        };
        if entry.generation != *generation || entry.idle != Some(linger.token) || entry.users > 0 {
            return;
        }
        if let Some(entry) = self.map.remove(key) {
            effects.closing.push(entry.session);
            if let Some(parent) = entry.parent {
                self.release(parent, effects);
            }
        }
    }

    /// Removes every entry nobody uses, also those that became unused by
    /// it, and returns how many.
    fn close_idle(&mut self, effects: &mut Effects) -> usize {
        let mut count = 0;
        loop {
            let mut idle: Vec<Key> = self
                .map
                .iter()
                .filter(|(_, entry)| entry.users == 0)
                .map(|(key, _)| key.clone())
                .collect();
            if idle.is_empty() {
                return count;
            }
            // The deepest first, so they close from the inside out.
            idle.sort_by_key(|key| std::cmp::Reverse(key.len()));
            for key in idle {
                let Some(entry) = self.map.remove(&key) else {
                    continue;
                };
                count += 1;
                effects.closing.push(entry.session);
                if let Some((parent_key, parent_generation)) = entry.parent
                    && let Some(parent) = self.map.get_mut(&parent_key)
                    && parent.generation == parent_generation
                {
                    parent.users = parent.users.saturating_sub(1);
                }
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
        entry.idle = None;
        Some((entry.generation, Arc::clone(&entry.session)))
    }

    /// Puts `session` at `key` with one user, on top of `parent`. What was at
    /// `key` or behind it is gone: it ran over a dead connection.
    fn insert(
        &mut self,
        key: Key,
        session: Arc<Session>,
        parent: Option<Slot>,
        keep_open: Duration,
        effects: &mut Effects,
    ) -> u64 {
        let stale: Vec<Key> = self
            .map
            .keys()
            .filter(|k| k.starts_with(&key))
            .cloned()
            .collect();
        for stale_key in stale {
            if let Some(entry) = self.map.remove(&stale_key) {
                effects.closing.push(entry.session);
                // Entries behind it pointed into the removed part; only the
                // entry at `key` held a use of something still in the pool.
                if stale_key.len() == key.len()
                    && let Some(old_parent) = entry.parent
                {
                    self.release(old_parent, effects);
                }
            }
        }
        if let Some((parent_key, parent_generation)) = &parent
            && let Some(entry) = self.map.get_mut(parent_key)
            && entry.generation == *parent_generation
        {
            entry.users += 1;
            entry.idle = None;
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
                keep_open,
                idle: None,
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
    proxy_connect_timeout: Duration,
    code_grace: Duration,
}

impl Shared {
    fn entries(&self) -> MutexGuard<'_, Entries> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn release(self: &Arc<Self>, slot: Option<Slot>) {
        let Some(slot) = slot else {
            return;
        };
        let mut effects = Effects::default();
        self.entries().release(slot, &mut effects);
        self.apply(effects);
    }

    /// Closes what left the pool and starts the timers of lingering
    /// entries. Without a runtime there is no timer, so they close at once.
    fn apply(self: &Arc<Self>, effects: Effects) {
        close_later(effects.closing);
        for linger in effects.lingering {
            match tokio::runtime::Handle::try_current() {
                Ok(runtime) => {
                    let shared = Arc::downgrade(self);
                    runtime.spawn(expire_later(shared, linger));
                }
                Err(_) => self.expire(&linger),
            }
        }
    }

    fn expire(self: &Arc<Self>, linger: &Linger) {
        let mut effects = Effects::default();
        self.entries().expire(linger, &mut effects);
        self.apply(effects);
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

/// Timer of a lingering entry. Holds the pool only weakly: a dropped pool
/// closes everything anyway.
async fn expire_later(shared: Weak<Shared>, linger: Linger) {
    tokio::time::sleep(linger.after).await;
    if let Some(shared) = shared.upgrade() {
        shared.expire(&linger);
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
/// uses it; once the last one is gone, it is closed. A hop that asked a
/// question during sign-in (a one-time code) stays open a while longer, for
/// [`crate::KeyboardAnswer::keep_open`] or else [`PoolConfig::code_grace`],
/// so a new session in that time needs no new code;
/// [`SessionPool::close_idle`] ends that wait at once. Dead connections are
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
                proxy_connect_timeout: config.proxy_connect_timeout,
                code_grace: config.code_grace,
            }),
        }
    }

    /// Events of every hop of every route of this pool. A receiver that falls
    /// more than 64 events behind loses the oldest.
    pub fn subscribe(&self) -> broadcast::Receiver<HopEvent> {
        self.shared.events.subscribe()
    }

    /// Closes every connection nobody uses at once, also those kept open
    /// after a one-time code, for example when the user locks the app.
    /// Returns how many were closed.
    pub fn close_idle(&self) -> usize {
        let mut effects = Effects::default();
        let count = self.shared.entries().close_idle(&mut effects);
        self.shared.apply(effects);
        count
    }

    /// A session on the target of `route`, shared with every other lease on
    /// the same route. Jumps never forward the agent, whatever their
    /// `agent_forward` says.
    ///
    /// A failing hop ends in [`SshError::Hop`] with its index, and nothing
    /// set up for this call stays in the pool, except hops that asked a
    /// one-time code: they stay as after the last lease, so a retry needs no
    /// second code.
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
            let proxy = route.proxy_command.as_deref().filter(|_| index == 0);
            key.push(HopKey::of(hop, proxy));
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
                pause: Arc::new(watch::channel(Pause::default()).0),
            };
            let built = self
                .build(hop, below.as_deref(), proxy, reporter.clone())
                .await;
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
            let mut effects = Effects::default();
            let keep_open = session.linger(shared.code_grace);
            let generation = shared.entries().insert(
                key.clone(),
                Arc::clone(&session),
                hold.slot.clone(),
                keep_open,
                &mut effects,
            );
            shared.apply(effects);
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

    /// Opens the transport to `hop` (TCP, the command `proxy` for the first
    /// hop, or a channel on `below`) and signs in, within the time limit.
    /// Time spent waiting for the user does not count, neither towards the
    /// limit nor towards the latency.
    async fn build(
        &self,
        hop: &SshTarget,
        below: Option<&Session>,
        proxy: Option<&str>,
        reporter: Reporter,
    ) -> Result<(Session, Duration), (SshError, HopFailure)> {
        let started = Instant::now();
        let config = Arc::clone(&self.shared.config);
        // Held here, so `changed` below never fails while this runs.
        let pause = Arc::clone(&reporter.pause);
        let mut pauses = pause.subscribe();
        let set_up = async {
            let session = match below {
                None if let Some(command) = proxy => {
                    Session::start_command(command, hop, config, Some(reporter)).await
                }
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
        tokio::pin!(set_up);
        let limit = match (below, proxy) {
            (None, Some(_)) => self.shared.proxy_connect_timeout,
            _ => self.shared.connect_timeout,
        };
        let result = loop {
            let current = *pauses.borrow_and_update();
            if current.since.is_some() {
                // Waiting for the user: no limit until the answer.
                tokio::select! {
                    result = &mut set_up => break Some(result),
                    _ = pauses.changed() => continue,
                }
            }
            let deadline = tokio::time::Instant::from_std(started + limit + current.total);
            tokio::select! {
                result = &mut set_up => break Some(result),
                () = tokio::time::sleep_until(deadline) => break None,
                _ = pauses.changed() => {}
            }
        };
        match result {
            Some(Ok(session)) => {
                let waited = pauses.borrow().elapsed();
                Ok((session, started.elapsed().saturating_sub(waited)))
            }
            Some(Err(failed)) => Err(failed),
            None => Err((SshError::Timeout(hop.label()), HopFailure::Timeout)),
        }
    }
}

/// A session from a [`SessionPool`]. Dropping it gives the connection back;
/// the pool closes what nobody uses any more, hops that asked a one-time
/// code after their time to stay open.
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
        let mut effects = Effects::default();
        if self.own {
            effects.closing.push(Arc::clone(&self.session));
        }
        if let Some(slot) = self.hold.take() {
            self.shared.entries().release(slot, &mut effects);
        }
        self.shared.apply(effects);
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
                proxy: None,
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
        assert_eq!(
            HopFailure::from(&SshError::ProxyCommand("ended with exit status: 1".into())),
            HopFailure::ProxyCommand
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
            keyboard_interactive: None,
        };
        let route = Route {
            jumps: vec![hop("bastion"), hop("jump")],
            target: hop("target"),
            proxy_command: Some("cloudflared access ssh --token geheim".into()),
        };
        assert!(!format!("{route:?}").contains("geheim"));
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
        let mut over_command = key(&["a", "x"]);
        over_command[0].proxy = Some("nc %h %p".into());
        assert_ne!(over_command, behind_a);
        assert!(!over_command.starts_with(&key(&["a"])));
    }
}
