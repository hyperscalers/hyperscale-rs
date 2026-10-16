//! What kind of path each connection sends on, and what a relayed path may
//! carry.
//!
//! A connection between two hosts behind NAT opens through a relay and moves
//! to a direct path once the hole punch succeeds; if the direct path later
//! dies, the connection falls back to the relay. The relayed path rides the
//! relay's TCP links, shares the relay with every other pair homed on it,
//! and is a degraded fallback, not a second route. [`PathPolicy`] follows
//! each connection's selected path and applies one rule per message class
//! to what is sent while it is relayed:
//!
//! - `Consensus` always goes. Its frames are small, and dropping one turns
//!   a slow pair into a view change. The bytes are counted.
//! - `BlockCompletion` and `CrossShardProgress` go under a byte budget per
//!   peer per minute.
//! - `Recovery` and `Bulk` never go. The sender drops the frame or picks
//!   another peer.
//!
//! The library reports the selected path through its path events; nothing
//! in its stable API closes one path or bans the relay for a connection, so
//! the rule is enforced here, by every sender, on both sides of a request.
//!
//! A connection that has fallen back returns to a direct path only when the
//! library next tries a hole punch, which it does on its own once a minute.
//! It also tries one whenever a new client connection to the peer opens,
//! and a path that punch finds serves every connection to the peer.
//! [`Redialer`] uses that: while a connection this host dialed is relayed,
//! it opens a short lived connection to the peer on a [`RedialSchedule`],
//! so a pair is back on a direct path seconds after an outage ends. When
//! many connections fall back together, as when the host's own network
//! stops passing UDP, every re-dial it makes or admits draws on one
//! [`RedialBudget`], so the relay carries a bounded amount of re-dialing
//! however many peers fell back.

use std::cmp::Reverse;
use std::collections::BTreeSet;
use std::future::pending;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use futures::StreamExt;
use hyperscale_types::MessageClass;
use iroh::endpoint::{Connection, Path, PathEvent, TransportAddrInfo, VarInt};
use iroh::{Endpoint, EndpointAddr, EndpointId, TransportAddr};
use parking_lot::Mutex;
use tokio::runtime::Handle;
use tokio::sync::Notify;
use tokio::time::{Instant as TokioInstant, MissedTickBehavior, interval, sleep_until, timeout};
use tracing::{debug, info, warn};

/// Bytes of the budgeted classes one peer is sent over a relayed path in
/// one [`BUDGET_WINDOW`].
pub const RELAYED_BUDGET_BYTES: u64 = 1024 * 1024;

/// Window over which the relayed budget is counted.
const BUDGET_WINDOW: Duration = Duration::from_mins(1);

/// Interval at which a connection's round trip time is read.
const RTT_INTERVAL: Duration = Duration::from_secs(5);

/// How long a re-dial has to complete its handshake through the relay.
const REDIAL_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Close code of a re-dial connection the dialer no longer needs.
const CLOSE_REDIAL_DONE: VarInt = VarInt::from_u32(0);

/// The two kinds of path a connection to a validator's host can send on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PathKind {
    /// Datagrams travel between the two hosts' own sockets.
    Direct,
    /// Datagrams travel through a relay server, over its TCP link to each
    /// host.
    Relayed,
}

impl PathKind {
    /// The kind of a path to `remote`.
    #[must_use]
    pub fn of(remote: &TransportAddr) -> Self {
        if remote.is_relay() {
            Self::Relayed
        } else {
            Self::Direct
        }
    }
}

/// The kind of the path `connection` currently sends on, or `None` while it
/// has selected none.
#[must_use]
pub fn selected(connection: &Connection) -> Option<PathKind> {
    connection
        .paths()
        .iter()
        .find(Path::is_selected)
        .map(|path| PathKind::of(path.remote_addr()))
}

impl PathKind {
    const fn to_code(kind: Option<Self>) -> u8 {
        match kind {
            None => 0,
            Some(Self::Direct) => 1,
            Some(Self::Relayed) => 2,
        }
    }

    const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Direct),
            2 => Some(Self::Relayed),
            _ => None,
        }
    }
}

/// What a relayed path does with a message class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayedRule {
    /// Carried, and counted.
    Always,
    /// Carried while the peer's budget for the window has room.
    Budgeted,
    /// Not carried.
    Never,
}

const fn relayed_rule(class: MessageClass) -> RelayedRule {
    match class {
        MessageClass::Consensus => RelayedRule::Always,
        MessageClass::BlockCompletion | MessageClass::CrossShardProgress => RelayedRule::Budgeted,
        MessageClass::Recovery | MessageClass::Bulk => RelayedRule::Never,
    }
}

/// Budgeted bytes sent to one peer over a relayed path in the current
/// window.
struct Budget {
    window_start: Instant,
    spent: u64,
}

impl Budget {
    /// Charge `bytes` at `now` if the window has room for them.
    fn charge(&mut self, bytes: u64, now: Instant) -> bool {
        if now.saturating_duration_since(self.window_start) >= BUDGET_WINDOW {
            self.window_start = now;
            self.spent = 0;
        }
        if self.spent.saturating_add(bytes) > RELAYED_BUDGET_BYTES {
            return false;
        }
        self.spent += bytes;
        true
    }
}

/// Path state and relayed traffic of one peer's connection.
struct PeerPath {
    /// Stable id of the connection this state follows.
    connection: usize,
    kind: AtomicU8,
    rtt_micros: AtomicU64,
    fallbacks: AtomicU64,
    relayed_consensus_bytes: AtomicU64,
    relayed_budgeted_bytes: AtomicU64,
    refused: AtomicU64,
    /// When `Consensus` traffic last went either way, in milliseconds
    /// since the policy's epoch; zero when none has.
    last_consensus_ms: AtomicU64,
    budget: Mutex<Budget>,
}

impl PeerPath {
    fn kind(&self) -> Option<PathKind> {
        PathKind::from_code(self.kind.load(Ordering::Relaxed))
    }

    /// Record the selected path's kind, returning the kind it replaces.
    fn replace_kind(&self, kind: Option<PathKind>) -> Option<PathKind> {
        PathKind::from_code(self.kind.swap(PathKind::to_code(kind), Ordering::Relaxed))
    }
}

/// A peer's path as the policy sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathStatus {
    /// Kind of the selected path, or `None` while none is selected.
    pub kind: Option<PathKind>,
    /// Round trip time of the selected path when last read.
    pub rtt: Option<Duration>,
    /// Times the connection fell back from a direct path to the relay.
    pub fallbacks: u64,
    /// `Consensus` bytes sent over the relayed path.
    pub relayed_consensus_bytes: u64,
    /// Budgeted bytes sent over the relayed path.
    pub relayed_budgeted_bytes: u64,
    /// Sends refused because the path was relayed.
    pub refused: u64,
}

/// How a host reaches the other members of the committees it sits in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Readiness {
    /// Members reached on a direct path.
    pub direct: usize,
    /// Members reached only through a relay.
    pub relayed: usize,
    /// Members with no bound connection.
    pub unbound: usize,
}

impl Readiness {
    /// Whether fewer than two thirds of the members are on a direct path.
    /// A degraded host keeps voting; its operator should forward a port.
    #[must_use]
    pub const fn degraded(&self) -> bool {
        self.direct * 3 < (self.direct + self.relayed + self.unbound) * 2
    }
}

/// Follows every bound connection's selected path and decides what is sent
/// on it.
pub struct PathPolicy {
    /// Origin of the per-peer consensus times.
    epoch: Instant,
    peers: DashMap<EndpointId, Arc<PeerPath>>,
}

impl Default for PathPolicy {
    fn default() -> Self {
        Self {
            epoch: Instant::now(),
            peers: DashMap::new(),
        }
    }
}

impl PathPolicy {
    /// Follow `connection`'s selected path until it closes.
    pub(crate) fn track(self: &Arc<Self>, connection: &Connection, runtime: &Handle) {
        let peer = connection.remote_id();
        // Subscribe before reading the paths: events from before a
        // subscription are not replayed, and a change between the two
        // would otherwise be missed.
        let mut events = connection.path_events();
        let state = Arc::new(PeerPath {
            connection: connection.stable_id(),
            kind: AtomicU8::new(PathKind::to_code(selected(connection))),
            rtt_micros: AtomicU64::new(0),
            fallbacks: AtomicU64::new(0),
            relayed_consensus_bytes: AtomicU64::new(0),
            relayed_budgeted_bytes: AtomicU64::new(0),
            refused: AtomicU64::new(0),
            last_consensus_ms: AtomicU64::new(0),
            budget: Mutex::new(Budget {
                window_start: Instant::now(),
                spent: 0,
            }),
        });
        self.peers.insert(peer, Arc::clone(&state));

        let policy = Arc::clone(self);
        let connection = connection.clone();
        runtime.spawn(async move {
            let mut rtt_tick = interval(RTT_INTERVAL);
            rtt_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    event = events.next() => {
                        let kind = match event {
                            Some(PathEvent::Selected { remote_addr, .. }) => {
                                Some(PathKind::of(&remote_addr))
                            }
                            // Events were dropped; the path list is the truth.
                            Some(PathEvent::Lagged { .. }) => selected(&connection),
                            Some(_) => continue,
                            None => break,
                        };
                        note_selection(peer, &state, kind);
                    }
                    _ = rtt_tick.tick() => {
                        let rtt = connection
                            .paths()
                            .iter()
                            .find(Path::is_selected)
                            .map(|path| path.rtt());
                        if let Some(rtt) = rtt {
                            let micros = u64::try_from(rtt.as_micros()).unwrap_or(u64::MAX);
                            state.rtt_micros.store(micros, Ordering::Relaxed);
                        }
                    }
                }
            }
            policy
                .peers
                .remove_if(&peer, |_, held| held.connection == state.connection);
        });
    }

    /// Kind of the path `peer`'s connection sends on, or `None` when the
    /// peer is not bound or its connection has selected no path.
    #[must_use]
    pub fn kind(&self, peer: EndpointId) -> Option<PathKind> {
        self.peers.get(&peer).and_then(|state| state.kind())
    }

    /// Whether a message of `class` is sent to `peer` at all on its current
    /// path, leaving the budget aside.
    #[must_use]
    pub(crate) fn carries(&self, peer: EndpointId, class: MessageClass) -> bool {
        self.kind(peer) != Some(PathKind::Relayed) || relayed_rule(class) != RelayedRule::Never
    }

    /// Decide whether `bytes` of `class` go to `peer` now, charging the
    /// budget and the counters when the path is relayed.
    #[must_use]
    pub(crate) fn admit(&self, peer: EndpointId, class: MessageClass, bytes: usize) -> bool {
        let Some(state) = self.peers.get(&peer).map(|state| Arc::clone(&state)) else {
            return true;
        };
        if class == MessageClass::Consensus {
            self.stamp_consensus(&state);
        }
        if state.kind() != Some(PathKind::Relayed) {
            return true;
        }
        let bytes = bytes as u64;
        let admitted = match relayed_rule(class) {
            RelayedRule::Always => {
                state
                    .relayed_consensus_bytes
                    .fetch_add(bytes, Ordering::Relaxed);
                true
            }
            RelayedRule::Budgeted => {
                let fits = state.budget.lock().charge(bytes, Instant::now());
                if fits {
                    state
                        .relayed_budgeted_bytes
                        .fetch_add(bytes, Ordering::Relaxed);
                }
                fits
            }
            RelayedRule::Never => false,
        };
        if !admitted {
            state.refused.fetch_add(1, Ordering::Relaxed);
        }
        admitted
    }

    /// Note that `Consensus` traffic arrived from `peer`.
    pub(crate) fn note_consensus(&self, peer: EndpointId) {
        if let Some(state) = self.peers.get(&peer) {
            self.stamp_consensus(&state);
        }
    }

    fn stamp_consensus(&self, state: &PeerPath) {
        // One millisecond past the epoch at least, so that zero stays "never".
        let since = u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX);
        state
            .last_consensus_ms
            .store(since.max(1), Ordering::Relaxed);
    }

    /// Where a re-dial of `peer` stands among others waiting for the
    /// host's re-dial budget.
    fn redial_rank(&self, peer: EndpointId) -> RedialRank {
        RedialRank(Reverse(self.peers.get(&peer).map_or(0, |state| {
            state.last_consensus_ms.load(Ordering::Relaxed)
        })))
    }

    /// The path of `peer`'s connection and what it has carried while
    /// relayed, or `None` when the peer is not bound.
    #[must_use]
    pub fn status(&self, peer: EndpointId) -> Option<PathStatus> {
        let state = self.peers.get(&peer)?;
        let rtt_micros = state.rtt_micros.load(Ordering::Relaxed);
        Some(PathStatus {
            kind: state.kind(),
            rtt: (rtt_micros > 0).then(|| Duration::from_micros(rtt_micros)),
            fallbacks: state.fallbacks.load(Ordering::Relaxed),
            relayed_consensus_bytes: state.relayed_consensus_bytes.load(Ordering::Relaxed),
            relayed_budgeted_bytes: state.relayed_budgeted_bytes.load(Ordering::Relaxed),
            refused: state.refused.load(Ordering::Relaxed),
        })
    }
}

/// Record a newly selected path, logging a change of kind.
fn note_selection(peer: EndpointId, state: &PeerPath, kind: Option<PathKind>) {
    let previous = state.replace_kind(kind);
    if previous == kind {
        return;
    }
    match (previous, kind) {
        (Some(PathKind::Direct), Some(PathKind::Relayed)) => {
            state.fallbacks.fetch_add(1, Ordering::Relaxed);
            warn!(
                peer = %peer.fmt_short(),
                "Connection fell back to the relay; only consensus traffic is sent freely"
            );
        }
        (_, Some(PathKind::Direct)) => {
            info!(peer = %peer.fmt_short(), "Connection is on a direct path");
        }
        _ => {}
    }
}

/// How much re-dialing one host does across all its peers: a bucket of
/// `burst` re-dials that refills by one every `refill`. Re-dials this host
/// makes and re-dials it admits from peers both draw on it.
///
/// A peer is re-dialed at most once every few seconds, so a single peer's
/// recovery never waits on the bucket. When many connections fall back at
/// once the bucket sets the pace, and the relay carries at most `burst`
/// re-dials and then one every `refill`, however many peers fell back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedialBudget {
    /// Re-dials available at once.
    pub burst: u32,
    /// Time in which one more re-dial becomes available.
    pub refill: Duration,
}

/// Which of several re-dials waiting for the budget goes first: the one to
/// the peer this host exchanged `Consensus` traffic with most recently. A
/// relayed path carries that traffic over the relay's TCP links, so those
/// are the peers a direct path matters most for now; the committees a
/// host's votes and headers go to are exactly the ones it keeps exchanging
/// them with. Peers it never did go last, in the order they asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct RedialRank(Reverse<u64>);

/// One re-dial waiting for the budget: its rank, then its arrival.
type RedialClaim = (RedialRank, u64);

/// The budget's bucket and the re-dials waiting on it.
struct Bucket {
    available: u32,
    /// When the last token was added, or the bucket last seen full.
    refilled_at: TokioInstant,
    waiting: BTreeSet<RedialClaim>,
    next_ticket: u64,
}

impl Bucket {
    fn refill(&mut self, budget: RedialBudget, now: TokioInstant) {
        if self.available >= budget.burst {
            self.refilled_at = now;
            return;
        }
        let earned = now.saturating_duration_since(self.refilled_at).as_nanos()
            / budget.refill.as_nanos().max(1);
        if earned == 0 {
            return;
        }
        let earned = u32::try_from(earned).unwrap_or(u32::MAX);
        self.available = self.available.saturating_add(earned).min(budget.burst);
        self.refilled_at = if self.available >= budget.burst {
            now
        } else {
            self.refilled_at + budget.refill * earned
        };
    }
}

/// The host's re-dial budget.
struct RedialTokens {
    budget: RedialBudget,
    bucket: Mutex<Bucket>,
    /// Woken whenever a token is taken or a waiting re-dial gives up, so
    /// the next in line looks again.
    changed: Notify,
}

impl RedialTokens {
    fn new(budget: RedialBudget) -> Self {
        Self {
            budget,
            bucket: Mutex::new(Bucket {
                available: budget.burst,
                refilled_at: TokioInstant::now(),
                waiting: BTreeSet::new(),
                next_ticket: 0,
            }),
            changed: Notify::new(),
        }
    }

    /// Wait for a token, behind every waiting re-dial of better rank.
    async fn take(&self, rank: RedialRank) {
        let claim = {
            let mut bucket = self.bucket.lock();
            let claim = (rank, bucket.next_ticket);
            bucket.next_ticket += 1;
            bucket.waiting.insert(claim);
            claim
        };
        let _queued = Queued {
            tokens: self,
            claim,
        };
        loop {
            let mut changed = pin!(self.changed.notified());
            changed.as_mut().enable();
            let next_token = {
                let mut bucket = self.bucket.lock();
                let now = TokioInstant::now();
                bucket.refill(self.budget, now);
                if bucket.available > 0 && bucket.waiting.first() == Some(&claim) {
                    bucket.available -= 1;
                    bucket.waiting.remove(&claim);
                    drop(bucket);
                    self.changed.notify_waiters();
                    return;
                }
                bucket.refilled_at + self.budget.refill
            };
            tokio::select! {
                () = sleep_until(next_token) => {}
                () = changed => {}
            }
        }
    }

    /// Take a token now if one is free and no re-dial of at least `rank`
    /// is waiting for it.
    fn try_take(&self, rank: RedialRank) -> bool {
        let mut bucket = self.bucket.lock();
        bucket.refill(self.budget, TokioInstant::now());
        let behind = bucket
            .waiting
            .first()
            .is_some_and(|(ahead, _)| *ahead <= rank);
        if bucket.available == 0 || behind {
            return false;
        }
        bucket.available -= 1;
        true
    }

    /// Return a token a re-dial took and did not use.
    fn give_back(&self) {
        let mut bucket = self.bucket.lock();
        bucket.available = (bucket.available + 1).min(self.budget.burst);
        drop(bucket);
        self.changed.notify_waiters();
    }
}

/// A re-dial's place in line, given up when its wait ends either way.
struct Queued<'a> {
    tokens: &'a RedialTokens,
    claim: RedialClaim,
}

impl Drop for Queued<'_> {
    fn drop(&mut self) {
        if self.tokens.bucket.lock().waiting.remove(&self.claim) {
            self.tokens.changed.notify_waiters();
        }
    }
}

/// When a host re-dials a peer whose connection is relayed.
///
/// The first re-dial comes `interval` after the connection is seen relayed,
/// each later one half as long again after the last, up to
/// `max_interval`, and there are at most `attempts` of them before the
/// connection is next direct. After that the library's own check, once a
/// minute, is all that brings the pair back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedialSchedule {
    /// Wait before the first re-dial.
    pub interval: Duration,
    /// Longest wait between two re-dials.
    pub max_interval: Duration,
    /// Re-dials made while a connection stays relayed. Zero turns
    /// re-dialing off.
    pub attempts: u32,
}

impl RedialSchedule {
    /// Wait before re-dial number `attempt`, counting from zero.
    #[must_use]
    pub fn delay(&self, attempt: u32) -> Duration {
        let mut delay = self.interval.min(self.max_interval);
        for _ in 0..attempt {
            delay = (delay * 3 / 2).min(self.max_interval);
        }
        delay
    }
}

/// Re-dials peers whose connection has fallen back to the relay, so that
/// the library tries a hole punch at once instead of at its next minute
/// check.
///
/// Only the side that dialed a connection re-dials over it: that side
/// already holds a client connection, on which the library runs the punch.
/// A peer is re-dialed only while the endpoint knows a direct address for
/// it; a peer reachable only through the relay never gets a direct path
/// from a punch. Each peer holds at most one re-dial connection, closed as
/// soon as the next replaces it or the connection is direct again. Every
/// re-dial made, and every one admitted from a peer, takes a turn from the
/// host's [`RedialBudget`]. Nothing here selects a path: the library still
/// picks which one carries the connection.
pub struct Redialer {
    endpoint: Endpoint,
    alpn: Vec<u8>,
    schedule: RedialSchedule,
    tokens: RedialTokens,
    paths: Arc<PathPolicy>,
    redials: AtomicU64,
    refused: AtomicU64,
}

impl Redialer {
    /// A redialer that opens its connections on `endpoint` under protocol
    /// `alpn`, which the peer accepts and holds without serving anything.
    /// `paths` says which peers this host exchanges consensus traffic
    /// with, and so whose re-dials go first when the budget is short.
    #[must_use]
    pub fn new(
        endpoint: Endpoint,
        alpn: &[u8],
        schedule: RedialSchedule,
        budget: RedialBudget,
        paths: Arc<PathPolicy>,
    ) -> Arc<Self> {
        Arc::new(Self {
            endpoint,
            alpn: alpn.to_vec(),
            schedule,
            tokens: RedialTokens::new(budget),
            paths,
            redials: AtomicU64::new(0),
            refused: AtomicU64::new(0),
        })
    }

    /// Re-dials made so far, completed or not.
    #[must_use]
    pub fn redials(&self) -> u64 {
        self.redials.load(Ordering::Relaxed)
    }

    /// Re-dials from peers refused because the budget had no turn for them.
    #[must_use]
    pub fn refused(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }

    /// Whether a re-dial arriving from `peer` may complete its handshake,
    /// taking a turn from the budget if so. `None` is a peer whose identity
    /// is not known before the handshake; it ranks last.
    pub(crate) fn admit(&self, peer: Option<EndpointId>) -> bool {
        let rank = peer.map_or(RedialRank(Reverse(0)), |peer| self.paths.redial_rank(peer));
        let admitted = self.tokens.try_take(rank);
        if !admitted {
            self.refused.fetch_add(1, Ordering::Relaxed);
        }
        admitted
    }

    /// Re-dial `connection`'s peer on the schedule whenever the connection
    /// is relayed, until it closes. Does nothing for a connection the peer
    /// dialed.
    pub fn follow(self: &Arc<Self>, connection: &Connection, runtime: &Handle) {
        if !connection.side().is_client() || self.schedule.attempts == 0 {
            return;
        }
        // Subscribe before reading the path, as `PathPolicy::track` does.
        let mut events = connection.path_events();
        let redialer = Arc::clone(self);
        let connection = connection.clone();
        runtime.spawn(async move {
            let mut kind = selected(&connection);
            let mut made = 0u32;
            let mut spare: Option<Connection> = None;
            let mut next = redialer.due(kind, made, None);
            loop {
                let wait = async {
                    match next {
                        Some(at) => sleep_until(TokioInstant::from_std(at)).await,
                        None => pending().await,
                    }
                };
                tokio::select! {
                    event = events.next() => {
                        kind = match event {
                            Some(PathEvent::Selected { remote_addr, .. }) => {
                                Some(PathKind::of(&remote_addr))
                            }
                            Some(PathEvent::Lagged { .. }) => selected(&connection),
                            Some(_) => continue,
                            None => break,
                        };
                        if kind == Some(PathKind::Direct) {
                            made = 0;
                            close_spare(&mut spare);
                        }
                        next = redialer.due(kind, made, next);
                    }
                    () = wait => {
                        if made >= redialer.schedule.attempts {
                            // The last re-dial has had its interval.
                            close_spare(&mut spare);
                            next = None;
                            continue;
                        }
                        made += 1;
                        if let Some(fresh) = redialer.redial(&connection).await {
                            close_spare(&mut spare);
                            spare = Some(fresh);
                        }
                        kind = selected(&connection);
                        next = (kind == Some(PathKind::Relayed))
                            .then(|| Instant::now() + redialer.schedule.delay(made));
                    }
                }
            }
            close_spare(&mut spare);
        });
    }

    /// When the next re-dial is due, given the selected path's `kind`, the
    /// re-dials `made` since the connection was last direct, and the
    /// deadline already set, which a relayed connection keeps.
    fn due(&self, kind: Option<PathKind>, made: u32, current: Option<Instant>) -> Option<Instant> {
        match kind {
            Some(PathKind::Relayed) if made < self.schedule.attempts => {
                current.or_else(|| Some(Instant::now() + self.schedule.delay(made)))
            }
            _ => None,
        }
    }

    /// Open a connection to `connection`'s peer at every address the
    /// endpoint knows for it, unless it knows no direct one, once the
    /// budget gives this re-dial its turn. Returns the connection once its
    /// handshake completes; the library has then tried a hole punch.
    async fn redial(&self, connection: &Connection) -> Option<Connection> {
        let peer = connection.remote_id();
        let info = self.endpoint.remote_info(peer).await?;
        let addrs: Vec<TransportAddr> = info
            .into_addrs()
            .map(TransportAddrInfo::into_addr)
            .collect();
        if !addrs.iter().any(TransportAddr::is_ip) {
            debug!(peer = %peer.fmt_short(), "Not re-dialing: no direct address is known");
            return None;
        }
        tokio::select! {
            () = self.tokens.take(self.paths.redial_rank(peer)) => {}
            _ = connection.closed() => return None,
        }
        // The wait for a turn can be long; the library may have found a
        // direct path meanwhile.
        if selected(connection) != Some(PathKind::Relayed) {
            self.tokens.give_back();
            return None;
        }
        self.redials.fetch_add(1, Ordering::Relaxed);
        let target = EndpointAddr::from_parts(peer, addrs);
        match timeout(
            REDIAL_CONNECT_TIMEOUT,
            self.endpoint.connect(target, &self.alpn),
        )
        .await
        {
            Ok(Ok(connection)) => Some(connection),
            Ok(Err(error)) => {
                debug!(peer = %peer.fmt_short(), %error, "Re-dial failed");
                None
            }
            Err(_) => {
                debug!(peer = %peer.fmt_short(), "Re-dial timed out");
                None
            }
        }
    }
}

fn close_spare(spare: &mut Option<Connection>) {
    if let Some(connection) = spare.take() {
        connection.close(CLOSE_REDIAL_DONE, b"redial done");
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::thread;

    use iroh::SecretKey;
    use tokio::spawn;
    use tokio::task::yield_now;
    use tokio::time::advance;

    use super::*;

    fn peer_path(kind: Option<PathKind>) -> Arc<PeerPath> {
        Arc::new(PeerPath {
            connection: 1,
            kind: AtomicU8::new(PathKind::to_code(kind)),
            rtt_micros: AtomicU64::new(0),
            fallbacks: AtomicU64::new(0),
            relayed_consensus_bytes: AtomicU64::new(0),
            relayed_budgeted_bytes: AtomicU64::new(0),
            refused: AtomicU64::new(0),
            last_consensus_ms: AtomicU64::new(0),
            budget: Mutex::new(Budget {
                window_start: Instant::now(),
                spent: 0,
            }),
        })
    }

    fn policy_with(kind: Option<PathKind>) -> (PathPolicy, EndpointId) {
        let policy = PathPolicy::default();
        let peer = SecretKey::generate().public();
        policy.peers.insert(peer, peer_path(kind));
        (policy, peer)
    }

    #[test]
    fn a_direct_path_carries_every_class_uncounted() {
        let (policy, peer) = policy_with(Some(PathKind::Direct));
        for class in MessageClass::ALL {
            assert!(policy.carries(peer, class));
            assert!(policy.admit(peer, class, 10_000_000));
        }
        let status = policy.status(peer).unwrap();
        assert_eq!(status.relayed_consensus_bytes, 0);
        assert_eq!(status.relayed_budgeted_bytes, 0);
        assert_eq!(status.refused, 0);
    }

    #[test]
    fn a_peer_the_policy_does_not_follow_is_not_held_back() {
        let policy = PathPolicy::default();
        let stranger = SecretKey::generate().public();
        assert!(policy.carries(stranger, MessageClass::Bulk));
        assert!(policy.admit(stranger, MessageClass::Bulk, 1));
        assert_eq!(policy.status(stranger), None);
    }

    #[test]
    fn a_relayed_path_never_carries_recovery_or_bulk() {
        let (policy, peer) = policy_with(Some(PathKind::Relayed));
        for class in [MessageClass::Recovery, MessageClass::Bulk] {
            assert!(!policy.carries(peer, class));
            assert!(!policy.admit(peer, class, 1));
        }
        assert_eq!(policy.status(peer).unwrap().refused, 2);
    }

    #[test]
    fn a_relayed_path_always_carries_consensus_and_counts_it() {
        let (policy, peer) = policy_with(Some(PathKind::Relayed));
        for _ in 0..4 {
            assert!(policy.admit(peer, MessageClass::Consensus, 1_000_000));
        }
        let status = policy.status(peer).unwrap();
        assert_eq!(status.relayed_consensus_bytes, 4_000_000);
        assert_eq!(status.refused, 0);
    }

    #[test]
    fn a_relayed_path_carries_the_budgeted_classes_up_to_the_budget() {
        let (policy, peer) = policy_with(Some(PathKind::Relayed));
        let half = usize::try_from(RELAYED_BUDGET_BYTES / 2).unwrap();
        assert!(policy.carries(peer, MessageClass::BlockCompletion));
        assert!(policy.admit(peer, MessageClass::BlockCompletion, half));
        assert!(policy.admit(peer, MessageClass::CrossShardProgress, half));
        assert!(
            !policy.admit(peer, MessageClass::CrossShardProgress, 1),
            "the two classes share one budget"
        );
        let status = policy.status(peer).unwrap();
        assert_eq!(status.relayed_budgeted_bytes, RELAYED_BUDGET_BYTES);
        assert_eq!(status.refused, 1);
        // Consensus is not held to the budget.
        assert!(policy.admit(peer, MessageClass::Consensus, half));
    }

    #[test]
    fn the_budget_refills_when_its_window_turns() {
        let start = Instant::now();
        let mut budget = Budget {
            window_start: start,
            spent: 0,
        };
        assert!(budget.charge(RELAYED_BUDGET_BYTES, start));
        assert!(!budget.charge(1, start + BUDGET_WINDOW / 2));
        assert!(budget.charge(1, start + BUDGET_WINDOW));
        assert_eq!(budget.spent, 1);
    }

    #[test]
    fn a_fall_back_is_counted_and_a_first_selection_is_not() {
        let peer = SecretKey::generate().public();
        let state = peer_path(None);

        note_selection(peer, &state, Some(PathKind::Relayed));
        assert_eq!(state.fallbacks.load(Ordering::Relaxed), 0, "began relayed");
        note_selection(peer, &state, Some(PathKind::Direct));
        note_selection(peer, &state, Some(PathKind::Relayed));
        note_selection(peer, &state, Some(PathKind::Relayed));
        assert_eq!(state.fallbacks.load(Ordering::Relaxed), 1);
        assert_eq!(state.kind(), Some(PathKind::Relayed));
    }

    #[test]
    fn re_dials_space_out_by_half_again_up_to_the_cap() {
        let schedule = RedialSchedule {
            interval: Duration::from_secs(4),
            max_interval: Duration::from_secs(10),
            attempts: 6,
        };
        let delays: Vec<u64> = (0..5).map(|n| schedule.delay(n).as_secs()).collect();
        assert_eq!(delays, [4, 6, 9, 10, 10]);
        let capped = RedialSchedule {
            interval: Duration::from_secs(20),
            ..schedule
        };
        assert_eq!(capped.delay(0), Duration::from_secs(10));
    }

    #[test]
    fn a_host_is_degraded_under_two_thirds_direct() {
        let ready = |direct, relayed, unbound| Readiness {
            direct,
            relayed,
            unbound,
        };
        assert!(!Readiness::default().degraded(), "no committee, no deficit");
        assert!(!ready(2, 1, 0).degraded());
        assert!(!ready(22, 9, 0).degraded());
        assert!(ready(20, 11, 0).degraded());
        assert!(ready(1, 0, 1).degraded(), "an unbound member is not direct");
    }

    #[test]
    fn a_relay_url_is_relayed_and_a_socket_is_direct() {
        let relay = TransportAddr::Relay("https://relay.example".parse().unwrap());
        let socket = TransportAddr::Ip(SocketAddr::from((Ipv4Addr::LOCALHOST, 4001)));
        assert_eq!(PathKind::of(&relay), PathKind::Relayed);
        assert_eq!(PathKind::of(&socket), PathKind::Direct);
    }

    const BUDGET: RedialBudget = RedialBudget {
        burst: 4,
        refill: Duration::from_secs(1),
    };

    fn rank(last_consensus_ms: u64) -> RedialRank {
        RedialRank(Reverse(last_consensus_ms))
    }

    #[tokio::test(start_paused = true)]
    async fn a_lone_re_dial_never_waits_for_the_budget() {
        let tokens = RedialTokens::new(BUDGET);
        let start = TokioInstant::now();
        tokens.take(rank(0)).await;
        assert_eq!(start.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn many_re_dials_at_once_keep_to_the_budget() {
        let tokens = Arc::new(RedialTokens::new(BUDGET));
        let start = TokioInstant::now();
        let waiting: Vec<_> = (0..20)
            .map(|_| {
                let tokens = Arc::clone(&tokens);
                spawn(async move {
                    tokens.take(rank(0)).await;
                    start.elapsed()
                })
            })
            .collect();
        let mut granted = Vec::new();
        for wait in waiting {
            granted.push(wait.await.unwrap());
        }
        granted.sort();
        for (turn, at) in granted.iter().enumerate() {
            let turn = u32::try_from(turn).unwrap();
            let earliest = BUDGET.refill * turn.saturating_sub(BUDGET.burst - 1);
            assert!(
                *at >= earliest,
                "turn {turn} came at {at:?}, before {earliest:?}"
            );
        }
        assert_eq!(
            granted[19],
            BUDGET.refill * 16,
            "and no later than the budget allows"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_peer_with_the_most_recent_consensus_traffic_goes_first() {
        let tokens = Arc::new(RedialTokens::new(BUDGET));
        for _ in 0..BUDGET.burst {
            tokens.take(rank(0)).await;
        }
        let order = Arc::new(Mutex::new(Vec::new()));
        let mut waiting = Vec::new();
        for (name, last) in [("silent", 0), ("older", 10), ("recent", 500)] {
            let (tokens, order) = (Arc::clone(&tokens), Arc::clone(&order));
            waiting.push(spawn(async move {
                tokens.take(rank(last)).await;
                order.lock().push(name);
            }));
            yield_now().await;
        }
        for wait in waiting {
            wait.await.unwrap();
        }
        assert_eq!(*order.lock(), ["recent", "older", "silent"]);
    }

    #[tokio::test(start_paused = true)]
    async fn an_admitted_re_dial_waits_behind_a_better_ranked_one() {
        let tokens = Arc::new(RedialTokens::new(RedialBudget {
            burst: 1,
            refill: Duration::from_secs(1),
        }));
        assert!(tokens.try_take(rank(0)), "the bucket starts full");
        assert!(!tokens.try_take(rank(0)), "and is then empty");

        let waiter = {
            let tokens = Arc::clone(&tokens);
            spawn(async move { tokens.take(rank(10)).await })
        };
        yield_now().await;
        advance(Duration::from_millis(1500)).await;
        assert!(
            !tokens.try_take(rank(5)),
            "the free token goes to the better ranked waiter"
        );
        waiter.await.unwrap();

        advance(Duration::from_secs(1)).await;
        assert!(
            tokens.try_take(rank(5)),
            "with nobody waiting it is admitted"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_unused_turn_goes_back_to_the_bucket() {
        let tokens = RedialTokens::new(RedialBudget {
            burst: 1,
            refill: Duration::from_secs(60),
        });
        assert!(tokens.try_take(rank(0)));
        tokens.give_back();
        assert!(tokens.try_take(rank(0)));
    }

    #[test]
    fn consensus_traffic_either_way_ranks_a_peer() {
        let (policy, peer) = policy_with(Some(PathKind::Direct));
        let stranger = SecretKey::generate().public();
        assert_eq!(policy.redial_rank(peer), rank(0), "no traffic yet");

        assert!(policy.admit(peer, MessageClass::Bulk, 1));
        assert_eq!(policy.redial_rank(peer), rank(0), "only consensus counts");

        assert!(policy.admit(peer, MessageClass::Consensus, 1));
        let sent = policy.redial_rank(peer);
        assert!(
            sent < rank(0),
            "a peer sent consensus ranks ahead of one never sent any"
        );

        thread::sleep(Duration::from_millis(5));
        policy.note_consensus(peer);
        assert!(
            policy.redial_rank(peer) < sent,
            "a later exchange ranks it higher"
        );
        assert_eq!(policy.redial_rank(stranger), rank(0));
    }
}
