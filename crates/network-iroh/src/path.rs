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
//! so a pair is back on a direct path seconds after an outage ends.

use std::future::pending;
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
use tokio::sync::Semaphore;
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

/// Re-dials one host has in flight at once, across all its peers, so that
/// a fallback of many connections together does not become a burst of
/// handshakes through the relay.
const MAX_REDIALS_IN_FLIGHT: usize = 16;

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
#[derive(Default)]
pub struct PathPolicy {
    peers: DashMap<EndpointId, Arc<PeerPath>>,
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
/// soon as the next replaces it or the connection is direct again, and the
/// whole host has at most [`MAX_REDIALS_IN_FLIGHT`] handshakes in flight.
/// Nothing here selects a path: the library still picks which one carries
/// the connection.
pub struct Redialer {
    endpoint: Endpoint,
    alpn: Vec<u8>,
    schedule: RedialSchedule,
    in_flight: Semaphore,
    redials: AtomicU64,
}

impl Redialer {
    /// A redialer that opens its connections on `endpoint` under protocol
    /// `alpn`, which the peer accepts and holds without serving anything.
    #[must_use]
    pub fn new(endpoint: Endpoint, alpn: &[u8], schedule: RedialSchedule) -> Arc<Self> {
        Arc::new(Self {
            endpoint,
            alpn: alpn.to_vec(),
            schedule,
            in_flight: Semaphore::new(MAX_REDIALS_IN_FLIGHT),
            redials: AtomicU64::new(0),
        })
    }

    /// Re-dials made so far, completed or not.
    #[must_use]
    pub fn redials(&self) -> u64 {
        self.redials.load(Ordering::Relaxed)
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
            let peer = connection.remote_id();
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
                        if let Some(fresh) = redialer.redial(peer).await {
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

    /// Open a connection to `peer` at every address the endpoint knows for
    /// it, unless it knows no direct one. Returns the connection once its
    /// handshake completes; the library has then tried a hole punch.
    async fn redial(&self, peer: EndpointId) -> Option<Connection> {
        let info = self.endpoint.remote_info(peer).await?;
        let addrs: Vec<TransportAddr> = info
            .into_addrs()
            .map(TransportAddrInfo::into_addr)
            .collect();
        if !addrs.iter().any(TransportAddr::is_ip) {
            debug!(peer = %peer.fmt_short(), "Not re-dialing: no direct address is known");
            return None;
        }
        let _permit = self.in_flight.acquire().await.ok()?;
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

    use iroh::SecretKey;

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
}
