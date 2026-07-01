//! Simulated in-memory network used by deterministic-replay tests.
//!
//! Implements the same [`Network`](hyperscale_network) trait as the libp2p
//! transport but routes messages through a single-process priority queue
//! ordered by `(deliver_at, sequence)`, so that a fixed seed always
//! produces an identical event interleaving.
//!
//! # Determinism
//!
//! Latency, jitter, and packet loss draw from a [`ChaCha8Rng`] seeded by
//! the test harness. Inter-shard latency and intra-shard latency are
//! configurable independently. All randomness flows through this RNG, so
//! reordering of network events between runs only happens if the harness
//! reseeds.
//!
//! # Fault injection
//!
//! The fault [`Engine`](hyperscale_network::fault::Engine) hooks every outbound
//! message and request, letting tests drop messages by class, peer, or time
//! window. Used by the `simulation` crate's fault-tests to exercise crash
//! recovery, network partitions, and gossip outages.
//!
//! # Traffic accounting
//!
//! [`NetworkTrafficAnalyzer`] aggregates bytes/messages by message type
//! and shard pair. Read by the simulator's metrics layer to render
//! per-test traffic summaries.

// `NodeIndex = u32` and `ValidatorId = u64` are interchangeable identifiers in
// the simulator (validator counts are bounded by the test harness, well under
// `u32::MAX`); the casts between them are domain-sized.
#![allow(clippy::cast_possible_truncation)]

use std::cmp::Reverse;
use std::collections::{BTreeSet, BinaryHeap, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use hyperscale_network::fault::{Decision, Engine, FaultBuilder, HostId, MessageContext, Tier};
use hyperscale_network::{HandlerRegistry, RequestError, ResponseVerdict, compression};
use hyperscale_types::{ShardId, ValidatorId};
use rand::RngExt;
use rand_chacha::ChaCha8Rng;
use tracing::{debug, trace};

use crate::NodeIndex;
use crate::sim_network::{
    BroadcastTarget, OutboxEntry, PendingNotification, PendingRequest, SimNetworkAdapter,
};
use crate::traffic::NetworkTrafficAnalyzer;

// Retry / rotation parameters mirroring the libp2p `RequestManagerConfig`
// defaults, so the simulated transport rotates and backs off the way the real
// one does. A request that can't be served runs this whole loop synchronously
// inside `accept_requests`; the accumulated latency is what the failure (or a
// late success after rotation) costs in simulated time. This is what gives the
// sim parity with the transport — a failed fetch re-dispatches on a real
// cadence instead of spinning at zero delay, which under the single-clock
// event loop would freeze time outright.

/// Attempts against the same peer before rotating to another.
const RETRIES_BEFORE_ROTATION: u32 = 2;
/// Total attempts before the request gives up with [`RequestError::Exhausted`].
const MAX_TOTAL_ATTEMPTS: u32 = 15;
/// First backoff applied after a timed-out attempt.
const INITIAL_BACKOFF: Duration = Duration::from_millis(100);
/// Ceiling the backoff grows toward.
const MAX_BACKOFF: Duration = Duration::from_millis(500);
/// Geometric growth factor between successive backoffs.
const BACKOFF_MULTIPLIER: f64 = 1.5;
/// Modeled time an attempt waits on a peer that never answers before the
/// transport declares a timeout and retries. The libp2p stream timeout adapts
/// to per-peer RTT; the sim uses the fixed warm floor, since its configured
/// latencies already stand in for RTT and the adaptive path adds no signal.
const STREAM_TIMEOUT: Duration = Duration::from_millis(300);

/// Modeled time to discover the target committee is empty. The transport
/// returns [`RequestError::NoPeers`] without attempting a send, so this is
/// short — but still positive so a node re-requesting an unpopulated committee
/// paces itself rather than spinning the clock.
const NO_PEERS_LATENCY: Duration = Duration::from_millis(200);

/// EMA smoothing for the per-peer success rate; mirrors `PeerHealth::EMA_ALPHA`.
const HEALTH_EMA_ALPHA: f64 = 0.2;
/// Selection-weight floor so even an unresponsive peer keeps an occasional
/// chance, mirroring the libp2p health tracker.
const HEALTH_WEIGHT_FLOOR: f64 = 0.05;
/// Selection weight for a peer this requester has never contacted — neutral,
/// matching the tracker's treatment of unknown peers.
const HEALTH_WEIGHT_NEUTRAL: f64 = 0.5;

/// Transport configuration for the simulated network: per-message latency
/// tiers, jitter, and packet loss.
///
/// Cluster layout — which validators run on which hosts and serve which
/// shards — is the harness's concern and reaches the transport as a
/// [`HostLayout`], never as config fields here.
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Base latency between two hosts that serve a shard in common.
    pub intra_shard_latency: Duration,
    /// Base latency between two hosts that serve no shard in common.
    pub cross_shard_latency: Duration,
    /// Jitter as a fraction of base latency (0.0 - 1.0).
    pub jitter_fraction: f64,
    /// Packet loss rate (0.0 - 1.0). Messages are dropped with this probability.
    pub packet_loss_rate: f64,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            intra_shard_latency: Duration::from_millis(150),
            cross_shard_latency: Duration::from_millis(150),
            jitter_fraction: 0.1,
            packet_loss_rate: 0.0,
        }
    }
}

/// The per-host shard layout the simulated transport routes on, supplied by
/// the harness that owns cluster placement.
///
/// `hosted[h]` is host `h`'s shard set — empty for a shard-less
/// beacon-follower host — and becomes that host's [`HandlerRegistry`] hosted
/// set; `validator_to_host` maps each hosted validator to its host index. The
/// transport holds these as its routing tables and never derives placement
/// itself.
pub struct HostLayout {
    /// Per-host hosted-shard set, indexed by host (`NodeIndex`).
    pub hosted: Vec<BTreeSet<ShardId>>,
    /// Hosted validator → host index. Validators absent from the map run on
    /// no host (an unplaced pool extra).
    pub validator_to_host: HashMap<ValidatorId, NodeIndex>,
}

/// Stats returned by [`SimulatedNetwork::accept_requests`],
/// [`SimulatedNetwork::accept_notifications`], and
/// [`SimulatedNetwork::accept_gossip`].
#[derive(Debug, Default)]
pub struct FulfillmentStats {
    /// Messages successfully scheduled for delivery.
    pub messages_sent: u64,
    /// Messages dropped because sender and receiver are partitioned.
    pub messages_dropped_partition: u64,
    /// Messages dropped to model packet loss.
    pub messages_dropped_loss: u64,
    /// Messages dropped by an installed fault rule.
    pub messages_dropped_fault: u64,
    /// Messages suppressed because the recipient already received that gossip ID.
    pub messages_deduplicated: u64,
}

/// Common interface for entries on a delivery heap: every scheduled item is
/// ordered by `(delivery_time, sequence)` and answers "when should this fire?"
trait Scheduled {
    fn delivery_time(&self) -> Duration;
}

/// Drain `heap` of every entry whose `delivery_time` is `<= now`, invoking
/// `deliver` for each. The closure returns `true` to count the entry as
/// delivered, `false` to drop it (e.g. no registered handler).
///
/// # Panics
///
/// Panics if a peeked entry disappears before the matching `pop()` — never
/// observed in practice; the heap is owned and not concurrently mutated.
fn flush_heap<T: Scheduled + Ord>(
    heap: &mut BinaryHeap<Reverse<T>>,
    now: Duration,
    mut deliver: impl FnMut(T) -> bool,
) -> usize {
    let mut delivered = 0;
    while let Some(Reverse(scheduled)) = heap.peek() {
        if scheduled.delivery_time() > now {
            break;
        }
        let Reverse(scheduled) = heap.pop().unwrap();
        if deliver(scheduled) {
            delivered += 1;
        }
    }
    delivered
}

/// A gossip delivery scheduled for future delivery via the internal latency queue.
struct ScheduledGossip {
    delivery_time: Duration,
    sequence: u64,
    target_node: NodeIndex,
    message_type: &'static str,
    payload: Vec<u8>,
    /// Shard the topic encoded for shard-scoped messages; `None` for
    /// global-scoped messages. Threaded through to the typed handler so
    /// cross-shard hosting can route the resulting `NodeInput` to the
    /// right hosted shard.
    shard: Option<ShardId>,
}

// Only (delivery_time, sequence) matters for ordering/identity — `sequence` is a
// unique monotonic counter, so two entries with the same sequence are the same entry.
impl PartialEq for ScheduledGossip {
    fn eq(&self, other: &Self) -> bool {
        (self.delivery_time, self.sequence) == (other.delivery_time, other.sequence)
    }
}
impl Eq for ScheduledGossip {}

impl PartialOrd for ScheduledGossip {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for ScheduledGossip {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.delivery_time, self.sequence).cmp(&(other.delivery_time, other.sequence))
    }
}
impl Scheduled for ScheduledGossip {
    fn delivery_time(&self) -> Duration {
        self.delivery_time
    }
}

/// A notification delivery scheduled for future delivery via the internal latency queue.
struct ScheduledNotification {
    delivery_time: Duration,
    sequence: u64,
    target_node: NodeIndex,
    message_type: &'static str,
    payload: Vec<u8>,
}

impl PartialEq for ScheduledNotification {
    fn eq(&self, other: &Self) -> bool {
        (self.delivery_time, self.sequence) == (other.delivery_time, other.sequence)
    }
}
impl Eq for ScheduledNotification {}

impl PartialOrd for ScheduledNotification {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for ScheduledNotification {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.delivery_time, self.sequence).cmp(&(other.delivery_time, other.sequence))
    }
}
impl Scheduled for ScheduledNotification {
    fn delivery_time(&self) -> Duration {
        self.delivery_time
    }
}

/// A request-response callback scheduled for future delivery.
///
/// Both outcomes are deferred to model transport latency: a success carries
/// the bytes the handler produced at accept-time (a data lookup), while a
/// failure carries the [`RequestError`] the production `RequestManager` would
/// surface only after spending its retry budget.
struct ScheduledResponse {
    delivery_time: Duration,
    sequence: u64,
    #[allow(dead_code)]
    requester_node: NodeIndex,
    on_response: Box<dyn FnOnce(Result<Vec<u8>, RequestError>) -> ResponseVerdict + Send>,
    result: Result<Vec<u8>, RequestError>,
}

impl PartialEq for ScheduledResponse {
    fn eq(&self, other: &Self) -> bool {
        (self.delivery_time, self.sequence) == (other.delivery_time, other.sequence)
    }
}
impl Eq for ScheduledResponse {}

impl PartialOrd for ScheduledResponse {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for ScheduledResponse {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.delivery_time, self.sequence).cmp(&(other.delivery_time, other.sequence))
    }
}
/// Per-(requester, peer) request health driving weighted peer selection.
///
/// A trimmed port of the libp2p `PeerHealth`: only the success-rate EMA is
/// kept. The sim's configured latencies already stand in for RTT, and the
/// synchronous fulfillment loop has no persistent in-flight state, so the
/// RTT-EMA, load, and recency factors add no signal here.
#[derive(Clone, Copy)]
struct PeerHealth {
    /// Exponential moving average of the success rate (0.0 - 1.0), seeded
    /// neutral and moved toward each observed outcome.
    success_rate_ema: f64,
}

impl Default for PeerHealth {
    fn default() -> Self {
        Self {
            success_rate_ema: HEALTH_WEIGHT_NEUTRAL,
        }
    }
}

impl PeerHealth {
    fn record_success(&mut self) {
        self.success_rate_ema = self
            .success_rate_ema
            .mul_add(1.0 - HEALTH_EMA_ALPHA, HEALTH_EMA_ALPHA);
    }

    /// A timeout is weighted half as severely as a hard error: under packet
    /// loss a timeout doesn't mean the peer is bad. Mirrors the libp2p penalty.
    fn record_failure(&mut self, timed_out: bool) {
        let penalty = if timed_out {
            HEALTH_EMA_ALPHA * 0.5
        } else {
            HEALTH_EMA_ALPHA
        };
        self.success_rate_ema *= 1.0 - penalty;
    }

    const fn selection_weight(self) -> f64 {
        if self.success_rate_ema > HEALTH_WEIGHT_FLOOR {
            self.success_rate_ema
        } else {
            HEALTH_WEIGHT_FLOOR
        }
    }
}

/// The stable identity of a request, threaded through each retry attempt.
struct RequestAttempt<'a> {
    requester: NodeIndex,
    shard: ShardId,
    type_id: &'static str,
    body: &'a [u8],
}

/// Outcome of one modeled attempt inside the retry loop.
enum AttemptOutcome {
    /// The peer answered; carries the response bytes and the round-trip cost.
    Success { bytes: Vec<u8>, rtt: Duration },
    /// The peer never answered (partition, packet loss, dropping fault rule).
    /// The transport waits out a stream timeout, then backs off and retries.
    Timeout,
    /// The peer answered with an application-level error (no handler, empty
    /// response). The transport rotates immediately, without backoff.
    HardError { rtt: Duration },
}

impl Scheduled for ScheduledResponse {
    fn delivery_time(&self) -> Duration {
        self.delivery_time
    }
}

/// Simulated network for deterministic message delivery.
///
/// Supports:
/// - Configurable latency with jitter
/// - Packet loss (probabilistic message drops)
/// - Network partitions (blocking communication between node pairs)
/// - Request fulfillment via per-type handlers in per-node [`HandlerRegistry`]s
/// - Internalized latency queues for gossip, notifications, and request-responses
pub struct SimulatedNetwork {
    config: NetworkConfig,
    /// Per-node handler registries, shared with each node's [`SimNetworkAdapter`].
    ///
    /// Populated when `register_gossip_handler` / `register_request_handler` /
    /// `register_notification_handler` are called on the adapter; read during
    /// `flush_gossip` / `flush_notifications` / `accept_requests`.
    registries: Vec<Arc<HandlerRegistry>>,
    /// Internal latency queue for pending gossip deliveries.
    pending_gossip: BinaryHeap<Reverse<ScheduledGossip>>,
    /// Monotonic sequence counter for deterministic gossip ordering.
    gossip_sequence: u64,
    /// Internal latency queue for pending notification deliveries.
    pending_notifications: BinaryHeap<Reverse<ScheduledNotification>>,
    /// Monotonic sequence counter for deterministic notification ordering.
    notification_sequence: u64,
    /// Internal latency queue for pending request-response callback deliveries.
    pending_responses: BinaryHeap<Reverse<ScheduledResponse>>,
    /// Monotonic sequence counter for deterministic response ordering.
    response_sequence: u64,
    /// Optional traffic analyzer for bandwidth metrics.
    traffic_analyzer: Option<Arc<NetworkTrafficAnalyzer>>,
    /// Runtime validator→host bindings for vnodes seated after
    /// construction (split-child flips, pool draws); checked before the
    /// hosting-mode formula in [`Self::validator_to_node`].
    validator_bindings: HashMap<ValidatorId, NodeIndex>,
    /// Per-node gossip dedup: tracks message IDs already delivered to each node.
    /// Matches production gossipsub's content-based deduplication (hash of data + topic).
    gossip_seen: Vec<HashSet<u64>>,
    /// Fault-injection state: per-message-type drop rules plus the partition
    /// block-set, layered on top of packet loss.
    faults: Engine,
    /// Per-(requester, peer) request health, driving weighted peer selection
    /// inside the retry loop. Each requester tracks its own view of every peer
    /// it has asked, mirroring the libp2p per-node `PeerHealthTracker`.
    peer_health: HashMap<(NodeIndex, NodeIndex), PeerHealth>,
}

impl std::fmt::Debug for SimulatedNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SimulatedNetwork")
            .field("config", &self.config)
            .field("blocked", &self.faults.block_count())
            .field("registries", &self.registries.len())
            .field("pending_gossip", &self.pending_gossip.len())
            .field("pending_notifications", &self.pending_notifications.len())
            .field("pending_responses", &self.pending_responses.len())
            .finish_non_exhaustive()
    }
}

impl SimulatedNetwork {
    /// Create a new simulated network from an explicit per-host
    /// [`HostLayout`]. The harness computes the layout (host→shard and
    /// validator→host); the transport builds one [`HandlerRegistry`] per host
    /// from `layout.hosted` and seeds its validator→host bindings, deriving no
    /// placement of its own.
    #[must_use]
    pub fn new(config: NetworkConfig, layout: HostLayout, seed: u64) -> Self {
        let num_hosts = layout.hosted.len();
        let registries: Vec<Arc<HandlerRegistry>> = layout
            .hosted
            .into_iter()
            .map(|hosted| Arc::new(HandlerRegistry::new(hosted)))
            .collect();
        Self {
            config,
            registries,
            pending_gossip: BinaryHeap::new(),
            gossip_sequence: 0,
            pending_notifications: BinaryHeap::new(),
            notification_sequence: 0,
            pending_responses: BinaryHeap::new(),
            response_sequence: 0,
            traffic_analyzer: None,
            validator_bindings: layout.validator_to_host,
            gossip_seen: (0..num_hosts).map(|_| HashSet::new()).collect(),
            faults: Engine::new(seed),
            peer_health: HashMap::new(),
        }
    }

    /// Translate a `ValidatorId` to its hosting `NodeIndex`, from the
    /// validator→host map seeded at construction and updated by
    /// [`Self::bind_validator`] as vnodes relocate. A validator that runs on
    /// no host (an unplaced pool extra) maps to an out-of-range index, which
    /// the delivery guards drop the same as an unreachable peer.
    #[must_use]
    pub fn validator_to_node(&self, validator: ValidatorId) -> NodeIndex {
        self.validator_bindings
            .get(&validator)
            .copied()
            .unwrap_or(self.registries.len() as NodeIndex)
    }

    /// Bind `validator` to `node`, overriding its construction-time host.
    /// Harnesses call this when seating a vnode at runtime on a different
    /// host (a pool draw or a split-child flip).
    pub fn bind_validator(&mut self, validator: ValidatorId, node: NodeIndex) {
        self.validator_bindings.insert(validator, node);
    }

    /// Builder for installing or removing per-message-type fault rules.
    ///
    /// Rules are layered on top of partition + packet-loss decisions: the
    /// network first checks partitions, then global packet loss, then
    /// fault rules.
    pub const fn fault(&mut self) -> FaultBuilder<'_> {
        FaultBuilder::new(&mut self.faults)
    }

    /// Set the traffic analyzer for bandwidth metrics recording.
    pub fn set_traffic_analyzer(&mut self, analyzer: Arc<NetworkTrafficAnalyzer>) {
        self.traffic_analyzer = Some(analyzer);
    }

    /// Create a [`SimNetworkAdapter`] for a node, sharing its handler registry.
    ///
    /// The returned adapter's `register_gossip_handler` / `register_request_handler`
    /// calls populate the shared registry, making them visible to
    /// [`accept_requests`](Self::accept_requests), [`flush_notifications`](Self::flush_notifications),
    /// and [`flush_gossip`](Self::flush_gossip).
    #[must_use]
    pub fn create_adapter(&self, node: NodeIndex) -> SimNetworkAdapter {
        SimNetworkAdapter::new(Arc::clone(&self.registries[node as usize]))
    }

    // ─── Partition Management ───

    /// Check if two nodes are partitioned (message from `from` to `to` would be dropped).
    #[must_use]
    pub fn is_partitioned(&self, from: NodeIndex, to: NodeIndex) -> bool {
        self.faults.is_blocked(HostId(from), HostId(to))
    }

    /// Create a unidirectional partition: messages from `from` to `to` are dropped.
    pub fn partition_unidirectional(&mut self, from: NodeIndex, to: NodeIndex) {
        self.faults.block(HostId(from), HostId(to));
    }

    /// Create a bidirectional partition between two nodes.
    pub fn partition_bidirectional(&mut self, a: NodeIndex, b: NodeIndex) {
        self.faults.block(HostId(a), HostId(b));
        self.faults.block(HostId(b), HostId(a));
    }

    /// Create a bidirectional partition between two groups of nodes.
    /// All messages between `group_a` and `group_b` are dropped (both directions).
    pub fn partition_groups(&mut self, group_a: &[NodeIndex], group_b: &[NodeIndex]) {
        for &a in group_a {
            for &b in group_b {
                self.faults.block(HostId(a), HostId(b));
                self.faults.block(HostId(b), HostId(a));
            }
        }
    }

    /// Isolate a node from all other nodes in the network.
    pub fn isolate_node(&mut self, node: NodeIndex) {
        for other in self.all_nodes() {
            if other != node {
                self.faults.block(HostId(node), HostId(other));
                self.faults.block(HostId(other), HostId(node));
            }
        }
    }

    /// Heal a unidirectional partition.
    pub fn heal_unidirectional(&mut self, from: NodeIndex, to: NodeIndex) {
        self.faults.unblock(HostId(from), HostId(to));
    }

    /// Heal a bidirectional partition between two nodes.
    pub fn heal_bidirectional(&mut self, a: NodeIndex, b: NodeIndex) {
        self.faults.unblock(HostId(a), HostId(b));
        self.faults.unblock(HostId(b), HostId(a));
    }

    /// Heal all partitions - restore full network connectivity.
    pub fn heal_all(&mut self) {
        self.faults.unblock_all();
    }

    /// Get the number of active partition pairs.
    #[must_use]
    pub fn partition_count(&self) -> usize {
        self.faults.block_count()
    }

    // ─── Packet Loss ───

    /// Check if a packet should be dropped based on the configured loss rate.
    /// Returns true if the packet should be dropped.
    pub fn should_drop_packet(&self, rng: &mut ChaCha8Rng) -> bool {
        self.config.packet_loss_rate > 0.0 && rng.random::<f64>() < self.config.packet_loss_rate
    }

    /// Set the packet loss rate (0.0 - 1.0).
    pub const fn set_packet_loss_rate(&mut self, rate: f64) {
        self.config.packet_loss_rate = rate.clamp(0.0, 1.0);
    }

    /// Get the current packet loss rate.
    #[must_use]
    pub const fn packet_loss_rate(&self) -> f64 {
        self.config.packet_loss_rate
    }

    // ─── Message Delivery Decision ───

    /// Determine if a message should be delivered from `from` to `to`.
    /// Returns `None` if the message should be dropped (partition or packet loss).
    /// Returns `Some(latency)` if the message should be delivered.
    pub fn should_deliver(
        &self,
        from: NodeIndex,
        to: NodeIndex,
        rng: &mut ChaCha8Rng,
    ) -> Option<Duration> {
        // A destination with no host (a hostless pool-extra validator) is
        // unreachable, same as a partitioned peer.
        if to as usize >= self.total_nodes() {
            return None;
        }

        // Check partition first (deterministic)
        if self.is_partitioned(from, to) {
            return None;
        }

        // Check packet loss (probabilistic but deterministic with seeded RNG)
        if self.should_drop_packet(rng) {
            return None;
        }

        // Message will be delivered - sample latency
        Some(self.sample_latency(from, to, rng))
    }

    /// Sample latency for a message between two nodes. Two hosts that
    /// serve a shard in common take `intra_shard_latency`; otherwise
    /// `cross_shard_latency`. Co-location is read from the live registries
    /// (see [`Self::hosts_share_shard`]), so a host that joins a shard at
    /// runtime becomes near to that shard's peers.
    pub fn sample_latency(&self, from: NodeIndex, to: NodeIndex, rng: &mut ChaCha8Rng) -> Duration {
        let base = if self.hosts_share_shard(from, to) {
            self.config.intra_shard_latency
        } else {
            self.config.cross_shard_latency
        };

        // Add jitter
        let jitter_range = base.as_secs_f64() * self.config.jitter_fraction;
        let jitter = rng.random_range(-jitter_range..jitter_range);
        let latency_secs = (base.as_secs_f64() + jitter).max(0.001);

        Duration::from_secs_f64(latency_secs)
    }

    /// Whether hosts `a` and `b` serve at least one shard in common — the
    /// latency model's "near" classifier. Reads each host's registry
    /// hosted set, the same source [`Self::peers_in_shard`] routes on, so it
    /// tracks reshape: a shard-less follower (empty hosted set) shares with
    /// nobody and is far from every peer.
    #[must_use]
    fn hosts_share_shard(&self, a: NodeIndex, b: NodeIndex) -> bool {
        let a_shards = self.registries[a as usize].hosted_shards();
        let b_shards = self.registries[b as usize].hosted_shards();
        a_shards.iter().any(|shard| b_shards.contains(shard))
    }

    /// Get all hosts (`IoLoop` indices) whose registry hosts `shard` — the
    /// reshape-aware peer pool the request and gossip paths route on.
    #[must_use]
    pub fn peers_in_shard(&self, shard: ShardId) -> Vec<NodeIndex> {
        self.registries
            .iter()
            .enumerate()
            .filter(|(_, registry)| registry.hosted_shards().contains(&shard))
            .map(|(node, _)| node as NodeIndex)
            .collect()
    }

    /// Get all hosts in the network.
    ///
    /// # Panics
    ///
    /// Panics if the host count exceeds `NodeIndex` — test harnesses are far
    /// smaller.
    #[must_use]
    pub fn all_nodes(&self) -> Vec<NodeIndex> {
        let total = NodeIndex::try_from(self.total_nodes()).expect("host count fits NodeIndex");
        (0..total).collect()
    }

    /// Get the total number of hosts (`IoLoop`s), including any dedicated
    /// pool-extra hosts — one per registry.
    #[must_use]
    pub const fn total_nodes(&self) -> usize {
        self.registries.len()
    }

    /// Get network configuration.
    #[must_use]
    pub const fn config(&self) -> &NetworkConfig {
        &self.config
    }

    // ─── Request Acceptance (Latency-Modeled) ───

    /// Accept pending requests: invoke handler immediately, schedule callback
    /// with round-trip latency.
    ///
    /// For each request:
    /// 1. Select a peer (`preferred_peer` if set, otherwise random from list)
    /// 2. Check partition and packet loss (request + response directions)
    /// 3. On error (partition/loss/no handler/empty): invoke callback immediately
    /// 4. On success: invoke handler to get response bytes, sample two
    ///    independent latencies (request + response legs), schedule callback
    ///    delivery at `now + latency_request + latency_response`
    pub fn accept_requests(
        &mut self,
        requester: NodeIndex,
        now: Duration,
        requests: Vec<PendingRequest>,
        rng: &mut ChaCha8Rng,
    ) -> FulfillmentStats {
        let mut stats = FulfillmentStats::default();
        for request in requests {
            self.fulfill_request(requester, now, request, rng, &mut stats);
        }
        stats
    }

    /// Run the retry/rotation loop for one request and schedule its single
    /// final outcome, mirroring `RequestManager::request_inner`: retry the same
    /// peer first (packet loss is probabilistic), rotate to a health-weighted
    /// alternative after [`RETRIES_BEFORE_ROTATION`], back off between
    /// timed-out attempts, and give up with [`RequestError::Exhausted`] after
    /// [`MAX_TOTAL_ATTEMPTS`]. Latency accumulates across attempts, so a late
    /// success after rotation costs that accumulated time — a recoverable
    /// failure succeeds instead of being charged a full exhaustion.
    fn fulfill_request(
        &mut self,
        requester: NodeIndex,
        now: Duration,
        request: PendingRequest,
        rng: &mut ChaCha8Rng,
        stats: &mut FulfillmentStats,
    ) {
        let PendingRequest {
            shard,
            preferred_peer,
            type_id,
            request_bytes,
            on_response,
        } = request;

        // Target committee, dropping ourselves so we never round-trip through
        // our own node.
        let candidates: Vec<NodeIndex> = self
            .peers_in_shard(shard)
            .into_iter()
            .filter(|&n| n != requester)
            .collect();

        // Initial peer: the preferred peer if it resolves into the committee,
        // otherwise a health-weighted pick. An empty committee surfaces
        // `NoPeers` after only the short discovery delay.
        let initial = preferred_peer
            .map(|vid| self.validator_to_node(vid))
            .filter(|p| candidates.contains(p))
            .or_else(|| self.select_peer_weighted(requester, &candidates, rng));
        let Some(mut current_peer) = initial else {
            self.schedule_response(
                now,
                NO_PEERS_LATENCY,
                requester,
                Err(RequestError::NoPeers),
                on_response,
            );
            return;
        };

        let attempt = RequestAttempt {
            requester,
            shard,
            type_id,
            body: &request_bytes,
        };
        let mut attempts: u32 = 0;
        let mut current_peer_attempts: u32 = 0;
        let mut elapsed = Duration::ZERO;
        let mut backoff = INITIAL_BACKOFF;

        loop {
            match self.attempt_request(&attempt, current_peer, now + elapsed, rng, stats) {
                AttemptOutcome::Success { bytes, rtt } => {
                    self.record_peer_success(requester, current_peer);
                    elapsed += rtt;
                    self.schedule_response(now, elapsed, requester, Ok(bytes), on_response);
                    return;
                }
                AttemptOutcome::Timeout => {
                    self.record_peer_failure(requester, current_peer, true);
                    attempts += 1;
                    current_peer_attempts += 1;
                    elapsed += STREAM_TIMEOUT;
                    if attempts >= MAX_TOTAL_ATTEMPTS {
                        self.schedule_response(
                            now,
                            elapsed,
                            requester,
                            Err(RequestError::Exhausted { attempts }),
                            on_response,
                        );
                        return;
                    }
                    // A timed-out peer might just have dropped a packet: retry
                    // it before rotating, then back off.
                    if current_peer_attempts >= RETRIES_BEFORE_ROTATION {
                        if let Some(next) =
                            self.select_peer_excluding(requester, &candidates, current_peer, rng)
                        {
                            current_peer = next;
                        }
                        current_peer_attempts = 0;
                    }
                    elapsed += backoff;
                    backoff = backoff.mul_f64(BACKOFF_MULTIPLIER).min(MAX_BACKOFF);
                }
                AttemptOutcome::HardError { rtt } => {
                    self.record_peer_failure(requester, current_peer, false);
                    attempts += 1;
                    elapsed += rtt;
                    if attempts >= MAX_TOTAL_ATTEMPTS {
                        self.schedule_response(
                            now,
                            elapsed,
                            requester,
                            Err(RequestError::Exhausted { attempts }),
                            on_response,
                        );
                        return;
                    }
                    // An application-level error won't fix itself on retry:
                    // rotate immediately, no backoff.
                    if let Some(next) =
                        self.select_peer_excluding(requester, &candidates, current_peer, rng)
                    {
                        current_peer = next;
                    }
                    current_peer_attempts = 0;
                }
            }
        }
    }

    /// Model one attempt against `peer`, updating drop stats. Returns the
    /// outcome plus, on success, the response bytes and round-trip cost.
    fn attempt_request(
        &self,
        req: &RequestAttempt<'_>,
        peer: NodeIndex,
        attempt_now: Duration,
        rng: &mut ChaCha8Rng,
        stats: &mut FulfillmentStats,
    ) -> AttemptOutcome {
        let RequestAttempt {
            requester,
            shard,
            type_id,
            body,
        } = *req;

        // Partition / packet loss (request then response direction) — the peer
        // never answers, so this attempt times out.
        if self.is_partitioned(requester, peer) {
            stats.messages_dropped_partition += 1;
            trace!(requester, peer, "Request dropped: partition");
            return AttemptOutcome::Timeout;
        }
        if self.should_drop_packet(rng) {
            stats.messages_dropped_loss += 1;
            trace!(requester, peer, "Request dropped: packet loss");
            return AttemptOutcome::Timeout;
        }
        if self.should_drop_packet(rng) {
            stats.messages_dropped_loss += 1;
            trace!(requester, peer, "Response dropped: packet loss");
            return AttemptOutcome::Timeout;
        }

        // Fault rules gate the request leg only, mirroring the libp2p gate in
        // `RequestStreamPool::send_request` — the transport has no response-leg
        // gate. Bidirectional packet loss above already models response-direction
        // drops; gating the response here too would let a request-typed rule fire
        // twice per attempt, so the sim's effective drop rate would diverge from
        // production's for the same portable rule.
        if self.faults.decide(
            &MessageContext {
                sender: HostId(requester),
                recipient: HostId(peer),
                type_id,
                tier: Tier::Request,
            },
            attempt_now,
        ) == Decision::Drop
        {
            stats.messages_dropped_fault += 1;
            trace!(requester, peer, type_id, "Request dropped: fault rule");
            return AttemptOutcome::Timeout;
        }

        let rtt =
            self.sample_latency(requester, peer, rng) + self.sample_latency(peer, requester, rng);

        // A missing handler or empty payload is an application-level error:
        // the peer answered, but with nothing usable.
        let Some(handler) = self
            .registries
            .get(peer as usize)
            .and_then(|r| r.get_request(type_id, shard))
        else {
            return AttemptOutcome::HardError { rtt };
        };
        let response_bytes = handler(body);
        if response_bytes.is_empty() {
            return AttemptOutcome::HardError { rtt };
        }

        stats.messages_sent += 2; // request + response
        if let Some(ref analyzer) = self.traffic_analyzer {
            analyzer.record_message(type_id, body.len(), body.len(), requester, peer);
            let response_type = format!("{type_id}.response");
            analyzer.record_message(
                &response_type,
                response_bytes.len(),
                response_bytes.len(),
                peer,
                requester,
            );
        }
        AttemptOutcome::Success {
            bytes: response_bytes,
            rtt,
        }
    }

    /// Health-weighted random selection from `candidates`, preferring peers
    /// this requester has had success with. Unknown peers get neutral weight.
    /// Mirrors `PeerHealthTracker::select_peer`.
    fn select_peer_weighted(
        &self,
        requester: NodeIndex,
        candidates: &[NodeIndex],
        rng: &mut ChaCha8Rng,
    ) -> Option<NodeIndex> {
        if candidates.is_empty() {
            return None;
        }
        let weights: Vec<f64> = candidates
            .iter()
            .map(|&p| {
                self.peer_health
                    .get(&(requester, p))
                    .map_or(HEALTH_WEIGHT_NEUTRAL, |h| h.selection_weight())
            })
            .collect();
        let total: f64 = weights.iter().sum();
        if total <= 0.0 {
            return candidates.first().copied();
        }
        let mut target = rng.random_range(0.0..total);
        for (&peer, &weight) in candidates.iter().zip(&weights) {
            target -= weight;
            if target <= 0.0 {
                return Some(peer);
            }
        }
        candidates.last().copied()
    }

    /// Select a peer other than `exclude`, falling back to `exclude` only when
    /// it is the sole candidate. Mirrors `select_peer_excluding`.
    fn select_peer_excluding(
        &self,
        requester: NodeIndex,
        candidates: &[NodeIndex],
        exclude: NodeIndex,
        rng: &mut ChaCha8Rng,
    ) -> Option<NodeIndex> {
        let filtered: Vec<NodeIndex> = candidates
            .iter()
            .copied()
            .filter(|&p| p != exclude)
            .collect();
        if filtered.is_empty() {
            return candidates.contains(&exclude).then_some(exclude);
        }
        self.select_peer_weighted(requester, &filtered, rng)
    }

    fn record_peer_success(&mut self, requester: NodeIndex, peer: NodeIndex) {
        self.peer_health
            .entry((requester, peer))
            .or_default()
            .record_success();
    }

    fn record_peer_failure(&mut self, requester: NodeIndex, peer: NodeIndex, timed_out: bool) {
        self.peer_health
            .entry((requester, peer))
            .or_default()
            .record_failure(timed_out);
    }

    /// Queue a request-response callback to fire at `now + latency`.
    ///
    /// Both successes and failures route through here so an error costs the
    /// same kind of simulated time the production transport spends before
    /// surfacing it — never the zero delay that would freeze the event loop.
    fn schedule_response(
        &mut self,
        now: Duration,
        latency: Duration,
        requester: NodeIndex,
        result: Result<Vec<u8>, RequestError>,
        on_response: Box<dyn FnOnce(Result<Vec<u8>, RequestError>) -> ResponseVerdict + Send>,
    ) {
        self.response_sequence += 1;
        self.pending_responses.push(Reverse(ScheduledResponse {
            delivery_time: now + latency,
            sequence: self.response_sequence,
            requester_node: requester,
            on_response,
            result,
        }));
    }

    // ─── Notification Acceptance (Latency-Modeled) ───

    /// Buffer notifications for delivery with simulated latency.
    ///
    /// Decompresses the payload once, then for each recipient: checks
    /// partition/loss, samples latency, and queues into `pending_notifications`.
    ///
    /// The harness calls [`flush_notifications()`](Self::flush_notifications)
    /// to deliver due messages via each target's registered notification handler.
    pub fn accept_notifications(
        &mut self,
        sender: NodeIndex,
        now: Duration,
        notifications: Vec<PendingNotification>,
        rng: &mut ChaCha8Rng,
    ) -> FulfillmentStats {
        let mut stats = FulfillmentStats::default();

        for notification in notifications {
            let PendingNotification {
                recipients,
                type_id,
                data,
            } = notification;

            let payload = match compression::decompress(&data) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(
                        sender,
                        type_id,
                        ?e,
                        "Notification decompress error in accept_notifications"
                    );
                    continue;
                }
            };

            for &recipient in &recipients {
                let to = self.validator_to_node(recipient);

                match self.should_deliver(sender, to, rng) {
                    None => {
                        if self.is_partitioned(sender, to) {
                            stats.messages_dropped_partition += 1;
                        } else {
                            stats.messages_dropped_loss += 1;
                        }
                    }
                    Some(latency) => {
                        if self.faults.decide(
                            &MessageContext {
                                sender: HostId(sender),
                                recipient: HostId(to),
                                type_id,
                                tier: Tier::Notification,
                            },
                            now,
                        ) == Decision::Drop
                        {
                            stats.messages_dropped_fault += 1;
                            continue;
                        }
                        stats.messages_sent += 1;
                        if let Some(ref analyzer) = self.traffic_analyzer {
                            analyzer.record_message(type_id, payload.len(), data.len(), sender, to);
                        }
                        self.notification_sequence += 1;
                        self.pending_notifications
                            .push(Reverse(ScheduledNotification {
                                delivery_time: now + latency,
                                sequence: self.notification_sequence,
                                target_node: to,
                                message_type: type_id,
                                payload: payload.clone(),
                            }));
                    }
                }
            }
        }

        stats
    }

    // ─── Internalized Gossip Queue ───

    /// Buffer an outbox entry for delivery with simulated latency.
    ///
    /// The message is decompressed once, then per-peer deliveries are pushed into
    /// the internal `pending_gossip` heap with sampled latency offsets.
    ///
    /// The harness calls [`flush_gossip()`](Self::flush_gossip) to deliver
    /// due messages via each target's registered `GossipHandler`.
    #[allow(clippy::needless_pass_by_value)] // mirrors `accept_notifications` / `accept_requests` for symmetry
    pub fn accept_gossip(
        &mut self,
        from: NodeIndex,
        now: Duration,
        entry: OutboxEntry,
        rng: &mut ChaCha8Rng,
    ) -> FulfillmentStats {
        let mut stats = FulfillmentStats::default();

        let peers = match &entry.target {
            BroadcastTarget::Shard(shard) => self.peers_in_shard(*shard),
            BroadcastTarget::Global => {
                let total = self.total_nodes();
                (0..total as NodeIndex).collect()
            }
        };

        let payload = match compression::decompress(&entry.data) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(
                    from,
                    message_type = entry.message_type,
                    ?e,
                    "Gossip decompress error in accept_gossip"
                );
                return stats;
            }
        };

        let message_type = entry.message_type;

        // Compute content-based message ID for dedup, matching production
        // gossipsub's message_id_fn: hash(data || topic).
        // Wire bytes (compressed) are used as the data, message_type as the topic.
        let msg_id = {
            use std::hash::{Hash, Hasher};
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            entry.data.hash(&mut hasher);
            message_type.hash(&mut hasher);
            hasher.finish()
        };

        for to in peers {
            if to == from {
                continue;
            }

            // Gossipsub dedup: each node receives a given message at most once,
            // regardless of how many validators broadcast it.
            if !self.gossip_seen[to as usize].insert(msg_id) {
                stats.messages_deduplicated += 1;
                continue;
            }

            match self.should_deliver(from, to, rng) {
                None => {
                    if self.is_partitioned(from, to) {
                        stats.messages_dropped_partition += 1;
                    } else {
                        stats.messages_dropped_loss += 1;
                    }
                }
                Some(latency) => {
                    if self.faults.decide(
                        &MessageContext {
                            sender: HostId(from),
                            recipient: HostId(to),
                            type_id: message_type,
                            tier: Tier::Gossip,
                        },
                        now,
                    ) == Decision::Drop
                    {
                        stats.messages_dropped_fault += 1;
                        continue;
                    }
                    stats.messages_sent += 1;
                    if let Some(ref analyzer) = self.traffic_analyzer {
                        analyzer.record_message(
                            message_type,
                            payload.len(),
                            entry.data.len(),
                            from,
                            to,
                        );
                    }
                    self.gossip_sequence += 1;
                    let shard = match entry.target {
                        BroadcastTarget::Shard(s) => Some(s),
                        BroadcastTarget::Global => None,
                    };
                    self.pending_gossip.push(Reverse(ScheduledGossip {
                        delivery_time: now + latency,
                        sequence: self.gossip_sequence,
                        target_node: to,
                        message_type,
                        payload: payload.clone(),
                        shard,
                    }));
                }
            }
        }

        stats
    }

    /// Deliver all pending gossip with `delivery_time <= now`.
    ///
    /// Calls each target node's registered `GossipHandler`. Returns the
    /// number of messages delivered.
    pub fn flush_gossip(&mut self, now: Duration) -> usize {
        flush_heap(&mut self.pending_gossip, now, |scheduled| {
            let Some(registry) = self.registries.get(scheduled.target_node as usize) else {
                debug!(
                    target_node = scheduled.target_node,
                    message_type = scheduled.message_type,
                    "No registry for target node, dropping gossip"
                );
                return false;
            };
            let gossip = registry.get_gossip(scheduled.message_type);
            // A Global broadcast (no topic shard) also reaches a shard-less
            // host's beacon follower pool; shard-scoped deliveries never do.
            let host_handler = if scheduled.shard.is_none() {
                registry.get_host_gossip(scheduled.message_type)
            } else {
                None
            };
            match (gossip, host_handler) {
                (Some(gossip), Some(host_handler)) => {
                    let _ = gossip(scheduled.payload.clone(), scheduled.shard);
                    host_handler(scheduled.payload);
                    true
                }
                (Some(gossip), None) => {
                    let _ = gossip(scheduled.payload, scheduled.shard);
                    true
                }
                (None, Some(host_handler)) => {
                    host_handler(scheduled.payload);
                    true
                }
                (None, None) => {
                    debug!(
                        target_node = scheduled.target_node,
                        message_type = scheduled.message_type,
                        "No gossip handler for message type on target node, dropping"
                    );
                    false
                }
            }
        })
    }

    /// Earliest pending gossip delivery time (for event loop scheduling).
    #[must_use]
    pub fn next_gossip_delivery_time(&self) -> Option<Duration> {
        self.pending_gossip.peek().map(|Reverse(s)| s.delivery_time)
    }

    /// Clear gossip dedup caches. Call periodically to prevent unbounded memory growth.
    pub fn prune_gossip_dedup(&mut self) {
        for seen in &mut self.gossip_seen {
            seen.clear();
        }
    }

    // ─── Notification Latency Queue ───

    /// Deliver all pending notifications with `delivery_time <= now`.
    ///
    /// Calls each target node's registered notification handler. Returns
    /// the number of notifications delivered.
    pub fn flush_notifications(&mut self, now: Duration) -> usize {
        flush_heap(&mut self.pending_notifications, now, |scheduled| {
            if let Some(handler) = self
                .registries
                .get(scheduled.target_node as usize)
                .and_then(|r| r.get_notification(scheduled.message_type))
            {
                handler(scheduled.payload);
                true
            } else {
                debug!(
                    target_node = scheduled.target_node,
                    message_type = scheduled.message_type,
                    "No notification handler for message type on target node, dropping"
                );
                false
            }
        })
    }

    /// Earliest pending notification delivery time.
    #[must_use]
    pub fn next_notification_delivery_time(&self) -> Option<Duration> {
        self.pending_notifications
            .peek()
            .map(|Reverse(s)| s.delivery_time)
    }

    // ─── Response Callback Latency Queue ───

    /// Deliver all pending response callbacks with `delivery_time <= now`.
    ///
    /// Invokes each deferred `on_response` callback with the pre-computed
    /// response bytes. Returns the number of responses delivered.
    pub fn flush_responses(&mut self, now: Duration) -> usize {
        flush_heap(&mut self.pending_responses, now, |scheduled| {
            (scheduled.on_response)(scheduled.result);
            true
        })
    }

    /// Earliest pending response delivery time.
    #[must_use]
    pub fn next_response_delivery_time(&self) -> Option<Duration> {
        self.pending_responses
            .peek()
            .map(|Reverse(s)| s.delivery_time)
    }

    // ─── Unified Delivery Time ───

    /// Earliest pending delivery time across gossip, notifications, and responses.
    #[must_use]
    pub fn next_delivery_time(&self) -> Option<Duration> {
        [
            self.next_gossip_delivery_time(),
            self.next_notification_delivery_time(),
            self.next_response_delivery_time(),
        ]
        .into_iter()
        .flatten()
        .min()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_network::{Network, RawRequestHandler};
    use rand::SeedableRng;

    use super::*;

    type SharedRequestResult = Arc<std::sync::Mutex<Option<Result<Vec<u8>, RequestError>>>>;

    /// Construct a network over a uniform layout (default transport config).
    fn sim_network(num_shards: u32, validators_per_shard: u32) -> SimulatedNetwork {
        sim_network_cfg(NetworkConfig::default(), num_shards, validators_per_shard)
    }

    /// Construct a network over a uniform layout with a given transport config.
    fn sim_network_cfg(
        config: NetworkConfig,
        num_shards: u32,
        validators_per_shard: u32,
    ) -> SimulatedNetwork {
        SimulatedNetwork::new(config, layout(num_shards, validators_per_shard), 0)
    }

    /// A uniform single-vnode-per-host layout: `validators_per_shard` hosts on
    /// each of `num_shards` shards, with validator id equal to host index.
    /// Enough for the transport tests, which exercise delivery and routing,
    /// not cluster placement.
    fn layout(num_shards: u32, validators_per_shard: u32) -> HostLayout {
        let shard_depth = num_shards.trailing_zeros();
        let mut hosted: Vec<BTreeSet<ShardId>> = Vec::new();
        let mut validator_to_host: HashMap<ValidatorId, NodeIndex> = HashMap::new();
        for shard_idx in 0..num_shards {
            let shard = ShardId::leaf(shard_depth, u64::from(shard_idx));
            for _ in 0..validators_per_shard {
                let host = hosted.len() as NodeIndex;
                validator_to_host.insert(ValidatorId::new(u64::from(host)), host);
                hosted.push(std::iter::once(shard).collect());
            }
        }
        HostLayout {
            hosted,
            validator_to_host,
        }
    }

    #[test]
    fn latency_classifies_by_shared_shard() {
        let network = sim_network(2, 4);

        // Hosts 0-3 serve shard 0; hosts 4-7 serve shard 1.
        assert!(network.hosts_share_shard(0, 3), "same-shard hosts are near");
        assert!(
            network.hosts_share_shard(0, 0),
            "a host shares its own shards"
        );
        assert!(
            !network.hosts_share_shard(0, 4),
            "cross-shard hosts are far"
        );
    }

    #[test]
    fn test_hyperscale_latency() {
        let network = sim_network(2, 4);
        let mut rng1 = ChaCha8Rng::seed_from_u64(42);
        let mut rng2 = ChaCha8Rng::seed_from_u64(42);

        let latency1 = network.sample_latency(0, 1, &mut rng1);
        let latency2 = network.sample_latency(0, 1, &mut rng2);

        assert_eq!(latency1, latency2, "Same seed should produce same latency");
    }

    // ─── Partition Tests ───

    #[test]
    fn test_unidirectional_partition() {
        let mut network = sim_network(2, 4);

        // No partition initially
        assert!(!network.is_partitioned(0, 1));
        assert!(!network.is_partitioned(1, 0));

        // Create unidirectional partition: 0 -> 1 blocked
        network.partition_unidirectional(0, 1);

        assert!(network.is_partitioned(0, 1));
        assert!(!network.is_partitioned(1, 0)); // Reverse direction still works

        // Heal
        network.heal_unidirectional(0, 1);
        assert!(!network.is_partitioned(0, 1));
    }

    #[test]
    fn test_bidirectional_partition() {
        let mut network = sim_network(2, 4);

        network.partition_bidirectional(0, 1);

        assert!(network.is_partitioned(0, 1));
        assert!(network.is_partitioned(1, 0));

        network.heal_bidirectional(0, 1);
        assert!(!network.is_partitioned(0, 1));
        assert!(!network.is_partitioned(1, 0));
    }

    #[test]
    fn test_group_partition() {
        let mut network = sim_network(2, 2);

        // Partition shard 0 (nodes 0,1) from shard 1 (nodes 2,3)
        let group_a = vec![0, 1];
        let group_b = vec![2, 3];
        network.partition_groups(&group_a, &group_b);

        // All cross-group pairs should be partitioned
        assert!(network.is_partitioned(0, 2));
        assert!(network.is_partitioned(0, 3));
        assert!(network.is_partitioned(1, 2));
        assert!(network.is_partitioned(1, 3));
        assert!(network.is_partitioned(2, 0));
        assert!(network.is_partitioned(3, 1));

        // Intra-group should still work
        assert!(!network.is_partitioned(0, 1));
        assert!(!network.is_partitioned(2, 3));

        // Heal all
        network.heal_all();
        assert_eq!(network.partition_count(), 0);
    }

    #[test]
    fn test_isolate_node() {
        let mut network = sim_network(1, 4);

        network.isolate_node(0);

        // Node 0 can't communicate with anyone
        assert!(network.is_partitioned(0, 1));
        assert!(network.is_partitioned(0, 2));
        assert!(network.is_partitioned(0, 3));
        assert!(network.is_partitioned(1, 0));
        assert!(network.is_partitioned(2, 0));
        assert!(network.is_partitioned(3, 0));

        // Other nodes can still communicate
        assert!(!network.is_partitioned(1, 2));
        assert!(!network.is_partitioned(2, 3));
    }

    // ─── Packet Loss Tests ───

    #[test]
    fn test_no_packet_loss_by_default() {
        let network = sim_network(2, 4);
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        // With 0% loss rate, no packets should be dropped
        for _ in 0..100 {
            assert!(!network.should_drop_packet(&mut rng));
        }
    }

    #[test]
    fn test_packet_loss_rate() {
        let mut network = sim_network_cfg(
            NetworkConfig {
                packet_loss_rate: 0.5, // 50% loss rate
                ..Default::default()
            },
            2,
            4,
        );

        let mut rng = ChaCha8Rng::seed_from_u64(42);

        // Count drops over many iterations
        let mut drops: u32 = 0;
        let iterations: u32 = 10000;
        for _ in 0..iterations {
            if network.should_drop_packet(&mut rng) {
                drops += 1;
            }
        }

        // Should be roughly 50% (within reasonable variance)
        let drop_rate = f64::from(drops) / f64::from(iterations);
        assert!(
            (0.45..0.55).contains(&drop_rate),
            "Expected ~50% drop rate, got {:.2}%",
            drop_rate * 100.0
        );

        // Test setting rate
        network.set_packet_loss_rate(0.0);
        assert!(network.packet_loss_rate().abs() < f64::EPSILON);

        // Clamping
        network.set_packet_loss_rate(1.5);
        assert!((network.packet_loss_rate() - 1.0).abs() < f64::EPSILON);

        network.set_packet_loss_rate(-0.5);
        assert!(network.packet_loss_rate().abs() < f64::EPSILON);
    }

    #[test]
    fn test_hyperscale_packet_loss() {
        let network = sim_network_cfg(
            NetworkConfig {
                packet_loss_rate: 0.3,
                ..Default::default()
            },
            2,
            4,
        );

        // Same seed should produce same drop decisions
        let mut rng1 = ChaCha8Rng::seed_from_u64(12345);
        let mut rng2 = ChaCha8Rng::seed_from_u64(12345);

        for _ in 0..100 {
            assert_eq!(
                network.should_drop_packet(&mut rng1),
                network.should_drop_packet(&mut rng2)
            );
        }
    }

    // ─── Combined Delivery Tests ───

    #[test]
    fn test_should_deliver_with_partition() {
        let mut network = sim_network(2, 4);
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        // Normal delivery works
        assert!(network.should_deliver(0, 1, &mut rng).is_some());

        // Partition blocks delivery
        network.partition_bidirectional(0, 1);
        assert!(network.should_deliver(0, 1, &mut rng).is_none());
        assert!(network.should_deliver(1, 0, &mut rng).is_none());

        // Other routes still work
        assert!(network.should_deliver(0, 2, &mut rng).is_some());
    }

    #[test]
    fn test_should_deliver_with_packet_loss() {
        let network = sim_network_cfg(
            NetworkConfig {
                packet_loss_rate: 1.0, // 100% loss
                ..Default::default()
            },
            2,
            4,
        );
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        // All packets should be dropped
        for _ in 0..10 {
            assert!(network.should_deliver(0, 1, &mut rng).is_none());
        }
    }

    #[test]
    fn test_partition_takes_precedence_over_packet_loss() {
        let mut network = sim_network_cfg(
            NetworkConfig {
                packet_loss_rate: 0.0, // No random loss
                ..Default::default()
            },
            2,
            4,
        );

        network.partition_bidirectional(0, 1);

        // Even with 0% packet loss, partition still blocks
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        assert!(network.should_deliver(0, 1, &mut rng).is_none());
    }

    // ─── accept_requests() Tests ───

    /// Helper: mark every host as hosting `shard`, so the peer pool the
    /// request/gossip paths derive from the per-host hosted sets covers
    /// the whole network — these tests exercise routing infrastructure
    /// (partitions, latency, peer selection), not shard placement.
    fn host_shard_everywhere(network: &SimulatedNetwork, shard: ShardId) {
        for node in network.all_nodes() {
            network.create_adapter(node).subscribe_shard(shard);
        }
    }

    /// Helper: register an echo handler on a node's adapter for a given
    /// `type_id` under `shard`.
    ///
    /// Registers directly on the shared registry since these tests exercise
    /// the `SimulatedNetwork` infrastructure (partitions, latency), not the
    /// typed handler registration API.
    fn register_echo(adapter: &SimNetworkAdapter, type_id: &'static str, shard: ShardId) {
        let handler: Arc<RawRequestHandler> =
            Arc::new(|payload: &[u8]| -> Vec<u8> { payload.to_vec() });
        adapter
            .registry
            .register_raw_request(type_id, shard, handler);
    }

    /// Helper: build a `PendingRequest` with a callback that captures the result.
    fn make_request_with_capture(
        shard: ShardId,
        preferred_peer: Option<ValidatorId>,
    ) -> (PendingRequest, SharedRequestResult) {
        let result = Arc::new(std::sync::Mutex::new(None));
        let result_clone = result.clone();
        let request = PendingRequest {
            shard,
            preferred_peer,
            type_id: "test.request",
            request_bytes: vec![1, 2, 3],
            on_response: Box::new(move |r| {
                *result_clone.lock().unwrap() = Some(r);
                ResponseVerdict::Accept
            }),
        };
        (request, result)
    }

    #[test]
    fn test_accept_requests_happy_path() {
        let mut network = sim_network(1, 4);
        host_shard_everywhere(&network, ShardId::leaf(1, 0));
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        // Register echo handler on node 1
        let adapter1 = network.create_adapter(1);
        register_echo(&adapter1, "test.request", ShardId::leaf(1, 0));

        let (request, result) =
            make_request_with_capture(ShardId::leaf(1, 0), Some(ValidatorId::new(1)));

        let stats = network.accept_requests(0, Duration::ZERO, vec![request], &mut rng);

        assert_eq!(stats.messages_sent, 2); // request + response
        assert_eq!(stats.messages_dropped_partition, 0);
        assert_eq!(stats.messages_dropped_loss, 0);

        // Callback is deferred — not yet invoked
        assert!(result.lock().unwrap().is_none());

        // Flush to deliver the response
        network.flush_responses(FAR_FUTURE);

        let captured = result.lock().unwrap().take().unwrap();
        assert!(captured.is_ok());
    }

    #[test]
    fn test_accept_requests_rotates_around_partitioned_peer() {
        let mut network = sim_network(1, 4);
        host_shard_everywhere(&network, ShardId::leaf(1, 0));
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        // Every peer can serve; only the preferred one is unreachable.
        for i in 0..4 {
            let adapter = network.create_adapter(i);
            register_echo(&adapter, "test.request", ShardId::leaf(1, 0));
        }
        network.partition_unidirectional(0, 1);

        let (request, result) =
            make_request_with_capture(ShardId::leaf(1, 0), Some(ValidatorId::new(1)));
        let stats = network.accept_requests(0, Duration::ZERO, vec![request], &mut rng);

        // Node 1 is tried `RETRIES_BEFORE_ROTATION` times (both partitioned),
        // then the loop rotates to a live peer and succeeds — the request never
        // fails just because the preferred peer is down.
        assert_eq!(
            stats.messages_dropped_partition,
            u64::from(RETRIES_BEFORE_ROTATION)
        );
        assert_eq!(stats.messages_sent, 2);

        assert!(result.lock().unwrap().is_none());
        network.flush_responses(FAR_FUTURE);
        let captured = result.lock().unwrap().take().unwrap();
        assert!(captured.is_ok());
    }

    #[test]
    fn test_accept_requests_retries_transient_loss_then_succeeds() {
        let mut network = sim_network_cfg(
            NetworkConfig {
                packet_loss_rate: 0.5, // transient loss — recoverable on retry
                ..Default::default()
            },
            1,
            4,
        );
        host_shard_everywhere(&network, ShardId::leaf(1, 0));
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        for i in 0..4 {
            let adapter = network.create_adapter(i);
            register_echo(&adapter, "test.request", ShardId::leaf(1, 0));
        }

        // With 15 attempts at 50% loss, the odds of never getting a packet
        // through are ~0.003% — retrying the same peer recovers the request
        // instead of charging it a full exhaustion.
        let (request, result) = make_request_with_capture(ShardId::leaf(1, 0), None);
        let stats = network.accept_requests(0, Duration::ZERO, vec![request], &mut rng);

        assert_eq!(stats.messages_sent, 2);
        network.flush_responses(FAR_FUTURE);
        let captured = result.lock().unwrap().take().unwrap();
        assert!(captured.is_ok());
    }

    #[test]
    fn test_accept_requests_exhausts_when_all_packets_dropped() {
        let mut network = sim_network_cfg(
            NetworkConfig {
                packet_loss_rate: 1.0, // 100% loss — no peer ever answers
                ..Default::default()
            },
            1,
            4,
        );
        host_shard_everywhere(&network, ShardId::leaf(1, 0));
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        for i in 0..4 {
            let adapter = network.create_adapter(i);
            register_echo(&adapter, "test.request", ShardId::leaf(1, 0));
        }

        let (request, result) =
            make_request_with_capture(ShardId::leaf(1, 0), Some(ValidatorId::new(1)));
        let stats = network.accept_requests(0, Duration::ZERO, vec![request], &mut rng);

        // Every one of the `MAX_TOTAL_ATTEMPTS` attempts drops, so nothing is
        // sent and the request gives up with `Exhausted`.
        assert_eq!(stats.messages_sent, 0);
        assert_eq!(stats.messages_dropped_loss, u64::from(MAX_TOTAL_ATTEMPTS));

        assert!(result.lock().unwrap().is_none());
        network.flush_responses(FAR_FUTURE);
        let captured = result.lock().unwrap().take().unwrap();
        assert!(matches!(
            captured,
            Err(RequestError::Exhausted { attempts }) if attempts == MAX_TOTAL_ATTEMPTS
        ));
    }

    #[test]
    fn test_accept_requests_no_handler_anywhere_exhausts() {
        let mut network = sim_network(1, 4);
        host_shard_everywhere(&network, ShardId::leaf(1, 0));
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        // No peer registers a handler: every attempt is an application error
        // that rotates and ultimately exhausts.
        let (request, result) =
            make_request_with_capture(ShardId::leaf(1, 0), Some(ValidatorId::new(1)));
        network.accept_requests(0, Duration::ZERO, vec![request], &mut rng);

        assert!(result.lock().unwrap().is_none());
        network.flush_responses(FAR_FUTURE);
        let captured = result.lock().unwrap().take().unwrap();
        assert!(matches!(captured, Err(RequestError::Exhausted { .. })));
    }

    #[test]
    fn test_accept_requests_empty_response_exhausts() {
        let mut network = sim_network(1, 4);
        host_shard_everywhere(&network, ShardId::leaf(1, 0));
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        // Only the preferred peer answers, and only with an empty payload; the
        // others have no handler. Every attempt is an application error, so the
        // request rotates through them all and exhausts.
        let adapter1 = network.create_adapter(1);
        let handler: Arc<RawRequestHandler> = Arc::new(|_: &[u8]| -> Vec<u8> { vec![] });
        adapter1
            .registry
            .register_raw_request("test.request", ShardId::leaf(1, 0), handler);

        let (request, result) =
            make_request_with_capture(ShardId::leaf(1, 0), Some(ValidatorId::new(1)));
        network.accept_requests(0, Duration::ZERO, vec![request], &mut rng);

        assert!(result.lock().unwrap().is_none());
        network.flush_responses(FAR_FUTURE);
        let captured = result.lock().unwrap().take().unwrap();
        assert!(matches!(captured, Err(RequestError::Exhausted { .. })));
    }

    #[test]
    fn test_peer_health_weighting_prefers_successful_peer() {
        let network = sim_network(1, 4);
        let mut net = network;
        let mut rng = ChaCha8Rng::seed_from_u64(7);

        // Teach requester 0 that peer 1 fails and peer 2 succeeds.
        for _ in 0..20 {
            net.record_peer_failure(0, 1, false);
            net.record_peer_success(0, 2);
        }

        let mut healthy = 0;
        for _ in 0..1000 {
            if net.select_peer_weighted(0, &[1, 2], &mut rng) == Some(2) {
                healthy += 1;
            }
        }
        // The successful peer is chosen far more often, but the unhealthy one
        // keeps an occasional chance via the weight floor.
        assert!(healthy > 800, "healthy selected {healthy}/1000");
        assert!(healthy < 1000, "unhealthy peer must keep a chance");
    }

    #[test]
    fn test_accept_requests_random_peer_selection() {
        let mut network = sim_network(1, 4);
        host_shard_everywhere(&network, ShardId::leaf(1, 0));
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        // Register handlers on all nodes
        for i in 0..4 {
            let adapter = network.create_adapter(i);
            register_echo(&adapter, "test.request", ShardId::leaf(1, 0));
        }

        // No preferred peer — should pick a random peer from the shard
        // committee (validators 1..=3 after the requester at index 0
        // filters itself out).
        let (request, result) = make_request_with_capture(ShardId::leaf(1, 0), None);
        let stats = network.accept_requests(0, Duration::ZERO, vec![request], &mut rng);

        assert_eq!(stats.messages_sent, 2);

        // Flush to deliver the deferred response
        network.flush_responses(FAR_FUTURE);
        let captured = result.lock().unwrap().take().unwrap();
        assert!(captured.is_ok());
    }

    #[test]
    fn test_accept_requests_single_node_no_peers() {
        let mut network = sim_network(1, 1);
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        let adapter0 = network.create_adapter(0);
        register_echo(&adapter0, "test.request", ShardId::leaf(1, 0));

        // No preferred peer, and empty peer list
        let (request, result) = make_request_with_capture(ShardId::leaf(1, 0), None);
        network.accept_requests(0, Duration::ZERO, vec![request], &mut rng);

        // An empty committee surfaces `NoPeers` after the short discovery delay.
        assert!(result.lock().unwrap().is_none());
        network.flush_responses(FAR_FUTURE);
        let captured = result.lock().unwrap().take().unwrap();
        assert!(matches!(captured, Err(RequestError::NoPeers)));
    }

    #[test]
    fn test_accept_requests_response_latency() {
        let mut network = sim_network_cfg(
            NetworkConfig {
                packet_loss_rate: 0.0,
                ..Default::default()
            },
            1,
            4,
        );
        host_shard_everywhere(&network, ShardId::leaf(1, 0));
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        let adapter1 = network.create_adapter(1);
        register_echo(&adapter1, "test.request", ShardId::leaf(1, 0));

        let (request, result) =
            make_request_with_capture(ShardId::leaf(1, 0), Some(ValidatorId::new(1)));

        network.accept_requests(0, Duration::from_millis(100), vec![request], &mut rng);

        // Response should be scheduled with round-trip latency after 100ms
        let next = network.next_response_delivery_time().unwrap();
        assert!(next > Duration::from_millis(100));

        // Flush at 100ms — should not deliver yet
        let delivered = network.flush_responses(Duration::from_millis(100));
        assert_eq!(delivered, 0);
        assert!(result.lock().unwrap().is_none());

        // Flush at far future — should deliver
        network.flush_responses(FAR_FUTURE);
        let captured = result.lock().unwrap().take().unwrap();
        assert!(captured.is_ok());
    }

    // ─── accept_gossip / flush_gossip Tests ───

    /// Helper: create a wire-encoded (LZ4-compressed) outbox entry.
    fn make_gossip_entry(target: BroadcastTarget) -> OutboxEntry {
        let data = compression::compress(b"test gossip payload");
        OutboxEntry {
            target,
            message_type: "test.gossip",
            data,
        }
    }

    /// Test gossip handler that records received payloads.
    ///
    /// Each handler is registered for a single message type, so the type is
    /// implicit — we only need to record the payloads.
    struct RecordingHandler {
        received: std::sync::Mutex<Vec<Vec<u8>>>,
    }

    impl RecordingHandler {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                received: std::sync::Mutex::new(Vec::new()),
            })
        }

        fn count(&self) -> usize {
            self.received.lock().unwrap().len()
        }

        fn payloads(&self) -> Vec<Vec<u8>> {
            self.received.lock().unwrap().clone()
        }
    }

    /// The message type used in gossip tests.
    const TEST_GOSSIP_TYPE: &str = "test.gossip";

    /// Register recording handlers on all nodes and return them.
    ///
    /// Registers directly on the shared registry since these tests exercise
    /// the `SimulatedNetwork` infrastructure, not the typed handler API.
    fn register_gossip_handlers(network: &SimulatedNetwork) -> Vec<Arc<RecordingHandler>> {
        use hyperscale_network::GossipVerdict;
        use hyperscale_network::registry::RawGossipHandler;
        let total = network.total_nodes();
        (0..total as NodeIndex)
            .map(|i| {
                let handler = RecordingHandler::new();
                let adapter = network.create_adapter(i);
                let handler_clone = handler.clone();
                let raw: Arc<RawGossipHandler> =
                    Arc::new(move |payload: Vec<u8>, _shard: Option<ShardId>| {
                        handler_clone.received.lock().unwrap().push(payload);
                        GossipVerdict::Accept
                    });
                adapter.registry.register_raw_gossip(TEST_GOSSIP_TYPE, raw);
                handler
            })
            .collect()
    }

    /// Far-future time that ensures all pending gossip is delivered.
    const FAR_FUTURE: Duration = Duration::from_mins(1);

    #[test]
    fn test_accept_gossip_shard_scoped() {
        let mut network = sim_network_cfg(
            NetworkConfig {
                packet_loss_rate: 0.0,
                ..Default::default()
            },
            2,
            2,
        );
        let handlers = register_gossip_handlers(&network);
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        // Node 0 is in shard 0, along with node 1. Nodes 2,3 are in shard 1.
        let entry = make_gossip_entry(BroadcastTarget::Shard(ShardId::leaf(1, 0)));
        let stats = network.accept_gossip(0, Duration::ZERO, entry, &mut rng);
        network.flush_gossip(FAR_FUTURE);

        // Should deliver only to node 1 (same shard, excluding sender)
        assert_eq!(stats.messages_sent, 1);
        assert_eq!(handlers[0].count(), 0); // sender
        assert_eq!(handlers[1].count(), 1);
        assert_eq!(handlers[2].count(), 0); // different shard
        assert_eq!(handlers[3].count(), 0); // different shard
    }

    #[test]
    fn test_accept_gossip_global() {
        let mut network = sim_network_cfg(
            NetworkConfig {
                packet_loss_rate: 0.0,
                ..Default::default()
            },
            2,
            2,
        );
        let handlers = register_gossip_handlers(&network);
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        let entry = make_gossip_entry(BroadcastTarget::Global);
        let stats = network.accept_gossip(0, Duration::ZERO, entry, &mut rng);
        network.flush_gossip(FAR_FUTURE);

        // Should deliver to nodes 1, 2, 3 (everyone except sender node 0)
        assert_eq!(stats.messages_sent, 3);
        assert_eq!(handlers[0].count(), 0);
        assert_eq!(handlers[1].count(), 1);
        assert_eq!(handlers[2].count(), 1);
        assert_eq!(handlers[3].count(), 1);
    }

    #[test]
    fn test_accept_gossip_excludes_sender() {
        let mut network = sim_network_cfg(
            NetworkConfig {
                packet_loss_rate: 0.0,
                ..Default::default()
            },
            1,
            4,
        );
        let handlers = register_gossip_handlers(&network);
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        let entry = make_gossip_entry(BroadcastTarget::Global);
        network.accept_gossip(0, Duration::ZERO, entry, &mut rng);
        network.flush_gossip(FAR_FUTURE);

        // Sender (node 0) should never receive its own gossip
        assert_eq!(handlers[0].count(), 0);
        for h in &handlers[1..] {
            assert_eq!(h.count(), 1);
        }
    }

    #[test]
    fn test_accept_gossip_partition_blocks() {
        let mut network = sim_network_cfg(
            NetworkConfig {
                packet_loss_rate: 0.0,
                ..Default::default()
            },
            2,
            2,
        );
        let handlers = register_gossip_handlers(&network);
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        // Partition node 0 → node 1
        network.partition_unidirectional(0, 1);

        let entry = make_gossip_entry(BroadcastTarget::Global);
        let stats = network.accept_gossip(0, Duration::ZERO, entry, &mut rng);
        network.flush_gossip(FAR_FUTURE);

        // Node 1 should be blocked, nodes 2,3 should receive
        assert_eq!(handlers[1].count(), 0);
        assert_eq!(handlers[2].count(), 1);
        assert_eq!(handlers[3].count(), 1);
        assert_eq!(stats.messages_dropped_partition, 1);
        assert_eq!(stats.messages_sent, 2);
    }

    #[test]
    fn test_accept_gossip_100_percent_loss() {
        let mut network = sim_network_cfg(
            NetworkConfig {
                packet_loss_rate: 1.0,
                ..Default::default()
            },
            1,
            4,
        );
        let handlers = register_gossip_handlers(&network);
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        let entry = make_gossip_entry(BroadcastTarget::Global);
        let stats = network.accept_gossip(0, Duration::ZERO, entry, &mut rng);
        let delivered = network.flush_gossip(FAR_FUTURE);

        assert_eq!(delivered, 0);
        for h in &handlers {
            assert_eq!(h.count(), 0);
        }
        assert_eq!(stats.messages_dropped_loss, 3);
        assert_eq!(stats.messages_sent, 0);
    }

    #[test]
    fn test_accept_gossip_latency_varies() {
        let mut network = sim_network_cfg(
            NetworkConfig {
                jitter_fraction: 0.5, // High jitter
                packet_loss_rate: 0.0,
                ..Default::default()
            },
            1,
            4,
        );
        let handlers = register_gossip_handlers(&network);
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        let entry = make_gossip_entry(BroadcastTarget::Global);
        let stats = network.accept_gossip(0, Duration::ZERO, entry, &mut rng);
        assert_eq!(stats.messages_sent, 3);

        // With high jitter, not all messages should arrive at the same time.
        // Flush at the earliest delivery time — should deliver at least one
        // but not necessarily all.
        let first_time = network.next_gossip_delivery_time().unwrap();
        let delivered_at_first = network.flush_gossip(first_time);
        assert!(delivered_at_first >= 1);

        // Flush the rest
        network.flush_gossip(FAR_FUTURE);

        // All 3 peers should have received
        let total: usize = handlers.iter().map(|h| h.count()).sum();
        assert_eq!(total, 3);
    }

    #[test]
    fn test_accept_gossip_payload_decompressed() {
        let mut network = sim_network_cfg(
            NetworkConfig {
                packet_loss_rate: 0.0,
                ..Default::default()
            },
            1,
            2,
        );
        let handlers = register_gossip_handlers(&network);
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        let original_payload = b"test gossip payload";
        let entry = make_gossip_entry(BroadcastTarget::Global);
        network.accept_gossip(0, Duration::ZERO, entry, &mut rng);
        network.flush_gossip(FAR_FUTURE);

        // Node 1 should have received the decompressed payload
        let payloads = handlers[1].payloads();
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0], original_payload);
    }

    #[test]
    fn test_accept_gossip_invalid_compressed_data() {
        let mut network = sim_network(1, 2);
        let handlers = register_gossip_handlers(&network);
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        // Pass garbage data that can't be decompressed
        let entry = OutboxEntry {
            target: BroadcastTarget::Global,
            message_type: "test.gossip",
            data: vec![0xFF, 0xFE, 0xFD],
        };

        let stats = network.accept_gossip(0, Duration::ZERO, entry, &mut rng);
        let delivered = network.flush_gossip(FAR_FUTURE);

        assert_eq!(delivered, 0);
        assert_eq!(stats.messages_sent, 0);
        for h in &handlers {
            assert_eq!(h.count(), 0);
        }
    }

    #[test]
    fn test_accept_gossip_stats_accurate() {
        // nodes 0,1 in shard 0; nodes 2,3 in shard 1
        let mut network = sim_network_cfg(
            NetworkConfig {
                packet_loss_rate: 0.0,
                ..Default::default()
            },
            2,
            2,
        );
        let handlers = register_gossip_handlers(&network);
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        // Partition node 0 → node 2
        network.partition_unidirectional(0, 2);

        let entry = make_gossip_entry(BroadcastTarget::Global);
        let stats = network.accept_gossip(0, Duration::ZERO, entry, &mut rng);
        network.flush_gossip(FAR_FUTURE);

        // 3 targets (1, 2, 3), 1 partitioned (node 2), 2 delivered
        assert_eq!(stats.messages_sent, 2);
        assert_eq!(stats.messages_dropped_partition, 1);
        assert_eq!(stats.messages_dropped_loss, 0);
        assert_eq!(handlers[1].count(), 1);
        assert_eq!(handlers[2].count(), 0); // partitioned
        assert_eq!(handlers[3].count(), 1);
    }

    #[test]
    fn test_next_gossip_delivery_time() {
        let mut network = sim_network_cfg(
            NetworkConfig {
                packet_loss_rate: 0.0,
                ..Default::default()
            },
            1,
            2,
        );
        let _handlers = register_gossip_handlers(&network);
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        // No pending gossip
        assert!(network.next_gossip_delivery_time().is_none());

        let entry = make_gossip_entry(BroadcastTarget::Global);
        network.accept_gossip(0, Duration::from_millis(100), entry, &mut rng);

        // Should have a delivery time > 100ms (100ms + latency)
        let next = network.next_gossip_delivery_time().unwrap();
        assert!(next > Duration::from_millis(100));

        // Flush clears queue
        network.flush_gossip(FAR_FUTURE);
        assert!(network.next_gossip_delivery_time().is_none());
    }

    // ─── create_adapter and Integration ───

    #[test]
    fn test_create_adapter_shares_handler_slot() {
        let mut network = sim_network(1, 2);
        host_shard_everywhere(&network, ShardId::leaf(1, 0));
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        // Create adapter for node 1 and register handler through it
        let adapter1 = network.create_adapter(1);
        register_echo(&adapter1, "test.request", ShardId::leaf(1, 0));

        // accept_requests should be able to find the handler
        let (request, result) =
            make_request_with_capture(ShardId::leaf(1, 0), Some(ValidatorId::new(1)));
        let stats = network.accept_requests(0, Duration::ZERO, vec![request], &mut rng);

        assert_eq!(stats.messages_sent, 2);
        network.flush_responses(FAR_FUTURE);
        let captured = result.lock().unwrap().take().unwrap();
        assert!(captured.is_ok());
    }

    #[test]
    fn test_full_gossip_roundtrip() {
        use hyperscale_network::GossipVerdict;
        use hyperscale_network::registry::RawGossipHandler;
        use hyperscale_types::ShardId;
        use hyperscale_types::network::gossip::TransactionGossip;
        use hyperscale_types::test_utils::{test_node, test_transaction_with_nodes};

        let mut network = sim_network_cfg(
            NetworkConfig {
                packet_loss_rate: 0.0,
                ..Default::default()
            },
            1,
            2,
        );
        host_shard_everywhere(&network, ShardId::leaf(1, 0));
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        // Register per-type handlers for "transaction.gossip" on each node.
        // Register directly on registry since we want raw recording handlers.
        let handlers: Vec<Arc<RecordingHandler>> = (0..network.total_nodes() as NodeIndex)
            .map(|i| {
                let handler = RecordingHandler::new();
                let adapter = network.create_adapter(i);
                let handler_clone = handler.clone();
                let raw: Arc<RawGossipHandler> =
                    Arc::new(move |payload: Vec<u8>, _shard: Option<ShardId>| {
                        handler_clone.received.lock().unwrap().push(payload);
                        GossipVerdict::Accept
                    });
                adapter
                    .registry
                    .register_raw_gossip("transaction.gossip", raw);
                handler
            })
            .collect();

        let adapter0 = network.create_adapter(0);

        // Node 0 broadcasts a transaction via its adapter
        let gossip = TransactionGossip::new(vec![Arc::new(test_transaction_with_nodes(
            &[1, 2, 3],
            vec![test_node(1)],
            vec![test_node(2)],
        ))]);
        Network::broadcast_to_shard(&adapter0, ShardId::leaf(1, 0), &gossip);

        // Drain and deliver via accept_gossip + flush_gossip
        let entries = adapter0.drain_outbox();
        assert_eq!(entries.len(), 1);

        let stats = network.accept_gossip(
            0,
            Duration::ZERO,
            entries.into_iter().next().unwrap(),
            &mut rng,
        );
        assert_eq!(stats.messages_sent, 1);

        network.flush_gossip(FAR_FUTURE);

        // Node 1 should have received the transaction gossip
        let payloads = handlers[1].payloads();
        assert_eq!(payloads.len(), 1);
        assert!(!payloads[0].is_empty());
    }
}
