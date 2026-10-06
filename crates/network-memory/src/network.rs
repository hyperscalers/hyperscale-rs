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
//! the test harness. All randomness flows through this RNG, so
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
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap, HashSet, VecDeque};
use std::ops::Range;
use std::sync::Arc;
use std::time::Duration;

use blake3::Hasher as Blake3Hasher;
use hyperscale_network::fault::{
    Decision, DropSpec, Engine, FaultBuilder, HostId, MessageContext, Rewrite, RuleHandle, Tier,
};
use hyperscale_network::retry::{
    AllHeld, Attempts, Outcome, PeerHealthBook, Resolution, RetryConfig,
};
use hyperscale_network::stream_backoff::{StreamBackoff, StreamFailure};
use hyperscale_network::{HandlerRegistry, RequestError, ResponseVerdict, compression};
use hyperscale_types::{MessageClass, ShardId, ValidatorId};
use rand::RngExt;
use rand_chacha::ChaCha8Rng;
use tracing::{debug, trace};

use crate::geography::{Geography, RegionPlan};
use crate::sim_network::{
    BroadcastTarget, OutboxEntry, PendingNotification, PendingRequest, SimNetworkAdapter,
};
use crate::traffic::NetworkTrafficAnalyzer;
use crate::{LinkStreams, NodeIndex};

/// Transport configuration for the simulated network: per-message latency
/// tiers, jitter, and packet loss.
///
/// Cluster layout — which validators run on which hosts and serve which
/// shards — is the harness's concern and reaches the transport as a
/// [`HostLayout`], never as config fields here.
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Base latency between any two hosts. Shard membership is a random
    /// draw, unrelated to where a host sits, so a link within a shard is no
    /// nearer than one between shards.
    pub latency: Duration,
    /// Jitter as a fraction of base latency (0.0 - 1.0).
    pub jitter_fraction: f64,
    /// Packet loss rate (0.0 - 1.0). A gossip or notification copy is
    /// dropped with this probability; a request or response leg rides a
    /// stream that retransmits, so a loss costs it one more round trip on its
    /// link instead.
    pub packet_loss_rate: f64,
    /// Probability a delivered copy arrives twice (0.0 - 1.0): a gossip or
    /// notification copy past the recipient's dedup, or a request leg the
    /// peer serves twice. Zero draws nothing.
    pub duplicate_rate: f64,
    /// Probability a delivered gossip or notification copy brings an old
    /// payload of its type with it (0.0 - 1.0), sampled from the last
    /// [`REPLAY_DEPTH`] the transport carried. Zero draws nothing.
    pub replay_rate: f64,
    /// Probability one delivery's latency spikes 10-50x (0.0 - 1.0). Zero
    /// draws nothing.
    pub spike_rate: f64,
    /// Hosts spread over regions, each link priced by its region pair:
    /// its base latency stands in for `latency`, and a payload also waits
    /// its size over the link's bandwidth. `None` prices every link alike.
    pub regions: Option<RegionPlan>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            latency: Duration::from_millis(150),
            jitter_fraction: 0.1,
            packet_loss_rate: 0.0,
            duplicate_rate: 0.0,
            replay_rate: 0.0,
            spike_rate: 0.0,
            regions: None,
        }
    }
}

/// Old payloads kept per message type for replay.
const REPLAY_DEPTH: usize = 64;

/// A payload the transport carried, kept for replay.
struct Carried {
    payload: Vec<u8>,
    shard: Option<ShardId>,
    class: MessageClass,
    wire_bytes: usize,
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
    /// Gossip and notification copies dropped to model packet loss.
    pub messages_dropped_loss: u64,
    /// Request and response legs that lost a packet and arrived a
    /// retransmission round trip late.
    pub messages_retransmitted: u64,
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
///
/// `record` describes the delivery as it will happen: its edge, and its
/// topic shard, which is threaded through to the typed handler so
/// cross-shard hosting can route the resulting `NodeInput` to the right
/// hosted shard. It reaches the delivery log only once the copy lands.
struct ScheduledGossip {
    sequence: u64,
    record: DeliveryRecord,
    /// The dedup id the recipient marked seen when this copy was scheduled;
    /// `None` for a duplicate or replayed copy, which marked nothing.
    msg_id: Option<u64>,
    payload: Vec<u8>,
}

// Only (delivery time, sequence) matters for ordering/identity — `sequence` is a
// unique monotonic counter, so two entries with the same sequence are the same entry.
impl PartialEq for ScheduledGossip {
    fn eq(&self, other: &Self) -> bool {
        (self.delivery_time(), self.sequence) == (other.delivery_time(), other.sequence)
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
        (self.delivery_time(), self.sequence).cmp(&(other.delivery_time(), other.sequence))
    }
}
impl Scheduled for ScheduledGossip {
    fn delivery_time(&self) -> Duration {
        self.record.delivered_at
    }
}

/// A notification delivery scheduled for future delivery via the internal
/// latency queue; `record` reaches the delivery log only once it lands.
struct ScheduledNotification {
    sequence: u64,
    record: DeliveryRecord,
    payload: Vec<u8>,
}

impl PartialEq for ScheduledNotification {
    fn eq(&self, other: &Self) -> bool {
        (self.delivery_time(), self.sequence) == (other.delivery_time(), other.sequence)
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
        (self.delivery_time(), self.sequence).cmp(&(other.delivery_time(), other.sequence))
    }
}
impl Scheduled for ScheduledNotification {
    fn delivery_time(&self) -> Duration {
        self.record.delivered_at
    }
}

/// Modeled time to discover the target committee is empty. The transport
/// returns [`RequestError::NoPeers`] without attempting a send, so this is
/// short — but still positive so a node re-requesting an unpopulated committee
/// paces itself rather than spinning the clock.
const NO_PEERS_LATENCY: Duration = Duration::from_millis(200);

/// What a requester hands the transport to receive its result.
type ResponseCallback = Box<dyn FnOnce(Result<Vec<u8>, RequestError>) -> ResponseVerdict + Send>;

/// One request from its first dispatch to its result.
struct InFlightRequest {
    requester: NodeIndex,
    shard: ShardId,
    type_id: &'static str,
    class: MessageClass,
    response_class: MessageClass,
    body: Vec<u8>,
    on_response: ResponseCallback,
    /// Whether an answer holds nothing of what was asked, in the request
    /// type's terms.
    is_empty_response: fn(&[u8]) -> bool,
    attempts: Attempts<NodeIndex>,
    /// Attempts dispatched so far; the newest one's serial.
    serial: u32,
    /// The attempt awaiting an outcome; `None` between an attempt's
    /// resolution and the next dispatch.
    open: Option<OpenAttempt>,
}

/// The attempt a request awaits an outcome of.
struct OpenAttempt {
    serial: u32,
    sent_at: Duration,
    leg: LegFate,
}

/// How far an attempt's request leg got, which decides what its end does to
/// the requester's stream backoff.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LegFate {
    /// On the wire, or cut by a partition before it landed: the stream to
    /// the peer could not be opened.
    Sent,
    /// Landed at the peer: the stream opened.
    Reached,
    /// Taken by a fault rule before the transport saw it, as the libp2p
    /// fault gate fails an attempt before it reaches the stream pool.
    Gated,
}

/// A step of a request, run at its scheduled time.
enum RequestEvent {
    /// Dispatch the request's next attempt.
    Dispatch { request: u64 },
    /// An attempt's request leg reaches its peer.
    Arrive {
        request: u64,
        attempt: u32,
        leg: DeliveryRecord,
    },
    /// An attempt's response leg reaches the requester, carrying how the
    /// peer ended the attempt; never [`AttemptEnd::TimedOut`].
    Answer {
        request: u64,
        attempt: u32,
        leg: DeliveryRecord,
        end: AttemptEnd,
    },
    /// An attempt's timeout fires.
    Timeout { request: u64, attempt: u32 },
    /// Hand a requester its final result.
    Settle {
        on_response: ResponseCallback,
        result: Result<Vec<u8>, RequestError>,
    },
}

/// How an attempt ended at its requester.
enum AttemptEnd {
    /// The peer's answer arrived.
    Answered(Vec<u8>),
    /// The peer answered with an empty payload.
    Unusable,
    /// The peer serves the shard but has no handler for the request type,
    /// so it reset the stream, as the production inbound router does.
    Reset,
    /// The peer does not serve the shard, so it refused the stream's
    /// protocol.
    Unsupported,
    /// The timeout fired first.
    TimedOut,
}

impl AttemptEnd {
    /// The requester's backoff on its stream to the peer once an attempt
    /// whose request leg met `leg` ends this way, given the backoff it held.
    ///
    /// Mirrors the production request pool: an opened stream clears the
    /// series, so a stream that opened and then failed restarts it; an open
    /// that fails escalates it; a protocol refusal escalates on the
    /// unsupported series; and an attempt the fault gate took never touches
    /// it.
    fn stream_backoff(
        &self,
        leg: LegFate,
        held: Option<StreamBackoff<Duration>>,
        now: Duration,
    ) -> Option<StreamBackoff<Duration>> {
        match (self, leg) {
            (Self::Answered(_) | Self::Unusable, _) => None,
            (Self::Unsupported, _) => Some(StreamBackoff::after(
                held.as_ref(),
                StreamFailure::Unsupported,
                now,
            )),
            (Self::TimedOut, LegFate::Gated) => held,
            (Self::TimedOut, LegFate::Sent) => Some(StreamBackoff::after(
                held.as_ref(),
                StreamFailure::Transient,
                now,
            )),
            (Self::Reset | Self::TimedOut, _) => {
                Some(StreamBackoff::after(None, StreamFailure::Transient, now))
            }
        }
    }
}

/// A [`RequestEvent`] on the request heap, ordered by `(time, sequence)`.
struct ScheduledRequestEvent {
    time: Duration,
    sequence: u64,
    event: RequestEvent,
}

impl PartialEq for ScheduledRequestEvent {
    fn eq(&self, other: &Self) -> bool {
        (self.time, self.sequence) == (other.time, other.sequence)
    }
}
impl Eq for ScheduledRequestEvent {}

impl PartialOrd for ScheduledRequestEvent {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for ScheduledRequestEvent {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.time, self.sequence).cmp(&(other.time, other.sequence))
    }
}

/// One delivery the transport carried, recorded when it lands.
///
/// A record exists only for a message that survived partition, packet loss,
/// and the fault engine, so it describes a delivery that happened rather than
/// one that was attempted. `sent_at` and `delivered_at` are simulated-clock
/// instants — their difference is the latency this delivery drew, and neither
/// is BFT-attested time.
///
/// Gossip suppressed by a receiver's dedup produces no record: the transport
/// never schedules it, so there is no delivery to describe. Those are counted
/// in [`FulfillmentStats::messages_deduplicated`] instead.
#[derive(Debug, Clone)]
pub struct DeliveryRecord {
    /// Sending host.
    pub from: NodeIndex,
    /// Receiving host.
    pub to: NodeIndex,
    /// Message type identifier, shared by both legs of a request round trip —
    /// which leg this is shows in the direction.
    pub message_type: &'static str,
    /// Class of the sending type, carried from the send site.
    pub class: MessageClass,
    /// When the sender put it on the wire.
    pub sent_at: Duration,
    /// When the receiving handler runs.
    pub delivered_at: Duration,
    /// Shard the delivery was scoped to; `None` for globally scoped traffic
    /// and for request round trips, whose target shard is the committee's,
    /// not the message's.
    pub shard: Option<ShardId>,
    /// Encoded size on the wire.
    pub(crate) wire_bytes: usize,
}

/// Per-class totals over a drain interval, indexed by `MessageClass as usize`.
///
/// Exact, unlike the sampled records beside them: a consumer that thins the
/// records for display still reports true volume.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ClassTally {
    /// Deliveries carried.
    pub deliveries: u64,
    /// Bytes carried.
    pub bytes: u64,
}

/// Everything the delivery log accumulated since the last drain.
#[derive(Debug, Default, Clone)]
pub struct DeliveryDrain {
    /// Records retained, oldest first, bounded by the log's capacity.
    pub records: Vec<DeliveryRecord>,
    /// Records the capacity forced out. A consumer that displays the sample
    /// reports this rather than letting a thinned view read as a quiet
    /// network.
    pub dropped: u64,
    /// Exact totals, one entry per [`MessageClass`], covering dropped
    /// records as well as retained ones.
    pub by_class: [ClassTally; MessageClass::COUNT],
}

/// A bounded, opt-in record of what the transport delivered.
///
/// Off unless a harness asks for it, because the default simulation suite
/// pays for it on every delivery and reads none of it. Recording appends and
/// tallies; it draws no randomness and reads no simulation state, so a seeded
/// run is byte-identical whether or not the log is on.
#[derive(Debug, Default)]
struct DeliveryLog {
    capacity: usize,
    records: VecDeque<DeliveryRecord>,
    dropped: u64,
    by_class: [ClassTally; MessageClass::COUNT],
}

impl DeliveryLog {
    fn record(&mut self, record: DeliveryRecord) {
        if self.capacity == 0 {
            return;
        }
        let tally = &mut self.by_class[record.class as usize];
        tally.deliveries += 1;
        tally.bytes += record.wire_bytes as u64;
        if self.records.len() == self.capacity {
            self.records.pop_front();
            self.dropped += 1;
        }
        self.records.push_back(record);
    }

    fn drain(&mut self) -> DeliveryDrain {
        DeliveryDrain {
            records: self.records.drain(..).collect(),
            dropped: std::mem::take(&mut self.dropped),
            by_class: std::mem::take(&mut self.by_class),
        }
    }
}

/// Simulated network for deterministic message delivery.
///
/// Supports:
/// - Configurable latency with jitter
/// - Packet loss: a dropped gossip or notification copy, a request or
///   response leg retransmitted a round trip late
/// - Per-requester stream backoff, as the production request pool keeps
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
    /// Every scheduled step of every open request.
    pending_requests: BinaryHeap<Reverse<ScheduledRequestEvent>>,
    /// Monotonic sequence counter for deterministic request event ordering.
    request_event_sequence: u64,
    /// Requests between their first dispatch and their result, by id.
    requests: BTreeMap<u64, InFlightRequest>,
    /// The last request id handed out.
    request_sequence: u64,
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
    /// Each requester's view of every peer it has asked, indexed by host,
    /// as each production host keeps its own.
    peer_health: Vec<PeerHealthBook<NodeIndex>>,
    /// Each requester's backoff on its `(peer, shard)` request streams,
    /// indexed by host. Learned only from how its own attempts end, as the
    /// production request pool learns it.
    stream_backoff: Vec<BTreeMap<(NodeIndex, ShardId), StreamBackoff<Duration>>>,
    /// Opt-in record of what was delivered, for harnesses that observe
    /// traffic rather than chain content. Inert until
    /// [`Self::enable_delivery_log`].
    deliveries: DeliveryLog,
    /// The last [`REPLAY_DEPTH`] gossip payloads carried, per topic: a
    /// replay reaches only a host subscribed to the topic it came on.
    gossip_carried: BTreeMap<(&'static str, Option<ShardId>), VecDeque<Carried>>,
    /// The last [`REPLAY_DEPTH`] notification payloads carried, per type.
    notifications_carried: BTreeMap<&'static str, VecDeque<Carried>>,
    /// Where hosts sit, when the config spreads them over regions.
    geography: Option<Geography>,
    /// Hosts whose process is down: nothing reaches them or leaves them,
    /// whatever the partitions say.
    down: BTreeSet<NodeIndex>,
}

impl std::fmt::Debug for SimulatedNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SimulatedNetwork")
            .field("config", &self.config)
            .field("blocked", &self.faults.block_count())
            .field("registries", &self.registries.len())
            .field("pending_gossip", &self.pending_gossip.len())
            .field("pending_notifications", &self.pending_notifications.len())
            .field("pending_requests", &self.pending_requests.len())
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
        let geography = config.regions.map(Geography::new);
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
            pending_requests: BinaryHeap::new(),
            request_event_sequence: 0,
            requests: BTreeMap::new(),
            request_sequence: 0,
            traffic_analyzer: None,
            validator_bindings: layout.validator_to_host,
            gossip_seen: (0..num_hosts).map(|_| HashSet::new()).collect(),
            faults: Engine::new(seed),
            peer_health: vec![PeerHealthBook::default(); num_hosts],
            stream_backoff: vec![BTreeMap::new(); num_hosts],
            deliveries: DeliveryLog::default(),
            gossip_carried: BTreeMap::new(),
            notifications_carried: BTreeMap::new(),
            geography,
            down: BTreeSet::new(),
        }
    }

    /// Start recording deliveries, retaining at most `capacity` records
    /// between drains.
    ///
    /// Everything beyond the capacity is counted, not kept: a caller that
    /// wants exact volume reads [`DeliveryDrain::by_class`], and a caller
    /// that wants individual deliveries gets the most recent `capacity` of
    /// them. Passing zero turns recording back off.
    pub const fn enable_delivery_log(&mut self, capacity: usize) {
        self.deliveries.capacity = capacity;
    }

    /// Take everything recorded since the last drain, resetting the log.
    pub fn drain_deliveries(&mut self) -> DeliveryDrain {
        self.deliveries.drain()
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

    /// Install a rewrite over the responses `host` serves for `type_id`.
    ///
    /// The byzantine seam: the host answers, and answers wrongly. A drop
    /// rule can only make it silent, which every fetch path already has a
    /// fallback for; what an evidence check is exercised by is a
    /// well-formed answer that says the wrong thing.
    pub fn rewrite_responses(
        &mut self,
        host: NodeIndex,
        type_id: &'static str,
        rewrite: Rewrite,
    ) -> RuleHandle {
        self.rewrite_outbound(host, type_id, Tier::Response, rewrite)
    }

    /// Install a rewrite over the notifications `host` unicasts for `type_id`.
    ///
    /// The closure is invoked once per recipient, so a stateful one
    /// equivocates — sending different bytes to different peers. That is the
    /// seam every vote, timeout and ready signal travels on, none of which a
    /// response rewrite can reach.
    pub fn rewrite_notifications(
        &mut self,
        host: NodeIndex,
        type_id: &'static str,
        rewrite: Rewrite,
    ) -> RuleHandle {
        self.rewrite_outbound(host, type_id, Tier::Notification, rewrite)
    }

    /// Install a rewrite over the gossip `host` broadcasts for `type_id`.
    ///
    /// Also invoked once per recipient. Dedup keys on the honest message id,
    /// so each recipient still admits exactly one of the diverging copies.
    pub fn rewrite_gossip(
        &mut self,
        host: NodeIndex,
        type_id: &'static str,
        rewrite: Rewrite,
    ) -> RuleHandle {
        self.rewrite_outbound(host, type_id, Tier::Gossip, rewrite)
    }

    /// The bytes `sender` actually delivers to `recipient`, after any rewrite
    /// installed on it. Called per recipient at each delivery seam, so a
    /// stateful rewrite equivocates.
    fn rewritten(
        &self,
        sender: NodeIndex,
        recipient: NodeIndex,
        type_id: &'static str,
        tier: Tier,
        payload: &[u8],
    ) -> Vec<u8> {
        self.faults.rewrite(
            &MessageContext {
                sender: HostId(sender),
                recipient: HostId(recipient),
                type_id,
                tier,
            },
            payload,
            payload.to_vec(),
        )
    }

    fn rewrite_outbound(
        &mut self,
        host: NodeIndex,
        type_id: &'static str,
        tier: Tier,
        rewrite: Rewrite,
    ) -> RuleHandle {
        self.faults.install_rewrite(
            &DropSpec {
                type_id: Some(type_id),
                from: Some(HostId(host)),
                tier: Some(tier),
                ..DropSpec::default()
            },
            rewrite,
        )
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
    pub(crate) fn is_partitioned(&self, from: NodeIndex, to: NodeIndex, now: Duration) -> bool {
        self.down.contains(&from)
            || self.down.contains(&to)
            || self.faults.is_blocked(HostId(from), HostId(to), now)
    }

    // ─── Process Crashes ───

    /// Take `node`'s process down: from now until [`Self::bring_up`],
    /// nothing reaches it and nothing it sent before going down lands.
    /// Everything the process held goes with it — the requests it was
    /// waiting on, the gossip it had seen, what it had learned of its
    /// peers — and its handlers with them, so the adapter a restarted
    /// process takes from [`Self::create_adapter`] starts empty.
    pub fn take_down(&mut self, node: NodeIndex) {
        let i = node as usize;
        self.down.insert(node);
        self.requests.retain(|_, request| request.requester != node);
        self.registries[i] = Arc::new(HandlerRegistry::new(BTreeSet::new()));
        self.gossip_seen[i].clear();
        self.peer_health[i] = PeerHealthBook::default();
        self.stream_backoff[i].clear();
    }

    /// Bring `node`'s process back up.
    pub fn bring_up(&mut self, node: NodeIndex) {
        self.down.remove(&node);
    }

    /// Whether `node`'s process is down.
    #[must_use]
    pub fn is_down(&self, node: NodeIndex) -> bool {
        self.down.contains(&node)
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

    /// Partition the two groups from each other (both directions) during
    /// each of `windows`, on the simulated clock.
    pub fn partition_groups_during(
        &mut self,
        group_a: &[NodeIndex],
        group_b: &[NodeIndex],
        windows: &[Range<Duration>],
    ) {
        for &a in group_a {
            for &b in group_b {
                for window in windows {
                    self.faults
                        .block_during(HostId(a), HostId(b), window.clone());
                    self.faults
                        .block_during(HostId(b), HostId(a), window.clone());
                }
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
    pub(crate) fn should_drop_packet(&self, rng: &mut ChaCha8Rng) -> bool {
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
    pub(crate) fn should_deliver(
        &self,
        from: NodeIndex,
        to: NodeIndex,
        now: Duration,
        bytes: usize,
        rng: &mut ChaCha8Rng,
    ) -> Option<Duration> {
        // A destination with no host (a hostless pool-extra validator) is
        // unreachable, same as a partitioned peer.
        if to as usize >= self.total_nodes() {
            return None;
        }

        // Check partition first (deterministic)
        if self.is_partitioned(from, to, now) {
            return None;
        }

        // Check packet loss (probabilistic but deterministic with seeded RNG)
        if self.should_drop_packet(rng) {
            return None;
        }

        // Message will be delivered - sample latency
        Some(self.sample_latency(from, to, bytes, rng))
    }

    /// Sample the latency of one delivery of `bytes` from `from` to `to`:
    /// the link's base plus uniform jitter, plus the payload's time on the
    /// wire where hosts sit in regions.
    pub(crate) fn sample_latency(
        &self,
        from: NodeIndex,
        to: NodeIndex,
        bytes: usize,
        rng: &mut ChaCha8Rng,
    ) -> Duration {
        let link = self
            .geography
            .as_ref()
            .map(|geography| geography.link(from, to));
        let base = link.map_or(self.config.latency, |link| link.base);

        let jitter_range = base.as_secs_f64() * self.config.jitter_fraction;
        let jitter = if jitter_range > 0.0 {
            rng.random_range(-jitter_range..jitter_range)
        } else {
            0.0
        };
        let latency_secs = (base.as_secs_f64() + jitter).max(0.001);
        let latency = Duration::from_secs_f64(latency_secs)
            + link.map_or(Duration::ZERO, |link| link.transmission(bytes));
        if self.config.spike_rate > 0.0 && rng.random::<f64>() < self.config.spike_rate {
            return latency.mul_f64(rng.random_range(10.0..50.0));
        }
        latency
    }

    /// Get all hosts (`IoLoop` indices) whose registry hosts `shard` — the
    /// reshape-aware peer pool the request and gossip paths route on.
    #[must_use]
    pub(crate) fn peers_in_shard(&self, shard: ShardId) -> Vec<NodeIndex> {
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
    pub(crate) fn all_nodes(&self) -> Vec<NodeIndex> {
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

    // ─── Requests ───

    /// Open each request: a host serving the target shard answers from its
    /// own handler first, as the production adapter does, and asks the
    /// committee only when that answer is empty. A request for the committee
    /// dispatches its first attempt at `now`; every later step is an event
    /// [`flush_requests`](Self::flush_requests) runs at its own time.
    pub fn accept_requests(
        &mut self,
        requester: NodeIndex,
        now: Duration,
        requests: Vec<PendingRequest>,
        streams: &mut LinkStreams,
    ) -> FulfillmentStats {
        let mut stats = FulfillmentStats::default();
        for request in requests {
            if let Some(bytes) = self.serve_locally(requester, &request) {
                self.schedule_request_event(
                    now,
                    RequestEvent::Settle {
                        on_response: request.on_response,
                        result: Ok(bytes),
                    },
                );
                continue;
            }
            let candidates: Vec<NodeIndex> = self
                .peers_in_shard(request.shard)
                .into_iter()
                .filter(|&peer| peer != requester)
                .collect();
            let preferred = request
                .preferred_peer
                .map(|validator| self.validator_to_node(validator));
            let Some(attempts) = Attempts::start(
                RetryConfig::default(),
                candidates,
                preferred,
                request.class,
                &self.peer_health[requester as usize],
                now,
                streams.picker(requester),
            ) else {
                self.schedule_request_event(
                    now + NO_PEERS_LATENCY,
                    RequestEvent::Settle {
                        on_response: request.on_response,
                        result: Err(RequestError::NoPeers),
                    },
                );
                continue;
            };
            self.request_sequence += 1;
            let id = self.request_sequence;
            self.requests.insert(
                id,
                InFlightRequest {
                    requester,
                    shard: request.shard,
                    type_id: request.type_id,
                    class: request.class,
                    response_class: request.response_class,
                    body: request.request_bytes,
                    on_response: request.on_response,
                    is_empty_response: request.is_empty_response,
                    attempts,
                    serial: 0,
                    open: None,
                },
            );
            self.dispatch(id, now, streams, &mut stats);
        }
        stats
    }

    /// What `requester`'s own handler answers `request` with, where the
    /// host serves the target shard and the answer is not empty in the
    /// request type's terms. No transport is involved, so no fault, loss or
    /// latency applies.
    fn serve_locally(&self, requester: NodeIndex, request: &PendingRequest) -> Option<Vec<u8>> {
        let registry = self.registries.get(requester as usize)?;
        if !registry.hosted_shards().contains(&request.shard) {
            return None;
        }
        let handler = registry.get_request(request.type_id, request.shard)?;
        Some(handler(&request.request_bytes)).filter(|bytes| !(request.is_empty_response)(bytes))
    }

    /// Run every request event due by `now`: attempts dispatched, request
    /// legs arriving at their peers, answers and timeouts resolving attempts,
    /// and final results handed to their requesters. Returns how many
    /// requesters were answered, and what the legs sent and dropped.
    pub fn flush_requests(
        &mut self,
        now: Duration,
        streams: &mut LinkStreams,
    ) -> (usize, FulfillmentStats) {
        let mut stats = FulfillmentStats::default();
        let mut answered = 0;
        while let Some(Reverse(next)) = self.pending_requests.peek() {
            if next.time > now {
                break;
            }
            let Some(Reverse(ScheduledRequestEvent { time, event, .. })) =
                self.pending_requests.pop()
            else {
                break;
            };
            match event {
                RequestEvent::Dispatch { request } => {
                    self.dispatch(request, time, streams, &mut stats);
                }
                RequestEvent::Arrive {
                    request,
                    attempt,
                    leg,
                } => {
                    if self.lands(leg, &mut stats) {
                        self.arrive(request, attempt, time, streams, &mut stats);
                    }
                }
                RequestEvent::Answer {
                    request,
                    attempt,
                    leg,
                    end,
                } => {
                    if !self.lands(leg, &mut stats) {
                        continue;
                    }
                    answered += self.resolve(request, attempt, end, time, streams);
                }
                RequestEvent::Timeout { request, attempt } => {
                    answered += self.resolve(request, attempt, AttemptEnd::TimedOut, time, streams);
                }
                RequestEvent::Settle {
                    on_response,
                    result,
                } => {
                    let _ = on_response(result);
                    answered += 1;
                }
            }
        }
        (answered, stats)
    }

    /// Send `request`'s next attempt to a peer whose stream is not backing
    /// off: arm its timeout, and put the request leg on the wire unless a
    /// partition or a fault rule takes it. A lost packet delays the leg by a
    /// retransmission round trip rather than dropping it. Fault rules gate
    /// the request leg only, as the libp2p gate in
    /// `RequestStreamPool::send_request` does. With every candidate's stream
    /// backing off, the request settles [`RequestError::BackingOff`] at
    /// once, as the production request manager's does: the wait until the
    /// soonest stream reopens is the caller's pacing, and it is never zero.
    fn dispatch(
        &mut self,
        request: u64,
        now: Duration,
        streams: &mut LinkStreams,
        stats: &mut FulfillmentStats,
    ) {
        let Some(open) = self.requests.get_mut(&request) else {
            return;
        };
        let (requester, shard) = (open.requester, open.shard);
        let backoff = &self.stream_backoff[requester as usize];
        let dispatched = open.attempts.dispatch(
            |peer| {
                backoff
                    .get(&(peer, shard))
                    .and_then(|state| state.held_for(now))
            },
            &mut self.peer_health[requester as usize],
            now,
            streams.picker(requester),
        );
        let (peer, timeout) = match dispatched {
            Ok(dispatched) => dispatched,
            Err(AllHeld { retry_in }) => {
                trace!(
                    requester,
                    ?retry_in,
                    "Request settled: every stream backing off"
                );
                if let Some(open) = self.requests.remove(&request) {
                    self.schedule_request_event(
                        now,
                        RequestEvent::Settle {
                            on_response: open.on_response,
                            result: Err(RequestError::BackingOff { retry_in }),
                        },
                    );
                }
                return;
            }
        };
        open.serial += 1;
        let attempt = open.serial;
        open.open = Some(OpenAttempt {
            serial: attempt,
            sent_at: now,
            leg: LegFate::Sent,
        });
        let (type_id, class, body_len) = (open.type_id, open.class, open.body.len());
        self.schedule_request_event(now + timeout, RequestEvent::Timeout { request, attempt });

        if self.is_partitioned(requester, peer, now) {
            stats.messages_dropped_partition += 1;
            trace!(requester, peer, "Request dropped: partition");
            return;
        }
        let lost = self.should_drop_packet(streams.link(requester, peer));
        if self.faults.decide(
            &MessageContext {
                sender: HostId(requester),
                recipient: HostId(peer),
                type_id,
                tier: Tier::Request,
            },
            now,
        ) == Decision::Drop
        {
            stats.messages_dropped_fault += 1;
            trace!(requester, peer, type_id, "Request dropped: fault rule");
            if let Some(attempt) = self
                .requests
                .get_mut(&request)
                .and_then(|open| open.open.as_mut())
            {
                attempt.leg = LegFate::Gated;
            }
            return;
        }
        let mut latency =
            self.sample_latency(requester, peer, body_len, streams.link(requester, peer));
        if lost {
            stats.messages_retransmitted += 1;
            trace!(requester, peer, "Request leg retransmitted: packet loss");
            latency += self.retransmission_delay(requester, peer, streams);
        }
        stats.messages_sent += 1;
        if let Some(ref analyzer) = self.traffic_analyzer {
            analyzer.record_message(type_id, body_len, body_len, requester, peer);
        }
        let leg = DeliveryRecord {
            from: requester,
            to: peer,
            message_type: type_id,
            class,
            sent_at: now,
            delivered_at: now + latency,
            shard: None,
            wire_bytes: body_len,
        };
        self.schedule_request_leg(request, attempt, leg, streams);
    }

    /// Schedule `attempt`'s request `leg` to arrive when it says. A
    /// duplicated request leg reaches the peer twice; whichever answer
    /// lands first resolves the attempt and the other is discarded.
    fn schedule_request_leg(
        &mut self,
        request: u64,
        attempt: u32,
        leg: DeliveryRecord,
        streams: &mut LinkStreams,
    ) {
        let (from, to) = (leg.from, leg.to);
        let echo = self.duplicates(streams.link(from, to)).then(|| {
            let latency = self.sample_latency(from, to, leg.wire_bytes, streams.link(from, to));
            DeliveryRecord {
                delivered_at: leg.sent_at + latency,
                ..leg.clone()
            }
        });
        for leg in std::iter::once(leg).chain(echo) {
            self.schedule_request_event(
                leg.delivered_at,
                RequestEvent::Arrive {
                    request,
                    attempt,
                    leg,
                },
            );
        }
    }

    /// An attempt's request leg reaches its peer: the peer's handler answers
    /// from its state now, and the answer starts back unless a partition
    /// takes it; a lost packet delays it by a retransmission round trip. A
    /// peer not serving the shard refuses the protocol, and one serving it
    /// without a handler for the type resets the stream. An attempt already
    /// resolved is skipped, since its answer could only be discarded.
    fn arrive(
        &mut self,
        request: u64,
        attempt: u32,
        now: Duration,
        streams: &mut LinkStreams,
        stats: &mut FulfillmentStats,
    ) {
        let Some(open) = self.requests.get_mut(&request) else {
            return;
        };
        let Some(open_attempt) = open.open.as_mut().filter(|open| open.serial == attempt) else {
            return;
        };
        open_attempt.leg = LegFate::Reached;
        let open = &*open;
        let (requester, peer) = (open.requester, open.attempts.peer());
        let (type_id, response_class) = (open.type_id, open.response_class);
        // The answering host's own bytes, before any rewrite installed on
        // it: a byzantine responder is one that answers wrongly, which is
        // the one thing a drop rule cannot model.
        let end = match self.registries.get(peer as usize) {
            Some(registry) if registry.hosted_shards().contains(&open.shard) => {
                match registry.get_request(type_id, open.shard) {
                    Some(handler) => {
                        let bytes = self.faults.rewrite(
                            &MessageContext {
                                sender: HostId(peer),
                                recipient: HostId(requester),
                                type_id,
                                tier: Tier::Response,
                            },
                            &open.body,
                            handler(&open.body),
                        );
                        if bytes.is_empty() {
                            AttemptEnd::Unusable
                        } else {
                            AttemptEnd::Answered(bytes)
                        }
                    }
                    None => AttemptEnd::Reset,
                }
            }
            _ => AttemptEnd::Unsupported,
        };

        if self.is_partitioned(peer, requester, now) {
            stats.messages_dropped_partition += 1;
            trace!(requester, peer, "Response dropped: partition");
            return;
        }
        let lost = self.should_drop_packet(streams.link(peer, requester));
        let wire_bytes = match &end {
            AttemptEnd::Answered(bytes) => bytes.len(),
            _ => 0,
        };
        let mut latency =
            self.sample_latency(peer, requester, wire_bytes, streams.link(peer, requester));
        if lost {
            stats.messages_retransmitted += 1;
            trace!(requester, peer, "Response leg retransmitted: packet loss");
            latency += self.retransmission_delay(peer, requester, streams);
        }
        stats.messages_sent += 1;
        if let Some(ref analyzer) = self.traffic_analyzer {
            let response_type = format!("{type_id}.response");
            analyzer.record_message(&response_type, wire_bytes, wire_bytes, peer, requester);
        }
        let leg = DeliveryRecord {
            from: peer,
            to: requester,
            message_type: type_id,
            class: response_class,
            sent_at: now,
            delivered_at: now + latency,
            shard: None,
            wire_bytes,
        };
        self.schedule_request_event(
            now + latency,
            RequestEvent::Answer {
                request,
                attempt,
                leg,
                end,
            },
        );
    }

    /// What a leg from `from` to `to` that lost a packet waits for the
    /// stream to retransmit it: one more round trip on that link, about
    /// what QUIC's loss detection costs before it resends.
    fn retransmission_delay(
        &self,
        from: NodeIndex,
        to: NodeIndex,
        streams: &mut LinkStreams,
    ) -> Duration {
        self.sample_latency(from, to, 0, streams.link(from, to))
            + self.sample_latency(to, from, 0, streams.link(to, from))
    }

    /// Resolve `attempt` of `request` by how it ended, unless it is no
    /// longer the open attempt: an answer after its timeout, or a timeout
    /// after its answer, is discarded. Returns 1 when the requester is
    /// answered now.
    fn resolve(
        &mut self,
        request: u64,
        attempt: u32,
        end: AttemptEnd,
        now: Duration,
        streams: &mut LinkStreams,
    ) -> usize {
        let Some(open) = self.requests.get_mut(&request) else {
            return 0;
        };
        let Some(OpenAttempt { sent_at, leg, .. }) =
            open.open.take_if(|open| open.serial == attempt)
        else {
            return 0;
        };
        let requester = open.requester;
        let stream = (open.attempts.peer(), open.shard);
        let backoff = &mut self.stream_backoff[requester as usize];
        let held = backoff.remove(&stream);
        if let Some(state) = end.stream_backoff(leg, held, now) {
            backoff.insert(stream, state);
        }
        let (outcome, bytes) = match end {
            AttemptEnd::Answered(bytes) => {
                let rtt = now.saturating_sub(sent_at);
                let outcome = if (open.is_empty_response)(&bytes) {
                    Outcome::Empty { rtt }
                } else {
                    Outcome::Answered { rtt }
                };
                (outcome, Some(bytes))
            }
            AttemptEnd::Unusable | AttemptEnd::Reset | AttemptEnd::Unsupported => {
                (Outcome::Failed, None)
            }
            AttemptEnd::TimedOut => (Outcome::TimedOut, None),
        };
        let resolution = open.attempts.resolve(
            outcome,
            &mut self.peer_health[requester as usize],
            now,
            streams.picker(requester),
        );
        match resolution {
            Resolution::Retry { after } => {
                self.schedule_request_event(now + after, RequestEvent::Dispatch { request });
                0
            }
            Resolution::Exhausted { attempts, after } => {
                if let Some(open) = self.requests.remove(&request) {
                    self.schedule_request_event(
                        now + after,
                        RequestEvent::Settle {
                            on_response: open.on_response,
                            result: Err(RequestError::Exhausted { attempts }),
                        },
                    );
                }
                0
            }
            Resolution::Done => {
                let (Some(open), Some(bytes)) = (self.requests.remove(&request), bytes) else {
                    return 0;
                };
                let peer = open.attempts.peer();
                if (open.on_response)(Ok(bytes)) == ResponseVerdict::Reject {
                    self.peer_health[requester as usize].record_rejected(peer);
                }
                1
            }
        }
    }

    /// Whether a delivered copy on this link arrives twice.
    fn duplicates(&self, rng: &mut ChaCha8Rng) -> bool {
        self.config.duplicate_rate > 0.0 && rng.random::<f64>() < self.config.duplicate_rate
    }

    /// An old payload of `message_type` to bring along with a delivered
    /// copy on this link, sampled from `carried`.
    fn replayed<'a>(
        replay_rate: f64,
        carried: Option<&'a VecDeque<Carried>>,
        rng: &mut ChaCha8Rng,
    ) -> Option<&'a Carried> {
        if replay_rate <= 0.0 || rng.random::<f64>() >= replay_rate {
            return None;
        }
        let carried = carried.filter(|carried| !carried.is_empty())?;
        carried.get(rng.random_range(0..carried.len()))
    }

    /// Keep `carried` as one of the last [`REPLAY_DEPTH`] payloads under `key`.
    fn remember<K: Ord>(ring: &mut BTreeMap<K, VecDeque<Carried>>, key: K, carried: Carried) {
        let kept = ring.entry(key).or_default();
        if kept.len() == REPLAY_DEPTH {
            kept.pop_front();
        }
        kept.push_back(carried);
    }

    /// The echoes of a gossip copy just scheduled from `from` to `to`: a
    /// duplicate past the dedup set, and a replayed old payload of its
    /// topic, each at the configured rate and with its own latency. Then
    /// `carried` joins its topic's replay ring.
    fn echo_gossip(
        &mut self,
        from: NodeIndex,
        to: NodeIndex,
        now: Duration,
        message_type: &'static str,
        carried: Carried,
        streams: &mut LinkStreams,
    ) {
        if self.config.duplicate_rate <= 0.0 && self.config.replay_rate <= 0.0 {
            return;
        }
        let link = streams.link(from, to);
        let duplicate = self.duplicates(link);
        let topic = (message_type, carried.shard);
        let replay = Self::replayed(
            self.config.replay_rate,
            self.gossip_carried.get(&topic),
            link,
        )
        .map(|old| (old.payload.clone(), old.shard, old.class, old.wire_bytes));
        let echoes = duplicate
            .then(|| {
                (
                    carried.payload.clone(),
                    carried.shard,
                    carried.class,
                    carried.wire_bytes,
                )
            })
            .into_iter()
            .chain(replay);
        for (payload, shard, class, wire_bytes) in echoes {
            let latency = self.sample_latency(from, to, wire_bytes, streams.link(from, to));
            self.gossip_sequence += 1;
            self.pending_gossip.push(Reverse(ScheduledGossip {
                sequence: self.gossip_sequence,
                record: DeliveryRecord {
                    from,
                    to,
                    message_type,
                    class,
                    sent_at: now,
                    delivered_at: now + latency,
                    shard,
                    wire_bytes,
                },
                msg_id: None,
                payload,
            }));
        }
        Self::remember(&mut self.gossip_carried, topic, carried);
    }

    /// As [`Self::echo_gossip`], for a notification.
    fn echo_notification(
        &mut self,
        from: NodeIndex,
        to: NodeIndex,
        now: Duration,
        message_type: &'static str,
        carried: Carried,
        streams: &mut LinkStreams,
    ) {
        if self.config.duplicate_rate <= 0.0 && self.config.replay_rate <= 0.0 {
            return;
        }
        let link = streams.link(from, to);
        let duplicate = self.duplicates(link);
        let replay = Self::replayed(
            self.config.replay_rate,
            self.notifications_carried.get(message_type),
            link,
        )
        .map(|old| (old.payload.clone(), old.class, old.wire_bytes));
        let echoes = duplicate
            .then(|| (carried.payload.clone(), carried.class, carried.wire_bytes))
            .into_iter()
            .chain(replay);
        for (payload, class, wire_bytes) in echoes {
            let latency = self.sample_latency(from, to, wire_bytes, streams.link(from, to));
            self.notification_sequence += 1;
            self.pending_notifications
                .push(Reverse(ScheduledNotification {
                    sequence: self.notification_sequence,
                    record: DeliveryRecord {
                        from,
                        to,
                        message_type,
                        class,
                        sent_at: now,
                        delivered_at: now + latency,
                        shard: None,
                        wire_bytes,
                    },
                    payload,
                }));
        }
        Self::remember(&mut self.notifications_carried, message_type, carried);
    }

    /// Whether a leg on the wire reaches its recipient: a partition
    /// installed while it was in flight takes it. A leg that lands is
    /// logged.
    fn lands(&mut self, leg: DeliveryRecord, stats: &mut FulfillmentStats) -> bool {
        if self.is_partitioned(leg.from, leg.to, leg.delivered_at) {
            stats.messages_dropped_partition += 1;
            trace!(from = leg.from, to = leg.to, "Dropped in flight: partition");
            return false;
        }
        self.deliveries.record(leg);
        true
    }

    fn schedule_request_event(&mut self, time: Duration, event: RequestEvent) {
        self.request_event_sequence += 1;
        self.pending_requests.push(Reverse(ScheduledRequestEvent {
            time,
            sequence: self.request_event_sequence,
            event,
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
        streams: &mut LinkStreams,
    ) -> FulfillmentStats {
        let mut stats = FulfillmentStats::default();

        for notification in notifications {
            let PendingNotification {
                recipients,
                type_id,
                class,
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

                match self.should_deliver(sender, to, now, data.len(), streams.link(sender, to)) {
                    None => {
                        if self.is_partitioned(sender, to, now) {
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
                        // The sender's own bytes, before any rewrite installed
                        // on it: a byzantine sender is one that notifies
                        // wrongly, which is the one thing a drop rule cannot
                        // model. Rewriting inside the recipient loop is what
                        // lets one sender equivocate across its peers.
                        let payload =
                            self.rewritten(sender, to, type_id, Tier::Notification, &payload);
                        stats.messages_sent += 1;
                        if let Some(ref analyzer) = self.traffic_analyzer {
                            analyzer.record_message(type_id, payload.len(), data.len(), sender, to);
                        }
                        self.notification_sequence += 1;
                        self.pending_notifications
                            .push(Reverse(ScheduledNotification {
                                sequence: self.notification_sequence,
                                record: DeliveryRecord {
                                    from: sender,
                                    to,
                                    message_type: type_id,
                                    class,
                                    sent_at: now,
                                    delivered_at: now + latency,
                                    shard: None,
                                    wire_bytes: data.len(),
                                },
                                payload: payload.clone(),
                            }));
                        let carried = Carried {
                            payload,
                            shard: None,
                            class,
                            wire_bytes: data.len(),
                        };
                        self.echo_notification(sender, to, now, type_id, carried, streams);
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
        streams: &mut LinkStreams,
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

        let msg_id = gossip_message_id(&entry);

        for to in peers {
            if to == from {
                continue;
            }

            // Gossipsub dedup: each node receives a given message at most once,
            // regardless of how many validators broadcast it. Only a delivered
            // copy is seen: one lost to a partition, packet loss or a drop
            // rule leaves the node free to take another broadcaster's
            // identical copy, as a mesh peer's forward would reach it.
            if self.gossip_seen[to as usize].contains(&msg_id) {
                stats.messages_deduplicated += 1;
                continue;
            }

            match self.should_deliver(from, to, now, entry.data.len(), streams.link(from, to)) {
                None => {
                    if self.is_partitioned(from, to, now) {
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
                    // As on the notification tier: a byzantine broadcaster
                    // publishes different bytes to different peers, and the
                    // gossipsub dedup above keys on the honest message id, so
                    // each recipient still admits exactly one of them.
                    let payload = self.rewritten(from, to, message_type, Tier::Gossip, &payload);
                    self.gossip_seen[to as usize].insert(msg_id);
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
                        sequence: self.gossip_sequence,
                        record: DeliveryRecord {
                            from,
                            to,
                            message_type,
                            class: entry.class,
                            sent_at: now,
                            delivered_at: now + latency,
                            shard,
                            wire_bytes: entry.data.len(),
                        },
                        msg_id: Some(msg_id),
                        payload: payload.clone(),
                    }));
                    let carried = Carried {
                        payload,
                        shard,
                        class: entry.class,
                        wire_bytes: entry.data.len(),
                    };
                    self.echo_gossip(from, to, now, message_type, carried, streams);
                }
            }
        }

        stats
    }

    /// Deliver all pending gossip with `delivery_time <= now`.
    ///
    /// Calls each target node's registered `GossipHandler`. A copy whose edge
    /// a partition blocked while it was in flight is dropped, and its
    /// recipient may take another broadcaster's copy. Returns the number of
    /// messages delivered and what was dropped in flight.
    pub fn flush_gossip(&mut self, now: Duration) -> (usize, FulfillmentStats) {
        let mut stats = FulfillmentStats::default();
        let Self {
            pending_gossip,
            registries,
            faults,
            gossip_seen,
            deliveries,
            down,
            ..
        } = self;
        let delivered = flush_heap(pending_gossip, now, |scheduled| {
            let ScheduledGossip {
                record,
                msg_id,
                payload,
                ..
            } = scheduled;
            let (to, message_type, shard) = (record.to, record.message_type, record.shard);
            if down.contains(&record.from)
                || down.contains(&to)
                || faults.is_blocked(HostId(record.from), HostId(to), record.delivered_at)
            {
                stats.messages_dropped_partition += 1;
                if let Some(msg_id) = msg_id {
                    gossip_seen[to as usize].remove(&msg_id);
                }
                return false;
            }
            deliveries.record(record);
            let Some(registry) = registries.get(to as usize) else {
                debug!(
                    target_node = to,
                    message_type, "No registry for target node, dropping gossip"
                );
                return false;
            };
            let gossip = registry.get_gossip(message_type);
            // A Global broadcast (no topic shard) also reaches a shard-less
            // host's beacon follower pool; shard-scoped deliveries never do.
            let host_handler = if shard.is_none() {
                registry.get_host_gossip(message_type)
            } else {
                None
            };
            match (gossip, host_handler) {
                (Some(gossip), Some(host_handler)) => {
                    let _ = gossip(payload.clone(), shard);
                    host_handler(payload);
                    true
                }
                (Some(gossip), None) => {
                    let _ = gossip(payload, shard);
                    true
                }
                (None, Some(host_handler)) => {
                    host_handler(payload);
                    true
                }
                (None, None) => {
                    debug!(
                        target_node = to,
                        message_type, "No gossip handler for message type on target node, dropping"
                    );
                    false
                }
            }
        });
        (delivered, stats)
    }

    /// Earliest pending gossip delivery time (for event loop scheduling).
    #[must_use]
    pub(crate) fn next_gossip_delivery_time(&self) -> Option<Duration> {
        self.pending_gossip
            .peek()
            .map(|Reverse(s)| s.delivery_time())
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
    /// Calls each target node's registered notification handler, dropping a
    /// notification whose edge a partition blocked while it was in flight.
    /// Returns the number delivered and what was dropped in flight.
    pub fn flush_notifications(&mut self, now: Duration) -> (usize, FulfillmentStats) {
        let mut stats = FulfillmentStats::default();
        let Self {
            pending_notifications,
            registries,
            faults,
            deliveries,
            down,
            ..
        } = self;
        let delivered = flush_heap(pending_notifications, now, |scheduled| {
            let ScheduledNotification {
                record, payload, ..
            } = scheduled;
            let (to, message_type) = (record.to, record.message_type);
            if down.contains(&record.from)
                || down.contains(&to)
                || faults.is_blocked(HostId(record.from), HostId(to), record.delivered_at)
            {
                stats.messages_dropped_partition += 1;
                return false;
            }
            deliveries.record(record);
            let Some(handler) = registries
                .get(to as usize)
                .and_then(|r| r.get_notification(message_type))
            else {
                debug!(
                    target_node = to,
                    message_type,
                    "No notification handler for message type on target node, dropping"
                );
                return false;
            };
            handler(payload);
            true
        });
        (delivered, stats)
    }

    /// Earliest pending notification delivery time.
    #[must_use]
    pub(crate) fn next_notification_delivery_time(&self) -> Option<Duration> {
        self.pending_notifications
            .peek()
            .map(|Reverse(s)| s.delivery_time())
    }

    // ─── Unified Delivery Time ───

    /// Earliest pending delivery time across gossip, notifications, and request events.
    #[must_use]
    pub fn next_delivery_time(&self) -> Option<Duration> {
        [
            self.next_gossip_delivery_time(),
            self.next_notification_delivery_time(),
            self.pending_requests.peek().map(|Reverse(next)| next.time),
        ]
        .into_iter()
        .flatten()
        .min()
    }
}

/// The content-based message id gossipsub dedups on, matching production's
/// `message_id_fn`: hash(data || topic).
///
/// Wire bytes (compressed) are the data; the topic is the message type and the
/// shard it is published to, since a shard-scoped type has one topic per shard
/// and a host serving two of them is owed the same batch once on each — a
/// transaction touching both shards is published to both, and the second copy
/// is what the other shard's loop admits from.
fn gossip_message_id(entry: &OutboxEntry) -> u64 {
    let mut hasher = Blake3Hasher::new();
    hasher.update(entry.message_type.as_bytes());
    match entry.target {
        BroadcastTarget::Shard(shard) => {
            hasher.update(&[1]);
            hasher.update(&shard.depth().to_le_bytes());
            hasher.update(&shard.path().to_le_bytes());
        }
        BroadcastTarget::Global => {
            hasher.update(&[0]);
        }
    }
    hasher.update(&entry.data);
    let digest = hasher.finalize();
    let mut id = [0u8; 8];
    id.copy_from_slice(&digest.as_bytes()[..8]);
    u64::from_le_bytes(id)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering as AtomicOrdering};

    use hyperscale_hbor::Capped;
    use hyperscale_network::retry::stream_timeout;
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
    fn test_hyperscale_latency() {
        let network = sim_network(2, 4);
        let mut rng1 = ChaCha8Rng::seed_from_u64(42);
        let mut rng2 = ChaCha8Rng::seed_from_u64(42);

        let latency1 = network.sample_latency(0, 1, 0, &mut rng1);
        let latency2 = network.sample_latency(0, 1, 0, &mut rng2);

        assert_eq!(latency1, latency2, "Same seed should produce same latency");
    }

    // ─── Partition Tests ───

    #[test]
    fn test_unidirectional_partition() {
        let mut network = sim_network(2, 4);

        // No partition initially
        assert!(!network.is_partitioned(0, 1, Duration::ZERO));
        assert!(!network.is_partitioned(1, 0, Duration::ZERO));

        // Create unidirectional partition: 0 -> 1 blocked
        network.partition_unidirectional(0, 1);

        assert!(network.is_partitioned(0, 1, Duration::ZERO));
        assert!(!network.is_partitioned(1, 0, Duration::ZERO)); // Reverse direction still works

        // Heal
        network.heal_unidirectional(0, 1);
        assert!(!network.is_partitioned(0, 1, Duration::ZERO));
    }

    #[test]
    fn test_bidirectional_partition() {
        let mut network = sim_network(2, 4);

        network.partition_bidirectional(0, 1);

        assert!(network.is_partitioned(0, 1, Duration::ZERO));
        assert!(network.is_partitioned(1, 0, Duration::ZERO));

        network.heal_bidirectional(0, 1);
        assert!(!network.is_partitioned(0, 1, Duration::ZERO));
        assert!(!network.is_partitioned(1, 0, Duration::ZERO));
    }

    #[test]
    fn test_group_partition() {
        let mut network = sim_network(2, 2);

        // Partition shard 0 (nodes 0,1) from shard 1 (nodes 2,3)
        let group_a = vec![0, 1];
        let group_b = vec![2, 3];
        network.partition_groups(&group_a, &group_b);

        // All cross-group pairs should be partitioned
        assert!(network.is_partitioned(0, 2, Duration::ZERO));
        assert!(network.is_partitioned(0, 3, Duration::ZERO));
        assert!(network.is_partitioned(1, 2, Duration::ZERO));
        assert!(network.is_partitioned(1, 3, Duration::ZERO));
        assert!(network.is_partitioned(2, 0, Duration::ZERO));
        assert!(network.is_partitioned(3, 1, Duration::ZERO));

        // Intra-group should still work
        assert!(!network.is_partitioned(0, 1, Duration::ZERO));
        assert!(!network.is_partitioned(2, 3, Duration::ZERO));

        // Heal all
        network.heal_all();
        assert_eq!(network.partition_count(), 0);
    }

    #[test]
    fn test_isolate_node() {
        let mut network = sim_network(1, 4);

        network.isolate_node(0);

        // Node 0 can't communicate with anyone
        assert!(network.is_partitioned(0, 1, Duration::ZERO));
        assert!(network.is_partitioned(0, 2, Duration::ZERO));
        assert!(network.is_partitioned(0, 3, Duration::ZERO));
        assert!(network.is_partitioned(1, 0, Duration::ZERO));
        assert!(network.is_partitioned(2, 0, Duration::ZERO));
        assert!(network.is_partitioned(3, 0, Duration::ZERO));

        // Other nodes can still communicate
        assert!(!network.is_partitioned(1, 2, Duration::ZERO));
        assert!(!network.is_partitioned(2, 3, Duration::ZERO));
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
        assert!(
            network
                .should_deliver(0, 1, Duration::ZERO, 0, &mut rng)
                .is_some()
        );

        // Partition blocks delivery
        network.partition_bidirectional(0, 1);
        assert!(
            network
                .should_deliver(0, 1, Duration::ZERO, 0, &mut rng)
                .is_none()
        );
        assert!(
            network
                .should_deliver(1, 0, Duration::ZERO, 0, &mut rng)
                .is_none()
        );

        // Other routes still work
        assert!(
            network
                .should_deliver(0, 2, Duration::ZERO, 0, &mut rng)
                .is_some()
        );
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
            assert!(
                network
                    .should_deliver(0, 1, Duration::ZERO, 0, &mut rng)
                    .is_none()
            );
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
        assert!(
            network
                .should_deliver(0, 1, Duration::ZERO, 0, &mut rng)
                .is_none()
        );
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
            class: MessageClass::Recovery,
            response_class: MessageClass::Recovery,
            request_bytes: vec![1, 2, 3],
            is_empty_response: <[u8]>::is_empty,
            on_response: Box::new(move |r| {
                *result_clone.lock().unwrap() = Some(r);
                ResponseVerdict::Accept
            }),
        };
        (request, result)
    }

    /// Run every request event, however far ahead, returning what the legs
    /// sent and dropped.
    fn settle(network: &mut SimulatedNetwork, streams: &mut LinkStreams) -> FulfillmentStats {
        network.flush_requests(FAR_FUTURE, streams).1
    }

    #[test]
    fn test_accept_requests_happy_path() {
        let mut network = sim_network(1, 4);
        host_shard_everywhere(&network, ShardId::leaf(1, 0));
        let mut streams = LinkStreams::new(42);

        let adapter1 = network.create_adapter(1);
        register_echo(&adapter1, "test.request", ShardId::leaf(1, 0));

        let (request, result) =
            make_request_with_capture(ShardId::leaf(1, 0), Some(ValidatorId::new(1)));

        let sent = network.accept_requests(0, Duration::ZERO, vec![request], &mut streams);
        assert_eq!(sent.messages_sent, 1, "the request leg");
        assert!(result.lock().unwrap().is_none());

        let answered = settle(&mut network, &mut streams);
        assert_eq!(answered.messages_sent, 1, "the response leg");
        assert_eq!(answered.messages_dropped_partition, 0);
        assert_eq!(answered.messages_dropped_loss, 0);

        let captured = result.lock().unwrap().take().unwrap();
        assert!(captured.is_ok());
    }

    #[test]
    fn test_accept_requests_rotates_around_partitioned_peer() {
        let mut network = sim_network(1, 4);
        host_shard_everywhere(&network, ShardId::leaf(1, 0));
        let mut streams = LinkStreams::new(42);

        // Every peer can serve; only the preferred one is unreachable. The
        // requester serves nothing itself, so every attempt crosses the wire.
        for i in 1..4 {
            let adapter = network.create_adapter(i);
            register_echo(&adapter, "test.request", ShardId::leaf(1, 0));
        }
        network.partition_unidirectional(0, 1);

        let (request, result) =
            make_request_with_capture(ShardId::leaf(1, 0), Some(ValidatorId::new(1)));
        let first = network.accept_requests(0, Duration::ZERO, vec![request], &mut streams);
        let rest = settle(&mut network, &mut streams);

        // Node 1 is tried `retries_before_rotation` times, both cut, then the
        // request rotates to a live peer and succeeds.
        assert_eq!(
            first.messages_dropped_partition + rest.messages_dropped_partition,
            u64::from(RetryConfig::default().retries_before_rotation)
        );
        assert_eq!(rest.messages_sent, 2);
        let captured = result.lock().unwrap().take().unwrap();
        assert!(captured.is_ok());
    }

    /// The answer's way back is cut, not the request's: the peer serves the
    /// request, its answer is lost, and the requester times out and rotates.
    #[test]
    fn a_request_whose_answer_is_cut_times_out_and_rotates() {
        let mut network = sim_network(1, 4);
        host_shard_everywhere(&network, ShardId::leaf(1, 0));
        let mut streams = LinkStreams::new(42);
        let served = Arc::new(AtomicU32::new(0));
        for i in 1..4 {
            let served = Arc::clone(&served);
            let handler: Arc<RawRequestHandler> = Arc::new(move |payload: &[u8]| -> Vec<u8> {
                served.fetch_add(1, AtomicOrdering::Relaxed);
                payload.to_vec()
            });
            network.create_adapter(i).registry.register_raw_request(
                "test.request",
                ShardId::leaf(1, 0),
                handler,
            );
        }
        network.partition_unidirectional(1, 0);

        let (request, result) =
            make_request_with_capture(ShardId::leaf(1, 0), Some(ValidatorId::new(1)));
        network.accept_requests(0, Duration::ZERO, vec![request], &mut streams);
        let stats = settle(&mut network, &mut streams);

        let rotation = RetryConfig::default().retries_before_rotation;
        assert_eq!(stats.messages_dropped_partition, u64::from(rotation));
        assert_eq!(served.load(AtomicOrdering::Relaxed), rotation + 1);
        assert!(result.lock().unwrap().take().unwrap().is_ok());
    }

    /// A peer answers from its state when the request reaches it, not when
    /// the request was sent.
    #[test]
    fn a_peer_answers_from_its_state_when_the_request_arrives() {
        let mut network = sim_network(1, 4);
        host_shard_everywhere(&network, ShardId::leaf(1, 0));
        let mut streams = LinkStreams::new(42);
        let state = Arc::new(AtomicU32::new(1));
        let reader = Arc::clone(&state);
        let handler: Arc<RawRequestHandler> = Arc::new(move |_: &[u8]| -> Vec<u8> {
            vec![u8::try_from(reader.load(AtomicOrdering::Relaxed)).unwrap()]
        });
        network.create_adapter(1).registry.register_raw_request(
            "test.request",
            ShardId::leaf(1, 0),
            handler,
        );

        let (request, result) =
            make_request_with_capture(ShardId::leaf(1, 0), Some(ValidatorId::new(1)));
        network.accept_requests(0, Duration::ZERO, vec![request], &mut streams);
        state.store(7, AtomicOrdering::Relaxed);
        settle(&mut network, &mut streams);

        assert_eq!(result.lock().unwrap().take().unwrap().unwrap(), vec![7]);
    }

    /// A round trip longer than the cold timeout never answers in time: each
    /// answer lands after its attempt timed out and is discarded, the RTT
    /// estimate is never seeded, and the request exhausts.
    #[test]
    fn an_answer_after_its_attempt_timed_out_is_discarded() {
        let mut network = sim_network_cfg(
            NetworkConfig {
                latency: Duration::from_millis(1500),
                jitter_fraction: 0.0,
                ..Default::default()
            },
            1,
            4,
        );
        host_shard_everywhere(&network, ShardId::leaf(1, 0));
        let mut streams = LinkStreams::new(42);
        for i in 1..4 {
            register_echo(
                &network.create_adapter(i),
                "test.request",
                ShardId::leaf(1, 0),
            );
        }

        let (request, result) = make_request_with_capture(ShardId::leaf(1, 0), None);
        network.accept_requests(0, Duration::ZERO, vec![request], &mut streams);
        let (answered, _) = network.flush_requests(FAR_FUTURE, &mut streams);

        assert_eq!(answered, 1, "the requester hears once");
        assert!(matches!(
            result.lock().unwrap().take().unwrap(),
            Err(RequestError::Exhausted { .. })
        ));
    }

    /// An answer its requester rejects counts against the peer that gave it,
    /// so selection drifts toward the peer whose answers are kept.
    #[test]
    fn a_rejected_answer_counts_against_its_peer() {
        let mut network = sim_network(1, 3);
        host_shard_everywhere(&network, ShardId::leaf(1, 0));
        let mut streams = LinkStreams::new(42);
        for i in 1..3 {
            let marker = vec![u8::try_from(i).unwrap()];
            let handler: Arc<RawRequestHandler> =
                Arc::new(move |_: &[u8]| -> Vec<u8> { marker.clone() });
            network.create_adapter(i).registry.register_raw_request(
                "test.request",
                ShardId::leaf(1, 0),
                handler,
            );
        }

        let from_rejected = Arc::new(AtomicU32::new(0));
        for round in 0..400 {
            let counter = Arc::clone(&from_rejected);
            let request = PendingRequest {
                shard: ShardId::leaf(1, 0),
                preferred_peer: None,
                type_id: "test.request",
                class: MessageClass::Recovery,
                response_class: MessageClass::Recovery,
                request_bytes: vec![1],
                is_empty_response: <[u8]>::is_empty,
                on_response: Box::new(move |answer| {
                    if answer.unwrap() == vec![1] {
                        if round >= 200 {
                            counter.fetch_add(1, AtomicOrdering::Relaxed);
                        }
                        ResponseVerdict::Reject
                    } else {
                        ResponseVerdict::Accept
                    }
                }),
            };
            let now = Duration::from_secs(round);
            network.accept_requests(0, now, vec![request], &mut streams);
            network.flush_requests(now + Duration::from_secs(1), &mut streams);
        }

        let rejected = from_rejected.load(AtomicOrdering::Relaxed);
        assert!(
            rejected < 85,
            "the rejected peer answered {rejected} of the last 200"
        );
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
        let mut rng = LinkStreams::new(42);

        // The requester serves nothing itself, so every attempt crosses the
        // wire.
        for i in 1..4 {
            let adapter = network.create_adapter(i);
            register_echo(&adapter, "test.request", ShardId::leaf(1, 0));
        }

        // With 15 attempts at 50% loss, the odds of never getting a packet
        // through are ~0.003% — retrying the same peer recovers the request
        // instead of charging it a full exhaustion.
        let (request, result) = make_request_with_capture(ShardId::leaf(1, 0), None);
        network.accept_requests(0, Duration::ZERO, vec![request], &mut rng);
        settle(&mut network, &mut rng);
        let captured = result.lock().unwrap().take().unwrap();
        assert!(captured.is_ok());
    }

    /// A request rides a stream that retransmits: a lost packet on either
    /// leg costs that leg one more round trip, not the attempt's timeout.
    #[test]
    fn a_lost_leg_arrives_a_round_trip_late_without_timing_out() {
        let latency = Duration::from_millis(150);
        let mut network = sim_network_cfg(
            NetworkConfig {
                latency,
                jitter_fraction: 0.0,
                packet_loss_rate: 1.0,
                ..Default::default()
            },
            1,
            2,
        );
        host_shard_everywhere(&network, ShardId::leaf(1, 0));
        let mut streams = LinkStreams::new(42);
        register_echo(
            &network.create_adapter(1),
            "test.request",
            ShardId::leaf(1, 0),
        );

        let (request, result) =
            make_request_with_capture(ShardId::leaf(1, 0), Some(ValidatorId::new(1)));
        let first = network.accept_requests(0, Duration::ZERO, vec![request], &mut streams);

        // Each leg waits its own latency plus a retransmission round trip.
        let answered_at = latency * 6;
        let (early, rest) = network.flush_requests(
            answered_at.saturating_sub(Duration::from_millis(1)),
            &mut streams,
        );
        assert_eq!(early, 0);
        assert!(result.lock().unwrap().is_none());
        let (answered, last) = network.flush_requests(answered_at, &mut streams);
        assert_eq!(answered, 1);
        assert_eq!(
            result.lock().unwrap().take().unwrap().unwrap(),
            vec![1, 2, 3]
        );

        let retransmitted = first.messages_retransmitted
            + rest.messages_retransmitted
            + last.messages_retransmitted;
        let dropped =
            first.messages_dropped_loss + rest.messages_dropped_loss + last.messages_dropped_loss;
        assert_eq!(retransmitted, 2, "one per leg");
        assert_eq!(dropped, 0);
        assert_eq!(
            network.flush_requests(FAR_FUTURE, &mut streams).0,
            0,
            "no attempt timed out"
        );
    }

    /// Partition `requester` from `peer` and time an attempt out on it at
    /// the cold timeout, leaving that stream backing off for
    /// [`INITIAL_BACKOFF`](hyperscale_network::stream_backoff::INITIAL_BACKOFF).
    fn time_out_once_on(
        network: &mut SimulatedNetwork,
        streams: &mut LinkStreams,
        peer: ValidatorId,
    ) -> (SharedRequestResult, Duration) {
        network.partition_unidirectional(0, network.validator_to_node(peer));
        let (request, result) = make_request_with_capture(ShardId::leaf(1, 0), Some(peer));
        network.accept_requests(0, Duration::ZERO, vec![request], streams);
        let timed_out = stream_timeout(None);
        network.flush_requests(timed_out, streams);
        assert!(result.lock().unwrap().is_none());
        (result, timed_out)
    }

    /// A timeout backs the peer's stream off: a request dispatched while it
    /// holds goes to another peer, and one dispatched after it lapses asks
    /// the peer again.
    #[test]
    fn a_timed_out_peer_is_skipped_until_its_stream_backoff_lapses() {
        use hyperscale_network::stream_backoff::INITIAL_BACKOFF;

        let mut network = sim_network(1, 3);
        host_shard_everywhere(&network, ShardId::leaf(1, 0));
        let mut streams = LinkStreams::new(42);
        for i in 1..3 {
            register_echo(
                &network.create_adapter(i),
                "test.request",
                ShardId::leaf(1, 0),
            );
        }
        let (_, timed_out) = time_out_once_on(&mut network, &mut streams, ValidatorId::new(1));

        let (held, _) = make_request_with_capture(ShardId::leaf(1, 0), Some(ValidatorId::new(1)));
        let skipped = network.accept_requests(0, timed_out, vec![held], &mut streams);
        assert_eq!(skipped.messages_sent, 1, "sent to the other peer");
        assert_eq!(skipped.messages_dropped_partition, 0);

        let (lapsed, _) = make_request_with_capture(ShardId::leaf(1, 0), Some(ValidatorId::new(1)));
        let asked =
            network.accept_requests(0, timed_out + INITIAL_BACKOFF, vec![lapsed], &mut streams);
        assert_eq!(asked.messages_sent, 0);
        assert_eq!(
            asked.messages_dropped_partition, 1,
            "asked the partitioned peer"
        );
    }

    /// A peer that stopped serving the shard refuses the protocol, which
    /// backs its stream off on the long unsupported series rather than the
    /// transient one.
    #[test]
    fn a_peer_refusing_the_protocol_backs_off_on_the_unsupported_series() {
        use hyperscale_network::stream_backoff::UNSUPPORTED_INITIAL_BACKOFF;

        let mut network = sim_network(1, 3);
        let shard = ShardId::leaf(1, 0);
        host_shard_everywhere(&network, shard);
        let mut streams = LinkStreams::new(42);
        let register_marker = |network: &SimulatedNetwork, host: NodeIndex| {
            let marker = vec![u8::try_from(host).unwrap()];
            let handler: Arc<RawRequestHandler> =
                Arc::new(move |_: &[u8]| -> Vec<u8> { marker.clone() });
            network.create_adapter(host).registry.register_raw_request(
                "test.request",
                shard,
                handler,
            );
        };
        register_marker(&network, 1);
        register_marker(&network, 2);
        let mut ask_peer_one = |network: &mut SimulatedNetwork, at: Duration, unseat: bool| {
            let (request, result) = make_request_with_capture(shard, Some(ValidatorId::new(1)));
            network.accept_requests(0, at, vec![request], &mut streams);
            if unseat {
                network.create_adapter(1).unsubscribe_shard(shard);
            }
            network.flush_requests(at + Duration::from_secs(1), &mut streams);
            result.lock().unwrap().take().unwrap().unwrap()
        };

        // Peer 1 unseats while the request leg is on the wire.
        assert_eq!(ask_peer_one(&mut network, Duration::ZERO, true), vec![2]);
        network.create_adapter(1).subscribe_shard(shard);
        register_marker(&network, 1);

        // Well past any early step of the transient series, still inside
        // the unsupported one.
        assert_eq!(
            ask_peer_one(&mut network, Duration::from_secs(2), false),
            vec![2]
        );
        assert_eq!(
            ask_peer_one(
                &mut network,
                UNSUPPORTED_INITIAL_BACKOFF + Duration::from_secs(1),
                false
            ),
            vec![1]
        );
    }

    /// An attempt the fault gate takes times out without backing the
    /// stream off, as the libp2p gate fails it before the stream pool.
    #[test]
    fn a_fault_gated_timeout_leaves_the_stream_unbacked() {
        let mut network = sim_network(1, 3);
        let shard = ShardId::leaf(1, 0);
        host_shard_everywhere(&network, shard);
        let mut streams = LinkStreams::new(42);
        for host in 1..3 {
            let marker = vec![u8::try_from(host).unwrap()];
            let handler: Arc<RawRequestHandler> =
                Arc::new(move |_: &[u8]| -> Vec<u8> { marker.clone() });
            network.create_adapter(host).registry.register_raw_request(
                "test.request",
                shard,
                handler,
            );
        }
        let rule = network.fault().drop_type("test.request").install();
        let (gated, _) = make_request_with_capture(shard, Some(ValidatorId::new(1)));
        network.accept_requests(0, Duration::ZERO, vec![gated], &mut streams);
        let timed_out = stream_timeout(None);
        network.flush_requests(timed_out, &mut streams);
        assert!(network.fault().remove(&rule));

        let (request, result) = make_request_with_capture(shard, Some(ValidatorId::new(1)));
        network.accept_requests(0, timed_out, vec![request], &mut streams);
        network.flush_requests(timed_out + Duration::from_secs(1), &mut streams);
        assert_eq!(result.lock().unwrap().take().unwrap().unwrap(), vec![1]);
    }

    /// With every candidate's stream backing off, a request settles
    /// `BackingOff` at once with the wait until the soonest reopens,
    /// whether it is opening or already retrying.
    #[test]
    fn every_stream_backing_off_settles_with_the_soonest_reopening() {
        use hyperscale_network::stream_backoff::{BACKOFF_MULTIPLIER, INITIAL_BACKOFF};

        let mut network = sim_network(1, 2);
        host_shard_everywhere(&network, ShardId::leaf(1, 0));
        let mut streams = LinkStreams::new(42);
        register_echo(
            &network.create_adapter(1),
            "test.request",
            ShardId::leaf(1, 0),
        );
        let (retrying, timed_out) =
            time_out_once_on(&mut network, &mut streams, ValidatorId::new(1));

        let (opening, opened) = make_request_with_capture(ShardId::leaf(1, 0), None);
        let stats = network.accept_requests(0, timed_out, vec![opening], &mut streams);
        assert_eq!(stats.messages_sent + stats.messages_dropped_partition, 0);
        network.flush_requests(timed_out, &mut streams);
        assert!(matches!(
            opened.lock().unwrap().take(),
            Some(Err(RequestError::BackingOff { retry_in })) if retry_in == INITIAL_BACKOFF
        ));

        // The lone peer's backoff doubles on each timeout and outgrows the
        // request's own retry backoff, so the retrying request finds no
        // stream to send on and settles rather than waiting forever. Its
        // third timeout held the stream for the third step of the series.
        settle(&mut network, &mut streams);
        let third_step = INITIAL_BACKOFF * BACKOFF_MULTIPLIER * BACKOFF_MULTIPLIER;
        assert!(matches!(
            retrying.lock().unwrap().take(),
            Some(Err(RequestError::BackingOff { retry_in }))
                if !retry_in.is_zero() && retry_in < third_step
        ));
    }

    #[test]
    fn test_accept_requests_no_handler_anywhere_exhausts() {
        let mut network = sim_network(1, 4);
        host_shard_everywhere(&network, ShardId::leaf(1, 0));
        let mut rng = LinkStreams::new(42);

        // No peer registers a handler: every attempt is an application error
        // that rotates and ultimately exhausts.
        let (request, result) =
            make_request_with_capture(ShardId::leaf(1, 0), Some(ValidatorId::new(1)));
        network.accept_requests(0, Duration::ZERO, vec![request], &mut rng);

        assert!(result.lock().unwrap().is_none());
        settle(&mut network, &mut rng);
        let captured = result.lock().unwrap().take().unwrap();
        assert!(matches!(captured, Err(RequestError::Exhausted { .. })));
    }

    #[test]
    fn test_accept_requests_empty_response_exhausts() {
        let mut network = sim_network(1, 4);
        host_shard_everywhere(&network, ShardId::leaf(1, 0));
        let mut rng = LinkStreams::new(42);

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
        settle(&mut network, &mut rng);
        let captured = result.lock().unwrap().take().unwrap();
        assert!(matches!(captured, Err(RequestError::Exhausted { .. })));
    }

    #[test]
    fn test_accept_requests_random_peer_selection() {
        let mut network = sim_network(1, 4);
        host_shard_everywhere(&network, ShardId::leaf(1, 0));
        let mut rng = LinkStreams::new(42);

        // Register handlers on every peer; the requester serves nothing
        // itself, so the request crosses the wire.
        for i in 1..4 {
            let adapter = network.create_adapter(i);
            register_echo(&adapter, "test.request", ShardId::leaf(1, 0));
        }

        // No preferred peer — should pick a random peer from the shard
        // committee (validators 1..=3 after the requester at index 0
        // filters itself out).
        let (request, result) = make_request_with_capture(ShardId::leaf(1, 0), None);
        let sent = network.accept_requests(0, Duration::ZERO, vec![request], &mut rng);
        let answered = settle(&mut network, &mut rng);
        assert_eq!(sent.messages_sent + answered.messages_sent, 2);
        let captured = result.lock().unwrap().take().unwrap();
        assert!(captured.is_ok());
    }

    #[test]
    fn test_accept_requests_single_node_no_peers() {
        let mut network = sim_network(1, 1);
        let mut rng = LinkStreams::new(42);

        let adapter0 = network.create_adapter(0);
        register_echo(&adapter0, "test.request", ShardId::leaf(1, 0));

        // No preferred peer, and empty peer list
        let (request, result) = make_request_with_capture(ShardId::leaf(1, 0), None);
        network.accept_requests(0, Duration::ZERO, vec![request], &mut rng);

        // An empty committee surfaces `NoPeers` after the short discovery delay.
        assert!(result.lock().unwrap().is_none());
        settle(&mut network, &mut rng);
        let captured = result.lock().unwrap().take().unwrap();
        assert!(matches!(captured, Err(RequestError::NoPeers)));
    }

    /// A requester serving the shard answers from its own handler at once:
    /// nothing crosses the wire, and the answer lands at `now`.
    #[test]
    fn test_accept_requests_serves_a_hosted_shard_locally() {
        let mut network = sim_network(1, 4);
        host_shard_everywhere(&network, ShardId::leaf(1, 0));
        let mut rng = LinkStreams::new(42);
        for i in 0..4 {
            let adapter = network.create_adapter(i);
            register_echo(&adapter, "test.request", ShardId::leaf(1, 0));
        }

        let (request, result) =
            make_request_with_capture(ShardId::leaf(1, 0), Some(ValidatorId::new(1)));
        let stats = network.accept_requests(0, Duration::ZERO, vec![request], &mut rng);

        assert_eq!(stats.messages_sent, 0);
        network.flush_requests(Duration::ZERO, &mut rng);
        let captured = result.lock().unwrap().take().unwrap();
        assert_eq!(captured.unwrap(), vec![1, 2, 3]);
    }

    /// An empty local answer is no answer: the request goes on to the
    /// committee.
    #[test]
    fn test_accept_requests_asks_the_committee_past_an_empty_local_answer() {
        let mut network = sim_network(1, 4);
        host_shard_everywhere(&network, ShardId::leaf(1, 0));
        let mut rng = LinkStreams::new(42);
        let silent: Arc<RawRequestHandler> = Arc::new(|_: &[u8]| -> Vec<u8> { Vec::new() });
        network.create_adapter(0).registry.register_raw_request(
            "test.request",
            ShardId::leaf(1, 0),
            silent,
        );
        for i in 1..4 {
            let adapter = network.create_adapter(i);
            register_echo(&adapter, "test.request", ShardId::leaf(1, 0));
        }

        let (request, result) =
            make_request_with_capture(ShardId::leaf(1, 0), Some(ValidatorId::new(1)));
        let sent = network.accept_requests(0, Duration::ZERO, vec![request], &mut rng);
        let answered = settle(&mut network, &mut rng);
        assert_eq!(sent.messages_sent + answered.messages_sent, 2);
        let captured = result.lock().unwrap().take().unwrap();
        assert_eq!(captured.unwrap(), vec![1, 2, 3]);
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
        let mut rng = LinkStreams::new(42);

        let adapter1 = network.create_adapter(1);
        register_echo(&adapter1, "test.request", ShardId::leaf(1, 0));

        let (request, result) =
            make_request_with_capture(ShardId::leaf(1, 0), Some(ValidatorId::new(1)));

        network.accept_requests(0, Duration::from_millis(100), vec![request], &mut rng);

        // The request leg is on the wire past 100ms.
        let next = network.next_delivery_time().unwrap();
        assert!(next > Duration::from_millis(100));

        // Nothing has come back at 100ms.
        let (answered, _) = network.flush_requests(Duration::from_millis(100), &mut rng);
        assert_eq!(answered, 0);
        assert!(result.lock().unwrap().is_none());

        settle(&mut network, &mut rng);
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
            class: MessageClass::Bulk,
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
        let mut rng = LinkStreams::new(42);

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

    /// One batch published to two shard topics reaches a host serving
    /// both shards once on each: the dedup key is the payload under its
    /// topic, as production's is, so the second shard's copy — the one
    /// that shard's loop admits from — is not read as a replay of the
    /// first.
    #[test]
    fn the_same_batch_on_a_second_shard_topic_is_delivered_again() {
        let (left, right) = (ShardId::leaf(1, 0), ShardId::leaf(1, 1));
        let hosted = vec![
            std::iter::once(left).collect(),
            [left, right].into_iter().collect(),
        ];
        let validator_to_host = (0..2u64)
            .map(|host| (ValidatorId::new(host), host as NodeIndex))
            .collect();
        let mut network = SimulatedNetwork::new(
            NetworkConfig {
                packet_loss_rate: 0.0,
                ..Default::default()
            },
            HostLayout {
                hosted,
                validator_to_host,
            },
            0,
        );
        let handlers = register_gossip_handlers(&network);
        let mut rng = LinkStreams::new(42);

        let on_left = make_gossip_entry(BroadcastTarget::Shard(left));
        let on_right = make_gossip_entry(BroadcastTarget::Shard(right));
        let first = network.accept_gossip(0, Duration::ZERO, on_left, &mut rng);
        let second = network.accept_gossip(0, Duration::ZERO, on_right, &mut rng);
        network.flush_gossip(FAR_FUTURE);

        assert_eq!(first.messages_sent, 1);
        assert_eq!(second.messages_sent, 1);
        assert_eq!(second.messages_deduplicated, 0);
        assert_eq!(handlers[1].count(), 2, "once per topic the host serves");
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
        let mut rng = LinkStreams::new(42);

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
        let mut rng = LinkStreams::new(42);

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
        let mut rng = LinkStreams::new(42);

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

    /// A copy the partition kept from node 1 is not seen there, so the
    /// same bytes broadcast by another node still reach it; node 3, which
    /// took the first copy, dedups the second.
    #[test]
    fn test_accept_gossip_lost_copy_is_not_seen() {
        let mut network = sim_network_cfg(
            NetworkConfig {
                packet_loss_rate: 0.0,
                ..Default::default()
            },
            2,
            2,
        );
        let handlers = register_gossip_handlers(&network);
        let mut rng = LinkStreams::new(42);

        network.partition_unidirectional(0, 1);
        network.accept_gossip(
            0,
            Duration::ZERO,
            make_gossip_entry(BroadcastTarget::Global),
            &mut rng,
        );
        let second = network.accept_gossip(
            2,
            Duration::ZERO,
            make_gossip_entry(BroadcastTarget::Global),
            &mut rng,
        );
        network.flush_gossip(FAR_FUTURE);

        assert_eq!(handlers[1].count(), 1);
        assert_eq!(handlers[3].count(), 1);
        assert_eq!(second.messages_deduplicated, 1);
    }

    /// A partition installed while a copy is in flight takes it, and the
    /// recipient, never having seen it, takes the next broadcaster's copy.
    #[test]
    fn a_partition_takes_gossip_already_in_flight() {
        let mut network = sim_network_cfg(
            NetworkConfig {
                packet_loss_rate: 0.0,
                ..Default::default()
            },
            2,
            2,
        );
        let handlers = register_gossip_handlers(&network);
        let mut rng = LinkStreams::new(42);

        network.accept_gossip(
            0,
            Duration::ZERO,
            make_gossip_entry(BroadcastTarget::Global),
            &mut rng,
        );
        network.partition_unidirectional(0, 1);
        let (_, dropped) = network.flush_gossip(FAR_FUTURE);
        assert_eq!(dropped.messages_dropped_partition, 1);
        assert_eq!(handlers[1].count(), 0);
        assert_eq!(handlers[2].count(), 1);

        let second = network.accept_gossip(
            2,
            FAR_FUTURE,
            make_gossip_entry(BroadcastTarget::Global),
            &mut rng,
        );
        network.flush_gossip(FAR_FUTURE * 2);
        assert_eq!(second.messages_deduplicated, 1, "host 3 already holds it");
        assert_eq!(handlers[1].count(), 1);
    }

    /// A request leg in flight when its edge is cut never arrives: the
    /// attempt times out and the request rotates.
    #[test]
    fn a_partition_takes_a_request_already_in_flight() {
        let mut network = sim_network(1, 4);
        host_shard_everywhere(&network, ShardId::leaf(1, 0));
        let mut streams = LinkStreams::new(42);
        let served = Arc::new(AtomicU32::new(0));
        for i in 1..4 {
            let served = Arc::clone(&served);
            let handler: Arc<RawRequestHandler> = Arc::new(move |payload: &[u8]| -> Vec<u8> {
                served.fetch_add(1, AtomicOrdering::Relaxed);
                payload.to_vec()
            });
            network.create_adapter(i).registry.register_raw_request(
                "test.request",
                ShardId::leaf(1, 0),
                handler,
            );
        }

        let (request, result) =
            make_request_with_capture(ShardId::leaf(1, 0), Some(ValidatorId::new(1)));
        network.accept_requests(0, Duration::ZERO, vec![request], &mut streams);
        network.partition_unidirectional(0, 1);
        let (_, stats) = network.flush_requests(FAR_FUTURE, &mut streams);

        let rotation = RetryConfig::default().retries_before_rotation;
        assert_eq!(stats.messages_dropped_partition, u64::from(rotation));
        assert_eq!(
            served.load(AtomicOrdering::Relaxed),
            1,
            "only the rotated attempt"
        );
        assert!(result.lock().unwrap().take().unwrap().is_ok());
    }

    /// A windowed partition cuts only while its window is open: a copy sent
    /// before the window and landing inside it is dropped, one sent and
    /// landing after it arrives.
    #[test]
    fn a_windowed_partition_cuts_only_inside_its_window() {
        let mut network = sim_network_cfg(
            NetworkConfig {
                packet_loss_rate: 0.0,
                jitter_fraction: 0.0,
                ..Default::default()
            },
            2,
            2,
        );
        let handlers = register_gossip_handlers(&network);
        let mut rng = LinkStreams::new(42);
        let at = Duration::from_millis;
        network.partition_groups_during(&[0], &[1], &[at(100)..at(1000)]);

        network.accept_gossip(
            0,
            at(0),
            make_gossip_entry(BroadcastTarget::Global),
            &mut rng,
        );
        let (_, dropped) = network.flush_gossip(at(500));
        assert_eq!(dropped.messages_dropped_partition, 1);
        assert_eq!(handlers[1].count(), 0);

        network.accept_gossip(
            0,
            at(1000),
            make_gossip_entry(BroadcastTarget::Global),
            &mut rng,
        );
        network.flush_gossip(FAR_FUTURE);
        assert_eq!(handlers[1].count(), 1);
    }

    fn gossip_of(bytes: &[u8]) -> OutboxEntry {
        OutboxEntry {
            target: BroadcastTarget::Global,
            message_type: "test.gossip",
            class: MessageClass::Bulk,
            data: compression::compress(bytes),
        }
    }

    /// A duplicated copy reaches its recipient twice: past the dedup set,
    /// as a mesh forward after the seen cache expires would.
    #[test]
    fn a_duplicated_gossip_copy_arrives_twice() {
        let mut network = sim_network_cfg(
            NetworkConfig {
                duplicate_rate: 1.0,
                ..Default::default()
            },
            1,
            2,
        );
        let handlers = register_gossip_handlers(&network);
        let mut rng = LinkStreams::new(42);
        network.accept_gossip(0, Duration::ZERO, gossip_of(b"once"), &mut rng);
        network.flush_gossip(FAR_FUTURE);
        assert_eq!(
            handlers[1].payloads(),
            vec![b"once".to_vec(), b"once".to_vec()]
        );
    }

    /// A replay brings an old payload of the same type along with a new one.
    #[test]
    fn a_replay_redelivers_an_old_payload_of_its_type() {
        let mut network = sim_network_cfg(
            NetworkConfig {
                replay_rate: 1.0,
                ..Default::default()
            },
            1,
            2,
        );
        let handlers = register_gossip_handlers(&network);
        let mut rng = LinkStreams::new(42);
        network.accept_gossip(0, Duration::ZERO, gossip_of(b"old"), &mut rng);
        network.flush_gossip(FAR_FUTURE);
        network.accept_gossip(0, FAR_FUTURE, gossip_of(b"new"), &mut rng);
        network.flush_gossip(FAR_FUTURE * 2);
        let mut got = handlers[1].payloads();
        got.sort();
        assert_eq!(got, vec![b"new".to_vec(), b"old".to_vec(), b"old".to_vec()]);
    }

    /// A replay stays on its topic: an old payload published to one shard
    /// never reaches another shard's subscribers riding a new copy there.
    #[test]
    fn a_replay_stays_on_its_topic() {
        let mut network = sim_network_cfg(
            NetworkConfig {
                replay_rate: 1.0,
                ..Default::default()
            },
            2,
            2,
        );
        let handlers = register_gossip_handlers(&network);
        let mut rng = LinkStreams::new(42);
        let on = |shard: ShardId, bytes: &[u8]| OutboxEntry {
            target: BroadcastTarget::Shard(shard),
            message_type: "test.gossip",
            class: MessageClass::Bulk,
            data: compression::compress(bytes),
        };
        network.accept_gossip(
            0,
            Duration::ZERO,
            on(ShardId::leaf(1, 0), b"left"),
            &mut rng,
        );
        network.flush_gossip(FAR_FUTURE);
        network.accept_gossip(2, FAR_FUTURE, on(ShardId::leaf(1, 1), b"right"), &mut rng);
        network.flush_gossip(FAR_FUTURE * 2);
        assert_eq!(handlers[3].payloads(), vec![b"right".to_vec()]);
    }

    /// A spike multiplies one delivery's latency at least tenfold.
    #[test]
    fn a_spiked_delivery_lands_far_later() {
        let mut network = sim_network_cfg(
            NetworkConfig {
                spike_rate: 1.0,
                jitter_fraction: 0.0,
                ..Default::default()
            },
            1,
            2,
        );
        let _handlers = register_gossip_handlers(&network);
        let mut rng = LinkStreams::new(42);
        network.accept_gossip(0, Duration::ZERO, gossip_of(b"slow"), &mut rng);
        let base = NetworkConfig::default().latency;
        assert!(network.next_gossip_delivery_time().unwrap() >= base * 10);
    }

    /// A duplicated request leg is served twice, and the requester hears
    /// one answer.
    #[test]
    fn a_duplicated_request_is_served_twice_and_answered_once() {
        let mut network = sim_network_cfg(
            NetworkConfig {
                duplicate_rate: 1.0,
                ..Default::default()
            },
            1,
            4,
        );
        host_shard_everywhere(&network, ShardId::leaf(1, 0));
        let mut streams = LinkStreams::new(42);
        let served = Arc::new(AtomicU32::new(0));
        let counter = Arc::clone(&served);
        let handler: Arc<RawRequestHandler> = Arc::new(move |payload: &[u8]| -> Vec<u8> {
            counter.fetch_add(1, AtomicOrdering::Relaxed);
            payload.to_vec()
        });
        network.create_adapter(1).registry.register_raw_request(
            "test.request",
            ShardId::leaf(1, 0),
            handler,
        );
        let (request, result) =
            make_request_with_capture(ShardId::leaf(1, 0), Some(ValidatorId::new(1)));
        network.accept_requests(0, Duration::ZERO, vec![request], &mut streams);
        let (answered, _) = network.flush_requests(FAR_FUTURE, &mut streams);
        assert_eq!(served.load(AtomicOrdering::Relaxed), 2);
        assert_eq!(answered, 1);
        assert!(result.lock().unwrap().take().unwrap().is_ok());
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
        let mut rng = LinkStreams::new(42);

        let entry = make_gossip_entry(BroadcastTarget::Global);
        let stats = network.accept_gossip(0, Duration::ZERO, entry, &mut rng);
        let (delivered, _) = network.flush_gossip(FAR_FUTURE);

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
        let mut rng = LinkStreams::new(42);

        let entry = make_gossip_entry(BroadcastTarget::Global);
        let stats = network.accept_gossip(0, Duration::ZERO, entry, &mut rng);
        assert_eq!(stats.messages_sent, 3);

        // With high jitter, not all messages should arrive at the same time.
        // Flush at the earliest delivery time — should deliver at least one
        // but not necessarily all.
        let first_time = network.next_gossip_delivery_time().unwrap();
        let (delivered_at_first, _) = network.flush_gossip(first_time);
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
        let mut rng = LinkStreams::new(42);

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
    fn a_notification_rewrite_equivocates_across_recipients() {
        // The tier every vote, timeout and ready signal travels on. Without a
        // rewrite here a byzantine sender can only be made silent, and a drop
        // exercises the fetch fallback rather than the content check.
        use hyperscale_network::registry::RawNotificationHandler;
        const TYPE: &str = "test.notification";

        let mut network = sim_network_cfg(
            NetworkConfig {
                packet_loss_rate: 0.0,
                ..Default::default()
            },
            1,
            4,
        );
        let mut rng = LinkStreams::new(42);

        let received: Vec<Arc<RecordingHandler>> = (0..network.total_nodes() as NodeIndex)
            .map(|i| {
                let handler = RecordingHandler::new();
                let adapter = network.create_adapter(i);
                let sink = handler.clone();
                let raw: Arc<RawNotificationHandler> = Arc::new(move |payload: Vec<u8>| {
                    sink.received.lock().unwrap().push(payload);
                });
                adapter.registry.register_raw_notification(TYPE, raw);
                handler
            })
            .collect();

        let nth = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&nth);
        let handle = network.rewrite_notifications(
            0,
            TYPE,
            Arc::new(move |_asked: &[u8], bytes: &[u8]| {
                let n = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let mut out = bytes.to_vec();
                out.extend_from_slice(format!("-{n}").as_bytes());
                out
            }),
        );

        network.accept_notifications(
            0,
            Duration::ZERO,
            vec![PendingNotification {
                recipients: (1..4).map(ValidatorId::new).collect(),
                type_id: TYPE,
                class: MessageClass::Bulk,
                data: compression::compress(b"vote"),
            }],
            &mut rng,
        );
        network.flush_notifications(FAR_FUTURE);

        assert_eq!(handle.fired(), 3, "one rewrite per recipient");
        for (n, h) in received[1..4].iter().enumerate() {
            let got = h.payloads();
            assert_eq!(got.len(), 1);
            assert_eq!(got[0], format!("vote-{n}").as_bytes());
        }
    }

    #[test]
    fn a_gossip_rewrite_equivocates_across_recipients() {
        // The rewrite runs inside the recipient loop, so a stateful closure
        // sends different bytes to each peer while the dedup above still keys
        // on the one honest message id.
        let mut network = sim_network_cfg(
            NetworkConfig {
                packet_loss_rate: 0.0,
                ..Default::default()
            },
            1,
            4,
        );
        let handlers = register_gossip_handlers(&network);
        let mut rng = LinkStreams::new(42);

        let nth = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&nth);
        let handle = network.rewrite_gossip(
            0,
            "test.gossip",
            Arc::new(move |_asked: &[u8], bytes: &[u8]| {
                let n = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let mut out = bytes.to_vec();
                out.extend_from_slice(format!("-{n}").as_bytes());
                out
            }),
        );

        let entry = make_gossip_entry(BroadcastTarget::Global);
        network.accept_gossip(0, Duration::ZERO, entry, &mut rng);
        network.flush_gossip(FAR_FUTURE);

        assert_eq!(
            handle.fired(),
            3,
            "one rewrite per recipient, sender excluded"
        );
        let delivered: Vec<Vec<u8>> = handlers[1..]
            .iter()
            .map(|h| h.payloads().first().unwrap().clone())
            .collect();
        assert_eq!(delivered.len(), 3);
        for (n, got) in delivered.iter().enumerate() {
            assert_eq!(got, format!("test gossip payload-{n}").as_bytes());
        }
    }

    #[test]
    fn test_accept_gossip_invalid_compressed_data() {
        let mut network = sim_network(1, 2);
        let handlers = register_gossip_handlers(&network);
        let mut rng = LinkStreams::new(42);

        // Pass garbage data that can't be decompressed
        let entry = OutboxEntry {
            target: BroadcastTarget::Global,
            message_type: "test.gossip",
            class: MessageClass::Bulk,
            data: vec![0xFF, 0xFE, 0xFD],
        };

        let stats = network.accept_gossip(0, Duration::ZERO, entry, &mut rng);
        let (delivered, _) = network.flush_gossip(FAR_FUTURE);

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
        let mut rng = LinkStreams::new(42);

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
        let mut rng = LinkStreams::new(42);

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
        let mut rng = LinkStreams::new(42);

        // Create adapter for node 1 and register handler through it
        let adapter1 = network.create_adapter(1);
        register_echo(&adapter1, "test.request", ShardId::leaf(1, 0));

        // accept_requests should be able to find the handler
        let (request, result) =
            make_request_with_capture(ShardId::leaf(1, 0), Some(ValidatorId::new(1)));
        let sent = network.accept_requests(0, Duration::ZERO, vec![request], &mut rng);
        let answered = settle(&mut network, &mut rng);

        assert_eq!(sent.messages_sent + answered.messages_sent, 2);
        let captured = result.lock().unwrap().take().unwrap();
        assert!(captured.is_ok());
    }

    #[test]
    fn test_full_gossip_roundtrip() {
        use hyperscale_network::GossipVerdict;
        use hyperscale_network::registry::RawGossipHandler;
        use hyperscale_types::ShardId;
        use hyperscale_types::network::gossip::TransactionGossip;
        use hyperscale_types::test_utils::{test_prefix, test_transaction_with_prefixes};

        let mut network = sim_network_cfg(
            NetworkConfig {
                packet_loss_rate: 0.0,
                ..Default::default()
            },
            1,
            2,
        );
        host_shard_everywhere(&network, ShardId::leaf(1, 0));
        let mut rng = LinkStreams::new(42);

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
        let gossip = TransactionGossip::new(Capped::from_array([Arc::new(
            test_transaction_with_prefixes(&[1, 2, 3], &[test_prefix(1)], &[test_prefix(2)]),
        )]));
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
