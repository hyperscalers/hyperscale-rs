//! Simulated network with deterministic latency, packet loss, and partitions.

use crate::sim_network::{BroadcastTarget, OutboxEntry, PendingRequest, SimNetworkAdapter};
use crate::NodeIndex;
use hyperscale_network::{HandlerRegistry, RequestError};
use hyperscale_types::{ShardGroupId, ValidatorId};
use rand::seq::SliceRandom;
use rand::Rng;
use rand_chacha::ChaCha8Rng;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, trace};

/// Configuration for simulated network.
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Base latency for intra-shard messages.
    pub intra_shard_latency: Duration,
    /// Base latency for cross-shard messages.
    pub cross_shard_latency: Duration,
    /// Jitter as a fraction of base latency (0.0 - 1.0).
    pub jitter_fraction: f64,
    /// Number of validators per shard.
    pub validators_per_shard: u32,
    /// Number of shards.
    pub num_shards: u32,
    /// Packet loss rate (0.0 - 1.0). Messages are dropped with this probability.
    pub packet_loss_rate: f64,
    /// When enabled, messages are wire-encoded (SBOR + LZ4) in the outbox and
    /// decoded on delivery, exercising the same serialization path as production.
    pub codec_roundtrip: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            intra_shard_latency: Duration::from_millis(150),
            cross_shard_latency: Duration::from_millis(150),
            jitter_fraction: 0.1,
            validators_per_shard: 4,
            num_shards: 2,
            packet_loss_rate: 0.0,
            codec_roundtrip: true,
        }
    }
}

/// Stats returned by [`SimulatedNetwork::fulfill_requests`] and
/// [`SimulatedNetwork::accept_gossip`].
#[derive(Debug, Default)]
pub struct FulfillmentStats {
    pub messages_sent: u64,
    pub messages_dropped_partition: u64,
    pub messages_dropped_loss: u64,
}

/// A gossip delivery scheduled for future delivery via the internal latency queue.
struct ScheduledGossip {
    delivery_time: Duration,
    sequence: u64,
    target_node: NodeIndex,
    message_type: &'static str,
    payload: Vec<u8>,
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

/// Simulated network for deterministic message delivery.
///
/// Supports:
/// - Configurable latency with jitter
/// - Packet loss (probabilistic message drops)
/// - Network partitions (blocking communication between node pairs)
/// - Request fulfillment via per-type handlers in per-node [`HandlerRegistry`]s
/// - Internalized gossip latency queue with per-type gossip handlers
pub struct SimulatedNetwork {
    config: NetworkConfig,
    /// Partitioned node pairs. If (a, b) is in this set, messages from a to b are dropped.
    /// Partitions are directional - add both (a, b) and (b, a) for bidirectional partition.
    partitions: HashSet<(NodeIndex, NodeIndex)>,
    /// Per-node handler registries, shared with each node's [`SimNetworkAdapter`].
    ///
    /// Populated when `register_gossip_handler` / `register_request_handler`
    /// are called on the adapter; read during `fulfill_requests` / `flush_gossip`.
    registries: Vec<Arc<HandlerRegistry>>,
    /// Internal latency queue for pending gossip deliveries.
    pending_gossip: BinaryHeap<Reverse<ScheduledGossip>>,
    /// Monotonic sequence counter for deterministic ordering of same-time deliveries.
    gossip_sequence: u64,
}

impl std::fmt::Debug for SimulatedNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SimulatedNetwork")
            .field("config", &self.config)
            .field("partitions", &self.partitions)
            .field("registries", &self.registries.len())
            .field("pending_gossip", &self.pending_gossip.len())
            .finish()
    }
}

impl SimulatedNetwork {
    /// Create a new simulated network with per-node handler registries.
    pub fn new(config: NetworkConfig) -> Self {
        let num_nodes = (config.num_shards * config.validators_per_shard) as usize;
        let registries = (0..num_nodes)
            .map(|_| Arc::new(HandlerRegistry::new()))
            .collect();
        Self {
            config,
            partitions: HashSet::new(),
            registries,
            pending_gossip: BinaryHeap::new(),
            gossip_sequence: 0,
        }
    }

    /// Create a [`SimNetworkAdapter`] for a node, sharing its handler registry.
    ///
    /// The returned adapter's `register_gossip_handler` / `register_request_handler`
    /// calls populate the shared registry, making them visible to
    /// [`fulfill_requests`](Self::fulfill_requests) and [`flush_gossip`](Self::flush_gossip).
    pub fn create_adapter(&self, node: NodeIndex) -> SimNetworkAdapter {
        SimNetworkAdapter::new(Arc::clone(&self.registries[node as usize]))
    }

    // ─── Partition Management ───

    /// Check if two nodes are partitioned (message from `from` to `to` would be dropped).
    pub fn is_partitioned(&self, from: NodeIndex, to: NodeIndex) -> bool {
        self.partitions.contains(&(from, to))
    }

    /// Create a unidirectional partition: messages from `from` to `to` are dropped.
    pub fn partition_unidirectional(&mut self, from: NodeIndex, to: NodeIndex) {
        self.partitions.insert((from, to));
    }

    /// Create a bidirectional partition between two nodes.
    pub fn partition_bidirectional(&mut self, a: NodeIndex, b: NodeIndex) {
        self.partitions.insert((a, b));
        self.partitions.insert((b, a));
    }

    /// Create a bidirectional partition between two groups of nodes.
    /// All messages between group_a and group_b are dropped (both directions).
    pub fn partition_groups(&mut self, group_a: &[NodeIndex], group_b: &[NodeIndex]) {
        for &a in group_a {
            for &b in group_b {
                self.partitions.insert((a, b));
                self.partitions.insert((b, a));
            }
        }
    }

    /// Isolate a node from all other nodes in the network.
    pub fn isolate_node(&mut self, node: NodeIndex) {
        for other in self.all_nodes() {
            if other != node {
                self.partitions.insert((node, other));
                self.partitions.insert((other, node));
            }
        }
    }

    /// Heal a unidirectional partition.
    pub fn heal_unidirectional(&mut self, from: NodeIndex, to: NodeIndex) {
        self.partitions.remove(&(from, to));
    }

    /// Heal a bidirectional partition between two nodes.
    pub fn heal_bidirectional(&mut self, a: NodeIndex, b: NodeIndex) {
        self.partitions.remove(&(a, b));
        self.partitions.remove(&(b, a));
    }

    /// Heal all partitions - restore full network connectivity.
    pub fn heal_all(&mut self) {
        self.partitions.clear();
    }

    /// Get the number of active partition pairs.
    pub fn partition_count(&self) -> usize {
        self.partitions.len()
    }

    // ─── Packet Loss ───

    /// Check if a packet should be dropped based on the configured loss rate.
    /// Returns true if the packet should be dropped.
    pub fn should_drop_packet(&self, rng: &mut ChaCha8Rng) -> bool {
        self.config.packet_loss_rate > 0.0 && rng.gen::<f64>() < self.config.packet_loss_rate
    }

    /// Set the packet loss rate (0.0 - 1.0).
    pub fn set_packet_loss_rate(&mut self, rate: f64) {
        self.config.packet_loss_rate = rate.clamp(0.0, 1.0);
    }

    /// Get the current packet loss rate.
    pub fn packet_loss_rate(&self) -> f64 {
        self.config.packet_loss_rate
    }

    // ─── Codec Roundtrip ───

    /// Whether codec roundtrip is enabled.
    pub fn codec_roundtrip(&self) -> bool {
        self.config.codec_roundtrip
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

    /// Sample latency for a message between two nodes.
    pub fn sample_latency(&self, from: NodeIndex, to: NodeIndex, rng: &mut ChaCha8Rng) -> Duration {
        let from_shard = self.shard_for_node(from);
        let to_shard = self.shard_for_node(to);

        let base = if from_shard == to_shard {
            self.config.intra_shard_latency
        } else {
            self.config.cross_shard_latency
        };

        // Add jitter
        let jitter_range = base.as_secs_f64() * self.config.jitter_fraction;
        let jitter = rng.gen_range(-jitter_range..jitter_range);
        let latency_secs = (base.as_secs_f64() + jitter).max(0.001);

        Duration::from_secs_f64(latency_secs)
    }

    /// Get the shard for a node index.
    pub fn shard_for_node(&self, node: NodeIndex) -> ShardGroupId {
        ShardGroupId((node / self.config.validators_per_shard) as u64)
    }

    /// Get all nodes in a shard.
    pub fn peers_in_shard(&self, shard: ShardGroupId) -> Vec<NodeIndex> {
        let start = (shard.0 as u32) * self.config.validators_per_shard;
        let end = start + self.config.validators_per_shard;
        (start..end).collect()
    }

    /// Get all nodes in the network.
    pub fn all_nodes(&self) -> Vec<NodeIndex> {
        let total = self.config.num_shards * self.config.validators_per_shard;
        (0..total).collect()
    }

    /// Get the total number of nodes.
    pub fn total_nodes(&self) -> usize {
        (self.config.num_shards * self.config.validators_per_shard) as usize
    }

    /// Get network configuration.
    pub fn config(&self) -> &NetworkConfig {
        &self.config
    }

    // ─── Request Fulfillment ───

    /// Fulfill pending requests by routing them through peer request handlers.
    ///
    /// Handlers are obtained from per-node [`HandlerRegistry`]s populated by
    /// each node's `register_request_handler` calls.
    ///
    /// For each request:
    /// 1. Select a peer (preferred_peer if set, otherwise random non-self peer)
    /// 2. Check partition and packet loss (request + response directions)
    /// 3. Look up the per-type handler and pass the raw SBOR payload
    /// 4. Invoke the callback with the response bytes
    pub fn fulfill_requests(
        &self,
        requester: NodeIndex,
        requests: Vec<PendingRequest>,
        rng: &mut ChaCha8Rng,
    ) -> FulfillmentStats {
        let mut stats = FulfillmentStats::default();

        for request in requests {
            let PendingRequest {
                peers,
                preferred_peer,
                type_id,
                request_bytes,
                on_response,
            } = request;

            // Select target peer from the caller-provided peer list.
            let peer = match preferred_peer {
                Some(vid) => vid.0 as NodeIndex,
                None => {
                    // Pick a random peer from the provided list.
                    let mut candidates: Vec<NodeIndex> =
                        peers.iter().map(|v| v.0 as NodeIndex).collect();
                    candidates.shuffle(rng);
                    match candidates.first() {
                        Some(&p) => p,
                        None => {
                            on_response(Err(RequestError::PeerUnreachable(ValidatorId(
                                requester as u64,
                            ))));
                            continue;
                        }
                    }
                }
            };

            // Partition check.
            if self.is_partitioned(requester, peer) {
                stats.messages_dropped_partition += 1;
                trace!(requester, peer, "Request dropped: partition");
                on_response(Err(RequestError::PeerUnreachable(ValidatorId(peer as u64))));
                continue;
            }

            // Packet loss (request direction).
            if self.should_drop_packet(rng) {
                stats.messages_dropped_loss += 1;
                trace!(requester, peer, "Request dropped: packet loss");
                on_response(Err(RequestError::PeerUnreachable(ValidatorId(peer as u64))));
                continue;
            }

            // Packet loss (response direction).
            if self.should_drop_packet(rng) {
                stats.messages_dropped_loss += 1;
                trace!(requester, peer, "Response dropped: packet loss");
                on_response(Err(RequestError::PeerUnreachable(ValidatorId(peer as u64))));
                continue;
            }

            stats.messages_sent += 2; // request + response

            // Look up the per-type request handler from the peer's registry.
            let handler = match self
                .registries
                .get(peer as usize)
                .and_then(|r| r.get_request(type_id))
            {
                Some(h) => h,
                None => {
                    on_response(Err(RequestError::PeerError(format!(
                        "no handler for {type_id} on node {peer}"
                    ))));
                    continue;
                }
            };

            let response_bytes = handler.handle_request(&request_bytes);

            if response_bytes.is_empty() {
                on_response(Err(RequestError::PeerError(
                    "handler returned empty response".to_string(),
                )));
            } else {
                on_response(Ok(response_bytes));
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

        let payload = match hyperscale_network::wire::decompress(&entry.data) {
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

        for to in peers {
            if to == from {
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
                    stats.messages_sent += 1;
                    self.gossip_sequence += 1;
                    self.pending_gossip.push(Reverse(ScheduledGossip {
                        delivery_time: now + latency,
                        sequence: self.gossip_sequence,
                        target_node: to,
                        message_type,
                        payload: payload.clone(),
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
        let mut delivered = 0;
        while let Some(Reverse(scheduled)) = self.pending_gossip.peek() {
            if scheduled.delivery_time > now {
                break;
            }
            let Reverse(scheduled) = self.pending_gossip.pop().unwrap();
            if let Some(handler) = self
                .registries
                .get(scheduled.target_node as usize)
                .and_then(|r| r.get_gossip(scheduled.message_type))
            {
                handler.on_message(scheduled.payload);
                delivered += 1;
            } else {
                debug!(
                    target_node = scheduled.target_node,
                    message_type = scheduled.message_type,
                    "No gossip handler for message type on target node, dropping"
                );
            }
        }
        delivered
    }

    /// Earliest pending gossip delivery time (for event loop scheduling).
    pub fn next_gossip_delivery_time(&self) -> Option<Duration> {
        self.pending_gossip.peek().map(|Reverse(s)| s.delivery_time)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn test_shard_assignment() {
        let network = SimulatedNetwork::new(NetworkConfig {
            validators_per_shard: 3,
            num_shards: 2,
            ..Default::default()
        });

        assert_eq!(network.shard_for_node(0), ShardGroupId(0));
        assert_eq!(network.shard_for_node(1), ShardGroupId(0));
        assert_eq!(network.shard_for_node(2), ShardGroupId(0));
        assert_eq!(network.shard_for_node(3), ShardGroupId(1));
        assert_eq!(network.shard_for_node(4), ShardGroupId(1));
        assert_eq!(network.shard_for_node(5), ShardGroupId(1));
    }

    #[test]
    fn test_hyperscale_latency() {
        let network = SimulatedNetwork::new(NetworkConfig::default());
        let mut rng1 = ChaCha8Rng::seed_from_u64(42);
        let mut rng2 = ChaCha8Rng::seed_from_u64(42);

        let latency1 = network.sample_latency(0, 1, &mut rng1);
        let latency2 = network.sample_latency(0, 1, &mut rng2);

        assert_eq!(latency1, latency2, "Same seed should produce same latency");
    }

    // ─── Partition Tests ───

    #[test]
    fn test_unidirectional_partition() {
        let mut network = SimulatedNetwork::new(NetworkConfig::default());

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
        let mut network = SimulatedNetwork::new(NetworkConfig::default());

        network.partition_bidirectional(0, 1);

        assert!(network.is_partitioned(0, 1));
        assert!(network.is_partitioned(1, 0));

        network.heal_bidirectional(0, 1);
        assert!(!network.is_partitioned(0, 1));
        assert!(!network.is_partitioned(1, 0));
    }

    #[test]
    fn test_group_partition() {
        let mut network = SimulatedNetwork::new(NetworkConfig {
            validators_per_shard: 2,
            num_shards: 2,
            ..Default::default()
        });

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
        let mut network = SimulatedNetwork::new(NetworkConfig {
            validators_per_shard: 4,
            num_shards: 1,
            ..Default::default()
        });

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
        let network = SimulatedNetwork::new(NetworkConfig::default());
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        // With 0% loss rate, no packets should be dropped
        for _ in 0..100 {
            assert!(!network.should_drop_packet(&mut rng));
        }
    }

    #[test]
    fn test_packet_loss_rate() {
        let mut network = SimulatedNetwork::new(NetworkConfig {
            packet_loss_rate: 0.5, // 50% loss rate
            ..Default::default()
        });

        let mut rng = ChaCha8Rng::seed_from_u64(42);

        // Count drops over many iterations
        let mut drops = 0;
        let iterations = 10000;
        for _ in 0..iterations {
            if network.should_drop_packet(&mut rng) {
                drops += 1;
            }
        }

        // Should be roughly 50% (within reasonable variance)
        let drop_rate = drops as f64 / iterations as f64;
        assert!(
            (0.45..0.55).contains(&drop_rate),
            "Expected ~50% drop rate, got {:.2}%",
            drop_rate * 100.0
        );

        // Test setting rate
        network.set_packet_loss_rate(0.0);
        assert_eq!(network.packet_loss_rate(), 0.0);

        // Clamping
        network.set_packet_loss_rate(1.5);
        assert_eq!(network.packet_loss_rate(), 1.0);

        network.set_packet_loss_rate(-0.5);
        assert_eq!(network.packet_loss_rate(), 0.0);
    }

    #[test]
    fn test_hyperscale_packet_loss() {
        let network = SimulatedNetwork::new(NetworkConfig {
            packet_loss_rate: 0.3,
            ..Default::default()
        });

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
        let mut network = SimulatedNetwork::new(NetworkConfig::default());
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
        let network = SimulatedNetwork::new(NetworkConfig {
            packet_loss_rate: 1.0, // 100% loss
            ..Default::default()
        });
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        // All packets should be dropped
        for _ in 0..10 {
            assert!(network.should_deliver(0, 1, &mut rng).is_none());
        }
    }

    #[test]
    fn test_partition_takes_precedence_over_packet_loss() {
        let mut network = SimulatedNetwork::new(NetworkConfig {
            packet_loss_rate: 0.0, // No random loss
            ..Default::default()
        });

        network.partition_bidirectional(0, 1);

        // Even with 0% packet loss, partition still blocks
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        assert!(network.should_deliver(0, 1, &mut rng).is_none());
    }

    #[test]
    fn test_codec_roundtrip_default_enabled() {
        let network = SimulatedNetwork::new(NetworkConfig::default());
        assert!(network.codec_roundtrip());
    }

    #[test]
    fn test_codec_roundtrip_disabled() {
        let network = SimulatedNetwork::new(NetworkConfig {
            codec_roundtrip: false,
            ..Default::default()
        });
        assert!(!network.codec_roundtrip());
    }

    // ─── fulfill_requests() Tests ───

    /// Helper: create a simple echo handler that returns the payload as-is.
    fn echo_handler() -> Arc<dyn hyperscale_network::RequestHandler> {
        struct Echo;
        impl hyperscale_network::RequestHandler for Echo {
            fn handle_request(&self, payload: &[u8]) -> Vec<u8> {
                payload.to_vec()
            }
        }
        Arc::new(Echo)
    }

    /// Helper: register an echo handler on a node's adapter for a given type_id.
    fn register_echo(adapter: &SimNetworkAdapter, type_id: &'static str) {
        hyperscale_network::Network::register_request_handler(adapter, type_id, echo_handler());
    }

    /// Helper: build a PendingRequest with a callback that captures the result.
    fn make_request_with_capture(
        peers: Vec<ValidatorId>,
        preferred_peer: Option<ValidatorId>,
    ) -> (
        PendingRequest,
        Arc<std::sync::Mutex<Option<Result<Vec<u8>, hyperscale_network::RequestError>>>>,
    ) {
        let result = Arc::new(std::sync::Mutex::new(None));
        let result_clone = result.clone();
        let request = PendingRequest {
            peers,
            preferred_peer,
            type_id: "test.request",
            request_bytes: vec![1, 2, 3],
            on_response: Box::new(move |r| {
                *result_clone.lock().unwrap() = Some(r);
            }),
        };
        (request, result)
    }

    #[test]
    fn test_fulfill_requests_happy_path() {
        let network = SimulatedNetwork::new(NetworkConfig {
            validators_per_shard: 4,
            num_shards: 1,
            ..Default::default()
        });
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        // Register echo handler on node 1
        let adapter1 = network.create_adapter(1);
        register_echo(&adapter1, "test.request");

        let (request, result) =
            make_request_with_capture(vec![ValidatorId(1)], Some(ValidatorId(1)));

        let stats = network.fulfill_requests(0, vec![request], &mut rng);

        assert_eq!(stats.messages_sent, 2); // request + response
        assert_eq!(stats.messages_dropped_partition, 0);
        assert_eq!(stats.messages_dropped_loss, 0);

        // Callback should have been invoked with Ok
        let captured = result.lock().unwrap().take().unwrap();
        assert!(captured.is_ok());
    }

    #[test]
    fn test_fulfill_requests_partition_drops() {
        let mut network = SimulatedNetwork::new(NetworkConfig {
            validators_per_shard: 4,
            num_shards: 1,
            ..Default::default()
        });
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        let adapter1 = network.create_adapter(1);
        register_echo(&adapter1, "test.request");

        // Partition node 0 → node 1
        network.partition_unidirectional(0, 1);

        let (request, result) =
            make_request_with_capture(vec![ValidatorId(1)], Some(ValidatorId(1)));
        let stats = network.fulfill_requests(0, vec![request], &mut rng);

        assert_eq!(stats.messages_dropped_partition, 1);
        assert_eq!(stats.messages_sent, 0);

        let captured = result.lock().unwrap().take().unwrap();
        assert!(matches!(
            captured,
            Err(hyperscale_network::RequestError::PeerUnreachable(_))
        ));
    }

    #[test]
    fn test_fulfill_requests_packet_loss() {
        let network = SimulatedNetwork::new(NetworkConfig {
            validators_per_shard: 4,
            num_shards: 1,
            packet_loss_rate: 1.0, // 100% loss
            ..Default::default()
        });
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        let adapter1 = network.create_adapter(1);
        register_echo(&adapter1, "test.request");

        let (request, result) =
            make_request_with_capture(vec![ValidatorId(1)], Some(ValidatorId(1)));
        let stats = network.fulfill_requests(0, vec![request], &mut rng);

        assert_eq!(stats.messages_dropped_loss, 1);
        assert_eq!(stats.messages_sent, 0);

        let captured = result.lock().unwrap().take().unwrap();
        assert!(matches!(
            captured,
            Err(hyperscale_network::RequestError::PeerUnreachable(_))
        ));
    }

    #[test]
    fn test_fulfill_requests_no_handler() {
        let network = SimulatedNetwork::new(NetworkConfig {
            validators_per_shard: 4,
            num_shards: 1,
            ..Default::default()
        });
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        // Don't register any handler
        let _adapter1 = network.create_adapter(1);

        let (request, result) =
            make_request_with_capture(vec![ValidatorId(1)], Some(ValidatorId(1)));
        network.fulfill_requests(0, vec![request], &mut rng);

        let captured = result.lock().unwrap().take().unwrap();
        assert!(matches!(
            captured,
            Err(hyperscale_network::RequestError::PeerError(_))
        ));
    }

    #[test]
    fn test_fulfill_requests_empty_response() {
        let network = SimulatedNetwork::new(NetworkConfig {
            validators_per_shard: 4,
            num_shards: 1,
            ..Default::default()
        });
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        // Register handler that returns empty
        struct EmptyHandler;
        impl hyperscale_network::RequestHandler for EmptyHandler {
            fn handle_request(&self, _: &[u8]) -> Vec<u8> {
                vec![]
            }
        }
        let adapter1 = network.create_adapter(1);
        hyperscale_network::Network::register_request_handler(
            &adapter1,
            "test.request",
            Arc::new(EmptyHandler),
        );

        let (request, result) =
            make_request_with_capture(vec![ValidatorId(1)], Some(ValidatorId(1)));
        network.fulfill_requests(0, vec![request], &mut rng);

        let captured = result.lock().unwrap().take().unwrap();
        assert!(
            matches!(captured, Err(hyperscale_network::RequestError::PeerError(ref s)) if s.contains("empty"))
        );
    }

    #[test]
    fn test_fulfill_requests_random_peer_selection() {
        let network = SimulatedNetwork::new(NetworkConfig {
            validators_per_shard: 4,
            num_shards: 1,
            ..Default::default()
        });
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        // Register handlers on all nodes
        for i in 0..4 {
            let adapter = network.create_adapter(i);
            register_echo(&adapter, "test.request");
        }

        // No preferred peer — should pick a random peer from the provided list
        let peers = vec![ValidatorId(1), ValidatorId(2), ValidatorId(3)];
        let (request, result) = make_request_with_capture(peers, None);
        let stats = network.fulfill_requests(0, vec![request], &mut rng);

        assert_eq!(stats.messages_sent, 2);
        let captured = result.lock().unwrap().take().unwrap();
        assert!(captured.is_ok());
    }

    #[test]
    fn test_fulfill_requests_single_node_no_peers() {
        let network = SimulatedNetwork::new(NetworkConfig {
            validators_per_shard: 1,
            num_shards: 1,
            ..Default::default()
        });
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        let adapter0 = network.create_adapter(0);
        register_echo(&adapter0, "test.request");

        // No preferred peer, and empty peer list
        let (request, result) = make_request_with_capture(vec![], None);
        network.fulfill_requests(0, vec![request], &mut rng);

        let captured = result.lock().unwrap().take().unwrap();
        assert!(matches!(
            captured,
            Err(hyperscale_network::RequestError::PeerUnreachable(_))
        ));
    }

    // ─── accept_gossip / flush_gossip Tests ───

    /// Helper: create a wire-encoded (LZ4-compressed) outbox entry.
    fn make_gossip_entry(target: BroadcastTarget) -> OutboxEntry {
        let data = hyperscale_network::wire::compress(b"test gossip payload");
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

    impl hyperscale_network::GossipHandler for RecordingHandler {
        fn on_message(&self, payload: Vec<u8>) {
            self.received.lock().unwrap().push(payload);
        }
    }

    /// The message type used in gossip tests.
    const TEST_GOSSIP_TYPE: &str = "test.gossip";

    /// Register recording handlers on all nodes and return them.
    ///
    /// Each adapter is ephemeral — the handler survives in the shared registry.
    fn register_gossip_handlers(network: &SimulatedNetwork) -> Vec<Arc<RecordingHandler>> {
        let total = network.total_nodes();
        (0..total as NodeIndex)
            .map(|i| {
                let handler = RecordingHandler::new();
                let adapter = network.create_adapter(i);
                hyperscale_network::Network::register_gossip_handler(
                    &adapter,
                    TEST_GOSSIP_TYPE,
                    hyperscale_network::TopicScope::Global,
                    handler.clone() as Arc<dyn hyperscale_network::GossipHandler>,
                );
                handler
            })
            .collect()
    }

    /// Far-future time that ensures all pending gossip is delivered.
    const FAR_FUTURE: Duration = Duration::from_secs(60);

    #[test]
    fn test_accept_gossip_shard_scoped() {
        let mut network = SimulatedNetwork::new(NetworkConfig {
            validators_per_shard: 2,
            num_shards: 2,
            packet_loss_rate: 0.0,
            ..Default::default()
        });
        let handlers = register_gossip_handlers(&network);
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        // Node 0 is in shard 0, along with node 1. Nodes 2,3 are in shard 1.
        let entry = make_gossip_entry(BroadcastTarget::Shard(ShardGroupId(0)));
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
        let mut network = SimulatedNetwork::new(NetworkConfig {
            validators_per_shard: 2,
            num_shards: 2,
            packet_loss_rate: 0.0,
            ..Default::default()
        });
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
        let mut network = SimulatedNetwork::new(NetworkConfig {
            validators_per_shard: 4,
            num_shards: 1,
            packet_loss_rate: 0.0,
            ..Default::default()
        });
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
        let mut network = SimulatedNetwork::new(NetworkConfig {
            validators_per_shard: 2,
            num_shards: 2,
            packet_loss_rate: 0.0,
            ..Default::default()
        });
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
        let mut network = SimulatedNetwork::new(NetworkConfig {
            validators_per_shard: 4,
            num_shards: 1,
            packet_loss_rate: 1.0,
            ..Default::default()
        });
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
        let mut network = SimulatedNetwork::new(NetworkConfig {
            validators_per_shard: 4,
            num_shards: 1,
            jitter_fraction: 0.5, // High jitter
            packet_loss_rate: 0.0,
            ..Default::default()
        });
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
        let mut network = SimulatedNetwork::new(NetworkConfig {
            validators_per_shard: 2,
            num_shards: 1,
            packet_loss_rate: 0.0,
            ..Default::default()
        });
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
        let mut network = SimulatedNetwork::new(NetworkConfig {
            validators_per_shard: 2,
            num_shards: 1,
            ..Default::default()
        });
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
        let mut network = SimulatedNetwork::new(NetworkConfig {
            validators_per_shard: 2,
            num_shards: 2, // nodes 0,1 in shard 0; nodes 2,3 in shard 1
            packet_loss_rate: 0.0,
            ..Default::default()
        });
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
        let mut network = SimulatedNetwork::new(NetworkConfig {
            validators_per_shard: 2,
            num_shards: 1,
            packet_loss_rate: 0.0,
            ..Default::default()
        });
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
        let network = SimulatedNetwork::new(NetworkConfig {
            validators_per_shard: 2,
            num_shards: 1,
            ..Default::default()
        });
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        // Create adapter for node 1 and register handler through it
        let adapter1 = network.create_adapter(1);
        register_echo(&adapter1, "test.request");

        // fulfill_requests should be able to find the handler
        let (request, result) =
            make_request_with_capture(vec![ValidatorId(1)], Some(ValidatorId(1)));
        let stats = network.fulfill_requests(0, vec![request], &mut rng);

        assert_eq!(stats.messages_sent, 2);
        let captured = result.lock().unwrap().take().unwrap();
        assert!(captured.is_ok());
    }

    #[test]
    fn test_full_gossip_roundtrip() {
        use hyperscale_messages::BlockVoteGossip;
        use hyperscale_types::{zero_bls_signature, BlockHeight, BlockVote, Hash, ShardGroupId};

        let mut network = SimulatedNetwork::new(NetworkConfig {
            validators_per_shard: 2,
            num_shards: 1,
            packet_loss_rate: 0.0,
            ..Default::default()
        });
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        // Register per-type handlers for "block.vote" on each node.
        let handlers: Vec<Arc<RecordingHandler>> = (0..network.total_nodes() as NodeIndex)
            .map(|i| {
                let handler = RecordingHandler::new();
                let adapter = network.create_adapter(i);
                hyperscale_network::Network::register_gossip_handler(
                    &adapter,
                    "block.vote",
                    hyperscale_network::TopicScope::Shard,
                    handler.clone() as Arc<dyn hyperscale_network::GossipHandler>,
                );
                handler
            })
            .collect();

        let adapter0 = network.create_adapter(0);

        // Node 0 broadcasts a vote via its adapter
        let gossip = BlockVoteGossip::new(BlockVote {
            block_hash: Hash::from_bytes(b"test_block"),
            shard_group_id: ShardGroupId(0),
            height: BlockHeight(42),
            round: 0,
            voter: ValidatorId(0),
            signature: zero_bls_signature(),
            timestamp: 1_000_000_000_000,
        });
        hyperscale_network::Network::broadcast_to_shard(&adapter0, ShardGroupId(0), &gossip);

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

        // Node 1 should have received the vote gossip
        let payloads = handlers[1].payloads();
        assert_eq!(payloads.len(), 1);
        assert!(!payloads[0].is_empty());
    }
}
