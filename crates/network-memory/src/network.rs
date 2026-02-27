//! Simulated network with deterministic latency, packet loss, and partitions.

use crate::sim_network::{
    BroadcastTarget, HandlerSlot, OutboxEntry, PendingRequest, SimNetworkAdapter,
};
use crate::NodeIndex;
use hyperscale_core::NodeInput;
use hyperscale_network::{frame_request, InboundRequestHandler, RequestError};
use hyperscale_types::{ShardGroupId, ValidatorId};
use rand::seq::SliceRandom;
use rand::Rng;
use rand_chacha::ChaCha8Rng;
use std::collections::HashSet;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tracing::trace;

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
/// [`SimulatedNetwork::deliver_gossip`].
#[derive(Debug, Default)]
pub struct FulfillmentStats {
    pub messages_sent: u64,
    pub messages_dropped_partition: u64,
    pub messages_dropped_loss: u64,
}

/// A single gossip delivery to a target node.
///
/// Returned by [`SimulatedNetwork::deliver_gossip`]. The caller schedules the
/// contained event directly — no channel draining required.
#[derive(Debug)]
pub struct GossipDelivery {
    /// Target node.
    pub to: NodeIndex,
    /// Sampled one-way latency.
    pub latency: Duration,
    /// The event to deliver.
    pub event: NodeInput,
}

/// Simulated network for deterministic message delivery.
///
/// Supports:
/// - Configurable latency with jitter
/// - Packet loss (probabilistic message drops)
/// - Network partitions (blocking communication between node pairs)
/// - Request fulfillment via registered [`InboundRequestHandler`]s (one per node)
pub struct SimulatedNetwork {
    config: NetworkConfig,
    /// Partitioned node pairs. If (a, b) is in this set, messages from a to b are dropped.
    /// Partitions are directional - add both (a, b) and (b, a) for bidirectional partition.
    partitions: HashSet<(NodeIndex, NodeIndex)>,
    /// Per-node handler slots, shared with each node's [`SimNetworkAdapter`].
    ///
    /// Populated when [`Network::register_inbound_handler`] is called on the
    /// adapter; read during [`fulfill_requests`](Self::fulfill_requests).
    handler_slots: Vec<HandlerSlot>,
}

impl std::fmt::Debug for SimulatedNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SimulatedNetwork")
            .field("config", &self.config)
            .field("partitions", &self.partitions)
            .field("handler_slots", &self.handler_slots.len())
            .finish()
    }
}

impl SimulatedNetwork {
    /// Create a new simulated network with pre-allocated handler slots.
    pub fn new(config: NetworkConfig) -> Self {
        let num_nodes = (config.num_shards * config.validators_per_shard) as usize;
        let handler_slots = (0..num_nodes).map(|_| Arc::new(OnceLock::new())).collect();
        Self {
            config,
            partitions: HashSet::new(),
            handler_slots,
        }
    }

    /// Create a [`SimNetworkAdapter`] for a node, sharing its handler slot.
    ///
    /// The returned adapter's [`Network::register_inbound_handler`] call
    /// will populate the shared slot, making the handler visible to
    /// [`fulfill_requests`](Self::fulfill_requests).
    pub fn create_adapter(&self, node: NodeIndex) -> SimNetworkAdapter {
        SimNetworkAdapter::new(Arc::clone(&self.handler_slots[node as usize]))
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

    /// Fulfill pending requests by routing them through peer InboundRequestHandlers.
    ///
    /// Handlers are obtained from the shared [`HandlerSlot`]s populated by each
    /// node's [`Network::register_inbound_handler`] call.
    ///
    /// For each request:
    /// 1. Select a peer (preferred_peer if set, otherwise random non-self peer)
    /// 2. Check partition and packet loss (request + response directions)
    /// 3. Frame the request bytes with type_id and call the peer's handler
    /// 4. Invoke the callback with the response bytes
    ///
    /// This ensures simulation exercises the same encode/decode/dispatch path
    /// as production (via `InboundHandler`).
    pub fn fulfill_requests(
        &self,
        requester: NodeIndex,
        requests: Vec<PendingRequest>,
        rng: &mut ChaCha8Rng,
    ) -> FulfillmentStats {
        let mut stats = FulfillmentStats::default();

        for request in requests {
            let PendingRequest {
                preferred_peer,
                type_id,
                request_bytes,
                on_response,
            } = request;

            // Select target peer.
            let peer = match preferred_peer {
                Some(vid) => vid.0 as NodeIndex,
                None => {
                    // Pick a random peer (excluding self) for block sync.
                    let mut candidates: Vec<NodeIndex> = self
                        .all_nodes()
                        .into_iter()
                        .filter(|&n| n != requester)
                        .collect();
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

            // Frame the request and dispatch through the peer's handler.
            let handler = match self.handler_slots.get(peer as usize).and_then(|s| s.get()) {
                Some(h) => h,
                None => {
                    on_response(Err(RequestError::PeerError(format!(
                        "no handler for node {peer}"
                    ))));
                    continue;
                }
            };

            let framed = frame_request(type_id, &request_bytes);
            let response_bytes = handler.handle_request(&framed);

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

    // ─── Gossip Delivery ───

    /// Fan out a gossip outbox entry, LZ4-decompressing once and producing a
    /// [`GossipDelivery`] per target peer.
    ///
    /// For each target peer (excluding the sender):
    /// 1. Check partition and packet loss
    /// 2. Sample one-way latency
    /// 3. Create a `NodeInput::GossipReceived` event with the decompressed payload
    ///
    /// The caller schedules each delivery directly — no channel draining needed.
    pub fn deliver_gossip(
        &self,
        from: NodeIndex,
        entry: OutboxEntry,
        rng: &mut ChaCha8Rng,
    ) -> (Vec<GossipDelivery>, FulfillmentStats) {
        let mut stats = FulfillmentStats::default();
        let mut deliveries = Vec::new();

        // Determine target peers from broadcast target.
        let peers = match &entry.target {
            BroadcastTarget::Shard(shard) => self.peers_in_shard(*shard),
            BroadcastTarget::Global => {
                let total = self.total_nodes();
                (0..total as NodeIndex).collect()
            }
        };

        // LZ4-decompress once; each target gets a clone of the decompressed payload.
        let payload = match hyperscale_network::wire::decompress(&entry.data) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(
                    from,
                    message_type = entry.message_type,
                    ?e,
                    "Gossip decompress error"
                );
                return (deliveries, stats);
            }
        };

        let message_type = entry.message_type.to_string();

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

                    deliveries.push(GossipDelivery {
                        to,
                        latency,
                        event: NodeInput::GossipReceived {
                            message_type: message_type.clone(),
                            payload: payload.clone(),
                        },
                    });
                }
            }
        }

        (deliveries, stats)
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
}
