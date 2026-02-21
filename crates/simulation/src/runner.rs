//! Deterministic simulation runner.
//!
//! Uses [`NodeLoop`] to process all actions per-node, with the simulation harness
//! controlling event scheduling, network delivery, and time.

use crate::event_queue::EventKey;
use crate::NodeIndex;
use crate::SimStorage;
use hyperscale_bft::{BftConfig, RecoveredState};
use hyperscale_core::{NodeInput, ProtocolEvent, TimerId};
use hyperscale_dispatch_sync::SyncDispatch;
use hyperscale_engine::RadixExecutor;
use hyperscale_execution::{DEFAULT_SPECULATIVE_MAX_TXS, DEFAULT_VIEW_CHANGE_COOLDOWN_ROUNDS};
use hyperscale_mempool::MempoolConfig;
use hyperscale_network::{RequestError, Topic};
use hyperscale_network_memory::{
    BroadcastTarget, NetworkConfig, NetworkTrafficAnalyzer, PendingRequest, SimNetworkAdapter,
    SimulatedNetwork,
};
use hyperscale_node::gossip_dispatch::decode_gossip_to_events;
use hyperscale_node::node_loop::{NodeLoop, StepOutput};
use hyperscale_node::TimerOp;
use hyperscale_node::{NodeStateMachine, SyncConfig, SyncProtocol};
use hyperscale_storage::ConsensusStore;
use hyperscale_types::{
    bls_keypair_from_seed, Block, Bls12381G1PrivateKey, Bls12381G1PublicKey, Hash as TxHash,
    QuorumCertificate, ShardGroupId, StaticTopology, Topology, TransactionStatus, ValidatorId,
    ValidatorInfo, ValidatorSet,
};
use radix_common::network::NetworkDefinition;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, trace, warn};

/// Type alias for the simulation's concrete NodeLoop.
type SimNodeLoop = NodeLoop<SimStorage, SimNetworkAdapter, SyncDispatch>;

/// Deterministic simulation runner.
///
/// Processes events in deterministic order using [`NodeLoop`] for action handling.
/// Given the same seed, produces identical results every run.
///
/// Each node has its own independent storage and executor inside its `NodeLoop`.
/// The harness controls the event queue, network delivery (latency, partitions,
/// packet loss), and time advancement.
pub struct SimulationRunner {
    /// Per-node NodeLoop instances. Index corresponds to NodeIndex.
    node_loops: Vec<SimNodeLoop>,

    /// Per-node event receivers (from crossbeam channels passed to NodeLoop).
    event_rxs: Vec<crossbeam::channel::Receiver<NodeInput>>,

    /// Global event queue, ordered deterministically.
    event_queue: BTreeMap<EventKey, NodeInput>,

    /// Sequence counter for deterministic ordering.
    sequence: u64,

    /// Current simulation time.
    now: Duration,

    /// Network simulator (latency, partitions, packet loss).
    network: SimulatedNetwork,

    /// RNG for network conditions (seeded for determinism).
    rng: ChaCha8Rng,

    /// Timer registry for cancellation support.
    /// Maps (node, timer_id) -> event_key for removal.
    timers: HashMap<(NodeIndex, TimerId), EventKey>,

    /// Statistics.
    stats: SimulationStats,

    /// Whether engine genesis has been executed on each node's storage.
    genesis_executed: Vec<bool>,

    /// Optional traffic analyzer for bandwidth estimation.
    traffic_analyzer: Option<Arc<NetworkTrafficAnalyzer>>,

    /// Per-node transaction status cache. Captures all emitted statuses.
    /// Maps (node_index, tx_hash) -> status for querying final transaction states.
    tx_status_cache: HashMap<(NodeIndex, TxHash), TransactionStatus>,
}

/// Statistics collected during simulation.
#[derive(Debug, Default, Clone)]
pub struct SimulationStats {
    /// Total events processed.
    pub events_processed: u64,
    /// Events processed by type.
    pub events_by_priority: [u64; 4],
    /// Total actions generated.
    pub actions_generated: u64,
    /// Messages sent (successfully scheduled for delivery).
    pub messages_sent: u64,
    /// Messages dropped due to network partition.
    pub messages_dropped_partition: u64,
    /// Messages dropped due to packet loss.
    pub messages_dropped_loss: u64,
    /// Messages deduplicated (same message already received by node).
    pub messages_deduplicated: u64,
    /// Timers set.
    pub timers_set: u64,
    /// Timers cancelled.
    pub timers_cancelled: u64,
}

impl SimulationStats {
    /// Total messages dropped (partition + packet loss).
    pub fn messages_dropped(&self) -> u64 {
        self.messages_dropped_partition + self.messages_dropped_loss
    }

    /// Message delivery rate (sent / (sent + dropped)).
    pub fn delivery_rate(&self) -> f64 {
        let total = self.messages_sent + self.messages_dropped();
        if total == 0 {
            1.0
        } else {
            self.messages_sent as f64 / total as f64
        }
    }
}

impl SimulationRunner {
    // ═══════════════════════════════════════════════════════════════════════
    // Construction
    // ═══════════════════════════════════════════════════════════════════════

    /// Create a new simulation runner with the given configuration.
    pub fn new(network_config: NetworkConfig, seed: u64) -> Self {
        let network = SimulatedNetwork::new(network_config.clone());
        let rng = ChaCha8Rng::seed_from_u64(seed);

        // Generate keys for all validators using deterministic seeding
        let total_validators = network_config.num_shards * network_config.validators_per_shard;
        let keys: Vec<Bls12381G1PrivateKey> = (0..total_validators)
            .map(|i| {
                let mut seed_bytes = [0u8; 32];
                let key_seed = seed.wrapping_add(i as u64).wrapping_mul(0x517cc1b727220a95);
                seed_bytes[..8].copy_from_slice(&key_seed.to_le_bytes());
                seed_bytes[8..16].copy_from_slice(&(i as u64).to_le_bytes());
                bls_keypair_from_seed(&seed_bytes)
            })
            .collect();
        let public_keys: Vec<Bls12381G1PublicKey> = keys.iter().map(|k| k.public_key()).collect();

        // Build global validator set
        let global_validators: Vec<ValidatorInfo> = (0..total_validators)
            .map(|i| ValidatorInfo {
                validator_id: ValidatorId(i as u64),
                public_key: public_keys[i as usize],
                voting_power: 1,
            })
            .collect();
        let global_validator_set = ValidatorSet::new(global_validators);

        // Build per-shard committee mappings
        let mut shard_committees: HashMap<ShardGroupId, Vec<ValidatorId>> = HashMap::new();
        for shard_id in 0..network_config.num_shards {
            let shard = ShardGroupId(shard_id as u64);
            let shard_start = shard_id * network_config.validators_per_shard;
            let shard_end = shard_start + network_config.validators_per_shard;
            let committee: Vec<ValidatorId> = (shard_start..shard_end)
                .map(|i| ValidatorId(i as u64))
                .collect();
            shard_committees.insert(shard, committee);
        }

        // Create NodeLoop for each validator
        let num_nodes = total_validators as usize;
        let mut node_loops = Vec::with_capacity(num_nodes);
        let mut event_rxs = Vec::with_capacity(num_nodes);

        for shard_id in 0..network_config.num_shards {
            let shard = ShardGroupId(shard_id as u64);
            let shard_start = shard_id * network_config.validators_per_shard;

            for v in 0..network_config.validators_per_shard {
                let node_index = shard_start + v;
                let validator_id = ValidatorId(node_index as u64);

                let topology: Arc<dyn Topology> = Arc::new(StaticTopology::with_shard_committees(
                    validator_id,
                    shard,
                    network_config.num_shards as u64,
                    &global_validator_set,
                    shard_committees.clone(),
                ));

                let key_bytes = keys[node_index as usize].to_bytes();
                let signing_key =
                    Bls12381G1PrivateKey::from_bytes(&key_bytes).expect("valid key bytes");

                let state = NodeStateMachine::with_speculative_config(
                    node_index as NodeIndex,
                    topology.clone(),
                    // Clone key for state machine (it needs its own copy)
                    Bls12381G1PrivateKey::from_bytes(&key_bytes).expect("valid key bytes"),
                    BftConfig::default(),
                    RecoveredState::default(),
                    DEFAULT_SPECULATIVE_MAX_TXS,
                    DEFAULT_VIEW_CHANGE_COOLDOWN_ROUNDS,
                    MempoolConfig::default(),
                );

                let (event_tx, event_rx) = crossbeam::channel::unbounded();

                let network_def = NetworkDefinition::simulator();
                let tx_validator = Arc::new(hyperscale_engine::TransactionValidation::permissive(
                    network_def.clone(),
                ));

                let node_loop = NodeLoop::new(
                    state,
                    SimStorage::new(),
                    RadixExecutor::new(network_def),
                    SimNetworkAdapter::new(),
                    SyncDispatch,
                    event_tx,
                    signing_key,
                    topology,
                    shard,
                    validator_id,
                    SyncProtocol::new(SyncConfig::default()),
                    tx_validator,
                );

                node_loops.push(node_loop);
                event_rxs.push(event_rx);
            }
        }

        info!(
            num_nodes = node_loops.len(),
            num_shards = network_config.num_shards,
            validators_per_shard = network_config.validators_per_shard,
            seed,
            "Created simulation runner"
        );

        Self {
            node_loops,
            event_rxs,
            event_queue: BTreeMap::new(),
            sequence: 0,
            now: Duration::ZERO,
            network,
            rng,
            timers: HashMap::new(),
            stats: SimulationStats::default(),
            genesis_executed: vec![false; num_nodes],
            traffic_analyzer: None,
            tx_status_cache: HashMap::new(),
        }
    }

    /// Create a new simulation runner with traffic analysis enabled.
    pub fn with_traffic_analysis(network_config: NetworkConfig, seed: u64) -> Self {
        let mut runner = Self::new(network_config, seed);
        runner.traffic_analyzer = Some(Arc::new(NetworkTrafficAnalyzer::new()));
        runner
    }

    /// Enable traffic analysis on an existing runner.
    pub fn enable_traffic_analysis(&mut self) {
        if self.traffic_analyzer.is_none() {
            self.traffic_analyzer = Some(Arc::new(NetworkTrafficAnalyzer::new()));
        }
    }

    /// Check if traffic analysis is enabled.
    pub fn has_traffic_analysis(&self) -> bool {
        self.traffic_analyzer.is_some()
    }

    /// Get a bandwidth report from the traffic analyzer.
    pub fn traffic_report(&self) -> Option<hyperscale_network_memory::BandwidthReport> {
        self.traffic_analyzer
            .as_ref()
            .map(|analyzer| analyzer.generate_report(self.now, self.network.total_nodes()))
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Accessors
    // ═══════════════════════════════════════════════════════════════════════

    /// Get a reference to a node's storage.
    pub fn node_storage(&self, node: NodeIndex) -> Option<&SimStorage> {
        self.node_loops.get(node as usize).map(|nl| nl.storage())
    }

    /// Get the last emitted transaction status for a node.
    pub fn tx_status(&self, node: NodeIndex, tx_hash: &TxHash) -> Option<&TransactionStatus> {
        self.tx_status_cache.get(&(node, *tx_hash))
    }

    /// Get simulation statistics.
    pub fn stats(&self) -> &SimulationStats {
        &self.stats
    }

    /// Get current simulation time.
    pub fn now(&self) -> Duration {
        self.now
    }

    /// Get a reference to a node's state machine by index.
    pub fn node(&self, index: NodeIndex) -> Option<&NodeStateMachine> {
        self.node_loops.get(index as usize).map(|nl| nl.state())
    }

    /// Get a reference to the network.
    pub fn network(&self) -> &SimulatedNetwork {
        &self.network
    }

    /// Get a mutable reference to the network for partition/loss configuration.
    pub fn network_mut(&mut self) -> &mut SimulatedNetwork {
        &mut self.network
    }

    /// Get the number of committed blocks stored for a specific node.
    pub fn committed_block_count(&self, node: NodeIndex) -> usize {
        self.node_loops
            .get(node as usize)
            .map(|nl| {
                let s = nl.storage();
                let committed = s.committed_height();
                if committed.0 == 0 {
                    if s.get_block(hyperscale_types::BlockHeight(0)).is_some() {
                        1
                    } else {
                        0
                    }
                } else {
                    (committed.0 + 1) as usize
                }
            })
            .unwrap_or(0)
    }

    /// Check if a specific block is stored for a node.
    pub fn has_committed_block(&self, node: NodeIndex, height: u64) -> bool {
        self.node_loops
            .get(node as usize)
            .map(|nl| {
                nl.storage()
                    .get_block(hyperscale_types::BlockHeight(height))
                    .is_some()
            })
            .unwrap_or(false)
    }

    /// Schedule an initial event (e.g., to start the simulation).
    pub fn schedule_initial_event(&mut self, node: NodeIndex, delay: Duration, event: NodeInput) {
        let time = self.now + delay;
        self.schedule_event(node, time, event);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Genesis
    // ═══════════════════════════════════════════════════════════════════════

    /// Initialize all nodes with genesis blocks and start consensus.
    pub fn initialize_genesis(&mut self) {
        use hyperscale_storage::SubstateStore;
        use hyperscale_types::{Block, BlockHeader, BlockHeight, Hash, QuorumCertificate};

        // Run Radix Engine genesis on each node's storage
        for node_idx in 0..self.node_loops.len() {
            if !self.genesis_executed[node_idx] {
                let result = self.node_loops[node_idx]
                    .with_storage_and_executor(|storage, executor| executor.run_genesis(storage));
                if let Err(e) = result {
                    warn!(node = node_idx, "Radix Engine genesis failed: {:?}", e);
                }
                self.genesis_executed[node_idx] = true;
            }
        }
        info!(
            num_nodes = self.node_loops.len(),
            "Radix Engine genesis complete on all nodes"
        );

        let num_shards = self.network.config().num_shards;
        let validators_per_shard = self.network.config().validators_per_shard;

        for shard_id in 0..num_shards {
            let shard_start = shard_id * validators_per_shard;
            let first_node_storage = self.node_loops[shard_start as usize].storage();
            let genesis_jmt_version = first_node_storage.state_version();
            let genesis_jmt_root = first_node_storage.state_root_hash();

            info!(
                shard = shard_id,
                genesis_jmt_version,
                genesis_jmt_root = ?genesis_jmt_root,
                "JMT state after genesis bootstrap"
            );

            let genesis_header = BlockHeader {
                height: BlockHeight(0),
                parent_hash: Hash::from_bytes(&[0u8; 32]),
                parent_qc: QuorumCertificate::genesis(),
                proposer: ValidatorId((shard_id * validators_per_shard) as u64),
                timestamp: 0,
                round: 0,
                is_fallback: false,
                state_root: genesis_jmt_root,
                state_version: genesis_jmt_version,
                transaction_root: Hash::ZERO,
            };

            let genesis_block = Block {
                header: genesis_header,
                retry_transactions: vec![],
                priority_transactions: vec![],
                transactions: vec![],
                certificates: vec![],
                deferred: vec![],
                aborted: vec![],
                commitment_proofs: std::collections::HashMap::new(),
            };

            let shard_end = shard_start + validators_per_shard;
            for node_index in shard_start..shard_end {
                let i = node_index as usize;
                let actions = self.node_loops[i]
                    .state_mut()
                    .initialize_genesis(genesis_block.clone());
                self.node_loops[i].handle_actions(actions);
                self.node_loops[i].flush_all_batches();

                // Drain outputs from genesis initialization (timer sets, etc.)
                let output = self.node_loops[i].drain_pending_output();
                self.drain_node_io(node_index);
                self.process_step_output(node_index, output);

                // Sync state machine with actual JMT state after genesis bootstrap
                let genesis_commit_event =
                    NodeInput::Protocol(ProtocolEvent::StateCommitComplete {
                        height: 0,
                        state_version: genesis_jmt_version,
                        state_root: genesis_jmt_root,
                    });
                self.schedule_event(node_index, self.now, genesis_commit_event);
            }

            info!(
                shard = shard_id,
                genesis_hash = ?genesis_block.hash(),
                validators = validators_per_shard,
                "Initialized genesis for shard"
            );
        }
    }

    /// Initialize genesis with pre-funded accounts.
    pub fn initialize_genesis_with_balances(
        &mut self,
        balances: Vec<(
            radix_common::types::ComponentAddress,
            radix_common::math::Decimal,
        )>,
    ) {
        use hyperscale_engine::GenesisConfig;
        use hyperscale_storage::SubstateStore;
        use hyperscale_types::{Block, BlockHeader, BlockHeight, Hash, QuorumCertificate};

        // Run Radix Engine genesis on each node's storage with balances
        for node_idx in 0..self.node_loops.len() {
            if !self.genesis_executed[node_idx] {
                let balances = balances.clone();
                let result =
                    self.node_loops[node_idx].with_storage_and_executor(|storage, executor| {
                        let config = GenesisConfig {
                            xrd_balances: balances,
                            ..GenesisConfig::test_default()
                        };
                        executor.run_genesis_with_config(storage, config)
                    });
                if let Err(e) = result {
                    warn!(node = node_idx, "Radix Engine genesis failed: {:?}", e);
                }
                self.genesis_executed[node_idx] = true;
            }
        }
        info!(
            num_nodes = self.node_loops.len(),
            num_funded_accounts = balances.len(),
            "Radix Engine genesis complete with funded accounts"
        );

        let num_shards = self.network.config().num_shards;
        let validators_per_shard = self.network.config().validators_per_shard;

        for shard_id in 0..num_shards {
            let shard_start = shard_id * validators_per_shard;
            let first_node_storage = self.node_loops[shard_start as usize].storage();
            let genesis_jmt_version = first_node_storage.state_version();
            let genesis_jmt_root = first_node_storage.state_root_hash();

            info!(
                shard = shard_id,
                genesis_jmt_version,
                genesis_jmt_root = ?genesis_jmt_root,
                "JMT state after genesis bootstrap"
            );

            let genesis_header = BlockHeader {
                height: BlockHeight(0),
                parent_hash: Hash::from_bytes(&[0u8; 32]),
                parent_qc: QuorumCertificate::genesis(),
                proposer: ValidatorId((shard_id * validators_per_shard) as u64),
                timestamp: 0,
                round: 0,
                is_fallback: false,
                state_root: genesis_jmt_root,
                state_version: genesis_jmt_version,
                transaction_root: Hash::ZERO,
            };

            let genesis_block = Block {
                header: genesis_header,
                retry_transactions: vec![],
                priority_transactions: vec![],
                transactions: vec![],
                certificates: vec![],
                deferred: vec![],
                aborted: vec![],
                commitment_proofs: std::collections::HashMap::new(),
            };

            let shard_end = shard_start + validators_per_shard;
            for node_index in shard_start..shard_end {
                let i = node_index as usize;
                let actions = self.node_loops[i]
                    .state_mut()
                    .initialize_genesis(genesis_block.clone());
                self.node_loops[i].handle_actions(actions);
                self.node_loops[i].flush_all_batches();

                let output = self.node_loops[i].drain_pending_output();
                self.drain_node_io(node_index);
                self.process_step_output(node_index, output);

                let genesis_commit_event =
                    NodeInput::Protocol(ProtocolEvent::StateCommitComplete {
                        height: 0,
                        state_version: genesis_jmt_version,
                        state_root: genesis_jmt_root,
                    });
                self.schedule_event(node_index, self.now, genesis_commit_event);
            }

            info!(
                shard = shard_id,
                genesis_hash = ?genesis_block.hash(),
                validators = validators_per_shard,
                "Initialized genesis for shard"
            );
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Main Loop
    // ═══════════════════════════════════════════════════════════════════════

    /// Run simulation until no more events or time limit reached.
    pub fn run_until(&mut self, end_time: Duration) {
        trace!(
            end_time_secs = end_time.as_secs_f64(),
            "Running simulation step"
        );

        while let Some((&key, _)) = self.event_queue.first_key_value() {
            if key.time > end_time {
                debug!(
                    remaining_events = self.event_queue.len(),
                    "Time limit reached"
                );
                break;
            }

            let (key, event) = self.event_queue.pop_first().unwrap();
            self.now = key.time;
            let node_index = key.node_index;

            trace!(
                time = ?self.now,
                node = node_index,
                "Processing event"
            );

            // Update stats
            self.stats.events_processed += 1;
            self.stats.events_by_priority[event.priority() as usize] += 1;

            // For SubmitTransaction events, gossip to all relevant shards first.
            if let NodeInput::SubmitTransaction { ref tx } = event {
                let topology = self.node_loops[node_index as usize].state().topology();
                let shards: Vec<ShardGroupId> = topology.all_shards_for_transaction(tx);
                for shard in shards {
                    let event = NodeInput::Protocol(ProtocolEvent::TransactionGossipReceived {
                        tx: Arc::clone(tx),
                        submitted_locally: false,
                    });
                    let peers = self.network.peers_in_shard(shard);
                    for to in peers {
                        if to != node_index {
                            self.try_deliver_event(node_index, to, event.clone());
                        }
                    }
                }
            }

            // Normal event processing through NodeLoop
            self.node_loops[node_index as usize].set_time(self.now);
            let output = self.node_loops[node_index as usize].step(event);
            self.node_loops[node_index as usize].flush_all_batches();

            self.drain_node_io(node_index);
            self.process_step_output(node_index, output);
        }

        if self.now < end_time {
            self.now = end_time;
        }

        trace!(
            events_processed = self.stats.events_processed,
            actions_generated = self.stats.actions_generated,
            final_time = ?self.now,
            "Simulation step complete"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Output Draining
    // ═══════════════════════════════════════════════════════════════════════

    /// Drain network outbox, timer ops, pending requests, and buffered events from a node.
    ///
    /// Converts NodeLoop-internal outputs into harness-level operations:
    /// outbox entries → network delivery, timer ops → event queue,
    /// pending requests → fulfill from peer data, buffered events → event queue.
    fn drain_node_io(&mut self, node: NodeIndex) {
        let i = node as usize;
        let outbox = self.node_loops[i].network().drain_outbox();

        for entry in outbox {
            self.deliver_outbox_entry(node, entry);
        }

        // Fulfill pending network requests (block, tx, cert fetches).
        // Must happen BEFORE draining buffered events so that callback-generated
        // events are included in the drain below.
        let pending_requests = self.node_loops[i].network().drain_pending_requests();
        for request in pending_requests {
            self.fulfill_pending_request(node, request);
        }

        // Drain buffered events (includes events from callbacks above).
        while let Ok(event) = self.event_rxs[i].try_recv() {
            self.schedule_event(node, self.now, event);
        }
    }

    /// Process StepOutput: statuses, stats, and timer ops.
    fn process_step_output(&mut self, node: NodeIndex, output: StepOutput) {
        self.stats.actions_generated += output.actions_generated as u64;
        for (hash, status) in output.emitted_statuses {
            self.tx_status_cache.insert((node, hash), status);
        }
        for op in output.timer_ops {
            self.process_timer_op(node, op);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Network Delivery
    // ═══════════════════════════════════════════════════════════════════════

    /// Decode an outbox entry and deliver to target peers with partition/latency/loss.
    fn deliver_outbox_entry(
        &mut self,
        from: NodeIndex,
        entry: hyperscale_network_memory::OutboxEntry,
    ) {
        // Build topic for codec decoding
        let (topic, peers) = match entry.target {
            BroadcastTarget::Shard(shard) => {
                let topic = Topic::shard(entry.message_type, shard);
                let peers = self.network.peers_in_shard(shard);
                (topic, peers)
            }
            BroadcastTarget::Global => {
                let topic = Topic::global(entry.message_type);
                let total = self.network.total_nodes();
                let peers: Vec<NodeIndex> = (0..total as NodeIndex).collect();
                (topic, peers)
            }
            BroadcastTarget::Peer(peer) => {
                let topic = Topic::global(entry.message_type);
                let peers = vec![peer.0 as NodeIndex];
                (topic, peers)
            }
        };

        // Decode wire bytes back to events
        let events = decode_gossip_to_events(&topic, &entry.data)
            .expect("SimNetworkAdapter: encode/decode roundtrip failed");

        for to in peers {
            if to != from {
                for event in &events {
                    self.try_deliver_event(from, to, event.clone());
                }
            }
        }
    }

    /// Try to deliver an event, accounting for partitions and packet loss.
    fn try_deliver_event(&mut self, from: NodeIndex, to: NodeIndex, event: NodeInput) {
        if self.network.is_partitioned(from, to) {
            self.stats.messages_dropped_partition += 1;
            trace!(from = from, to = to, "Event dropped due to partition");
            return;
        }

        if self.network.should_drop_packet(&mut self.rng) {
            self.stats.messages_dropped_loss += 1;
            trace!(from = from, to = to, "Event dropped due to packet loss");
            return;
        }

        let latency = self.network.sample_latency(from, to, &mut self.rng);
        let delivery_time = self.now + latency;
        self.schedule_event(to, delivery_time, event);
        self.stats.messages_sent += 1;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Timer Handling
    // ═══════════════════════════════════════════════════════════════════════

    /// Process a timer operation from SimTimer.
    fn process_timer_op(&mut self, node: NodeIndex, op: TimerOp) {
        match op {
            TimerOp::Set { id, duration } => {
                let fire_time = self.now + duration;
                let event = self.timer_to_event(id.clone());
                let key = self.schedule_event(node, fire_time, event);
                self.timers.insert((node, id), key);
                self.stats.timers_set += 1;
            }
            TimerOp::Cancel { id } => {
                if let Some(key) = self.timers.remove(&(node, id)) {
                    self.event_queue.remove(&key);
                    self.stats.timers_cancelled += 1;
                }
            }
        }
    }

    /// Convert a timer ID to an event.
    fn timer_to_event(&self, id: TimerId) -> NodeInput {
        match id {
            TimerId::Proposal => NodeInput::Protocol(ProtocolEvent::ProposalTimer),
            TimerId::Cleanup => NodeInput::Protocol(ProtocolEvent::CleanupTimer),
            TimerId::GlobalConsensus => NodeInput::Protocol(ProtocolEvent::GlobalConsensusTimer),
            TimerId::FetchTick => NodeInput::FetchTick,
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Pending Request Fulfillment
    // ═══════════════════════════════════════════════════════════════════════

    /// Fulfill a pending network request from NodeLoop.
    ///
    /// Dispatches on `type_id` to decode the request, looks up data from peer
    /// nodes, applies partition/latency simulation, SBOR-encodes the response,
    /// and calls the callback with raw bytes.
    fn fulfill_pending_request(&mut self, node: NodeIndex, request: PendingRequest) {
        use hyperscale_messages::request::{
            GetBlockRequest, GetCertificatesRequest, GetTransactionsRequest,
        };
        use hyperscale_messages::response::{
            GetBlockResponse, GetCertificatesResponse, GetTransactionsResponse,
        };

        let PendingRequest {
            preferred_peer,
            type_id,
            request_bytes,
            on_response,
        } = request;

        match type_id {
            "block.request" => {
                let req: GetBlockRequest = match sbor::basic_decode(&request_bytes) {
                    Ok(r) => r,
                    Err(e) => {
                        warn!(node = node, error = ?e, "Failed to decode block request");
                        (on_response)(Err(RequestError::PeerError(format!("{e:?}"))));
                        return;
                    }
                };
                if let Some((peer, block, qc)) = self.find_block_from_any_peer(req.height.0) {
                    if self.simulate_request_response(node, peer).is_some() {
                        let resp = GetBlockResponse::found(block, qc);
                        let bytes = sbor::basic_encode(&resp).unwrap();
                        (on_response)(Ok(bytes));
                    } else {
                        (on_response)(Err(RequestError::PeerUnreachable(ValidatorId(peer as u64))));
                    }
                } else {
                    let resp = GetBlockResponse::not_found();
                    let bytes = sbor::basic_encode(&resp).unwrap();
                    (on_response)(Ok(bytes));
                }
            }
            "transaction.request" => {
                let req: GetTransactionsRequest = match sbor::basic_decode(&request_bytes) {
                    Ok(r) => r,
                    Err(e) => {
                        warn!(node = node, error = ?e, "Failed to decode tx request");
                        (on_response)(Err(RequestError::PeerError(format!("{e:?}"))));
                        return;
                    }
                };
                let proposer = preferred_peer.unwrap_or(ValidatorId(0));
                let proposer_node = proposer.0 as NodeIndex;
                if proposer_node as usize >= self.node_loops.len() {
                    warn!(
                        node = node,
                        proposer = ?proposer,
                        "Transaction fetch: proposer node not found"
                    );
                    (on_response)(Err(RequestError::PeerUnreachable(proposer)));
                    return;
                }

                if self
                    .simulate_request_response(node, proposer_node)
                    .is_none()
                {
                    trace!(
                        node = node,
                        proposer = proposer_node,
                        "Transaction fetch: request dropped (partition or packet loss)"
                    );
                    (on_response)(Err(RequestError::PeerUnreachable(proposer)));
                    return;
                }

                let mut found = Vec::new();
                {
                    let proposer_state = self.node_loops[proposer_node as usize].state();
                    let mempool = proposer_state.mempool();
                    for tx_hash in &req.tx_hashes {
                        if let Some(tx) = mempool.get_transaction(tx_hash) {
                            found.push(tx);
                        }
                    }
                }

                debug!(
                    node = node,
                    found_count = found.len(),
                    requested = req.tx_hashes.len(),
                    "Transaction fetch: fulfilled"
                );
                let resp = GetTransactionsResponse::new(found);
                let bytes = sbor::basic_encode(&resp).unwrap();
                (on_response)(Ok(bytes));
            }
            "certificate.request" => {
                let req: GetCertificatesRequest = match sbor::basic_decode(&request_bytes) {
                    Ok(r) => r,
                    Err(e) => {
                        warn!(node = node, error = ?e, "Failed to decode cert request");
                        (on_response)(Err(RequestError::PeerError(format!("{e:?}"))));
                        return;
                    }
                };
                let proposer = preferred_peer.unwrap_or(ValidatorId(0));
                let proposer_node = proposer.0 as NodeIndex;
                if proposer_node as usize >= self.node_loops.len() {
                    warn!(
                        node = node,
                        proposer = ?proposer,
                        "Certificate fetch: proposer node not found"
                    );
                    (on_response)(Err(RequestError::PeerUnreachable(proposer)));
                    return;
                }

                if self
                    .simulate_request_response(node, proposer_node)
                    .is_none()
                {
                    trace!(
                        node = node,
                        proposer = proposer_node,
                        "Certificate fetch: request dropped (partition or packet loss)"
                    );
                    (on_response)(Err(RequestError::PeerUnreachable(proposer)));
                    return;
                }

                let mut found = Vec::new();
                let proposer_storage = self.node_loops[proposer_node as usize].storage();
                for cert_hash in &req.cert_hashes {
                    if let Some(cert) = proposer_storage.get_certificate(cert_hash) {
                        found.push(cert);
                    }
                }

                debug!(
                    node = node,
                    found_count = found.len(),
                    requested = req.cert_hashes.len(),
                    "Certificate fetch: fulfilled"
                );
                let resp = GetCertificatesResponse::new(found);
                let bytes = sbor::basic_encode(&resp).unwrap();
                (on_response)(Ok(bytes));
            }
            _ => {
                warn!(node = node, type_id = type_id, "Unknown request type");
                (on_response)(Err(RequestError::PeerError(format!(
                    "unknown request type: {type_id}"
                ))));
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Fetch Helpers
    // ═══════════════════════════════════════════════════════════════════════

    /// Find a block at a given height from any peer's storage.
    fn find_block_from_any_peer(
        &self,
        height: u64,
    ) -> Option<(NodeIndex, Block, QuorumCertificate)> {
        for (idx, nl) in self.node_loops.iter().enumerate() {
            if let Some((block, qc)) = nl
                .storage()
                .get_block(hyperscale_types::BlockHeight(height))
            {
                return Some((idx as NodeIndex, block, qc));
            }
        }
        None
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Helpers
    // ═══════════════════════════════════════════════════════════════════════

    /// Schedule an event.
    fn schedule_event(&mut self, node: NodeIndex, time: Duration, event: NodeInput) -> EventKey {
        self.sequence += 1;
        let key = EventKey::new(time, &event, node, self.sequence);
        self.event_queue.insert(key, event);
        key
    }

    /// Simulate a request/response round-trip with network latency.
    fn simulate_request_response(
        &mut self,
        requester: NodeIndex,
        responder: NodeIndex,
    ) -> Option<Duration> {
        if self.network.is_partitioned(requester, responder) {
            self.stats.messages_dropped_partition += 1;
            trace!(
                requester = requester,
                responder = responder,
                "Request dropped due to partition"
            );
            return None;
        }

        if self.network.should_drop_packet(&mut self.rng) {
            self.stats.messages_dropped_loss += 1;
            trace!(
                requester = requester,
                responder = responder,
                "Request dropped due to packet loss"
            );
            return None;
        }

        if self.network.should_drop_packet(&mut self.rng) {
            self.stats.messages_dropped_loss += 1;
            trace!(
                requester = requester,
                responder = responder,
                "Response dropped due to packet loss"
            );
            return None;
        }

        let request_latency = self
            .network
            .sample_latency(requester, responder, &mut self.rng);
        let response_latency = self
            .network
            .sample_latency(responder, requester, &mut self.rng);
        let round_trip = request_latency + response_latency;

        self.stats.messages_sent += 2;

        Some(self.now + round_trip)
    }

    /// Get a committed block from a peer's storage.
    #[allow(dead_code)]
    fn get_committed_block(
        &self,
        peer: NodeIndex,
        height: u64,
    ) -> Option<(Block, QuorumCertificate)> {
        self.node_loops.get(peer as usize).and_then(|nl| {
            nl.storage()
                .get_block(hyperscale_types::BlockHeight(height))
        })
    }
}
