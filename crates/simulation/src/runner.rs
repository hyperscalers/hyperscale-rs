//! Deterministic simulation runner.
//!
//! Uses [`IoLoop`] to process all actions per-node, with the simulation harness
//! controlling event scheduling, network delivery, and time.

use crate::event_queue::EventKey;
use crate::NodeIndex;
use hyperscale_bft::{BftConfig, RecoveredState};
use hyperscale_core::{NodeInput, ProtocolEvent, TimerId};
use hyperscale_dispatch_sync::SyncDispatch;
use hyperscale_engine::{Engine, RadixExecutor, SimExecutionCache, SimulationEngine};
use hyperscale_mempool::MempoolConfig;
use hyperscale_network_memory::{
    NetworkConfig, NetworkTrafficAnalyzer, SimNetworkAdapter, SimulatedNetwork,
};
use hyperscale_node::io_loop::{IoLoop, StepOutput};
use hyperscale_node::{NodeConfig, NodeStateMachine, TimerOp};
use hyperscale_storage::{ChainReader, GenesisWrapper};
use hyperscale_storage_memory::SimStorage;
use hyperscale_topology::TopologyState;
use hyperscale_types::{
    bls_keypair_from_seed, shard_for_node, BlockHeight, Bls12381G1PrivateKey, Bls12381G1PublicKey,
    CertifiedBlock, NodeId, ShardGroupId, TransactionStatus, TxHash, ValidatorId, ValidatorInfo,
    ValidatorSet,
};
use radix_common::network::NetworkDefinition;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, trace, warn};

/// Type alias for the simulation's concrete IoLoop.
type SimIoLoop = IoLoop<SimStorage, SimNetworkAdapter, SyncDispatch, SimulationEngine>;

/// Type alias for the simulation's genesis wrapper.
type SimGenesisWrapper<'a> = GenesisWrapper<'a, SimStorage>;

/// Deterministic simulation runner.
///
/// Processes events in deterministic order using [`IoLoop`] for action handling.
/// Given the same seed, produces identical results every run.
///
/// Each node has its own independent storage and executor inside its `IoLoop`.
/// The harness controls the event queue, network delivery (latency, partitions,
/// packet loss), and time advancement.
pub struct SimulationRunner {
    /// Per-node IoLoop instances. Index corresponds to NodeIndex.
    io_loops: Vec<SimIoLoop>,

    /// Per-node event receivers (from crossbeam channels passed to IoLoop).
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

    /// Last time gossip dedup caches were pruned.
    last_gossip_dedup_prune: Duration,
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

        // Create IoLoop for each validator
        let num_nodes = total_validators as usize;
        let mut io_loops = Vec::with_capacity(num_nodes);
        let mut event_rxs = Vec::with_capacity(num_nodes);

        for shard_id in 0..network_config.num_shards {
            let shard = ShardGroupId(shard_id as u64);
            let shard_start = shard_id * network_config.validators_per_shard;

            // Shared execution cache for all validators in this shard.
            // Identical transactions against identical state produce identical
            // results — only the first validator computes; others get the cache.
            let shard_cache: SimExecutionCache = Default::default();

            for v in 0..network_config.validators_per_shard {
                let node_index = shard_start + v;
                let validator_id = ValidatorId(node_index as u64);

                let topology_state = TopologyState::with_shard_committees(
                    validator_id,
                    shard,
                    network_config.num_shards as u64,
                    &global_validator_set,
                    shard_committees.clone(),
                );

                let key_bytes = keys[node_index as usize].to_bytes();
                let signing_key =
                    Bls12381G1PrivateKey::from_bytes(&key_bytes).expect("valid key bytes");

                // Clone the current snapshot for IoLoop (state machine owns TopologyState)
                let topology_arc = Arc::new(arc_swap::ArcSwap::from(Arc::clone(
                    topology_state.snapshot(),
                )));

                let state = NodeStateMachine::new(
                    node_index as NodeIndex,
                    topology_state,
                    &BftConfig::default(),
                    RecoveredState::default(),
                    MempoolConfig::default(),
                    hyperscale_provisions::ProvisionConfig::default(),
                    Arc::new(hyperscale_provisions::ProvisionStore::new()),
                );

                let (event_tx, event_rx) = crossbeam::channel::unbounded();

                let network_def = NetworkDefinition::simulator();
                let tx_validator = Arc::new(hyperscale_engine::TransactionValidation::permissive(
                    network_def.clone(),
                ));

                let sim_engine =
                    SimulationEngine::new(RadixExecutor::new(network_def), shard_cache.clone());

                let io_loop = IoLoop::new(
                    state,
                    SimStorage::new(),
                    sim_engine,
                    network.create_adapter(node_index),
                    SyncDispatch,
                    event_tx,
                    signing_key,
                    topology_arc,
                    NodeConfig::default(),
                    tx_validator,
                );

                io_loops.push(io_loop);
                event_rxs.push(event_rx);
            }
        }

        info!(
            num_nodes = io_loops.len(),
            num_shards = network_config.num_shards,
            validators_per_shard = network_config.validators_per_shard,
            seed,
            "Created simulation runner"
        );

        Self {
            io_loops,
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
            last_gossip_dedup_prune: Duration::ZERO,
        }
    }

    /// Create a new simulation runner with traffic analysis enabled.
    pub fn with_traffic_analysis(network_config: NetworkConfig, seed: u64) -> Self {
        let mut runner = Self::new(network_config, seed);
        let analyzer = Arc::new(NetworkTrafficAnalyzer::new());
        runner.network.set_traffic_analyzer(Arc::clone(&analyzer));
        runner.traffic_analyzer = Some(analyzer);
        runner
    }

    /// Enable traffic analysis on an existing runner.
    pub fn enable_traffic_analysis(&mut self) {
        if self.traffic_analyzer.is_none() {
            let analyzer = Arc::new(NetworkTrafficAnalyzer::new());
            self.network.set_traffic_analyzer(Arc::clone(&analyzer));
            self.traffic_analyzer = Some(analyzer);
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
        self.io_loops.get(node as usize).map(|nl| nl.storage())
    }

    /// Get the last emitted transaction status for a node.
    pub fn tx_status(&self, node: NodeIndex, tx_hash: &TxHash) -> Option<TransactionStatus> {
        self.io_loops
            .get(node as usize)
            .and_then(|nl| nl.tx_status(tx_hash))
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
        self.io_loops.get(index as usize).map(|nl| nl.state())
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
        self.io_loops
            .get(node as usize)
            .map(|nl| {
                let s = nl.storage();
                let committed = s.committed_height();
                if committed.0 == 0 {
                    if s.get_block(BlockHeight(0)).is_some() {
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
    pub fn has_committed_block(&self, node: NodeIndex, height: BlockHeight) -> bool {
        self.io_loops
            .get(node as usize)
            .map(|nl| nl.storage().get_block(height).is_some())
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
        // Run Radix Engine genesis on each node's storage.
        // SimGenesisWrapper writes substates only (no JMT) during bootstrap,
        // then computes JMT once at version 0 to avoid collisions with block 1.
        for node_idx in 0..self.io_loops.len() {
            if !self.genesis_executed[node_idx] {
                self.io_loops[node_idx].with_storage_and_executor(|storage, executor| {
                    let mut wrapper = SimGenesisWrapper::new(storage);
                    if let Err(e) = executor.run_genesis(&mut wrapper) {
                        warn!(node = node_idx, "Radix Engine genesis failed: {:?}", e);
                        return;
                    }
                    let merged = wrapper.into_merged();
                    storage.finalize_genesis_jmt(&merged);
                });
                self.genesis_executed[node_idx] = true;
            }
        }
        info!(
            num_nodes = self.io_loops.len(),
            "Radix Engine genesis complete on all nodes"
        );

        self.finalize_genesis();
    }

    /// Initialize genesis with pre-funded accounts.
    ///
    /// Each node only receives the accounts that belong to its shard, avoiding
    /// the Radix Engine genesis limit (~8000 accounts per node). The balances
    /// list may contain accounts from all shards — they are filtered per-node.
    pub fn initialize_genesis_with_balances(
        &mut self,
        balances: Vec<(
            radix_common::types::ComponentAddress,
            radix_common::math::Decimal,
        )>,
    ) {
        use hyperscale_engine::GenesisConfig;

        let num_shards = self.network.config().num_shards as u64;
        let validators_per_shard = self.network.config().validators_per_shard;

        // Pre-group balances by shard so we don't re-filter for every node.
        let mut balances_by_shard: HashMap<ShardGroupId, Vec<_>> = HashMap::new();
        for (address, balance) in &balances {
            let radix_node_id = address.into_node_id();
            let det_node_id = NodeId(radix_node_id.0[..30].try_into().unwrap());
            let shard = shard_for_node(&det_node_id, num_shards);
            balances_by_shard
                .entry(shard)
                .or_default()
                .push((*address, *balance));
        }

        // Run Radix Engine genesis on each node's storage with only its shard's accounts.
        // SimGenesisWrapper writes substates only (no JMT) during bootstrap,
        // then computes JMT once at version 0 to avoid collisions with block 1.
        for node_idx in 0..self.io_loops.len() {
            if !self.genesis_executed[node_idx] {
                let shard_id = ShardGroupId(node_idx as u64 / validators_per_shard as u64);
                let shard_balances = balances_by_shard
                    .get(&shard_id)
                    .cloned()
                    .unwrap_or_default();

                self.io_loops[node_idx].with_storage_and_executor(|storage, executor| {
                    let mut wrapper = SimGenesisWrapper::new(storage);
                    let config = GenesisConfig {
                        xrd_balances: shard_balances,
                        ..GenesisConfig::test_default()
                    };
                    if let Err(e) = executor.run_genesis_with_config(&mut wrapper, config) {
                        warn!(node = node_idx, "Radix Engine genesis failed: {:?}", e);
                        return;
                    }
                    let merged = wrapper.into_merged();
                    storage.finalize_genesis_jmt(&merged);
                });
                self.genesis_executed[node_idx] = true;
            }
        }
        info!(
            num_nodes = self.io_loops.len(),
            num_funded_accounts = balances.len(),
            "Radix Engine genesis complete with funded accounts"
        );

        self.finalize_genesis();
    }

    /// Initialize state-machine genesis on all nodes.
    ///
    /// Called after engine genesis via `with_storage_and_executor` (which also
    /// registers inbound handlers). Creates genesis blocks per shard and
    /// initializes each node's state machine.
    fn finalize_genesis(&mut self) {
        use hyperscale_storage::SubstateStore;
        use hyperscale_types::Block;

        let num_shards = self.network.config().num_shards;
        let validators_per_shard = self.network.config().validators_per_shard;

        for shard_id in 0..num_shards {
            let shard_start = shard_id * validators_per_shard;
            let first_node_storage = self.io_loops[shard_start as usize].storage();
            let genesis_jmt_root = first_node_storage.state_root();

            info!(
                shard = shard_id,
                genesis_jmt_root = ?genesis_jmt_root,
                "JMT state after genesis bootstrap"
            );

            let proposer = ValidatorId((shard_id * validators_per_shard) as u64);
            let genesis_block = Block::genesis(
                hyperscale_types::ShardGroupId(shard_id as u64),
                proposer,
                genesis_jmt_root,
            );

            let shard_end = shard_start + validators_per_shard;
            for node_index in shard_start..shard_end {
                let i = node_index as usize;
                let actions = self.io_loops[i]
                    .state_mut()
                    .initialize_genesis(&genesis_block);
                self.io_loops[i].handle_actions(actions);
                self.io_loops[i].flush_all_batches();

                // Drain outputs from genesis initialization (timer sets, etc.)
                let output = self.io_loops[i].drain_pending_output();
                self.drain_node_io(node_index);
                self.process_step_output(node_index, output);

                // Sync state machine with actual JMT state after genesis bootstrap.
                // Pair the genesis block with a zeroed QC whose `block_hash` matches
                // so the CertifiedBlock pairing invariant holds.
                let genesis_qc = hyperscale_types::QuorumCertificate {
                    block_hash: genesis_block.hash(),
                    ..hyperscale_types::QuorumCertificate::genesis()
                };
                let genesis_certified =
                    CertifiedBlock::new_unchecked(genesis_block.clone(), genesis_qc);
                let genesis_commit_event = NodeInput::Protocol(ProtocolEvent::BlockCommitted {
                    certified: genesis_certified,
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

        loop {
            // Determine next time: min(event_queue, all pending deliveries)
            let next_event = self.event_queue.first_key_value().map(|(k, _)| k.time);
            let next_delivery = self.network.next_delivery_time();

            let next_time = match (next_event, next_delivery) {
                (Some(e), Some(d)) => e.min(d),
                (Some(t), None) | (None, Some(t)) => t,
                (None, None) => break,
            };

            if next_time > end_time {
                debug!(
                    remaining_events = self.event_queue.len(),
                    "Time limit reached"
                );
                break;
            }

            self.now = next_time;

            // Prune gossip dedup caches every 5 simulated seconds.
            // Dedup only needs to cover the window in which duplicate broadcasts
            // arrive (~cross-shard latency), so 5s is very conservative.
            const GOSSIP_DEDUP_PRUNE_INTERVAL: Duration = Duration::from_secs(5);
            if self.now.saturating_sub(self.last_gossip_dedup_prune) >= GOSSIP_DEDUP_PRUNE_INTERVAL
            {
                self.network.prune_gossip_dedup();
                self.last_gossip_dedup_prune = self.now;
            }

            // Flush all delivery queues that are due — handlers/callbacks push
            // events into crossbeam channels.
            let gossip_delivered = self.network.flush_gossip(self.now);
            let notif_delivered = self.network.flush_notifications(self.now);
            let response_delivered = self.network.flush_responses(self.now);

            if gossip_delivered + notif_delivered + response_delivered > 0 {
                // Drain events that handlers pushed into channels.
                for node_idx in 0..self.io_loops.len() as u32 {
                    while let Ok(event) = self.event_rxs[node_idx as usize].try_recv() {
                        self.schedule_event(node_idx, self.now, event);
                    }
                }
            }

            // Process all events at current time.
            while let Some((&key, _)) = self.event_queue.first_key_value() {
                if key.time > self.now {
                    break;
                }

                let (key, event) = self.event_queue.pop_first().unwrap();
                let node_index = key.node_index;

                trace!(
                    time = ?self.now,
                    node = node_index,
                    "Processing event"
                );

                self.stats.events_processed += 1;
                self.stats.events_by_priority[event.priority() as usize] += 1;

                self.io_loops[node_index as usize].set_time(
                    hyperscale_types::LocalTimestamp::from_millis(self.now.as_millis() as u64),
                );
                let output = self.io_loops[node_index as usize].step(event);
                self.io_loops[node_index as usize].flush_all_batches();

                self.drain_node_io(node_index);
                self.process_step_output(node_index, output);
            }
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

    /// Drain network outbox, pending requests, pending notifications, and
    /// buffered events from a node.
    ///
    /// Converts IoLoop-internal outputs into harness-level operations:
    /// - Outbox entries → gossip latency queue
    /// - Pending requests → handler invoked, response callback deferred
    /// - Pending notifications → notification latency queue
    /// - Buffered events (from error callbacks, IoLoop step) → event queue
    fn drain_node_io(&mut self, node: NodeIndex) {
        let i = node as usize;
        let outbox = self.io_loops[i].network().drain_outbox();

        for entry in outbox {
            let stats = self
                .network
                .accept_gossip(node, self.now, entry, &mut self.rng);
            self.stats.messages_sent += stats.messages_sent;
            self.stats.messages_dropped_partition += stats.messages_dropped_partition;
            self.stats.messages_dropped_loss += stats.messages_dropped_loss;
            self.stats.messages_deduplicated += stats.messages_deduplicated;
        }

        // Accept pending requests: handler invoked now, response callback
        // deferred with round-trip latency. Error callbacks fire immediately
        // and push events into channels, so drain must happen after this.
        let pending_requests = self.io_loops[i].network().drain_pending_requests();
        if !pending_requests.is_empty() {
            let stats =
                self.network
                    .accept_requests(node, self.now, pending_requests, &mut self.rng);
            self.stats.messages_sent += stats.messages_sent;
            self.stats.messages_dropped_partition += stats.messages_dropped_partition;
            self.stats.messages_dropped_loss += stats.messages_dropped_loss;
        }

        // Accept pending notifications: queued for deferred delivery with latency.
        let pending_notifications = self.io_loops[i].network().drain_pending_notifications();
        if !pending_notifications.is_empty() {
            let stats = self.network.accept_notifications(
                node,
                self.now,
                pending_notifications,
                &mut self.rng,
            );
            self.stats.messages_sent += stats.messages_sent;
            self.stats.messages_dropped_partition += stats.messages_dropped_partition;
            self.stats.messages_dropped_loss += stats.messages_dropped_loss;
        }

        // Drain buffered events (from error callbacks in accept_requests,
        // plus any events the IoLoop step itself pushed).
        while let Ok(event) = self.event_rxs[i].try_recv() {
            self.schedule_event(node, self.now, event);
        }
    }

    /// Process StepOutput: stats and timer ops.
    fn process_step_output(&mut self, node: NodeIndex, output: StepOutput) {
        self.stats.actions_generated += output.actions_generated as u64;
        if let Some(task) = output.commit_task {
            task();
        }
        for op in output.timer_ops {
            self.process_timer_op(node, op);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Timer Handling
    // ═══════════════════════════════════════════════════════════════════════

    /// Process a timer operation from SimTimer.
    fn process_timer_op(&mut self, node: NodeIndex, op: TimerOp) {
        match op {
            TimerOp::Set { id, duration } => {
                let fire_time = self.now + duration;
                let event = id.clone().into_event();
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

    // ═══════════════════════════════════════════════════════════════════════
    // Helpers
    // ═══════════════════════════════════════════════════════════════════════

    /// Schedule a [`NodeInput`] event for delivery at the given time.
    fn schedule_event(&mut self, node: NodeIndex, time: Duration, event: NodeInput) -> EventKey {
        self.sequence += 1;
        let key = EventKey::new(time, &event, node, self.sequence);
        self.event_queue.insert(key, event);
        key
    }
}
