//! Deterministic simulation runner.
//!
//! Each node has its own storage and executor. When a node emits
//! `Action::ExecuteTransactions`, the runner calls that node's executor
//! inline (synchronously) for deterministic execution.

use crate::event_queue::EventKey;
use crate::network::{NetworkConfig, SimulatedNetwork};
use crate::storage::SimStorage;
use crate::traffic::NetworkTrafficAnalyzer;
use crate::NodeIndex;
use hyperscale_bft::{BftConfig, RecoveredState};
use hyperscale_core::{Action, Event, OutboundMessage, StateMachine, TimerId};
use hyperscale_engine::{JmtSnapshot, RadixExecutor};
use hyperscale_execution::{DEFAULT_SPECULATIVE_MAX_TXS, DEFAULT_VIEW_CHANGE_COOLDOWN_ROUNDS};
use hyperscale_mempool::MempoolConfig;
use hyperscale_node::NodeStateMachine;
use hyperscale_types::{
    batch_verify_bls_same_message, bls_keypair_from_seed, verify_bls12381_v1, zero_bls_signature,
    Block, BlockVote, Bls12381G1PrivateKey, Bls12381G1PublicKey, Bls12381G2Signature,
    CommitmentProof, Hash as TxHash, QuorumCertificate, ShardGroupId, SignerBitfield,
    StateCertificate, StateVoteBlock, StaticTopology, Topology, TransactionStatus, ValidatorId,
    ValidatorInfo, ValidatorSet, VotePower,
};
use radix_common::network::NetworkDefinition;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::{Hash, Hasher}; // Used by compute_dedup_key
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, trace, warn};

/// Deterministic simulation runner.
///
/// Processes events in deterministic order and executes actions.
/// Given the same seed, produces identical results every run.
///
/// Each node has its own independent storage and executor - they are separate
/// validators that don't share state. When a node emits `Action::ExecuteTransactions`,
/// the runner calls that node's executor inline (synchronously).
pub struct SimulationRunner {
    /// All nodes in the simulation, indexed by NodeIndex.
    nodes: Vec<NodeStateMachine>,

    /// Global event queue, ordered deterministically.
    event_queue: BTreeMap<EventKey, Event>,

    /// Sequence counter for deterministic ordering.
    sequence: u64,

    /// Current simulation time.
    now: Duration,

    /// Network simulator.
    network: SimulatedNetwork,

    /// RNG for network conditions (seeded for determinism).
    rng: ChaCha8Rng,

    /// Timer registry for cancellation support.
    /// Maps (node, timer_id) -> event_key for removal.
    timers: HashMap<(NodeIndex, TimerId), EventKey>,

    /// Statistics.
    stats: SimulationStats,

    /// Per-node storage. Each node has its own independent storage.
    /// Index corresponds to node index.
    node_storage: Vec<SimStorage>,

    /// Per-node executor. Each node has its own executor instance.
    /// Index corresponds to node index.
    node_executor: Vec<RadixExecutor>,

    /// Per-node signing keys. Each node has its own key for signing votes.
    /// Index corresponds to node index.
    node_keys: Vec<Bls12381G1PrivateKey>,

    /// Whether genesis has been executed on each node's storage.
    /// Index corresponds to node index.
    genesis_executed: Vec<bool>,

    /// Optional traffic analyzer for bandwidth estimation.
    traffic_analyzer: Option<Arc<NetworkTrafficAnalyzer>>,

    /// Seen message cache for deduplication (matches libp2p gossipsub behavior).
    /// Key is hash of (recipient, message_hash) to deduplicate per-node.
    seen_messages: HashSet<u64>,

    /// Per-node sync targets. Maps node index to sync target height.
    /// Used by the runner to track sync progress (replaces SyncState tracking).
    sync_targets: HashMap<NodeIndex, u64>,

    /// Per-node transaction status cache. Captures all emitted statuses.
    /// Maps (node_index, tx_hash) -> status for querying final transaction states.
    tx_status_cache: HashMap<(NodeIndex, TxHash), TransactionStatus>,

    /// Per-node JMT snapshot cache.
    /// Stores snapshots created during verification for reuse at commit time.
    /// Maps (node_index, block_hash) -> snapshot.
    jmt_cache: HashMap<(NodeIndex, TxHash), JmtSnapshot>,
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
    /// Create a new simulation runner with the given configuration.
    pub fn new(network_config: NetworkConfig, seed: u64) -> Self {
        let network = SimulatedNetwork::new(network_config.clone());
        let rng = ChaCha8Rng::seed_from_u64(seed);

        // Generate keys for all validators using deterministic seeding
        let total_validators = network_config.num_shards * network_config.validators_per_shard;
        let keys: Vec<Bls12381G1PrivateKey> = (0..total_validators)
            .map(|i| {
                // Use deterministic seed for each validator's key
                let mut seed_bytes = [0u8; 32];
                let key_seed = seed.wrapping_add(i as u64).wrapping_mul(0x517cc1b727220a95);
                seed_bytes[..8].copy_from_slice(&key_seed.to_le_bytes());
                seed_bytes[8..16].copy_from_slice(&(i as u64).to_le_bytes());
                bls_keypair_from_seed(&seed_bytes)
            })
            .collect();
        let public_keys: Vec<Bls12381G1PublicKey> = keys.iter().map(|k| k.public_key()).collect();

        // Build global validator set for the entire network
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

        // Create per-node storage
        let num_nodes = total_validators as usize;
        let node_storage: Vec<SimStorage> = (0..num_nodes).map(|_| SimStorage::new()).collect();
        let node_executor: Vec<RadixExecutor> = (0..num_nodes)
            .map(|_| RadixExecutor::new(NetworkDefinition::simulator()))
            .collect();
        let genesis_executed = vec![false; num_nodes];

        // Create nodes with StaticTopology
        let mut nodes = Vec::new();
        for shard_id in 0..network_config.num_shards {
            let shard = ShardGroupId(shard_id as u64);
            let shard_start = shard_id * network_config.validators_per_shard;

            for v in 0..network_config.validators_per_shard {
                let node_index = shard_start + v;
                let validator_id = ValidatorId(node_index as u64);

                // Create topology for this node
                let topology: Arc<dyn Topology> = Arc::new(StaticTopology::with_shard_committees(
                    validator_id,
                    shard,
                    network_config.num_shards as u64,
                    &global_validator_set,
                    shard_committees.clone(),
                ));

                // Fresh start - no recovered state
                // Clone key bytes since Bls12381G1PrivateKey doesn't impl Clone
                let key_bytes = keys[node_index as usize].to_bytes();
                let signing_key =
                    Bls12381G1PrivateKey::from_bytes(&key_bytes).expect("valid key bytes");
                nodes.push(NodeStateMachine::with_speculative_config(
                    node_index as NodeIndex,
                    topology,
                    signing_key,
                    BftConfig::default(),
                    RecoveredState::default(),
                    DEFAULT_SPECULATIVE_MAX_TXS,
                    DEFAULT_VIEW_CHANGE_COOLDOWN_ROUNDS,
                    MempoolConfig::default(),
                ));
            }
        }

        info!(
            num_nodes = nodes.len(),
            num_shards = network_config.num_shards,
            validators_per_shard = network_config.validators_per_shard,
            seed,
            "Created simulation runner"
        );

        Self {
            nodes,
            event_queue: BTreeMap::new(),
            sequence: 0,
            now: Duration::ZERO,
            network,
            rng,
            timers: HashMap::new(),
            stats: SimulationStats::default(),
            node_storage,
            node_executor,
            node_keys: keys,
            genesis_executed,
            traffic_analyzer: None,
            seen_messages: HashSet::new(),
            sync_targets: HashMap::new(),
            tx_status_cache: HashMap::new(),
            jmt_cache: HashMap::new(),
        }
    }

    /// Create a new simulation runner with traffic analysis enabled.
    ///
    /// This creates a runner that records all network messages for bandwidth
    /// analysis. Use `traffic_report()` at the end of the simulation to get
    /// detailed bandwidth statistics.
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
    ///
    /// Returns `None` if traffic analysis is not enabled.
    pub fn traffic_report(&self) -> Option<crate::traffic::BandwidthReport> {
        self.traffic_analyzer
            .as_ref()
            .map(|analyzer| analyzer.generate_report(self.now, self.network.total_nodes()))
    }

    /// Get a reference to a node's storage.
    pub fn node_storage(&self, node: NodeIndex) -> Option<&SimStorage> {
        self.node_storage.get(node as usize)
    }

    /// Get the last emitted transaction status for a node.
    ///
    /// Unlike `node.mempool().status()`, this returns the last status that was
    /// emitted via `EmitTransactionStatus` action, even if the transaction has
    /// been evicted from the mempool (e.g., after reaching terminal state).
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

    /// Get a reference to a node by index.
    pub fn node(&self, index: NodeIndex) -> Option<&NodeStateMachine> {
        self.nodes.get(index as usize)
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
        self.node_storage
            .get(node as usize)
            .map(|s| {
                // Count blocks from height 0 to committed_height
                let committed = s.committed_height();
                if committed.0 == 0 {
                    // Check if genesis block exists
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
        self.node_storage
            .get(node as usize)
            .map(|s| s.get_block(hyperscale_types::BlockHeight(height)).is_some())
            .unwrap_or(false)
    }

    /// Schedule an initial event (e.g., to start the simulation).
    pub fn schedule_initial_event(&mut self, node: NodeIndex, delay: Duration, event: Event) {
        let time = self.now + delay;
        self.schedule_event(node, time, event);
    }

    /// Initialize all nodes with genesis blocks and start consensus.
    ///
    /// This performs two types of genesis:
    /// 1. **Radix Engine genesis**: Initializes each node's storage with system
    ///    packages, faucet, initial accounts, etc.
    /// 2. **Consensus genesis**: Creates genesis blocks for each shard and
    ///    initializes all validators.
    ///
    /// The consensus genesis block has:
    /// - Height 0
    /// - Zero parent hash
    /// - Genesis QC (empty)
    /// - First validator as proposer
    ///
    /// After initialization, proposal timers are scheduled for all nodes.
    pub fn initialize_genesis(&mut self) {
        use hyperscale_engine::SubstateStore;
        use hyperscale_types::{Block, BlockHeader, BlockHeight, Hash, QuorumCertificate};

        // Run Radix Engine genesis on each node's storage
        for node_idx in 0..self.nodes.len() {
            if !self.genesis_executed[node_idx] {
                let storage = &mut self.node_storage[node_idx];
                let executor = &self.node_executor[node_idx];

                if let Err(e) = executor.run_genesis(storage) {
                    warn!(node = node_idx, "Radix Engine genesis failed: {:?}", e);
                    // Continue anyway - tests may not need full Radix state
                }
                self.genesis_executed[node_idx] = true;
            }
        }
        info!(
            num_nodes = self.nodes.len(),
            "Radix Engine genesis complete on all nodes"
        );

        let num_shards = self.network.config().num_shards;
        let validators_per_shard = self.network.config().validators_per_shard;

        for shard_id in 0..num_shards {
            // Get the JMT state AFTER genesis bootstrap from the first node in this shard.
            // All nodes in the shard should have identical JMT state after genesis.
            // This is critical - genesis block header must reflect the actual JMT state.
            let shard_start = shard_id * validators_per_shard;
            let first_node_storage = &self.node_storage[shard_start as usize];
            let genesis_jmt_version = first_node_storage.state_version();
            let genesis_jmt_root = Hash::from_bytes(&first_node_storage.state_root_hash().0);

            info!(
                shard = shard_id,
                genesis_jmt_version,
                genesis_jmt_root = ?genesis_jmt_root,
                "JMT state after genesis bootstrap"
            );

            // Create genesis block for this shard using actual JMT state
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
            };

            let genesis_block = Block {
                header: genesis_header,
                retry_transactions: vec![],
                priority_transactions: vec![],
                transactions: vec![],
                committed_certificates: vec![],
                deferred: vec![],
                aborted: vec![],
                commitment_proofs: std::collections::HashMap::new(),
            };

            // Initialize all validators in this shard
            let shard_end = shard_start + validators_per_shard;

            for node_index in shard_start..shard_end {
                let node = &mut self.nodes[node_index as usize];
                let actions = node.initialize_genesis(genesis_block.clone());

                // Process the actions (which should set initial timers)
                for action in actions {
                    self.process_action(node_index, action);
                }

                // CRITICAL: Send StateCommitComplete to sync state machine with actual JMT state.
                // The state machine was initialized with zero/default state, but genesis bootstrap
                // has populated the JMT. We need to sync so future blocks compute state_root
                // from the correct base.
                let genesis_commit_event = Event::StateCommitComplete {
                    height: 0,
                    state_version: genesis_jmt_version,
                    state_root: genesis_jmt_root,
                };
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
    ///
    /// Like `initialize_genesis`, but also funds the specified accounts at genesis time.
    /// This is useful for simulations that need accounts with XRD balances.
    pub fn initialize_genesis_with_balances(
        &mut self,
        balances: Vec<(
            radix_common::types::ComponentAddress,
            radix_common::math::Decimal,
        )>,
    ) {
        use hyperscale_engine::{GenesisConfig, SubstateStore};
        use hyperscale_types::{Block, BlockHeader, BlockHeight, Hash, QuorumCertificate};

        // Run Radix Engine genesis on each node's storage with balances
        for node_idx in 0..self.nodes.len() {
            if !self.genesis_executed[node_idx] {
                let storage = &mut self.node_storage[node_idx];
                let executor = &self.node_executor[node_idx];

                // Create genesis config with balances
                let config = GenesisConfig {
                    xrd_balances: balances.clone(),
                    ..GenesisConfig::test_default()
                };

                if let Err(e) = executor.run_genesis_with_config(storage, config) {
                    warn!(node = node_idx, "Radix Engine genesis failed: {:?}", e);
                    // Continue anyway - tests may not need full Radix state
                }
                self.genesis_executed[node_idx] = true;
            }
        }
        info!(
            num_nodes = self.nodes.len(),
            num_funded_accounts = balances.len(),
            "Radix Engine genesis complete with funded accounts"
        );

        let num_shards = self.network.config().num_shards;
        let validators_per_shard = self.network.config().validators_per_shard;

        for shard_id in 0..num_shards {
            // Get the JMT state AFTER genesis bootstrap from the first node in this shard.
            // All nodes in the shard should have identical JMT state after genesis.
            // This is critical - genesis block header must reflect the actual JMT state.
            let shard_start = shard_id * validators_per_shard;
            let first_node_storage = &self.node_storage[shard_start as usize];
            let genesis_jmt_version = first_node_storage.state_version();
            let genesis_jmt_root = Hash::from_bytes(&first_node_storage.state_root_hash().0);

            info!(
                shard = shard_id,
                genesis_jmt_version,
                genesis_jmt_root = ?genesis_jmt_root,
                "JMT state after genesis bootstrap"
            );

            // Create genesis block for this shard using actual JMT state
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
            };

            let genesis_block = Block {
                header: genesis_header,
                retry_transactions: vec![],
                priority_transactions: vec![],
                transactions: vec![],
                committed_certificates: vec![],
                deferred: vec![],
                aborted: vec![],
                commitment_proofs: std::collections::HashMap::new(),
            };

            // Initialize all validators in this shard
            let shard_end = shard_start + validators_per_shard;

            for node_index in shard_start..shard_end {
                let node = &mut self.nodes[node_index as usize];
                let actions = node.initialize_genesis(genesis_block.clone());

                // Process the actions (which should set initial timers)
                for action in actions {
                    self.process_action(node_index, action);
                }

                // CRITICAL: Send StateCommitComplete to sync state machine with actual JMT state.
                // The state machine was initialized with zero/default state, but genesis bootstrap
                // has populated the JMT. We need to sync so future blocks compute state_root
                // from the correct base.
                let genesis_commit_event = Event::StateCommitComplete {
                    height: 0,
                    state_version: genesis_jmt_version,
                    state_root: genesis_jmt_root,
                };
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

            // Pop the next event
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
            // This mirrors production behavior where the runner handles gossip,
            // not the state machine.
            if let Event::SubmitTransaction { ref tx } = event {
                let topology = self.nodes[node_index as usize].topology();
                let gossip = hyperscale_messages::TransactionGossip::from_arc(Arc::clone(tx));
                for shard in topology.all_shards_for_transaction(tx) {
                    let message = OutboundMessage::TransactionGossip(Box::new(gossip.clone()));
                    let peers = self.network.peers_in_shard(shard);
                    for to in peers {
                        if to != node_index {
                            self.try_deliver_message(node_index, to, &message);
                        }
                    }
                }
            }

            // Handle TransactionCertificateReceived directly in runner (like production).
            // Verify signatures synchronously (no async in simulation) and persist.
            if let Event::TransactionCertificateReceived { ref certificate } = event {
                let storage = &mut self.node_storage[node_index as usize];
                let tx_hash = certificate.transaction_hash;

                // Skip if already in storage
                if storage.get_certificate(&tx_hash).is_some() {
                    continue;
                }

                // In simulation, we trust certificates (skip BLS verification for speed).
                // Production verifies signatures before persisting.
                // For full fidelity, we could add verification here but it would slow tests.

                // Store certificate WITHOUT committing state writes.
                // State writes are only applied when the certificate is included in a
                // committed block (via Action::PersistTransactionCertificate).
                // This matches production behavior and keeps JMT state consistent.
                storage.store_certificate(certificate);

                // Notify state machine to cancel local building and add to finalized
                let node = &mut self.nodes[node_index as usize];
                let actions = node.handle(Event::GossipedCertificateVerified {
                    certificate: certificate.clone(),
                });
                for action in actions {
                    self.process_action(node_index, action);
                }

                continue;
            }

            // Update node's time and process event
            let node = &mut self.nodes[node_index as usize];
            node.set_time(self.now);
            let actions = node.handle(event);

            self.stats.actions_generated += actions.len() as u64;

            // Handle actions
            for action in actions {
                self.process_action(node_index, action);
            }

            // If this node is syncing, check if more blocks can be fetched from peers.
            // This handles the case where sync was triggered before target blocks were
            // available on peers. As other nodes commit blocks and broadcast headers,
            // new blocks become available for sync.
            if let Some(&sync_target) = self.sync_targets.get(&node_index) {
                let current_height = self.nodes[node_index as usize].bft().committed_height();
                if current_height < sync_target {
                    self.handle_sync_needed(node_index, sync_target);
                }
            }
        }

        // Always advance time to end_time, even if we ran out of events.
        // This ensures callers can rely on runner.now() advancing to the requested time,
        // preventing infinite loops in polling patterns like:
        //   while runner.now() < deadline { runner.run_until(runner.now() + step); }
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

    /// Process an action from a node.
    fn process_action(&mut self, from: NodeIndex, action: Action) {
        match action {
            Action::BroadcastToShard { shard, message } => {
                let peers = self.network.peers_in_shard(shard);
                for to in peers {
                    if to != from {
                        self.try_deliver_message(from, to, &message);
                    }
                }
            }

            Action::BroadcastGlobal { message } => {
                for to in self.network.all_nodes() {
                    if to != from {
                        self.try_deliver_message(from, to, &message);
                    }
                }
            }

            // Domain-specific execution broadcasts (no batching in simulation)
            Action::BroadcastStateVote { shard, vote } => {
                let event = Event::StateVoteReceived { vote };
                let peers = self.network.peers_in_shard(shard);
                for to in peers {
                    if to != from {
                        self.try_deliver_event(from, to, event.clone());
                    }
                }
            }

            Action::BroadcastStateCertificate { shard, certificate } => {
                let event = Event::StateCertificateReceived {
                    cert: Arc::unwrap_or_clone(certificate),
                };
                let peers = self.network.peers_in_shard(shard);
                for to in peers {
                    if to != from {
                        self.try_deliver_event(from, to, event.clone());
                    }
                }
            }

            Action::BroadcastStateProvision { shard, provision } => {
                let event = Event::StateProvisionReceived { provision };
                let peers = self.network.peers_in_shard(shard);
                for to in peers {
                    if to != from {
                        self.try_deliver_event(from, to, event.clone());
                    }
                }
            }

            Action::SetTimer { id, duration } => {
                let fire_time = self.now + duration;
                let event = self.timer_to_event(id.clone());
                let key = self.schedule_event(from, fire_time, event);
                self.timers.insert((from, id.clone()), key);
                self.stats.timers_set += 1;
            }

            Action::CancelTimer { id } => {
                if let Some(key) = self.timers.remove(&(from, id)) {
                    self.event_queue.remove(&key);
                    self.stats.timers_cancelled += 1;
                }
            }

            Action::EnqueueInternal { event } => {
                // Internal events get scheduled for immediate processing
                self.schedule_event(from, self.now, event);
            }

            // ═══════════════════════════════════════════════════════════════════════
            // Runner I/O Requests (network fetches)
            // These are requests from the state machine for the runner to perform
            // network I/O. Results are delivered back as Events.
            // ═══════════════════════════════════════════════════════════════════════
            Action::StartSync {
                target_height,
                target_hash: _,
            } => {
                self.handle_sync_needed(from, target_height);
            }

            Action::FetchTransactions {
                block_hash,
                proposer,
                tx_hashes,
            } => {
                self.handle_transaction_fetch_needed(from, block_hash, proposer, tx_hashes);
            }

            Action::FetchCertificates {
                block_hash,
                proposer,
                cert_hashes,
            } => {
                self.handle_certificate_fetch_needed(from, block_hash, proposer, cert_hashes);
            }

            // Delegated work executes instantly in simulation
            Action::VerifyAndBuildQuorumCertificate {
                block_hash,
                height,
                round,
                parent_block_hash,
                signing_message,
                votes_to_verify,
                verified_votes: already_verified,
                total_voting_power,
            } => {
                // Start with already-verified votes (e.g., our own vote)
                let mut all_verified: Vec<(usize, BlockVote, u64)> = already_verified;
                let mut all_signatures: Vec<Bls12381G2Signature> =
                    all_verified.iter().map(|(_, v, _)| v.signature).collect();

                // Batch verify all new signatures (same message optimization)
                let signatures: Vec<Bls12381G2Signature> = votes_to_verify
                    .iter()
                    .map(|(_, v, _, _)| v.signature)
                    .collect();
                let public_keys: Vec<Bls12381G1PublicKey> =
                    votes_to_verify.iter().map(|(_, _, pk, _)| *pk).collect();

                let batch_valid = if votes_to_verify.is_empty() {
                    true
                } else {
                    batch_verify_bls_same_message(&signing_message, &signatures, &public_keys)
                };

                if batch_valid {
                    // Happy path: all new signatures valid, add them to verified set
                    for (idx, vote, _, power) in votes_to_verify {
                        all_signatures.push(vote.signature);
                        all_verified.push((idx, vote, power));
                    }
                } else {
                    // Some signatures invalid - verify individually
                    for (idx, vote, pk, power) in &votes_to_verify {
                        if verify_bls12381_v1(&signing_message, pk, &vote.signature) {
                            all_signatures.push(vote.signature);
                            all_verified.push((*idx, vote.clone(), *power));
                        }
                    }
                }

                let verified_power: u64 = all_verified.iter().map(|(_, _, power)| power).sum();

                // Check if we have quorum with all verified votes
                if VotePower::has_quorum(verified_power, total_voting_power)
                    && !all_signatures.is_empty()
                {
                    // Build QC - aggregate signatures
                    let qc = match Bls12381G2Signature::aggregate(&all_signatures, true) {
                        Ok(aggregated_signature) => {
                            let mut sorted_votes = all_verified.clone();
                            sorted_votes.sort_by_key(|(idx, _, _)| *idx);

                            let max_idx = sorted_votes
                                .iter()
                                .map(|(idx, _, _)| *idx)
                                .max()
                                .unwrap_or(0);
                            let mut signers = SignerBitfield::new(max_idx + 1);
                            let mut timestamp_weight_sum: u128 = 0;

                            for (idx, vote, power) in &sorted_votes {
                                signers.set(*idx);
                                timestamp_weight_sum += vote.timestamp as u128 * *power as u128;
                            }

                            let weighted_timestamp_ms = if verified_power == 0 {
                                0
                            } else {
                                (timestamp_weight_sum / verified_power as u128) as u64
                            };

                            Some(QuorumCertificate {
                                block_hash,
                                height,
                                parent_block_hash,
                                round,
                                aggregated_signature,
                                signers,
                                voting_power: VotePower(verified_power),
                                weighted_timestamp_ms,
                            })
                        }
                        Err(_) => None,
                    };

                    // Determine verified_votes before moving qc
                    let return_votes = if qc.is_none() { all_verified } else { vec![] };
                    self.schedule_event(
                        from,
                        self.now,
                        Event::QuorumCertificateResult {
                            block_hash,
                            qc,
                            verified_votes: return_votes,
                        },
                    );
                } else {
                    // No quorum - return all verified votes
                    self.schedule_event(
                        from,
                        self.now,
                        Event::QuorumCertificateResult {
                            block_hash,
                            qc: None,
                            verified_votes: all_verified,
                        },
                    );
                }
            }

            Action::VerifyAndAggregateProvisions {
                tx_hash,
                source_shard,
                block_height,
                block_timestamp,
                entries,
                provisions,
                public_keys,
                committee_size,
            } => {
                // All provisions for the same (tx, source_shard) sign the SAME message.
                // Happy path: aggregate verification with single pairing check.
                let signatures: Vec<Bls12381G2Signature> =
                    provisions.iter().map(|p| p.signature).collect();
                let message = provisions
                    .first()
                    .map(|p| p.signing_message())
                    .unwrap_or_default();

                let topology = self.nodes[from as usize].topology();
                let all_valid = batch_verify_bls_same_message(&message, &signatures, &public_keys);

                let (verified_provisions, commitment_proof) = if all_valid {
                    // Fast path: all valid
                    let mut signers = SignerBitfield::new(committee_size);
                    for provision in &provisions {
                        if let Some(idx) =
                            topology.committee_index_for_shard(source_shard, provision.validator_id)
                        {
                            signers.set(idx);
                        }
                    }

                    let aggregated_signature = Bls12381G2Signature::aggregate(&signatures, true)
                        .unwrap_or_else(|_| zero_bls_signature());

                    let proof = CommitmentProof::new(
                        tx_hash,
                        source_shard,
                        signers,
                        aggregated_signature,
                        block_height,
                        block_timestamp,
                        entries,
                    );

                    (provisions, Some(proof))
                } else {
                    // Slow path: find valid signatures individually
                    let mut verified = Vec::new();
                    let mut valid_sigs = Vec::new();
                    let mut signer_indices = Vec::new();

                    for (provision, pk) in provisions.iter().zip(public_keys.iter()) {
                        if verify_bls12381_v1(&message, pk, &provision.signature) {
                            verified.push(provision.clone());
                            valid_sigs.push(provision.signature);
                            if let Some(idx) = topology
                                .committee_index_for_shard(source_shard, provision.validator_id)
                            {
                                signer_indices.push(idx);
                            }
                        }
                    }

                    let proof = if !valid_sigs.is_empty() {
                        let mut signers = SignerBitfield::new(committee_size);
                        for idx in &signer_indices {
                            signers.set(*idx);
                        }

                        let aggregated_signature =
                            Bls12381G2Signature::aggregate(&valid_sigs, true)
                                .unwrap_or_else(|_| zero_bls_signature());

                        Some(CommitmentProof::new(
                            tx_hash,
                            source_shard,
                            signers,
                            aggregated_signature,
                            block_height,
                            block_timestamp,
                            entries,
                        ))
                    } else {
                        None
                    };

                    (verified, proof)
                };

                self.schedule_event(
                    from,
                    self.now,
                    Event::ProvisionsVerifiedAndAggregated {
                        tx_hash,
                        source_shard,
                        verified_provisions,
                        commitment_proof,
                    },
                );
            }

            Action::AggregateStateCertificate {
                tx_hash,
                shard,
                merkle_root,
                votes,
                read_nodes,
                voting_power,
                committee_size,
            } => {
                // Deduplicate votes by validator
                let mut seen_validators = std::collections::HashSet::new();
                let unique_votes: Vec<_> = votes
                    .iter()
                    .filter(|vote| seen_validators.insert(vote.validator))
                    .collect();

                // Aggregate BLS signatures
                let bls_signatures: Vec<Bls12381G2Signature> =
                    unique_votes.iter().map(|vote| vote.signature).collect();

                let aggregated_signature = if !bls_signatures.is_empty() {
                    Bls12381G2Signature::aggregate(&bls_signatures, true)
                        .unwrap_or_else(|_| zero_bls_signature())
                } else {
                    zero_bls_signature()
                };

                // Create signer bitfield
                // Compute committee index from validator ID and shard.
                // In simulation, validator IDs are sequential across shards:
                // Shard 0: validators 0, 1, 2; Shard 1: validators 3, 4, 5, etc.
                // Committee index = validator_id - (shard * validators_per_shard)
                let validators_per_shard = self.network.config().validators_per_shard as u64;
                let shard_base = shard.0 * validators_per_shard;
                let mut signers = SignerBitfield::new(committee_size);
                for vote in &unique_votes {
                    let idx = (vote.validator.0 - shard_base) as usize;
                    if idx < committee_size {
                        signers.set(idx);
                    }
                }

                let success = votes.first().map(|v| v.success).unwrap_or(false);

                let certificate = StateCertificate {
                    transaction_hash: tx_hash,
                    shard_group_id: shard,
                    read_nodes,
                    state_writes: vec![],
                    outputs_merkle_root: merkle_root,
                    success,
                    aggregated_signature,
                    signers,
                    voting_power: voting_power.0,
                };

                self.schedule_event(
                    from,
                    self.now,
                    Event::StateCertificateAggregated {
                        tx_hash,
                        certificate,
                    },
                );
            }

            Action::VerifyAndAggregateStateVotes { tx_hash, votes } => {
                // Batch verify state votes using BLS same-message optimization.
                // All votes for the same (tx_hash, state_root, shard, success) sign the SAME message,
                // enabling aggregate signature verification.
                //
                // In simulation, we use the same logic as production for correctness,
                // just without parallelism.
                use std::collections::HashMap;
                let mut by_message: HashMap<
                    Vec<u8>,
                    Vec<(StateVoteBlock, Bls12381G1PublicKey, u64)>,
                > = HashMap::new();
                for (vote, pk, power) in votes {
                    let msg = vote.signing_message();
                    by_message.entry(msg).or_default().push((vote, pk, power));
                }

                let mut verified_votes: Vec<(StateVoteBlock, u64)> = Vec::new();

                for (message, votes_for_root) in by_message {
                    if votes_for_root.len() >= 2 {
                        // Use BLS same-message batch verification
                        let signatures: Vec<Bls12381G2Signature> =
                            votes_for_root.iter().map(|(v, _, _)| v.signature).collect();
                        let pubkeys: Vec<Bls12381G1PublicKey> =
                            votes_for_root.iter().map(|(_, pk, _)| *pk).collect();

                        let batch_valid =
                            batch_verify_bls_same_message(&message, &signatures, &pubkeys);

                        if batch_valid {
                            for (vote, _, power) in votes_for_root {
                                verified_votes.push((vote, power));
                            }
                        } else {
                            // Fallback to individual verification
                            for (vote, pk, power) in votes_for_root {
                                if verify_bls12381_v1(&message, &pk, &vote.signature) {
                                    verified_votes.push((vote, power));
                                }
                            }
                        }
                    } else {
                        // Single vote - verify individually
                        let (vote, pk, power) = votes_for_root.into_iter().next().unwrap();
                        if verify_bls12381_v1(&message, &pk, &vote.signature) {
                            verified_votes.push((vote, power));
                        }
                    }
                }

                self.schedule_event(
                    from,
                    self.now,
                    Event::StateVotesVerifiedAndAggregated {
                        tx_hash,
                        verified_votes,
                    },
                );
            }

            Action::VerifyStateCertificateSignature {
                certificate,
                public_keys,
            } => {
                // Verify aggregated BLS signature on certificate
                // For simulation, we verify the aggregated signature against the participating keys

                // Use centralized signing message - StateCertificates aggregate signatures
                // from StateVoteBlocks, so they use the same EXEC_VOTE domain tag.
                let msg = certificate.signing_message();

                // Get the public keys of actual signers based on the bitfield
                let signer_keys: Vec<_> = public_keys
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| certificate.signers.is_set(*i))
                    .map(|(_, pk)| *pk)
                    .collect();

                // Verify aggregated signature
                let valid = if signer_keys.is_empty() {
                    // No signers - valid only if it's a zero signature (single-shard case)
                    certificate.aggregated_signature == zero_bls_signature()
                } else {
                    // Aggregate the public keys and verify (skip PK validation - trusted topology)
                    match Bls12381G1PublicKey::aggregate(&signer_keys, false) {
                        Ok(aggregated_pk) => verify_bls12381_v1(
                            &msg,
                            &aggregated_pk,
                            &certificate.aggregated_signature,
                        ),
                        Err(_) => false,
                    }
                };

                if !valid {
                    tracing::warn!(
                        tx_hash = ?certificate.transaction_hash,
                        shard = certificate.shard_group_id.0,
                        "State certificate signature verification failed"
                    );
                }

                self.schedule_event(
                    from,
                    self.now,
                    Event::StateCertificateSignatureVerified { certificate, valid },
                );
            }

            Action::VerifyQcSignature {
                qc,
                public_keys,
                block_hash,
                signing_message,
            } => {
                // Verify aggregated BLS signature on QC
                // The QC's aggregated_signature is over the domain-separated signing message

                // Get the public keys of actual signers based on the QC's signer bitfield
                let signer_keys: Vec<_> = public_keys
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| qc.signers.is_set(*i))
                    .map(|(_, pk)| *pk)
                    .collect();

                // Verify aggregated signature against domain-separated message
                let valid = if signer_keys.is_empty() {
                    // No signers - invalid QC (genesis QC is handled before action is emitted)
                    false
                } else {
                    // Aggregate the public keys and verify (skip PK validation - trusted topology)
                    match Bls12381G1PublicKey::aggregate(&signer_keys, false) {
                        Ok(aggregated_pk) => verify_bls12381_v1(
                            &signing_message,
                            &aggregated_pk,
                            &qc.aggregated_signature,
                        ),
                        Err(_) => false,
                    }
                };

                self.schedule_event(
                    from,
                    self.now,
                    Event::QcSignatureVerified { block_hash, valid },
                );
            }

            Action::VerifyCycleProof {
                block_hash,
                deferral_index,
                cycle_proof,
                public_keys,
                signing_message,
                quorum_threshold,
            } => {
                // Verify aggregated BLS signature on CycleProof's CommitmentProof
                // Same logic as production - full cryptographic verification for correctness

                let valid = if public_keys.is_empty() {
                    // No signers - invalid proof
                    false
                } else {
                    // Verify aggregated signature against the commitment proof message
                    let sig_valid = match Bls12381G1PublicKey::aggregate(&public_keys, false) {
                        Ok(aggregated_pk) => verify_bls12381_v1(
                            &signing_message,
                            &aggregated_pk,
                            &cycle_proof.winner_commitment.aggregated_signature,
                        ),
                        Err(_) => false,
                    };

                    // Also verify quorum threshold
                    sig_valid
                        && cycle_proof.winner_commitment.signer_count() as u64 >= quorum_threshold
                };

                self.schedule_event(
                    from,
                    self.now,
                    Event::CycleProofVerified {
                        block_hash,
                        deferral_index,
                        valid,
                    },
                );
            }

            Action::VerifyStateRoot {
                block_hash,
                parent_state_root,
                expected_root,
                certificates,
            } => {
                // Extract state writes from certificates for our local shard.
                let local_shard = self.nodes[from as usize].shard();
                let writes_per_cert: Vec<Vec<_>> = certificates
                    .iter()
                    .map(|cert| {
                        cert.shard_proofs
                            .get(&local_shard)
                            .map(|proof| proof.state_writes.clone())
                            .unwrap_or_default()
                    })
                    .collect();

                // Compute speculative state root using overlay pattern.
                // Each certificate's writes are applied at a separate JMT version.
                // Use parent_state_root as base to match proposer's computation.
                //
                // Also captures a snapshot of the JMT nodes for reuse at commit time.
                let storage = &self.node_storage[from as usize];
                let (computed_root, snapshot) =
                    storage.compute_speculative_root_from_base(parent_state_root, &writes_per_cert);

                let valid = computed_root == expected_root;

                if !valid {
                    tracing::warn!(
                        node = from,
                        ?block_hash,
                        ?computed_root,
                        ?expected_root,
                        ?parent_state_root,
                        "State root verification failed"
                    );
                } else {
                    // Cache the snapshot for reuse during commit
                    self.jmt_cache.insert((from, block_hash), snapshot);
                }

                self.schedule_event(
                    from,
                    self.now,
                    Event::StateRootVerified { block_hash, valid },
                );
            }

            Action::ComputeStateRoot {
                height,
                round,
                parent_state_root,
                writes_per_cert,
                timeout: _, // Timeout ignored in simulation - everything is synchronous
            } => {
                // In simulation, JMT commits are synchronous so we can compute immediately.
                // Check if JMT is at the expected parent state.
                //
                // NOTE: We don't cache the snapshot here because we don't know the block
                // hash yet (it's computed after the block is built). The proposer will
                // fall back to per-certificate commits. This is fine because:
                // 1. Only 1 out of N validators is the proposer
                // 2. The N-1 verifiers will cache their snapshots
                let storage = &self.node_storage[from as usize];
                let current_root = storage.current_jmt_root();

                let result = if current_root == parent_state_root {
                    // JMT is ready - compute speculative root
                    let (state_root, _snapshot) = storage
                        .compute_speculative_root_from_base(parent_state_root, &writes_per_cert);
                    hyperscale_core::StateRootComputeResult::Success { state_root }
                } else {
                    // In simulation, if JMT isn't at the right state, it means we're ahead
                    // of the commit sequence. This shouldn't happen often in well-behaved
                    // simulation, but we handle it by returning timeout.
                    tracing::warn!(
                        node = from,
                        height = height,
                        round = round,
                        ?current_root,
                        ?parent_state_root,
                        "JMT not at expected parent state in simulation - returning timeout"
                    );
                    hyperscale_core::StateRootComputeResult::Timeout
                };

                self.schedule_event(
                    from,
                    self.now,
                    Event::StateRootComputed {
                        height,
                        round,
                        result,
                    },
                );
            }

            // Note: BuildQuorumCertificate has been replaced by VerifyAndBuildQuorumCertificate
            // which combines vote verification and QC building into a single operation.

            // Note: View change verification actions removed - using HotStuff-2 implicit rounds
            Action::ExecuteTransactions {
                block_hash: _,
                transactions,
                ..
            } => {
                // Execute transactions using the node's own Radix Engine and storage
                // Each node has independent storage - this runs inline (synchronously)
                //
                // NOTE: Execution is READ-ONLY. State writes are collected in the results
                // and committed later when TransactionCertificate is included in a block
                // (via PersistTransactionCertificate handler).
                //
                // After execution, sign votes and send StateVoteReceived directly
                // (matches production runner pattern).
                let storage = &self.node_storage[from as usize];
                let executor = &self.node_executor[from as usize];
                // Clone key bytes since Bls12381G1PrivateKey doesn't impl Clone
                let key_bytes = self.node_keys[from as usize].to_bytes();
                let signing_key =
                    Bls12381G1PrivateKey::from_bytes(&key_bytes).expect("valid key bytes");
                let local_shard = self.nodes[from as usize].shard();
                let validator_id = self.nodes[from as usize].topology().local_validator_id();

                let results: Vec<hyperscale_types::ExecutionResult> =
                    match executor.execute_single_shard(storage, &transactions) {
                        Ok(output) => output
                            .results()
                            .iter()
                            .map(|r| hyperscale_types::ExecutionResult {
                                transaction_hash: r.tx_hash,
                                success: r.success,
                                state_root: r.outputs_merkle_root,
                                writes: r.state_writes.clone(),
                                error: r.error.clone(),
                            })
                            .collect(),
                        Err(e) => {
                            // Execution failed - mark all transactions as failed
                            warn!(node = from, error = %e, "Transaction execution failed");
                            transactions
                                .iter()
                                .map(|tx| hyperscale_types::ExecutionResult {
                                    transaction_hash: tx.hash(),
                                    success: false,
                                    state_root: hyperscale_types::Hash::ZERO,
                                    writes: vec![],
                                    error: Some(format!("{}", e)),
                                })
                                .collect()
                        }
                    };

                // Sign votes and send StateVoteReceived for each result
                for result in results {
                    let message = hyperscale_types::exec_vote_message(
                        &result.transaction_hash,
                        &result.state_root,
                        local_shard,
                        result.success,
                    );
                    let signature = signing_key.sign_v1(&message);

                    let vote = StateVoteBlock {
                        transaction_hash: result.transaction_hash,
                        shard_group_id: local_shard,
                        state_root: result.state_root,
                        success: result.success,
                        state_writes: result.writes.clone(),
                        validator: validator_id,
                        signature,
                    };

                    // Broadcast to shard peers
                    let broadcast_event = Event::StateVoteReceived { vote: vote.clone() };
                    let peers = self.network.peers_in_shard(local_shard);
                    for to in peers {
                        if to != from {
                            self.try_deliver_event(from, to, broadcast_event.clone());
                        }
                    }

                    // Send to state machine for local handling (skips verification for own votes)
                    self.schedule_event(from, self.now, Event::StateVoteReceived { vote });
                }
            }

            Action::SpeculativeExecute {
                block_hash,
                transactions,
            } => {
                // Speculatively execute single-shard transactions AND sign votes inline.
                // Same as ExecuteTransactions - votes are sent via StateVoteReceived.
                // SpeculativeExecutionComplete just reports tx_hashes for cache tracking.
                let storage = &self.node_storage[from as usize];
                let executor = &self.node_executor[from as usize];
                // Clone key bytes since Bls12381G1PrivateKey doesn't impl Clone
                let key_bytes = self.node_keys[from as usize].to_bytes();
                let signing_key =
                    Bls12381G1PrivateKey::from_bytes(&key_bytes).expect("valid key bytes");
                let local_shard = self.nodes[from as usize].shard();
                let validator_id = self.nodes[from as usize].topology().local_validator_id();

                let mut tx_hashes = Vec::new();

                match executor.execute_single_shard(storage, &transactions) {
                    Ok(output) => {
                        for r in output.results() {
                            tx_hashes.push(r.tx_hash);

                            // Sign and broadcast vote (same as ExecuteTransactions)
                            let message = hyperscale_types::exec_vote_message(
                                &r.tx_hash,
                                &r.outputs_merkle_root,
                                local_shard,
                                r.success,
                            );
                            let signature = signing_key.sign_v1(&message);

                            let vote = StateVoteBlock {
                                transaction_hash: r.tx_hash,
                                shard_group_id: local_shard,
                                state_root: r.outputs_merkle_root,
                                success: r.success,
                                state_writes: r.state_writes.clone(),
                                validator: validator_id,
                                signature,
                            };

                            // Broadcast to shard peers
                            let broadcast_event = Event::StateVoteReceived { vote: vote.clone() };
                            let peers = self.network.peers_in_shard(local_shard);
                            for to in peers {
                                if to != from {
                                    self.try_deliver_event(from, to, broadcast_event.clone());
                                }
                            }

                            // Send to state machine for local handling
                            self.schedule_event(from, self.now, Event::StateVoteReceived { vote });
                        }
                    }
                    Err(e) => {
                        // Execution failed - sign votes with failure results
                        warn!(node = from, ?block_hash, error = %e, "Speculative execution failed");
                        for tx in &transactions {
                            let tx_hash = tx.hash();
                            tx_hashes.push(tx_hash);

                            let message = hyperscale_types::exec_vote_message(
                                &tx_hash,
                                &hyperscale_types::Hash::ZERO,
                                local_shard,
                                false,
                            );
                            let signature = signing_key.sign_v1(&message);

                            let vote = StateVoteBlock {
                                transaction_hash: tx_hash,
                                shard_group_id: local_shard,
                                state_root: hyperscale_types::Hash::ZERO,
                                success: false,
                                state_writes: vec![],
                                validator: validator_id,
                                signature,
                            };

                            // Broadcast to shard peers
                            let broadcast_event = Event::StateVoteReceived { vote: vote.clone() };
                            let peers = self.network.peers_in_shard(local_shard);
                            for to in peers {
                                if to != from {
                                    self.try_deliver_event(from, to, broadcast_event.clone());
                                }
                            }

                            // Send to state machine for local handling
                            self.schedule_event(from, self.now, Event::StateVoteReceived { vote });
                        }
                    }
                }

                // Notify state machine that speculative execution completed (for cache tracking)
                self.schedule_event(
                    from,
                    self.now,
                    Event::SpeculativeExecutionComplete {
                        block_hash,
                        tx_hashes,
                    },
                );
            }

            Action::ExecuteCrossShardTransaction {
                tx_hash,
                transaction,
                provisions,
            } => {
                // Execute cross-shard transaction with provisions using the node's Radix Engine
                //
                // NOTE: Execution is READ-ONLY. State writes are collected in the results
                // and committed later when TransactionCertificate is included in a block
                // (via PersistTransactionCertificate handler).
                //
                // After execution, sign vote and send StateVoteReceived directly
                // (matches production runner pattern).
                let storage = &self.node_storage[from as usize];
                let executor = &self.node_executor[from as usize];
                // Clone key bytes since Bls12381G1PrivateKey doesn't impl Clone
                let key_bytes = self.node_keys[from as usize].to_bytes();
                let signing_key =
                    Bls12381G1PrivateKey::from_bytes(&key_bytes).expect("valid key bytes");
                let local_shard = self.nodes[from as usize].shard();
                let validator_id = self.nodes[from as usize].topology().local_validator_id();

                // Determine which nodes are local to this shard
                let is_local_node = |node_id: &hyperscale_types::NodeId| -> bool {
                    self.nodes[from as usize]
                        .topology()
                        .shard_for_node_id(node_id)
                        == local_shard
                };

                let result = match executor.execute_cross_shard(
                    storage,
                    &[transaction],
                    &provisions,
                    is_local_node,
                ) {
                    Ok(output) => {
                        if let Some(r) = output.results().first() {
                            hyperscale_types::ExecutionResult {
                                transaction_hash: r.tx_hash,
                                success: r.success,
                                state_root: r.outputs_merkle_root,
                                writes: r.state_writes.clone(),
                                error: r.error.clone(),
                            }
                        } else {
                            hyperscale_types::ExecutionResult {
                                transaction_hash: tx_hash,
                                success: false,
                                state_root: hyperscale_types::Hash::ZERO,
                                writes: vec![],
                                error: Some("No execution result".to_string()),
                            }
                        }
                    }
                    Err(e) => {
                        warn!(node = from, ?tx_hash, error = %e, "Cross-shard transaction execution failed");
                        hyperscale_types::ExecutionResult {
                            transaction_hash: tx_hash,
                            success: false,
                            state_root: hyperscale_types::Hash::ZERO,
                            writes: vec![],
                            error: Some(format!("{}", e)),
                        }
                    }
                };

                // Sign vote and send StateVoteReceived
                let message = hyperscale_types::exec_vote_message(
                    &result.transaction_hash,
                    &result.state_root,
                    local_shard,
                    result.success,
                );
                let signature = signing_key.sign_v1(&message);

                let vote = StateVoteBlock {
                    transaction_hash: result.transaction_hash,
                    shard_group_id: local_shard,
                    state_root: result.state_root,
                    success: result.success,
                    state_writes: result.writes.clone(),
                    validator: validator_id,
                    signature,
                };

                // Broadcast to shard peers
                let broadcast_event = Event::StateVoteReceived { vote: vote.clone() };
                let peers = self.network.peers_in_shard(local_shard);
                for to in peers {
                    if to != from {
                        self.try_deliver_event(from, to, broadcast_event.clone());
                    }
                }

                // Send to state machine for local handling (skips verification for own votes)
                self.schedule_event(from, self.now, Event::StateVoteReceived { vote });
            }

            Action::ComputeMerkleRoot { tx_hash, writes } => {
                // Compute merkle root from the writes
                // The writes are (NodeId, value) pairs - we hash them deterministically
                use hyperscale_types::Hash;

                let root = if writes.is_empty() {
                    Hash::ZERO
                } else {
                    // Sort writes for determinism and hash
                    let mut sorted_writes = writes.clone();
                    sorted_writes.sort_by(|a, b| a.0 .0.cmp(&b.0 .0));

                    let mut data = Vec::new();
                    for (node_id, value) in &sorted_writes {
                        data.extend_from_slice(&node_id.0);
                        data.extend_from_slice(value);
                    }
                    Hash::from_bytes(&data)
                };

                self.schedule_event(from, self.now, Event::MerkleRootComputed { tx_hash, root });
            }

            // Notifications - these would go to external observers
            Action::EmitCommittedBlock { block } => {
                debug!(block_hash = ?block.hash(), "Block committed");

                // Commit state writes for all certificates in this block.
                // This matches production behavior where state is committed in EmitCommittedBlock.
                //
                // OPTIMIZATION: If we have a cached JMT snapshot from verification,
                // apply it directly instead of recomputing certificate-by-certificate.
                let storage = &mut self.node_storage[from as usize];
                let local_shard = self.nodes[from as usize].shard();
                let block_hash = block.hash();

                // NOTE: JMT snapshot cache disabled in simulation pending further investigation.
                // The snapshot application causes tree inconsistencies in some edge cases.
                // Always use slow path (per-certificate commits) for now.
                // See: https://github.com/hyperscale/hyperscale-rs/issues/XXX
                let _snapshot = self.jmt_cache.remove(&(from, block_hash));
                {
                    // Slow path: recompute per-certificate (proposer case or cache miss)
                    for cert in &block.committed_certificates {
                        if let Some(shard_proof) = cert.shard_proofs.get(&local_shard) {
                            let writes = &shard_proof.state_writes;
                            if !writes.is_empty() {
                                storage.commit_certificate_with_writes(cert, writes);
                            }
                        }
                    }
                }

                // Send StateCommitComplete so state machine knows JMT is up to date.
                // In simulation this is synchronous, but we still need the event for tracking.
                use hyperscale_engine::SubstateStore;
                let state_version = storage.state_version();
                let state_root_hash = storage.state_root_hash();
                let state_root = hyperscale_types::Hash::from_bytes(&state_root_hash.0);
                self.schedule_event(
                    from,
                    self.now,
                    Event::StateCommitComplete {
                        height: block.header.height.0,
                        state_version,
                        state_root,
                    },
                );
            }

            Action::EmitTransactionStatus {
                tx_hash, status, ..
            } => {
                debug!(?tx_hash, ?status, "Transaction status");
                // Cache the status for test queries
                self.tx_status_cache.insert((from, tx_hash), status);
            }

            // Storage writes - store in SimStorage
            Action::PersistBlock { block, qc } => {
                // Store block and QC in this node's storage
                let height = block.header.height;
                let storage = &mut self.node_storage[from as usize];
                storage.put_block(height, block, qc);
                // Update committed height if this is the highest
                if height > storage.committed_height() {
                    storage.set_committed_height(height);
                }
                // Prune old votes - we no longer need votes at or below committed height
                storage.prune_own_votes(height.0);

                // If this node is syncing, try to fetch more blocks that may now be available.
                // This handles the case where sync was triggered before all target blocks
                // were committed on peers.
                if let Some(&sync_target) = self.sync_targets.get(&from) {
                    let current_height = self.nodes[from as usize].bft().committed_height();
                    if current_height < sync_target {
                        // Still need to sync more blocks - retry fetching
                        self.handle_sync_needed(from, sync_target);
                    } else {
                        // Sync complete - notify state machine so it can resume view changes
                        self.sync_targets.remove(&from);
                        let sync_complete_event = Event::SyncComplete {
                            height: sync_target,
                        };
                        let actions = self.nodes[from as usize].handle(sync_complete_event);
                        for action in actions {
                            self.process_action(from, action);
                        }
                    }
                }
            }
            Action::PersistTransactionCertificate { certificate } => {
                // Store certificate AND commit state writes in this node's storage
                // This is the deferred commit - state writes are only applied when
                // the certificate is included in a committed block.
                let storage = &mut self.node_storage[from as usize];
                let local_shard = self.nodes[from as usize].shard();

                // Extract writes for local shard from the certificate's shard_proofs
                let writes = certificate
                    .shard_proofs
                    .get(&local_shard)
                    .map(|cert| cert.state_writes.as_slice())
                    .unwrap_or(&[]);

                // Commit certificate + writes atomically (mirrors production behavior)
                storage.commit_certificate_with_writes(&certificate, writes);

                // After persisting, gossip certificate to same-shard peers.
                // This ensures other validators have the certificate before the proposer
                // includes it in a block, avoiding fetch delays.
                let gossip =
                    hyperscale_messages::TransactionCertificateGossip::new(certificate.clone());
                let message = OutboundMessage::TransactionCertificateGossip(gossip);
                let peers = self.network.peers_in_shard(local_shard);
                for to in peers {
                    if to != from {
                        self.try_deliver_message(from, to, &message);
                    }
                }
            }
            Action::PersistAndBroadcastVote {
                height,
                round,
                block_hash,
                shard,
                message,
            } => {
                // **BFT Safety Critical**: Store our vote before broadcasting.
                // This ensures we remember what we voted for after a restart.
                let storage = &mut self.node_storage[from as usize];
                storage.put_own_vote(height.0, round, block_hash);
                trace!(
                    node = from,
                    height = height.0,
                    round = round,
                    block_hash = ?block_hash,
                    "Persisted own vote"
                );

                // Now broadcast the vote (simulated immediately after persist)
                let broadcast_action = Action::BroadcastToShard { shard, message };
                self.process_action(from, broadcast_action);
            }
            // Storage reads - immediately return callback events in simulation
            // In production, these would be async operations
            Action::FetchStateEntries { tx_hash, nodes } => {
                // Fetch actual state entries from storage for provisioning
                let storage = &self.node_storage[from as usize];
                let executor = &self.node_executor[from as usize];
                let entries = executor.fetch_state_entries(storage, &nodes);
                trace!(
                    node = from,
                    tx_hash = ?tx_hash,
                    nodes = nodes.len(),
                    entries = entries.len(),
                    "Fetching state entries from storage"
                );
                self.schedule_event(
                    from,
                    self.now,
                    Event::StateEntriesFetched { tx_hash, entries },
                );
            }
            Action::FetchBlock { height } => {
                // In simulation, return None (no persistent storage)
                self.schedule_event(
                    from,
                    self.now,
                    Event::BlockFetched {
                        height,
                        block: None,
                    },
                );
            }
            Action::FetchChainMetadata => {
                // In simulation, return genesis state
                self.schedule_event(
                    from,
                    self.now,
                    Event::ChainMetadataFetched {
                        height: hyperscale_types::BlockHeight(0),
                        hash: None,
                        qc: None,
                    },
                );
            }

            // ═══════════════════════════════════════════════════════════════════════
            // Global Consensus Actions (TODO: implement when GlobalConsensusState exists)
            // ═══════════════════════════════════════════════════════════════════════
            Action::ProposeGlobalBlock { epoch, height, .. } => {
                tracing::trace!(?epoch, ?height, "ProposeGlobalBlock - not yet implemented");
            }
            Action::BroadcastGlobalBlockVote {
                block_hash, shard, ..
            } => {
                tracing::trace!(
                    ?block_hash,
                    ?shard,
                    "BroadcastGlobalBlockVote - not yet implemented"
                );
            }
            Action::TransitionEpoch {
                from_epoch,
                to_epoch,
                ..
            } => {
                tracing::debug!(
                    ?from_epoch,
                    ?to_epoch,
                    "TransitionEpoch - not yet implemented"
                );
            }
            Action::MarkValidatorReady { epoch, shard } => {
                tracing::debug!(?epoch, ?shard, "MarkValidatorReady - not yet implemented");
            }
            Action::InitiateShardSplit {
                source_shard,
                new_shard,
                split_point,
            } => {
                tracing::info!(
                    ?source_shard,
                    ?new_shard,
                    split_point,
                    "InitiateShardSplit - not yet implemented"
                );
            }
            Action::CompleteShardSplit {
                source_shard,
                new_shard,
            } => {
                tracing::info!(
                    ?source_shard,
                    ?new_shard,
                    "CompleteShardSplit - not yet implemented"
                );
            }
            Action::InitiateShardMerge {
                shard_a,
                shard_b,
                merged_shard,
            } => {
                tracing::info!(
                    ?shard_a,
                    ?shard_b,
                    ?merged_shard,
                    "InitiateShardMerge - not yet implemented"
                );
            }
            Action::CompleteShardMerge { merged_shard } => {
                tracing::info!(?merged_shard, "CompleteShardMerge - not yet implemented");
            }
            Action::PersistEpochConfig { .. } => {
                tracing::debug!("PersistEpochConfig - not yet implemented");
            }
            Action::FetchEpochConfig { epoch } => {
                tracing::debug!(?epoch, "FetchEpochConfig - not yet implemented");
            }
            Action::CancelFetch { block_hash } => {
                // In simulation, fetches are synchronous so there's nothing to cancel.
                // This action is only relevant for production where fetches are async.
                tracing::trace!(?block_hash, "CancelFetch - no-op in simulation");
            }
        }
    }

    /// Handle sync needed: the simulation runner fetches blocks directly.
    ///
    /// In production, this is handled by SyncManager with network I/O.
    /// In simulation, we look up blocks from any peer's storage that has them
    /// and deliver them directly to BFT via SyncBlockReadyToApply.
    ///
    /// Note: We send blocks one at a time. When BFT commits a block (via PersistBlock),
    /// the runner will check if more sync blocks are needed and fetch them.
    pub fn handle_sync_needed(&mut self, node: NodeIndex, target_height: u64) {
        // Track the sync target (replaces SyncState tracking)
        // Only update if target is higher than current
        let current_target = self.sync_targets.get(&node).copied().unwrap_or(0);
        if target_height > current_target {
            self.sync_targets.insert(node, target_height);
        }
        let effective_target = target_height.max(current_target);

        // Get node's current committed height from BFT state
        let committed_height = self.nodes[node as usize].bft().committed_height();
        let next_height = committed_height + 1;

        // Check if sync is complete
        if committed_height >= effective_target {
            self.sync_targets.remove(&node);
            // Notify state machine so it can resume view changes
            let sync_complete_event = Event::SyncComplete {
                height: effective_target,
            };
            let actions = self.nodes[node as usize].handle(sync_complete_event);
            for action in actions {
                self.process_action(node, action);
            }
            return;
        }

        // Only fetch the next block in sequence
        if next_height <= effective_target {
            if let Some((peer, block, qc)) = self.find_block_from_any_peer_with_index(next_height) {
                // Simulate network round-trip to the peer
                if let Some(delivery_time) = self.simulate_request_response(node, peer) {
                    let event = Event::SyncBlockReadyToApply { block, qc };
                    self.schedule_event(node, delivery_time, event);
                    trace!(
                        node = node,
                        peer = peer,
                        height = next_height,
                        "Sync: scheduled block fetch with network latency"
                    );
                } else {
                    trace!(
                        node = node,
                        peer = peer,
                        height = next_height,
                        "Sync: request dropped (partition or packet loss)"
                    );
                    // Request dropped - will retry on next timer or when triggered again
                }
            } else {
                trace!(
                    node = node,
                    height = next_height,
                    target = effective_target,
                    "Sync: no peer has block at height yet"
                );
                // Block not available yet - will retry when peers commit more blocks
            }
        }
    }

    /// Find a block at a given height from any peer's storage, returning the peer index.
    fn find_block_from_any_peer_with_index(
        &self,
        height: u64,
    ) -> Option<(NodeIndex, Block, QuorumCertificate)> {
        for (idx, storage) in self.node_storage.iter().enumerate() {
            if let Some((block, qc)) = storage.get_block(hyperscale_types::BlockHeight(height)) {
                return Some((idx as NodeIndex, block, qc));
            }
        }
        None
    }

    /// Handle transaction fetch needed: fetch missing transactions from proposer's mempool.
    ///
    /// Simulates a network request/response to the proposer with realistic latency.
    pub fn handle_transaction_fetch_needed(
        &mut self,
        node: NodeIndex,
        block_hash: hyperscale_types::Hash,
        proposer: ValidatorId,
        missing_tx_hashes: Vec<hyperscale_types::Hash>,
    ) {
        // Find the proposer's node index
        let proposer_node = proposer.0 as NodeIndex;

        if proposer_node as usize >= self.nodes.len() {
            warn!(
                node = node,
                proposer = ?proposer,
                "Transaction fetch: proposer node not found"
            );
            return;
        }

        // Simulate network round-trip to proposer
        let delivery_time = match self.simulate_request_response(node, proposer_node) {
            Some(time) => time,
            None => {
                trace!(
                    node = node,
                    proposer = proposer_node,
                    block_hash = ?block_hash,
                    "Transaction fetch: request dropped (partition or packet loss)"
                );
                return;
            }
        };

        // Look up transactions from proposer's mempool
        let mut found_transactions = Vec::new();
        {
            let proposer_state = &self.nodes[proposer_node as usize];
            let mempool = proposer_state.mempool();

            for tx_hash in &missing_tx_hashes {
                if let Some(tx) = mempool.get_transaction(tx_hash) {
                    found_transactions.push(tx);
                }
            }
        }

        if found_transactions.is_empty() {
            debug!(
                node = node,
                block_hash = ?block_hash,
                missing_count = missing_tx_hashes.len(),
                "Transaction fetch: no transactions found in proposer's mempool"
            );
            return;
        }

        debug!(
            node = node,
            block_hash = ?block_hash,
            found_count = found_transactions.len(),
            missing_count = missing_tx_hashes.len(),
            "Transaction fetch: scheduling delivery with network latency"
        );

        // Deliver the transactions to the requesting node with network delay
        let event = Event::TransactionReceived {
            block_hash,
            transactions: found_transactions,
        };
        self.schedule_event(node, delivery_time, event);
    }

    /// Handle certificate fetch needed: fetch missing certificates from proposer's execution state.
    ///
    /// Simulates a network request/response to the proposer with realistic latency.
    pub fn handle_certificate_fetch_needed(
        &mut self,
        node: NodeIndex,
        block_hash: hyperscale_types::Hash,
        proposer: ValidatorId,
        missing_cert_hashes: Vec<hyperscale_types::Hash>,
    ) {
        // Find the proposer's node index
        let proposer_node = proposer.0 as NodeIndex;

        if proposer_node as usize >= self.nodes.len() {
            warn!(
                node = node,
                proposer = ?proposer,
                "Certificate fetch: proposer node not found"
            );
            return;
        }

        // Simulate network round-trip to proposer
        let delivery_time = match self.simulate_request_response(node, proposer_node) {
            Some(time) => time,
            None => {
                trace!(
                    node = node,
                    proposer = proposer_node,
                    block_hash = ?block_hash,
                    "Certificate fetch: request dropped (partition or packet loss)"
                );
                return;
            }
        };

        // Look up certificates from proposer's execution state
        let mut found_certificates = Vec::new();
        {
            let proposer_state = &self.nodes[proposer_node as usize];
            let execution = proposer_state.execution();

            for cert_hash in &missing_cert_hashes {
                if let Some(cert) = execution.get_finalized_certificate(cert_hash) {
                    found_certificates.push((*cert).clone());
                }
            }
        }

        if found_certificates.is_empty() {
            debug!(
                node = node,
                block_hash = ?block_hash,
                missing_count = missing_cert_hashes.len(),
                "Certificate fetch: no certificates found in proposer's execution state"
            );
            return;
        }

        debug!(
            node = node,
            block_hash = ?block_hash,
            found_count = found_certificates.len(),
            missing_count = missing_cert_hashes.len(),
            "Certificate fetch: scheduling delivery with network latency"
        );

        // Deliver the certificates to the requesting node with network delay
        let event = Event::CertificateReceived {
            block_hash,
            certificates: found_certificates,
        };
        self.schedule_event(node, delivery_time, event);
    }

    /// Schedule an event.
    fn schedule_event(&mut self, node: NodeIndex, time: Duration, event: Event) -> EventKey {
        self.sequence += 1;
        let key = EventKey::new(time, &event, node, self.sequence);
        self.event_queue.insert(key, event);
        key
    }

    /// Compute deduplication key for a (recipient, message) pair.
    /// Each node maintains its own deduplication, so we include the recipient.
    fn compute_dedup_key(to: NodeIndex, message_hash: u64) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        to.hash(&mut hasher);
        message_hash.hash(&mut hasher);
        hasher.finish()
    }

    /// Try to deliver a message, accounting for partitions, packet loss, and deduplication.
    /// Updates stats based on delivery outcome.
    fn try_deliver_message(&mut self, from: NodeIndex, to: NodeIndex, message: &OutboundMessage) {
        // Check partition first (deterministic - doesn't consume RNG)
        if self.network.is_partitioned(from, to) {
            self.stats.messages_dropped_partition += 1;
            trace!(from = from, to = to, "Message dropped due to partition");
            return;
        }

        // Check packet loss (probabilistic but deterministic with seeded RNG)
        if self.network.should_drop_packet(&mut self.rng) {
            self.stats.messages_dropped_loss += 1;
            trace!(from = from, to = to, "Message dropped due to packet loss");
            return;
        }

        // Check deduplication (matches libp2p gossipsub behavior)
        // Uses OutboundMessage::message_hash() which hashes encoded message data
        let message_hash = message.message_hash();
        let dedup_key = Self::compute_dedup_key(to, message_hash);
        if !self.seen_messages.insert(dedup_key) {
            // Message already seen by this recipient - deduplicate
            self.stats.messages_deduplicated += 1;
            trace!(
                from = from,
                to = to,
                message_type = message.type_name(),
                "Message deduplicated (already seen)"
            );
            return;
        }

        // Record traffic for bandwidth analysis (if enabled)
        if let Some(ref analyzer) = self.traffic_analyzer {
            let (payload_size, wire_size) = message.encoded_size();
            analyzer.record_message(message.type_name(), payload_size, wire_size, from, to);
        }

        // Message will be delivered - sample latency and schedule
        // Batched messages expand to multiple events
        let events = message.to_received_events();
        let latency = self.network.sample_latency(from, to, &mut self.rng);
        let delivery_time = self.now + latency;
        for event in events {
            self.schedule_event(to, delivery_time, event);
        }
        self.stats.messages_sent += 1;
    }

    /// Try to deliver an event directly, accounting for partitions and packet loss.
    /// Used for domain-specific actions that don't go through OutboundMessage.
    fn try_deliver_event(&mut self, from: NodeIndex, to: NodeIndex, event: Event) {
        // Check partition first (deterministic - doesn't consume RNG)
        if self.network.is_partitioned(from, to) {
            self.stats.messages_dropped_partition += 1;
            trace!(from = from, to = to, "Event dropped due to partition");
            return;
        }

        // Check packet loss (probabilistic but deterministic with seeded RNG)
        if self.network.should_drop_packet(&mut self.rng) {
            self.stats.messages_dropped_loss += 1;
            trace!(from = from, to = to, "Event dropped due to packet loss");
            return;
        }

        // Note: No deduplication for domain-specific events - they are unique per transaction
        // The state machine already handles duplicate detection via tracker sets

        // Schedule delivery with network latency
        let latency = self.network.sample_latency(from, to, &mut self.rng);
        let delivery_time = self.now + latency;
        self.schedule_event(to, delivery_time, event);
        self.stats.messages_sent += 1;
    }

    /// Simulate a request/response round-trip with network latency.
    ///
    /// This simulates:
    /// 1. Request from `requester` to `responder` (one-way latency)
    /// 2. Response from `responder` back to `requester` (one-way latency)
    ///
    /// Returns `None` if the request would be dropped due to partition or packet loss.
    /// Returns `Some(delivery_time)` with the time the response would arrive.
    fn simulate_request_response(
        &mut self,
        requester: NodeIndex,
        responder: NodeIndex,
    ) -> Option<Duration> {
        // Check partition (either direction)
        if self.network.is_partitioned(requester, responder) {
            self.stats.messages_dropped_partition += 1;
            trace!(
                requester = requester,
                responder = responder,
                "Request dropped due to partition"
            );
            return None;
        }

        // Check packet loss for request
        if self.network.should_drop_packet(&mut self.rng) {
            self.stats.messages_dropped_loss += 1;
            trace!(
                requester = requester,
                responder = responder,
                "Request dropped due to packet loss"
            );
            return None;
        }

        // Check packet loss for response
        if self.network.should_drop_packet(&mut self.rng) {
            self.stats.messages_dropped_loss += 1;
            trace!(
                requester = requester,
                responder = responder,
                "Response dropped due to packet loss"
            );
            return None;
        }

        // Sample latency for request and response
        let request_latency = self
            .network
            .sample_latency(requester, responder, &mut self.rng);
        let response_latency = self
            .network
            .sample_latency(responder, requester, &mut self.rng);
        let round_trip = request_latency + response_latency;

        self.stats.messages_sent += 2; // Request + response

        Some(self.now + round_trip)
    }

    /// Convert a timer ID to an event.
    fn timer_to_event(&self, id: TimerId) -> Event {
        match id {
            TimerId::Proposal => Event::ProposalTimer,
            TimerId::Cleanup => Event::CleanupTimer,
            TimerId::GlobalConsensus => Event::GlobalConsensusTimer,
        }
    }

    /// Get a committed block from a peer's storage.
    #[allow(dead_code)]
    fn get_committed_block(
        &self,
        peer: NodeIndex,
        height: u64,
    ) -> Option<(Block, QuorumCertificate)> {
        self.node_storage
            .get(peer as usize)
            .and_then(|s| s.get_block(hyperscale_types::BlockHeight(height)))
    }
}
