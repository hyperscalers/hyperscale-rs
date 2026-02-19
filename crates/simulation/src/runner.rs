//! Deterministic simulation runner.
//!
//! Each node has its own storage and executor. When a node emits
//! `Action::ExecuteTransactions`, the runner calls that node's executor
//! inline (synchronously) for deterministic execution.

use crate::event_queue::EventKey;
use crate::NodeIndex;
use crate::SimStorage;
use hyperscale_bft::{BftConfig, RecoveredState};
use hyperscale_core::{Action, Event, StateMachine, TimerId};
use hyperscale_engine::RadixExecutor;
use hyperscale_execution::{DEFAULT_SPECULATIVE_MAX_TXS, DEFAULT_VIEW_CHANGE_COOLDOWN_ROUNDS};
use hyperscale_mempool::MempoolConfig;
use hyperscale_network_memory::{NetworkConfig, NetworkTrafficAnalyzer, SimulatedNetwork};
use hyperscale_node::NodeStateMachine;
use hyperscale_node::{SyncConfig, SyncInput, SyncOutput, SyncProtocol};
use hyperscale_storage::{CommitStore, ConsensusStore};
use hyperscale_types::{
    bls_keypair_from_seed, Block, Bls12381G1PrivateKey, Bls12381G1PublicKey, Hash as TxHash,
    QuorumCertificate, ShardGroupId, StaticTopology, Topology, TransactionStatus, ValidatorId,
    ValidatorInfo, ValidatorSet,
};
use radix_common::network::NetworkDefinition;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use std::collections::{BTreeMap, HashMap, HashSet};
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

    /// Per-node sync protocol state machines. One per node.
    sync_protocols: Vec<SyncProtocol>,

    /// Per-node pending sync fetches. Heights where the block wasn't available
    /// on any peer yet, to be retried when new blocks become available.
    sync_pending_fetches: HashMap<NodeIndex, HashSet<u64>>,

    /// Per-node transaction status cache. Captures all emitted statuses.
    /// Maps (node_index, tx_hash) -> status for querying final transaction states.
    tx_status_cache: HashMap<(NodeIndex, TxHash), TransactionStatus>,

    /// Precomputed commit handles from `prepare_block_commit`, keyed by (node, block_hash).
    /// Populated by `VerifyStateRoot` / `BuildProposal`, consumed by `EmitCommittedBlock`.
    prepared_commits: HashMap<(NodeIndex, TxHash), <SimStorage as CommitStore>::PreparedCommit>,
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
            sync_protocols: (0..num_nodes)
                .map(|_| SyncProtocol::new(SyncConfig::default()))
                .collect(),
            sync_pending_fetches: HashMap::new(),
            tx_status_cache: HashMap::new(),
            prepared_commits: HashMap::new(),
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
    pub fn traffic_report(&self) -> Option<hyperscale_network_memory::BandwidthReport> {
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
        use hyperscale_storage::SubstateStore;
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
            let genesis_jmt_root = first_node_storage.state_root_hash();

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
        use hyperscale_engine::GenesisConfig;
        use hyperscale_storage::SubstateStore;
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
            let genesis_jmt_root = first_node_storage.state_root_hash();

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
                for shard in topology.all_shards_for_transaction(tx) {
                    let event = Event::TransactionGossipReceived { tx: Arc::clone(tx) };
                    let peers = self.network.peers_in_shard(shard);
                    for to in peers {
                        if to != node_index {
                            self.try_deliver_event(node_index, to, event.clone());
                        }
                    }
                }
            }

            // Handle TransactionCertificateReceived directly in runner (like production).
            // Verify signatures synchronously (no async in simulation) and persist.
            if let Event::TransactionCertificateReceived { ref certificate } = event {
                let storage = &self.node_storage[node_index as usize];
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

            // Retry pending sync fetches if any blocks may now be available.
            if self.sync_pending_fetches.contains_key(&node_index) {
                self.retry_pending_sync_fetches(node_index);
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
            Action::BroadcastBlockHeader { shard, header } => {
                let event = Event::BlockHeaderReceived {
                    header: header.header.clone(),
                    retry_hashes: header.retry_hashes.clone(),
                    priority_hashes: header.priority_hashes.clone(),
                    tx_hashes: header.transaction_hashes.clone(),
                    cert_hashes: header.certificate_hashes.clone(),
                    deferred: header.deferred.clone(),
                    aborted: header.aborted.clone(),
                    commitment_proofs: header.commitment_proofs.clone(),
                };
                let peers = self.network.peers_in_shard(shard);
                for to in peers {
                    if to != from {
                        self.try_deliver_event(from, to, event.clone());
                    }
                }
            }

            Action::BroadcastBlockVote { shard, vote } => {
                let event = Event::BlockVoteReceived {
                    vote: vote.vote.clone(),
                };
                let peers = self.network.peers_in_shard(shard);
                for to in peers {
                    if to != from {
                        self.try_deliver_event(from, to, event.clone());
                    }
                }
            }

            Action::BroadcastTransaction { shard, gossip } => {
                let event = Event::TransactionGossipReceived {
                    tx: Arc::clone(&gossip.transaction),
                };
                let peers = self.network.peers_in_shard(shard);
                for to in peers {
                    if to != from {
                        self.try_deliver_event(from, to, event.clone());
                    }
                }
            }

            Action::BroadcastTransactionCertificate { shard, gossip } => {
                let event = Event::TransactionCertificateReceived {
                    certificate: gossip.certificate.clone(),
                };
                let peers = self.network.peers_in_shard(shard);
                for to in peers {
                    if to != from {
                        self.try_deliver_event(from, to, event.clone());
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
                target_hash,
            } => {
                let outputs = self.sync_protocols[from as usize].handle(SyncInput::StartSync {
                    target_height,
                    target_hash,
                });
                self.process_sync_outputs(from, outputs);
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

            // ═══════════════════════════════════════════════════════════════════════
            // Delegated work — executes instantly in simulation via shared pure functions.
            // Crypto verification, state root, proposal building, and execution all use
            // the same algorithms as production (extracted to subsystem crates).
            // ═══════════════════════════════════════════════════════════════════════
            Action::VerifyAndBuildQuorumCertificate { .. }
            | Action::VerifyQcSignature { .. }
            | Action::VerifyCycleProof { .. }
            | Action::VerifyStateRoot { .. }
            | Action::VerifyTransactionRoot { .. }
            | Action::BuildProposal { .. }
            | Action::AggregateStateCertificate { .. }
            | Action::VerifyAndAggregateStateVotes { .. }
            | Action::VerifyStateCertificateSignature { .. }
            | Action::VerifyAndAggregateProvisions { .. }
            | Action::ExecuteTransactions { .. }
            | Action::SpeculativeExecute { .. }
            | Action::ExecuteCrossShardTransaction { .. }
            | Action::ComputeMerkleRoot { .. } => {
                self.handle_delegated_action(from, action);
            }

            // Notifications - these would go to external observers
            Action::EmitCommittedBlock { block, qc } => {
                debug!(block_hash = ?block.hash(), "Block committed");

                let storage = &self.node_storage[from as usize];
                let block_hash = block.hash();
                let height = block.header.height;
                let local_shard = self.nodes[from as usize].shard();

                let prepared = self.prepared_commits.remove(&(from, block_hash));
                if let Some(commit_event) = hyperscale_node::action_handler::commit_block(
                    storage,
                    &block,
                    block_hash,
                    height,
                    &qc,
                    local_shard,
                    prepared,
                ) {
                    self.schedule_event(from, self.now, commit_event);
                }

                // Feed committed height to sync protocol so it advances its window.
                let outputs = self.sync_protocols[from as usize]
                    .handle(SyncInput::BlockCommitted { height: height.0 });
                self.process_sync_outputs(from, outputs);
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
                // Store block and QC in this node's storage for sync availability.
                // NOTE: Committed metadata (set_committed_state, prune_own_votes) is NOT
                // set here. PersistBlock fires at certification time, not commit time.
                // Committed metadata is set in EmitCommittedBlock after state is applied.
                let height = block.header.height;
                let storage = &self.node_storage[from as usize];
                ConsensusStore::put_block(storage, height, &block, &qc);

                // Retry any pending sync fetches — this peer may have just stored
                // a block another syncing node needs.
                if let Some(pending) = self.sync_pending_fetches.get(&from).cloned() {
                    if !pending.is_empty() {
                        self.retry_pending_sync_fetches(from);
                    }
                }
            }
            Action::PersistTransactionCertificate { certificate } => {
                // Only store certificate metadata; state writes are committed
                // at EmitCommittedBlock time via commit_prepared_block/commit_block.
                // This matches production behavior and prevents double-commit.
                let storage = &self.node_storage[from as usize];
                let local_shard = self.nodes[from as usize].shard();

                storage.store_certificate(&certificate);

                // After persisting, gossip certificate to same-shard peers.
                // This ensures other validators have the certificate before the proposer
                // includes it in a block, avoiding fetch delays.
                let event = Event::TransactionCertificateReceived {
                    certificate: certificate.clone(),
                };
                let peers = self.network.peers_in_shard(local_shard);
                for to in peers {
                    if to != from {
                        self.try_deliver_event(from, to, event.clone());
                    }
                }
            }
            Action::PersistAndBroadcastVote {
                height,
                round,
                block_hash,
                shard,
                vote,
            } => {
                // **BFT Safety Critical**: Store our vote before broadcasting.
                // This ensures we remember what we voted for after a restart.
                let storage = &self.node_storage[from as usize];
                storage.put_own_vote(height.0, round, block_hash);
                trace!(
                    node = from,
                    height = height.0,
                    round = round,
                    block_hash = ?block_hash,
                    "Persisted own vote"
                );

                // Now broadcast the vote (simulated immediately after persist)
                let broadcast_action = Action::BroadcastBlockVote { shard, vote };
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

    /// Handle a delegated action using the shared pure functions.
    ///
    /// For execution actions, additionally broadcasts state votes to shard peers.
    fn handle_delegated_action(&mut self, from: NodeIndex, action: Action) {
        let local_shard = self.nodes[from as usize].shard();
        let dispatch = hyperscale_dispatch_sync::SyncDispatch;
        let ctx = hyperscale_node::action_handler::ActionContext {
            storage: &self.node_storage[from as usize],
            executor: &self.node_executor[from as usize],
            topology: self.nodes[from as usize].topology().as_ref(),
            signing_key: &self.node_keys[from as usize],
            local_shard,
            validator_id: self.nodes[from as usize].topology().local_validator_id(),
            dispatch: &dispatch,
        };
        if let Some(result) = hyperscale_node::action_handler::handle_delegated_action(action, &ctx)
        {
            // Cache prepared commit handle for use at block commit time
            if let Some((hash, prepared)) = result.prepared_commit {
                self.prepared_commits.insert((from, hash), prepared);
            }
            for event in result.events {
                // For StateVoteReceived, also broadcast to shard peers
                if matches!(event, Event::StateVoteReceived { .. }) {
                    let broadcast_event = event.clone();
                    let peers = self.network.peers_in_shard(local_shard);
                    for to in peers {
                        if to != from {
                            self.try_deliver_event(from, to, broadcast_event.clone());
                        }
                    }
                }
                self.schedule_event(from, self.now, event);
            }
        }
    }

    /// Process outputs from the sync protocol state machine.
    fn process_sync_outputs(&mut self, node: NodeIndex, outputs: Vec<SyncOutput>) {
        for output in outputs {
            match output {
                SyncOutput::FetchBlock { height } => {
                    if let Some((peer, block, qc)) =
                        self.find_block_from_any_peer_with_index(height)
                    {
                        if let Some(_delivery_time) = self.simulate_request_response(node, peer) {
                            // Feed successful response back to protocol
                            let inner_outputs = self.sync_protocols[node as usize].handle(
                                SyncInput::BlockResponseReceived {
                                    height,
                                    block: Box::new(Some((block, qc))),
                                },
                            );
                            self.process_sync_outputs(node, inner_outputs);
                        } else {
                            // Network drop — track as pending for retry
                            self.sync_pending_fetches
                                .entry(node)
                                .or_default()
                                .insert(height);
                        }
                    } else {
                        // Block not available on any peer yet — track for retry
                        self.sync_pending_fetches
                            .entry(node)
                            .or_default()
                            .insert(height);
                    }
                }
                SyncOutput::DeliverBlock { block, qc } => {
                    let event = Event::SyncBlockReadyToApply {
                        block: *block,
                        qc: *qc,
                    };
                    self.schedule_event(node, self.now, event);
                }
                SyncOutput::SyncComplete { height } => {
                    self.sync_pending_fetches.remove(&node);
                    let actions = self.nodes[node as usize].handle(Event::SyncComplete { height });
                    for action in actions {
                        self.process_action(node, action);
                    }
                }
            }
        }
    }

    /// Retry pending sync fetches that previously failed because blocks weren't available.
    fn retry_pending_sync_fetches(&mut self, node: NodeIndex) {
        let Some(pending) = self.sync_pending_fetches.get(&node).cloned() else {
            return;
        };
        for height in pending {
            if let Some((peer, block, qc)) = self.find_block_from_any_peer_with_index(height) {
                if let Some(_delivery_time) = self.simulate_request_response(node, peer) {
                    self.sync_pending_fetches
                        .get_mut(&node)
                        .unwrap()
                        .remove(&height);
                    let outputs = self.sync_protocols[node as usize].handle(
                        SyncInput::BlockResponseReceived {
                            height,
                            block: Box::new(Some((block, qc))),
                        },
                    );
                    self.process_sync_outputs(node, outputs);
                }
            }
        }
        // Clean up empty sets
        if self
            .sync_pending_fetches
            .get(&node)
            .is_some_and(|s| s.is_empty())
        {
            self.sync_pending_fetches.remove(&node);
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

        // Look up certificates from proposer's storage
        let mut found_certificates = Vec::new();
        let proposer_storage = &self.node_storage[proposer_node as usize];
        for cert_hash in &missing_cert_hashes {
            if let Some(cert) = proposer_storage.get_certificate(cert_hash) {
                found_certificates.push(cert);
            }
        }

        if found_certificates.is_empty() {
            debug!(
                node = node,
                block_hash = ?block_hash,
                missing_count = missing_cert_hashes.len(),
                "Certificate fetch: no certificates found in proposer's storage"
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

    /// Try to deliver an event directly, accounting for partitions and packet loss.
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
