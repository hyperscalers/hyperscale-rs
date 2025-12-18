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
use hyperscale_engine::RadixExecutor;
use hyperscale_node::NodeStateMachine;
use hyperscale_types::{
    Block, Hash as TxHash, KeyPair, KeyType, PublicKey, QuorumCertificate, ShardGroupId,
    StaticTopology, Topology, TransactionStatus, ValidatorId, ValidatorInfo, ValidatorSet,
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
        let keys: Vec<KeyPair> = (0..total_validators)
            .map(|i| {
                // Use deterministic seed for each validator's key
                let mut seed_bytes = [0u8; 32];
                let key_seed = seed.wrapping_add(i as u64).wrapping_mul(0x517cc1b727220a95);
                seed_bytes[..8].copy_from_slice(&key_seed.to_le_bytes());
                seed_bytes[8..16].copy_from_slice(&(i as u64).to_le_bytes());
                KeyPair::from_seed(KeyType::Bls12381, &seed_bytes)
            })
            .collect();
        let public_keys: Vec<PublicKey> = keys.iter().map(|k| k.public_key()).collect();

        // Build global validator set for the entire network
        let global_validators: Vec<ValidatorInfo> = (0..total_validators)
            .map(|i| ValidatorInfo {
                validator_id: ValidatorId(i as u64),
                public_key: public_keys[i as usize].clone(),
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
                nodes.push(NodeStateMachine::new(
                    node_index as NodeIndex,
                    topology,
                    keys[node_index as usize].clone(),
                    BftConfig::default(),
                    RecoveredState::default(),
                ));
            }
        }

        // Create per-node storage and executor
        let num_nodes = nodes.len();
        let node_storage: Vec<SimStorage> = (0..num_nodes).map(|_| SimStorage::new()).collect();
        let node_executor: Vec<RadixExecutor> = (0..num_nodes)
            .map(|_| RadixExecutor::new(NetworkDefinition::simulator()))
            .collect();
        let genesis_executed = vec![false; num_nodes];

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
            genesis_executed,
            traffic_analyzer: None,
            seen_messages: HashSet::new(),
            sync_targets: HashMap::new(),
            tx_status_cache: HashMap::new(),
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
            // Create genesis block for this shard
            let genesis_header = BlockHeader {
                height: BlockHeight(0),
                parent_hash: Hash::from_bytes(&[0u8; 32]),
                parent_qc: QuorumCertificate::genesis(),
                proposer: ValidatorId((shard_id * validators_per_shard) as u64),
                timestamp: 0,
                round: 0,
                is_fallback: false,
            };

            let genesis_block = Block {
                header: genesis_header,
                transactions: vec![],
                committed_certificates: vec![],
                deferred: vec![],
                aborted: vec![],
            };

            // Initialize all validators in this shard
            let shard_start = shard_id * validators_per_shard;
            let shard_end = shard_start + validators_per_shard;

            for node_index in shard_start..shard_end {
                let node = &mut self.nodes[node_index as usize];
                let actions = node.initialize_genesis(genesis_block.clone());

                // Process the actions (which should set initial timers)
                for action in actions {
                    self.process_action(node_index, action);
                }
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
            // Create genesis block for this shard
            let genesis_header = BlockHeader {
                height: BlockHeight(0),
                parent_hash: Hash::from_bytes(&[0u8; 32]),
                parent_qc: QuorumCertificate::genesis(),
                proposer: ValidatorId((shard_id * validators_per_shard) as u64),
                timestamp: 0,
                round: 0,
                is_fallback: false,
            };

            let genesis_block = Block {
                header: genesis_header,
                transactions: vec![],
                committed_certificates: vec![],
                deferred: vec![],
                aborted: vec![],
            };

            // Initialize all validators in this shard
            let shard_start = shard_id * validators_per_shard;
            let shard_end = shard_start + validators_per_shard;

            for node_index in shard_start..shard_end {
                let node = &mut self.nodes[node_index as usize];
                let actions = node.initialize_genesis(genesis_block.clone());

                // Process the actions (which should set initial timers)
                for action in actions {
                    self.process_action(node_index, action);
                }
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
            Action::VerifyVoteSignature {
                vote,
                public_key,
                signing_message,
            } => {
                // In simulation, verify signature against domain-separated message (instant, deterministic)
                let valid = public_key.verify(&signing_message, &vote.signature);
                self.schedule_event(from, self.now, Event::VoteSignatureVerified { vote, valid });
            }

            Action::VerifyProvisionSignature {
                provision,
                public_key,
            } => {
                // Use centralized signing message (must match ExecutionState::sign_provision)
                let msg = provision.signing_message();

                let valid = public_key.verify(&msg, &provision.signature);
                self.schedule_event(
                    from,
                    self.now,
                    Event::ProvisionSignatureVerified { provision, valid },
                );
            }

            Action::VerifyStateVoteSignature { vote, public_key } => {
                // Use centralized signing message (must match ExecutionState::create_vote)
                let msg = vote.signing_message();

                let valid = public_key.verify(&msg, &vote.signature);
                self.schedule_event(
                    from,
                    self.now,
                    Event::StateVoteSignatureVerified { vote, valid },
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
                    .map(|(_, pk)| pk.clone())
                    .collect();

                // Verify aggregated signature
                let valid = if signer_keys.is_empty() {
                    // No signers - valid only if it's a zero signature (single-shard case)
                    certificate.aggregated_signature == hyperscale_types::Signature::zero()
                } else {
                    // Aggregate the public keys and verify
                    match hyperscale_types::PublicKey::aggregate_bls(&signer_keys) {
                        Ok(aggregated_pk) => {
                            aggregated_pk.verify(&msg, &certificate.aggregated_signature)
                        }
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
                    .map(|(_, pk)| pk.clone())
                    .collect();

                // Verify aggregated signature against domain-separated message
                let valid = if signer_keys.is_empty() {
                    // No signers - invalid QC (genesis QC is handled before action is emitted)
                    false
                } else {
                    // Aggregate the public keys and verify
                    match hyperscale_types::PublicKey::aggregate_bls(&signer_keys) {
                        Ok(aggregated_pk) => {
                            aggregated_pk.verify(&signing_message, &qc.aggregated_signature)
                        }
                        Err(_) => false,
                    }
                };

                self.schedule_event(
                    from,
                    self.now,
                    Event::QcSignatureVerified { block_hash, valid },
                );
            }

            // Note: View change verification actions removed - using HotStuff-2 implicit rounds
            Action::ExecuteTransactions {
                block_hash,
                transactions,
                ..
            } => {
                // Execute transactions using the node's own Radix Engine and storage
                // Each node has independent storage - this runs inline (synchronously)
                //
                // NOTE: Execution is READ-ONLY. State writes are collected in the results
                // and committed later when TransactionCertificate is included in a block
                // (via PersistTransactionCertificate handler).
                let storage = &self.node_storage[from as usize];
                let executor = &self.node_executor[from as usize];

                let results = match executor.execute_single_shard(storage, &transactions) {
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
                        warn!(node = from, ?block_hash, error = %e, "Transaction execution failed");
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

                self.schedule_event(
                    from,
                    self.now,
                    Event::TransactionsExecuted {
                        block_hash,
                        results,
                    },
                );
            }

            Action::SpeculativeExecute {
                block_hash,
                transactions,
            } => {
                // Speculatively execute single-shard transactions before block commit.
                // This is identical to ExecuteTransactions but returns a different event.
                // Results are cached and used when the block commits (if still valid).
                let storage = &self.node_storage[from as usize];
                let executor = &self.node_executor[from as usize];

                let results: Vec<(hyperscale_types::Hash, hyperscale_types::ExecutionResult)> =
                    match executor.execute_single_shard(storage, &transactions) {
                        Ok(output) => output
                            .results()
                            .iter()
                            .map(|r| {
                                (
                                    r.tx_hash,
                                    hyperscale_types::ExecutionResult {
                                        transaction_hash: r.tx_hash,
                                        success: r.success,
                                        state_root: r.outputs_merkle_root,
                                        writes: r.state_writes.clone(),
                                        error: r.error.clone(),
                                    },
                                )
                            })
                            .collect(),
                        Err(e) => {
                            // Execution failed - mark all transactions as failed
                            warn!(node = from, ?block_hash, error = %e, "Speculative execution failed");
                            transactions
                                .iter()
                                .map(|tx| {
                                    (
                                        tx.hash(),
                                        hyperscale_types::ExecutionResult {
                                            transaction_hash: tx.hash(),
                                            success: false,
                                            state_root: hyperscale_types::Hash::ZERO,
                                            writes: vec![],
                                            error: Some(format!("{}", e)),
                                        },
                                    )
                                })
                                .collect()
                        }
                    };

                self.schedule_event(
                    from,
                    self.now,
                    Event::SpeculativeExecutionComplete {
                        block_hash,
                        results,
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
                let storage = &self.node_storage[from as usize];
                let executor = &self.node_executor[from as usize];

                // Determine which nodes are local to this shard
                let local_shard = self.nodes[from as usize].shard();
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

                self.schedule_event(
                    from,
                    self.now,
                    Event::CrossShardTransactionExecuted { tx_hash, result },
                );
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
                        // Sync complete
                        self.sync_targets.remove(&from);
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
            }
            Action::PersistOwnVote {
                height,
                round,
                block_hash,
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
        let event = message.to_received_event();
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
