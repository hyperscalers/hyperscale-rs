//! Deterministic simulation runner.
//!
//! Each node has its own storage and executor. When a node emits
//! `Action::ExecuteTransactions`, the runner calls that node's executor
//! inline (synchronously) for deterministic execution.

use crate::event_queue::EventKey;
use crate::network::{NetworkConfig, SimulatedNetwork};
use crate::storage::SimStorage;
use crate::NodeIndex;
use hyperscale_bft::BftConfig;
use hyperscale_core::{Action, Event, OutboundMessage, StateMachine, TimerId};
use hyperscale_engine::RadixExecutor;
use hyperscale_node::NodeStateMachine;
use hyperscale_types::{
    Block, KeyPair, KeyType, PublicKey, QuorumCertificate, ShardGroupId, StaticTopology, Topology,
    ValidatorId, ValidatorInfo, ValidatorSet,
};
use radix_common::network::NetworkDefinition;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use std::collections::{BTreeMap, HashMap};
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

                nodes.push(NodeStateMachine::new(
                    node_index as NodeIndex,
                    topology,
                    keys[node_index as usize].clone(),
                    BftConfig::default(),
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
        }
    }

    /// Get a reference to a node's storage.
    pub fn node_storage(&self, node: NodeIndex) -> Option<&SimStorage> {
        self.node_storage.get(node as usize)
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
        info!(
            end_time_secs = end_time.as_secs_f64(),
            "Starting simulation"
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

            // Update node's time and process event
            let node = &mut self.nodes[node_index as usize];
            node.set_time(self.now);
            let actions = node.handle(event);

            self.stats.actions_generated += actions.len() as u64;

            // Handle actions
            for action in actions {
                self.process_action(node_index, action);
            }
        }

        info!(
            events_processed = self.stats.events_processed,
            actions_generated = self.stats.actions_generated,
            final_time = ?self.now,
            "Simulation complete"
        );
    }

    /// Process an action from a node.
    fn process_action(&mut self, from: NodeIndex, action: Action) {
        match action {
            Action::BroadcastToShard { shard, message } => {
                let peers = self.network.peers_in_shard(shard);
                for to in peers {
                    if to != from {
                        if let Some(event) = self.message_to_event(message.clone()) {
                            self.try_deliver_message(from, to, event);
                        }
                    }
                }
            }

            Action::BroadcastGlobal { message } => {
                for to in self.network.all_nodes() {
                    if to != from {
                        if let Some(event) = self.message_to_event(message.clone()) {
                            self.try_deliver_message(from, to, event);
                        }
                    }
                }
            }

            Action::SetTimer { id, duration } => {
                let fire_time = self.now + duration;
                let event = self.timer_to_event(id);
                let key = self.schedule_event(from, fire_time, event);
                self.timers.insert((from, id), key);
                self.stats.timers_set += 1;
            }

            Action::CancelTimer { id } => {
                if let Some(key) = self.timers.remove(&(from, id)) {
                    self.event_queue.remove(&key);
                    self.stats.timers_cancelled += 1;
                }
            }

            Action::EnqueueInternal { event } => {
                // Special handling for SyncNeeded: the runner fetches blocks directly
                let sync_target = if let Event::SyncNeeded { target_height, .. } = &event {
                    Some(*target_height)
                } else {
                    None
                };

                // Schedule the event so the state machine knows about it
                self.schedule_event(from, self.now, event);

                // If it was a sync request, fetch the blocks (runner owns sync I/O)
                if let Some(target_height) = sync_target {
                    self.handle_sync_needed(from, target_height);
                }
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
                // Verify provision signature
                // The signing message format must match ExecutionState::sign_provision()
                let mut msg = Vec::new();
                msg.extend_from_slice(b"STATE_PROVISION");
                msg.extend_from_slice(provision.transaction_hash.as_bytes());
                msg.extend_from_slice(&provision.target_shard.0.to_le_bytes());
                msg.extend_from_slice(&provision.source_shard.0.to_le_bytes());
                msg.extend_from_slice(&provision.block_height.0.to_le_bytes());
                for entry in &provision.entries {
                    msg.extend_from_slice(entry.hash().as_bytes());
                }

                let valid = public_key.verify(&msg, &provision.signature);
                self.schedule_event(
                    from,
                    self.now,
                    Event::ProvisionSignatureVerified { provision, valid },
                );
            }

            Action::VerifyStateVoteSignature { vote, public_key } => {
                // Verify state vote signature
                // The signing message format must match ExecutionState::create_vote()
                let mut msg = Vec::new();
                msg.extend_from_slice(b"EXEC_VOTE");
                msg.extend_from_slice(vote.transaction_hash.as_bytes());
                msg.extend_from_slice(vote.state_root.as_bytes());
                msg.extend_from_slice(&vote.shard_group_id.0.to_le_bytes());
                msg.push(if vote.success { 1 } else { 0 });

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
                // In production, this would verify the BLS aggregate properly

                // Build the message that was signed by the votes
                // Must match the format in ExecutionState::create_vote()
                let mut msg = Vec::new();
                msg.extend_from_slice(b"EXEC_VOTE");
                msg.extend_from_slice(certificate.transaction_hash.as_bytes());
                msg.extend_from_slice(certificate.outputs_merkle_root.as_bytes());
                msg.extend_from_slice(&certificate.shard_group_id.0.to_le_bytes());
                msg.push(if certificate.success { 1 } else { 0 });

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

            Action::VerifyViewChangeVoteSignature {
                vote,
                public_key,
                signing_message,
            } => {
                // In simulation, verify the signature instantly
                let valid = public_key.verify(&signing_message, &vote.signature);
                self.schedule_event(
                    from,
                    self.now,
                    Event::ViewChangeVoteSignatureVerified { vote, valid },
                );
            }

            Action::VerifyViewChangeHighestQc {
                vote,
                public_keys,
                signing_message,
            } => {
                // Verify aggregated BLS signature on the highest_qc
                let signer_keys: Vec<_> = public_keys
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| vote.highest_qc.signers.is_set(*i))
                    .map(|(_, pk)| pk.clone())
                    .collect();

                // Verify against domain-separated signing message
                let valid = if signer_keys.is_empty() {
                    false
                } else {
                    match hyperscale_types::PublicKey::aggregate_bls(&signer_keys) {
                        Ok(aggregated_pk) => aggregated_pk
                            .verify(&signing_message, &vote.highest_qc.aggregated_signature),
                        Err(_) => false,
                    }
                };

                self.schedule_event(
                    from,
                    self.now,
                    Event::ViewChangeHighestQcVerified { vote, valid },
                );
            }

            Action::ExecuteTransactions {
                block_hash,
                transactions,
                ..
            } => {
                // Execute transactions using the node's own Radix Engine and storage
                // Each node has independent storage - this runs inline (synchronously)
                let storage = &mut self.node_storage[from as usize];
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

            Action::ExecuteCrossShardTransaction {
                tx_hash,
                transaction,
                provisions,
            } => {
                // Execute cross-shard transaction with provisions using the node's Radix Engine
                let storage = &mut self.node_storage[from as usize];
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

            Action::EmitTransactionResult { request_id, result } => {
                debug!(?request_id, ?result, "Transaction result");
            }

            Action::EmitTransactionStatus {
                request_id,
                tx_hash,
                status,
            } => {
                debug!(?request_id, ?tx_hash, ?status, "Transaction status");
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
            }
            Action::PersistTransactionCertificate { certificate } => {
                // Store certificate in this node's storage
                let storage = &mut self.node_storage[from as usize];
                storage.put_certificate(certificate.transaction_hash, certificate);
            }
            Action::PersistSubstateWrites { .. } => {}

            // Storage reads - immediately return callback events in simulation
            // In production, these would be async operations
            Action::FetchStateEntries { tx_hash, nodes } => {
                // In simulation, return empty entries (no persistent storage)
                // A full implementation would read from SimStorage and return actual substates
                trace!(
                    node = from,
                    tx_hash = ?tx_hash,
                    nodes = nodes.len(),
                    "Fetching state entries (returning empty in simulation)"
                );
                self.schedule_event(
                    from,
                    self.now,
                    Event::StateEntriesFetched {
                        tx_hash,
                        entries: vec![], // Empty in simulation - no actual state
                    },
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
        }
    }

    /// Handle sync needed: the simulation runner fetches blocks directly.
    ///
    /// In production, this would be handled by the SyncManager with network I/O.
    /// In simulation, we look up blocks from any peer's storage that has them.
    pub fn handle_sync_needed(&mut self, node: NodeIndex, target_height: u64) {
        // Collect information from node state first (immutable borrow)
        let (start_height, heights_to_skip) = {
            let node_state = &self.nodes[node as usize];
            let committed_height = node_state.bft().committed_height();
            let sync_committed_height = node_state.sync().committed_height();
            let start = committed_height.max(sync_committed_height) + 1;

            // Collect which heights are already fetched
            let mut skip = Vec::new();
            for h in start..=target_height {
                if node_state.sync().has_fetched_block(h) {
                    skip.push(h);
                }
            }
            (start, skip)
        };

        // Fetch blocks from start_height to target_height
        for height in start_height..=target_height {
            // Skip if sync state already has this block fetched
            if heights_to_skip.contains(&height) {
                continue;
            }

            // Find any peer that has this block
            if let Some((block, qc)) = self.find_block_from_any_peer(height) {
                // Deliver immediately (simulation has instant storage access)
                let event = Event::SyncBlockReceived { block, qc };
                self.schedule_event(node, self.now, event);
            } else {
                warn!(
                    node = node,
                    height = height,
                    "Sync: no peer has block at height"
                );
                break; // Can't continue sync without this block
            }
        }
    }

    /// Find a block at a given height from any peer's storage.
    fn find_block_from_any_peer(&self, height: u64) -> Option<(Block, QuorumCertificate)> {
        for storage in &self.node_storage {
            if let Some(block_qc) = storage.get_block(hyperscale_types::BlockHeight(height)) {
                return Some(block_qc);
            }
        }
        None
    }

    /// Schedule an event.
    fn schedule_event(&mut self, node: NodeIndex, time: Duration, event: Event) -> EventKey {
        self.sequence += 1;
        let key = EventKey::new(time, &event, node, self.sequence);
        self.event_queue.insert(key, event);
        key
    }

    /// Try to deliver a message, accounting for partitions and packet loss.
    /// Updates stats based on delivery outcome.
    fn try_deliver_message(&mut self, from: NodeIndex, to: NodeIndex, event: Event) {
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

        // Message will be delivered - sample latency and schedule
        let latency = self.network.sample_latency(from, to, &mut self.rng);
        let delivery_time = self.now + latency;
        self.schedule_event(to, delivery_time, event);
        self.stats.messages_sent += 1;
    }

    /// Convert an outbound message to an inbound event.
    ///
    /// Note: Sender identity is not included in Events anymore.
    /// In production, sender identity comes from message signatures (ValidatorId).
    /// In simulation, sender identity isn't needed for consensus correctness.
    fn message_to_event(&self, message: OutboundMessage) -> Option<Event> {
        Some(match message {
            OutboundMessage::BlockHeader(gossip) => Event::BlockHeaderReceived {
                header: gossip.header,
                tx_hashes: gossip.transaction_hashes,
                cert_hashes: gossip.certificate_hashes,
                deferred: gossip.deferred,
                aborted: gossip.aborted,
            },
            OutboundMessage::BlockVote(gossip) => Event::BlockVoteReceived { vote: gossip.vote },
            OutboundMessage::ViewChangeVote(gossip) => {
                Event::ViewChangeVoteReceived { vote: gossip.vote }
            }
            OutboundMessage::ViewChangeCertificate(gossip) => {
                Event::ViewChangeCertificateReceived {
                    cert: gossip.certificate,
                }
            }
            OutboundMessage::StateProvision(gossip) => Event::StateProvisionReceived {
                provision: gossip.provision,
            },
            OutboundMessage::StateVoteBlock(gossip) => {
                Event::StateVoteReceived { vote: gossip.vote }
            }
            OutboundMessage::StateCertificate(gossip) => Event::StateCertificateReceived {
                cert: gossip.certificate,
            },
            OutboundMessage::TransactionGossip(gossip) => Event::TransactionGossipReceived {
                tx: gossip.transaction,
            },
        })
    }

    /// Convert a timer ID to an event.
    fn timer_to_event(&self, id: TimerId) -> Event {
        match id {
            TimerId::Proposal => Event::ProposalTimer,
            TimerId::ViewChange => Event::ViewChangeTimer,
            TimerId::Cleanup => Event::CleanupTimer,
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
