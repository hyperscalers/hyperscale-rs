//! Node state machine.

use hyperscale_bft::{BftConfig, BftState, RecoveredState};
use hyperscale_core::{Action, Event, StateMachine, TimerId};
use hyperscale_execution::ExecutionState;
use hyperscale_livelock::LivelockState;
use hyperscale_mempool::{MempoolConfig, MempoolState};
use hyperscale_provisions::ProvisionCoordinator;
use hyperscale_types::{Block, BlockHeight, Bls12381G1PrivateKey, ShardGroupId, Topology};
use std::sync::Arc;
use std::time::Duration;
use tracing::instrument;

/// Index type for simulation-only node routing.
/// Production uses ValidatorId (from message signatures) and PeerId (libp2p).
pub type NodeIndex = u32;

/// Combined node state machine.
///
/// Composes BFT, execution, mempool, provisions, and livelock into a single state machine.
/// View changes are handled implicitly via local round advancement in BftState (HotStuff-2 style).
///
/// Note: Sync is handled entirely by the runner (production: SyncManager, simulation: runner logic).
/// The runner sends SyncBlockReadyToApply events directly to BFT when synced blocks are ready.
pub struct NodeStateMachine {
    /// This node's index (simulation-only, for routing).
    node_index: NodeIndex,

    /// Network topology (single source of truth).
    topology: Arc<dyn Topology>,

    /// BFT consensus state (includes implicit round advancement).
    bft: BftState,

    /// Execution state.
    execution: ExecutionState,

    /// Mempool state.
    mempool: MempoolState,

    /// Provision coordination for cross-shard transactions.
    provisions: ProvisionCoordinator,

    /// Livelock prevention state (cycle detection for cross-shard TXs).
    livelock: LivelockState,

    /// Current time.
    now: Duration,
}

impl std::fmt::Debug for NodeStateMachine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeStateMachine")
            .field("node_index", &self.node_index)
            .field("shard", &self.topology.local_shard())
            .field("bft", &self.bft)
            .field("now", &self.now)
            .finish()
    }
}

impl NodeStateMachine {
    /// Create a new node state machine with default speculative execution settings.
    ///
    /// # Arguments
    ///
    /// * `node_index` - Deterministic node index for ordering
    /// * `topology` - Network topology (single source of truth)
    /// * `signing_key` - Key for signing votes and proposals
    /// * `bft_config` - BFT configuration
    /// * `recovered` - State recovered from storage. Use `RecoveredState::default()` for fresh start.
    pub fn new(
        node_index: NodeIndex,
        topology: Arc<dyn Topology>,
        signing_key: Bls12381G1PrivateKey,
        bft_config: BftConfig,
        recovered: RecoveredState,
    ) -> Self {
        Self::with_speculative_config(
            node_index,
            topology,
            signing_key,
            bft_config,
            recovered,
            hyperscale_execution::DEFAULT_SPECULATIVE_MAX_TXS,
            hyperscale_execution::DEFAULT_VIEW_CHANGE_COOLDOWN_ROUNDS,
            MempoolConfig::default(),
        )
    }

    /// Create a new node state machine with custom speculative execution config.
    #[allow(clippy::too_many_arguments)]
    pub fn with_speculative_config(
        node_index: NodeIndex,
        topology: Arc<dyn Topology>,
        signing_key: Bls12381G1PrivateKey,
        bft_config: BftConfig,
        recovered: RecoveredState,
        speculative_max_txs: usize,
        view_change_cooldown_rounds: u64,
        mempool_config: MempoolConfig,
    ) -> Self {
        let local_shard = topology.local_shard();

        // Clone key bytes to create a new keypair since Bls12381G1PrivateKey doesn't impl Clone
        let key_bytes = signing_key.to_bytes();
        let bft_signing_key =
            Bls12381G1PrivateKey::from_bytes(&key_bytes).expect("valid key bytes");

        Self {
            node_index,
            topology: topology.clone(),
            bft: BftState::new(
                node_index,
                bft_signing_key,
                topology.clone(),
                bft_config.clone(),
                recovered,
            ),
            execution: ExecutionState::with_speculative_config(
                topology.clone(),
                signing_key,
                speculative_max_txs,
                view_change_cooldown_rounds,
            ),
            mempool: MempoolState::with_config(topology.clone(), mempool_config),
            provisions: ProvisionCoordinator::new(local_shard, topology.clone()),
            livelock: LivelockState::new(local_shard, topology),
            now: Duration::ZERO,
        }
    }

    /// Get this node's index.
    pub fn node_index(&self) -> NodeIndex {
        self.node_index
    }

    /// Get this node's shard.
    pub fn shard(&self) -> ShardGroupId {
        self.topology.local_shard()
    }

    /// Get a reference to the topology.
    pub fn topology(&self) -> &Arc<dyn Topology> {
        &self.topology
    }

    /// Get a reference to the mempool state.
    pub fn mempool(&self) -> &MempoolState {
        &self.mempool
    }

    /// Get a reference to the BFT state.
    pub fn bft(&self) -> &BftState {
        &self.bft
    }

    /// Get a mutable reference to the BFT state.
    pub fn bft_mut(&mut self) -> &mut BftState {
        &mut self.bft
    }

    /// Get a reference to the execution state.
    pub fn execution(&self) -> &ExecutionState {
        &self.execution
    }

    /// Get a mutable reference to the execution state.
    pub fn execution_mut(&mut self) -> &mut ExecutionState {
        &mut self.execution
    }

    /// Get a reference to the livelock state.
    pub fn livelock(&self) -> &LivelockState {
        &self.livelock
    }

    /// Get a reference to the provision coordinator.
    pub fn provisions(&self) -> &ProvisionCoordinator {
        &self.provisions
    }

    /// Initialize the node with a genesis block.
    ///
    /// Returns actions to be processed (e.g., initial timers).
    pub fn initialize_genesis(&mut self, genesis: Block) -> Vec<Action> {
        self.bft.initialize_genesis(genesis)
        // Note: No separate view change timer - round advancement is handled
        // implicitly via the proposal timer (HotStuff-2 style)
    }

    /// Handle cleanup timer.
    #[instrument(skip(self))]
    fn on_cleanup_timer(&mut self) -> Vec<Action> {
        // Reschedule the cleanup timer
        let mut actions = vec![Action::SetTimer {
            id: TimerId::Cleanup,
            duration: self.bft.config().cleanup_interval,
        }];

        // Clean up expired tombstones in livelock state
        self.livelock.cleanup();

        // Check pending blocks that need fetch requests.
        // We delay fetching to give gossip and local certificate creation
        // time to fill in missing data first.
        actions.extend(self.bft.check_pending_block_fetches());

        // Clean up stale incomplete pending blocks in BFT state.
        // This prevents nodes from getting stuck when transaction/certificate
        // fetches fail permanently (e.g., proposer offline).
        // Returns CancelFetch actions for removed blocks.
        actions.extend(self.bft.cleanup_stale_pending_blocks());

        // Check if we're behind and need to catch up via sync.
        // This handles the case where we have a higher latest_qc than committed_height,
        // meaning the network has progressed but we're stuck.
        actions.extend(self.bft.check_sync_health());

        // Clean up old tombstones in mempool to prevent unbounded memory growth.
        // Retain tombstones for 1000 blocks (plenty of time for gossip propagation).
        const TOMBSTONE_RETENTION_BLOCKS: u64 = 1000;
        let current_height = BlockHeight(self.bft.committed_height());
        self.mempool
            .cleanup_old_tombstones(current_height, TOMBSTONE_RETENTION_BLOCKS);

        // Clean up stale speculative execution results (30 second timeout)
        const SPECULATIVE_MAX_AGE: Duration = Duration::from_secs(30);
        self.execution
            .cleanup_stale_speculative(SPECULATIVE_MAX_AGE);

        actions
    }

    /// Build commitment proofs for priority transactions.
    ///
    /// Returns a HashMap mapping transaction hash to CommitmentProof for all
    /// priority transactions (cross-shard with verified provisions). This is included
    /// in the block to make it self-contained for validation.
    ///
    /// Only priority transactions need proofs - they are already classified by the
    /// mempool as having verified provisions.
    fn build_commitment_proofs(
        &self,
        ready_txs: &hyperscale_types::ReadyTransactions,
    ) -> std::collections::HashMap<hyperscale_types::Hash, hyperscale_types::CommitmentProof> {
        let mut proofs = std::collections::HashMap::new();

        // Only priority transactions have verified provisions
        for tx in &ready_txs.priority {
            let tx_hash = tx.hash();
            if let Some(proof) = self.provisions.build_commitment_proof(&tx_hash) {
                proofs.insert(tx_hash, proof);
            }
        }

        proofs
    }
}

impl StateMachine for NodeStateMachine {
    #[instrument(skip(self), fields(
        node = self.node_index,
        shard = self.topology.local_shard().0,
        event = %event.type_name(),
        height = self.bft.committed_height(),
    ))]
    fn handle(&mut self, event: Event) -> Vec<Action> {
        // Route event to appropriate sub-state machine
        match &event {
            // Timer events
            Event::CleanupTimer => return self.on_cleanup_timer(),

            // ProposalTimer handles both proposal AND implicit round advancement
            Event::ProposalTimer => {
                // Check if we should advance the round due to timeout.
                // This is now handled in BftState which owns the timeout tracking.
                if let Some(actions) = self.bft.check_round_timeout() {
                    let current_height =
                        hyperscale_types::BlockHeight(self.bft.committed_height() + 1);

                    // Notify execution of view change to pause speculation temporarily
                    self.execution.on_view_change(current_height.0);

                    return actions;
                }

                // Normal proposal timer - try to propose if we're the proposer
                //
                // Account for pipelining: multiple blocks can be proposed before any commit.
                // We must count txs/certs in ALL pending blocks to avoid exceeding in-flight limits.
                let (pending_txs, pending_certs) = self.bft.pending_block_tx_cert_counts();

                // Get certificates we're about to propose - these also reduce in-flight
                let certificates = self.execution.get_finalized_certificates();
                let new_certs = certificates.len();

                let max_txs = self.bft.config().max_transactions_per_block;
                let ready_txs = self.mempool.ready_transactions(
                    max_txs,
                    pending_txs,               // txs in uncommitted pipeline blocks
                    pending_certs + new_certs, // certs in pipeline + certs we're proposing
                );
                let commitment_proofs = self.build_commitment_proofs(&ready_txs);
                // Get pending deferrals from livelock state
                let deferred = self.livelock.get_pending_deferrals();
                // Get timed-out transactions from mempool
                // Config: 30 blocks timeout, max 3 retries (per design Decision #27)
                let current_height = hyperscale_types::BlockHeight(self.bft.committed_height() + 1);
                let aborted = self.mempool.get_timed_out_transactions(
                    current_height,
                    30, // execution_timeout_blocks
                    3,  // max_retries
                );

                return self.bft.on_proposal_timer(
                    &ready_txs,
                    deferred,
                    aborted,
                    certificates,
                    commitment_proofs,
                );
            }

            // BlockHeaderReceived needs mempool for transaction lookup and certificates
            Event::BlockHeaderReceived {
                header,
                retry_hashes,
                priority_hashes,
                tx_hashes,
                cert_hashes,
                deferred,
                aborted,
                commitment_proofs,
            } => {
                // Total transaction count across all sections
                let total_tx_count = retry_hashes.len() + priority_hashes.len() + tx_hashes.len();

                // Validate in-flight limits only for the next block after committed height.
                // For blocks further ahead, skip validation - validators at different heights
                // have different in_flight() counts, causing split votes and view changes.
                let committed_height = self.bft.committed_height();
                let is_next_block = header.height.0 == committed_height + 1;

                if is_next_block {
                    let current_in_flight = self.mempool.in_flight();
                    let certs_in_block = cert_hashes.len();
                    let config = self.mempool.config();
                    let soft_limit = config.max_in_flight;
                    let hard_limit = config.max_in_flight_hard_limit;

                    // Retry and priority transactions bypass soft limit
                    // Only "other" transactions (tx_hashes) are subject to soft limit
                    let without_proofs = tx_hashes.len();

                    let new_in_flight = current_in_flight
                        .saturating_add(total_tx_count)
                        .saturating_sub(certs_in_block);

                    // Reject if exceeding hard limit AND making things worse.
                    // Allow blocks that don't increase in-flight (prevents deadlock).
                    let would_exceed = new_in_flight > hard_limit;
                    let would_increase = new_in_flight > current_in_flight;

                    if would_exceed && would_increase {
                        tracing::warn!(
                            current_in_flight,
                            certs_in_block,
                            proposed_tx_count = total_tx_count,
                            new_in_flight,
                            hard_limit,
                            block_hash = ?header.hash(),
                            height = header.height.0,
                            "Rejecting block that would exceed in-flight hard limit"
                        );
                        return vec![];
                    }

                    // Soft limit: only allow TXs with proofs when at limit
                    // Note: retry_hashes and priority_hashes bypass this check
                    if current_in_flight >= soft_limit && without_proofs > 0 {
                        tracing::warn!(
                            current_in_flight,
                            soft_limit,
                            txs_without_proofs = without_proofs,
                            block_hash = ?header.hash(),
                            height = header.height.0,
                            "Rejecting block with non-priority transactions while at soft limit"
                        );
                        return vec![];
                    }
                }

                let mempool_txs = self.mempool.transactions_by_hash();
                let local_certs = self.execution.finalized_certificates_by_hash();

                // Trigger speculative execution for single-shard transactions
                // This hides execution latency behind consensus latency
                let block_hash = header.hash();
                let height = header.height.0;
                let all_tx_hashes: Vec<_> = retry_hashes
                    .iter()
                    .chain(priority_hashes.iter())
                    .chain(tx_hashes.iter())
                    .collect();
                let transactions: Vec<_> = all_tx_hashes
                    .iter()
                    .filter_map(|h| mempool_txs.get(*h).cloned())
                    .collect();
                let spec_actions =
                    self.execution
                        .trigger_speculative_execution(block_hash, height, transactions);

                let mut actions = self.bft.on_block_header(
                    header.clone(),
                    retry_hashes.clone(),
                    priority_hashes.clone(),
                    tx_hashes.clone(),
                    cert_hashes.clone(),
                    deferred.clone(),
                    aborted.clone(),
                    commitment_proofs.clone(),
                    &mempool_txs,
                    &local_certs,
                );
                actions.extend(spec_actions);
                return actions;
            }

            // QuorumCertificateFormed may trigger immediate proposal, so pass mempool
            Event::QuorumCertificateFormed { block_hash, qc } => {
                // Count transactions and certificates in the block that will be committed.
                // This is critical for respecting in-flight limits: the BlockCommitted
                // event won't be processed until after we select transactions, so we
                // need to preemptively account for:
                // - Transactions that will INCREASE in-flight (new commits)
                // - Certificates that will DECREASE in-flight (completed transactions)
                let (pending_tx_count, pending_cert_count) = self.bft.pending_commit_counts(qc);

                let max_txs = self.bft.config().max_transactions_per_block;
                let ready_txs =
                    self.mempool
                        .ready_transactions(max_txs, pending_tx_count, pending_cert_count);
                let commitment_proofs = self.build_commitment_proofs(&ready_txs);
                let deferred = self.livelock.get_pending_deferrals();
                let current_height = hyperscale_types::BlockHeight(self.bft.committed_height() + 1);
                let aborted = self.mempool.get_timed_out_transactions(
                    current_height,
                    30, // execution_timeout_blocks
                    3,  // max_retries
                );
                let certificates = self.execution.get_finalized_certificates();
                return self.bft.on_qc_formed(
                    *block_hash,
                    qc.clone(),
                    &ready_txs,
                    deferred,
                    aborted,
                    certificates,
                    commitment_proofs,
                );
            }

            // Self-contained BFT events - direct delegation
            Event::BlockVoteReceived { vote } => {
                return self.bft.on_block_vote(vote.clone());
            }
            Event::BlockReadyToCommit { block_hash, qc } => {
                return self.bft.on_block_ready_to_commit(*block_hash, qc.clone());
            }
            Event::QuorumCertificateResult {
                block_hash,
                qc,
                verified_votes,
            } => {
                return self
                    .bft
                    .on_qc_result(*block_hash, qc.clone(), verified_votes.clone());
            }
            Event::QcSignatureVerified { block_hash, valid } => {
                return self.bft.on_qc_signature_verified(*block_hash, *valid);
            }

            // Block committed needs special handling - notify multiple subsystems
            Event::BlockCommitted {
                block_hash,
                height,
                block,
            } => {
                let mut actions = Vec::new();
                let block_height = hyperscale_types::BlockHeight(*height);

                // Register newly committed cross-shard TXs with livelock for cycle detection.
                // Must happen BEFORE livelock.on_block_committed() processes deferrals.
                for tx in block.all_transactions() {
                    if self.livelock.is_cross_shard(tx) {
                        self.livelock.on_cross_shard_committed(tx, block_height);
                    }
                }

                // Livelock: process deferrals/aborts/certs, add tombstones, cleanup tracking
                self.livelock.on_block_committed(block);

                // Cleanup execution state for deferred transactions
                // This must happen BEFORE passing new transactions to execution,
                // so that retries can be processed fresh
                for deferral in &block.deferred {
                    self.execution.cleanup_transaction(&deferral.tx_hash);
                }

                // Cleanup execution state for aborted transactions
                for abort in &block.aborted {
                    self.execution.cleanup_transaction(&abort.tx_hash);
                }

                // Remove committed certificates from execution state
                // They've been included in this block, so don't need to be proposed again
                // Also invalidate any speculative results that conflict with these writes
                for cert in &block.committed_certificates {
                    self.execution
                        .remove_finalized_certificate(&cert.transaction_hash, *height);
                    // Invalidate speculative results that read from nodes being written
                    self.execution.invalidate_speculative_on_commit(cert);
                }

                // Pass all transactions from block to execution (no need for mempool lookup)
                // NOTE: execution.on_block_committed emits CrossShardTxRegistered events, which
                // will be processed by the coordinator via EnqueueInternal actions.
                let all_txs: Vec<_> = block.all_transactions().cloned().collect();
                let exec_actions = self
                    .execution
                    .on_block_committed(*block_hash, *height, all_txs);

                // Process CrossShardTxRegistered events immediately so coordinator has
                // registrations before any subsequent provisions arrive.
                // This ensures ProvisionQuorumReached can be emitted for livelock.
                for action in &exec_actions {
                    if let Action::EnqueueInternal {
                        event:
                            Event::CrossShardTxRegistered {
                                tx_hash,
                                required_shards,
                                quorum_thresholds,
                                committed_height,
                            },
                    } = action
                    {
                        let registration = hyperscale_provisions::TxRegistration {
                            required_shards: required_shards.clone(),
                            quorum_thresholds: quorum_thresholds.clone(),
                            registered_at: *committed_height,
                            nodes_by_shard: std::collections::HashMap::new(),
                        };
                        actions.extend(self.provisions.on_tx_registered(*tx_hash, registration));
                    }
                }
                actions.extend(exec_actions);

                // Also let mempool handle it (marks transactions as committed, processes deferrals/aborts)
                actions.extend(self.mempool.on_block_committed_full(block));

                // Let provisions coordinator handle cleanup (certificates, aborts, deferrals)
                actions.extend(self.provisions.on_block_committed(block));

                return actions;
            }

            // ═══════════════════════════════════════════════════════════════════════
            // Provision Events (Byzantine-safe)
            //
            // Provisions are routed ONLY to ProvisionCoordinator, which:
            // 1. Verifies signatures
            // 2. Tracks quorum per source shard
            // 3. Emits ProvisionQuorumReached when a shard reaches quorum
            // 4. Emits ProvisioningComplete when ALL required shards reach quorum
            //
            // ExecutionState listens to ProvisioningComplete to trigger execution.
            // LivelockState listens to ProvisionQuorumReached for cycle detection.
            // ═══════════════════════════════════════════════════════════════════════
            Event::StateProvisionReceived { provision } => {
                return self.provisions.on_provision_received(provision.clone());
            }

            // ProvisionsVerifiedAndAggregated: callback from batch verification + aggregation
            Event::ProvisionsVerifiedAndAggregated {
                tx_hash,
                source_shard,
                verified_provisions,
                commitment_proof,
            } => {
                // Notify mempool to promote this transaction to priority tier.
                // This enables cross-shard transactions with verified provisions
                // to bypass the soft backpressure limit.
                self.mempool.on_provision_verified(*tx_hash);

                // Route to provision coordinator to handle verified provisions and quorum
                return self.provisions.on_provisions_verified_and_aggregated(
                    *tx_hash,
                    *source_shard,
                    verified_provisions.clone(),
                    commitment_proof.clone(),
                );
            }

            // CrossShardTxRegistered: route to coordinator for tracking
            Event::CrossShardTxRegistered {
                tx_hash,
                required_shards,
                quorum_thresholds,
                committed_height,
            } => {
                let registration = hyperscale_provisions::TxRegistration {
                    required_shards: required_shards.clone(),
                    quorum_thresholds: quorum_thresholds.clone(),
                    registered_at: *committed_height,
                    nodes_by_shard: std::collections::HashMap::new(),
                };
                return self.provisions.on_tx_registered(*tx_hash, registration);
            }

            // CrossShardTxCompleted: route to coordinator for cleanup
            Event::CrossShardTxCompleted { tx_hash } => {
                return self.provisions.on_tx_completed(tx_hash);
            }

            // CrossShardTxAborted: route to coordinator for cleanup
            Event::CrossShardTxAborted { tx_hash } => {
                return self.provisions.on_tx_aborted(tx_hash);
            }

            // ProvisionQuorumReached: Byzantine-safe cycle detection (per-shard)
            //
            // This is the ONLY entry point for livelock cycle detection.
            // Only verified provisions that have reached quorum trigger this event.
            // This prevents Byzantine validators from triggering false deferrals
            // by sending forged provisions.
            Event::ProvisionQuorumReached {
                tx_hash,
                source_shard,
                commitment_proof,
            } => {
                // Cycle detection in livelock (may queue a deferral)
                self.livelock.on_provision_quorum_reached(
                    *tx_hash,
                    *source_shard,
                    commitment_proof,
                );

                // No actions needed - execution waits for ProvisioningComplete
                return vec![];
            }

            // ProvisioningComplete: All shards have quorum, trigger execution
            Event::ProvisioningComplete {
                tx_hash,
                provisions,
            } => {
                return self
                    .execution
                    .on_provisioning_complete(*tx_hash, provisions.clone());
            }

            // Execution events - direct delegation
            Event::TransactionsExecuted { .. } | Event::CrossShardTransactionsExecuted { .. } => {
                // These are deprecated - runners now sign votes directly
                return vec![];
            }
            Event::StateVoteReceived { vote } => {
                return self.execution.on_vote(vote.clone());
            }
            Event::StateCertificateReceived { cert } => {
                return self.execution.on_certificate(cert.clone());
            }
            Event::MerkleRootComputed { .. } => {
                // Not yet implemented
                return vec![];
            }
            Event::StateVotesVerifiedAndAggregated {
                tx_hash,
                verified_votes,
            } => {
                return self
                    .execution
                    .on_state_votes_verified(*tx_hash, verified_votes.clone());
            }
            Event::StateCertificateSignatureVerified { certificate, valid } => {
                return self
                    .execution
                    .on_certificate_verified(certificate.clone(), *valid);
            }
            Event::StateCertificateAggregated {
                tx_hash,
                certificate,
            } => {
                return self
                    .execution
                    .on_state_certificate_aggregated(*tx_hash, certificate.clone());
            }
            Event::SpeculativeExecutionComplete {
                block_hash,
                tx_hashes,
            } => {
                return self
                    .execution
                    .on_speculative_execution_complete(*block_hash, tx_hashes.clone());
            }

            // SubmitTransaction: add to local mempool only.
            // Gossip is handled by the runner before this event is sent, so we only
            // need to add to the mempool here.
            Event::SubmitTransaction { tx } => {
                // Only add to our mempool if this transaction involves our shard.
                // The runner will have already gossiped to all relevant shards.
                if self.topology.involves_local_shard(tx) {
                    return self.mempool.on_submit_transaction_arc(Arc::clone(tx));
                }
                return vec![];
            }

            // TransactionExecuted is emitted by execution, handled by mempool AND BFT
            // BFT might have pending blocks waiting for this certificate
            Event::TransactionExecuted { tx_hash, accepted } => {
                // Notify mempool
                let mut actions = self.mempool.on_transaction_executed(*tx_hash, *accepted);

                // Check if any pending blocks are now complete with this certificate
                let local_certs = self.execution.finalized_certificates_by_hash();
                actions.extend(
                    self.bft
                        .check_pending_blocks_for_certificate(*tx_hash, &local_certs),
                );

                return actions;
            }

            // TransactionGossipReceived: add to mempool AND notify BFT
            // The BFT might have pending blocks waiting for this transaction
            Event::TransactionGossipReceived { tx } => {
                // Only add to our mempool if this transaction involves our shard.
                // Cross-shard transactions that don't touch our shard should be ignored.
                if !self.topology.involves_local_shard(tx) {
                    return vec![];
                }

                let tx_hash = tx.hash();
                let mut actions = self.mempool.on_transaction_gossip_arc(Arc::clone(tx));

                // Check if any pending blocks are now complete
                let mempool_map = self.mempool.as_hash_map();
                actions.extend(
                    self.bft
                        .check_pending_blocks_for_transaction(tx_hash, &mempool_map),
                );

                return actions;
            }

            // Storage callback events - route to appropriate handler
            Event::StateEntriesFetched { tx_hash, entries } => {
                return self
                    .execution
                    .on_state_entries_fetched(*tx_hash, entries.clone());
            }

            Event::BlockFetched { .. } => {
                // This is for local storage fetch, not sync
                // For now, this is a no-op
            }

            // Sync protocol events - routed to BFT
            // Note: SyncNeeded is now Action::StartSync (emitted by BFT, handled by runner).
            // SyncBlockReceived is handled by the runner's SyncManager.
            // The runner sends SyncBlockReadyToApply and SyncComplete to the state machine.
            Event::SyncBlockReceived { .. } => {
                // Runner handles this - should not reach state machine
                tracing::warn!("SyncBlockReceived event reached NodeStateMachine - should be handled by runner");
            }

            Event::SyncBlockReadyToApply { block, qc } => {
                return self
                    .bft
                    .on_sync_block_ready_to_apply(block.clone(), qc.clone());
            }
            Event::SyncComplete { .. } => {
                let mut actions = self.bft.on_sync_complete();
                // Reschedule the cleanup timer. During sync, the cleanup timer
                // fires StartSync actions which don't reschedule the timer.
                // Now that sync is complete, we need to restart the cleanup timer
                // to resume periodic fetch checks and sync health monitoring.
                actions.push(Action::SetTimer {
                    id: TimerId::Cleanup,
                    duration: self.bft.config().cleanup_interval,
                });
                return actions;
            }
            Event::ChainMetadataFetched { height, hash, qc } => {
                return self
                    .bft
                    .on_chain_metadata_fetched(*height, *hash, qc.clone());
            }

            // Transaction status changes from execution state machine
            Event::TransactionStatusChanged { tx_hash, status } => {
                return self.mempool.update_status(tx_hash, status.clone());
            }

            // ═══════════════════════════════════════════════════════════════════════
            // Global Consensus / Epoch Events
            // TODO: Route to GlobalConsensusState when implemented
            // ═══════════════════════════════════════════════════════════════════════
            Event::GlobalConsensusTimer => {
                // Will be handled by GlobalConsensusState
                tracing::trace!("GlobalConsensusTimer - not yet implemented");
            }

            Event::GlobalBlockReceived { epoch, height, .. } => {
                tracing::debug!(?epoch, ?height, "GlobalBlockReceived - not yet implemented");
            }

            Event::GlobalBlockVoteReceived {
                block_hash, shard, ..
            } => {
                tracing::debug!(
                    ?block_hash,
                    ?shard,
                    "GlobalBlockVoteReceived - not yet implemented"
                );
            }

            Event::GlobalQcFormed { block_hash, epoch } => {
                tracing::info!(?block_hash, ?epoch, "GlobalQcFormed - not yet implemented");
            }

            Event::EpochEndApproaching {
                current_epoch,
                end_height,
            } => {
                tracing::info!(
                    ?current_epoch,
                    ?end_height,
                    "EpochEndApproaching - not yet implemented"
                );
                // TODO: Stop accepting new transactions, drain in-flight
            }

            Event::EpochTransitionReady {
                from_epoch,
                to_epoch,
                ..
            } => {
                tracing::info!(
                    ?from_epoch,
                    ?to_epoch,
                    "EpochTransitionReady - not yet implemented"
                );
                // TODO: Update DynamicTopology, notify subsystems
            }

            Event::EpochTransitionComplete {
                new_epoch,
                new_shard,
                is_waiting,
            } => {
                tracing::info!(
                    ?new_epoch,
                    ?new_shard,
                    is_waiting,
                    "EpochTransitionComplete - not yet implemented"
                );
            }

            Event::ValidatorSyncComplete { epoch, shard } => {
                tracing::info!(
                    ?epoch,
                    ?shard,
                    "ValidatorSyncComplete - not yet implemented"
                );
                // TODO: Transition from Waiting to Active state
            }

            Event::ShardSplitInitiated {
                source_shard,
                new_shard,
                split_point,
            } => {
                tracing::info!(
                    ?source_shard,
                    ?new_shard,
                    split_point,
                    "ShardSplitInitiated - not yet implemented"
                );
                // TODO: Mark shard as splitting in topology
            }

            Event::ShardSplitComplete {
                source_shard,
                new_shard,
            } => {
                tracing::info!(
                    ?source_shard,
                    ?new_shard,
                    "ShardSplitComplete - not yet implemented"
                );
            }

            Event::ShardMergeInitiated {
                shard_a,
                shard_b,
                merged_shard,
            } => {
                tracing::info!(
                    ?shard_a,
                    ?shard_b,
                    ?merged_shard,
                    "ShardMergeInitiated - not yet implemented"
                );
            }

            Event::ShardMergeComplete { merged_shard } => {
                tracing::info!(?merged_shard, "ShardMergeComplete - not yet implemented");
            }

            // ═══════════════════════════════════════════════════════════════════════
            // Transaction Fetch Protocol
            // BFT emits Action::FetchTransactions; runner handles retries and delivers results.
            // ═══════════════════════════════════════════════════════════════════════
            Event::TransactionReceived {
                block_hash,
                transactions,
            } => {
                return self
                    .bft
                    .on_transaction_fetch_received(*block_hash, transactions.clone());
            }

            // ═══════════════════════════════════════════════════════════════════════
            // Certificate Fetch Protocol
            // BFT emits Action::FetchCertificates; runner handles retries and delivers results.
            // ═══════════════════════════════════════════════════════════════════════
            Event::CertificateReceived {
                block_hash,
                certificates,
            } => {
                // Verify each fetched certificate's embedded StateCertificates against
                // our current topology. This ensures we don't accept forged certificates
                // from Byzantine peers.
                let mut actions = Vec::new();
                for cert in certificates {
                    actions.extend(
                        self.execution
                            .verify_fetched_certificate(*block_hash, cert.clone()),
                    );
                }
                return actions;
            }

            Event::FetchedCertificateVerified {
                block_hash,
                certificate,
            } => {
                // Cancel local certificate building - we're using the fetched one
                self.execution
                    .cancel_certificate_building(&certificate.transaction_hash);

                // Certificate has been verified - add to pending block
                return self.bft.on_certificate_fetch_received(
                    *block_hash,
                    vec![std::sync::Arc::new(certificate.clone())],
                );
            }

            // TransactionCertificateReceived is handled directly by the production runner
            // (verified and persisted to storage without going through the state machine).
            // In simulation, we handle it in the simulator's runner, not here.
            Event::TransactionCertificateReceived { .. } => {
                // No action needed - runner handles verification and persistence
                return vec![];
            }

            // GossipedCertificateVerified - a gossiped certificate has been verified and persisted.
            // Cancel local certificate building and add to finalized certificates.
            Event::GossipedCertificateVerified { certificate } => {
                let tx_hash = certificate.transaction_hash;

                // Cancel any ongoing local certificate building
                self.execution.cancel_certificate_building(&tx_hash);

                // Add to finalized certificates if not already present
                self.execution.add_verified_certificate(certificate.clone());

                // Notify mempool that transaction is finalized
                return vec![Action::EnqueueInternal {
                    event: Event::TransactionExecuted {
                        tx_hash,
                        accepted: certificate.is_accepted(),
                    },
                }];
            }

            // GossipedCertificateSignatureVerified is handled by the runner, not here
            Event::GossipedCertificateSignatureVerified { .. } => {
                return vec![];
            }
        }

        // Event not handled by any sub-machine
        tracing::warn!(?event, "Unhandled event");
        vec![]
    }

    fn set_time(&mut self, now: Duration) {
        self.now = now;
        self.bft.set_time(now);
        self.execution.set_time(now);
        self.mempool.set_time(now);
        self.provisions.set_time(now);
        self.livelock.set_time(now);
    }

    fn now(&self) -> Duration {
        self.now
    }
}
