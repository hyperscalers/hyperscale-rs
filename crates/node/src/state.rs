//! Node state machine.

use hyperscale_bft::{BftConfig, BftState, RecoveredState};
use hyperscale_core::{Action, ProtocolEvent, StateMachine, TimerId};
use hyperscale_execution::ExecutionState;
use hyperscale_livelock::LivelockState;
use hyperscale_mempool::{MempoolConfig, MempoolState};
use hyperscale_provisions::ProvisionCoordinator;
use hyperscale_remote_headers::RemoteHeaderCoordinator;
use hyperscale_topology::TopologyState;
use hyperscale_types::{
    AbortIntent, Block, BlockHeader, BlockHeight, BlockManifest, Bls12381G1PrivateKey, Hash,
    QuorumCertificate, ReadyTransactions, RoutableTransaction, ShardGroupId, TopologySnapshot,
    TransactionCertificate,
};
use std::sync::Arc;
use std::time::Duration;
use tracing::instrument;

/// Index type for simulation-only node routing.
/// Production uses ValidatorId (from message signatures) and PeerId (libp2p).
pub type NodeIndex = u32;

// ─── Constants ──────────────────────────────────────────────────────────

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

    /// Network topology — passed by reference to subsystem methods.
    topology: TopologyState,

    /// BFT consensus state (includes implicit round advancement).
    bft: BftState,

    /// Execution state.
    execution: ExecutionState,

    /// Mempool state.
    mempool: MempoolState,

    /// Provision coordination for cross-shard transactions.
    provisions: ProvisionCoordinator,

    /// Remote block header coordination (single source of truth).
    remote_headers: RemoteHeaderCoordinator,

    /// Livelock prevention state (cycle detection for cross-shard TXs).
    livelock: LivelockState,

    /// Current time.
    now: Duration,
}

impl std::fmt::Debug for NodeStateMachine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeStateMachine")
            .field("node_index", &self.node_index)
            .field("shard", &self.topology.snapshot().local_shard())
            .field("bft", &self.bft)
            .field("now", &self.now)
            .finish()
    }
}

/// Inputs gathered for building a block proposal.
///
/// Used by both `ProposalTimer` and `QuorumCertificateFormed` handlers
/// to avoid duplicating the ready-transaction gathering logic.
struct ProposalInputs {
    ready_txs: ReadyTransactions,
    abort_intents: Vec<AbortIntent>,
    certificates: Vec<Arc<TransactionCertificate>>,
    /// Pre-computed per-certificate database updates for proposal building.
    /// Keyed by transaction hash; excludes aborted certificates (no state changes).
    cert_updates: std::collections::HashMap<Hash, Arc<hyperscale_types::DatabaseUpdates>>,
}

impl NodeStateMachine {
    /// Create a new node state machine with default speculative execution settings.
    ///
    /// # Arguments
    ///
    /// * `node_index` - Deterministic node index for ordering
    /// * `topology` - Network topology
    /// * `signing_key` - Key for signing votes and proposals
    /// * `bft_config` - BFT configuration
    /// * `recovered` - State recovered from storage. Use `RecoveredState::default()` for fresh start.
    pub fn new(
        node_index: NodeIndex,
        topology: TopologyState,
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
        topology: TopologyState,
        signing_key: Bls12381G1PrivateKey,
        bft_config: BftConfig,
        recovered: RecoveredState,
        speculative_max_txs: usize,
        view_change_cooldown_rounds: u64,
        mempool_config: MempoolConfig,
    ) -> Self {
        // Clone key bytes to create a new keypair since Bls12381G1PrivateKey doesn't impl Clone
        let key_bytes = signing_key.to_bytes();
        let bft_signing_key =
            Bls12381G1PrivateKey::from_bytes(&key_bytes).expect("valid key bytes");

        Self {
            node_index,
            bft: BftState::new(
                node_index,
                bft_signing_key,
                topology.snapshot(),
                bft_config.clone(),
                recovered,
            ),
            execution: ExecutionState::with_speculative_config(
                speculative_max_txs,
                view_change_cooldown_rounds,
            ),
            mempool: MempoolState::with_config(mempool_config),
            provisions: ProvisionCoordinator::new(),
            remote_headers: RemoteHeaderCoordinator::new(),
            livelock: LivelockState::new(),
            topology,
            now: Duration::ZERO,
        }
    }

    // ─── Accessors ──────────────────────────────────────────────────────

    /// Get this node's index.
    pub fn node_index(&self) -> NodeIndex {
        self.node_index
    }

    /// Get this node's shard.
    pub fn shard(&self) -> ShardGroupId {
        self.topology.snapshot().local_shard()
    }

    /// Get the current topology snapshot.
    pub fn topology(&self) -> &TopologySnapshot {
        self.topology.snapshot()
    }

    /// Get a reference to the mempool state.
    pub fn mempool(&self) -> &MempoolState {
        &self.mempool
    }

    /// Get a reference to the BFT state.
    pub fn bft(&self) -> &BftState {
        &self.bft
    }

    /// Get a reference to the execution state.
    pub fn execution(&self) -> &ExecutionState {
        &self.execution
    }

    /// Get a mutable reference to the execution state.
    pub(crate) fn execution_mut(&mut self) -> &mut ExecutionState {
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

    /// Get a reference to the remote header coordinator.
    pub fn remote_headers(&self) -> &RemoteHeaderCoordinator {
        &self.remote_headers
    }

    /// Get the last committed JVT root hash (delegated to BFT's verification pipeline).
    pub fn last_committed_jvt_root(&self) -> Hash {
        self.bft.jvt_root()
    }

    /// Initialize the node with a genesis block.
    ///
    /// Returns actions to be processed (e.g., initial timers).
    pub fn initialize_genesis(&mut self, genesis: Block) -> Vec<Action> {
        self.bft
            .initialize_genesis(self.topology.snapshot(), genesis)
        // Note: No separate view change timer - round advancement is handled
        // implicitly via the proposal timer (HotStuff-2 style)
    }

    // ─── Shared Helpers ─────────────────────────────────────────────────

    /// Gather all inputs needed for a block proposal.
    ///
    /// Used by both `on_proposal_timer` and `on_qc_formed` to avoid duplicating
    /// the ready-transaction + abort intents + certificates gathering logic.
    fn gather_proposal_inputs(
        &mut self,
        pending_txs: usize,
        pending_certs: usize,
    ) -> ProposalInputs {
        // Request extra transactions from the mempool to compensate for QC-chain
        // duplicates that will be filtered by BFT during proposal building.
        let max_txs = self.bft.config().max_transactions_per_block + self.bft.dedup_overhead();
        let ready_txs = self
            .mempool
            .ready_transactions(max_txs, pending_txs, pending_certs);
        let current_height = BlockHeight(self.bft.committed_height() + 1);
        // Livelock cycle abort intents (from cycle detection).
        let livelock_intents = self.livelock.get_pending_abort_intents().to_vec();
        // Timed-out transactions from the mempool.
        // The mempool tracks ALL committed transactions including those received
        // via block sync (added by on_block_committed_full), so this covers
        // cross-shard txs that weren't in the local mempool originally.
        let timed_out = self
            .mempool
            .get_default_timed_out_transactions(current_height);
        // Combine both sources into a single abort_intents list.
        // Timeouts first: they are cheaper to verify (no inclusion proof) and BFT
        // dedup keeps the first intent per tx_hash, so timeouts take priority.
        let abort_intents: Vec<AbortIntent> =
            timed_out.into_iter().chain(livelock_intents).collect();
        let certificates = self.execution.get_finalized_certificates();

        let cert_updates = self.execution.proposal_cert_updates(&certificates);

        ProposalInputs {
            ready_txs,
            abort_intents,
            certificates,
            cert_updates,
        }
    }

    // ─── Event Handlers ─────────────────────────────────────────────────

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
        actions.extend(
            self.bft
                .check_pending_block_fetches(self.topology.snapshot()),
        );

        // Check if we're behind and need to catch up via sync.
        // This handles the case where we have a higher latest_qc than committed_height,
        // meaning the network has progressed but we're stuck.
        actions.extend(self.bft.check_sync_health(self.topology.snapshot()));

        // Clean up old tombstones in mempool to prevent unbounded memory growth.
        let current_height = BlockHeight(self.bft.committed_height());
        self.mempool.cleanup_default_tombstones(current_height);

        // Clean up stale speculative execution results
        self.execution.cleanup_stale_speculative();

        actions
    }

    /// Handle proposal timer — propose a block or advance the round on timeout.
    fn on_proposal_timer(&mut self) -> Vec<Action> {
        // Check if we should advance the round due to timeout.
        // Delegated to BftState which owns timeout tracking.
        if let Some(actions) = self.bft.check_round_timeout(self.topology.snapshot()) {
            let current_height = BlockHeight(self.bft.committed_height() + 1);

            // Notify execution of view change to pause speculation temporarily
            self.execution.on_view_change(current_height.0);

            return actions;
        }

        // Normal proposal timer - try to propose if we're the proposer
        //
        // Account for pipelining: multiple blocks can be proposed before any commit.
        // We must count txs/certs in ALL pending blocks to avoid exceeding in-flight limits.
        let (pending_txs, pending_certs) = self.bft.pending_block_tx_cert_counts();

        let inputs = self.gather_proposal_inputs(pending_txs, pending_certs);

        let finalized = self.execution.finalized_tx_hashes();
        self.bft.on_proposal_timer(
            self.topology.snapshot(),
            &inputs.ready_txs,
            inputs.abort_intents,
            inputs.certificates,
            &inputs.cert_updates,
            &finalized,
        )
    }

    /// Handle a received block header — validate in-flight limits and trigger speculative execution.
    fn on_block_header_received(
        &mut self,
        header: BlockHeader,
        manifest: BlockManifest,
    ) -> Vec<Action> {
        // Total transaction count across all sections
        let total_tx_count = manifest.transaction_count();

        // Validate in-flight limits only for the next block after committed height.
        // For blocks further ahead, skip validation - validators at different heights
        // have different in_flight() counts, causing split votes and view changes.
        let committed_height = self.bft.committed_height();
        let is_next_block = header.height.0 == committed_height + 1;

        if is_next_block
            && self
                .mempool
                .would_exceed_in_flight(total_tx_count, manifest.cert_hashes.len())
        {
            tracing::warn!(
                block_hash = ?header.hash(),
                height = header.height.0,
                "Rejecting block that would exceed in-flight limit"
            );
            return vec![];
        }

        // Trigger speculative execution for single-shard transactions
        // This hides execution latency behind consensus latency
        let block_hash = header.hash();
        let height = header.height.0;
        let transactions: Vec<_> = manifest
            .tx_hashes
            .iter()
            .filter_map(|h| self.mempool.get_transaction(h))
            .collect();
        let spec_actions = self.execution.trigger_speculative_execution(
            self.topology.snapshot(),
            block_hash,
            height,
            transactions,
        );

        let mut actions = self.bft.on_block_header(
            self.topology.snapshot(),
            header,
            manifest,
            |h| self.mempool.get_transaction(h),
            |h| self.execution.get_finalized_certificate(h),
            |h| self.execution.has_cached_updates(h),
        );
        actions.extend(spec_actions);
        actions
    }

    /// Handle QC formed — may trigger immediate next proposal.
    fn on_qc_formed(&mut self, block_hash: Hash, qc: QuorumCertificate) -> Vec<Action> {
        // Count transactions and certificates in the block that will be committed.
        // This is critical for respecting in-flight limits: the BlockCommitted
        // event won't be processed until after we select transactions, so we
        // need to preemptively account for:
        // - Transactions that will INCREASE in-flight (new commits)
        // - Certificates that will DECREASE in-flight (completed transactions)
        let (pending_tx_count, pending_cert_count) = self.bft.pending_commit_counts(&qc);

        let inputs = self.gather_proposal_inputs(pending_tx_count, pending_cert_count);

        let finalized = self.execution.finalized_tx_hashes();
        self.bft.on_qc_formed(
            self.topology.snapshot(),
            block_hash,
            qc,
            &inputs.ready_txs,
            inputs.abort_intents,
            inputs.certificates,
            &inputs.cert_updates,
            &finalized,
        )
    }

    /// Handle JVT state commit completion — forward to BFT.
    ///
    /// BFT's verification pipeline tracks the committed JVT root internally.
    /// Unblocked state root verifications are pushed to the ready queue
    /// and drained by handle() via drain_ready_state_root_verifications().
    fn on_state_commit_complete(&mut self, height: u64, state_root: Hash) -> Vec<Action> {
        self.bft
            .on_state_commit_complete(self.topology.snapshot(), height, state_root);
        vec![]
    }

    /// Handle block committed — notify all subsystems in the correct order.
    ///
    /// Order invariants:
    /// 1. Register cross-shard TXs with livelock BEFORE processing abort intents
    /// 2. Process abort intents BEFORE passing new TXs to execution
    /// 3. Process CrossShardTxRegistered continuations BEFORE other exec actions
    fn on_block_committed(&mut self, block_hash: Hash, height: u64, block: Block) -> Vec<Action> {
        let mut actions = Vec::new();
        let block_height = BlockHeight(height);

        // Livelock: register cross-shard TXs for cycle detection, then process
        // abort intents/certs, add tombstones, cleanup tracking.
        self.livelock
            .on_block_committed(self.topology.snapshot(), &block);

        // Register committed tx hashes with BFT for timeout abort validation.
        let tx_hashes: Vec<Hash> = block.transactions.iter().map(|tx| tx.hash()).collect();
        self.bft
            .register_committed_transactions(&tx_hashes, block_height);

        // Abort intents feed the execution accumulator with override semantics.
        // Votes are NOT emitted here — the wave scan at the end of block commit
        // will detect complete waves and emit votes deterministically.
        self.execution.record_abort_intents(&block.abort_intents);

        // Remove committed certificates from execution state.
        // They've been included in this block, so don't need to be proposed again.
        // Also invalidate any speculative results that conflict with these writes.
        self.execution
            .on_certificates_committed(&block.certificates);
        for cert in &block.certificates {
            self.bft
                .remove_committed_transaction(&cert.transaction_hash);
        }

        // Pass all transactions from block to execution (no need for mempool lookup).
        let all_txs = block.transactions.clone();
        let exec_output = self.execution.on_block_committed(
            self.topology.snapshot(),
            block_hash,
            height,
            block.header.timestamp,
            block.header.proposer,
            all_txs,
        );

        // Register cross-shard transactions with provisions BEFORE extending
        // actions, so coordinator has registrations before provisions arrive.
        for reg in exec_output.cross_shard_registrations {
            let registration = hyperscale_provisions::TxRegistration {
                required_shards: reg.required_shards,
                registered_at: reg.committed_height,
            };
            actions.extend(self.provisions.on_tx_registered(reg.tx_hash, registration));
        }
        actions.extend(exec_output.actions);

        // Also let mempool handle it (marks transactions as committed, processes deferrals/aborts)
        actions.extend(
            self.mempool
                .on_block_committed_full(self.topology.snapshot(), &block),
        );

        // Remote header coordinator: update liveness and check for timeouts.
        actions.extend(
            self.remote_headers
                .on_block_committed(self.topology.snapshot()),
        );

        // Let provisions coordinator handle cleanup (certificates, aborts, deferrals).
        actions.extend(
            self.provisions
                .on_block_committed(self.topology.snapshot(), &block),
        );

        // Round voting: scan all incomplete waves and emit votes for complete ones.
        // This is the SINGLE path to execution voting. Abort intents have already
        // been processed above (with override semantics), so the accumulator state
        // is deterministic at this height. All validators at this height produce
        // the same votes.
        actions.extend(
            self.execution
                .emit_vote_actions(self.topology.snapshot(), height),
        );

        actions
    }

    /// Handle an inclusion proof received from a source shard (livelock deferral).
    ///
    /// Called by the I/O loop when a `GetTxInclusionProofResponse` is received.
    /// Forwards to the livelock state machine to finalize the deferral.
    pub(crate) fn on_inclusion_proof_received(
        &mut self,
        winner_tx_hash: Hash,
        loser_tx_hash: Hash,
        source_shard: ShardGroupId,
        source_block_height: BlockHeight,
        proof: hyperscale_types::TransactionInclusionProof,
    ) -> Vec<Action> {
        self.livelock.on_inclusion_proof_received(
            winner_tx_hash,
            loser_tx_hash,
            proof,
            source_shard,
            source_block_height,
        );
        vec![]
    }

    /// Handle transaction executed — notify mempool and check pending blocks.
    fn on_transaction_executed(&mut self, tx_hash: Hash, accepted: bool) -> Vec<Action> {
        // Notify mempool
        let mut actions =
            self.mempool
                .on_transaction_executed(self.topology.snapshot(), tx_hash, accepted);

        // Check if any pending blocks are now complete with this certificate
        if let Some(cert) = self.execution.get_finalized_certificate(&tx_hash) {
            actions.extend(self.bft.check_pending_blocks_for_certificate(
                self.topology.snapshot(),
                tx_hash,
                &cert,
            ));
        }

        actions
    }

    /// Handle transaction gossip received — add to mempool and check pending blocks.
    fn on_transaction_gossip_received(
        &mut self,
        tx: Arc<RoutableTransaction>,
        submitted_locally: bool,
    ) -> Vec<Action> {
        // Only add to our mempool if this transaction involves our shard.
        // Cross-shard transactions that don't touch our shard should be ignored.
        if !self.topology.snapshot().involves_local_shard(&tx) {
            return vec![];
        }

        let tx_hash = tx.hash();
        let tx_for_pending = Arc::clone(&tx);
        let mut actions =
            self.mempool
                .on_transaction_gossip(self.topology.snapshot(), tx, submitted_locally);

        // Check if any pending blocks are now complete
        actions.extend(self.bft.check_pending_blocks_for_transaction(
            self.topology.snapshot(),
            tx_hash,
            &tx_for_pending,
        ));

        actions
    }

    /// Handle sync complete — resume cleanup timer.
    fn on_sync_complete(&mut self) -> Vec<Action> {
        let mut actions = self.bft.on_sync_complete(self.topology.snapshot());
        // Reschedule the cleanup timer. During sync, the cleanup timer
        // fires StartSync actions which don't reschedule the timer.
        // Now that sync is complete, we need to restart the cleanup timer
        // to resume periodic fetch checks and sync health monitoring.
        actions.push(Action::SetTimer {
            id: TimerId::Cleanup,
            duration: self.bft.config().cleanup_interval,
        });
        actions
    }
}

impl StateMachine for NodeStateMachine {
    #[instrument(skip(self), fields(
        node = self.node_index,
        shard = self.topology.snapshot().local_shard().0,
        event = %event.type_name(),
        height = self.bft.committed_height(),
    ))]
    fn handle(&mut self, event: ProtocolEvent) -> Vec<Action> {
        let mut actions = match event {
            // ── Timers ───────────────────────────────────────────────────
            ProtocolEvent::CleanupTimer => self.on_cleanup_timer(),
            ProtocolEvent::ProposalTimer => self.on_proposal_timer(),

            // ── BFT Consensus ────────────────────────────────────────────
            ProtocolEvent::BlockHeaderReceived { header, manifest } => {
                self.on_block_header_received(header, manifest)
            }
            ProtocolEvent::QuorumCertificateFormed { block_hash, qc } => {
                self.on_qc_formed(block_hash, qc)
            }
            ProtocolEvent::RemoteBlockCommitted {
                committed_header,
                sender,
            } => {
                // Route through the centralized remote header coordinator.
                // It performs structural pre-checks and dispatches QC verification.
                // Downstream consumers receive headers via RemoteHeaderVerified.
                let header = Arc::new(committed_header);
                let topology = self.topology.snapshot();
                self.remote_headers
                    .on_remote_block_committed(topology, header, sender)
            }
            ProtocolEvent::BlockVoteReceived { vote } => {
                self.bft.on_block_vote(self.topology.snapshot(), vote)
            }
            ProtocolEvent::BlockReadyToCommit { block_hash, qc } => self
                .bft
                .on_block_ready_to_commit(self.topology.snapshot(), block_hash, qc),
            ProtocolEvent::QuorumCertificateResult {
                block_hash,
                qc,
                verified_votes,
            } => self
                .bft
                .on_qc_result(self.topology.snapshot(), block_hash, qc, verified_votes),
            ProtocolEvent::QcSignatureVerified { block_hash, valid } => self
                .bft
                .on_qc_signature_verified(self.topology.snapshot(), block_hash, valid),
            ProtocolEvent::RemoteHeaderQcVerified {
                shard,
                height,
                header,
                valid,
            } => {
                // Store valid headers into BFT immediately so they're available
                // for deferral merkle proof validation without a 1-step delay.
                // Must capture returned actions — unblocked abort intent
                // verifications are emitted here.
                let mut actions = if valid {
                    self.bft.on_verified_remote_header(Arc::clone(&header))
                } else {
                    vec![]
                };
                actions.extend(self.remote_headers.on_remote_header_qc_verified(
                    self.topology.snapshot(),
                    shard,
                    height,
                    header,
                    valid,
                ));
                actions
            }
            ProtocolEvent::RemoteHeaderVerified { committed_header } => {
                // Fan out verified header to downstream consumers.
                // BFT already received the header in RemoteHeaderQcVerified
                // (early insertion for deferral proof validation).
                let topology = self.topology.snapshot();
                let shard = committed_header.shard_group_id();

                // Execution: register expected execution certs from waves.
                self.execution.on_verified_remote_header(
                    topology,
                    shard,
                    committed_header.header.height.0,
                    &committed_header.header.waves,
                );

                // Provisions: register expected provisions and join with buffered batches.
                self.provisions
                    .on_verified_remote_header(topology, committed_header)
            }
            ProtocolEvent::StateRootVerified { block_hash, valid } => self
                .bft
                .on_state_root_verified(self.topology.snapshot(), block_hash, valid),
            ProtocolEvent::TransactionRootVerified { block_hash, valid } => self
                .bft
                .on_transaction_root_verified(self.topology.snapshot(), block_hash, valid),
            ProtocolEvent::ReceiptRootVerified { block_hash, valid } => self
                .bft
                .on_receipt_root_verified(self.topology.snapshot(), block_hash, valid),
            ProtocolEvent::AbortIntentProofsVerified { block_hash, valid } => self
                .bft
                .on_abort_intents_verified(self.topology.snapshot(), block_hash, valid),
            ProtocolEvent::ProposalBuilt {
                height,
                round,
                block,
                block_hash,
                merged_updates,
            } => {
                let mut actions = self.bft.on_proposal_built(
                    self.topology.snapshot(),
                    height,
                    round,
                    block.clone(),
                    block_hash,
                );
                // Trigger speculative execution for single-shard transactions.
                // The proposer knows the block contents at build time — start
                // execution now so results are cached by the time the block commits.
                actions.extend(self.execution.trigger_speculative_execution(
                    self.topology.snapshot(),
                    block_hash,
                    height.0,
                    block.transactions.clone(),
                ));
                // Trigger speculative provision prep if we have certificate writes
                if let Some(updates) = merged_updates {
                    actions.extend(self.execution.trigger_speculative_provisions(
                        self.topology.snapshot(),
                        block_hash,
                        height.0,
                        block.header.timestamp,
                        &block.transactions,
                        updates,
                    ));
                }
                actions
            }

            // ── State Commit ─────────────────────────────────────────────
            ProtocolEvent::StateCommitComplete { height, state_root } => {
                self.on_state_commit_complete(height, state_root)
            }

            // ── Block Committed ──────────────────────────────────────────
            ProtocolEvent::BlockCommitted {
                block_hash,
                height,
                block,
            } => self.on_block_committed(block_hash, height, block),

            // ── Provisions ───────────────────────────────────────────────
            ProtocolEvent::SpeculativeProvisionsComplete {
                block_hash,
                batches,
                block_timestamp,
            } => self.execution.on_speculative_provisions_complete(
                block_hash,
                batches,
                block_timestamp,
            ),
            ProtocolEvent::StateProvisionsReceived { batch } => self
                .provisions
                .on_state_provisions_received(self.topology.snapshot(), batch),
            ProtocolEvent::StateProvisionsVerified {
                batch,
                committed_header,
                valid,
            } => self.provisions.on_state_provisions_verified(
                self.topology.snapshot(),
                batch,
                committed_header,
                valid,
            ),
            ProtocolEvent::ProvisionsAccepted { batch } => self
                .livelock
                .on_provisions_accepted_actions(&batch, self.topology.snapshot()),
            ProtocolEvent::ProvisioningComplete { transactions } => self
                .execution
                .on_batch_provisioning_complete(self.topology.snapshot(), transactions),

            // ── Execution ────────────────────────────────────────────────
            ProtocolEvent::ExecutionBatchCompleted {
                results,
                tx_outcomes,
                speculative,
            } => {
                // Extract tx_hashes before results are consumed — these receipts
                // are now available in the execution cache for state root verification.
                let receipt_tx_hashes: Vec<hyperscale_types::Hash> =
                    results.iter().map(|r| r.tx_hash).collect();

                let mut actions = self.execution.on_execution_batch_completed(
                    results,
                    tx_outcomes,
                    speculative,
                    self.bft.committed_height(),
                );

                // Feed receipt availability to BFT pending blocks. A pending block
                // that was waiting for these receipts may now be complete and ready
                // for voting. This prevents voting on blocks where state_root
                // cannot be verified due to missing execution results.
                if !receipt_tx_hashes.is_empty() {
                    actions.extend(
                        self.bft
                            .on_receipts_available(self.topology.snapshot(), &receipt_tx_hashes),
                    );
                }

                actions
            }
            ProtocolEvent::SpeculativeExecutionComplete {
                block_hash,
                tx_hashes,
            } => self
                .execution
                .on_speculative_execution_complete(block_hash, tx_hashes),

            // ── Wave Execution (wave-based voting) ────────────────────────
            ProtocolEvent::ExecutionVoteReceived { vote } => self
                .execution
                .on_execution_vote(self.topology.snapshot(), vote),
            ProtocolEvent::ExecutionVotesVerifiedAndAggregated {
                wave_id,
                block_hash,
                verified_votes,
            } => self.execution.on_votes_verified(
                self.topology.snapshot(),
                wave_id,
                block_hash,
                verified_votes,
            ),
            ProtocolEvent::ExecutionCertificateAggregated {
                wave_id,
                certificate,
            } => self.execution.on_certificate_aggregated(
                self.topology.snapshot(),
                wave_id,
                certificate,
            ),
            ProtocolEvent::ExecutionCertificateReceived { cert } => self
                .execution
                .on_wave_certificate(self.topology.snapshot(), cert),
            ProtocolEvent::ExecutionCertificateSignatureVerified { certificate, valid } => self
                .execution
                .on_certificate_verified(self.topology.snapshot(), certificate, valid),

            // ── Transactions ─────────────────────────────────────────────
            ProtocolEvent::TransactionExecuted { tx_hash, accepted } => {
                self.on_transaction_executed(tx_hash, accepted)
            }
            ProtocolEvent::TransactionGossipReceived {
                tx,
                submitted_locally,
            } => self.on_transaction_gossip_received(tx, submitted_locally),
            // ── Fetch Protocol ───────────────────────────────────────────
            ProtocolEvent::TransactionFetchDelivered {
                block_hash,
                transactions,
            } => self.bft.on_transaction_fetch_received(
                self.topology.snapshot(),
                block_hash,
                transactions,
            ),
            ProtocolEvent::CertificateFetchDelivered {
                block_hash,
                certificates,
            } => self.bft.on_certificate_fetch_received(
                self.topology.snapshot(),
                block_hash,
                certificates,
            ),
            // ── Storage / Sync ───────────────────────────────────────────
            ProtocolEvent::BlockFetched { .. } => vec![],
            ProtocolEvent::SyncBlockReadyToApply { block, qc } => self
                .bft
                .on_sync_block_ready_to_apply(self.topology.snapshot(), block, qc),
            // Handled by IoLoop directly (sync verification pipeline).
            ProtocolEvent::SyncEcVerificationComplete { .. } => vec![],
            ProtocolEvent::SyncComplete { .. } => self.on_sync_complete(),
            ProtocolEvent::ChainMetadataFetched { height, hash, qc } => self
                .bft
                .on_chain_metadata_fetched(self.topology.snapshot(), height, hash, qc),

            // ── Global Consensus / Epoch (not yet implemented) ───────────
            // When implemented, route to GlobalConsensusState.
            // The #[instrument] span already logs the specific event name.
            //
            // TODO(epoch): After transition_to_next_epoch() / mark_shard_splitting() /
            // clear_shard_splitting() mutates self.topology, emit
            // Action::TopologyChanged { topology: Arc::clone(self.topology.snapshot()) }
            // so the io_loop updates its shared topology snapshot.
            ProtocolEvent::GlobalConsensusTimer
            | ProtocolEvent::GlobalBlockReceived { .. }
            | ProtocolEvent::GlobalBlockVoteReceived { .. }
            | ProtocolEvent::GlobalQcFormed { .. }
            | ProtocolEvent::EpochEndApproaching { .. }
            | ProtocolEvent::EpochTransitionReady { .. }
            | ProtocolEvent::EpochTransitionComplete { .. }
            | ProtocolEvent::ValidatorSyncComplete { .. }
            | ProtocolEvent::ShardSplitInitiated { .. }
            | ProtocolEvent::ShardSplitComplete { .. }
            | ProtocolEvent::ShardMergeInitiated { .. }
            | ProtocolEvent::ShardMergeComplete { .. } => vec![],
        };

        // Drain any state root verifications that became ready during this event.
        // The BFT verification pipeline queues these; we compute merged_updates
        // from the execution cache and emit VerifyStateRoot actions.
        for ready in self.bft.drain_ready_state_root_verifications() {
            let per_cert_updates = self.execution.updates_for_tx_hashes(&ready.cert_tx_hashes);
            actions.push(Action::VerifyStateRoot {
                block_hash: ready.block_hash,
                parent_state_root: ready.parent_state_root,
                expected_root: ready.expected_root,
                per_cert_updates,
                block_height: ready.block_height,
            });
        }

        actions
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
