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
    AbortIntent, Block, BlockHeader, BlockHeight, BlockManifest, Bls12381G1PrivateKey,
    CommittedBlockHeader, Hash, ProvisionBatch, QuorumCertificate, ReadyTransactions,
    ReceiptBundle, RoutableTransaction, ShardGroupId, TopologySnapshot, TransactionCertificate,
};
use std::sync::Arc;
use std::time::Duration;
use tracing::instrument;

/// Index type for simulation-only node routing.
/// Production uses ValidatorId (from message signatures) and PeerId (libp2p).
pub type NodeIndex = u32;

// ─── Constants ──────────────────────────────────────────────────────────

/// How many blocks a cross-shard transaction can wait before being aborted.
/// Must be comfortably longer than the exec cert fallback fetch timeout (10 blocks)
/// plus the fallback retry cycle (~15 blocks) to avoid aborting transactions that
/// the fallback path would have recovered.
const EXECUTION_TIMEOUT_BLOCKS: u64 = 50;

/// How many blocks to retain tombstones in the mempool (gossip deduplication).
const TOMBSTONE_RETENTION_BLOCKS: u64 = 500;

/// Maximum age for speculative execution results before cleanup.
const SPECULATIVE_MAX_AGE: Duration = Duration::from_secs(30);

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

    /// Last committed JVT root hash.
    ///
    /// Updated when `StateCommitComplete` is received from the runner.
    /// Used by BftState (via StateCommitComplete) to track when JVT is ready
    /// for state root verification.
    ///
    /// The JVT version always equals block height.
    last_committed_jvt_root: Hash,

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

        // Initialize last_committed_jvt_root from recovered JVT state.
        // This ensures we use actual persisted state, not genesis defaults.
        let jvt_root = recovered.jvt_root.unwrap_or(Hash::ZERO);

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
            // Use recovered JVT root - critical for correct state root computation
            last_committed_jvt_root: jvt_root,
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

    /// Get the last committed JVT root hash.
    pub fn last_committed_jvt_root(&self) -> Hash {
        self.last_committed_jvt_root
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

    /// Build source attestations and commitment entries for priority transactions.
    ///
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
        // duplicates that will be filtered by the proposer. This keeps blocks
        // full despite dedup filtering.
        let parent_hash = self.bft.proposal_parent_hash();
        let (_, qc_chain_tx_hashes, _) = self.bft.collect_qc_chain_hashes(parent_hash);
        let max_txs = self.bft.config().max_transactions_per_block + qc_chain_tx_hashes.len();
        let ready_txs = self
            .mempool
            .ready_transactions(max_txs, pending_txs, pending_certs);
        let current_height = BlockHeight(self.bft.committed_height() + 1);
        // Livelock cycle abort intents (from cycle detection).
        let livelock_intents = self.livelock.get_pending_abort_intents().to_vec();
        // Timed-out transactions from the mempool, converted to AbortIntent.
        let timed_out = self
            .mempool
            .get_timed_out_transactions(current_height, EXECUTION_TIMEOUT_BLOCKS);
        let timed_out_intents = timed_out.into_iter().map(|a| AbortIntent {
            tx_hash: a.tx_hash,
            reason: a.reason,
            block_height: a.block_height,
        });
        // Combine both sources into a single abort_intents list.
        let abort_intents: Vec<AbortIntent> = livelock_intents
            .into_iter()
            .chain(timed_out_intents)
            .collect();
        let certificates = self.execution.get_finalized_certificates();

        // Filter out abort intents for transactions that are already finalized
        // (TC created). Once all participating shards have collected ECs and formed
        // the TransactionCertificate, proposing an abort would cause split-brain:
        // remote shards commit the TC while we discard it.
        let abort_intents = abort_intents
            .into_iter()
            .filter(|a| {
                if self.execution.is_finalized(&a.tx_hash) {
                    tracing::info!(
                        tx_hash = %a.tx_hash,
                        "Filtering abort intent from proposal: transaction already finalized (TC created)"
                    );
                    false
                } else {
                    true
                }
            })
            .collect();

        ProposalInputs {
            ready_txs,
            abort_intents,
            certificates,
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
        self.mempool
            .cleanup_old_tombstones(current_height, TOMBSTONE_RETENTION_BLOCKS);

        // Clean up stale speculative execution results
        self.execution
            .cleanup_stale_speculative(SPECULATIVE_MAX_AGE);

        actions
    }

    /// Collect per-certificate `Arc<DatabaseUpdates>` for a set of tx_hashes.
    ///
    /// Returns cheap Arc clones — merging is deferred to the thread pool.
    fn collect_updates_for_tx_hashes(
        &self,
        tx_hashes: &[Hash],
    ) -> Vec<Arc<hyperscale_types::DatabaseUpdates>> {
        let cache = self.execution.execution_cache();
        tx_hashes
            .iter()
            .filter_map(|tx_hash| cache.get(tx_hash).cloned())
            .collect()
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

        // Get certificates we're about to propose - these also reduce in-flight
        let certificates = self.execution.get_finalized_certificates();
        let new_certs = certificates.len();

        // Request extra transactions to compensate for QC-chain duplicates
        // that the proposer will filter out, keeping blocks full.
        let parent_hash = self.bft.proposal_parent_hash();
        let (_, qc_chain_tx_hashes, _) = self.bft.collect_qc_chain_hashes(parent_hash);
        let max_txs = self.bft.config().max_transactions_per_block + qc_chain_tx_hashes.len();
        let ready_txs = self.mempool.ready_transactions(
            max_txs,
            pending_txs,               // txs in uncommitted pipeline blocks
            pending_certs + new_certs, // certs in pipeline + certs we're proposing
        );
        let current_height = BlockHeight(self.bft.committed_height() + 1);
        let livelock_intents = self.livelock.get_pending_abort_intents().to_vec();
        let timed_out = self
            .mempool
            .get_timed_out_transactions(current_height, EXECUTION_TIMEOUT_BLOCKS);
        let abort_intents: Vec<AbortIntent> = livelock_intents
            .into_iter()
            .chain(timed_out.into_iter().map(|a| AbortIntent {
                tx_hash: a.tx_hash,
                reason: a.reason,
                block_height: a.block_height,
            }))
            .collect();

        // Collect per-certificate Arc<DatabaseUpdates> from execution cache.
        // The closure captures the cache; BftState calls it with the final
        // filtered certificate list after dedup. Returns cheap Arc clones —
        // merging is deferred to the thread pool.
        let topology = self.topology.snapshot();
        let cache = self.execution.execution_cache();
        let collect_updates = |certs: &[Arc<TransactionCertificate>]| {
            certs
                .iter()
                .filter_map(|cert| cache.get(&cert.transaction_hash).cloned())
                .collect::<Vec<Arc<hyperscale_types::DatabaseUpdates>>>()
        };

        self.bft.on_proposal_timer(
            topology,
            &ready_txs,
            abort_intents,
            certificates,
            collect_updates,
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

        if is_next_block {
            let current_in_flight = self.mempool.in_flight();
            let certs_in_block = manifest.cert_hashes.len();
            let limit = self.mempool.config().max_in_flight;

            let new_in_flight = current_in_flight
                .saturating_add(total_tx_count)
                .saturating_sub(certs_in_block);

            // Reject if exceeding limit AND making things worse.
            // Allow blocks that don't increase in-flight (prevents deadlock).
            let would_exceed = new_in_flight > limit;
            let would_increase = new_in_flight > current_in_flight;

            if would_exceed && would_increase {
                tracing::warn!(
                    current_in_flight,
                    certs_in_block,
                    proposed_tx_count = total_tx_count,
                    new_in_flight,
                    limit,
                    block_hash = ?header.hash(),
                    height = header.height.0,
                    "Rejecting block that would exceed in-flight limit"
                );
                return vec![];
            }
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

        // Collect per-certificate Arc<DatabaseUpdates> from execution cache.
        // Returns cheap Arc clones — merging is deferred to the thread pool.
        let topology = self.topology.snapshot();
        let cache = self.execution.execution_cache();
        let collect_updates = |certs: &[Arc<TransactionCertificate>]| {
            certs
                .iter()
                .filter_map(|cert| cache.get(&cert.transaction_hash).cloned())
                .collect::<Vec<Arc<hyperscale_types::DatabaseUpdates>>>()
        };

        self.bft.on_qc_formed(
            topology,
            block_hash,
            qc,
            &inputs.ready_txs,
            inputs.abort_intents,
            inputs.certificates,
            collect_updates,
        )
    }

    /// Handle JVT state commit completion — update tracked state and notify BFT.
    fn on_state_commit_complete(&mut self, height: u64, state_root: Hash) -> Vec<Action> {
        let prev_height = self.bft.committed_height();

        // Update if this is the current or a newer height. Use `>=` because
        // the BFT state machine advances `committed_height` in
        // `commit_block_and_buffered` *before* the IO loop commits the JVT
        // and sends `StateCommitComplete`. With `>` the root update for the
        // current height would be silently dropped.
        if height >= prev_height {
            self.last_committed_jvt_root = state_root;

            tracing::debug!(
                height,
                state_root = ?state_root,
                "JVT state commit complete"
            );
        }

        // Notify BFT so it can update its committed state tracking.
        // BFT uses this as the source of truth for block height in block headers,
        // preventing speculative version propagation that causes deadlocks.
        // Unblocked state root verifications are pushed to the ready queue
        // and drained by handle() via drain_ready_state_root_verifications().
        self.bft
            .on_state_commit_complete(self.topology.snapshot(), height, state_root);
        vec![]
    }

    /// Handle block committed — notify all subsystems in the correct order.
    ///
    /// Order invariants:
    /// 1. Register cross-shard TXs with livelock BEFORE processing deferrals
    /// 2. Cleanup deferred/aborted/retried execution state BEFORE passing new TXs
    /// 3. Process CrossShardTxRegistered continuations BEFORE other exec actions
    fn on_block_committed(&mut self, block_hash: Hash, height: u64, block: Block) -> Vec<Action> {
        let mut actions = Vec::new();
        let block_height = BlockHeight(height);

        // Register newly committed cross-shard TXs with livelock for cycle detection.
        // Must happen BEFORE livelock.on_block_committed() processes deferrals.
        for tx in block.transactions.iter() {
            if self.livelock.is_cross_shard(self.topology.snapshot(), tx) {
                self.livelock
                    .on_cross_shard_committed(self.topology.snapshot(), tx, block_height);
            }
        }

        // Livelock: process abort intents/certs, add tombstones, cleanup tracking
        self.livelock.on_block_committed(&block);

        // Abort intents feed the execution accumulator only — no cleanup,
        // no mempool state change. The actual terminal state comes when the
        // TC commits (via on_certificate_committed).
        for intent in &block.abort_intents {
            if let Some(completion) = self
                .execution
                .record_abort_intent(intent.tx_hash, intent.reason.clone())
            {
                actions.push(Action::SignAndBroadcastExecutionVote {
                    block_hash: completion.block_hash,
                    block_height: completion.block_height,
                    wave_id: completion.wave_id,
                    receipt_root: completion.receipt_root,
                    tx_count: completion.tx_outcomes.len() as u32,
                    tx_outcomes: completion.tx_outcomes,
                    participating_shards: completion.participating_shards,
                });
            }
        }

        // Remove committed certificates from execution state.
        // They've been included in this block, so don't need to be proposed again.
        // Also invalidate any speculative results that conflict with these writes.
        for cert in &block.certificates {
            // Debug cross-check: verify our local execution produced the same
            // receipt_hash as the quorum-signed certificate. A mismatch indicates
            // an engine determinism bug (different outcome/events for same input).
            if let Some(local_receipt_hash) = self
                .execution
                .execution_cache()
                .get_receipt_hash(&cert.transaction_hash)
            {
                if let Some(ec) = cert.shard_proofs.values().next() {
                    // Skip check for aborted transactions — local execution may have
                    // completed but the abort intent won the accumulator race.
                    if ec.receipt_hash != Hash::ZERO {
                        debug_assert_eq!(
                            local_receipt_hash,
                            ec.receipt_hash,
                            "receipt_hash mismatch for tx {}: local engine produced different \
                             outcome/events than certificate. This indicates an engine determinism bug.",
                            cert.transaction_hash,
                        );
                    }
                }
            }

            self.execution
                .remove_finalized_certificate(&cert.transaction_hash);
            // Invalidate speculative results that read from nodes being written
            self.execution.invalidate_speculative_on_commit(cert);
        }

        // Pass all transactions from block to execution (no need for mempool lookup).
        // NOTE: execution.on_block_committed emits CrossShardTxRegistered events, which
        // will be processed by the coordinator via Continuation actions.
        let all_txs = block.transactions.clone();
        let exec_actions = self.execution.on_block_committed(
            self.topology.snapshot(),
            block_hash,
            height,
            block.header.timestamp,
            block.header.proposer,
            all_txs,
        );

        // Process CrossShardTxRegistered events immediately so coordinator has
        // registrations before any subsequent provisions arrive.
        // This ensures ProvisionAccepted can be emitted for livelock.
        for action in &exec_actions {
            if let Action::Continuation(ProtocolEvent::CrossShardTxRegistered {
                tx_hash,
                required_shards,
                committed_height,
            }) = action
            {
                let registration = hyperscale_provisions::TxRegistration {
                    required_shards: required_shards.clone(),
                    registered_at: *committed_height,
                };
                actions.extend(self.provisions.on_tx_registered(*tx_hash, registration));
            }
        }
        actions.extend(exec_actions);

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
        // Enrich RequestMissingProvisions actions with the source shard's committee.
        let mut provision_actions = self
            .provisions
            .on_block_committed(self.topology.snapshot(), &block);
        for action in &mut provision_actions {
            if let Action::RequestMissingProvisions {
                source_shard,
                peers,
                ..
            } = action
            {
                *peers = self
                    .topology
                    .snapshot()
                    .committee_for_shard(*source_shard)
                    .to_vec();
            }
        }
        actions.extend(provision_actions);

        actions
    }

    /// Handle state provisions verified — notify mempool and coordinator.
    fn on_state_provisions_verified(
        &mut self,
        batch: ProvisionBatch,
        committed_header: Option<Arc<CommittedBlockHeader>>,
        valid: bool,
    ) -> Vec<Action> {
        // No need to promote headers into BFT — RemoteHeaderCoordinator
        // already stores verified headers, and BFT receives them via
        // RemoteHeaderVerified event.
        self.provisions.on_state_provisions_verified(
            self.topology.snapshot(),
            batch,
            committed_header,
            valid,
        )
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
                // Store valid headers into BFT immediately (before the
                // RemoteHeaderVerified continuation is processed) so they're
                // available for deferral merkle proof validation without a
                // 1-step delay.
                if valid {
                    self.bft.on_verified_remote_header(Arc::clone(&header));
                }
                self.remote_headers.on_remote_header_qc_verified(
                    self.topology.snapshot(),
                    shard,
                    height,
                    header,
                    valid,
                )
            }
            ProtocolEvent::RemoteHeaderVerified { committed_header } => {
                // Fan out verified header to all downstream consumers.
                let topology = self.topology.snapshot();
                let shard = committed_header.shard_group_id();

                // BFT: store for deferral merkle proof validation.
                let mut actions = self
                    .bft
                    .on_verified_remote_header(Arc::clone(&committed_header));

                // Execution: register expected execution certs from waves.
                self.execution.on_verified_remote_header(
                    topology,
                    shard,
                    committed_header.header.height.0,
                    &committed_header.header.waves,
                );

                // Provisions: register expected provisions and join with buffered batches.
                actions.extend(
                    self.provisions
                        .on_verified_remote_header(topology, committed_header),
                );

                actions
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
            ProtocolEvent::ProposalBuilt {
                height,
                round,
                block,
                block_hash,
            } => self.bft.on_proposal_built(
                self.topology.snapshot(),
                height,
                round,
                block,
                block_hash,
            ),

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
            ProtocolEvent::StateProvisionsReceived { batch } => self
                .provisions
                .on_state_provisions_received(self.topology.snapshot(), batch),
            ProtocolEvent::StateProvisionsVerified {
                batch,
                committed_header,
                valid,
            } => self.on_state_provisions_verified(batch, committed_header, valid),
            ProtocolEvent::CrossShardTxRegistered {
                tx_hash,
                required_shards,
                committed_height,
            } => {
                let registration = hyperscale_provisions::TxRegistration {
                    required_shards,
                    registered_at: committed_height,
                };
                self.provisions.on_tx_registered(tx_hash, registration)
            }
            ProtocolEvent::ProvisionAccepted {
                tx_hash,
                source_shard,
                source_block_height,
                entries,
            } => {
                let outputs = self.livelock.on_provision_accepted(
                    tx_hash,
                    source_shard,
                    source_block_height,
                    &entries,
                );
                // Group deferral proof requests by (source_shard, block_height).
                let mut grouped: std::collections::HashMap<
                    (ShardGroupId, BlockHeight),
                    Vec<(Hash, hyperscale_core::InclusionProofFetchReason)>,
                > = std::collections::HashMap::new();
                for output in outputs {
                    match output {
                        hyperscale_livelock::LivelockOutput::FetchInclusionProof {
                            source_shard,
                            source_block_height,
                            winner_tx_hash,
                            loser_tx_hash,
                        } => {
                            grouped
                                .entry((source_shard, source_block_height))
                                .or_default()
                                .push((
                                    winner_tx_hash,
                                    hyperscale_core::InclusionProofFetchReason::Deferral {
                                        loser_tx_hash,
                                    },
                                ));
                        }
                    }
                }
                let mut actions = Vec::new();
                for ((source_shard, source_block_height), entries) in grouped {
                    let peers = self
                        .topology
                        .snapshot()
                        .committee_for_shard(source_shard)
                        .to_vec();
                    actions.push(Action::RequestTxInclusionProofs {
                        source_shard,
                        source_block_height,
                        entries,
                        peers,
                    });
                }
                actions
            }
            ProtocolEvent::ProvisioningComplete {
                tx_hash,
                provisions,
            } => {
                if let Some(req) = self.execution.on_provisioning_complete(
                    self.topology.snapshot(),
                    tx_hash,
                    provisions,
                ) {
                    vec![Action::ExecuteCrossShardTransactions {
                        requests: vec![req],
                    }]
                } else {
                    vec![]
                }
            }

            // ── Execution ────────────────────────────────────────────────
            ProtocolEvent::ExecutionBatchCompleted {
                results,
                tx_outcomes,
                speculative,
            } => {
                // Single pass: populate execution cache and build receipt bundles.
                // Consumes results by value — no clones needed.
                //
                // Receipts are stored for BOTH speculative and canonical executions.
                // The sync protocol requires ledger receipts to serve blocks; without
                // them `serve_block_request` returns not_found, permanently blocking
                // any peer that needs to sync past the affected height.
                //
                // For speculative batches, we only store receipts for transactions
                // still tracked in `speculative_in_flight_txs`. After a view change,
                // that set is cleared — so a slow speculative execution completing
                // post-view-change won't overwrite a canonical receipt produced by
                // the re-execution that the view-change path dispatches.
                let mut bundles: Vec<ReceiptBundle> = Vec::with_capacity(results.len());

                for result in results {
                    let tx_hash = result.tx_hash;
                    let receipt_hash = result.receipt_hash;
                    let db_updates = Arc::new(result.database_updates);

                    // For speculative batches, skip receipts for transactions that
                    // are no longer tracked (cleared by view change). Canonical
                    // execution will produce the correct receipt.
                    let dominated =
                        speculative && !self.execution.is_speculative_in_flight_for_tx(&tx_hash);
                    if !dominated {
                        bundles.push(ReceiptBundle {
                            tx_hash,
                            ledger_receipt: Arc::new(result.ledger_receipt),
                            local_execution: Some(result.local_execution),
                            database_updates: Some(Arc::clone(&db_updates)),
                        });
                    }

                    self.execution.execution_cache_mut().insert(
                        tx_hash,
                        db_updates,
                        receipt_hash,
                        self.bft.committed_height(),
                    );
                }

                // Dispatch receipt storage (fire-and-forget, off main thread)
                let mut actions: Vec<Action> = Vec::new();
                if !bundles.is_empty() {
                    tracing::debug!(
                        speculative,
                        bundle_count = bundles.len(),
                        "Emitting StoreReceiptBundles"
                    );
                    actions.push(Action::StoreReceiptBundles { bundles });
                } else {
                    tracing::warn!(
                        speculative,
                        results_count = 0, // results already consumed
                        "ExecutionBatchCompleted produced ZERO receipt bundles"
                    );
                }

                // Record outcomes into execution accumulators.
                // Outcomes were extracted on the handler thread — no data
                // munging needed here on the main thread.
                for wr in tx_outcomes {
                    if let Some(completion) = self
                        .execution
                        .record_execution_result(wr.tx_hash, wr.outcome)
                    {
                        actions.push(Action::SignAndBroadcastExecutionVote {
                            block_hash: completion.block_hash,
                            block_height: completion.block_height,
                            wave_id: completion.wave_id,
                            receipt_root: completion.receipt_root,
                            tx_count: completion.tx_outcomes.len() as u32,
                            tx_outcomes: completion.tx_outcomes,
                            participating_shards: completion.participating_shards,
                        });
                    }
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
            // ── Storage / Sync ───────────────────────────────────────────
            ProtocolEvent::BlockFetched { .. } => vec![],
            ProtocolEvent::SyncBlockReadyToApply { block, qc } => self
                .bft
                .on_sync_block_ready_to_apply(self.topology.snapshot(), block, qc),
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
            let per_cert_updates = self.collect_updates_for_tx_hashes(&ready.cert_tx_hashes);
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
