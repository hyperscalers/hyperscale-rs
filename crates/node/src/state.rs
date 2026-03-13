//! Node state machine.

use hyperscale_bft::{BftConfig, BftState, RecoveredState};
use hyperscale_core::{Action, ProtocolEvent, ProvisionVerificationResult, StateMachine, TimerId};
use hyperscale_execution::ExecutionState;
use hyperscale_livelock::LivelockState;
use hyperscale_mempool::{MempoolConfig, MempoolState};
use hyperscale_provisions::ProvisionCoordinator;
use hyperscale_topology::TopologyState;
use hyperscale_types::{
    Block, BlockHeader, BlockHeight, BlockManifest, Bls12381G1PrivateKey, CommitmentProof,
    CommittedBlockHeader, Hash, QuorumCertificate, ReadyTransactions, ReceiptBundle,
    RoutableTransaction, ShardGroupId, TopologySnapshot, TransactionAbort, TransactionCertificate,
    TransactionDefer,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::instrument;

/// Index type for simulation-only node routing.
/// Production uses ValidatorId (from message signatures) and PeerId (libp2p).
pub type NodeIndex = u32;

// ─── Constants ──────────────────────────────────────────────────────────

/// How many blocks a cross-shard transaction can wait before being aborted.
const EXECUTION_TIMEOUT_BLOCKS: u64 = 30;

/// Maximum number of times a timed-out transaction can be retried.
const MAX_RETRIES: u32 = 3;

/// How many blocks to retain tombstones in the mempool (gossip deduplication).
const TOMBSTONE_RETENTION_BLOCKS: u64 = 1000;

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

    /// Livelock prevention state (cycle detection for cross-shard TXs).
    livelock: LivelockState,

    /// Last committed JMT root hash.
    ///
    /// Updated when `StateCommitComplete` is received from the runner.
    /// Used by BftState (via StateCommitComplete) to track when JMT is ready
    /// for state root verification.
    ///
    /// The JMT version always equals block height.
    last_committed_jmt_root: Hash,

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
    commitment_proofs: HashMap<Hash, CommitmentProof>,
    deferred: Vec<TransactionDefer>,
    aborted: Vec<TransactionAbort>,
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

        // Initialize last_committed_jmt_root from recovered JMT state.
        // This ensures we use actual persisted state, not genesis defaults.
        let jmt_root = recovered.jmt_root.unwrap_or(Hash::ZERO);

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
            livelock: LivelockState::new(),
            topology,
            // Use recovered JMT root - critical for correct state root computation
            last_committed_jmt_root: jmt_root,
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

    /// Get the last committed JMT root hash.
    pub fn last_committed_jmt_root(&self) -> Hash {
        self.last_committed_jmt_root
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
        ready_txs: &ReadyTransactions,
    ) -> HashMap<Hash, CommitmentProof> {
        let mut proofs = HashMap::new();

        // Only priority transactions have verified provisions
        for tx in &ready_txs.priority {
            let tx_hash = tx.hash();
            if let Some(proof) = self.provisions.build_commitment_proof(&tx_hash) {
                proofs.insert(tx_hash, proof);
            }
        }

        proofs
    }

    /// Gather all inputs needed for a block proposal.
    ///
    /// Used by both `on_proposal_timer` and `on_qc_formed` to avoid duplicating
    /// the ready-transaction + deferred + aborted + certificates gathering logic.
    fn gather_proposal_inputs(&self, pending_txs: usize, pending_certs: usize) -> ProposalInputs {
        let max_txs = self.bft.config().max_transactions_per_block;
        let ready_txs = self
            .mempool
            .ready_transactions(max_txs, pending_txs, pending_certs);
        let commitment_proofs = self.build_commitment_proofs(&ready_txs);
        let deferred = self.livelock.get_pending_deferrals().to_vec();
        let current_height = BlockHeight(self.bft.committed_height() + 1);
        let aborted = self.mempool.get_timed_out_transactions(
            current_height,
            EXECUTION_TIMEOUT_BLOCKS,
            MAX_RETRIES,
        );
        let certificates = self.execution.get_finalized_certificates();

        ProposalInputs {
            ready_txs,
            commitment_proofs,
            deferred,
            aborted,
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

    /// Compute pre-merged `DatabaseUpdates` for a set of certificate tx_hashes.
    ///
    /// Same as `compute_merged_updates_for_certs` but works from tx_hashes
    /// (used by the state root verification drain path).
    fn compute_merged_updates_for_tx_hashes(
        &self,
        tx_hashes: &[Hash],
    ) -> hyperscale_types::DatabaseUpdates {
        let topology = self.topology.snapshot();
        let local_shard = topology.local_shard();
        let num_shards = topology.num_shards();
        let cache = self.execution.execution_cache();

        let per_cert: Vec<hyperscale_types::DatabaseUpdates> = tx_hashes
            .iter()
            .filter_map(|tx_hash| {
                let raw = cache.get(tx_hash)?;
                Some(hyperscale_storage::filter_updates_to_shard(
                    raw,
                    local_shard,
                    num_shards,
                ))
            })
            .collect();

        hyperscale_storage::merge_database_updates(&per_cert)
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

        let max_txs = self.bft.config().max_transactions_per_block;
        let ready_txs = self.mempool.ready_transactions(
            max_txs,
            pending_txs,               // txs in uncommitted pipeline blocks
            pending_certs + new_certs, // certs in pipeline + certs we're proposing
        );
        let commitment_proofs = self.build_commitment_proofs(&ready_txs);
        let deferred = self.livelock.get_pending_deferrals().to_vec();
        let current_height = BlockHeight(self.bft.committed_height() + 1);
        let aborted = self.mempool.get_timed_out_transactions(
            current_height,
            EXECUTION_TIMEOUT_BLOCKS,
            MAX_RETRIES,
        );

        // Compute merged DatabaseUpdates from execution cache.
        // The closure captures the execution cache and topology; BftState calls
        // it with the final filtered certificate list after dedup.
        let topology = self.topology.snapshot();
        let local_shard = topology.local_shard();
        let num_shards = topology.num_shards();
        let cache = self.execution.execution_cache();
        let compute_writes = |certs: &[Arc<TransactionCertificate>]| {
            let per_cert: Vec<hyperscale_types::DatabaseUpdates> = certs
                .iter()
                .filter_map(|cert| {
                    let raw = cache.get(&cert.transaction_hash)?;
                    Some(hyperscale_storage::filter_updates_to_shard(
                        raw,
                        local_shard,
                        num_shards,
                    ))
                })
                .collect();
            hyperscale_storage::merge_database_updates(&per_cert)
        };

        self.bft.on_proposal_timer(
            topology,
            &ready_txs,
            deferred,
            aborted,
            certificates,
            commitment_proofs,
            compute_writes,
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
            let config = self.mempool.config();
            let soft_limit = config.max_in_flight;
            let hard_limit = config.max_in_flight_hard_limit;

            // Retry and priority transactions bypass soft limit
            // Only "other" transactions (tx_hashes) are subject to soft limit
            let without_proofs = manifest.tx_hashes.len();

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
        let all_tx_hashes: Vec<_> = manifest.all_tx_hashes().collect();
        let transactions: Vec<_> = all_tx_hashes
            .iter()
            .filter_map(|h| mempool_txs.get(*h).cloned())
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
            &mempool_txs,
            &local_certs,
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

        // Build the closure for computing merged DatabaseUpdates from execution cache.
        let topology = self.topology.snapshot();
        let local_shard = topology.local_shard();
        let num_shards = topology.num_shards();
        let cache = self.execution.execution_cache();
        let compute_writes = |certs: &[Arc<TransactionCertificate>]| {
            let per_cert: Vec<hyperscale_types::DatabaseUpdates> = certs
                .iter()
                .filter_map(|cert| {
                    let raw = cache.get(&cert.transaction_hash)?;
                    Some(hyperscale_storage::filter_updates_to_shard(
                        raw,
                        local_shard,
                        num_shards,
                    ))
                })
                .collect();
            hyperscale_storage::merge_database_updates(&per_cert)
        };

        self.bft.on_qc_formed(
            topology,
            block_hash,
            qc,
            &inputs.ready_txs,
            inputs.deferred,
            inputs.aborted,
            inputs.certificates,
            inputs.commitment_proofs,
            compute_writes,
        )
    }

    /// Handle JMT state commit completion — update tracked state and notify BFT.
    fn on_state_commit_complete(&mut self, height: u64, state_root: Hash) -> Vec<Action> {
        let prev_height = self.bft.committed_height();

        // Update if this is the current or a newer height. Use `>=` because
        // the BFT state machine advances `committed_height` in
        // `commit_block_and_buffered` *before* the IO loop commits the JMT
        // and sends `StateCommitComplete`. With `>` the root update for the
        // current height would be silently dropped.
        if height >= prev_height {
            self.last_committed_jmt_root = state_root;

            tracing::debug!(
                height,
                state_root = ?state_root,
                "JMT state commit complete"
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
        for tx in block.all_transactions() {
            if self.livelock.is_cross_shard(self.topology.snapshot(), tx) {
                self.livelock
                    .on_cross_shard_committed(self.topology.snapshot(), tx, block_height);
            }
        }

        // Livelock: process deferrals/aborts/certs, add tombstones, cleanup tracking
        self.livelock.on_block_committed(&block);

        // Cleanup execution state for deferred transactions.
        // This must happen BEFORE passing new transactions to execution,
        // so that retries can be processed fresh.
        for deferral in &block.deferred {
            self.execution.cleanup_transaction(&deferral.tx_hash);
        }

        // Cleanup execution state for aborted transactions
        for abort in &block.aborted {
            self.execution.cleanup_transaction(&abort.tx_hash);
        }

        // Cleanup execution state for original transactions superseded by retries.
        // When a retry T' is committed, the original T's execution state must be
        // cleaned up so T' can execute fresh. The mempool marks T as Retried and
        // releases its locks; here we clean up execution tracking.
        for retry_tx in &block.retry_transactions {
            let original_hash = retry_tx.original_hash();
            // Only cleanup if the original is different from the retry
            // (original_hash returns self.hash() for non-retries, but retry_transactions
            // should only contain actual retries)
            if original_hash != retry_tx.hash() {
                self.execution.cleanup_transaction(&original_hash);
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
                    debug_assert_eq!(
                        local_receipt_hash,
                        ec.receipt_hash,
                        "receipt_hash mismatch for tx {}: local engine produced different \
                         outcome/events than certificate. This indicates an engine determinism bug.",
                        cert.transaction_hash,
                    );
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
        let all_txs: Vec<_> = block.all_transactions().cloned().collect();
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
        results: Vec<ProvisionVerificationResult>,
        committed_header: Option<CommittedBlockHeader>,
    ) -> Vec<Action> {
        for result in &results {
            if result.valid {
                self.mempool.on_provision_verified(result.tx_hash);
            }
        }
        self.provisions.on_state_provisions_verified(
            self.topology.snapshot(),
            results,
            committed_header,
        )
    }

    /// Handle transaction executed — notify mempool and check pending blocks.
    fn on_transaction_executed(&mut self, tx_hash: Hash, accepted: bool) -> Vec<Action> {
        // Notify mempool
        let mut actions =
            self.mempool
                .on_transaction_executed(self.topology.snapshot(), tx_hash, accepted);

        // Check if any pending blocks are now complete with this certificate
        let local_certs = self.execution.finalized_certificates_by_hash();
        actions.extend(self.bft.check_pending_blocks_for_certificate(
            self.topology.snapshot(),
            tx_hash,
            &local_certs,
        ));

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
        let mut actions =
            self.mempool
                .on_transaction_gossip_arc(self.topology.snapshot(), tx, submitted_locally);

        // Check if any pending blocks are now complete
        let mempool_map = self.mempool.as_hash_map();
        actions.extend(self.bft.check_pending_blocks_for_transaction(
            self.topology.snapshot(),
            tx_hash,
            &mempool_map,
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

    /// Handle fetched certificates delivered — verify each against topology.
    fn on_certificate_fetch_delivered(
        &mut self,
        block_hash: Hash,
        certificates: Vec<TransactionCertificate>,
    ) -> Vec<Action> {
        // Verify each fetched certificate's embedded ExecutionCertificates against
        // our current topology. This ensures we don't accept forged certificates
        // from Byzantine peers.
        let mut actions = Vec::new();
        for cert in certificates {
            actions.extend(self.execution.verify_fetched_certificate(
                self.topology.snapshot(),
                block_hash,
                cert,
            ));
        }
        actions
    }

    /// Handle a received certificate that has been fully verified.
    fn on_transaction_certificate_verified(
        &mut self,
        certificate: Arc<TransactionCertificate>,
    ) -> Vec<Action> {
        let tx_hash = certificate.transaction_hash;
        let accepted = certificate.is_accepted();

        // Cancel any ongoing local certificate building
        self.execution.cancel_certificate_building(&tx_hash);

        // Add to finalized certificates if not already present
        self.execution.add_verified_certificate(certificate);

        // Notify mempool that transaction is finalized
        vec![Action::Continuation(ProtocolEvent::TransactionExecuted {
            tx_hash,
            accepted,
        })]
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
            } => self.provisions.on_remote_block_committed(
                self.topology.snapshot(),
                committed_header,
                sender,
            ),
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
            ProtocolEvent::CommitmentProofVerified {
                block_hash,
                deferral_index,
                valid,
            } => self.bft.on_commitment_proof_verified(
                self.topology.snapshot(),
                block_hash,
                deferral_index,
                valid,
            ),
            ProtocolEvent::StateRootVerified { block_hash, valid } => self
                .bft
                .on_state_root_verified(self.topology.snapshot(), block_hash, valid),
            ProtocolEvent::TransactionRootVerified { block_hash, valid } => self
                .bft
                .on_transaction_root_verified(self.topology.snapshot(), block_hash, valid),
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
            ProtocolEvent::StateProvisionsReceived { provisions } => self
                .provisions
                .on_state_provisions_received(self.topology.snapshot(), provisions),
            ProtocolEvent::StateProvisionsVerified {
                results,
                committed_header,
            } => self.on_state_provisions_verified(results, committed_header),
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
                commitment_proof,
            } => {
                self.livelock
                    .on_provision_accepted(tx_hash, source_shard, &commitment_proof);
                vec![]
            }
            ProtocolEvent::ProvisioningComplete {
                tx_hash,
                provisions,
            } => self.execution.on_provisioning_complete(
                self.topology.snapshot(),
                tx_hash,
                provisions,
            ),

            // ── Execution ────────────────────────────────────────────────
            ProtocolEvent::ExecutionVoteReceived { vote } => {
                self.execution.on_vote(self.topology.snapshot(), vote)
            }
            ProtocolEvent::ExecutionBatchCompleted {
                votes,
                results,
                speculative,
            } => {
                // 1. Build receipt bundles before consuming results
                //    (only for canonical execution — speculative results are ephemeral)
                let bundles: Vec<ReceiptBundle> = if !speculative {
                    results
                        .iter()
                        .map(|r| ReceiptBundle {
                            tx_hash: r.tx_hash,
                            ledger_receipt: Arc::new(r.ledger_receipt.clone()),
                            local_execution: Some(r.local_execution.clone()),
                        })
                        .collect()
                } else {
                    Vec::new()
                };

                // 2. Populate execution cache (in-memory, for block commit fast path)
                for result in results {
                    let receipt_hash = result.ledger_receipt.receipt_hash();
                    self.execution.execution_cache_mut().insert(
                        result.tx_hash,
                        result.database_updates,
                        receipt_hash,
                    );
                }

                // 3. Dispatch receipt storage (fire-and-forget, off main thread)
                let mut actions: Vec<Action> = Vec::new();
                if !bundles.is_empty() {
                    actions.push(Action::StoreReceiptBundles { bundles });
                }

                // 4. Process votes through VoteTracker
                for vote in votes {
                    actions.extend(self.execution.on_vote(self.topology.snapshot(), vote));
                }
                actions
            }
            ProtocolEvent::ExecutionCertificateReceived { cert } => self
                .execution
                .on_certificate(self.topology.snapshot(), cert),
            ProtocolEvent::ExecutionVotesVerifiedAndAggregated {
                tx_hash,
                verified_votes,
            } => self.execution.on_execution_votes_verified(
                self.topology.snapshot(),
                tx_hash,
                verified_votes,
            ),
            ProtocolEvent::ExecutionCertificateSignatureVerified { certificate, valid } => self
                .execution
                .on_certificate_verified(self.topology.snapshot(), certificate, valid),
            ProtocolEvent::ExecutionCertificateAggregated {
                tx_hash,
                certificate,
            } => self.execution.on_execution_certificate_aggregated(
                self.topology.snapshot(),
                tx_hash,
                certificate,
            ),
            ProtocolEvent::SpeculativeExecutionComplete {
                block_hash,
                tx_hashes,
            } => self
                .execution
                .on_speculative_execution_complete(block_hash, tx_hashes),

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
            } => self.on_certificate_fetch_delivered(block_hash, certificates),
            ProtocolEvent::FetchedCertificateVerified {
                block_hash,
                certificate,
            } => {
                self.execution
                    .cancel_certificate_building(&certificate.transaction_hash);
                self.bft.on_certificate_fetch_received(
                    self.topology.snapshot(),
                    block_hash,
                    vec![Arc::new(certificate)],
                )
            }
            ProtocolEvent::TransactionCertificateVerified { certificate } => {
                self.on_transaction_certificate_verified(certificate)
            }

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
            let merged = self.compute_merged_updates_for_tx_hashes(&ready.cert_tx_hashes);
            actions.push(Action::VerifyStateRoot {
                block_hash: ready.block_hash,
                parent_state_root: ready.parent_state_root,
                expected_root: ready.expected_root,
                merged_updates: Arc::new(merged),
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
