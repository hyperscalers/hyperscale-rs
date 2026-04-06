//! Execution state machine.
//!
//! Handles transaction execution after blocks are committed.
//!
//! # Transaction Types
//!
//! - **Single-shard**: Execute locally, then vote within shard for BLS signature aggregation.
//! - **Cross-shard**: Atomic execution protocol with provisioning, voting, and finalization.
//!
//! # Cross-Shard Atomic Execution Protocol
//!
//! ## Phase 1: State Provisioning
//! When a block commits with cross-shard transactions, the block proposer broadcasts
//! state provisions (with merkle inclusion proofs) to target shards.
//!
//! ## Phase 2: Provision Verification
//! Target shards receive provisions, verify the QC signature and merkle proofs
//! against the committed state root, then mark provisioning complete.
//!
//! ## Phase 3: Deterministic Execution
//! With provisioned state, validators execute the transaction and create
//! an ExecutionVote with the receipt hash of execution results.
//!
//! ## Phase 4: Vote Aggregation
//! Validators broadcast votes to their local shard. When 2f+1 voting power agrees
//! on the same receipt hash, an execution certificate is created and broadcast to
//! remote participating shards (local peers form it independently).
//!
//! ## Phase 5: Finalization
//! Validators collect shard execution proofs from all participating shards. When all
//! proofs are received, a TransactionCertificate is created.

use hyperscale_core::{Action, CrossShardExecutionRequest, ProtocolEvent, ProvisionRequest};
use hyperscale_types::{
    AbortReason, BlockHeight, Bls12381G1PublicKey, DatabaseUpdates, ExecutionResult, ExecutionVote,
    Hash, NodeId, ProvisionBatch, ReceiptBundle, RoutableTransaction, ShardExecutionProof,
    ShardGroupId, StateProvision, TopologySnapshot, TransactionCertificate, TransactionDecision,
    TxExecutionOutcome, TxOutcome, ValidatorId, WaveId,
};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tracing::instrument;

use crate::accumulator::ExecutionAccumulator;
use crate::execution_cache::ExecutionCache;
use crate::trackers::{CertificateTracker, VoteTracker};

/// Maximum age for speculative execution results before they're considered stale.
/// Results older than this are pruned on each block commit to prevent unbounded growth.
const SPECULATIVE_MAX_AGE: Duration = Duration::from_secs(30);

/// Data returned when a wave completes (all txs executed).
///
/// The state machine produces this; the io_loop uses it to sign the execution vote
/// and broadcast (since the state machine doesn't hold the signing key).
#[derive(Debug)]
pub struct CompletionData {
    /// Block this wave belongs to.
    pub block_hash: Hash,
    /// Block height.
    pub block_height: u64,
    /// Wave identifier.
    pub wave_id: WaveId,
    /// Merkle root over per-tx outcome leaves.
    pub receipt_root: Hash,
    /// Per-tx outcomes in wave order.
    pub tx_outcomes: Vec<hyperscale_types::TxOutcome>,
}

/// A cross-shard transaction registration for provision tracking.
///
/// Returned by [`ExecutionState::on_block_committed`] as structured data
/// instead of `Action::Continuation` events.
#[derive(Debug, Clone)]
pub struct CrossShardRegistration {
    /// Hash of the cross-shard transaction.
    pub tx_hash: Hash,
    /// Remote shards this transaction needs provisions from.
    pub required_shards: BTreeSet<ShardGroupId>,
    /// Block height when the transaction was committed.
    pub committed_height: BlockHeight,
}

/// Output from [`ExecutionState::on_block_committed`].
///
/// Separates actions from cross-shard registrations so the orchestrator
/// can process registrations before forwarding actions.
pub struct BlockCommittedOutput {
    /// Actions to dispatch (execution, provisioning, etc.).
    pub actions: Vec<Action>,
    /// Cross-shard registrations for the provision coordinator.
    pub cross_shard_registrations: Vec<CrossShardRegistration>,
}

/// Cached entry for speculative execution.
///
/// With inline signing, the votes have already been signed and sent when
/// speculative execution completes. This entry just tracks that the tx was
/// speculatively executed so we can skip re-execution when the block commits.
///
/// The read_set is kept for invalidation: if a conflicting write commits before
/// this block, the speculative execution is invalidated and the transaction will
/// be re-executed normally when the block commits.
#[derive(Debug, Clone)]
pub struct SpeculativeResult {
    /// NodeIds that were READ during execution (for invalidation).
    /// Populated from the transaction's declared_reads.
    pub read_set: HashSet<NodeId>,
    /// When this speculative execution completed.
    pub created_at: Duration,
}

/// Execution memory statistics for monitoring collection sizes.
#[derive(Clone, Copy, Debug, Default)]
pub struct ExecutionMemoryStats {
    pub cache_entries: usize,
    pub finalized_certificates: usize,
    pub pending_provisioning: usize,
    pub accumulators: usize,
    pub vote_trackers: usize,
    pub early_votes: usize,
    pub certificate_trackers: usize,
    pub speculative_results: usize,
    pub expected_exec_certs: usize,
    pub speculative_provision_in_flight: usize,
    pub speculative_provision_results: usize,
    pub pending_provision_commits: usize,
}

/// Execution state machine.
///
/// Handles transaction execution after blocks are committed.
pub struct ExecutionState {
    /// Current time.
    now: Duration,

    /// In-memory cache of execution write sets (DatabaseUpdates), keyed by tx hash.
    /// Populated when execution completes, read during block commit, evicted after commit.
    execution_cache: ExecutionCache,

    /// Finalized transaction certificates ready for block inclusion.
    /// Uses BTreeMap for deterministic iteration order.
    /// Stores (certificate, height_when_finalized) for stale-entry pruning.
    finalized_certificates: BTreeMap<Hash, (Arc<TransactionCertificate>, u64)>,

    /// Current committed height for pruning stale entries.
    committed_height: u64,

    // ═══════════════════════════════════════════════════════════════════════
    // Cross-shard state (Phase 1-2: Provisioning)
    // ═══════════════════════════════════════════════════════════════════════
    /// Transactions waiting for provisioning to complete before execution.
    /// Maps tx_hash -> (transaction, block_height)
    /// Note: Provision tracking is handled by ProvisionCoordinator.
    pending_provisioning: HashMap<Hash, (Arc<RoutableTransaction>, u64)>,

    // ═══════════════════════════════════════════════════════════════════════
    // Wave-based voting state
    // ═══════════════════════════════════════════════════════════════════════
    /// Execution accumulators: collect per-tx execution results within each wave.
    /// Keyed by (block_hash, wave_id) to handle multiple blocks in flight.
    accumulators: HashMap<(Hash, WaveId), ExecutionAccumulator>,

    /// Execution vote trackers: collect execution votes from other validators.
    /// Keyed by (block_hash, wave_id). Only created on the wave leader.
    vote_trackers: HashMap<(Hash, WaveId), VoteTracker>,

    /// Waves that have a canonical EC (aggregated by leader, or received from leader).
    /// Used to stop re-voting in `scan_complete_waves`. Replaces the old check of
    /// "VoteTracker absent" now that only wave leaders create VoteTrackers.
    waves_with_ec: HashSet<(Hash, WaveId)>,

    /// Tx → wave assignment lookup for the current block.
    /// Maps tx_hash → (block_hash, wave_id).
    wave_assignments: HashMap<Hash, (Hash, WaveId)>,

    /// Early execution votes that arrived before tracking started.
    /// Keyed by (block_hash, wave_id). Only buffered for the wave leader.
    early_votes: HashMap<(Hash, WaveId), Vec<ExecutionVote>>,

    // ═══════════════════════════════════════════════════════════════════════
    // Cross-shard state (Phase 5: Finalization)
    // ═══════════════════════════════════════════════════════════════════════
    /// Certificate trackers for cross-shard transactions.
    /// Maps tx_hash -> (CertificateTracker, height_when_created) for stale-entry pruning.
    certificate_trackers: HashMap<Hash, (CertificateTracker, u64)>,

    // ═══════════════════════════════════════════════════════════════════════
    // Early arrivals (before tracking starts)
    // ═══════════════════════════════════════════════════════════════════════
    /// Execution results that arrived before the wave was assigned.
    /// This happens with speculative execution — results arrive before
    /// on_block_committed creates the wave/accumulator.
    /// Maps tx_hash -> TxExecutionOutcome. Replayed during assign_waves.
    early_execution_results: HashMap<Hash, TxExecutionOutcome>,

    /// ProvisioningComplete events that arrived before the block was committed.
    /// This can happen when provisions reach quorum before we've seen the block.
    /// Maps tx_hash -> (provisions, first_arrival_height) for cleanup of stale entries.
    early_provisioning_complete: HashMap<Hash, (Vec<StateProvision>, u64)>,

    /// Proofs that arrived before tracking started.
    /// Tracks (shard_id, proof) pairs with first_arrival_height for cleanup of stale entries.
    early_certificates: HashMap<Hash, (Vec<(ShardGroupId, ShardExecutionProof)>, u64)>,

    // ═══════════════════════════════════════════════════════════════════════
    // Speculative Execution State
    // ═══════════════════════════════════════════════════════════════════════
    /// Cache of speculative execution results.
    /// Maps tx_hash -> SpeculativeResult
    speculative_results: HashMap<Hash, SpeculativeResult>,

    /// Transaction hashes currently being speculatively executed.
    /// Used for memory-based backpressure and to detect when speculation is in progress.
    speculative_in_flight_txs: HashSet<Hash>,

    /// Index: which speculative txs read from which nodes.
    /// Used for O(1) invalidation when a committed write touches a node.
    /// Maps node_id -> set of tx_hashes that read from that node.
    speculative_reads_index: HashMap<NodeId, HashSet<Hash>>,

    /// Pending speculative executions waiting for callback.
    /// Maps block_hash -> (list of transactions, height) being speculatively executed.
    /// Used to retrieve declared_reads when speculative execution completes.
    pending_speculative_executions: HashMap<Hash, (Vec<Arc<RoutableTransaction>>, u64)>,

    // ═══════════════════════════════════════════════════════════════════════
    // Speculative Execution Config
    // ═══════════════════════════════════════════════════════════════════════
    /// Maximum number of transactions to track speculatively (in-flight + cached).
    /// This is a memory limit to prevent unbounded growth.
    speculative_max_txs: usize,

    /// Number of rounds to pause speculation after a view change.
    /// This avoids wasted work when the network is unstable.
    view_change_cooldown_rounds: u64,

    /// Height at which the last view change occurred.
    /// Speculation is paused for a few rounds after view changes to avoid wasted work.
    last_view_change_height: u64,

    // ═══════════════════════════════════════════════════════════════════════
    // Speculative Execution Metrics (accumulated counters, reset on read)
    // ═══════════════════════════════════════════════════════════════════════
    /// Count of speculative executions started since last metrics read.
    speculative_started_count: u64,
    /// Count of speculative cache hits since last metrics read.
    /// Includes both early hits (speculation completed before commit) and
    /// late hits (commit arrived before speculation, but waited for it).
    speculative_cache_hit_count: u64,
    /// Count of "late hits" - speculation completed after commit but we waited.
    /// This is a subset of cache_hit_count, tracking the dedup optimization.
    speculative_late_hit_count: u64,
    /// Count of speculative cache misses since last metrics read.
    speculative_cache_miss_count: u64,
    /// Count of speculative results invalidated since last metrics read.
    speculative_invalidated_count: u64,

    // ═══════════════════════════════════════════════════════════════════════
    // Execution Certificate Cache (for fallback serving)
    // ═══════════════════════════════════════════════════════════════════════
    // ═══════════════════════════════════════════════════════════════════════
    // Expected Execution Certificate Tracking (Fallback Detection)
    // ═══════════════════════════════════════════════════════════════════════
    /// Expected execution certificates from remote shards.
    /// Populated when remote block headers with waves targeting our shard are seen.
    /// Cleared when the matching cert is received and verified.
    /// After timeout, triggers `RequestMissingExecutionCerts` fallback.
    expected_exec_certs: HashMap<(ShardGroupId, u64, WaveId), ExpectedExecCert>,

    /// Fulfilled execution cert keys — prevents late-arriving duplicate headers
    /// from re-registering expectations after certs have already been received.
    /// Maps (source_shard, block_height, wave_id) → local_height_when_fulfilled
    /// for age-based pruning using local time.
    fulfilled_exec_certs: HashMap<(ShardGroupId, u64, WaveId), u64>,

    // ═══════════════════════════════════════════════════════════════════════
    // Speculative Provision State
    // ═══════════════════════════════════════════════════════════════════════
    /// Block hashes with in-flight speculative provision prep.
    speculative_provision_in_flight: HashSet<Hash>,
    /// Cached speculative provision results, keyed by block_hash.
    speculative_provision_results: HashMap<Hash, CachedProvisions>,
    /// When commit arrives while speculation is in-flight, store full context
    /// so we can emit SendProvisions or fall back to FetchAndBroadcastProvisions.
    pending_provision_commits: HashMap<Hash, PendingProvisionCommit>,
}

impl Default for ExecutionState {
    fn default() -> Self {
        Self::new()
    }
}

/// Tracks an expected execution certificate that hasn't arrived yet.
#[derive(Debug, Clone)]
struct ExpectedExecCert {
    /// Local committed height when we first learned about this expected cert.
    discovered_at: u64,
    /// Local committed height when we last sent a fallback request, if any.
    /// `None` means never requested. Allows periodic re-requests with cooldown.
    last_requested_at: Option<u64>,
}

/// Number of blocks to wait before the first fallback request.
const EXEC_CERT_FALLBACK_TIMEOUT_BLOCKS: u64 = 10;

/// Number of blocks between repeated fallback requests for the same cert.
const EXEC_CERT_RETRY_INTERVAL_BLOCKS: u64 = 20;

/// Per-shard recipient lists for provision broadcasting.
type ShardRecipients = HashMap<ShardGroupId, Vec<ValidatorId>>;

/// Cached provision batches from speculative preparation.
struct CachedProvisions {
    batches: Vec<(ShardGroupId, ProvisionBatch, Vec<ValidatorId>)>,
    block_timestamp: u64,
}

/// Context stored when a block commits while speculative provisions are in-flight.
/// Contains everything needed to fall back to `FetchAndBroadcastProvisions` if
/// speculation returns empty.
struct PendingProvisionCommit {
    block_timestamp: u64,
    requests: Vec<ProvisionRequest>,
    source_shard: ShardGroupId,
    block_height: BlockHeight,
    shard_recipients: ShardRecipients,
}

/// Default maximum transactions for speculative execution (in-flight + cached).
pub const DEFAULT_SPECULATIVE_MAX_TXS: usize = 500;

/// Default number of rounds to pause speculation after a view change.
pub const DEFAULT_VIEW_CHANGE_COOLDOWN_ROUNDS: u64 = 3;

impl ExecutionState {
    /// Create a new execution state machine with default settings.
    pub fn new() -> Self {
        Self::with_speculative_config(
            DEFAULT_SPECULATIVE_MAX_TXS,
            DEFAULT_VIEW_CHANGE_COOLDOWN_ROUNDS,
        )
    }

    /// Create a new execution state machine with custom speculative execution config.
    ///
    /// # Arguments
    /// * `speculative_max_txs` - Maximum transactions to track speculatively (in-flight + cached)
    /// * `view_change_cooldown_rounds` - Rounds to pause speculation after a view change
    pub fn with_speculative_config(
        speculative_max_txs: usize,
        view_change_cooldown_rounds: u64,
    ) -> Self {
        Self {
            now: Duration::ZERO,
            execution_cache: ExecutionCache::new(),
            finalized_certificates: BTreeMap::new(),
            committed_height: 0,
            pending_provisioning: HashMap::new(),
            accumulators: HashMap::new(),
            vote_trackers: HashMap::new(),
            waves_with_ec: HashSet::new(),
            wave_assignments: HashMap::new(),
            early_votes: HashMap::new(),
            certificate_trackers: HashMap::new(),
            early_execution_results: HashMap::new(),
            early_provisioning_complete: HashMap::new(),
            early_certificates: HashMap::new(),
            speculative_results: HashMap::new(),
            speculative_in_flight_txs: HashSet::new(),
            speculative_reads_index: HashMap::new(),
            pending_speculative_executions: HashMap::new(),
            speculative_max_txs,
            view_change_cooldown_rounds,
            last_view_change_height: 0,
            speculative_started_count: 0,
            speculative_cache_hit_count: 0,
            speculative_late_hit_count: 0,
            speculative_cache_miss_count: 0,
            speculative_invalidated_count: 0,
            expected_exec_certs: HashMap::new(),
            fulfilled_exec_certs: HashMap::new(),
            speculative_provision_in_flight: HashSet::new(),
            speculative_provision_results: HashMap::new(),
            pending_provision_commits: HashMap::new(),
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Time Management
    // ═══════════════════════════════════════════════════════════════════════════

    /// Set the current time.
    pub fn set_time(&mut self, now: Duration) {
        self.now = now;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Execution Cache
    // ═══════════════════════════════════════════════════════════════════════════

    /// Collect per-certificate database updates for proposal building.
    ///
    /// Filters out aborted certificates (they carry no state changes) and returns
    /// only entries present in the execution cache. BFT uses this map after its
    /// own QC-chain dedup filtering.
    pub fn proposal_cert_updates(
        &self,
        certificates: &[Arc<TransactionCertificate>],
    ) -> HashMap<Hash, Arc<DatabaseUpdates>> {
        certificates
            .iter()
            .filter(|c| c.decision != TransactionDecision::Aborted)
            .filter_map(|c| {
                self.execution_cache
                    .get(&c.transaction_hash)
                    .map(|u| (c.transaction_hash, u.clone()))
            })
            .collect()
    }

    /// Collect database updates for a set of transaction hashes.
    ///
    /// Returns cheap `Arc` clones for entries present in the cache.
    /// Used by state root verification to gather per-certificate write sets.
    pub fn updates_for_tx_hashes(&self, tx_hashes: &[Hash]) -> Vec<Arc<DatabaseUpdates>> {
        tx_hashes
            .iter()
            .filter_map(|h| self.execution_cache.get(h).cloned())
            .collect()
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Wave Assignment
    // ═══════════════════════════════════════════════════════════════════════════

    /// Compute deterministic wave assignments for a block's transactions.
    ///
    /// Partitions transactions by their provision dependency set (remote shards
    /// needed). All validators compute identical assignments from the same block.
    ///
    /// Returns a map from WaveId to list of (tx_hash, participating_shards) in
    /// block order within each wave.
    fn assign_waves(
        &self,
        topology: &TopologySnapshot,
        transactions: &[Arc<RoutableTransaction>],
    ) -> BTreeMap<WaveId, Vec<(Hash, Vec<ShardGroupId>)>> {
        let local_shard = topology.local_shard();
        let mut waves: BTreeMap<WaveId, Vec<(Hash, Vec<ShardGroupId>)>> = BTreeMap::new();

        for tx in transactions {
            let tx_hash = tx.hash();

            // Compute provision dependency set = remote shards needed
            let all_shards: BTreeSet<ShardGroupId> = topology
                .all_shards_for_transaction(tx)
                .into_iter()
                .collect();

            let remote_shards: BTreeSet<ShardGroupId> = all_shards
                .iter()
                .filter(|&&s| s != local_shard)
                .copied()
                .collect();

            let wave_id = WaveId(remote_shards);
            let participating: Vec<ShardGroupId> = all_shards.into_iter().collect();

            waves
                .entry(wave_id)
                .or_default()
                .push((tx_hash, participating));
        }

        waves
    }

    /// Set up execution accumulators and vote trackers for a newly committed block.
    ///
    /// Creates a `ExecutionAccumulator` and `VoteTracker` per wave, and records
    /// the tx → wave mapping for later result routing.
    ///
    /// Returns any early execution votes that arrived before tracking was set up,
    /// so the caller can replay them through `on_execution_vote()`.
    fn setup_execution_tracking(
        &mut self,
        topology: &TopologySnapshot,
        block_hash: Hash,
        block_height: u64,
        transactions: &[Arc<RoutableTransaction>],
    ) -> Vec<ExecutionVote> {
        let waves = self.assign_waves(topology, transactions);
        let quorum = topology.local_quorum_threshold();
        let mut votes_to_replay = Vec::new();

        let local_vid = topology.local_validator_id();
        let local_committee = topology.local_committee();

        for (wave_id, txs) in waves {
            let key = (block_hash, wave_id.clone());

            // Record tx → wave assignments
            for (tx_hash, _) in &txs {
                self.wave_assignments
                    .insert(*tx_hash, (block_hash, wave_id.clone()));
            }

            // Create accumulator
            let accumulator =
                ExecutionAccumulator::new(wave_id.clone(), block_hash, block_height, txs);
            self.accumulators.insert(key.clone(), accumulator);

            // Only the wave leader creates a VoteTracker and aggregates votes.
            // Non-leaders receive the canonical EC from the wave leader via
            // on_wave_certificate → on_certificate_verified.
            let leader = hyperscale_types::wave_leader(&block_hash, &wave_id, local_committee);
            if local_vid == leader {
                let tracker = VoteTracker::new(wave_id, block_hash, quorum);
                self.vote_trackers.insert(key.clone(), tracker);

                // Collect early execution votes for caller to replay through on_execution_vote()
                if let Some(early_votes) = self.early_votes.remove(&key) {
                    tracing::debug!(
                        block_hash = ?block_hash,
                        wave = %key.1,
                        count = early_votes.len(),
                        "Replaying early execution votes"
                    );
                    votes_to_replay.extend(early_votes);
                }
            } else {
                // Non-leader: discard any buffered votes (we won't aggregate them)
                self.early_votes.remove(&key);
            }
        }

        // Replay any early execution results that arrived before wave setup
        // (e.g. speculative execution completing before on_block_committed).
        let early_tx_hashes: Vec<Hash> = self
            .early_execution_results
            .keys()
            .filter(|h| self.wave_assignments.contains_key(h))
            .copied()
            .collect();
        if !early_tx_hashes.is_empty() {
            tracing::debug!(
                block_hash = ?block_hash,
                count = early_tx_hashes.len(),
                "Replaying early execution results into accumulators"
            );
            for tx_hash in early_tx_hashes {
                if let Some(outcome) = self.early_execution_results.remove(&tx_hash) {
                    if let Some(wave_key) = self.wave_assignments.get(&tx_hash).cloned() {
                        if let Some(acc) = self.accumulators.get_mut(&wave_key) {
                            acc.record_result(tx_hash, outcome);
                        }
                    }
                }
            }
        }

        tracing::debug!(
            block_hash = ?block_hash,
            wave_count = self.accumulators.iter()
                .filter(|((bh, _), _)| *bh == block_hash)
                .count(),
            "Wave tracking set up for block"
        );

        votes_to_replay
    }

    /// Record a transaction execution result into the appropriate execution accumulator.
    ///
    /// Updates the accumulator silently. Votes are NOT emitted here — they are
    /// emitted during the block commit wave scan (`scan_complete_waves`), ensuring
    /// deterministic voting at each consensus height.
    pub fn record_execution_result(&mut self, tx_hash: Hash, outcome: TxExecutionOutcome) {
        let Some(wave_key) = self.wave_assignments.get(&tx_hash).cloned() else {
            // Wave not assigned yet (e.g. speculative execution completed before
            // on_block_committed created the wave). Buffer for replay.
            self.early_execution_results.insert(tx_hash, outcome);
            return;
        };

        let Some(accumulator) = self.accumulators.get_mut(&wave_key) else {
            return;
        };

        accumulator.record_result(tx_hash, outcome);
    }

    /// Record an abort intent into the appropriate execution accumulator.
    ///
    /// Record an abort intent into the appropriate execution accumulator.
    ///
    /// Abort intents are consensus-committed (deterministic) and ALWAYS override
    /// async execution results. This ensures all validators converge to the same
    /// receipt_root regardless of execution timing.
    ///
    /// Updates the accumulator silently. Votes are NOT emitted here — they are
    /// emitted during the block commit wave scan (`scan_complete_waves`).
    ///
    /// A missing wave assignment means the transaction already reached terminal
    /// state (TC committed) — the abort intent is a harmless late arrival.
    pub fn record_abort_intent(&mut self, tx_hash: Hash, reason: AbortReason) {
        let Some(wave_key) = self.wave_assignments.get(&tx_hash).cloned() else {
            tracing::debug!(
                tx_hash = %tx_hash,
                ?reason,
                committed_height = self.committed_height,
                "Abort intent: no wave assignment (already cleaned up)"
            );
            return;
        };

        let Some(accumulator) = self.accumulators.get_mut(&wave_key) else {
            tracing::debug!(
                tx_hash = %tx_hash,
                wave = %wave_key.1,
                "Abort intent: no accumulator for wave"
            );
            return;
        };

        let outcome = TxExecutionOutcome::Aborted { reason };
        accumulator.record_abort(tx_hash, outcome);
    }

    /// Scan all incomplete waves and return completion data for any that are ready.
    ///
    /// Called at each block commit AFTER abort intents have been processed.
    /// This is the SINGLE path to voting — votes are never emitted from
    /// `record_execution_result` or `record_abort_intent`.
    ///
    /// Returns a `CompletionData` for each wave that is complete at this height.
    /// Waves that already had an EC formed (vote tracker removed) are skipped.
    pub fn scan_complete_waves(&self) -> Vec<CompletionData> {
        let mut completions = Vec::new();

        for (key, accumulator) in &self.accumulators {
            // Skip waves that already have a canonical EC (aggregated by
            // wave leader, or received from wave leader).
            if self.waves_with_ec.contains(key) {
                continue;
            }

            if !accumulator.is_complete() {
                continue;
            }

            let Some((receipt_root, tx_outcomes)) = accumulator.build_data() else {
                continue;
            };

            completions.push(CompletionData {
                block_hash: accumulator.block_hash(),
                block_height: accumulator.block_height(),
                wave_id: accumulator.wave_id().clone(),
                receipt_root,
                tx_outcomes,
            });
        }

        completions
    }

    /// Process a completed execution batch: build receipt bundles, update cache, record outcomes.
    ///
    /// Moves receipt-bundle construction and cache insertion out of the node orchestrator.
    /// `committed_height` is the current BFT committed height (used for cache eviction tracking).
    pub fn on_execution_batch_completed(
        &mut self,
        results: Vec<ExecutionResult>,
        tx_outcomes: Vec<TxOutcome>,
        speculative: bool,
        committed_height: u64,
    ) -> Vec<Action> {
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
            let dominated = speculative && !self.is_speculative_in_flight_for_tx(&tx_hash);
            if !dominated {
                bundles.push(ReceiptBundle {
                    tx_hash,
                    ledger_receipt: Arc::new(result.ledger_receipt),
                    local_execution: Some(result.local_execution),
                    database_updates: Some(Arc::clone(&db_updates)),
                });
            }

            self.execution_cache
                .insert(tx_hash, db_updates, receipt_hash, committed_height);
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
        } else if speculative {
            // Expected after a view change: speculative_in_flight_txs
            // was cleared, so all results are dominated. Receipts from
            // canonical re-execution will be stored instead.
            tracing::debug!(
                "ExecutionBatchCompleted produced zero receipt bundles (speculative, post-view-change)"
            );
        } else {
            tracing::warn!(
                results_count = 0,
                "ExecutionBatchCompleted produced ZERO receipt bundles"
            );
        }

        // Record outcomes into execution accumulators silently.
        // Votes are emitted during the block commit wave scan, not here.
        for wr in tx_outcomes {
            self.record_execution_result(wr.tx_hash, wr.outcome);
        }

        actions
    }

    /// Scan complete waves and emit `SignAndSendExecutionVote` actions.
    ///
    /// This is the SINGLE path to execution voting. Call after abort intents
    /// have been processed so accumulator state is deterministic at this height.
    /// Each vote is targeted to the wave leader (N→1 routing).
    pub fn emit_vote_actions(&self, topology: &TopologySnapshot, vote_height: u64) -> Vec<Action> {
        let local_committee = topology.local_committee();
        self.scan_complete_waves()
            .into_iter()
            .map(|completion| {
                let target = hyperscale_types::wave_leader(
                    &completion.block_hash,
                    &completion.wave_id,
                    local_committee,
                );
                Action::SignAndSendExecutionVote {
                    block_hash: completion.block_hash,
                    block_height: completion.block_height,
                    vote_height,
                    wave_id: completion.wave_id,
                    receipt_root: completion.receipt_root,
                    tx_outcomes: completion.tx_outcomes,
                    target,
                }
            })
            .collect()
    }

    /// Process committed certificates: cross-check receipt hashes, remove finalized state,
    /// and invalidate conflicting speculative results.
    ///
    /// The caller is responsible for any BFT-side cleanup (e.g. `bft.remove_committed_transaction`).
    pub fn on_certificates_committed(&mut self, certificates: &[Arc<TransactionCertificate>]) {
        for cert in certificates {
            // Debug cross-check: verify our local execution produced the same
            // receipt_hash as the quorum-signed certificate. A mismatch indicates
            // an engine determinism bug (different outcome/events for same input).
            if let Some(local_receipt_hash) = self
                .execution_cache
                .get_receipt_hash(&cert.transaction_hash)
            {
                if let Some(ShardExecutionProof::Executed { receipt_hash, .. }) =
                    cert.shard_proofs.values().next()
                {
                    debug_assert_eq!(
                        local_receipt_hash,
                        *receipt_hash,
                        "receipt_hash mismatch for tx {}: local engine produced different \
                         outcome/events than certificate. This indicates an engine determinism bug.",
                        cert.transaction_hash,
                    );
                }
            }

            self.remove_finalized_certificate(&cert.transaction_hash, cert.decision);
            // Invalidate speculative results that read from nodes being written
            self.invalidate_speculative_on_commit(cert);
        }
    }

    /// Record abort intents from a committed block into execution accumulators.
    ///
    /// Abort intents override async execution results to ensure validator convergence.
    pub fn record_abort_intents(&mut self, intents: &[hyperscale_types::AbortIntent]) {
        for intent in intents {
            self.record_abort_intent(intent.tx_hash, intent.reason.clone());
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Wave Vote Handling
    // ═══════════════════════════════════════════════════════════════════════════

    /// Handle an execution vote received from another validator (or self).
    ///
    /// Only the wave leader aggregates votes. Non-leaders discard them.
    pub fn on_execution_vote(
        &mut self,
        topology: &TopologySnapshot,
        vote: ExecutionVote,
    ) -> Vec<Action> {
        let key = (vote.block_hash, vote.wave_id.clone());
        let validator_id = vote.validator;

        // Check if we're tracking this wave (only wave leaders have VoteTrackers)
        if !self.vote_trackers.contains_key(&key) {
            // If we have an accumulator for this wave but no VoteTracker,
            // we're a non-leader — discard the vote.
            if self.accumulators.contains_key(&key) {
                return vec![];
            }
            // No accumulator yet — block hasn't committed. Buffer for the
            // wave leader case (will be discarded in setup if non-leader).
            self.early_votes.entry(key).or_default().push(vote);
            return vec![];
        }

        // Skip verification for our own vote
        if validator_id == topology.local_validator_id() {
            return self.handle_verified_vote(topology, vote);
        }

        // Get public key for signature verification
        let Some(public_key) = topology.public_key(validator_id) else {
            tracing::warn!(
                validator = validator_id.0,
                "Unknown validator for execution vote"
            );
            return vec![];
        };

        let voting_power = topology.voting_power(validator_id).unwrap_or(0);

        let tracker = self.vote_trackers.get_mut(&key).unwrap();

        // buffer_unverified_vote handles dedup per (validator, vote_height).
        // Same validator can vote at multiple heights (round voting).
        if !tracker.buffer_unverified_vote(vote, public_key, voting_power) {
            return vec![];
        }

        self.maybe_trigger_vote_verification(key)
    }

    /// Check if we should trigger batch verification for a wave's votes.
    fn maybe_trigger_vote_verification(&mut self, key: (Hash, WaveId)) -> Vec<Action> {
        let Some(tracker) = self.vote_trackers.get_mut(&key) else {
            return vec![];
        };

        if !tracker.should_trigger_verification() {
            return vec![];
        }

        let votes = tracker.take_unverified_votes();
        if votes.is_empty() {
            return vec![];
        }

        tracing::debug!(
            block_hash = ?key.0,
            wave = %key.1,
            vote_count = votes.len(),
            "Dispatching execution vote batch verification"
        );
        vec![Action::VerifyAndAggregateExecutionVotes {
            wave_id: key.1,
            block_hash: key.0,
            votes,
        }]
    }

    /// Handle a verified execution vote (own vote or already-verified).
    fn handle_verified_vote(
        &mut self,
        topology: &TopologySnapshot,
        vote: ExecutionVote,
    ) -> Vec<Action> {
        let key = (vote.block_hash, vote.wave_id.clone());
        let voting_power = topology.voting_power(vote.validator).unwrap_or(0);

        let Some(tracker) = self.vote_trackers.get_mut(&key) else {
            return vec![];
        };

        tracker.add_verified_vote(vote, voting_power);

        let mut actions = self.check_vote_quorum(topology, key.clone());
        actions.extend(self.maybe_trigger_vote_verification(key));
        actions
    }

    /// Handle batch execution vote verification completed.
    pub fn on_votes_verified(
        &mut self,
        topology: &TopologySnapshot,
        wave_id: WaveId,
        block_hash: Hash,
        verified_votes: Vec<(ExecutionVote, u64)>,
    ) -> Vec<Action> {
        let key = (block_hash, wave_id);

        let Some(tracker) = self.vote_trackers.get_mut(&key) else {
            return vec![];
        };

        tracker.on_verification_complete();

        for (vote, power) in verified_votes {
            tracker.add_verified_vote(vote, power);
        }

        let mut actions = self.check_vote_quorum(topology, key.clone());
        actions.extend(self.maybe_trigger_vote_verification(key));
        actions
    }

    /// Check if quorum is reached for a wave's votes.
    fn check_vote_quorum(
        &mut self,
        topology: &TopologySnapshot,
        key: (Hash, WaveId),
    ) -> Vec<Action> {
        let Some(tracker) = self.vote_trackers.get_mut(&key) else {
            return vec![];
        };

        let Some((receipt_root, vote_height, _total_power)) = tracker.check_quorum() else {
            return vec![];
        };

        tracing::info!(
            block_hash = ?key.0,
            wave = %key.1,
            vote_height,
            "Execution vote quorum reached — aggregating certificate"
        );

        let votes = tracker.take_votes(&receipt_root, vote_height);
        let committee = topology.local_committee().to_vec();

        // Remove the vote tracker — this EC is the shard's final answer.
        // Mark wave as having an EC to stop re-voting in scan_complete_waves.
        self.vote_trackers.remove(&key);
        self.waves_with_ec.insert(key.clone());

        tracing::debug!(
            block_hash = ?key.0,
            wave = %key.1,
            votes = votes.len(),
            "Delegating BLS aggregation to crypto pool"
        );

        // tx_outcomes are extracted from votes by the aggregation handler
        // (all quorum votes carry identical outcomes).
        vec![Action::AggregateExecutionCertificate {
            wave_id: key.1,
            shard: topology.local_shard(),
            receipt_root,
            votes,
            committee,
        }]
    }

    /// Handle execution certificate aggregation completed.
    ///
    /// Called when the crypto pool finishes BLS aggregation for a wave's votes.
    /// Broadcasts the execution cert to remote shards, then extracts per-tx outcomes
    /// and feeds them to per-tx CertificateTrackers for finalization.
    pub fn on_certificate_aggregated(
        &mut self,
        topology: &TopologySnapshot,
        wave_id: WaveId,
        certificate: hyperscale_types::ExecutionCertificate,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        let local_vid = topology.local_validator_id();
        let block_hash = certificate.block_hash;

        // The wave_id IS the set of remote shards — no need to look up the
        // accumulator (which may have been pruned by the time the cert is
        // aggregated, especially with many shards where provision flow is slower).
        let remote_shards: Vec<ShardGroupId> = wave_id.0.iter().copied().collect();

        let certificate = Arc::new(certificate);

        // Cache the cert in io_loop for fallback serving — any node can serve
        // requests from remote shards if the wave leader fails.
        actions.push(Action::PersistExecutionCertificate {
            certificate: Arc::clone(&certificate),
        });

        // The wave leader broadcasts the EC to:
        // 1. Local peers — so they receive the canonical EC (same path as remote ECs)
        // 2. Remote shard validators — for cross-shard finalization
        {
            // Broadcast to local peers (all local committee minus self)
            let local_peers: Vec<ValidatorId> = topology
                .local_committee()
                .iter()
                .copied()
                .filter(|&v| v != local_vid)
                .collect();
            if !local_peers.is_empty() {
                actions.push(Action::BroadcastExecutionCertificate {
                    shard: topology.local_shard(),
                    certificate: Arc::clone(&certificate),
                    recipients: local_peers,
                });
            }

            // Broadcast to remote shard validators
            for target_shard in &remote_shards {
                let recipients: Vec<ValidatorId> = topology
                    .committee_for_shard(*target_shard)
                    .iter()
                    .copied()
                    .filter(|&v| v != local_vid)
                    .collect();
                actions.push(Action::BroadcastExecutionCertificate {
                    shard: *target_shard,
                    certificate: Arc::clone(&certificate),
                    recipients,
                });
            }
        }

        tracing::debug!(
            ?block_hash,
            wave = %wave_id,
            tx_count = certificate.tx_outcomes.len(),
            remote_shards = remote_shards.len(),
            "Wave leader broadcasting EC to local peers + remote shards"
        );

        // Feed each tx's outcome to per-tx CertificateTracker for finalization.
        // Deferred/aborted txs (Hash::ZERO) are filtered by handle_certificate_internal.
        let ec_hash = certificate.canonical_hash();
        for outcome in &certificate.tx_outcomes {
            let proof = outcome.to_shard_proof(ec_hash);

            actions.extend(self.handle_certificate_internal(
                topology,
                outcome.tx_hash,
                certificate.shard_group_id,
                proof,
            ));
        }

        actions
    }

    /// Handle an execution certificate received from another validator.
    ///
    /// This handles ECs from both:
    /// - The wave leader (local shard EC broadcast to local peers)
    /// - Remote shards (cross-shard EC for finalization)
    ///
    /// A execution cert covers many txs. Each tx is handled independently:
    /// - If tracker exists → needs verification, then feed proof
    /// - If already finalized → skip
    /// - If no tracker yet → buffer as early proof for later replay
    ///
    /// Delegates BLS signature verification to the crypto pool before processing
    /// any tracked txs. Buffered txs are replayed when their block commits.
    pub fn on_wave_certificate(
        &mut self,
        topology: &TopologySnapshot,
        cert: hyperscale_types::ExecutionCertificate,
    ) -> Vec<Action> {
        let shard = cert.shard_group_id;
        let current_height = self.committed_height;

        // Clear expected cert tracking and mark as fulfilled so late-arriving
        // duplicate headers don't re-register the expectation.
        let key = (shard, cert.block_height, cert.wave_id.clone());
        self.expected_exec_certs.remove(&key);
        self.fulfilled_exec_certs.insert(key, self.committed_height);

        // Buffer proofs for txs that don't have trackers yet (block not committed).
        // Skip txs that are already finalized.
        // If ANY tx has a tracker, we need to verify the execution cert signature.
        let ec_hash = cert.canonical_hash();
        let mut needs_verification = false;
        for outcome in &cert.tx_outcomes {
            if self.certificate_trackers.contains_key(&outcome.tx_hash) {
                needs_verification = true;
            } else if !self.finalized_certificates.contains_key(&outcome.tx_hash) {
                // No tracker, not finalized — buffer for later replay
                self.early_certificates
                    .entry(outcome.tx_hash)
                    .or_insert_with(|| (Vec::new(), current_height))
                    .0
                    .push((shard, outcome.to_shard_proof(ec_hash)));
            }
        }

        if !needs_verification {
            return vec![];
        }

        // Get public keys for the source shard's committee
        let committee = topology.committee_for_shard(shard);
        let public_keys: Vec<Bls12381G1PublicKey> = committee
            .iter()
            .filter_map(|&vid| topology.public_key(vid))
            .collect();

        if public_keys.len() != committee.len() {
            tracing::warn!(
                shard = shard.0,
                "Could not resolve all public keys for execution cert verification"
            );
            return vec![];
        }

        // Delegate signature verification to crypto pool
        vec![Action::VerifyExecutionCertificateSignature {
            certificate: cert,
            public_keys,
        }]
    }

    /// Handle execution certificate signature verification result.
    ///
    /// If valid, extract per-tx outcomes and feed to CertificateTrackers.
    /// Txs without trackers are buffered as early proofs for later replay.
    pub fn on_certificate_verified(
        &mut self,
        topology: &TopologySnapshot,
        certificate: hyperscale_types::ExecutionCertificate,
        valid: bool,
    ) -> Vec<Action> {
        if !valid {
            tracing::warn!(
                shard = certificate.shard_group_id.0,
                block_hash = ?certificate.block_hash,
                wave = %certificate.wave_id,
                "Invalid execution certificate signature"
            );
            return vec![];
        }

        let shard = certificate.shard_group_id;
        let current_height = self.committed_height;
        let ec_hash = certificate.canonical_hash();
        let mut actions = Vec::new();

        // If this is a local shard EC from the wave leader, mark the wave as
        // having an EC so non-leaders stop re-voting in scan_complete_waves,
        // and persist it for fallback serving to remote shards.
        if shard == topology.local_shard() {
            let wave_key = (certificate.block_hash, certificate.wave_id.clone());
            self.waves_with_ec.insert(wave_key);
            actions.push(Action::PersistExecutionCertificate {
                certificate: Arc::new(certificate.clone()),
            });
        }

        // Extract per-tx outcomes — feed to tracker if exists, buffer otherwise
        for outcome in &certificate.tx_outcomes {
            let proof = outcome.to_shard_proof(ec_hash);

            if self.certificate_trackers.contains_key(&outcome.tx_hash) {
                actions.extend(self.handle_certificate_internal(
                    topology,
                    outcome.tx_hash,
                    shard,
                    proof,
                ));
            } else if !self.finalized_certificates.contains_key(&outcome.tx_hash) {
                // Buffer for later replay when block commits
                self.early_certificates
                    .entry(outcome.tx_hash)
                    .or_insert_with(|| (Vec::new(), current_height))
                    .0
                    .push((shard, proof));
            }
        }

        actions
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Expected Execution Certificate Tracking
    // ═══════════════════════════════════════════════════════════════════════════

    /// Register expected execution certificates from a remote block header.
    ///
    /// Called when a remote shard's committed block header is received. For each
    /// wave in the header that includes our shard, we register an expected cert.
    /// If the cert doesn't arrive within the timeout, we request it via fallback.
    pub fn on_verified_remote_header(
        &mut self,
        topology: &TopologySnapshot,
        source_shard: ShardGroupId,
        block_height: u64,
        waves: &[WaveId],
    ) {
        let local_shard = topology.local_shard();

        for wave in waves {
            if wave.0.contains(&local_shard) {
                let key = (source_shard, block_height, wave.clone());
                // Don't re-register if this cert was already received.
                // Prevents late-arriving duplicate headers from causing
                // spurious fallback requests.
                if self.fulfilled_exec_certs.contains_key(&key) {
                    continue;
                }
                self.expected_exec_certs
                    .entry(key)
                    .or_insert(ExpectedExecCert {
                        discovered_at: self.committed_height,
                        last_requested_at: None,
                    });
            }
        }
    }

    /// Check for timed-out expected execution certs and emit fallback requests.
    ///
    /// Called during block commit processing. Returns actions for any certs
    /// that have exceeded the timeout.
    fn check_exec_cert_timeouts(&mut self, topology: &TopologySnapshot) -> Vec<Action> {
        let mut actions = Vec::new();
        let current_height = self.committed_height;
        for ((source_shard, block_height, wave_id), expected) in &mut self.expected_exec_certs {
            let age = current_height.saturating_sub(expected.discovered_at);

            let should_request = match expected.last_requested_at {
                // Never requested — use initial timeout
                None => age >= EXEC_CERT_FALLBACK_TIMEOUT_BLOCKS,
                // Previously requested — use retry interval
                Some(last) => {
                    current_height.saturating_sub(last) >= EXEC_CERT_RETRY_INTERVAL_BLOCKS
                }
            };

            if should_request {
                let is_retry = expected.last_requested_at.is_some();
                expected.last_requested_at = Some(current_height);
                let peers = topology.committee_for_shard(*source_shard).to_vec();
                tracing::warn!(
                    source_shard = source_shard.0,
                    block_height = block_height,
                    wave = %wave_id,
                    age,
                    retry = is_retry,
                    "Execution cert timeout — requesting fallback"
                );
                actions.push(Action::RequestMissingExecutionCerts {
                    source_shard: *source_shard,
                    block_height: *block_height,
                    wave_ids: vec![wave_id.clone()],
                    peers,
                });
            }
        }
        // Prune old entries that have been requested and are very stale,
        // BUT keep entries whose transactions still have active certificate
        // trackers waiting for the remote EC. Without this, txs whose local
        // EC formed but remote EC never arrived stop retrying and are stuck
        // permanently.
        self.expected_exec_certs.retain(|(_, _, wave_id), e| {
            let age = self.committed_height.saturating_sub(e.discovered_at);
            if age < 100 {
                return true;
            }
            // Check if any tx still needs the remote EC for this wave.
            // A tx needs it if it has either:
            // - An active certificate tracker (waiting for remote proofs to form TC)
            // - A wave assignment to a wave matching this wave_id (EC was sent,
            //   cannot abort — still retrying to get the remote EC)
            let has_waiting_tx = self
                .wave_assignments
                .iter()
                .any(|(_, (_, wid))| wid == wave_id);
            has_waiting_tx
        });

        // Prune fulfilled set using local height when fulfilled (not remote
        // block height, which can differ significantly across shards).
        let fulfilled_cutoff = self.committed_height.saturating_sub(100);
        self.fulfilled_exec_certs
            .retain(|_, &mut fulfilled_at| fulfilled_at > fulfilled_cutoff);

        actions
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Block Commit Handling
    // ═══════════════════════════════════════════════════════════════════════════

    /// Handle block committed - start executing transactions.
    #[instrument(skip(self, transactions), fields(
        height = height,
        block_hash = ?block_hash,
        tx_count = transactions.len()
    ))]
    #[allow(clippy::too_many_arguments)]
    pub fn on_block_committed(
        &mut self,
        topology: &TopologySnapshot,
        block_hash: Hash,
        height: u64,
        block_timestamp: u64,
        proposer: ValidatorId,
        transactions: Vec<Arc<RoutableTransaction>>,
    ) -> BlockCommittedOutput {
        let mut actions = Vec::new();
        let mut cross_shard_registrations = Vec::new();

        // ── Provision broadcasting (proposer only) ─────────────────────
        //
        // Provisioning is a block-level proposer duty: the proposer must
        // broadcast state entries for all cross-shard transactions in the
        // committed block, regardless of local execution state.
        let local_shard = topology.local_shard();
        let is_proposer = topology.local_validator_id() == proposer;

        if is_proposer {
            if let Some(cached) = self.take_speculative_provisions(&block_hash) {
                // Speculative provisions already built — send immediately
                tracing::debug!(
                    block_hash = ?block_hash,
                    batch_count = cached.batches.len(),
                    "Speculative provision cache HIT"
                );
                actions.push(Action::SendProvisions {
                    batches: cached.batches,
                    block_timestamp: cached.block_timestamp,
                });
            } else if self.speculative_provision_in_flight.remove(&block_hash) {
                // Speculation in-flight — store full fallback context so we can
                // either send cached results or fall back to FetchAndBroadcastProvisions
                // if speculation returns empty.
                tracing::debug!(
                    block_hash = ?block_hash,
                    "Speculative provisions in-flight — deferring to completion"
                );
                if let Some((requests, shard_recipients)) =
                    Self::build_provision_requests(topology, &transactions, local_shard)
                {
                    self.pending_provision_commits.insert(
                        block_hash,
                        PendingProvisionCommit {
                            block_timestamp,
                            requests,
                            source_shard: local_shard,
                            block_height: BlockHeight(height),
                            shard_recipients,
                        },
                    );
                }
            } else {
                // No speculation — fall back to existing path
                if let Some((requests, shard_recipients)) =
                    Self::build_provision_requests(topology, &transactions, local_shard)
                {
                    actions.push(Action::FetchAndBroadcastProvisions {
                        requests,
                        source_shard: local_shard,
                        block_height: BlockHeight(height),
                        block_timestamp,
                        shard_recipients,
                    });
                }
            }
        }

        // Update committed height before anything else — needed for timeout
        // calculations and pruning even when there are no new transactions.
        if height > self.committed_height {
            self.committed_height = height;
        }

        // Check for timed-out expected execution certs and prune stale entries.
        // Must run every block, not just when there are new transactions.
        actions.extend(self.check_exec_cert_timeouts(topology));

        // Prune ephemeral state (speculative execution, orphaned provisions).
        // Cross-shard resolution state (certificate trackers, finalized certs,
        // pending provisioning, execution cache, early arrivals) is only cleaned
        // up on terminal state — never by block-count timeout.
        self.prune_execution_state();
        self.prune_pending_speculative();
        self.cleanup_stale_speculative();
        self.prune_speculative_provisions();

        if transactions.is_empty() {
            return BlockCommittedOutput {
                actions,
                cross_shard_registrations,
            };
        }

        tracing::debug!(
            height = height,
            tx_count = transactions.len(),
            "Starting execution for new transactions"
        );

        // Set up wave tracking for this block's transactions.
        // Returns any early execution votes that arrived before tracking was ready.
        let early_votes =
            self.setup_execution_tracking(topology, block_hash, height, &transactions);
        for vote in early_votes {
            actions.extend(self.on_execution_vote(topology, vote));
        }

        // Separate single-shard and cross-shard transactions
        let (single_shard, cross_shard): (Vec<_>, Vec<_>) = transactions
            .into_iter()
            .partition(|tx| topology.is_single_shard_transaction(tx));

        // Handle single-shard transactions (voting, same as cross-shard)
        // All WRITE operations need BLS signature aggregation
        //
        // With inline signing, speculative execution has already signed and sent votes.
        // We just need to:
        // 1. Check if speculation completed (votes already sent) - skip execution
        // 2. Check if speculation is in-flight (votes will arrive soon) - skip execution
        // 3. Otherwise execute normally
        let mut txs_needing_execution = Vec::new();

        for tx in single_shard {
            let tx_hash = tx.hash();

            if self.take_speculative_result(&tx_hash).is_some() {
                // Speculation completed - results already cached
                self.speculative_in_flight_txs.remove(&tx_hash);
                tracing::debug!(
                    tx_hash = ?tx_hash,
                    "SPECULATIVE HIT: Results already cached, skipping execution"
                );
                actions.extend(self.start_single_shard_execution(topology, tx.clone()));
                actions.extend(self.try_record_speculative_wave_result(tx_hash));
            } else if self.speculative_in_flight_txs.contains(&tx_hash) {
                // Speculation in-flight - results will arrive when it completes.
                // This counts as a hit since we're skipping re-execution.
                //
                // Do NOT remove from speculative_in_flight_txs here — leaving
                // the tx tracked ensures that when the speculative
                // ExecutionBatchCompleted arrives, it passes the dominated
                // check and its receipts are stored. Cleanup happens in
                // on_speculative_execution_complete when SpeculativeExecutionComplete
                // is processed (the next event in the same batch).
                self.speculative_cache_hit_count += 1;
                self.speculative_late_hit_count += 1;
                tracing::debug!(
                    tx_hash = ?tx_hash,
                    "SPECULATIVE IN-FLIGHT: Results will arrive soon, skipping execution"
                );
                actions.extend(self.start_single_shard_execution(topology, tx.clone()));
                // If execution already completed (ExecutionBatchCompleted processed
                // before BlockCommitted but SpeculativeExecutionComplete hasn't been
                // processed yet), re-extract from cache. If execution hasn't completed
                // yet, cache will be empty and the later ExecutionBatchCompleted will
                // record wave results normally (wave tracking is now set up).
                actions.extend(self.try_record_speculative_wave_result(tx_hash));
            } else {
                // No speculation at all - execute normally
                tracing::debug!(
                    tx_hash = ?tx_hash,
                    speculative_results_count = self.speculative_results.len(),
                    in_flight_txs = self.speculative_in_flight_txs.len(),
                    "SPECULATIVE MISS: No cached result, executing normally"
                );
                self.record_speculative_cache_miss();
                txs_needing_execution.push(tx);
            }
        }

        // Block is now committed — remove the pending_speculative_executions
        // entry so that a late-arriving on_speculative_execution_complete knows
        // to discard results instead of caching zombies.
        self.pending_speculative_executions.remove(&block_hash);

        // Start execution tracking for transactions that need execution
        for tx in &txs_needing_execution {
            actions.extend(self.start_single_shard_execution(topology, tx.clone()));
        }

        // Batch execute transactions that didn't have cached results
        if !txs_needing_execution.is_empty() {
            actions.push(Action::ExecuteTransactions {
                block_hash,
                transactions: txs_needing_execution,
                state_root: Hash::from_bytes(&[0u8; 32]),
            });
        }

        // Handle cross-shard execution tracking
        let mut cross_shard_requests = Vec::new();
        for tx in cross_shard {
            actions.extend(self.start_cross_shard_execution(
                topology,
                tx,
                height,
                &mut cross_shard_requests,
                &mut cross_shard_registrations,
            ));
        }
        if !cross_shard_requests.is_empty() {
            actions.push(Action::ExecuteCrossShardTransactions {
                requests: cross_shard_requests,
            });
        }

        BlockCommittedOutput {
            actions,
            cross_shard_registrations,
        }
    }

    /// Start single-shard execution tracking.
    ///
    /// Sets up certificate tracking for finalization. Voting is handled by
    /// the wave path — no per-tx vote tracking needed.
    fn start_single_shard_execution(
        &mut self,
        topology: &TopologySnapshot,
        tx: Arc<RoutableTransaction>,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        let tx_hash = tx.hash();
        let local_shard = topology.local_shard();

        tracing::debug!(
            tx_hash = ?tx_hash,
            shard = local_shard.0,
            "Starting single-shard execution tracking"
        );

        // Start tracking certificates for finalization (single shard only)
        let participating_shards: BTreeSet<_> = [local_shard].into_iter().collect();
        let cert_tracker = CertificateTracker::new(tx_hash, participating_shards);
        self.certificate_trackers
            .insert(tx_hash, (cert_tracker, self.committed_height));

        // Replay any early proofs that arrived before tracking started.
        if let Some((early_proofs, _arrival_height)) = self.early_certificates.remove(&tx_hash) {
            tracing::debug!(
                tx_hash = ?tx_hash,
                count = early_proofs.len(),
                "Replaying early proofs for single-shard tx"
            );
            for (shard, proof) in early_proofs {
                actions.extend(self.handle_certificate_internal(topology, tx_hash, shard, proof));
            }
        }

        actions
    }

    /// Start cross-shard execution (Phase 1: State Provisioning).
    ///
    /// Provision broadcasting is handled at the block level via
    /// `FetchAndBroadcastProvisions` — this method only sets up tracking.
    fn start_cross_shard_execution(
        &mut self,
        topology: &TopologySnapshot,
        tx: Arc<RoutableTransaction>,
        height: u64,
        cross_shard_requests: &mut Vec<CrossShardExecutionRequest>,
        registrations: &mut Vec<CrossShardRegistration>,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        let tx_hash = tx.hash();
        let local_shard = topology.local_shard();

        // Identify all participating shards
        let participating_shards: BTreeSet<ShardGroupId> = topology
            .all_shards_for_transaction(&tx)
            .into_iter()
            .collect();

        tracing::debug!(
            tx_hash = ?tx_hash,
            shard = local_shard.0,
            participating = ?participating_shards,
            "Starting cross-shard execution"
        );

        // Start tracking provisioning
        // Find remote shards we need provisions from
        let remote_shards: BTreeSet<_> = participating_shards
            .iter()
            .filter(|&&s| s != local_shard)
            .copied()
            .collect();

        if remote_shards.is_empty() {
            // No remote state needed - shouldn't happen for cross-shard tx
            // but handle gracefully
            tracing::warn!(tx_hash = ?tx_hash, "Cross-shard tx with no remote shards");
        } else {
            // Register with provision coordinator (via structured output).
            registrations.push(CrossShardRegistration {
                tx_hash,
                required_shards: remote_shards,
                committed_height: BlockHeight(height),
            });

            // Store transaction for later execution (will execute when ProvisioningComplete arrives)
            self.pending_provisioning
                .insert(tx_hash, (tx.clone(), height));

            // Check if ProvisioningComplete arrived before the block committed
            if let Some((provisions, _arrival_height)) =
                self.early_provisioning_complete.remove(&tx_hash)
            {
                tracing::debug!(
                    tx_hash = ?tx_hash,
                    count = provisions.len(),
                    "Replaying early ProvisioningComplete"
                );
                if let Some(req) = self.on_provisioning_complete(topology, tx_hash, provisions) {
                    cross_shard_requests.push(req);
                }
            }
        }

        // Start tracking certificates for finalization
        let cert_tracker = CertificateTracker::new(tx_hash, participating_shards.clone());
        self.certificate_trackers
            .insert(tx_hash, (cert_tracker, self.committed_height));

        // Replay any early proofs that arrived before tracking started.
        if let Some((early_proofs, _arrival_height)) = self.early_certificates.remove(&tx_hash) {
            tracing::debug!(tx_hash = ?tx_hash, count = early_proofs.len(), "Replaying early proofs");
            for (shard, proof) in early_proofs {
                actions.extend(self.handle_certificate_internal(topology, tx_hash, shard, proof));
            }
        }

        actions
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Phase 2: Provisioning Complete
    // ═══════════════════════════════════════════════════════════════════════════

    /// Handle provisioning complete (all source shards have reached quorum).
    ///
    /// Called when ProvisionCoordinator emits `ProvisioningComplete`, meaning
    /// all required source shards have provided a quorum of verified provisions.
    /// This triggers cross-shard execution.
    ///
    /// If the block hasn't been committed yet (i.e., tx not in pending_provisioning),
    /// we buffer the provisions and replay when the block commits.
    /// Returns `Some(request)` if execution is ready, `None` if buffered.
    #[instrument(skip(self, provisions), fields(tx_hash = ?tx_hash))]
    pub fn on_provisioning_complete(
        &mut self,
        topology: &TopologySnapshot,
        tx_hash: Hash,
        provisions: Vec<StateProvision>,
    ) -> Option<CrossShardExecutionRequest> {
        let local_shard = topology.local_shard();

        // Get the transaction waiting for provisions
        let Some((tx, _height)) = self.pending_provisioning.remove(&tx_hash) else {
            // Block hasn't committed yet - buffer for later
            tracing::debug!(
                tx_hash = ?tx_hash,
                shard = local_shard.0,
                "Provisioning complete before block committed, buffering"
            );
            // Track arrival height for cleanup of stale entries
            let current_height = self.committed_height;
            self.early_provisioning_complete
                .insert(tx_hash, (provisions, current_height));
            return None;
        };

        tracing::debug!(
            tx_hash = ?tx_hash,
            shard = local_shard.0,
            provision_count = provisions.len(),
            "Provisioning complete, executing cross-shard transaction"
        );

        Some(CrossShardExecutionRequest {
            tx_hash,
            transaction: tx,
            provisions,
        })
    }

    /// Handle batch provisioning complete for multiple transactions.
    ///
    /// Returns an `ExecuteCrossShardTransactions` action for all transactions
    /// that are ready (block already committed). Transactions whose blocks
    /// haven't committed yet are buffered in `early_provisioning_complete`.
    pub fn on_batch_provisioning_complete(
        &mut self,
        topology: &TopologySnapshot,
        transactions: Vec<hyperscale_core::ProvisionedTransaction>,
    ) -> Vec<Action> {
        let requests: Vec<CrossShardExecutionRequest> = transactions
            .into_iter()
            .filter_map(|pt| self.on_provisioning_complete(topology, pt.tx_hash, pt.provisions))
            .collect();
        if requests.is_empty() {
            vec![]
        } else {
            vec![Action::ExecuteCrossShardTransactions { requests }]
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Phase 5: Finalization
    // ═══════════════════════════════════════════════════════════════════════════

    /// Internal proof handling (assumes tracking is active).
    #[instrument(level = "debug", skip(self, proof), fields(
        tx_hash = %tx_hash,
        cert_shard = cert_shard.0,
    ))]
    fn handle_certificate_internal(
        &mut self,
        topology: &TopologySnapshot,
        tx_hash: Hash,
        cert_shard: ShardGroupId,
        proof: ShardExecutionProof,
    ) -> Vec<Action> {
        let mut actions = Vec::new();

        let local_shard = topology.local_shard();
        let Some((tracker, _)) = self.certificate_trackers.get_mut(&tx_hash) else {
            tracing::debug!(
                tx_hash = ?tx_hash,
                cert_shard = cert_shard.0,
                local_shard = local_shard.0,
                "No certificate tracker for tx, ignoring proof"
            );
            return actions;
        };

        let complete = tracker.add_proof(cert_shard, proof);

        if complete {
            tracing::debug!(
                tx_hash = ?tx_hash,
                shards = tracker.certificate_count(),
                local_shard = local_shard.0,
                "Certificate tracker ready, creating TransactionCertificate"
            );

            // Create transaction certificate
            if let Some(tx_cert) = tracker.create_tx_certificate() {
                let accepted = tx_cert.decision == TransactionDecision::Accept;

                tracing::debug!(
                    tx_hash = ?tx_hash,
                    accepted = accepted,
                    local_shard = local_shard.0,
                    "TransactionCertificate created successfully"
                );

                // Eagerly persist certificate so peers can fetch it before block commit.
                // This is idempotent - storing twice (here and in put_block_denormalized) is safe.
                actions.push(Action::PersistTransactionCertificate {
                    certificate: tx_cert.clone(),
                });

                self.finalized_certificates
                    .insert(tx_hash, (Arc::new(tx_cert), self.committed_height));

                // Notify mempool that transaction execution is complete
                actions.push(Action::Continuation(ProtocolEvent::TransactionExecuted {
                    tx_hash,
                    accepted,
                }));
            } else {
                tracing::warn!(
                    tx_hash = ?tx_hash,
                    local_shard = local_shard.0,
                    "Failed to create TransactionCertificate despite all certs collected"
                );
            }

            // Remove tracker
            self.certificate_trackers.remove(&tx_hash);
        }

        actions
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Query Methods
    // ═══════════════════════════════════════════════════════════════════════════

    /// Get finalized certificates for block inclusion.
    pub fn get_finalized_certificates(&self) -> Vec<Arc<TransactionCertificate>> {
        self.finalized_certificates
            .values()
            .map(|(cert, _)| cert.clone())
            .collect()
    }

    /// Get a single finalized certificate by transaction hash.
    ///
    /// Returns certificates that have been finalized but not yet committed to a block.
    /// Once committed, certificates are persisted to storage and should be fetched from there.
    pub fn get_finalized_certificate(&self, tx_hash: &Hash) -> Option<Arc<TransactionCertificate>> {
        self.finalized_certificates
            .get(tx_hash)
            .map(|(cert, _)| cert.clone())
    }

    /// Remove a finalized certificate (after it's been included in a block).
    ///
    /// Cleans up all transaction tracking state. The certificate itself is already
    /// persisted to storage by this point and can be fetched from there by peers.
    pub fn remove_finalized_certificate(&mut self, tx_hash: &Hash, decision: TransactionDecision) {
        self.finalized_certificates.remove(tx_hash);

        // Evict from execution cache — writes have been applied to JVT at this point.
        self.execution_cache.remove(tx_hash);

        // Clean up all transaction tracking state now that it's finalized.
        // This is the same cleanup done by cleanup_transaction() for aborts/deferrals,
        // but we need to do it here for successful completions too.
        self.pending_provisioning.remove(tx_hash);

        // Remove this TX from the wave's expected set. The TC is canonical —
        // this TX is done and should no longer block the wave from completing.
        //
        // All validators process committed blocks identically, so the reduced
        // expected set is deterministic. The receipt_root will be computed over
        // the remaining TXs only, and all validators will agree.
        //
        // If the TX already has a result in the accumulator (execution completed
        // before the TC committed), remove_expected cleans it up. If not, the
        // TX is simply removed from the expected set, unblocking the wave.
        if let Some(wave_key) = self.wave_assignments.get(tx_hash).cloned() {
            if let Some(accumulator) = self.accumulators.get_mut(&wave_key) {
                let had_result = accumulator.has_result(tx_hash);
                let complete = accumulator.remove_expected(tx_hash);
                if !had_result {
                    tracing::info!(
                        tx_hash = %tx_hash,
                        wave = %wave_key.1,
                        ?decision,
                        complete,
                        "TC committed before local execution — removed from wave"
                    );
                }
            }
        }

        // Wave assignment cleanup — once removed, the accumulator becomes
        // eligible for pruning by prune_execution_state on the next cycle.
        self.wave_assignments.remove(tx_hash);

        self.certificate_trackers.remove(tx_hash);
        self.early_provisioning_complete.remove(tx_hash);
        self.early_certificates.remove(tx_hash);
    }

    /// Prune stale wave state (accumulators, vote trackers, early votes).
    ///
    /// Execution accumulators and vote trackers are keyed by (block_hash, wave_id).
    /// Prune wave state that is no longer needed.
    ///
    /// Only prunes accumulators (and their vote trackers) when they are old
    /// enough AND have no remaining wave_assignments pointing to them. Active
    /// wave_assignments mean the transaction has not yet reached terminal state
    /// (TC committed or abort completed), so the accumulator must stay alive to
    /// allow abort intents and late-arriving votes to resolve the transaction.
    ///
    /// Also prunes early_votes for waves that were never set up.
    fn prune_execution_state(&mut self) {
        // Build set of accumulator keys still referenced by active wave assignments.
        let active_keys: std::collections::HashSet<&(Hash, WaveId)> =
            self.wave_assignments.values().collect();

        // Prune accumulators only when no active wave assignments reference them.
        // Waves must be retained until they resolve (EC formed + TC committed),
        // regardless of age. Time-based pruning would destroy accumulator state
        // needed for abort intents to take effect.
        let before_acc = self.accumulators.len();
        self.accumulators.retain(|key, _| active_keys.contains(key));
        let pruned_acc = before_acc - self.accumulators.len();

        // Prune vote trackers and waves_with_ec — same keys as accumulators
        let before_vt = self.vote_trackers.len();
        self.vote_trackers
            .retain(|key, _| self.accumulators.contains_key(key));
        let pruned_vt = before_vt - self.vote_trackers.len();
        self.waves_with_ec
            .retain(|key| self.accumulators.contains_key(key));

        // Prune early execution votes that have been consumed (accumulator exists
        // and would have replayed them) or that are stale (50+ blocks old).
        // We must NOT prune votes for blocks that haven't committed yet — those
        // votes arrived before the accumulator was created and will be replayed
        // when setup_execution_tracking runs during on_block_committed.
        let ev_cutoff = self.committed_height.saturating_sub(50);
        let before_ev = self.early_votes.len();
        self.early_votes.retain(|key, votes| {
            // If the accumulator already exists, the votes were replayed during
            // setup_execution_tracking — safe to prune any leftovers.
            if self.accumulators.contains_key(key) {
                return false;
            }
            // No accumulator yet — keep unless stale.
            votes
                .first()
                .map(|v| v.block_height > ev_cutoff)
                .unwrap_or(false)
        });
        let pruned_ev = before_ev - self.early_votes.len();

        if pruned_acc > 0 || pruned_vt > 0 || pruned_ev > 0 {
            tracing::debug!(
                pruned_acc,
                pruned_vt,
                pruned_ev,
                "Pruned resolved wave state"
            );
        }
    }

    /// Prune stale pending speculative executions whose callbacks never arrived.
    fn prune_pending_speculative(&mut self) {
        let cutoff = self.committed_height.saturating_sub(50);

        let before = self.pending_speculative_executions.len();
        self.pending_speculative_executions
            .retain(|_, (_, height)| *height > cutoff);
        let pruned = before - self.pending_speculative_executions.len();

        if pruned > 0 {
            tracing::debug!(
                pruned,
                cutoff_height = cutoff,
                "Pruned stale pending speculative executions"
            );
        }
    }

    /// Prune stale speculative provision state.
    ///
    /// Entries are normally consumed by `on_block_committed` (cache hit) or
    /// `on_speculative_provisions_complete` (pending commit). This cleans up
    /// orphans from proposals that never committed. Cap-based since we don't
    /// track heights per hash — entries rarely accumulate beyond a handful.
    fn prune_speculative_provisions(&mut self) {
        if self.speculative_provision_results.len() > 10 {
            self.speculative_provision_results.clear();
        }
        if self.speculative_provision_in_flight.len() > 5 {
            self.speculative_provision_in_flight.clear();
        }
        if self.pending_provision_commits.len() > 5 {
            self.pending_provision_commits.clear();
        }
    }

    /// Check if a transaction is finalized (TC created from all shard ECs).
    pub fn is_finalized(&self, tx_hash: &Hash) -> bool {
        self.finalized_certificates.contains_key(tx_hash)
    }

    /// Returns the set of all finalized transaction hashes.
    ///
    /// Used by the node orchestrator to pass to BFT for abort intent filtering.
    pub fn finalized_tx_hashes(&self) -> std::collections::HashSet<Hash> {
        self.finalized_certificates.keys().copied().collect()
    }

    /// Check if we're waiting for provisioning to complete for a transaction.
    ///
    /// Note: Actual provision tracking is handled by ProvisionCoordinator.
    pub fn is_awaiting_provisioning(&self, tx_hash: &Hash) -> bool {
        self.pending_provisioning.contains_key(tx_hash)
    }

    /// Get debug info about certificate tracking state for a transaction.
    pub fn certificate_tracking_debug(&self, tx_hash: &Hash) -> String {
        let has_cert_tracker = self.certificate_trackers.contains_key(tx_hash);
        let early_cert_count = self
            .early_certificates
            .get(tx_hash)
            .map(|(v, _)| v.len())
            .unwrap_or(0);

        let cert_tracker_info = if let Some((tracker, _)) = self.certificate_trackers.get(tx_hash) {
            format!(
                "{}/{} certs",
                tracker.certificate_count(),
                tracker.expected_count()
            )
        } else {
            "no tracker".to_string()
        };

        format!(
            "cert_tracker={} ({}), early_certs={}",
            has_cert_tracker, cert_tracker_info, early_cert_count
        )
    }

    /// Cleanup all tracking state for a deferred or aborted transaction.
    ///
    /// Called when a transaction is deferred (livelock cycle) or aborted (timeout).
    /// This releases all resources associated with the transaction so it doesn't
    /// continue consuming memory or processing.
    ///
    /// IMPORTANT: If a finalized TransactionCertificate exists, we preserve it.
    /// The TC represents cross-shard consensus (all participating shards agreed on
    /// the execution result). A local deferral/abort cannot override that — the TC
    /// must be committed in the next block to supersede the deferral. Removing it
    /// here would cause split-brain: remote shards commit the TC while we discard it.
    ///
    /// Stale TCs (where execution happened locally but was never committed) are
    /// handled by `prune_finalized_certificates()` which runs on every block commit.
    pub fn cleanup_transaction(&mut self, tx_hash: &Hash) {
        // If the transaction is finalized (TC created), we must preserve ALL tracking state.
        // Removing the certificate_tracker, wave_assignment, or finalized_certificate
        // would prevent us from completing the TC when the remote EC arrives — causing
        // split-brain with remote shards that DO form the TC from our EC.
        if self.finalized_certificates.contains_key(tx_hash) {
            tracing::info!(
                tx_hash = %tx_hash,
                finalized = self.finalized_certificates.contains_key(tx_hash),
                "Skipping cleanup for finalized transaction \
                 (must complete TC to avoid split-brain with remote shards)"
            );
            return;
        }

        // Evict from execution cache — transaction is being retried or abandoned.
        self.execution_cache.remove(tx_hash);

        // Phase 1-2: Provisioning cleanup
        // Note: Provision tracking is handled by ProvisionCoordinator
        self.pending_provisioning.remove(tx_hash);

        // Phase 3-4: Vote cleanup

        // Wave voting cleanup
        if let Some(wave_key) = self.wave_assignments.remove(tx_hash) {
            // Don't remove the execution accumulator/tracker — other txs in the wave may still be active.
            // The execution accumulator will be cleaned up when all its txs are cleaned up or the block is abandoned.
            // Just remove this tx's assignment.
            let _ = wave_key;
        }

        // Phase 5: Certificate cleanup
        self.certificate_trackers.remove(tx_hash);

        // Early arrivals cleanup
        self.early_provisioning_complete.remove(tx_hash);
        self.early_certificates.remove(tx_hash);

        tracing::debug!(
            tx_hash = %tx_hash,
            "Cleaned up execution state for deferred/aborted transaction"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Speculative Execution
    // ═══════════════════════════════════════════════════════════════════════════

    /// Notify that a view change (round timeout) occurred at the given height.
    ///
    /// Speculation will be paused for a few rounds to avoid wasted work,
    /// since blocks proposed during instability may not commit.
    #[instrument(skip(self), fields(height = height))]
    pub fn on_view_change(&mut self, height: u64) {
        tracing::debug!(
            height,
            cooldown_rounds = self.view_change_cooldown_rounds,
            "View change detected - pausing speculation"
        );
        self.last_view_change_height = height;

        // Clear all speculative state — the old leader's block won't commit,
        // so cached results are stale and would waste the memory budget.
        self.speculative_in_flight_txs.clear();
        self.pending_speculative_executions.clear();
        for tx_hash in self.speculative_results.keys().copied().collect::<Vec<_>>() {
            self.remove_speculative_result(&tx_hash);
        }
    }

    /// Check if we should speculatively execute transactions at the given height.
    ///
    /// Returns false if:
    /// 1. Memory limit exceeded (too many in-flight + cached txs)
    /// 2. Within cooldown period after a view change
    pub fn should_speculative_execute(&self, height: u64) -> bool {
        // Don't speculate within cooldown period after view change
        if height <= self.last_view_change_height + self.view_change_cooldown_rounds {
            return false;
        }

        // Memory limit - don't cache unlimited results
        // In-flight txs will become cached results, so count both
        let total_speculative =
            self.speculative_results.len() + self.speculative_in_flight_txs.len();
        total_speculative < self.speculative_max_txs
    }

    /// Trigger speculative execution for single-shard transactions in a block.
    ///
    /// Called when a block header is received, before the block commits.
    /// Returns an action to execute the transactions speculatively.
    pub fn trigger_speculative_execution(
        &mut self,
        topology: &TopologySnapshot,
        block_hash: Hash,
        height: u64,
        transactions: Vec<Arc<RoutableTransaction>>,
    ) -> Vec<Action> {
        if !self.should_speculative_execute(height) {
            let in_cooldown =
                height <= self.last_view_change_height + self.view_change_cooldown_rounds;
            tracing::debug!(
                block_hash = ?block_hash,
                height,
                in_flight_txs = self.speculative_in_flight_txs.len(),
                cache_size = self.speculative_results.len(),
                in_cooldown,
                last_view_change = self.last_view_change_height,
                "Skipping speculative execution"
            );
            return vec![];
        }

        // Filter to single-shard transactions that aren't already cached or in-flight
        let single_shard_txs: Vec<_> = transactions
            .into_iter()
            .filter(|tx| topology.is_single_shard_transaction(tx))
            .filter(|tx| !self.speculative_results.contains_key(&tx.hash()))
            .filter(|tx| !self.speculative_in_flight_txs.contains(&tx.hash()))
            .collect();

        if single_shard_txs.is_empty() {
            return vec![];
        }

        tracing::info!(
            block_hash = ?block_hash,
            tx_count = single_shard_txs.len(),
            "SPECULATIVE TRIGGER: Starting speculative execution"
        );

        // Track in-flight txs (no block limit - only memory matters)
        for tx in &single_shard_txs {
            self.speculative_in_flight_txs.insert(tx.hash());
        }

        // Store transactions so we can get declared_reads when execution completes
        self.pending_speculative_executions
            .insert(block_hash, (single_shard_txs.clone(), height));

        // Track metrics
        self.speculative_started_count += single_shard_txs.len() as u64;

        vec![Action::SpeculativeExecute {
            block_hash,
            transactions: single_shard_txs,
        }]
    }

    /// Handle speculative execution completion callback.
    ///
    /// With inline signing, the votes have already been signed and sent by the runner.
    /// This callback just updates tracking state so we know to skip re-execution
    /// when the block commits.
    #[instrument(skip(self, tx_hashes), fields(block_hash = ?block_hash, tx_count = tx_hashes.len()))]
    pub fn on_speculative_execution_complete(
        &mut self,
        block_hash: Hash,
        tx_hashes: Vec<Hash>,
    ) -> Vec<Action> {
        tracing::info!(
            block_hash = ?block_hash,
            tx_count = tx_hashes.len(),
            "SPECULATIVE COMPLETE: Votes already sent, updating cache tracking"
        );

        // Get the transactions we were executing to retrieve their declared_reads.
        // If the entry is gone, the block already committed — just clean up
        // in-flight tracking and return. This prevents zombie entries from
        // accumulating in speculative_results and exhausting capacity.
        let Some((transactions, _)) = self.pending_speculative_executions.remove(&block_hash)
        else {
            for tx_hash in tx_hashes {
                self.speculative_in_flight_txs.remove(&tx_hash);
            }
            tracing::debug!(
                block_hash = ?block_hash,
                "Speculation completed for already-committed block, discarding results"
            );
            return Vec::new();
        };

        // Build a map from tx_hash to transaction for quick lookup
        let tx_map: HashMap<Hash, &Arc<RoutableTransaction>> =
            transactions.iter().map(|tx| (tx.hash(), tx)).collect();

        // Mark each transaction as speculatively executed (votes already sent)
        for tx_hash in tx_hashes {
            // Remove from in-flight tracking
            self.speculative_in_flight_txs.remove(&tx_hash);

            // Get the read set from the transaction's declared_reads
            let read_set: HashSet<NodeId> = tx_map
                .get(&tx_hash)
                .map(|tx| tx.declared_reads.iter().copied().collect())
                .unwrap_or_default();

            // Index for fast invalidation
            for node_id in &read_set {
                self.speculative_reads_index
                    .entry(*node_id)
                    .or_default()
                    .insert(tx_hash);
            }

            // Cache entry (no result needed - votes already sent)
            self.speculative_results.insert(
                tx_hash,
                SpeculativeResult {
                    read_set,
                    created_at: self.now,
                },
            );

            tracing::debug!(
                tx_hash = ?tx_hash,
                block_hash = ?block_hash,
                "Marked as speculatively executed"
            );
        }

        // No actions needed - votes were already sent by the runner
        Vec::new()
    }

    /// Invalidate speculative results that conflict with a committed certificate.
    ///
    /// Called when a transaction certificate is being committed. Any speculative
    /// result whose read set overlaps with the certificate's write set must be
    /// invalidated to ensure correctness.
    pub fn invalidate_speculative_on_commit(&mut self, certificate: &TransactionCertificate) {
        // Collect all nodes being written by this certificate
        let written_nodes: HashSet<NodeId> = certificate
            .shard_proofs
            .values()
            .flat_map(|proof| match proof {
                ShardExecutionProof::Executed { write_nodes, .. } => write_nodes.iter().copied(),
                ShardExecutionProof::Aborted { .. } => [].iter().copied(),
            })
            .collect();

        if written_nodes.is_empty() {
            return;
        }

        // Single-pass: collect tx_hashes to invalidate by iterating written nodes,
        // then remove each speculative result. We avoid cloning by collecting
        // into a Vec directly (HashSet dedup happens via speculative_results.remove).
        //
        // Note: We can't inline the removal because remove_speculative_result
        // mutates speculative_reads_index, which we're reading from.
        let to_invalidate: Vec<Hash> = written_nodes
            .iter()
            .filter_map(|node_id| self.speculative_reads_index.get(node_id))
            .flatten()
            .copied()
            .collect();

        // Remove invalidated results (speculative_results.remove handles dedup)
        for tx_hash in to_invalidate {
            // Only count and log if we actually removed something (handles duplicates)
            if self.speculative_results.contains_key(&tx_hash) {
                self.remove_speculative_result(&tx_hash);
                self.speculative_invalidated_count += 1;
                tracing::debug!(
                    tx_hash = ?tx_hash,
                    "Invalidated speculative execution due to state conflict"
                );
            }
        }
    }

    /// Remove a speculative result and clean up its index entries.
    fn remove_speculative_result(&mut self, tx_hash: &Hash) {
        if let Some(spec) = self.speculative_results.remove(tx_hash) {
            // Clean up reads index
            for node_id in &spec.read_set {
                if let Some(set) = self.speculative_reads_index.get_mut(node_id) {
                    set.remove(tx_hash);
                    if set.is_empty() {
                        self.speculative_reads_index.remove(node_id);
                    }
                }
            }
        }
    }

    /// Try to record a wave result from a speculative execution's cached data.
    ///
    /// When speculation completes before (or during) block commit, the
    /// `ExecutionBatchCompleted` event populated the execution cache but wave
    /// tracking wasn't set up yet, so the result was dropped. This re-extracts
    /// the result from the execution cache now that wave tracking is ready.
    ///
    /// Returns a `SignAndSendExecutionVote` action if the cache had data
    /// and the wave was completed, or empty if execution hasn't finished yet
    /// (the later `ExecutionBatchCompleted` will record normally).
    fn try_record_speculative_wave_result(&mut self, tx_hash: Hash) -> Vec<Action> {
        let Some(receipt_hash) = self.execution_cache.get_receipt_hash(&tx_hash) else {
            return vec![];
        };
        let write_nodes = self
            .execution_cache
            .get(&tx_hash)
            .map(|updates| crate::handlers::extract_write_nodes(updates))
            .unwrap_or_default();
        // Record silently — votes emitted during block commit wave scan.
        self.record_execution_result(
            tx_hash,
            TxExecutionOutcome::Executed {
                receipt_hash,
                success: true,
                write_nodes,
            },
        );
        vec![]
    }

    /// Try to use a cached speculative result for a transaction.
    ///
    /// Returns Some(result) if a valid cached result exists, None otherwise.
    /// Removes the result from the cache if found.
    ///
    /// Note: Call `record_speculative_cache_miss()` separately when falling back
    /// to normal execution for a transaction that was speculatively executed.
    ///
    /// With inline signing, this just returns true if the tx was speculatively
    /// executed (votes already sent). The caller should skip execution.
    pub fn take_speculative_result(&mut self, tx_hash: &Hash) -> Option<()> {
        if let Some(spec) = self.speculative_results.remove(tx_hash) {
            // Clean up reads index
            for node_id in &spec.read_set {
                if let Some(set) = self.speculative_reads_index.get_mut(node_id) {
                    set.remove(tx_hash);
                    if set.is_empty() {
                        self.speculative_reads_index.remove(node_id);
                    }
                }
            }

            self.speculative_cache_hit_count += 1;

            tracing::debug!(
                tx_hash = ?tx_hash,
                "Speculative hit - votes already sent"
            );

            Some(())
        } else {
            None
        }
    }

    /// Record a cache miss (called when falling back to normal execution).
    pub fn record_speculative_cache_miss(&mut self) {
        self.speculative_cache_miss_count += 1;
    }

    /// Check if a speculative result exists for a transaction.
    pub fn has_speculative_result(&self, tx_hash: &Hash) -> bool {
        self.speculative_results.contains_key(tx_hash)
    }

    /// Check if speculative execution is in flight for a transaction.
    pub fn is_speculative_in_flight_for_tx(&self, tx_hash: &Hash) -> bool {
        self.speculative_in_flight_txs.contains(tx_hash)
    }

    /// Cleanup stale speculative results that have exceeded the max age.
    ///
    /// Called periodically (e.g., on CleanupTimer) to prevent memory growth
    /// from speculative results that were never used.
    pub fn cleanup_stale_speculative(&mut self) {
        let now = self.now;
        let stale: Vec<Hash> = self
            .speculative_results
            .iter()
            .filter(|(_, spec)| now.saturating_sub(spec.created_at) > SPECULATIVE_MAX_AGE)
            .map(|(hash, _)| *hash)
            .collect();

        for tx_hash in stale {
            self.remove_speculative_result(&tx_hash);
            tracing::debug!(
                tx_hash = ?tx_hash,
                "Removed stale speculative result"
            );
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Speculative Provision Preparation
    // ═══════════════════════════════════════════════════════════════════════

    /// Build provision requests and shard recipients for cross-shard transactions.
    ///
    /// Returns `None` if there are no cross-shard transactions needing provisions.
    fn build_provision_requests(
        topology: &TopologySnapshot,
        transactions: &[Arc<RoutableTransaction>],
        local_shard: ShardGroupId,
    ) -> Option<(Vec<ProvisionRequest>, ShardRecipients)> {
        let local_vid = topology.local_validator_id();

        let mut provision_requests = Vec::new();
        for tx in transactions {
            if topology.is_single_shard_transaction(tx) {
                continue;
            }
            let mut owned_nodes: Vec<_> = tx
                .declared_reads
                .iter()
                .chain(tx.declared_writes.iter())
                .filter(|&node_id| topology.shard_for_node_id(node_id) == local_shard)
                .copied()
                .collect();
            owned_nodes.sort();
            owned_nodes.dedup();

            if !owned_nodes.is_empty() {
                let target_shards: Vec<_> = topology
                    .all_shards_for_transaction(tx)
                    .into_iter()
                    .filter(|&s| s != local_shard)
                    .collect();

                if !target_shards.is_empty() {
                    provision_requests.push(ProvisionRequest {
                        tx_hash: tx.hash(),
                        nodes: owned_nodes,
                        target_shards,
                    });
                }
            }
        }

        if provision_requests.is_empty() {
            return None;
        }

        let mut shard_recipients = HashMap::new();
        for req in &provision_requests {
            for &target_shard in &req.target_shards {
                shard_recipients.entry(target_shard).or_insert_with(|| {
                    topology
                        .committee_for_shard(target_shard)
                        .iter()
                        .copied()
                        .filter(|&v| v != local_vid)
                        .collect()
                });
            }
        }

        Some((provision_requests, shard_recipients))
    }

    /// Trigger speculative provision preparation at proposal time.
    ///
    /// Called after `ProposalBuilt` when the block includes certificates.
    /// Builds the provision request list and emits `SpeculativeProvisionPrep`
    /// to run on the Provisions pool while BFT voting proceeds.
    pub fn trigger_speculative_provisions(
        &mut self,
        topology: &TopologySnapshot,
        block_hash: Hash,
        height: u64,
        block_timestamp: u64,
        transactions: &[Arc<RoutableTransaction>],
        merged_updates: Arc<DatabaseUpdates>,
    ) -> Vec<Action> {
        let local_shard = topology.local_shard();

        let (provision_requests, shard_recipients) =
            match Self::build_provision_requests(topology, transactions, local_shard) {
                Some(result) => result,
                None => return vec![],
            };

        // parent_height = height - 1 (the last committed block)
        let parent_height = self.committed_height;

        self.speculative_provision_in_flight.insert(block_hash);

        tracing::debug!(
            block_hash = ?block_hash,
            height = height,
            request_count = provision_requests.len(),
            parent_height = parent_height,
            "Triggering speculative provision preparation"
        );

        vec![Action::SpeculativeProvisionPrep {
            block_hash,
            requests: provision_requests,
            source_shard: local_shard,
            block_height: BlockHeight(height),
            block_timestamp,
            shard_recipients,
            merged_updates,
            parent_height,
        }]
    }

    /// Handle speculative provision preparation completion.
    ///
    /// Caches the result. If the block has already committed while speculation
    /// was in-flight, immediately emits `SendProvisions`.
    pub fn on_speculative_provisions_complete(
        &mut self,
        block_hash: Hash,
        batches: Vec<(ShardGroupId, ProvisionBatch, Vec<ValidatorId>)>,
        block_timestamp: u64,
    ) -> Vec<Action> {
        self.speculative_provision_in_flight.remove(&block_hash);

        // If batches are empty (e.g., SimStorage fallback), fall back to
        // FetchAndBroadcastProvisions if a commit is pending.
        if batches.is_empty() {
            if let Some(pending) = self.pending_provision_commits.remove(&block_hash) {
                tracing::debug!(
                    block_hash = ?block_hash,
                    "Speculative provision prep returned empty — falling back to FetchAndBroadcastProvisions"
                );
                return vec![Action::FetchAndBroadcastProvisions {
                    requests: pending.requests,
                    source_shard: pending.source_shard,
                    block_height: pending.block_height,
                    block_timestamp: pending.block_timestamp,
                    shard_recipients: pending.shard_recipients,
                }];
            }
            tracing::debug!(
                block_hash = ?block_hash,
                "Speculative provision prep returned empty — no pending commit"
            );
            return vec![];
        }

        // If commit already happened while we were preparing
        if let Some(pending) = self.pending_provision_commits.remove(&block_hash) {
            tracing::debug!(
                block_hash = ?block_hash,
                "Speculative provisions complete — commit was pending, sending now"
            );
            return vec![Action::SendProvisions {
                batches,
                block_timestamp: pending.block_timestamp,
            }];
        }

        // Cache for later use at commit time
        self.speculative_provision_results.insert(
            block_hash,
            CachedProvisions {
                batches,
                block_timestamp,
            },
        );

        vec![]
    }

    /// Take cached speculative provisions for a block, if available.
    fn take_speculative_provisions(&mut self, block_hash: &Hash) -> Option<CachedProvisions> {
        self.speculative_provision_results.remove(block_hash)
    }

    /// Get the number of cached speculative results.
    pub fn speculative_cache_size(&self) -> usize {
        self.speculative_results.len()
    }

    /// Get the number of transactions with speculative execution in flight.
    pub fn speculative_in_flight_count(&self) -> usize {
        self.speculative_in_flight_txs.len()
    }

    /// Get execution memory statistics for monitoring collection sizes.
    pub fn memory_stats(&self) -> ExecutionMemoryStats {
        ExecutionMemoryStats {
            cache_entries: self.execution_cache.len(),
            finalized_certificates: self.finalized_certificates.len(),
            pending_provisioning: self.pending_provisioning.len(),
            accumulators: self.accumulators.len(),
            vote_trackers: self.vote_trackers.len(),
            early_votes: self.early_votes.len(),
            certificate_trackers: self.certificate_trackers.len(),
            speculative_results: self.speculative_results.len(),
            expected_exec_certs: self.expected_exec_certs.len(),
            speculative_provision_in_flight: self.speculative_provision_in_flight.len(),
            speculative_provision_results: self.speculative_provision_results.len(),
            pending_provision_commits: self.pending_provision_commits.len(),
        }
    }

    /// Get and reset speculative execution metrics.
    ///
    /// Returns (started, cache_hits, late_hits, cache_misses, invalidated) and resets counters to 0.
    /// Note: late_hits is a subset of cache_hits (both are incremented for late hits).
    pub fn take_speculative_metrics(&mut self) -> (u64, u64, u64, u64, u64) {
        let metrics = (
            self.speculative_started_count,
            self.speculative_cache_hit_count,
            self.speculative_late_hit_count,
            self.speculative_cache_miss_count,
            self.speculative_invalidated_count,
        );
        self.speculative_started_count = 0;
        self.speculative_cache_hit_count = 0;
        self.speculative_late_hit_count = 0;
        self.speculative_cache_miss_count = 0;
        self.speculative_invalidated_count = 0;
        metrics
    }

    /// Get the number of cross-shard transactions currently in flight.
    ///
    /// Counts unique transaction hashes across all cross-shard tracking phases:
    /// - Provisioning phase (waiting for state provisions from other shards)
    /// - Vote aggregation phase (waiting for vote quorum)
    /// - Certificate collection phase (waiting for certificates from all shards)
    ///
    /// Note: Actual provision tracking is handled by ProvisionCoordinator.
    /// This counts transactions in pending_provisioning and certificate_trackers.
    pub fn cross_shard_pending_count(&self) -> usize {
        // Use a HashSet to count unique transactions since a tx might be in multiple phases
        let mut pending_txs = HashSet::new();

        // Phase 1-2: Waiting for provisioning (tracked by ProvisionCoordinator)
        pending_txs.extend(self.pending_provisioning.keys());

        // Phase 3-5: Vote aggregation and certificate collection
        // Cross-shard txs will have certificate_trackers with multiple shards.
        for (tx_hash, (tracker, _)) in &self.certificate_trackers {
            if tracker.expected_count() > 1 {
                pending_txs.insert(*tx_hash);
            }
        }

        pending_txs.len()
    }
}

impl std::fmt::Debug for ExecutionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecutionState")
            .field("finalized_certificates", &self.finalized_certificates.len())
            .field("pending_provisioning", &self.pending_provisioning.len())
            .field("certificate_trackers", &self.certificate_trackers.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::test_utils::test_transaction;
    use hyperscale_types::{
        generate_bls_keypair, Bls12381G1PrivateKey, ValidatorInfo, ValidatorSet,
    };

    fn make_test_topology() -> TopologySnapshot {
        let keys: Vec<Bls12381G1PrivateKey> = (0..4).map(|_| generate_bls_keypair()).collect();

        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| ValidatorInfo {
                validator_id: ValidatorId(i as u64),
                public_key: k.public_key(),
                voting_power: 1,
            })
            .collect();
        let validator_set = ValidatorSet::new(validators);

        TopologySnapshot::new(ValidatorId(0), 1, validator_set)
    }

    fn make_test_state() -> ExecutionState {
        ExecutionState::new()
    }

    #[test]
    fn test_execution_state_creation() {
        let state = make_test_state();
        assert!(state.finalized_certificates.is_empty());
    }

    #[test]
    fn test_single_shard_execution_flow() {
        let mut state = make_test_state();
        let topology = make_test_topology();

        let tx = test_transaction(1);
        let tx_hash = tx.hash();
        let block_hash = Hash::from_bytes(b"block1");

        // Block committed with transaction
        let actions = state
            .on_block_committed(
                &topology,
                block_hash,
                1,
                1000,
                ValidatorId(0),
                vec![Arc::new(tx.clone())],
            )
            .actions;

        // Should request execution (single-shard path) and set up wave tracking
        assert!(!actions.is_empty());
        // First action should be ExecuteTransactions
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::ExecuteTransactions { .. })));

        // Certificate tracker should be set up for finalization
        assert!(state.certificate_trackers.contains_key(&tx_hash));
    }

    #[test]
    fn test_speculative_hit_before_commit() {
        // Scenario: Speculation completes BEFORE block commits (normal HIT)
        // With inline signing, votes are already sent - we just skip re-execution.
        let mut state = make_test_state();
        let topology = make_test_topology();

        let tx = Arc::new(test_transaction(1));
        let tx_hash = tx.hash();
        let block_hash = Hash::from_bytes(b"block1");

        // Use height past view change cooldown (default cooldown is 3 rounds)
        let height = 10;

        // Trigger speculative execution
        let actions =
            state.trigger_speculative_execution(&topology, block_hash, height, vec![tx.clone()]);
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::SpeculativeExecute { .. })));
        assert!(state.speculative_in_flight_txs.contains(&tx_hash));

        // Speculation completes (with inline signing, votes are already sent by runner)
        let tx_hashes = vec![tx_hash];
        let _ = state.on_speculative_execution_complete(block_hash, tx_hashes);

        // Should be marked as speculatively executed
        assert!(state.has_speculative_result(&tx_hash));
        assert!(!state.speculative_in_flight_txs.contains(&tx_hash));

        // Now block commits - should skip execution (votes already sent)
        let actions = state
            .on_block_committed(
                &topology,
                block_hash,
                height,
                10000,
                ValidatorId(0),
                vec![tx],
            )
            .actions;

        // Should NOT emit ExecuteTransactions (speculation was used, votes already sent)
        assert!(!actions
            .iter()
            .any(|a| matches!(a, Action::ExecuteTransactions { .. })));

        // No SignExecutionResults needed - votes were signed inline
    }

    #[test]
    fn test_speculative_in_flight_at_commit() {
        // Scenario: Block commits WHILE speculation is in-flight
        // With inline signing, we just wait - votes will arrive soon.
        let mut state = make_test_state();
        let topology = make_test_topology();

        let tx = Arc::new(test_transaction(1));
        let tx_hash = tx.hash();
        let block_hash = Hash::from_bytes(b"block1");

        // Use height past view change cooldown (default cooldown is 3 rounds)
        let height = 10;

        // Trigger speculative execution
        let actions =
            state.trigger_speculative_execution(&topology, block_hash, height, vec![tx.clone()]);
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::SpeculativeExecute { .. })));
        assert!(state.speculative_in_flight_txs.contains(&tx_hash));

        // Block commits WHILE speculation is in-flight
        let commit_actions = state
            .on_block_committed(
                &topology,
                block_hash,
                height,
                10000,
                ValidatorId(0),
                vec![tx],
            )
            .actions;

        // Should NOT emit ExecuteTransactions (votes will arrive from speculation)
        assert!(!commit_actions
            .iter()
            .any(|a| matches!(a, Action::ExecuteTransactions { .. })));

        // In-flight kept so ExecutionBatchCompleted can store receipts
        assert!(state.speculative_in_flight_txs.contains(&tx_hash));

        // pending_speculative_executions removed on commit
        assert!(!state
            .pending_speculative_executions
            .contains_key(&block_hash));

        // Speculation completes later (votes already sent by runner)
        // Since the block already committed, results are discarded — no zombies
        let tx_hashes = vec![tx_hash];
        let complete_actions = state.on_speculative_execution_complete(block_hash, tx_hashes);

        // No actions needed - votes were already sent by the runner
        assert!(complete_actions.is_empty());
        assert!(!state.speculative_in_flight_txs.contains(&tx_hash));
        // No zombie entries in speculative_results
        assert!(!state.speculative_results.contains_key(&tx_hash));
    }

    #[test]
    fn test_speculative_miss_no_speculation() {
        // Scenario: No speculation was triggered (MISS - normal execution)
        let mut state = make_test_state();
        let topology = make_test_topology();

        let tx = Arc::new(test_transaction(1));
        let block_hash = Hash::from_bytes(b"block1");

        // Block commits without any speculation
        let actions = state
            .on_block_committed(&topology, block_hash, 1, 1000, ValidatorId(0), vec![tx])
            .actions;

        // Should emit ExecuteTransactions (no speculation to use)
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::ExecuteTransactions { .. })));
    }

    // ========================================================================
    // Crypto Verification Tests - Using real BLS signatures
    // ========================================================================

    #[test]
    fn test_shard_execution_proof_basic() {
        use hyperscale_types::ShardExecutionProof;

        let receipt_hash = Hash::from_bytes(b"commitment");
        let proof = ShardExecutionProof::Executed {
            receipt_hash,
            success: true,
            write_nodes: vec![],
            ec_hash: Hash::ZERO,
        };

        assert!(proof.is_success());
        assert_eq!(proof.receipt_hash_or_zero(), receipt_hash);
        assert!(!proof.is_aborted());
    }

    #[test]
    fn test_batch_verify_execution_votes_different_messages() {
        use hyperscale_test_helpers::TestCommittee;

        let committee = TestCommittee::new(4, 42);
        let shard = ShardGroupId(0);
        let block = Hash::from_bytes(b"block");
        let wave_id = WaveId::zero();

        // Different receipt roots = different messages
        let root1 = Hash::from_bytes(b"root1");
        let root2 = Hash::from_bytes(b"root2");
        let root3 = Hash::from_bytes(b"root3");

        let msg1 = hyperscale_types::exec_vote_message(&block, 1, 1, &wave_id, shard, &root1, 1);
        let msg2 = hyperscale_types::exec_vote_message(&block, 1, 1, &wave_id, shard, &root2, 1);
        let msg3 = hyperscale_types::exec_vote_message(&block, 1, 1, &wave_id, shard, &root3, 1);

        let sig1 = committee.keypair(0).sign_v1(&msg1);
        let sig2 = committee.keypair(1).sign_v1(&msg2);
        let sig3 = committee.keypair(2).sign_v1(&msg3);

        let messages: Vec<&[u8]> = vec![&msg1, &msg2, &msg3];
        let signatures = vec![sig1, sig2, sig3];
        let pubkeys: Vec<_> = (0..3).map(|i| *committee.public_key(i)).collect();

        let results =
            hyperscale_types::batch_verify_bls_different_messages(&messages, &signatures, &pubkeys);

        assert_eq!(
            results,
            vec![true, true, true],
            "All signatures should verify"
        );
    }

    #[test]
    fn test_batch_verify_execution_votes_partial_failure() {
        use hyperscale_test_helpers::TestCommittee;

        let committee = TestCommittee::new(4, 42);
        let shard = ShardGroupId(0);
        let block = Hash::from_bytes(b"block");
        let wave_id = WaveId::zero();

        let root1 = Hash::from_bytes(b"root1");
        let root2 = Hash::from_bytes(b"root2");

        let msg1 = hyperscale_types::exec_vote_message(&block, 1, 1, &wave_id, shard, &root1, 1);
        let msg2 = hyperscale_types::exec_vote_message(&block, 1, 1, &wave_id, shard, &root2, 1);

        // First is valid, second is signed with wrong key
        let sig1 = committee.keypair(0).sign_v1(&msg1);
        let sig2 = committee.keypair(3).sign_v1(&msg2); // Wrong key! Should be keypair 1

        let messages: Vec<&[u8]> = vec![&msg1, &msg2];
        let signatures = vec![sig1, sig2];
        let pubkeys = vec![
            *committee.public_key(0),
            *committee.public_key(1), // Verifying with key 1
        ];

        let results =
            hyperscale_types::batch_verify_bls_different_messages(&messages, &signatures, &pubkeys);

        assert_eq!(
            results,
            vec![true, false],
            "Second signature should fail verification"
        );
    }
}
