//! Execution state machine.
//!
//! Drives transaction execution after blocks are committed. Transactions are
//! grouped into waves (same provision dependency set within a block) and each
//! wave runs through its lifecycle inside a [`WaveState`](crate::WaveState).
//!
//! # Transaction Types
//!
//! - **Single-shard**: Dispatched immediately at block commit; local quorum
//!   votes produce an execution certificate.
//! - **Cross-shard**: Dispatched once the wave's provisions assemble, then
//!   voted and cross-shard-finalized.
//!
//! # Cross-Shard Atomic Execution Protocol
//!
//! ## Phase 1: State Provisioning
//! When a block commits with cross-shard transactions, the block proposer broadcasts
//! state provisions (with merkle inclusion proofs) to target shards. Provisions are
//! committed in blocks via `provision_root` — all validators have the same data.
//!
//! ## Phase 2: Conflict Detection
//! At commit time, the [`ConflictDetector`](crate::conflict::ConflictDetector) checks
//! committed provisions for node-ID overlap with local cross-shard transactions.
//! Overlapping transactions are aborted (lower hash wins) deterministically.
//!
//! ## Phase 3: Wave-Atomic Execution
//! Once every tx in a wave is provisioned (or at block commit for single-shard
//! waves), the whole wave dispatches atomically via
//! `ExecuteTransactions` / `ExecuteCrossShardTransactions`.
//!
//! ## Phase 4: Vote Aggregation
//! Validators send execution votes to the wave leader. When the leader collects
//! 2f+1 voting power agreeing on the same receipt hash, it aggregates an
//! execution certificate and broadcasts it to local peers and remote shards.
//!
//! ## Phase 5: Finalization
//! Validators collect shard execution proofs from all participating shards. When all
//! proofs are received, a WaveCertificate is created.

use hyperscale_core::{Action, CrossShardExecutionRequest, ProtocolEvent, ProvisionRequest};
use hyperscale_types::{
    Block, BlockHeight, Bls12381G1PublicKey, ExecutionCertificate, ExecutionOutcome, ExecutionVote,
    Hash, LocalExecutionEntry, NodeId, Provision, ReceiptBundle, RoutableTransaction, ShardGroupId,
    StateProvision, TopologySnapshot, TransactionDecision, TxOutcome, ValidatorId, WaveCertificate,
    WaveId,
};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tracing::instrument;

use crate::conflict::{ConflictDetector, DetectedConflict};
use crate::vote_tracker::VoteTracker;
use crate::wave_state::WaveState;

/// Data returned when a wave is ready for voting.
///
/// The state machine produces this; the io_loop uses it to sign the execution vote
/// and broadcast (since the state machine doesn't hold the signing key).
#[derive(Debug)]
pub struct CompletionData {
    /// Block this wave belongs to.
    pub block_hash: Hash,
    /// Block height (= wave_starting_height).
    pub block_height: u64,
    /// Relative vote height (blocks since wave started).
    pub vote_height: u64,
    /// Wave identifier.
    pub wave_id: WaveId,
    /// Merkle root over per-tx outcome leaves (cross-shard agreement).
    pub global_receipt_root: Hash,
    /// Per-tx outcomes in wave order.
    pub tx_outcomes: Vec<hyperscale_types::TxOutcome>,
}

// FinalizedWave is defined in hyperscale_types.
use hyperscale_types::FinalizedWave;

/// Execution memory statistics for monitoring collection sizes.
#[derive(Clone, Copy, Debug, Default)]
pub struct ExecutionMemoryStats {
    pub receipt_cache: usize,
    pub finalized_wave_certificates: usize,
    pub waves: usize,
    pub vote_trackers: usize,
    pub early_votes: usize,
    pub expected_exec_certs: usize,
    pub verified_provisions: usize,
    pub required_provision_shards: usize,
    pub received_provision_shards: usize,
    pub waves_with_ec: usize,
    pub pending_vote_retries: usize,
    pub wave_assignments: usize,
    pub early_wave_attestations: usize,
    pub pending_routing: usize,
    pub fulfilled_exec_certs: usize,
}

/// Execution state machine.
///
/// Handles transaction execution after blocks are committed.
pub struct ExecutionState {
    /// Current time.
    now: Duration,

    /// In-memory receipt cache — holds ReceiptBundles from execution until
    /// they are consumed by `finalize_wave` (moved into `FinalizedWave.receipts`)
    /// or cleaned up on abort/deferral.
    receipt_cache: HashMap<Hash, ReceiptBundle>,

    /// Finalized wave certificates ready for block inclusion.
    /// Uses BTreeMap for deterministic iteration order (keyed by WaveId).
    finalized_wave_certificates: BTreeMap<WaveId, FinalizedWave>,

    /// Current committed height for pruning stale entries.
    committed_height: u64,

    /// Height of the most recent block whose full content (txs, certs,
    /// provisions) was locally resolvable AND whose state transitions have
    /// been applied. Distinct from `committed_height`, which advances on BFT
    /// QC alone; execution may lag when data is still being fetched.
    /// Invariant: `processed_height <= committed_height`.
    processed_height: u64,

    // ═══════════════════════════════════════════════════════════════════════
    // Provisioning
    // ═══════════════════════════════════════════════════════════════════════
    /// Verified provisions stored by tx_hash. Written when provisions are
    /// verified (regardless of block commit timing). Read when cross-shard
    /// execution starts. Cleaned up only when WC is committed (terminal state).
    verified_provisions: HashMap<Hash, Vec<StateProvision>>,

    /// Remote shards each cross-shard tx requires provisions from.
    /// Populated in `setup_waves_and_dispatch` from topology.
    required_provision_shards: HashMap<Hash, BTreeSet<ShardGroupId>>,

    /// Remote shards whose provisions have been received for each tx.
    /// Populated in `apply_committed_provisions` from batch source shard.
    received_provision_shards: HashMap<Hash, BTreeSet<ShardGroupId>>,

    /// Detects node-ID overlap conflicts between local cross-shard txs and
    /// committed remote provisions. Deterministic because provisions are
    /// consensus-committed via `provision_root`.
    conflict_detector: ConflictDetector,

    // ═══════════════════════════════════════════════════════════════════════
    // Per-wave execution
    // ═══════════════════════════════════════════════════════════════════════
    /// Per-wave state tracking execution progress, local vote generation, and
    /// cross-shard EC collection. One entry per in-flight wave.
    waves: HashMap<WaveId, WaveState>,

    /// Execution vote trackers: collect execution votes for EC aggregation.
    /// Only created by wave leaders (primary or fallback via rotation).
    vote_trackers: HashMap<WaveId, VoteTracker>,

    /// Waves whose local EC aggregation has been dispatched OR whose local EC
    /// has already been received. Guards against creating a duplicate fallback
    /// VoteTracker during the aggregation window — `check_vote_quorum` fires
    /// `AggregateExecutionCertificate` here, but `WaveState.local_ec_emitted`
    /// only flips once the aggregated cert is fed back via
    /// `add_execution_certificate`.
    waves_with_ec: HashSet<WaveId>,

    /// Pending vote retries for waves where the leader hasn't produced an EC.
    /// Populated by non-leaders in emit_vote_actions(). Cleared on EC receipt.
    pending_vote_retries: HashMap<WaveId, PendingVoteRetry>,

    /// Tx → wave assignment. Maps tx_hash → WaveId.
    wave_assignments: HashMap<Hash, WaveId>,

    // ═══════════════════════════════════════════════════════════════════════
    // Early arrivals (buffered until tracking starts at block commit)
    // ═══════════════════════════════════════════════════════════════════════
    /// Execution votes that arrived before tracking started.
    early_votes: HashMap<WaveId, Vec<ExecutionVote>>,

    /// ECs that arrived before the tx's wave assignment was created.
    /// Keyed by tx_hash for efficient lookup when wave assignments are created.
    /// Multiple tx_hash entries may reference the same Arc<EC> (one EC covers many txs).
    early_wave_attestations: HashMap<Hash, Vec<Arc<ExecutionCertificate>>>,

    /// Per-EC bookkeeping for buffered ECs in `early_wave_attestations`.
    /// Tracks the set of tx_hashes still awaiting a local wave assignment.
    /// When the set drains to empty, the EC has been fully routed and the
    /// entry is dropped. Also drives height-based GC for ECs whose txs
    /// never land locally (orphans, malicious tx_hashes).
    pending_routing: HashMap<WaveId, BufferedEc>,

    // ═══════════════════════════════════════════════════════════════════════
    // Expected Execution Certificate Tracking (Fallback Detection)
    // ═══════════════════════════════════════════════════════════════════════
    /// Expected execution certificates from remote shards.
    /// Populated when remote block headers with waves targeting our shard are seen.
    /// Cleared when the matching cert is received and verified.
    /// After timeout, triggers `RequestMissingExecutionCert` fallback.
    expected_exec_certs: HashMap<(ShardGroupId, u64, WaveId), ExpectedExecCert>,

    /// Fulfilled execution cert keys — prevents late-arriving duplicate headers
    /// from re-registering expectations after certs have already been received.
    /// Maps (source_shard, block_height, wave_id) → local_height_when_fulfilled
    /// for age-based pruning using local time.
    fulfilled_exec_certs: HashMap<(ShardGroupId, u64, WaveId), u64>,
}

impl Default for ExecutionState {
    fn default() -> Self {
        Self::new()
    }
}

/// Bookkeeping for an EC buffered in `early_wave_attestations`.
///
/// Holds a single owning reference to the EC plus the set of tx_hashes from
/// `tx_outcomes` that haven't been routed to a local wave tracker yet. As
/// each unrouted tx eventually lands in a local block, the tx_hash is
/// removed from `pending_txs`; when the set drains to empty the EC has
/// been fully routed and the entry is dropped.
#[derive(Debug)]
struct BufferedEc {
    ec: Arc<ExecutionCertificate>,
    pending_txs: HashSet<Hash>,
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

/// Blocks to wait before retrying a vote with the next rotated wave leader.
const VOTE_RETRY_BLOCKS: u64 = 5;

/// Blocks to retain committed remote provisions in `ConflictDetector` for
/// reverse conflict detection. A local tx that hasn't registered against a
/// stored provision this many blocks after its commit can't conflict with it
/// — its own block has long committed. Anything older is dropped to bound the
/// detector's memory and per-block iteration cost (see
/// `ConflictDetector::prune_provisions_older_than`).
const CONFLICT_PROVISION_RETENTION_BLOCKS: u64 = 50;

/// Maximum age (in local committed blocks past the EC's source block height)
/// before a buffered EC is considered stale and evicted. Bounds the leak from
/// ECs whose tx_hashes never land in a local block (orphaned txs, malicious
/// or buggy remotes referencing tx_hashes our shard will never see).
/// Sized well above the longest plausible cross-shard inclusion lag.
const EC_BUFFER_RETENTION_BLOCKS: u64 = 200;

/// Tracks a pending vote sent to a wave leader, for retry on timeout.
///
/// Retries are unbounded — the loop self-terminates when a working leader
/// aggregates the EC and broadcasts it back. Capping retries would stall
/// waves that haven't resolved yet (including timeout-abort waves, which
/// still need a leader to aggregate the timeout votes).
#[derive(Debug, Clone)]
struct PendingVoteRetry {
    sent_at_height: u64,
    attempt: u32,
    block_hash: Hash,
    block_height: u64,
    vote_height: u64,
    global_receipt_root: Hash,
    tx_outcomes: Arc<Vec<TxOutcome>>,
}

/// Per-shard recipient lists for provision broadcasting.
type ShardRecipients = HashMap<ShardGroupId, Vec<ValidatorId>>;

/// A single tx's layout within a wave: the transaction plus the set of shards
/// that participate in its execution (local + any remote provision sources).
type WaveTxEntry = (Arc<RoutableTransaction>, BTreeSet<ShardGroupId>);

/// Deterministic grouping of a block's transactions into waves, used by
/// `setup_waves_and_dispatch` to drive wave construction.
type WaveAssignments = BTreeMap<WaveId, Vec<WaveTxEntry>>;

/// Build the one-shot execution dispatch action for a fully-provisioned wave.
///
/// Returns `Some(Action::ExecuteTransactions)` for single-shard waves, or
/// `Some(Action::ExecuteCrossShardTransactions)` for cross-shard waves with
/// all required `verified_provisions` present. Returns `None` if a cross-shard
/// tx is missing its provisions, or if every tx in the wave is pre-aborted —
/// caller must not mark the wave dispatched.
///
/// Txs with pre-dispatch explicit aborts (from reverse-conflict detection) are
/// excluded from the dispatch: they produce no state change, so there's no
/// reason to execute them.
fn build_dispatch_action(
    wave: &WaveState,
    verified_provisions: &HashMap<Hash, Vec<StateProvision>>,
    block_hash: Hash,
) -> Option<Action> {
    if wave.wave_id().is_zero() {
        // Single-shard wave: no provisions needed.
        let transactions: Vec<Arc<RoutableTransaction>> = wave
            .tx_hashes()
            .iter()
            .filter(|h| !wave.is_tx_explicitly_aborted(h))
            .filter_map(|h| wave.transaction(h).cloned())
            .collect();
        if transactions.is_empty() {
            return None;
        }
        return Some(Action::ExecuteTransactions {
            wave_id: wave.wave_id().clone(),
            block_hash,
            transactions,
            state_root: Hash::from_bytes(&[0u8; 32]),
        });
    }

    // Cross-shard wave: every non-aborted tx needs its verified provisions assembled.
    let mut requests: Vec<CrossShardExecutionRequest> = Vec::with_capacity(wave.tx_hashes().len());
    for tx_hash in wave.tx_hashes() {
        if wave.is_tx_explicitly_aborted(tx_hash) {
            continue;
        }
        let tx = wave.transaction(tx_hash)?;
        let provisions = verified_provisions.get(tx_hash)?.clone();
        requests.push(CrossShardExecutionRequest {
            tx_hash: *tx_hash,
            transaction: Arc::clone(tx),
            provisions,
        });
    }
    if requests.is_empty() {
        return None;
    }
    Some(Action::ExecuteCrossShardTransactions {
        wave_id: wave.wave_id().clone(),
        block_hash,
        requests,
    })
}

impl ExecutionState {
    /// Create a new execution state machine.
    pub fn new() -> Self {
        Self {
            now: Duration::ZERO,
            receipt_cache: HashMap::new(),
            finalized_wave_certificates: BTreeMap::new(),
            committed_height: 0,
            processed_height: 0,
            waves: HashMap::new(),
            vote_trackers: HashMap::new(),
            waves_with_ec: HashSet::new(),
            pending_vote_retries: HashMap::new(),
            wave_assignments: HashMap::new(),
            early_votes: HashMap::new(),
            verified_provisions: HashMap::new(),
            early_wave_attestations: HashMap::new(),
            pending_routing: HashMap::new(),
            required_provision_shards: HashMap::new(),
            received_provision_shards: HashMap::new(),
            conflict_detector: ConflictDetector::new(),
            expected_exec_certs: HashMap::new(),
            fulfilled_exec_certs: HashMap::new(),
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Time Management
    // ═══════════════════════════════════════════════════════════════════════════

    /// Set the current time.
    pub fn set_time(&mut self, now: Duration) {
        self.now = now;
    }

    /// Height of the latest block fully processed by execution. See the field
    /// on `ExecutionState` for the semantic contract.
    pub fn processed_height(&self) -> u64 {
        self.processed_height
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Certificate Updates (from finalized_certificates)
    // ═══════════════════════════════════════════════════════════════════════════

    // ═══════════════════════════════════════════════════════════════════════════
    // Wave Assignment
    // ═══════════════════════════════════════════════════════════════════════════

    /// Compute deterministic wave assignments for a block's transactions.
    ///
    /// Partitions transactions by their provision dependency set (remote shards
    /// needed). All validators compute identical assignments from the same block.
    ///
    /// Returns a map from WaveId to list of (tx, participating_shards) in
    /// block order within each wave.
    fn assign_waves(
        &self,
        topology: &TopologySnapshot,
        block_height: u64,
        transactions: &[Arc<RoutableTransaction>],
    ) -> WaveAssignments {
        let local_shard = topology.local_shard();
        let mut waves: WaveAssignments = BTreeMap::new();

        for tx in transactions {
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

            let wave_id = WaveId::new(local_shard, block_height, remote_shards);

            waves
                .entry(wave_id)
                .or_default()
                .push((Arc::clone(tx), all_shards));
        }

        waves
    }

    /// Set up per-wave execution state for a newly committed block.
    ///
    /// For each distinct wave, creates a [`WaveState`], records tx → wave
    /// assignments, registers cross-shard txs with the conflict detector, and
    /// pre-populates provisions that arrived before the block.
    ///
    /// Emits `ExecuteTransactions` / `ExecuteCrossShardTransactions` actions
    /// for waves that are fully provisioned at creation time: single-shard
    /// waves always qualify; cross-shard waves do when all required provisions
    /// arrived before block commit.
    ///
    /// Returns the emitted dispatch actions plus any early execution votes
    /// that need to be replayed through `on_execution_vote()`.
    fn setup_waves_and_dispatch(
        &mut self,
        topology: &TopologySnapshot,
        block_hash: Hash,
        block_height: u64,
        transactions: &[Arc<RoutableTransaction>],
    ) -> (Vec<Action>, Vec<ExecutionVote>) {
        let waves = self.assign_waves(topology, block_height, transactions);
        let quorum = topology.local_quorum_threshold();
        let local_shard = topology.local_shard();
        let mut dispatch_actions: Vec<Action> = Vec::new();
        let mut votes_to_replay: Vec<ExecutionVote> = Vec::new();

        for (wave_id, txs) in waves {
            let tx_hashes: Vec<Hash> = txs.iter().map(|(tx, _)| tx.hash()).collect();
            for &tx_hash in &tx_hashes {
                self.wave_assignments.insert(tx_hash, wave_id.clone());
            }

            let is_single_shard = wave_id.is_zero();

            // Cross-shard: register each tx with the conflict detector and
            // populate required-provision tracking. Collect reverse conflicts
            // (where the newly-registered tx is the loser against a
            // previously-committed remote provision); they only apply if the
            // tx isn't already fully provisioned — if provisions are in,
            // execution can proceed and there's no deadlock to break.
            let mut reverse_conflicts: Vec<DetectedConflict> = Vec::new();
            if !is_single_shard {
                for (tx, participating) in &txs {
                    let tx_hash = tx.hash();
                    let remote_shards: BTreeSet<ShardGroupId> = participating
                        .iter()
                        .filter(|&&s| s != local_shard)
                        .copied()
                        .collect();
                    if remote_shards.is_empty() {
                        continue;
                    }
                    self.required_provision_shards
                        .insert(tx_hash, remote_shards);

                    let conflicts = self.conflict_detector.register_tx(
                        tx_hash,
                        topology,
                        &tx.declared_reads,
                        &tx.declared_writes,
                    );
                    let already_provisioned = self
                        .required_provision_shards
                        .get(&tx_hash)
                        .is_some_and(|required| {
                            self.received_provision_shards
                                .get(&tx_hash)
                                .is_some_and(|received| required.is_subset(received))
                        });
                    if !already_provisioned {
                        reverse_conflicts.extend(conflicts);
                    }
                }
            }

            // Create the WaveState. For single-shard waves, `all_provisioned_at`
            // is set to `block_height` immediately by the constructor.
            let mut wave_state = WaveState::new(
                wave_id.clone(),
                block_hash,
                block_height,
                txs,
                is_single_shard,
            );

            // Apply the deadlock-resolving reverse conflicts collected above.
            for conflict in reverse_conflicts {
                wave_state.record_abort(conflict.loser_tx, conflict.committed_at_height);
            }

            // For cross-shard waves: fold in any provisions that already arrived
            // (tracked in `received_provision_shards`). If every tx is fully
            // covered, the wave transitions to "provisioned" at block_height.
            if !is_single_shard {
                for &tx_hash in &tx_hashes {
                    let all_ready =
                        self.required_provision_shards
                            .get(&tx_hash)
                            .is_some_and(|required| {
                                self.received_provision_shards
                                    .get(&tx_hash)
                                    .is_some_and(|received| required.is_subset(received))
                            });
                    if all_ready {
                        wave_state.mark_tx_provisioned(tx_hash, block_height);
                    }
                }
            }

            // Dispatch execution if fully provisioned at creation.
            if wave_state.is_fully_provisioned() && !wave_state.dispatched() {
                if let Some(action) =
                    build_dispatch_action(&wave_state, &self.verified_provisions, block_hash)
                {
                    wave_state.mark_dispatched();
                    dispatch_actions.push(action);
                }
            }

            self.waves.insert(wave_id.clone(), wave_state);

            // Only the wave leader creates a VoteTracker for aggregation.
            let leader = hyperscale_types::wave_leader(&wave_id, topology.local_committee());
            if topology.local_validator_id() == leader {
                let tracker = VoteTracker::new(wave_id.clone(), block_hash, quorum);
                self.vote_trackers.insert(wave_id.clone(), tracker);

                if let Some(early_votes) = self.early_votes.remove(&wave_id) {
                    tracing::debug!(
                        block_hash = ?block_hash,
                        wave = %wave_id,
                        count = early_votes.len(),
                        "Replaying early execution votes"
                    );
                    votes_to_replay.extend(early_votes);
                }
            }
        }

        (dispatch_actions, votes_to_replay)
    }

    /// Record a transaction execution result into its wave.
    ///
    /// Updates the wave silently. Votes are NOT emitted here — they are
    /// emitted during the block commit wave scan (`scan_complete_waves`), ensuring
    /// deterministic voting at each consensus height.
    ///
    /// Execution is dispatched per wave, so a result for an unassigned tx is
    /// a bug (e.g. stale engine callback for a pruned wave) — logged and dropped.
    pub fn record_execution_result(&mut self, tx_hash: Hash, outcome: ExecutionOutcome) {
        let Some(wave_key) = self.wave_assignments.get(&tx_hash).cloned() else {
            tracing::warn!(
                tx_hash = ?tx_hash,
                "Execution result for unassigned tx — dropping"
            );
            return;
        };

        let Some(wave) = self.waves.get_mut(&wave_key) else {
            return;
        };

        wave.record_execution_result(tx_hash, outcome);
    }

    /// Scan all waves and return completion data for any that can emit a vote.
    ///
    /// Called at each block commit AFTER conflicts have been processed,
    /// and also when provisions arrive or execution results complete.
    ///
    /// A wave can emit a vote when:
    /// 1. It's fully provisioned and every tx has an outcome, OR
    /// 2. The `WAVE_TIMEOUT_BLOCKS` deadline has passed (wave aborts entirely)
    ///
    /// Waves that already had an EC formed are skipped.
    pub fn scan_complete_waves(&mut self) -> Vec<CompletionData> {
        let committed_height = self.committed_height;
        let waves_with_ec = &self.waves_with_ec;

        let votable_wave_ids: Vec<WaveId> = self
            .waves
            .iter()
            .filter(|(wid, w)| {
                !waves_with_ec.contains(wid)
                    && !w.local_ec_emitted()
                    && w.can_emit_vote(committed_height)
            })
            .map(|(wid, _)| wid.clone())
            .collect();

        let mut completions = Vec::new();
        for wave_id in votable_wave_ids {
            let wave = self.waves.get_mut(&wave_id).unwrap();
            let block_hash = wave.block_hash();
            let block_height = wave.block_height();
            let Some((vote_height, global_receipt_root, tx_outcomes)) =
                wave.build_vote_data(committed_height)
            else {
                continue;
            };

            completions.push(CompletionData {
                block_hash,
                block_height,
                vote_height,
                wave_id,
                global_receipt_root,
                tx_outcomes,
            });
        }

        // Sort for deterministic ordering (waves is a HashMap).
        completions.sort_by(|a, b| a.wave_id.cmp(&b.wave_id));

        completions
    }

    /// Absorb a completed execution batch: route receipts into the cache and
    /// record per-tx outcomes on the wave. Votes are emitted separately in
    /// the block commit wave scan.
    pub fn on_execution_batch_completed(
        &mut self,
        wave_id: WaveId,
        results: Vec<LocalExecutionEntry>,
        tx_outcomes: Vec<TxOutcome>,
    ) {
        if results.is_empty() && tx_outcomes.is_empty() {
            tracing::warn!(
                wave = %wave_id,
                "ExecutionBatchCompleted produced ZERO results"
            );
            return;
        }

        for result in results {
            let tx_hash = result.tx_hash;
            let bundle = ReceiptBundle {
                tx_hash,
                local_receipt: Arc::new(result.local_receipt),
                execution_output: Some(result.execution_output),
            };
            self.receipt_cache.insert(tx_hash, bundle);
        }

        let Some(wave) = self.waves.get_mut(&wave_id) else {
            tracing::warn!(
                wave = %wave_id,
                "ExecutionBatchCompleted for unknown wave — dropping (wave was pruned or never created)"
            );
            return;
        };
        for wr in tx_outcomes {
            wave.record_execution_result(wr.tx_hash, wr.outcome);
        }
    }

    /// Scan complete waves and emit `SignAndSendExecutionVote` actions.
    ///
    /// This is the SINGLE path to execution voting. Call after conflicts
    /// have been processed so wave state is deterministic at this height.
    /// Each vote is sent to the wave leader (unicast). The `vote_height` is a
    /// relative offset determined by the wave (either `all_provisioned_at -
    /// block_height` or `WAVE_TIMEOUT_BLOCKS` for timeout-abort).
    pub fn emit_vote_actions(&mut self, topology: &TopologySnapshot) -> Vec<Action> {
        let committee = topology.local_committee().to_vec();
        let local_vid = topology.local_validator_id();
        let completions = self.scan_complete_waves();
        let mut actions = Vec::with_capacity(completions.len());
        for completion in completions {
            let leader = hyperscale_types::wave_leader(&completion.wave_id, &committee);
            // Track retry state for non-leaders so we can re-send to a
            // rotated leader if this one doesn't produce an EC.
            let tx_outcomes = Arc::new(completion.tx_outcomes);
            if local_vid != leader {
                self.pending_vote_retries.insert(
                    completion.wave_id.clone(),
                    PendingVoteRetry {
                        sent_at_height: self.committed_height,
                        attempt: 0,
                        block_hash: completion.block_hash,
                        block_height: completion.block_height,
                        vote_height: completion.vote_height,
                        global_receipt_root: completion.global_receipt_root,
                        tx_outcomes: Arc::clone(&tx_outcomes),
                    },
                );
            }
            actions.push(Action::SignAndSendExecutionVote {
                block_hash: completion.block_hash,
                block_height: completion.block_height,
                vote_height: completion.vote_height,
                wave_id: completion.wave_id,
                global_receipt_root: completion.global_receipt_root,
                tx_outcomes: (*tx_outcomes).clone(),
                leader,
            });
        }
        actions
    }

    /// Clean up execution-local per-wave state for wave certs included in the
    /// committed block.
    ///
    /// Per-tx terminal state for the mempool is now driven by
    /// `mempool::on_block_committed_full` reading `block.certificates` directly
    /// (single source of truth per `.plans/_wc-and-finalized-wave-refactor.md`).
    /// This function only handles execution's own bookkeeping.
    pub fn cleanup_committed_waves(
        &mut self,
        certificates: &[Arc<hyperscale_types::FinalizedWave>],
    ) {
        for fw in certificates {
            // No-op for synced waves we never aggregated locally; for waves we
            // tracked, releases accumulator/cache state for the wave's txs.
            self.remove_finalized_wave(fw.as_ref());
        }
    }

    /// Apply provisions committed in a block.
    ///
    /// Two phases — absorb all batches first, then detect conflicts. If
    /// interleaved, the `already_provisioned` guard in phase 2 reads a
    /// partially-absorbed map whose contents depend on batch iteration order,
    /// which diverges abort decisions across validators.
    fn apply_committed_provisions(
        &mut self,
        topology: &TopologySnapshot,
        batches: &[Arc<Provision>],
        committed_height: u64,
    ) -> Vec<Action> {
        // Sort for deterministic phase-2 iteration (logs, action vector order).
        let mut ordered: Vec<&Arc<Provision>> = batches.iter().collect();
        ordered.sort_by_key(|b| b.hash());

        // Phase 1: absorb all provisions. Populated unconditionally so
        // `setup_waves_and_dispatch` can replay them at wave-creation time.
        let mut affected_waves: BTreeSet<WaveId> = BTreeSet::new();
        for batch in &ordered {
            let source_shard = batch.source_shard;
            for tx_entry in &batch.transactions {
                let tx_hash = tx_entry.tx_hash;

                let provisions = vec![StateProvision {
                    transaction_hash: tx_hash,
                    target_shard: topology.local_shard(),
                    source_shard,
                    block_height: batch.block_height,
                    block_timestamp: 0,
                    entries: Arc::new(tx_entry.entries.clone()),
                }];
                self.verified_provisions
                    .entry(tx_hash)
                    .or_default()
                    .extend(provisions);

                self.received_provision_shards
                    .entry(tx_hash)
                    .or_default()
                    .insert(source_shard);

                if let Some(wave_id) = self.wave_assignments.get(&tx_hash).cloned() {
                    affected_waves.insert(wave_id);
                }
            }
        }

        // Phase 2: detect node-ID overlap conflicts against the fully-absorbed
        // provisioned set. A conflict is skipped if the loser is already
        // fully provisioned (execution can proceed) or its wave has already
        // dispatched (inert to mid-flight input).
        for batch in &ordered {
            let source_shard = batch.source_shard;
            for conflict in self
                .conflict_detector
                .detect_conflicts(batch, committed_height)
            {
                let loser = conflict.loser_tx;
                let already_provisioned =
                    self.required_provision_shards
                        .get(&loser)
                        .is_some_and(|required| {
                            self.received_provision_shards
                                .get(&loser)
                                .is_some_and(|received| required.is_subset(received))
                        });
                if already_provisioned {
                    continue;
                }
                let Some(wave_id) = self.wave_assignments.get(&loser).cloned() else {
                    continue;
                };
                let Some(wave) = self.waves.get_mut(&wave_id) else {
                    continue;
                };
                if wave.dispatched() {
                    continue;
                }
                wave.record_abort(loser, conflict.committed_at_height);
                affected_waves.insert(wave_id);
                tracing::debug!(
                    loser_tx = %loser,
                    source_shard = source_shard.0,
                    committed_at = committed_height,
                    "Node-ID overlap conflict — aborting loser"
                );
            }
        }

        // Step 2: for each affected wave, mark newly-ready txs provisioned. If
        // a wave transitions from partial → fully provisioned, emit the one-shot
        // dispatch action. A wave that already dispatched is left alone.
        let mut actions: Vec<Action> = Vec::new();
        for wave_id in affected_waves {
            let Some(wave) = self.waves.get_mut(&wave_id) else {
                continue;
            };
            if wave.dispatched() {
                continue;
            }

            // Identify txs that are now all-shards-ready.
            let tx_hashes: Vec<Hash> = wave.tx_hashes().to_vec();
            for tx_hash in &tx_hashes {
                let all_ready =
                    self.required_provision_shards
                        .get(tx_hash)
                        .is_some_and(|required| {
                            self.received_provision_shards
                                .get(tx_hash)
                                .is_some_and(|received| required.is_subset(received))
                        });
                if all_ready {
                    wave.mark_tx_provisioned(*tx_hash, committed_height);
                }
            }

            // Anchor reads at the wave-start block, matching the single-shard
            // path (which dispatches at wave-start and uses the same block
            // hash). Using `committed_block_hash` would include intervening
            // blocks' cert writes in the view, and those writes come from
            // each validator's own local receipts — one validator's
            // divergence there seeds divergence everywhere downstream.
            if wave.is_fully_provisioned() {
                if let Some(action) =
                    build_dispatch_action(wave, &self.verified_provisions, wave.block_hash())
                {
                    wave.mark_dispatched();
                    actions.push(action);
                }
            }
        }

        actions
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Wave Vote Handling
    // ═══════════════════════════════════════════════════════════════════════════

    /// Handle an execution vote received from another validator (or self).
    ///
    /// Only the wave leader (or a fallback leader via rotation) aggregates votes.
    /// If a vote arrives at a non-leader that has the accumulator but no tracker,
    /// a fallback VoteTracker is created on-demand (the sender determined this
    /// validator is the rotated leader for their retry attempt).
    pub fn on_execution_vote(
        &mut self,
        topology: &TopologySnapshot,
        vote: ExecutionVote,
    ) -> Vec<Action> {
        let wave_id = vote.wave_id.clone();
        let validator_id = vote.validator;

        if !self.vote_trackers.contains_key(&wave_id) {
            if !self.waves.contains_key(&wave_id) {
                // Block hasn't committed yet — buffer as early vote.
                self.early_votes.entry(wave_id).or_default().push(vote);
                return vec![];
            }
            if self.waves_with_ec.contains(&wave_id) {
                // Already have EC for this wave — discard late vote.
                return vec![];
            }
            // Wave exists but no VoteTracker and no EC yet. This validator
            // was targeted as a fallback leader (rotated attempt). Create tracker.
            let quorum = topology.local_quorum_threshold();
            let block_hash = self.waves.get(&wave_id).unwrap().block_hash();
            tracing::info!(
                wave = %wave_id,
                "Creating fallback VoteTracker — receiving votes as rotated leader"
            );
            let tracker = VoteTracker::new(wave_id.clone(), block_hash, quorum);
            self.vote_trackers.insert(wave_id.clone(), tracker);

            // Replay any early votes that were buffered before block commit.
            // These may include retried votes from other validators who
            // committed faster and rotated to us before our block committed.
            if let Some(early) = self.early_votes.remove(&wave_id) {
                tracing::debug!(
                    wave = %wave_id,
                    count = early.len(),
                    "Replaying early votes into fallback VoteTracker"
                );
                let mut actions = Vec::new();
                for ev in early {
                    actions.extend(self.on_execution_vote(topology, ev));
                }
                // Process the current vote that triggered fallback creation.
                actions.extend(self.on_execution_vote(topology, vote));
                return actions;
            }
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

        let tracker = self.vote_trackers.get_mut(&wave_id).unwrap();

        // buffer_unverified_vote handles dedup per (validator, vote_height).
        // Same validator can vote at multiple heights (round voting).
        if !tracker.buffer_unverified_vote(vote, public_key, voting_power) {
            return vec![];
        }

        self.maybe_trigger_vote_verification(wave_id)
    }

    /// Check if we should trigger batch verification for a wave's votes.
    fn maybe_trigger_vote_verification(&mut self, wave_id: WaveId) -> Vec<Action> {
        let Some(tracker) = self.vote_trackers.get_mut(&wave_id) else {
            return vec![];
        };

        if !tracker.should_trigger_verification() {
            return vec![];
        }

        let votes = tracker.take_unverified_votes();
        if votes.is_empty() {
            return vec![];
        }

        let block_hash = tracker.block_hash();

        tracing::debug!(
            block_hash = ?block_hash,
            wave = %wave_id,
            vote_count = votes.len(),
            "Dispatching execution vote batch verification"
        );
        vec![Action::VerifyAndAggregateExecutionVotes {
            wave_id,
            block_hash,
            votes,
        }]
    }

    /// Handle a verified execution vote (own vote or already-verified).
    fn handle_verified_vote(
        &mut self,
        topology: &TopologySnapshot,
        vote: ExecutionVote,
    ) -> Vec<Action> {
        let wave_id = vote.wave_id.clone();
        let voting_power = topology.voting_power(vote.validator).unwrap_or(0);

        let Some(tracker) = self.vote_trackers.get_mut(&wave_id) else {
            return vec![];
        };

        tracker.add_verified_vote(vote, voting_power);

        let mut actions = self.check_vote_quorum(topology, wave_id.clone());
        actions.extend(self.maybe_trigger_vote_verification(wave_id));
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
        let Some(tracker) = self.vote_trackers.get_mut(&wave_id) else {
            return vec![];
        };

        tracker.on_verification_complete();

        for (vote, power) in verified_votes {
            tracker.add_verified_vote(vote, power);
        }

        // Warn if we have enough total power for quorum but it's split
        // across multiple global receipt roots — this means validators disagree
        // on execution results.
        if tracker.check_quorum().is_none()
            && tracker.total_verified_power() >= topology.local_quorum_threshold()
            && tracker.distinct_global_receipt_root_count() > 1
        {
            let summary = tracker.global_receipt_root_power_summary();
            tracing::warn!(
                block_hash = ?block_hash,
                wave = %wave_id,
                global_receipt_root_split = ?summary,
                quorum = topology.local_quorum_threshold(),
                "Execution vote quorum blocked: global receipt roots are split across validators"
            );
        }

        let mut actions = self.check_vote_quorum(topology, wave_id.clone());
        actions.extend(self.maybe_trigger_vote_verification(wave_id));
        actions
    }

    /// Check if quorum is reached for a wave's votes.
    fn check_vote_quorum(&mut self, topology: &TopologySnapshot, wave_id: WaveId) -> Vec<Action> {
        let Some(tracker) = self.vote_trackers.get_mut(&wave_id) else {
            return vec![];
        };

        let Some((global_receipt_root, vote_height, _total_power)) = tracker.check_quorum() else {
            return vec![];
        };

        let block_hash = tracker.block_hash();

        tracing::info!(
            block_hash = ?block_hash,
            wave = %wave_id,
            vote_height,
            "Execution vote quorum reached — aggregating certificate"
        );

        let votes = tracker.take_votes(&global_receipt_root, vote_height);
        let committee = topology.local_committee().to_vec();

        // Remove the vote tracker — this EC is the shard's final answer.
        // Mark wave as having an EC to skip it in scan_complete_waves.
        self.vote_trackers.remove(&wave_id);
        self.waves_with_ec.insert(wave_id.clone());

        tracing::debug!(
            block_hash = ?block_hash,
            wave = %wave_id,
            votes = votes.len(),
            "Delegating BLS aggregation to crypto pool"
        );

        // Notify mempool that the local EC was created for these txs.
        let ec_tx_hashes = self
            .waves
            .get(&wave_id)
            .map(|w| w.tx_hashes().to_vec())
            .unwrap_or_default();

        // tx_outcomes are extracted from votes by the aggregation handler
        // (all quorum votes carry identical outcomes).
        vec![
            Action::AggregateExecutionCertificate {
                wave_id,
                shard: topology.local_shard(),
                global_receipt_root,
                votes,
                committee,
            },
            Action::Continuation(ProtocolEvent::ExecutionCertificateCreated {
                tx_hashes: ec_tx_hashes,
            }),
        ]
    }

    /// Handle execution certificate aggregation completed.
    ///
    /// Called when the crypto pool finishes BLS aggregation for a wave's votes.
    /// Only the wave leader (primary or fallback) reaches this path.
    /// Broadcasts the EC to all local peers and remote participating shards,
    /// then feeds it to the wave-level certificate tracker for finalization.
    pub fn on_certificate_aggregated(
        &mut self,
        topology: &TopologySnapshot,
        wave_id: WaveId,
        certificate: hyperscale_types::ExecutionCertificate,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        let local_vid = topology.local_validator_id();

        // The wave_id IS the set of remote shards — no need to look up the
        // accumulator (which may have been pruned by the time the cert is
        // aggregated, especially with many shards where provision flow is slower).
        let remote_shards: Vec<ShardGroupId> = wave_id.remote_shards.iter().copied().collect();

        let certificate = Arc::new(certificate);

        // Cache the cert in io_loop for fallback serving.
        actions.push(Action::TrackExecutionCertificate {
            certificate: Arc::clone(&certificate),
        });

        // Broadcast EC to all local peers (they don't aggregate — they need it).
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

        // Broadcast EC to remote participating shards.
        for target_shard in &remote_shards {
            let recipients: Vec<ValidatorId> = topology.committee_for_shard(*target_shard).to_vec();
            actions.push(Action::BroadcastExecutionCertificate {
                shard: *target_shard,
                certificate: Arc::clone(&certificate),
                recipients,
            });
        }

        tracing::debug!(
            wave = %wave_id,
            tx_count = certificate.tx_outcomes.len(),
            remote_shards = remote_shards.len(),
            "Wave leader broadcasting EC to local peers and remote shards"
        );

        // Feed the EC to the wave-level certificate tracker for finalization.
        actions.extend(self.handle_wave_attestation(topology, certificate));

        actions
    }

    /// Handle an execution certificate received from another validator.
    ///
    /// This handles ECs from both:
    /// - The wave leader (local shard EC broadcast, or remote shard EC for finalization)
    /// - Fallback fetch (when wave leader or remote broadcast fails)
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
        let shard = cert.shard_group_id();

        // Clear expected cert tracking and mark as fulfilled so late-arriving
        // duplicate headers don't re-register the expectation.
        let key = (shard, cert.block_height(), cert.wave_id.clone());
        self.expected_exec_certs.remove(&key);
        self.fulfilled_exec_certs.insert(key, self.committed_height);

        // Check if any local wave tracker covers txs in this EC.
        // Route by tx_hash → local wave, not by ec.wave_id (which is the remote shard's wave).
        let has_any_tracker = cert.tx_outcomes.iter().any(|o| {
            self.wave_assignments
                .get(&o.tx_hash)
                .and_then(|wid| self.waves.get(wid))
                .is_some()
        });

        if !has_any_tracker {
            // No tracker yet — buffer by tx_hash for targeted replay when block commits
            let ec_arc = Arc::new(cert);
            let tx_hashes: Vec<Hash> = ec_arc.tx_outcomes.iter().map(|o| o.tx_hash).collect();
            self.buffer_ec(&ec_arc, &tx_hashes);
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

        // Delegate signature verification to the crypto pool. The signing
        // message derives solely from WaveId (self-contained) + receipt root.
        vec![Action::VerifyExecutionCertificateSignature {
            certificate: cert,
            public_keys,
        }]
    }

    /// Handle execution certificate signature verification result.
    ///
    /// If valid, route per-tx outcomes into their local waves. Txs without a
    /// local wave are buffered as early attestations for replay when their
    /// block commits.
    pub fn on_certificate_verified(
        &mut self,
        topology: &TopologySnapshot,
        certificate: hyperscale_types::ExecutionCertificate,
        valid: bool,
    ) -> Vec<Action> {
        if !valid {
            tracing::warn!(
                shard = certificate.shard_group_id().0,
                wave = %certificate.wave_id,
                "Invalid execution certificate signature"
            );
            return vec![];
        }

        let shard = certificate.shard_group_id();
        let mut actions = Vec::new();

        // If this is a local shard EC, mark the wave as having an EC to skip
        // it in scan_complete_waves, and persist it for fallback serving to
        // remote shards.
        if shard == topology.local_shard() {
            self.waves_with_ec.insert(certificate.wave_id.clone());
            // EC received from wave leader — cancel any pending vote retry.
            self.pending_vote_retries.remove(&certificate.wave_id);
            let cert_arc = Arc::new(certificate.clone());
            actions.push(Action::TrackExecutionCertificate {
                certificate: cert_arc.clone(),
            });
        }

        // Feed EC to wave-level certificate tracker via tx-hash routing,
        // or buffer if no local tracker covers any of its txs yet.
        let ec_arc = Arc::new(certificate);
        let has_any_tracker = ec_arc.tx_outcomes.iter().any(|o| {
            self.wave_assignments
                .get(&o.tx_hash)
                .and_then(|wid| self.waves.get(wid))
                .is_some()
        });
        if has_any_tracker {
            actions.extend(self.handle_wave_attestation(topology, ec_arc));
        } else {
            // Buffer by tx_hash for targeted replay when block commits
            let tx_hashes: Vec<Hash> = ec_arc.tx_outcomes.iter().map(|o| o.tx_hash).collect();
            self.buffer_ec(&ec_arc, &tx_hashes);
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
            if wave.remote_shards.contains(&local_shard) {
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
                tracing::info!(
                    source_shard = source_shard.0,
                    block_height = block_height,
                    wave = %wave_id,
                    age,
                    retry = is_retry,
                    "Execution cert timeout — requesting fallback"
                );
                actions.push(Action::RequestMissingExecutionCert {
                    source_shard: *source_shard,
                    block_height: *block_height,
                    wave_id: wave_id.clone(),
                    peers,
                });
            }
        }
        // Retain expectations while any local wave still needs an EC from that
        // source shard. `self.waves` is the authoritative "what am I still
        // waiting on" set — entries are removed by `finalize_wave` once a wave
        // is complete. Keyed by source shard (not wave_id) because expected
        // entries carry the remote shard's wave decomposition, which cannot be
        // matched against local wave ids.
        let local_shard = topology.local_shard();
        let shards_needed: HashSet<ShardGroupId> = self
            .waves
            .keys()
            .flat_map(|wid| wid.remote_shards.iter().copied())
            .filter(|s| *s != local_shard)
            .collect();
        self.expected_exec_certs
            .retain(|(source_shard, _, _), _| shards_needed.contains(source_shard));

        // Prune fulfilled set using local height when fulfilled (not remote
        // block height, which can differ significantly across shards).
        let fulfilled_cutoff = self.committed_height.saturating_sub(100);
        self.fulfilled_exec_certs
            .retain(|_, &mut fulfilled_at| fulfilled_at > fulfilled_cutoff);

        actions
    }

    /// Re-send votes to rotated leaders for waves that haven't produced an EC.
    ///
    /// Called during block commit processing. If VOTE_RETRY_BLOCKS have elapsed
    /// since a vote was sent and no EC has been received, re-send the same vote
    /// to the next deterministically-rotated leader.
    fn check_vote_retry_timeouts(&mut self, topology: &TopologySnapshot) -> Vec<Action> {
        let mut actions = Vec::new();
        let current_height = self.committed_height;
        let committee = topology.local_committee().to_vec();

        // Collect retries first to avoid borrow conflict.
        let retries: Vec<(WaveId, PendingVoteRetry)> = self
            .pending_vote_retries
            .iter()
            .filter(|(_, p)| current_height.saturating_sub(p.sent_at_height) >= VOTE_RETRY_BLOCKS)
            .map(|(w, p)| (w.clone(), p.clone()))
            .collect();

        for (wave_id, mut pending) in retries {
            pending.attempt += 1;
            pending.sent_at_height = current_height;
            let new_leader =
                hyperscale_types::wave_leader_at(&wave_id, pending.attempt, &committee);

            tracing::info!(
                wave = %wave_id,
                attempt = pending.attempt,
                new_leader = new_leader.0,
                "Vote retry timeout — re-sending to rotated leader"
            );

            actions.push(Action::SignAndSendExecutionVote {
                block_hash: pending.block_hash,
                block_height: pending.block_height,
                vote_height: pending.vote_height,
                wave_id: wave_id.clone(),
                global_receipt_root: pending.global_receipt_root,
                tx_outcomes: (*pending.tx_outcomes).clone(),
                leader: new_leader,
            });

            self.pending_vote_retries.insert(wave_id, pending);
        }
        actions
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Block Commit Handling
    // ═══════════════════════════════════════════════════════════════════════════

    /// Handle block committed - start executing transactions.
    #[instrument(skip(self, block), fields(
        height = block.header().height.0,
        block_hash = ?block.hash(),
        tx_count = block.transactions().len(),
        is_live = block.is_live(),
    ))]
    pub fn on_block_committed(
        &mut self,
        topology: &TopologySnapshot,
        block: &Block,
    ) -> Vec<Action> {
        let block_hash = block.hash();
        let header = block.header();
        let height = header.height.0;
        let block_timestamp = header.timestamp;
        let proposer = header.proposer;
        let transactions = block.transactions();
        // Provisions for `Live`; `Sealed` never carries any (the window
        // that needed them has passed). Both handled uniformly below.
        let provisions: &[Arc<Provision>] = block.provisions().unwrap_or(&[]);

        let mut actions = Vec::new();

        // ── Provision broadcasting (proposer only) ─────────────────────
        //
        // Only applies to `Live` blocks: `Sealed` is past the execution
        // window, so any waves it sourced have already been aggregated and
        // finalized upstream — there's nothing left to broadcast.
        if block.is_live() {
            let local_shard = topology.local_shard();
            let is_proposer = topology.local_validator_id() == proposer;

            if is_proposer {
                if let Some((requests, shard_recipients)) =
                    Self::build_provision_requests(topology, transactions, local_shard)
                {
                    actions.push(Action::FetchAndBroadcastProvision {
                        block_hash,
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

        // Re-send votes to rotated leaders for waves where the leader hasn't
        // produced an EC within VOTE_RETRY_BLOCKS.
        actions.extend(self.check_vote_retry_timeouts(topology));

        // Prune ephemeral wave state (waves + vote trackers + early votes)
        // whose backing tx assignments have all resolved. Cross-shard
        // resolution state is only cleaned up on terminal state — never by
        // block-count timeout.
        self.prune_execution_state();

        // Drop buffered ECs whose source block height is too far behind the
        // local committed height — covers tx_hashes that will never land
        // locally (orphaned txs, malicious tx_hashes from remote shards).
        self.prune_stale_buffered_ecs();

        // Drop conflict-detector entries for remote provisions older than the
        // retention window. `register_tx` iterates over these per cross-shard
        // tx; left unbounded they drive quadratic TPS decay.
        let cutoff = height.saturating_sub(CONFLICT_PROVISION_RETENTION_BLOCKS);
        if cutoff > 0 {
            let dropped = self.conflict_detector.prune_provisions_older_than(cutoff);
            if dropped > 0 {
                tracing::debug!(dropped, cutoff, "Pruned aged conflict-detector provisions");
            }
        }

        if !transactions.is_empty() {
            let block_tx_hashes: Vec<Hash> = transactions.iter().map(|tx| tx.hash()).collect();

            if block.is_live() {
                tracing::debug!(
                    height = height,
                    tx_count = transactions.len(),
                    "Starting execution for new transactions"
                );

                let (dispatch_actions, early_votes) =
                    self.setup_waves_and_dispatch(topology, block_hash, height, transactions);
                actions.extend(dispatch_actions);
                for vote in early_votes {
                    actions.extend(self.on_execution_vote(topology, vote));
                }
            } else {
                // Sealed: the cross-shard execution window has passed for
                // this block. Its waves will finalize from the already-
                // aggregated cert + receipts included downstream. Record
                // only the tx→wave mapping so a late-arriving cert can
                // still route back to each tx for mempool terminal state;
                // skip WaveState creation, dispatch, and vote tracking.
                self.register_sealed_wave_assignments(topology, height, transactions);
            }

            // Replay buffered early ECs for txs that now have wave assignments.
            // Runs for both variants: a Sealed block's txs still need cert
            // routing when that cert eventually lands.
            let mut ecs_to_replay: Vec<Arc<ExecutionCertificate>> = Vec::new();
            let mut seen_ec_ptrs: HashSet<usize> = HashSet::new();
            for tx_hash in &block_tx_hashes {
                if let Some(ecs) = self.early_wave_attestations.remove(tx_hash) {
                    for ec in ecs {
                        let ptr = Arc::as_ptr(&ec) as usize;
                        if seen_ec_ptrs.insert(ptr) {
                            ecs_to_replay.push(ec);
                        }
                    }
                }
            }
            if !ecs_to_replay.is_empty() {
                tracing::debug!(
                    count = ecs_to_replay.len(),
                    "Replaying early wave attestations for newly committed txs"
                );
                for ec in ecs_to_replay {
                    actions.extend(self.handle_wave_attestation(topology, ec));
                }
            }
        }

        // Apply this block's provisions after wave setup so newly-created
        // waves can transition to provisioned from the same block's batches.
        // Sealed blocks skip this: provisions are dropped by design past the
        // window, and the waves they would have fed are already resolved.
        if block.is_live() && !provisions.is_empty() {
            actions.extend(self.apply_committed_provisions(topology, provisions, height));
        }

        if height > self.processed_height {
            self.processed_height = height;
        }

        actions
    }

    /// Register tx → wave assignments for a `Sealed` block without any of
    /// the execution-side state setup (WaveState, vote tracker, conflict
    /// detector, required-provision tracking). The block's waves are
    /// already settled; we only need the mapping so a future cert can
    /// route back to the tx for mempool terminal-state bookkeeping.
    fn register_sealed_wave_assignments(
        &mut self,
        topology: &TopologySnapshot,
        block_height: u64,
        transactions: &[Arc<RoutableTransaction>],
    ) {
        let waves = self.assign_waves(topology, block_height, transactions);
        for (wave_id, txs) in waves {
            for (tx, _) in &txs {
                self.wave_assignments.insert(tx.hash(), wave_id.clone());
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Phase 5: Finalization
    // ═══════════════════════════════════════════════════════════════════════════

    /// Buffer an EC under tx_hashes that don't have a local wave assignment yet.
    ///
    /// Idempotent: tx_hashes already tracked in `pending_routing[ec.wave_id]`
    /// are skipped, so replaying an already-buffered EC won't create duplicate
    /// entries in `early_wave_attestations`.
    fn buffer_ec(&mut self, ec: &Arc<ExecutionCertificate>, tx_hashes: &[Hash]) {
        if tx_hashes.is_empty() {
            return;
        }
        let entry = self
            .pending_routing
            .entry(ec.wave_id.clone())
            .or_insert_with(|| BufferedEc {
                ec: Arc::clone(ec),
                pending_txs: HashSet::new(),
            });
        for tx_hash in tx_hashes {
            if entry.pending_txs.insert(*tx_hash) {
                self.early_wave_attestations
                    .entry(*tx_hash)
                    .or_default()
                    .push(Arc::clone(ec));
            }
        }
    }

    /// Mark `tx_hashes` as routed for `ec`. When the pending set drains to
    /// empty the EC has been fully delivered to local trackers and the
    /// bookkeeping entry is dropped.
    fn clear_routed_txs(&mut self, ec: &Arc<ExecutionCertificate>, tx_hashes: &[Hash]) {
        let Some(entry) = self.pending_routing.get_mut(&ec.wave_id) else {
            return;
        };
        for tx_hash in tx_hashes {
            entry.pending_txs.remove(tx_hash);
        }
        if entry.pending_txs.is_empty() {
            self.pending_routing.remove(&ec.wave_id);
        }
    }

    /// Drop buffered ECs whose source wave is older than
    /// `EC_BUFFER_RETENTION_BLOCKS` behind the local committed height.
    /// Covers the leak from tx_hashes that never land in a local block
    /// (orphaned txs, malicious or buggy remotes referencing unknown txs).
    fn prune_stale_buffered_ecs(&mut self) {
        if self.committed_height < EC_BUFFER_RETENTION_BLOCKS {
            return;
        }
        let cutoff = self.committed_height - EC_BUFFER_RETENTION_BLOCKS;
        let stale: Vec<WaveId> = self
            .pending_routing
            .iter()
            .filter(|(wid, _)| wid.block_height <= cutoff)
            .map(|(wid, _)| wid.clone())
            .collect();
        if stale.is_empty() {
            return;
        }
        let count = stale.len();
        for wid in stale {
            let Some(entry) = self.pending_routing.remove(&wid) else {
                continue;
            };
            for tx_hash in &entry.pending_txs {
                if let Some(vec) = self.early_wave_attestations.get_mut(tx_hash) {
                    vec.retain(|e| !Arc::ptr_eq(e, &entry.ec));
                    if vec.is_empty() {
                        self.early_wave_attestations.remove(tx_hash);
                    }
                }
            }
        }
        tracing::debug!(
            count,
            committed_height = self.committed_height,
            "Pruned stale buffered ECs"
        );
    }

    /// Handle a wave-level attestation (execution certificate) from any shard.
    ///
    /// A remote EC's wave_id reflects the remote shard's wave decomposition,
    /// which differs from the local shard's. A single remote EC may contain
    /// outcomes for transactions in MULTIPLE local waves.
    ///
    /// Routing: iterate tx_outcomes → look up local wave via wave_assignments →
    /// feed the EC to each affected local wave tracker. Tx_hashes without a
    /// local assignment are buffered (or kept buffered) via `pending_routing`
    /// until their blocks commit; routed tx_hashes are cleared from the
    /// pending set, dropping the EC entirely once fully routed.
    fn handle_wave_attestation(
        &mut self,
        _topology: &TopologySnapshot,
        ec: Arc<ExecutionCertificate>,
    ) -> Vec<Action> {
        let mut affected_waves: BTreeSet<WaveId> = BTreeSet::new();
        let mut routed_tx_hashes: Vec<Hash> = Vec::new();
        let mut unrouted_tx_hashes: Vec<Hash> = Vec::new();
        for outcome in &ec.tx_outcomes {
            if let Some(local_wave_id) = self.wave_assignments.get(&outcome.tx_hash) {
                affected_waves.insert(local_wave_id.clone());
                routed_tx_hashes.push(outcome.tx_hash);
            } else {
                unrouted_tx_hashes.push(outcome.tx_hash);
            }
        }

        self.clear_routed_txs(&ec, &routed_tx_hashes);
        self.buffer_ec(&ec, &unrouted_tx_hashes);

        if affected_waves.is_empty() {
            return vec![];
        }

        // Feed the EC to each affected local wave. Completion requires both
        // the local EC and all remote shards' coverage (aborted txs are
        // terminal-covered). Once `local_ec_emitted` is true, every tx
        // already has an outcome and a matching receipt in the cache.
        let mut actions = Vec::new();
        for wave_id in &affected_waves {
            let Some(wave) = self.waves.get_mut(wave_id) else {
                continue;
            };
            if wave.add_execution_certificate(Arc::clone(&ec)) && wave.is_complete() {
                actions.extend(self.finalize_wave(wave_id));
            }
        }
        actions
    }

    /// Finalize a wave: create WaveCertificate, record FinalizedWave, emit events.
    ///
    /// Called when the wave's local EC is present and every non-aborted tx is
    /// covered by all participating shards.
    fn finalize_wave(&mut self, wave_id: &WaveId) -> Vec<Action> {
        let Some(wave) = self.waves.remove(wave_id) else {
            return vec![];
        };

        let wc = wave.create_wave_certificate();
        let tx_hashes = wave.tx_hashes().to_vec();

        let receipts: Vec<ReceiptBundle> = tx_hashes
            .iter()
            .filter_map(|h| self.receipt_cache.remove(h))
            .collect();

        let cert_arc = Arc::new(wc);
        let finalized = FinalizedWave {
            certificate: Arc::clone(&cert_arc),
            receipts,
        };
        let finalized_arc = Arc::new(finalized.clone());
        self.finalized_wave_certificates
            .insert(wave_id.clone(), finalized);

        // Cache the finalized wave so peers can fetch the complete data they
        // need to vote on blocks containing this wave.
        let mut actions = vec![Action::CacheFinalizedWave {
            wave: finalized_arc,
        }];

        actions.push(Action::Continuation(ProtocolEvent::WaveCompleted {
            wave_cert: cert_arc,
            tx_hashes: tx_hashes.clone(),
        }));

        for (tx_hash, decision) in wave.tx_decisions() {
            actions.push(Action::Continuation(ProtocolEvent::TransactionExecuted {
                tx_hash,
                accepted: decision == TransactionDecision::Accept,
            }));
        }
        actions
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Query Methods
    // ═══════════════════════════════════════════════════════════════════════════

    /// Get the local wave assignment for a transaction.
    pub fn get_wave_assignment(&self, tx_hash: &Hash) -> Option<WaveId> {
        self.wave_assignments.get(tx_hash).cloned()
    }

    /// Get all finalized waves (for proposal building).
    pub fn get_finalized_waves(&self) -> Vec<Arc<FinalizedWave>> {
        self.finalized_wave_certificates
            .values()
            .map(|fw| Arc::new(fw.clone()))
            .collect()
    }

    /// Get a finalized wave by its wave_id hash (returns Arc for sharing).
    pub fn get_finalized_wave_by_hash(&self, wave_id_hash: &Hash) -> Option<Arc<FinalizedWave>> {
        self.finalized_wave_certificates
            .values()
            .find(|fw| fw.certificate.wave_id.hash() == *wave_id_hash)
            .map(|fw| Arc::new(fw.clone()))
    }

    /// Get the finalized wave certificate containing a specific transaction.
    ///
    /// Returns the wave certificate if the tx is part of a finalized wave.
    /// Once committed, certificates are persisted to storage and should be fetched from there.
    pub fn get_finalized_certificate(&self, tx_hash: &Hash) -> Option<Arc<WaveCertificate>> {
        self.finalized_wave_certificates
            .values()
            .find(|fw| fw.contains_tx(tx_hash))
            .map(|fw| Arc::clone(&fw.certificate))
    }

    /// Remove a finalized wave (after its wave cert has been committed in a block).
    ///
    /// Cleans up all per-tx tracking state for transactions in this wave.
    /// Takes the `FinalizedWave` directly (rather than just a `WaveId`) so
    /// cleanup works even when the wave was never aggregated locally — e.g.
    /// for blocks received via sync. The committed `FinalizedWave` is the
    /// authoritative tx-set source.
    pub fn remove_finalized_wave(&mut self, fw: &hyperscale_types::FinalizedWave) {
        let wave_id = fw.wave_id();
        self.finalized_wave_certificates.remove(wave_id);
        // The wave may already have been removed by `finalize_wave` (local
        // aggregation path) or be absent entirely (sync path: the block was
        // received as committed without local tracking). Either case is fine.
        self.waves.remove(wave_id);

        for tx_hash in fw.tx_hashes() {
            self.receipt_cache.remove(&tx_hash);
            self.wave_assignments.remove(&tx_hash);
            self.verified_provisions.remove(&tx_hash);
            self.required_provision_shards.remove(&tx_hash);
            self.received_provision_shards.remove(&tx_hash);
            self.conflict_detector.remove_tx(&tx_hash);
        }
    }

    /// Prune stale wave state (waves, vote trackers, early votes).
    ///
    /// Prunes waves only when no active wave_assignments reference them.
    /// Active wave_assignments mean the transaction has not yet reached terminal
    /// state (TC committed or abort completed), so the wave must stay alive to
    /// allow conflicts and late-arriving votes to resolve the transaction.
    fn prune_execution_state(&mut self) {
        // Build set of WaveIds still referenced by active wave assignments.
        let active_keys: std::collections::HashSet<&WaveId> =
            self.wave_assignments.values().collect();

        let before_waves = self.waves.len();
        self.waves.retain(|key, _| active_keys.contains(key));
        let pruned_waves = before_waves - self.waves.len();

        // Prune vote trackers keyed to removed waves.
        let before_vt = self.vote_trackers.len();
        self.vote_trackers.retain(|key, tracker| {
            if self.waves.contains_key(key) {
                return true;
            }
            let root_count = tracker.distinct_global_receipt_root_count();
            if root_count > 1 {
                let summary = tracker.global_receipt_root_power_summary();
                tracing::warn!(
                    wave = %key,
                    global_receipt_root_split = ?summary,
                    "Pruning vote tracker that never reached quorum — global receipt roots were split"
                );
            } else if tracker.total_verified_power() > 0 {
                tracing::warn!(
                    wave = %key,
                    verified_power = tracker.total_verified_power(),
                    "Pruning vote tracker that never reached quorum — insufficient votes"
                );
            }
            false
        });
        let pruned_vt = before_vt - self.vote_trackers.len();
        self.waves_with_ec
            .retain(|key| self.waves.contains_key(key));
        self.pending_vote_retries
            .retain(|key, _| active_keys.contains(key));

        // Prune early execution votes:
        // - Wave resolved (EC formed) → votes no longer needed
        // - Leader replayed them (VoteTracker exists) → already consumed
        // - No wave and stale (50+ blocks) → block never committed, BFT broken
        //
        // Non-leaders with a wave but no VoteTracker KEEP early votes. They may
        // become fallback leaders via rotation and need to replay them into the
        // on-demand VoteTracker created in on_execution_vote().
        let ev_cutoff = self.committed_height.saturating_sub(50);
        let before_ev = self.early_votes.len();
        self.early_votes.retain(|key, votes| {
            if self.waves_with_ec.contains(key) {
                return false;
            }
            if self.vote_trackers.contains_key(key) {
                return false;
            }
            if self.waves.contains_key(key) {
                return true;
            }
            votes
                .first()
                .map(|v| v.block_height > ev_cutoff)
                .unwrap_or(false)
        });
        let pruned_ev = before_ev - self.early_votes.len();

        // Prune wave_assignments for waves that no longer exist.
        let before_wa = self.wave_assignments.len();
        self.wave_assignments
            .retain(|_, wave_id| self.waves.contains_key(wave_id));
        let pruned_wa = before_wa - self.wave_assignments.len();

        if pruned_waves > 0 || pruned_vt > 0 || pruned_ev > 0 || pruned_wa > 0 {
            tracing::debug!(
                pruned_waves,
                pruned_vt,
                pruned_ev,
                pruned_wa,
                "Pruned resolved wave state"
            );
        }
    }

    /// Check if a transaction is finalized (part of a finalized wave).
    pub fn is_finalized(&self, tx_hash: &Hash) -> bool {
        self.finalized_wave_certificates
            .values()
            .any(|fw| fw.contains_tx(tx_hash))
    }

    /// Returns the set of all finalized transaction hashes.
    ///
    /// Used by the node orchestrator to pass to BFT for conflict filtering.
    pub fn finalized_tx_hashes(&self) -> std::collections::HashSet<Hash> {
        self.finalized_wave_certificates
            .values()
            .flat_map(|fw| fw.tx_hashes())
            .collect()
    }

    /// Check if we're waiting for provisioning to complete for a transaction.
    ///
    /// Note: Actual provision tracking is handled by ProvisionCoordinator.
    pub fn is_awaiting_provisioning(&self, tx_hash: &Hash) -> bool {
        let Some(wave_id) = self.wave_assignments.get(tx_hash) else {
            return false;
        };
        self.waves
            .get(wave_id)
            .is_some_and(|w| !w.is_fully_provisioned())
    }

    /// Get debug info about wave state for a transaction.
    pub fn certificate_tracking_debug(&self, tx_hash: &Hash) -> String {
        let wave_info = if let Some(wave_id) = self.wave_assignments.get(tx_hash) {
            if let Some(wave) = self.waves.get(wave_id) {
                format!("wave={}, complete={}", wave_id, wave.is_complete())
            } else if self.finalized_wave_certificates.contains_key(wave_id) {
                format!("wave={}, finalized", wave_id)
            } else {
                format!("wave={}, no tracker", wave_id)
            }
        } else {
            "no wave assignment".to_string()
        };

        let early_count = self
            .early_wave_attestations
            .get(tx_hash)
            .map(|v| v.len())
            .unwrap_or(0);

        format!("{}, early_wave_attestations={}", wave_info, early_count)
    }

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
                // Build per-target-shard node needs for conflict detection.
                let mut targets: Vec<(ShardGroupId, Vec<NodeId>)> = Vec::new();
                let all_nodes: Vec<&NodeId> = tx
                    .declared_reads
                    .iter()
                    .chain(tx.declared_writes.iter())
                    .collect();
                for &target_shard in &topology
                    .all_shards_for_transaction(tx)
                    .into_iter()
                    .filter(|&s| s != local_shard)
                    .collect::<Vec<_>>()
                {
                    let needed: Vec<NodeId> = all_nodes
                        .iter()
                        .filter(|&&n| topology.shard_for_node_id(n) == target_shard)
                        .copied()
                        .copied()
                        .collect();
                    targets.push((target_shard, needed));
                }

                if !targets.is_empty() {
                    provision_requests.push(ProvisionRequest {
                        tx_hash: tx.hash(),
                        nodes: owned_nodes,
                        targets,
                    });
                }
            }
        }

        if provision_requests.is_empty() {
            return None;
        }

        let mut shard_recipients = HashMap::new();
        for req in &provision_requests {
            for &(target_shard, _) in &req.targets {
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

    /// Get execution memory statistics for monitoring collection sizes.
    pub fn memory_stats(&self) -> ExecutionMemoryStats {
        ExecutionMemoryStats {
            receipt_cache: self.receipt_cache.len(),
            finalized_wave_certificates: self.finalized_wave_certificates.len(),
            waves: self.waves.len(),
            vote_trackers: self.vote_trackers.len(),
            early_votes: self.early_votes.len(),
            expected_exec_certs: self.expected_exec_certs.len(),
            verified_provisions: self.verified_provisions.len(),
            required_provision_shards: self.required_provision_shards.len(),
            received_provision_shards: self.received_provision_shards.len(),
            waves_with_ec: self.waves_with_ec.len(),
            pending_vote_retries: self.pending_vote_retries.len(),
            wave_assignments: self.wave_assignments.len(),
            early_wave_attestations: self.early_wave_attestations.len(),
            pending_routing: self.pending_routing.len(),
            fulfilled_exec_certs: self.fulfilled_exec_certs.len(),
        }
    }

    /// Get the number of cross-shard transactions currently in flight.
    ///
    /// Counts unique transaction hashes in cross-shard waves that haven't yet
    /// finalized. Covers provisioning, voting, and certificate collection
    /// phases uniformly (one `WaveState` tracks all of them).
    pub fn cross_shard_pending_count(&self) -> usize {
        let mut pending_txs = HashSet::new();
        for (wave_id, wave) in &self.waves {
            if !wave_id.is_zero() {
                for h in wave.tx_hashes() {
                    pending_txs.insert(*h);
                }
            }
        }
        pending_txs.len()
    }
}

impl std::fmt::Debug for ExecutionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecutionState")
            .field(
                "finalized_wave_certificates",
                &self.finalized_wave_certificates.len(),
            )
            .field("waves", &self.waves.len())
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

    /// Build a minimal `Block::Live` suitable for driving
    /// `on_block_committed` in tests. The returned block's `hash()` is
    /// derived from a deterministic header built from the inputs.
    fn make_live_block(
        topology: &TopologySnapshot,
        height: u64,
        timestamp: u64,
        proposer: ValidatorId,
        transactions: Vec<Arc<RoutableTransaction>>,
    ) -> Block {
        use hyperscale_types::{BlockHeader, QuorumCertificate};
        let header = BlockHeader {
            shard_group_id: topology.local_shard(),
            height: BlockHeight(height),
            parent_hash: Hash::ZERO,
            parent_qc: QuorumCertificate::genesis(),
            proposer,
            timestamp,
            round: 0,
            is_fallback: false,
            state_root: Hash::ZERO,
            transaction_root: Hash::ZERO,
            certificate_root: Hash::ZERO,
            local_receipt_root: Hash::ZERO,
            provision_root: Hash::ZERO,
            waves: vec![],
            in_flight: 0,
        };
        Block::Live {
            header,
            transactions,
            certificates: vec![],
            provisions: vec![],
        }
    }

    #[test]
    fn test_execution_state_creation() {
        let state = make_test_state();
        assert!(state.finalized_wave_certificates.is_empty());
    }

    #[test]
    fn test_single_shard_execution_flow() {
        let mut state = make_test_state();
        let topology = make_test_topology();

        let tx = test_transaction(1);
        let tx_hash = tx.hash();
        let block = make_live_block(
            &topology,
            1,
            1000,
            ValidatorId(0),
            vec![Arc::new(tx.clone())],
        );

        // Block committed with transaction
        let actions = state.on_block_committed(&topology, &block);

        // Should request execution (single-shard path) and set up wave tracking
        assert!(!actions.is_empty());
        // First action should be ExecuteTransactions
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::ExecuteTransactions { .. })));

        // WaveState should be set up for this wave.
        let wave_id = state.wave_assignments.get(&tx_hash).cloned();
        assert!(wave_id.is_some());
        assert!(state.waves.contains_key(&wave_id.unwrap()));
    }

    // ========================================================================
    // Crypto Verification Tests - Using real BLS signatures
    // ========================================================================

    #[test]
    fn test_shard_execution_proof_basic() {
        use hyperscale_types::ExecutionOutcome;

        let receipt_hash = Hash::from_bytes(b"commitment");
        let proof = ExecutionOutcome::Executed {
            receipt_hash,
            success: true,
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
        let wave_id = WaveId::new(ShardGroupId(0), 0, BTreeSet::new());

        // Different receipt roots = different messages
        let root1 = Hash::from_bytes(b"root1");
        let root2 = Hash::from_bytes(b"root2");
        let root3 = Hash::from_bytes(b"root3");

        let msg1 = hyperscale_types::exec_vote_message(1, &wave_id, shard, &root1, 1);
        let msg2 = hyperscale_types::exec_vote_message(1, &wave_id, shard, &root2, 1);
        let msg3 = hyperscale_types::exec_vote_message(1, &wave_id, shard, &root3, 1);

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
        let wave_id = WaveId::new(ShardGroupId(0), 0, BTreeSet::new());

        let root1 = Hash::from_bytes(b"root1");
        let root2 = Hash::from_bytes(b"root2");

        let msg1 = hyperscale_types::exec_vote_message(1, &wave_id, shard, &root1, 1);
        let msg2 = hyperscale_types::exec_vote_message(1, &wave_id, shard, &root2, 1);

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

    // ========================================================================
    // Wave Leader Tests
    // ========================================================================

    /// Build a topology where the given validator_id is the local validator.
    fn make_topology_for(local_vid: u64) -> TopologySnapshot {
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
        TopologySnapshot::new(ValidatorId(local_vid), 1, validator_set)
    }

    #[test]
    fn test_only_leader_gets_vote_tracker() {
        let tx = test_transaction(1);

        // Determine who the wave leader will be for this block's wave.
        let topo0 = make_topology_for(0);
        let committee = topo0.local_committee().to_vec();
        let block = make_live_block(&topo0, 1, 1000, ValidatorId(0), vec![Arc::new(tx.clone())]);

        // Commit the block as validator 0 to discover the wave_id.
        let mut state0 = make_test_state();
        state0.on_block_committed(&topo0, &block);
        let wave_id = state0.wave_assignments.values().next().unwrap().clone();

        let leader = hyperscale_types::wave_leader(&wave_id, &committee);

        // Leader should have a VoteTracker.
        let topo_leader = make_topology_for(leader.0);
        let block_leader = make_live_block(
            &topo_leader,
            1,
            1000,
            ValidatorId(0),
            vec![Arc::new(tx.clone())],
        );
        let mut state_leader = make_test_state();
        state_leader.on_block_committed(&topo_leader, &block_leader);
        assert!(
            state_leader.vote_trackers.contains_key(&wave_id),
            "Leader should have VoteTracker"
        );

        // A non-leader should NOT have a VoteTracker.
        let non_leader_id = committee.iter().find(|&&v| v != leader).unwrap();
        let topo_non = make_topology_for(non_leader_id.0);
        let block_non = make_live_block(
            &topo_non,
            1,
            1000,
            ValidatorId(0),
            vec![Arc::new(tx.clone())],
        );
        let mut state_non = make_test_state();
        state_non.on_block_committed(&topo_non, &block_non);
        assert!(
            !state_non.vote_trackers.contains_key(&wave_id),
            "Non-leader should NOT have VoteTracker"
        );
    }

    #[test]
    fn test_fallback_tracker_created_on_vote() {
        let tx = test_transaction(1);
        let topo = make_topology_for(0);
        let committee = topo.local_committee().to_vec();
        let block = make_live_block(&topo, 1, 1000, ValidatorId(0), vec![Arc::new(tx.clone())]);
        let block_hash = block.hash();

        let mut state = make_test_state();
        state.on_block_committed(&topo, &block);

        let wave_id = state.wave_assignments.values().next().unwrap().clone();
        let leader = hyperscale_types::wave_leader(&wave_id, &committee);

        // If we're the leader, this test doesn't apply — find a non-leader topology.
        let non_leader_id = committee.iter().find(|&&v| v != leader).unwrap();
        let topo_non = make_topology_for(non_leader_id.0);
        let block_non = make_live_block(
            &topo_non,
            1,
            1000,
            ValidatorId(0),
            vec![Arc::new(tx.clone())],
        );
        let mut state_non = make_test_state();
        state_non.on_block_committed(&topo_non, &block_non);

        assert!(!state_non.vote_trackers.contains_key(&wave_id));
        assert!(state_non.waves.contains_key(&wave_id));

        // Simulate receiving a vote (as if we're a fallback leader).
        let fake_vote = ExecutionVote {
            block_hash,
            block_height: 1,
            vote_height: 0,
            wave_id: wave_id.clone(),
            shard_group_id: ShardGroupId(0),
            global_receipt_root: Hash::ZERO,
            tx_count: 1,
            tx_outcomes: vec![],
            validator: leader, // vote from the original leader
            signature: hyperscale_types::zero_bls_signature(),
        };

        state_non.on_execution_vote(&topo_non, fake_vote);

        // Should have created a fallback VoteTracker.
        assert!(
            state_non.vote_trackers.contains_key(&wave_id),
            "Fallback VoteTracker should be created"
        );
    }

    #[test]
    fn test_vote_retry_timeout_emits_rotated_action() {
        let wave_id = WaveId::new(ShardGroupId(0), 1, BTreeSet::new());
        let topo = make_test_topology();
        let committee = topo.local_committee().to_vec();

        let mut state = make_test_state();
        state.committed_height = 10;

        // Manually insert a pending retry as if we'd sent a vote at height 5.
        state.pending_vote_retries.insert(
            wave_id.clone(),
            PendingVoteRetry {
                sent_at_height: 5,
                attempt: 0,
                block_hash: Hash::from_bytes(b"block1"),
                block_height: 1,
                vote_height: 0,
                global_receipt_root: Hash::ZERO,
                tx_outcomes: Arc::new(vec![]),
            },
        );

        let actions = state.check_vote_retry_timeouts(&topo);

        // Height 10 - 5 = 5 >= VOTE_RETRY_BLOCKS (5), so should emit retry.
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            Action::SignAndSendExecutionVote {
                leader,
                wave_id: wid,
                ..
            } => {
                assert_eq!(wid, &wave_id);
                let expected_leader = hyperscale_types::wave_leader_at(&wave_id, 1, &committee);
                assert_eq!(*leader, expected_leader, "Should rotate to attempt 1");
            }
            other => panic!(
                "Expected SignAndSendExecutionVote, got {:?}",
                other.type_name()
            ),
        }

        // Pending retry should be updated to attempt 1.
        let retry = state.pending_vote_retries.get(&wave_id).unwrap();
        assert_eq!(retry.attempt, 1);
        assert_eq!(retry.sent_at_height, 10);
    }

    #[test]
    fn test_vote_retry_cancelled_on_ec_receipt() {
        let wave_id = WaveId::new(ShardGroupId(0), 1, BTreeSet::new());
        let topo = make_test_topology();

        let mut state = make_test_state();
        state.committed_height = 10;
        state.pending_vote_retries.insert(
            wave_id.clone(),
            PendingVoteRetry {
                sent_at_height: 5,
                attempt: 0,
                block_hash: Hash::from_bytes(b"block1"),
                block_height: 1,
                vote_height: 0,
                global_receipt_root: Hash::ZERO,
                tx_outcomes: Arc::new(vec![]),
            },
        );

        assert!(state.pending_vote_retries.contains_key(&wave_id));

        // Simulate receiving a verified local shard EC.
        let cert = hyperscale_types::ExecutionCertificate::new(
            wave_id.clone(),
            0,
            Hash::ZERO,
            vec![],
            hyperscale_types::zero_bls_signature(),
            hyperscale_types::SignerBitfield::new(4),
        );
        state.on_certificate_verified(&topo, cert, true);

        // Retry should be cancelled.
        assert!(
            !state.pending_vote_retries.contains_key(&wave_id),
            "Retry should be cancelled on EC receipt"
        );
    }

    #[test]
    fn test_leader_broadcasts_ec_locally() {
        let wave_id = WaveId::new(ShardGroupId(0), 1, [ShardGroupId(1)].into_iter().collect());
        let topo = make_test_topology();

        let mut state = make_test_state();

        let cert = hyperscale_types::ExecutionCertificate::new(
            wave_id.clone(),
            0,
            Hash::ZERO,
            vec![],
            hyperscale_types::zero_bls_signature(),
            hyperscale_types::SignerBitfield::new(4),
        );

        let actions = state.on_certificate_aggregated(&topo, wave_id, cert);

        // Should have: TrackExecutionCertificate + BroadcastEC(local) + BroadcastEC(remote shard 1)
        let broadcast_actions: Vec<_> = actions
            .iter()
            .filter(|a| matches!(a, Action::BroadcastExecutionCertificate { .. }))
            .collect();

        assert!(
            broadcast_actions.len() >= 2,
            "Should broadcast to local peers AND remote shards, got {}",
            broadcast_actions.len()
        );

        // One should be for the local shard (shard 0).
        let has_local = broadcast_actions.iter().any(|a| match a {
            Action::BroadcastExecutionCertificate { shard, .. } => *shard == ShardGroupId(0),
            _ => false,
        });
        assert!(has_local, "Should include local shard broadcast");

        // One should be for the remote shard (shard 1).
        let has_remote = broadcast_actions.iter().any(|a| match a {
            Action::BroadcastExecutionCertificate { shard, .. } => *shard == ShardGroupId(1),
            _ => false,
        });
        assert!(has_remote, "Should include remote shard broadcast");
    }

    // ========================================================================
    // Expected Execution Cert Retention
    // ========================================================================

    /// Multi-shard topology for expected-cert tests: 4 validators, 2 shards.
    /// Local is validator 0 (shard 0); shard 1 = {1, 3}.
    fn make_two_shard_topology() -> TopologySnapshot {
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
        TopologySnapshot::new(ValidatorId(0), 2, ValidatorSet::new(validators))
    }

    /// `expected_exec_certs` entries must be retained while any local
    /// `WaveState` still lists their source shard as a participating remote —
    /// otherwise a cross-shard wave whose remote EC missed the broadcast
    /// window would be stranded once the expectation aged out, with no
    /// fallback fetch continuing to fire.
    #[test]
    fn test_expected_exec_cert_retained_while_tracker_pending() {
        use hyperscale_types::test_utils::test_transaction;
        use std::collections::BTreeSet;

        let topo = make_two_shard_topology();
        let mut state = make_test_state();

        let remote_shard = ShardGroupId(1);
        let remote_wave = WaveId::new(remote_shard, 5, [ShardGroupId(0)].into_iter().collect());
        state.on_verified_remote_header(&topo, remote_shard, 5, std::slice::from_ref(&remote_wave));
        assert_eq!(
            state.expected_exec_certs.len(),
            1,
            "expectation should register for wave targeting local shard"
        );

        // Simulate an outstanding local cross-shard wave needing shard 1's EC.
        let local_wave = WaveId::new(ShardGroupId(0), 10, [remote_shard].into_iter().collect());
        let tx = Arc::new(test_transaction(7));
        let tx_hash = tx.hash();
        let mut participating = BTreeSet::new();
        participating.insert(ShardGroupId(0));
        participating.insert(remote_shard);
        state.waves.insert(
            local_wave.clone(),
            WaveState::new(
                local_wave.clone(),
                Hash::from_bytes(b"block"),
                10,
                vec![(tx, participating)],
                false,
            ),
        );
        state.wave_assignments.insert(tx_hash, local_wave.clone());

        // Advance committed_height far enough that age-based pruning would
        // otherwise evict the expectation.
        state.committed_height = 500;
        let actions = state.check_exec_cert_timeouts(&topo);

        assert_eq!(
            state.expected_exec_certs.len(),
            1,
            "expectation must survive age pruning while a local wave still needs shard 1"
        );
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::RequestMissingExecutionCert { .. })),
            "fallback fetch must keep firing while the expectation is retained"
        );

        // Once the local wave resolves (simulating finalize_wave), the
        // expectation is no longer needed and gets pruned.
        state.waves.remove(&local_wave);
        state.wave_assignments.remove(&tx_hash);
        state.committed_height = 600;
        let _ = state.check_exec_cert_timeouts(&topo);
        assert!(
            state.expected_exec_certs.is_empty(),
            "expectation must be pruned once no wave needs the source shard"
        );
    }
}
