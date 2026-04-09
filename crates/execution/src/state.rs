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
//! proofs are received, a WaveCertificate is created.

use hyperscale_core::{Action, CrossShardExecutionRequest, ProtocolEvent, ProvisionRequest};
use hyperscale_types::{
    AbortReason, BlockHeight, Bls12381G1PublicKey, ExecutionCertificate, ExecutionResult,
    ExecutionVote, Hash, LocalReceipt, ReceiptBundle, RoutableTransaction, ShardGroupId,
    StateProvision, TopologySnapshot, TransactionDecision, TxExecutionOutcome, TxOutcome,
    ValidatorId, WaveCertificate, WaveId,
};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tracing::instrument;

use crate::accumulator::ExecutionAccumulator;
use crate::trackers::{VoteTracker, WaveCertificateTracker};

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

// FinalizedWave is defined in hyperscale_types (TxDecision comes via crate::trackers).
use hyperscale_types::FinalizedWave;

/// Execution memory statistics for monitoring collection sizes.
#[derive(Clone, Copy, Debug, Default)]
pub struct ExecutionMemoryStats {
    pub receipt_cache: usize,
    pub finalized_wave_certificates: usize,
    pub pending_provisioning: usize,
    pub accumulators: usize,
    pub vote_trackers: usize,
    pub early_votes: usize,
    pub wave_certificate_trackers: usize,
    pub expected_exec_certs: usize,
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
    /// Keyed by WaveId (globally unique: shard_group_id + block_height + remote_shards).
    accumulators: HashMap<WaveId, ExecutionAccumulator>,

    /// Execution vote trackers: collect execution votes from other validators.
    /// Keyed by WaveId. Only created on the wave leader.
    vote_trackers: HashMap<WaveId, VoteTracker>,

    /// Waves that have a canonical EC (aggregated by leader, or received from leader).
    /// Used to stop re-voting in `scan_complete_waves`. Replaces the old check of
    /// "VoteTracker absent" now that only wave leaders create VoteTrackers.
    waves_with_ec: HashSet<WaveId>,

    /// Tx → wave assignment lookup for the current block.
    /// Maps tx_hash → WaveId.
    wave_assignments: HashMap<Hash, WaveId>,

    /// Early execution votes that arrived before tracking started.
    /// Keyed by WaveId. Only buffered for the wave leader.
    early_votes: HashMap<WaveId, Vec<ExecutionVote>>,

    // ═══════════════════════════════════════════════════════════════════════
    // Cross-shard state (Phase 5: Finalization)
    // ═══════════════════════════════════════════════════════════════════════
    /// Wave certificate trackers for wave-level finalization.
    /// Maps WaveId -> WaveCertificateTracker. One tracker per wave.
    wave_certificate_trackers: HashMap<WaveId, WaveCertificateTracker>,

    // ═══════════════════════════════════════════════════════════════════════
    // Early arrivals (before tracking starts)
    // ═══════════════════════════════════════════════════════════════════════
    /// Execution results that arrived before the wave was assigned.
    /// Maps tx_hash -> TxExecutionOutcome. Replayed during assign_waves.
    early_execution_results: HashMap<Hash, TxExecutionOutcome>,

    /// ProvisioningComplete events that arrived before the block was committed.
    /// This can happen when provisions reach quorum before we've seen the block.
    /// Maps tx_hash -> (provisions, first_arrival_height) for cleanup of stale entries.
    early_provisioning_complete: HashMap<Hash, (Vec<StateProvision>, u64)>,

    /// Execution certificates that arrived before the wave tracker was created.
    /// Keyed by WaveId, storing Arc<ExecutionCertificate> with first_arrival_height.
    /// ECs that arrived before their local wave tracker was created.
    /// Replayed through handle_wave_attestation after setup_execution_tracking.
    early_wave_attestations: Vec<(Arc<ExecutionCertificate>, u64)>,

    /// Waves whose tracker completed but some txs still need receipts emitted.
    /// Maps WaveId -> set of tx_hashes still missing receipts. When the set
    /// becomes empty, `finalize_wave` is called.
    pending_wave_receipts: HashMap<WaveId, HashSet<Hash>>,

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

impl ExecutionState {
    /// Create a new execution state machine.
    pub fn new() -> Self {
        Self {
            now: Duration::ZERO,
            receipt_cache: HashMap::new(),
            finalized_wave_certificates: BTreeMap::new(),
            committed_height: 0,
            pending_provisioning: HashMap::new(),
            accumulators: HashMap::new(),
            vote_trackers: HashMap::new(),
            waves_with_ec: HashSet::new(),
            wave_assignments: HashMap::new(),
            early_votes: HashMap::new(),
            wave_certificate_trackers: HashMap::new(),
            early_execution_results: HashMap::new(),
            early_provisioning_complete: HashMap::new(),
            early_wave_attestations: Vec::new(),
            pending_wave_receipts: HashMap::new(),
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
    /// Returns a map from WaveId to list of (tx_hash, participating_shards) in
    /// block order within each wave.
    fn assign_waves(
        &self,
        topology: &TopologySnapshot,
        block_height: u64,
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

            let wave_id = WaveId::new(local_shard, block_height, remote_shards);
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
        let waves = self.assign_waves(topology, block_height, transactions);
        let quorum = topology.local_quorum_threshold();
        let mut votes_to_replay = Vec::new();

        let local_vid = topology.local_validator_id();
        let local_committee = topology.local_committee();

        for (wave_id, txs) in waves {
            // Record tx → wave assignments
            for (tx_hash, _) in &txs {
                self.wave_assignments.insert(*tx_hash, wave_id.clone());
            }

            // Create WaveCertificateTracker for finalization.
            // Build tx_participating_shards from the wave's transaction data.
            let local_shard = topology.local_shard();
            let tx_participating_shards: BTreeMap<Hash, BTreeSet<ShardGroupId>> = txs
                .iter()
                .map(|(tx_hash, _participating)| {
                    let shards: BTreeSet<ShardGroupId> = if wave_id.is_zero() {
                        // Single-shard wave: only local shard participates
                        [local_shard].into_iter().collect()
                    } else {
                        // Cross-shard wave: local shard + remote shards
                        let mut s: BTreeSet<ShardGroupId> =
                            wave_id.remote_shards.iter().copied().collect();
                        s.insert(local_shard);
                        s
                    };
                    (*tx_hash, shards)
                })
                .collect();
            if !self.wave_certificate_trackers.contains_key(&wave_id) {
                let wct = WaveCertificateTracker::new(
                    wave_id.clone(),
                    tx_participating_shards,
                    self.committed_height,
                );
                self.wave_certificate_trackers.insert(wave_id.clone(), wct);
            }

            // Create accumulator
            let mut accumulator =
                ExecutionAccumulator::new(wave_id.clone(), block_hash, block_height, txs);

            // Single-shard txs are always provisioned (no remote state needed).
            if wave_id.is_zero() {
                for tx_hash in accumulator.tx_hashes() {
                    accumulator.mark_provisioned(tx_hash);
                }
            }

            self.accumulators.insert(wave_id.clone(), accumulator);

            // Only the wave leader creates a VoteTracker and aggregates votes.
            // Non-leaders receive the canonical EC from the wave leader via
            // on_wave_certificate → on_certificate_verified.
            let leader = hyperscale_types::wave_leader(&wave_id, local_committee);
            if local_vid == leader {
                let tracker = VoteTracker::new(wave_id.clone(), block_hash, quorum);
                self.vote_trackers.insert(wave_id.clone(), tracker);

                // Collect early execution votes for caller to replay through on_execution_vote()
                if let Some(early_votes) = self.early_votes.remove(&wave_id) {
                    tracing::debug!(
                        block_hash = ?block_hash,
                        wave = %wave_id,
                        count = early_votes.len(),
                        "Replaying early execution votes"
                    );
                    votes_to_replay.extend(early_votes);
                }
            } else {
                // Non-leader: discard any buffered votes (we won't aggregate them)
                self.early_votes.remove(&wave_id);
            }
        }

        // Replay any early execution results that arrived before wave setup.
        let mut early_tx_hashes: Vec<Hash> = self
            .early_execution_results
            .keys()
            .filter(|h| self.wave_assignments.contains_key(h))
            .copied()
            .collect();
        early_tx_hashes.sort();
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
                .filter(|(_, acc)| acc.block_hash() == block_hash)
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
            // Wave not assigned yet (e.g. execution completed before
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
    /// global_receipt_root regardless of execution timing.
    ///
    /// Updates the accumulator silently. Votes are NOT emitted here — they are
    /// emitted during the block commit wave scan (`scan_complete_waves`).
    ///
    /// A missing wave assignment means the transaction already reached terminal
    /// state (TC committed) — the abort intent is a harmless late arrival.
    pub fn record_abort_intent(
        &mut self,
        tx_hash: Hash,
        reason: AbortReason,
        committed_at_height: u64,
    ) {
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
                wave = %wave_key,
                "Abort intent: no accumulator for wave"
            );
            return;
        };

        accumulator.record_abort(tx_hash, committed_at_height, reason);
    }

    /// Scan all waves and return completion data for any that can emit a vote.
    ///
    /// Called at each block commit AFTER abort intents have been processed,
    /// and also when provisions arrive or execution results complete.
    ///
    /// A wave can emit a vote when:
    /// 1. A target vote height exists (all txs coverable)
    /// 2. All execution-covered txs at that height have results
    /// 3. The target height is lower than any previous vote (re-vote downward only)
    ///
    /// Waves that already had an EC formed are skipped.
    pub fn scan_complete_waves(&mut self) -> Vec<CompletionData> {
        // Two-pass: first identify votable waves, then build data.
        // Split borrow: check waves_with_ec first, then mutably iterate accumulators.
        let waves_with_ec = &self.waves_with_ec;
        let candidate_ids: Vec<WaveId> = self
            .accumulators
            .keys()
            .filter(|wid| !waves_with_ec.contains(*wid))
            .cloned()
            .collect();

        let mut votable_wave_ids = Vec::new();
        for wave_id in &candidate_ids {
            if let Some(acc) = self.accumulators.get_mut(wave_id) {
                if acc.can_emit_vote() {
                    votable_wave_ids.push(wave_id.clone());
                }
            }
        }

        let mut completions = Vec::new();
        for wave_id in votable_wave_ids {
            let accumulator = self.accumulators.get_mut(&wave_id).unwrap();
            let Some((vote_height, global_receipt_root, tx_outcomes)) =
                accumulator.build_vote_data()
            else {
                continue;
            };

            completions.push(CompletionData {
                block_hash: accumulator.block_hash(),
                block_height: accumulator.block_height(),
                vote_height,
                wave_id: accumulator.wave_id().clone(),
                global_receipt_root,
                tx_outcomes,
            });
        }

        // Sort for deterministic ordering (accumulators is a HashMap).
        completions.sort_by(|a, b| a.wave_id.cmp(&b.wave_id));

        completions
    }

    /// Process a completed execution batch: build receipt bundles, update cache, record outcomes.
    ///
    /// Moves receipt-bundle construction and cache insertion out of the node orchestrator.
    pub fn on_execution_batch_completed(
        &mut self,
        results: Vec<ExecutionResult>,
        tx_outcomes: Vec<TxOutcome>,
    ) -> Vec<Action> {
        let mut newly_emitted: HashSet<Hash> = HashSet::with_capacity(results.len());

        for result in results {
            let tx_hash = result.tx_hash;
            let bundle = ReceiptBundle {
                tx_hash,
                local_receipt: Arc::new(result.local_receipt),
                execution_output: Some(result.execution_output),
            };
            self.receipt_cache.insert(tx_hash, bundle);
            newly_emitted.insert(tx_hash);
        }

        // Also write receipts to storage eagerly for read access by
        // VerifyStateRoot and BuildProposal action handlers (which run on
        // Receipts are held in receipt_cache → FinalizedWave.receipts → atomic
        // block commit. No eager storage writes needed.
        let mut actions: Vec<Action> = Vec::new();
        if newly_emitted.is_empty() {
            tracing::warn!(
                results_count = 0,
                "ExecutionBatchCompleted produced ZERO receipts"
            );
        }

        // Check pending_wave_receipts: waves whose tracker completed but some
        // txs were still missing receipts. Now that receipts have been emitted,
        // check if any pending wave's missing set is now empty → finalize it.
        let waves_to_check: Vec<WaveId> = self
            .pending_wave_receipts
            .iter()
            .filter(|(_, missing)| missing.iter().any(|h| newly_emitted.contains(h)))
            .map(|(wid, _)| wid.clone())
            .collect();
        for wave_id in waves_to_check {
            if let Some(missing) = self.pending_wave_receipts.get_mut(&wave_id) {
                missing.retain(|h| !self.receipt_cache.contains_key(h));
                if missing.is_empty() {
                    // All receipts emitted — finalize this wave.
                    // Need topology for finalize_wave, but we don't have it here.
                    // Instead, just remove the pending entry; finalize_wave will be
                    // called from handle_wave_attestation or directly.
                    // We can call finalize_wave without topology since it only needs
                    // it for the continuation events.
                    actions.extend(self.finalize_wave(&wave_id));
                }
            }
        }

        // Record outcomes into execution accumulators silently.
        // Votes are emitted during the block commit wave scan, not here.
        for wr in tx_outcomes {
            self.record_execution_result(wr.tx_hash, wr.outcome);
        }

        actions
    }

    /// Overwrite cached receipts for transactions the EC declares as aborted.
    ///
    /// The EC is the canonical source of truth for abort decisions. Canonical
    /// execution may have already cached a success receipt before
    /// the abort was decided at the aggregated vote_height. This replaces those
    /// stale receipts with `LocalReceipt::failure()` so that any
    /// downstream consumer (sync, RPC, state root) sees a consistent abort.
    ///
    /// Only processes the LOCAL shard's EC — remote shard ECs don't produce
    /// local receipts.
    fn overwrite_aborted_receipts(&mut self, certificate: &hyperscale_types::ExecutionCertificate) {
        let mut count = 0;
        for outcome in &certificate.tx_outcomes {
            if outcome.is_aborted() {
                self.receipt_cache.insert(
                    outcome.tx_hash,
                    ReceiptBundle {
                        tx_hash: outcome.tx_hash,
                        local_receipt: Arc::new(LocalReceipt::failure()),
                        execution_output: None,
                    },
                );
                count += 1;
            }
        }

        if count > 0 {
            tracing::debug!(
                wave = %certificate.wave_id,
                abort_count = count,
                "Overwrote cached receipts for EC-aborted transactions"
            );
        }
    }

    /// Scan complete waves and emit `SignAndSendExecutionVote` actions.
    ///
    /// This is the SINGLE path to execution voting. Call after abort intents
    /// have been processed so accumulator state is deterministic at this height.
    /// Each vote is targeted to the wave leader (N→1 routing).
    ///
    /// The vote_height is now a relative offset determined by the accumulator
    /// (lowest height where all txs are coverable), not passed in externally.
    pub fn emit_vote_actions(&mut self, topology: &TopologySnapshot) -> Vec<Action> {
        let local_committee = topology.local_committee();
        self.scan_complete_waves()
            .into_iter()
            .map(|completion| {
                let target = hyperscale_types::wave_leader(&completion.wave_id, local_committee);
                Action::SignAndSendExecutionVote {
                    block_hash: completion.block_hash,
                    block_height: completion.block_height,
                    vote_height: completion.vote_height,
                    wave_id: completion.wave_id,
                    global_receipt_root: completion.global_receipt_root,
                    tx_outcomes: completion.tx_outcomes,
                    target,
                }
            })
            .collect()
    }

    /// Process committed wave certificates: remove finalized per-tx state for all
    /// transactions whose certificates were included in the committed block.
    ///
    /// Returns `(tx_hash, decision)` pairs for each committed transaction, so the
    /// caller can forward them to the mempool for terminal state transitions.
    ///
    /// Wave certs are lean (no per-tx data). We look up the per-tx
    /// WaveCertificate from finalized_certificates to get tx_hash + decision,
    /// then clean up the finalized entry.
    pub fn on_certificates_committed(
        &mut self,
        certificates: &[Arc<hyperscale_types::WaveCertificate>],
    ) -> Vec<(Hash, hyperscale_types::TransactionDecision)> {
        if certificates.is_empty() {
            return vec![];
        }

        let mut committed_txs = Vec::new();

        for wc in certificates {
            let wave_id = &wc.wave_id;
            if let Some(finalized) = self.finalized_wave_certificates.get(wave_id) {
                // Extract per-tx decisions from the finalized wave
                for d in &finalized.tx_decisions {
                    committed_txs.push((d.tx_hash, d.decision));
                }
            }
            // Clean up all state associated with this wave
            self.remove_finalized_wave(wave_id);
        }

        committed_txs
    }

    /// Record abort intents from a committed block into execution accumulators.
    ///
    /// `committed_at_height` is the local block height at which these intents
    /// were committed. Used for height-indexed abort tracking in the re-voting
    /// protocol.
    pub fn record_abort_intents(
        &mut self,
        intents: &[hyperscale_types::AbortIntent],
        committed_at_height: u64,
    ) {
        for intent in intents {
            self.record_abort_intent(intent.tx_hash, intent.reason.clone(), committed_at_height);
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
        let wave_id = vote.wave_id.clone();
        let validator_id = vote.validator;

        // Check if we're tracking this wave (only wave leaders have VoteTrackers)
        if !self.vote_trackers.contains_key(&wave_id) {
            // If we have an accumulator for this wave but no VoteTracker,
            // we're a non-leader — discard the vote.
            if self.accumulators.contains_key(&wave_id) {
                return vec![];
            }
            // No accumulator yet — block hasn't committed. Buffer for the
            // wave leader case (will be discarded in setup if non-leader).
            self.early_votes.entry(wave_id).or_default().push(vote);
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
        // Mark wave as having an EC to stop re-voting in scan_complete_waves.
        self.vote_trackers.remove(&wave_id);
        self.waves_with_ec.insert(wave_id.clone());

        tracing::debug!(
            block_hash = ?block_hash,
            wave = %wave_id,
            votes = votes.len(),
            "Delegating BLS aggregation to crypto pool"
        );

        // tx_outcomes are extracted from votes by the aggregation handler
        // (all quorum votes carry identical outcomes).
        vec![Action::AggregateExecutionCertificate {
            wave_id,
            shard: topology.local_shard(),
            global_receipt_root,
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

        // The wave_id IS the set of remote shards — no need to look up the
        // accumulator (which may have been pruned by the time the cert is
        // aggregated, especially with many shards where provision flow is slower).
        let remote_shards: Vec<ShardGroupId> = wave_id.remote_shards.iter().copied().collect();

        let certificate = Arc::new(certificate);

        // Cache the cert in io_loop for fallback serving — any node can serve
        // requests from remote shards if the wave leader fails.
        actions.push(Action::TrackExecutionCertificate {
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
            wave = %wave_id,
            tx_count = certificate.tx_outcomes.len(),
            remote_shards = remote_shards.len(),
            "Wave leader broadcasting EC to local peers + remote shards"
        );

        // The EC is canonical — if it says a tx is aborted, the stored receipt
        // must reflect that. Canonical execution may have stored
        // a success receipt before the abort was decided. Overwrite now.
        self.overwrite_aborted_receipts(&certificate);

        // Feed the EC to the wave-level certificate tracker for finalization.
        actions.extend(self.handle_wave_attestation(topology, certificate));

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
        let shard = cert.shard_group_id();
        let current_height = self.committed_height;

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
                .and_then(|wid| self.wave_certificate_trackers.get(wid))
                .is_some()
        });

        if !has_any_tracker {
            // No tracker yet — buffer entire EC for later replay when block commits
            let ec_arc = Arc::new(cert);
            self.early_wave_attestations.push((ec_arc, current_height));
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
        // (block_hash is no longer needed in the signing message — WaveId is self-contained)
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
                shard = certificate.shard_group_id().0,
                wave = %certificate.wave_id,
                "Invalid execution certificate signature"
            );
            return vec![];
        }

        let shard = certificate.shard_group_id();
        let current_height = self.committed_height;
        let mut actions = Vec::new();

        // If this is a local shard EC from the wave leader, mark the wave as
        // having an EC so non-leaders stop re-voting in scan_complete_waves,
        // and persist it for fallback serving to remote shards.
        if shard == topology.local_shard() {
            self.waves_with_ec.insert(certificate.wave_id.clone());
            let cert_arc = Arc::new(certificate.clone());
            actions.push(Action::TrackExecutionCertificate {
                certificate: cert_arc.clone(),
            });

            // The EC is canonical — overwrite any stale success receipts for
            // transactions the EC declares as aborted.
            self.overwrite_aborted_receipts(&cert_arc);
        }

        // Feed EC to wave-level certificate tracker via tx-hash routing,
        // or buffer if no local tracker covers any of its txs yet.
        let ec_arc = Arc::new(certificate);
        let has_any_tracker = ec_arc.tx_outcomes.iter().any(|o| {
            self.wave_assignments
                .get(&o.tx_hash)
                .and_then(|wid| self.wave_certificate_trackers.get(wid))
                .is_some()
        });
        if has_any_tracker {
            actions.extend(self.handle_wave_attestation(topology, ec_arc));
        } else {
            // Buffer for later replay when block commits and tracker is created
            self.early_wave_attestations.push((ec_arc, current_height));
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
                let committee = topology.committee_for_shard(*source_shard);
                let leader = hyperscale_types::wave_leader(wave_id, committee);
                let peers = committee.to_vec();
                tracing::info!(
                    source_shard = source_shard.0,
                    block_height = block_height,
                    wave = %wave_id,
                    wave_leader = leader.0,
                    age,
                    retry = is_retry,
                    "Execution cert timeout — requesting fallback"
                );
                actions.push(Action::RequestMissingExecutionCert {
                    source_shard: *source_shard,
                    block_height: *block_height,
                    wave_id: wave_id.clone(),
                    wave_leader: leader,
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
            let has_waiting_tx = self.wave_assignments.iter().any(|(_, wid)| wid == wave_id);
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

        // Update committed height before anything else — needed for timeout
        // calculations and pruning even when there are no new transactions.
        if height > self.committed_height {
            self.committed_height = height;
        }

        // Check for timed-out expected execution certs and prune stale entries.
        // Must run every block, not just when there are new transactions.
        actions.extend(self.check_exec_cert_timeouts(topology));

        // Check for waves whose wave leader has completely failed (no EC at all).
        // Prune ephemeral state (orphaned provisions).
        // Cross-shard resolution state (certificate trackers, finalized certs,
        // pending provisioning, execution cache, early arrivals) is only cleaned
        // up on terminal state — never by block-count timeout.
        self.prune_execution_state();

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

        // Handle single-shard transactions — set up tracking and execute
        for tx in &single_shard {
            actions.extend(self.start_single_shard_execution(topology, tx.clone()));
        }

        if !single_shard.is_empty() {
            actions.push(Action::ExecuteTransactions {
                block_hash,
                transactions: single_shard,
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

        // Replay ALL buffered early ECs now that wave trackers exist.
        // handle_wave_attestation routes each EC to the correct local wave(s)
        // via tx_hash → wave_assignments lookup.
        let early_ecs: Vec<_> = std::mem::take(&mut self.early_wave_attestations);
        if !early_ecs.is_empty() {
            tracing::debug!(
                count = early_ecs.len(),
                "Replaying early wave attestations after tracker creation"
            );
            for (ec, _arrival_height) in early_ecs {
                actions.extend(self.handle_wave_attestation(topology, ec));
            }
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
        let actions = Vec::new();
        let tx_hash = tx.hash();
        let local_shard = topology.local_shard();

        tracing::debug!(
            tx_hash = ?tx_hash,
            shard = local_shard.0,
            "Starting single-shard execution tracking"
        );

        // Early EC replay is handled in on_block_committed after all trackers are created.
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
        let actions = Vec::new();
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

        // Early EC replay is handled in on_block_committed after all trackers are created.
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
            tracing::info!(
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

        // Mark as provisioned in accumulator for vote height tracking
        if let Some(wave_key) = self.wave_assignments.get(&tx_hash) {
            if let Some(acc) = self.accumulators.get_mut(wave_key) {
                acc.mark_provisioned(tx_hash);
            }
        }

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

    /// Handle a wave-level attestation (execution certificate) from any shard.
    ///
    /// A remote EC's wave_id reflects the remote shard's wave decomposition,
    /// which differs from the local shard's. A single remote EC may contain
    /// outcomes for transactions in MULTIPLE local waves.
    ///
    /// Routing: iterate tx_outcomes → look up local wave via wave_assignments →
    /// feed the EC to each affected local wave tracker.
    fn handle_wave_attestation(
        &mut self,
        _topology: &TopologySnapshot,
        ec: Arc<ExecutionCertificate>,
    ) -> Vec<Action> {
        // Find all local waves affected by this EC's tx_outcomes.
        let mut affected_waves: BTreeSet<WaveId> = BTreeSet::new();
        for outcome in &ec.tx_outcomes {
            if let Some(local_wave_id) = self.wave_assignments.get(&outcome.tx_hash) {
                affected_waves.insert(local_wave_id.clone());
            }
        }

        if affected_waves.is_empty() {
            return vec![];
        }

        // Feed the EC to each affected local wave tracker.
        let mut completed_waves: Vec<WaveId> = Vec::new();
        for wave_id in &affected_waves {
            let Some(tracker) = self.wave_certificate_trackers.get_mut(wave_id) else {
                continue;
            };
            if tracker.add_execution_certificate(Arc::clone(&ec)) {
                completed_waves.push(wave_id.clone());
            }
        }

        // For each completed wave, check receipt availability and finalize.
        let mut actions = Vec::new();
        for wave_id in completed_waves {
            let Some(tracker) = self.wave_certificate_trackers.get(&wave_id) else {
                continue;
            };
            let missing: HashSet<Hash> = tracker
                .tx_hashes()
                .iter()
                .filter(|h| !self.receipt_cache.contains_key(h))
                .copied()
                .collect();
            if !missing.is_empty() {
                tracing::debug!(
                    wave = %wave_id,
                    missing_receipts = missing.len(),
                    "Wave tracker complete but receipts not yet emitted — deferring finalization"
                );
                self.pending_wave_receipts.insert(wave_id, missing);
            } else {
                actions.extend(self.finalize_wave(&wave_id));
            }
        }
        actions
    }

    /// Finalize a wave: create WaveCertificate, record FinalizedWave, emit events.
    ///
    /// Called when all participating shards have reported ECs and all tx receipts
    /// have been emitted.
    fn finalize_wave(&mut self, wave_id: &WaveId) -> Vec<Action> {
        let Some(mut tracker) = self.wave_certificate_trackers.remove(wave_id) else {
            return vec![];
        };
        self.pending_wave_receipts.remove(wave_id);

        let wc = tracker.create_wave_certificate();
        let tx_decisions = tracker.tx_decisions();
        let tx_hashes = tracker.tx_hashes().to_vec();
        let ecs = tracker.take_execution_certificates();

        // Move receipts from cache into FinalizedWave for atomic commit.
        let receipts: Vec<ReceiptBundle> = tx_hashes
            .iter()
            .filter_map(|h| self.receipt_cache.remove(h))
            .collect();

        let cert_arc = Arc::new(wc);
        let finalized = FinalizedWave {
            certificate: Arc::clone(&cert_arc),
            tx_hashes: tx_hashes.clone(),
            execution_certificates: ecs.clone(),
            tx_decisions: tx_decisions.clone(),
            receipts,
            finalized_height: self.committed_height,
        };
        self.finalized_wave_certificates
            .insert(wave_id.clone(), finalized);

        // Cache the wave certificate so peers can fetch it before voting.
        let mut actions = vec![Action::CacheWaveCertificate {
            certificate: Arc::clone(&cert_arc),
        }];

        // Emit WaveCompleted (wave-level event)
        actions.push(Action::Continuation(ProtocolEvent::WaveCompleted {
            wave_cert: cert_arc,
            tx_hashes: tx_hashes.clone(),
            execution_certificates: ecs,
        }));

        // Emit TransactionExecuted for each tx (per-tx mempool status updates)
        for d in &tx_decisions {
            actions.push(Action::Continuation(ProtocolEvent::TransactionExecuted {
                tx_hash: d.tx_hash,
                accepted: d.decision == TransactionDecision::Accept,
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
            .find(|fw| fw.tx_hashes.contains(tx_hash))
            .map(|fw| Arc::clone(&fw.certificate))
    }

    /// Remove a finalized wave (after its wave cert has been committed in a block).
    ///
    /// Cleans up all per-tx tracking state for transactions in this wave.
    pub fn remove_finalized_wave(&mut self, wave_id: &WaveId) {
        let tx_hashes = self
            .finalized_wave_certificates
            .get(wave_id)
            .map(|fw| fw.tx_hashes.clone())
            .unwrap_or_default();

        self.finalized_wave_certificates.remove(wave_id);
        // Early attestations are a flat vec — no per-wave removal needed.
        // They're drained on block commit replay.

        for tx_hash in &tx_hashes {
            self.receipt_cache.remove(tx_hash);
            self.pending_provisioning.remove(tx_hash);

            // Remove this TX from the wave's expected set in the accumulator.
            if let Some(wave_key) = self.wave_assignments.get(tx_hash).cloned() {
                if let Some(accumulator) = self.accumulators.get_mut(&wave_key) {
                    accumulator.remove_expected(tx_hash);
                }
            }

            self.wave_assignments.remove(tx_hash);
            self.early_provisioning_complete.remove(tx_hash);
        }
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
        // Build set of WaveIds still referenced by active wave assignments.
        let active_keys: std::collections::HashSet<&WaveId> =
            self.wave_assignments.values().collect();

        // Prune accumulators only when no active wave assignments reference them.
        // Waves must be retained until they resolve (EC formed + wave cert committed),
        // regardless of age. Time-based pruning would destroy accumulator state
        // needed for abort intents to take effect.
        let before_acc = self.accumulators.len();
        self.accumulators.retain(|key, _| active_keys.contains(key));
        let pruned_acc = before_acc - self.accumulators.len();

        // Prune vote trackers and waves_with_ec — same keys as accumulators.
        // Warn about any vote trackers being pruned with split global receipt roots
        // (they never reached quorum, possibly due to non-deterministic execution).
        let before_vt = self.vote_trackers.len();
        self.vote_trackers.retain(|key, tracker| {
            if self.accumulators.contains_key(key) {
                return true;
            }
            // About to prune — log diagnostic if there was a global receipt root split
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

    /// Check if a transaction is finalized (part of a finalized wave).
    pub fn is_finalized(&self, tx_hash: &Hash) -> bool {
        self.finalized_wave_certificates
            .values()
            .any(|fw| fw.tx_hashes.contains(tx_hash))
    }

    /// Returns the set of all finalized transaction hashes.
    ///
    /// Used by the node orchestrator to pass to BFT for abort intent filtering.
    pub fn finalized_tx_hashes(&self) -> std::collections::HashSet<Hash> {
        self.finalized_wave_certificates
            .values()
            .flat_map(|fw| fw.tx_hashes.iter().copied())
            .collect()
    }

    /// Check if we're waiting for provisioning to complete for a transaction.
    ///
    /// Note: Actual provision tracking is handled by ProvisionCoordinator.
    pub fn is_awaiting_provisioning(&self, tx_hash: &Hash) -> bool {
        self.pending_provisioning.contains_key(tx_hash)
    }

    /// Get debug info about certificate tracking state for a transaction.
    pub fn certificate_tracking_debug(&self, tx_hash: &Hash) -> String {
        // Find the wave this tx belongs to
        let wave_info = if let Some(wave_id) = self.wave_assignments.get(tx_hash) {
            if let Some(tracker) = self.wave_certificate_trackers.get(wave_id) {
                format!("wave={}, complete={}", wave_id, tracker.is_complete())
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
            .iter()
            .filter(|(ec, _)| ec.tx_outcomes.iter().any(|o| o.tx_hash == *tx_hash))
            .count();

        format!("{}, early_wave_attestations={}", wave_info, early_count)
    }

    /// Cleanup all tracking state for a deferred or aborted transaction.
    ///
    /// Called when a transaction is deferred (livelock cycle) or aborted (timeout).
    /// This releases all resources associated with the transaction so it doesn't
    /// continue consuming memory or processing.
    ///
    /// IMPORTANT: If a finalized WaveCertificate exists, we preserve it.
    /// The TC represents cross-shard consensus (all participating shards agreed on
    /// the execution result). A local deferral/abort cannot override that — the TC
    /// must be committed in the next block to supersede the deferral. Removing it
    /// here would cause split-brain: remote shards commit the TC while we discard it.
    ///
    /// Stale TCs (where execution happened locally but was never committed) are
    /// handled by `prune_finalized_certificates()` which runs on every block commit.
    pub fn cleanup_transaction(&mut self, tx_hash: &Hash) {
        // If the transaction is part of a finalized wave, we must preserve ALL tracking state.
        // Removing the wave_assignment or finalized_wave_certificate would prevent us from
        // completing the wave — causing split-brain with remote shards.
        let is_finalized = self
            .finalized_wave_certificates
            .values()
            .any(|fw| fw.tx_hashes.contains(tx_hash));
        if is_finalized {
            tracing::info!(
                tx_hash = %tx_hash,
                "Skipping cleanup for finalized transaction \
                 (must complete wave to avoid split-brain with remote shards)"
            );
            return;
        }

        // Evict receipt from cache — transaction is being retried or abandoned.
        self.receipt_cache.remove(tx_hash);

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

        // Early arrivals cleanup
        self.early_provisioning_complete.remove(tx_hash);

        tracing::debug!(
            tx_hash = %tx_hash,
            "Cleaned up execution state for deferred/aborted transaction"
        );
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

    /// Get execution memory statistics for monitoring collection sizes.
    pub fn memory_stats(&self) -> ExecutionMemoryStats {
        ExecutionMemoryStats {
            receipt_cache: self.receipt_cache.len(),
            finalized_wave_certificates: self.finalized_wave_certificates.len(),
            pending_provisioning: self.pending_provisioning.len(),
            accumulators: self.accumulators.len(),
            vote_trackers: self.vote_trackers.len(),
            early_votes: self.early_votes.len(),
            wave_certificate_trackers: self.wave_certificate_trackers.len(),
            expected_exec_certs: self.expected_exec_certs.len(),
        }
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
        // Cross-shard waves have non-zero wave IDs (remote_shards is non-empty).
        for (wave_id, tracker) in &self.wave_certificate_trackers {
            if !wave_id.is_zero() {
                for h in tracker.tx_hashes() {
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
            .field("pending_provisioning", &self.pending_provisioning.len())
            .field(
                "wave_certificate_trackers",
                &self.wave_certificate_trackers.len(),
            )
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
        assert!(state.finalized_wave_certificates.is_empty());
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

        // Wave certificate tracker should be set up for finalization
        let wave_id = state.wave_assignments.get(&tx_hash).cloned();
        assert!(wave_id.is_some());
        assert!(state
            .wave_certificate_trackers
            .contains_key(&wave_id.unwrap()));
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
}
