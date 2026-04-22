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

use hyperscale_core::{Action, ProtocolEvent, ProvisionRequest};
use hyperscale_types::{
    Attempt, Block, BlockHeight, ExecutionCertificate, ExecutionOutcome, ExecutionVote, Hash,
    LocalExecutionEntry, NodeId, Provision, ReceiptBundle, RoutableTransaction, ShardGroupId,
    TopologySnapshot, TransactionDecision, TxOutcome, ValidatorId, WaveCertificate, WaveId,
    WeightedTimestamp,
};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tracing::instrument;

use crate::conflict::DetectedConflict;
use crate::early_arrivals::{EarlyArrivalBuffer, EARLY_VOTE_RETENTION};
use crate::expected_certs::{ExpectedCertTracker, FallbackFetch};
use crate::finalized_waves::FinalizedWaveStore;
use crate::handlers::build_dispatch_action;
use crate::lookups::{committee_public_keys_for_shard, peers_excluding_self};
use crate::provisioning::ProvisioningTracker;
use crate::vote_tracker::VoteTracker;
use crate::wave_state::WaveState;
use crate::waves::{PendingVoteRetry, RetryEffect, WaveRegistry};

/// Data returned when a wave is ready for voting.
///
/// The state machine produces this; the io_loop uses it to sign the execution vote
/// and broadcast (since the state machine doesn't hold the signing key).
#[derive(Debug)]
pub struct CompletionData {
    /// Block this wave belongs to.
    pub block_hash: Hash,
    /// Block height (= wave_starting_height).
    pub block_height: BlockHeight,
    /// BFT-authenticated weighted timestamp at which this wave's outcome is
    /// fixed. Included in the vote payload and the EC canonical hash, so all
    /// validators aggregate under the same identifier.
    pub vote_anchor_ts_ms: WeightedTimestamp,
    /// Wave identifier.
    pub wave_id: WaveId,
    /// Merkle root over per-tx outcome leaves (cross-shard agreement).
    pub global_receipt_root: Hash,
    /// Per-tx outcomes in wave order.
    pub tx_outcomes: Vec<hyperscale_types::TxOutcome>,
}

use hyperscale_types::FinalizedWave;

/// Execution memory statistics for monitoring collection sizes.
#[derive(Clone, Copy, Debug, Default)]
pub struct ExecutionMemoryStats {
    /// Total receipts held across all in-flight waves, awaiting finalization.
    pub wave_execution_receipts: usize,
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
pub struct ExecutionCoordinator {
    /// Local wall-clock "now" — kept for symmetry with the other sub-state
    /// machines even though execution's deterministic timeouts all anchor on
    /// `committed_ts_ms` (the QC's weighted timestamp).
    now: Duration,

    /// Finalized wave certificates ready for block inclusion, keyed by
    /// `WaveId`. Terminal-state lookup surface for wave-id-hash fetches,
    /// tx-membership queries, and proposal building.
    finalized: FinalizedWaveStore,

    /// Current committed height for pruning stale entries.
    committed_height: BlockHeight,

    /// BFT-authenticated weighted timestamp of the last locally committed
    /// block. "Now" reference for timeouts that must be deterministic across
    /// validators and independent of block production rate.
    committed_ts_ms: WeightedTimestamp,

    // ═══════════════════════════════════════════════════════════════════════
    // Provisioning
    // ═══════════════════════════════════════════════════════════════════════
    /// Owns the verified-provision map, required/received remote-shard sets
    /// per tx, and the `ConflictDetector` used for bidirectional node-ID
    /// overlap detection. Wraps the detector as a field so conflict flows
    /// stay co-located with the provision state they reason about.
    provisioning: ProvisioningTracker,

    // ═══════════════════════════════════════════════════════════════════════
    // Per-wave execution
    // ═══════════════════════════════════════════════════════════════════════
    /// Owns in-flight `WaveState`s, their `VoteTracker`s, the EC-dispatched
    /// gate, vote-retry bookkeeping, and the `tx_hash → WaveId` reverse
    /// index. Every per-wave mutation the coordinator drives flows through
    /// this field.
    waves: WaveRegistry,

    // ═══════════════════════════════════════════════════════════════════════
    // Early arrivals (buffered until tracking starts at block commit)
    // ═══════════════════════════════════════════════════════════════════════
    /// Buffers execution votes and cross-shard ECs that arrived before the
    /// local wave was tracked. Drained on block commit (ECs) and on leader
    /// tracker creation (votes).
    early: EarlyArrivalBuffer,

    // ═══════════════════════════════════════════════════════════════════════
    // Expected Execution Certificate Tracking (Fallback Detection)
    // ═══════════════════════════════════════════════════════════════════════
    /// Tracks expected ECs from remote block headers and drives timeout-based
    /// fallback fetches when they don't arrive. Owns both the active-expectation
    /// set and the fulfilled-tombstone set used to guard against duplicate
    /// headers re-opening closed expectations.
    expected_certs: ExpectedCertTracker,
}

impl Default for ExecutionCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

/// How long to retain committed remote provisions in `ConflictDetector` for
/// reverse conflict detection. A local tx that hasn't registered against a
/// stored provision after this window can't conflict with it — its own block
/// has long committed. Anything older is dropped to bound the detector's
/// memory and per-block iteration cost (see
/// `ConflictDetector::prune_provisions_older_than`). Anchored on the
/// committing QC's `weighted_timestamp_ms`.
const CONFLICT_PROVISION_RETENTION: Duration = Duration::from_secs(30);

/// Per-shard recipient lists for provision broadcasting.
type ShardRecipients = HashMap<ShardGroupId, Vec<ValidatorId>>;

/// A single tx's layout within a wave: the transaction plus the set of shards
/// that participate in its execution (local + any remote provision sources).
type WaveTxEntry = (Arc<RoutableTransaction>, BTreeSet<ShardGroupId>);

/// Deterministic grouping of a block's transactions into waves, used by
/// `setup_waves_and_dispatch` to drive wave construction.
type WaveAssignments = BTreeMap<WaveId, Vec<WaveTxEntry>>;

impl ExecutionCoordinator {
    /// Create a new execution state machine.
    pub fn new() -> Self {
        Self {
            now: Duration::ZERO,
            finalized: FinalizedWaveStore::new(),
            committed_height: BlockHeight::GENESIS,
            committed_ts_ms: WeightedTimestamp::ZERO,
            waves: WaveRegistry::new(),
            early: EarlyArrivalBuffer::new(),
            provisioning: ProvisioningTracker::new(),
            expected_certs: ExpectedCertTracker::new(),
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Time Management
    // ═══════════════════════════════════════════════════════════════════════════

    /// Set the current wall-clock time.
    pub fn set_time(&mut self, now: Duration) {
        self.now = now;
    }

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
        block_height: BlockHeight,
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
        block_height: BlockHeight,
        block_ts_ms: WeightedTimestamp,
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
                self.waves.assign_tx(tx_hash, wave_id.clone());
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
                    self.provisioning.record_required(tx_hash, remote_shards);

                    let conflicts = self.provisioning.register_tx(
                        tx_hash,
                        topology,
                        &tx.declared_reads,
                        &tx.declared_writes,
                    );
                    if !self.provisioning.is_fully_provisioned(&tx_hash) {
                        reverse_conflicts.extend(conflicts);
                    }
                }
            }

            // Create the WaveState. For single-shard waves,
            // `all_provisioned_at_ts_ms` is set to `wave_start_ts_ms`
            // immediately by the constructor.
            let mut wave_state = WaveState::new(
                wave_id.clone(),
                block_hash,
                block_ts_ms,
                txs,
                is_single_shard,
            );

            // Apply the deadlock-resolving reverse conflicts collected above.
            for conflict in reverse_conflicts {
                wave_state.record_abort(conflict.loser_tx, conflict.committed_at_ts_ms);
            }

            // For cross-shard waves: fold in any provisions that already arrived.
            // If every tx is fully covered, the wave transitions to
            // "provisioned" at block_height.
            if !is_single_shard {
                for &tx_hash in &tx_hashes {
                    if self.provisioning.is_fully_provisioned(&tx_hash) {
                        wave_state.mark_tx_provisioned(tx_hash, block_ts_ms);
                    }
                }
            }

            // Dispatch execution if fully provisioned at creation.
            if wave_state.is_fully_provisioned() && !wave_state.dispatched() {
                if let Some(action) =
                    build_dispatch_action(&wave_state, self.provisioning.verified(), block_hash)
                {
                    wave_state.mark_dispatched();
                    dispatch_actions.push(action);
                }
            }

            self.waves.insert_wave(wave_id.clone(), wave_state);

            // Only the wave leader creates a VoteTracker for aggregation.
            let leader = hyperscale_types::wave_leader(&wave_id, topology.local_committee());
            if topology.local_validator_id() == leader {
                let tracker = VoteTracker::new(wave_id.clone(), block_hash, quorum);
                self.waves.insert_tracker(wave_id.clone(), tracker);

                let early_votes = self.early.drain_votes_for_wave(&wave_id);
                if !early_votes.is_empty() {
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
        let Some(wave_key) = self.waves.wave_assignment(&tx_hash) else {
            tracing::warn!(
                tx_hash = ?tx_hash,
                "Execution result for unassigned tx — dropping"
            );
            return;
        };

        let Some(wave) = self.waves.get_wave_mut(&wave_key) else {
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
    /// 2. The `WAVE_TIMEOUT` deadline has passed (wave aborts entirely)
    ///
    /// Waves that already had an EC formed are skipped.
    pub fn scan_complete_waves(&mut self) -> Vec<CompletionData> {
        let committed_ts_ms = self.committed_ts_ms;

        let votable_wave_ids: Vec<WaveId> = self
            .waves
            .waves_iter()
            .filter(|(wid, w)| {
                !self.waves.is_ec_dispatched(wid)
                    && !w.local_ec_emitted()
                    && w.can_emit_vote(committed_ts_ms)
            })
            .map(|(wid, _)| wid.clone())
            .collect();

        let mut completions = Vec::new();
        for wave_id in votable_wave_ids {
            let wave = self.waves.get_wave_mut(&wave_id).unwrap();
            let block_hash = wave.block_hash();
            let block_height = wave.block_height();
            let Some((vote_anchor_ts_ms, global_receipt_root, tx_outcomes)) =
                wave.build_vote_data(committed_ts_ms)
            else {
                continue;
            };

            completions.push(CompletionData {
                block_hash,
                block_height,
                vote_anchor_ts_ms,
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
    /// record per-tx outcomes on the wave.
    ///
    /// Returns any actions that became newly possible because the batch
    /// unblocked a wave that was waiting only on local receipts. In
    /// particular, a cross-shard wave whose local EC arrived before this
    /// validator's engine finished will defer finalization under the
    /// `has_local_receipts_for_non_aborted` gate in `WaveState::is_complete`;
    /// once the batch lands, the wave becomes complete and we finalize
    /// here rather than waiting for some unrelated trigger.
    pub fn on_execution_batch_completed(
        &mut self,
        wave_id: WaveId,
        results: Vec<LocalExecutionEntry>,
        tx_outcomes: Vec<TxOutcome>,
    ) -> Vec<Action> {
        if results.is_empty() && tx_outcomes.is_empty() {
            tracing::warn!(
                wave = %wave_id,
                "ExecutionBatchCompleted produced ZERO results"
            );
            return Vec::new();
        }

        let Some(wave) = self.waves.get_wave_mut(&wave_id) else {
            tracing::warn!(
                wave = %wave_id,
                "ExecutionBatchCompleted for unknown wave — dropping (wave was pruned or never created)"
            );
            return Vec::new();
        };
        for result in results {
            wave.record_receipt(ReceiptBundle {
                tx_hash: result.tx_hash,
                local_receipt: Arc::new(result.local_receipt),
                execution_output: Some(result.execution_output),
            });
        }
        for wr in tx_outcomes {
            wave.record_execution_result(wr.tx_hash, wr.outcome);
        }

        // With local receipts now in hand, the wave may have crossed into
        // `is_complete` if its local EC arrived ahead of the engine. Drive
        // finalization from here so the deferred finalize happens on the
        // same event that unblocked it.
        if wave.is_complete() {
            self.finalize_wave(&wave_id)
        } else {
            Vec::new()
        }
    }

    /// Scan complete waves and emit `SignAndSendExecutionVote` actions.
    ///
    /// This is the SINGLE path to execution voting. Call after conflicts
    /// have been processed so wave state is deterministic at this height.
    /// Each vote is sent to the wave leader (unicast). The `vote_anchor_ts_ms`
    /// is the BFT-authenticated weighted timestamp determined by the wave
    /// (either `all_provisioned_at_ts_ms`, or `wave_start_ts_ms + WAVE_TIMEOUT`
    /// for timeout-abort).
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
                self.waves.record_vote_retry(
                    completion.wave_id.clone(),
                    PendingVoteRetry {
                        sent_at_ts_ms: self.committed_ts_ms,
                        attempt: Attempt::INITIAL,
                        block_hash: completion.block_hash,
                        block_height: completion.block_height,
                        vote_anchor_ts_ms: completion.vote_anchor_ts_ms,
                        global_receipt_root: completion.global_receipt_root,
                        tx_outcomes: Arc::clone(&tx_outcomes),
                    },
                );
            }
            actions.push(Action::SignAndSendExecutionVote {
                block_hash: completion.block_hash,
                block_height: completion.block_height,
                vote_anchor_ts_ms: completion.vote_anchor_ts_ms,
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
    /// Per-tx terminal state for the mempool is driven by
    /// `mempool::on_block_committed` reading `block.certificates` directly.
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
        committed_height: BlockHeight,
        committed_ts_ms: WeightedTimestamp,
    ) -> Vec<Action> {
        // Sort for deterministic phase-2 iteration (logs, action vector order).
        let mut ordered: Vec<&Arc<Provision>> = batches.iter().collect();
        ordered.sort_by_key(|b| b.hash());

        // Phase 1: absorb all provisions. Populated unconditionally so
        // `setup_waves_and_dispatch` can replay them at wave-creation time.
        let local_shard = topology.local_shard();
        let mut affected_waves: BTreeSet<WaveId> = BTreeSet::new();
        for batch in &ordered {
            for tx_hash in self.provisioning.absorb_batch(batch, local_shard) {
                if let Some(wave_id) = self.waves.wave_assignment(&tx_hash) {
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
            for conflict in self.provisioning.detect_conflicts(batch, committed_ts_ms) {
                let loser = conflict.loser_tx;
                if self.provisioning.is_fully_provisioned(&loser) {
                    continue;
                }
                let Some(wave_id) = self.waves.wave_assignment(&loser) else {
                    continue;
                };
                let Some(wave) = self.waves.get_wave_mut(&wave_id) else {
                    continue;
                };
                if wave.dispatched() {
                    continue;
                }
                wave.record_abort(loser, conflict.committed_at_ts_ms);
                affected_waves.insert(wave_id);
                tracing::debug!(
                    loser_tx = %loser,
                    source_shard = source_shard.0,
                    committed_at = committed_height.0,
                    "Node-ID overlap conflict — aborting loser"
                );
            }
        }

        // Step 2: for each affected wave, mark newly-ready txs provisioned. If
        // a wave transitions from partial → fully provisioned, emit the one-shot
        // dispatch action. A wave that already dispatched is left alone.
        let mut actions: Vec<Action> = Vec::new();
        for wave_id in affected_waves {
            let Some(wave) = self.waves.get_wave_mut(&wave_id) else {
                continue;
            };
            if wave.dispatched() {
                continue;
            }

            // Identify txs that are now all-shards-ready.
            let tx_hashes: Vec<Hash> = wave.tx_hashes().to_vec();
            for tx_hash in &tx_hashes {
                if self.provisioning.is_fully_provisioned(tx_hash) {
                    wave.mark_tx_provisioned(*tx_hash, committed_ts_ms);
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
                    build_dispatch_action(wave, self.provisioning.verified(), wave.block_hash())
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

        if !self.waves.contains_tracker(&wave_id) {
            if !self.waves.contains_wave(&wave_id) {
                // Block hasn't committed yet — buffer as early vote.
                self.early.buffer_vote(wave_id, vote);
                return vec![];
            }
            if self.waves.is_ec_dispatched(&wave_id) {
                // Already have EC for this wave — discard late vote.
                return vec![];
            }
            // Wave exists but no VoteTracker and no EC yet. This validator
            // was targeted as a fallback leader (rotated attempt). Create tracker.
            let quorum = topology.local_quorum_threshold();
            let block_hash = self.waves.get_wave(&wave_id).unwrap().block_hash();
            tracing::info!(
                wave = %wave_id,
                "Creating fallback VoteTracker — receiving votes as rotated leader"
            );
            let tracker = VoteTracker::new(wave_id.clone(), block_hash, quorum);
            self.waves.insert_tracker(wave_id.clone(), tracker);

            // Replay any early votes that were buffered before block commit.
            // These may include retried votes from other validators who
            // committed faster and rotated to us before our block committed.
            let early = self.early.drain_votes_for_wave(&wave_id);
            if !early.is_empty() {
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

        let tracker = self.waves.get_tracker_mut(&wave_id).unwrap();

        // buffer_unverified_vote handles dedup per (validator, vote_anchor_ts_ms).
        // Same validator can vote at multiple heights (round voting).
        if !tracker.buffer_unverified_vote(vote, public_key, voting_power) {
            return vec![];
        }

        self.maybe_trigger_vote_verification(wave_id)
    }

    /// Check if we should trigger batch verification for a wave's votes.
    fn maybe_trigger_vote_verification(&mut self, wave_id: WaveId) -> Vec<Action> {
        let Some(tracker) = self.waves.get_tracker_mut(&wave_id) else {
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

        let Some(tracker) = self.waves.get_tracker_mut(&wave_id) else {
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
        let Some(tracker) = self.waves.get_tracker_mut(&wave_id) else {
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
        let Some(tracker) = self.waves.get_tracker_mut(&wave_id) else {
            return vec![];
        };

        let Some((global_receipt_root, vote_anchor_ts_ms, _total_power)) = tracker.check_quorum()
        else {
            return vec![];
        };

        let block_hash = tracker.block_hash();

        tracing::info!(
            block_hash = ?block_hash,
            wave = %wave_id,
            vote_anchor_ts_ms = vote_anchor_ts_ms.as_millis(),
            "Execution vote quorum reached — aggregating certificate"
        );

        let votes = tracker.take_votes(&global_receipt_root, vote_anchor_ts_ms);
        let committee = topology.local_committee().to_vec();

        // Remove the vote tracker — this EC is the shard's final answer.
        // Mark wave as having an EC to skip it in scan_complete_waves.
        self.waves.remove_tracker(&wave_id);
        self.waves.mark_ec_dispatched(wave_id.clone());

        tracing::debug!(
            block_hash = ?block_hash,
            wave = %wave_id,
            votes = votes.len(),
            "Delegating BLS aggregation to crypto pool"
        );

        // Notify mempool that the local EC was created for these txs.
        let ec_tx_hashes = self
            .waves
            .get_wave(&wave_id)
            .map(|w| w.tx_hashes().to_vec())
            .unwrap_or_default();

        // tx_outcomes are extracted from votes by the aggregation handler
        // (all quorum votes carry identical outcomes).
        vec![
            Action::AggregateExecutionCertificate {
                wave_id,
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
        let local_peers = peers_excluding_self(topology, topology.local_shard());
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
    /// Always dispatches BLS signature verification before the cert can
    /// influence any wave state. Routing (and any buffering for txs whose
    /// blocks haven't committed yet) happens in `on_certificate_verified`
    /// once the crypto pool confirms the signature — buffering here without
    /// verifying would let a Byzantine remote inject forged `tx_outcomes`
    /// that the replay path later trusts.
    pub fn on_wave_certificate(
        &mut self,
        topology: &TopologySnapshot,
        cert: hyperscale_types::ExecutionCertificate,
    ) -> Vec<Action> {
        let shard = cert.shard_group_id();

        // Clear expected cert tracking and mark as fulfilled so late-arriving
        // duplicate headers don't re-register the expectation.
        let cleared = self.expected_certs.mark_fulfilled(
            shard,
            cert.block_height(),
            &cert.wave_id,
            self.committed_ts_ms,
        );

        let mut actions = Vec::new();

        // If a fallback fetch was already dispatched for this expectation, tell
        // the fetch protocol to drop it — otherwise it would keep retrying
        // forever even after the EC has arrived here.
        if cleared {
            tracing::debug!(
                source_shard = shard.0,
                block_height = cert.block_height().0,
                wave = %cert.wave_id,
                at_local_ts_ms = self.committed_ts_ms.as_millis(),
                "Fulfilled expected exec cert"
            );
            actions.push(Action::CancelExecutionCertFetch {
                source_shard: shard,
                block_height: cert.block_height(),
            });
        }

        let Some(public_keys) = committee_public_keys_for_shard(topology, shard) else {
            tracing::warn!(
                shard = shard.0,
                "Could not resolve all public keys for execution cert verification"
            );
            return actions;
        };

        actions.push(Action::VerifyExecutionCertificateSignature {
            certificate: cert,
            public_keys,
        });
        actions
    }

    /// Handle execution certificate signature verification result.
    ///
    /// If valid, hand the cert to `handle_wave_attestation` which routes
    /// per-tx outcomes into any local wave trackers and buffers txs whose
    /// blocks haven't committed yet for replay.
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
        let ec_arc = Arc::new(certificate);
        let mut actions = Vec::new();

        // If this is a local shard EC, mark the wave as having an EC to skip
        // it in scan_complete_waves, and persist it for fallback serving to
        // remote shards.
        if shard == topology.local_shard() {
            self.waves.mark_ec_dispatched(ec_arc.wave_id.clone());
            // EC received from wave leader — cancel any pending vote retry.
            self.waves.clear_vote_retry(&ec_arc.wave_id);
            actions.push(Action::TrackExecutionCertificate {
                certificate: Arc::clone(&ec_arc),
            });
        }

        actions.extend(self.handle_wave_attestation(topology, ec_arc));
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
        block_height: BlockHeight,
        waves: &[WaveId],
    ) {
        let local_shard = topology.local_shard();

        for wave in waves {
            if wave.remote_shards.contains(&local_shard) {
                self.expected_certs.register(
                    source_shard,
                    block_height,
                    wave.clone(),
                    self.committed_ts_ms,
                );
            }
        }
    }

    /// Check for timed-out expected execution certs and emit fallback requests.
    ///
    /// Called during block commit processing. Returns actions for any certs
    /// that have exceeded the timeout.
    fn check_exec_cert_timeouts(&mut self, topology: &TopologySnapshot) -> Vec<Action> {
        let now_ts = self.committed_ts_ms;
        let fetches = self.expected_certs.check_timeouts(now_ts);

        let mut actions = Vec::with_capacity(fetches.len());
        for FallbackFetch {
            source_shard,
            block_height,
            wave_id,
            is_retry,
        } in fetches
        {
            let peers = topology.committee_for_shard(source_shard).to_vec();
            tracing::info!(
                source_shard = source_shard.0,
                block_height = block_height.0,
                wave = %wave_id,
                retry = is_retry,
                "Execution cert timeout — requesting fallback"
            );
            actions.push(Action::RequestMissingExecutionCert {
                source_shard,
                block_height,
                wave_id,
                peers,
            });
        }

        // Retain expectations while any local wave still needs an EC from
        // that source shard. `self.waves` is the authoritative "what am I
        // still waiting on" set — entries are removed by `finalize_wave`
        // once a wave is complete. Keyed by source shard (not wave_id)
        // because expected entries carry the remote shard's wave
        // decomposition, which cannot be matched against local wave ids.
        let local_shard = topology.local_shard();
        let shards_needed: HashSet<ShardGroupId> = self
            .waves
            .waves_iter()
            .flat_map(|(wid, _)| wid.remote_shards.iter().copied())
            .filter(|s| *s != local_shard)
            .collect();
        self.expected_certs.retain_if_shard_needed(&shards_needed);
        self.expected_certs.prune_fulfilled(now_ts);

        actions
    }

    /// Re-send votes to rotated leaders for waves that haven't produced an EC.
    ///
    /// Called during block commit processing. When a retry's deadline has
    /// elapsed against the committed QC's weighted timestamp, the registry
    /// returns a [`RetryEffect`] for each fired retry with the new attempt
    /// number; the coordinator resolves the rotated leader via topology
    /// and lifts each effect to `Action::SignAndSendExecutionVote`.
    fn check_vote_retry_timeouts(&mut self, topology: &TopologySnapshot) -> Vec<Action> {
        let effects = self.waves.check_vote_retry_timeouts(self.committed_ts_ms);
        if effects.is_empty() {
            return Vec::new();
        }

        let committee = topology.local_committee().to_vec();
        let mut actions = Vec::with_capacity(effects.len());
        for RetryEffect {
            wave_id,
            attempt,
            block_hash,
            block_height,
            vote_anchor_ts_ms,
            global_receipt_root,
            tx_outcomes,
        } in effects
        {
            let new_leader = hyperscale_types::wave_leader_at(&wave_id, attempt, &committee);
            tracing::info!(
                wave = %wave_id,
                attempt = attempt.0,
                new_leader = new_leader.0,
                "Vote retry timeout — re-sending to rotated leader"
            );
            actions.push(Action::SignAndSendExecutionVote {
                block_hash,
                block_height,
                vote_anchor_ts_ms,
                wave_id,
                global_receipt_root,
                tx_outcomes: (*tx_outcomes).clone(),
                leader: new_leader,
            });
        }
        actions
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Block Commit Handling
    // ═══════════════════════════════════════════════════════════════════════════

    /// Handle block committed.
    ///
    /// Runs the variant-agnostic bookkeeping (height bump, timeout checks,
    /// pruning), then dispatches to either `on_live_block_committed` —
    /// which drives fresh execution — or `on_sealed_block_committed` —
    /// which only records tx → wave mappings so late-arriving certs can
    /// route back to the mempool.
    ///
    /// Orchestration order matters. The phases below run in sequence and
    /// depend on earlier phases completing first:
    ///
    /// 1. **Anchor time** — bump `committed_height` and `committed_ts_ms`
    ///    from the QC. Every downstream phase reads these.
    /// 2. **First-commit retro-stamp** — entries buffered pre-first-commit
    ///    carry `WeightedTimestamp::ZERO`; stamp them with the new
    ///    `committed_ts_ms` before timeout checks, otherwise
    ///    `elapsed_since(ZERO)` dwarfs every deadline and triggers a
    ///    fallback-fetch storm.
    /// 3. **Timeout checks** — expected-cert fallbacks and vote retries.
    ///    Read the freshly-bumped `committed_ts_ms`.
    /// 4. **Pruning** — resolved waves, stale buffered ECs, aged
    ///    conflict-detector provisions. Must follow timeouts so a retry
    ///    fires before the wave it references is pruned away.
    /// 5. **Dispatch** — route to the live or sealed path for block-specific
    ///    work (wave setup + dispatch, or late-cert routing).
    #[instrument(skip(self, certified), fields(
        height = certified.block.height().0,
        block_hash = ?certified.block.hash(),
        tx_count = certified.block.transactions().len(),
        is_live = certified.block.is_live(),
    ))]
    pub fn on_block_committed(
        &mut self,
        topology: &TopologySnapshot,
        certified: &hyperscale_types::CertifiedBlock,
    ) -> Vec<Action> {
        let block = &certified.block;
        let height = block.height();

        // Update committed height + timestamp before anything else — needed
        // for timeout calculations and pruning even when there are no new
        // transactions.
        let first_commit = self.committed_ts_ms == WeightedTimestamp::ZERO;
        if height > self.committed_height {
            self.committed_height = height;
            self.committed_ts_ms = certified.qc.weighted_timestamp;
        }

        // Retro-stamp entries recorded before the first local commit. Remote
        // headers can register expected exec certs (and ECs themselves can be
        // buffered) while `committed_ts_ms` is still zero; without this, every
        // such entry would report a ~57-year age on the next commit and
        // trigger a fallback fetch storm.
        if first_commit && self.committed_ts_ms != WeightedTimestamp::ZERO {
            let now_ts = self.committed_ts_ms;
            self.expected_certs.retro_stamp_zero_timestamps(now_ts);
            self.early.retro_stamp_zero_timestamps(now_ts);
        }

        let mut actions = Vec::new();

        // Timeout checks + pruning run every block, not just commits that
        // carry txs.
        actions.extend(self.check_exec_cert_timeouts(topology));
        actions.extend(self.check_vote_retry_timeouts(topology));
        self.prune_execution_state();
        self.early.gc_stale_ecs(self.committed_ts_ms);

        for (_, wave) in self.waves.waves_iter_mut() {
            wave.log_if_overdue(self.committed_ts_ms);
        }

        // Drop conflict-detector entries for remote provisions older than the
        // retention window. `register_tx` iterates over these per cross-shard
        // tx; left unbounded they drive quadratic TPS decay.
        let cutoff = self.committed_ts_ms.minus(CONFLICT_PROVISION_RETENTION);
        if cutoff.as_millis() > 0 {
            let dropped = self.provisioning.prune_old_provisions(cutoff);
            if dropped > 0 {
                tracing::debug!(
                    dropped,
                    cutoff_ms = cutoff.as_millis(),
                    "Pruned aged conflict-detector provisions"
                );
            }
        }

        match block {
            Block::Live {
                header,
                transactions,
                provisions,
                ..
            } => actions.extend(self.on_live_block_committed(
                topology,
                block.hash(),
                header,
                transactions,
                provisions,
            )),
            Block::Sealed {
                header,
                transactions,
                ..
            } => actions.extend(self.on_sealed_block_committed(topology, header, transactions)),
        }

        actions
    }

    /// Live path: still within the cross-shard execution window. Proposer
    /// broadcasts provisions, setup+dispatch runs for the block's txs, and
    /// inline provisions are applied so newly-created waves can transition
    /// to `Provisioned` immediately.
    fn on_live_block_committed(
        &mut self,
        topology: &TopologySnapshot,
        block_hash: Hash,
        header: &hyperscale_types::BlockHeader,
        transactions: &[Arc<RoutableTransaction>],
        provisions: &[Arc<Provision>],
    ) -> Vec<Action> {
        let height = header.height;
        let mut actions = Vec::new();

        // ── Provision broadcasting (proposer only) ─────────────────────
        if topology.local_validator_id() == header.proposer {
            let local_shard = topology.local_shard();
            if let Some((requests, shard_recipients)) =
                Self::build_provision_requests(topology, transactions, local_shard)
            {
                actions.push(Action::FetchAndBroadcastProvision {
                    block_hash,
                    requests,
                    source_shard: local_shard,
                    block_height: height,
                    shard_recipients,
                });
            }
        }

        if !transactions.is_empty() {
            tracing::debug!(
                height = height.0,
                tx_count = transactions.len(),
                "Starting execution for new transactions"
            );

            let (dispatch_actions, early_votes) = self.setup_waves_and_dispatch(
                topology,
                block_hash,
                height,
                self.committed_ts_ms,
                transactions,
            );
            actions.extend(dispatch_actions);
            for vote in early_votes {
                actions.extend(self.on_execution_vote(topology, vote));
            }

            actions.extend(self.replay_early_wave_attestations(topology, transactions));
        }

        // Apply this block's provisions after wave setup so newly-created
        // waves can transition to provisioned from the same block's batches.
        if !provisions.is_empty() {
            actions.extend(self.apply_committed_provisions(
                topology,
                provisions,
                height,
                self.committed_ts_ms,
            ));
        }

        actions
    }

    /// Sealed path: past the cross-shard execution window. Waves will
    /// finalize from the already-aggregated cert + receipts included
    /// downstream, so we skip WaveState creation, dispatch, and vote
    /// tracking. Only the tx → wave mapping is recorded (plus any early
    /// ECs replayed) so a late-arriving cert still routes back to each
    /// tx for mempool terminal-state bookkeeping.
    fn on_sealed_block_committed(
        &mut self,
        topology: &TopologySnapshot,
        header: &hyperscale_types::BlockHeader,
        transactions: &[Arc<RoutableTransaction>],
    ) -> Vec<Action> {
        if transactions.is_empty() {
            return Vec::new();
        }
        self.register_sealed_wave_assignments(topology, header.height, transactions);
        self.replay_early_wave_attestations(topology, transactions)
    }

    /// Replay buffered early ECs for txs that have just received wave
    /// assignments. Invoked from both the live and sealed commit paths —
    /// in either case, a cert that arrived ahead of the commit now has a
    /// tx target to route to.
    fn replay_early_wave_attestations(
        &mut self,
        topology: &TopologySnapshot,
        transactions: &[Arc<RoutableTransaction>],
    ) -> Vec<Action> {
        let tx_hashes: Vec<Hash> = transactions.iter().map(|tx| tx.hash()).collect();
        let ecs_to_replay = self.early.drain_ecs_for_txs(&tx_hashes);
        if ecs_to_replay.is_empty() {
            return Vec::new();
        }
        tracing::debug!(
            count = ecs_to_replay.len(),
            "Replaying early wave attestations for newly committed txs"
        );
        let mut actions = Vec::new();
        for ec in ecs_to_replay {
            actions.extend(self.handle_wave_attestation(topology, ec));
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
        block_height: BlockHeight,
        transactions: &[Arc<RoutableTransaction>],
    ) {
        let waves = self.assign_waves(topology, block_height, transactions);
        for (wave_id, txs) in waves {
            for (tx, _) in &txs {
                self.waves.assign_tx(tx.hash(), wave_id.clone());
            }
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
    /// feed the EC to each affected local wave tracker. Tx_hashes without a
    /// local assignment are buffered (or kept buffered) via `pending_routing`
    /// until their blocks commit; routed tx_hashes are cleared from the
    /// pending set, dropping the EC entirely once fully routed.
    fn handle_wave_attestation(
        &mut self,
        _topology: &TopologySnapshot,
        ec: Arc<ExecutionCertificate>,
    ) -> Vec<Action> {
        let routing = self.waves.classify_attestation(&ec);

        self.early.clear_routed(&ec, &routing.routed_tx_hashes);
        self.early
            .buffer_ec(&ec, &routing.unrouted_tx_hashes, self.committed_ts_ms);

        if routing.affected_waves.is_empty() {
            return vec![];
        }

        // Feed the EC to each affected local wave. Completion requires both
        // the local EC and all remote shards' coverage (aborted txs are
        // terminal-covered). Once `local_ec_emitted` is true, every tx
        // already has an outcome and a matching receipt in the cache.
        let mut actions = Vec::new();
        for wave_id in &routing.affected_waves {
            let Some(wave) = self.waves.get_wave_mut(wave_id) else {
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
        let Some(mut wave) = self.waves.remove_wave(wave_id) else {
            return vec![];
        };

        let wc = wave.create_wave_certificate();

        // Walk the local EC's tx_outcomes in canonical order and collect a
        // receipt for each non-aborted outcome. Aborted outcomes contribute
        // no receipt; stray receipts for aborted txs (e.g. local execution
        // completed before the aggregated EC attested `Aborted`) are dropped
        // with the wave. This mirrors `FinalizedWave::reconstruct` and is
        // what `validate_receipts_against_ec` enforces at peer ingress.
        let local_ec = wc
            .execution_certificates
            .iter()
            .find(|ec| ec.wave_id == wc.wave_id)
            .expect("WaveCertificate invariant: local EC must be present");
        let mut receipts: Vec<ReceiptBundle> = Vec::with_capacity(local_ec.tx_outcomes.len());
        for outcome in &local_ec.tx_outcomes {
            if outcome.is_aborted() {
                continue;
            }
            match wave.take_receipt(&outcome.tx_hash) {
                Some(bundle) => receipts.push(bundle),
                None => tracing::error!(
                    wave = %wave_id,
                    tx_hash = ?outcome.tx_hash,
                    "finalize_wave: non-aborted tx is missing its local receipt \
                     (is_complete gate bypassed)"
                ),
            }
        }

        let cert_arc = Arc::new(wc);
        let finalized = FinalizedWave {
            certificate: Arc::clone(&cert_arc),
            receipts,
        };
        let finalized_arc = Arc::new(finalized.clone());
        self.finalized.insert(wave_id.clone(), finalized);

        // Cache the finalized wave so peers can fetch the complete data they
        // need to vote on blocks containing this wave.
        let mut actions = vec![Action::CacheFinalizedWave {
            wave: finalized_arc,
        }];

        actions.push(Action::Continuation(ProtocolEvent::WaveCompleted {
            wave_cert: cert_arc,
            tx_hashes: wave.tx_hashes().to_vec(),
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
        self.waves.wave_assignment(tx_hash)
    }

    /// Get all finalized waves (for proposal building).
    pub fn get_finalized_waves(&self) -> Vec<Arc<FinalizedWave>> {
        self.finalized.all_waves()
    }

    /// Get a finalized wave by its wave_id hash (returns Arc for sharing).
    pub fn get_finalized_wave_by_hash(&self, wave_id_hash: &Hash) -> Option<Arc<FinalizedWave>> {
        self.finalized.get_by_wave_id_hash(wave_id_hash)
    }

    /// Get the finalized wave certificate containing a specific transaction.
    ///
    /// Returns the wave certificate if the tx is part of a finalized wave.
    /// Once committed, certificates are persisted to storage and should be fetched from there.
    pub fn get_finalized_certificate(&self, tx_hash: &Hash) -> Option<Arc<WaveCertificate>> {
        self.finalized.get_certificate_for_tx(tx_hash)
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
        self.finalized.remove(wave_id);
        // The wave may already have been removed by `finalize_wave` (local
        // aggregation path) or be absent entirely (sync path: the block was
        // received as committed without local tracking). Either case is fine.
        self.waves.remove_wave(wave_id);

        for tx_hash in fw.tx_hashes() {
            self.waves.remove_assignment(&tx_hash);
            self.provisioning.remove_tx(&tx_hash);
        }
    }

    /// Prune stale wave state (waves, vote trackers, early votes).
    ///
    /// Waves stay alive while their `wave_assignment`s list them — an
    /// active assignment means the transaction hasn't reached terminal
    /// state (TC committed or abort completed) so late-arriving votes and
    /// conflicts can still resolve it. Early execution votes follow a
    /// separate policy tied to the registry's state plus a timestamp
    /// retention floor.
    fn prune_execution_state(&mut self) {
        let counts = self.waves.prune_resolved();

        // Early execution votes:
        // - Wave resolved (EC formed) → votes no longer needed
        // - Leader replayed them (VoteTracker exists) → already consumed
        // - No wave and older than `EARLY_VOTE_RETENTION` → block never
        //   committed, BFT broken
        //
        // Non-leaders with a wave but no VoteTracker KEEP early votes. They
        // may become fallback leaders via rotation and need to replay them
        // into the on-demand VoteTracker created in `on_execution_vote`.
        let ev_cutoff = self.committed_ts_ms.minus(EARLY_VOTE_RETENTION);
        let before_ev = self.early.vote_len();
        let registry = &self.waves;
        self.early.retain_votes(|key, votes| {
            if registry.is_ec_dispatched(key) {
                return false;
            }
            if registry.contains_tracker(key) {
                return false;
            }
            if registry.contains_wave(key) {
                return true;
            }
            votes
                .first()
                .map(|v| v.vote_anchor_ts_ms > ev_cutoff)
                .unwrap_or(false)
        });
        let pruned_ev = before_ev - self.early.vote_len();

        if counts.waves > 0 || counts.trackers > 0 || pruned_ev > 0 || counts.assignments > 0 {
            tracing::debug!(
                pruned_waves = counts.waves,
                pruned_vt = counts.trackers,
                pruned_ev,
                pruned_wa = counts.assignments,
                "Pruned resolved wave state"
            );
        }
    }

    /// Check if a transaction is finalized (part of a finalized wave).
    pub fn is_finalized(&self, tx_hash: &Hash) -> bool {
        self.finalized.is_finalized(tx_hash)
    }

    /// Returns the set of all finalized transaction hashes.
    ///
    /// Used by the node orchestrator to pass to BFT for conflict filtering.
    pub fn finalized_tx_hashes(&self) -> std::collections::HashSet<Hash> {
        self.finalized.all_tx_hashes()
    }

    /// Check if we're waiting for provisioning to complete for a transaction.
    ///
    /// Note: Actual provision tracking is handled by ProvisionCoordinator.
    pub fn is_awaiting_provisioning(&self, tx_hash: &Hash) -> bool {
        self.waves.is_awaiting_provisioning(tx_hash)
    }

    /// Get debug info about wave state for a transaction.
    pub fn certificate_tracking_debug(&self, tx_hash: &Hash) -> String {
        let wave_info = if let Some(wave_id) = self.waves.wave_assignment(tx_hash) {
            if let Some(wave) = self.waves.get_wave(&wave_id) {
                format!("wave={}, complete={}", wave_id, wave.is_complete())
            } else if self.finalized.contains(&wave_id) {
                format!("wave={}, finalized", wave_id)
            } else {
                format!("wave={}, no tracker", wave_id)
            }
        } else {
            "no wave assignment".to_string()
        };

        let early_count = self.early.attestation_count_for_tx(tx_hash);

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
            wave_execution_receipts: self
                .waves
                .waves_iter()
                .map(|(_, w)| w.receipt_count())
                .sum(),
            finalized_wave_certificates: self.finalized.len(),
            waves: self.waves.waves_len(),
            vote_trackers: self.waves.trackers_len(),
            early_votes: self.early.vote_len(),
            expected_exec_certs: self.expected_certs.expected_len(),
            verified_provisions: self.provisioning.verified_len(),
            required_provision_shards: self.provisioning.required_len(),
            received_provision_shards: self.provisioning.received_len(),
            waves_with_ec: self.waves.ec_dispatched_len(),
            pending_vote_retries: self.waves.retries_len(),
            wave_assignments: self.waves.assignments_len(),
            early_wave_attestations: self.early.tx_index_len(),
            pending_routing: self.early.pending_routing_len(),
            fulfilled_exec_certs: self.expected_certs.fulfilled_len(),
        }
    }

    /// Get the number of cross-shard transactions currently in flight.
    ///
    /// Counts unique transaction hashes in cross-shard waves that haven't yet
    /// finalized. Covers provisioning, voting, and certificate collection
    /// phases uniformly (one `WaveState` tracks all of them).
    pub fn cross_shard_pending_count(&self) -> usize {
        self.waves.cross_shard_pending_count()
    }
}

impl std::fmt::Debug for ExecutionCoordinator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecutionCoordinator")
            .field("finalized_wave_certificates", &self.finalized.len())
            .field("waves", &self.waves.waves_len())
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

    fn make_test_state() -> ExecutionCoordinator {
        ExecutionCoordinator::new()
    }

    /// Pair a test `Block` with a matching zeroed QC so it satisfies the
    /// `CertifiedBlock` pairing invariant.
    fn certify(block: Block) -> hyperscale_types::CertifiedBlock {
        let qc = hyperscale_types::QuorumCertificate {
            block_hash: block.hash(),
            ..hyperscale_types::QuorumCertificate::genesis()
        };
        hyperscale_types::CertifiedBlock::new_unchecked(block, qc)
    }

    /// Build a minimal `Block::Live` suitable for driving
    /// `on_block_committed` in tests. The returned block's `hash()` is
    /// derived from a deterministic header built from the inputs.
    fn make_live_block(
        topology: &TopologySnapshot,
        height: BlockHeight,
        timestamp_ms: u64,
        proposer: ValidatorId,
        transactions: Vec<Arc<RoutableTransaction>>,
    ) -> Block {
        use hyperscale_types::{BlockHeader, ProposerTimestamp, QuorumCertificate, Round};
        let header = BlockHeader {
            shard_group_id: topology.local_shard(),
            height,
            parent_hash: Hash::ZERO,
            parent_qc: QuorumCertificate::genesis(),
            proposer,
            timestamp: ProposerTimestamp(timestamp_ms),
            round: Round::INITIAL,
            is_fallback: false,
            state_root: Hash::ZERO,
            transaction_root: Hash::ZERO,
            certificate_root: Hash::ZERO,
            local_receipt_root: Hash::ZERO,
            provision_root: Hash::ZERO,
            waves: vec![],
            provision_tx_roots: BTreeMap::new(),
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
    fn test_single_shard_execution_flow() {
        let mut state = make_test_state();
        let topology = make_test_topology();

        let tx = test_transaction(1);
        let tx_hash = tx.hash();
        let block = make_live_block(
            &topology,
            BlockHeight(1),
            1000,
            ValidatorId(0),
            vec![Arc::new(tx.clone())],
        );

        // Block committed with transaction
        let actions = state.on_block_committed(&topology, &certify(block.clone()));

        // Should request execution (single-shard path) and set up wave tracking
        assert!(!actions.is_empty());
        // First action should be ExecuteTransactions
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::ExecuteTransactions { .. })));

        // WaveState should be set up for this wave.
        let wave_id = state.waves.wave_assignment(&tx_hash);
        assert!(wave_id.is_some());
        assert!(state.waves.contains_wave(&wave_id.unwrap()));
    }

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
        let block = make_live_block(
            &topo0,
            BlockHeight(1),
            1000,
            ValidatorId(0),
            vec![Arc::new(tx.clone())],
        );

        // Commit the block as validator 0 to discover the wave_id.
        let mut state0 = make_test_state();
        state0.on_block_committed(&topo0, &certify(block.clone()));
        let wave_id = state0
            .waves
            .waves_iter()
            .next()
            .map(|(wid, _)| wid.clone())
            .unwrap();

        let leader = hyperscale_types::wave_leader(&wave_id, &committee);

        // Leader should have a VoteTracker.
        let topo_leader = make_topology_for(leader.0);
        let block_leader = make_live_block(
            &topo_leader,
            BlockHeight(1),
            1000,
            ValidatorId(0),
            vec![Arc::new(tx.clone())],
        );
        let mut state_leader = make_test_state();
        state_leader.on_block_committed(&topo_leader, &certify(block_leader.clone()));
        assert!(
            state_leader.waves.contains_tracker(&wave_id),
            "Leader should have VoteTracker"
        );

        // A non-leader should NOT have a VoteTracker.
        let non_leader_id = committee.iter().find(|&&v| v != leader).unwrap();
        let topo_non = make_topology_for(non_leader_id.0);
        let block_non = make_live_block(
            &topo_non,
            BlockHeight(1),
            1000,
            ValidatorId(0),
            vec![Arc::new(tx.clone())],
        );
        let mut state_non = make_test_state();
        state_non.on_block_committed(&topo_non, &certify(block_non.clone()));
        assert!(
            !state_non.waves.contains_tracker(&wave_id),
            "Non-leader should NOT have VoteTracker"
        );
    }

    #[test]
    fn test_fallback_tracker_created_on_vote() {
        let tx = test_transaction(1);
        let topo = make_topology_for(0);
        let committee = topo.local_committee().to_vec();
        let block = make_live_block(
            &topo,
            BlockHeight(1),
            1000,
            ValidatorId(0),
            vec![Arc::new(tx.clone())],
        );
        let block_hash = block.hash();

        let mut state = make_test_state();
        state.on_block_committed(&topo, &certify(block.clone()));

        let wave_id = state
            .waves
            .waves_iter()
            .next()
            .map(|(wid, _)| wid.clone())
            .unwrap();
        let leader = hyperscale_types::wave_leader(&wave_id, &committee);

        // If we're the leader, this test doesn't apply — find a non-leader topology.
        let non_leader_id = committee.iter().find(|&&v| v != leader).unwrap();
        let topo_non = make_topology_for(non_leader_id.0);
        let block_non = make_live_block(
            &topo_non,
            BlockHeight(1),
            1000,
            ValidatorId(0),
            vec![Arc::new(tx.clone())],
        );
        let mut state_non = make_test_state();
        state_non.on_block_committed(&topo_non, &certify(block_non.clone()));

        assert!(!state_non.waves.contains_tracker(&wave_id));
        assert!(state_non.waves.contains_wave(&wave_id));

        // Simulate receiving a vote (as if we're a fallback leader).
        let fake_vote = ExecutionVote {
            block_hash,
            block_height: BlockHeight(1),
            vote_anchor_ts_ms: WeightedTimestamp::ZERO,
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
            state_non.waves.contains_tracker(&wave_id),
            "Fallback VoteTracker should be created"
        );
    }

    #[test]
    fn test_vote_retry_timeout_emits_rotated_action() {
        use crate::waves::VOTE_RETRY_TIMEOUT;
        let wave_id = WaveId::new(ShardGroupId(0), BlockHeight(1), BTreeSet::new());
        let topo = make_test_topology();
        let committee = topo.local_committee().to_vec();

        let mut state = make_test_state();
        state.committed_height = BlockHeight(20);
        // "Now" timestamp exactly VOTE_RETRY_TIMEOUT past the original send.
        state.committed_ts_ms = WeightedTimestamp(10_000).plus(VOTE_RETRY_TIMEOUT);

        // Manually insert a pending retry as if we'd sent a vote at t=10_000ms.
        state.waves.record_vote_retry(
            wave_id.clone(),
            PendingVoteRetry {
                sent_at_ts_ms: WeightedTimestamp(10_000),
                attempt: Attempt::INITIAL,
                block_hash: Hash::from_bytes(b"block1"),
                block_height: BlockHeight(1),
                vote_anchor_ts_ms: WeightedTimestamp::ZERO,
                global_receipt_root: Hash::ZERO,
                tx_outcomes: Arc::new(vec![]),
            },
        );

        let actions = state.check_vote_retry_timeouts(&topo);

        // Elapsed == VOTE_RETRY_TIMEOUT, so should emit retry.
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            Action::SignAndSendExecutionVote {
                leader,
                wave_id: wid,
                ..
            } => {
                assert_eq!(wid, &wave_id);
                let expected_leader =
                    hyperscale_types::wave_leader_at(&wave_id, Attempt(1), &committee);
                assert_eq!(*leader, expected_leader, "Should rotate to attempt 1");
            }
            other => panic!(
                "Expected SignAndSendExecutionVote, got {:?}",
                other.type_name()
            ),
        }

        // The retry is still tracked with its cooldown re-anchored at the
        // current committed timestamp — advance exactly one more
        // VOTE_RETRY_TIMEOUT and check that a retry at attempt 2 fires.
        state.committed_ts_ms = state.committed_ts_ms.plus(VOTE_RETRY_TIMEOUT);
        let next = state.check_vote_retry_timeouts(&topo);
        assert_eq!(next.len(), 1);
        if let Action::SignAndSendExecutionVote { leader, .. } = &next[0] {
            let expected = hyperscale_types::wave_leader_at(&wave_id, Attempt(2), &committee);
            assert_eq!(*leader, expected, "second fire rotates to attempt 2");
        } else {
            panic!("expected SignAndSendExecutionVote");
        }
    }

    #[test]
    fn test_vote_retry_cancelled_on_ec_receipt() {
        use crate::waves::VOTE_RETRY_TIMEOUT;
        let wave_id = WaveId::new(ShardGroupId(0), BlockHeight(1), BTreeSet::new());
        let topo = make_test_topology();

        let mut state = make_test_state();
        state.committed_height = BlockHeight(10);
        state.waves.record_vote_retry(
            wave_id.clone(),
            PendingVoteRetry {
                sent_at_ts_ms: WeightedTimestamp(5_000),
                attempt: Attempt::INITIAL,
                block_hash: Hash::from_bytes(b"block1"),
                block_height: BlockHeight(1),
                vote_anchor_ts_ms: WeightedTimestamp::ZERO,
                global_receipt_root: Hash::ZERO,
                tx_outcomes: Arc::new(vec![]),
            },
        );

        // Simulate receiving a verified local shard EC.
        let cert = hyperscale_types::ExecutionCertificate::new(
            wave_id.clone(),
            WeightedTimestamp::ZERO,
            Hash::ZERO,
            vec![],
            hyperscale_types::zero_bls_signature(),
            hyperscale_types::SignerBitfield::new(4),
        );
        state.on_certificate_verified(&topo, cert, true);

        // Advance time past the retry deadline; if the retry had survived,
        // this would fire a SignAndSendExecutionVote action.
        state.committed_ts_ms = WeightedTimestamp(5_000).plus(VOTE_RETRY_TIMEOUT);
        let actions = state.check_vote_retry_timeouts(&topo);
        assert!(
            actions.is_empty(),
            "EC receipt must cancel the retry so no action fires"
        );
    }

    #[test]
    fn test_leader_broadcasts_ec_locally() {
        let wave_id = WaveId::new(
            ShardGroupId(0),
            BlockHeight(1),
            [ShardGroupId(1)].into_iter().collect(),
        );
        let topo = make_test_topology();

        let mut state = make_test_state();

        let cert = hyperscale_types::ExecutionCertificate::new(
            wave_id.clone(),
            WeightedTimestamp::ZERO,
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

    /// A received cross-shard EC must always dispatch BLS verification
    /// before any wave state sees it — including when no local wave tracks
    /// any tx in the cert. Without that, a Byzantine remote could buffer
    /// forged `tx_outcomes` that the replay path later trusts at commit
    /// time.
    #[test]
    fn test_on_wave_certificate_always_dispatches_verification_even_without_tracker() {
        let topo = make_two_shard_topology();
        let mut state = make_test_state();

        let remote_shard = ShardGroupId(1);
        let wave_id = WaveId::new(
            remote_shard,
            BlockHeight(5),
            [ShardGroupId(0)].into_iter().collect(),
        );
        // No local waves / trackers have been created for this tx.
        let cert = hyperscale_types::ExecutionCertificate::new(
            wave_id,
            WeightedTimestamp::ZERO,
            Hash::ZERO,
            vec![hyperscale_types::TxOutcome {
                tx_hash: Hash::from_bytes(b"untracked_tx"),
                outcome: ExecutionOutcome::Aborted,
            }],
            hyperscale_types::zero_bls_signature(),
            hyperscale_types::SignerBitfield::new(4),
        );

        let actions = state.on_wave_certificate(&topo, cert);
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::VerifyExecutionCertificateSignature { .. })),
            "must dispatch BLS verification even when no local tracker matches"
        );
        // Nothing lands in the early-arrival buffer until verification passes.
        assert_eq!(state.memory_stats().pending_routing, 0);
        assert_eq!(state.memory_stats().early_wave_attestations, 0);
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

    /// Expected-cert entries must be retained while any local `WaveState`
    /// still lists their source shard as a participating remote — otherwise
    /// a cross-shard wave whose remote EC missed the broadcast window would
    /// be stranded once the expectation aged out, with no fallback fetch
    /// continuing to fire.
    #[test]
    fn test_expected_exec_cert_retained_while_tracker_pending() {
        use hyperscale_types::test_utils::test_transaction;
        use std::collections::BTreeSet;

        let topo = make_two_shard_topology();
        let mut state = make_test_state();

        let remote_shard = ShardGroupId(1);
        let remote_wave = WaveId::new(
            remote_shard,
            BlockHeight(5),
            [ShardGroupId(0)].into_iter().collect(),
        );
        state.on_verified_remote_header(
            &topo,
            remote_shard,
            BlockHeight(5),
            std::slice::from_ref(&remote_wave),
        );
        assert_eq!(
            state.expected_certs.expected_len(),
            1,
            "expectation should register for wave targeting local shard"
        );

        // Simulate an outstanding local cross-shard wave needing shard 1's EC.
        let local_wave = WaveId::new(
            ShardGroupId(0),
            BlockHeight(10),
            [remote_shard].into_iter().collect(),
        );
        let tx = Arc::new(test_transaction(7));
        let tx_hash = tx.hash();
        let mut participating = BTreeSet::new();
        participating.insert(ShardGroupId(0));
        participating.insert(remote_shard);
        state.waves.insert_wave(
            local_wave.clone(),
            WaveState::new(
                local_wave.clone(),
                Hash::from_bytes(b"block"),
                WeightedTimestamp(5_000),
                vec![(tx, participating)],
                false,
            ),
        );
        state.waves.assign_tx(tx_hash, local_wave.clone());

        // Advance committed time past fallback + retry thresholds so the
        // age-based gate would fire. The expectation must survive regardless
        // because a local wave still needs shard 1's EC.
        state.committed_height = BlockHeight(500);
        state.committed_ts_ms = WeightedTimestamp(60_000);
        let actions = state.check_exec_cert_timeouts(&topo);

        assert_eq!(
            state.expected_certs.expected_len(),
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
        state.waves.remove_wave(&local_wave);
        state.waves.remove_assignment(&tx_hash);
        state.committed_height = BlockHeight(600);
        state.committed_ts_ms = WeightedTimestamp(120_000);
        let _ = state.check_exec_cert_timeouts(&topo);
        assert_eq!(
            state.expected_certs.expected_len(),
            0,
            "expectation must be pruned once no wave needs the source shard"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // finalize_wave — verifies the critical cross-sub-machine fanout that
    // happens when a wave reaches terminal state.
    // ═══════════════════════════════════════════════════════════════════════════

    /// Build a single-shard wave in the "ready to finalize" state: every tx
    /// has an execution result and a local receipt, and the local EC has
    /// been added. `WaveState::is_complete` returns true.
    fn make_ready_single_shard_wave(tx_seeds: &[u8]) -> (WaveId, WaveState) {
        let wave_id = WaveId::new(ShardGroupId(0), BlockHeight(1), BTreeSet::new());
        let txs: Vec<(Arc<RoutableTransaction>, BTreeSet<ShardGroupId>)> = tx_seeds
            .iter()
            .map(|s| {
                let mut participating = BTreeSet::new();
                participating.insert(ShardGroupId(0));
                (Arc::new(test_transaction(*s)), participating)
            })
            .collect();
        let mut wave = WaveState::new(
            wave_id.clone(),
            Hash::from_bytes(b"block"),
            WeightedTimestamp(1_000),
            txs,
            true,
        );

        // Record per-tx execution results + receipts.
        let tx_hashes: Vec<Hash> = wave.tx_hashes().to_vec();
        let tx_outcomes: Vec<hyperscale_types::TxOutcome> = tx_hashes
            .iter()
            .map(|h| hyperscale_types::TxOutcome {
                tx_hash: *h,
                outcome: ExecutionOutcome::Executed {
                    receipt_hash: Hash::ZERO,
                    success: true,
                },
            })
            .collect();
        for h in &tx_hashes {
            wave.record_execution_result(
                *h,
                ExecutionOutcome::Executed {
                    receipt_hash: Hash::ZERO,
                    success: true,
                },
            );
            wave.record_receipt(hyperscale_types::ReceiptBundle {
                tx_hash: *h,
                local_receipt: Arc::new(hyperscale_types::LocalReceipt {
                    outcome: hyperscale_types::TransactionOutcome::Success,
                    database_updates: Default::default(),
                    application_events: vec![],
                }),
                execution_output: None,
            });
        }

        // Add the local EC; same wave_id flips `local_ec_emitted` to true.
        let local_ec = Arc::new(hyperscale_types::ExecutionCertificate::new(
            wave_id.clone(),
            WeightedTimestamp(1_000),
            Hash::from_bytes(b"global_receipt_root"),
            tx_outcomes,
            hyperscale_types::zero_bls_signature(),
            hyperscale_types::SignerBitfield::new(4),
        ));
        wave.add_execution_certificate(local_ec);
        assert!(
            wave.is_complete(),
            "fixture precondition: wave must be ready to finalize"
        );

        (wave_id, wave)
    }

    #[test]
    fn test_finalize_wave_populates_finalized_store() {
        let mut state = make_test_state();
        let (wave_id, wave) = make_ready_single_shard_wave(&[1, 2]);
        state.waves.insert_wave(wave_id.clone(), wave);

        let _actions = state.finalize_wave(&wave_id);

        assert!(!state.waves.contains_wave(&wave_id), "wave handed off");
        assert!(
            state.finalized.contains(&wave_id),
            "finalized store populated"
        );
        assert_eq!(state.finalized.len(), 1);
    }

    #[test]
    fn test_finalize_wave_emits_cache_wave_completed_and_per_tx_events() {
        let mut state = make_test_state();
        let (wave_id, wave) = make_ready_single_shard_wave(&[1, 2]);
        state.waves.insert_wave(wave_id.clone(), wave);

        let actions = state.finalize_wave(&wave_id);

        // 1 CacheFinalizedWave + 1 WaveCompleted + 2 TransactionExecuted = 4.
        assert_eq!(actions.len(), 4);
        assert!(matches!(actions[0], Action::CacheFinalizedWave { .. }));
        assert!(matches!(
            actions[1],
            Action::Continuation(ProtocolEvent::WaveCompleted { .. })
        ));
        let tx_events = actions
            .iter()
            .filter(|a| {
                matches!(
                    a,
                    Action::Continuation(ProtocolEvent::TransactionExecuted { .. })
                )
            })
            .count();
        assert_eq!(tx_events, 2, "one TransactionExecuted per wave tx");
    }

    #[test]
    fn test_finalize_wave_is_noop_for_absent_wave_id() {
        let mut state = make_test_state();
        let unknown = WaveId::new(ShardGroupId(0), BlockHeight(99), BTreeSet::new());
        let actions = state.finalize_wave(&unknown);
        assert!(actions.is_empty());
        assert!(state.finalized.is_empty());
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // remove_finalized_wave — cascade correctness across all sub-machines.
    // Refactor plan called this out as a key risk: any new sub-machine added
    // to the coordinator must be updated here or its per-tx state leaks.
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_remove_finalized_wave_cascades_across_every_sub_machine() {
        let mut state = make_test_state();
        let (wave_id, wave) = make_ready_single_shard_wave(&[7]);
        let tx_hash = wave.tx_hashes()[0];

        // Seed every sub-machine with state for this wave's tx.
        state.waves.insert_wave(wave_id.clone(), wave);
        state.waves.assign_tx(tx_hash, wave_id.clone());
        state
            .provisioning
            .record_required(tx_hash, [ShardGroupId(1)].into_iter().collect());
        // Drive finalize_wave to populate the FinalizedWaveStore naturally.
        let _ = state.finalize_wave(&wave_id);
        let finalized = state
            .finalized
            .get_by_wave_id_hash(&wave_id.hash())
            .expect("wave must be in the finalized store after finalize_wave");

        // Sanity: state is populated across sub-machines.
        let before = state.memory_stats();
        assert_eq!(before.finalized_wave_certificates, 1);
        assert_eq!(before.wave_assignments, 1);
        assert_eq!(before.required_provision_shards, 1);

        state.remove_finalized_wave(&finalized);

        let after = state.memory_stats();
        assert_eq!(after.finalized_wave_certificates, 0);
        assert_eq!(after.waves, 0);
        assert_eq!(after.wave_assignments, 0);
        assert_eq!(after.verified_provisions, 0);
        assert_eq!(after.required_provision_shards, 0);
        assert_eq!(after.received_provision_shards, 0);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // First-commit retro-stamp — remote headers can register expected ECs
    // while committed_ts_ms is still ZERO. Without retro-stamp, the first
    // commit triggers a fallback-fetch storm because elapsed_since(ZERO)
    // dwarfs the fallback timeout.
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_first_commit_retro_stamps_expected_certs_and_suppresses_fallback() {
        let topo = make_two_shard_topology();
        let mut state = make_test_state();

        // Pre-first-commit: register an expectation. discovered_at_ts_ms is ZERO.
        let remote_shard = ShardGroupId(1);
        let remote_wave = WaveId::new(
            remote_shard,
            BlockHeight(5),
            [ShardGroupId(0)].into_iter().collect(),
        );
        state.on_verified_remote_header(
            &topo,
            remote_shard,
            BlockHeight(5),
            std::slice::from_ref(&remote_wave),
        );
        // Also seed a local wave that needs shard 1's EC, so the retention
        // check in `check_exec_cert_timeouts` keeps the expectation alive.
        let local_wave = WaveId::new(
            ShardGroupId(0),
            BlockHeight(10),
            [remote_shard].into_iter().collect(),
        );
        let tx = Arc::new(test_transaction(1));
        let mut participating = BTreeSet::new();
        participating.insert(ShardGroupId(0));
        participating.insert(remote_shard);
        state.waves.insert_wave(
            local_wave.clone(),
            WaveState::new(
                local_wave,
                Hash::from_bytes(b"block"),
                WeightedTimestamp(0),
                vec![(tx, participating)],
                false,
            ),
        );

        // Commit the first block with a QC weighted_timestamp that, without
        // retro-stamping, would imply an elapsed_since of ~billions of ms.
        let block = make_live_block(&topo, BlockHeight(1), 30_000, ValidatorId(0), vec![]);
        let mut certified = certify(block);
        certified.qc.weighted_timestamp = WeightedTimestamp(30_000);

        let actions = state.on_block_committed(&topo, &certified);

        let fallback_fired = actions
            .iter()
            .any(|a| matches!(a, Action::RequestMissingExecutionCert { .. }));
        assert!(
            !fallback_fired,
            "retro-stamp must suppress the first-commit fallback storm"
        );
    }
}
