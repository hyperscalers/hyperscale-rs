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
//! proofs are received, a `WaveCertificate` is created.

use std::collections::{BTreeSet, HashSet};
use std::sync::Arc;

use hyperscale_core::{Action, FetchAbandon, FetchRequest, ProtocolEvent};
use hyperscale_types::{
    Attempt, AwaitingTopologyBuffer, Block, BlockHash, BlockHeader, BlockHeight, BloomFilter,
    CertifiedBlock, ExecutionCertificate, ExecutionCertificateVerifyError, ExecutionVote,
    FinalizedWave, FinalizedWaveVerifyError, GlobalReceiptRoot, Hash, Provisions,
    RoutableTransaction, ScheduleLookup, ShardId, StoredReceipt, TopologySchedule,
    TopologySnapshot, TxHash, TxOutcome, ValidatorId, Verifiable, Verified, WAVE_TIMEOUT,
    WaveCertificate, WaveId, WeightedTimestamp, wave_leader, wave_leader_at,
};
use tracing::instrument;

use crate::conflict::DetectedConflict;
use crate::early_arrivals::{EARLY_VOTE_RETENTION, EarlyArrivalBuffer};
use crate::exec_cert_store::ExecCertStore;
use crate::expected_certs::ExpectedCertTracker;
use crate::finalized_waves::FinalizedWaveStore;
use crate::lookups::{
    assign_waves, build_provision_requests, committee_public_keys_for_shard,
    ec_has_shard_quorum_power, peers_excluding_self,
};
use crate::outbound_certs::OutboundExecutionCertificateTracker;
use crate::provisioning::ProvisioningTracker;
use crate::vote_tracker::VoteTracker;
use crate::wave_state::WaveState;
use crate::waves::{PendingVoteRetry, RetryEffect, WaveRegistry};

/// Data returned when a wave is ready for voting.
///
/// The state machine produces this; the `io_loop` uses it to sign the execution vote
/// and broadcast (since the state machine doesn't hold the signing key).
#[derive(Debug)]
pub struct CompletionData {
    /// Block this wave belongs to; pairs with `wave_id` to identify the vote target.
    pub block_hash: BlockHash,
    /// Height of the wave-starting block.
    pub block_height: BlockHeight,
    /// BFT-authenticated weighted timestamp at which this wave's outcome is
    /// fixed. Included in the vote payload and the EC canonical hash, so all
    /// validators aggregate under the same identifier.
    pub vote_anchor_ts: WeightedTimestamp,
    /// Wave identifier; unique within `block_hash`.
    pub wave_id: WaveId,
    /// Merkle root over per-tx outcome leaves (cross-shard agreement).
    pub global_receipt_root: GlobalReceiptRoot,
    /// Per-tx outcomes in wave order.
    pub tx_outcomes: Vec<TxOutcome>,
}

/// Execution memory statistics for monitoring collection sizes.
#[derive(Clone, Copy, Debug, Default)]
pub struct ExecutionMemoryStats {
    /// Total receipts held across all in-flight waves, awaiting finalization.
    pub wave_execution_receipts: usize,
    /// Finalized waves cached in memory until their proposing block commits.
    pub finalized_wave_certificates: usize,
    /// In-flight wave states (created, not yet finalized or evicted).
    pub waves: usize,
    /// Per-wave vote trackers awaiting quorum.
    pub vote_trackers: usize,
    /// Buffered execution votes waiting for their wave to begin.
    pub early_votes: usize,
    /// Expected EC arrivals from remote shards we're awaiting.
    pub expected_exec_certs: usize,
    /// Verified provisions held per cross-shard tx.
    pub verified_provisions: usize,
    /// Distinct (tx, source-shard) requirements awaiting provisioning.
    pub required_provision_shards: usize,
    /// Distinct (tx, source-shard) provisions received so far.
    pub received_provision_shards: usize,
    /// Waves whose local EC has been emitted.
    pub waves_with_ec: usize,
    /// Vote retries scheduled for resend after rotation timeout.
    pub pending_vote_retries: usize,
    /// Active tx → wave assignments in the registry.
    pub wave_assignments: usize,
    /// Early wave attestations buffered before local routing.
    pub early_wave_attestations: usize,
    /// Buffered ECs awaiting tx assignment routing.
    pub pending_routing: usize,
    /// Expected ECs that have already been fulfilled (kept for diagnostics).
    pub fulfilled_exec_certs: usize,
    /// Outbound ECs retained for re-broadcast to remote shards.
    pub outbound_certs: usize,
}

/// Execution state machine.
///
/// Handles transaction execution after blocks are committed.
pub struct ExecutionCoordinator {
    /// Finalized wave certificates ready for block inclusion, keyed by
    /// `WaveId`. Terminal-state lookup surface for wave-id fetches,
    /// tx-membership queries, and proposal building. Held behind an
    /// `Arc` and shared across same-shard `ExecutionCoordinator`s so
    /// `IoLoop`'s sync-inventory bloom and elided-block rehydration read
    /// from one canonical store per shard rather than vnode-0's
    /// incidentally-convergent copy.
    finalized: Arc<FinalizedWaveStore>,

    /// Current committed height for pruning stale entries.
    committed_height: BlockHeight,

    /// BFT-authenticated weighted timestamp of the last locally committed
    /// block. "Now" reference for timeouts that must be deterministic across
    /// validators and independent of block production rate.
    committed_ts: WeightedTimestamp,

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

    // ═══════════════════════════════════════════════════════════════════════
    // Outbound EC Retention (target → source delivery guarantee)
    // ═══════════════════════════════════════════════════════════════════════
    /// Retains ECs the wave leader broadcast to remote shards and re-emits
    /// them on a deterministic interval until the wave finalizes locally
    /// (positive ACK signal) or the safety horizon elapses. Symmetric to
    /// `OutboundProvisionTracker` on the source side.
    outbound_certs: OutboundExecutionCertificateTracker,

    /// Aggregated local-shard execution certificates awaiting block commit.
    /// Held behind an `Arc` and shared with the `io_loop` so the inbound EC
    /// fetch handler can serve cross-shard fallback requests without taking
    /// a coordinator lock. Populated on local aggregation and on verifying
    /// a local-shard EC received via broadcast; evicted in
    /// `remove_finalized_wave` once the containing block commits.
    exec_certs: Arc<ExecCertStore>,

    /// In-flight EC BLS-verifications, keyed by a content hash over the
    /// cached SBOR bytes. A flooding peer would otherwise re-trigger a BLS
    /// dispatch on every byte-identical retransmit. Different aggregations
    /// of the same logical EC produce distinct wire bytes and so still
    /// dispatch — important when a first aggregation's signature is bad and
    /// a peer follows up with a valid one.
    pending_ec_verifications: HashSet<Hash>,

    /// In-flight `FinalizedWave` BLS-verifications, keyed by `WaveId`. The
    /// wave is content-addressed by id (one wave per `WaveId`), so a second
    /// fetch arrival for the same wave can short-circuit the BLS pool.
    pending_finalized_wave_verifications: HashSet<WaveId>,

    // ═══════════════════════════════════════════════════════════════════════
    // Beacon-sync-lag buffers
    // ═══════════════════════════════════════════════════════════════════════
    /// Cross-shard ECs whose committee epoch this node's beacon hasn't reached,
    /// so `at(vote_anchor_ts)` can't resolve the signing committee. Keyed by the
    /// EC's own shard, bounded per shard (drop-oldest). Re-attempted on
    /// `BeaconBlockPersisted`. Pure catch-up: a buffered EC means *we* are
    /// behind, since under lookahead its committee is already globally fixed.
    awaiting_certs: AwaitingTopologyBuffer<Verifiable<ExecutionCertificate>>,

    /// Fetched `FinalizedWave`s deferred for the same reason — a contained EC's
    /// committee epoch isn't in our schedule yet. Keyed by the wave's own shard;
    /// re-attempted on `BeaconBlockPersisted`.
    awaiting_waves: AwaitingTopologyBuffer<Arc<Verifiable<FinalizedWave>>>,

    /// This validator's identity.
    me: ValidatorId,

    /// This validator's home shard.
    local_shard: ShardId,
}

impl ExecutionCoordinator {
    /// Create a new execution state machine with its own fresh stores.
    /// For hosts running multiple same-shard validators, prefer
    /// [`Self::with_shared_stores`] to share one set of stores across
    /// every coordinator in the shard.
    #[must_use]
    pub fn new(me: ValidatorId, local_shard: ShardId) -> Self {
        Self::with_shared_stores(
            me,
            local_shard,
            Arc::new(ExecCertStore::new()),
            Arc::new(FinalizedWaveStore::new()),
        )
    }

    /// Create a new execution state machine sharing both externally-owned
    /// `ExecCertStore` and `FinalizedWaveStore`. Same-shard vnodes share
    /// one set of stores so the `IoLoop`'s inbound fetch handler and
    /// sync-inventory bloom read from a single canonical view per shard
    /// rather than vnode-0's incidentally-convergent copy.
    #[must_use]
    pub fn with_shared_stores(
        me: ValidatorId,
        local_shard: ShardId,
        exec_certs: Arc<ExecCertStore>,
        finalized: Arc<FinalizedWaveStore>,
    ) -> Self {
        Self {
            finalized,
            committed_height: BlockHeight::GENESIS,
            committed_ts: WeightedTimestamp::ZERO,
            waves: WaveRegistry::new(),
            early: EarlyArrivalBuffer::new(),
            provisioning: ProvisioningTracker::new(),
            expected_certs: ExpectedCertTracker::new(),
            outbound_certs: OutboundExecutionCertificateTracker::new(),
            exec_certs,
            pending_ec_verifications: HashSet::new(),
            pending_finalized_wave_verifications: HashSet::new(),
            awaiting_certs: AwaitingTopologyBuffer::new(),
            awaiting_waves: AwaitingTopologyBuffer::new(),
            me,
            local_shard,
        }
    }

    /// Reference to the shared finalized-wave store. The `io_loop`
    /// clones this `Arc` into its `SharedCaches` so sync-inventory
    /// blooms and elided-block rehydration read from a single canonical
    /// per-shard store rather than vnode-0's incidentally-convergent
    /// copy.
    #[must_use]
    pub const fn finalized_wave_store(&self) -> &Arc<FinalizedWaveStore> {
        &self.finalized
    }

    /// Reference to the shared execution-certificate store. The `io_loop`
    /// clones this `Arc` into its `SharedCaches` so the inbound EC fetch
    /// handler can read aggregated local-shard certificates without
    /// acquiring a coordinator lock.
    #[must_use]
    pub const fn exec_cert_store(&self) -> &Arc<ExecCertStore> {
        &self.exec_certs
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Wave Assignment
    // ═══════════════════════════════════════════════════════════════════════════

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
    /// that need to be replayed through `dispatch_execution_vote()`.
    fn setup_waves_and_dispatch(
        &mut self,
        topology: &TopologySchedule,
        block_hash: BlockHash,
        block_height: BlockHeight,
        block_ts: WeightedTimestamp,
        transactions: &[Arc<Verifiable<RoutableTransaction>>],
    ) -> (Vec<Action>, Vec<Verifiable<ExecutionVote>>) {
        let waves = assign_waves(
            topology.head(),
            self.local_shard,
            block_height,
            transactions,
        );
        // Setup-time leader/quorum key on the wave-start timestamp — a
        // best-effort guess, since the wave's `vote_anchor_ts` isn't fixed
        // until it votes. When that lands in a later epoch, the
        // fallback-tracker path rebuilds under the correct committee; `None`
        // (beacon hasn't reached this epoch) just skips the optimization.
        let setup_committee = topology.at(block_ts);
        let local_shard = self.local_shard;
        let mut dispatch_actions: Vec<Action> = Vec::new();
        let mut votes_to_replay: Vec<Verifiable<ExecutionVote>> = Vec::new();

        for (wave_id, txs) in waves {
            let tx_hashes: Vec<TxHash> = txs.iter().map(|(tx, _)| tx.hash()).collect();
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
                    let remote_shards: BTreeSet<ShardId> = participating
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
                        self.local_shard,
                        topology.head(),
                        tx.declared_reads(),
                        tx.declared_writes(),
                    );
                    if !self.provisioning.is_fully_provisioned(tx_hash) {
                        reverse_conflicts.extend(conflicts);
                    }
                }
            }

            // Create the WaveState. For single-shard waves,
            // `all_provisioned_at` is set to `wave_start_ts`
            // immediately by the constructor.
            let mut wave_state =
                WaveState::new(wave_id.clone(), block_hash, block_ts, txs, is_single_shard);

            // Apply the deadlock-resolving reverse conflicts collected above.
            for conflict in reverse_conflicts {
                wave_state.record_abort(conflict.loser_tx, conflict.committed_at);
            }

            // For cross-shard waves: fold in any provisions that already arrived.
            // If every tx is fully covered, the wave transitions to
            // "provisioned" at block_height.
            if !is_single_shard {
                wave_state.absorb_ready_provisions(&self.provisioning, block_ts);
            }

            // Dispatch execution if fully provisioned at creation.
            if let Some(action) = wave_state.dispatch_if_ready(&self.provisioning) {
                dispatch_actions.push(action);
            }

            self.waves.insert_wave(wave_id.clone(), wave_state);

            // Only the wave leader creates a VoteTracker for aggregation.
            // Resolved under `setup_committee` (the wave-start guess); the
            // fallback-tracker path corrects a boundary-straddling wave whose
            // real committee differs.
            if let Some(committee) = setup_committee
                && self.me == wave_leader(&wave_id, committee.committee_for_shard(local_shard))
            {
                let quorum = committee.quorum_threshold_for_shard(local_shard);
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
    ///
    /// # Panics
    ///
    /// Panics if `waves_iter()` and `get_wave_mut()` disagree about wave
    /// presence — unreachable, no concurrent mutation between them.
    pub fn scan_complete_waves(&mut self) -> Vec<CompletionData> {
        let committed_ts = self.committed_ts;

        let votable_wave_ids: Vec<WaveId> = self
            .waves
            .waves_iter()
            .filter(|(wid, w)| {
                !self.waves.is_ec_dispatched(wid)
                    && !w.local_ec_emitted()
                    && w.can_emit_vote(committed_ts)
            })
            .map(|(wid, _)| wid.clone())
            .collect();

        let mut completions = Vec::new();
        for wave_id in votable_wave_ids {
            let wave = self
                .waves
                .get_wave_mut(&wave_id)
                .expect("wave_id was just produced by waves_iter() in this method");
            let block_hash = wave.block_hash();
            let block_height = wave.block_height();
            let Some((vote_anchor_ts, global_receipt_root, tx_outcomes)) =
                wave.build_vote_data(committed_ts)
            else {
                continue;
            };

            completions.push(CompletionData {
                block_hash,
                block_height,
                vote_anchor_ts,
                wave_id,
                global_receipt_root,
                tx_outcomes,
            });
        }

        // Sort for deterministic ordering (waves is a HashMap).
        completions.sort_by(|a, b| a.wave_id.cmp(&b.wave_id));

        completions
    }

    /// Absorb a completed execution provisions: route receipts into the cache and
    /// record per-tx outcomes on the wave.
    ///
    /// Returns any actions that became newly possible because the provisions
    /// unblocked a wave that was waiting only on local receipts. In
    /// particular, a cross-shard wave whose local EC arrived before this
    /// validator's engine finished will defer finalization under the
    /// `has_local_receipts_for_non_aborted` gate in `WaveState::is_complete`;
    /// once the provisions lands, the wave becomes complete and we finalize
    /// here rather than waiting for some unrelated trigger.
    pub fn on_execution_batch_completed(
        &mut self,
        wave_id: &WaveId,
        results: Vec<StoredReceipt>,
        tx_outcomes: Vec<TxOutcome>,
    ) -> Vec<Action> {
        if results.is_empty() && tx_outcomes.is_empty() {
            tracing::warn!(
                wave = %wave_id,
                "ExecutionBatchCompleted produced ZERO results"
            );
            return Vec::new();
        }

        let Some(wave) = self.waves.get_wave_mut(wave_id) else {
            tracing::warn!(
                wave = %wave_id,
                "ExecutionBatchCompleted for unknown wave — dropping (wave was pruned or never created)"
            );
            return Vec::new();
        };
        for result in results {
            wave.record_receipt(result);
        }
        for wr in tx_outcomes {
            let (tx_hash, outcome) = wr.into_parts();
            wave.record_execution_result(tx_hash, outcome);
        }

        // With local receipts in hand, the wave may have crossed into
        // `is_complete` if its local EC arrived ahead of the engine. Drive
        // finalization from here so the deferred finalize happens on the
        // same event that unblocked it.
        if wave.is_complete() {
            self.finalize_wave(wave_id)
        } else {
            Vec::new()
        }
    }

    /// Scan complete waves and emit `SignAndSendExecutionVote` actions.
    ///
    /// This is the SINGLE path to execution voting. Call after conflicts
    /// have been processed so wave state is deterministic at this height.
    /// Each vote is sent to the wave leader (unicast). The `vote_anchor_ts`
    /// is the shard consensus-authenticated weighted timestamp determined by the wave
    /// (either `all_provisioned_at`, or `wave_start_ts + WAVE_TIMEOUT`
    /// for timeout-abort).
    pub fn emit_vote_actions(&mut self, topology: &TopologySchedule) -> Vec<Action> {
        let local_vid = self.me;
        let completions = self.scan_complete_waves();
        let mut actions = Vec::with_capacity(completions.len());
        for completion in completions {
            // The wave's committee is the one seated at its vote anchor — the
            // same committee that will verify the EC. `None` (beacon behind
            // that epoch) defers this completion; it re-scans on a later commit.
            let Some(committee) = topology
                .at(completion.vote_anchor_ts)
                .map(|s| s.committee_for_shard(self.local_shard).to_vec())
            else {
                continue;
            };
            let leader = wave_leader(&completion.wave_id, &committee);
            // Track retry state for non-leaders so we can re-send to a
            // rotated leader if this one doesn't produce an EC.
            let tx_outcomes = Arc::new(completion.tx_outcomes);
            if local_vid != leader {
                self.waves.record_vote_retry(
                    completion.wave_id.clone(),
                    PendingVoteRetry {
                        sent_at: self.committed_ts,
                        attempt: Attempt::INITIAL,
                        block_hash: completion.block_hash,
                        block_height: completion.block_height,
                        vote_anchor_ts: completion.vote_anchor_ts,
                        global_receipt_root: completion.global_receipt_root,
                        tx_outcomes: Arc::clone(&tx_outcomes),
                    },
                );
            }
            actions.push(Action::SignAndSendExecutionVote {
                block_hash: completion.block_hash,
                block_height: completion.block_height,
                vote_anchor_ts: completion.vote_anchor_ts,
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
    pub fn cleanup_committed_waves(&mut self, certificates: &[Arc<Verifiable<FinalizedWave>>]) {
        for fw in certificates {
            // No-op for synced waves we never aggregated locally; for waves we
            // tracked, releases accumulator/cache state for the wave's txs.
            self.remove_finalized_wave(fw.as_unverified());
        }
    }

    /// Apply provisions committed in a block.
    ///
    /// Two phases — absorb all batches first, then detect conflicts. If
    /// interleaved, the `already_provisioned` guard in phase 2 reads a
    /// partially-absorbed map whose contents depend on provisions iteration order,
    /// which diverges abort decisions across validators.
    ///
    /// Each batch is peeked for its [`Verifiable::verified`] marker before
    /// re-wrapping. Same-process upstream paths leave the marker live, so
    /// we borrow the existing [`Verified<Provisions>`] without a body
    /// clone. Wire-decoded blocks land at `Unverified`; the
    /// [`Verified::<Provisions>::from_committed_block`] gate then carries
    /// the BFT-transitive trust source via a re-wrap (one body clone).
    fn apply_committed_provisions(
        &mut self,
        batches: &[Arc<Verifiable<Provisions>>],
        committed_height: BlockHeight,
        committed_ts: WeightedTimestamp,
    ) -> Vec<Action> {
        // Sort for deterministic phase-2 iteration (logs, action vector order).
        let mut ordered: Vec<&Arc<Verifiable<Provisions>>> = batches.iter().collect();
        ordered.sort_by_key(|b| b.hash());

        // Phase 1: absorb all provisions. Populated unconditionally so
        // `setup_waves_and_dispatch` can replay them at wave-creation time.
        let mut affected_waves: BTreeSet<WaveId> = BTreeSet::new();
        for provisions in &ordered {
            let touched = if let Some(v) = provisions.verified() {
                self.provisioning.absorb_provisions(v)
            } else {
                let verified = Verified::<Provisions>::from_committed_block(
                    provisions.as_unverified().clone(),
                );
                self.provisioning.absorb_provisions(&verified)
            };
            for tx_hash in touched {
                if let Some(wave_id) = self.waves.wave_assignment(tx_hash) {
                    affected_waves.insert(wave_id);
                }
            }
        }

        // Phase 2: detect node-ID overlap conflicts against the fully-absorbed
        // provisioned set. A conflict is skipped if the loser is already
        // fully provisioned (execution can proceed) or its wave has already
        // dispatched (inert to mid-flight input).
        for provisions in &ordered {
            let source_shard = provisions.source_shard();
            for conflict in self
                .provisioning
                .detect_conflicts(provisions.as_unverified(), committed_ts)
            {
                let loser = conflict.loser_tx;
                if self.provisioning.is_fully_provisioned(loser) {
                    continue;
                }
                let Some(wave_id) = self.waves.wave_assignment(loser) else {
                    continue;
                };
                let Some(wave) = self.waves.get_wave_mut(&wave_id) else {
                    continue;
                };
                if wave.dispatched() {
                    continue;
                }
                wave.record_abort(loser, conflict.committed_at);
                affected_waves.insert(wave_id);
                tracing::debug!(
                    loser_tx = %loser,
                    source_shard = source_shard.inner(),
                    committed_at = committed_height.inner(),
                    "Node-ID overlap conflict — aborting loser"
                );
            }
        }

        // Phase 3: for each affected wave, mark newly-ready txs provisioned. If
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

            wave.absorb_ready_provisions(&self.provisioning, committed_ts);

            if let Some(action) = wave.dispatch_if_ready(&self.provisioning) {
                actions.push(action);
            }
        }

        actions
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Wave Vote Handling
    // ═══════════════════════════════════════════════════════════════════════════

    /// Handle a locally-produced, pre-verified execution vote.
    /// Bypasses the BLS batch path and lands directly in the verified
    /// tally. See [`Self::dispatch_execution_vote`] for the leader,
    /// fallback, and early-buffer routing rules.
    pub fn on_verified_execution_vote(
        &mut self,
        topology: &TopologySchedule,
        vote: Verified<ExecutionVote>,
    ) -> Vec<Action> {
        self.dispatch_execution_vote(topology, vote.into())
    }

    /// Handle a wire-arrived execution vote. Buffered for batch BLS
    /// verification once combined power could reach quorum. See
    /// [`Self::dispatch_execution_vote`] for the full routing rules.
    pub fn on_unverified_execution_vote(
        &mut self,
        topology: &TopologySchedule,
        vote: ExecutionVote,
    ) -> Vec<Action> {
        self.dispatch_execution_vote(topology, vote.into())
    }

    /// Routing hub for both ingestion paths.
    ///
    /// Only the wave leader (or a fallback leader via rotation)
    /// aggregates votes. If a vote arrives at a non-leader that has
    /// the accumulator but no tracker, a fallback `VoteTracker` is
    /// created on-demand (the sender determined this validator is the
    /// rotated leader for their retry attempt).
    ///
    /// The `Verifiable<ExecutionVote>` signature lets the
    /// early-arrivals buffer hold either taxonomy under one shape and
    /// replay them through the same path when a fallback tracker
    /// spins up.
    ///
    /// # Panics
    ///
    /// Panics if a vote tracker is created or recovered for a wave but
    /// is missing on the immediate `take_unverified_votes` lookup — the
    /// tracker is locked across `&mut self`, so this is unreachable.
    fn dispatch_execution_vote(
        &mut self,
        topology: &TopologySchedule,
        vote: Verifiable<ExecutionVote>,
    ) -> Vec<Action> {
        let wave_id = vote.wave_id().clone();
        let validator_id = vote.validator();

        // The committee seated at the vote's anchor — the same one whose
        // positional bitfield the EC will carry. `None` means our beacon
        // hasn't reached that epoch; drop and let the sender's retry re-deliver
        // once we catch up.
        let Some(committee) = topology.at(vote.vote_anchor_ts()) else {
            return vec![];
        };

        // Only votes from local-committee members count. A globally-known
        // validator outside this shard's committee whose vote pooled into
        // `unverified_power` would puff up the tracker into early
        // aggregation, producing an EC whose BLS aggregate carries
        // signatures the verifier's bitfield-derived pubkey pool excludes
        // — guaranteed to fail verification and waste a leader rotation.
        // Mirrors `vote_keeper::record_received_vote`.
        if committee
            .committee_index_for_shard(self.local_shard, validator_id)
            .is_none()
        {
            tracing::warn!(
                validator = validator_id.inner(),
                "Execution vote from validator not in local committee"
            );
            return vec![];
        }

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
            let quorum = committee.quorum_threshold_for_shard(self.local_shard);
            let block_hash = self
                .waves
                .get_wave(&wave_id)
                .expect("contains_wave returned true two lines above")
                .block_hash();
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
                    actions.extend(self.dispatch_execution_vote(topology, ev));
                }
                // Process the current vote that triggered fallback creation.
                actions.extend(self.dispatch_execution_vote(topology, vote));
                return actions;
            }
        }

        // Already-verified votes (own votes from the sign-and-send gate, or
        // future cached-verified inputs) skip the buffer + batch-verify
        // round trip and land directly in the verified tally.
        let vote = match vote.into_verified() {
            Ok(verified) => return self.handle_verified_vote(topology, verified),
            Err(raw) => raw,
        };

        // Committee membership was confirmed above; the topology snapshot
        // invariant guarantees the public key resolves.
        let public_key = committee
            .public_key(validator_id)
            .expect("committee member has public key (TopologySnapshot invariant)");

        let tracker = self
            .waves
            .get_tracker_mut(&wave_id)
            .expect("tracker was inserted above when contains_tracker returned false");

        // buffer_unverified_vote handles dedup per (validator, vote_anchor_ts).
        // Same validator can vote at multiple heights (round voting).
        if !tracker.buffer_unverified_vote(vote, public_key) {
            return vec![];
        }

        self.maybe_trigger_vote_verification(wave_id)
    }

    /// Check if we should trigger provisions verification for a wave's votes.
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
            "Dispatching execution vote provisions verification"
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
        topology: &TopologySchedule,
        vote: Verified<ExecutionVote>,
    ) -> Vec<Action> {
        let wave_id = vote.wave_id().clone();
        // The vote anchors to a committee the beacon has reached: `at` returning
        // `None` means the beacon hasn't committed that epoch yet (drop and let
        // the sender retry). Membership was confirmed before delegating here.
        if topology.at(vote.vote_anchor_ts()).is_none() {
            return vec![];
        }

        let Some(tracker) = self.waves.get_tracker_mut(&wave_id) else {
            return vec![];
        };

        tracker.add_verified_vote(vote);

        let mut actions = self.check_vote_quorum(topology, wave_id.clone());
        actions.extend(self.maybe_trigger_vote_verification(wave_id));
        actions
    }

    /// Handle provisions execution vote verification completed.
    pub fn on_votes_verified(
        &mut self,
        topology: &TopologySchedule,
        wave_id: WaveId,
        block_hash: BlockHash,
        verified_votes: Vec<Verified<ExecutionVote>>,
    ) -> Vec<Action> {
        // Diagnostic quorum threshold for the split-root warning below, keyed
        // on the votes' anchor before they're consumed into the tracker.
        let warn_quorum = verified_votes
            .first()
            .and_then(|v| topology.at(v.vote_anchor_ts()))
            .map(|s| s.quorum_threshold_for_shard(self.local_shard));

        let Some(tracker) = self.waves.get_tracker_mut(&wave_id) else {
            return vec![];
        };

        tracker.on_verification_complete();

        for vote in verified_votes {
            tracker.add_verified_vote(vote);
        }

        // Warn if we have enough total power for quorum but it's split
        // across multiple global receipt roots — this means validators disagree
        // on execution results.
        if let Some(quorum) = warn_quorum
            && tracker.check_quorum().is_none()
            && tracker.total_verified_power() >= quorum
            && tracker.distinct_global_receipt_root_count() > 1
        {
            let summary = tracker.global_receipt_root_power_summary();
            tracing::warn!(
                block_hash = ?block_hash,
                wave = %wave_id,
                global_receipt_root_split = ?summary,
                quorum = quorum.inner(),
                "Execution vote quorum blocked: global receipt roots are split across validators"
            );
        }

        let mut actions = self.check_vote_quorum(topology, wave_id.clone());
        actions.extend(self.maybe_trigger_vote_verification(wave_id));
        actions
    }

    /// Check if quorum is reached for a wave's votes.
    fn check_vote_quorum(&mut self, topology: &TopologySchedule, wave_id: WaveId) -> Vec<Action> {
        let local_shard = self.local_shard;
        let Some(tracker) = self.waves.get_tracker_mut(&wave_id) else {
            return vec![];
        };

        let Some((global_receipt_root, vote_anchor_ts, _total_power)) = tracker.check_quorum()
        else {
            return vec![];
        };

        // The EC's signer bitfield is positional against the committee seated
        // at `vote_anchor_ts` — the committee every verifier resolves from the
        // EC's own anchor. Resolve it before consuming the votes; `None`
        // (beacon behind this epoch) leaves the tracker intact to re-check on a
        // later commit.
        let Some(committee) = topology
            .at(vote_anchor_ts)
            .map(|s| s.committee_for_shard(local_shard).to_vec())
        else {
            return vec![];
        };

        let block_hash = tracker.block_hash();

        tracing::info!(
            block_hash = ?block_hash,
            wave = %wave_id,
            vote_anchor_ts = vote_anchor_ts.as_millis(),
            "Execution vote quorum reached — aggregating certificate"
        );

        let votes = tracker.take_votes(global_receipt_root, vote_anchor_ts);

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

        // Stamp phase times for txs covered by the new local EC. Pure
        // telemetry — IoLoop's slow-tx finalization log reads it.
        let ec_tx_hashes = self
            .waves
            .get_wave(&wave_id)
            .map(|w| w.tx_hashes().to_vec())
            .unwrap_or_default();

        // tx_outcomes are extracted from votes by the aggregation handler
        // (all quorum votes carry identical outcomes).
        let mut actions = vec![Action::AggregateExecutionCertificate {
            wave_id,
            global_receipt_root,
            votes,
            committee,
        }];
        if !ec_tx_hashes.is_empty() {
            actions.push(Action::RecordTxEcCreated {
                tx_hashes: ec_tx_hashes,
            });
        }
        actions
    }

    /// Handle execution certificate aggregation completed.
    ///
    /// Called when the crypto pool finishes BLS aggregation for a wave's votes.
    /// Only the wave leader (primary or fallback) reaches this path.
    /// Broadcasts the EC to all local peers and remote participating shards,
    /// then feeds it to the wave-level certificate tracker for finalization.
    pub fn on_certificate_aggregated(
        &mut self,
        topology: &TopologySchedule,
        wave_id: &WaveId,
        certificate: &Arc<Verified<ExecutionCertificate>>,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        // EC broadcast is routing — who should receive it now — so recipients
        // key on the active head, not the EC's anchor committee.
        let head = topology.head();

        // The wave_id IS the set of remote shards — no need to look up the
        // accumulator (which may have been pruned by the time the cert is
        // aggregated, especially with many shards where provision flow is slower).
        let remote_shards: Vec<ShardId> = wave_id.remote_shards().iter().copied().collect();

        // Make the cert available to the io_loop's inbound EC fetch handler
        // for fallback serving until the containing block commits.
        self.exec_certs.insert(Arc::clone(certificate));

        // Broadcast EC to all local peers (they don't aggregate — they need it).
        let local_peers = peers_excluding_self(head, self.me, self.local_shard);
        if !local_peers.is_empty() {
            actions.push(Action::BroadcastExecutionCertificate {
                shard: self.local_shard,
                certificate: Arc::clone(certificate),
                recipients: local_peers,
            });
        }

        // Broadcast EC to remote participating shards. Track each per-target
        // send so a dropped notify is re-emitted before the source's 24s
        // fallback timer trips — symmetric to ef4eb45a on provisions.
        for target_shard in &remote_shards {
            let recipients: Vec<ValidatorId> = head.committee_for_shard(*target_shard).to_vec();
            self.outbound_certs.on_broadcast(
                Arc::clone(certificate),
                *target_shard,
                recipients.clone(),
            );
            actions.push(Action::BroadcastExecutionCertificate {
                shard: *target_shard,
                certificate: Arc::clone(certificate),
                recipients,
            });
        }

        tracing::debug!(
            wave = %wave_id,
            tx_count = certificate.tx_outcomes().len(),
            remote_shards = remote_shards.len(),
            "Wave leader broadcasting EC to local peers and remote shards"
        );

        // Feed the EC to the wave-level certificate tracker for finalization.
        actions.extend(self.handle_wave_attestation(certificate));

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
        topology: &TopologySchedule,
        cert: Verifiable<ExecutionCertificate>,
    ) -> Vec<Action> {
        let shard = cert.shard_id();
        let wire_hash = cert.wire_hash();

        // Cached-verified short-circuit. `exec_certs` is shared across
        // same-shard vnodes (one `Arc<ExecCertStore>` per shard), so a
        // peer vnode's aggregation makes this EC available to ours
        // before the gossip arrives. A wire-hash match against the
        // cached entry means this is the same aggregation we already
        // verified and routed; a mismatch is a different aggregation
        // of the same logical EC and still needs its own BLS check.
        if let Some(cached) = self.exec_certs.get(cert.wave_id())
            && cached.wire_hash() == wire_hash
        {
            tracing::debug!(
                shard = shard.inner(),
                wave = %cert.wave_id(),
                "Cached verified EC matches incoming wire hash — skipping BLS dispatch"
            );
            return vec![];
        }

        // Skip BLS dispatch for byte-identical retransmits while a
        // verification is already in flight. Different aggregations of the
        // same logical EC produce distinct wire bytes, so the legitimate
        // case of "first aggregation invalid, second valid" is preserved.
        if !self.pending_ec_verifications.insert(wire_hash) {
            tracing::debug!(
                shard = shard.inner(),
                wave = %cert.wave_id(),
                "Duplicate EC verification dispatch suppressed"
            );
            return vec![];
        }

        let committee = match topology.lookup(cert.vote_anchor_ts()) {
            ScheduleLookup::Committee(committee) => committee,
            ScheduleLookup::NotYetCommitted => {
                // Beacon hasn't reached this EC's epoch — buffer for replay on
                // catch-up rather than abandoning and re-fetching. Release the
                // in-flight slot so the replay re-dispatches.
                self.pending_ec_verifications.remove(&wire_hash);
                self.awaiting_certs.push(cert.shard_id(), cert);
                return vec![];
            }
            ScheduleLookup::Evicted => {
                // Below the schedule floor the EC is past its retention
                // horizon — provably terminal everywhere, never resolvable
                // again. Drop instead of buffering, releasing the in-flight
                // slot and the fetch binding.
                tracing::warn!(
                    shard = shard.inner(),
                    wave = %cert.wave_id(),
                    "EC's committee epoch is below the schedule floor — dropping"
                );
                self.pending_ec_verifications.remove(&wire_hash);
                return vec![Action::AbandonFetch(FetchAbandon::ExecutionCerts {
                    ids: vec![cert.wave_id().clone()],
                })];
            }
        };
        let Some(public_keys) = committee_public_keys_for_shard(committee, shard) else {
            tracing::warn!(
                shard = shard.inner(),
                "Could not resolve EC committee keys — snapshot incomplete"
            );
            // Verification will never complete; release the in-flight slot
            // so a subsequent arrival isn't permanently shadowed.
            self.pending_ec_verifications.remove(&wire_hash);
            return vec![Action::AbandonFetch(FetchAbandon::ExecutionCerts {
                ids: vec![cert.wave_id().clone()],
            })];
        };

        vec![Action::VerifyExecutionCertificateSignature {
            certificate: cert,
            public_keys,
        }]
    }

    /// Handle execution certificate signature verification result.
    ///
    /// If valid, hand the cert to `handle_wave_attestation` which routes
    /// per-tx outcomes into any local wave trackers and buffers txs whose
    /// blocks haven't committed yet for replay.
    pub fn on_certificate_verified(
        &mut self,
        topology: &TopologySchedule,
        result: Result<
            Arc<Verified<ExecutionCertificate>>,
            (Arc<ExecutionCertificate>, ExecutionCertificateVerifyError),
        >,
    ) -> Vec<Action> {
        // Release the in-flight slot regardless of outcome — a failed
        // signature still lets the next byte-identical retransmit
        // dispatch again (in case the failure was transient pool error
        // rather than a real signature mismatch). Subsequent arrivals
        // with a different aggregation hash to a different `wire_hash`
        // and aren't gated by this slot.
        let ec_arc = match result {
            Ok(verified) => {
                self.pending_ec_verifications.remove(&verified.wire_hash());
                verified
            }
            Err((raw, err)) => {
                self.pending_ec_verifications.remove(&raw.wire_hash());
                tracing::warn!(
                    shard = raw.shard_id().inner(),
                    wave = %raw.wave_id(),
                    error = ?err,
                    "Invalid execution certificate signature"
                );
                return vec![Action::AbandonFetch(FetchAbandon::ExecutionCerts {
                    ids: vec![raw.wave_id().clone()],
                })];
            }
        };

        // A single Byzantine signer can produce a cryptographically valid
        // EC; require 2f+1 voting power on the EC's own shard before any
        // state mutation downstream. The committee is the one seated at the
        // EC's anchor. `on_wave_certificate` already resolved it to dispatch
        // this verification, so `None` here means that epoch aged out of the
        // schedule in the interim (the beacon advanced past retention) — the
        // EC is stale, so abandon it.
        let Some(committee) = topology.at(ec_arc.vote_anchor_ts()) else {
            tracing::warn!(
                shard = ec_arc.shard_id().inner(),
                wave = %ec_arc.wave_id(),
                "Discarding execution certificate — epoch evicted from schedule before verification completed"
            );
            return vec![Action::AbandonFetch(FetchAbandon::ExecutionCerts {
                ids: vec![ec_arc.wave_id().clone()],
            })];
        };
        if !ec_has_shard_quorum_power(committee, &ec_arc) {
            tracing::warn!(
                shard = ec_arc.shard_id().inner(),
                wave = %ec_arc.wave_id(),
                "Discarding sub-quorum execution certificate"
            );
            return vec![Action::AbandonFetch(FetchAbandon::ExecutionCerts {
                ids: vec![ec_arc.wave_id().clone()],
            })];
        }

        let shard = ec_arc.shard_id();

        // Clearing the tombstone before verification would let a Byzantine
        // peer ship an EC with a far-future `vote_anchor_ts`, populating
        // the fulfilled tombstone (deadline = vote_anchor_ts +
        // RETENTION_HORIZON) and suppressing legitimate fallback fetches
        // indefinitely while the verify pool silently rejects the forgery.
        let cleared = self.expected_certs.mark_fulfilled(
            shard,
            ec_arc.block_height(),
            ec_arc.wave_id(),
            ec_arc.tx_outcomes().iter().map(TxOutcome::tx_hash),
            ec_arc.deadline(),
        );
        if cleared {
            tracing::debug!(
                source_shard = shard.inner(),
                block_height = ec_arc.block_height().inner(),
                wave = %ec_arc.wave_id(),
                at_local_ts_ms = self.committed_ts.as_millis(),
                "Fulfilled expected exec cert"
            );
        }

        let mut actions = vec![Action::Continuation(
            ProtocolEvent::ExecutionCertificateAdmitted {
                certificate: Arc::clone(&ec_arc),
            },
        )];

        // If this is a local shard EC, mark the wave as having an EC to skip
        // it in scan_complete_waves, and persist it for fallback serving to
        // remote shards.
        if shard == self.local_shard {
            self.waves.mark_ec_dispatched(ec_arc.wave_id().clone());
            // EC received from wave leader — cancel any pending vote retry.
            self.waves.clear_vote_retry(ec_arc.wave_id());
            // Make the verified cert available to the io_loop's inbound EC
            // fetch handler for fallback serving until block commit.
            self.exec_certs.insert(Arc::clone(&ec_arc));
        }

        actions.extend(self.handle_wave_attestation(&ec_arc));
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
        source_shard: ShardId,
        block_height: BlockHeight,
        waves: &[WaveId],
    ) {
        let local_shard = self.local_shard;

        for wave in waves {
            if wave.remote_shards().contains(&local_shard) {
                self.expected_certs.register(
                    source_shard,
                    block_height,
                    wave.clone(),
                    self.committed_ts,
                );
            }
        }
    }

    /// Check for timed-out expected execution certs and emit fallback requests.
    ///
    /// Called during block commit processing. Returns actions for any certs
    /// that have exceeded the timeout.
    fn check_exec_cert_timeouts(&mut self) -> Vec<Action> {
        let now_ts = self.committed_ts;
        let fetches = self.expected_certs.check_timeouts(now_ts);

        let mut actions = Vec::with_capacity(fetches.len());
        for (wave_id, is_retry) in fetches {
            tracing::info!(
                source_shard = wave_id.shard_id().inner(),
                block_height = wave_id.block_height().inner(),
                wave = %wave_id,
                retry = is_retry,
                "Execution cert timeout — requesting fallback"
            );
            actions.push(Action::Fetch(FetchRequest::ExecutionCerts {
                wave_id,
                preferred: None,
                class: None,
            }));
        }

        // Retain expectations while any local wave still needs an EC from
        // that source shard. `self.waves` is the authoritative "what am I
        // still waiting on" set — entries are removed by `finalize_wave`
        // once a wave is complete. Keyed by source shard (not wave_id)
        // because expected entries carry the remote shard's wave
        // decomposition, which cannot be matched against local wave ids.
        let local_shard = self.local_shard;
        let shards_needed: HashSet<ShardId> = self
            .waves
            .waves_iter()
            .flat_map(|(wid, _)| wid.remote_shards().iter().copied())
            .filter(|s| *s != local_shard)
            .collect();
        self.expected_certs
            .retain_if_shard_needed(&shards_needed, now_ts);
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
    fn check_vote_retry_timeouts(&mut self, topology: &TopologySchedule) -> Vec<Action> {
        let effects = self.waves.check_vote_retry_timeouts(self.committed_ts);
        if effects.is_empty() {
            return Vec::new();
        }

        let mut actions = Vec::with_capacity(effects.len());
        for RetryEffect {
            wave_id,
            attempt,
            block_hash,
            block_height,
            vote_anchor_ts,
            global_receipt_root,
            tx_outcomes,
        } in effects
        {
            // The rotated leader is drawn from the committee seated at the
            // wave's anchor — the one that will verify the EC. `None` (beacon
            // behind) defers this retry to a later commit.
            let Some(committee) = topology
                .at(vote_anchor_ts)
                .map(|s| s.committee_for_shard(self.local_shard).to_vec())
            else {
                continue;
            };
            let new_leader = wave_leader_at(&wave_id, attempt, &committee);
            tracing::info!(
                wave = %wave_id,
                attempt = attempt.inner(),
                new_leader = new_leader.inner(),
                "Vote retry timeout — re-sending to rotated leader"
            );
            actions.push(Action::SignAndSendExecutionVote {
                block_hash,
                block_height,
                vote_anchor_ts,
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
    /// 1. **Anchor time** — bump `committed_height` and `committed_ts`
    ///    from the QC. Every downstream phase reads these.
    /// 2. **First-commit retro-stamp** — entries buffered pre-first-commit
    ///    carry `WeightedTimestamp::ZERO`; stamp them with the new
    ///    `committed_ts` before timeout checks, otherwise
    ///    `elapsed_since(ZERO)` dwarfs every deadline and triggers a
    ///    fallback-fetch storm.
    /// 3. **Timeout checks** — expected-cert fallbacks and vote retries.
    ///    Read the freshly-bumped `committed_ts`.
    /// 4. **Pruning** — resolved waves, stale buffered ECs, aged
    ///    conflict-detector provisions. Must follow timeouts so a retry
    ///    fires before the wave it references is pruned away.
    /// 5. **Dispatch** — route to the live or sealed path for block-specific
    ///    work (wave setup + dispatch, or late-cert routing).
    #[instrument(skip(self, certified, topology), fields(
        height = certified.block().height().inner(),
        block_hash = ?certified.block().hash(),
        tx_count = certified.block().transactions().len(),
        is_live = certified.block().is_live(),
    ))]
    pub fn on_block_committed(
        &mut self,
        topology: &TopologySchedule,
        certified: &CertifiedBlock,
    ) -> Vec<Action> {
        let block = certified.block();
        let height = block.height();

        // Update committed height + timestamp before anything else — needed
        // for timeout calculations and pruning even when there are no new
        // transactions.
        let first_commit = self.committed_ts == WeightedTimestamp::ZERO;
        if height > self.committed_height {
            self.committed_height = height;
            self.committed_ts = certified.block().header().parent_qc().weighted_timestamp();
        }
        self.provisioning.advance_clock(self.committed_ts);

        // Retro-stamp entries recorded before the first local commit. Remote
        // headers can register expected exec certs while `committed_ts` is
        // still zero; without this, every such entry would report a
        // ~57-year age on the next commit and trigger a fallback fetch
        // storm. Buffered ECs anchor on their own BFT-attested
        // `vote_anchor_ts` so they don't need this treatment.
        if first_commit && self.committed_ts != WeightedTimestamp::ZERO {
            let now_ts = self.committed_ts;
            self.expected_certs.retro_stamp_zero_timestamps(now_ts);
        }

        let mut actions = Vec::new();

        // Timeout checks + pruning run every block, not just commits that
        // carry txs.
        actions.extend(self.check_exec_cert_timeouts());
        actions.extend(self.check_vote_retry_timeouts(topology));
        self.prune_execution_state();
        self.early.gc_stale_ecs(self.committed_ts);
        self.provisioning.gc_stale_provisions(self.committed_ts);

        // Re-broadcast outbound ECs that haven't been ACKed via wave
        // finalization. Driven from the commit cadence so the schedule is
        // deterministic across validators.
        for directive in self.outbound_certs.on_block_committed(self.committed_ts) {
            actions.push(Action::BroadcastExecutionCertificate {
                shard: directive.target_shard,
                certificate: directive.certificate,
                recipients: directive.recipients,
            });
        }

        for (_, wave) in self.waves.waves_iter_mut() {
            wave.log_if_overdue(self.committed_ts);
        }

        // Drop conflict-detector entries past `WAVE_TIMEOUT` from their
        // commit. `register_tx` iterates over these per cross-shard tx;
        // left unbounded they drive quadratic TPS decay. Past the bound
        // the remote tx is provably terminal (its wave has either
        // finalized or hit the deterministic abort path), so the detector
        // entry can no longer flag a meaningful conflict.
        //
        // `MAX_VALIDITY_RANGE` is *not* the right bound here — that
        // governs admission, not post-inclusion lifetime. Once a remote
        // tx is in a block, the wave/execution timeout owns its
        // termination. This mirrors `RETENTION_HORIZON`'s
        // `MAX_VALIDITY_RANGE + WAVE_TIMEOUT` split, applied
        // per-stored-provision: each entry's `committed_at` already
        // accounts for the admission window, so only the post-inclusion
        // `WAVE_TIMEOUT` portion remains.
        let cutoff = self.committed_ts.minus(WAVE_TIMEOUT);
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
        topology: &TopologySchedule,
        block_hash: BlockHash,
        header: &BlockHeader,
        transactions: &[Arc<Verifiable<RoutableTransaction>>],
        provisions: &[Arc<Verifiable<Provisions>>],
    ) -> Vec<Action> {
        let height = header.height();
        let mut actions = Vec::new();

        // ── Provision broadcasting (proposer only) ─────────────────────
        if self.me == header.proposer() {
            let local_shard = self.local_shard;
            if let Some((requests, shard_recipients)) =
                build_provision_requests(topology.head(), transactions, self.me, local_shard)
            {
                actions.push(Action::FetchAndBroadcastProvisions {
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
                height = height.inner(),
                tx_count = transactions.len(),
                "Starting execution for new transactions"
            );

            let (dispatch_actions, early_votes) = self.setup_waves_and_dispatch(
                topology,
                block_hash,
                height,
                self.committed_ts,
                transactions,
            );
            actions.extend(dispatch_actions);
            for vote in early_votes {
                actions.extend(self.dispatch_execution_vote(topology, vote));
            }

            actions.extend(self.replay_early_wave_attestations(transactions));
        }

        // Apply this block's provisions after wave setup so newly-created
        // waves can transition to provisioned from the same block's batches.
        if !provisions.is_empty() {
            actions.extend(self.apply_committed_provisions(provisions, height, self.committed_ts));
        }

        actions
    }

    /// Sealed path: past the cross-shard execution window. Waves will
    /// finalize from the already-aggregated cert + receipts included
    /// downstream, so we skip `WaveState` creation, dispatch, and vote
    /// tracking. Only the tx → wave mapping is recorded (plus any early
    /// ECs replayed) so a late-arriving cert still routes back to each
    /// tx for mempool terminal-state bookkeeping.
    fn on_sealed_block_committed(
        &mut self,
        topology: &TopologySchedule,
        header: &BlockHeader,
        transactions: &[Arc<Verifiable<RoutableTransaction>>],
    ) -> Vec<Action> {
        if transactions.is_empty() {
            return Vec::new();
        }
        self.register_sealed_wave_assignments(topology.head(), header.height(), transactions);
        self.replay_early_wave_attestations(transactions)
    }

    /// Replay buffered early ECs for txs that have just received wave
    /// assignments. Invoked from both the live and sealed commit paths —
    /// in either case, a cert that arrived ahead of the commit now has a
    /// tx target to route to.
    fn replay_early_wave_attestations(
        &mut self,
        transactions: &[Arc<Verifiable<RoutableTransaction>>],
    ) -> Vec<Action> {
        let tx_hashes: Vec<TxHash> = transactions.iter().map(|tx| tx.hash()).collect();
        let ecs_to_replay = self.early.drain_ecs_for_txs(&tx_hashes);
        if ecs_to_replay.is_empty() {
            return Vec::new();
        }
        tracing::debug!(
            count = ecs_to_replay.len(),
            "Replaying early wave attestations for newly committed txs"
        );
        let mut actions = Vec::new();
        for ec in &ecs_to_replay {
            actions.extend(self.handle_wave_attestation(ec));
        }
        actions
    }

    /// Register tx → wave assignments for a `Sealed` block without any of
    /// the execution-side state setup (`WaveState`, vote tracker, conflict
    /// detector, required-provision tracking). The block's waves are
    /// already settled; we only need the mapping so a future cert can
    /// route back to the tx for mempool terminal-state bookkeeping.
    fn register_sealed_wave_assignments(
        &mut self,
        topology: &TopologySnapshot,
        block_height: BlockHeight,
        transactions: &[Arc<Verifiable<RoutableTransaction>>],
    ) {
        let waves = assign_waves(topology, self.local_shard, block_height, transactions);
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
    /// A remote EC's `wave_id` reflects the remote shard's wave decomposition,
    /// which differs from the local shard's. A single remote EC may contain
    /// outcomes for transactions in MULTIPLE local waves.
    ///
    /// Routing: iterate `tx_outcomes` → look up local wave via `wave_assignments` →
    /// feed the EC to each affected local wave tracker. `tx_hashes` without a
    /// local assignment are buffered (or kept buffered) via `pending_routing`
    /// until their blocks commit; routed `tx_hashes` are cleared from the
    /// pending set, dropping the EC entirely once fully routed.
    fn handle_wave_attestation(&mut self, ec: &Arc<Verified<ExecutionCertificate>>) -> Vec<Action> {
        let routing = self.waves.classify_attestation(ec);

        self.early.clear_routed(ec, &routing.routed_tx_hashes);
        self.early.buffer_ec(ec, &routing.unrouted_tx_hashes);

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
            if wave.add_execution_certificate(Arc::clone(ec)) && wave.is_complete() {
                actions.extend(self.finalize_wave(wave_id));
            }
        }
        actions
    }

    /// Finalize a wave: build the [`FinalizedWave`], record it, emit events.
    ///
    /// Called when the wave's local EC is present and every non-aborted tx is
    /// covered by all participating shards.
    fn finalize_wave(&mut self, wave_id: &WaveId) -> Vec<Action> {
        let Some(wave) = self.waves.remove_wave(wave_id) else {
            return vec![];
        };

        // Wave finalization requires every participating shard's EC, which
        // means each remote shard executed this wave — strong evidence they
        // also received our outbound EC (or are about to). Drop the
        // re-broadcast tracker entry to stop wasting bandwidth.
        self.outbound_certs.on_wave_finalized(wave_id);

        // Local-finalization gate produces `Verified<FinalizedWave>`; lift
        // into the `Block::Live.certificates` transport shape once so the
        // store, the admission event, and any downstream `PendingBlock`
        // entry share the same `Arc` without further per-consumer cloning.
        let finalized_arc = Arc::new(Verified::<FinalizedWave>::seal(wave.into_finalized()).into());
        self.finalized
            .insert(wave_id.clone(), Arc::clone(&finalized_arc));

        // Single admission event covers both the shard consensus subscriber and the
        // io_loop serving cache (via the Continuation interception arm).
        // The state machine latches a proposal-retry on this event.
        vec![Action::Continuation(
            ProtocolEvent::FinalizedWavesAdmitted {
                waves: vec![finalized_arc],
            },
        )]
    }

    /// Admission entry point for fetch-delivered (or otherwise externally
    /// sourced) finalized waves.
    ///
    /// Runs the cheap synchronous gates inline (per-EC quorum power and
    /// committee-key resolution) and dispatches BLS verification to the
    /// crypto pool via [`Action::VerifyFinalizedWave`]. The matching
    /// [`ProtocolEvent::FinalizedWaveVerified`] feeds
    /// [`Self::on_finalized_wave_verified`], which emits
    /// `Continuation(FinalizedWavesAdmitted)` only when every EC's
    /// signature passed.
    ///
    /// Without this gate a peer answering a `finalized_wave.request` could
    /// poison `caches.finalized_wave` with a bogus wave we'd re-serve.
    /// Locally finalized waves bypass this path: `finalize_wave` emits the
    /// same event from a WC built out of already-verified ECs. Synced
    /// blocks are likewise trusted at admission — the QC chain plus the
    /// synced-block apply path's quorum gate established their integrity
    /// upstream.
    #[must_use]
    pub fn admit_finalized_wave(
        &mut self,
        topology: &TopologySchedule,
        wave: Arc<Verifiable<FinalizedWave>>,
    ) -> Vec<Action> {
        let wave_id = wave.wave_id().clone();

        // Already-finalized short-circuit — a second fetch arrival for a
        // wave we've already admitted is wasted BLS work.
        if self.finalized.contains(&wave_id) {
            tracing::debug!(
                wave = %wave_id,
                "FinalizedWave already in canonical store — skipping verification"
            );
            return Vec::new();
        }

        // In-flight dedup — guards against a peer flooding the same fetched
        // wave while the first dispatch is still running.
        if !self
            .pending_finalized_wave_verifications
            .insert(wave_id.clone())
        {
            tracing::debug!(
                wave = %wave_id,
                "Duplicate FinalizedWave verification dispatch suppressed"
            );
            return Vec::new();
        }

        let ecs = wave.execution_certificates();
        let mut ec_public_keys = Vec::with_capacity(ecs.len());
        let mut beacon_behind = false;
        for ec in ecs {
            let shard = ec.shard_id();
            // Each contained EC is verified against the committee seated at its
            // own anchor on its own shard. A not-yet-committed epoch (our
            // beacon behind) defers the whole wave for replay once the beacon
            // catches up, rather than abandoning and re-fetching; a below-floor
            // epoch rejects it — the EC is past its retention horizon and can
            // never resolve again.
            let committee = match topology.lookup(ec.vote_anchor_ts()) {
                ScheduleLookup::Committee(committee) => committee,
                ScheduleLookup::NotYetCommitted => {
                    beacon_behind = true;
                    break;
                }
                ScheduleLookup::Evicted => {
                    tracing::warn!(
                        wave = %wave.wave_id(),
                        shard = shard.inner(),
                        "Rejecting fetched FinalizedWave: contained EC's committee epoch is \
                         below the schedule floor"
                    );
                    self.pending_finalized_wave_verifications.remove(&wave_id);
                    return vec![Action::AbandonFetch(FetchAbandon::FinalizedWaves {
                        ids: vec![wave_id],
                    })];
                }
            };
            if !ec_has_shard_quorum_power(committee, ec.as_unverified()) {
                tracing::warn!(
                    wave = %wave.wave_id(),
                    shard = shard.inner(),
                    "Rejecting fetched FinalizedWave: contained EC lacks quorum power"
                );
                self.pending_finalized_wave_verifications.remove(&wave_id);
                return vec![Action::AbandonFetch(FetchAbandon::FinalizedWaves {
                    ids: vec![wave_id],
                })];
            }
            let Some(public_keys) = committee_public_keys_for_shard(committee, shard) else {
                tracing::warn!(
                    wave = %wave.wave_id(),
                    shard = shard.inner(),
                    "Rejecting fetched FinalizedWave: cannot resolve EC committee keys"
                );
                self.pending_finalized_wave_verifications.remove(&wave_id);
                return vec![Action::AbandonFetch(FetchAbandon::FinalizedWaves {
                    ids: vec![wave_id],
                })];
            };
            ec_public_keys.push(public_keys);
        }
        if beacon_behind {
            // Buffer the whole wave; replayed on `BeaconBlockPersisted` once the
            // beacon reaches the deferred EC's epoch.
            self.pending_finalized_wave_verifications.remove(&wave_id);
            self.awaiting_waves.push(wave.wave_id().shard_id(), wave);
            return Vec::new();
        }
        vec![Action::VerifyFinalizedWave {
            wave,
            ec_public_keys,
        }]
    }

    /// Re-attempt every buffered cross-shard EC and finalized wave now that the
    /// beacon has advanced. Drains both buffers and replays each through its
    /// normal admission path, which re-resolves the committee and re-buffers
    /// any still beyond the schedule. Called on `BeaconBlockPersisted`.
    pub fn on_beacon_block_persisted(&mut self, topology: &TopologySchedule) -> Vec<Action> {
        let mut actions = Vec::new();
        for cert in self.awaiting_certs.drain() {
            actions.extend(self.on_wave_certificate(topology, cert));
        }
        for wave in self.awaiting_waves.drain() {
            actions.extend(self.admit_finalized_wave(topology, wave));
        }
        actions
    }

    /// Handle the result of [`Action::VerifyFinalizedWave`]. Emits the
    /// admission continuation only when every EC's BLS signature passed.
    #[must_use]
    pub fn on_finalized_wave_verified(
        &mut self,
        result: Result<
            Arc<Verified<FinalizedWave>>,
            (Arc<FinalizedWave>, FinalizedWaveVerifyError),
        >,
    ) -> Vec<Action> {
        // Release the in-flight slot regardless of outcome — future
        // arrivals can dispatch again.
        let wave = match result {
            Ok(verified) => {
                self.pending_finalized_wave_verifications
                    .remove(verified.wave_id());
                verified
            }
            Err((raw, err)) => {
                self.pending_finalized_wave_verifications
                    .remove(raw.wave_id());
                tracing::warn!(
                    wave = %raw.wave_id(),
                    error = ?err,
                    "Dropping fetched FinalizedWave: contained EC signature invalid"
                );
                return vec![Action::AbandonFetch(FetchAbandon::FinalizedWaves {
                    ids: vec![raw.wave_id().clone()],
                })];
            }
        };
        // Lift the verification result into the `Block::Live.certificates`
        // transport shape exactly once so the admission event and any
        // downstream pending-block storage share the same `Arc`.
        let wave = Arc::new((*wave).clone().into());
        vec![Action::Continuation(
            ProtocolEvent::FinalizedWavesAdmitted { waves: vec![wave] },
        )]
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Query Methods
    // ═══════════════════════════════════════════════════════════════════════════

    /// Get the local wave assignment for a transaction.
    #[must_use]
    pub fn get_wave_assignment(&self, tx_hash: TxHash) -> Option<WaveId> {
        self.waves.wave_assignment(tx_hash)
    }

    /// Get all finalized waves (for proposal building). Returns the
    /// `Block::Live.certificates` transport shape so the proposer can hand
    /// the result straight to the action without a per-element conversion.
    #[must_use]
    pub fn get_finalized_waves(&self) -> Vec<Arc<Verifiable<FinalizedWave>>> {
        self.finalized.all_waves()
    }

    /// Get a finalized wave by its `WaveId` (returns `Arc` for sharing).
    #[must_use]
    pub fn get_finalized_wave(&self, wave_id: &WaveId) -> Option<Arc<Verifiable<FinalizedWave>>> {
        self.finalized.get(wave_id)
    }

    /// Bloom filter over every tracked finalized-wave id hash. Attached to
    /// outgoing `GetBlockRequest`s so the responder can elide wave
    /// certificates the requester already has. Returns `None` when the
    /// cached set is too large to size a filter within the configured cap.
    #[must_use]
    pub fn cert_bloom_snapshot(&self) -> Option<BloomFilter<WaveId>> {
        self.finalized.cert_bloom_snapshot()
    }

    /// Get the finalized wave certificate containing a specific transaction.
    ///
    /// Returns the wave certificate if the tx is part of a finalized wave.
    /// Once committed, certificates are persisted to storage and should be fetched from there.
    #[must_use]
    pub fn get_finalized_certificate(&self, tx_hash: TxHash) -> Option<Arc<WaveCertificate>> {
        self.finalized.get_certificate_for_tx(tx_hash)
    }

    /// Remove a finalized wave (after its wave cert has been committed in a block).
    ///
    /// Cleans up all per-tx tracking state for transactions in this wave.
    /// Takes the `FinalizedWave` directly (rather than just a `WaveId`) so
    /// cleanup works even when the wave was never aggregated locally — e.g.
    /// for blocks received via sync. The committed `FinalizedWave` is the
    /// authoritative tx-set source.
    pub fn remove_finalized_wave(&mut self, fw: &FinalizedWave) {
        let wave_id = fw.wave_id();
        self.finalized.remove(wave_id);
        // The local-shard EC is now durable in storage via the committed
        // wave certificate; drop the in-memory copy so peers fetching after
        // this point fall through to storage.
        self.exec_certs.evict(wave_id);
        // The wave may already have been removed by `finalize_wave` (local
        // aggregation path) or be absent entirely (sync path: the block was
        // received as committed without local tracking). Either case is fine.
        self.waves.remove_wave(wave_id);

        let tx_hashes: Vec<TxHash> = fw.tx_hashes().collect();
        for &tx_hash in &tx_hashes {
            self.waves.remove_assignment(tx_hash);
            self.provisioning.remove_tx(tx_hash);
        }
        // Drain pending-tx sets on fulfilled-cert tombstones referencing
        // any of these txs. When the EC's last referenced tx terminates,
        // the tombstone evicts — independent of any wall-clock window.
        self.expected_certs
            .on_txs_terminated(tx_hashes.iter().copied());
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
        //   committed, shard consensus broken
        //
        // Non-leaders with a wave but no VoteTracker KEEP early votes. They
        // may become fallback leaders via rotation and need to replay them
        // into the on-demand VoteTracker created in `on_execution_vote`.
        let ev_cutoff = self.committed_ts.minus(EARLY_VOTE_RETENTION);
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
                .is_some_and(|v| v.vote_anchor_ts() > ev_cutoff)
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
    #[must_use]
    pub fn is_finalized(&self, tx_hash: TxHash) -> bool {
        self.finalized.is_finalized(tx_hash)
    }

    /// Returns the set of all finalized transaction hashes.
    ///
    /// Used by the node orchestrator to pass to shard consensus for conflict filtering.
    #[must_use]
    pub fn finalized_tx_hashes(&self) -> HashSet<TxHash> {
        self.finalized.all_tx_hashes()
    }

    /// Check if we're waiting for provisioning to complete for a transaction.
    #[must_use]
    pub fn is_awaiting_provisioning(&self, tx_hash: TxHash) -> bool {
        self.waves.is_awaiting_provisioning(tx_hash)
    }

    /// Get debug info about wave state for a transaction.
    #[must_use]
    pub fn certificate_tracking_debug(&self, tx_hash: TxHash) -> String {
        let wave_info = self.waves.wave_assignment(tx_hash).map_or_else(
            || "no wave assignment".to_string(),
            |wave_id| {
                self.waves.get_wave(&wave_id).map_or_else(
                    || {
                        if self.finalized.contains(&wave_id) {
                            format!("wave={wave_id}, finalized")
                        } else {
                            format!("wave={wave_id}, no tracker")
                        }
                    },
                    |wave| {
                        let complete = wave.is_complete();
                        format!("wave={wave_id}, complete={complete}")
                    },
                )
            },
        );

        let early_count = self.early.attestation_count_for_tx(tx_hash);

        format!("{wave_info}, early_wave_attestations={early_count}")
    }

    /// Get execution memory statistics for monitoring collection sizes.
    #[must_use]
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
            outbound_certs: self.outbound_certs.memory_stats().tracked_certificates,
        }
    }

    /// Get the number of cross-shard transactions currently in flight.
    ///
    /// Counts unique transaction hashes in cross-shard waves that haven't yet
    /// finalized. Covers provisioning, voting, and certificate collection
    /// phases uniformly (one `WaveState` tracks all of them).
    #[must_use]
    pub fn cross_shard_pending_count(&self) -> usize {
        self.waves.cross_shard_pending_count()
    }
}

impl std::fmt::Debug for ExecutionCoordinator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecutionCoordinator")
            .field("finalized_wave_certificates", &self.finalized.len())
            .field("waves", &self.waves.waves_len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_test_helpers::{
        certify as test_certify, make_live_block as helpers_make_live_block,
    };
    use hyperscale_types::test_utils::test_transaction;
    use hyperscale_types::{
        Bls12381G1PrivateKey, Bls12381G1PublicKey, BoundedVec, ConsensusReceipt, Epoch,
        ExecutionOutcome, GlobalReceiptHash, Hash, NetworkDefinition, QuorumCertificate,
        SignerBitfield, ValidatorInfo, ValidatorSet, generate_bls_keypair, zero_bls_signature,
    };

    use super::*;

    fn make_test_topology() -> TopologySchedule {
        let keys: Vec<Bls12381G1PrivateKey> = (0..4).map(|_| generate_bls_keypair()).collect();

        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| ValidatorInfo {
                validator_id: ValidatorId::new(i as u64),
                public_key: k.public_key(),
            })
            .collect();
        let validator_set = ValidatorSet::new(validators);

        TopologySchedule::single(Arc::new(TopologySnapshot::new(
            NetworkDefinition::simulator(),
            1,
            validator_set,
        )))
    }

    fn make_test_state() -> ExecutionCoordinator {
        make_test_state_for(ValidatorId::new(0))
    }

    fn make_test_state_for(me: ValidatorId) -> ExecutionCoordinator {
        ExecutionCoordinator::new(me, ShardId::ROOT)
    }

    fn make_test_state_for_shard(me: ValidatorId, local_shard: ShardId) -> ExecutionCoordinator {
        ExecutionCoordinator::new(me, local_shard)
    }

    fn make_live_block(
        height: BlockHeight,
        timestamp_ms: u64,
        proposer: ValidatorId,
        transactions: Vec<Arc<RoutableTransaction>>,
    ) -> Block {
        helpers_make_live_block(
            ShardId::ROOT,
            height,
            timestamp_ms,
            proposer,
            transactions,
            vec![],
        )
    }

    fn make_live_block_on_shard(
        shard: ShardId,
        height: BlockHeight,
        timestamp_ms: u64,
        proposer: ValidatorId,
        transactions: Vec<Arc<RoutableTransaction>>,
    ) -> Block {
        helpers_make_live_block(shard, height, timestamp_ms, proposer, transactions, vec![])
    }

    fn certify(block: Block) -> CertifiedBlock {
        test_certify(block, 0)
    }

    #[test]
    fn test_single_shard_execution_flow() {
        let mut state = make_test_state();
        let topology = make_test_topology();

        let tx = test_transaction(1);
        let tx_hash = tx.hash();
        let block = make_live_block(
            BlockHeight::new(1),
            1000,
            ValidatorId::new(0),
            vec![Arc::new(tx)],
        );

        // Block committed with transaction
        let actions = state.on_block_committed(&topology, &certify(block));

        // Should request execution (single-shard path) and set up wave tracking
        assert!(!actions.is_empty());
        // First action should be ExecuteTransactions
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::ExecuteTransactions { .. }))
        );

        // WaveState should be set up for this wave.
        let wave_id = state.waves.wave_assignment(tx_hash);
        assert!(wave_id.is_some());
        assert!(state.waves.contains_wave(&wave_id.unwrap()));
    }

    fn make_topology() -> TopologySchedule {
        let keys: Vec<Bls12381G1PrivateKey> = (0..4).map(|_| generate_bls_keypair()).collect();
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| ValidatorInfo {
                validator_id: ValidatorId::new(i as u64),
                public_key: k.public_key(),
            })
            .collect();
        let validator_set = ValidatorSet::new(validators);
        TopologySchedule::single(Arc::new(TopologySnapshot::new(
            NetworkDefinition::simulator(),
            1,
            validator_set,
        )))
    }

    #[test]
    fn test_only_leader_gets_vote_tracker() {
        let tx = test_transaction(1);

        // Determine who the wave leader will be for this block's wave.
        let topo0 = make_topology();
        let committee = topo0.head().committee_for_shard(ShardId::ROOT).to_vec();
        let block = make_live_block(
            BlockHeight::new(1),
            1000,
            ValidatorId::new(0),
            vec![Arc::new(tx.clone())],
        );

        // Commit the block as validator 0 to discover the wave_id.
        let mut state0 = make_test_state();
        state0.on_block_committed(&topo0, &certify(block));
        let wave_id = state0
            .waves
            .waves_iter()
            .next()
            .map(|(wid, _)| wid.clone())
            .unwrap();

        let leader = wave_leader(&wave_id, &committee);

        // Leader should have a VoteTracker.
        let topo_leader = make_topology();
        let block_leader = make_live_block(
            BlockHeight::new(1),
            1000,
            ValidatorId::new(0),
            vec![Arc::new(tx.clone())],
        );
        let mut state_leader = make_test_state_for(leader);
        state_leader.on_block_committed(&topo_leader, &certify(block_leader));
        assert!(
            state_leader.waves.contains_tracker(&wave_id),
            "Leader should have VoteTracker"
        );

        // A non-leader should NOT have a VoteTracker.
        let non_leader_id = *committee.iter().find(|&&v| v != leader).unwrap();
        let topo_non = make_topology();
        let block_non = make_live_block(
            BlockHeight::new(1),
            1000,
            ValidatorId::new(0),
            vec![Arc::new(tx)],
        );
        let mut state_non = make_test_state_for(non_leader_id);
        state_non.on_block_committed(&topo_non, &certify(block_non));
        assert!(
            !state_non.waves.contains_tracker(&wave_id),
            "Non-leader should NOT have VoteTracker"
        );
    }

    #[test]
    fn test_fallback_tracker_created_on_vote() {
        let tx = test_transaction(1);
        let topo = make_topology();
        let committee = topo.head().committee_for_shard(ShardId::ROOT).to_vec();
        let block = make_live_block(
            BlockHeight::new(1),
            1000,
            ValidatorId::new(0),
            vec![Arc::new(tx.clone())],
        );
        let block_hash = block.hash();

        let mut state = make_test_state();
        state.on_block_committed(&topo, &certify(block));

        let wave_id = state
            .waves
            .waves_iter()
            .next()
            .map(|(wid, _)| wid.clone())
            .unwrap();
        let leader = wave_leader(&wave_id, &committee);

        // If we're the leader, this test doesn't apply — find a non-leader topology.
        let non_leader_id = committee.iter().find(|&&v| v != leader).unwrap();
        let topo_non = make_topology();
        let block_non = make_live_block(
            BlockHeight::new(1),
            1000,
            ValidatorId::new(0),
            vec![Arc::new(tx)],
        );
        let mut state_non = make_test_state_for(*non_leader_id);
        state_non.on_block_committed(&topo_non, &certify(block_non));

        assert!(!state_non.waves.contains_tracker(&wave_id));
        assert!(state_non.waves.contains_wave(&wave_id));

        // Simulate receiving a vote (as if we're a fallback leader).
        let fake_vote = ExecutionVote::new(
            block_hash,
            BlockHeight::new(1),
            WeightedTimestamp::ZERO,
            wave_id.clone(),
            ShardId::ROOT,
            GlobalReceiptRoot::ZERO,
            1,
            vec![],
            leader,
            zero_bls_signature(),
        );

        state_non.on_unverified_execution_vote(&topo_non, fake_vote);

        // Should have created a fallback VoteTracker.
        assert!(
            state_non.waves.contains_tracker(&wave_id),
            "Fallback VoteTracker should be created"
        );
    }

    #[test]
    fn on_execution_vote_drops_non_committee_voter() {
        // Vote claiming to be from a validator outside the local shard
        // committee must be rejected at the top of on_execution_vote, with
        // no early-buffer or tracker side effect. Otherwise the vote could
        // pool its cross-shard power into the tracker and trigger premature
        // aggregation that produces an EC the BLS verifier will reject.
        let topo = make_two_shard_topology();
        let local = topo.head().committee_for_shard(ShardId::leaf(1, 0));
        let outsider = (0u64..4)
            .map(ValidatorId::new)
            .find(|v| !local.contains(v))
            .expect("two-shard topology has at least one non-local validator");

        let mut state = make_test_state_for_shard(ValidatorId::new(0), ShardId::leaf(1, 0));
        let wave_id = WaveId::new(ShardId::leaf(1, 0), BlockHeight::new(1), BTreeSet::new());
        let vote = ExecutionVote::new(
            BlockHash::ZERO,
            BlockHeight::new(1),
            WeightedTimestamp::ZERO,
            wave_id.clone(),
            ShardId::leaf(1, 0),
            GlobalReceiptRoot::ZERO,
            0,
            vec![],
            outsider,
            zero_bls_signature(),
        );

        let actions = state.on_unverified_execution_vote(&topo, vote);
        assert!(actions.is_empty(), "non-committee vote must be dropped");
        assert!(
            !state.waves.contains_tracker(&wave_id),
            "rejected vote must not seed a fallback VoteTracker"
        );
        assert_eq!(
            state.memory_stats().pending_routing,
            0,
            "rejected vote must not be early-buffered"
        );
    }

    #[test]
    fn test_vote_retry_timeout_emits_rotated_action() {
        use crate::waves::VOTE_RETRY_TIMEOUT;
        let wave_id = WaveId::new(ShardId::ROOT, BlockHeight::new(1), BTreeSet::new());
        let topo = make_test_topology();
        let committee = topo.head().committee_for_shard(ShardId::ROOT).to_vec();

        let mut state = make_test_state();
        state.committed_height = BlockHeight::new(20);
        // "Now" timestamp exactly VOTE_RETRY_TIMEOUT past the original send.
        state.committed_ts = WeightedTimestamp::from_millis(10_000).plus(VOTE_RETRY_TIMEOUT);

        // Manually insert a pending retry as if we'd sent a vote at t=10_000ms.
        state.waves.record_vote_retry(
            wave_id.clone(),
            PendingVoteRetry {
                sent_at: WeightedTimestamp::from_millis(10_000),
                attempt: Attempt::INITIAL,
                block_hash: BlockHash::from_raw(Hash::from_bytes(b"block1")),
                block_height: BlockHeight::new(1),
                vote_anchor_ts: WeightedTimestamp::ZERO,
                global_receipt_root: GlobalReceiptRoot::ZERO,
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
                let expected_leader = wave_leader_at(&wave_id, Attempt::new(1), &committee);
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
        state.committed_ts = state.committed_ts.plus(VOTE_RETRY_TIMEOUT);
        let next = state.check_vote_retry_timeouts(&topo);
        assert_eq!(next.len(), 1);
        if let Action::SignAndSendExecutionVote { leader, .. } = &next[0] {
            let expected = wave_leader_at(&wave_id, Attempt::new(2), &committee);
            assert_eq!(*leader, expected, "second fire rotates to attempt 2");
        } else {
            panic!("expected SignAndSendExecutionVote");
        }
    }

    #[test]
    fn test_vote_retry_cancelled_on_ec_receipt() {
        use crate::waves::VOTE_RETRY_TIMEOUT;
        let wave_id = WaveId::new(ShardId::ROOT, BlockHeight::new(1), BTreeSet::new());
        let topo = make_test_topology();

        let mut state = make_test_state();
        state.committed_height = BlockHeight::new(10);
        state.waves.record_vote_retry(
            wave_id.clone(),
            PendingVoteRetry {
                sent_at: WeightedTimestamp::from_millis(5_000),
                attempt: Attempt::INITIAL,
                block_hash: BlockHash::from_raw(Hash::from_bytes(b"block1")),
                block_height: BlockHeight::new(1),
                vote_anchor_ts: WeightedTimestamp::ZERO,
                global_receipt_root: GlobalReceiptRoot::ZERO,
                tx_outcomes: Arc::new(vec![]),
            },
        );

        // Simulate receiving a verified local shard EC with quorum signers.
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        let cert = ExecutionCertificate::new(
            wave_id,
            WeightedTimestamp::ZERO,
            GlobalReceiptRoot::ZERO,
            vec![],
            zero_bls_signature(),
            signers,
        );
        state.on_certificate_verified(&topo, Ok(Arc::new(Verified::new_unchecked_for_test(cert))));

        // Advance time past the retry deadline; if the retry had survived,
        // this would fire a SignAndSendExecutionVote action.
        state.committed_ts = WeightedTimestamp::from_millis(5_000).plus(VOTE_RETRY_TIMEOUT);
        let actions = state.check_vote_retry_timeouts(&topo);
        assert!(
            actions.is_empty(),
            "EC receipt must cancel the retry so no action fires"
        );
    }

    #[test]
    fn on_certificate_verified_rejects_subquorum_ec() {
        // A single Byzantine signer can produce a BLS-valid EC. Without a
        // quorum-power gate, that sub-quorum EC would clear the expected-
        // cert tombstone, populate the local-shard fallback-serving cache,
        // and feed wave attestation. The rejection now also emits an
        // `AbandonFetch::ExecutionCerts` so any pinned EC fetch on this
        // wave_id releases its FSM slot.
        let topo = make_test_topology();
        let mut state = make_test_state();
        state.committed_height = BlockHeight::new(10);

        let wave_id = WaveId::new(ShardId::ROOT, BlockHeight::new(1), BTreeSet::new());

        let mut signers = SignerBitfield::new(4);
        signers.set(0); // single signer — well below 2f+1 = 3
        let cert = Arc::new(ExecutionCertificate::new(
            wave_id.clone(),
            WeightedTimestamp::ZERO,
            GlobalReceiptRoot::ZERO,
            vec![],
            zero_bls_signature(),
            signers,
        ));

        let verified = Arc::new(Verified::new_unchecked_for_test((*cert).clone()));
        let actions = state.on_certificate_verified(&topo, Ok(verified));
        assert!(
            !actions.iter().any(|a| matches!(
                a,
                Action::Continuation(ProtocolEvent::ExecutionCertificateAdmitted { .. })
            )),
            "sub-quorum EC must produce no admission continuation"
        );
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::AbandonFetch(FetchAbandon::ExecutionCerts { ids }) if ids == &vec![wave_id.clone()]
            )),
            "sub-quorum drop must emit AbandonFetch::ExecutionCerts, got: {actions:?}"
        );
        assert!(
            state.exec_certs.get(&wave_id).is_none(),
            "sub-quorum EC must not enter the local-shard serving cache"
        );
    }

    #[test]
    fn on_certificate_verified_invalid_sig_abandons_fetch() {
        // BLS signature verification returns `valid=false`. The cert is
        // dropped without admission, and the FSM is told to release the
        // in-flight slot.
        let topo = make_test_topology();
        let mut state = make_test_state();

        let wave_id = WaveId::new(ShardId::ROOT, BlockHeight::new(1), BTreeSet::new());
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        let cert = Arc::new(ExecutionCertificate::new(
            wave_id.clone(),
            WeightedTimestamp::ZERO,
            GlobalReceiptRoot::ZERO,
            vec![],
            zero_bls_signature(),
            signers,
        ));

        let actions = state.on_certificate_verified(
            &topo,
            Err((
                cert,
                ExecutionCertificateVerifyError::BadAggregatedSignature,
            )),
        );
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::AbandonFetch(FetchAbandon::ExecutionCerts { ids }) if ids == &vec![wave_id.clone()]
            )),
            "invalid-sig drop must emit AbandonFetch::ExecutionCerts, got: {actions:?}"
        );
        assert!(
            !actions.iter().any(|a| matches!(
                a,
                Action::Continuation(ProtocolEvent::ExecutionCertificateAdmitted { .. })
            )),
            "invalid-sig must not emit admission continuation"
        );
    }

    // Note: the committee-keys-fail branch of `on_wave_certificate` is
    // structurally covered (emits the abandon when
    // `committee_public_keys_for_shard` returns `None`) but is not
    // exercised by a unit test here — `None` only fires when a known
    // committee member is missing a public key in the topology, a
    // corruption condition the public test fixtures can't easily
    // construct. Realistic failures (unknown shard with empty committee)
    // dispatch with an empty key set and fall through to the invalid-sig
    // branch, which is covered above.

    #[test]
    fn test_leader_broadcasts_ec_locally() {
        let wave_id = WaveId::new(
            ShardId::ROOT,
            BlockHeight::new(1),
            std::iter::once(ShardId::leaf(1, 1)).collect(),
        );
        let topo = make_test_topology();

        let mut state = make_test_state();

        let cert = ExecutionCertificate::new(
            wave_id.clone(),
            WeightedTimestamp::ZERO,
            GlobalReceiptRoot::ZERO,
            vec![],
            zero_bls_signature(),
            SignerBitfield::new(4),
        );

        let actions = state.on_certificate_aggregated(
            &topo,
            &wave_id,
            &Arc::new(Verified::new_unchecked_for_test(cert)),
        );

        // Should have: BroadcastEC(local) + BroadcastEC(remote shard 1)
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
            Action::BroadcastExecutionCertificate { shard, .. } => *shard == ShardId::ROOT,
            _ => false,
        });
        assert!(has_local, "Should include local shard broadcast");

        // One should be for the remote shard (shard 1).
        let has_remote = broadcast_actions.iter().any(|a| match a {
            Action::BroadcastExecutionCertificate { shard, .. } => *shard == ShardId::leaf(1, 1),
            _ => false,
        });
        assert!(has_remote, "Should include remote shard broadcast");
    }

    /// `admit_finalized_wave` must NOT emit `FinalizedWavesAdmitted`
    /// inline — that would mean BLS verification ran on the state-machine
    /// thread, bringing back the pre-async stall on the consensus path.
    /// The expected output is a single `VerifyFinalizedWave` action; the
    /// admission continuation only fires once the verify event lands.
    #[test]
    fn admit_finalized_wave_dispatches_async_verify() {
        let topo = make_test_topology();
        let mut state = make_test_state();

        let wave_id = WaveId::new(ShardId::ROOT, BlockHeight::new(1), BTreeSet::new());
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        let ec = Arc::new(ExecutionCertificate::new(
            wave_id.clone(),
            WeightedTimestamp::ZERO,
            GlobalReceiptRoot::ZERO,
            vec![],
            zero_bls_signature(),
            signers,
        ));
        let wave: Arc<Verifiable<FinalizedWave>> = Arc::new(
            FinalizedWave::new(Arc::new(WaveCertificate::new(wave_id, vec![ec])), vec![]).into(),
        );

        let actions = state.admit_finalized_wave(&topo, wave);
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], Action::VerifyFinalizedWave { .. }));
        assert!(
            !actions.iter().any(|a| matches!(
                a,
                Action::Continuation(ProtocolEvent::FinalizedWavesAdmitted { .. })
            )),
            "admission continuation must only fire after async verify"
        );
    }

    /// `on_finalized_wave_verified` with `valid = false` must drop the wave
    /// rather than emit the admission continuation — that's exactly the
    /// poisoning vector this gate exists to close. The dropped wave also
    /// surfaces a `FetchAbandon::FinalizedWaves` so any pinned fetch
    /// FSM entry releases its slot.
    #[test]
    fn on_finalized_wave_verified_drops_invalid() {
        let mut state = make_test_state();
        let wave_id = WaveId::new(ShardId::ROOT, BlockHeight::new(1), BTreeSet::new());
        let ec = Arc::new(ExecutionCertificate::new(
            wave_id.clone(),
            WeightedTimestamp::ZERO,
            GlobalReceiptRoot::ZERO,
            vec![],
            zero_bls_signature(),
            SignerBitfield::new(4),
        ));
        let wave = Arc::new(FinalizedWave::new(
            Arc::new(WaveCertificate::new(wave_id.clone(), vec![ec])),
            vec![],
        ));
        let actions = state.on_finalized_wave_verified(Err((
            wave,
            FinalizedWaveVerifyError::ExecutionCertificate {
                index: 0,
                source: ExecutionCertificateVerifyError::BadAggregatedSignature,
            },
        )));
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::AbandonFetch(FetchAbandon::FinalizedWaves { ids }) if ids == &vec![wave_id.clone()]
            )),
            "BLS-invalid drop must emit AbandonFetch::FinalizedWaves, got: {actions:?}"
        );
        assert!(
            !actions.iter().any(|a| matches!(
                a,
                Action::Continuation(ProtocolEvent::FinalizedWavesAdmitted { .. })
            )),
            "must not emit admission continuation on invalid"
        );
    }

    /// `admit_finalized_wave` with an EC lacking quorum power must emit
    /// the abandon (so the FSM doesn't pin) AND must clear the in-flight
    /// dedup set so future arrivals can retry — without that the same
    /// `WaveId` would silently fail every subsequent admission.
    #[test]
    fn admit_finalized_wave_quorum_power_fail_abandons_and_clears_dedup() {
        let topo = make_test_topology();
        let mut state = make_test_state();

        let wave_id = WaveId::new(ShardId::ROOT, BlockHeight::new(1), BTreeSet::new());
        // Only one signer in a 4-validator committee — sub-quorum
        // (2f+1=3 needed).
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        let ec = Arc::new(ExecutionCertificate::new(
            wave_id.clone(),
            WeightedTimestamp::ZERO,
            GlobalReceiptRoot::ZERO,
            vec![],
            zero_bls_signature(),
            signers,
        ));
        let wave: Arc<Verifiable<FinalizedWave>> = Arc::new(
            FinalizedWave::new(
                Arc::new(WaveCertificate::new(wave_id.clone(), vec![ec])),
                vec![],
            )
            .into(),
        );

        let actions = state.admit_finalized_wave(&topo, Arc::clone(&wave));
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::AbandonFetch(FetchAbandon::FinalizedWaves { ids }) if ids == &vec![wave_id.clone()]
            )),
            "quorum-power drop must emit AbandonFetch::FinalizedWaves, got: {actions:?}"
        );

        // Regression: dedup set must NOT retain this wave so a fresh
        // arrival of the same id (e.g., a peer retransmitting after
        // gossiping a corrected wave) is allowed to dispatch.
        let retry_actions = state.admit_finalized_wave(&topo, wave);
        assert!(
            retry_actions
                .iter()
                .any(|a| matches!(a, Action::AbandonFetch(FetchAbandon::FinalizedWaves { .. }))),
            "retry must still reach the quorum gate, got: {retry_actions:?}"
        );
    }

    /// `admit_finalized_wave` with an unresolvable committee shard must
    /// emit the abandon AND clear the dedup set, same shape as the
    /// quorum-power path.
    #[test]
    fn admit_finalized_wave_unknown_committee_abandons_and_clears_dedup() {
        let topo = make_test_topology();
        let mut state = make_test_state();

        // EC for a shard the test topology doesn't know about — the
        // committee-keys lookup returns `None` and triggers the gate.
        let wave_id = WaveId::new(ShardId::ROOT, BlockHeight::new(1), BTreeSet::new());
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        let ec = Arc::new(ExecutionCertificate::new(
            WaveId::new(ShardId::leaf(8, 99), BlockHeight::new(1), BTreeSet::new()),
            WeightedTimestamp::ZERO,
            GlobalReceiptRoot::ZERO,
            vec![],
            zero_bls_signature(),
            signers,
        ));
        let wave: Arc<Verifiable<FinalizedWave>> = Arc::new(
            FinalizedWave::new(
                Arc::new(WaveCertificate::new(wave_id.clone(), vec![ec])),
                vec![],
            )
            .into(),
        );

        let actions = state.admit_finalized_wave(&topo, Arc::clone(&wave));
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::AbandonFetch(FetchAbandon::FinalizedWaves { ids }) if ids == &vec![wave_id.clone()]
            )),
            "unknown-committee drop must emit AbandonFetch::FinalizedWaves, got: {actions:?}"
        );

        // Regression: dedup set clear lets retries through.
        let retry_actions = state.admit_finalized_wave(&topo, wave);
        assert!(
            retry_actions
                .iter()
                .any(|a| matches!(a, Action::AbandonFetch(FetchAbandon::FinalizedWaves { .. }))),
            "retry must still reach the committee-keys gate, got: {retry_actions:?}"
        );
    }

    /// `on_finalized_wave_verified` with `valid = true` emits exactly the
    /// admission continuation — same shape as the prior synchronous path.
    #[test]
    fn on_finalized_wave_verified_admits_valid() {
        let mut state = make_test_state();
        let wave_id = WaveId::new(ShardId::ROOT, BlockHeight::new(1), BTreeSet::new());
        let ec = Arc::new(ExecutionCertificate::new(
            wave_id.clone(),
            WeightedTimestamp::ZERO,
            GlobalReceiptRoot::ZERO,
            vec![],
            zero_bls_signature(),
            SignerBitfield::new(4),
        ));
        let wave = Arc::new(Verified::new_unchecked_for_test(FinalizedWave::new(
            Arc::new(WaveCertificate::new(wave_id, vec![ec])),
            vec![],
        )));
        let actions = state.on_finalized_wave_verified(Ok(wave));
        assert_eq!(actions.len(), 1);
        assert!(matches!(
            actions[0],
            Action::Continuation(ProtocolEvent::FinalizedWavesAdmitted { .. })
        ));
    }

    /// Two byte-identical EC arrivals while the first is still in flight
    /// must produce only one `VerifyExecutionCertificateSignature`
    /// dispatch. This shields the BLS pool from a flooding peer.
    #[test]
    fn on_wave_certificate_dedups_byte_identical_retransmit() {
        let topo = make_test_topology();
        let mut state = make_test_state();

        let wave_id = WaveId::new(ShardId::ROOT, BlockHeight::new(1), BTreeSet::new());
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        let cert = ExecutionCertificate::new(
            wave_id,
            WeightedTimestamp::ZERO,
            GlobalReceiptRoot::ZERO,
            vec![],
            zero_bls_signature(),
            signers,
        );

        let first = state.on_wave_certificate(&topo, cert.clone().into());
        assert_eq!(first.len(), 1);
        assert!(matches!(
            first[0],
            Action::VerifyExecutionCertificateSignature { .. }
        ));

        // Same bytes mid-flight — must drop without dispatching another
        // verify.
        let second = state.on_wave_certificate(&topo, cert.into());
        assert!(second.is_empty());
    }

    /// Once verification completes (success or failure), the in-flight
    /// slot is released and a subsequent retransmit is allowed to
    /// re-dispatch.
    #[test]
    fn on_wave_certificate_releases_slot_after_verification() {
        let topo = make_test_topology();
        let mut state = make_test_state();

        let wave_id = WaveId::new(ShardId::ROOT, BlockHeight::new(1), BTreeSet::new());
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        let cert = ExecutionCertificate::new(
            wave_id,
            WeightedTimestamp::ZERO,
            GlobalReceiptRoot::ZERO,
            vec![],
            zero_bls_signature(),
            signers,
        );

        let _ = state.on_wave_certificate(&topo, cert.clone().into());
        // Simulate the BLS pool returning an invalid result. The slot is
        // released so a follow-up arrival can re-dispatch.
        let _ = state.on_certificate_verified(
            &topo,
            Err((
                Arc::new(cert.clone()),
                ExecutionCertificateVerifyError::BadAggregatedSignature,
            )),
        );
        let again = state.on_wave_certificate(&topo, cert.into());
        assert_eq!(again.len(), 1);
        assert!(matches!(
            again[0],
            Action::VerifyExecutionCertificateSignature { .. }
        ));
    }

    /// An EC already in `exec_certs` (placed there by a co-hosted vnode's
    /// aggregation, or by an earlier verification of the same wire bytes)
    /// short-circuits the BLS dispatch on a wire-hash match.
    #[test]
    fn on_wave_certificate_skips_dispatch_on_cached_wire_hash_match() {
        let topo = make_test_topology();
        let mut state = make_test_state();

        let wave_id = WaveId::new(ShardId::ROOT, BlockHeight::new(1), BTreeSet::new());
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        let cert = ExecutionCertificate::new(
            wave_id,
            WeightedTimestamp::ZERO,
            GlobalReceiptRoot::ZERO,
            vec![],
            zero_bls_signature(),
            signers,
        );
        state
            .exec_certs
            .insert(Arc::new(Verified::new_unchecked_for_test(cert.clone())));

        let actions = state.on_wave_certificate(&topo, cert.into());
        assert!(
            actions.is_empty(),
            "cached wire-hash match must short-circuit"
        );
    }

    /// A different aggregation of the same logical EC (same `WaveId` but
    /// distinct signers / signature, hence distinct wire bytes) is not
    /// short-circuited by an earlier cache entry — it still needs its own
    /// BLS check.
    #[test]
    fn on_wave_certificate_falls_through_on_cached_wave_id_with_wire_hash_mismatch() {
        let topo = make_test_topology();
        let mut state = make_test_state();

        let wave_id = WaveId::new(ShardId::ROOT, BlockHeight::new(1), BTreeSet::new());
        let mut signers_a = SignerBitfield::new(4);
        signers_a.set(0);
        signers_a.set(1);
        signers_a.set(2);
        let mut signers_b = SignerBitfield::new(4);
        signers_b.set(1);
        signers_b.set(2);
        signers_b.set(3);

        let cached = ExecutionCertificate::new(
            wave_id.clone(),
            WeightedTimestamp::ZERO,
            GlobalReceiptRoot::ZERO,
            vec![],
            zero_bls_signature(),
            signers_a,
        );
        let incoming = ExecutionCertificate::new(
            wave_id,
            WeightedTimestamp::ZERO,
            GlobalReceiptRoot::ZERO,
            vec![],
            zero_bls_signature(),
            signers_b,
        );
        assert_ne!(cached.wire_hash(), incoming.wire_hash());
        state
            .exec_certs
            .insert(Arc::new(Verified::new_unchecked_for_test(cached)));

        let actions = state.on_wave_certificate(&topo, incoming.into());
        assert_eq!(actions.len(), 1);
        assert!(matches!(
            actions[0],
            Action::VerifyExecutionCertificateSignature { .. }
        ));
    }

    /// `admit_finalized_wave` dedups a second arrival for the same
    /// `WaveId` while verification is still in flight.
    #[test]
    fn admit_finalized_wave_dedups_in_flight_arrival() {
        let topo = make_test_topology();
        let mut state = make_test_state();

        let wave_id = WaveId::new(ShardId::ROOT, BlockHeight::new(1), BTreeSet::new());
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        let ec = Arc::new(ExecutionCertificate::new(
            wave_id.clone(),
            WeightedTimestamp::ZERO,
            GlobalReceiptRoot::ZERO,
            vec![],
            zero_bls_signature(),
            signers,
        ));
        let wave: Arc<Verifiable<FinalizedWave>> = Arc::new(
            FinalizedWave::new(Arc::new(WaveCertificate::new(wave_id, vec![ec])), vec![]).into(),
        );

        let first = state.admit_finalized_wave(&topo, Arc::clone(&wave));
        assert_eq!(first.len(), 1);
        assert!(matches!(first[0], Action::VerifyFinalizedWave { .. }));

        let second = state.admit_finalized_wave(&topo, wave);
        assert!(second.is_empty());
    }

    /// A `FinalizedWave` already in the canonical store short-circuits
    /// before any BLS dispatch.
    #[test]
    fn admit_finalized_wave_skips_when_already_finalized() {
        let topo = make_test_topology();
        let mut state = make_test_state();

        let wave_id = WaveId::new(ShardId::ROOT, BlockHeight::new(1), BTreeSet::new());
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        let ec = Arc::new(ExecutionCertificate::new(
            wave_id.clone(),
            WeightedTimestamp::ZERO,
            GlobalReceiptRoot::ZERO,
            vec![],
            zero_bls_signature(),
            signers,
        ));
        let raw_wave = FinalizedWave::new(
            Arc::new(WaveCertificate::new(wave_id.clone(), vec![ec])),
            vec![],
        );
        let verifiable_wave = Arc::new(Verified::new_unchecked_for_test(raw_wave.clone()).into());
        // Seed the canonical store directly (mirrors what `finalize_wave`
        // does on the local-aggregation path).
        state.finalized.insert(wave_id, verifiable_wave);

        let actions = state.admit_finalized_wave(&topo, Arc::new(Verifiable::from(raw_wave)));
        assert!(actions.is_empty());
    }

    /// A `FinalizedWave` delivered by `admit_finalized_wave` (the fetch
    /// entry point) must reject any wave whose contained ECs lack quorum
    /// power or signature validity. Otherwise a peer answering
    /// `finalized_wave.request` can poison the `io_loop` serving cache
    /// (via the `Continuation(FinalizedWavesAdmitted)` interception) and
    /// we re-serve the bogus wave to other peers.
    #[test]
    fn test_admit_finalized_wave_rejects_subquorum_ec() {
        let topo = make_two_shard_topology();
        let mut state = make_test_state_for_shard(ValidatorId::new(0), ShardId::leaf(1, 0));

        let wave_id = WaveId::new(ShardId::leaf(1, 0), BlockHeight::new(1), BTreeSet::new());
        let bogus_ec = Arc::new(ExecutionCertificate::new(
            wave_id.clone(),
            WeightedTimestamp::from_millis(1_000_000),
            GlobalReceiptRoot::ZERO,
            vec![],
            zero_bls_signature(),
            SignerBitfield::empty(), // no signers — far below 2f+1
        ));
        let wave: Arc<Verifiable<FinalizedWave>> = Arc::new(
            FinalizedWave::new(
                Arc::new(WaveCertificate::new(wave_id.clone(), vec![bogus_ec])),
                vec![],
            )
            .into(),
        );

        let actions = state.admit_finalized_wave(&topo, wave);
        // No admission continuation — the poisoning vector this gate
        // exists to close. The rejection now emits a `FetchAbandon` so
        // any pinned fetch FSM entry releases its slot.
        assert!(
            !actions.iter().any(|a| matches!(
                a,
                Action::Continuation(ProtocolEvent::FinalizedWavesAdmitted { .. })
            )),
            "sub-quorum FinalizedWave must produce no admission Continuation"
        );
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::AbandonFetch(FetchAbandon::FinalizedWaves { ids }) if ids == &vec![wave_id.clone()]
            )),
            "sub-quorum drop must emit AbandonFetch::FinalizedWaves, got: {actions:?}"
        );
    }

    /// Receipt of a cross-shard EC must NOT mark its expectation
    /// fulfilled until the BLS signature has been verified. Otherwise a
    /// Byzantine peer can ship a forged EC, the tombstone is set with
    /// `vote_anchor_ts + RETENTION_HORIZON` (peer-controlled), legitimate
    /// fallback fetches are suppressed, and the verify pool's silent
    /// rejection leaves us stranded.
    #[test]
    fn test_on_wave_certificate_does_not_mark_fulfilled_before_verification() {
        let topo = make_two_shard_topology();
        let mut state = make_test_state_for_shard(ValidatorId::new(0), ShardId::leaf(1, 0));

        let remote_shard = ShardId::leaf(1, 1);
        let wave_id = WaveId::new(
            remote_shard,
            BlockHeight::new(5),
            std::iter::once(ShardId::leaf(1, 0)).collect(),
        );
        state.on_verified_remote_header(
            remote_shard,
            BlockHeight::new(5),
            std::slice::from_ref(&wave_id),
        );
        assert_eq!(state.expected_certs.expected_len(), 1);
        assert_eq!(state.expected_certs.fulfilled_len(), 0);

        let cert = ExecutionCertificate::new(
            wave_id.clone(),
            WeightedTimestamp::from_millis(1_000_000),
            GlobalReceiptRoot::ZERO,
            vec![],
            zero_bls_signature(),
            SignerBitfield::new(4),
        );
        let _ = state.on_wave_certificate(&topo, cert.clone().into());
        assert_eq!(
            state.expected_certs.expected_len(),
            1,
            "expectation must remain pending until verification completes"
        );
        assert_eq!(
            state.expected_certs.fulfilled_len(),
            0,
            "no tombstone must be created from an unverified EC"
        );

        // Verification fails — the EC was a forgery. State is unchanged;
        // the legitimate cert can still arrive and clear the expectation.
        let _ = state.on_certificate_verified(
            &topo,
            Err((
                Arc::new(cert),
                ExecutionCertificateVerifyError::BadAggregatedSignature,
            )),
        );
        assert_eq!(state.expected_certs.expected_len(), 1);
        assert_eq!(state.expected_certs.fulfilled_len(), 0);
    }

    /// A received cross-shard EC must always dispatch BLS verification
    /// before any wave state sees it — including when no local wave tracks
    /// any tx in the cert. Without that, a Byzantine remote could buffer
    /// forged `tx_outcomes` that the replay path later trusts at commit
    /// time.
    #[test]
    fn test_on_wave_certificate_always_dispatches_verification_even_without_tracker() {
        let topo = make_two_shard_topology();
        let mut state = make_test_state_for_shard(ValidatorId::new(0), ShardId::leaf(1, 0));

        let remote_shard = ShardId::leaf(1, 1);
        let wave_id = WaveId::new(
            remote_shard,
            BlockHeight::new(5),
            std::iter::once(ShardId::leaf(1, 0)).collect(),
        );
        // No local waves / trackers have been created for this tx.
        let cert = ExecutionCertificate::new(
            wave_id,
            WeightedTimestamp::ZERO,
            GlobalReceiptRoot::ZERO,
            vec![TxOutcome::new(
                TxHash::from_raw(Hash::from_bytes(b"untracked_tx")),
                ExecutionOutcome::Aborted,
            )],
            zero_bls_signature(),
            SignerBitfield::new(4),
        );

        let actions = state.on_wave_certificate(&topo, cert.into());
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
    fn make_two_shard_topology() -> TopologySchedule {
        let keys: Vec<Bls12381G1PrivateKey> = (0..4).map(|_| generate_bls_keypair()).collect();
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| ValidatorInfo {
                validator_id: ValidatorId::new(i as u64),
                public_key: k.public_key(),
            })
            .collect();
        TopologySchedule::single(Arc::new(TopologySnapshot::new(
            NetworkDefinition::simulator(),
            2,
            ValidatorSet::new(validators),
        )))
    }

    /// A uniform-power committee over `ids`, one shard, plus its public keys in
    /// committee order (what `committee_public_keys_for_shard` returns).
    fn committee_snapshot(ids: &[u64]) -> (TopologySnapshot, Vec<Bls12381G1PublicKey>) {
        let validators: Vec<ValidatorInfo> = ids
            .iter()
            .map(|&id| {
                let k = generate_bls_keypair();
                ValidatorInfo {
                    validator_id: ValidatorId::new(id),
                    public_key: k.public_key(),
                }
            })
            .collect();
        let pubkeys = validators.iter().map(|v| v.public_key).collect();
        let snapshot = TopologySnapshot::new(
            NetworkDefinition::simulator(),
            1,
            ValidatorSet::new(validators),
        );
        (snapshot, pubkeys)
    }

    /// Committee A governs epoch 0 (the routing head); committee B, with
    /// disjoint signing keys, governs epoch 1. A remote EC whose
    /// `vote_anchor_ts` lands in epoch 1 must dispatch BLS verification against
    /// B's keys — the committee seated at the EC's anchor — not the head.
    #[test]
    fn remote_ec_verification_resolves_committee_at_its_vote_anchor() {
        const ED: u64 = 1_000;
        let shard = ShardId::ROOT;

        let (snap_a, keys_a) = committee_snapshot(&[0, 1, 2, 3]);
        let (snap_b, keys_b) = committee_snapshot(&[4, 5, 6, 7]);
        assert_ne!(keys_a, keys_b, "committees must have distinct keys");

        let mut schedule = TopologySchedule::new(ED, Epoch::new(0), Arc::new(snap_a));
        schedule.insert(Epoch::new(1), Arc::new(snap_b));

        let mut coord = make_test_state();
        let cert = ExecutionCertificate::new(
            WaveId::new(shard, BlockHeight::new(1), BTreeSet::new()),
            WeightedTimestamp::from_millis(ED), // epoch 1
            GlobalReceiptRoot::ZERO,
            vec![],
            zero_bls_signature(),
            SignerBitfield::new(4),
        );

        let actions = coord.on_wave_certificate(&schedule, Verifiable::from(cert));
        let public_keys = actions
            .iter()
            .find_map(|a| match a {
                Action::VerifyExecutionCertificateSignature { public_keys, .. } => {
                    Some(public_keys)
                }
                _ => None,
            })
            .expect("on_wave_certificate dispatches a signature verification");
        assert_eq!(
            *public_keys, keys_b,
            "remote EC must verify against the committee at its vote_anchor_ts, not the head",
        );
    }

    /// The leader-side counterpart to the test above: when a local vote quorum
    /// forms, `check_vote_quorum` packs the committee at the wave's
    /// `vote_anchor_ts` into the EC. That committee positions the signer
    /// bitfield every verifier later resolves, so it must be the epoch-1
    /// committee (the wave is anchored there), not the head.
    #[test]
    fn local_aggregation_packs_committee_at_vote_anchor() {
        const ED: u64 = 1_000;
        let shard = ShardId::ROOT;

        let (snap_a, _keys_a) = committee_snapshot(&[0, 1, 2, 3]);
        let (snap_b, _keys_b) = committee_snapshot(&[4, 5, 6, 7]);
        let committee_b: Vec<ValidatorId> = snap_b.committee_for_shard(shard).to_vec();
        let mut schedule = TopologySchedule::new(ED, Epoch::new(0), Arc::new(snap_a));
        schedule.insert(Epoch::new(1), Arc::new(snap_b));

        // Local node is a committee-B member; commit a single-shard wave anchored
        // in epoch 1 (block weighted timestamp = ED, so vote_anchor_ts = ED).
        let mut coord = make_test_state_for(ValidatorId::new(4));
        let block = make_live_block(
            BlockHeight::new(1),
            ED,
            ValidatorId::new(4),
            vec![Arc::new(test_transaction(1))],
        );
        let block_hash = block.hash();
        coord.on_block_committed(&schedule, &test_certify(block, ED));
        let wave_id = coord
            .waves
            .waves_iter()
            .next()
            .map(|(w, _)| w.clone())
            .expect("single-shard wave created on commit");

        // Feed a 2f+1 quorum of verified votes from committee B, all sharing the
        // wave's anchor and receipt root so they land in one quorum bucket.
        let mut actions = Vec::new();
        for v in [4u64, 5, 6] {
            let vote = ExecutionVote::new(
                block_hash,
                BlockHeight::new(1),
                WeightedTimestamp::from_millis(ED),
                wave_id.clone(),
                shard,
                GlobalReceiptRoot::ZERO,
                1,
                vec![],
                ValidatorId::new(v),
                zero_bls_signature(),
            );
            actions.extend(
                coord.on_verified_execution_vote(&schedule, Verified::new_unchecked_for_test(vote)),
            );
        }

        let committee = actions
            .iter()
            .find_map(|a| match a {
                Action::AggregateExecutionCertificate { committee, .. } => Some(committee),
                _ => None,
            })
            .expect("vote quorum dispatches certificate aggregation");
        assert_eq!(
            *committee, committee_b,
            "the EC's bitfield committee must be the one at vote_anchor_ts (epoch 1), not the head",
        );
    }

    #[test]
    fn cross_shard_ec_buffers_when_beacon_behind_then_drains_on_catch_up() {
        const ED: u64 = 1_000;
        let shard = ShardId::ROOT;

        // Schedule head is epoch 0; an EC anchored in epoch 5 is ahead of this
        // node's beacon and can't resolve yet.
        let behind = TopologySchedule::new(
            ED,
            Epoch::new(0),
            Arc::new(committee_snapshot(&[0, 1, 2, 3]).0),
        );
        let mut coord = make_test_state();
        let cert = ExecutionCertificate::new(
            WaveId::new(shard, BlockHeight::new(1), BTreeSet::new()),
            WeightedTimestamp::from_millis(5 * ED), // epoch 5, past the head
            GlobalReceiptRoot::ZERO,
            vec![],
            zero_bls_signature(),
            SignerBitfield::new(4),
        );

        let actions = coord.on_wave_certificate(&behind, Verifiable::from(cert));
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::VerifyExecutionCertificateSignature { .. })),
            "an EC whose epoch the beacon hasn't reached must buffer, not dispatch",
        );

        let caught_up = TopologySchedule::single(Arc::new(committee_snapshot(&[0, 1, 2, 3]).0));
        let drained = coord.on_beacon_block_persisted(&caught_up);
        assert!(
            drained
                .iter()
                .any(|a| matches!(a, Action::VerifyExecutionCertificateSignature { .. })),
            "draining on catch-up must dispatch the buffered EC's verification",
        );
    }

    #[test]
    fn finalized_wave_buffers_when_beacon_behind_then_drains_on_catch_up() {
        const ED: u64 = 1_000;
        let shard = ShardId::ROOT;

        let behind = TopologySchedule::new(
            ED,
            Epoch::new(0),
            Arc::new(committee_snapshot(&[0, 1, 2, 3]).0),
        );
        let mut coord = make_test_state();

        let wave_id = WaveId::new(shard, BlockHeight::new(1), BTreeSet::new());
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        let ec = Arc::new(ExecutionCertificate::new(
            wave_id.clone(),
            WeightedTimestamp::from_millis(5 * ED), // epoch 5, past the head
            GlobalReceiptRoot::ZERO,
            vec![],
            zero_bls_signature(),
            signers,
        ));
        let wave: Arc<Verifiable<FinalizedWave>> = Arc::new(
            FinalizedWave::new(Arc::new(WaveCertificate::new(wave_id, vec![ec])), vec![]).into(),
        );

        let actions = coord.admit_finalized_wave(&behind, Arc::clone(&wave));
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::VerifyFinalizedWave { .. })),
            "a finalized wave whose EC epoch the beacon hasn't reached must buffer, not dispatch",
        );

        let caught_up = TopologySchedule::single(Arc::new(committee_snapshot(&[0, 1, 2, 3]).0));
        let drained = coord.on_beacon_block_persisted(&caught_up);
        assert!(
            drained
                .iter()
                .any(|a| matches!(a, Action::VerifyFinalizedWave { .. })),
            "draining on catch-up must dispatch the buffered wave's verification",
        );
    }

    /// Expected-cert entries must be retained while any local `WaveState`
    /// still lists their source shard as a participating remote — otherwise
    /// a cross-shard wave whose remote EC missed the broadcast window would
    /// be stranded once the expectation aged out, with no fallback fetch
    /// continuing to fire.
    #[test]
    fn test_expected_exec_cert_retained_while_tracker_pending() {
        use std::collections::BTreeSet;

        use hyperscale_types::test_utils::test_transaction;

        let _topo = make_two_shard_topology();
        let mut state = make_test_state_for_shard(ValidatorId::new(0), ShardId::leaf(1, 0));

        let remote_shard = ShardId::leaf(1, 1);
        let remote_wave = WaveId::new(
            remote_shard,
            BlockHeight::new(5),
            std::iter::once(ShardId::leaf(1, 0)).collect(),
        );
        state.on_verified_remote_header(
            remote_shard,
            BlockHeight::new(5),
            std::slice::from_ref(&remote_wave),
        );
        assert_eq!(
            state.expected_certs.expected_len(),
            1,
            "expectation should register for wave targeting local shard"
        );

        // Simulate an outstanding local cross-shard wave needing shard 1's EC.
        let local_wave = WaveId::new(
            ShardId::leaf(1, 0),
            BlockHeight::new(10),
            std::iter::once(remote_shard).collect(),
        );
        let tx = Arc::new(test_transaction(7));
        let tx_hash = tx.hash();
        let mut participating = BTreeSet::new();
        participating.insert(ShardId::leaf(1, 0));
        participating.insert(remote_shard);
        state.waves.insert_wave(
            local_wave.clone(),
            WaveState::new(
                local_wave.clone(),
                BlockHash::from_raw(Hash::from_bytes(b"block")),
                WeightedTimestamp::from_millis(5_000),
                vec![(Arc::new(Verifiable::from((*tx).clone())), participating)],
                false,
            ),
        );
        state.waves.assign_tx(tx_hash, local_wave.clone());

        // Advance committed time past fallback + retry thresholds so the
        // age-based gate would fire. The expectation must survive regardless
        // because a local wave still needs shard 1's EC.
        state.committed_height = BlockHeight::new(500);
        state.committed_ts = WeightedTimestamp::from_millis(60_000);
        let actions = state.check_exec_cert_timeouts();

        assert_eq!(
            state.expected_certs.expected_len(),
            1,
            "expectation must survive age pruning while a local wave still needs shard 1"
        );
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::Fetch(FetchRequest::ExecutionCerts { .. }))),
            "fallback fetch must keep firing while the expectation is retained"
        );

        // Once the local wave resolves (simulating finalize_wave), the
        // expectation is no longer needed and gets pruned.
        state.waves.remove_wave(&local_wave);
        state.waves.remove_assignment(tx_hash);
        state.committed_height = BlockHeight::new(600);
        state.committed_ts = WeightedTimestamp::from_millis(120_000);
        let _ = state.check_exec_cert_timeouts();
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
        let wave_id = WaveId::new(ShardId::ROOT, BlockHeight::new(1), BTreeSet::new());
        let txs: Vec<(Arc<Verifiable<RoutableTransaction>>, BTreeSet<ShardId>)> = tx_seeds
            .iter()
            .map(|s| {
                let mut participating = BTreeSet::new();
                participating.insert(ShardId::ROOT);
                (
                    Arc::new(Verifiable::from(test_transaction(*s))),
                    participating,
                )
            })
            .collect();
        let mut wave = WaveState::new(
            wave_id.clone(),
            BlockHash::from_raw(Hash::from_bytes(b"block")),
            WeightedTimestamp::from_millis(1_000),
            txs,
            true,
        );

        // Record per-tx execution results + receipts.
        let tx_hashes: Vec<TxHash> = wave.tx_hashes().to_vec();
        let tx_outcomes: Vec<TxOutcome> = tx_hashes
            .iter()
            .map(|h| {
                TxOutcome::new(
                    *h,
                    ExecutionOutcome::Succeeded {
                        receipt_hash: GlobalReceiptHash::ZERO,
                    },
                )
            })
            .collect();
        for h in &tx_hashes {
            wave.record_execution_result(
                *h,
                ExecutionOutcome::Succeeded {
                    receipt_hash: GlobalReceiptHash::ZERO,
                },
            );
            wave.record_receipt(StoredReceipt {
                tx_hash: *h,
                consensus: Arc::new(ConsensusReceipt::Succeeded {
                    receipt_hash: GlobalReceiptHash::ZERO,
                    #[allow(clippy::default_trait_access)]
                    database_updates: Default::default(),
                    owned_nodes: BoundedVec::new(),
                    application_events: vec![],
                    beacon_witness_events: Vec::new(),
                }),
                metadata: None,
            });
        }

        // Add the local EC; same wave_id flips `local_ec_emitted` to true.
        let local_ec = Arc::new(Verified::new_unchecked_for_test(ExecutionCertificate::new(
            wave_id.clone(),
            WeightedTimestamp::from_millis(1_000),
            GlobalReceiptRoot::from_raw(Hash::from_bytes(b"global_receipt_root")),
            tx_outcomes,
            zero_bls_signature(),
            SignerBitfield::new(4),
        )));
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
    fn test_finalize_wave_emits_admission_event() {
        let mut state = make_test_state();
        let (wave_id, wave) = make_ready_single_shard_wave(&[1, 2]);
        state.waves.insert_wave(wave_id.clone(), wave);

        let actions = state.finalize_wave(&wave_id);

        assert_eq!(actions.len(), 1);
        assert!(matches!(
            actions[0],
            Action::Continuation(ProtocolEvent::FinalizedWavesAdmitted { .. })
        ));
    }

    #[test]
    fn test_finalize_wave_is_noop_for_absent_wave_id() {
        let mut state = make_test_state();
        let unknown = WaveId::new(ShardId::ROOT, BlockHeight::new(99), BTreeSet::new());
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
            .record_required(tx_hash, std::iter::once(ShardId::leaf(1, 1)).collect());
        // Drive finalize_wave to populate the FinalizedWaveStore naturally.
        let _ = state.finalize_wave(&wave_id);
        let finalized = state
            .finalized
            .get(&wave_id)
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
    // while committed_ts is still ZERO. Without retro-stamp, the first
    // commit triggers a fallback-fetch storm because elapsed_since(ZERO)
    // dwarfs the fallback timeout.
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_first_commit_retro_stamps_expected_certs_and_suppresses_fallback() {
        let topo = make_two_shard_topology();
        let mut state = make_test_state_for_shard(ValidatorId::new(0), ShardId::leaf(1, 0));

        // Pre-first-commit: register an expectation. discovered_at is ZERO.
        let remote_shard = ShardId::leaf(1, 1);
        let remote_wave = WaveId::new(
            remote_shard,
            BlockHeight::new(5),
            std::iter::once(ShardId::leaf(1, 0)).collect(),
        );
        state.on_verified_remote_header(
            remote_shard,
            BlockHeight::new(5),
            std::slice::from_ref(&remote_wave),
        );
        // Also seed a local wave that needs shard 1's EC, so the retention
        // check in `check_exec_cert_timeouts` keeps the expectation alive.
        let local_wave = WaveId::new(
            ShardId::leaf(1, 0),
            BlockHeight::new(10),
            std::iter::once(remote_shard).collect(),
        );
        let tx = Arc::new(test_transaction(1));
        let mut participating = BTreeSet::new();
        participating.insert(ShardId::leaf(1, 0));
        participating.insert(remote_shard);
        state.waves.insert_wave(
            local_wave.clone(),
            WaveState::new(
                local_wave,
                BlockHash::from_raw(Hash::from_bytes(b"block")),
                WeightedTimestamp::from_millis(0),
                vec![(Arc::new(Verifiable::from((*tx).clone())), participating)],
                false,
            ),
        );

        // Commit the first block with a QC weighted_timestamp that, without
        // retro-stamping, would imply an elapsed_since of ~billions of ms.
        let block = make_live_block_on_shard(
            ShardId::leaf(1, 0),
            BlockHeight::new(1),
            30_000,
            ValidatorId::new(0),
            vec![],
        );
        let (block, qc) = certify(block).into_parts();
        let qc = QuorumCertificate::new(
            qc.block_hash(),
            qc.shard_id(),
            qc.height(),
            qc.parent_block_hash(),
            qc.round(),
            qc.signers().clone(),
            qc.aggregated_signature(),
            WeightedTimestamp::from_millis(30_000),
        );
        let certified = CertifiedBlock::new_unchecked(block, qc);

        let actions = state.on_block_committed(&topo, &certified);

        let fallback_fired = actions
            .iter()
            .any(|a| matches!(a, Action::Fetch(FetchRequest::ExecutionCerts { .. })));
        assert!(
            !fallback_fired,
            "retro-stamp must suppress the first-commit fallback storm"
        );
    }
}
