//! Shard consensus state machine (HotStuff-2).
//!
//! This module implements the shard consensus state machine
//! as a synchronous, event-driven model.
//!
//! # Data Availability Guarantee
//!
//! Validators only vote for blocks after receiving ALL transaction and certificate
//! data. This is enforced in [`ShardCoordinator::on_block_header`] which checks `is_complete()`
//! before voting. Incomplete blocks wait for data via gossip or fetch.
//!
//! This provides a strong DA guarantee: if a QC forms, at least 2f+1 validators have
//! the complete block data, making it recoverable from any honest validator in that set.

use hyperscale_core::{Action, CommitSource, ProtocolEvent, TimerId};
use hyperscale_types::{
    BlockHash, Hash, InFlightCount, LocalTimestamp, MAX_FINALIZED_TX_PER_BLOCK, MAX_PROGRESS_WAIT,
    MAX_READY_SIGNALS_PER_BLOCK, MAX_TXS_PER_BLOCK, ProposerTimestamp, ProvisionHash, QuiesceCut,
    RETENTION_HORIZON, ReadySignal, ReshapeThresholds, ReshapeTrigger, ScheduleLookup,
    SettledSetVerdict, SettledWaveSet, ShardId, SplitAtBoundary, StoredReceipt, WaveId,
    WeightedTimestamp, derive_reshape_trigger, ready_signal_window, settled_set_verdict,
};

/// Shard consensus statistics for monitoring.
#[derive(Clone, Copy, Debug, Default)]
pub struct ShardStats {
    /// Total number of view changes (round advances due to local
    /// leader-activity timeout — i.e. *we* timed out).
    pub view_changes: u64,
    /// Total number of view syncs (rounds we jumped to because a header /
    /// vote / QC arrived carrying a higher round). Distinct from
    /// `view_changes` — a follower whose `view_changes` stays at zero can
    /// still see its `view` climb to thousands while peers churn. Watch
    /// both to see cluster-wide view-change activity.
    pub view_syncs: u64,
    /// Round within the current height; resets to 0 on commit, increments on view change.
    pub current_round: u64,
    /// Highest height committed to local storage.
    pub committed_height: BlockHeight,
}

/// Shard consensus memory statistics for monitoring collection sizes.
#[derive(Clone, Copy, Debug, Default)]
pub struct ShardMemoryStats {
    /// Pending blocks awaiting transaction / wave / provision arrival.
    pub pending_blocks: usize,
    /// Per-block vote sets aggregating received votes.
    pub vote_sets: usize,
    /// Commits queued out-of-order (parent not yet committed).
    pub pending_commits: usize,
    /// Commits whose block data hasn't fully arrived yet.
    pub pending_commits_awaiting_data: usize,
    /// Equivocation-detection records keyed by `(height, validator)`.
    pub received_votes_by_height: usize,
    /// Committed tx-hash → `end_timestamp_exclusive` entries used for fast
    /// dedup lookup.
    pub committed_tx_lookup: usize,
    /// Committed wave-id → deadline entries for proposal/validation dedup.
    /// Keyed by `vote_anchor_ts + RETENTION_HORIZON`.
    pub committed_cert_lookup: usize,
    /// Committed provision-hash → deadline entries for proposal/validation
    /// dedup. Keyed by `local_committed_ts + RETENTION_HORIZON`.
    pub committed_provision_lookup: usize,
    /// Block headers whose parent QC signature is still being verified.
    pub pending_qc_verifications: usize,
    /// QC-signature verification cache (block hash → height).
    pub verified_qcs: usize,
    /// State-root verifications in flight or deferred awaiting parent.
    pub pending_state_root_verifications: usize,
    /// Synced blocks buffered out-of-order during catch-up sync.
    pub buffered_synced_blocks: usize,
    /// Synced blocks pending QC-signature verification before apply.
    pub pending_synced_block_verifications: usize,
    /// Composite assemblies awaiting QC + per-root sub-results.
    pub pending_assemblies: usize,
}

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use hyperscale_storage::RecoveredState;
use hyperscale_types::{
    BeaconWitnessCommit, BeaconWitnessLeafCount, BeaconWitnessRoot, BeaconWitnessRootVerifyError,
    Block, BlockHeader, BlockHeight, BlockManifest, BlockVote, CertRootVerifyError,
    CertificateRoot, CertifiedBlock, CertifiedBlockHeader, ChainOrigin, FinalizedWave,
    LocalReceiptRoot, LocalReceiptRootVerifyError, MAX_ROUND_GAP, ProvisionRootVerifyError,
    ProvisionTxRootsMap, ProvisionTxRootsVerifyError, Provisions, ProvisionsRoot, QcContext,
    QcVerifyError, QuorumCertificate, Round, RoutableTransaction, SafeVoteRegisters, StateRoot,
    StateRootVerifyError, Timeout, TopologySchedule, TopologySnapshot, TransactionRoot, TxHash,
    TxRootVerifyError, ValidatorId, Verifiable, Verified, Verify, VoteCount, derive_leaves,
    missed_proposals_since_prev_commit, ready_leaf_payload, vrf_output_from_proof,
};
use tracing::field::Empty;
use tracing::{debug, info, instrument, trace, warn};

use crate::beacon_witnesses::{BeaconWitnessAccumulator, prospective_parent_witness_leaves};
use crate::block_sync::{
    BlockSyncHealthDecision, BlockSyncManager, BlockSyncVerificationResult, IngestOutcome,
};
use crate::chain_view::ChainView;
use crate::commit_dedup::CommitDedupIndex;
use crate::commit_pipeline::CommitPipeline;
use crate::config::ShardConsensusConfig;
use crate::deferred_qc::DeferredQc;
use crate::lookups::{committee_public_keys, vote_recipients};
use crate::pending::{OrphanedFetches, PendingBlock, PendingBlocks};
use crate::proposal::{
    ProposalKind, ProposalTracker, TakeResult, assemble_build_action, dispatch_or_defer,
    select_finalized_waves, select_provisions, select_transactions,
};
use crate::ready_signal_pool::{MIN_READY_SIGNAL_DWELL, ReadySignalPool};
use crate::timeout_keeper::TimeoutKeeper;
use crate::validation::{
    qc_has_local_quorum_power, qc_weighted_timestamp_too_far_ahead, validate_block_for_vote,
    validate_header,
};
use crate::verification::{
    InFlightCheck, ReadyStateRootVerification, SubstateCountBlocked, SubstateCountSource,
    VerificationKind, VerificationPipeline,
};
use crate::view_change::ViewChangeController;
use crate::vote_keeper::VoteKeeper;

/// Floor on the `round - parent_qc.round` gap for which a header is verified
/// speculatively. The beacon-witness verification derives one leaf per skipped
/// round, so this bounds that work per header during normal operation, when
/// the local view sits within a handful of rounds of `locked_round`. The
/// effective bound is `max(SPECULATIVE_VERIFY_GAP, view - locked_round)` (see
/// `try_vote_on_block`): any safe-votable block has `round == view` and
/// `parent_qc.round >= locked_round`, so the second term keeps every round the
/// pacemaker can actually reach votable — after a long certification stall the
/// recovery block's gap equals the rounds the local pacemaker itself burned
/// through verified 2f+1 quorums, and refusing to verify it would wedge the
/// shard permanently (every timed-out round is vote-burned, so the votable
/// window must slide with the view). Both terms of the bound advance only via
/// verified progress, so a Byzantine proposer cannot inflate them; per-header
/// work beyond the floor is work the protocol mandates at commit anyway (one
/// `MissedProposal` leaf per burned round). Blocks past the bound are admitted
/// but not verified; if one is genuinely committed, this node is behind and
/// recovers it through block-sync.
///
/// Must stay at or above `VIEW_SYNC_GAP`: an unverified header claim may drag
/// the view that far past `high_qc`, and the dragged-to round must remain
/// votable under the floor or a header flood could park the shard at a round
/// where every candidate is gap-skipped.
pub const SPECULATIVE_VERIFY_GAP: u64 = 1024;

/// Cap on distinct pending headers retained per `(height, round)`. An honest
/// proposer signs exactly one block per round, so anything beyond a small
/// allowance is a Byzantine proposer equivocating (or varying the unsigned
/// content roots to mint distinct hashes); the excess is dropped before it is
/// stored or verified.
const MAX_HEADERS_PER_HEIGHT_ROUND: usize = 4;

/// Cap on pending headers retained per height. `validate_header` checks only
/// the parent QC's signer power, not its signature, so a forged full-bitfield
/// `parent_qc` lets a Byzantine proposer plant a header at every round it
/// proposes for a height; this bounds how many are stored at once. On overflow
/// the entry whose round is farthest from the verified `high_qc` is evicted,
/// keeping the rounds nearest verified progress (where the committable block
/// lives) and shedding flood rounds. Generous above honest view-change churn.
const MAX_PENDING_PER_HEIGHT: usize = 64;

/// Refuse to store a header whose height exceeds `committed + this`. A far
/// future header isn't actionable until the chain advances to it, and a node
/// genuinely that far behind catches up via block-sync, not by buffering tip
/// headers it can't yet vote on. Bounds the number of populated height buckets
/// so the per-height cap bounds total pending storage.
const MAX_HEADER_HEIGHT_LOOKAHEAD: u64 = 256;

/// What [`ShardCoordinator::preview_witness_commitment`] resolves for a
/// proposal: the drained ready signals, the reshape assertion, the trimmed
/// parent-window leaves the block's new leaves append onto, and the window
/// base. The beacon-witness root is finalized in the `BuildProposal` handler,
/// which signs the block's randomness reveal (leaf 0) on the dispatch pool and
/// derives the block's leaves over `parent_window`.
struct WitnessCommitmentPreview {
    ready_signals: Vec<ReadySignal>,
    reshape_trigger: Option<ReshapeTrigger>,
    parent_window: Vec<Hash>,
    base: BeaconWitnessLeafCount,
}

/// Shard consensus state machine (HotStuff-2).
///
/// Handles block proposal, voting, QC formation, commitment, and view changes.
/// This is a synchronous implementation of shard consensus.
///
/// # State Machine Flow
///
/// 1. **Proposal Timer** → If proposer, build and broadcast block header
/// 2. **Block Header Received** → Validate, track pending, vote if valid
/// 3. **Block Vote Received** → Collect votes, form QC when quorum reached
/// 4. **QC Formed** → Update chain state, commit if ready (two-chain rule)
/// 5. **View Change Timer** → Initiate view change if no progress
pub struct ShardCoordinator {
    // ═══════════════════════════════════════════════════════════════════════════
    // Chain State
    // ═══════════════════════════════════════════════════════════════════════════
    /// View change liveness state: current round, linear-backoff tracking,
    /// leader-activity timestamps, and the cumulative view-change counter.
    view_change: ViewChangeController,

    /// Latest committed block height.
    committed_height: BlockHeight,

    /// Hash of the latest committed block.
    committed_hash: BlockHash,

    /// BFT-authenticated weighted timestamp of the latest committed block.
    /// "Now" reference for time-based retention in proposal dedup.
    committed_ts: WeightedTimestamp,

    /// Committee anchor of the latest committed block: its parent QC's
    /// weighted timestamp, the value that selects the committee the block
    /// belongs to (`committee(tip) == at(committed_anchor_ts)`). Held as a
    /// scalar because the committed tip is pruned from `pending_blocks`, so
    /// [`Self::committee_anchor`] can still resolve its committee when
    /// verifying the QC of the first block extending it.
    committed_anchor_ts: WeightedTimestamp,

    /// State root from the latest committed block header.
    /// Updated synchronously at commit time (not dependent on async JMT).
    committed_state_root: StateRoot,

    /// Substate-byte frontier: the highest height with a known
    /// committed substate byte total, and that count. Advances at commit
    /// when the committed block's delta is known (the live path —
    /// deltas arrive with build / state-root verification) and
    /// reconciles from storage via `BlockPersisted`, which heals the
    /// sync path where blocks commit QC-trusted with no local
    /// verification delta. Feeds reshape-trigger derivation.
    substate_bytes_frontier: (BlockHeight, u64),

    /// Latest QC (certifies the latest certified block). Verified at
    /// every adoption gate; the typestate makes that invariant local.
    latest_qc: Option<Verified<QuorumCertificate>>,

    /// QC deferred because the block header wasn't in memory when it formed.
    /// Adopted in `on_block_header` when the header arrives.
    deferred_qc: DeferredQc,

    // ═══════════════════════════════════════════════════════════════════════════
    // Pending State
    // ═══════════════════════════════════════════════════════════════════════════
    /// Pending blocks being assembled (hash -> pending block).
    pending_blocks: PendingBlocks,

    /// Net substate delta per uncommitted block. Entries retire into
    /// the byte frontier at commit and are pruned with their blocks.
    pending_bytes_deltas: HashMap<BlockHash, i64>,

    /// Vote accounting: per-block vote sets and received-vote equivocation
    /// tracking. The safe-vote lock itself lives on the coordinator
    /// (`locked_round` / `last_voted_round`).
    votes: VoteKeeper,

    /// Timeout accounting for the pacemaker: per-round verified timeout shares,
    /// reporting the f+1 (Bracha) and 2f+1 (advance) thresholds.
    timeouts: TimeoutKeeper,

    /// The last round we broadcast our own timeout for, so Bracha amplification
    /// emits at most one timeout per round (the timer itself retransmits).
    last_timed_out_round: Option<Round>,

    /// HotStuff-2 safe-vote lock: the highest `parent_qc` round we have ever
    /// voted to extend. We refuse to vote for a block whose `parent_qc` round
    /// is below this — the entire fork-safety mechanism, kept local (no
    /// certificate rides on the block).
    locked_round: Round,

    /// Highest round in which we have cast a vote or broadcast a timeout. One
    /// vote per round, monotone: we never sign two votes, or a vote and a
    /// timeout, in the same round.
    last_voted_round: Round,

    /// Certified blocks awaiting commit, out-of-order commit buffering, and
    /// awaiting-data commit buffering.
    commits: CommitPipeline,

    /// Async verification tracking (QC signatures, commitment proofs, state/tx roots).
    verification: VerificationPipeline,

    /// Sync coordination (block buffering, verification tracking, sync flag).
    block_sync: BlockSyncManager,

    /// In-flight proposal awaiting `Event::ProposalBuilt` callback.
    proposal: ProposalTracker,

    /// Dedup cache for committed transaction and certificate hashes.
    /// Bridges synchronous shard commits to async mempool processing, and
    /// provides a bounded retention window for historical dedup.
    dedup_index: CommitDedupIndex,

    /// Validator "ready on shard" signals waiting for inclusion in the
    /// next proposed block. Drained at proposal time.
    ready_signal_pool: ReadySignalPool,

    /// Per-shard beacon-witness accumulator. Previewed at proposal time
    /// to fill the new block's `(beacon_witness_root, beacon_witness_leaf_count)`;
    /// mutated on each committed block via [`Self::record_block_committed`].
    /// Seeded at startup from
    /// [`RecoveredState::beacon_witness_leaf_hashes`](hyperscale_storage::RecoveredState),
    /// which the storage backend loads from the persisted
    /// `beacon_witnesses` CF.
    beacon_witness_accumulator: BeaconWitnessAccumulator,

    // ═══════════════════════════════════════════════════════════════════════════
    // Configuration
    // ═══════════════════════════════════════════════════════════════════════════
    config: ShardConsensusConfig,

    // ═══════════════════════════════════════════════════════════════════════════
    // Time
    // ═══════════════════════════════════════════════════════════════════════════
    /// Local wall-clock time, set by the runner before each `handle()` call.
    /// Drives view-change timing, IO retry backoff, and the proposer-skew
    /// gate on incoming headers — never used as a deterministic consensus
    /// anchor (use `committed_ts: WeightedTimestamp` for that).
    now: LocalTimestamp,

    /// This validator's identity.
    me: ValidatorId,

    /// This validator's home shard.
    local_shard: ShardId,

    /// The chain's origin — genesis height plus start-time anchor.
    /// `ChainOrigin::ROOT` for chains born at network genesis; a child
    /// chain created by a shard split continues the parent's height line
    /// and clock. Genesis-fallback QCs reconstructed here must byte-match
    /// the chain's real genesis QC.
    chain_origin: ChainOrigin,

    /// Settled-wave sets for shards that have terminated at a split,
    /// keyed by the terminated shard. The split-boundary fence consults
    /// this when voting on a block whose finalized waves carry a
    /// certificate from a past-terminal shard: a cross-shard wave names
    /// that shard, so the vote may only commit if the shard actually
    /// settled the wave. Populated by the settled-waves acquisition via
    /// [`Self::record_settled_waves`].
    settled_sets: HashMap<ShardId, SettledWaveSet>,
}

impl std::fmt::Debug for ShardCoordinator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShardCoordinator")
            .field("view", &self.view_change.view)
            .field("committed_height", &self.committed_height)
            .field("pending_blocks", &self.pending_blocks.len())
            .field("vote_sets", &self.votes.vote_sets_len())
            .finish_non_exhaustive()
    }
}

impl ShardCoordinator {
    /// Create a new shard consensus state machine.
    ///
    /// # Arguments
    ///
    /// * `config` - Shard consensus configuration
    /// * `recovered` - State recovered from storage. Use `RecoveredState::default()` for fresh start.
    #[must_use]
    pub fn new(
        me: ValidatorId,
        local_shard: ShardId,
        config: ShardConsensusConfig,
        recovered: RecoveredState,
    ) -> Self {
        // Rounds increase per block, so the first block we propose sits one
        // round past the highest QC we recovered (the genesis QC's round 0 on
        // a fresh start).
        let high_qc_round = recovered
            .latest_qc
            .as_deref()
            .map_or(Round::INITIAL, QuorumCertificate::round);
        let initial_view = high_qc_round.next();
        // The committed tip's committee was keyed on its parent QC's weighted
        // timestamp, and the live commit path anchors `committed_ts` on that
        // same value; storage recovers it from the tip's stored header. When it
        // didn't (fresh start, or genesis tip), fall back to the tip's own WT —
        // identical except when the recovered tip is an epoch's first block, and
        // exact again after the next commit. Restoring both `committed_ts` and
        // `committed_anchor_ts` from it keeps a restarted node's BFT clock equal
        // to a non-restarted peer's rather than one to two blocks ahead.
        let committed_anchor_ts = recovered.committee_anchor_ts();
        let recovered_registers = recovered
            .safe_vote_registers
            .get(&me)
            .copied()
            .unwrap_or_default();
        Self {
            view_change: ViewChangeController::new(initial_view),
            committed_height: recovered.committed_height,
            committed_hash: recovered.committed_hash.unwrap_or(BlockHash::ZERO),
            committed_ts: committed_anchor_ts,
            committed_anchor_ts,
            committed_state_root: recovered.jmt_root.unwrap_or(StateRoot::ZERO),
            substate_bytes_frontier: (recovered.committed_height, recovered.substate_bytes),
            pending_bytes_deltas: HashMap::new(),
            latest_qc: recovered.latest_qc,
            deferred_qc: DeferredQc::new(),
            pending_blocks: PendingBlocks::new(),
            votes: VoteKeeper::new(),
            timeouts: TimeoutKeeper::new(),
            last_timed_out_round: None,
            // Recover the registers from the durable record (which holds
            // every position this validator signed — persisted before each
            // signature left the process), floored at the high QC's round
            // so the lock can't slip beneath a committed block even when
            // no record survives (fresh store, new chain incarnation).
            locked_round: high_qc_round.max(recovered_registers.locked_round),
            last_voted_round: high_qc_round.max(recovered_registers.last_voted_round),
            commits: CommitPipeline::new(),
            verification: VerificationPipeline::new(
                recovered.committed_height,
                recovered.chain_origin,
            ),
            block_sync: BlockSyncManager::new(),
            proposal: ProposalTracker::new(),
            dedup_index: CommitDedupIndex::new(),
            ready_signal_pool: ReadySignalPool::new(),
            beacon_witness_accumulator: BeaconWitnessAccumulator::from_leaves(
                recovered.beacon_witness_start,
                recovered.beacon_witness_leaf_hashes,
            ),
            config,
            now: LocalTimestamp::ZERO,
            me,
            local_shard,
            chain_origin: recovered.chain_origin,
            settled_sets: HashMap::new(),
        }
    }

    /// QC-attested state root of the latest committed block. Updated
    /// synchronously at commit time and surfaced via the status API as the
    /// canonical current state root.
    #[must_use]
    pub const fn jmt_root(&self) -> StateRoot {
        self.committed_state_root
    }

    /// Borrow-view of the node's knowledge of the chain. Short-lived; see
    /// [`ChainView`] for the lookup API. The coordinator's `local_shard`
    /// tags genesis-fallback QCs produced by [`ChainView::proposal_parent`].
    const fn chain_view(&self) -> ChainView<'_> {
        ChainView::new(
            self.local_shard,
            self.chain_origin,
            self.committed_height,
            self.committed_hash,
            self.committed_state_root,
            self.latest_qc.as_ref(),
            &self.pending_blocks,
            self.verification.verified_certified_blocks(),
        )
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Committee resolution
    // ═══════════════════════════════════════════════════════════════════════════
    //
    // A block's committee is keyed on its parent's weighted timestamp: every
    // honest node resolves `committee(block) == at(committee_anchor(block))`,
    // where `committee_anchor(block) == block.header.parent_qc.weighted_timestamp()`.
    // Keying on the parent (already attested) rather than the block's own
    // not-yet-aggregated weighted timestamp lets proposer, voters, and
    // verifiers agree before the block's votes exist. The committee for the
    // height currently in progress / our next proposal keys on `high_qc`'s
    // weighted timestamp, since that is the tip we extend.

    /// Weighted timestamp selecting `block_hash`'s committee — its parent QC's
    /// weighted timestamp. The committed tip (pruned from pending and the
    /// certified cache alike) uses the `committed_anchor_ts` scalar; every
    /// other block resolves through [`ChainView::get_header`], whose
    /// certified-cache fallback covers an applied-but-uncommitted synced
    /// block — such a tip exists only via block-sync (its header was never
    /// gossiped here), so without it a live proposal extending it would
    /// defer on "parent not held" while every re-fetch of the parent is
    /// deduplicated as already applied. `None` when the block is unknown by
    /// every route, so its committee can't be resolved (caller stalls).
    fn committee_anchor(&self, block_hash: BlockHash) -> Option<WeightedTimestamp> {
        if block_hash == self.committed_hash {
            return Some(self.committed_anchor_ts);
        }
        self.chain_view()
            .get_header(block_hash)
            .map(|header| header.parent_qc().weighted_timestamp())
    }

    /// Weighted timestamp selecting the committee for the height in progress /
    /// our next proposal: we extend `high_qc`, so the committee is
    /// `at(high_qc.weighted_timestamp())`. With no QC yet the chain sits at
    /// its genesis, whose QC carries the chain origin's anchor — `ZERO` for
    /// root chains, the parent's terminal canonical timestamp for a split
    /// child (a `ZERO` fallback would resolve a child's first proposal
    /// against epoch 0).
    fn tip_anchor_ts(&self) -> WeightedTimestamp {
        self.latest_qc
            .as_ref()
            .map_or(self.chain_origin.anchor_wt, |qc| qc.weighted_timestamp())
    }

    /// Committee that signed/produced `block_hash`. `None` to stall: the block
    /// is unknown, or this node's beacon hasn't synced the block's epoch.
    /// Resolution clamps to this shard's terminal window, so the coast
    /// blocks past a split's cut still resolve the committee that signs
    /// them (the shard's final-epoch committee) — and bridges an in-flight
    /// halt recovery, so a block extending the halted tip resolves the
    /// fresh committee (the halted one resolves itself out of authority at
    /// the same fold).
    fn committee_of_block<'t>(
        &self,
        topology_schedule: &'t TopologySchedule,
        block_hash: BlockHash,
    ) -> Option<&'t TopologySnapshot> {
        topology_schedule
            .at_for_shard_live(self.local_shard, self.committee_anchor(block_hash)?)
            .map(|(snapshot, _)| snapshot.as_ref())
    }

    /// Committee that signed `qc` — the certified binding. Unlike
    /// [`Self::committee_of_block`] this resolves with the QC's own
    /// timestamp in hand, so a halt recovery's bridge applies exactly to
    /// blocks certified at or past the bridge window: the halted suffix
    /// keeps verifying against the windows that produced it, while a
    /// recovery bridge block verifies against the fresh committee.
    fn committee_of_qc<'t>(
        &self,
        topology_schedule: &'t TopologySchedule,
        qc: &QuorumCertificate,
    ) -> Option<&'t TopologySnapshot> {
        topology_schedule
            .at_for_shard_certified(
                self.local_shard,
                self.committee_anchor(qc.block_hash())?,
                qc.weighted_timestamp(),
            )
            .map(|(snapshot, _)| snapshot.as_ref())
    }

    /// Committee for the height in progress / our next proposal (extends
    /// `high_qc`). `None` to stall when the beacon lacks that epoch — or
    /// while an in-flight recovery quiesces the chain (see
    /// [`Self::recovery_quiesced`]). Terminal-clamped and recovery-bridged
    /// like [`Self::committee_of_block`], so the final-epoch committee can
    /// still coast the chain to its crossing and a fresh recovery
    /// committee can extend the halted tip.
    fn tip_committee<'t>(
        &self,
        topology_schedule: &'t TopologySchedule,
    ) -> Option<&'t TopologySnapshot> {
        if self.recovery_quiesced(topology_schedule, self.tip_anchor_ts()) {
            return None;
        }
        topology_schedule
            .at_for_shard_live(self.local_shard, self.tip_anchor_ts())
            .map(|(snapshot, _)| snapshot.as_ref())
    }

    /// Whether work anchored at `wt` rides an in-flight halt recovery's
    /// bridge: the anchor predates the window the fresh committee governs
    /// from. Bridge blocks must be empty — the anchored-committee
    /// resolution downstream (execution votes, wave fencing) never sees a
    /// stale-anchored block carry content — mirroring the coast blocks
    /// past a terminal cut.
    fn recovery_bridging(
        &self,
        topology_schedule: &TopologySchedule,
        wt: WeightedTimestamp,
    ) -> bool {
        topology_schedule.recovery_bridging(self.local_shard, wt)
    }

    /// Whether work anchored at `wt` is quiesced by an in-flight recovery:
    /// the fresh committee is seated but its first governed window hasn't
    /// opened on the local clock. Nothing may propose, vote, or time out
    /// across the seating window — a QC aggregated there would carry a
    /// timestamp below the bridge and bake a certificate no verifier can
    /// bind into the chain. Every vote is gated by the same clock that
    /// stamps it, so every QC the fresh committee forms lands at or past
    /// its window.
    fn recovery_quiesced(
        &self,
        topology_schedule: &TopologySchedule,
        wt: WeightedTimestamp,
    ) -> bool {
        let Some(bridge) = topology_schedule.recovery_bridge(self.local_shard) else {
            return false;
        };
        let window_start = topology_schedule.windows().window_of(bridge).start;
        topology_schedule.recovery_bridging(self.local_shard, wt)
            && self.now.as_millis() < window_start.as_millis()
    }

    /// Record a terminated shard's settled-wave set for the
    /// split-boundary fence. A one-shot acquisition fetches the complete
    /// window list and verifies it against the beacon-attested
    /// `settled_waves_root` before feeding it here; voting on a block
    /// whose finalized waves name `shard` then resolves against the set
    /// instead of deferring. Pair with [`Self::redrive_pending_votes`] to
    /// re-drive votes that deferred at the fence before the set was known.
    pub fn record_settled_waves(&mut self, shard: ShardId, settled: SettledWaveSet) {
        self.settled_sets.insert(shard, settled);
    }

    /// Drop settled-wave sets past their retention horizon. Once the
    /// committed chain advances beyond `terminal_wt + RETENTION_HORIZON`,
    /// the fence rejects any wave naming the shard regardless of the set,
    /// so retaining it only leaks memory.
    fn gc_settled_sets(&mut self) {
        let now = self.committed_anchor_ts;
        self.settled_sets
            .retain(|_, settled| now <= settled.terminal_wt.plus(RETENTION_HORIZON));
    }

    /// The settled-wave set this validator has acquired for a terminated
    /// shard, or `None` if it hasn't yet. The acquisition host populates
    /// it; a test or RPC reads it to observe that the acquisition ran.
    #[must_use]
    pub fn settled_set(&self, shard: ShardId) -> Option<&SettledWaveSet> {
        self.settled_sets.get(&shard)
    }

    /// Re-drive the vote path for every pending complete block. Called
    /// after a settled set is recorded ([`Self::record_settled_waves`]):
    /// blocks that deferred at the split-boundary fence for want of that
    /// set can now resolve. `trigger_qc_verification_or_vote` is
    /// idempotent (already-verified / already-voted short-circuit), so
    /// re-driving every pending block is safe.
    pub fn redrive_pending_votes(&mut self, topology_schedule: &TopologySchedule) -> Vec<Action> {
        let pending: Vec<BlockHash> = self
            .pending_blocks
            .values()
            .filter(|p| p.block().is_some())
            .map(|p| p.header().hash())
            .collect();
        let mut actions = Vec::new();
        for block_hash in pending {
            actions.extend(self.trigger_qc_verification_or_vote(topology_schedule, block_hash));
        }
        actions
    }

    /// The split-boundary fence over a block's committed finalized waves.
    ///
    /// A finalized wave's certificate carries one execution certificate
    /// per participating shard. When a constituent certificate names a
    /// shard that is **past-terminal** at the block's anchored window,
    /// the cross-shard wave straddled that shard's split: committing this
    /// block applies the wave's local half, so it may only commit if the
    /// terminated shard actually settled the wave in its own chain by its
    /// terminal block — otherwise one side of a cross-shard transaction
    /// applies without the other.
    ///
    /// Past-terminal-ness is read off the **anchored** snapshot at
    /// `anchored_wt` (the block's `parent_qc` weighted timestamp), never
    /// the head, so every replica voting this block reaches the same
    /// verdict. A shard evicted from every retained window is so far past
    /// its terminal that any wave naming it is unreachable everywhere —
    /// reject. A past-terminal shard whose settled set isn't known yet
    /// defers the vote; past `terminal_wt + RETENTION_HORIZON` the wave
    /// is categorically unreachable and rejects.
    fn fence_finalized_waves(
        &self,
        topology_schedule: &TopologySchedule,
        block: &Block,
        anchored_wt: WeightedTimestamp,
    ) -> SettledSetVerdict {
        let ecs = block.certificates().iter().flat_map(|fw| {
            fw.execution_certificates()
                .iter()
                .map(|ec| (ec.shard_id(), ec.wave_id()))
        });
        settled_set_verdict(
            &self.settled_sets,
            topology_schedule,
            self.local_shard,
            anchored_wt,
            ecs,
        )
    }

    /// Apply the split-boundary fence at vote time; returns `true` (and
    /// logs) when the vote must not proceed. `Reject` declines the vote
    /// outright (the block can never commit here); `Defer` holds the
    /// block pending until the settled set is acquired (the vote
    /// re-drives on [`Self::record_settled_waves`]).
    fn fence_blocks_vote(
        &self,
        topology_schedule: &TopologySchedule,
        block: &Block,
        block_hash: BlockHash,
    ) -> bool {
        match self.fence_finalized_waves(
            topology_schedule,
            block,
            block.header().parent_qc().weighted_timestamp(),
        ) {
            SettledSetVerdict::Pass => false,
            SettledSetVerdict::Reject => {
                warn!(
                    validator = ?self.me,
                    block_hash = ?block_hash,
                    "Finalized wave names a past-terminal shard that didn't settle it — not voting"
                );
                true
            }
            SettledSetVerdict::Defer => {
                trace!(
                    validator = ?self.me,
                    block_hash = ?block_hash,
                    "Settled set for a past-terminal shard unknown at vote; deferring"
                );
                true
            }
        }
    }

    /// Whether `wt` lands past this shard's terminal window — the coast
    /// region after a split's cut. A block whose parent QC carries such a
    /// timestamp must be empty (it exists only to certify the crossing),
    /// and a committed one terminates the chain.
    fn past_terminal_window(
        &self,
        topology_schedule: &TopologySchedule,
        wt: WeightedTimestamp,
    ) -> bool {
        topology_schedule
            .at_for_shard(self.local_shard, wt)
            .is_some_and(|(_, past_terminal)| past_terminal)
    }

    /// Whether this chain has gone **quiescent**: the committed tip's parent QC
    /// sits past the shard's terminal window, i.e. the first coast block has
    /// committed and the crossing's canonical QC is readable from the committed
    /// chain. Content stops here — the terminal block is the last that can
    /// decide a transaction — so the one-shot terminal sweep (aborting in-flight
    /// transactions no later block can ever decide) keys on this flip.
    ///
    /// Quiescence is *not* the end of the chain's life: the committee keeps
    /// coasting, voting, and serving past this point until its reshape
    /// successors are live (see [`Self::dissolved`]). The two coincide today;
    /// they part once the successor-live gate lands.
    #[must_use]
    pub fn quiescent(&self, topology_schedule: &TopologySchedule) -> bool {
        self.past_terminal_window(topology_schedule, self.committed_anchor_ts)
    }

    /// Whether this chain may **dissolve** — stop proposing, ingesting headers,
    /// and running its pacemaker, and let the committee tear down. Narrower than
    /// [`Self::quiescent`]: the chain quiesces its content at the cut, but its
    /// committee keeps coasting (empty blocks), voting, and serving until the
    /// beacon shows its reshape successors **live** — both split children, or a
    /// merge's reformed parent, producing on their own chains. Holding the
    /// committee together through the handoff is what lets the terminal block
    /// commit (so the children can seed from it) instead of being stranded as a
    /// certified-but-uncommitted tail when members drop out at the cut. Once the
    /// successors are live the handoff has demonstrably succeeded, so dropping
    /// out — even a co-located pair in lockstep — loses nothing.
    #[must_use]
    pub fn dissolved(&self, topology_schedule: &TopologySchedule) -> bool {
        self.quiescent(topology_schedule) && topology_schedule.successors_live(self.local_shard)
    }

    /// Whether a header keyed at `wt` carries `split_child_roots` — the
    /// split-pending shard's final-epoch delivery, identical on the
    /// build side (carry) and the vote side (required). `None` when the
    /// window's verdict is locally unresolvable yet
    /// ([`SplitAtBoundary::Unresolved`]); callers defer and retry once
    /// the local beacon catches up.
    fn split_child_roots_bit(
        &self,
        topology_schedule: &TopologySchedule,
        wt: WeightedTimestamp,
    ) -> Option<bool> {
        match topology_schedule.split_at_next_boundary(self.local_shard, wt) {
            SplitAtBoundary::Children(..) => Some(true),
            SplitAtBoundary::No => Some(false),
            SplitAtBoundary::Unresolved => None,
        }
    }

    /// Whether a header keyed at `wt` carries `settled_waves_root` — set on
    /// any terminating boundary header (a split parent's *or* a merge
    /// child's final epoch), identical on the build side (carry) and the
    /// vote side (required). Broader than [`Self::split_child_roots_bit`]: a
    /// merge child terminates without carrying `split_child_roots`. `None`
    /// when the window's verdict is locally unresolvable yet; callers defer
    /// and retry once the local beacon catches up.
    fn settled_waves_root_bit(
        &self,
        topology_schedule: &TopologySchedule,
        wt: WeightedTimestamp,
    ) -> Option<bool> {
        topology_schedule.terminates_at_next_boundary(self.local_shard, wt)
    }

    /// The reshape-boundary quiesce window when this shard sits in its final
    /// epoch before terminating — a split *or* a merge — anchored on the
    /// proposer's tip. `None` in steady state, so the proposer's quiesce
    /// filter is inert away from a reshape boundary. The cut is the end of
    /// the tip's epoch window. An unresolved boundary (the local beacon
    /// hasn't seen the next window yet) yields `None`: the abort backstop
    /// covers any straddler this lets through, so quiescing on a guess buys
    /// nothing.
    #[must_use]
    pub fn quiesce_cut(&self, topology_schedule: &TopologySchedule) -> Option<QuiesceCut> {
        let now_wt = self.tip_anchor_ts();
        (topology_schedule.terminates_at_next_boundary(self.local_shard, now_wt) == Some(true))
            .then(|| {
                let windows = topology_schedule.windows();
                QuiesceCut {
                    now_wt,
                    cut_wt: windows.window_of(windows.epoch_for(now_wt)).end,
                }
            })
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Time Management
    // ═══════════════════════════════════════════════════════════════════════════

    /// Set the current time.
    pub const fn set_time(&mut self, now: LocalTimestamp) {
        self.now = now;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Sync State Management
    // ═══════════════════════════════════════════════════════════════════════════

    /// Set whether this validator is currently syncing.
    ///
    /// When syncing:
    /// - Proposer will create empty "sync blocks" instead of skipping their turn
    /// - View changes are suppressed (we're intentionally behind)
    fn set_block_syncing(&mut self, syncing: bool) {
        if syncing && !self.block_sync.is_syncing() {
            info!(
                validator = ?self.me,
                "Entering sync mode - will propose empty blocks if selected"
            );
        } else if !syncing && self.block_sync.is_syncing() {
            info!(
                validator = ?self.me,
                "Exiting sync mode - resuming normal block production"
            );
            // Reset leader activity timeout since we've caught up
            self.view_change.last_leader_activity = Some(self.now);
        }
        self.block_sync.set_syncing(syncing);
    }

    /// Check if this validator is currently syncing.
    #[must_use]
    pub const fn is_block_syncing(&self) -> bool {
        self.block_sync.is_syncing()
    }

    /// Start syncing to catch up to the network.
    ///
    /// This is the single entry point for initiating sync. It:
    /// 1. Sets the syncing flag immediately (enables sync block proposals, suppresses fetches)
    /// 2. Returns the `StartBlockSync` action for the runner to begin fetching blocks
    ///
    /// Setting the syncing flag immediately (rather than waiting for the first synced block)
    /// ensures that:
    /// - `check_pending_block_fetches()` stops emitting fetch requests that would compete with sync
    /// - Proposers create empty sync blocks instead of full blocks
    /// - The state machine accurately reflects that we're waiting for sync data
    ///
    /// The syncing flag will be cleared when `Event::SyncComplete` arrives.
    fn start_block_sync(&mut self, target_height: BlockHeight) -> Vec<Action> {
        // Don't raise the target while already syncing. The io_loop's
        // BlockSync manages its own target internally. Once the current
        // sync completes and we resume consensus, a new start_sync will
        // fire naturally if we're still behind.
        if self.block_sync.is_syncing() {
            return vec![];
        }

        info!(
            validator = ?self.me,
            target_height = target_height.inner(),
            committed_height = self.committed_height.inner(),
            "Starting sync - setting syncing flag and requesting blocks"
        );

        // Set syncing flag immediately - this:
        // - Enables sync block proposals if we're the proposer
        // - Suppresses fetch requests (check_pending_block_fetches returns empty)
        // - Signals to other code that we're catching up
        self.set_block_syncing(true);
        self.block_sync.set_sync_target(target_height);

        vec![Action::StartBlockSync {
            target: target_height,
        }]
    }

    /// Handle a synced block ready to apply (from runner via
    /// `Event::BlockSyncReadyToApply`). Delegates the dedup/routing
    /// decision to [`BlockSyncManager::ingest`] and translates the outcome into
    /// a submit dispatch or a buffer drain.
    pub fn on_sync_block_ready_to_apply(
        &mut self,
        topology_schedule: &TopologySchedule,
        certified: CertifiedBlock,
    ) -> Vec<Action> {
        match self.block_sync.ingest(certified, self.committed_height) {
            IngestOutcome::Drop => vec![],
            IngestOutcome::Submit(certified) => {
                self.submit_synced_block_for_verification(topology_schedule, *certified)
            }
            IngestOutcome::Buffered => self.try_drain_buffered_synced_blocks(topology_schedule),
        }
    }

    /// Handle sync complete (from runner via `Event::SyncComplete`).
    ///
    /// Re-enables normal block proposals and view changes.
    /// Also triggers fetch requests for any pending blocks that still need data,
    /// since fetching was suppressed during sync.
    ///
    /// `NodeStateMachine` flushes expected remote headers and provisions in
    /// the same `BlockSyncComplete` arm, so this returns only shard-local
    /// resume actions.
    pub fn on_block_sync_complete(&mut self, topology_schedule: &TopologySchedule) -> Vec<Action> {
        info!(
            validator = ?self.me,
            "Sync complete, resuming normal consensus"
        );
        self.set_block_syncing(false);

        // Resume fetching for any pending blocks that still need data.
        // During sync, check_pending_block_fetches() returns empty because we
        // don't want to compete with sync for network resources. Now that sync
        // is done, we need to fetch any missing transactions/certificates.
        // Use force_immediate=true to bypass the age timeout — blocks received
        // during sync shouldn't wait another timeout period to be fetched.
        let mut actions = self.check_pending_block_fetches(true);
        actions.extend(self.maybe_emit_ready_signal(topology_schedule));
        actions
    }

    /// A self-signed `ReadySignal` if the local validator is a committee
    /// member of this shard still outside the consensus subset — placed,
    /// now synced to tip, and waiting on the beacon to flip
    /// `ready: true`. `None` for already-ready members (a routine
    /// catch-up resync stays silent) and for non-members.
    ///
    /// The window opens at the current committed weighted timestamp and
    /// spans [`ready_signal_window`] of the configured epoch; if it passes
    /// uncollected the beacon's ready timeout remains the fallback.
    fn maybe_emit_ready_signal(&self, topology_schedule: &TopologySchedule) -> Option<Action> {
        let head = topology_schedule.head();
        let committee = head.committee_for_shard(self.local_shard);
        if !committee.contains(&self.me)
            || head
                .consensus_committee_for_shard(self.local_shard)
                .contains(&self.me)
        {
            return None;
        }
        let wt_window_start = self.committed_ts;
        let wt_window_end =
            wt_window_start.plus(ready_signal_window(topology_schedule.epoch_duration_ms()));
        let recipients: Vec<ValidatorId> = committee
            .iter()
            .copied()
            .filter(|&v| v != self.me)
            .collect();
        info!(
            validator = ?self.me,
            window_start = wt_window_start.as_millis(),
            window_end = wt_window_end.as_millis(),
            "Synced to tip while not yet ready — broadcasting ReadySignal"
        );
        Some(Action::SignAndBroadcastReadySignal {
            shard: self.local_shard,
            wt_window_start,
            wt_window_end,
            recipients,
        })
    }

    /// Record leader activity (resets the view change timeout).
    ///
    /// Called when we observe leader activity:
    /// - We propose a block
    /// - A QC forms
    /// - A block commits
    /// - We receive a valid header (rate-limited per height/round)
    const fn record_leader_activity(&mut self) {
        self.view_change.record_leader_activity(self.now);
    }

    /// Record leader activity from receiving a block header.
    ///
    /// Rate-limited to once per (height, round) to prevent a Byzantine leader
    /// from spamming headers with different hashes to delay view changes.
    fn record_header_activity(&mut self, height: BlockHeight, round: Round) {
        self.view_change
            .record_header_activity(height, round, self.now);
    }

    /// Linear-backoff view change timeout for the current round.
    #[must_use]
    pub fn current_view_change_timeout(&self) -> Duration {
        self.view_change.current_timeout()
    }

    /// Time remaining until the view change timer should fire.
    #[must_use]
    pub fn remaining_view_change_timeout(&self) -> Duration {
        self.view_change.remaining_timeout(self.now)
    }

    /// Check if we should advance the round due to timeout.
    ///
    /// Returns true if the leader has been inactive for longer than the
    /// current timeout (which increases with each failed round at this height).
    ///
    /// View changes should only happen when the leader fails to propose,
    /// not just because vote aggregation is slow.
    ///
    /// Note: Syncing nodes DO participate in view changes. They receive headers
    /// from the network at the current height/round and need to help advance
    /// the view if the leader fails. When a syncing node becomes the proposer
    /// after a view change, they propose an empty sync block.
    fn should_advance_round(&self) -> bool {
        // Don't view-change while we're actively processing or waiting on
        // the leader's block. The timeout should detect leader *failure*,
        // not slow vote/QC propagation around a healthy proposal.
        //
        // Three suppression sources, all bounded by `MAX_PROGRESS_WAIT`
        // measured from the last leader-activity reset so a Byzantine
        // proposer who only sends a header (and never advances the chain)
        // can't pin us at a stale round forever:
        //
        // 1. Verification in flight — block roots being checked.
        // 2. A pending block exists at the proposal tip — covers both
        //    followers fetching content and proposers awaiting their own
        //    QC after broadcasting. Proposers' pending blocks are fully
        //    assembled at emission time, so this case must include
        //    complete blocks too, not just incomplete ones.
        // 3. Block sync has unverified work in flight.
        let next_height = self.latest_qc.as_ref().map_or_else(
            || self.committed_height.inner() + 1,
            |qc| qc.height().inner() + 1,
        );
        let has_pending_at_tip = self
            .pending_blocks
            .has_any_at(BlockHeight::new(next_height));
        let suppressed = self.verification.has_verification_in_flight()
            || has_pending_at_tip
            || self.block_sync.has_unverified_in_flight();
        if suppressed {
            let within_progress_window = self
                .view_change
                .last_leader_activity
                .is_some_and(|t| self.now.saturating_sub(t) < MAX_PROGRESS_WAIT);
            if within_progress_window {
                return false;
            }
        }

        self.view_change.timeout_elapsed(self.now)
    }

    /// Check for round timeout and advance if needed.
    ///
    /// This should be called before processing the proposal timer.
    /// Returns actions for view change if timeout triggered, or empty vec if not.
    ///
    /// If a view change occurs, the caller should NOT proceed to call
    /// `try_propose` in the same event handling cycle.
    pub fn check_round_timeout(
        &mut self,
        topology_schedule: &TopologySchedule,
    ) -> Option<Vec<Action>> {
        if !self.should_advance_round() {
            return None;
        }

        // Reset the timeout baseline so we don't immediately re-fire; the round
        // advances on a 2f+1 timeout quorum (`advance_on_timeout_quorum`), not
        // on this local timer.
        self.view_change.record_leader_activity(self.now);
        self.view_change.last_header_reset = None;

        let round = self.view_change.view;
        info!(
            validator = ?self.me,
            view = round.inner(),
            timeout_ms = self.current_view_change_timeout().as_millis(),
            "Round timeout — broadcasting timeout (HotStuff-2 pacemaker)"
        );

        // Broadcast our timeout (deduped per round) and keep the timer running
        // so we re-check until the 2f+1 quorum forms.
        let mut actions = self.broadcast_timeout(topology_schedule, round);
        actions.push(Action::SetTimer {
            id: TimerId::ViewChange,
            duration: self.current_view_change_timeout(),
        });
        Some(actions)
    }

    /// Initialize with genesis block (for fresh start).
    pub fn initialize_genesis(&mut self, genesis: &Block) -> Vec<Action> {
        let hash = genesis.hash();

        self.committed_hash = hash;
        self.committed_state_root = genesis.header().state_root();
        // A chain's genesis height and clock are per-chain properties: a
        // split child's genesis continues the parent's height line and
        // anchors at its final canonical weighted timestamp (ZERO and
        // height 0 for chains born at network genesis).
        self.committed_height = genesis.height();
        self.committed_ts = genesis.header().parent_qc().weighted_timestamp();
        self.committed_anchor_ts = self.committed_ts;
        self.substate_bytes_frontier.0 = genesis.height();

        // Record genesis time as initial leader activity so that the view
        // change timeout counts from startup rather than being disabled.
        self.view_change.record_leader_activity(self.now);

        info!(
            validator = ?self.me,
            genesis_hash = ?hash,
            "Initialized genesis block"
        );

        // Set initial timers and trigger first proposal attempt
        self.queue_ready_proposal();
        vec![
            Action::SetTimer {
                id: TimerId::ViewChange,
                duration: self.current_view_change_timeout(),
            },
            Action::SetTimer {
                id: TimerId::Cleanup,
                duration: self.config.cleanup_interval,
            },
        ]
    }

    /// Seed the reshape trigger's substate-byte frontier from the genesis
    /// store count. Genesis lays down the engine bootstrap and any funded
    /// accounts as substates that never appear as a commit delta, so
    /// without this the frontier reads zero until the first delta-bearing
    /// block — and a non-zero reshape threshold would misfire (a quiet
    /// shard below `merge_bytes` spuriously triggers a merge). Called
    /// by the I/O loop after the genesis block commits, with the count it
    /// reads from storage.
    pub const fn seed_substate_bytes_frontier(&mut self, height: BlockHeight, count: u64) {
        self.substate_bytes_frontier = (height, count);
    }

    /// Handle committed state restored from storage (recovery).
    ///
    /// Called when the runner completes `Action::RestoreCommittedState`.
    #[instrument(skip(self, qc), fields(height = height.inner(), has_hash = hash.is_some(), has_qc = qc.is_some()))]
    pub fn on_committed_state_restored(
        &mut self,
        height: BlockHeight,
        hash: Option<BlockHash>,
        qc: Option<Verified<QuorumCertificate>>,
    ) -> Vec<Action> {
        if height == BlockHeight::GENESIS && hash.is_none() {
            // No committed blocks - this is a fresh start
            info!(
                validator = ?self.me,
                "No committed blocks found - fresh start"
            );
            return vec![];
        }

        self.committed_height = height;
        if let Some(h) = hash {
            self.committed_hash = h;
        }
        let has_qc = qc.is_some();
        // Raise the safe-vote lock to the QC's round without ever lowering
        // it: `Self::new` already floored both registers at the max of the
        // durable record — every round this validator signed, persisted
        // before the signature left the process — and the high QC's round.
        // Assigning the QC round here would roll that floor back for a
        // validator whose last vote or timeout outran its highest committed
        // QC, letting it vote twice in one round. `max` keeps the durable
        // floor.
        if let Some(qc_round) = qc.as_deref().map(QuorumCertificate::round) {
            self.locked_round = self.locked_round.max(qc_round);
            self.last_voted_round = self.last_voted_round.max(qc_round);
        }
        self.latest_qc = qc;

        self.view_change.reset_for_height_advance();

        // Clean up any votes for heights at or below the committed height.
        // This handles the case where we loaded votes from storage that are now stale.
        // The recovery sweep runs before any fetches are issued, so any
        // returned abandon would target ids the FSM has never seen — drop it.
        let _ = self.cleanup_old_state(height);

        // Record recovery time as initial leader activity so that the view
        // change timeout counts from startup rather than being disabled.
        self.view_change.last_leader_activity = Some(self.now);

        info!(
            validator = ?self.me,
            committed_height = self.committed_height.inner(),
            committed_hash = ?self.committed_hash,
            has_qc,
            "Recovered chain state from storage"
        );

        // Pending blocks at or below the recovered committed height are pruned
        // by `cleanup_old_state` on the next commit.

        // Set timers to resume consensus and trigger first proposal attempt
        self.queue_ready_proposal();
        vec![
            Action::SetTimer {
                id: TimerId::ViewChange,
                duration: self.current_view_change_timeout(),
            },
            Action::SetTimer {
                id: TimerId::Cleanup,
                duration: self.config.cleanup_interval,
            },
        ]
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Proposer Logic
    // ═══════════════════════════════════════════════════════════════════════════

    /// Try to build and broadcast a new block proposal.
    ///
    /// This is the unified proposal entry point, called from:
    /// - new-content events (transactions, waves, or provisions)
    /// - `on_qc_formed` (eager next-block proposal)
    ///
    /// Returns empty if preconditions aren't met (not proposer, build in-flight,
    /// already voted at this height, etc.). No periodic rescheduling — callers
    /// are responsible for triggering the next attempt via events.
    #[instrument(skip(self, topology_schedule, ready_txs, finalized_waves), fields(
        tx_count = ready_txs.len(),
        cert_count = finalized_waves.len(),
    ))]
    pub fn try_propose(
        &mut self,
        topology_schedule: &TopologySchedule,
        ready_txs: &[Arc<Verified<RoutableTransaction>>],
        finalized_waves: Vec<Arc<Verifiable<FinalizedWave>>>,
        provisions: Vec<Arc<Verifiable<Provisions>>>,
    ) -> Vec<Action> {
        // The next height to propose is one above the highest certified block,
        // not the committed block — this lets the chain grow while the
        // two-chain commit rule is being satisfied.
        let next_height = self
            .latest_qc
            .as_ref()
            .map_or_else(|| self.committed_height.next(), |qc| qc.height().next());
        let round = self.view_change.view;

        if !self.can_propose(topology_schedule, next_height, round) {
            return vec![];
        }

        // Syncing validators propose an empty sync block to keep the chain
        // advancing while catching up on execution state.
        if self.block_sync.is_syncing() {
            return self.build_and_dispatch_proposal(
                topology_schedule,
                next_height,
                round,
                ProposalKind::Sync,
            );
        }

        let (parent_block_hash, parent_qc) = self.chain_view().proposal_parent();

        // Post-fallback recovery: if the parent is a fallback, propose an
        // empty block too. The QC on this block is what commits the parent
        // fallback (HotStuff-2 two-chain rule); if this block carries
        // content that can't be fetched, no QC forms, the fallback never
        // commits, `weighted_timestamp` never advances, and deadline-based
        // pruning of stale provisions/txs never fires — so the next Normal
        // proposer keeps pulling in the same unfetchable items, locking the
        // shard in a view-change storm. An empty block votes trivially,
        // commits the fallback, advances `weighted_timestamp`, and lets the
        // following block carry fresh content. We keep `is_fallback = false`
        // so the rule doesn't recurse: the block after this one resumes
        // Normal proposals against pruned coordinator state.
        let parent_is_fallback = self
            .chain_view()
            .get_header(parent_block_hash)
            .is_some_and(BlockHeader::is_fallback);
        if parent_is_fallback {
            return self.build_and_dispatch_proposal(
                topology_schedule,
                next_height,
                round,
                ProposalKind::Normal {
                    transactions: Vec::new(),
                    finalized_waves: Vec::new(),
                    provisions: Vec::new(),
                    finalized_tx_count: 0,
                },
            );
        }

        // Past the shard's terminal window the chain only coasts: the
        // parent QC's weighted timestamp has crossed the split's cut, so
        // this block exists solely to certify the crossing. It must be
        // empty — state stays frozen at the crossing's root — and the
        // chain stops once the crossing's canonical QC commits. A halt
        // recovery's bridge block is empty under the same discipline: it
        // exists solely to carry the chain's clock across the halt gap, so
        // the anchored-committee resolution downstream never sees a
        // stale-anchored block carry content.
        if self.past_terminal_window(topology_schedule, parent_qc.weighted_timestamp())
            || self.recovery_bridging(topology_schedule, parent_qc.weighted_timestamp())
        {
            return self.build_and_dispatch_proposal(
                topology_schedule,
                next_height,
                round,
                ProposalKind::Normal {
                    transactions: Vec::new(),
                    finalized_waves: Vec::new(),
                    provisions: Vec::new(),
                    finalized_tx_count: 0,
                },
            );
        }

        // Walk the QC chain to find certificates, transactions, and
        // provisions already in pending/certified blocks above committed
        // height — the two-chain commit window leaves them visible and the
        // mempool doesn't clear its ready-set until commit, so we must dedup
        // here to avoid repeating items across consecutive blocks.
        let (qc_chain_cert_hashes, qc_chain_tx_hashes, qc_chain_provision_hashes) =
            self.collect_qc_chain_hashes(parent_block_hash);

        // Anchor validity-window filtering on the parent QC's weighted
        // timestamp — the deterministic clock voters will use to verify
        // this block. The one-block lag (this block's own QC may carry a
        // slightly later timestamp) is bounded by MAX_VALIDITY_RANGE.
        let validity_anchor = parent_qc.weighted_timestamp();
        let transactions = select_transactions(
            ready_txs,
            &qc_chain_tx_hashes,
            &self.dedup_index,
            validity_anchor,
        );
        let (finalized_waves, finalized_tx_count) = select_finalized_waves(
            finalized_waves,
            &qc_chain_cert_hashes,
            &self.dedup_index,
            MAX_FINALIZED_TX_PER_BLOCK,
        );
        let provisions = select_provisions(
            provisions,
            &qc_chain_provision_hashes,
            &self.dedup_index,
            MAX_TXS_PER_BLOCK,
        );

        self.build_and_dispatch_proposal(
            topology_schedule,
            next_height,
            round,
            ProposalKind::Normal {
                transactions,
                finalized_waves,
                provisions,
                finalized_tx_count: u32::try_from(finalized_tx_count).unwrap_or(u32::MAX),
            },
        )
    }

    /// Pre-build gate: we must be the proposer for this round, must not have
    /// voted at it yet, and must not already be building (or parked on the
    /// verification pipeline for) the same height/round.
    fn can_propose(
        &self,
        topology_schedule: &TopologySchedule,
        next_height: BlockHeight,
        round: Round,
    ) -> bool {
        // A terminated chain proposes nothing — the crossing is committed
        // and the post-split children carry on from it.
        if self.dissolved(topology_schedule) {
            return false;
        }

        // We extend `high_qc`, so the proposer is drawn from that committee.
        // Without it (beacon behind) we can't know whether we're the proposer
        // — stall rather than guess.
        let Some(committee) = self.tip_committee(topology_schedule) else {
            return false;
        };
        if committee.proposer_for(self.local_shard, round) != self.me {
            return false;
        }

        // Safe-vote rule, proposer side: `on_proposal_built` self-votes the
        // block, so building again at a round we already voted in would sign
        // a second vote at one round — and `proposal_parent()` is unchanged
        // until a QC forms, so that second block would be a sibling of the
        // first. A QC or timeout always advances the view past
        // `last_voted_round`, so the legitimate next proposal passes.
        if round <= self.last_voted_round {
            trace!(
                validator = ?self.me,
                height = next_height.inner(),
                round = round.inner(),
                last_voted_round = self.last_voted_round.inner(),
                "Already voted at this round, skipping proposal"
            );
            return false;
        }

        if let Some(pending) = self.proposal.pending()
            && pending.height == next_height
            && pending.round == round
        {
            trace!(
                validator = ?self.me,
                height = next_height.inner(),
                round = round.inner(),
                "Proposal build already in-flight, skipping"
            );
            return false;
        }

        // Suppress re-entry while a prior dispatch for the same target is
        // parked on the verification pipeline waiting for the parent JMT
        // tree. Without this, every proposal-retry / `on_qc_formed` hit
        // re-runs `assemble_build_action` and re-registers the defer,
        // burning CPU and log bandwidth while peers time out on the
        // proposer slot.
        if let Some(deferred) = self.proposal.deferred()
            && deferred.height == next_height
            && deferred.round == round
        {
            trace!(
                validator = ?self.me,
                height = next_height.inner(),
                round = round.inner(),
                "Proposal deferred pending parent tree, skipping"
            );
            return false;
        }

        true
    }

    /// Build and broadcast a fallback block after a view-change timeout.
    ///
    /// Fallback blocks have an empty payload and inherit the parent's
    /// weighted timestamp, preventing a Byzantine proposer from manipulating
    /// consensus time across extended view changes. `is_fallback = true`.
    fn build_and_broadcast_fallback_block(
        &mut self,
        topology_schedule: &TopologySchedule,
        height: BlockHeight,
        round: Round,
    ) -> Vec<Action> {
        self.build_and_dispatch_proposal(topology_schedule, height, round, ProposalKind::Fallback)
    }

    /// Substate count behind the proposal parent's post-state for the
    /// reshape predicate, or `None` when the predicate is out of play —
    /// reshaping disabled (it can never fire), or the parent's ancestry
    /// crosses a pending halt recovery's sync-admitted suffix, whose
    /// byte total is unknowable until the suffix commits (a commit that
    /// needs this very proposal's QC). Every replica that can vote
    /// synced the same suffix and recomputes the same `None`, so the
    /// header's absent assertion stays byte-agreed. `Err` names the
    /// ancestor whose delta — or, for a frontier lagging the committed
    /// tip, the tip's persistence reconcile — is still outstanding; the
    /// caller defers the build and retries, mirroring the verifier's park
    /// on the same gap.
    fn proposal_substate_bytes(
        &self,
        topology_schedule: &TopologySchedule,
        topology_snapshot: &TopologySnapshot,
        parent_block_hash: BlockHash,
    ) -> Result<Option<u64>, BlockHash> {
        let thresholds = topology_snapshot.reshape_thresholds();
        if thresholds == ReshapeThresholds::DISABLED {
            return Ok(None);
        }
        let count_source = SubstateCountSource {
            thresholds,
            frontier: self.substate_bytes_frontier,
            committed_height: self.committed_height,
            deltas: &self.pending_bytes_deltas,
        };
        match count_source.count_behind(
            self.committed_hash,
            parent_block_hash,
            &self.pending_blocks,
            self.verification.verified_certified_blocks(),
        ) {
            Ok(count) => Ok(Some(count)),
            Err(SubstateCountBlocked::SyncAdmitted(_))
                if topology_schedule
                    .recovery_bridge(self.local_shard)
                    .is_some() =>
            {
                Ok(None)
            }
            Err(blocked) => Err(blocked.blocking_hash()),
        }
    }

    /// The reshape assertion for a proposal: the load predicate over the
    /// resolved substate byte total, deduped against the same trimmed window
    /// the witness root commits. A `None` count (predicate out of play)
    /// yields no assertion. Every replica recomputes this in verification;
    /// the count is resolved — or the build deferred — by
    /// [`Self::proposal_substate_bytes`] before the witness preview, so
    /// this never guesses an assertion the local walk can't justify.
    fn derive_proposal_reshape_trigger(
        &self,
        topology_snapshot: &TopologySnapshot,
        substate_bytes: Option<u64>,
        window: &[Hash],
    ) -> Option<ReshapeTrigger> {
        let count = substate_bytes?;
        let thresholds = topology_snapshot.reshape_thresholds();
        derive_reshape_trigger(self.local_shard, count, &thresholds, window)
    }

    /// Drain dwell-eligible ready signals and preview the beacon-witness
    /// commitment a proposal at `height` would carry — the parent-prefix
    /// walk, the window-base trim, the reshape assertion, and the new
    /// leaves appended — all resolved against the same schedule entry
    /// verifiers use.
    ///
    /// The preview anchors on the prefix the parent block leaves behind,
    /// not the committed accumulator: the parent may be certified but not
    /// yet committed, so its own witness leaves (e.g. a missed-proposal
    /// leaf after a view change) aren't folded into `committed` yet.
    /// Every verifier reconstructs this same prefix via
    /// [`prospective_parent_witness_leaves`], so previewing against the
    /// committed accumulator alone would omit those leaves and produce a
    /// root no validator accepts.
    #[allow(clippy::too_many_arguments)] // proposer-side witness preview: chain prefix + committee + reshape inputs
    fn preview_witness_commitment(
        &mut self,
        topology_schedule: &TopologySchedule,
        topology_snapshot: &TopologySnapshot,
        proposal_wt: WeightedTimestamp,
        parent_block_hash: BlockHash,
        substate_bytes: Option<u64>,
    ) -> WitnessCommitmentPreview {
        let mut ready_signals = self.ready_signal_pool.drain_eligible(
            proposal_wt,
            self.now,
            MIN_READY_SIGNAL_DWELL,
            MAX_READY_SIGNALS_PER_BLOCK,
        );
        let (parent_start, mut parent_leaves) = prospective_parent_witness_leaves(
            &self.beacon_witness_accumulator,
            self.committed_hash,
            parent_block_hash,
            proposal_wt,
            &self.pending_blocks,
            self.verification.verified_certified_blocks(),
            self.local_shard,
            topology_schedule,
        )
        .unwrap_or_else(|blocking| {
            warn!(
                validator = ?self.me,
                ?blocking,
                "Beacon-witness ancestor walk blocked at proposal; previewing against committed prefix"
            );
            (
                self.beacon_witness_accumulator.start_index(),
                self.beacon_witness_accumulator.leaves().to_vec(),
            )
        });
        // The window base resolves from the same schedule entry as the
        // committee — verifiers check the header's claim against it.
        // The root commits the window only, so parent leaves below the
        // base trim off before the preview; the base never undercuts the
        // parent window's start (it is bounded by a committed ancestor's
        // count, and pruning follows commits).
        let base = topology_snapshot.witness_base(self.local_shard);
        let trim = usize::try_from(base.inner().saturating_sub(parent_start.inner()))
            .unwrap_or(usize::MAX)
            .min(parent_leaves.len());
        parent_leaves.drain(..trim);

        // A ready signal whose leaf already sits in this window is committed
        // for good — the merkle accumulator retains it and the beacon folds
        // it once, so re-emitting only bloats the chunk the beacon must
        // fetch. Drop it, mirroring the reshape-trigger dedup against the
        // same window. The re-emission that landed it here is absorbed: the
        // pool already dropped it on drain.
        ready_signals.retain(|signal| {
            let leaf = ready_leaf_payload(
                self.local_shard,
                topology_snapshot,
                signal.validator_id(),
                signal.shard(),
            );
            !parent_leaves.contains(&leaf.leaf_hash())
        });

        let reshape_trigger =
            self.derive_proposal_reshape_trigger(topology_snapshot, substate_bytes, &parent_leaves);
        // The block's new leaves — the randomness reveal (leaf 0) plus the
        // content leaves — are derived and merkle-committed in the
        // `BuildProposal` handler, where the reveal is signed off the main
        // loop. The preview resolves only the inputs to that: the trimmed
        // parent window the new leaves append onto, the deduped ready signals,
        // the reshape assertion, and the window base.
        WitnessCommitmentPreview {
            ready_signals,
            reshape_trigger,
            parent_window: parent_leaves,
            base,
        }
    }

    /// Unified proposal build + dispatch.
    ///
    /// Resolves the parent from the chain view, assembles a `BuildProposal`
    /// action whose payload/timestamp/`is_fallback` bits come from `kind`,
    /// and dispatches via the `proposal` tracker — or defers (the parent
    /// JMT, the split-at-boundary bit, or the reshape substate byte total not
    /// yet resolved) and retries on the next tick.
    #[allow(clippy::too_many_lines)]
    fn build_and_dispatch_proposal(
        &mut self,
        topology_schedule: &TopologySchedule,
        height: BlockHeight,
        round: Round,
        kind: ProposalKind,
    ) -> Vec<Action> {
        let waveless = match &kind {
            ProposalKind::Normal {
                finalized_waves, ..
            } => finalized_waves.is_empty(),
            ProposalKind::Fallback | ProposalKind::Sync => true,
        };
        let (parent_block_hash, parent_qc) = self.chain_view().proposal_parent();
        // The block we build belongs to `at(parent_qc weighted ts)`; its
        // proposer schedule (missed-proposal leaves) and beacon-witness preview
        // resolve against that committee. Stall if the beacon lacks it.
        // Terminal-clamped: coast blocks past a split's cut resolve the
        // shard's final-epoch committee. Recovery-bridged: a block extending
        // a halted tip resolves the fresh committee.
        let Some((committee, _)) =
            topology_schedule.at_for_shard_live(self.local_shard, parent_qc.weighted_timestamp())
        else {
            return vec![];
        };
        // The final-epoch headers of a splitting shard carry the root
        // node's child hashes; the window predicate keys on the same
        // schedule entry as the committee. Whether this window is the
        // final one is unknowable until the local beacon commits the
        // fold that decides it — stall the build (before the witness
        // preview drains the ready-signal pool) rather than guess a
        // header replicas would reject.
        let Some(carry_split_child_roots) =
            self.split_child_roots_bit(topology_schedule, parent_qc.weighted_timestamp())
        else {
            trace!(
                validator = ?self.me,
                height = height.inner(),
                "Split-at-boundary unresolved at proposal; deferring until the beacon catches up"
            );
            return vec![];
        };
        let Some(carry_settled_waves_root) =
            self.settled_waves_root_bit(topology_schedule, parent_qc.weighted_timestamp())
        else {
            trace!(
                validator = ?self.me,
                height = height.inner(),
                "Termination-at-boundary unresolved at proposal; deferring until the beacon catches up"
            );
            return vec![];
        };
        // The reshape predicate reads the substate byte total behind the parent
        // state. Resolve it before the witness preview drains the
        // ready-signal pool: a missing ancestor delta defers the whole
        // build — the verifier parks on the same gap — rather than emitting
        // a header whose omitted assertion every replica recomputes as
        // required and rejects.
        let substate_bytes = match self.proposal_substate_bytes(
            topology_schedule,
            committee,
            parent_block_hash,
        ) {
            Ok(count) => count,
            Err(blocking) => {
                trace!(
                    validator = ?self.me,
                    height = height.inner(),
                    ?blocking,
                    "Substate count unavailable at proposal; deferring until the ancestor delta lands"
                );
                return vec![];
            }
        };
        let preview = self.preview_witness_commitment(
            topology_schedule,
            committee,
            parent_qc.weighted_timestamp(),
            parent_block_hash,
            substate_bytes,
        );

        let plan = assemble_build_action(
            self.me,
            self.local_shard,
            &self.chain_view(),
            height,
            round,
            self.now,
            kind,
            preview.ready_signals,
            preview.reshape_trigger,
            preview.parent_window,
            preview.base,
            carry_split_child_roots,
            carry_settled_waves_root,
            topology_schedule
                .settled_window_floor(self.local_shard, parent_qc.weighted_timestamp()),
            Arc::clone(committee),
        );

        info!(
            validator = ?self.me,
            height = height.inner(),
            round = round.inner(),
            plan.log_label,
        );

        if plan.record_leader_activity {
            self.record_leader_activity();
        }

        // The build-side recovery-bridge escape, under the same conditions as
        // the verifier's (`initiate_state_root_verification`): a wave-less
        // block in the bridge band whose parent is a sync-admitted,
        // QC-attested certified block dispatches without the parent tree.
        let bridge_over_attested_parent = waveless
            && self.recovery_bridging(topology_schedule, parent_qc.weighted_timestamp())
            && self
                .verification
                .cached_verified_certified_block(plan.parent_block_hash)
                .is_some();

        dispatch_or_defer(
            &mut self.proposal,
            &mut self.verification,
            plan,
            height,
            round,
            bridge_over_attested_parent,
        )
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Header Reception
    // ═══════════════════════════════════════════════════════════════════════════

    /// Handle a received block header. Sender identity is taken from the
    /// header's signed `proposer` field — there's no separate peer-id
    /// parameter because sync detection doesn't need it.
    #[instrument(skip(self, topology_schedule, header, manifest, lookup_tx, lookup_finalized_wave, lookup_provision), fields(
        height = header.height().inner(),
        round = header.round().inner(),
        proposer = ?header.proposer(),
        tx_count = manifest.transaction_count()
    ))]
    #[allow(clippy::too_many_arguments)]
    pub fn on_block_header(
        &mut self,
        topology_schedule: &TopologySchedule,
        header: &BlockHeader,
        manifest: BlockManifest,
        lookup_tx: impl Fn(&TxHash) -> Option<Arc<Verifiable<RoutableTransaction>>>,
        lookup_finalized_wave: impl Fn(&WaveId) -> Option<Arc<Verifiable<FinalizedWave>>>,
        lookup_provision: impl Fn(&ProvisionHash) -> Option<Arc<Verifiable<Provisions>>>,
    ) -> Vec<Action> {
        let block_hash = header.hash();
        let height = header.height();
        let round = header.round();

        // A terminated chain ingests no new headers: the crossing is
        // committed, every extension is pointless, and stragglers reach
        // the terminal tip via block sync rather than live proposals.
        if self.dissolved(topology_schedule) {
            debug!(
                validator = ?self.me,
                block_hash = ?block_hash,
                "Ignoring block header — chain terminated at its crossing"
            );
            return vec![];
        }

        debug!(
            validator = ?self.me,
            proposer = ?header.proposer(),
            height = height.inner(),
            round = round.inner(),
            block_hash = ?block_hash,
            "Received block header"
        );

        // Absorbing the parent QC may have started block sync, latching the
        // coordinator's syncing flag. The runner only learns the sync target
        // from the returned action, so every drop path below must still
        // return `sync_actions` — discarding them leaves the flag set with
        // no fetch ever issued, and the flag blocks any retrigger.
        let sync_actions = self.absorb_parent_qc_from_header(header);

        if self.reject_invalid_header(topology_schedule, header) {
            return sync_actions;
        }

        // View sync runs only after validation, so a header that fails the
        // proposer, timestamp, or quorum checks can't nudge the local view.
        self.sync_view_to_header_round(header);
        self.record_header_activity(height, round);

        if self.pending_blocks.contains_key(block_hash) {
            trace!("Already have pending block {}", block_hash);
            return sync_actions;
        }

        // Don't store headers far above the committed tip. A forged
        // quorum-power `parent_qc` passes `validate_header` at any height, so
        // without this a Byzantine proposer plants headers across unbounded
        // future heights; one this far ahead isn't actionable until the chain
        // reaches it, and a node genuinely behind catches up via block-sync.
        if height.inner()
            > self
                .committed_height
                .inner()
                .saturating_add(MAX_HEADER_HEIGHT_LOOKAHEAD)
        {
            warn!(
                validator = ?self.me,
                height = height.inner(),
                committed = self.committed_height.inner(),
                "Dropping header — height beyond storage lookahead"
            );
            return sync_actions;
        }

        // Cap distinct headers per `(height, round)`. The proposer signs one
        // block per round, so beyond a small allowance the rest are a Byzantine
        // proposer equivocating — or varying the unsigned content roots to mint
        // distinct hashes. Drop them before they are stored and verified; the
        // round is already forfeit if its proposer is equivocating.
        if self.pending_blocks.count_at(height, round) >= MAX_HEADERS_PER_HEIGHT_ROUND {
            warn!(
                validator = ?self.me,
                proposer = ?header.proposer(),
                height = height.inner(),
                round = round.inner(),
                "Dropping header — (height, round) at equivocation cap"
            );
            return sync_actions;
        }

        // Per-height cap: evict the stored header farthest from verified
        // progress to make room, or drop this one if it is itself the farthest.
        let Some(cap_actions) = self.enforce_pending_block_cap(height, round) else {
            warn!(
                validator = ?self.me,
                height = height.inner(),
                round = round.inner(),
                "Dropping header — height at pending cap and no farther entry to evict"
            );
            return sync_actions;
        };

        self.pending_blocks.assemble(
            header.clone(),
            manifest,
            self.now,
            lookup_tx,
            lookup_finalized_wave,
            lookup_provision,
        );
        self.adopt_deferred_qc_if_matches(block_hash);

        // Admit any pre-header votes for this block (held raw until now), then
        // re-check the tally — both against the exact committee the
        // just-assembled header anchors. The header passed
        // `reject_invalid_header` (which resolved the same committee), so
        // `None` here would mean the beacon evicted the epoch out from under a
        // long-stalled block — tally nothing rather than guess.
        let mut actions = self.link_buffered_votes_to_header(topology_schedule, block_hash, header);
        if let Some(committee) = self.committee_of_block(topology_schedule, block_hash) {
            actions.extend(self.votes.maybe_trigger_verification(
                committee,
                self.local_shard,
                block_hash,
            ));
        }
        actions.extend(sync_actions);
        // Cancel fetches orphaned by any eviction the cap performed.
        actions.extend(cap_actions);

        // Process this block's own completion — unless vote verification was
        // already scheduled (we only short-circuit on that case, still falling
        // through for sync-only extensions).
        let scheduled_vote_verification = actions
            .iter()
            .any(|a| matches!(a, Action::VerifyQcSignature { .. }));
        if !scheduled_vote_verification
            && !self.finalize_complete_block(topology_schedule, block_hash, &mut actions)
        {
            self.log_incomplete_block(block_hash);
        }

        // A header for `block_hash` just landed, so `committee(block_hash)` now
        // resolves for any child that deferred its parent-QC verification
        // awaiting this parent. Re-trigger them.
        actions.extend(self.retry_pending_children(topology_schedule, block_hash));
        actions
    }

    /// If `header.parent_qc()` moves the chain forward, adopt it: trigger sync
    /// when the parent is missing, update `latest_qc`, fire two-chain commit,
    /// and schedule a proposal attempt. Returns any sync/commit/continuation
    /// actions produced along the way.
    ///
    /// Crucially this does NOT return early when sync is needed — we keep
    /// processing the header so the validator can still participate in
    /// consensus at the tip while catching up on historical blocks.
    fn absorb_parent_qc_from_header(&mut self, header: &BlockHeader) -> Vec<Action> {
        let mut actions = Vec::new();
        if header.parent_qc().is_genesis() {
            return actions;
        }

        let parent_height = header.parent_qc().height();

        // Check for a COMPLETE parent block; an incomplete pending block still
        // requires sync for the full data.
        let have_parent = self.has_complete_block_at_height(parent_height);

        if !have_parent {
            info!(
                validator = ?self.me,
                committed_height = self.committed_height.inner(),
                parent_height = parent_height.inner(),
                target_height = parent_height.inner(),
                "Missing parent block, triggering sync (continuing to process header)"
            );
            actions = self.start_block_sync(parent_height);
        }

        // Defer adoption until the BLS signature has been verified. Without
        // this gate a Byzantine proposer can pass `validate_header` (which
        // only checks signer-power, not signatures) and have us unlock vote
        // locks / fire two-chain commit on a forged QC. The vote-flow path
        // dispatches `Action::VerifyQcSignature` when we want to vote on
        // this block; on success `on_qc_signature_verified` re-enters the
        // adoption logic via `try_adopt_verified_qc`.
        //
        // The cache hit must match the candidate QC byte-for-byte, not just
        // by `block_hash`. Otherwise a Byzantine peer could reuse a known-
        // cached `block_hash` X while fabricating `signers` / `round` /
        // `parent_block_hash`, and have those forged fields adopted into
        // `latest_qc` / drive view sync without re-verification.
        if have_parent {
            let cached = self
                .verification
                .cached_qc(&header.parent_qc().block_hash())
                .filter(|cached| cached.as_ref() == header.parent_qc())
                .cloned();
            if let Some(cached) = cached {
                actions.extend(self.try_adopt_verified_qc(&cached));
            }
        }

        actions
    }

    /// Adopt `qc` as the new `high_qc` (`latest_qc`) if it sits in a higher
    /// round than the one we hold, advance the view past it, and fire
    /// two-chain commit. Caller MUST have confirmed the QC's BLS signature (or
    /// it's the genesis QC) — see [`Self::absorb_parent_qc_from_header`] for
    /// the consensus-path entry and [`Self::on_qc_signature_verified`] for the
    /// post-verify entry.
    ///
    /// Adoption compares by **round**, not height: along a chain round and
    /// height move together, but across a fork the higher-round QC is the one
    /// HotStuff-2 keeps as `high_qc`.
    fn try_adopt_verified_qc(&mut self, qc: &Verified<QuorumCertificate>) -> Vec<Action> {
        let advances = self
            .latest_qc
            .as_ref()
            .is_none_or(|existing| qc.round() > existing.round());
        if !advances {
            return Vec::new();
        }
        debug!(
            validator = ?self.me,
            qc_height = qc.height().inner(),
            qc_round = qc.round().inner(),
            "Adopted verified parent QC"
        );
        self.latest_qc = Some(qc.clone());
        self.advance_view_for_qc(qc);
        // Every adoption path lands here — including timeout-carried
        // high QCs and byte-equal cached QCs that skip the signature
        // dispatch — so this is where the certified tip becomes
        // servable to block sync ahead of its commit.
        let mut actions = Vec::new();
        let certified_hash = qc.block_hash();
        if let Some(block) = self.pending_blocks.get_block(certified_hash) {
            let block = Arc::clone(block);
            if let Some(certified) = self.populate_certified_for(certified_hash, block, qc.clone())
            {
                actions.push(Action::AttachCertifiedUncommitted { certified });
            }
        }
        // Non-proposers learn about QCs via block headers rather than
        // forming them locally — they need two-chain commit + a proposal
        // kick to advance the chain in the event-driven model.
        actions.extend(self.try_two_chain_commit(qc, CommitSource::Header));
        self.queue_ready_proposal();
        actions
    }

    /// Advance the local view toward the header's round if the header is
    /// ahead, so late joiners converge faster than QC-based view sync alone.
    /// The header is one validator's unverified round claim, so the advance
    /// is capped per [`ViewChangeController::sync_to_observed_round`].
    fn sync_view_to_header_round(&mut self, header: &BlockHeader) {
        let old_view = self.view_change.view;
        if self
            .view_change
            .sync_to_observed_round(header.round(), self.high_qc_round())
        {
            info!(
                validator = ?self.me,
                old_view = old_view.inner(),
                new_view = self.view_change.view.inner(),
                header_height = header.height().inner(),
                "View synchronization: advancing view to match received block header"
            );
        }
    }

    /// Validate the header; logs and returns `true` if the caller should
    /// reject (short-circuit with empty actions). An unresolvable committee
    /// is a drop either way — beacon-behind recovers via sync, while a
    /// below-floor epoch marks a forged weighted timestamp or ancient
    /// replay — the split is diagnostic.
    fn reject_invalid_header(
        &self,
        topology_schedule: &TopologySchedule,
        header: &BlockHeader,
    ) -> bool {
        // Proposer of `h` is drawn from `committee(h) == at(parent_qc weighted
        // ts)`, terminal-clamped so a coast header past a split's cut
        // resolves the shard's final-epoch committee, and recovery-bridged
        // so a header extending a halted tip resolves the fresh committee.
        let proposer_committee = match topology_schedule
            .lookup_for_shard_live(self.local_shard, header.parent_qc().weighted_timestamp())
            .0
        {
            ScheduleLookup::Committee(committee) => committee.as_ref(),
            ScheduleLookup::NotYetCommitted => {
                warn!(
                    validator = ?self.me,
                    "No committee for header's epoch yet — beacon behind, dropping header"
                );
                return true;
            }
            ScheduleLookup::Evicted => {
                warn!(
                    validator = ?self.me,
                    "Header's committee epoch is below the schedule floor — dropping header"
                );
                return true;
            }
        };
        // The parent QC over `h-1` was signed by `committee(h-1)`. Skip the
        // quorum pre-check (`None`) when the parent QC is genesis (no quorum to
        // check) or when `h-1`'s header hasn't arrived, so its committee can't
        // be resolved. The pre-check is a cheap DoS filter; the parent QC is
        // fully BLS-verified against the exact committee before this node votes,
        // once `h-1` lands. Substituting `committee(h)` here would run the
        // pre-check against the wrong committee at an epoch boundary.
        let parent_committee = (!header.parent_qc().is_genesis())
            .then(|| self.committee_of_qc(topology_schedule, header.parent_qc()))
            .flatten();
        if let Err(e) = validate_header(
            proposer_committee,
            parent_committee,
            self.local_shard,
            header,
            self.committed_height,
            self.now,
        ) {
            warn!(
                validator = ?self.me,
                error = %e,
                "Invalid block header"
            );
            true
        } else {
            false
        }
    }

    /// If we have a `deferred_qc` whose `block_hash` matches `block_hash`
    /// (votes arrived before this header), adopt it now. Latches a
    /// proposal-retry on adoption. If the deferred QC is for a different
    /// block, it's put back.
    fn adopt_deferred_qc_if_matches(&mut self, block_hash: BlockHash) {
        let Some(deferred_qc) = self.deferred_qc.take_for(block_hash) else {
            return;
        };

        let should_adopt = self
            .latest_qc
            .as_ref()
            .is_none_or(|existing| deferred_qc.round() > existing.round());
        if should_adopt {
            self.latest_qc = Some(deferred_qc.clone());
            self.advance_view_for_qc(&deferred_qc);
            self.queue_ready_proposal();
        }
    }

    /// The header for `block_hash` just arrived, so its exact committee now
    /// resolves: admit any votes that were held raw because they arrived first
    /// (see [`Self::on_unverified_block_vote`]). Each is run through the normal
    /// committee-membership filter against the exact committee, so fabricated
    /// pre-header votes are dropped here. Returns the admissions' trigger
    /// actions.
    fn link_buffered_votes_to_header(
        &mut self,
        topology_schedule: &TopologySchedule,
        block_hash: BlockHash,
        header: &BlockHeader,
    ) -> Vec<Action> {
        let buffered = self.votes.take_unanchored_votes(block_hash);
        if buffered.is_empty() {
            return vec![];
        }
        // The header is now in `pending_blocks`, so this resolves the exact
        // committee; `None` (beacon behind) can't occur after the header
        // passed `reject_invalid_header`, but drop rather than guess if it did.
        let Some(committee) = self.committee_of_block(topology_schedule, block_hash) else {
            return vec![];
        };
        info!(
            block_hash = ?block_hash,
            count = buffered.len(),
            "Admitting pre-header votes now that the header anchors their committee"
        );
        let mut actions = Vec::new();
        for vote in buffered {
            actions.extend(self.votes.accept_unverified_vote(
                committee,
                self.me,
                self.local_shard,
                vote,
                self.committed_height,
                Some(header),
            ));
        }
        actions
    }

    /// A block `parent_hash` just became locally available (its header arrived,
    /// or it committed), so `committee(parent_hash)` now resolves. Re-trigger
    /// any complete pending child that extends it — these are the blocks whose
    /// parent-QC verification [`trigger_qc_verification_or_vote`] deferred for
    /// lack of the parent. This is the stateless retry that pairs with that
    /// deferral; `trigger_qc_verification_or_vote` is idempotent (cache hits /
    /// the safe-vote rule short-circuit a child already handled), so
    /// re-triggering unconditionally is safe.
    fn retry_pending_children(
        &mut self,
        topology_schedule: &TopologySchedule,
        parent_hash: BlockHash,
    ) -> Vec<Action> {
        let children: Vec<BlockHash> = self
            .pending_blocks
            .values()
            .filter(|p| p.header().parent_block_hash() == parent_hash && p.block().is_some())
            .map(|p| p.header().hash())
            .collect();
        let mut actions = Vec::new();
        for child in children {
            actions.extend(self.trigger_qc_verification_or_vote(topology_schedule, child));
        }
        actions
    }

    /// If the pending block is complete, construct it and trigger QC
    /// verification / voting. Returns `true` if the block was handled (the
    /// caller should return the accumulated actions).
    fn finalize_complete_block(
        &mut self,
        topology_schedule: &TopologySchedule,
        block_hash: BlockHash,
        actions: &mut Vec<Action>,
    ) -> bool {
        let is_complete = self.pending_blocks.is_complete(block_hash);
        if !is_complete {
            return false;
        }

        if let Some(pending) = self.pending_blocks.get_mut(block_hash)
            && pending.block().is_none()
            && let Err(e) = pending.construct_block()
        {
            warn!("Failed to construct block {}: {}", block_hash, e);
            return true;
        }

        actions.extend(self.trigger_qc_verification_or_vote(topology_schedule, block_hash));
        true
    }

    /// Log an incomplete block. The cleanup timer's
    /// `check_pending_block_fetches()` will eventually emit fetch requests;
    /// deferring here avoids unnecessary traffic when gossip or local cert
    /// creation fills in the data.
    fn log_incomplete_block(&self, block_hash: BlockHash) {
        if let Some(pending) = self.pending_blocks.get(block_hash) {
            debug!(
                validator = ?self.me,
                block_hash = ?block_hash,
                missing_txs = pending.missing_transaction_count(),
                missing_waves = pending.missing_wave_count(),
                missing_provisions = pending.missing_provision_count(),
                "Block incomplete, will fetch after timeout if still missing"
            );
        }
    }

    /// Trigger QC verification (if needed) and then vote on a complete block.
    ///
    /// This is the single entry point for voting on a block after it becomes complete.
    /// It handles:
    /// 1. Non-genesis QC: Triggers async signature verification, vote happens in callback
    /// 2. Genesis QC: Votes directly (no signature to verify)
    ///
    /// SAFETY: This must be called instead of `try_vote_on_block` directly to ensure
    /// QC signatures are always verified before voting.
    fn trigger_qc_verification_or_vote(
        &mut self,
        topology_schedule: &TopologySchedule,
        block_hash: BlockHash,
    ) -> Vec<Action> {
        let Some(pending) = self.pending_blocks.get(block_hash) else {
            warn!(
                "trigger_qc_verification_or_vote: no pending block for {}",
                block_hash
            );
            return vec![];
        };

        let header = pending.header().clone();
        let height = header.height();
        let round = header.round();

        // For non-genesis QC, delegate signature verification before voting.
        // This is CRITICAL for shard consensus safety - prevents Byzantine proposers from
        // including fake QCs with invalid signatures.
        if !header.parent_qc().is_genesis() {
            // The parent QC's weighted timestamp keys this block's committee
            // but rides outside the QC's signed message, so a Byzantine
            // proposer can rewrite it on a genuine QC and steer verification
            // to any retained epoch's committee. Honest aggregation clamps
            // every vote to the voted block's own anchor (`VoteSet`), so a
            // genuine QC never regresses below its parent's anchor — enforce
            // that floor here, the chokepoint every vote path crosses (fresh
            // headers, deferred children, and the verified-QC cache hit
            // below). Unresolvable only while the parent itself is unknown —
            // defer like the committee resolution below does;
            // `retry_pending_children` re-enters when the parent lands.
            let Some(parent_anchor) = self.committee_anchor(header.parent_qc().block_hash()) else {
                trace!(
                    validator = ?self.me,
                    block_hash = ?block_hash,
                    parent = ?header.parent_qc().block_hash(),
                    "Parent block not held — deferring anchor check until it arrives"
                );
                return vec![];
            };
            if header.parent_qc().weighted_timestamp() < parent_anchor {
                warn!(
                    validator = ?self.me,
                    block_hash = ?block_hash,
                    height = height.inner(),
                    qc_weighted_ms = header.parent_qc().weighted_timestamp().as_millis(),
                    parent_anchor_ms = parent_anchor.as_millis(),
                    "Parent QC weighted timestamp regresses below the parent's anchor — not voting"
                );
                return vec![];
            }

            // Check if we've already verified this exact QC. The cache hit
            // must match byte-for-byte, not just by `block_hash` — see
            // `absorb_parent_qc_from_header` for the same trust gap. A
            // mismatch falls through to BLS verification rather than being
            // accepted.
            let qc_block_hash = header.parent_qc().block_hash();
            if self
                .verification
                .cached_qc(&qc_block_hash)
                .is_some_and(|cached| cached.as_ref() == header.parent_qc())
            {
                trace!(
                    qc_block_hash = ?qc_block_hash,
                    block_hash = ?block_hash,
                    "QC already verified, skipping re-verification"
                );
                return self.try_vote_on_block(topology_schedule, block_hash, height, round);
            }

            // Check if we already have pending verification for this block
            if self.verification.has_pending_qc(&block_hash) {
                trace!("QC verification already pending for block {}", block_hash);
                return vec![];
            }

            // The parent QC was signed by `committee(h-1)`, resolved from
            // `h-1`'s header. If we don't hold `h-1` yet, defer: we can't
            // verify the parent QC — and so can't safely vote on `h` — until it
            // arrives. `on_block_header` re-triggers `h` when a header for
            // `h-1` lands (see `retry_pending_children`); a node genuinely
            // behind recovers the chain via block-sync regardless. `None` here
            // is "parent not held", not beacon-behind: `committee(h-1)` is an
            // epoch at or below `committee(h)`, which `reject_invalid_header`
            // already resolved.
            let Some(parent_committee) =
                self.committee_of_qc(topology_schedule, header.parent_qc())
            else {
                trace!(
                    validator = ?self.me,
                    block_hash = ?block_hash,
                    parent = ?header.parent_qc().block_hash(),
                    "Parent block not held — deferring parent-QC verification until it arrives"
                );
                return vec![];
            };

            // Collect public keys and voting powers for verification —
            // both halves of the QC's predicate (signature + quorum
            // power) need them.
            let public_keys = committee_public_keys(parent_committee, self.local_shard);
            let quorum_threshold =
                VoteCount::quorum_threshold(parent_committee.committee_votes(self.local_shard));

            // Store pending verification info
            self.verification
                .track_pending_qc(block_hash, header.clone());

            // Delegate verification to runner. Preserve any verified
            // marker on the embedded parent_qc so the handler can short-
            // circuit when the wrapper arrives `Verifiable::Verified`
            // (cache hit, local dispatch).
            return vec![Action::VerifyQcSignature {
                qc: header.parent_qc_verifiable().clone(),
                public_keys,
                quorum_threshold,
                block_hash,
            }];
        }

        // Genesis QC - vote directly (no signature to verify)
        self.try_vote_on_block(topology_schedule, block_hash, height, round)
    }

    /// HotStuff-2 safe-vote predicate (Rule 1): may vote for a block at
    /// `round` extending a QC at `parent_qc_round` iff it is the current round,
    /// strictly beyond any round we have already voted or timed out in, and it
    /// extends a QC at least as high as our lock. The local `locked_round` is
    /// the entire fork-safety mechanism — nothing rides on the block but its
    /// `parent_qc`.
    fn can_safe_vote(&self, round: Round, parent_qc_round: Round) -> bool {
        round == self.view_change.view
            && round > self.last_voted_round
            && parent_qc_round >= self.locked_round
    }

    /// Try to vote on a block after it's complete and QC is verified.
    ///
    /// Precondition: caller must have completed QC verification. Use
    /// `trigger_qc_verification_or_vote` as the main entry point.
    #[allow(clippy::too_many_lines)] // linear vote pipeline: safe-vote, gap, content, fence, verify
    fn try_vote_on_block(
        &mut self,
        topology_schedule: &TopologySchedule,
        block_hash: BlockHash,
        height: BlockHeight,
        round: Round,
    ) -> Vec<Action> {
        // Safe-vote rule. A block that fails the rule still runs verification —
        // so its `PreparedCommit` is ready if a quorum forms it elsewhere — but
        // we never emit a vote for it.
        let parent_qc_round = self
            .pending_blocks
            .get_header(block_hash)
            .map_or(self.locked_round, |h| h.parent_qc().round());
        let safe = self.can_safe_vote(round, parent_qc_round);
        if !safe {
            trace!(
                validator = ?self.me,
                block_hash = ?block_hash,
                height = height.inner(),
                round = round.inner(),
                cur_round = self.view_change.view.inner(),
                last_voted_round = self.last_voted_round.inner(),
                locked_round = self.locked_round.inner(),
                parent_qc_round = parent_qc_round.inner(),
                "Safe-vote rule declines — running verification only"
            );
        }

        // Bound speculative work to verified progress. The beacon-witness
        // verification derives one leaf per skipped round, so its cost is
        // `round - parent_qc.round` — and a Byzantine proposer can drive that
        // gap to `MAX_ROUND_GAP` (a genesis `parent_qc` makes the gap the whole
        // round number) and flood the verification pool with such headers. The
        // floor covers any legitimate view-change run in normal operation; the
        // `view - locked_round` term keeps every pacemaker-reachable round
        // votable, so a recovery block after a long certification stall (its
        // gap equals the rounds this node's own pacemaker burned) is still
        // verified rather than wedging the shard. See `SPECULATIVE_VERIFY_GAP`
        // for the full argument. Blocks past the bound are left for
        // block-sync, which admits via QC attestation rather than re-deriving
        // the witness locally.
        let justified_gap = SPECULATIVE_VERIFY_GAP.max(
            self.view_change
                .view
                .inner()
                .saturating_sub(self.locked_round.inner()),
        );
        if round.inner().saturating_sub(parent_qc_round.inner()) > justified_gap {
            trace!(
                validator = ?self.me,
                block_hash = ?block_hash,
                round = round.inner(),
                parent_qc_round = parent_qc_round.inner(),
                justified_gap,
                "Round gap beyond speculative bound — deferring to block-sync"
            );
            return vec![];
        }

        // A recovery's seating window quiesces the vote: a QC aggregated
        // from votes stamped before the fresh committee's first window
        // would bind below the recovery bridge and be unverifiable. The
        // pacemaker re-drives the proposal once the window opens.
        if let Some(anchor) = self.committee_anchor(block_hash)
            && self.recovery_quiesced(topology_schedule, anchor)
        {
            trace!(
                validator = ?self.me,
                block_hash = ?block_hash,
                "Recovery seating window open on this anchor — deferring the vote"
            );
            return vec![];
        }

        // If the block is assembled, run validation + verification.
        // Otherwise fall through to the voting path directly — reachable only
        // from test fixtures; production always assembles before reaching
        // here.
        if let Some(block) = self.pending_blocks.get_block(block_hash) {
            // Content validation (`waves` recomputation) and the beacon-witness
            // verification key on this block's own committee — the header is in
            // hand, so `None` is a beacon-behind stall, not a missing anchor.
            let Some(committee) = self.committee_of_block(topology_schedule, block_hash) else {
                return vec![];
            };
            // Coast blocks past a terminal cut and recovery bridge blocks
            // across a halt gap are both required empty.
            let anchor_wt = block.header().parent_qc().weighted_timestamp();
            let coasting = self.past_terminal_window(topology_schedule, anchor_wt)
                || self.recovery_bridging(topology_schedule, anchor_wt);
            if self.reject_invalid_block_contents(committee, block_hash, block, coasting) {
                return vec![];
            }

            // Blocks the safe-vote rule declines must still run verification to
            // produce PreparedCommit. Parent-pruned blocks likewise run
            // verification but can't contribute in-flight accounting.
            let (parent_in_flight, finalized_tx_count) = {
                let chain = self.chain_view();
                let parent_in_flight = if block.header().parent_qc().is_genesis() {
                    Some(InFlightCount::ZERO)
                } else {
                    chain
                        .get_header(block.header().parent_block_hash())
                        .map(BlockHeader::in_flight)
                };
                let finalized_tx_count: u32 = chain.get_pending(block_hash).map_or(0, |p| {
                    p.finalized_waves()
                        .iter()
                        .map(|fw| u32::try_from(fw.tx_count()).unwrap_or(u32::MAX))
                        .sum()
                });
                (parent_in_flight, finalized_tx_count)
            };
            let skip_vote = match self.verification.classify_vote_in_flight(
                parent_in_flight,
                finalized_tx_count,
                block_hash,
                block,
                !safe,
            ) {
                InFlightCheck::Proceed => false,
                InFlightCheck::SkipVote => true,
                InFlightCheck::Abort => return vec![],
            };

            // Whether this window requires the header's split-child-root
            // pair is decided by the fold that starts it — locally
            // unresolvable until that beacon commit lands. Defer the vote
            // like a missing committee (the block stays pending) rather
            // than judge the header against a guess.
            let Some(split_child_roots_required) = self.split_child_roots_bit(
                topology_schedule,
                block.header().parent_qc().weighted_timestamp(),
            ) else {
                trace!(
                    validator = ?self.me,
                    block_hash = ?block_hash,
                    "Split-at-boundary unresolved at vote; deferring until the beacon catches up"
                );
                return vec![];
            };
            let Some(settled_waves_root_required) = self.settled_waves_root_bit(
                topology_schedule,
                block.header().parent_qc().weighted_timestamp(),
            ) else {
                trace!(
                    validator = ?self.me,
                    block_hash = ?block_hash,
                    "Termination-at-boundary unresolved at vote; deferring until the beacon catches up"
                );
                return vec![];
            };

            // Split-boundary fence over the block's finalized waves.
            if self.fence_blocks_vote(topology_schedule, block, block_hash) {
                return vec![];
            }
            let verification_actions = self.verification.initiate_block_verifications(
                committee,
                topology_schedule,
                self.local_shard,
                &self.pending_blocks,
                &self.beacon_witness_accumulator,
                self.committed_hash,
                block_hash,
                block,
                SubstateCountSource {
                    thresholds: committee.reshape_thresholds(),
                    frontier: self.substate_bytes_frontier,
                    committed_height: self.committed_height,
                    deltas: &self.pending_bytes_deltas,
                },
                split_child_roots_required,
                settled_waves_root_required,
            );

            // Wait for initiated verifications, or exit early when we're
            // running verifications only (skip_vote) or the block isn't
            // fully verified yet.
            if skip_vote
                || !verification_actions.is_empty()
                || !self.verification.is_block_verified(block)
            {
                return verification_actions;
            }
        }

        if !safe {
            return vec![];
        }

        self.create_vote(topology_schedule, block_hash, height, round)
    }

    /// Validate transaction ordering, waves, and cross-ancestor tx uniqueness
    /// against the QC chain + retention cache. Returns `true` when the caller
    /// should reject the block (logs the reason).
    fn reject_invalid_block_contents(
        &self,
        topology_snapshot: &TopologySnapshot,
        block_hash: BlockHash,
        block: &Block,
        coasting: bool,
    ) -> bool {
        let (qc_chain_cert_ids, qc_chain_tx_hashes, qc_chain_provision_hashes) =
            self.collect_qc_chain_hashes(block.header().parent_block_hash());
        if let Err(e) = validate_block_for_vote(
            topology_snapshot,
            self.local_shard,
            block,
            &qc_chain_tx_hashes,
            &qc_chain_cert_ids,
            &qc_chain_provision_hashes,
            &self.dedup_index,
            coasting,
        ) {
            warn!(
                validator = ?self.me,
                block_hash = ?block_hash,
                error = %e,
                "Block failed pre-vote validation - not voting"
            );
            return true;
        }
        false
    }

    /// Create a vote for a block.
    #[tracing::instrument(level = "debug", skip(self, topology_schedule), fields(
        height = height.inner(),
        round = round.inner(),
        sign_us = Empty,
    ))]
    fn create_vote(
        &mut self,
        topology_schedule: &TopologySchedule,
        block_hash: BlockHash,
        height: BlockHeight,
        round: Round,
    ) -> Vec<Action> {
        // Advance the safe-vote lock (Rule 1). `last_voted_round` enforces one
        // vote per round; `locked_round` rises to the round of the QC this
        // block extends, so we will never again vote for a block that extends a
        // QC below it. Both are local — no certificate rides on the block.
        let header = self.pending_blocks.get_header(block_hash);
        let parent_qc_round = header.map_or(self.locked_round, |h| h.parent_qc().round());
        // Sign over the block's own parent so the QC commits to which block it extends.
        let parent_block_hash = header.map_or(self.committed_hash, BlockHeader::parent_block_hash);
        // The weighted timestamp the block's committee resolves against, used
        // below to route the vote — terminal-clamped, so a coasting shard
        // already dropped from the head still reaches its own committee.
        let anchored_wt = header.map(|h| h.parent_qc().weighted_timestamp());
        self.last_voted_round = round;
        self.locked_round = self.locked_round.max(parent_qc_round);

        // Reset the view change timer — voting proves the leader produced a
        // valid block. Non-proposers only learn about QC formation when the
        // next block header arrives (votes go to proposer only), so without
        // this reset the 5s timeout fires before the header arrives, causing
        // cascading view changes under normal load.
        self.record_leader_activity();

        let timestamp = ProposerTimestamp::from_local(self.now);

        debug!(
            validator = ?self.me,
            height = height.inner(),
            round = round.inner(),
            block_hash = ?block_hash,
            "Emitting vote (signing delegated to crypto pool)"
        );

        // Vote recipients are a routing hint (next-round proposers for
        // pipelining), self-healing via gossip — resolved on the head. Once a
        // coasting shard drops from the head the head carries no committee for
        // it, so fall back to the terminal-clamped committee the block
        // anchors against, which still certifies the coast.
        let head_has_committee = !topology_schedule
            .head()
            .consensus_committee_for_shard(self.local_shard)
            .is_empty();
        let recipient_snapshot = if head_has_committee {
            topology_schedule.head()
        } else {
            anchored_wt
                .and_then(|wt| topology_schedule.at_for_shard(self.local_shard, wt))
                .map_or_else(|| topology_schedule.head(), |(snapshot, _)| snapshot)
        };
        let next_proposers = vote_recipients(recipient_snapshot, self.local_shard, self.me, round);

        // Emit SignAndBroadcastBlockVote — the io_loop persists the
        // ratcheted registers, signs on the consensus crypto pool,
        // broadcasts, and feeds the signed vote back for local VoteSet
        // tracking via VerifiedBlockVoteReceived.
        vec![Action::SignAndBroadcastBlockVote {
            block_hash,
            parent_block_hash,
            height,
            round,
            timestamp,
            next_proposers,
            registers: self.safe_vote_registers(),
        }]
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Vote Collection (Deferred Verification)
    // ═══════════════════════════════════════════════════════════════════════════

    /// Handle a locally-produced, pre-verified block vote. Skips the
    /// BLS batch path — the vote is admitted directly to the verified
    /// tally. Wire-arrived votes route through
    /// [`Self::on_unverified_block_vote`].
    #[instrument(skip(self, topology_schedule, vote), fields(
        height = vote.height().inner(),
        voter = ?vote.voter(),
        block_hash = ?vote.block_hash()
    ))]
    pub fn on_verified_block_vote(
        &mut self,
        topology_schedule: &TopologySchedule,
        vote: Verified<BlockVote>,
    ) -> Vec<Action> {
        trace!(
            validator = ?self.me,
            voter = ?vote.voter(),
            block_hash = ?vote.block_hash(),
            "Received pre-verified block vote"
        );

        // Our own verified votes are only produced after we hold the block, so
        // its committee resolves exactly; `None` is a beacon-behind stall.
        let Some(committee) = self.committee_of_block(topology_schedule, vote.block_hash()) else {
            return vec![];
        };
        let header_for_vote = self.pending_blocks.get_header(vote.block_hash());
        self.votes.accept_verified_vote(
            committee,
            self.me,
            self.local_shard,
            vote,
            self.committed_height,
            header_for_vote,
        )
    }

    /// Handle a wire-arrived block vote.
    ///
    /// Uses deferred verification: votes are buffered until we have
    /// enough voting power to possibly reach quorum. Only then do we
    /// batch-verify all buffered signatures and build the QC in a
    /// single operation. The sender identity comes from `vote.voter`
    /// (`ValidatorId`), which is itself part of the signed payload.
    #[instrument(skip(self, topology_schedule, vote), fields(
        height = vote.height().inner(),
        voter = ?vote.voter(),
        block_hash = ?vote.block_hash()
    ))]
    pub fn on_unverified_block_vote(
        &mut self,
        topology_schedule: &TopologySchedule,
        vote: BlockVote,
    ) -> Vec<Action> {
        trace!(
            validator = ?self.me,
            voter = ?vote.voter(),
            block_hash = ?vote.block_hash(),
            "Received block vote"
        );

        // A vote tallies against its block's committee, resolved from the
        // block's header. If the header hasn't arrived, the exact committee is
        // unknowable — hold the vote raw and admit it against the exact
        // committee in `link_buffered_votes_to_header` once the header lands.
        // (Header present but `None` ⇒ beacon-behind stall.)
        if self.pending_blocks.get_header(vote.block_hash()).is_none() {
            self.votes.buffer_unanchored_vote(vote);
            return vec![];
        }
        let Some(committee) = self.committee_of_block(topology_schedule, vote.block_hash()) else {
            return vec![];
        };
        let header_for_vote = self.pending_blocks.get_header(vote.block_hash());
        self.votes.accept_unverified_vote(
            committee,
            self.me,
            self.local_shard,
            vote,
            self.committed_height,
            header_for_vote,
        )
    }

    /// Admit a validator's "ready on shard" signal into the local pool.
    ///
    /// `IoLoop` has already BLS-verified the signal against the sender's
    /// pubkey. This call gates on local-shard membership (a multi-shard
    /// host's `IoLoop` fans the notification out to every hosted shard;
    /// the wrong shard's pool drops here) and on the signal's window
    /// being in the future — past-window signals are stale on arrival.
    /// Re-emissions from the same validator overwrite the prior pool
    /// entry and reset the dwell clock.
    pub fn on_ready_signal_received(
        &mut self,
        topology_schedule: &TopologySchedule,
        signal: ReadySignal,
    ) {
        // Membership admission gate — "is this validator on our committee
        // now?" — answered on the routing head against full membership: a
        // Ready signal's sender is by definition not yet in the consensus
        // subset. An observer seat on this shard's pending split admits
        // too: a freshly drawn cohort sits in the lookahead committee for
        // its first window, but its sync can complete inside that window
        // and the signal must not be dropped on the floor.
        let head = topology_schedule.head();
        let sender = signal.validator_id();
        if !head.committee_for_shard(self.local_shard).contains(&sender)
            && head
                .reshape_observer_child(self.local_shard, sender)
                .is_none()
        {
            return;
        }
        if signal.wt_window_end() < self.committed_ts {
            return;
        }
        self.ready_signal_pool.admit(signal, self.now);
    }

    /// Handle QC verification and building result.
    ///
    /// Called when the runner completes `Action::VerifyAndBuildQuorumCertificate`.
    ///
    /// If QC was built successfully, enqueues `QuorumCertificateFormed` event.
    /// If quorum wasn't reached (some sigs invalid), adds verified votes back
    /// to `VoteSet` and checks if more buffered votes can now reach quorum.
    #[instrument(skip(self, topology_schedule, qc, verified_votes), fields(
        block_hash = ?block_hash,
        has_qc = qc.is_some(),
        verified_count = verified_votes.len()
    ))]
    pub fn on_qc_result(
        &mut self,
        topology_schedule: &TopologySchedule,
        block_hash: BlockHash,
        qc: Option<Verified<QuorumCertificate>>,
        verified_votes: Vec<(usize, Verified<BlockVote>)>,
    ) -> Vec<Action> {
        if let Some(qc) = qc {
            info!(
                block_hash = ?block_hash,
                height = qc.height().inner(),
                signers = qc.signer_count(),
                "QC built successfully"
            );
            self.votes.mark_qc_built(block_hash);
            let mut actions = Vec::new();
            if let Some(block) = self.pending_blocks.get_block(block_hash) {
                let block = Arc::clone(block);
                if let Some(certified) = self.populate_certified_for(block_hash, block, qc.clone())
                {
                    actions.push(Action::AttachCertifiedUncommitted { certified });
                }
            }
            actions.push(Action::Continuation(
                ProtocolEvent::QuorumCertificateFormed { block_hash, qc },
            ));
            return actions;
        }

        // Per-vote: view sync + equivocation tracking. Tracking runs only on
        // verified votes so a forged vote can't pre-empt a legitimate one.
        let validator_id = self.me;
        let high_qc_round = self.high_qc_round();
        for (_, vote) in &verified_votes {
            let old_view = self.view_change.view;
            if self
                .view_change
                .sync_to_observed_round(vote.round(), high_qc_round)
            {
                info!(
                    validator = ?validator_id,
                    old_view = old_view.inner(),
                    new_view = self.view_change.view.inner(),
                    vote_anchor_ts = vote.height().inner(),
                    voter = ?vote.voter(),
                    "View synchronization: advancing view to match verified vote"
                );
            }
            self.votes.track_verified_received_vote(block_hash, vote);
        }

        self.votes
            .finalize_pending_batch(block_hash, verified_votes);
        // The QC build we're resulting from was dispatched off this block's
        // header, so its committee resolves; `None` is a beacon-behind stall.
        match self.committee_of_block(topology_schedule, block_hash) {
            Some(committee) => {
                self.votes
                    .maybe_trigger_verification(committee, self.local_shard, block_hash)
            }
            None => vec![],
        }
    }

    /// Handle QC signature verification result.
    ///
    /// Called when the runner completes `Action::VerifyQcSignature`.
    /// On success, the verified QC rides in the event payload — no
    /// separate cache lookup needed.
    #[instrument(skip(self, topology_schedule, result), fields(block_hash = ?block_hash, valid = result.is_ok()))]
    pub fn on_qc_signature_verified(
        &mut self,
        topology_schedule: &TopologySchedule,
        block_hash: BlockHash,
        result: Result<Verified<QuorumCertificate>, QcVerifyError>,
    ) -> Vec<Action> {
        let valid = result.is_ok();
        // Check if this is a synced block verification
        info!(
            block_hash = ?block_hash,
            valid,
            pending_sync_count = self.block_sync.pending_verification_count(),
            pending_consensus_count = self.verification.pending_qc_count(),
            "on_qc_signature_verified: received callback"
        );
        if let Some(sync_result) = self
            .block_sync
            .on_qc_verified(block_hash, result.as_ref().ok().cloned())
        {
            return match sync_result {
                // Even on failure, try applying verified blocks below the gap.
                // The failed block creates a gap that blocks further progress,
                // but blocks already verified at lower heights can still apply.
                BlockSyncVerificationResult::Failed | BlockSyncVerificationResult::Verified => {
                    self.try_apply_verified_synced_blocks(topology_schedule)
                }
            };
        }

        // Otherwise, it's a consensus block QC verification
        let Some((header, is_valid)) = self.verification.on_qc_verified(block_hash, valid) else {
            warn!(
                "QC signature verified but no pending verification for block {}",
                block_hash
            );
            return vec![];
        };

        let verified_qc = match result {
            Ok(v) => v,
            Err(e) => {
                warn!(
                    block_hash = ?block_hash,
                    height = header.height().inner(),
                    reason = %e,
                    "QC signature verification FAILED - potential Byzantine attack! Rejecting block."
                );
                // Remove the pending block since we can't trust it; cancel any
                // fetches it orphans so the FSM releases their slots.
                let _ = is_valid; // tracked by `verification.on_qc_verified` for diagnostics
                return self.remove_pending_block(block_hash);
            }
        };

        debug!(
            block_hash = ?block_hash,
            height = header.height().inner(),
            "QC signature verified successfully, proceeding to vote"
        );

        // Cache the verified QC so we don't re-verify it for other blocks
        // with the same parent_qc (e.g., during view changes). Cache hits
        // require full byte equality with the cached QC — see the field
        // doc on `VerificationPipeline::verified_qcs`.
        self.verification.cache_verified_qc(verified_qc.clone());

        // Drive composite assembly for the parent block whose QC we just
        // verified. Aggregator-of-N goes through `on_qc_result` for this;
        // non-aggregators (who learn N's QC via N+1's `parent_qc`) need
        // the matching kick here so the parent's
        // `verified_certified_blocks` entry exists when `try_two_chain_commit`
        // looks it up.
        let parent_block_hash = verified_qc.block_hash();
        let mut actions = Vec::new();
        if let Some(parent_block) = self.pending_blocks.get_block(parent_block_hash) {
            let parent_block = Arc::clone(parent_block);
            if let Some(certified) =
                self.populate_certified_for(parent_block_hash, parent_block, verified_qc.clone())
            {
                actions.push(Action::AttachCertifiedUncommitted { certified });
            }
        }

        // The parent QC is now provably authentic; perform the adoption
        // that `absorb_parent_qc_from_header` deferred. Safe to run before
        // `try_vote_on_block` — adoption only mutates `latest_qc` /
        // commit-related state, not the per-block voting machinery.
        if self.has_complete_block_at_height(verified_qc.height()) {
            actions.extend(self.try_adopt_verified_qc(&verified_qc));
        }

        // QC is valid - proceed to vote on the block
        let height = header.height();
        let round = header.round();
        actions.extend(self.try_vote_on_block(topology_schedule, block_hash, height, round));
        actions
    }

    /// Handle state root verification result.
    ///
    /// Called when the runner completes `Action::VerifyStateRoot`. If the state root
    /// Handle a block root verification result (unified handler).
    ///
    /// Handle a completed transaction-root verification.
    pub fn on_transaction_root_verified(
        &mut self,
        topology_schedule: &TopologySchedule,
        block_hash: BlockHash,
        result: Result<Verified<TransactionRoot>, TxRootVerifyError>,
    ) -> Vec<Action> {
        let valid = result.is_ok();
        if let Ok(verified) = result {
            self.verification
                .record_transaction_root_result(block_hash, verified);
        }
        self.on_root_verified_impl(
            topology_schedule,
            VerificationKind::TransactionRoot,
            block_hash,
            valid,
        )
    }

    /// Handle a completed certificate-root verification.
    pub fn on_certificate_root_verified(
        &mut self,
        topology_schedule: &TopologySchedule,
        block_hash: BlockHash,
        result: Result<Verified<CertificateRoot>, CertRootVerifyError>,
    ) -> Vec<Action> {
        let valid = result.is_ok();
        if let Ok(verified) = result {
            self.verification
                .record_certificate_root_result(block_hash, verified);
        }
        self.on_root_verified_impl(
            topology_schedule,
            VerificationKind::CertificateRoot,
            block_hash,
            valid,
        )
    }

    /// Handle a completed local-receipt-root verification.
    pub fn on_local_receipt_root_verified(
        &mut self,
        topology_schedule: &TopologySchedule,
        block_hash: BlockHash,
        result: Result<Verified<LocalReceiptRoot>, LocalReceiptRootVerifyError>,
    ) -> Vec<Action> {
        let valid = result.is_ok();
        if let Ok(verified) = result {
            self.verification
                .record_local_receipt_root_result(block_hash, verified);
        }
        self.on_root_verified_impl(
            topology_schedule,
            VerificationKind::LocalReceiptRoot,
            block_hash,
            valid,
        )
    }

    /// Handle a completed provisions-root verification.
    pub fn on_provisions_root_verified(
        &mut self,
        topology_schedule: &TopologySchedule,
        block_hash: BlockHash,
        result: Result<Verified<ProvisionsRoot>, ProvisionRootVerifyError>,
    ) -> Vec<Action> {
        let valid = result.is_ok();
        if let Ok(verified) = result {
            self.verification
                .record_provisions_root_result(block_hash, verified);
        }
        self.on_root_verified_impl(
            topology_schedule,
            VerificationKind::ProvisionRoot,
            block_hash,
            valid,
        )
    }

    /// Handle a completed provision-tx-roots verification.
    pub fn on_provision_tx_roots_verified(
        &mut self,
        topology_schedule: &TopologySchedule,
        block_hash: BlockHash,
        result: Result<Verified<ProvisionTxRootsMap>, ProvisionTxRootsVerifyError>,
    ) -> Vec<Action> {
        let valid = result.is_ok();
        if let Ok(verified) = result {
            self.verification
                .record_provision_tx_roots_result(block_hash, verified);
        }
        self.on_root_verified_impl(
            topology_schedule,
            VerificationKind::ProvisionTxRoots,
            block_hash,
            valid,
        )
    }

    /// Handle a completed beacon-witness-root verification.
    pub fn on_beacon_witness_root_verified(
        &mut self,
        topology_schedule: &TopologySchedule,
        block_hash: BlockHash,
        result: Result<Verified<BeaconWitnessRoot>, BeaconWitnessRootVerifyError>,
    ) -> Vec<Action> {
        let valid = result.is_ok();
        if let Ok(verified) = result {
            self.verification
                .record_beacon_witness_root_result(block_hash, verified);
        }
        self.on_root_verified_impl(
            topology_schedule,
            VerificationKind::BeaconWitnessRoot,
            block_hash,
            valid,
        )
    }

    /// Handle a completed state-root verification. The `PreparedCommit`
    /// byproduct was already side-channelled inside the action handler;
    /// the verified handle here signals success or failure of the JMT replay.
    pub fn on_state_root_verified(
        &mut self,
        topology_schedule: &TopologySchedule,
        block_hash: BlockHash,
        result: Result<Verified<StateRoot>, StateRootVerifyError>,
        bytes_delta: i64,
    ) -> Vec<Action> {
        let valid = result.is_ok();
        if let Ok(verified) = result {
            self.verification
                .record_state_root_result(block_hash, verified);
            self.pending_bytes_deltas.insert(block_hash, bytes_delta);
        }
        self.on_root_verified_impl(
            topology_schedule,
            VerificationKind::StateRoot,
            block_hash,
            valid,
        )
    }

    /// Shared completion logic for the per-kind root-verified handlers above.
    /// If invalid, the block is rejected. If valid and every other root for
    /// the block has been verified, proceeds to vote.
    #[instrument(skip(self, topology_schedule), fields(block_hash = ?block_hash, ?kind, valid = valid))]
    fn on_root_verified_impl(
        &mut self,
        topology_schedule: &TopologySchedule,
        kind: VerificationKind,
        block_hash: BlockHash,
        valid: bool,
    ) -> Vec<Action> {
        let pipeline_ok = match kind {
            VerificationKind::StateRoot => {
                self.verification.on_state_root_verified(block_hash, valid)
            }
            other => self.verification.on_root_verified(block_hash, other, valid),
        };

        if !pipeline_ok {
            warn!(
                block_hash = ?block_hash,
                ?kind,
                "Block root verification FAILED"
            );
            return self.remove_pending_block(block_hash);
        }

        let mut actions = Vec::new();
        if matches!(
            kind,
            VerificationKind::BeaconWitnessRoot | VerificationKind::StateRoot
        ) {
            // StateRoot completion also supplies the block's substate
            // delta, which children's reshape predicates may be
            // deferred on.
            actions.extend(self.retry_deferred_beacon_witness(topology_schedule, block_hash));
        }

        let Some(pending_block) = self.pending_blocks.get(block_hash) else {
            debug!(
                block_hash = ?block_hash,
                ?kind,
                "Verification complete but block not found in pending or synced"
            );
            return actions;
        };

        let Some(block) = pending_block.block() else {
            return actions;
        };

        if !self.verification.is_block_verified(block) {
            debug!(
                block_hash = ?block_hash,
                ?kind,
                "Verification done, waiting for other verifications"
            );
            return actions;
        }

        let height = pending_block.header().height();
        let round = pending_block.header().round();
        let parent_qc_round = pending_block.header().parent_qc().round();

        // Re-check the safe-vote rule at emission time: the round or our lock
        // may have advanced while the async verifications were in flight, in
        // which case this block is now stale and we must not vote for it (it
        // can still commit via a quorum formed elsewhere).
        if self.can_safe_vote(round, parent_qc_round) {
            actions.extend(self.create_vote(topology_schedule, block_hash, height, round));
        }
        // If this completion finished assembly for a block that
        // `latest_qc` already chose as its 2-chain committable, the
        // earlier `try_two_chain_commit` deferred for lack of an
        // assembled certified handle. Re-drive it now that the cache
        // entry exists.
        actions.extend(self.drive_deferred_commit_for());
        actions
    }

    /// If `latest_qc.committable_hash()` now has an assembled handle in
    /// the verification cache, drive the 2-chain commit. `try_two_chain_commit`
    /// is idempotent against `committed_height`, so calling it on every
    /// completion is safe.
    fn drive_deferred_commit_for(&self) -> Vec<Action> {
        let Some(qc) = self.latest_qc.clone() else {
            return vec![];
        };
        self.try_two_chain_commit(&qc, CommitSource::Aggregator)
    }

    /// Populate `verified_certified_blocks[block_hash]` so the 2-chain
    /// commit can thread a typed handle. Tries the local-assembly path
    /// first via [`VerificationPipeline::record_qc_assembly`]; falls
    /// back to [`Verified::<CertifiedBlock>::from_qc_attestation`] when
    /// the local per-root state isn't complete (typical for an
    /// aggregator that collected 2f+1 votes without voting itself, so
    /// never ran the per-root verifiers locally — the QC's BFT
    /// majority attests they pass).
    ///
    /// Returns the handle it landed so callers can emit
    /// [`Action::AttachCertifiedUncommitted`], making the certified
    /// block servable to block sync ahead of its commit; `None` when
    /// neither path could establish the linkage.
    fn populate_certified_for(
        &mut self,
        block_hash: BlockHash,
        block: Arc<Block>,
        qc: Verified<QuorumCertificate>,
    ) -> Option<Arc<Verified<CertifiedBlock>>> {
        self.verification.track_pending_assembly(Arc::clone(&block));
        if let Some(assembled) = self.verification.record_qc_assembly(block_hash, qc.clone()) {
            return assembled.ok();
        }
        // Local assembly couldn't complete — synthesize via the
        // BFT-transitive trust gate. SAFETY: `qc` is verified and
        // certifies `block_hash`; the QC's signers ran the per-root
        // verifiers at the source committee.
        let block = Arc::unwrap_or_clone(block);
        let certified_raw = CertifiedBlock::new_unchecked(block, qc.clone());
        match Verified::<CertifiedBlock>::from_qc_attestation(certified_raw, qc) {
            Ok(certified) => {
                let certified = Arc::new(certified);
                self.verification
                    .insert_verified_certified_block(block_hash, Arc::clone(&certified));
                Some(certified)
            }
            Err(e) => {
                warn!(
                    ?block_hash,
                    ?e,
                    "Verified<CertifiedBlock> linkage check failed at populate"
                );
                None
            }
        }
    }

    /// Retry beacon-witness verification for any children that deferred
    /// on `parent_hash`. Called after `parent_hash` either successfully
    /// verified its own beacon-witness root or committed past the tip
    /// — in both cases the child's prospective-leaf walk can now make
    /// progress past `parent_hash`.
    fn retry_deferred_beacon_witness(
        &mut self,
        topology_schedule: &TopologySchedule,
        parent_hash: BlockHash,
    ) -> Vec<Action> {
        let children = self
            .verification
            .take_deferred_beacon_witness_children(parent_hash);
        children
            .into_iter()
            .flat_map(|child_hash| {
                self.dispatch_or_park_beacon_witness(topology_schedule, child_hash)
            })
            .collect()
    }

    /// Retry beacon-witness verifications parked because this node's beacon
    /// was behind the block's committee epoch. Called on beacon advance: the
    /// schedule may now seat that epoch, so the walk can resolve the committee
    /// and dispatch. A block still beacon-behind re-parks; one no longer
    /// pending (committed or pruned) is dropped. This is the only path that
    /// revives such a block — no shard event does — so without it a transient
    /// beacon lag during a reshape strands the block at `NOT_STARTED`.
    fn retry_beacon_witness_awaiting_committee(
        &mut self,
        topology_schedule: &TopologySchedule,
    ) -> Vec<Action> {
        let parked = self.verification.take_beacon_witness_awaiting_committee();
        parked
            .into_iter()
            .flat_map(|block_hash| {
                self.dispatch_or_park_beacon_witness(topology_schedule, block_hash)
            })
            .collect()
    }

    /// Resolve `block_hash`'s governing committee and dispatch its
    /// beacon-witness root verification. Empty if the block is no longer
    /// pending (committed or pruned). On a committee miss the block's header
    /// is in hand, so `None` is a beacon-behind stall — its committee's epoch
    /// isn't committed here yet — and the block parks for retry when the
    /// beacon advances rather than dropping: deriving under the head would
    /// verify against the wrong committee, but silently discarding strands the
    /// block at `NOT_STARTED` with no shard event to revive it, wedging the
    /// shard on a view-change loop.
    fn dispatch_or_park_beacon_witness(
        &mut self,
        topology_schedule: &TopologySchedule,
        block_hash: BlockHash,
    ) -> Vec<Action> {
        let Some(block) = self.pending_blocks.get_block(block_hash).map(Arc::clone) else {
            return Vec::new();
        };
        let Some(committee) = self.committee_of_block(topology_schedule, block_hash) else {
            self.verification
                .park_beacon_witness_awaiting_committee(block_hash);
            return Vec::new();
        };
        self.verification.initiate_beacon_witness_root_verification(
            block_hash,
            &block,
            &self.pending_blocks,
            &self.beacon_witness_accumulator,
            self.committed_hash,
            self.local_shard,
            committee,
            topology_schedule,
            SubstateCountSource {
                thresholds: committee.reshape_thresholds(),
                frontier: self.substate_bytes_frontier,
                committed_height: self.committed_height,
                deltas: &self.pending_bytes_deltas,
            },
        )
    }

    /// Handle proposal built by the runner.
    ///
    /// Called when the runner completes `Action::BuildProposal`. The runner has
    /// computed the state root, built the complete block, and cached the `WriteBatch`
    /// for efficient commit later.
    #[instrument(skip(self, topology_schedule, block, manifest, finalized_waves), fields(height = %height.inner(), round = round.inner()))]
    #[allow(clippy::too_many_arguments)]
    pub fn on_proposal_built(
        &mut self,
        topology_schedule: &TopologySchedule,
        height: BlockHeight,
        round: Round,
        block: &Block,
        block_hash: BlockHash,
        manifest: &BlockManifest,
        finalized_waves: Vec<Arc<Verifiable<FinalizedWave>>>,
        provisions: Vec<Arc<Verifiable<Provisions>>>,
        bytes_delta: i64,
    ) -> Vec<Action> {
        match self.proposal.take_matching(height, round) {
            TakeResult::Matched => {}
            TakeResult::NotPending => {
                warn!(
                    height = height.inner(),
                    round = round.inner(),
                    "ProposalBuilt received but no pending proposal"
                );
                return vec![];
            }
            TakeResult::Mismatch { expected } => {
                warn!(
                    expected_height = expected.height.inner(),
                    expected_round = expected.round.inner(),
                    received_height = height.inner(),
                    received_round = round.inner(),
                    "ProposalBuilt mismatch - discarding stale result"
                );
                return vec![];
            }
        }

        let has_certificates = !block.certificates().is_empty();

        // Store our own block as pending (with all finalized waves + provisions).
        // The supplied `manifest` carries the proposer-drained
        // `ready_signals`, which the block itself doesn't carry — thread
        // them through `from_complete_block` so the pending entry's
        // manifest mirrors the header the proposer broadcasts.
        let ready_signals: Vec<ReadySignal> = manifest.ready_signals().iter().cloned().collect();
        let mut pending_block = PendingBlock::from_complete_block(
            block,
            ready_signals,
            manifest.reshape_trigger(),
            finalized_waves,
            provisions,
            self.now,
        );

        let total_tx_count = pending_block.transaction_count();
        info!(
            validator = ?self.me,
            height = height.inner(),
            round = round.inner(),
            block_hash = ?block_hash,
            transactions = total_tx_count,
            certificates = pending_block.certificate_count(),
            has_certificates = has_certificates,
            "Broadcasting proposal"
        );

        if let Err(e) = pending_block.construct_block() {
            warn!("Failed to construct own proposal block: {}", e);
            return vec![];
        }

        let manifest = pending_block.manifest().clone();

        self.pending_blocks.insert(pending_block);
        self.pending_bytes_deltas.insert(block_hash, bytes_delta);
        self.record_leader_activity();

        // The proposer built the block, so all roots are inherently correct.
        // Mark everything verified so the pipeline is complete. This also
        // unblocks child block verifications that need the overlay from this
        // block's PreparedCommit.
        self.verification.mark_proposal_fully_verified(block_hash);

        let mut actions = vec![Action::BroadcastBlockHeader {
            header: Box::new(block.header().clone()),
            manifest: Box::new(manifest),
        }];

        // Vote for our own block
        actions.extend(self.create_vote(topology_schedule, block_hash, height, round));

        actions
    }

    /// Handle JMT state commit completion.
    ///
    /// Called when the runner has finished committing a block's state to the JMT.
    /// This updates our tracked local JMT root (`last_committed_jmt_root`) and
    /// checks if any pending state root verifications can now proceed.
    ///
    /// Unblocked verifications are pushed to the ready queue; the caller
    /// (`NodeStateMachine`) drains them and computes `merged_updates`.
    ///
    /// A block has been persisted to disk — advances the persisted tip and
    /// unblocks any deferred verifications still waiting on persistence
    /// (boot-time catch-up or fallback if the consensus-commit hook was
    /// missed). Also auto-resumes from sync when persistence reaches the
    /// sync target.
    pub fn on_block_persisted(
        &mut self,
        topology_schedule: &TopologySchedule,
        block_height: BlockHeight,
        substate_bytes: u64,
    ) -> Vec<Action> {
        self.verification.on_block_persisted(block_height);

        // Reconcile the byte frontier from storage. Strictly newer
        // heights only: live commits already advanced the frontier via
        // their deltas, so this is the catch-up path for sync commits
        // (which carry no delta) and boot-time backlogs.
        let mut actions = Vec::new();
        if block_height > self.substate_bytes_frontier.0 {
            self.substate_bytes_frontier = (block_height, substate_bytes);
            if topology_schedule.reshape_thresholds() != ReshapeThresholds::DISABLED {
                for parent in self.verification.deferred_beacon_witness_parents() {
                    actions.extend(self.retry_deferred_beacon_witness(topology_schedule, parent));
                }
            }
        }

        // Auto-resume from sync the moment persistence catches up to the
        // sync target: a single event carries the signal, so there's no
        // room for ordering races between sync completion and persistence.
        if self.block_sync.is_syncing()
            && let Some(target) = self.block_sync.sync_target_height()
            && block_height >= target
        {
            actions.extend(self.on_block_sync_complete(topology_schedule));
        }
        actions
    }

    /// A block has been committed by consensus — mark its state root as
    /// available for child verifications without waiting for persistence
    /// or local re-verification. The block's JMT snapshot is in
    /// `PendingChain` by the time `BlockCommitted` fires, so child
    /// verifications can read the parent tree via the overlay.
    pub fn on_block_committed_verification(&mut self, block_hash: BlockHash) {
        self.verification.on_block_committed(block_hash);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // QC and Commit Logic
    // ═══════════════════════════════════════════════════════════════════════════

    /// Count transactions and certificates in the block that would be committed by a QC.
    ///
    /// This is used by the mempool to account for "about to be committed" transactions
    /// when calculating in-flight limits. When a QC forms, the 2-chain commit rule
    /// may commit a parent block, but that commit event won't be processed until after
    /// transaction selection. This method allows the caller to preemptively count:
    /// - Transactions that will INCREASE in-flight (new commits)
    /// - Certificates that will DECREASE in-flight (completed transactions)
    ///
    /// Returns (`tx_count`, `cert_count`). Both are 0 if the QC won't trigger a commit
    /// or the block data isn't available.
    #[must_use]
    pub fn pending_commit_counts(&self, qc: &Verified<QuorumCertificate>) -> (usize, usize) {
        if !qc.has_committable_block() {
            return (0, 0);
        }

        let Some(committable_hash) = qc.committable_hash() else {
            return (0, 0);
        };
        let Some(committable_height) = qc.committable_height() else {
            return (0, 0);
        };

        // Only count if we haven't already committed this height
        if committable_height <= self.committed_height {
            return (0, 0);
        }

        // Look up the block to count transactions and certificates
        self.pending_blocks
            .get_block(committable_hash)
            .map_or((0, 0), |block| {
                (block.transactions().len(), block.certificates().len())
            })
    }

    /// Count transactions and certificates in ALL pending blocks above committed height.
    ///
    /// This accounts for pipelining in chained BFT: multiple blocks can be proposed
    /// before the first one commits. Each pending block's transactions will increase
    /// in-flight when they commit, and each pending block's certificates will decrease
    /// in-flight.
    ///
    /// Returns (`total_tx_count`, `total_cert_count`) across all pending blocks.
    #[must_use]
    pub fn pending_block_counts(&self) -> (usize, usize) {
        (
            self.pending_blocks.total_transaction_count(),
            self.pending_blocks.total_certificate_count(),
        )
    }

    /// Handle QC formation.
    ///
    /// When a QC forms, we:
    /// 1. Update our latest QC
    /// 2. Check if any blocks can be committed (two-chain rule)
    /// 3. Immediately try to propose the next block if we're the proposer
    ///
    /// Step 3 is critical for chain progress: without it, the chain would stall
    /// waiting for the next proposal timer, but the designated proposer for the
    /// next height might not know about this QC yet.
    ///
    /// # State Root Parameter
    ///
    /// `state_root` is the computed JMT root after applying writes from the certificates.
    /// If certificates is empty, parent state is inherited.
    #[instrument(skip(self, topology_schedule, qc, ready_txs, finalized_waves), fields(
        height = qc.height().inner(),
        block_hash = ?block_hash
    ))]
    #[allow(clippy::too_many_arguments)]
    pub fn on_qc_formed(
        &mut self,
        topology_schedule: &TopologySchedule,
        block_hash: BlockHash,
        qc: &Verified<QuorumCertificate>,
        ready_txs: &[Arc<Verified<RoutableTransaction>>],
        finalized_waves: Vec<Arc<Verifiable<FinalizedWave>>>,
        provisions: Vec<Arc<Verifiable<Provisions>>>,
    ) -> Vec<Action> {
        let height = qc.height();

        info!(
            validator = ?self.me,
            block_hash = ?block_hash,
            height = height.inner(),
            "QC formed"
        );

        // The QC's weighted timestamp is the mean of per-vote `timestamp`
        // fields, which ride outside the vote's signed message — ~f Byzantine
        // voters (or a relay rewriting timestamps in flight) can drag the
        // mean far forward. A locally-aggregated QC is as untrusted an
        // ingress as any other; adopting one past the bound poisons
        // `latest_qc` so `tip_committee()` resolves to an epoch beyond the
        // schedule and proposals + timeout tallying stall. Drop it instead:
        // the untouched view-change timer recovers the round, and peers
        // would reject a header carrying this QC for the same reason.
        if qc_weighted_timestamp_too_far_ahead(qc, self.now) {
            warn!(
                validator = ?self.me,
                block_hash = ?block_hash,
                height = height.inner(),
                weighted_ms = qc.weighted_timestamp().as_millis(),
                now_ms = self.now.as_millis(),
                "Locally formed QC weighted timestamp too far ahead — discarding"
            );
            return vec![];
        }

        // Record leader activity - QC forming indicates progress
        self.record_leader_activity();

        // Update latest QC if this is newer (by round — see `try_adopt_verified_qc`)
        let should_update = self
            .latest_qc
            .as_ref()
            .is_none_or(|existing| qc.round() > existing.round());

        if should_update {
            // Defer adoption if the header isn't in memory yet — we need it
            // to look up parent_state_root / parent_in_flight at proposal time.
            if self.chain_view().get_header(block_hash).is_some() {
                self.latest_qc = Some(qc.clone());
                self.advance_view_for_qc(qc);
                // Cache the just-formed QC so the next 2-chain commit
                // (driven by the *next* QC certifying our successor)
                // can look up this QC as the certifying handle for the
                // committable block.
                self.verification.cache_verified_qc(qc.clone());
            } else {
                debug!(
                    block_hash = ?block_hash,
                    height = height.inner(),
                    "Deferring QC adoption — block header not yet in memory"
                );
                self.deferred_qc.defer(block_hash, qc.clone());
            }
        }

        // Reset the view change timer to count from now (leader progress).
        let mut actions = vec![Action::SetTimer {
            id: TimerId::ViewChange,
            duration: self.current_view_change_timeout(),
        }];

        actions.extend(self.try_two_chain_commit(qc, CommitSource::Aggregator));

        // Propose the next block immediately — under the 2-chain commit rule,
        // block N+1 is what certifies block N, so any gap in proposing N+1
        // stalls the finalization of N and everything pending behind it.
        // `try_propose` handles the proposer-rotation / backpressure checks.
        actions.extend(self.try_propose(topology_schedule, ready_txs, finalized_waves, provisions));

        actions
    }

    /// Round-contiguous two-chain commit rule (Rule 2): a QC for block `C`
    /// commits its parent `B` only when `C` sits in the round immediately
    /// following `B` — `qc.round() == B.round() + 1`. A block proposed after a
    /// view change has a non-contiguous child, so its commit defers until a
    /// direct 2-chain forms above it; committing that descendant then commits
    /// the whole prefix back down to the committed tip.
    ///
    /// Called from both `on_qc_formed` (when we build the QC locally) and
    /// `on_block_header` (when we learn about a QC via the next block's
    /// `parent_qc`). This ensures all validators commit regardless of whether
    /// they received votes directly.
    fn try_two_chain_commit(
        &self,
        qc: &Verified<QuorumCertificate>,
        source: CommitSource,
    ) -> Vec<Action> {
        if !qc.has_committable_block() {
            return vec![];
        }

        let Some(committable_height) = qc.committable_height() else {
            return vec![];
        };
        let Some(committable_hash) = qc.committable_hash() else {
            return vec![];
        };

        if committable_height <= self.committed_height {
            return vec![];
        }

        // The committable block's `Verified<CertifiedBlock>` was produced
        // by the verification pipeline when its per-root verifications
        // completed (consensus path) or by sync's
        // `from_qc_attestation` constructor (sync path); look it up
        // rather than reassembling. If the handle isn't present yet
        // (per-root verifications haven't all completed for the
        // committable block), defer — the next commit-driving trigger
        // (later QC arrival, state-root completion) will re-enter
        // here.
        let Some(committable) = self
            .verification
            .cached_verified_certified_block(committable_hash)
            .map(Arc::clone)
        else {
            warn!(
                validator = ?self.me,
                qc_block_hash = ?qc.block_hash(),
                committable_hash = ?committable_hash,
                "Cannot extract assembled Verified<CertifiedBlock> for committable block — deferring commit"
            );
            return vec![];
        };

        // Direct-chain check: only a contiguous round (`qc.round ==
        // committable.round + 1`) finalizes. Otherwise defer — the commit
        // rides up to a later descendant whose direct 2-chain pulls this
        // block in.
        if qc.round() != committable.block().header().round().next() {
            trace!(
                validator = ?self.me,
                qc_round = qc.round().inner(),
                committable_round = committable.block().header().round().inner(),
                committable_height = committable_height.inner(),
                "Two-chain not round-contiguous — deferring commit until a direct chain forms above"
            );
            return vec![];
        }

        // Commit the whole prefix from the committed tip up to the committable
        // block. Steady state this is just the committable block itself; after
        // a view change it also flushes the deferred non-contiguous ancestors.
        let Some(prefix) = self.collect_commit_prefix(&committable) else {
            return vec![];
        };

        prefix
            .into_iter()
            .map(|certified| {
                Action::Continuation(ProtocolEvent::BlockReadyToCommit { certified, source })
            })
            .collect()
    }

    /// Walk down from `committable` through its parent links, collecting the
    /// assembled `Verified<CertifiedBlock>` handles for every block above the
    /// committed tip, returned in ascending height order. Returns `None` if any
    /// ancestor's handle isn't assembled yet — the caller defers the whole
    /// commit until it is.
    fn collect_commit_prefix(
        &self,
        committable: &Arc<Verified<CertifiedBlock>>,
    ) -> Option<Vec<Arc<Verified<CertifiedBlock>>>> {
        let mut chain = vec![Arc::clone(committable)];
        let mut parent_hash = committable.block().header().parent_block_hash();
        while chain
            .last()
            .is_some_and(|c| c.block().height() > self.committed_height.next())
        {
            let parent = self
                .verification
                .cached_verified_certified_block(parent_hash)
                .map(Arc::clone)?;
            parent_hash = parent.block().header().parent_block_hash();
            chain.push(parent);
        }
        chain.reverse();
        Some(chain)
    }

    /// Handle block ready to commit.
    #[instrument(skip(self, topology_schedule, certified), fields(
        height = certified.block().height().inner(),
        block_hash = ?certified.block().hash()
    ))]
    pub fn on_block_ready_to_commit(
        &mut self,
        topology_schedule: &TopologySchedule,
        certified: Arc<Verified<CertifiedBlock>>,
        source: CommitSource,
    ) -> Vec<Action> {
        let block_hash = certified.block().hash();
        let height = certified.block().height();

        // Check if we've already committed this or higher
        if height <= self.committed_height {
            trace!(
                "Block {} at height {} already committed",
                block_hash,
                height.inner()
            );
            return vec![];
        }

        // Buffer out-of-order commits for later processing
        // This handles the case where signature verification completes out of order,
        // causing BlockReadyToCommit events to arrive non-sequentially.
        if height != self.committed_height.next() {
            warn!(
                "Buffering out-of-order commit: expected height {}, got {}",
                self.committed_height.inner() + 1,
                height.inner()
            );
            self.commits.buffer_out_of_order(height, certified, source);
            return vec![];
        }

        // Commit this block and any buffered subsequent blocks
        self.commit_block_and_buffered(topology_schedule, certified, source)
    }

    /// Common bookkeeping for committing a block (shared between consensus and
    /// sync paths). Updates `committed_height`/`hash`, registers committed
    /// artifacts in the dedup index, resets backoff tracking, and cleans up
    /// old state. Returns the abandon-fetch action from the post-commit
    /// sweep when there are orphaned pending-block fetches to cancel.
    fn record_block_committed(
        &mut self,
        topology_schedule: &TopologySchedule,
        block: &Block,
        block_hash: BlockHash,
        certifying_qc: &QuorumCertificate,
        commit_ts: WeightedTimestamp,
    ) -> (Vec<Action>, BeaconWitnessCommit) {
        let height = block.height();

        // The committed chain is linear: every block extends the prior
        // committed tip. The safe-vote + round-contiguous commit rules
        // guarantee it, and reaching here needs both a 2f+1 QC and a
        // round-contiguous two-chain, neither of which a Byzantine peer can
        // forge for a sibling — so a mismatch is a genuine fork (a safety-rule
        // regression or local-state corruption). Fail fast rather than splice a
        // divergent chain onto the tip.
        assert!(
            block.header().parent_block_hash() == self.committed_hash,
            "commit linkage broken at height {}: block {block_hash:?} extends {:?}, not committed tip {:?}",
            height.inner(),
            block.header().parent_block_hash(),
            self.committed_hash,
        );

        self.committed_height = height;
        self.committed_hash = block_hash;
        self.committed_ts = commit_ts;
        // The committee that signed this block is `at(parent_qc weighted ts)`;
        // retain it so [`Self::committee_anchor`] can resolve the tip's
        // committee after it is pruned from `pending_blocks`.
        self.committed_anchor_ts = block.header().parent_qc().weighted_timestamp();
        self.committed_state_root = block.header().state_root();
        self.gc_settled_sets();

        // Retire the committed block's substate delta into the count
        // frontier. Sync commits carry no delta (QC-trusted, never
        // verified locally); `BlockPersisted` reconciles the frontier
        // from storage for those.
        if let Some(delta) = self.pending_bytes_deltas.remove(&block_hash)
            && self.substate_bytes_frontier.0 + 1 == height
        {
            let count = self
                .substate_bytes_frontier
                .1
                .checked_add_signed(delta)
                .expect("substate byte total must not go negative");
            self.substate_bytes_frontier = (height, count);
        }

        // Register committed artifacts synchronously. The retention maps
        // are populated here so the just-committed block's contents are
        // visible to dedup before any subsequent `try_propose` runs in the
        // same `on_qc_formed` tick — even though `cleanup_old_state` below
        // evicts the block from `pending_blocks`. Provisions are keyed off
        // the block's manifest rather than `block.provisions()` so a
        // `Block::Sealed` arriving via the sync path past the live serve
        // window still registers its hashes correctly.
        let manifest = self.pending_blocks.get(block_hash).map_or_else(
            || BlockManifest::from_block(block),
            |pending| pending.manifest().clone(),
        );
        self.dedup_index
            .register_committed_txs(block.transactions());
        self.dedup_index
            .register_committed_certs(block.certificates());
        self.dedup_index
            .register_committed_provisions(manifest.provision_hashes(), commit_ts);

        // Derive this block's beacon-witness leaves from the same three
        // canonical sources the proposer used (receipts from finalized
        // waves, missed-proposal walk over `(parent_round, round)`, and
        // the manifest's `ready_signals`). The leaves are folded into
        // the in-memory accumulator and packaged into a
        // [`BeaconWitnessCommit`] so the io_loop can persist them in
        // the same atomic `WriteBatch` as the block.
        let parent_round = block.header().parent_qc().round();
        let receipts: Vec<StoredReceipt> = block
            .certificates()
            .iter()
            .flat_map(|fw| fw.receipts().iter().cloned())
            .collect();
        // The committed block's missed-proposal leaves resolve against the
        // committee that produced it — the certified binding of its anchor
        // and certifying QC. That binding is a pure function of folded
        // chain content: a halt recovery's sync-admitted suffix keeps
        // deriving under the old committee its headers committed, a bridge
        // block under the fresh committee that proposed it, and every
        // replica derives the same leaves however late it commits (the
        // completed recovery keeps the bridge answering after the pending
        // record clears). Every path that reaches commit first verified
        // the block against this committee, so it always resolves here.
        // If it ever doesn't, local state is corrupt: deriving leaves
        // under a different committee would fork the beacon-witness
        // accumulator across the committee, so fail fast rather than
        // fork, mirroring the commit-linkage assert above.
        let Some(committee) = self.committee_of_qc(topology_schedule, certifying_qc) else {
            panic!(
                "commit-time committee unresolved at height {} for block {block_hash:?} \
                 (anchor {:?}) — beacon-witness accumulator would diverge",
                height.inner(),
                self.committee_anchor(block_hash),
            );
        };
        let missed = missed_proposals_since_prev_commit(
            self.local_shard,
            height,
            parent_round,
            block.header().round(),
            committee,
        );
        let new_leaves = derive_leaves(
            self.local_shard,
            committee,
            vrf_output_from_proof(block.randomness_reveal()),
            &receipts,
            &missed,
            manifest.ready_signals().as_slice(),
            manifest
                .reshape_trigger()
                .and_then(|t| t.to_payload(self.local_shard)),
            manifest.equivocations().as_slice(),
        );
        let starting_leaf_index = self.beacon_witness_accumulator.leaf_count();
        self.beacon_witness_accumulator.commit_append(&new_leaves);
        let leaf_count_at_block_end = self.beacon_witness_accumulator.leaf_count();
        // A committed block whose (QC-attested) window base advanced past
        // the accumulator's start moves both retention floors: the
        // in-memory window prunes to the new base, while the persisted
        // payloads retain everything two consumers can still ask for —
        // the beacon fold draining below the current base (never below
        // the attested anchor's own base), and snap-sync joiners
        // assembling the attested anchor's window against its header
        // root. Under a lagging fold the anchor sits several base
        // advances behind the chain, so the floor clamps to the anchor's
        // window base rather than assuming one window of hysteresis
        // covers it.
        let prior_start = self.beacon_witness_accumulator.start_index();
        let block_base = block.header().beacon_witness_base();
        let prune_persisted_below = (block_base > prior_start).then(|| {
            topology_schedule
                .head()
                .boundary(self.local_shard)
                .map_or(prior_start, |anchor| anchor.witness_base.min(prior_start))
        });
        self.beacon_witness_accumulator.prune_to(block_base);
        let witness = BeaconWitnessCommit {
            starting_leaf_index,
            leaves: new_leaves,
            leaf_count_at_block_end,
            prune_persisted_below,
        };
        self.ready_signal_pool.evict_expired(commit_ts);

        // Reset backoff tracking — new height means fresh round counting.
        self.view_change.reset_for_height_advance();

        (self.cleanup_old_state(height), witness)
    }

    /// Drive the commit chain: commit the given block, then any buffered
    /// out-of-order commits whose turn has come.
    ///
    /// Called when we have a block at the expected height
    /// (`committed_height + 1`). Each iteration commits one block and peeks
    /// the buffer for its successor; the loop terminates when the block is
    /// missing, unassembled, at the wrong height, or no buffered successor
    /// exists.
    fn commit_block_and_buffered(
        &mut self,
        topology_schedule: &TopologySchedule,
        certified: Arc<Verified<CertifiedBlock>>,
        source: CommitSource,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        let mut next = Some((certified, source));

        while let Some((certified, source)) = next.take() {
            let Some(committed_height) =
                self.commit_one_buffered_block(topology_schedule, &certified, source, &mut actions)
            else {
                break;
            };

            if let Some(buffered) = self.commits.take_out_of_order(committed_height.next()) {
                debug!(
                    "Processing buffered commit for height {} after committing {}",
                    committed_height.next().inner(),
                    committed_height.inner()
                );
                next = Some(buffered);
            }
        }

        // Consensus may have unblocked synced blocks that were waiting for a
        // predecessor — try to drain them now.
        actions.extend(self.try_drain_buffered_synced_blocks(topology_schedule));

        actions
    }

    /// Commit a single block in the chain and append the resulting actions
    /// (cancel-fetch for evicted pending blocks, the commit action itself,
    /// and a broadcast if we're the proposer).
    ///
    /// Returns `Some(committed_height)` if the commit succeeded and the
    /// caller should look for a buffered successor; returns `None` if the
    /// block arrives out of height order — the caller should stop driving
    /// the chain.
    fn commit_one_buffered_block(
        &mut self,
        topology_schedule: &TopologySchedule,
        certified: &Arc<Verified<CertifiedBlock>>,
        source: CommitSource,
        actions: &mut Vec<Action>,
    ) -> Option<BlockHeight> {
        let block_hash = certified.block().hash();
        let height = certified.block().height();
        if height != self.committed_height.next() {
            warn!(
                "Unexpected height in commit_block_and_buffered: expected {}, got {}",
                self.committed_height.inner() + 1,
                height.inner()
            );
            return None;
        }

        info!(
            validator = ?self.me,
            height = height.inner(),
            block_hash = ?block_hash,
            transactions = certified.block().transactions().len(),
            "Committing block"
        );

        // `CommitBlock` expects a cached PreparedCommit from `VerifyStateRoot`.
        // If we never verified (non-voter path), route through QcOnly so the
        // io_loop computes it inline. Capture parent state before
        // `record_block_committed` advances it.
        let state_root_verified = self.verification.is_state_root_verified(&block_hash);
        let parent_state_root = self.committed_state_root;
        let parent_block_height = self.committed_height;
        // Anchor on the parent QC's `weighted_timestamp`: it's hash-pinned in
        // this block's header, so every validator reads the identical value —
        // unlike the block's own QC, whose timestamp rides outside the signed
        // message and can be rewritten by a relay. The vote path enforces the
        // per-block monotonicity floor, but sync-admitted blocks commit on QC
        // attestation without a local vote, so the field is still not
        // monotonicity-guaranteed here. Clamp to the prior committed value:
        // deadlines keyed off `committed_ts` (dedup retention, validity
        // windows) must never run backwards.
        let weighted_ts = certified
            .block()
            .header()
            .parent_qc()
            .weighted_timestamp()
            .max(self.committed_ts);

        let (abandon, witness) = self.record_block_committed(
            topology_schedule,
            certified.block(),
            block_hash,
            certified.qc(),
            weighted_ts,
        );
        actions.extend(abandon);
        // The just-committed block's leaves are now folded into the
        // committed accumulator and `committed_hash` advanced to it,
        // so any beacon-witness verifications previously parked on
        // this hash can re-walk past it.
        actions.extend(self.retry_deferred_beacon_witness(topology_schedule, block_hash));
        // The committed block is now the resolvable tip, so a child that
        // deferred its parent-QC verification awaiting it (e.g. delivered via
        // sync rather than gossip) can proceed.
        actions.extend(self.retry_pending_children(topology_schedule, block_hash));
        self.record_leader_activity();

        let proposer = certified.block().header().proposer();
        actions.push(if state_root_verified {
            Action::CommitBlock {
                certified: Arc::clone(certified),
                source,
                witness,
            }
        } else {
            Action::CommitBlockByQcOnly {
                certified: Arc::clone(certified),
                parent_state_root,
                parent_block_height,
                source,
                witness,
            }
        });

        // Only the block proposer gossips the certified header globally.
        // Other validators rely on receiving it via gossip propagation. If the
        // proposer is Byzantine/slow, the RemoteHeaderCoordinator will detect
        // the liveness timeout and trigger a fallback fetch.
        if proposer == self.me {
            // SAFETY: attestation source is the local `Verified<CertifiedBlock>`.
            let certified_header = Verified::<CertifiedBlockHeader>::from_qc_attestation(
                certified.block().header().clone(),
                certified.qc_verified().clone(),
            )
            .expect("Verified<CertifiedBlock> binds qc.block_hash to header.hash");
            actions.push(Action::BroadcastCertifiedBlockHeader { certified_header });
        }

        Some(height)
    }

    /// Submit a synced block for QC signature verification. Genesis QCs
    /// skip verification and apply directly (no signature to check);
    /// everything else is registered with the sync manager and dispatched
    /// via a `VerifyQcSignature` action.
    fn submit_synced_block_for_verification(
        &mut self,
        topology_schedule: &TopologySchedule,
        certified: CertifiedBlock,
    ) -> Vec<Action> {
        if certified.qc().is_genesis() {
            // The wire decoder enforces `qc.block_hash() == block.hash()` on
            // `CertifiedBlock`, so a genesis QC (qc.block_hash() == ZERO) can
            // only ride alongside the genesis block itself. The local
            // `block.is_genesis()` guard catches any locally-constructed
            // pair that bypasses the decoder.
            if !certified.block().is_genesis() {
                warn!(
                    height = certified.block().height().inner(),
                    "Genesis QC paired with non-genesis block — rejecting"
                );
                return vec![];
            }
            debug!(
                height = certified.block().height().inner(),
                "Synced block has genesis QC, applying directly"
            );
            let shard = certified.qc().shard_id();
            let (block, _) = certified.into_parts();
            let verified_qc = Verified::<QuorumCertificate>::genesis(shard, self.chain_origin);
            return self.apply_synced_block(block, verified_qc);
        }

        // The synced block's QC was signed by its own committee,
        // `at(parent_qc weighted ts)`. A not-yet-committed epoch defers:
        // the block goes back to the buffer and `on_beacon_block_persisted`
        // re-drains it once the beacon catches up — discarding it here
        // would leave a hole the drain can never refill without a network
        // re-fetch. An evicted epoch rejects: the schedule's floor retains
        // every epoch the local chain can still verify against, so a synced
        // block keyed below it carries a forged weighted timestamp (it
        // rides outside the signed message) or sits on a stale fork — no
        // amount of retrying resolves it. Certified resolution: a halt
        // recovery's bridge block — anchored below the bridge, certified
        // at or past it — verifies against the fresh committee.
        let committee = match topology_schedule
            .lookup_for_shard_certified(
                self.local_shard,
                certified.block().header().parent_qc().weighted_timestamp(),
                certified.qc().weighted_timestamp(),
            )
            .0
        {
            ScheduleLookup::Committee(committee) => committee,
            ScheduleLookup::NotYetCommitted => {
                warn!(
                    height = certified.block().height().inner(),
                    "No committee for synced block's epoch yet — beacon behind, re-buffering"
                );
                let height = certified.block().height();
                self.block_sync.buffer_block(height, certified);
                return vec![];
            }
            ScheduleLookup::Evicted => {
                warn!(
                    height = certified.block().height().inner(),
                    "Synced block's committee epoch is below the schedule floor — rejecting"
                );
                return vec![];
            }
        };

        // Quorum-power gate: `VerifyQcSignature` only checks the BLS
        // aggregation, not whether the signers represent ≥ 2f+1 of voting
        // power. Without this check a single Byzantine signer suffices to
        // pass and fork the local chain. Mirrors the consensus-path gate
        // in `validate_header`.
        if !qc_has_local_quorum_power(committee, self.local_shard, certified.qc()) {
            warn!(
                height = certified.block().height().inner(),
                signers = certified.qc().signers().count(),
                "Synced block QC lacks quorum power — rejecting"
            );
            return vec![];
        }

        // Timestamp gate: the QC's `weighted_timestamp` rides outside the signed
        // message, so a Byzantine sync peer can forge a far-future value on an
        // otherwise-valid QC and poison `committed_ts` past recovery. Mirrors
        // the consensus-path gate in `validate_header`.
        if qc_weighted_timestamp_too_far_ahead(certified.qc(), self.now) {
            warn!(
                height = certified.block().height().inner(),
                "Synced block QC weighted timestamp too far ahead — rejecting"
            );
            return vec![];
        }

        let public_keys = committee_public_keys(committee, self.local_shard);
        let quorum_threshold =
            VoteCount::quorum_threshold(committee.committee_votes(self.local_shard));

        vec![
            self.block_sync
                .register_for_verification(certified, public_keys, quorum_threshold),
        ]
    }

    /// Try to drain buffered synced blocks in sequential order. Asks
    /// [`BlockSyncManager::next_submitable`] which blocks are eligible — the
    /// coordinator just dispatches each for QC verification.
    fn try_drain_buffered_synced_blocks(
        &mut self,
        topology_schedule: &TopologySchedule,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        let blocks = self.block_sync.next_submitable(
            self.committed_height,
            self.config.max_parallel_sync_verifications,
        );
        for certified in blocks {
            actions.extend(self.submit_synced_block_for_verification(topology_schedule, certified));
        }
        actions
    }

    /// The beacon committed an epoch — replay synced blocks parked in the
    /// buffer because their committee epoch wasn't yet in the schedule
    /// (`submit_synced_block_for_verification` re-buffers on a
    /// `NotYetCommitted` lookup). The beacon adopting the epoch is that
    /// path's only retry signal.
    ///
    /// Also re-evaluates Ready emission: a vnode that finished its
    /// bootstrap sync before its committee window opened got `None`
    /// from the sync-complete gate (it wasn't yet in the head
    /// committee), and a beacon commit is the only signal that the
    /// window may now be active. Skipped mid-sync — completion re-fires
    /// the emission anyway. Re-emission is bounded to one signal per
    /// beacon commit and self-silences once the fold flips the
    /// validator into the consensus subset.
    pub fn on_beacon_block_persisted(
        &mut self,
        topology_schedule: &TopologySchedule,
    ) -> Vec<Action> {
        let mut actions = self.try_drain_buffered_synced_blocks(topology_schedule);
        // The beacon just advanced, so an epoch that was uncommitted here may
        // now seat a block's committee — retry any beacon-witness verification
        // that was parked on that lag before it strands the shard.
        actions.extend(self.retry_beacon_witness_awaiting_committee(topology_schedule));
        if !self.is_block_syncing() {
            actions.extend(self.maybe_emit_ready_signal(topology_schedule));
        }
        actions
    }

    /// Admit a QC-verified synced block into the chain state and drive the
    /// round-contiguous two-chain commit.
    ///
    /// The block does not commit on its own QC. It caches its
    /// `Verified<CertifiedBlock>` and adopts its QC, then lets
    /// `try_two_chain_commit` finalize it once a child certified at exactly
    /// `round + 1` is admitted — the same rule the consensus path uses, and
    /// the only one that distinguishes a committed block from a
    /// certified-but-orphaned sibling at one height (both carry a valid QC). A
    /// single QC is not a commit certificate; committing on it would let a
    /// peer-served orphan sibling fork a lagging node. The eventual commit
    /// flows through `commit_one_buffered_block`, which selects the
    /// synchronous inline-JMT `CommitBlockByQcOnly` path for blocks whose
    /// state root was not locally verified.
    fn apply_synced_block(
        &mut self,
        block: Block,
        verified_qc: Verified<QuorumCertificate>,
    ) -> Vec<Action> {
        let block_hash = block.hash();
        let height = block.height();

        info!(
            validator = ?self.me,
            height = height.inner(),
            block_hash = ?block_hash,
            transactions = block.transactions().len(),
            certificates = block.certificates().len(),
            "Admitting synced block"
        );

        // Update latest QC if this one is newer (by round).
        if self
            .latest_qc
            .as_ref()
            .is_none_or(|existing| verified_qc.round() > existing.round())
        {
            self.advance_view_for_qc(&verified_qc);
            self.latest_qc = Some(verified_qc.clone());
        }

        // The synced block's QC BFT-transitively attests every embedded wave's
        // per-EC signature predicate via the source committee's signature over
        // `certificate_root` + `local_receipt_root`, so the waves can be
        // admitted to the canonical store on receipt.
        let synced_waves: Vec<Arc<Verifiable<FinalizedWave>>> = block
            .certificates()
            .iter()
            .map(|fw| {
                // Reuse a live marker when present (local dispatch) by keeping the
                // existing `Arc`; otherwise mint via the committed-block gate.
                if fw.is_verified() {
                    Arc::clone(fw)
                } else {
                    let verified =
                        Verified::<FinalizedWave>::from_committed_block(fw.as_unverified().clone());
                    Arc::new(verified.into())
                }
            })
            .collect();
        let parent_qc_round = block.header().parent_qc().round();
        let parent_qc_not_genesis = !block.header().parent_qc().is_genesis();

        // Assemble the synced block into a `Verified<CertifiedBlock>` via the
        // BFT-transitive trust gate: the source committee's QC attests to the
        // block's per-root verifications.
        let certified_raw = CertifiedBlock::new_unchecked(block, verified_qc.clone());
        let certified =
            match Verified::<CertifiedBlock>::from_qc_attestation(certified_raw, verified_qc) {
                Ok(c) => Arc::new(c),
                Err(e) => {
                    warn!(?block_hash, ?e, "synced block QC linkage failed");
                    return vec![];
                }
            };

        // Adopt the parent_qc from the block header if it's newer still.
        if parent_qc_not_genesis
            && self
                .latest_qc
                .as_ref()
                .is_none_or(|existing| parent_qc_round > existing.round())
        {
            let verified_parent = certified.parent_qc_attested();
            self.advance_view_for_qc(&verified_parent);
            self.latest_qc = Some(verified_parent);
        }

        // Cache the certified handle so the round-contiguous two-chain rule can
        // find this block as a committable parent — and as a
        // `collect_commit_prefix` ancestor — once its child is admitted.
        self.verification
            .insert_verified_certified_block(block_hash, Arc::clone(&certified));
        self.block_sync.mark_applied(height, block_hash);

        let mut actions = self.try_two_chain_commit(certified.qc_verified(), CommitSource::Sync);

        if !synced_waves.is_empty() {
            actions.push(Action::Continuation(
                ProtocolEvent::FinalizedWavesAdmitted {
                    waves: synced_waves,
                },
            ));
        }

        actions
    }

    /// Apply all consecutive verified synced blocks, then drain the buffer
    /// for further parallel QC verifications. The sync manager computes the
    /// next expected height from its own applied-height marker so we don't
    /// double-apply blocks already handed off.
    fn try_apply_verified_synced_blocks(
        &mut self,
        topology_schedule: &TopologySchedule,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        while let Some((block, verified_qc)) =
            self.block_sync.take_next_verified(self.committed_height)
        {
            actions.extend(self.apply_synced_block(block, verified_qc));
        }
        actions.extend(self.try_drain_buffered_synced_blocks(topology_schedule));

        // Sync completes when the verified frontier reaches the target. Under
        // the round-contiguous commit rule the trailing block finalizes
        // through live consensus, so completion tracks the processed frontier
        // rather than the committed height, which lags it by a block.
        if self.block_sync.is_syncing()
            && let Some(target) = self.block_sync.sync_target_height()
            && self.block_sync.sync_applied_height() >= target
        {
            actions.extend(self.on_block_sync_complete(topology_schedule));
        }
        actions
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // View Change
    // ═══════════════════════════════════════════════════════════════════════════
    // Implicit Round Advancement (HotStuff-2 Style)
    // ═══════════════════════════════════════════════════════════════════════════

    /// Enter the current `view_change.view` as a fresh round: clear the stale
    /// proposal, schedule the next view-change timer, and — if we are the new
    /// round's leader — propose a fresh block extending `high_qc` (the
    /// quorum-max the timeout quorum just adopted). Reached via the
    /// timeout-quorum advance ([`Self::advance_on_timeout_quorum`]).
    fn enter_round(&mut self, topology_schedule: &TopologySchedule) -> Vec<Action> {
        // The next height to propose is one above the highest certified block,
        // NOT one above the committed block. This matches try_propose behavior.
        let height = self
            .latest_qc
            .as_ref()
            .map_or_else(|| self.committed_height.next(), |qc| qc.height().next());

        // Clear any in-flight proposal — a stale build from the previous
        // round should not block the new round's proposer. If the old build
        // completes later, on_proposal_built will see a NotPending result and
        // discard it.
        self.proposal.clear();

        info!(
            validator = ?self.me,
            height = height.inner(),
            new_round = self.view_change.view.inner(),
            view_changes = self.view_change.view_changes,
            "Entering new round"
        );

        // Log why any pending blocks at this height couldn't be verified in time.
        for pending in self.pending_blocks.values() {
            if pending.header().height() == height {
                if let Some(block) = pending.block() {
                    if !self.verification.is_block_verified(block) {
                        self.verification.log_incomplete_verification(block);
                    }
                } else {
                    warn!(
                        block_hash = ?pending.header().hash(),
                        height = height.inner(),
                        missing_txs = pending.missing_transaction_count(),
                        missing_waves = pending.missing_wave_count(),
                        missing_provisions = pending.missing_provision_count(),
                        "View change — block still incomplete (missing data)"
                    );
                }
            }
        }

        // Always schedule the next view change timer — proposers need it too
        // in case their block doesn't gather quorum (e.g., other validators are
        // behind or offline). Without this, a proposer whose block fails to
        // reach quorum would never advance rounds again.
        let timer = Action::SetTimer {
            id: TimerId::ViewChange,
            duration: self.current_view_change_timeout(),
        };

        // The new round's leader proposes a fresh fallback block extending
        // `high_qc`. There is no lock to re-propose: HotStuff-2 carries safety
        // in the local `locked_round`, not on the block, so a new round always
        // builds anew rather than re-broadcasting a prior height's proposal.
        // Without the in-progress committee we can't know the leader — only the
        // timer goes out.
        let is_new_proposer = self
            .tip_committee(topology_schedule)
            .is_some_and(|c| c.proposer_for(self.local_shard, self.view_change.view) == self.me);
        if is_new_proposer {
            info!(
                validator = ?self.me,
                height = height.inner(),
                new_round = self.view_change.view.inner(),
                "We are the new proposer after round advance - building block"
            );

            let mut actions = self.build_and_broadcast_fallback_block(
                topology_schedule,
                height,
                self.view_change.view,
            );
            actions.push(timer);
            return actions;
        }

        vec![timer]
    }

    // ── Pacemaker: timeout-driven view change (HotStuff-2 synchronizer) ─────

    /// Our current `high_qc` — the highest QC we've adopted, or the genesis QC.
    fn high_qc(&self) -> QuorumCertificate {
        self.latest_qc
            .as_deref()
            .cloned()
            .unwrap_or_else(|| QuorumCertificate::genesis(self.local_shard, self.chain_origin))
    }

    /// Round of our `high_qc` (genesis round if we hold none). The anchor for
    /// bounding unverified observed-round view sync to verified progress.
    fn high_qc_round(&self) -> Round {
        self.latest_qc
            .as_ref()
            .map_or(Round::INITIAL, |qc| qc.round())
    }

    /// Highest timeout round the pacemaker will spend a verify on or tally.
    /// The pacemaker can only advance within `MAX_ROUND_GAP` of verified
    /// progress (the same ceiling observed-round view sync uses), so a timeout
    /// beyond it can never drive a quorum and would only cost a pairing check
    /// and a never-pruned keeper entry. Anchored to the verified `high_qc`, not
    /// the local view, so a Byzantine round can't ratchet the bound upward.
    fn max_pacemaker_round(&self) -> Round {
        Round::new(self.high_qc_round().inner().saturating_add(MAX_ROUND_GAP))
    }

    /// Broadcast our timeout for `round` (carrying our `high_qc`) to the
    /// committee, which tallies it. The round timer drives this on every fire,
    /// so a timeout lost to a partition is retransmitted until a 2f+1 quorum
    /// forms — without retransmission a healed partition never re-collects the
    /// shares it dropped and the chain wedges.
    fn broadcast_timeout(
        &mut self,
        topology_schedule: &TopologySchedule,
        round: Round,
    ) -> Vec<Action> {
        // A terminated chain drives no view changes; the pacemaker only
        // needed to reach the crossing's commit, which has happened.
        if self.dissolved(topology_schedule) {
            return vec![];
        }
        // The timeout is tallied by the in-progress committee (the one that
        // would form the next QC). Without it (beacon behind) we can't drive a
        // view change — stall.
        let Some(committee) = self.tip_committee(topology_schedule) else {
            return vec![];
        };
        self.last_timed_out_round = Some(round);
        // A timed-out round is never voted: bump `last_voted_round` so the
        // safe-vote rule refuses any block that arrives at this round after we
        // gave up on it (Rule 1).
        self.last_voted_round = self.last_voted_round.max(round);
        let recipients: Vec<ValidatorId> = committee
            .committee_for_shard(self.local_shard)
            .iter()
            .copied()
            .filter(|v| *v != self.me)
            .collect();
        vec![Action::SignAndBroadcastTimeout {
            round,
            high_qc: self.high_qc(),
            recipients,
            registers: self.safe_vote_registers(),
        }]
    }

    /// Bracha-amplify: broadcast our own timeout for `round` the first time we
    /// hear f+1 of them, so every honest replica eventually times out. Unlike
    /// the timer-driven retransmit, this fires at most once per round — a
    /// replica that already broadcast (via its timer or an earlier amplify)
    /// stays quiet.
    fn amplify_timeout(
        &mut self,
        topology_schedule: &TopologySchedule,
        round: Round,
    ) -> Vec<Action> {
        if self.last_timed_out_round == Some(round) {
            return Vec::new();
        }
        self.broadcast_timeout(topology_schedule, round)
    }

    /// Voting power of `voter` iff it belongs to the local shard committee —
    /// the bound the pacemaker tallies against, mirroring the vote path
    /// (`VoteKeeper`). `None` for any validator outside the committee, so a
    /// globally-registered validator from another shard never counts toward the
    /// timeout thresholds (whose total is committee-scoped).
    ///
    /// # Panics
    ///
    /// Panics if `voter` is in the committee but has no voting power — a
    /// `BeaconState` invariant violation, as in [`committee_public_keys`].
    fn committee_timeout_power(
        &self,
        topology_snapshot: &TopologySnapshot,
        voter: ValidatorId,
    ) -> Option<VoteCount> {
        topology_snapshot.committee_index_for_shard(self.local_shard, voter)?;
        // Membership is confirmed above, so the power resolves; a miss is the
        // same invariant violation the committee-key lookups assert on.
        Some(topology_snapshot.vote_of(voter).unwrap_or_else(|| {
            panic!(
                "committee member {voter:?} has no voting power — \
                 BeaconState invariant (committees subset of validators) violated"
            )
        }))
    }

    /// Screen a wire timeout, then delegate its BLS share verification to the
    /// consensus crypto pool. The verified share returns as
    /// `ProtocolEvent::VerifiedTimeoutReceived` and is tallied by
    /// [`Self::on_verified_timeout`] — keeping per-timeout pairing checks off
    /// the shard loop thread during a view change, as the vote path does.
    ///
    /// # Panics
    ///
    /// Panics if a committee member has no public key — a `BeaconState`
    /// invariant violation, as in [`committee_public_keys`].
    pub fn on_unverified_timeout(
        &mut self,
        topology_schedule: &TopologySchedule,
        timeout: &Timeout,
    ) -> Vec<Action> {
        if timeout.shard_id() != self.local_shard {
            return Vec::new();
        }
        // The pacemaker is driven by the in-progress committee. Absent it
        // (beacon behind) we can't safely tally — drop.
        let Some(committee) = self.tip_committee(topology_schedule) else {
            return Vec::new();
        };
        // Only this shard's committee drives its pacemaker. Reject outsiders
        // before spending a BLS verify on them; `on_verified_timeout` re-checks
        // the same bound for locally echoed timeouts.
        if self
            .committee_timeout_power(committee, timeout.voter())
            .is_none()
        {
            // A pending recovery's retained ex-member is the one line back
            // to the halted tip: its share can't tally, but its carried
            // `high_qc` names the certified frontier the fresh committee
            // must extend, and a halted chain gossips nothing else. Harvest
            // the tip from it instead of dropping outright.
            if let Some(actions) = self.harvest_retained_tip(topology_schedule, timeout) {
                return actions;
            }
            warn!(validator = ?self.me, voter = ?timeout.voter(), "Dropping timeout from non-committee validator");
            return Vec::new();
        }
        // Skip rounds we've advanced past, rounds too far beyond verified
        // progress to ever reach, and voters already tallied: such a share
        // would verify and then be dropped (or never drive a quorum), so screen
        // it here rather than spend a pairing check. Mirrors the vote path,
        // which drops a seen voter before delegating crypto.
        if timeout.round() < self.view_change.view
            || timeout.round() > self.max_pacemaker_round()
            || self.timeouts.contains(timeout.round(), timeout.voter())
        {
            return Vec::new();
        }
        // `committee_timeout_power` above confirmed committee membership, so the
        // public key resolves; a miss is the same BeaconState invariant
        // violation the committee-key lookups assert on.
        let voter = timeout.voter();
        let voter_public_key = committee.public_key(voter).unwrap_or_else(|| {
            panic!(
                "committee member {voter:?} has no public key — \
                 BeaconState invariant (committees subset of validators) violated"
            )
        });
        vec![Action::VerifyTimeout {
            timeout: timeout.clone(),
            voter_public_key,
        }]
    }

    /// Harvest the halted tip from a retained ex-member's timeout while a
    /// recovery is pending on this shard, or `None` when the sender holds
    /// no retained seat (the ordinary outsider drop applies).
    ///
    /// The recovery seats the fresh committee from a snap-synced anchor
    /// with no QC past it, and the halted chain gossips nothing, so the
    /// old committee's timeout retransmissions — resolved onto the fresh
    /// committee by the recovery bridge — are the only signal carrying the
    /// certified frontier. The share itself is never tallied. The carried
    /// QC is adopted only if it verifies against the committee that signed
    /// it (its block's header in hand); otherwise it serves as a fetch
    /// target — sync admits the real certified blocks through the normal
    /// verified pipeline, so a fabricated height costs a bounded fetch
    /// round, never state.
    fn harvest_retained_tip(
        &mut self,
        topology_schedule: &TopologySchedule,
        timeout: &Timeout,
    ) -> Option<Vec<Action>> {
        topology_schedule
            .head()
            .pending_recoveries()
            .get(&self.local_shard)
            .filter(|recovery| recovery.retained.contains(&timeout.voter()))?;
        let carried = timeout.high_qc();
        if carried.height() <= self.committed_height
            || qc_weighted_timestamp_too_far_ahead(carried, self.now)
        {
            return Some(Vec::new());
        }
        info!(
            validator = ?self.me,
            voter = ?timeout.voter(),
            carried_height = carried.height().inner(),
            committed_height = self.committed_height.inner(),
            "Harvesting the halted tip from a retained ex-member's timeout"
        );
        if carried.round() > self.high_qc_round()
            && let Some(verified) = self.verify_qc_sync(topology_schedule, carried)
        {
            return Some(self.try_adopt_verified_qc(&verified));
        }
        // Sync to the committable prefix, not the certified tip: the tip
        // block commits only under a successor QC, and on a halted chain
        // none exists yet — a sync targeted at it never completes, and a
        // committee parked in sync mode never drives the view changes
        // that would produce that successor. A prefix within the applied
        // frontier is already fetched and processed; its trailing block
        // commits under the successor this committee must produce live,
        // so re-syncing toward it would only park the pacemaker again.
        let prefix = BlockHeight::new(carried.height().inner().saturating_sub(1));
        if prefix <= self.committed_height || self.block_sync.sync_applied_height() >= prefix {
            return Some(Vec::new());
        }
        Some(self.start_block_sync(prefix))
    }

    /// Tally a verified timeout: amplify at f+1 (Bracha), advance at 2f+1.
    pub fn on_verified_timeout(
        &mut self,
        topology_schedule: &TopologySchedule,
        timeout: Verified<Timeout>,
    ) -> Vec<Action> {
        let round = timeout.round();
        // Ignore timeouts we've advanced past or that sit too far beyond
        // verified progress for the pacemaker to ever reach.
        if round < self.view_change.view || round > self.max_pacemaker_round() {
            return Vec::new();
        }
        // The pacemaker's quorum is measured against the in-progress committee.
        let Some(committee) = self.tip_committee(topology_schedule) else {
            return Vec::new();
        };
        // A verified BLS share proves who signed, not that the signer sits in
        // the committee whose 2f+1 the pacemaker measures against. Restrict the
        // tally to the local committee: the quorum total is committee-scoped, so
        // a globally-registered validator from another shard must not count
        // toward the f+1 / 2f+1 thresholds.
        let Some(power) = self.committee_timeout_power(committee, timeout.voter()) else {
            warn!(validator = ?self.me, voter = ?timeout.voter(), "Dropping timeout from non-committee validator");
            return Vec::new();
        };
        let carried_high_qc = timeout.high_qc().clone();
        if !self.timeouts.record(timeout, power) {
            return Vec::new();
        }

        let total = committee.committee_votes(self.local_shard);
        let seen = self.timeouts.power(round);
        let mut actions = Vec::new();

        // A timeout carries its sender's verified tip, so a higher carried
        // `high_qc` is adopted here, per share — not only at the 2f+1 quorum.
        // A replica that missed a QC (vote or header lost) otherwise wedges
        // the pacemaker in a round split: it keeps timing out the old round,
        // peers ahead drop those below-view timeouts, and neither round ever
        // reaches quorum. Adoption from the first share re-converges the
        // view (and can fire the two-chain commit). The carried QC rides
        // outside the share's signed message and its weighted timestamp is
        // forgeable, so it passes the same bound and verification as the
        // quorum-max path; a forged one costs one failed pairing.
        if carried_high_qc.round() > self.high_qc_round()
            && !qc_weighted_timestamp_too_far_ahead(&carried_high_qc, self.now)
            && let Some(verified) = self.verify_qc_sync(topology_schedule, &carried_high_qc)
        {
            actions.extend(self.try_adopt_verified_qc(&verified));
        }

        // Bracha amplification: f+1 timeouts seen → broadcast our own.
        if VoteCount::has_one_third(seen, total) {
            actions.extend(self.amplify_timeout(topology_schedule, round));
        }

        // 2f+1 timeouts → adopt the quorum-max high_qc and advance together.
        if VoteCount::has_quorum(seen, total) {
            actions.extend(self.advance_on_timeout_quorum(topology_schedule, round));
        }

        actions
    }

    /// On a 2f+1 timeout quorum for `round`: adopt the quorum-max `high_qc`
    /// (verified) so the next leader extends it, then advance to `round + 1`.
    fn advance_on_timeout_quorum(
        &mut self,
        topology_schedule: &TopologySchedule,
        round: Round,
    ) -> Vec<Action> {
        let mut actions = self.adopt_timeout_quorum_high_qc(topology_schedule, round);
        // One round past the pacemaker ceiling nothing is wire-valid (a
        // proposal there would exceed `MAX_ROUND_GAP` vs any adoptable parent
        // QC) and no timeout tallies, so the view must never enter it. The
        // quorum-max `high_qc` adoption above may have just raised the
        // ceiling; at the clamp the view parks until a higher carried
        // `high_qc` slides it.
        if self
            .view_change
            .advance_to(round.next().min(self.max_pacemaker_round()))
        {
            // Reset the timeout baseline so the new leader gets a full window.
            self.view_change.record_leader_activity(self.now);
            self.timeouts.prune_below(self.view_change.view);
            actions.extend(self.enter_round(topology_schedule));
        }
        actions
    }

    /// Verify and adopt the highest valid `high_qc` reported by the round's
    /// timeouts if it exceeds our current `high_qc`. This is what makes the next
    /// leader extend a QC at least as high as any committed block.
    ///
    /// The carried `high_qc`s are unverified at intake, so we walk them from the
    /// highest round down and adopt the first that *verifies*. A Byzantine
    /// timeout can carry a forged high-round `high_qc`, but its only effect is
    /// one failed verification — it cannot suppress the genuine quorum-max an
    /// honest timeout carries.
    fn adopt_timeout_quorum_high_qc(
        &mut self,
        topology_schedule: &TopologySchedule,
        round: Round,
    ) -> Vec<Action> {
        let cur_high = self
            .latest_qc
            .as_deref()
            .map_or(Round::INITIAL, QuorumCertificate::round);
        for candidate in self.timeouts.high_qcs_by_round_desc(round) {
            // Candidates are sorted descending, so once one can't advance us
            // nothing below it can either.
            if candidate.is_genesis() || candidate.round() <= cur_high {
                break;
            }
            // The carried `high_qc`'s `weighted_timestamp` is forgeable (rides
            // outside the signed message), so skip a far-future one before
            // spending a pairing on it — like a verification failure, a
            // lower-round candidate may still be sound.
            if qc_weighted_timestamp_too_far_ahead(&candidate, self.now) {
                warn!(
                    validator = ?self.me,
                    qc_round = candidate.round().inner(),
                    "Timeout high_qc weighted timestamp too far ahead — trying next-highest"
                );
                continue;
            }
            let Some(verified) = self.verify_qc_sync(topology_schedule, &candidate) else {
                warn!(
                    validator = ?self.me,
                    qc_round = candidate.round().inner(),
                    "Timeout high_qc failed verification — trying next-highest"
                );
                continue;
            };
            return self.try_adopt_verified_qc(&verified);
        }
        Vec::new()
    }

    /// Synchronously verify a QC against the local committee. Used on the
    /// infrequent view-change path; the steady-state QC verification stays
    /// delegated to the consensus pool.
    fn verify_qc_sync(
        &self,
        topology_schedule: &TopologySchedule,
        qc: &QuorumCertificate,
    ) -> Option<Verified<QuorumCertificate>> {
        // The QC was signed by the committee of the block it certifies; resolve
        // it from that block's anchor. `None` (block unknown, or beacon behind)
        // means we can't verify this candidate — skip it, as a failed pairing
        // would.
        let committee = self.committee_of_qc(topology_schedule, qc)?;
        let public_keys = committee_public_keys(committee, self.local_shard);
        let ctx = QcContext {
            network: committee.network(),
            public_keys: &public_keys,
            quorum_threshold: committee.quorum_threshold_for_shard(self.local_shard),
        };
        qc.verify(&ctx).ok()
    }

    /// Synchronise our view to a QC we adopted: a QC for round `r` means the
    /// chain reached `r`, so the successor block is proposed in `r + 1`. Rounds
    /// therefore increase per block, keeping a lagging node in step with the
    /// network as it adopts QCs (via headers, votes, or timeout quorums).
    ///
    /// The safe-vote lock is *not* touched here — `locked_round` only ever
    /// advances on a vote (`create_vote`), never on adopting someone else's QC.
    fn advance_view_for_qc(&mut self, qc: &Verified<QuorumCertificate>) {
        if qc.is_genesis() {
            return;
        }
        let old_view = self.view_change.view;
        if self.view_change.advance_on_qc(qc.round()) {
            info!(
                validator = ?self.me,
                old_view = old_view.inner(),
                new_view = self.view_change.view.inner(),
                qc_height = qc.height().inner(),
                qc_round = qc.round().inner(),
                "View advanced past QC round"
            );
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Transaction admission subscriber
    // ═══════════════════════════════════════════════════════════════════════════

    /// React to transactions newly admitted to the canonical mempool.
    ///
    /// Every gossip arrival, fetch response, RPC submit, and locally produced
    /// tx funnels through `MempoolCoordinator` first; the resulting
    /// `Continuation(ProtocolEvent::TransactionsAdmitted { txs })` event
    /// reaches shard consensus here. Walks pending blocks, populates each one's
    /// `received_transactions` cache for hashes it was waiting on, and
    /// emits any unblocked vote / commit-resume actions via the shared
    /// machinery on [`PendingBlocks`].
    #[instrument(skip(self, topology_schedule, txs), fields(count = txs.len()))]
    pub fn on_transactions_admitted(
        &mut self,
        topology_schedule: &TopologySchedule,
        txs: &[Arc<Verified<RoutableTransaction>>],
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        for tx in txs {
            let wrapped: Arc<Verifiable<RoutableTransaction>> =
                Arc::new(Verifiable::from((**tx).clone()));
            for block_hash in self.pending_blocks.receive_transaction(&wrapped) {
                actions.extend(self.dispatch_block_complete(topology_schedule, block_hash));
            }
        }
        actions
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Receipt Availability
    // ═══════════════════════════════════════════════════════════════════════════

    /// React to finalized waves newly admitted to the canonical execution
    /// store. Same shape as `on_transactions_admitted` and
    /// `on_provisions_admitted`.
    ///
    /// Each wave is validated against its own EC before use: a peer with
    /// divergent local execution could serve a wave whose receipts disagree
    /// with the outcomes the EC attests to. Rejecting such a wave leaves the
    /// pending block incomplete; the fetch protocol retries from a different
    /// peer.
    pub fn on_finalized_waves_admitted(
        &mut self,
        topology_schedule: &TopologySchedule,
        waves: &[Arc<Verifiable<FinalizedWave>>],
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        for fw in waves {
            if let Err(err) = fw.validate_receipts_against_ec() {
                warn!(
                    wave_id = ?fw.wave_id(),
                    ?err,
                    "Rejecting FinalizedWave: receipts inconsistent with its EC"
                );
                continue;
            }
            for block_hash in self.pending_blocks.receive_finalized_wave(fw) {
                actions.extend(self.dispatch_block_complete(topology_schedule, block_hash));
            }
        }
        actions
    }

    /// React to provisions newly admitted to the canonical store.
    ///
    /// Called via state.rs when a `Continuation(ProvisionsAdmitted)` event
    /// reaches the dispatcher — same shape as `on_transactions_admitted`.
    /// Walks pending blocks, populates `received_provisions` for each block
    /// waiting on these hashes, and emits any unblocked vote / commit-resume
    /// actions.
    pub fn on_provisions_admitted(
        &mut self,
        topology_schedule: &TopologySchedule,
        provisions: &[Arc<Verifiable<Provisions>>],
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        for batch in provisions {
            for block_hash in self.pending_blocks.receive_provision(batch) {
                actions.extend(self.dispatch_block_complete(topology_schedule, block_hash));
            }
        }
        actions
    }

    /// Common dispatch tail for a pending block that just became complete:
    /// emit QC-verification / vote actions, then drain any parked commit.
    /// Triggering QC verification (rather than voting directly) is critical:
    /// signatures must be verified before voting even when data arrives late.
    fn dispatch_block_complete(
        &mut self,
        topology_schedule: &TopologySchedule,
        block_hash: BlockHash,
    ) -> Vec<Action> {
        debug!(
            validator = ?self.me,
            block_hash = ?block_hash,
            "Pending block completed"
        );
        self.trigger_qc_verification_or_vote(topology_schedule, block_hash)
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Cleanup
    // ═══════════════════════════════════════════════════════════════════════════

    /// Clean up old state after commit. Drops pending-block, vote, and
    /// commit-tracking entries at or below `committed_height`. Returns
    /// `AbandonFetch` actions for the dropped blocks' orphaned transaction,
    /// finalized-wave, and provision fetches — those no surviving block still
    /// needs — so the FSM releases their slots.
    fn cleanup_old_state(&mut self, committed_height: BlockHeight) -> Vec<Action> {
        let orphaned = self.pending_blocks.prune_committed(committed_height);

        self.votes.cleanup_committed(committed_height);
        self.commits.cleanup_committed(committed_height);

        // Prune committed tx entries older than the retention window. Used
        // for proposal dedup — transactions committed far in the past will
        // have been evicted from mempool already, so stale entries just waste
        // memory.
        self.dedup_index.prune(self.committed_ts);

        // Remote headers are pruned per-shard-tip at insertion time, not by
        // local committed height (remote shards have independent heights).

        self.block_sync.cleanup(committed_height);
        self.verification
            .cleanup(&self.pending_blocks, committed_height);
        self.pending_bytes_deltas
            .retain(|hash, _| self.pending_blocks.get(*hash).is_some());

        orphaned.into_abandon_actions()
    }

    /// Check pending blocks and emit fetch requests for those that have been
    /// waiting longer than the configured timeout.
    ///
    /// Suppressed while syncing so `BlockSync`'s block deliveries aren't
    /// starved by gossip-fetch requests competing for the same slots.
    #[must_use]
    pub fn check_pending_block_fetches(&self, force_immediate: bool) -> Vec<Action> {
        if self.block_sync.is_syncing() {
            return vec![];
        }

        self.pending_blocks.check_fetches(
            self.me,
            self.local_shard,
            self.now,
            self.config.transaction_fetch_timeout,
            force_immediate,
        )
    }

    /// Check if we're behind and need to catch up via sync. Called
    /// periodically by the cleanup timer. Delegates the decision to
    /// [`BlockSyncManager::health_check`] and translates a trigger into a
    /// `start_sync`.
    pub fn check_sync_health(&mut self, topology_schedule: &TopologySchedule) -> Vec<Action> {
        let next_needed_height = self.committed_height.next();
        let has_next_block = self.has_complete_block_at_height(next_needed_height);

        match self.block_sync.health_check(
            self.me,
            self.committed_height,
            self.latest_qc.as_deref(),
            has_next_block,
            &self.commits,
            self.pending_blocks.len(),
            self.view_change.view_changes,
        ) {
            BlockSyncHealthDecision::Idle => vec![],
            BlockSyncHealthDecision::TriggerSync { target_height } => {
                // While a halt recovery pends, a certified tip within the
                // applied frontier commits only under the successor QC this
                // committee must produce live — a sync toward it waits on
                // deliveries that never come, with view changes suppressed
                // the whole while. On a live chain the same re-entry stays
                // legitimate: it re-fetches a certified sibling a peer
                // served that never committed.
                if topology_schedule
                    .recovery_bridge(self.local_shard)
                    .is_some()
                    && self.block_sync.sync_applied_height() >= target_height
                {
                    return vec![];
                }
                self.start_block_sync(target_height)
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Accessors
    // ═══════════════════════════════════════════════════════════════════════════

    /// Drain state root verifications that are ready to dispatch: takes the
    /// pipeline's ready set via
    /// [`VerificationPipeline::take_ready_state_root_verifications`] and
    /// resolves each against the chain view via
    /// [`VerificationPipeline::resolve_ready_state_root_verification`].
    pub fn drain_ready_state_root_verifications(&mut self) -> Vec<ReadyStateRootVerification> {
        let taken = self.verification.take_ready_state_root_verifications();
        if taken.is_empty() {
            return Vec::new();
        }
        let chain = self.chain_view();
        taken
            .into_iter()
            .filter_map(|pending| {
                VerificationPipeline::resolve_ready_state_root_verification(&pending, &chain)
            })
            .collect()
    }

    /// Latch a proposal-retry attempt for after the current dispatch.
    /// Coalesces with any other emitter in the same dispatch; the
    /// post-dispatch drain runs `try_propose` once.
    pub const fn queue_ready_proposal(&mut self) {
        self.verification.queue_ready_proposal();
    }

    /// Drain the proposal-retry latch. Returns `true` once if any emitter
    /// queued a retry during the current dispatch (or the shard coordinator's internal
    /// verification path unblocked a deferred proposal).
    pub fn take_ready_proposal(&mut self) -> bool {
        let ready = self.verification.take_ready_proposal();
        if ready {
            // Drop the tracker's deferred slot so `can_propose` lets the
            // re-entry through. The next `try_propose` call will either
            // successfully dispatch (new `start`) or re-defer with the
            // current parent.
            self.proposal.clear_deferred();
        }
        ready
    }

    /// Get the current committed height.
    #[must_use]
    pub const fn committed_height(&self) -> BlockHeight {
        self.committed_height
    }

    /// Single chokepoint for dropping a pending block. All single-block
    /// removals (failed verification, abort, view-change drop) go through
    /// here so future bookkeeping (metrics, indices, etc.) has one place to
    /// hook. Bulk pruning at commit time uses `cleanup_old_state` which
    /// retains in-place.
    ///
    /// Returns `AbandonFetch` actions for the dropped block's outstanding
    /// transaction, finalized-wave, and provision fetches that no surviving
    /// block still needs — without this the FSM's `in_flight` entries pinned
    /// for this block would linger past its lifetime, eating slots in the
    /// `max_in_flight` cap.
    fn remove_pending_block(&mut self, block_hash: BlockHash) -> Vec<Action> {
        self.pending_blocks
            .remove_orphaning(block_hash)
            .map(OrphanedFetches::into_abandon_actions)
            .unwrap_or_default()
    }

    /// Enforce [`MAX_PENDING_PER_HEIGHT`] before storing a header at `(height,
    /// round)`. Returns `Some(actions)` to proceed — `actions` cancel the
    /// fetches of any block evicted to make room — or `None` if the incoming
    /// header should be dropped because it is itself the entry farthest from
    /// verified progress at a full height.
    ///
    /// The eviction anchor is the verified `high_qc` round, not the local
    /// `view`: `view` is draggable by unverified gossip, so anchoring there
    /// would let a flood pull the metric onto its own rounds and evict the
    /// canonical block. `high_qc` only moves on a verified QC.
    fn enforce_pending_block_cap(
        &mut self,
        height: BlockHeight,
        round: Round,
    ) -> Option<Vec<Action>> {
        if self.pending_blocks.count_at_height(height) < MAX_PENDING_PER_HEIGHT {
            return Some(vec![]);
        }
        let anchor = self.high_qc_round();
        let new_distance = round.inner().abs_diff(anchor.inner());
        let (farthest_hash, farthest_distance) = self
            .pending_blocks
            .farthest_round_at_height(height, anchor)?;
        if new_distance >= farthest_distance {
            return None;
        }
        Some(self.remove_pending_block(farthest_hash))
    }

    /// Get the committed block hash.
    #[must_use]
    pub const fn committed_hash(&self) -> BlockHash {
        self.committed_hash
    }

    /// Get the latest QC.
    #[must_use]
    pub const fn latest_qc(&self) -> Option<&Verified<QuorumCertificate>> {
        self.latest_qc.as_ref()
    }

    /// Get the current view/round.
    #[must_use]
    pub const fn view(&self) -> Round {
        self.view_change.view
    }

    /// Get shard consensus statistics for monitoring.
    #[must_use]
    pub const fn stats(&self) -> ShardStats {
        ShardStats {
            view_changes: self.view_change.view_changes,
            view_syncs: self.view_change.view_syncs,
            current_round: self.view_change.view.inner(),
            committed_height: self.committed_height,
        }
    }

    /// Get shard consensus memory statistics for monitoring collection sizes.
    #[must_use]
    pub fn memory_stats(&self) -> ShardMemoryStats {
        ShardMemoryStats {
            pending_blocks: self.pending_blocks.len(),
            vote_sets: self.votes.vote_sets_len(),
            pending_commits: self.commits.out_of_order_len(),
            pending_commits_awaiting_data: 0,
            received_votes_by_height: self.votes.received_votes_len(),
            committed_tx_lookup: self.dedup_index.tx_retention_len(),
            committed_cert_lookup: self.dedup_index.cert_retention_len(),
            committed_provision_lookup: self.dedup_index.provision_retention_len(),
            pending_qc_verifications: self.verification.pending_qc_verifications_len(),
            verified_qcs: self.verification.verified_qcs_len(),
            pending_state_root_verifications: self
                .verification
                .pending_state_root_verifications_len(),
            buffered_synced_blocks: self.block_sync.buffered_synced_blocks_len(),
            pending_synced_block_verifications: self.block_sync.pending_verification_count(),
            pending_assemblies: self.verification.pending_assembly_count(),
        }
    }

    /// Check if we are the proposer for the current round. `false` when the
    /// in-progress committee isn't yet known (beacon behind).
    #[must_use]
    pub fn is_current_proposer(&self, topology_schedule: &TopologySchedule) -> bool {
        self.tip_committee(topology_schedule)
            .is_some_and(|c| c.proposer_for(self.local_shard, self.view_change.view) == self.me)
    }

    /// Compute the parent hash for the next proposal.
    ///
    /// This is the latest certified block hash, or the committed hash if no QC
    /// exists yet (genesis case).
    #[must_use]
    pub fn proposal_parent_block_hash(&self) -> BlockHash {
        self.latest_qc
            .as_deref()
            .map_or(self.committed_hash, QuorumCertificate::block_hash)
    }

    /// Returns the number of transactions in the QC chain above committed height.
    ///
    /// Callers should request this many extra transactions from the mempool to
    /// compensate for duplicates that will be filtered during proposal building.
    /// This avoids the caller needing to call `collect_qc_chain_hashes` separately.
    #[must_use]
    pub fn dedup_overhead(&self) -> usize {
        let parent_block_hash = self.proposal_parent_block_hash();
        let (_, tx_hashes, _) = self.collect_qc_chain_hashes(parent_block_hash);
        tx_hashes.len()
    }

    /// Walk the QC chain from `parent_block_hash` back to committed height,
    /// collecting certificate, transaction, and provision hashes from
    /// ancestor blocks. Thin wrapper over [`ChainView::collect_ancestor_hashes`]
    /// that supplies the coordinator's `dedup_index`.
    #[must_use]
    pub fn collect_qc_chain_hashes(
        &self,
        parent_block_hash: BlockHash,
    ) -> (
        std::collections::HashSet<WaveId>,
        std::collections::HashSet<TxHash>,
        std::collections::HashSet<ProvisionHash>,
    ) {
        self.chain_view().collect_ancestor_hashes(parent_block_hash)
    }

    /// Get the shard consensus configuration.
    #[must_use]
    pub const fn config(&self) -> &ShardConsensusConfig {
        &self.config
    }

    /// Highest round in which we have voted or timed out (for testing/debugging).
    #[must_use]
    pub const fn last_voted_round(&self) -> Round {
        self.last_voted_round
    }

    /// Our current safe-vote lock round (for testing/debugging).
    #[must_use]
    pub const fn locked_round(&self) -> Round {
        self.locked_round
    }

    /// Snapshot of both safe-vote registers, carried on vote and timeout
    /// signing actions so the runner can persist them ahead of the
    /// signature.
    #[must_use]
    pub const fn safe_vote_registers(&self) -> SafeVoteRegisters {
        SafeVoteRegisters {
            locked_round: self.locked_round,
            last_voted_round: self.last_voted_round,
        }
    }

    /// Check if we have a COMPLETE block at the given height that can be committed.
    ///
    /// This only returns true if the block is fully
    /// constructed and ready for commit. Incomplete pending blocks (waiting for
    /// transactions/certificates) return false.
    ///
    /// Returns true if:
    /// - Height is already committed
    /// - Block is in `pending_blocks` AND is complete (has all data, block constructed)
    /// - Block is in `pending_synced_block_verifications` (synced blocks are always complete)
    /// - Block is in `buffered_synced_blocks` (synced blocks are always complete)
    fn has_complete_block_at_height(&self, height: BlockHeight) -> bool {
        if height <= self.committed_height {
            return true;
        }

        // A synced block admitted by `apply_synced_block` sits above the
        // committed tip awaiting its round-contiguous child; it is complete
        // even though it is not in `pending_blocks`.
        if height <= self.block_sync.sync_applied_height() {
            return true;
        }

        if self.pending_blocks.has_complete_at(height) {
            return true;
        }

        if self.block_sync.has_pending_at_height(height) {
            return true;
        }

        if self.block_sync.has_any_buffered_at_height(height) {
            return true;
        }

        false
    }

    /// Check if this node will propose in the current round.
    ///
    /// Returns true if we are the round's proposer and haven't already voted
    /// (or timed out) in it. Used to avoid destructively taking certificates
    /// from execution state when we won't actually be proposing a block.
    #[must_use]
    pub fn will_propose_next(&self, topology_schedule: &TopologySchedule) -> bool {
        let round = self.view_change.view;
        self.last_voted_round < round
            && self
                .tip_committee(topology_schedule)
                .is_some_and(|c| c.proposer_for(self.local_shard, round) == self.me)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use hyperscale_core::Action;
    use hyperscale_types::{
        BeaconWitnessLeafCount, BeaconWitnessRoot, Bls12381G1PrivateKey, BoundedVec,
        CertificateRoot, Epoch, Hash, InFlightCount, LocalReceiptRoot, MAX_TIMESTAMP_DELAY,
        MAX_TIMESTAMP_RUSH, NetworkDefinition, ProvisionsRoot, RETENTION_HORIZON,
        RoutableTransaction, ShardId, SignerBitfield, TopologySchedule, TopologySnapshot,
        TransactionRoot, ValidatorId, ValidatorInfo, ValidatorSet, VoteCount, VrfProof,
        WeightedTimestamp, generate_bls_keypair, test_utils, zero_bls_signature,
    };

    use super::*;
    use crate::validation::validate_no_duplicate_transactions;

    fn install_complete_block(state: &mut ShardCoordinator, block: &Block) {
        let mut pending = PendingBlock::from_complete_block(
            block,
            vec![],
            None,
            vec![],
            vec![],
            LocalTimestamp::ZERO,
        );
        pending
            .construct_block()
            .expect("complete block constructs cleanly");
        state.pending_blocks.insert(pending);
    }

    fn make_test_state() -> (ShardCoordinator, TopologySchedule) {
        make_test_state_with_validators(4)
    }

    fn make_test_state_with_validators(n: usize) -> (ShardCoordinator, TopologySchedule) {
        make_test_state_with_config(n, ShardConsensusConfig::default())
    }

    fn make_test_state_with_config(
        n: usize,
        config: ShardConsensusConfig,
    ) -> (ShardCoordinator, TopologySchedule) {
        let keys: Vec<Bls12381G1PrivateKey> = (0..n).map(|_| generate_bls_keypair()).collect();

        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| ValidatorInfo {
                validator_id: ValidatorId::new(i as u64),
                public_key: k.public_key(),
            })
            .collect();
        let validator_set = ValidatorSet::new(validators);
        let topology_snapshot =
            TopologySnapshot::new(NetworkDefinition::simulator(), 1, validator_set);

        let state = ShardCoordinator::new(
            ValidatorId::new(0),
            ShardId::ROOT,
            config,
            RecoveredState::default(),
        );
        (state, TopologySchedule::single(Arc::new(topology_snapshot)))
    }

    #[test]
    fn test_proposer_rotation() {
        // proposer_for = round % committee_size
        let (_state, topology_schedule) = make_test_state();
        let shard = ShardId::ROOT;
        assert_eq!(
            topology_schedule.head().proposer_for(shard, Round::new(0)),
            ValidatorId::new(0)
        );
        assert_eq!(
            topology_schedule.head().proposer_for(shard, Round::new(1)),
            ValidatorId::new(1)
        );
        assert_eq!(
            topology_schedule.head().proposer_for(shard, Round::new(2)),
            ValidatorId::new(2)
        );
        assert_eq!(
            topology_schedule.head().proposer_for(shard, Round::new(3)),
            ValidatorId::new(3)
        );
    }

    #[test]
    fn test_should_propose() {
        // Local validator is ValidatorId::new(0) — only proposes when proposer_for = 0.
        let (state, topology_schedule) = make_test_state();
        let shard = state.local_shard;
        let me = state.me;
        assert_eq!(
            topology_schedule.head().proposer_for(shard, Round::new(0)),
            me
        );
        assert_ne!(
            topology_schedule.head().proposer_for(shard, Round::new(1)),
            me
        );
        assert_ne!(
            topology_schedule.head().proposer_for(shard, Round::new(2)),
            me
        );
    }

    /// Committee resolution stalls — it never silently falls back to the head
    /// — when the schedule lacks the committee for the height in progress. A
    /// fresh coordinator extends genesis (weighted timestamp 0, epoch 0); a
    /// schedule holding only a later epoch must make the proposer gate answer
    /// `false` rather than acting under whatever committee happens to be head.
    #[test]
    fn proposer_gate_stalls_when_committee_for_epoch_absent() {
        // me = V1, the round-1 proposer in a fresh 4-member committee.
        let (state, full) = make_multi_validator_state_at(1);
        assert!(state.is_current_proposer(&full));
        assert!(state.will_propose_next(&full));

        // A schedule whose only entry is epoch 5 has no committee for the
        // tip's epoch 0, so resolution returns `None` and the gate stalls.
        let snapshot = Arc::clone(full.head());
        let stalled = TopologySchedule::new(300_000, Epoch::new(5), snapshot);
        assert!(
            !state.is_current_proposer(&stalled),
            "absent committee must stall the proposer gate, not fall back to head",
        );
        assert!(!state.will_propose_next(&stalled));
    }

    /// A uniform-power committee over `ids`, one shard.
    fn committee_snapshot_with_ids(ids: &[u64]) -> TopologySnapshot {
        let validators: Vec<ValidatorInfo> = ids
            .iter()
            .map(|&id| ValidatorInfo {
                validator_id: ValidatorId::new(id),
                public_key: generate_bls_keypair().public_key(),
            })
            .collect();
        TopologySnapshot::new(
            NetworkDefinition::simulator(),
            1,
            ValidatorSet::new(validators),
        )
    }

    /// A complete empty block at `height` whose parent QC carries
    /// `parent_weighted_ms` — the committee anchor `committee_of_block` keys on.
    fn block_with_parent_qc_ts(height: BlockHeight, parent_weighted_ms: u64) -> Block {
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        let parent_qc = QuorumCertificate::new(
            BlockHash::from_raw(Hash::from_bytes(b"anchor_parent")),
            ShardId::ROOT,
            BlockHeight::new(height.inner() - 1),
            BlockHash::ZERO,
            Round::new(0),
            signers,
            zero_bls_signature(),
            WeightedTimestamp::from_millis(parent_weighted_ms),
        );
        let header = BlockHeader::new(
            ShardId::ROOT,
            height,
            parent_qc.block_hash(),
            parent_qc,
            ValidatorId::new(0),
            ProposerTimestamp::from_millis(parent_weighted_ms),
            Round::new(height.inner()),
            false,
            StateRoot::from_raw(Hash::from_bytes(
                &[u8::try_from(height.inner() % 251).unwrap(); 32],
            )),
            TransactionRoot::ZERO,
            CertificateRoot::ZERO,
            LocalReceiptRoot::ZERO,
            ProvisionsRoot::ZERO,
            Vec::new(),
            std::collections::BTreeMap::new(),
            InFlightCount::ZERO,
            BeaconWitnessRoot::ZERO,
            BeaconWitnessLeafCount::ZERO,
            BeaconWitnessLeafCount::ZERO,
            None,
            None,
        );
        Block::Live {
            header,
            transactions: Arc::new(BoundedVec::new()),
            certificates: Arc::new(BoundedVec::new()),
            provisions: Arc::new(BoundedVec::new()),
            ready_signals: Arc::new(BoundedVec::new()),
            equivocations: Arc::new(BoundedVec::new()),
            reshape_trigger: None,
            randomness_reveal: VrfProof::ZERO,
        }
    }

    #[test]
    fn committee_of_block_keys_on_parent_qc_weighted_timestamp() {
        // committee(block) == at(parent_qc.weighted_timestamp()). A block whose
        // parent QC weighted timestamp sits just below an epoch boundary resolves
        // to the prior epoch's committee — the keying that lets every honest node
        // verify a boundary-straddling block under committee_(N-1), and its
        // successor (parent QC at the boundary) under committee_N.
        const ED: u64 = 1_000;
        let shard = ShardId::ROOT;

        let epoch0 = Arc::new(committee_snapshot_with_ids(&[0, 1, 2, 3]));
        let epoch1 = Arc::new(committee_snapshot_with_ids(&[10, 11, 12, 13]));
        let mut schedule = TopologySchedule::new(ED, Epoch::new(0), Arc::clone(&epoch0));
        schedule.insert(Epoch::new(1), Arc::clone(&epoch1));

        let mut state = ShardCoordinator::new(
            ValidatorId::new(0),
            shard,
            ShardConsensusConfig::default(),
            RecoveredState::default(),
        );

        // Straddling block: parent QC weighted timestamp 999ms — epoch 0.
        let straddle = block_with_parent_qc_ts(BlockHeight::new(5), ED - 1);
        let straddle_hash = straddle.hash();
        install_complete_block(&mut state, &straddle);

        // Its successor: parent QC weighted timestamp 1000ms — epoch 1.
        let successor = block_with_parent_qc_ts(BlockHeight::new(6), ED);
        let successor_hash = successor.hash();
        install_complete_block(&mut state, &successor);

        let straddle_committee = state
            .committee_of_block(&schedule, straddle_hash)
            .expect("epoch 0 committee is in the schedule");
        assert_eq!(
            straddle_committee.committee_for_shard(shard),
            epoch0.committee_for_shard(shard),
            "a parent QC weighted timestamp below N·ED must resolve to committee_(N-1)",
        );

        let successor_committee = state
            .committee_of_block(&schedule, successor_hash)
            .expect("epoch 1 committee is in the schedule");
        assert_eq!(
            successor_committee.committee_for_shard(shard),
            epoch1.committee_for_shard(shard),
            "a parent QC weighted timestamp at N·ED must resolve to committee_N",
        );
    }

    #[test]
    fn vote_path_rejects_anchor_regressing_below_parent() {
        // The parent QC's weighted timestamp rides outside the QC's signed
        // message, so a Byzantine proposer can rewrite it on a genuine QC to
        // steer the block's committee to an older retained epoch. Honest
        // aggregation floor-clamps every vote to the voted block's own
        // anchor, so a genuine QC never regresses below the parent's anchor:
        // a child carrying one must not reach verification or a vote. One
        // carrying an equal anchor (a fallback's all-at-floor mean) must.
        let (mut state, topology_schedule) = make_test_state();
        state.set_time(LocalTimestamp::from_millis(100_000));

        let parent = block_with_parent_qc_ts(BlockHeight::new(5), 5_000);
        let parent_hash = parent.hash();
        install_complete_block(&mut state, &parent);

        let child_with_anchor = |weighted_ms: u64, tag: &[u8]| {
            let mut signers = SignerBitfield::new(4);
            signers.set(0);
            signers.set(1);
            signers.set(2);
            let parent_qc = QuorumCertificate::new(
                parent_hash,
                ShardId::ROOT,
                BlockHeight::new(5),
                parent.header().parent_block_hash(),
                Round::new(5),
                signers,
                zero_bls_signature(),
                WeightedTimestamp::from_millis(weighted_ms),
            );
            let header = BlockHeader::new(
                ShardId::ROOT,
                BlockHeight::new(6),
                parent_hash,
                parent_qc,
                ValidatorId::new(2),
                ProposerTimestamp::from_millis(weighted_ms),
                Round::new(6),
                false,
                StateRoot::from_raw(Hash::from_bytes(tag)),
                TransactionRoot::ZERO,
                CertificateRoot::ZERO,
                LocalReceiptRoot::ZERO,
                ProvisionsRoot::ZERO,
                Vec::new(),
                std::collections::BTreeMap::new(),
                InFlightCount::ZERO,
                BeaconWitnessRoot::ZERO,
                BeaconWitnessLeafCount::ZERO,
                BeaconWitnessLeafCount::ZERO,
                None,
                None,
            );
            Block::Live {
                header,
                transactions: Arc::new(BoundedVec::new()),
                certificates: Arc::new(BoundedVec::new()),
                provisions: Arc::new(BoundedVec::new()),
                ready_signals: Arc::new(BoundedVec::new()),
                equivocations: Arc::new(BoundedVec::new()),
                reshape_trigger: None,
                randomness_reveal: VrfProof::ZERO,
            }
        };

        // Anchor regresses below the parent's (5_000): declined outright.
        let regressing = child_with_anchor(4_999, b"regressing");
        let regressing_hash = regressing.hash();
        install_complete_block(&mut state, &regressing);
        let actions = state.trigger_qc_verification_or_vote(&topology_schedule, regressing_hash);
        assert!(
            actions.is_empty(),
            "regressing anchor must not reach verification: {actions:?}"
        );

        // Anchor equal to the parent's: proceeds to QC verification.
        let level = child_with_anchor(5_000, b"level");
        let level_hash = level.hash();
        install_complete_block(&mut state, &level);
        let actions = state.trigger_qc_verification_or_vote(&topology_schedule, level_hash);
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::VerifyQcSignature { .. })),
            "level anchor must proceed to parent-QC verification: {actions:?}"
        );
    }

    fn make_header_at_height(height: BlockHeight, timestamp_ms: u64) -> BlockHeader {
        // Rounds increase per block, so the happy-path round equals the height;
        // the proposer is then committee[round % 4] = committee[height % 4].
        let round = Round::new(height.inner());
        BlockHeader::new(
            ShardId::ROOT,
            height,
            BlockHash::from_raw(Hash::from_bytes(b"parent")),
            QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT),
            ValidatorId::new(height.inner() % 4),
            ProposerTimestamp::from_millis(timestamp_ms),
            round,
            false,
            StateRoot::ZERO,
            TransactionRoot::ZERO,
            CertificateRoot::ZERO,
            LocalReceiptRoot::ZERO,
            ProvisionsRoot::ZERO,
            Vec::new(),
            std::collections::BTreeMap::new(),
            InFlightCount::ZERO,
            BeaconWitnessRoot::ZERO,
            BeaconWitnessLeafCount::ZERO,
            BeaconWitnessLeafCount::ZERO,
            None,
            None,
        )
    }

    fn make_test_qc(block_hash: BlockHash, height: BlockHeight) -> Verified<QuorumCertificate> {
        // SAFETY: synthetic test fixture, no real signature.
        Verified::<QuorumCertificate>::new_unchecked_for_test(QuorumCertificate::new(
            block_hash,
            ShardId::ROOT,
            height,
            BlockHash::ZERO,
            Round::new(0),
            SignerBitfield::empty(),
            zero_bls_signature(),
            WeightedTimestamp::from_millis(100_000),
        ))
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // QC Signature Verification Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_qc_signature_verification_delegates_to_runner() {
        let (mut state, topology_schedule) = make_multi_validator_state_at(1);
        state.set_time(LocalTimestamp::from_millis(100_000));

        // committed_height = 1 avoids triggering sync on the non-genesis parent QC.
        let parent_block_hash = BlockHash::from_raw(Hash::from_bytes(b"parent_block"));
        state.committed_height = BlockHeight::new(1);
        state.committed_hash = parent_block_hash;

        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        let parent_qc = {
            let __qc = make_test_qc(parent_block_hash, BlockHeight::new(1));
            QuorumCertificate::new(
                __qc.block_hash(),
                __qc.shard_id(),
                __qc.height(),
                __qc.parent_block_hash(),
                __qc.round(),
                signers,
                __qc.aggregated_signature(),
                WeightedTimestamp::from_millis(99_000),
            )
        };
        let header = {
            let __h = make_header_at_height(BlockHeight::new(2), 100_000);
            BlockHeader::new(
                __h.shard_id(),
                __h.height(),
                parent_block_hash,
                parent_qc,
                __h.proposer(),
                __h.timestamp(),
                __h.round(),
                __h.is_fallback(),
                __h.state_root(),
                __h.transaction_root(),
                __h.certificate_root(),
                __h.local_receipt_root(),
                __h.provision_root(),
                __h.waves().clone().into_inner(),
                __h.provision_tx_roots().clone().into_inner(),
                __h.in_flight(),
                BeaconWitnessRoot::ZERO,
                BeaconWitnessLeafCount::ZERO,
                BeaconWitnessLeafCount::ZERO,
                None,
                None,
            )
        };

        let actions = state.on_block_header(
            &topology_schedule,
            &header,
            BlockManifest::default(),
            |_| None,
            |_| None,
            |_| None,
        );
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::VerifyQcSignature { .. }))
        );
    }

    /// A header can both trigger block sync (missing parent) and itself be
    /// dropped (its committee epoch isn't in the schedule yet — the local
    /// beacon is behind). The sync trigger latches the coordinator's syncing
    /// flag, and the runner only learns the target from the returned
    /// `StartBlockSync` action, so the drop path must still return it.
    /// Swallowing it leaves the flag set with no fetch ever issued, and the
    /// flag blocks every retrigger — a permanent sync wedge.
    #[test]
    fn dropped_header_still_returns_the_sync_trigger_it_latched() {
        let (mut state, full) = make_multi_validator_state_at(1);

        // Retain only epoch 0; the header below keys its committee at epoch
        // 10, which resolves as not-yet-committed and drops the header.
        let behind = TopologySchedule::new(5_000, Epoch::GENESIS, Arc::clone(full.head()));

        let parent_height = BlockHeight::new(9);
        let parent_block_hash = BlockHash::from_raw(Hash::from_bytes(b"missing_parent"));
        let parent_qc = QuorumCertificate::new(
            parent_block_hash,
            ShardId::ROOT,
            parent_height,
            BlockHash::from_raw(Hash::from_bytes(b"grandparent")),
            Round::new(9),
            SignerBitfield::new(4),
            zero_bls_signature(),
            WeightedTimestamp::from_millis(50_000),
        );
        let header = BlockHeader::new(
            ShardId::ROOT,
            BlockHeight::new(10),
            parent_block_hash,
            parent_qc,
            ValidatorId::new(2),
            ProposerTimestamp::from_millis(50_000),
            Round::new(10),
            false,
            StateRoot::ZERO,
            TransactionRoot::ZERO,
            CertificateRoot::ZERO,
            LocalReceiptRoot::ZERO,
            ProvisionsRoot::ZERO,
            Vec::new(),
            std::collections::BTreeMap::new(),
            InFlightCount::ZERO,
            BeaconWitnessRoot::ZERO,
            BeaconWitnessLeafCount::ZERO,
            BeaconWitnessLeafCount::ZERO,
            None,
            None,
        );

        let actions = state.on_block_header(
            &behind,
            &header,
            BlockManifest::default(),
            |_| None,
            |_| None,
            |_| None,
        );

        assert!(
            state.is_block_syncing(),
            "missing parent must latch the syncing flag"
        );
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::StartBlockSync { target } if *target == parent_height
            )),
            "the dropped header's sync trigger must reach the runner"
        );
    }

    /// Build a complete empty block at `(height=1, round)` extending the
    /// committed tip under a genesis parent QC — so the round gap is `round`.
    fn empty_block_at_round(committed_hash: BlockHash, round: u64) -> Block {
        let header = BlockHeader::new(
            ShardId::ROOT,
            BlockHeight::new(1),
            committed_hash,
            QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT),
            ValidatorId::new(round % 4),
            ProposerTimestamp::from_millis(100_000),
            Round::new(round),
            false,
            StateRoot::from_raw(Hash::from_bytes(&[u8::try_from(round % 251).unwrap(); 32])),
            TransactionRoot::ZERO,
            CertificateRoot::ZERO,
            LocalReceiptRoot::ZERO,
            ProvisionsRoot::ZERO,
            Vec::new(),
            std::collections::BTreeMap::new(),
            InFlightCount::ZERO,
            BeaconWitnessRoot::ZERO,
            BeaconWitnessLeafCount::ZERO,
            BeaconWitnessLeafCount::ZERO,
            None,
            None,
        );
        Block::Live {
            header,
            transactions: Arc::new(BoundedVec::new()),
            certificates: Arc::new(BoundedVec::new()),
            provisions: Arc::new(BoundedVec::new()),
            ready_signals: Arc::new(BoundedVec::new()),
            equivocations: Arc::new(BoundedVec::new()),
            reshape_trigger: None,
            randomness_reveal: VrfProof::ZERO,
        }
    }

    #[test]
    fn large_round_gap_header_skips_speculative_verification() {
        // The beacon-witness verification derives one leaf per skipped round, so
        // a header whose round is far above its parent QC's round (here a
        // genesis parent_qc at a high round) would be O(round-gap) to verify. It
        // must be left for block-sync, not verified speculatively.
        let (mut state, topology_schedule) = make_test_state();
        state.set_time(LocalTimestamp::from_millis(100_000));
        let committed_hash = BlockHash::from_raw(Hash::from_bytes(b"committed_tip"));
        state.committed_hash = committed_hash;

        // Just below the bound: verification is dispatched.
        let near = empty_block_at_round(committed_hash, SPECULATIVE_VERIFY_GAP - 1);
        let near_hash = near.hash();
        let near_round = near.header().round();
        install_complete_block(&mut state, &near);
        let near_actions = state.try_vote_on_block(
            &topology_schedule,
            near_hash,
            BlockHeight::new(1),
            near_round,
        );
        assert!(
            !near_actions.is_empty(),
            "a within-bound round gap should still verify",
        );

        // Beyond the bound: no verification, no action.
        let far = empty_block_at_round(committed_hash, SPECULATIVE_VERIFY_GAP + 10);
        let far_hash = far.hash();
        let far_round = far.header().round();
        install_complete_block(&mut state, &far);
        let far_actions =
            state.try_vote_on_block(&topology_schedule, far_hash, BlockHeight::new(1), far_round);
        assert!(
            far_actions.is_empty(),
            "a round gap beyond the bound must skip verification: {far_actions:?}",
        );
    }

    #[test]
    fn stall_witnessed_gap_remains_votable() {
        // After a long certification stall the recovery block's round gap
        // equals the rounds the local pacemaker burned — far beyond the
        // static floor. The bound slides with `view - locked_round`, so the
        // block is still verified; without that the shard would wedge
        // permanently once the view drifted past the floor (every timed-out
        // round is vote-burned, so no older round can recover it).
        let (mut state, topology_schedule) = make_test_state();
        state.set_time(LocalTimestamp::from_millis(100_000));
        let committed_hash = BlockHash::from_raw(Hash::from_bytes(b"committed_tip"));
        state.committed_hash = committed_hash;

        // The pacemaker witnessed a drift far past the floor.
        let stalled_view = SPECULATIVE_VERIFY_GAP * 3;
        state.view_change.view = Round::new(stalled_view);

        // Recovery block at the current view, extending the stuck QC: its
        // gap exceeds the floor but not the witnessed drift.
        let recovery = empty_block_at_round(committed_hash, stalled_view);
        let recovery_hash = recovery.hash();
        let recovery_round = recovery.header().round();
        install_complete_block(&mut state, &recovery);
        let actions = state.try_vote_on_block(
            &topology_schedule,
            recovery_hash,
            BlockHeight::new(1),
            recovery_round,
        );
        assert!(
            !actions.is_empty(),
            "a gap the local pacemaker witnessed must still verify",
        );

        // Beyond even the witnessed drift: skipped.
        let beyond = empty_block_at_round(committed_hash, stalled_view + 10);
        let beyond_hash = beyond.hash();
        let beyond_round = beyond.header().round();
        install_complete_block(&mut state, &beyond);
        let actions = state.try_vote_on_block(
            &topology_schedule,
            beyond_hash,
            BlockHeight::new(1),
            beyond_round,
        );
        assert!(
            actions.is_empty(),
            "a gap beyond the witnessed drift must skip verification: {actions:?}",
        );
    }

    #[test]
    fn timeout_quorum_advance_clamps_at_pacemaker_ceiling() {
        // One round past `high_qc + MAX_ROUND_GAP` nothing is wire-valid and
        // no timeout tallies, so a quorum at the ceiling must park the view
        // there rather than advance into the dead round.
        let (mut state, topology_schedule) = make_test_state();
        state.set_time(LocalTimestamp::from_millis(100_000));

        let ceiling = state.max_pacemaker_round();
        state.view_change.view = ceiling;
        let _ = state.advance_on_timeout_quorum(&topology_schedule, ceiling);
        assert_eq!(
            state.view_change.view, ceiling,
            "the view must never pass the pacemaker ceiling"
        );

        // A quorum below the ceiling still advances normally.
        let below = Round::new(ceiling.inner() - 10);
        state.view_change.view = below;
        let _ = state.advance_on_timeout_quorum(&topology_schedule, below);
        assert_eq!(state.view_change.view, below.next());
    }

    #[test]
    fn header_flood_at_one_round_is_capped() {
        // A Byzantine proposer can mint many distinct hashes at one
        // (height, round) by varying the unsigned content roots. Only a small
        // allowance is stored; the rest are dropped before storage/verification.
        let (mut state, topology_schedule) = make_test_state();
        state.set_time(LocalTimestamp::from_millis(100_000));
        let committed_hash = BlockHash::from_raw(Hash::from_bytes(b"genesis_tip"));
        state.committed_hash = committed_hash;

        // Round 1's proposer is committee[1]; vary the state root to mint
        // distinct headers all validly attributed to that proposer.
        for i in 0..(MAX_HEADERS_PER_HEIGHT_ROUND + 3) {
            let header = BlockHeader::new(
                ShardId::ROOT,
                BlockHeight::new(1),
                committed_hash,
                QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT),
                ValidatorId::new(1),
                ProposerTimestamp::from_millis(100_000),
                Round::new(1),
                false,
                StateRoot::from_raw(Hash::from_bytes(&[u8::try_from(i).unwrap(); 32])),
                TransactionRoot::ZERO,
                CertificateRoot::ZERO,
                LocalReceiptRoot::ZERO,
                ProvisionsRoot::ZERO,
                Vec::new(),
                std::collections::BTreeMap::new(),
                InFlightCount::ZERO,
                BeaconWitnessRoot::ZERO,
                BeaconWitnessLeafCount::ZERO,
                BeaconWitnessLeafCount::ZERO,
                None,
                None,
            );
            let _ = state.on_block_header(
                &topology_schedule,
                &header,
                BlockManifest::default(),
                |_| None,
                |_| None,
                |_| None,
            );
        }

        assert_eq!(
            state
                .pending_blocks
                .count_at(BlockHeight::new(1), Round::new(1)),
            MAX_HEADERS_PER_HEIGHT_ROUND,
            "distinct headers at one (height, round) must be capped",
        );
    }

    #[test]
    fn header_flood_across_rounds_is_capped_per_height() {
        // A Byzantine proposer plants one genesis-QC header per round it
        // proposes for, all at the tip height. The per-height cap bounds how
        // many are stored; eviction anchored to high_qc keeps the rounds
        // nearest verified progress and sheds the far flood rounds.
        let (mut state, topology_schedule) = make_test_state();
        state.set_time(LocalTimestamp::from_millis(100_000));
        let committed_hash = BlockHash::from_raw(Hash::from_bytes(b"genesis_tip"));
        state.committed_hash = committed_hash;

        let round_header = |round: u64| {
            BlockHeader::new(
                ShardId::ROOT,
                BlockHeight::new(1),
                committed_hash,
                QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT),
                ValidatorId::new(round % 4),
                ProposerTimestamp::from_millis(100_000),
                Round::new(round),
                false,
                StateRoot::ZERO,
                TransactionRoot::ZERO,
                CertificateRoot::ZERO,
                LocalReceiptRoot::ZERO,
                ProvisionsRoot::ZERO,
                Vec::new(),
                std::collections::BTreeMap::new(),
                InFlightCount::ZERO,
                BeaconWitnessRoot::ZERO,
                BeaconWitnessLeafCount::ZERO,
                BeaconWitnessLeafCount::ZERO,
                None,
                None,
            )
        };

        let cap = u64::try_from(MAX_PENDING_PER_HEIGHT).unwrap();
        for round in 1..=cap + 6 {
            let header = round_header(round);
            let _ = state.on_block_header(
                &topology_schedule,
                &header,
                BlockManifest::default(),
                |_| None,
                |_| None,
                |_| None,
            );
        }

        assert_eq!(
            state.pending_blocks.count_at_height(BlockHeight::new(1)),
            MAX_PENDING_PER_HEIGHT,
            "distinct-round headers at one height must be capped",
        );
        // high_qc sits at the genesis round, so the lowest rounds survive and
        // the farthest flood rounds are shed.
        assert!(state.pending_blocks.contains_key(round_header(1).hash()));
        assert!(
            !state
                .pending_blocks
                .contains_key(round_header(cap + 6).hash())
        );
    }

    #[test]
    fn header_beyond_lookahead_is_not_stored() {
        // A forged full-bitfield `parent_qc` passes `validate_header` (the
        // signature is checked later) at any height, so a header far above the
        // committed tip is well-formed — but it must not be stored.
        let (mut state, topology_schedule) = make_test_state();
        state.set_time(LocalTimestamp::from_millis(1_000_000));
        let now_ms = state.now.as_millis();

        let forged_future_header = |height: u64| {
            let round = 4u64; // proposer_for(4) == committee[0]
            let mut signers = SignerBitfield::new(4);
            signers.set(0);
            signers.set(1);
            signers.set(2);
            let parent_block_hash = BlockHash::from_raw(Hash::from_bytes(b"forged_parent"));
            let parent_qc = QuorumCertificate::new(
                parent_block_hash,
                ShardId::ROOT,
                BlockHeight::new(height - 1),
                BlockHash::ZERO,
                Round::new(round),
                signers,
                zero_bls_signature(),
                WeightedTimestamp::from_millis(now_ms - 5_000),
            );
            BlockHeader::new(
                ShardId::ROOT,
                BlockHeight::new(height),
                parent_block_hash,
                parent_qc,
                ValidatorId::new(round % 4),
                ProposerTimestamp::from_millis(now_ms),
                Round::new(round),
                false,
                StateRoot::ZERO,
                TransactionRoot::ZERO,
                CertificateRoot::ZERO,
                LocalReceiptRoot::ZERO,
                ProvisionsRoot::ZERO,
                Vec::new(),
                std::collections::BTreeMap::new(),
                InFlightCount::ZERO,
                BeaconWitnessRoot::ZERO,
                BeaconWitnessLeafCount::ZERO,
                BeaconWitnessLeafCount::ZERO,
                None,
                None,
            )
        };

        // At the lookahead edge (committed is genesis): stored.
        let edge = forged_future_header(MAX_HEADER_HEIGHT_LOOKAHEAD);
        let _ = state.on_block_header(
            &topology_schedule,
            &edge,
            BlockManifest::default(),
            |_| None,
            |_| None,
            |_| None,
        );
        assert!(
            state.pending_blocks.contains_key(edge.hash()),
            "a header at the lookahead edge must be stored",
        );

        // One past the edge: dropped before storage.
        let beyond = forged_future_header(MAX_HEADER_HEIGHT_LOOKAHEAD + 1);
        let _ = state.on_block_header(
            &topology_schedule,
            &beyond,
            BlockManifest::default(),
            |_| None,
            |_| None,
            |_| None,
        );
        assert!(
            !state.pending_blocks.contains_key(beyond.hash()),
            "a header beyond the lookahead must not be stored",
        );
    }

    /// `absorb_parent_qc_from_header` must NOT mutate `latest_qc` until the
    /// parent QC's BLS signature has been verified — otherwise a Byzantine
    /// proposer can forge a signers-pass-but-signature-invalid QC and have
    /// us advance the chain (and the view, via `advance_view_for_qc`) on a
    /// non-existent quorum.
    #[test]
    fn test_header_with_unverified_parent_qc_does_not_update_latest_qc() {
        let (mut state, topology_schedule) = make_multi_validator_state_at(1);
        state.set_time(LocalTimestamp::from_millis(100_000));

        let parent_block_hash = BlockHash::from_raw(Hash::from_bytes(b"parent_block"));
        state.committed_height = BlockHeight::new(1);
        state.committed_hash = parent_block_hash;
        let prior_latest_qc = state.latest_qc.clone();

        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        let parent_qc = {
            let __qc = make_test_qc(parent_block_hash, BlockHeight::new(1));
            QuorumCertificate::new(
                __qc.block_hash(),
                __qc.shard_id(),
                __qc.height(),
                __qc.parent_block_hash(),
                __qc.round(),
                signers,
                __qc.aggregated_signature(),
                WeightedTimestamp::from_millis(99_000),
            )
        };
        let header = {
            let __h = make_header_at_height(BlockHeight::new(2), 100_000);
            BlockHeader::new(
                __h.shard_id(),
                __h.height(),
                parent_block_hash,
                parent_qc,
                __h.proposer(),
                __h.timestamp(),
                __h.round(),
                __h.is_fallback(),
                __h.state_root(),
                __h.transaction_root(),
                __h.certificate_root(),
                __h.local_receipt_root(),
                __h.provision_root(),
                __h.waves().clone().into_inner(),
                __h.provision_tx_roots().clone().into_inner(),
                __h.in_flight(),
                BeaconWitnessRoot::ZERO,
                BeaconWitnessLeafCount::ZERO,
                BeaconWitnessLeafCount::ZERO,
                None,
                None,
            )
        };

        let _ = state.on_block_header(
            &topology_schedule,
            &header,
            BlockManifest::default(),
            |_| None,
            |_| None,
            |_| None,
        );

        // latest_qc must still be the pre-header value — adoption is gated
        // on BLS verification, which hasn't happened yet.
        assert_eq!(
            state.latest_qc.as_deref().map(QuorumCertificate::height),
            prior_latest_qc.as_deref().map(QuorumCertificate::height),
            "unverified parent_qc must not advance latest_qc"
        );
    }

    /// After successful BLS verification, the deferred `latest_qc`
    /// adoption should run as part of `on_qc_signature_verified` — so
    /// adoption is just one verify-round late, not lost entirely.
    #[test]
    fn test_qc_signature_verified_success_adopts_latest_qc() {
        let (mut state, topology_schedule) = make_multi_validator_state_at(1);
        state.set_time(LocalTimestamp::from_millis(100_000));

        let parent_block_hash = BlockHash::from_raw(Hash::from_bytes(b"parent_block"));
        state.committed_height = BlockHeight::new(1);
        state.committed_hash = parent_block_hash;

        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        let parent_qc = {
            let __qc = make_test_qc(parent_block_hash, BlockHeight::new(1));
            QuorumCertificate::new(
                __qc.block_hash(),
                __qc.shard_id(),
                __qc.height(),
                __qc.parent_block_hash(),
                __qc.round(),
                signers,
                __qc.aggregated_signature(),
                WeightedTimestamp::from_millis(99_000),
            )
        };
        let header = {
            let __h = make_header_at_height(BlockHeight::new(2), 100_000);
            BlockHeader::new(
                __h.shard_id(),
                __h.height(),
                parent_block_hash,
                parent_qc,
                __h.proposer(),
                __h.timestamp(),
                __h.round(),
                __h.is_fallback(),
                __h.state_root(),
                __h.transaction_root(),
                __h.certificate_root(),
                __h.local_receipt_root(),
                __h.provision_root(),
                __h.waves().clone().into_inner(),
                __h.provision_tx_roots().clone().into_inner(),
                __h.in_flight(),
                BeaconWitnessRoot::ZERO,
                BeaconWitnessLeafCount::ZERO,
                BeaconWitnessLeafCount::ZERO,
                None,
                None,
            )
        };
        let block_hash = header.hash();

        let _ = state.on_block_header(
            &topology_schedule,
            &header,
            BlockManifest::default(),
            |_| None,
            |_| None,
            |_| None,
        );
        assert_ne!(
            state.latest_qc.as_deref().map(QuorumCertificate::height),
            Some(BlockHeight::new(1)),
            "precondition: latest_qc not yet at height 1"
        );

        // SAFETY: synthetic test fixture, parent_qc was constructed locally,
        // so wrapping it as verified models the action arm's success result.
        let verified =
            Verified::<QuorumCertificate>::new_unchecked_for_test(header.parent_qc().clone());
        let _ = state.on_qc_signature_verified(&topology_schedule, block_hash, Ok(verified));
        assert_eq!(
            state.latest_qc.as_deref().map(QuorumCertificate::height),
            Some(BlockHeight::new(1)),
            "successful verification must trigger the deferred adoption"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // synthetic QC/header fixtures, one block field per line
    fn test_qc_signature_verified_success_triggers_vote() {
        let (mut state, topology_schedule) = make_multi_validator_state_at(1);
        state.set_time(LocalTimestamp::from_millis(100_000));

        let parent_block = Block::Live {
            header: make_header_at_height(BlockHeight::new(1), 99_000),
            transactions: Arc::new(BoundedVec::new()),
            certificates: Arc::new(BoundedVec::new()),
            provisions: Arc::new(BoundedVec::new()),
            ready_signals: Arc::new(BoundedVec::new()),
            equivocations: Arc::new(BoundedVec::new()),
            reshape_trigger: None,
            randomness_reveal: VrfProof::ZERO,
        };
        let parent_block_hash = parent_block.hash();
        state.committed_height = BlockHeight::new(1);
        state.committed_hash = parent_block_hash;
        install_complete_block(&mut state, &parent_block);

        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        let parent_qc = {
            let __qc = make_test_qc(parent_block_hash, BlockHeight::new(1));
            QuorumCertificate::new(
                __qc.block_hash(),
                __qc.shard_id(),
                __qc.height(),
                __qc.parent_block_hash(),
                __qc.round(),
                signers,
                __qc.aggregated_signature(),
                WeightedTimestamp::from_millis(99_000),
            )
        };
        let header = {
            let __h = make_header_at_height(BlockHeight::new(2), 100_000);
            BlockHeader::new(
                __h.shard_id(),
                __h.height(),
                parent_block_hash,
                parent_qc,
                __h.proposer(),
                __h.timestamp(),
                __h.round(),
                __h.is_fallback(),
                __h.state_root(),
                __h.transaction_root(),
                __h.certificate_root(),
                __h.local_receipt_root(),
                __h.provision_root(),
                __h.waves().clone().into_inner(),
                __h.provision_tx_roots().clone().into_inner(),
                __h.in_flight(),
                BeaconWitnessRoot::ZERO,
                BeaconWitnessLeafCount::ZERO,
                BeaconWitnessLeafCount::ZERO,
                None,
                None,
            )
        };
        let block_hash = header.hash();

        let _ = state.on_block_header(
            &topology_schedule,
            &header,
            BlockManifest::default(),
            |_| None,
            |_| None,
            |_| None,
        );

        // QC verified — but state root verification is still pending, so no vote yet.
        // SAFETY: synthetic test fixture, parent_qc built locally.
        let verified =
            Verified::<QuorumCertificate>::new_unchecked_for_test(header.parent_qc().clone());
        let after_qc = state.on_qc_signature_verified(&topology_schedule, block_hash, Ok(verified));
        assert!(
            !after_qc
                .iter()
                .any(|a| matches!(a, Action::SignAndBroadcastBlockVote { .. }))
        );

        // State root completes — beacon witness root still pending.
        let state_root_ok = Ok(Verified::<StateRoot>::new_unchecked_for_test(
            StateRoot::ZERO,
        ));
        let after_state =
            state.on_state_root_verified(&topology_schedule, block_hash, state_root_ok, 0);
        assert!(
            !after_state
                .iter()
                .any(|a| matches!(a, Action::SignAndBroadcastBlockVote { .. }))
        );

        // Beacon witness root completes — now we vote.
        let beacon_root = state
            .pending_blocks
            .get_block(block_hash)
            .expect("pending block")
            .header()
            .beacon_witness_root();
        let after_roots = state.on_beacon_witness_root_verified(
            &topology_schedule,
            block_hash,
            Ok(Verified::<BeaconWitnessRoot>::new_unchecked_for_test(
                beacon_root,
            )),
        );
        assert!(
            after_roots
                .iter()
                .any(|a| matches!(a, Action::SignAndBroadcastBlockVote { .. }))
        );
    }

    #[test]
    fn test_qc_signature_verified_failure_rejects_block() {
        let (mut state, topology_schedule) = make_multi_validator_state_at(1);
        state.set_time(LocalTimestamp::from_millis(100_000));

        let parent_block_hash = BlockHash::from_raw(Hash::from_bytes(b"parent_block"));
        state.committed_height = BlockHeight::new(1);
        state.committed_hash = parent_block_hash;

        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        let parent_qc = {
            let __qc = make_test_qc(parent_block_hash, BlockHeight::new(1));
            QuorumCertificate::new(
                __qc.block_hash(),
                __qc.shard_id(),
                __qc.height(),
                __qc.parent_block_hash(),
                __qc.round(),
                signers,
                __qc.aggregated_signature(),
                WeightedTimestamp::from_millis(99_000),
            )
        };
        let header = {
            let __h = make_header_at_height(BlockHeight::new(2), 100_000);
            BlockHeader::new(
                __h.shard_id(),
                __h.height(),
                parent_block_hash,
                parent_qc,
                __h.proposer(),
                __h.timestamp(),
                __h.round(),
                __h.is_fallback(),
                __h.state_root(),
                __h.transaction_root(),
                __h.certificate_root(),
                __h.local_receipt_root(),
                __h.provision_root(),
                __h.waves().clone().into_inner(),
                __h.provision_tx_roots().clone().into_inner(),
                __h.in_flight(),
                BeaconWitnessRoot::ZERO,
                BeaconWitnessLeafCount::ZERO,
                BeaconWitnessLeafCount::ZERO,
                None,
                None,
            )
        };
        let block_hash = header.hash();

        let _ = state.on_block_header(
            &topology_schedule,
            &header,
            BlockManifest::default(),
            |_| None,
            |_| None,
            |_| None,
        );
        assert!(state.pending_blocks.contains_key(block_hash));

        let actions = state.on_qc_signature_verified(
            &topology_schedule,
            block_hash,
            Err(QcVerifyError::InvalidSignature),
        );
        assert!(actions.is_empty());
        assert!(!state.pending_blocks.contains_key(block_hash));
    }

    #[test]
    fn test_genesis_qc_skips_verification() {
        let (mut state, topology_schedule) = make_multi_validator_state_at(1);

        state.set_time(LocalTimestamp::from_millis(100_000));

        // Genesis QC has no signature — verification must be skipped, not queued.
        let header = {
            let __h = make_header_at_height(BlockHeight::new(1), 100_000);
            BlockHeader::new(
                __h.shard_id(),
                __h.height(),
                BlockHash::ZERO,
                __h.parent_qc().clone(),
                __h.proposer(),
                __h.timestamp(),
                __h.round(),
                __h.is_fallback(),
                __h.state_root(),
                __h.transaction_root(),
                __h.certificate_root(),
                __h.local_receipt_root(),
                __h.provision_root(),
                __h.waves().clone().into_inner(),
                __h.provision_tx_roots().clone().into_inner(),
                __h.in_flight(),
                BeaconWitnessRoot::ZERO,
                BeaconWitnessLeafCount::ZERO,
                BeaconWitnessLeafCount::ZERO,
                None,
                None,
            )
        };
        let actions = state.on_block_header(
            &topology_schedule,
            &header,
            BlockManifest::default(),
            |_| None,
            |_| None,
            |_| None,
        );
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::VerifyQcSignature { .. }))
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Implicit Round Advancement Tests (HotStuff-2 Style)
    // ═══════════════════════════════════════════════════════════════════════════

    /// Advance the coordinator one round the way the pacemaker does on a
    /// 2f+1 timeout quorum — bump the view, then re-enter — without standing
    /// up a full timeout quorum. Exercises the shared `enter_round` path.
    fn advance_one_round(
        state: &mut ShardCoordinator,
        topology_schedule: &TopologySchedule,
    ) -> Vec<Action> {
        let next = state.view_change.view.next();
        state.view_change.advance_to(next);
        state.enter_round(topology_schedule)
    }

    #[test]
    fn test_enter_round_proposer_broadcasts() {
        // Rounds increase per block: a fresh state starts at view 1, and a
        // single advance moves to round 2. Local = ValidatorId::new(2) is the
        // proposer at round 2 since proposer_for(2) = committee[2 % 4] = 2.
        let (mut state, topology_schedule) = make_multi_validator_state_at(2);
        state.set_time(LocalTimestamp::from_millis(100_000));

        let actions = advance_one_round(&mut state, &topology_schedule);
        assert!(actions.iter().any(|a| matches!(
            a,
            Action::BuildProposal {
                is_fallback: true,
                ..
            }
        )));
    }

    #[test]
    fn test_safe_vote_rule_clauses() {
        // HotStuff-2 Rule 1: vote iff the block is at the current round, beyond
        // any round we've already voted/timed-out in, and extends a QC at least
        // as high as our lock.
        let (mut state, _topology) = make_test_state();
        state.view_change.view = Round::new(5);
        state.last_voted_round = Round::new(4);
        state.locked_round = Round::new(3);

        // All three clauses satisfied.
        assert!(state.can_safe_vote(Round::new(5), Round::new(3)));
        // The safe-vote bar: an honest validator refuses a block extending a QC
        // below its locked round.
        assert!(!state.can_safe_vote(Round::new(5), Round::new(2)));
        // Not the current round.
        assert!(!state.can_safe_vote(Round::new(4), Round::new(3)));
        assert!(!state.can_safe_vote(Round::new(6), Round::new(3)));
        // One vote per round: a round we have already voted (or timed out) in is
        // refused even with an otherwise-safe parent QC.
        state.last_voted_round = Round::new(5);
        assert!(!state.can_safe_vote(Round::new(5), Round::new(3)));
    }

    #[test]
    fn committed_state_restore_never_lowers_the_safe_vote_registers() {
        // A crash-restart restores committed state carrying the highest QC's
        // round, which can trail the durable safe-vote registers when the
        // validator's last vote or timeout outran its highest committed QC.
        // The restore must not roll the registers back to the QC round, or
        // the one-vote-per-round guard would admit a second vote at a round
        // already signed.
        let (mut state, _topology) = make_test_state();
        state.last_voted_round = Round::new(7);
        state.locked_round = Round::new(6);

        let trailing_qc =
            Verified::<QuorumCertificate>::new_unchecked_for_test(QuorumCertificate::new(
                BlockHash::ZERO,
                ShardId::ROOT,
                BlockHeight::new(4),
                BlockHash::ZERO,
                Round::new(5),
                SignerBitfield::empty(),
                zero_bls_signature(),
                WeightedTimestamp::from_millis(100_000),
            ));
        state.on_committed_state_restored(
            BlockHeight::new(4),
            Some(BlockHash::ZERO),
            Some(trailing_qc),
        );

        assert_eq!(
            state.last_voted_round,
            Round::new(7),
            "the restore must not lower last_voted_round below the durable register",
        );
        assert_eq!(
            state.locked_round,
            Round::new(6),
            "the restore must not lower locked_round below the durable register",
        );
    }

    #[test]
    fn non_committee_timeout_is_not_tallied() {
        // The pacemaker's f+1 / 2f+1 thresholds are measured against the local
        // committee's power, so only committee members may contribute timeouts.
        // A globally-signed timeout from outside the committee must be dropped,
        // exactly as the vote path drops non-committee votes.
        let (mut state, topology_schedule) = make_test_state();
        let shard = ShardId::ROOT;
        let round = state.view();
        let net = NetworkDefinition::simulator();
        let mk = |voter: u64| {
            Verified::<Timeout>::sign_local(
                &net,
                shard,
                round,
                QuorumCertificate::genesis(shard, ChainOrigin::ROOT),
                ValidatorId::new(voter),
                &generate_bls_keypair(),
            )
        };

        // Outsider (not in the 4-member committee): dropped, nothing recorded.
        assert!(
            state
                .on_verified_timeout(&topology_schedule, mk(9))
                .is_empty()
        );
        assert_eq!(state.timeouts.power(round), VoteCount::ZERO);

        // Committee member: recorded, power accrues.
        assert!(
            state
                .on_verified_timeout(&topology_schedule, mk(1))
                .is_empty()
        );
        assert_eq!(state.timeouts.power(round), VoteCount::new(1));

        // A second committee member reaches f+1 and amplifies. Had the outsider
        // counted, this threshold would have tripped one timeout earlier.
        let actions = state.on_verified_timeout(&topology_schedule, mk(2));
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::SignAndBroadcastTimeout { .. })),
            "f+1 committee timeouts should amplify",
        );
    }

    #[test]
    fn far_future_timeout_is_not_tallied() {
        // The pacemaker advances at most `MAX_ROUND_GAP` beyond verified
        // progress, so a committee timeout for an unreachable round is dropped
        // rather than verified and stored — otherwise a Byzantine member could
        // grow the keeper without bound with rounds the view never reaches.
        let (mut state, topology_schedule) = make_test_state();
        let shard = ShardId::ROOT;
        let net = NetworkDefinition::simulator();
        // high_qc is genesis, so the ceiling is `MAX_ROUND_GAP`.
        let far = Round::new(MAX_ROUND_GAP + 1);
        let far_timeout = Verified::<Timeout>::sign_local(
            &net,
            shard,
            far,
            QuorumCertificate::genesis(shard, ChainOrigin::ROOT),
            ValidatorId::new(1),
            &generate_bls_keypair(),
        );

        assert!(
            state
                .on_verified_timeout(&topology_schedule, far_timeout)
                .is_empty()
        );
        assert_eq!(state.timeouts.power(far), VoteCount::ZERO);
    }

    /// A verified timeout's carried `high_qc` is adopted at share receipt,
    /// not only at the 2f+1 quorum. A replica that missed a QC (vote or
    /// header lost) otherwise deadlocks the pacemaker in a round split: it
    /// keeps timing out the old round, peers ahead drop those below-view
    /// timeouts, and neither round can reach quorum. One share from an
    /// ahead peer must lift the replica's `high_qc` and view.
    #[test]
    fn verified_timeout_share_adopts_higher_carried_high_qc() {
        let (mut state, topology_schedule, keys) = make_multi_validator_state_with_keys(0);
        state.set_time(LocalTimestamp::from_millis(100_000));
        let net = NetworkDefinition::simulator();

        // A complete pending block at height 1, round 1, extending the
        // committed tip. Its QC is what this node "missed".
        let block = empty_block_at_round(state.committed_hash, 1);
        install_complete_block(&mut state, &block);

        // The QC the ahead peers hold: 3-of-4 real vote signatures.
        let votes: Vec<(usize, Verified<BlockVote>)> = [1usize, 2, 3]
            .into_iter()
            .map(|idx| {
                let vote = Verified::<BlockVote>::sign_local(
                    &net,
                    block.hash(),
                    state.committed_hash,
                    ShardId::ROOT,
                    BlockHeight::new(1),
                    Round::new(1),
                    ValidatorId::new(idx as u64),
                    &keys[idx],
                    ProposerTimestamp::from_millis(100_000),
                );
                (idx, vote)
            })
            .collect();
        let missed_qc = Verified::<QuorumCertificate>::from_verified_votes(
            block.hash(),
            ShardId::ROOT,
            BlockHeight::new(1),
            Round::new(1),
            state.committed_hash,
            WeightedTimestamp::ZERO,
            &votes,
        )
        .expect("vote aggregation succeeds");

        // An ahead peer times out round 2, carrying that QC.
        let timeout = Verified::<Timeout>::sign_local(
            &net,
            ShardId::ROOT,
            Round::new(2),
            (*missed_qc).clone(),
            ValidatorId::new(1),
            &keys[1],
        );

        assert!(state.latest_qc().is_none());
        let _ = state.on_verified_timeout(&topology_schedule, timeout);

        let adopted = state
            .latest_qc()
            .expect("a single share's carried high_qc must be adopted");
        assert_eq!(adopted.round(), Round::new(1));
        assert_eq!(adopted.height(), BlockHeight::new(1));
        assert_eq!(
            state.view(),
            Round::new(2),
            "view must sync past the adopted QC",
        );
        // The share itself is still tallied for the pacemaker.
        assert_eq!(state.timeouts.power(Round::new(2)), VoteCount::new(1));
    }

    #[test]
    fn on_unverified_timeout_delegates_committee_share() {
        // Wire timeouts are screened on the shard loop thread, then their BLS
        // share is verified off-thread via `Action::VerifyTimeout`. Outsiders,
        // stale rounds, and already-tallied voters are dropped before delegating
        // — no pairing check is spent on a share that would be discarded.
        let (mut state, topology_schedule) = make_test_state();
        let shard = ShardId::ROOT;
        let round = state.view();
        let net = NetworkDefinition::simulator();
        let mk = |voter: u64, round: Round| {
            Timeout::new(
                &net,
                shard,
                round,
                QuorumCertificate::genesis(shard, ChainOrigin::ROOT),
                ValidatorId::new(voter),
                &generate_bls_keypair(),
            )
        };

        // Committee member, current round: delegated for off-thread verify.
        let actions = state.on_unverified_timeout(&topology_schedule, &mk(1, round));
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::VerifyTimeout { .. })),
            "a fresh committee timeout should be delegated",
        );

        // Outsider and stale round: dropped without delegating crypto.
        assert!(
            state
                .on_unverified_timeout(&topology_schedule, &mk(9, round))
                .is_empty()
        );
        assert!(
            state
                .on_unverified_timeout(&topology_schedule, &mk(1, Round::INITIAL))
                .is_empty()
        );

        // Far beyond verified progress (high_qc is genesis here, so the ceiling
        // is `MAX_ROUND_GAP`): dropped before delegating crypto, so a Byzantine
        // committee member can't pump unbounded distinct rounds through the
        // pacemaker.
        assert!(
            state
                .on_unverified_timeout(&topology_schedule, &mk(1, Round::new(MAX_ROUND_GAP + 1)))
                .is_empty(),
            "a timeout beyond high_qc + MAX_ROUND_GAP must be screened out",
        );

        // Already tallied: a retransmit is screened out before re-verifying.
        state.timeouts.record(
            Verified::<Timeout>::sign_local(
                &net,
                shard,
                round,
                QuorumCertificate::genesis(shard, ChainOrigin::ROOT),
                ValidatorId::new(2),
                &generate_bls_keypair(),
            ),
            VoteCount::new(1),
        );
        assert!(
            state
                .on_unverified_timeout(&topology_schedule, &mk(2, round))
                .is_empty()
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Vote Locking Safety Tests
    // ═══════════════════════════════════════════════════════════════════════════

    /// Build a fresh coordinator + 4-validator topology. Local validator sits at
    /// committee index 0. For tests that need a different local index, call
    /// [`make_multi_validator_state_at`]. For tests that need to sign votes
    /// themselves, call [`make_multi_validator_state_with_keys`].
    fn make_multi_validator_state() -> (ShardCoordinator, TopologySchedule) {
        make_multi_validator_state_at(0)
    }

    fn make_multi_validator_state_at(local_idx: u32) -> (ShardCoordinator, TopologySchedule) {
        let (state, topology_schedule, _keys) = make_multi_validator_state_with_keys(local_idx);
        (state, topology_schedule)
    }

    fn make_multi_validator_state_with_keys(
        local_idx: u32,
    ) -> (
        ShardCoordinator,
        TopologySchedule,
        Vec<Bls12381G1PrivateKey>,
    ) {
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
        let topology_snapshot =
            TopologySnapshot::new(NetworkDefinition::simulator(), 1, validator_set);
        let state = ShardCoordinator::new(
            ValidatorId::new(u64::from(local_idx)),
            ShardId::ROOT,
            ShardConsensusConfig::default(),
            RecoveredState::default(),
        );
        (
            state,
            TopologySchedule::single(Arc::new(topology_snapshot)),
            keys,
        )
    }

    #[test]
    fn test_forged_vote_cannot_block_legitimate_validator() {
        // Forged votes are buffered pre-verification and never reach
        // received_votes_by_height, so a legitimate vote for a different block
        // from the same voter is not flagged as equivocation on verification.
        let (mut state, topology_schedule) = make_multi_validator_state();
        state.set_time(LocalTimestamp::from_millis(100_000));

        let height = BlockHeight::new(5);
        let voter = ValidatorId::new(2);
        let block_b = BlockHash::from_raw(Hash::from_bytes(b"legitimate_block"));
        let vote = BlockVote::from_parts(
            block_b,
            ShardId::ROOT,
            height,
            Round::new(0),
            voter,
            zero_bls_signature(),
            ProposerTimestamp::from_millis(100_000),
        );

        let _ = state.on_qc_result(
            &topology_schedule,
            block_b,
            None,
            vec![(0, Verified::<BlockVote>::new_unchecked_for_test(vote))],
        );

        let (recorded_hash, _) = state
            .votes
            .received_vote(height, voter)
            .expect("legitimate vote must be recorded");
        assert_eq!(recorded_hash, block_b);
    }
    // ═══════════════════════════════════════════════════════════════════════════
    // Re-proposal After View Change Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_reproposed_block_passes_validation() {
        // A receiving validator (possibly already at view=31) must still accept a
        // re-proposal carrying the original round — validation only keys off
        // proposer_for(header.round()), not the receiver's view.
        let (state, topology_schedule) = make_multi_validator_state();
        let header = make_header_at_height(BlockHeight::new(1), state.now.as_millis());

        assert!(
            validate_header(
                topology_schedule.head(),
                Some(topology_schedule.head().as_ref()),
                state.local_shard,
                &header,
                state.committed_height,
                state.now,
            )
            .is_ok()
        );
    }

    #[test]
    fn test_reproposed_block_with_wrong_proposer_fails_validation() {
        let (state, topology_schedule) = make_multi_validator_state();
        // proposer_for(1) = ValidatorId::new(1), but the header claims ValidatorId::new(3).
        let header = {
            let __h = make_header_at_height(BlockHeight::new(1), state.now.as_millis());
            BlockHeader::new(
                __h.shard_id(),
                __h.height(),
                __h.parent_block_hash(),
                __h.parent_qc().clone(),
                ValidatorId::new(3),
                __h.timestamp(),
                __h.round(),
                __h.is_fallback(),
                __h.state_root(),
                __h.transaction_root(),
                __h.certificate_root(),
                __h.local_receipt_root(),
                __h.provision_root(),
                __h.waves().clone().into_inner(),
                __h.provision_tx_roots().clone().into_inner(),
                __h.in_flight(),
                BeaconWitnessRoot::ZERO,
                BeaconWitnessLeafCount::ZERO,
                BeaconWitnessLeafCount::ZERO,
                None,
                None,
            )
        };

        let result = validate_header(
            topology_schedule.head(),
            Some(topology_schedule.head().as_ref()),
            state.local_shard,
            &header,
            state.committed_height,
            state.now,
        );
        assert!(
            result.is_err(),
            "Block with wrong proposer for round should fail validation"
        );
        assert!(
            result.unwrap_err().contains("wrong proposer"),
            "Error should mention wrong proposer"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Extended View Change Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_qc_formed_proposes_empty_block_for_finalization() {
        // Under the 2-chain commit rule, block N+1 is what certifies block N.
        // After a QC forms we must propose N+1 immediately — even with no
        // content — or finalization of N stalls.
        let (mut state, topology_schedule) = make_test_state();
        state.set_time(LocalTimestamp::from_millis(100_000));
        // Parent tree must be available or try_propose defers.
        state.committed_height = BlockHeight::new(3);
        state.verification.on_block_persisted(BlockHeight::new(3));
        // Rounds increase per block: height 4 is proposed at round 4, where
        // proposer_for(4, 4) = validator 0 (local).
        state.view_change.view = Round::new(4);

        let block_3_hash = BlockHash::from_raw(Hash::from_bytes(b"block_3"));

        let qc = {
            let __qc = make_test_qc(block_3_hash, BlockHeight::new(3));
            // SAFETY: synthetic test fixture, no real signature.
            Verified::<QuorumCertificate>::new_unchecked_for_test(QuorumCertificate::new(
                __qc.block_hash(),
                __qc.shard_id(),
                __qc.height(),
                BlockHash::from_raw(Hash::from_bytes(b"block_2")),
                __qc.round(),
                __qc.signers().clone(),
                __qc.aggregated_signature(),
                __qc.weighted_timestamp(),
            ))
        };

        let actions =
            state.on_qc_formed(&topology_schedule, block_3_hash, &qc, &[], vec![], vec![]);

        // Should emit BuildProposal for height 4 even with empty content.
        let has_build_proposal = actions.iter().any(
            |a| matches!(a, Action::BuildProposal { height, .. } if height == &BlockHeight::new(4)),
        );

        assert!(
            has_build_proposal,
            "Should propose empty block immediately after QC formation to advance finalization"
        );
    }

    #[test]
    fn qc_formed_rejects_weighted_timestamp_past_the_envelope() {
        // Per-vote timestamps ride outside the vote's signed message, so the
        // aggregated mean can be dragged far forward by Byzantine voters or
        // a rewriting relay. A locally formed QC past the bound must not be
        // adopted: it would poison `latest_qc` and stall proposals and
        // timeout tallying on an unresolvable tip committee. One at the
        // bound's edge must still adopt and drive the next proposal.
        let (mut state, topology_schedule) = make_test_state();
        let now = LocalTimestamp::from_millis(100_000);
        state.set_time(now);
        state.committed_height = BlockHeight::new(3);
        state.verification.on_block_persisted(BlockHeight::new(3));
        state.view_change.view = Round::new(4);
        let envelope_ms =
            u64::try_from((MAX_TIMESTAMP_DELAY + MAX_TIMESTAMP_RUSH).as_millis()).unwrap();

        let block_3_hash = BlockHash::from_raw(Hash::from_bytes(b"block_3"));
        let qc_with_ts = |weighted_ms: u64| {
            let __qc = make_test_qc(block_3_hash, BlockHeight::new(3));
            // SAFETY: synthetic test fixture, no real signature.
            Verified::<QuorumCertificate>::new_unchecked_for_test(QuorumCertificate::new(
                __qc.block_hash(),
                __qc.shard_id(),
                __qc.height(),
                BlockHash::from_raw(Hash::from_bytes(b"block_2")),
                __qc.round(),
                __qc.signers().clone(),
                __qc.aggregated_signature(),
                WeightedTimestamp::from_millis(weighted_ms),
            ))
        };

        // One millisecond past the envelope: discarded outright.
        let forged = qc_with_ts(now.as_millis() + envelope_ms + 1);
        let actions = state.on_qc_formed(
            &topology_schedule,
            block_3_hash,
            &forged,
            &[],
            vec![],
            vec![],
        );
        assert!(
            actions.is_empty(),
            "forged QC must emit nothing: {actions:?}"
        );
        assert!(state.latest_qc().is_none(), "forged QC must not be adopted");

        // Exactly at the envelope: kept, and the next proposal fires.
        let honest = qc_with_ts(now.as_millis() + envelope_ms);
        let actions = state.on_qc_formed(
            &topology_schedule,
            block_3_hash,
            &honest,
            &[],
            vec![],
            vec![],
        );
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::BuildProposal { .. })),
            "honest QC must drive the next proposal: {actions:?}"
        );
    }

    #[test]
    fn test_two_chain_commit_defers_when_certified_uncached() {
        // Two-chain commit emits `BlockReadyToCommit { certified, source }`
        // where `certified` is the assembled `Verified<CertifiedBlock>` for
        // the committable block. The handle lives in the pipeline's
        // `verified_certified_blocks` map once per-root + state-root
        // assembly completes. If the cache entry is missing (e.g.
        // assembly is still in flight), we must defer — a later root
        // completion drives the deferred commit via
        // `drive_deferred_commit_for`.
        let (state, _topology) = make_test_state();

        let committable_hash = BlockHash::from_raw(Hash::from_bytes(b"parent"));
        let child_hash = BlockHash::from_raw(Hash::from_bytes(b"child"));
        let qc = Verified::<QuorumCertificate>::new_unchecked_for_test(QuorumCertificate::new(
            child_hash,
            ShardId::ROOT,
            BlockHeight::new(4),
            committable_hash,
            Round::new(0),
            SignerBitfield::empty(),
            zero_bls_signature(),
            WeightedTimestamp::from_millis(100_000),
        ));

        // No verified certified cached — exercises the deferral path.
        let actions = state.try_two_chain_commit(&qc, CommitSource::Aggregator);
        assert!(
            actions.is_empty(),
            "expected no BlockReadyToCommit when certified uncached, got {actions:?}"
        );
    }

    #[test]
    fn test_deferred_proposal_suppresses_rebuild_until_unblocked() {
        // A deferred proposal (parent tree missing) must NOT re-emit
        // BuildProposal on every subsequent try_propose for the same
        // (height, round) — that's the spin loop v7 was hitting, producing
        // hundreds of `"Requesting block build for proposal"` log lines per
        // second while peers timed out on the proposer slot. After the
        // parent tree lands, `take_ready_proposal` must clear the gate so
        // the next try_propose can dispatch.

        let (mut state, topology_schedule) = make_test_state();
        state.set_time(LocalTimestamp::from_millis(100_000));

        // Local validator is ValidatorId::new(0). Rounds increase per block, so
        // point the chain at (h=4, r=4) where proposer = (4+4)%4 = ValidatorId::new(0).
        let parent_block_hash = BlockHash::from_raw(Hash::from_bytes(b"parent_tree_missing"));
        state.committed_height = BlockHeight::new(3);
        state.committed_hash = parent_block_hash;
        state.latest_qc = Some(make_test_qc(parent_block_hash, BlockHeight::new(3)));
        state.view_change.view = Round::new(4);
        // Intentionally do NOT call on_block_persisted — parent tree
        // unavailable forces the defer branch.

        let first = state.try_propose(&topology_schedule, &[], vec![], vec![]);
        assert!(
            first
                .iter()
                .all(|a| !matches!(a, Action::BuildProposal { .. })),
            "first try_propose should have deferred, not dispatched"
        );
        assert!(
            state.proposal.deferred().is_some(),
            "defer slot should be recorded"
        );

        let second = state.try_propose(&topology_schedule, &[], vec![], vec![]);
        assert!(
            second.is_empty(),
            "second try_propose for same (height, round) must be suppressed"
        );

        // Parent tree lands — verification pipeline signals unblock and
        // take_ready_proposal clears the tracker's deferred slot.
        state.verification.on_block_persisted(BlockHeight::new(3));
        assert!(
            state.take_ready_proposal(),
            "take_ready_proposal should report unblocked"
        );
        assert!(
            state.proposal.deferred().is_none(),
            "deferred slot should be cleared"
        );

        let third = state.try_propose(&topology_schedule, &[], vec![], vec![]);
        assert!(
            third.iter().any(
                |a| matches!(a, Action::BuildProposal { height, .. } if *height == BlockHeight::new(4))
            ),
            "third try_propose should dispatch the BuildProposal"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // straight-line sequence; splitting hurts readability
    fn test_qc_verification_caching_skips_redundant_verification() {
        // When the same parent QC appears in multiple block headers (e.g. after a
        // view change), we verify it once and hit the cache for subsequent blocks.

        let (mut state, topology_schedule) = make_multi_validator_state_at(0);
        state.set_time(LocalTimestamp::from_millis(100_000));

        let parent_block_hash = BlockHash::from_raw(Hash::from_bytes(b"parent_block"));
        state.committed_height = BlockHeight::new(1);
        state.committed_hash = parent_block_hash;

        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        let parent_qc = {
            let __qc = make_test_qc(parent_block_hash, BlockHeight::new(1));
            QuorumCertificate::new(
                __qc.block_hash(),
                __qc.shard_id(),
                __qc.height(),
                __qc.parent_block_hash(),
                __qc.round(),
                signers,
                __qc.aggregated_signature(),
                WeightedTimestamp::from_millis(99_000),
            )
        };

        let header1 = {
            let __h = make_header_at_height(BlockHeight::new(2), 100_000);
            BlockHeader::new(
                __h.shard_id(),
                __h.height(),
                parent_block_hash,
                parent_qc.clone(),
                __h.proposer(),
                __h.timestamp(),
                __h.round(),
                __h.is_fallback(),
                __h.state_root(),
                __h.transaction_root(),
                __h.certificate_root(),
                __h.local_receipt_root(),
                __h.provision_root(),
                __h.waves().clone().into_inner(),
                __h.provision_tx_roots().clone().into_inner(),
                __h.in_flight(),
                BeaconWitnessRoot::ZERO,
                BeaconWitnessLeafCount::ZERO,
                BeaconWitnessLeafCount::ZERO,
                None,
                None,
            )
        };
        let actions1 = state.on_block_header(
            &topology_schedule,
            &header1,
            BlockManifest::default(),
            |_| None,
            |_| None,
            |_| None,
        );
        assert!(
            actions1
                .iter()
                .any(|a| matches!(a, Action::VerifyQcSignature { .. })),
            "first block must trigger QC verification"
        );

        // Simulate verification success; same path as on_qc_signature_verified(valid=true).
        // SAFETY: synthetic test fixture, no real signature.
        state.verification.cache_verified_qc(
            Verified::<QuorumCertificate>::new_unchecked_for_test(parent_qc.clone()),
        );

        // Second block at round 1 sharing the same parent QC.
        let header2 = {
            let __h = make_header_at_height(BlockHeight::new(2), 100_001);
            BlockHeader::new(
                __h.shard_id(),
                __h.height(),
                parent_block_hash,
                parent_qc,
                ValidatorId::new(3),
                __h.timestamp(),
                Round::new(1),
                __h.is_fallback(),
                __h.state_root(),
                __h.transaction_root(),
                __h.certificate_root(),
                __h.local_receipt_root(),
                __h.provision_root(),
                __h.waves().clone().into_inner(),
                __h.provision_tx_roots().clone().into_inner(),
                __h.in_flight(),
                BeaconWitnessRoot::ZERO,
                BeaconWitnessLeafCount::ZERO,
                BeaconWitnessLeafCount::ZERO,
                None,
                None,
            )
        };
        let actions2 = state.on_block_header(
            &topology_schedule,
            &header2,
            BlockManifest::default(),
            |_| None,
            |_| None,
            |_| None,
        );
        assert!(
            !actions2
                .iter()
                .any(|a| matches!(a, Action::VerifyQcSignature { .. })),
            "second block must reuse cached verification"
        );
    }

    #[test]
    fn qc_cache_hit_requires_byte_equal_qc_not_just_block_hash() {
        // A Byzantine peer who sees a legitimately-cached `block_hash` must
        // not be able to ship a header whose parent_qc reuses that block_hash
        // with fabricated `signers` / `round` / `parent_block_hash` and have
        // those forged fields adopted into `latest_qc` without re-verification.

        let (mut state, topology_schedule) = make_multi_validator_state_at(0);
        state.set_time(LocalTimestamp::from_millis(100_000));

        let parent_block_hash = BlockHash::from_raw(Hash::from_bytes(b"parent_block"));
        state.committed_height = BlockHeight::new(1);
        state.committed_hash = parent_block_hash;

        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        let honest_qc = {
            let __qc = make_test_qc(parent_block_hash, BlockHeight::new(1));
            QuorumCertificate::new(
                __qc.block_hash(),
                __qc.shard_id(),
                __qc.height(),
                __qc.parent_block_hash(),
                __qc.round(),
                signers.clone(),
                __qc.aggregated_signature(),
                WeightedTimestamp::from_millis(99_000),
            )
        };

        // Cache the honest QC as if it had been verified.
        // SAFETY: synthetic test fixture, no real signature.
        state.verification.cache_verified_qc(
            Verified::<QuorumCertificate>::new_unchecked_for_test(honest_qc.clone()),
        );

        // Byzantine header reuses the honest QC's block_hash + signers + height
        // (so `validate_header`'s quorum-power and structural checks still pass)
        // but mutates fields outside the cache key, e.g. the weighted timestamp —
        // the cache must bind every signed field, otherwise a hit would skip
        // re-verifying a forged signature. The forged timestamp stays within the
        // clock envelope so this isolates the cache-binding check rather than the
        // far-future parent-QC timestamp bound.
        let forged_qc = {
            let __qc = honest_qc;
            QuorumCertificate::new(
                __qc.block_hash(),
                __qc.shard_id(),
                __qc.height(),
                __qc.parent_block_hash(),
                __qc.round(),
                __qc.signers().clone(),
                __qc.aggregated_signature(),
                WeightedTimestamp::from_millis(101_000),
            )
        };
        let forged_header = {
            let __h = make_header_at_height(BlockHeight::new(2), 100_000);
            BlockHeader::new(
                __h.shard_id(),
                __h.height(),
                parent_block_hash,
                forged_qc,
                __h.proposer(),
                __h.timestamp(),
                __h.round(),
                __h.is_fallback(),
                __h.state_root(),
                __h.transaction_root(),
                __h.certificate_root(),
                __h.local_receipt_root(),
                __h.provision_root(),
                __h.waves().clone().into_inner(),
                __h.provision_tx_roots().clone().into_inner(),
                __h.in_flight(),
                BeaconWitnessRoot::ZERO,
                BeaconWitnessLeafCount::ZERO,
                BeaconWitnessLeafCount::ZERO,
                None,
                None,
            )
        };

        let actions = state.on_block_header(
            &topology_schedule,
            &forged_header,
            BlockManifest::default(),
            |_| None,
            |_| None,
            |_| None,
        );

        // The forged QC must trigger BLS verification rather than being
        // accepted as a cache hit.
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::VerifyQcSignature { .. })),
            "forged QC reusing cached block_hash must still trigger BLS verification"
        );

        // And `latest_qc` must not have been mutated to reflect the forged
        // weighted_timestamp on the cache-hit path.
        assert!(
            state.latest_qc.as_ref().is_none_or(
                |qc| qc.weighted_timestamp() != forged_header.parent_qc().weighted_timestamp()
            ),
            "forged QC must not be adopted as latest_qc on cache hit"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Helpers retained for no-duplicate-transactions walk tests below
    // ═══════════════════════════════════════════════════════════════════════════

    fn make_test_tx_with_seed(seed: u8) -> Arc<Verifiable<RoutableTransaction>> {
        Arc::new(Verifiable::from(test_utils::test_transaction(seed)))
    }

    fn sort_txs_by_hash(txs: &mut [Arc<Verifiable<RoutableTransaction>>]) {
        txs.sort_by_key(|tx| tx.hash());
    }

    // ========================================================================
    // Sync Block Proposal Tests
    // ========================================================================

    #[test]
    fn test_syncing_validator_proposes_empty_block() {
        let (mut state, topology_schedule) = make_test_state();
        state.set_time(LocalTimestamp::from_millis(100_000));
        // Simulate committed state so parent tree is available for BuildProposal.
        state.committed_height = BlockHeight::new(3);
        state.verification.on_block_persisted(BlockHeight::new(3));

        // Validator 0 proposes for height 4 since (4+0)%4 = 0.
        state.latest_qc = Some({
            let __qc = make_test_qc(
                BlockHash::from_raw(Hash::from_bytes(b"block_3")),
                BlockHeight::new(3),
            );
            // SAFETY: synthetic test fixture, no real signature.
            Verified::<QuorumCertificate>::new_unchecked_for_test(QuorumCertificate::new(
                __qc.block_hash(),
                __qc.shard_id(),
                __qc.height(),
                BlockHash::from_raw(Hash::from_bytes(b"block_2")),
                __qc.round(),
                __qc.signers().clone(),
                __qc.aggregated_signature(),
                __qc.weighted_timestamp(),
            ))
        });

        // Rounds increase per block: height 4 proposes at round 4
        // (proposer_for(4, 4) = validator 0).
        state.view_change.view = Round::new(4);
        state.set_block_syncing(true);
        assert!(state.is_block_syncing());

        // Ready txs must be dropped — sync blocks are always empty.
        let ready_txs = vec![Arc::new(test_utils::verified_test_transaction(1))];
        let actions = state.try_propose(&topology_schedule, &ready_txs, vec![], vec![]);

        let proposal = actions
            .iter()
            .find(|a| matches!(a, Action::BuildProposal { .. }))
            .expect("sync block should still produce BuildProposal");
        let Action::BuildProposal {
            is_fallback,
            transactions,
            finalized_waves,
            ..
        } = proposal
        else {
            unreachable!()
        };
        assert!(!is_fallback);
        assert!(transactions.is_empty());
        assert!(finalized_waves.is_empty());
    }

    #[test]
    fn test_syncing_validator_uses_current_timestamp() {
        // Sync blocks timestamp with the wall clock; they do not inherit the
        // parent's weighted timestamp like fallback blocks do.
        let (mut state, topology_schedule) = make_test_state();
        let current_time = LocalTimestamp::from_millis(12_345_000);
        state.set_time(current_time);
        state.committed_height = BlockHeight::new(3);
        state.verification.on_block_persisted(BlockHeight::new(3));

        let old_timestamp = 1000u64;
        state.latest_qc = Some({
            let __qc = make_test_qc(
                BlockHash::from_raw(Hash::from_bytes(b"block_3")),
                BlockHeight::new(3),
            );
            // SAFETY: synthetic test fixture, no real signature.
            Verified::<QuorumCertificate>::new_unchecked_for_test(QuorumCertificate::new(
                __qc.block_hash(),
                __qc.shard_id(),
                __qc.height(),
                BlockHash::from_raw(Hash::from_bytes(b"block_2")),
                __qc.round(),
                __qc.signers().clone(),
                __qc.aggregated_signature(),
                WeightedTimestamp::from_millis(old_timestamp),
            ))
        });
        // Height 4 proposes at round 4 (rounds increase per block).
        state.view_change.view = Round::new(4);
        state.set_block_syncing(true);

        let actions = state.try_propose(&topology_schedule, &[], vec![], vec![]);
        let Some(Action::BuildProposal { timestamp, .. }) = actions
            .iter()
            .find(|a| matches!(a, Action::BuildProposal { .. }))
        else {
            panic!("expected BuildProposal");
        };
        assert_eq!(*timestamp, ProposerTimestamp::from_local(current_time));
        assert_ne!(timestamp.as_millis(), old_timestamp);
    }

    #[test]
    fn second_propose_after_self_vote_is_suppressed() {
        // Once a proposal's build completes and the proposer self-votes it,
        // a retry at the still-current view (routinely queued by
        // TransactionsAdmitted / ProvisionsAdmitted) must not build a sibling
        // block — that would sign two votes at one round.
        let (mut state, topology_schedule) = make_test_state();
        state.set_time(LocalTimestamp::from_millis(100_000));
        state.committed_height = BlockHeight::new(3);
        state.verification.on_block_persisted(BlockHeight::new(3));
        state.latest_qc = Some(make_test_qc(
            BlockHash::from_raw(Hash::from_bytes(b"block_3")),
            BlockHeight::new(3),
        ));
        // Height 4 proposes at round 4 (rounds increase per block).
        state.view_change.view = Round::new(4);

        let height = BlockHeight::new(4);
        let round = Round::new(4);
        let actions = state.try_propose(&topology_schedule, &[], vec![], vec![]);
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::BuildProposal { .. })),
            "first proposal should build"
        );

        // The runner completes the build: the tracker slot clears and the
        // proposer self-votes, consuming the round.
        assert!(matches!(
            state.proposal.take_matching(height, round),
            TakeResult::Matched
        ));
        let block_hash = BlockHash::from_raw(Hash::from_bytes(b"own_block_4"));
        let vote = state.create_vote(&topology_schedule, block_hash, height, round);
        assert!(
            vote.iter()
                .any(|a| matches!(a, Action::SignAndBroadcastBlockVote { .. }))
        );
        assert_eq!(state.last_voted_round(), round);

        // The retry at the same view must be a no-op, not a sibling build.
        let retry = state.try_propose(&topology_schedule, &[], vec![], vec![]);
        assert!(retry.is_empty(), "retry built a sibling: {retry:?}");
    }

    #[test]
    fn build_proposal_classifies_against_the_anchored_committee_not_the_head() {
        // The proposed block anchors at its `parent_qc` weighted timestamp
        // (epoch 0, where ROOT is one shard). The schedule's head has
        // already flipped to the post-split window (two shards). The
        // verifier recomputes `waves`/`provision_tx_roots` against the
        // anchored window, so the proposer must classify against it too —
        // never the flipped head — or every replica rejects the header.
        let (mut state, _) = make_test_state();
        state.set_time(LocalTimestamp::from_millis(100_000));
        let parent = BlockHash::from_raw(Hash::from_bytes(b"block_3"));
        state.committed_height = BlockHeight::new(3);
        state.committed_hash = parent;
        state.committed_anchor_ts = WeightedTimestamp::from_millis(500);
        state.verification.on_block_persisted(BlockHeight::new(3));
        state.latest_qc = Some({
            let __qc = make_test_qc(parent, BlockHeight::new(3));
            // SAFETY: synthetic test fixture, no real signature. Anchored at
            // epoch 0 (wt 500 with a 1000 ms epoch).
            Verified::<QuorumCertificate>::new_unchecked_for_test(QuorumCertificate::new(
                __qc.block_hash(),
                __qc.shard_id(),
                __qc.height(),
                BlockHash::ZERO,
                __qc.round(),
                __qc.signers().clone(),
                __qc.aggregated_signature(),
                WeightedTimestamp::from_millis(500),
            ))
        });
        state.view_change.view = Round::new(4);

        // Epoch 0 carries ROOT (one shard) — the proposal's anchor; epoch 1
        // splits it (two shards) and is installed as the flipped head.
        let keys: Vec<Bls12381G1PrivateKey> = (0..4).map(|_| generate_bls_keypair()).collect();
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| ValidatorInfo {
                validator_id: ValidatorId::new(i as u64),
                public_key: k.public_key(),
            })
            .collect();
        let pre_split = Arc::new(TopologySnapshot::new(
            NetworkDefinition::simulator(),
            1,
            ValidatorSet::new(validators.clone()),
        ));
        let post_split = Arc::new(TopologySnapshot::new(
            NetworkDefinition::simulator(),
            2,
            ValidatorSet::new(validators),
        ));
        let mut sched = TopologySchedule::new(1000, Epoch::new(0), Arc::clone(&pre_split));
        sched.insert(Epoch::new(1), Arc::clone(&post_split));
        sched.set_head(post_split);

        let actions = state.try_propose(&sched, &[], vec![], vec![]);
        let classification = actions
            .iter()
            .find_map(|a| match a {
                Action::BuildProposal {
                    classification_topology_snapshot: classification_topology,
                    ..
                } => Some(classification_topology),
                _ => None,
            })
            .expect("a BuildProposal must dispatch");
        assert_eq!(
            classification.num_shards(),
            1,
            "classification anchors at the parent_qc window (ROOT, pre-split), not the two-shard head",
        );
    }

    #[test]
    fn test_sync_complete_exits_sync_mode() {
        let (mut state, topology_schedule) = make_test_state();
        state.set_block_syncing(true);
        assert!(state.is_block_syncing());

        // Fresh state has no pending blocks and is already in the
        // consensus subset, so on_sync_complete returns no actions — the
        // remote-header / provision flushes happen in NodeStateMachine's
        // BlockSyncComplete arm.
        let actions = state.on_block_sync_complete(&topology_schedule);
        assert!(!state.is_block_syncing());
        assert!(actions.is_empty());
    }

    /// A 4-member committee where validator 0 (the local node) is a
    /// full member but outside the consensus subset — placed, not yet
    /// ready.
    fn not_ready_member_topology() -> TopologySchedule {
        use std::collections::{BTreeMap, HashMap};

        let validators: Vec<ValidatorInfo> = (0..4)
            .map(|i| ValidatorInfo {
                validator_id: ValidatorId::new(i),
                public_key: generate_bls_keypair().public_key(),
            })
            .collect();
        let vs = ValidatorSet::new(validators);
        let members: Vec<ValidatorId> = (0..4).map(ValidatorId::new).collect();
        let mut committees = HashMap::new();
        committees.insert(ShardId::ROOT, members.clone());
        let mut consensus = HashMap::new();
        consensus.insert(ShardId::ROOT, members[1..].to_vec());
        let snapshot = TopologySnapshot::from_explicit_committees(
            NetworkDefinition::simulator(),
            &vs,
            committees,
            consensus,
            HashMap::new(),
            HashMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
        );
        TopologySchedule::single(Arc::new(snapshot))
    }

    /// A committee member outside the consensus subset — placed but not
    /// yet ready — emits exactly one `SignAndBroadcastReadySignal` when
    /// sync reaches the tip, windowed from the next committable height
    /// and addressed to every other committee member. (The already-ready
    /// case stays silent: `test_sync_complete_exits_sync_mode`.)
    #[test]
    fn sync_complete_emits_ready_signal_when_not_in_consensus_subset() {
        use std::collections::{BTreeMap, HashMap};

        let (mut state, _) = make_test_state();
        let validators: Vec<ValidatorInfo> = (0..4)
            .map(|i| ValidatorInfo {
                validator_id: ValidatorId::new(i),
                public_key: generate_bls_keypair().public_key(),
            })
            .collect();
        let vs = ValidatorSet::new(validators);
        let members: Vec<ValidatorId> = (0..4).map(ValidatorId::new).collect();
        let mut committees = HashMap::new();
        committees.insert(ShardId::ROOT, members.clone());
        // Validator 0 (the local node) is a member but not ready.
        let mut consensus = HashMap::new();
        consensus.insert(ShardId::ROOT, members[1..].to_vec());
        let snapshot = TopologySnapshot::from_explicit_committees(
            NetworkDefinition::simulator(),
            &vs,
            committees,
            consensus,
            HashMap::new(),
            HashMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
        );
        let topology_schedule = TopologySchedule::single(Arc::new(snapshot));

        state.set_block_syncing(true);
        let actions = state.on_block_sync_complete(&topology_schedule);
        assert!(!state.is_block_syncing());

        let signals: Vec<_> = actions
            .iter()
            .filter_map(|a| match a {
                Action::SignAndBroadcastReadySignal {
                    wt_window_start,
                    wt_window_end,
                    recipients,
                    ..
                } => Some((wt_window_start, wt_window_end, recipients)),
                _ => None,
            })
            .collect();
        let [(start, end, recipients)] = signals.as_slice() else {
            panic!("expected exactly one ready signal, got {actions:?}");
        };
        assert_eq!(**start, state.committed_ts);
        assert_eq!(
            **end,
            start.plus(ready_signal_window(topology_schedule.epoch_duration_ms()))
        );
        assert_eq!(recipients.len(), 3);
        assert!(!recipients.contains(&state.me));
    }

    /// A vnode that finished bootstrap sync before its committee window
    /// opened missed the sync-complete emission (the head committee
    /// didn't include it yet). The beacon commit that activates the
    /// window must re-fire the signal — without this the flag only
    /// flips via the ready timeout.
    #[test]
    fn beacon_commit_re_fires_ready_signal_for_synced_not_ready_member() {
        let (mut state, _) = make_test_state();
        let topology_schedule = not_ready_member_topology();

        let actions = state.on_beacon_block_persisted(&topology_schedule);
        let signals = actions
            .iter()
            .filter(|a| matches!(a, Action::SignAndBroadcastReadySignal { .. }))
            .count();
        assert_eq!(
            signals, 1,
            "expected exactly one re-fired ready signal, got {actions:?}"
        );

        // Mid-sync the re-kick stays quiet: the height window would be
        // stale, and sync completion re-fires the emission itself.
        state.set_block_syncing(true);
        let actions = state.on_beacon_block_persisted(&topology_schedule);
        assert!(
            actions.is_empty(),
            "no ready signal while block sync is in flight, got {actions:?}"
        );
    }

    /// An already-ready member (in the consensus subset) stays silent on
    /// beacon commits — the re-kick is only for the placed-but-not-ready
    /// window.
    #[test]
    fn beacon_commit_emits_no_ready_signal_for_consensus_member() {
        let (mut state, topology_schedule) = make_test_state();
        let actions = state.on_beacon_block_persisted(&topology_schedule);
        assert!(actions.is_empty(), "expected no actions, got {actions:?}");
    }

    #[test]
    fn beacon_behind_synced_block_re_buffers_until_epoch_adoption() {
        // A synced block whose committee epoch the beacon hasn't committed
        // yet must survive the lookup miss: it returns to the buffer and the
        // beacon adopting the epoch replays it into QC verification.
        // Discarding it would leave a hole the drain could never refill
        // without a network re-fetch.
        const ED: u64 = 1_000;
        let epoch0 = Arc::new(committee_snapshot_with_ids(&[0, 1, 2, 3]));
        let mut schedule = TopologySchedule::new(ED, Epoch::new(0), epoch0);

        let mut state = ShardCoordinator::new(
            ValidatorId::new(0),
            ShardId::ROOT,
            ShardConsensusConfig::default(),
            RecoveredState::default(),
        );
        state.set_time(LocalTimestamp::from_millis(100_000));
        state.committed_height = BlockHeight::new(3);
        state.set_block_syncing(true);

        // Parent QC weighted timestamp in epoch 5 — above the schedule head.
        let block = block_with_parent_qc_ts(BlockHeight::new(4), 5 * ED);
        let block_hash = block.hash();
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        let qc = QuorumCertificate::new(
            block_hash,
            ShardId::ROOT,
            BlockHeight::new(4),
            block.header().parent_block_hash(),
            block.header().round(),
            signers,
            zero_bls_signature(),
            WeightedTimestamp::from_millis(5 * ED),
        );
        let certified = CertifiedBlock::new_unchecked(block, qc);

        let actions = state.on_sync_block_ready_to_apply(&schedule, certified);
        assert!(
            actions.is_empty(),
            "beacon-behind defer emits nothing: {actions:?}"
        );
        assert!(
            state
                .block_sync
                .has_buffered(BlockHeight::new(4), &block_hash)
        );

        // Beacon adopts the epoch: the parked block replays into verification.
        schedule.insert(
            Epoch::new(5),
            Arc::new(committee_snapshot_with_ids(&[0, 1, 2, 3])),
        );
        let actions = state.on_beacon_block_persisted(&schedule);
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::VerifyQcSignature { .. })),
            "expected VerifyQcSignature after epoch adoption; got {actions:?}"
        );
        assert!(
            !state
                .block_sync
                .has_buffered(BlockHeight::new(4), &block_hash)
        );
    }

    #[test]
    fn beacon_witness_parked_on_beacon_lag_retries_on_epoch_adoption() {
        // A block whose committee epoch this node's beacon hasn't committed
        // yet must survive the committee lookup miss: its beacon-witness
        // verification parks and replays when the beacon adopts the epoch.
        // Dropping it strands the block at `NOT_STARTED` — no shard event can
        // revive it — so the shard wedges on a view-change loop.
        const ED: u64 = 1_000;
        let epoch0 = Arc::new(committee_snapshot_with_ids(&[0, 1, 2, 3]));
        let mut schedule = TopologySchedule::new(ED, Epoch::new(0), epoch0);

        let mut state = ShardCoordinator::new(
            ValidatorId::new(0),
            ShardId::ROOT,
            ShardConsensusConfig::default(),
            RecoveredState::default(),
        );
        state.committed_height = BlockHeight::new(3);
        // The block's parent is the committed tip, so the witness-leaf walk
        // terminates immediately and verification can dispatch the moment the
        // committee resolves.
        state.committed_hash = BlockHash::from_raw(Hash::from_bytes(b"anchor_parent"));

        // Parent QC weighted timestamp in epoch 5 — above the schedule head,
        // so the block's committee is unresolvable until the beacon catches up.
        let block = block_with_parent_qc_ts(BlockHeight::new(4), 5 * ED);
        let block_hash = block.hash();
        install_complete_block(&mut state, &block);

        // Park exactly as the beacon-behind retry path does on a committee miss.
        state
            .verification
            .park_beacon_witness_awaiting_committee(block_hash);

        // Beacon still behind epoch 5: the block re-parks, nothing dispatches.
        let actions = state.on_beacon_block_persisted(&schedule);
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::VerifyBeaconWitnessRoot { .. })),
            "a still-behind beacon must not dispatch: {actions:?}"
        );

        // Beacon adopts epoch 5: the parked verification replays.
        schedule.insert(
            Epoch::new(5),
            Arc::new(committee_snapshot_with_ids(&[0, 1, 2, 3])),
        );
        let actions = state.on_beacon_block_persisted(&schedule);
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::VerifyBeaconWitnessRoot { .. })),
            "epoch adoption must replay the parked beacon-witness verification; got {actions:?}"
        );
    }

    #[test]
    fn sync_recovers_hole_left_by_failed_qc_verification() {
        // A synced block that fails QC verification leaves a gap with
        // verified entries stranded above it. The re-fetched replacement
        // arrives above `committed + 1` (admission runs ahead of the lagging
        // round-contiguous commit), so it lands in the buffer — and the
        // drain must reach down to that hole instead of starting above the
        // stranded heights, or sync wedges until restart.
        let (mut state, topology_schedule) = make_test_state();
        state.set_time(LocalTimestamp::from_millis(100_000));
        state.committed_height = BlockHeight::new(3);
        state.set_block_syncing(true);
        // Height 4 admitted to chain state, commit lagging a block behind.
        state.block_sync.mark_applied(
            BlockHeight::new(4),
            BlockHash::from_raw(Hash::from_bytes(b"applied4")),
        );

        let deliver = |state: &mut ShardCoordinator, height: u64, ts: u64| {
            let block = block_with_parent_qc_ts(BlockHeight::new(height), ts);
            let block_hash = block.hash();
            let mut signers = SignerBitfield::new(4);
            signers.set(0);
            signers.set(1);
            signers.set(2);
            let qc = QuorumCertificate::new(
                block_hash,
                ShardId::ROOT,
                BlockHeight::new(height),
                block.header().parent_block_hash(),
                block.header().round(),
                signers,
                zero_bls_signature(),
                WeightedTimestamp::from_millis(ts),
            );
            let actions = state.on_sync_block_ready_to_apply(
                &topology_schedule,
                CertifiedBlock::new_unchecked(block, qc),
            );
            (block_hash, actions)
        };

        let (hash5, actions) = deliver(&mut state, 5, 100);
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::VerifyQcSignature { .. }))
        );
        let (hash6, _) = deliver(&mut state, 6, 110);
        let (hash7, _) = deliver(&mut state, 7, 120);

        // 6 and 7 verify; 5 fails (Byzantine peer served a forged QC).
        for (hash, height) in [(hash6, 6), (hash7, 7)] {
            let qc = make_test_qc(hash, BlockHeight::new(height));
            let _ = state.on_qc_signature_verified(&topology_schedule, hash, Ok(qc));
        }
        let _ = state.on_qc_signature_verified(
            &topology_schedule,
            hash5,
            Err(QcVerifyError::InvalidSignature),
        );

        // The honest replacement at height 5 buffers (5 > committed + 1) and
        // must drain into a fresh verification despite 6 and 7 pending above.
        let (hash5b, actions) = deliver(&mut state, 5, 200);
        assert_ne!(hash5b, hash5);
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::VerifyQcSignature { .. })),
            "re-fetched block at the hole must resubmit for verification; got {actions:?}"
        );
    }

    #[test]
    fn sync_applies_certified_sibling_at_already_applied_height() {
        // HotStuff-2 fork-safety allows two QCs to certify sibling blocks
        // at one height, and a peer can serve block sync the sibling that
        // never commits. The committing sibling's later delivery must
        // still verify and apply — buried below the applied frontier, the
        // round-contiguous commit walk defers forever on its missing
        // handle and the node wedges on a height it believes is synced.
        let (mut state, topology_schedule) = make_test_state();
        state.set_time(LocalTimestamp::from_millis(100_000));
        state.committed_height = BlockHeight::new(3);
        state.set_block_syncing(true);

        let deliver = |state: &mut ShardCoordinator, height: u64, ts: u64| {
            let block = block_with_parent_qc_ts(BlockHeight::new(height), ts);
            let block_hash = block.hash();
            let mut signers = SignerBitfield::new(4);
            signers.set(0);
            signers.set(1);
            signers.set(2);
            let qc = QuorumCertificate::new(
                block_hash,
                ShardId::ROOT,
                BlockHeight::new(height),
                block.header().parent_block_hash(),
                block.header().round(),
                signers,
                zero_bls_signature(),
                WeightedTimestamp::from_millis(ts),
            );
            let actions = state.on_sync_block_ready_to_apply(
                &topology_schedule,
                CertifiedBlock::new_unchecked(block, qc),
            );
            (block_hash, actions)
        };

        // The losing sibling at height 4 arrives first and applies.
        let (loser, actions) = deliver(&mut state, 4, 100);
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::VerifyQcSignature { .. }))
        );
        let qc = make_test_qc(loser, BlockHeight::new(4));
        let _ = state.on_qc_signature_verified(&topology_schedule, loser, Ok(qc));
        assert_eq!(state.block_sync.sync_applied_height(), BlockHeight::new(4));

        // The committing sibling arrives on a re-fetch at the same height.
        let (winner, actions) = deliver(&mut state, 4, 200);
        assert_ne!(winner, loser);
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::VerifyQcSignature { .. })),
            "certified sibling at an applied height must resubmit for verification; got {actions:?}"
        );
        let qc = make_test_qc(winner, BlockHeight::new(4));
        let _ = state.on_qc_signature_verified(&topology_schedule, winner, Ok(qc));

        // Both siblings' handles are cached; the two-chain rule commits
        // whichever one a round-contiguous child extends.
        assert!(
            state
                .verification
                .cached_verified_certified_block(loser)
                .is_some()
        );
        assert!(
            state
                .verification
                .cached_verified_certified_block(winner)
                .is_some(),
            "the committing sibling's handle must be available to the commit walk"
        );
    }

    #[test]
    fn test_syncing_validator_can_vote_for_others_blocks() {
        // Syncing only blocks us from proposing content; we still vote on others'
        // blocks once verification completes.
        let (mut state, topology_schedule) = make_multi_validator_state();
        state.set_time(LocalTimestamp::from_millis(100_000));
        state.set_block_syncing(true);

        let block_hash = BlockHash::from_raw(Hash::from_bytes(b"other_proposer_block"));
        let height = BlockHeight::new(1);
        // A fresh state's current round is 1, so vote at the matching round.
        let round = Round::new(1);
        let actions = state.try_vote_on_block(&topology_schedule, block_hash, height, round);

        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::SignAndBroadcastBlockVote { .. }))
        );
        assert_eq!(state.last_voted_round(), round);
    }

    #[test]
    fn test_view_changes_allowed_during_sync() {
        // Syncing nodes still participate in view changes — they must help
        // advance the view if the leader fails, otherwise the chain stalls
        // while they catch up.
        let (mut state, topology_schedule) = make_test_state();
        state.set_time(LocalTimestamp::from_millis(100_000));
        state.view_change.last_leader_activity = Some(LocalTimestamp::ZERO);

        assert!(state.should_advance_round());
        state.set_block_syncing(true);
        assert!(state.should_advance_round());
        assert!(state.check_round_timeout(&topology_schedule).is_some());
    }

    #[test]
    fn test_sync_mode_resets_leader_activity_on_exit() {
        // Leaving sync resets leader activity to `now` so the fresh round doesn't
        // immediately time out on stale activity from before sync started.
        let (mut state, topology_schedule) = make_test_state();
        state.set_time(LocalTimestamp::from_millis(100_000));
        state.view_change.last_leader_activity = Some(LocalTimestamp::ZERO);

        state.set_block_syncing(true);
        state.on_block_sync_complete(&topology_schedule);

        assert_eq!(
            state.view_change.last_leader_activity,
            Some(LocalTimestamp::from_millis(100_000))
        );
    }

    #[test]
    fn test_start_sync_sets_syncing_flag() {
        // check_sync_health triggers StartBlockSync when the gap to latest_qc is
        // large (>3) without a pending commit.
        let (mut state, topology) = make_test_state();
        state.set_time(LocalTimestamp::from_millis(100_000));
        assert!(!state.is_block_syncing());

        state.latest_qc = Some({
            let __qc = make_test_qc(
                BlockHash::from_raw(Hash::from_bytes(b"block_5")),
                BlockHeight::new(5),
            );
            // SAFETY: synthetic test fixture, no real signature.
            Verified::<QuorumCertificate>::new_unchecked_for_test(QuorumCertificate::new(
                __qc.block_hash(),
                __qc.shard_id(),
                __qc.height(),
                BlockHash::from_raw(Hash::from_bytes(b"block_4")),
                __qc.round(),
                __qc.signers().clone(),
                __qc.aggregated_signature(),
                WeightedTimestamp::from_millis(1000),
            ))
        });
        let actions = state.check_sync_health(&topology);

        assert!(state.is_block_syncing());
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::StartBlockSync { .. }))
        );
    }

    #[test]
    fn test_sync_block_with_subquorum_qc_is_rejected_before_verification() {
        // A synced block whose QC has only one signer in a 4-validator
        // committee (1f+1, not 2f+1) must be rejected before reaching the
        // BLS-only `VerifyQcSignature` action. Without this gate a Byzantine
        // peer can fork the local chain by serving a self-signed block.
        let (mut state, topology_schedule) = make_test_state();
        state.set_time(LocalTimestamp::from_millis(100_000));

        let block = Block::Live {
            header: {
                let __h = make_header_at_height(BlockHeight::new(1), 1000);
                BlockHeader::new(
                    __h.shard_id(),
                    __h.height(),
                    BlockHash::ZERO,
                    __h.parent_qc().clone(),
                    __h.proposer(),
                    ProposerTimestamp::from_millis(1000),
                    __h.round(),
                    __h.is_fallback(),
                    __h.state_root(),
                    __h.transaction_root(),
                    __h.certificate_root(),
                    __h.local_receipt_root(),
                    __h.provision_root(),
                    __h.waves().clone().into_inner(),
                    __h.provision_tx_roots().clone().into_inner(),
                    __h.in_flight(),
                    BeaconWitnessRoot::ZERO,
                    BeaconWitnessLeafCount::ZERO,
                    BeaconWitnessLeafCount::ZERO,
                    None,
                    None,
                )
            },
            transactions: Arc::new(BoundedVec::new()),
            certificates: Arc::new(BoundedVec::new()),
            provisions: Arc::new(BoundedVec::new()),
            ready_signals: Arc::new(BoundedVec::new()),
            equivocations: Arc::new(BoundedVec::new()),
            reshape_trigger: None,
            randomness_reveal: VrfProof::ZERO,
        };
        let mut sub_quorum_signers = SignerBitfield::new(4);
        sub_quorum_signers.set(0); // single signer — far below 2f+1 = 3
        let qc = {
            let __qc = make_test_qc(block.hash(), BlockHeight::new(1));
            QuorumCertificate::new(
                __qc.block_hash(),
                __qc.shard_id(),
                __qc.height(),
                __qc.parent_block_hash(),
                __qc.round(),
                sub_quorum_signers,
                __qc.aggregated_signature(),
                WeightedTimestamp::from_millis(1000),
            )
        };
        let certified = CertifiedBlock::new_unchecked(block, qc);

        let actions = state.on_sync_block_ready_to_apply(&topology_schedule, certified);
        assert!(
            actions.is_empty(),
            "sub-quorum sync block must produce no VerifyQcSignature dispatch"
        );
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::VerifyQcSignature { .. })),
            "must not reach BLS verification with sub-quorum signers"
        );
    }

    #[test]
    #[should_panic(expected = "commit linkage broken")]
    fn commit_panics_when_block_does_not_extend_committed_tip() {
        // Defense-in-depth: a block whose parent isn't the committed tip means
        // a fork slipped past the safe-vote / round-contiguous rules, so the
        // commit path fails fast rather than splicing a divergent chain on.
        let (mut state, topology_schedule) = make_test_state();
        state.committed_height = BlockHeight::new(0);
        state.committed_hash = BlockHash::from_raw(Hash::from_bytes(b"real-tip"));

        // A height-1 block that extends some other block, not the committed tip.
        let block = Block::Live {
            header: {
                let __h = make_header_at_height(BlockHeight::new(1), 1000);
                BlockHeader::new(
                    __h.shard_id(),
                    __h.height(),
                    BlockHash::from_raw(Hash::from_bytes(b"wrong-parent")),
                    __h.parent_qc().clone(),
                    __h.proposer(),
                    ProposerTimestamp::from_millis(1000),
                    __h.round(),
                    __h.is_fallback(),
                    __h.state_root(),
                    __h.transaction_root(),
                    __h.certificate_root(),
                    __h.local_receipt_root(),
                    __h.provision_root(),
                    __h.waves().clone().into_inner(),
                    __h.provision_tx_roots().clone().into_inner(),
                    __h.in_flight(),
                    BeaconWitnessRoot::ZERO,
                    BeaconWitnessLeafCount::ZERO,
                    BeaconWitnessLeafCount::ZERO,
                    None,
                    None,
                )
            },
            transactions: Arc::new(BoundedVec::new()),
            certificates: Arc::new(BoundedVec::new()),
            provisions: Arc::new(BoundedVec::new()),
            ready_signals: Arc::new(BoundedVec::new()),
            equivocations: Arc::new(BoundedVec::new()),
            reshape_trigger: None,
            randomness_reveal: VrfProof::ZERO,
        };
        let block_hash = block.hash();
        // The linkage assert fires before the committee resolves, so a
        // placeholder QC suffices.
        let _ = state.record_block_committed(
            &topology_schedule,
            &block,
            block_hash,
            &QuorumCertificate::genesis(block.header().shard_id(), ChainOrigin::ROOT),
            WeightedTimestamp::from_millis(1000),
        );
    }

    #[test]
    fn test_stale_sync_block_ignored() {
        // A synced block below committed_height must be dropped without advancing
        // any state — including the syncing flag.
        let (mut state, topology_schedule) = make_test_state();
        state.set_time(LocalTimestamp::from_millis(100_000));
        state.committed_height = BlockHeight::new(10);

        let block = Block::Live {
            header: {
                let __h = make_header_at_height(BlockHeight::new(1), 1000);
                BlockHeader::new(
                    __h.shard_id(),
                    __h.height(),
                    BlockHash::ZERO,
                    __h.parent_qc().clone(),
                    __h.proposer(),
                    ProposerTimestamp::from_millis(1000),
                    __h.round(),
                    __h.is_fallback(),
                    __h.state_root(),
                    __h.transaction_root(),
                    __h.certificate_root(),
                    __h.local_receipt_root(),
                    __h.provision_root(),
                    __h.waves().clone().into_inner(),
                    __h.provision_tx_roots().clone().into_inner(),
                    __h.in_flight(),
                    BeaconWitnessRoot::ZERO,
                    BeaconWitnessLeafCount::ZERO,
                    BeaconWitnessLeafCount::ZERO,
                    None,
                    None,
                )
            },
            transactions: Arc::new(BoundedVec::new()),
            certificates: Arc::new(BoundedVec::new()),
            provisions: Arc::new(BoundedVec::new()),
            ready_signals: Arc::new(BoundedVec::new()),
            equivocations: Arc::new(BoundedVec::new()),
            reshape_trigger: None,
            randomness_reveal: VrfProof::ZERO,
        };
        let qc = {
            let __qc = make_test_qc(block.hash(), BlockHeight::new(1));
            QuorumCertificate::new(
                __qc.block_hash(),
                __qc.shard_id(),
                __qc.height(),
                __qc.parent_block_hash(),
                __qc.round(),
                __qc.signers().clone(),
                __qc.aggregated_signature(),
                WeightedTimestamp::from_millis(1000),
            )
        };
        let certified = CertifiedBlock::new_unchecked(block, qc);

        let actions = state.on_sync_block_ready_to_apply(&topology_schedule, certified);
        assert!(actions.is_empty());
        assert!(!state.is_block_syncing());
    }

    #[test]
    fn test_sync_block_records_leader_activity() {
        // Dispatching a sync proposal is progress — it must reset the leader
        // activity timer so we don't immediately view-change out of it.
        let (mut state, topology_schedule) = make_test_state();
        state.set_time(LocalTimestamp::from_millis(100_000));
        state.view_change.last_leader_activity = Some(LocalTimestamp::ZERO);

        state.latest_qc = Some({
            let __qc = make_test_qc(
                BlockHash::from_raw(Hash::from_bytes(b"block_3")),
                BlockHeight::new(3),
            );
            // SAFETY: synthetic test fixture, no real signature.
            Verified::<QuorumCertificate>::new_unchecked_for_test(QuorumCertificate::new(
                __qc.block_hash(),
                __qc.shard_id(),
                __qc.height(),
                BlockHash::from_raw(Hash::from_bytes(b"block_2")),
                __qc.round(),
                __qc.signers().clone(),
                __qc.aggregated_signature(),
                __qc.weighted_timestamp(),
            ))
        });
        // Height 4 proposes at round 4 (rounds increase per block).
        state.view_change.view = Round::new(4);
        state.set_block_syncing(true);
        let _ = state.try_propose(&topology_schedule, &[], vec![], vec![]);

        assert_eq!(
            state.view_change.last_leader_activity,
            Some(LocalTimestamp::from_millis(100_000))
        );
    }

    #[test]
    fn test_sync_block_vs_fallback_block_differences() {
        // Sync blocks use current time and is_fallback=false; fallback blocks
        // inherit the parent's weighted timestamp and set is_fallback=true.
        let (mut state, topology_schedule) = make_test_state();
        state.set_time(LocalTimestamp::from_millis(100_000));
        state.committed_height = BlockHeight::new(3);
        state.verification.on_block_persisted(BlockHeight::new(3));

        let parent_timestamp = 50_000u64;
        state.latest_qc = Some({
            let __qc = make_test_qc(
                BlockHash::from_raw(Hash::from_bytes(b"block_3")),
                BlockHeight::new(3),
            );
            // SAFETY: synthetic test fixture, no real signature.
            Verified::<QuorumCertificate>::new_unchecked_for_test(QuorumCertificate::new(
                __qc.block_hash(),
                __qc.shard_id(),
                __qc.height(),
                BlockHash::from_raw(Hash::from_bytes(b"block_2")),
                __qc.round(),
                __qc.signers().clone(),
                __qc.aggregated_signature(),
                WeightedTimestamp::from_millis(parent_timestamp),
            ))
        });

        state.set_block_syncing(true);
        let sync_actions = state.build_and_dispatch_proposal(
            &topology_schedule,
            BlockHeight::new(4),
            Round::new(0),
            ProposalKind::Sync,
        );
        state.set_block_syncing(false);

        state.pending_blocks.clear();

        let fallback_actions = state.build_and_broadcast_fallback_block(
            &topology_schedule,
            BlockHeight::new(4),
            Round::new(1),
        );

        let find_proposal = |actions: &[Action]| -> (bool, ProposerTimestamp) {
            for a in actions {
                if let Action::BuildProposal {
                    is_fallback,
                    timestamp,
                    ..
                } = a
                {
                    return (*is_fallback, *timestamp);
                }
            }
            panic!("expected a BuildProposal");
        };
        let (sync_fb, sync_ts) = find_proposal(&sync_actions);
        let (fb_fb, fb_ts) = find_proposal(&fallback_actions);

        assert!(!sync_fb);
        assert_eq!(sync_ts, ProposerTimestamp::from_millis(100_000));
        assert!(fb_fb);
        assert_eq!(fb_ts, ProposerTimestamp::from_millis(parent_timestamp));
    }

    #[test]
    fn test_chain_advances_with_syncing_proposer() {
        // Sync mode must not suppress proposal — a syncing proposer still emits
        // BuildProposal (with an empty payload) so the chain keeps advancing.
        let (mut state, topology_schedule) = make_test_state();
        state.set_time(LocalTimestamp::from_millis(100_000));
        state.committed_height = BlockHeight::new(3);
        state.verification.on_block_persisted(BlockHeight::new(3));

        state.latest_qc = Some({
            let __qc = make_test_qc(
                BlockHash::from_raw(Hash::from_bytes(b"block_3")),
                BlockHeight::new(3),
            );
            // SAFETY: synthetic test fixture, no real signature.
            Verified::<QuorumCertificate>::new_unchecked_for_test(QuorumCertificate::new(
                __qc.block_hash(),
                __qc.shard_id(),
                __qc.height(),
                BlockHash::from_raw(Hash::from_bytes(b"block_2")),
                __qc.round(),
                __qc.signers().clone(),
                __qc.aggregated_signature(),
                __qc.weighted_timestamp(),
            ))
        });
        // Height 4 proposes at round 4 (rounds increase per block).
        state.view_change.view = Round::new(4);
        state.set_block_syncing(true);

        let actions = state.try_propose(&topology_schedule, &[], vec![], vec![]);
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::BuildProposal { .. }))
        );
    }

    #[test]
    fn test_validate_no_duplicate_transactions_rejects_cross_block_dup() {
        let (mut state, _topology) = make_test_state();
        state.committed_height = BlockHeight::new(3);

        let tx1 = make_test_tx_with_seed(10);
        let tx2 = make_test_tx_with_seed(20);
        // Ancestor block at height 5 contains tx1
        let ancestor_block = Block::Live {
            header: {
                let __h = make_header_at_height(BlockHeight::new(5), 100_000);
                BlockHeader::new(
                    __h.shard_id(),
                    __h.height(),
                    BlockHash::from_raw(Hash::from_bytes(b"grandparent")),
                    __h.parent_qc().clone(),
                    __h.proposer(),
                    __h.timestamp(),
                    __h.round(),
                    __h.is_fallback(),
                    __h.state_root(),
                    __h.transaction_root(),
                    __h.certificate_root(),
                    __h.local_receipt_root(),
                    __h.provision_root(),
                    __h.waves().clone().into_inner(),
                    __h.provision_tx_roots().clone().into_inner(),
                    __h.in_flight(),
                    BeaconWitnessRoot::ZERO,
                    BeaconWitnessLeafCount::ZERO,
                    BeaconWitnessLeafCount::ZERO,
                    None,
                    None,
                )
            },
            transactions: Arc::new(vec![tx1.clone()].into()),
            certificates: Arc::new(BoundedVec::new()),
            provisions: Arc::new(BoundedVec::new()),
            ready_signals: Arc::new(BoundedVec::new()),
            equivocations: Arc::new(BoundedVec::new()),
            reshape_trigger: None,
            randomness_reveal: VrfProof::ZERO,
        };
        let ancestor_hash = ancestor_block.hash();
        install_complete_block(&mut state, &ancestor_block);

        // New block at height 6, parent = ancestor, contains tx1 (duplicate) + tx2
        let mut txs = vec![tx1, tx2];
        sort_txs_by_hash(&mut txs);
        let block = Block::Live {
            header: {
                let __h = make_header_at_height(BlockHeight::new(6), 100_001);
                BlockHeader::new(
                    __h.shard_id(),
                    __h.height(),
                    ancestor_hash,
                    __h.parent_qc().clone(),
                    __h.proposer(),
                    __h.timestamp(),
                    __h.round(),
                    __h.is_fallback(),
                    __h.state_root(),
                    __h.transaction_root(),
                    __h.certificate_root(),
                    __h.local_receipt_root(),
                    __h.provision_root(),
                    __h.waves().clone().into_inner(),
                    __h.provision_tx_roots().clone().into_inner(),
                    __h.in_flight(),
                    BeaconWitnessRoot::ZERO,
                    BeaconWitnessLeafCount::ZERO,
                    BeaconWitnessLeafCount::ZERO,
                    None,
                    None,
                )
            },
            transactions: Arc::new(txs.into()),
            certificates: Arc::new(BoundedVec::new()),
            provisions: Arc::new(BoundedVec::new()),
            ready_signals: Arc::new(BoundedVec::new()),
            equivocations: Arc::new(BoundedVec::new()),
            reshape_trigger: None,
            randomness_reveal: VrfProof::ZERO,
        };

        let result = {
            let (_, qc_chain, _) =
                state.collect_qc_chain_hashes(block.header().parent_block_hash());
            validate_no_duplicate_transactions(&block, &qc_chain, &state.dedup_index)
        };
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already in QC chain ancestor"));
    }

    #[test]
    fn test_validate_no_duplicate_transactions_ignores_committed_ancestors() {
        let (mut state, _topology) = make_test_state();
        state.committed_height = BlockHeight::new(5);

        let tx1 = make_test_tx_with_seed(10);

        // Ancestor at height 5 (== committed_height) contains tx1
        let ancestor_block = Block::Live {
            header: {
                let __h = make_header_at_height(BlockHeight::new(5), 100_000);
                BlockHeader::new(
                    __h.shard_id(),
                    __h.height(),
                    BlockHash::from_raw(Hash::from_bytes(b"grandparent")),
                    __h.parent_qc().clone(),
                    __h.proposer(),
                    __h.timestamp(),
                    __h.round(),
                    __h.is_fallback(),
                    __h.state_root(),
                    __h.transaction_root(),
                    __h.certificate_root(),
                    __h.local_receipt_root(),
                    __h.provision_root(),
                    __h.waves().clone().into_inner(),
                    __h.provision_tx_roots().clone().into_inner(),
                    __h.in_flight(),
                    BeaconWitnessRoot::ZERO,
                    BeaconWitnessLeafCount::ZERO,
                    BeaconWitnessLeafCount::ZERO,
                    None,
                    None,
                )
            },
            transactions: Arc::new(vec![tx1.clone()].into()),
            certificates: Arc::new(BoundedVec::new()),
            provisions: Arc::new(BoundedVec::new()),
            ready_signals: Arc::new(BoundedVec::new()),
            equivocations: Arc::new(BoundedVec::new()),
            reshape_trigger: None,
            randomness_reveal: VrfProof::ZERO,
        };
        let ancestor_hash = ancestor_block.hash();

        // Block at height 6, parent = ancestor. tx1 is in ancestor but ancestor
        // is at committed height so the walk stops — this should be allowed.
        let block = Block::Live {
            header: {
                let __h = make_header_at_height(BlockHeight::new(6), 100_001);
                BlockHeader::new(
                    __h.shard_id(),
                    __h.height(),
                    ancestor_hash,
                    __h.parent_qc().clone(),
                    __h.proposer(),
                    __h.timestamp(),
                    __h.round(),
                    __h.is_fallback(),
                    __h.state_root(),
                    __h.transaction_root(),
                    __h.certificate_root(),
                    __h.local_receipt_root(),
                    __h.provision_root(),
                    __h.waves().clone().into_inner(),
                    __h.provision_tx_roots().clone().into_inner(),
                    __h.in_flight(),
                    BeaconWitnessRoot::ZERO,
                    BeaconWitnessLeafCount::ZERO,
                    BeaconWitnessLeafCount::ZERO,
                    None,
                    None,
                )
            },
            transactions: Arc::new(vec![tx1].into()),
            certificates: Arc::new(BoundedVec::new()),
            provisions: Arc::new(BoundedVec::new()),
            ready_signals: Arc::new(BoundedVec::new()),
            equivocations: Arc::new(BoundedVec::new()),
            reshape_trigger: None,
            randomness_reveal: VrfProof::ZERO,
        };

        // Ancestor is at committed height, so walk stops before checking it
        assert!(
            {
                let (_, qc_chain, _) =
                    state.collect_qc_chain_hashes(block.header().parent_block_hash());
                validate_no_duplicate_transactions(&block, &qc_chain, &state.dedup_index)
            }
            .is_ok()
        );
    }

    /// Schedule whose window 0 carries `ROOT` (the coordinator's shard,
    /// with the full validator set) and whose window 1 carries its two
    /// children instead — `ROOT`'s terminal window is 0 and any weighted
    /// timestamp past 1000ms is coast territory.
    fn make_terminating_schedule(n: usize) -> TopologySchedule {
        let keys: Vec<Bls12381G1PrivateKey> = (0..n).map(|_| generate_bls_keypair()).collect();
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| ValidatorInfo {
                validator_id: ValidatorId::new(i as u64),
                public_key: k.public_key(),
            })
            .collect();
        let final_window = Arc::new(TopologySnapshot::new(
            NetworkDefinition::simulator(),
            1,
            ValidatorSet::new(validators.clone()),
        ));
        let post_split = Arc::new(TopologySnapshot::new(
            NetworkDefinition::simulator(),
            2,
            ValidatorSet::new(validators),
        ));
        let mut sched = TopologySchedule::new(1000, Epoch::new(0), final_window);
        sched.insert(Epoch::new(1), post_split);
        sched
    }

    /// [`make_terminating_schedule`] whose head additionally shows both of
    /// `ROOT`'s children live — seated and advanced past genesis — so a
    /// quiescent `ROOT` reads its successors as live and may dissolve.
    fn make_terminating_schedule_live_children(n: usize) -> TopologySchedule {
        let mut sched = make_terminating_schedule(n);
        let (left, right) = ShardId::ROOT.children();
        let validators = ValidatorSet::new(
            (0..n)
                .map(|i| ValidatorInfo {
                    validator_id: ValidatorId::new(i as u64),
                    public_key: generate_bls_keypair().public_key(),
                })
                .collect(),
        );
        let mut advanced = BTreeSet::new();
        advanced.insert(left);
        advanced.insert(right);
        let live_head = TopologySnapshot::new(NetworkDefinition::simulator(), 2, validators)
            .with_advanced(advanced);
        sched.set_head(Arc::new(live_head));
        sched
    }

    /// A schedule whose two genesis leaves merge into their parent `ROOT` at
    /// the epoch-0→1 boundary — the merge counterpart of
    /// [`make_terminating_schedule`]: the final window carries both children,
    /// the next carries only the parent.
    fn make_merging_schedule(n: usize) -> TopologySchedule {
        let keys: Vec<Bls12381G1PrivateKey> = (0..n).map(|_| generate_bls_keypair()).collect();
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| ValidatorInfo {
                validator_id: ValidatorId::new(i as u64),
                public_key: k.public_key(),
            })
            .collect();
        let pre_merge = Arc::new(TopologySnapshot::new(
            NetworkDefinition::simulator(),
            2,
            ValidatorSet::new(validators.clone()),
        ));
        let post_merge = Arc::new(TopologySnapshot::new(
            NetworkDefinition::simulator(),
            1,
            ValidatorSet::new(validators),
        ));
        let mut sched = TopologySchedule::new(1000, Epoch::new(0), pre_merge);
        sched.insert(Epoch::new(1), post_merge);
        sched
    }

    fn coordinator_with_committed_anchor(anchor_ms: u64) -> ShardCoordinator {
        let recovered = RecoveredState {
            committed_anchor_ts: Some(WeightedTimestamp::from_millis(anchor_ms)),
            ..RecoveredState::default()
        };
        ShardCoordinator::new(
            ValidatorId::new(0),
            ShardId::ROOT,
            ShardConsensusConfig::default(),
            recovered,
        )
    }

    #[test]
    fn chain_quiesces_once_a_coast_block_commits() {
        let sched = make_terminating_schedule(4);
        // Committed tip anchored inside the final window: still live.
        let live = coordinator_with_committed_anchor(500);
        assert!(!live.quiescent(&sched));
        // Committed tip anchored past the cut — the first coast block has
        // committed, so the crossing's canonical QC is readable: content stops.
        let done = coordinator_with_committed_anchor(1500);
        assert!(done.quiescent(&sched));
    }

    #[test]
    fn quiescent_chain_coasts_until_its_successors_are_live() {
        // Round 4 makes this validator (id 0 of 4) the proposer.
        // Quiescent (committed past the cut) but the children aren't live yet:
        // the chain keeps coasting — still proposes empty blocks and runs its
        // pacemaker — to hold the committee together so the terminal commits.
        let coasting = make_terminating_schedule(4);
        let mut done = coordinator_with_committed_anchor(1500);
        assert!(done.quiescent(&coasting));
        assert!(!done.dissolved(&coasting));
        assert!(done.can_propose(&coasting, BlockHeight::new(1), Round::new(4)));
        assert!(!done.broadcast_timeout(&coasting, Round::new(4)).is_empty());

        // Once the beacon shows both children live, the chain dissolves: no
        // more proposals, no timeouts.
        let dissolved = make_terminating_schedule_live_children(4);
        let mut done = coordinator_with_committed_anchor(1500);
        assert!(done.dissolved(&dissolved));
        assert!(!done.can_propose(&dissolved, BlockHeight::new(1), Round::new(4)));
        assert!(done.broadcast_timeout(&dissolved, Round::new(4)).is_empty());

        // A chain not yet past the cut proposes and times out regardless.
        let mut live = coordinator_with_committed_anchor(500);
        assert!(live.can_propose(&coasting, BlockHeight::new(1), Round::new(4)));
        assert!(!live.broadcast_timeout(&coasting, Round::new(4)).is_empty());
    }

    #[test]
    fn dissolved_chain_ignores_new_headers() {
        // A dissolved chain (quiescent and its successors live) ingests nothing.
        let dissolved = make_terminating_schedule_live_children(4);
        let mut done = coordinator_with_committed_anchor(1500);
        let block = block_with_parent_qc_ts(BlockHeight::new(1), 500);
        let actions = done.on_block_header(
            &dissolved,
            block.header(),
            BlockManifest::default(),
            |_| None,
            |_| None,
            |_| None,
        );
        assert!(actions.is_empty());

        // A quiescent-but-coasting chain has not dissolved, so the ingest gate
        // doesn't drop its coast-block headers — the committee keeps voting so
        // the terminal can collect its commit votes.
        let coasting = make_terminating_schedule(4);
        assert!(!coordinator_with_committed_anchor(1500).dissolved(&coasting));
    }

    #[test]
    fn quiesce_cut_fires_at_split_and_merge_boundaries() {
        // ROOT splits into its children at the epoch-0→1 boundary, so a
        // ROOT proposer anchored in epoch 0 is in its final epoch: the cut
        // is the end of that window (1000 ms), the anchor its tip (genesis,
        // 0 ms).
        let splitting = make_terminating_schedule(4);
        let root = ShardCoordinator::new(
            ValidatorId::new(0),
            ShardId::ROOT,
            ShardConsensusConfig::default(),
            RecoveredState::default(),
        );
        let cut = root
            .quiesce_cut(&splitting)
            .expect("ROOT is in its final epoch before the split");
        assert_eq!(cut.now_wt, WeightedTimestamp::from_millis(0));
        assert_eq!(cut.cut_wt, WeightedTimestamp::from_millis(1000));

        // A merging child — its two-leaf window collapses to the parent at
        // the boundary — is likewise in its final epoch and must quiesce.
        // This is the case the split-only predicate missed.
        let merging = make_merging_schedule(4);
        let (left, _) = ShardId::ROOT.children();
        let child = ShardCoordinator::new(
            ValidatorId::new(0),
            left,
            ShardConsensusConfig::default(),
            RecoveredState::default(),
        );
        let merge_cut = child
            .quiesce_cut(&merging)
            .expect("a merging child is in its final epoch before the merge");
        assert_eq!(merge_cut.cut_wt, WeightedTimestamp::from_millis(1000));

        // A shard present in both the current and the next window never
        // terminates at the boundary, so the quiesce stays inert.
        let stable = {
            let keys: Vec<Bls12381G1PrivateKey> = (0..4).map(|_| generate_bls_keypair()).collect();
            let validators: Vec<ValidatorInfo> = keys
                .iter()
                .enumerate()
                .map(|(i, k)| ValidatorInfo {
                    validator_id: ValidatorId::new(i as u64),
                    public_key: k.public_key(),
                })
                .collect();
            let window = Arc::new(TopologySnapshot::new(
                NetworkDefinition::simulator(),
                1,
                ValidatorSet::new(validators),
            ));
            let mut sched = TopologySchedule::new(1000, Epoch::new(0), Arc::clone(&window));
            sched.insert(Epoch::new(1), window);
            sched
        };
        assert!(
            root.quiesce_cut(&stable).is_none(),
            "no reshape pending → no quiesce cut",
        );
    }

    // ─── Split-boundary fence ────────────────────────────────────────────

    /// A live child coordinator (`leaf(1,0)`) of a `ROOT` that terminated
    /// at wt 1000 — so `ROOT` is past-terminal at any later anchor.
    fn fence_coordinator() -> ShardCoordinator {
        ShardCoordinator::new(
            ValidatorId::new(0),
            ShardId::leaf(1, 0),
            ShardConsensusConfig::default(),
            RecoveredState::default(),
        )
    }

    /// A finalized wave whose certificate carries this validator's local
    /// EC plus a remote EC on `remote` — the cross-shard shape the fence
    /// inspects.
    fn cross_shard_wave(
        local: ShardId,
        remote: ShardId,
        height: u64,
    ) -> Arc<Verifiable<FinalizedWave>> {
        use hyperscale_types::{
            ExecutionCertificate, ExecutionOutcome, GlobalReceiptHash, GlobalReceiptRoot,
            SignerBitfield, TxOutcome, WaveCertificate,
        };
        let ec = |shard: ShardId| {
            let wave = WaveId::new(shard, BlockHeight::new(height), BTreeSet::new());
            ExecutionCertificate::new(
                wave,
                WeightedTimestamp::from_millis(height),
                GlobalReceiptRoot::ZERO,
                vec![TxOutcome::new(
                    TxHash::from_raw(Hash::from_bytes(b"tx")),
                    ExecutionOutcome::Succeeded {
                        receipt_hash: GlobalReceiptHash::ZERO,
                    },
                )],
                zero_bls_signature(),
                SignerBitfield::new(4),
            )
        };
        let local_wave = WaveId::new(local, BlockHeight::new(height), BTreeSet::new());
        let wc = WaveCertificate::new(local_wave, vec![Arc::new(ec(local)), Arc::new(ec(remote))]);
        Arc::new(Verifiable::from(FinalizedWave::new(Arc::new(wc), vec![])))
    }

    fn block_with_certs(certs: Vec<Arc<Verifiable<FinalizedWave>>>) -> Block {
        Block::Live {
            header: make_header_at_height(BlockHeight::new(1), 1500),
            transactions: Arc::new(BoundedVec::new()),
            certificates: Arc::new(certs.into()),
            provisions: Arc::new(BoundedVec::new()),
            ready_signals: Arc::new(BoundedVec::new()),
            equivocations: Arc::new(BoundedVec::new()),
            reshape_trigger: None,
            randomness_reveal: VrfProof::ZERO,
        }
    }

    /// A finalized wave naming a past-terminal shard whose settled set is
    /// unknown defers the vote.
    #[test]
    fn fence_defers_when_settled_set_unknown() {
        let coord = fence_coordinator();
        let sched = make_terminating_schedule(4);
        let block = block_with_certs(vec![cross_shard_wave(
            ShardId::leaf(1, 0),
            ShardId::ROOT,
            1,
        )]);
        assert_eq!(
            coord.fence_finalized_waves(&sched, &block, WeightedTimestamp::from_millis(1500)),
            SettledSetVerdict::Defer,
        );
    }

    /// Once the past-terminal shard's settled set is known and contains
    /// the wave, the vote passes.
    #[test]
    fn fence_passes_when_wave_settled() {
        let mut coord = fence_coordinator();
        let sched = make_terminating_schedule(4);
        let settled_wave = WaveId::new(ShardId::ROOT, BlockHeight::new(1), BTreeSet::new());
        coord.record_settled_waves(
            ShardId::ROOT,
            SettledWaveSet {
                waves: std::iter::once(settled_wave).collect(),
                terminal_wt: WeightedTimestamp::from_millis(1000),
            },
        );
        let block = block_with_certs(vec![cross_shard_wave(
            ShardId::leaf(1, 0),
            ShardId::ROOT,
            1,
        )]);
        assert_eq!(
            coord.fence_finalized_waves(&sched, &block, WeightedTimestamp::from_millis(1500)),
            SettledSetVerdict::Pass,
        );
    }

    /// A wave the past-terminal shard did not settle is rejected.
    #[test]
    fn fence_rejects_unsettled_wave() {
        let mut coord = fence_coordinator();
        let sched = make_terminating_schedule(4);
        coord.record_settled_waves(
            ShardId::ROOT,
            SettledWaveSet {
                waves: BTreeSet::new(),
                terminal_wt: WeightedTimestamp::from_millis(1000),
            },
        );
        let block = block_with_certs(vec![cross_shard_wave(
            ShardId::leaf(1, 0),
            ShardId::ROOT,
            1,
        )]);
        assert_eq!(
            coord.fence_finalized_waves(&sched, &block, WeightedTimestamp::from_millis(1500)),
            SettledSetVerdict::Reject,
        );
    }

    /// Past `terminal_wt + RETENTION_HORIZON`, a wave naming the
    /// terminated shard is categorically unreachable and rejects, even if
    /// the (stale) settled set happens to contain it.
    #[test]
    fn fence_rejects_past_retention_horizon() {
        let mut coord = fence_coordinator();
        let sched = make_terminating_schedule(4);
        let settled_wave = WaveId::new(ShardId::ROOT, BlockHeight::new(1), BTreeSet::new());
        coord.record_settled_waves(
            ShardId::ROOT,
            SettledWaveSet {
                waves: std::iter::once(settled_wave).collect(),
                terminal_wt: WeightedTimestamp::from_millis(1000),
            },
        );
        let block = block_with_certs(vec![cross_shard_wave(
            ShardId::leaf(1, 0),
            ShardId::ROOT,
            1,
        )]);
        let beyond = WeightedTimestamp::from_millis(1000)
            .plus(RETENTION_HORIZON)
            .plus(Duration::from_millis(1));
        assert_eq!(
            coord.fence_finalized_waves(&sched, &block, beyond),
            SettledSetVerdict::Reject,
        );
    }

    /// A wave with no past-terminal-shard certificate passes regardless of
    /// any settled-set state — single-shard and live-cross-shard waves are
    /// untouched.
    #[test]
    fn fence_ignores_live_shard_certificates() {
        let coord = fence_coordinator();
        let sched = make_terminating_schedule(4);
        // Both ECs name live shards (the local child and its live sibling).
        let block = block_with_certs(vec![cross_shard_wave(
            ShardId::leaf(1, 0),
            ShardId::leaf(1, 1),
            1,
        )]);
        assert_eq!(
            coord.fence_finalized_waves(&sched, &block, WeightedTimestamp::from_millis(1500)),
            SettledSetVerdict::Pass,
        );
    }

    /// A height-1 block on `leaf(1,0)` anchored in epoch 1 (`parent_qc`
    /// weighted timestamp 1500, past ROOT's terminal window in
    /// [`make_terminating_schedule`]) carrying a finalized wave whose
    /// certificate names the past-terminal shard ROOT.
    fn straddling_block() -> Block {
        let parent_qc = QuorumCertificate::new(
            BlockHash::ZERO,
            ShardId::leaf(1, 0),
            BlockHeight::new(0),
            BlockHash::ZERO,
            Round::new(0),
            SignerBitfield::empty(),
            zero_bls_signature(),
            WeightedTimestamp::from_millis(1500),
        );
        let header = BlockHeader::new(
            ShardId::leaf(1, 0),
            BlockHeight::new(1),
            BlockHash::ZERO,
            parent_qc,
            ValidatorId::new(1),
            ProposerTimestamp::from_millis(1500),
            Round::new(1),
            false,
            StateRoot::ZERO,
            TransactionRoot::ZERO,
            CertificateRoot::ZERO,
            LocalReceiptRoot::ZERO,
            ProvisionsRoot::ZERO,
            Vec::new(),
            std::collections::BTreeMap::new(),
            InFlightCount::ZERO,
            BeaconWitnessRoot::ZERO,
            BeaconWitnessLeafCount::ZERO,
            BeaconWitnessLeafCount::ZERO,
            None,
            None,
        );
        Block::Live {
            header,
            transactions: Arc::new(BoundedVec::new()),
            certificates: Arc::new(
                vec![cross_shard_wave(ShardId::leaf(1, 0), ShardId::ROOT, 1)].into(),
            ),
            provisions: Arc::new(BoundedVec::new()),
            ready_signals: Arc::new(BoundedVec::new()),
            equivocations: Arc::new(BoundedVec::new()),
            reshape_trigger: None,
            randomness_reveal: VrfProof::ZERO,
        }
    }

    /// End to end through the real vote path: a block whose finalized
    /// wave names a past-terminal shard defers (no verification dispatched)
    /// while its settled set is unknown, then proceeds once the set is
    /// recorded and the vote is re-driven.
    #[test]
    fn vote_defers_at_fence_then_proceeds_once_settled_set_recorded() {
        // Local shard `leaf(1,0)` survives; ROOT is past-terminal at the
        // block's epoch-1 anchor.
        let mut coord = ShardCoordinator::new(
            ValidatorId::new(0),
            ShardId::leaf(1, 0),
            ShardConsensusConfig::default(),
            RecoveredState::default(),
        );
        let sched = make_terminating_schedule(4);
        let block = straddling_block();
        let block_hash = block.hash();
        let height = block.height();
        let round = block.header().round();
        // Install with the block's finalized waves threaded through, so the
        // constructed pending block carries its certificates (the default
        // `install_complete_block` helper drops them).
        let waves: Vec<Arc<Verifiable<FinalizedWave>>> =
            block.certificates().iter().cloned().collect();
        let mut pending = PendingBlock::from_complete_block(
            &block,
            vec![],
            None,
            waves,
            vec![],
            LocalTimestamp::ZERO,
        );
        pending
            .construct_block()
            .expect("complete block constructs cleanly");
        coord.pending_blocks.insert(pending);

        // The fence defers: ROOT's settled set is unknown, so the vote
        // path produces nothing (no verification, no vote).
        let deferred = coord.try_vote_on_block(&sched, block_hash, height, round);
        assert!(
            deferred.is_empty(),
            "the fence must defer the vote while the settled set is unknown: {deferred:?}",
        );

        // Record ROOT's settled set including the straddler's wave, then
        // re-drive: the fence now passes, so the block proceeds to
        // verification.
        let settled_wave = WaveId::new(ShardId::ROOT, BlockHeight::new(1), BTreeSet::new());
        coord.record_settled_waves(
            ShardId::ROOT,
            SettledWaveSet {
                waves: std::iter::once(settled_wave).collect(),
                terminal_wt: WeightedTimestamp::from_millis(1000),
            },
        );
        let released = coord.redrive_pending_votes(&sched);
        assert!(
            !released.is_empty(),
            "recording the settled set must release the deferred block into verification",
        );
    }
}
