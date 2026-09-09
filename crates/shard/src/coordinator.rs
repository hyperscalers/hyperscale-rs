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

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_core::{Action, CommitSource, FeeDemand, ProtocolEvent, TimerId};
use hyperscale_types::{
    AbandonmentRecord, Anchor, BlockHash, CheckOutcome, CounterpartMirror, DeferOn, Epoch,
    FinalizationHash, Hash, LocalTimestamp, MAX_PROGRESS_WAIT, MAX_READY_SIGNALS_PER_BLOCK,
    PrincipalAddr, ProposerTimestamp, ProvenAnchors, ProvenCells, ProvisionHash, ReadySignal,
    ReshapeThresholds, ReshapeTrigger, ScheduleLookup, ShardId, SplitAtBoundary, StateClaim,
    StoredReceipt, SubstateKey, VerificationKind, WeightedTimestamp, WorkInFlight,
    derive_reshape_trigger, ready_signal_window,
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
    /// Pending blocks awaiting transaction / tick / provision arrival.
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
    /// Whether the dedup lookups above cover the whole retention window.
    /// False while a coordinator that resumed or joined mid-chain is still
    /// folding forward to it, during which it refuses fewer duplicates
    /// than a peer that committed the window itself.
    pub dedup_window_complete: bool,
    /// Committed tick-id → deadline entries for proposal/validation dedup.
    /// Keyed by `vote_anchor_ts + RETENTION_HORIZON`.
    pub committed_resolution_lookup: usize,
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
    BeaconWitnessCommit, BeaconWitnessLeafCount, Block, BlockHeader, BlockHeight, BlockManifest,
    BlockVote, CertifiedBlock, CertifiedBlockHeader, ChainOrigin, CommittedTip, Finalization,
    MAX_ROUND_GAP, MAX_VALIDITY_RANGE, PredecessorTerminal, Provisions, QcContext, QcVerifyError,
    QuorumCertificate, RecoveryCause, Round, SafeVoteRegisters, StateRoot, Timeout,
    TopologySchedule, TopologySnapshot, Transaction, TxHash, ValidatorId, Verifiable, Verified,
    Verifier, Verify, VoteCount, VotePosition, derive_leaves, missed_proposals_since_prev_commit,
    ready_leaf_payload,
};
use tracing::field::Empty;
use tracing::{debug, info, instrument, trace, warn};

use crate::admission::{
    Admission, FinalizationsFold, ProvisionsFold, QcChainSets, RecordsFold, StateClaimsFold,
    TransactionsFold,
};
use crate::beacon_witnesses::{BeaconWitnessAccumulator, prospective_parent_witness_leaves};
use crate::block_sync::{
    BlockSyncHealthDecision, BlockSyncManager, BlockSyncVerificationResult, IngestOutcome,
};
use crate::chain_view::ChainView;
use crate::commit_dedup::CommitDedupIndex;
use crate::commit_pipeline::CommitPipeline;
use crate::config::ShardConsensusConfig;
use crate::deferred_qc::DeferredQc;
use crate::fee_ledger::FeeReservationLedger;
use crate::fence::{VoteFence, Withheld};
use crate::lookups::{committee_public_keys, vote_recipients};
use crate::pending::{OrphanedFetches, PendingBlock, PendingBlocks};
use crate::precut::Precut;
use crate::proposal::{
    Prefilter, ProposalKind, ProposalPayload, ProposalTracker, TakeResult, assemble_build_action,
    dispatch_or_defer, late_deliveries, select_abandonment_records, select_finalizations,
    select_provisions, select_state_claims, select_transactions,
};
use crate::ready_signal_pool::{MIN_READY_SIGNAL_DWELL, ReadySignalPool};
use crate::timeout_keeper::TimeoutKeeper;
use crate::validation::{
    qc_has_local_quorum_power, qc_weighted_timestamp_too_far_ahead, validate_block_for_vote,
    validate_header, validate_proposer,
};
use crate::verification::{
    InFlightCheck, ReadyStateRootVerification, SubstateCountBlocked, SubstateCountSource,
    VerificationPipeline, committed_cells_for,
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

/// Heights of committed-round history retained for the fee anchor's
/// ancestry walk (`ancestry_committed_height`). Covers the deepest
/// non-contiguous stretch a live vote's walk can descend through —
/// far past the consensus pipeline plus any view-change window — so
/// the beyond-horizon fallback only ever names a height every replica
/// committed long ago.
const COMMITTED_ROUNDS_HORIZON: usize = 128;

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
/// which signs the block's randomness reveal on the dispatch pool and
/// derives the block's leaves over `parent_window`.
struct WitnessCommitmentPreview {
    ready_signals: Vec<ReadySignal>,
    reshape_trigger: Option<ReshapeTrigger>,
    parent_window: Vec<Hash>,
    base: BeaconWitnessLeafCount,
}

/// One transaction's contribution to its payer's fee demand.
struct PayerFee {
    /// The payer's fee vault.
    vault: SubstateKey,
    /// The payer's stored-authority cell, read beside the balance.
    auth_cell: SubstateKey,
    /// The signed ceiling; zero where the caller only seeds prior
    /// demand.
    max_fee: u128,
    /// The envelope signer the payer's rule must admit — carried at
    /// vote, where the binding is judged, and absent at proposal seed.
    signer: Option<PrincipalAddr>,
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
    /// Scheme verifier for local (non-delegated) signature checks.
    verifier: Arc<dyn Verifier>,

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

    /// [`Self::block_anchor`] of the latest committed block: its parent QC's
    /// weighted timestamp. Held as a scalar because the committed tip is
    /// pruned from `pending_blocks`, so its anchor stays resolvable — and it
    /// is the committee anchor of the block extending it.
    committed_block_anchor_wt: WeightedTimestamp,

    /// [`Self::committee_anchor`] of the latest committed block — the anchor
    /// its *parent* carried. Kept alongside `committed_block_anchor_wt` because the
    /// committed tip's own parent is pruned too, so the committee that signed
    /// the tip could not otherwise be resolved when verifying the QC over it.
    committed_committee_anchor_wt: WeightedTimestamp,

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

    /// The committed tip's running values, retained so the vote path can
    /// check a block extending the tip after its header is pruned from the
    /// pending and certified caches. Seeded from the recovered tip, so a
    /// restart checks the first block it sees rather than waiting for a
    /// commit it may itself be needed to form. `None` only when no tip
    /// header was recovered, which skips the checks rather than guessing —
    /// and skips them together, because the tip either resolves or does not.
    committed_tip: Option<CommittedTip>,

    /// Latest QC (certifies the latest certified block). Verified at
    /// every adoption gate; the typestate makes that invariant local.
    latest_qc: Option<Verified<QuorumCertificate>>,

    /// The snap-synced boundary anchor's QC, structurally bound to the
    /// beacon-attested anchor by the bootstrap but not yet signature-verified.
    /// Verified against the schedule-resolved committee and adopted as
    /// `latest_qc` on the first opportunity — the parent QC the fresh
    /// committee's first block past the anchor extends. Cleared on
    /// adoption, on verification failure (a Byzantine serving peer's
    /// forgery), or when any higher QC adopts first.
    anchor_qc: Option<QuorumCertificate>,

    /// QC deferred because the block header wasn't in memory when it formed.
    /// Adopted in `on_block_header` when the header arrives.
    deferred_qc: DeferredQc,

    // ═══════════════════════════════════════════════════════════════════════════
    // Pending State
    // ═══════════════════════════════════════════════════════════════════════════
    /// Pending blocks being assembled (hash -> pending block).
    pending_blocks: PendingBlocks,
    /// Blocks the store handed back at startup, awaiting their first
    /// verification drive. They are assembled already; what they lack is
    /// the state each one left, which only re-running the verification
    /// pipeline produces — and that needs a topology schedule, which
    /// construction has no access to. Drained by
    /// [`Self::resume_recovered_blocks`] on the first periodic entry that
    /// carries one.
    recovered_blocks: Vec<BlockHash>,
    /// In-flight fee reservations at this (payer) shard — committed VM
    /// transactions whose ticks have not yet finalized.
    fee_ledger: FeeReservationLedger,
    /// The figures an abandonment record must restate for every
    /// committed transaction a record may still name — what the vote
    /// fence checks a record's entries against.
    /// Fee-reservation verifications whose balance-read anchor the local
    /// commit pipeline hasn't materialized yet: block hash → (demands,
    /// anchor). The anchor is ancestry-proven, so the commit that
    /// materializes it is coming; `record_block_committed` dispatches
    /// these as it lands.
    deferred_reservation_checks: HashMap<BlockHash, (Vec<FeeDemand>, BlockHeight)>,
    /// Rounds of recently committed blocks by height — the committed
    /// half of the ancestry walk in
    /// [`Self::ancestry_committed_height`], covering ancestors already
    /// pruned from pending. Bounded to a fixed horizon; anything older
    /// is committed far beyond any live vote's reach.
    committed_rounds: BTreeMap<BlockHeight, Round>,

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

    /// The highest certified height a retained ex-member has offered
    /// across a halt recovery — read off the timeouts
    /// [`Self::harvest_retained_tip`] harvests, which is the only signal
    /// carrying the halted tip to an incomer seated at the beacon's
    /// frontier. Gates this member's proposals until its own `high_qc`
    /// reaches it; see [`Self::recovery_behind_retained_tip`].
    retained_tip_offered: Option<BlockHeight>,

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

    /// Ticks whose determined half the chain still owes, mirrored from
    /// the execution fold so the proposer and the vote path judge
    /// settlement order by one rule. Empty until the node reports one,
    /// which enforces nothing — the safe direction.
    owed_determined: BTreeSet<BlockHeight>,

    /// Validator "ready on shard" signals waiting for inclusion in the
    /// next proposed block. Drained at proposal time.
    ready_signal_pool: ReadySignalPool,

    /// Validators whose double-vote this replica has already caught and
    /// handed to the host (which buffers it for the beacon and gossips
    /// it globally). One detection per key is enough — the conviction
    /// is permanent — so this gates the detection continuation, nothing
    /// more.
    detected_equivocators: BTreeSet<ValidatorId>,

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

    /// The chains this one succeeds, and what they have answered about
    /// transactions that predate it — what narrows the blanket pre-cut
    /// refusal to the transactions a predecessor actually committed.
    ///
    /// Seeded from the reshape flip, which is the delivery that lands
    /// inside the window the pre-cut rule is live for. A seat that missed
    /// the flip — a restart, or a validator rotated on afterwards — picks
    /// the predecessors up from its topology projection instead, at the
    /// first beacon block it commits; holding none means the strict rule
    /// stands, which is always safe. Retired once the chain has outlived
    /// its origin by `MAX_VALIDITY_RANGE`, past which nothing on offer
    /// predates the cut.
    precut: Precut,

    /// Advanced by every change to the predecessors' answers, beside the
    /// generations the two mirrors keep for themselves.
    precut_generation: u64,

    /// The generations of everything the fence reads — the counterpart
    /// mirror's, the proven anchors', the proven cells', the pre-cut
    /// answers' — at the last re-drive of the votes the fence deferred.
    /// Compared once per dispatch, so a vote deferred on any of them is
    /// re-driven by whatever advanced it.
    fence_seen: (u64, u64, u64, u64),

    /// What counterparts have said about the transactions legs here
    /// issued for, as the execution coordinator mirrored and folded
    /// them: a core's refusal, a proved absence, a consumer's claim.
    ///
    /// A record's arm is checked against this and nothing else —
    /// equality on the anchor — and a voter that does not hold the
    /// evidence defers. One mirror rather than a copy, so a record
    /// cannot pass here that its own composer would not have offered.
    mirror: Arc<CounterpartMirror>,

    /// Commit-proven anchors of remote shards — the root and parent-QC
    /// clock each header carries — mirrored off `RemoteHeaderCommitted`
    /// for the state-proof check: a block's bundle names an anchor, and
    /// the voter holds it to the header it has.
    ///
    /// Owned here and shared with the execution coordinator, which asks
    /// the same question of it — whether this node has proven a
    /// counterpart's height — for the certificate gate and the probe
    /// anchor. One mirror, so the fence cannot accept a bundle at an
    /// anchor the prober would not have chosen.
    proven_anchors: Arc<ProvenAnchors>,

    /// The counterpart cells this validator has proven for itself, for
    /// the state-claim check: a block states a reading, and the voter
    /// holds it to the one it took.
    ///
    /// Owned here and written by the execution coordinator, whose
    /// fetches are where a reading comes from, and read by the
    /// state-proof server, which relays a peer the proof one was taken
    /// from.
    proven_cells: Arc<ProvenCells>,
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
    ///
    /// # Panics
    ///
    /// Panics if a block the store handed back cannot be assembled. The
    /// store writes whole blocks, so an incomplete one is a corrupt
    /// store rather than a missing delivery, and resuming on it would
    /// build a chain no other replica agrees with.
    #[must_use]
    pub fn new(
        verifier: Arc<dyn Verifier>,
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
        // Both of the tip's anchors come back from stored headers: its own from
        // the tip's, and its committee's from the header one height below,
        // since a block's committee keys on its parent. Each falls back a hop
        // when its header is absent (fresh start, genesis tip, snap-synced
        // boundary, parent pruned past retention) — the fallback names the same
        // committee except when the tip sits at an epoch's first block, and the
        // next commit reseats both exactly. `committed_ts` shares the tip's own
        // anchor, which is what the live commit path sets it to, so a restarted
        // node's BFT clock equals a non-restarted peer's rather than running one
        // to two blocks ahead.
        let committed_block_anchor_wt = recovered.block_anchor_wt();
        let committed_committee_anchor_wt = recovered.committee_anchor_wt();
        let recovered_registers = recovered
            .safe_vote_registers
            .get(&me)
            .cloned()
            .unwrap_or_default();
        // The chain metadata only keeps the QC of a committed block, and a
        // lock rises on QCs that certify blocks well above the commit tip.
        // Restoring the higher of the two is what lets a validator satisfy
        // its own lock again: a committee that restarts together holds no
        // certificate above the lock anywhere else, and every proposal it
        // can build extends whatever it recovers here.
        let high_qc = match (recovered.latest_qc, recovered_registers.high_qc.clone()) {
            (Some(committed), Some(justification)) if justification.round() > committed.round() => {
                Some(Verified::<QuorumCertificate>::from_persisted(justification))
            }
            (Some(committed), _) => Some(committed),
            (None, Some(justification)) => {
                Some(Verified::<QuorumCertificate>::from_persisted(justification))
            }
            (None, None) => None,
        };
        // Seeded from the chain the store kept, not constructed empty: an
        // empty index refuses no duplicate, so a coordinator resuming a
        // chain without it re-admits everything the window still covers.
        //
        // A chain with no committed tip has folded nothing, and there is
        // nothing beneath it to have missed: the network's first chain
        // has no predecessor at all, and a reshape successor's
        // predecessor is refused on validity rather than on dedup — a
        // transaction whose window opened before this chain did cannot be
        // admitted here however the index reads.
        let mut dedup_index = CommitDedupIndex::seeded(&recovered.dedup);
        if recovered.committed_hash.is_none() {
            dedup_index.cover_to_origin();
        }
        // The uncommitted chain behind the restored certificate. Complete
        // as stored — the store wrote whole blocks — so each goes back as
        // an assembled pending block, needing no fetch. Their verification
        // is driven from `resume_recovered_blocks`, which runs on the
        // first periodic entry holding a topology schedule.
        let mut pending_blocks = PendingBlocks::new();
        let mut recovered_blocks = Vec::new();
        for block in &recovered.voted_blocks {
            recovered_blocks.push(block.header().hash());
            let mut pending = PendingBlock::from_complete_block(
                block,
                block.certificates().iter().map(Arc::clone).collect(),
                block.provisions().iter().map(Arc::clone).collect(),
                LocalTimestamp::ZERO,
            );
            pending
                .construct_block()
                .expect("a stored block is complete by construction");
            pending_blocks.insert(pending);
        }
        Self {
            verifier,
            view_change: ViewChangeController::new(initial_view),
            committed_height: recovered.committed_height,
            committed_hash: recovered.committed_hash.unwrap_or(BlockHash::ZERO),
            committed_ts: committed_block_anchor_wt,
            committed_block_anchor_wt,
            committed_committee_anchor_wt,
            committed_state_root: recovered.jmt_root.unwrap_or(StateRoot::ZERO),
            substate_bytes_frontier: (recovered.committed_height, recovered.substate_bytes),
            pending_bytes_deltas: HashMap::new(),
            deferred_reservation_checks: HashMap::new(),
            committed_rounds: BTreeMap::new(),
            // A fresh start's tip is the chain's genesis, whose header
            // carries zero of everything — known, not guessed. A real tip
            // whose header was not recovered stays `None` and defers the
            // checks until the first commit reseats it.
            committed_tip: recovered.committed_tip.or_else(|| {
                recovered
                    .committed_hash
                    .is_none()
                    .then_some(CommittedTip::GENESIS)
            }),
            latest_qc: high_qc,
            anchor_qc: recovered.anchor_qc,
            deferred_qc: DeferredQc::new(),
            pending_blocks,
            recovered_blocks,
            fee_ledger: FeeReservationLedger::new(),
            votes: VoteKeeper::new(),
            timeouts: TimeoutKeeper::new(),
            last_timed_out_round: None,
            retained_tip_offered: None,
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
            dedup_index,
            owed_determined: BTreeSet::new(),
            ready_signal_pool: ReadySignalPool::new(),
            detected_equivocators: BTreeSet::new(),
            beacon_witness_accumulator: BeaconWitnessAccumulator::from_leaves(
                recovered.beacon_witness_start,
                recovered.beacon_witness_leaf_hashes,
            ),
            config,
            now: LocalTimestamp::ZERO,
            me,
            local_shard,
            chain_origin: recovered.chain_origin,
            precut: Precut::succeeding(recovered.predecessors),
            precut_generation: 0,
            fence_seen: (0, 0, 0, 0),
            mirror: Arc::new(CounterpartMirror::new()),
            proven_anchors: Arc::new(ProvenAnchors::new()),
            proven_cells: Arc::new(ProvenCells::new()),
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
            self.committed_tip,
            self.latest_qc.as_ref(),
            &self.pending_blocks,
            self.verification.verified_certified_blocks(),
        )
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Committee resolution
    // ═══════════════════════════════════════════════════════════════════════════
    //
    // Two anchors, one hop apart, and conflating them is the bug this
    // separation exists to prevent.
    //
    // `block_anchor(b)` is `b`'s own position on the weighted-time grid —
    // `b.header.parent_qc.weighted_timestamp()`. It dates the block, and the
    // reveal chain and the parent-QC regression floor key on it.
    //
    // `committee_anchor(b)` is what selects `b`'s committee, and it is
    // `block_anchor(parent(b))`. A committee must be resolvable *before* the
    // block it governs exists, or the proposer for a height cannot be known
    // until someone has already proposed at it. `block_anchor(b)` fails that:
    // it reads a QC over `parent(b)`, and a QC's weighted timestamp is the
    // mean of whichever votes its aggregator held, so replicas hold values
    // for one block that differ by the spread of the voters' clocks. Either
    // side of an epoch cut that spread resolves two committees and elects two
    // leaders, and the round's votes split between proposals that both
    // verify. Anchoring a block's committee on its parent puts the selection
    // on a header every replica already holds and reads identically.
    //
    // So `committee(b) == at(committee_anchor(b))`, and the committee for the
    // height in progress is `at(block_anchor(tip))` — the same value, since
    // the block we are about to build is the tip's child.

    /// `block_hash`'s own position on the weighted-time grid — its parent QC's
    /// weighted timestamp. The committed tip (pruned from pending and the
    /// certified cache alike) uses the `committed_block_anchor_wt` scalar; every
    /// other block resolves through [`ChainView::get_header`], whose
    /// certified-cache fallback covers an applied-but-uncommitted synced
    /// block — such a tip exists only via block-sync (its header was never
    /// gossiped here), so without it a live proposal extending it would
    /// defer on "parent not held" while every re-fetch of the parent is
    /// deduplicated as already applied. `None` when the block is unknown by
    /// every route (caller stalls).
    fn block_anchor(&self, block_hash: BlockHash) -> Option<WeightedTimestamp> {
        if block_hash == self.committed_hash {
            return Some(self.committed_block_anchor_wt);
        }
        self.chain_view()
            .get_header(block_hash)
            .map(|header| header.parent_qc().weighted_timestamp())
    }

    /// Weighted timestamp selecting `block_hash`'s committee — its parent's
    /// [`Self::block_anchor`]. `None` when the block or its parent is unknown,
    /// so the committee can't be resolved (caller stalls or defers).
    fn committee_anchor(&self, block_hash: BlockHash) -> Option<WeightedTimestamp> {
        if block_hash == self.committed_hash {
            return Some(self.committed_committee_anchor_wt);
        }
        self.block_anchor(
            self.chain_view()
                .get_header(block_hash)?
                .parent_block_hash(),
        )
    }

    /// [`Self::committee_anchor`] for a synced block that is not yet held by
    /// any of the chain routes — it is arriving now, so the walk starts from
    /// the parent hash its header names rather than from the block itself.
    ///
    /// Reaches into the sync pipeline for that parent: the drain hands
    /// consecutive heights to QC verification in parallel, so the parent is
    /// usually still in flight rather than applied. Falls back to the block's
    /// own anchor when no route holds the parent at all — the first block of
    /// a sync window, or one whose parent sits below retention. That names
    /// the same committee except when the block is an epoch's first, and it
    /// is self-healing: the next arrival resolves exactly once its parent
    /// lands.
    fn synced_committee_anchor_wt(&self, header: &BlockHeader) -> WeightedTimestamp {
        let parent = header.parent_block_hash();
        self.block_anchor(parent)
            .or_else(|| {
                self.block_sync
                    .held_header(header.height().prev()?, parent)
                    .map(|parent| parent.parent_qc().weighted_timestamp())
            })
            .unwrap_or_else(|| header.parent_qc().weighted_timestamp())
    }

    /// Committee governing a block that extends `parent` — the one rule
    /// every committee question routes through.
    ///
    /// Three sites ask it, and they must agree or a block cannot survive its
    /// own lifecycle: `can_propose` asks about the tip it will extend, the
    /// build path asks about the parent it is extending, and
    /// [`Self::committee_of_block`] asks about a held block's parent. They
    /// were once three expressions of the same question and drifted apart —
    /// the beacon-witness base is frozen per window, so a block stamped from
    /// one window's entry and checked against another's is rejected by every
    /// verifier, at every epoch cut.
    fn committee_for_child_of<'t>(
        &self,
        topology_schedule: &'t TopologySchedule,
        parent: BlockHash,
    ) -> Option<&'t Arc<TopologySnapshot>> {
        self.committee_at(topology_schedule, self.block_anchor(parent)?)
    }

    /// The committee lookup itself, for the callers that hold an anchor
    /// rather than a parent hash. Terminal-clamped and recovery-bridged;
    /// `None` is a beacon-behind stall, an evicted window, or a window
    /// that seats nobody.
    ///
    /// That last one reads as a stall for the same reason the other two
    /// do: a snapshot whose ready-filtered committee for this shard is
    /// empty answers no committee question. Its quorum threshold is zero,
    /// which `VoteCount::has_quorum` satisfies with a single vote, and its
    /// proposer rotation has nothing to rotate over — so a caller handed
    /// one either asserts or proceeds on a quorum that means nothing.
    /// Stalling until a window that seats somebody governs the work is the
    /// same discipline as stalling on a beacon that has not caught up.
    ///
    /// `anchor` must be a *committee* anchor — [`Self::committee_anchor`] of
    /// the block in question, or equivalently [`Self::block_anchor`] of its
    /// parent. Passing a block's own anchor resolves the window it opens
    /// rather than the one it belongs to, which is a different committee for
    /// exactly the blocks that sit on an epoch cut.
    fn committee_at<'t>(
        &self,
        topology_schedule: &'t TopologySchedule,
        anchor: WeightedTimestamp,
    ) -> Option<&'t Arc<TopologySnapshot>> {
        topology_schedule
            .at_for_shard_live(self.local_shard, anchor)
            .map(|(snapshot, _)| snapshot)
            .filter(|snapshot| {
                !snapshot
                    .consensus_committee_for_shard(self.local_shard)
                    .is_empty()
            })
    }

    /// Committee anchor of the height in progress / our next proposal: the
    /// [`Self::block_anchor`] of the block we are about to extend, since a
    /// child's committee anchors on its parent. The build path resolves its
    /// committee from the same parent through
    /// [`Self::committee_for_child_of`], so election and build cannot disagree.
    ///
    /// Keying on the tip block rather than on our own aggregate over it is
    /// what makes the proposer agreed. A QC's weighted timestamp is the mean
    /// of whichever votes the aggregator held when quorum landed, so replicas
    /// hold different values for one block — by the spread of the voters'
    /// clocks. Within that spread of an epoch cut, the aggregate resolves two
    /// committees and elects two leaders, and the round's votes split between
    /// proposals that both verify.
    ///
    /// `None` when that block is unknown by every route, so its anchor can't
    /// be resolved and the caller stalls. With no QC yet the parent is the
    /// committed tip, whose anchor a split child's genesis carries from the
    /// parent chain's terminal canonical timestamp — resolving its first
    /// proposal in the window it inherited rather than epoch 0.
    fn next_proposal_committee_anchor_wt(&self) -> Option<WeightedTimestamp> {
        self.block_anchor(self.chain_view().proposal_parent().0)
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
        self.committee_at(topology_schedule, self.committee_anchor(block_hash)?)
            .map(Arc::as_ref)
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
        let anchor = self.next_proposal_committee_anchor_wt()?;
        if self.recovery_quiesced(topology_schedule, anchor) {
            return None;
        }
        self.committee_at(topology_schedule, anchor)
            .map(Arc::as_ref)
    }

    /// Whether work anchored at `wt` rides an in-flight halt recovery's
    /// bridge: the anchor predates the window the fresh committee governs
    /// from. Bridge blocks must be empty — the anchored-committee
    /// resolution downstream (execution votes, tick fencing) never sees a
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

    /// Mirror a commit-proven remote header for everything that asks
    /// whether this node has proven a counterpart's height.
    pub fn record_proven_anchor(&mut self, anchor: Anchor) {
        self.proven_anchors.record(anchor);
    }

    /// The counterpart mirror the vote fence reads, for the execution
    /// coordinator to write.
    #[must_use]
    pub const fn mirror(&self) -> &Arc<CounterpartMirror> {
        &self.mirror
    }

    /// The mirror, for the execution coordinator to read the same bytes
    /// this validator's vote fence reads.
    #[must_use]
    pub const fn proven_anchors(&self) -> &Arc<ProvenAnchors> {
        &self.proven_anchors
    }

    /// The cells this validator has proven, for the execution
    /// coordinator to write what its fetches attest and the state-proof
    /// server to relay the bytes they came from.
    #[must_use]
    pub const fn proven_cells(&self) -> &Arc<ProvenCells> {
        &self.proven_cells
    }

    /// Retire the commit-proven anchors nothing can probe against any
    /// more. One retirement for both consumers, since there is one
    /// mirror.
    ///
    /// What counterparts said is retired by the execution coordinator
    /// instead, against the ledger its entries speak for.
    fn retire_proven_anchors(&self) {
        self.proven_anchors
            .retire_below(self.committed_block_anchor_wt);
        self.proven_cells
            .retire_below(self.committed_block_anchor_wt);
    }

    /// The evidence a vote is fenced on, borrowed for one judgment.
    fn vote_fence(&self) -> VoteFence<'_> {
        VoteFence {
            mirror: &self.mirror,
            proven_anchors: &self.proven_anchors,
            proven_cells: &self.proven_cells,
            precut: &self.precut,
            cut: self.chain_origin.anchor_wt,
            local_shard: self.local_shard,
        }
    }

    /// Whether anything the vote fence reads has been written since the
    /// last time this answered `true`: a counterpart's word, a settled
    /// set, a record's cover, a proven anchor, a proven cell, a
    /// predecessor's answer.
    /// The state machine asks once per dispatch and re-drives the
    /// pending votes on `true`, so no writer has to know which votes
    /// were deferred on what it wrote.
    pub fn take_fence_evidence_advanced(&mut self) -> bool {
        let now = (
            self.mirror.generation(),
            self.proven_anchors.generation(),
            self.proven_cells.generation(),
            self.precut_generation,
        );
        let advanced = now != self.fence_seen;
        self.fence_seen = now;
        advanced
    }

    /// Re-drive the vote path for every pending complete block, for the
    /// votes the fence deferred on evidence that has since arrived.
    /// `trigger_qc_verification_or_vote` is idempotent (already-verified
    /// / already-voted short-circuit), so re-driving every pending block
    /// is safe.
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
    /// successors are live, which [`Self::dissolved`] is the test for.
    #[must_use]
    pub fn quiescent(&self, topology_schedule: &TopologySchedule) -> bool {
        self.past_terminal_window(topology_schedule, self.committed_block_anchor_wt)
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

    /// Whether content from before this chain began can still be offered
    /// to it.
    ///
    /// False on a chain born at network genesis, which has nothing before
    /// it. False again once the chain's certified clock has run
    /// `MAX_VALIDITY_RANGE` past its origin: that is the widest a validity
    /// window gets, so nothing signed since can open before the cut and
    /// nothing signed before it is still valid.
    ///
    /// A property of the chain rather than of what this node holds — which
    /// is what makes it the right gate for *acquiring* the predecessors,
    /// where [`Self::precut_rule_live`] would be circular.
    #[must_use]
    pub fn precut_window_open(&self) -> bool {
        self.chain_origin.anchor_wt > WeightedTimestamp::ZERO
            && self.high_qc().weighted_timestamp()
                < self.chain_origin.anchor_wt.plus(MAX_VALIDITY_RANGE)
    }

    /// Whether the relaxation is live: the window is open *and* this node
    /// holds predecessors to resolve against. A seat that missed the flip
    /// and has not yet read them off its topology projection holds none,
    /// and keeps the strict refusal until it does.
    #[must_use]
    pub fn precut_rule_live(&self) -> bool {
        self.precut.has_predecessors() && self.precut_window_open()
    }

    /// Read the chains this one succeeds off the beacon's own boundary
    /// records, for a seat the reshape flip never reached.
    ///
    /// The flip is the fast delivery and covers the seats present at the
    /// cut. This is the durable one, and the only path for a restart, a
    /// validator rotated onto the successor committee afterwards, or a
    /// snap-synced joiner — none of which run a reshape duty, and none of
    /// which can re-derive the roots from their own chain.
    ///
    /// Runs only while the window is open and only when nothing is held,
    /// so it neither displaces what the flip delivered nor undoes a
    /// retirement. Returns whether anything was adopted.
    pub fn adopt_precut_predecessors(&mut self, topology_schedule: &TopologySchedule) -> bool {
        if self.precut.has_predecessors() || !self.precut_window_open() {
            return false;
        }
        let predecessors =
            topology_schedule.predecessor_terminals(self.local_shard, self.chain_origin.anchor_wt);
        if predecessors.is_empty() {
            return false;
        }
        info!(
            validator = ?self.me,
            shard = ?self.local_shard,
            count = predecessors.len(),
            "Adopted this chain's predecessors from the topology projection"
        );
        self.precut = Precut::succeeding(predecessors);
        self.precut_generation += 1;
        true
    }

    /// Record one predecessor's answer about a transaction that predates
    /// this chain.
    ///
    /// `absent` must already have been verified against that
    /// predecessor's attested `committed_txs_root`; a `committed` answer
    /// carries no proof and needs none, since it leaves the standing
    /// refusal in place.
    pub fn record_precut_resolution(
        &mut self,
        predecessor: ShardId,
        tx_hash: TxHash,
        absent: bool,
    ) {
        self.precut.record(predecessor, tx_hash, absent);
        self.precut_generation += 1;
    }

    /// The `(predecessor, transaction)` pairs still owed an answer — what
    /// an acquisition driver turns into queries.
    ///
    /// `tx_hashes` is the caller's candidate set — the mempool's pending
    /// transactions that open before the cut. Blocks awaiting a vote
    /// contribute their own pre-cut transactions on top: a vote deferred
    /// by [`Self::precut_verdict`] resolves only once the query it waits
    /// on is issued, and nothing guarantees the block's transactions are
    /// also sitting in this node's pool.
    ///
    /// Empty on a chain with no predecessors, and empty again once the
    /// chain has outlived its origin by `MAX_VALIDITY_RANGE`, where
    /// nothing offered to it opens before the cut.
    #[must_use]
    pub fn outstanding_precut_queries(
        &self,
        tx_hashes: impl IntoIterator<Item = TxHash>,
    ) -> Vec<(PredecessorTerminal, TxHash)> {
        if !self.precut_rule_live() {
            return Vec::new();
        }
        let cut = self.chain_origin.anchor_wt;
        let awaiting_vote = self
            .pending_blocks
            .values()
            .filter_map(|pending| pending.block())
            .flat_map(|block| {
                block
                    .transactions()
                    .iter()
                    .filter(|tx| tx.validity_range().start_timestamp_inclusive < cut)
                    .map(|tx| tx.hash())
                    .collect::<Vec<_>>()
            });
        let candidates: BTreeSet<TxHash> = tx_hashes.into_iter().chain(awaiting_vote).collect();
        self.precut.outstanding(candidates)
    }

    /// Whether `tx_hash` may be proposed despite opening before this
    /// chain did — proven absent from every predecessor's committed set.
    #[must_use]
    pub fn precut_tx_admissible(&self, tx_hash: &TxHash) -> bool {
        self.precut.admissible(tx_hash)
    }

    /// Whether any predecessor is on hand to be asked at all — false on a
    /// chain born at network genesis, on a seat that missed the flip, and
    /// on one whose pre-cut rule has already retired.
    #[must_use]
    pub const fn has_precut_predecessors(&self) -> bool {
        self.precut.has_predecessors()
    }

    /// Drop the predecessors and their answers once the pre-cut rule has
    /// retired, so neither is held for this coordinator's life.
    ///
    /// The caller drives it, because forgetting the predecessors is also
    /// what stops it releasing the query slots they hold: the release is a
    /// request naming an empty set, and there is nothing to name it against
    /// afterwards. Returns whether anything was dropped.
    pub fn retire_precut(&mut self) -> bool {
        if self.precut.is_empty() || self.precut_rule_live() {
            return false;
        }
        self.precut.retire();
        self.precut_generation += 1;
        true
    }

    /// Whether a header keyed at `wt` carries `split_child_roots` — the
    /// split-pending shard's final-epoch delivery, identical on the
    /// build side (carry) and the vote side (required).
    ///
    /// `None` only when the schedule doesn't hold `wt`'s window at all
    /// ([`SplitAtBoundary::Unresolved`]). An admitted split no longer
    /// defers: its cut is scheduled a window ahead, so the window's own
    /// frozen projection answers. The committee lookup succeeding is not
    /// enough to rule this out — it resolves the window by `epoch_for`
    /// while the predicate steps back to the closing window at a boundary
    /// instant, so the two can want different entries.
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

    /// Whether a header keyed at `wt` carries the two terminal-boundary
    /// roots — `settled_txs_root` and `committed_txs_root` — set on any
    /// terminating boundary header (a split parent's *or* a merge child's
    /// final epoch), identical on the build side (carry) and the vote side
    /// (required). One bit for both: they answer different readers but are
    /// carried by the same headers, so nothing distinguishes when to emit
    /// one from when to emit the other. Broader than
    /// [`Self::split_child_roots_bit`]: a merge child terminates without
    /// carrying `split_child_roots`. `None` under that helper's retention
    /// condition, and only that one.
    fn terminal_roots_bit(
        &self,
        topology_schedule: &TopologySchedule,
        wt: WeightedTimestamp,
    ) -> Option<bool> {
        topology_schedule.terminates_at_next_boundary(self.local_shard, wt)
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
        // 2. This round's proposal sits at the tip and we have yet to vote on
        //    it — content still landing, or roots still to check.
        // 3. Block sync has unverified work in flight.
        //
        // Each is work this replica still owes the tip, which is what the
        // progress window is for. What it deliberately excludes is waiting on
        // *other* replicas: a proposal we have already voted on, and a block
        // left over from a round the pacemaker abandoned, both need a quorum
        // we cannot supply, and the round timer is what bounds that wait.
        // Suppressing on either prices it at `MAX_PROGRESS_WAIT` — three
        // times the nominal timeout — while the pacemaker sits on its hands.
        //
        // A block the vote fence withheld is excluded on the same
        // ground. It waits on a counterpart chain to answer for a claim
        // its proposer made, which no amount of work here completes and
        // a silent counterpart never ends; pricing it at the progress
        // window hands a proposer a stall worth three rounds for one
        // claim nobody can check.
        let next_height = self.latest_qc.as_ref().map_or_else(
            || self.committed_height.inner() + 1,
            |qc| qc.height().inner() + 1,
        );
        let awaiting_tip_proposal = self.last_voted_round < self.view_change.view
            && self
                .pending_blocks
                .has_own_work_at_round(BlockHeight::new(next_height), self.view_change.view);
        let suppressed = self.verification.has_verification_in_flight()
            || awaiting_tip_proposal
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
        self.committed_tip = Some(genesis.header().committed_tip());
        // A chain's genesis height and clock are per-chain properties: a
        // split child's genesis continues the parent's height line and
        // anchors at its final canonical weighted timestamp (ZERO and
        // height 0 for chains born at network genesis).
        self.committed_height = genesis.height();
        self.committed_ts = genesis.header().parent_qc().weighted_timestamp();
        self.committed_block_anchor_wt = self.committed_ts;
        self.committed_committee_anchor_wt = self.committed_ts;
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
        // The high QC only rises, for the same reason the lock does.
        // `Self::new` restored the higher of the committed tip's
        // certificate and the durable record's, and the record's is the
        // one above the tip. Assigning the committed one here would drop
        // back to a certificate beneath this node's own lock, which is
        // what it reports in a timeout — and a bound understated is a
        // bound another replica may vote beneath.
        let held = self.latest_qc.as_deref().map(QuorumCertificate::round);
        if qc.as_deref().map(QuorumCertificate::round) > held {
            self.latest_qc = qc;
        }

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

    /// What a block anchored at `anchor` over `parent_block_hash` is
    /// admitted against: the chain behind the parent, walked once, and
    /// the window the block sits in.
    fn admission<'a>(
        &'a self,
        snapshot: &'a TopologySnapshot,
        topology_schedule: &'a TopologySchedule,
        chain: &'a QcChainSets,
        parent_block_hash: BlockHash,
        anchor: WeightedTimestamp,
        genesis_parent: bool,
    ) -> Admission<'a> {
        let parent_settled_frontier = if genesis_parent {
            Some(BlockHeight::GENESIS)
        } else {
            self.chain_view()
                .parent_settled_frontier_checked(parent_block_hash)
        };
        Admission {
            snapshot,
            schedule: topology_schedule,
            local_shard: self.local_shard,
            anchor,
            chain_origin: self.chain_origin.anchor_wt,
            chain,
            dedup: &self.dedup_index,
            parent_settled_frontier,
            owed_determined: &self.owed_determined,
        }
    }

    /// Mirror the execution fold's owed determined halves, which
    /// settlement order at admission is judged against.
    pub fn set_owed_determined(&mut self, owed: BTreeSet<BlockHeight>) {
        self.owed_determined = owed;
    }

    /// Try to build and broadcast a new block proposal.
    ///
    /// This is the unified proposal entry point, called from:
    /// - new-content events (transactions, ticks, or provisions)
    /// - `on_qc_formed` (eager next-block proposal)
    ///
    /// Returns empty if preconditions aren't met (not proposer, build in-flight,
    /// already voted at this height, etc.). No periodic rescheduling — callers
    /// are responsible for triggering the next attempt via events.
    #[instrument(skip(self, topology_schedule, ready_txs, finalizations), fields(
        tx_count = ready_txs.len(),
        cert_count = finalizations.len(),
    ))]
    pub fn try_propose(
        &mut self,
        topology_schedule: &TopologySchedule,
        ready_txs: &[Arc<Verified<Transaction>>],
        finalizations: Vec<Arc<Verifiable<Finalization>>>,
        provisions: Vec<Arc<Verifiable<Provisions>>>,
        abandonment_records: Vec<AbandonmentRecord>,
        state_claims: Vec<StateClaim>,
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
                ProposalKind::Normal(ProposalPayload::default()),
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
                ProposalKind::Normal(ProposalPayload::default()),
            );
        }

        // Walk the QC chain once for what pending and certified blocks
        // above committed height already carry — the two-chain commit
        // window leaves them visible and the mempool doesn't clear its
        // ready set until commit — and admit each section against it
        // under the parent QC's weighted timestamp, the deterministic
        // clock voters will read this block at. The one-block lag (this
        // block's own QC may carry a slightly later timestamp) is
        // bounded by MAX_VALIDITY_RANGE.
        let chain = QcChainSets::behind(&self.chain_view(), parent_block_hash);
        let validity_anchor = parent_qc.weighted_timestamp();
        // The committee governing the block being built, not the schedule's
        // newest entry: package usability, the recovery fences, payer routing
        // and the sweep cap all read it, and a voter judges the block under
        // the committee its parent names. Reading the head instead disagrees
        // for the block after every fold, and while the parent QC lags the
        // beacon. Stall where the build itself would.
        let Some(committee) = self.committee_for_child_of(topology_schedule, parent_block_hash)
        else {
            return vec![];
        };
        let ctx = self.admission(
            committee,
            topology_schedule,
            &chain,
            parent_block_hash,
            validity_anchor,
            parent_qc.is_genesis(),
        );
        // In the order the folds depend on: provisions first, since a
        // cross-shard transaction rides only beside (or after) its payer
        // bundle; finalizations before the records held to their names.
        let mut provision_fold = ProvisionsFold::default();
        let provisions = select_provisions(&ctx, &mut provision_fold, provisions);
        let late = late_deliveries(
            ready_txs,
            topology_schedule,
            validity_anchor,
            self.local_shard,
        );
        let transactions = select_transactions(
            &ctx,
            &Prefilter {
                precut: &self.precut,
                late_deliveries: &late,
            },
            &mut TransactionsFold::beside(&provision_fold),
            ready_txs,
        );
        let mut finalization_fold = FinalizationsFold::from(&ctx);
        let finalizations = select_finalizations(&ctx, &mut finalization_fold, finalizations);
        let abandonment_records = select_abandonment_records(
            &ctx,
            &mut RecordsFold::after(&finalization_fold),
            abandonment_records,
        );
        let state_claims = select_state_claims(&ctx, &mut StateClaimsFold::default(), state_claims);

        self.build_and_dispatch_proposal(
            topology_schedule,
            next_height,
            round,
            ProposalKind::Normal(ProposalPayload {
                transactions,
                finalizations,
                provisions,
                abandonment_records,
                state_claims,
            }),
        )
    }

    /// Whether this member is still short of the halted tip a retained
    /// ex-member offered it.
    ///
    /// A halt recovery seats its fresh committee from a snap-synced
    /// anchor at the beacon-attested frontier — the last boundary the
    /// beacon folded, which sits well below the tip the old committee
    /// certified before it stopped. The suffix between them is what the
    /// incomers adopt, and until one of them holds a certificate over it,
    /// the highest QC each of them has names the frontier. A whole fresh
    /// committee proposing from there builds a second chain across
    /// heights the halted one already holds; every replica that took the
    /// suffix then refuses it, and the shard splits at the first
    /// collision.
    ///
    /// The offer is the retained ex-members' own timeouts, which
    /// [`Self::harvest_retained_tip`] already reads for exactly this
    /// purpose. Holding until `high_qc` reaches the highest one seen
    /// terminates on its own: the harvest drives the fetch that supplies
    /// the block, and adopting the carried QC closes the gap. A shard
    /// whose retained cohort offers nothing — no suffix above the
    /// frontier, or no ex-member left to answer — is never held, which is
    /// the case where extending the frontier is the only move there is.
    fn recovery_behind_retained_tip(&self) -> bool {
        self.retained_tip_offered.is_some_and(|offered| {
            offered
                > self
                    .latest_qc
                    .as_ref()
                    .map_or(BlockHeight::GENESIS, |qc| qc.height())
        })
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

        // A recovery's incomers extend the halted tip, not the frontier
        // they seeded at.
        if self.recovery_behind_retained_tip() {
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
            Ok(count) => Ok(count),
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
        committee_anchor_epoch: Epoch,
    ) -> Option<ReshapeTrigger> {
        let count = substate_bytes?;
        let thresholds = topology_snapshot.reshape_thresholds();
        derive_reshape_trigger(
            self.local_shard,
            count,
            &thresholds,
            window,
            committee_anchor_epoch,
        )
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
        committee_anchor_epoch: Epoch,
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
            self.committed_block_anchor_wt,
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

        let reshape_trigger = self.derive_proposal_reshape_trigger(
            topology_snapshot,
            substate_bytes,
            &parent_leaves,
            committee_anchor_epoch,
        );
        // The block's new leaves are derived and merkle-committed in the
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
        let (parent_block_hash, parent_qc) = self.chain_view().proposal_parent();
        // The block we build belongs to its parent's window — the same
        // committee `can_propose` drew our slot from and the same one every
        // verifier resolves for it. Its proposer schedule (missed-proposal
        // leaves) and beacon-witness preview key on that entry, and the
        // witness base is frozen per window, so reading it from any other
        // entry stamps a base no verifier accepts. Stall if the beacon lacks
        // it. Terminal-clamped: coast blocks past a split's cut resolve the
        // shard's final-epoch committee. Recovery-bridged: a block extending
        // a halted tip resolves the fresh committee.
        let Some(committee) = self.committee_for_child_of(topology_schedule, parent_block_hash)
        else {
            return vec![];
        };
        // The final-epoch headers of a splitting shard carry the root
        // node's child hashes. Whether this window is the final one is
        // decided by the window's own frozen schedule entry, so a reshape
        // in flight resolves here without waiting on the local beacon.
        // Only a window the schedule has evicted leaves it unanswerable —
        // stall the build (before the witness preview drains the
        // ready-signal pool) rather than guess a header replicas would
        // reject.
        let Some(carry_split_child_roots) =
            self.split_child_roots_bit(topology_schedule, parent_qc.weighted_timestamp())
        else {
            trace!(
                validator = ?self.me,
                height = height.inner(),
                "Split-at-boundary window missing from the schedule; deferring the build"
            );
            return vec![];
        };
        let Some(carry_terminal_roots) =
            self.terminal_roots_bit(topology_schedule, parent_qc.weighted_timestamp())
        else {
            trace!(
                validator = ?self.me,
                height = height.inner(),
                "Termination-at-boundary window missing from the schedule; deferring the build"
            );
            return vec![];
        };
        // The block's reveal chain extends the parent's, so an unresolvable
        // parent — pruned from pending with no recovered committed tip
        // — has no chain to extend. Defer rather than guess: a wrong chain
        // produces a header every other replica rejects. The first commit
        // past the gap reseats the scalar.
        // The chain reseeds when the block and its parent belong to different
        // epochs, and a block belongs to the epoch its committee is drawn
        // from — so both epochs are committee anchors: this block's is the
        // parent's own anchor, the parent's is the grandparent's.
        let (
            Some(parent_reveal_chain),
            Some(committee_anchor_wt),
            Some(parent_committee_anchor_wt),
        ) = (
            self.chain_view().parent_reveal_chain(parent_block_hash),
            self.block_anchor(parent_block_hash),
            self.committee_anchor(parent_block_hash),
        )
        else {
            trace!(
                validator = ?self.me,
                height = height.inner(),
                "Parent reveal chain unresolvable; deferring the build"
            );
            return vec![];
        };
        let parent_committee_anchor_epoch = topology_schedule.epoch_for(parent_committee_anchor_wt);
        let committee_anchor_epoch = topology_schedule.epoch_for(committee_anchor_wt);
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
                self.verification.defer_proposal_on_substate(blocking);
                // The blocking ancestor's delta needs its state root, which
                // needs its content. Ask for whatever is still missing now
                // rather than on the next cleanup tick — the tick's interval
                // is many block times, and nothing else is going to run while
                // the proposal is parked. Idempotent and deduped in flight,
                // so forcing a block that is merely slow costs nothing.
                return self.check_pending_block_fetches(true);
            }
        };
        let preview = self.preview_witness_commitment(
            topology_schedule,
            committee,
            parent_qc.weighted_timestamp(),
            parent_block_hash,
            substate_bytes,
            committee_anchor_epoch,
        );

        // Prior demand per candidate payer: in-flight holds plus the
        // uncommitted window. The builder adds candidate ceilings on
        // top and drops what a payer cannot cover.
        let fee_checks = match &kind {
            ProposalKind::Normal(ProposalPayload { transactions, .. }) => {
                let payer_seeds = self.local_payer_fees(
                    committee,
                    transactions.iter().map(|tx| PayerFee {
                        vault: tx.fee_vault(),
                        auth_cell: tx.auth_cell(),
                        max_fee: 0,
                        signer: None,
                    }),
                );
                self.fee_demands(&payer_seeds, parent_block_hash)
            }
            ProposalKind::Fallback | ProposalKind::Sync => Vec::new(),
        };
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
            parent_reveal_chain,
            parent_committee_anchor_epoch,
            committee_anchor_epoch,
            carry_split_child_roots,
            carry_terminal_roots,
            topology_schedule
                .settled_window_floor(self.local_shard, parent_qc.weighted_timestamp()),
            Arc::clone(committee),
            fee_checks,
            self.ancestry_committed_height(&parent_qc),
            substate_bytes,
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

        dispatch_or_defer(
            &mut self.proposal,
            &mut self.verification,
            plan,
            height,
            round,
        )
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Header Reception
    // ═══════════════════════════════════════════════════════════════════════════

    /// Handle a received block header. Sender identity is taken from the
    /// header's signed `proposer` field — there's no separate peer-id
    /// parameter because sync detection doesn't need it.
    #[instrument(skip(self, topology_schedule, header, manifest, lookup_tx, lookup_finalization, lookup_provision), fields(
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
        lookup_tx: impl Fn(&TxHash) -> Option<Arc<Verifiable<Transaction>>>,
        lookup_finalization: impl Fn(&FinalizationHash) -> Option<Arc<Verifiable<Finalization>>>,
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
        let sync_actions = self.absorb_parent_qc_from_header(topology_schedule, header);

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
            lookup_finalization,
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
        actions.extend(
            self.votes
                .maybe_trigger_verification(self.local_shard, block_hash),
        );
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
    fn absorb_parent_qc_from_header(
        &mut self,
        topology_schedule: &TopologySchedule,
        header: &BlockHeader,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        if header.parent_qc().is_genesis() {
            return actions;
        }

        let parent_height = header.parent_qc().height();

        // Check for a COMPLETE parent block; an incomplete pending block still
        // requires sync for the full data.
        let have_parent = self.has_complete_block_at_height(parent_height);

        if !have_parent && !self.fork_refuses_retained_suffix(topology_schedule, header.parent_qc())
        {
            info!(
                validator = ?self.me,
                committed_height = self.committed_height.inner(),
                parent_height = parent_height.inner(),
                target_height = parent_height.inner(),
                "Missing parent block, triggering sync (continuing to process header)"
            );
            actions = self.start_block_sync(parent_height);
        }

        // Defer adoption until the signature has been verified. Without
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

    /// Verify and adopt the snap-synced anchor QC once the schedule
    /// resolves its committee. The bootstrap bound the QC to the
    /// beacon-attested anchor structurally (it certifies the anchor's
    /// `block_hash`); this closes the aggregate-signature gap before the
    /// QC becomes `latest_qc` — and thereby the parent QC the fresh
    /// committee's first block past the anchor extends. An unresolvable
    /// committee retries on a later call; a verification failure
    /// discards the QC (a Byzantine serving peer's forgery — a higher
    /// adopted QC or the halt harvest routes around it); any QC adopted
    /// first makes it moot.
    fn try_adopt_anchor_qc(&mut self, topology_schedule: &TopologySchedule) -> Vec<Action> {
        if self.latest_qc.is_some() {
            self.anchor_qc = None;
            return Vec::new();
        }
        let Some(qc) = self.anchor_qc.clone() else {
            return Vec::new();
        };
        if qc.is_genesis() {
            // A genesis anchor needs no adoption: `proposal_parent`'s
            // chain-origin fallback reconstructs the genesis QC exactly.
            self.anchor_qc = None;
            return Vec::new();
        }
        // Fork-cause recoveries only. A halt recovery (and any ordinary
        // anchored join) seeds from the retained committee's signals — the
        // harvest carries the unique certified tip, and adopting the anchor
        // QC first would let the fresh committee certify a sibling of real
        // committed history above the anchor and break commit linkage when
        // the suffix then syncs in. A forked shard refuses that suffix
        // wholesale, so the anchor is its one legitimate parent. The QC
        // stays buffered: a halt recovery upgraded to fork provenance by a
        // later fold becomes adoptable then.
        if topology_schedule
            .head()
            .pending_recoveries()
            .get(&self.local_shard)
            .is_none_or(|recovery| recovery.cause != RecoveryCause::Fork)
        {
            return Vec::new();
        }
        let Some(verified) = self.verify_qc_sync(topology_schedule, &qc) else {
            // Either the committee is unresolvable (beacon behind — keep
            // the QC and retry) or the signature failed (discard). Split
            // the cases so a forgery cannot pin retries forever.
            if self.committee_of_qc(topology_schedule, &qc).is_some() {
                warn!(
                    validator = ?self.me,
                    height = qc.height().inner(),
                    "Snap-synced anchor QC failed verification — discarding"
                );
                self.anchor_qc = None;
            }
            return Vec::new();
        };
        info!(
            validator = ?self.me,
            height = qc.height().inner(),
            round = qc.round().inner(),
            "Adopted the snap-synced anchor QC"
        );
        self.anchor_qc = None;
        self.try_adopt_verified_qc(&verified)
    }

    /// Adopt `qc` as the new `high_qc` (`latest_qc`) if it sits in a higher
    /// round than the one we hold, advance the view past it, and fire
    /// two-chain commit. Caller MUST have confirmed the QC's signature (or
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
        // Proposer of `h` is drawn from `committee(h)`, anchored on `h-1` —
        // the same value the proposer's own gate resolved before building,
        // so election and validation cannot disagree. Reading the anchor off
        // the header's embedded QC instead would let a proposer pick the
        // committee that legitimizes it. Terminal-clamped so a coast header
        // past a split's cut resolves the shard's final-epoch committee, and
        // recovery-bridged so a header extending a halted tip resolves the
        // fresh committee.
        //
        // Skipped (`None`) when `h-1`'s header hasn't arrived, so its anchor
        // can't be resolved — a node catching up receives live headers far
        // above its committed tip and holds none of their parents. This
        // pre-check is a cheap DoS filter; the proposer is checked against
        // the exact committee in `trigger_qc_verification_or_vote`, which
        // already defers on the same condition and which no vote bypasses.
        let proposer_committee = match self.block_anchor(header.parent_block_hash()) {
            None => None,
            Some(anchor) => match topology_schedule
                .lookup_for_shard_live(self.local_shard, anchor)
                .0
            {
                ScheduleLookup::Committee(committee) => Some(committee.as_ref()),
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
            },
        };
        // The parent QC over `h-1` was signed by `committee(h-1)`. Skip the
        // quorum pre-check (`None`) when the parent QC is genesis (no quorum to
        // check) or when `h-1`'s header hasn't arrived, so its committee can't
        // be resolved. The pre-check is a cheap DoS filter; the parent QC is
        // fully signature-verified against the exact committee before this node votes,
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

    /// `block_hash`'s exact committee just became resolvable — its header
    /// arrived, or so did the parent that committee anchors on — so admit any
    /// votes held raw for want of it (see [`Self::on_unverified_block_vote`]).
    /// Each is run through the normal committee-membership filter against the
    /// exact committee, so fabricated pre-header votes are dropped here.
    /// Returns the admissions' trigger actions.
    ///
    /// The committee resolves *before* the buffer is drained. A block's
    /// committee anchors on its parent, so a header can land ahead of it and
    /// leave the committee unresolvable even though `reject_invalid_header`
    /// admitted the header (its own proposer check defers on the same
    /// condition). Draining first would discard the very votes the parent's
    /// arrival is about to admit.
    fn link_buffered_votes_to_header(
        &mut self,
        topology_schedule: &TopologySchedule,
        block_hash: BlockHash,
        header: &BlockHeader,
    ) -> Vec<Action> {
        let Some(committee) = self.committee_of_block(topology_schedule, block_hash) else {
            return vec![];
        };
        let buffered = self.votes.take_unanchored_votes(block_hash);
        if buffered.is_empty() {
            return vec![];
        }
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
    /// or it committed), so `committee(parent_hash)` now resolves — and so does
    /// the committee of every pending child that anchors on it. Two jobs, each
    /// with its own reach:
    ///
    /// - Admit the votes held raw for a child whose committee was unresolvable.
    ///   A QC builds off the header alone, so this covers every child with a
    ///   header, assembled or not.
    /// - Re-trigger the children whose parent-QC verification
    ///   [`trigger_qc_verification_or_vote`] deferred for lack of the parent.
    ///   Only an assembled child has anything to verify. That call is
    ///   idempotent (cache hits / the safe-vote rule short-circuit a child
    ///   already handled), so re-triggering unconditionally is safe.
    fn retry_pending_children(
        &mut self,
        topology_schedule: &TopologySchedule,
        parent_hash: BlockHash,
    ) -> Vec<Action> {
        let children: Vec<(BlockHeader, bool)> = self
            .pending_blocks
            .values()
            .filter(|p| p.header().parent_block_hash() == parent_hash)
            .map(|p| (p.header().clone(), p.block().is_some()))
            .collect();
        let mut actions = Vec::new();
        for (header, assembled) in children {
            let child = header.hash();
            actions.extend(self.link_buffered_votes_to_header(topology_schedule, child, &header));
            if assembled {
                actions.extend(self.trigger_qc_verification_or_vote(topology_schedule, child));
            }
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
                missing_finalizations = pending.missing_finalization_count(),
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
            // This header's committee anchor — the parent's own anchor, one
            // value that both checks below key on.
            //
            // The floor first: the parent QC's weighted timestamp is this
            // block's own anchor, and it rides outside the QC's signed
            // message, so a Byzantine proposer can rewrite it on a genuine QC
            // and steer verification to any retained epoch's committee.
            // Honest aggregation clamps every vote to the voted block's own
            // anchor (`VoteSet`), so a genuine QC never regresses below the
            // committee anchor — enforce that here, the chokepoint every vote
            // path crosses (fresh headers, deferred children, and the
            // verified-QC cache hit below). Unresolvable only while the parent
            // itself is unknown — defer like the committee resolution below
            // does; `retry_pending_children` re-enters when the parent lands.
            let Some(committee_anchor_wt) = self.block_anchor(header.parent_qc().block_hash())
            else {
                trace!(
                    validator = ?self.me,
                    block_hash = ?block_hash,
                    parent = ?header.parent_qc().block_hash(),
                    "Parent block not held — deferring anchor check until it arrives"
                );
                return vec![];
            };
            if header.parent_qc().weighted_timestamp() < committee_anchor_wt {
                warn!(
                    validator = ?self.me,
                    block_hash = ?block_hash,
                    height = height.inner(),
                    qc_weighted_ms = header.parent_qc().weighted_timestamp().as_millis(),
                    committee_anchor_ms = committee_anchor_wt.as_millis(),
                    "Parent QC weighted timestamp regresses below the committee anchor — not voting"
                );
                return vec![];
            }

            // The parent is now held, so `committee(h)` resolves — the
            // proposer check `reject_invalid_header` skips for a header
            // arriving ahead of its parent runs here, before any vote.
            if let ScheduleLookup::Committee(committee) = topology_schedule
                .lookup_for_shard_live(self.local_shard, committee_anchor_wt)
                .0
                && let Err(e) = validate_proposer(committee.as_ref(), self.local_shard, &header)
            {
                warn!(
                    validator = ?self.me,
                    block_hash = ?block_hash,
                    error = %e,
                    "Header names the wrong proposer for its committee — not voting"
                );
                return vec![];
            }

            // Check if we've already verified this exact QC. The cache hit
            // must match byte-for-byte, not just by `block_hash` — see
            // `absorb_parent_qc_from_header` for the same trust gap. A
            // mismatch falls through to signature verification rather than being
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
        if let Some(block) = self.pending_blocks.get_block(block_hash).cloned() {
            let block = &block;
            // Content validation (`ticks` recomputation) and the beacon-witness
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
            if self.reject_invalid_block_contents(
                committee,
                topology_schedule,
                block_hash,
                block,
                coasting,
            ) {
                return vec![];
            }

            // Blocks the safe-vote rule declines must still run verification to
            // produce PreparedCommit. Parent-pruned blocks likewise run
            // verification but can't contribute in-flight accounting.
            let (parent_in_flight, parent_settled_frontier, _finalized_tx_count) = {
                let chain = self.chain_view();
                let genesis_parent = block.header().parent_qc().is_genesis();
                let parent_in_flight = if genesis_parent {
                    Some(WorkInFlight::ZERO)
                } else {
                    chain.parent_in_flight_checked(block.header().parent_block_hash())
                };
                let parent_settled_frontier = if genesis_parent {
                    Some(BlockHeight::GENESIS)
                } else {
                    chain.parent_settled_frontier_checked(block.header().parent_block_hash())
                };
                let finalized_tx_count: u32 = chain.get_pending(block_hash).map_or(0, |p| {
                    p.finalizations()
                        .iter()
                        .map(|fw| u32::try_from(fw.tx_count()).unwrap_or(u32::MAX))
                        .sum()
                });
                (
                    parent_in_flight,
                    parent_settled_frontier,
                    finalized_tx_count,
                )
            };
            let skip_vote = match self.verification.classify_vote_terms(
                parent_in_flight,
                parent_settled_frontier,
                block_hash,
                block,
                !safe,
            ) {
                InFlightCheck::Proceed => false,
                InFlightCheck::SkipVote => true,
                InFlightCheck::Abort => return vec![],
            };

            // Whether this window requires the header's split-child-root
            // pair is decided by the window's own frozen schedule entry,
            // so the voter and the proposer read the same answer without
            // either waiting on a beacon fold. A window the schedule has
            // evicted defers the vote like a missing committee (the block
            // stays pending) rather than judging the header on a guess.
            let Some(split_child_roots_required) = self.split_child_roots_bit(
                topology_schedule,
                block.header().parent_qc().weighted_timestamp(),
            ) else {
                trace!(
                    validator = ?self.me,
                    block_hash = ?block_hash,
                    "Split-at-boundary window missing from the schedule; deferring the vote"
                );
                return vec![];
            };
            let Some(terminal_roots_required) = self.terminal_roots_bit(
                topology_schedule,
                block.header().parent_qc().weighted_timestamp(),
            ) else {
                trace!(
                    validator = ?self.me,
                    block_hash = ?block_hash,
                    "Termination-at-boundary window missing from the schedule; deferring the vote"
                );
                return vec![];
            };

            // The claims the block makes on other chains, held to what
            // this validator has mirrored: a refusal never votes, a
            // deferral leaves the block pending and asks for what would
            // let the vote proceed.
            match self.vote_fence().judge(topology_schedule, block) {
                Ok(()) => {
                    if let Some(pending) = self.pending_blocks.get_mut(block_hash) {
                        pending.set_awaiting_counterpart(false);
                    }
                }
                Err(Withheld::Refused(why)) => {
                    warn!(
                        validator = ?self.me,
                        block_hash = ?block_hash,
                        %why,
                        "The vote fence refuses the block — not voting"
                    );
                    return vec![];
                }
                Err(Withheld::Deferred { why, wanted }) => {
                    trace!(
                        validator = ?self.me,
                        block_hash = ?block_hash,
                        %why,
                        "The vote fence cannot yet judge the block — deferring"
                    );
                    if let Some(pending) = self.pending_blocks.get_mut(block_hash) {
                        pending.set_awaiting_counterpart(true);
                    }
                    return wanted;
                }
            }
            let block_fees = self.local_payer_fees(
                committee,
                block.transactions().iter().map(|tx| PayerFee {
                    vault: tx.fee_vault(),
                    auth_cell: tx.auth_cell(),
                    max_fee: tx.body().max_fee,
                    signer: Some(tx.signer()),
                }),
            );
            let fee_demands = self.fee_demands(&block_fees, block.header().parent_block_hash());
            let fee_read_height = self.ancestry_committed_height(block.header().parent_qc());
            let fee_read_ready = fee_read_height <= self.committed_height;
            if !fee_read_ready && !fee_demands.is_empty() {
                // The anchor's commit is proven but hasn't landed in the
                // local pipeline yet; hold the demands and dispatch from
                // `record_block_committed` when it does.
                self.deferred_reservation_checks
                    .entry(block_hash)
                    .or_insert_with(|| (fee_demands.clone(), fee_read_height));
            }
            let verification_actions = self.verification.initiate_block_verifications(
                committee,
                topology_schedule,
                self.local_shard,
                &self.pending_blocks,
                &self.beacon_witness_accumulator,
                self.committed_hash,
                self.committed_tip.map(|tip| tip.reveal_chain),
                self.committed_block_anchor_wt,
                self.committed_committee_anchor_wt,
                block_hash,
                block,
                SubstateCountSource {
                    thresholds: committee.reshape_thresholds(),
                    frontier: self.substate_bytes_frontier,
                    committed_height: self.committed_height,
                    deltas: &self.pending_bytes_deltas,
                },
                split_child_roots_required,
                terminal_roots_required,
                fee_demands,
                fee_read_height,
                fee_read_ready,
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

    /// Per-payer fee-reservation demands for the transaction list
    /// `fees`: each listed ceiling, plus the still-held ceilings in the
    /// complete uncommitted ancestor bodies behind `parent_block_hash`,
    /// plus the committed in-flight ledger holds. The signers are this
    /// block's own — ancestors answered for theirs at their own vote —
    /// and each must be one the payer's rule admits for the reservation
    /// to engage. Empty when the list names no local payer. A rare
    /// manifest-only ancestor under view changes contributes nothing —
    /// a bounded optimism the fee settlement's saturating debit absorbs.
    fn fee_demands(&self, fees: &[PayerFee], parent_block_hash: BlockHash) -> Vec<FeeDemand> {
        let mut demands: BTreeMap<SubstateKey, FeeDemand> = BTreeMap::new();
        for fee in fees {
            let entry = demands.entry(fee.vault).or_insert_with(|| FeeDemand {
                vault: fee.vault,
                auth_cell: fee.auth_cell,
                demand: 0,
                signers: BTreeSet::new(),
            });
            entry.demand = entry.demand.saturating_add(fee.max_fee);
            entry.signers.extend(fee.signer);
        }
        if demands.is_empty() {
            return Vec::new();
        }
        let mut cursor = parent_block_hash;
        while let Some(pending) = self.pending_blocks.get(cursor) {
            if pending.header().height() <= self.committed_height {
                break;
            }
            if let Some(block) = pending.block() {
                for tx in block.transactions().iter() {
                    if let Some(entry) = demands.get_mut(&tx.fee_vault()) {
                        let fee = tx.body().max_fee;
                        entry.demand = entry.demand.saturating_add(fee);
                    }
                }
            }
            cursor = pending.header().parent_block_hash();
        }
        for demand in demands.values_mut() {
            demand.demand = demand
                .demand
                .saturating_add(self.fee_ledger.held_for(demand.vault.owner));
        }
        demands.into_values().collect()
    }

    /// The highest height a block's own ancestry proves committed,
    /// walking down from the QC certifying its parent: a certified block
    /// commits its parent when their rounds are contiguous, and
    /// committing a block commits its whole prefix. The walk reads only
    /// chain content — block rounds along the parent line — so every
    /// replica holding the block derives the same height, which is what
    /// lets fee-reservation balance reads anchor here rather than at the
    /// local commit tip, where pipelined voters legitimately differ.
    ///
    /// Ancestors already committed and pruned from pending resolve
    /// through [`Self::committed_rounds`]; the committed chain is
    /// linear, so height alone identifies them. Past that ring's
    /// horizon the candidate is committed far beyond any live vote's
    /// pipeline and is returned as-is.
    fn ancestry_committed_height(&self, parent_qc: &QuorumCertificate) -> BlockHeight {
        // A genesis QC proves nothing above the chain origin.
        let Some(mut candidate_height) = parent_qc.committable_height() else {
            return parent_qc.height();
        };
        let mut candidate_hash = parent_qc.committable_hash();
        // The certified block's round — a QC certifies its block at the
        // block's own round.
        let mut child_round = parent_qc.round();
        loop {
            let (round, parent) =
                match candidate_hash.and_then(|hash| self.pending_blocks.get_header(hash)) {
                    Some(header) => (header.round(), Some(header.parent_block_hash())),
                    None => match self.committed_rounds.get(&candidate_height) {
                        Some(round) => (*round, None),
                        None => return candidate_height,
                    },
                };
            if child_round == round.next() {
                return candidate_height;
            }
            let Some(next_height) = candidate_height.prev() else {
                return candidate_height;
            };
            child_round = round;
            candidate_hash = parent;
            candidate_height = next_height;
        }
    }

    /// The fee contributions of `transactions` whose payer routes to
    /// this shard.
    fn local_payer_fees(
        &self,
        topology_snapshot: &TopologySnapshot,
        transactions: impl Iterator<Item = PayerFee>,
    ) -> Vec<PayerFee> {
        let trie = topology_snapshot.shard_trie();
        transactions
            .filter(|fee| trie.shard_for_prefix(fee.vault.owner) == self.local_shard)
            .collect()
    }

    /// Validate transaction ordering, ticks, and cross-ancestor tx uniqueness
    /// against the QC chain + retention cache. Returns `true` when the caller
    /// should reject the block (logs the reason).
    fn reject_invalid_block_contents(
        &self,
        topology_snapshot: &TopologySnapshot,
        topology_schedule: &TopologySchedule,
        block_hash: BlockHash,
        block: &Block,
        coasting: bool,
    ) -> bool {
        let parent = block.header().parent_block_hash();
        let chain = QcChainSets::behind(&self.chain_view(), parent);
        let ctx = self.admission(
            topology_snapshot,
            topology_schedule,
            &chain,
            parent,
            block.header().parent_qc().weighted_timestamp(),
            block.header().parent_qc().is_genesis(),
        );
        if let Err(e) = validate_block_for_vote(
            &ctx,
            block,
            coasting,
            self.chain_view().parent_load_checked(parent),
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
        // pipelining), self-healing via gossip — but a hint that names none
        // of the round's real proposers costs a view change, so it resolves
        // the same committee the next proposer will — by asking the same
        // question of the same block. The block being voted on is the tip
        // that proposer extends, so `committee_for_child_of` answers for both.
        // Falls back to the head where the schedule cannot answer at all:
        // genesis has no anchor, and an evicted window is far enough back that
        // the head is the better guess.
        // A snapshot that seats nobody for this shard answers the routing
        // question no better than one the schedule could not resolve at
        // all, so it falls through the same way rather than naming an
        // empty rotation.
        let seats_anyone = |snapshot: &Arc<TopologySnapshot>| {
            !snapshot
                .consensus_committee_for_shard(self.local_shard)
                .is_empty()
        };
        let governing = self
            .committee_for_child_of(topology_schedule, block_hash)
            .filter(|snapshot| seats_anyone(snapshot))
            .or_else(|| {
                // Past a terminal cut the live windows carry the shard no
                // longer, so the coast blocks certifying the crossing route
                // to the terminal-clamped committee that signs them.
                anchored_wt
                    .and_then(|wt| topology_schedule.at_for_shard(self.local_shard, wt))
                    .map(|(snapshot, _)| snapshot)
                    .filter(|snapshot| seats_anyone(snapshot))
            })
            .map_or_else(|| topology_schedule.head().as_ref(), Arc::as_ref);
        let next_proposers = vote_recipients(governing, self.local_shard, self.me, round);

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
            position: self.vote_position(Some(block_hash)),
        }]
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Vote Collection (Deferred Verification)
    // ═══════════════════════════════════════════════════════════════════════════

    /// Handle a locally-produced, pre-verified block vote. Skips the
    /// batch-verify path — the vote is admitted directly to the verified
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

        // A vote tallies against its block's committee, which anchors on the
        // block's *parent* — so a vote can outrun either header. While the
        // anchor is unresolvable the exact committee is unknowable: hold the
        // vote raw, and admit it in `link_buffered_votes_to_header`, which
        // runs both when the block's header lands and when its parent does.
        // (Anchor resolvable but committee `None` ⇒ beacon-behind stall.)
        if self.committee_anchor(vote.block_hash()).is_none() {
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
    /// `IoLoop` has already signature-verified the signal against the sender's
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
    #[instrument(skip(self, qc, verified_votes), fields(
        block_hash = ?block_hash,
        has_qc = qc.is_some(),
        verified_count = verified_votes.len()
    ))]
    pub fn on_qc_result(
        &mut self,
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
        // The voted block's parent is bound into every vote's signing
        // message, so it is needed to assemble equivocation evidence; all
        // votes here target `block_hash`, so it resolves once.
        let validator_id = self.me;
        let high_qc_round = self.high_qc_round();
        let parent_block_hash = self
            .pending_blocks
            .get_header(block_hash)
            .map(BlockHeader::parent_block_hash);
        let mut actions: Vec<Action> = Vec::new();
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
            if let Some(evidence) =
                self.votes
                    .track_verified_received_vote(block_hash, parent_block_hash, vote)
                && self.detected_equivocators.insert(evidence.validator)
            {
                // First sighting: hand the pair to the host, which
                // buffers it for the beacon and gossips it globally —
                // the lane that keeps the evidence alive after every
                // holder leaves this committee.
                actions.push(Action::Continuation(
                    ProtocolEvent::ShardVoteEquivocationDetected {
                        evidence: Box::new(evidence),
                    },
                ));
            }
        }

        self.votes
            .finalize_pending_batch(block_hash, verified_votes);
        // The tally's denominator rides on the vote set, latched from the
        // committee that governed the block when its first vote landed — so a
        // batch returning after the block's committee stops resolving still
        // retriggers rather than stranding the votes behind it.
        actions.extend(
            self.votes
                .maybe_trigger_verification(self.local_shard, block_hash),
        );
        actions
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

    /// One check on a pending block completed.
    ///
    /// A pass records the stage and, once every check the block demands
    /// has passed, votes — re-checking the safe-vote rule at emission,
    /// since the round or the lock may have moved while the checks ran —
    /// and re-drives the two-chain commit an assembled handle may have
    /// been waiting on. A refusal drops the block. A deferral clears the
    /// stage so the next re-drive of the vote dispatches the check again
    /// and leaves the block pending: this validator cannot say yet, and
    /// the block commits on a quorum's certificate like any block it did
    /// not vote for.
    #[instrument(skip(self, topology_schedule, outcome), fields(block_hash = ?block_hash, ?kind))]
    pub fn on_block_check_completed(
        &mut self,
        topology_schedule: &TopologySchedule,
        block_hash: BlockHash,
        kind: VerificationKind,
        outcome: CheckOutcome,
    ) -> Vec<Action> {
        match outcome {
            CheckOutcome::Refused => {
                warn!(
                    block_hash = ?block_hash,
                    ?kind,
                    "Block check FAILED — rejecting block"
                );
                self.verification.refused(block_hash, kind);
                return self.remove_pending_block(block_hash);
            }
            CheckOutcome::Deferred(DeferOn::Bodies(names)) => {
                trace!(
                    validator = ?self.me,
                    block_hash = ?block_hash,
                    ?kind,
                    ?names,
                    "Block check names transactions this validator does not hold; deferring"
                );
                self.verification.deferred(block_hash, kind);
                return vec![];
            }
            CheckOutcome::Checked { bytes_delta } => {
                if kind == VerificationKind::StateRoot {
                    self.pending_bytes_deltas.insert(block_hash, bytes_delta);
                }
                self.verification.checked(block_hash, kind);
            }
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
                "Check complete but block not found in pending or synced"
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
                "Check complete, waiting for the others"
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
            self.committed_tip.map(|tip| tip.reveal_chain),
            self.committed_block_anchor_wt,
            self.committed_committee_anchor_wt,
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
    #[instrument(skip(self, topology_schedule, block, finalizations), fields(height = %height.inner(), round = round.inner()))]
    #[allow(clippy::too_many_arguments)]
    pub fn on_proposal_built(
        &mut self,
        topology_schedule: &TopologySchedule,
        height: BlockHeight,
        round: Round,
        block: &Block,
        block_hash: BlockHash,
        finalizations: Vec<Arc<Verifiable<Finalization>>>,
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

        // Store our own block as pending (with all finalizations + provisions).
        let mut pending_block =
            PendingBlock::from_complete_block(block, finalizations, provisions, self.now);

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
        self.verification.mark_proposal_fully_verified(block);

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
            self.verification.release_substate_park_on_reconcile();
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
    #[instrument(skip(self, topology_schedule, qc, ready_txs, finalizations), fields(
        height = qc.height().inner(),
        block_hash = ?block_hash
    ))]
    #[allow(clippy::too_many_arguments)]
    pub fn on_qc_formed(
        &mut self,
        topology_schedule: &TopologySchedule,
        block_hash: BlockHash,
        qc: &Verified<QuorumCertificate>,
        ready_txs: &[Arc<Verified<Transaction>>],
        finalizations: Vec<Arc<Verifiable<Finalization>>>,
        provisions: Vec<Arc<Verifiable<Provisions>>>,
        abandonment_records: Vec<AbandonmentRecord>,
        state_claims: Vec<StateClaim>,
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
        actions.extend(self.try_propose(
            topology_schedule,
            ready_txs,
            finalizations,
            provisions,
            abandonment_records,
            state_claims,
        ));

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
        // The walk has to land *on* the committed tip, not merely at the
        // height above it. A branch that reaches the right height by a
        // different parent is a sibling of what this node committed, and
        // splicing it would fork the chain at the tip — which is what
        // `record_block_committed` asserts against, one step too late to
        // do anything but abort.
        //
        // Two certified siblings at one height is a shape block sync
        // already serves (`take_next_verified`), on the reasoning that
        // only one of them can gather a round-contiguous two-chain. That
        // holds under one committee. It does not hold while a halt
        // recovery has two of them live — the retained committee is
        // disarmed only once it folds the record — so the branch this
        // node is not on arrives certified, commit-driving, and at
        // exactly the next height.
        if parent_hash != self.committed_hash {
            warn!(
                validator = ?self.me,
                shard = ?self.local_shard,
                height = committable.block().height().inner(),
                committable = ?committable.block().hash(),
                extends = ?parent_hash,
                committed_tip = ?self.committed_hash,
                "Refusing a commit whose prefix leaves the committed tip"
            );
            return None;
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
        self.committed_rounds.insert(height, block.header().round());
        while self.committed_rounds.len() > COMMITTED_ROUNDS_HORIZON {
            self.committed_rounds.pop_first();
        }

        // Retain both anchors across the prune: the tip's own, which anchors
        // the committee of the block extending it, and the one its parent
        // carried, which anchors the committee that signed the tip itself.
        self.committed_committee_anchor_wt = self.committed_block_anchor_wt;
        self.committed_block_anchor_wt = block.header().parent_qc().weighted_timestamp();
        self.committed_state_root = block.header().state_root();
        self.committed_tip = Some(block.header().committed_tip());
        self.retire_proven_anchors();

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
        self.register_dedup_artifacts(block, &manifest, commit_ts);
        self.register_fee_holds(topology_schedule, block, commit_ts);

        // Derive this block's beacon-witness leaves from the same
        // canonical sources the proposer used (receipts from finalized
        // ticks, missed-proposal walk over `(parent_round, round)`, and
        // the block's carried witness sources). The leaves are folded
        // into the in-memory accumulator and packaged into a
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
            &receipts,
            &missed,
            block.witness_sources(),
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

        let mut actions = self.cleanup_old_state(height);
        self.drain_deferred_reservation_checks(height, &mut actions);
        (actions, witness)
    }

    /// Fold a committed block into the dedup index: what it committed, what
    /// its finalizations resolved, and the batches it carried.
    ///
    /// Committing is also what deepens the index's own coverage — a
    /// coordinator seeded short of the horizon reaches it by folding
    /// forward, and these are the blocks a backward walk would otherwise
    /// have had to read.
    fn register_dedup_artifacts(
        &mut self,
        block: &Block,
        manifest: &BlockManifest,
        commit_ts: WeightedTimestamp,
    ) {
        self.dedup_index
            .cover(block.header().parent_qc().weighted_timestamp());
        self.dedup_index
            .register_committed_txs(block.transactions());
        self.dedup_index
            .register_committed_certs(block.certificates());
        self.dedup_index
            .register_committed_provisions(manifest.provision_hashes(), commit_ts);
        // Bundle content feeds the engagement mirror — live bodies only;
        // a sealed manifest has no content and the mirror votes
        // conservatively across that gap.
        self.dedup_index
            .register_committed_provision_txs(block.provisions(), commit_ts);
    }

    /// Commit-time fee-ledger bookkeeping: engage reservations for the
    /// block's local payers, release those its finalizations resolve,
    /// and prune holds whose deadlines passed — the cover for
    /// resolution paths that never produce a certificate (a reshape
    /// terminal's abort by omission).
    fn register_fee_holds(
        &mut self,
        topology_schedule: &TopologySchedule,
        block: &Block,
        commit_ts: WeightedTimestamp,
    ) {
        let trie = topology_schedule.head().shard_trie();
        let local_shard = self.local_shard;
        self.fee_ledger
            .register_committed(block.transactions(), |payer| {
                trie.shard_for_prefix(payer) == local_shard
            });
        self.fee_ledger.release_finalized(block.certificates());
        self.fee_ledger.prune(commit_ts);
    }

    /// Dispatch fee-reservation verifications whose ancestry-proven
    /// balance anchor the commit at `height` just materialized. A
    /// deferred block that has since left pending (pruned, replaced)
    /// drops its entry.
    fn drain_deferred_reservation_checks(
        &mut self,
        height: BlockHeight,
        actions: &mut Vec<Action>,
    ) {
        let pending_blocks = &self.pending_blocks;
        self.deferred_reservation_checks
            .retain(|deferred_hash, (demands, anchor)| {
                if *anchor > height {
                    return true;
                }
                if let Some(pending) = pending_blocks.get(*deferred_hash) {
                    actions.push(Action::VerifyReservations {
                        block_hash: *deferred_hash,
                        demands: std::mem::take(demands),
                        read_height: *anchor,
                        clock: pending.header().parent_qc().weighted_timestamp(),
                    });
                }
                false
            });
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
        let parent_sweep_frontier = self
            .chain_view()
            .parent_sweep_frontier(certified.block().header().parent_block_hash());
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
                parent_sweep_frontier,
                creations: committed_cells_for(certified.block()),
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
            return self.apply_synced_block(topology_schedule, block, verified_qc);
        }

        // A fork-caused recovery pins the seed to the beacon-attested
        // frontier: the replaced committee provably committed two branches,
        // so any of its certified blocks above the frontier — anchored and
        // certified below the recovery bridge — may be either branch, and
        // admitting one seeds this replica onto an unattestable chain.
        // Blocks at or below the frontier are common attested history and
        // stay admissible, as do the fresh committee's own blocks (certified
        // past the bridge). A halt's unique suffix keeps today's admission.
        if let Some(recovery) = topology_schedule
            .head()
            .pending_recoveries()
            .get(&self.local_shard)
            && recovery.cause == RecoveryCause::Fork
            && certified.block().height() > recovery.attested_frontier
            && topology_schedule.recovery_suffix_band(
                self.local_shard,
                certified.block().header().parent_qc().weighted_timestamp(),
                certified.qc().weighted_timestamp(),
            )
        {
            warn!(
                height = certified.block().height().inner(),
                frontier = recovery.attested_frontier.inner(),
                "Rejecting a retained suffix block above the fork recovery frontier"
            );
            return vec![];
        }

        // The QC over this block was signed by the block's committee, which
        // anchors on its parent — the same rule the live vote path and every
        // remote consumer resolve by. Reading the block's own anchor instead
        // picks the window the block *opens*, and across an epoch cut that
        // moves keys the signature check fails and sync wedges at that height
        // rather than crossing the boundary.
        //
        // A not-yet-committed epoch defers: the block goes back to the buffer
        // and `on_beacon_block_persisted` re-drains it once the beacon catches
        // up — discarding it here would leave a hole the drain can never
        // refill without a network re-fetch. An evicted epoch rejects: the
        // schedule's floor retains every epoch the local chain can still
        // verify against, so a synced block keyed below it carries a forged
        // weighted timestamp (it rides outside the signed message) or sits on
        // a stale fork — no amount of retrying resolves it. Certified
        // resolution: a halt recovery's bridge block — anchored below the
        // bridge, certified at or past it — verifies against the fresh
        // committee.
        let committee_anchor_wt = self.synced_committee_anchor_wt(certified.block().header());
        let committee = match topology_schedule
            .lookup_for_shard_certified(
                self.local_shard,
                committee_anchor_wt,
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

        // Quorum-power gate: `VerifyQcSignature` only checks the
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
        // The same fold is what carries this chain's predecessors to a seat
        // the flip never reached, so a boot that lands mid-window picks
        // them up at the first beacon block it commits.
        self.adopt_precut_predecessors(topology_schedule);
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
    /// peer-served orphan sibling fork a lagging node.
    ///
    /// Its tree is prepared here, at admission, through the same state-root
    /// verification a live block gets: the QC attests the root, and the
    /// verification is what puts the block's JMT snapshot in the overlay
    /// for its children to build on. A block this node never verified
    /// itself commits through `CommitBlockByQcOnly`, which prepares inline.
    fn apply_synced_block(
        &mut self,
        topology_schedule: &TopologySchedule,
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

        // The synced block's QC BFT-transitively attests every embedded tick's
        // per-EC signature predicate via the source committee's signature over
        // `certificate_root` + `local_receipt_root`, so the ticks can be
        // admitted to the canonical store on receipt.
        let synced_finalizations: Vec<Arc<Verifiable<Finalization>>> = block
            .certificates()
            .iter()
            .map(|fw| {
                // Reuse a live marker when present (local dispatch) by keeping the
                // existing `Arc`; otherwise mint via the committed-block gate.
                if fw.is_verified() {
                    Arc::clone(fw)
                } else {
                    let verified =
                        Verified::<Finalization>::from_committed_block(fw.as_unverified().clone());
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
        self.initiate_synced_state_root_verification(topology_schedule, certified.block());

        let mut actions = self.try_two_chain_commit(certified.qc_verified(), CommitSource::Sync);

        if !synced_finalizations.is_empty() {
            actions.push(Action::Continuation(ProtocolEvent::FinalizationsAdmitted {
                finalizations: synced_finalizations,
            }));
        }

        actions
    }

    /// Queue a sync-admitted block's state-root verification, so its tree
    /// lands in the overlay for its children.
    ///
    /// Genesis is seated by the store's adoption and has no parent to
    /// verify against. The per-window verdict bits read the block's own
    /// window; a window the schedule has not resolved leaves the block
    /// unverified, and its commit prepares inline instead.
    fn initiate_synced_state_root_verification(
        &mut self,
        topology_schedule: &TopologySchedule,
        block: &Block,
    ) {
        if block.is_genesis() || !self.verification.needs_state_root_verification(block) {
            return;
        }
        let anchor_wt = block.header().parent_qc().weighted_timestamp();
        let (Some(split_child_roots_required), Some(terminal_roots_required)) = (
            self.split_child_roots_bit(topology_schedule, anchor_wt),
            self.terminal_roots_bit(topology_schedule, anchor_wt),
        ) else {
            debug!(
                validator = ?self.me,
                height = block.height().inner(),
                "Synced block's window missing from the schedule; leaving its tree to the commit"
            );
            return;
        };
        let settled_txs_window_floor =
            topology_schedule.settled_window_floor(self.local_shard, anchor_wt);
        self.verification.initiate_state_root_verification(
            block.hash(),
            block,
            block.header().parent_qc().height(),
            split_child_roots_required,
            terminal_roots_required,
            settled_txs_window_floor,
        );
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
            actions.extend(self.apply_synced_block(topology_schedule, block, verified_qc));
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
                        missing_finalizations = pending.missing_finalization_count(),
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
            position: self.vote_position(None),
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

    /// Screen a wire timeout, then delegate its signature share verification to the
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
        // before spending a signature verify on them; `on_verified_timeout` re-checks
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

    /// Whether a fork-caused recovery refuses `qc` as a sync source: the
    /// QC names a block above the beacon-attested frontier that the
    /// replaced committee certified before the re-draw (its weighted
    /// timestamp resolves below the recovery bridge). A forked retained
    /// committee provably committed two branches, so such a block may be
    /// either branch and must not seed this replica; the fresh chain's
    /// own blocks certify at post-bridge timestamps and pass. Halt
    /// recoveries keep the full suffix admissible — their retained tip is
    /// unique.
    fn fork_refuses_retained_suffix(
        &self,
        topology_schedule: &TopologySchedule,
        qc: &QuorumCertificate,
    ) -> bool {
        let wt = qc.weighted_timestamp();
        topology_schedule
            .head()
            .pending_recoveries()
            .get(&self.local_shard)
            .is_some_and(|recovery| {
                recovery.cause == RecoveryCause::Fork
                    && qc.height() > recovery.attested_frontier
                    && topology_schedule.recovery_suffix_band(self.local_shard, wt, wt)
            })
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
    ///
    /// The harvest is halt-only. A fork-caused recovery's retained
    /// committee provably committed two branches, so no retained tip is
    /// unique: a carried QC may name either branch (above the attested
    /// frontier, or a losing-branch sibling below it), and adopting one
    /// would seed the incomers onto divergent chains — the fresh committee
    /// forks at seed time, or its minority breaks commit linkage. The
    /// recovery's `attested_frontier` is the one beacon-attested anchor,
    /// and the relocation snap-sync already seeds it, so a forked shard
    /// refuses every retained suffix and its first fresh block extends the
    /// frontier.
    fn harvest_retained_tip(
        &mut self,
        topology_schedule: &TopologySchedule,
        timeout: &Timeout,
    ) -> Option<Vec<Action>> {
        let recovery = topology_schedule
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
        if recovery.cause == RecoveryCause::Fork {
            info!(
                validator = ?self.me,
                voter = ?timeout.voter(),
                carried_height = carried.height().inner(),
                frontier = recovery.attested_frontier.inner(),
                "Refusing a retained ex-member's tip on a forked shard; seeding from the attested frontier"
            );
            return Some(Vec::new());
        }
        info!(
            validator = ?self.me,
            voter = ?timeout.voter(),
            carried_height = carried.height().inner(),
            committed_height = self.committed_height.inner(),
            "Harvesting the halted tip from a retained ex-member's timeout"
        );
        // Remember what was offered even when the QC cannot be adopted
        // yet: the block it certifies is still being fetched, and until
        // this member's own `high_qc` reaches it, proposing would build
        // over heights the halted chain already holds.
        self.retained_tip_offered = Some(
            self.retained_tip_offered
                .map_or_else(|| carried.height(), |seen| seen.max(carried.height())),
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
        // A verified signature share proves who signed, not that the signer sits in
        // the committee whose 2f+1 the pacemaker measures against. Restrict the
        // tally to the local committee: the quorum total is committee-scoped, so
        // a globally-registered validator from another shard must not count
        // toward the f+1 / 2f+1 thresholds.
        let Some(power) = self.committee_timeout_power(committee, timeout.voter()) else {
            warn!(validator = ?self.me, voter = ?timeout.voter(), "Dropping timeout from non-committee validator");
            return Vec::new();
        };
        // A verified committee timeout at a higher round nudges the view
        // toward it, exactly as headers and votes do — and it is the one
        // signal an idle chain still emits. A view split thinner than f+1
        // per round produces nothing but timeout shares: amplification
        // needs f+1 in one round, carried adoption needs a QC to carry,
        // and no leader stands in its own round to header one. Without
        // this nudge no mechanism moves a view toward the shares and the
        // split is permanent.
        let high_qc_round = self.high_qc_round();
        if self
            .view_change
            .sync_to_observed_round(round, high_qc_round)
        {
            info!(
                validator = ?self.me,
                new_view = self.view_change.view.inner(),
                voter = ?timeout.voter(),
                "View synced forward to observed timeout round"
            );
        }
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
            verifier: self.verifier.as_ref(),
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
        txs: &[Arc<Verified<Transaction>>],
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        for tx in txs {
            let wrapped: Arc<Verifiable<Transaction>> = Arc::new(Verifiable::from((**tx).clone()));
            for block_hash in self.pending_blocks.receive_transaction(&wrapped) {
                actions.extend(self.dispatch_block_complete(topology_schedule, block_hash));
            }
        }
        actions
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Receipt Availability
    // ═══════════════════════════════════════════════════════════════════════════

    /// React to finalizations newly admitted to the canonical execution
    /// store. Same shape as `on_transactions_admitted` and
    /// `on_provisions_admitted`.
    ///
    /// Each tick is validated against the certificates it carries before
    /// use, and this is where a proposer's choice of them is checked. A
    /// peer with divergent local execution could serve a tick whose
    /// receipts disagree with the outcomes its own certificate attests
    /// to; a dishonest one could serve a tick whose certificates leave out
    /// a participant, which reads as unanimous acceptance and settles
    /// effects a counterpart discarded. Rejecting such a tick leaves the
    /// pending block incomplete, so the block gets no vote here; the fetch
    /// protocol retries from a different peer.
    pub fn on_finalizations_admitted(
        &mut self,
        topology_schedule: &TopologySchedule,
        ticks: &[Arc<Verifiable<Finalization>>],
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        for fw in ticks {
            if let Err(err) = fw.validate_against_certificates() {
                warn!(
                    tick_id = ?fw.tick_id(),
                    ?err,
                    "Rejecting Finalization: inconsistent with the certificates it carries"
                );
                continue;
            }
            for block_hash in self.pending_blocks.receive_finalization(fw) {
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
    /// finalization, and provision fetches — those no surviving block still
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

    /// Drive the verification of the blocks the store handed back at
    /// startup, lowest first.
    ///
    /// A restored certificate names a block above the committed tip, and
    /// a proposer extends the block its high QC certifies — which means
    /// executing that block over its own uncommitted ancestors. Seeding
    /// them as pending blocks restores the bodies; only the verification
    /// pipeline restores the state each one left, which is what the
    /// proposal builds on. The safe-vote rule declines every one of them
    /// (their rounds are consumed), and that is the path already taken by
    /// a block a validator verifies without voting for.
    ///
    /// Runs once — a second drive would re-enter verifications already in
    /// flight. Blocks whose parent has not been prepared yet defer inside
    /// the pipeline and resume when it is.
    fn resume_recovered_blocks(&mut self, topology_schedule: &TopologySchedule) -> Vec<Action> {
        if self.recovered_blocks.is_empty() {
            return Vec::new();
        }
        let mut resuming: Vec<BlockHash> = std::mem::take(&mut self.recovered_blocks);
        resuming.sort_by_key(|hash| {
            self.pending_blocks
                .get_header(*hash)
                .map_or(BlockHeight::GENESIS, BlockHeader::height)
        });
        let mut actions = Vec::new();
        for hash in resuming {
            actions.extend(self.trigger_qc_verification_or_vote(topology_schedule, hash));
        }
        actions
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
        // A snap-synced joiner adopts its anchor QC here — the periodic
        // entry that always has the schedule in hand — so the fresh
        // committee holds the parent QC for its first block even when no
        // peer signal ever supplies a higher one.
        let mut actions = self.try_adopt_anchor_qc(topology_schedule);
        actions.extend(self.resume_recovered_blocks(topology_schedule));

        let next_needed_height = self.committed_height.next();
        let has_next_block = self.has_complete_block_at_height(next_needed_height);

        let sync_actions = match self.block_sync.health_check(
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
                    vec![]
                } else {
                    self.start_block_sync(target_height)
                }
            }
        };
        actions.extend(sync_actions);
        actions
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

    /// The chain's origin — the height its first block sits at, and the
    /// clock that block anchors to. `ChainOrigin::ROOT` for a chain born
    /// at network genesis; a reshape child continues its parent's height
    /// line, so no block below `genesis_height` exists on this chain.
    #[must_use]
    pub const fn chain_origin(&self) -> ChainOrigin {
        self.chain_origin
    }

    /// The chains this one succeeds, and the commitments they left.
    ///
    /// Empty on a chain born at network genesis, and on any seat that
    /// missed the reshape flip — a restart, or a validator rotated on
    /// afterwards — until
    /// [`adopt_precut_predecessors`](Self::adopt_precut_predecessors)
    /// reads them off its topology projection.
    #[must_use]
    pub fn predecessors(&self) -> &[PredecessorTerminal] {
        self.precut.predecessors()
    }

    /// Number of distinct validators for which this coordinator holds
    /// detected double-vote equivocation evidence not yet carried into a
    /// committed block. Drained into each proposal and pruned once the
    /// evidence lands on-chain.
    #[must_use]
    pub fn pending_equivocation_count(&self) -> usize {
        self.detected_equivocators.len()
    }

    /// Single chokepoint for dropping a pending block. All single-block
    /// removals (failed verification, abort, view-change drop) go through
    /// here so future bookkeeping (metrics, indices, etc.) has one place to
    /// hook. Bulk pruning at commit time uses `cleanup_old_state` which
    /// retains in-place.
    ///
    /// Returns `AbandonFetch` actions for the dropped block's outstanding
    /// transaction, finalization, and provision fetches that no surviving
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
            dedup_window_complete: self.dedup_index.is_complete(self.committed_ts),
            committed_resolution_lookup: self.dedup_index.resolved_tx_retention_len(),
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

    /// The drain the committed tip records, in work units: what committed
    /// transactions reserved and their ticks have not yet returned. `0`
    /// before the first header is observed.
    #[must_use]
    pub fn committed_in_flight(&self) -> u64 {
        self.committed_tip
            .map_or(0, |tip| tip.work_in_flight.inner())
    }

    /// The drain this shard still owes at the proposal parent: committed
    /// transactions whose tick has not settled, read off the parent's
    /// header rather than tracked locally.
    ///
    /// Chain-derived, so every replica computes the same number from the
    /// same block — where a locally-tracked count drifts with each node's
    /// own pipeline position.
    #[must_use]
    pub fn proposal_parent_in_flight(&self) -> WorkInFlight {
        self.chain_view()
            .parent_in_flight(self.proposal_parent_block_hash())
    }

    /// Returns the number of transactions in the QC chain above committed height.
    ///
    /// Callers should request this many extra transactions from the mempool to
    /// compensate for duplicates that will be filtered during proposal building.
    #[must_use]
    pub fn dedup_overhead(&self) -> usize {
        let parent_block_hash = self.proposal_parent_block_hash();
        QcChainSets::behind(&self.chain_view(), parent_block_hash)
            .txs
            .len()
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

    /// Snapshot of the safe-vote registers, carried on vote and timeout
    /// signing actions so the runner can persist them ahead of the
    /// signature.
    ///
    /// The high QC rides along because the lock is unusable without it: a
    /// record restored with a lock above every QC the validator can
    /// produce refuses every proposal forever.
    #[must_use]
    pub fn safe_vote_registers(&self) -> SafeVoteRegisters {
        SafeVoteRegisters {
            locked_round: self.locked_round,
            last_voted_round: self.last_voted_round,
            high_qc: self.latest_qc.as_deref().map(|qc| (*qc).clone()),
        }
    }

    /// The signing position a vote or timeout ratchets: the registers,
    /// and the uncommitted chain behind the certificate they carry.
    ///
    /// The justification runs from the committed tip up to the block the
    /// high QC certifies, oldest first — the blocks a proposer replays to
    /// extend that certificate. A restarted committee holds the
    /// certificate either way; what it cannot rebuild from a committed
    /// chain alone is the state these blocks left.
    #[must_use]
    pub fn vote_position(&self, voted: Option<BlockHash>) -> VotePosition {
        let tip = voted.or_else(|| self.latest_qc.as_deref().map(QuorumCertificate::block_hash));
        VotePosition {
            registers: self.safe_vote_registers(),
            justification: tip
                .map(|tip| self.uncommitted_suffix(tip))
                .unwrap_or_default(),
        }
    }

    /// The assembled uncommitted blocks from the committed tip up to
    /// `tip` inclusive, oldest first.
    ///
    /// `tip` is the block a signature is about to name — the one this
    /// vote extends the chain to, or the one the high QC certifies when
    /// no vote is being cast. The vote itself is what turns the voted
    /// block into the next certificate, so keeping it is what lets the
    /// committee that produced that certificate still build on it.
    ///
    /// Empty when `tip` is the committed tip, and empty when any ancestor
    /// above the committed tip is missing or unassembled — a suffix with
    /// a hole in it is no use to a proposer, so it is not written down.
    fn uncommitted_suffix(&self, tip: BlockHash) -> Vec<Arc<Block>> {
        let mut suffix = Vec::new();
        let mut hash = tip;
        while let Some(pending) = self.pending_blocks.get(hash) {
            if pending.header().height() <= self.committed_height {
                break;
            }
            let Some(block) = pending.block() else {
                return Vec::new();
            };
            suffix.push(Arc::clone(block));
            hash = pending.header().parent_block_hash();
        }
        suffix.reverse();
        suffix
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
    use std::collections::{BTreeMap, BTreeSet};

    use hyperscale_core::Action;
    use hyperscale_crypto_bls::{BlsSigner, BlsVerifier};
    use hyperscale_types::test_utils::{make_live_block, stub_abort_charge};
    use hyperscale_types::{
        AbandonmentRoot, Address, AddressClass, AggregateSignature, BeaconWitnessLeafCount,
        BlockHeaderParts, CommittedAt, CommittedTxsRoot, ConsensusSignature, Deadline, Epoch, Hash,
        LeafRoot, MAX_TIMESTAMP_DELAY, MAX_TIMESTAMP_RUSH, NetworkDefinition, NetworkParams,
        RoutePrefix, SettledSetVerdict, SettledTxSet, SettledTxsRoot, ShardAnchor, ShardId, Signer,
        SignerBitfield, StateClaimsRoot, TerminalRoots, TimestampRange, TopologySchedule,
        TopologySnapshot, Transaction, TxClaim, TxOutcome, UnsettledTx, VIEW_CHANGE_TIMEOUT,
        ValidatorId, ValidatorInfo, ValidatorSet, VoteCount, WeightedTimestamp, WitnessSources,
        settled_set_verdict, test_utils,
    };

    use super::*;
    use crate::admission::{RecordsSection, TransactionsSection, admit_all, unwrapped};

    fn install_complete_block(state: &mut ShardCoordinator, block: &Block) {
        let mut pending =
            PendingBlock::from_complete_block(block, vec![], vec![], LocalTimestamp::ZERO);
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
        let keys: Vec<BlsSigner> = (0..n).map(|_| BlsSigner::generate()).collect();

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
            Arc::new(BlsVerifier),
            ValidatorId::new(0),
            ShardId::ROOT,
            config,
            RecoveredState::default(),
        );
        (state, TopologySchedule::single(Arc::new(topology_snapshot)))
    }

    // ─── Pre-cut queries ───────────────────────────────────────────────

    /// A successor of one chain, cut at `cut`, with its certified clock
    /// sitting at `now`.
    fn make_successor(cut: WeightedTimestamp, now: WeightedTimestamp) -> ShardCoordinator {
        successor_holding(
            cut,
            now,
            vec![PredecessorTerminal {
                shard: ShardId::leaf(1, 0),
                height: BlockHeight::new(9),
                block_hash: BlockHash::ZERO,
                committed_txs_root: CommittedTxsRoot::ZERO,
            }],
        )
    }

    /// A successor cut at `cut`, clock at `now`, holding `predecessors` —
    /// empty for the seat the reshape flip never reached.
    fn successor_holding(
        cut: WeightedTimestamp,
        now: WeightedTimestamp,
        predecessors: Vec<PredecessorTerminal>,
    ) -> ShardCoordinator {
        let mut recovered = RecoveredState {
            chain_origin: ChainOrigin {
                genesis_height: BlockHeight::new(10),
                anchor_wt: cut,
            },
            predecessors,
            ..RecoveredState::default()
        };
        recovered.latest_qc = Some(Verified::new_unchecked_for_test(QuorumCertificate::new(
            BlockHash::ZERO,
            ShardId::ROOT,
            BlockHeight::new(10),
            BlockHash::ZERO,
            Round::new(1),
            SignerBitfield::new(4),
            AggregateSignature::ZERO,
            now,
        )));
        ShardCoordinator::new(
            Arc::new(BlsVerifier),
            ValidatorId::new(0),
            ShardId::ROOT,
            ShardConsensusConfig::default(),
            recovered,
        )
    }

    fn precut_tx(seed: u8, opens_ms: u64) -> Arc<Transaction> {
        test_utils::install_stub_protocol_statics();
        Arc::new(test_utils::stub_transaction(
            test_utils::test_principal(seed),
            &[test_utils::test_prefix(seed)],
            1_000,
            TimestampRange::new(
                WeightedTimestamp::from_millis(opens_ms),
                WeightedTimestamp::from_millis(opens_ms + 100_000),
            ),
        ))
    }

    /// A chain born at network genesis anchors at zero, so nothing can
    /// open before it and nothing is ever asked.
    #[test]
    fn a_genesis_chain_asks_nothing() {
        let (state, _) = make_test_state();
        assert!(!state.precut_rule_live());
        assert!(
            state
                .outstanding_precut_queries([TxHash::from(Hash::from_bytes(b"probe"))])
                .is_empty()
        );
    }

    /// A candidate that opened before the cut is owed an answer by the
    /// predecessor; one that opened after is this chain's own business.
    #[test]
    fn a_successor_asks_its_predecessor_about_pre_cut_candidates() {
        let state = make_successor(
            WeightedTimestamp::from_millis(10_000),
            WeightedTimestamp::from_millis(10_500),
        );
        let predecessor = state.predecessors()[0];
        let probe = TxHash::from(Hash::from_bytes(b"probe"));

        assert_eq!(
            state.outstanding_precut_queries([probe]),
            vec![(predecessor, probe)]
        );
    }

    /// A transaction carried by a block awaiting a vote is asked about
    /// even though nothing handed it to the scan. The vote deferred on
    /// it, and nothing else would issue the query that releases it.
    #[test]
    fn a_block_awaiting_a_vote_contributes_its_own_pre_cut_transactions() {
        let mut state = make_successor(
            WeightedTimestamp::from_millis(10_000),
            WeightedTimestamp::from_millis(10_500),
        );
        let predecessor = state.predecessors()[0];
        // One opens before the cut, one after; only the first is the
        // predecessor's business.
        let before = precut_tx(1, 9_000);
        let after = precut_tx(2, 10_500);
        let block = make_live_block(
            ShardId::ROOT,
            BlockHeight::new(11),
            10_600,
            ValidatorId::new(1),
            vec![Arc::clone(&before), Arc::clone(&after)],
            vec![],
        );
        install_complete_block(&mut state, &block);

        assert_eq!(
            state.outstanding_precut_queries(std::iter::empty()),
            vec![(predecessor, before.hash())]
        );
    }

    /// Once the chain's clock has run `MAX_VALIDITY_RANGE` past its
    /// origin the rule retires: nothing still valid can have opened
    /// before the cut, so the queries stop even with candidates on hand.
    #[test]
    fn the_queries_retire_with_the_rule() {
        let cut = WeightedTimestamp::from_millis(10_000);
        let state = make_successor(cut, cut.plus(MAX_VALIDITY_RANGE));
        assert!(!state.precut_rule_live());
        assert!(
            state
                .outstanding_precut_queries([TxHash::from(Hash::from_bytes(b"probe"))])
                .is_empty()
        );
    }

    /// An answered pair drops out; its sibling stays owed.
    #[test]
    fn an_answered_pair_is_no_longer_outstanding() {
        let mut state = make_successor(
            WeightedTimestamp::from_millis(10_000),
            WeightedTimestamp::from_millis(10_500),
        );
        let predecessor = state.predecessors()[0];
        let answered = TxHash::from(Hash::from_bytes(b"answered"));
        let owed = TxHash::from(Hash::from_bytes(b"owed"));

        state.record_precut_resolution(predecessor.shard, answered, true);
        assert_eq!(
            state.outstanding_precut_queries([answered, owed]),
            vec![(predecessor, owed)]
        );
    }

    /// A schedule in which `ShardId::ROOT` terminated at `10_000ms`, leaving
    /// its two children live and its boundary record carrying the
    /// commitments a successor reads.
    fn post_split_schedule(committed: CommittedTxsRoot) -> TopologySchedule {
        let children: [ShardId; 2] = ShardId::ROOT.children().into();
        let anchor = ShardAnchor {
            state_root: StateRoot::ZERO,
            block_hash: BlockHash::from_raw(Hash::from_bytes(b"root terminal")),
            height: BlockHeight::new(9),
            weighted_timestamp: WeightedTimestamp::from_millis(10_000),
            witness_base: BeaconWitnessLeafCount::ZERO,
            terminal_roots: Some(TerminalRoots {
                settled_txs: SettledTxsRoot::ZERO,
                committed_txs: committed,
            }),
            handoff_complete: None,
        };
        let live = |shards: &[ShardId], boundaries: HashMap<ShardId, ShardAnchor>| {
            Arc::new(TopologySnapshot::from_explicit_committees(
                NetworkDefinition::simulator(),
                &ValidatorSet::new(Vec::new()),
                shards.iter().map(|shard| (*shard, Vec::new())).collect(),
                HashMap::new(),
                boundaries,
                HashMap::new(),
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeSet::new(),
            ))
        };
        let mut boundaries = HashMap::new();
        boundaries.insert(ShardId::ROOT, anchor);
        let head = live(&children, boundaries);
        let mut sched = TopologySchedule::new(
            10_000,
            Epoch::new(0),
            live(&[ShardId::ROOT], HashMap::new()),
        );
        sched.insert(Epoch::new(1), Arc::clone(&head));
        sched.set_head(head);
        sched
    }

    /// A seat the reshape flip never reached — a restart, or a validator
    /// rotated on afterwards — reads its predecessors off the beacon's own
    /// boundary records instead, and the pre-cut relaxation comes alive
    /// with them.
    #[test]
    fn a_seat_that_missed_the_flip_adopts_its_predecessors_from_the_projection() {
        let committed = CommittedTxsRoot::from_raw(Hash::from_bytes(b"parent window"));
        let sched = post_split_schedule(committed);
        let (left, _) = ShardId::ROOT.children();
        let mut state = successor_holding(
            WeightedTimestamp::from_millis(10_000),
            WeightedTimestamp::from_millis(10_500),
            Vec::new(),
        );
        state.local_shard = left;

        assert!(
            !state.precut_rule_live(),
            "holding no predecessors, the strict refusal stands",
        );
        assert!(
            state.precut_window_open(),
            "but the window it would relax is still open",
        );

        assert!(state.adopt_precut_predecessors(&sched));
        assert_eq!(
            state.predecessors(),
            &[PredecessorTerminal {
                shard: ShardId::ROOT,
                height: BlockHeight::new(9),
                block_hash: BlockHash::from_raw(Hash::from_bytes(b"root terminal")),
                committed_txs_root: committed,
            }],
        );
        assert!(state.precut_rule_live());
    }

    /// Adoption never displaces what the flip delivered: the flip is the
    /// authority for the seats it reached, and re-reading the projection
    /// over it would churn the answers already recorded against it.
    #[test]
    fn adoption_leaves_flip_delivered_predecessors_alone() {
        let sched = post_split_schedule(CommittedTxsRoot::from_raw(Hash::from_bytes(b"other")));
        let (left, _) = ShardId::ROOT.children();
        let mut state = make_successor(
            WeightedTimestamp::from_millis(10_000),
            WeightedTimestamp::from_millis(10_500),
        );
        state.local_shard = left;
        let delivered = state.predecessors().to_vec();

        assert!(!state.adopt_precut_predecessors(&sched));
        assert_eq!(state.predecessors(), delivered.as_slice());
    }

    /// Past the window there is nothing left to relax, so a late boot
    /// adopts nothing rather than taking on state it will only retire.
    #[test]
    fn adoption_stops_once_the_window_has_closed() {
        let sched = post_split_schedule(CommittedTxsRoot::ZERO);
        let (left, _) = ShardId::ROOT.children();
        let cut = WeightedTimestamp::from_millis(10_000);
        let mut state = successor_holding(cut, cut.plus(MAX_VALIDITY_RANGE), Vec::new());
        state.local_shard = left;

        assert!(!state.precut_window_open());
        assert!(!state.adopt_precut_predecessors(&sched));
        assert!(state.predecessors().is_empty());
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
                public_key: BlsSigner::generate().public_key(),
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
        block_chained_on(
            height,
            BlockHash::from_raw(Hash::from_bytes(b"anchor_parent")),
            parent_weighted_ms,
        )
    }

    /// As [`block_with_parent_qc_ts`], but extending `parent_hash` — so a
    /// caller can install a real two-block chain and exercise the committee
    /// anchor's hop to the parent.
    fn block_chained_on(
        height: BlockHeight,
        parent_hash: BlockHash,
        parent_weighted_ms: u64,
    ) -> Block {
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        let parent_qc = QuorumCertificate::new(
            parent_hash,
            ShardId::ROOT,
            BlockHeight::new(height.inner() - 1),
            BlockHash::ZERO,
            Round::new(0),
            signers,
            AggregateSignature::ZERO,
            WeightedTimestamp::from_millis(parent_weighted_ms),
        );
        let header = BlockHeader::new(BlockHeaderParts {
            height,
            parent_block_hash: parent_qc.block_hash(),
            parent_qc: parent_qc.into(),
            timestamp: ProposerTimestamp::from_millis(parent_weighted_ms),
            round: Round::new(height.inner()),
            state_root: StateRoot::from_raw(Hash::from_bytes(
                &[u8::try_from(height.inner() % 251).unwrap(); 32],
            )),
            ..Default::default()
        });
        Block::Live {
            header,
            transactions: Arc::new(Vec::new()),
            certificates: Arc::new(Vec::new()),
            provisions: Arc::new(Vec::new()),
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
        }
    }

    #[test]
    fn the_proposer_does_not_move_with_the_aggregate_across_a_cut() {
        // A QC's weighted timestamp is the mean of whichever votes the
        // aggregator held when quorum landed, so replicas hold different
        // values for one block — by the spread of the voters' clocks, a few
        // milliseconds on a healthy shard. Either side of an epoch cut that
        // spread once resolved two committees and elected two leaders, and
        // the round's votes split between proposals that both verified, each
        // carrying the QC that justified its own proposer.
        //
        // The committee for the height in progress anchors on the tip block,
        // which every replica reads identically, so the aggregate's timestamp
        // does not reach committee resolution at all. Two replicas holding
        // QCs a millisecond either side of the cut elect one proposer.
        const ED: u64 = 1_000;
        let shard = ShardId::ROOT;

        let epoch0 = Arc::new(committee_snapshot_with_ids(&[0, 1, 2, 3]));
        // A rotation that moves the seat: where both epochs elect the same
        // validator the split is invisible, which is the second condition the
        // stall needs and why most runs cross a cut without one.
        let epoch1 = Arc::new(committee_snapshot_with_ids(&[10, 11, 12, 13]));
        let mut schedule = TopologySchedule::new(ED, Epoch::new(0), Arc::clone(&epoch0));
        schedule.insert(Epoch::new(1), Arc::clone(&epoch1));

        let mut state = ShardCoordinator::new(
            Arc::new(BlsVerifier),
            ValidatorId::new(0),
            shard,
            ShardConsensusConfig::default(),
            RecoveredState::default(),
        );

        // The tip: one block, anchored below the cut, that both replicas hold.
        let tip = block_with_parent_qc_ts(BlockHeight::new(5), ED - 1);
        let tip_hash = tip.hash();
        install_complete_block(&mut state, &tip);

        // Two aggregates over that one block, straddling the cut by 1 ms.
        let proposer_for = |state: &mut ShardCoordinator, weighted_ms: u64| {
            state.latest_qc = Some(Verified::<QuorumCertificate>::new_unchecked_for_test(
                QuorumCertificate::new(
                    tip_hash,
                    shard,
                    BlockHeight::new(5),
                    BlockHash::ZERO,
                    Round::new(5),
                    SignerBitfield::empty(),
                    AggregateSignature::ZERO,
                    WeightedTimestamp::from_millis(weighted_ms),
                ),
            ));
            state
                .tip_committee(&schedule)
                .expect("the tip's committee is in the schedule")
                .proposer_for(shard, Round::new(6))
        };

        let below = proposer_for(&mut state, ED - 1);
        let above = proposer_for(&mut state, ED + 1);

        assert_eq!(
            below,
            above,
            "aggregates {} ms and {} ms across the cut at {ED} ms elected {below:?} and \
             {above:?} — the round draws two proposals and its votes split between them",
            ED - 1,
            ED + 1,
        );
    }

    #[test]
    fn a_committee_still_resolves_once_the_parent_has_committed() {
        // A block's committee anchors on its parent, and a parent does not
        // stay in `pending_blocks` — it is pruned as the chain commits past
        // it. Only the committed tip keeps a scalar, so the block *below* the
        // tip has neither: its header is gone and it is not `committed_hash`.
        //
        // Every steady-state vote crosses this. Verifying the parent QC on a
        // block `h` resolves `committee(h-1)`, which anchors on `h-2` — and by
        // the time `h` arrives, `h-2` is exactly one commit below the tip.
        const ED: u64 = 1_000;
        let shard = ShardId::ROOT;

        let epoch0 = Arc::new(committee_snapshot_with_ids(&[0, 1, 2, 3]));
        let schedule = TopologySchedule::new(ED, Epoch::new(0), Arc::clone(&epoch0));

        let mut state = ShardCoordinator::new(
            Arc::new(BlsVerifier),
            ValidatorId::new(0),
            shard,
            ShardConsensusConfig::default(),
            RecoveredState::default(),
        );

        // A three-block run: `grandparent` has committed and been pruned,
        // `parent` is the committed tip, `child` is arriving now.
        let grandparent = block_with_parent_qc_ts(BlockHeight::new(5), 100);
        let parent = block_chained_on(BlockHeight::new(6), grandparent.hash(), 200);
        let child = block_chained_on(BlockHeight::new(7), parent.hash(), 300);

        // Only the live blocks are held; the grandparent is pruned.
        install_complete_block(&mut state, &parent);
        install_complete_block(&mut state, &child);
        state.committed_hash = parent.hash();
        state.committed_block_anchor_wt = WeightedTimestamp::from_millis(200);
        state.committed_committee_anchor_wt = WeightedTimestamp::from_millis(100);

        assert!(
            state.committee_of_block(&schedule, child.hash()).is_some(),
            "the arriving block's committee anchors on the committed tip, which keeps a scalar",
        );
        assert!(
            state.committee_of_block(&schedule, parent.hash()).is_some(),
            "the committed tip's own committee anchors on a block already pruned — without a \
             second scalar it is unresolvable, and the parent-QC verification every vote runs \
             defers forever",
        );
    }

    #[test]
    fn committee_of_block_keys_on_the_parents_anchor() {
        // committee(block) == at(block_anchor(parent)). A block's committee
        // has to be resolvable before the block exists — otherwise no replica
        // can know who leads a height until someone has already proposed at
        // it — so it keys on the parent's anchor, which every replica reads
        // off a header it already holds. The block's own anchor comes from a
        // QC whose weighted timestamp varies by aggregator, and keying on
        // that is what once split a round across an epoch cut.
        const ED: u64 = 1_000;
        let shard = ShardId::ROOT;

        let epoch0 = Arc::new(committee_snapshot_with_ids(&[0, 1, 2, 3]));
        let epoch1 = Arc::new(committee_snapshot_with_ids(&[10, 11, 12, 13]));
        let mut schedule = TopologySchedule::new(ED, Epoch::new(0), Arc::clone(&epoch0));
        schedule.insert(Epoch::new(1), Arc::clone(&epoch1));

        let mut state = ShardCoordinator::new(
            Arc::new(BlsVerifier),
            ValidatorId::new(0),
            shard,
            ShardConsensusConfig::default(),
            RecoveredState::default(),
        );

        // Parent sits below the cut, so its anchor is epoch 0.
        let parent = block_with_parent_qc_ts(BlockHeight::new(5), ED - 1);
        let parent_hash = parent.hash();
        install_complete_block(&mut state, &parent);

        // The child's own anchor is past the cut — epoch 1 — but its
        // committee follows the parent's.
        let child = block_chained_on(BlockHeight::new(6), parent_hash, ED + 1);
        let child_hash = child.hash();
        install_complete_block(&mut state, &child);

        assert_eq!(
            state.block_anchor(child_hash),
            Some(WeightedTimestamp::from_millis(ED + 1)),
            "the child dates itself past the cut",
        );

        let child_committee = state
            .committee_of_block(&schedule, child_hash)
            .expect("epoch 0 committee is in the schedule");
        assert_eq!(
            child_committee.committee_for_shard(shard),
            epoch0.committee_for_shard(shard),
            "a block whose parent anchors below N·ED is governed by committee_(N-1), \
             however its own anchor falls",
        );

        // A grandchild of the epoch-1 block inherits that epoch in turn.
        let grandchild = block_chained_on(BlockHeight::new(7), child_hash, ED + 2);
        let grandchild_hash = grandchild.hash();
        install_complete_block(&mut state, &grandchild);
        let grandchild_committee = state
            .committee_of_block(&schedule, grandchild_hash)
            .expect("epoch 1 committee is in the schedule");
        assert_eq!(
            grandchild_committee.committee_for_shard(shard),
            epoch1.committee_for_shard(shard),
            "the epoch advances one block after the anchor crosses N·ED",
        );
    }

    #[test]
    fn a_synced_blocks_qc_verifies_under_the_committee_its_parent_anchors() {
        // Sync dispatches QC verification against `committee(h)`, which
        // anchors on `h-1` — the same rule the live vote path and every
        // remote consumer apply. Resolving on the block's own anchor picks
        // the window the block *opens*, so across a cut that rotates keys the
        // aggregate check fails and sync wedges at that height instead of
        // crossing the boundary.
        //
        // The parent here is still awaiting its own QC verification, which is
        // the normal case: the drain hands consecutive heights to
        // verification in parallel, so a block reaches this path long before
        // its parent has been applied.
        const ED: u64 = 1_000;
        let shard = ShardId::ROOT;

        let epoch0 = Arc::new(committee_snapshot_with_ids(&[0, 1, 2, 3]));
        let epoch1 = Arc::new(committee_snapshot_with_ids(&[10, 11, 12, 13]));
        let mut schedule = TopologySchedule::new(ED, Epoch::new(0), Arc::clone(&epoch0));
        schedule.insert(Epoch::new(1), Arc::clone(&epoch1));

        let mut state = ShardCoordinator::new(
            Arc::new(BlsVerifier),
            ValidatorId::new(0),
            shard,
            ShardConsensusConfig::default(),
            RecoveredState::default(),
        );

        let certify = |block: &Block, weighted_ms: u64| {
            let mut signers = SignerBitfield::new(4);
            for i in 0..3 {
                signers.set(i);
            }
            CertifiedBlock::new_unchecked(
                block.clone(),
                QuorumCertificate::new(
                    block.hash(),
                    shard,
                    block.height(),
                    block.header().parent_block_hash(),
                    block.header().round(),
                    signers,
                    AggregateSignature::ZERO,
                    WeightedTimestamp::from_millis(weighted_ms),
                ),
            )
        };

        // Parent anchors below the cut, child above it.
        let parent = block_with_parent_qc_ts(BlockHeight::new(5), ED - 1);
        let child = block_chained_on(BlockHeight::new(6), parent.hash(), ED + 1);

        let parent_actions =
            state.submit_synced_block_for_verification(&schedule, certify(&parent, ED - 1));
        assert!(
            parent_actions
                .iter()
                .any(|a| matches!(a, Action::VerifyQcSignature { .. })),
            "the parent dispatches first and stays in flight",
        );

        let actions =
            state.submit_synced_block_for_verification(&schedule, certify(&child, ED + 1));
        let keys = actions
            .iter()
            .find_map(|a| match a {
                Action::VerifyQcSignature { public_keys, .. } => Some(public_keys),
                _ => None,
            })
            .expect("the child dispatches QC verification");
        assert_eq!(
            *keys,
            committee_public_keys(&epoch0, shard),
            "the child's QC must verify under the window its parent anchors, not the one it \
             dates itself into",
        );
    }

    #[test]
    fn a_restarted_replica_resolves_its_tips_own_committee() {
        // Storage recovers two anchors because the tip's committee keys on the
        // header below it, and that header survives nowhere else: it is pruned
        // from `pending_blocks` and it is not `committed_hash`. Seeding both
        // from the tip's own anchor would resolve the tip against the window it
        // opens rather than the one that signed it — one epoch late whenever
        // the tip is an epoch's first block, which is exactly when the parent
        // QC over the tip fails to verify and the restart costs a vote.
        const ED: u64 = 1_000;
        let shard = ShardId::ROOT;

        let epoch0 = Arc::new(committee_snapshot_with_ids(&[0, 1, 2, 3]));
        let epoch1 = Arc::new(committee_snapshot_with_ids(&[10, 11, 12, 13]));
        let mut schedule = TopologySchedule::new(ED, Epoch::new(0), Arc::clone(&epoch0));
        schedule.insert(Epoch::new(1), Arc::clone(&epoch1));

        // A tip that is an epoch's first block: its own anchor sits at the cut,
        // the one its parent carried just below.
        let tip = BlockHash::from_raw(Hash::from_bytes(b"restarted_tip"));
        let state = ShardCoordinator::new(
            Arc::new(BlsVerifier),
            ValidatorId::new(0),
            shard,
            ShardConsensusConfig::default(),
            RecoveredState {
                committed_height: BlockHeight::new(9),
                committed_hash: Some(tip),
                committed_block_anchor_wt: Some(WeightedTimestamp::from_millis(ED)),
                committed_committee_anchor_wt: Some(WeightedTimestamp::from_millis(ED - 1)),
                ..RecoveredState::default()
            },
        );

        assert_eq!(
            state
                .committee_of_block(&schedule, tip)
                .expect("the tip's committee is in the schedule")
                .committee_for_shard(shard),
            epoch0.committee_for_shard(shard),
            "the tip was signed by the committee its parent anchors",
        );
        assert_eq!(
            state
                .committee_for_child_of(&schedule, tip)
                .expect("the extending block's committee is in the schedule")
                .committee_for_shard(shard),
            epoch1.committee_for_shard(shard),
            "the block extending the tip is governed by the window the tip opens",
        );
    }

    #[test]
    fn the_reveal_chain_reseeds_when_the_committee_epoch_changes() {
        // The chain reseeds when a block and its parent sit in different
        // epochs — and a block sits in the epoch its committee is drawn from,
        // which anchors on its parent. A block whose *own* anchor crosses a
        // cut is still governed by the window its parent anchors in, so it
        // extends the parent's chain rather than reseeding: reseeding on the
        // block's own anchor would label a chain with an epoch no committee
        // that signed it belongs to, and split one committee's reveals across
        // two chains.
        //
        // The same committee sits in both windows, so what this pins is the
        // epoch label, not committee identity.
        const ED: u64 = 1_000;
        let shard = ShardId::ROOT;
        let committee = Arc::new(committee_snapshot_with_ids(&[0, 1, 2, 3]));
        let mut schedule = TopologySchedule::new(ED, Epoch::new(1), Arc::clone(&committee));
        schedule.insert(Epoch::new(0), Arc::clone(&committee));

        let mut state = ShardCoordinator::new(
            Arc::new(BlsVerifier),
            ValidatorId::new(0),
            shard,
            ShardConsensusConfig::default(),
            RecoveredState::default(),
        );

        // The committed tip anchors in epoch 0; so does `parent`. `child`
        // dates itself past the cut, but its committee still anchors on
        // `parent`, below it.
        let parent = block_with_parent_qc_ts(BlockHeight::new(5), ED - 1);
        let child = block_chained_on(BlockHeight::new(6), parent.hash(), ED + 1);
        install_complete_block(&mut state, &parent);
        install_complete_block(&mut state, &child);
        state.committed_hash = parent.header().parent_block_hash();
        state.committed_block_anchor_wt = WeightedTimestamp::from_millis(ED - 2);
        state.committed_committee_anchor_wt = WeightedTimestamp::from_millis(ED - 2);

        let actions = state.dispatch_or_park_beacon_witness(&schedule, child.hash());
        let Some(Action::VerifyBeaconWitnessRoot {
            committee_anchor_epoch,
            parent_committee_anchor_epoch,
            ..
        }) = actions
            .iter()
            .find(|a| matches!(a, Action::VerifyBeaconWitnessRoot { .. }))
        else {
            panic!("the block's witness root dispatches: {actions:?}");
        };

        assert_eq!(
            (*committee_anchor_epoch, *parent_committee_anchor_epoch),
            (Epoch::new(0), Epoch::new(0)),
            "the child dates itself in epoch 1 but is governed by epoch 0, so it extends the \
             parent's reveal chain instead of reseeding",
        );
    }

    /// A wire vote for `block`, signed by committee member `voter`.
    fn wire_vote_for(keys: &[BlsSigner], voter: usize, block: &Block) -> BlockVote {
        BlockVote::new(
            &NetworkDefinition::simulator(),
            block.hash(),
            block.header().parent_block_hash(),
            ShardId::ROOT,
            block.height(),
            block.header().round(),
            ValidatorId::new(voter as u64),
            &keys[voter],
            ProposerTimestamp::ZERO,
        )
        .expect("vote signs")
    }

    #[test]
    fn a_header_ahead_of_its_parent_keeps_its_buffered_votes() {
        // A block's committee anchors on its parent, so a header can land
        // while the committee its votes tally against is still unresolvable —
        // `reject_invalid_header` admits such a header, deferring its own
        // proposer check on the same condition. The link attempt that header
        // triggers must leave the buffer intact: the parent's arrival is what
        // admits these votes, and nothing re-fetches a vote already gossiped.
        let (mut state, schedule, keys) = make_multi_validator_state_with_keys(0);
        let parent = block_with_parent_qc_ts(BlockHeight::new(5), 100);
        let child = block_chained_on(BlockHeight::new(6), parent.hash(), 200);
        let child_hash = child.hash();

        assert!(
            state
                .votes
                .buffer_unanchored_vote(wire_vote_for(&keys, 1, &child))
        );

        // The header lands while its parent is still missing.
        install_complete_block(&mut state, &child);
        assert!(
            state.committee_of_block(&schedule, child_hash).is_none(),
            "the parent is unheld, so the child's committee anchor is unresolvable",
        );

        assert!(
            state
                .link_buffered_votes_to_header(&schedule, child_hash, child.header())
                .is_empty(),
            "no committee, no admission",
        );
        assert_eq!(
            state.votes.take_unanchored_votes(child_hash).len(),
            1,
            "the vote must outlive a link attempt that couldn't resolve the committee",
        );
    }

    #[test]
    fn the_parent_landing_admits_votes_held_for_an_unassembled_child() {
        // A QC builds off the header alone — height, round and parent anchor
        // all come from it — so a child whose body hasn't arrived still tallies
        // votes. The parent's arrival is the only event that resolves such a
        // child's committee, and it is also the last one: no later step
        // revisits the buffer.
        let (mut state, schedule, keys) = make_multi_validator_state_with_keys(0);
        let grandparent = block_with_parent_qc_ts(BlockHeight::new(4), 100);
        let parent = block_chained_on(BlockHeight::new(5), grandparent.hash(), 200);
        let child = block_chained_on(BlockHeight::new(6), parent.hash(), 300);
        let child_hash = child.hash();

        // The grandparent has committed, so the parent's own anchor resolves
        // once it lands.
        state.committed_hash = grandparent.hash();
        state.committed_block_anchor_wt = WeightedTimestamp::from_millis(100);

        // The child holds a header naming a transaction we don't have, so its
        // block never assembles.
        state.pending_blocks.assemble(
            child.header().clone(),
            BlockManifest::new(
                vec![TxHash::from(Hash::from_bytes(b"absent-tx"))],
                vec![],
                vec![],
                vec![],
                vec![],
                WitnessSources::empty(),
            ),
            LocalTimestamp::ZERO,
            |_| None,
            |_| None,
            |_| None,
        );
        assert!(state.pending_blocks.get_block(child_hash).is_none());

        assert!(
            state
                .votes
                .buffer_unanchored_vote(wire_vote_for(&keys, 1, &child))
        );

        install_complete_block(&mut state, &parent);
        state.retry_pending_children(&schedule, parent.hash());

        assert!(
            state.votes.take_unanchored_votes(child_hash).is_empty(),
            "the parent resolved the child's committee, so the vote is admitted",
        );
        assert_eq!(
            state.votes.vote_sets_len(),
            1,
            "the admitted vote tallies against the child's exact committee",
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
        // The parent's committee anchors on *its* parent, so seat that as the
        // committed tip — otherwise the parent QC's committee is unresolvable
        // and the vote path defers before reaching the floor check.
        state.committed_hash = parent.header().parent_block_hash();
        state.committed_block_anchor_wt = WeightedTimestamp::from_millis(5_000);

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
                AggregateSignature::ZERO,
                WeightedTimestamp::from_millis(weighted_ms),
            );
            let header = BlockHeader::new(BlockHeaderParts {
                height: BlockHeight::new(6),
                parent_block_hash: parent_hash,
                parent_qc: parent_qc.into(),
                proposer: ValidatorId::new(2),
                timestamp: ProposerTimestamp::from_millis(weighted_ms),
                round: Round::new(6),
                state_root: StateRoot::from_raw(Hash::from_bytes(tag)),
                ..Default::default()
            });
            Block::Live {
                header,
                transactions: Arc::new(Vec::new()),
                certificates: Arc::new(Vec::new()),
                provisions: Arc::new(Vec::new()),
                abandonment_records: Arc::new(Vec::new()),
                state_claims: Arc::new(Vec::new()),
                witness_sources: Arc::new(WitnessSources::empty()),
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
        BlockHeader::new(BlockHeaderParts {
            height,
            parent_block_hash: BlockHash::from_raw(Hash::from_bytes(b"parent")),
            parent_qc: QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT).into(),
            proposer: ValidatorId::new(height.inner() % 4),
            timestamp: ProposerTimestamp::from_millis(timestamp_ms),
            round,
            ..Default::default()
        })
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
            AggregateSignature::ZERO,
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
            BlockHeader::new(BlockHeaderParts {
                shard_id: __h.shard_id(),
                height: __h.height(),
                parent_block_hash,
                parent_qc: parent_qc.into(),
                proposer: __h.proposer(),
                timestamp: __h.timestamp(),
                round: __h.round(),
                is_fallback: __h.is_fallback(),
                state_root: __h.state_root(),
                transaction_root: __h.transaction_root(),
                certificate_root: __h.certificate_root(),
                local_receipt_root: __h.local_receipt_root(),
                provision_root: __h.provision_root(),
                provision_tx_roots: __h.provision_tx_roots().clone(),
                work_in_flight: __h.work_in_flight(),
                ..Default::default()
            })
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
            AggregateSignature::ZERO,
            WeightedTimestamp::from_millis(50_000),
        );
        let header = BlockHeader::new(BlockHeaderParts {
            height: BlockHeight::new(10),
            parent_block_hash,
            parent_qc: parent_qc.into(),
            proposer: ValidatorId::new(2),
            timestamp: ProposerTimestamp::from_millis(50_000),
            round: Round::new(10),
            ..Default::default()
        });

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
        let header = BlockHeader::new(BlockHeaderParts {
            height: BlockHeight::new(1),
            parent_block_hash: committed_hash,
            parent_qc: QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT).into(),
            proposer: ValidatorId::new(round % 4),
            timestamp: ProposerTimestamp::from_millis(100_000),
            round: Round::new(round),
            state_root: StateRoot::from_raw(Hash::from_bytes(
                &[u8::try_from(round % 251).unwrap(); 32],
            )),
            ..Default::default()
        });
        Block::Live {
            header,
            transactions: Arc::new(Vec::new()),
            certificates: Arc::new(Vec::new()),
            provisions: Arc::new(Vec::new()),
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
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
            let header = BlockHeader::new(BlockHeaderParts {
                height: BlockHeight::new(1),
                parent_block_hash: committed_hash,
                parent_qc: QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT).into(),
                proposer: ValidatorId::new(1),
                timestamp: ProposerTimestamp::from_millis(100_000),
                round: Round::new(1),
                state_root: StateRoot::from_raw(Hash::from_bytes(&[u8::try_from(i).unwrap(); 32])),
                ..Default::default()
            });
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
            BlockHeader::new(BlockHeaderParts {
                height: BlockHeight::new(1),
                parent_block_hash: committed_hash,
                parent_qc: QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT).into(),
                proposer: ValidatorId::new(round % 4),
                timestamp: ProposerTimestamp::from_millis(100_000),
                round: Round::new(round),
                ..Default::default()
            })
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
                AggregateSignature::ZERO,
                WeightedTimestamp::from_millis(now_ms - 5_000),
            );
            BlockHeader::new(BlockHeaderParts {
                height: BlockHeight::new(height),
                parent_block_hash,
                parent_qc: parent_qc.into(),
                proposer: ValidatorId::new(round % 4),
                timestamp: ProposerTimestamp::from_millis(now_ms),
                round: Round::new(round),
                ..Default::default()
            })
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
    /// parent QC's signature has been verified — otherwise a Byzantine
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
            BlockHeader::new(BlockHeaderParts {
                shard_id: __h.shard_id(),
                height: __h.height(),
                parent_block_hash,
                parent_qc: parent_qc.into(),
                proposer: __h.proposer(),
                timestamp: __h.timestamp(),
                round: __h.round(),
                is_fallback: __h.is_fallback(),
                state_root: __h.state_root(),
                transaction_root: __h.transaction_root(),
                certificate_root: __h.certificate_root(),
                local_receipt_root: __h.local_receipt_root(),
                provision_root: __h.provision_root(),
                provision_tx_roots: __h.provision_tx_roots().clone(),
                work_in_flight: __h.work_in_flight(),
                ..Default::default()
            })
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
        // on signature verification, which hasn't happened yet.
        assert_eq!(
            state.latest_qc.as_deref().map(QuorumCertificate::height),
            prior_latest_qc.as_deref().map(QuorumCertificate::height),
            "unverified parent_qc must not advance latest_qc"
        );
    }

    /// After successful signature verification, the deferred `latest_qc`
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
            BlockHeader::new(BlockHeaderParts {
                shard_id: __h.shard_id(),
                height: __h.height(),
                parent_block_hash,
                parent_qc: parent_qc.into(),
                proposer: __h.proposer(),
                timestamp: __h.timestamp(),
                round: __h.round(),
                is_fallback: __h.is_fallback(),
                state_root: __h.state_root(),
                transaction_root: __h.transaction_root(),
                certificate_root: __h.certificate_root(),
                local_receipt_root: __h.local_receipt_root(),
                provision_root: __h.provision_root(),
                provision_tx_roots: __h.provision_tx_roots().clone(),
                work_in_flight: __h.work_in_flight(),
                ..Default::default()
            })
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
            transactions: Arc::new(Vec::new()),
            certificates: Arc::new(Vec::new()),
            provisions: Arc::new(Vec::new()),
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
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
            BlockHeader::new(BlockHeaderParts {
                shard_id: __h.shard_id(),
                height: __h.height(),
                parent_block_hash,
                parent_qc: parent_qc.into(),
                proposer: __h.proposer(),
                timestamp: __h.timestamp(),
                round: __h.round(),
                is_fallback: __h.is_fallback(),
                state_root: __h.state_root(),
                transaction_root: __h.transaction_root(),
                certificate_root: __h.certificate_root(),
                local_receipt_root: __h.local_receipt_root(),
                provision_root: __h.provision_root(),
                provision_tx_roots: __h.provision_tx_roots().clone(),
                work_in_flight: __h.work_in_flight(),
                ..Default::default()
            })
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
        let after_state = state.on_block_check_completed(
            &topology_schedule,
            block_hash,
            VerificationKind::StateRoot,
            CheckOutcome::Checked { bytes_delta: 0 },
        );
        assert!(
            !after_state
                .iter()
                .any(|a| matches!(a, Action::SignAndBroadcastBlockVote { .. }))
        );

        // Beacon witness root completes — now we vote.
        let after_roots = state.on_block_check_completed(
            &topology_schedule,
            block_hash,
            VerificationKind::BeaconWitnessRoot,
            CheckOutcome::Checked { bytes_delta: 0 },
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
            BlockHeader::new(BlockHeaderParts {
                shard_id: __h.shard_id(),
                height: __h.height(),
                parent_block_hash,
                parent_qc: parent_qc.into(),
                proposer: __h.proposer(),
                timestamp: __h.timestamp(),
                round: __h.round(),
                is_fallback: __h.is_fallback(),
                state_root: __h.state_root(),
                transaction_root: __h.transaction_root(),
                certificate_root: __h.certificate_root(),
                local_receipt_root: __h.local_receipt_root(),
                provision_root: __h.provision_root(),
                provision_tx_roots: __h.provision_tx_roots().clone(),
                work_in_flight: __h.work_in_flight(),
                ..Default::default()
            })
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
            BlockHeader::new(BlockHeaderParts {
                shard_id: __h.shard_id(),
                height: __h.height(),
                parent_block_hash: BlockHash::ZERO,
                parent_qc: __h.parent_qc().clone().into(),
                proposer: __h.proposer(),
                timestamp: __h.timestamp(),
                round: __h.round(),
                is_fallback: __h.is_fallback(),
                state_root: __h.state_root(),
                transaction_root: __h.transaction_root(),
                certificate_root: __h.certificate_root(),
                local_receipt_root: __h.local_receipt_root(),
                provision_root: __h.provision_root(),
                provision_tx_roots: __h.provision_tx_roots().clone(),
                work_in_flight: __h.work_in_flight(),
                ..Default::default()
            })
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
                AggregateSignature::ZERO,
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
                &BlsSigner::generate(),
            )
            .expect("sign")
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
            &BlsSigner::generate(),
        )
        .expect("sign");

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
                )
                .expect("sign");
                (idx, vote)
            })
            .collect();
        let missed_qc = Verified::<QuorumCertificate>::from_verified_votes(
            &BlsVerifier,
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
        )
        .expect("sign");

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
        // Wire timeouts are screened on the shard loop thread, then their
        // signature share is verified off-thread via `Action::VerifyTimeout`. Outsiders,
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
                &BlsSigner::generate(),
            )
            .expect("sign")
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
                &BlsSigner::generate(),
            )
            .expect("sign"),
            VoteCount::new(1),
        );
        assert!(
            state
                .on_unverified_timeout(&topology_schedule, &mk(2, round))
                .is_empty()
        );
    }

    /// A retained ex-member's timeout is harvested on a halted shard —
    /// its carried QC names the tip the fresh committee must extend — but
    /// refused on a forked one: a forked retained committee has no unique
    /// tip, so the incomer seeds from the attested frontier alone.
    #[test]
    fn retained_tip_harvest_is_refused_for_a_fork_recovery() {
        use hyperscale_types::{RecoveryCause, ShardRecovery};

        let harvest = |cause: RecoveryCause| {
            let (mut state, schedule) = make_test_state();
            let head = schedule.head().as_ref().clone().with_pending_recoveries(
                std::iter::once((
                    ShardId::ROOT,
                    ShardRecovery {
                        cause,
                        rotated_at: Epoch::new(2),
                        retained: vec![ValidatorId::new(9)],
                        attested_frontier: BlockHeight::GENESIS,
                    },
                ))
                .collect(),
            );
            let schedule = TopologySchedule::single(Arc::new(head));
            let carried = QuorumCertificate::new(
                BlockHash::from_raw(Hash::from_bytes(b"retained-tip")),
                ShardId::ROOT,
                BlockHeight::new(5),
                BlockHash::from_raw(Hash::from_bytes(b"retained-parent")),
                Round::new(1),
                SignerBitfield::new(4),
                AggregateSignature::ZERO,
                WeightedTimestamp::ZERO,
            );
            let timeout = Timeout::new(
                &NetworkDefinition::simulator(),
                ShardId::ROOT,
                Round::new(2),
                carried,
                ValidatorId::new(9),
                &BlsSigner::generate(),
            )
            .expect("sign");
            state.on_unverified_timeout(&schedule, &timeout)
        };

        assert!(
            harvest(RecoveryCause::Halt)
                .iter()
                .any(|a| matches!(a, Action::StartBlockSync { .. })),
            "a halt recovery harvests the retained tip into a sync",
        );
        assert!(
            harvest(RecoveryCause::Fork).is_empty(),
            "a fork recovery must refuse the retained suffix",
        );
    }

    /// A sync-delivered certified block above the fork recovery's attested
    /// frontier — anchored and certified below the recovery bridge — is
    /// rejected at admission: the forked retained committee's suffix may
    /// be either branch. The same block admits for QC verification under a
    /// halt recovery, whose retained suffix is unique.
    #[test]
    fn sync_admission_rejects_the_retained_suffix_above_the_fork_frontier() {
        use hyperscale_types::test_utils::make_live_block;
        use hyperscale_types::{CertifiedBlock, RecoveryCause, ShardRecovery};

        let admit = |cause: RecoveryCause| {
            let (mut state, schedule) = make_test_state();
            let head = schedule.head().as_ref().clone().with_pending_recoveries(
                std::iter::once((
                    ShardId::ROOT,
                    ShardRecovery {
                        cause,
                        rotated_at: Epoch::new(2),
                        retained: vec![ValidatorId::new(9)],
                        attested_frontier: BlockHeight::GENESIS,
                    },
                ))
                .collect(),
            );
            let schedule = TopologySchedule::single(Arc::new(head));
            let block = make_live_block(
                ShardId::ROOT,
                BlockHeight::new(5),
                1_000,
                ValidatorId::new(1),
                vec![],
                vec![],
            );
            let mut signers = SignerBitfield::new(4);
            for i in 0..3 {
                signers.set(i);
            }
            let qc = QuorumCertificate::new(
                block.hash(),
                ShardId::ROOT,
                block.height(),
                block.header().parent_block_hash(),
                Round::new(5),
                signers,
                AggregateSignature::ZERO,
                WeightedTimestamp::ZERO,
            );
            let certified = CertifiedBlock::new_unchecked(block, qc);
            state.submit_synced_block_for_verification(&schedule, certified)
        };

        assert!(
            admit(RecoveryCause::Halt)
                .iter()
                .any(|a| matches!(a, Action::VerifyQcSignature { .. })),
            "a halt recovery admits the retained suffix for QC verification",
        );
        assert!(
            admit(RecoveryCause::Fork).is_empty(),
            "a fork recovery must reject the retained suffix at admission",
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
    ) -> (ShardCoordinator, TopologySchedule, Vec<BlsSigner>) {
        let keys: Vec<BlsSigner> = (0..4).map(|_| BlsSigner::generate()).collect();
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
            Arc::new(BlsVerifier),
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
        let (mut state, _topology_schedule) = make_multi_validator_state();
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
            ConsensusSignature::ZERO,
            ProposerTimestamp::from_millis(100_000),
        );

        let _ = state.on_qc_result(
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
                Some(topology_schedule.head()),
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
            BlockHeader::new(BlockHeaderParts {
                shard_id: __h.shard_id(),
                height: __h.height(),
                parent_block_hash: __h.parent_block_hash(),
                parent_qc: __h.parent_qc().clone().into(),
                proposer: ValidatorId::new(3),
                timestamp: __h.timestamp(),
                round: __h.round(),
                is_fallback: __h.is_fallback(),
                state_root: __h.state_root(),
                transaction_root: __h.transaction_root(),
                certificate_root: __h.certificate_root(),
                local_receipt_root: __h.local_receipt_root(),
                provision_root: __h.provision_root(),
                provision_tx_roots: __h.provision_tx_roots().clone(),
                work_in_flight: __h.work_in_flight(),
                ..Default::default()
            })
        };

        let result = validate_header(
            Some(topology_schedule.head()),
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

        let actions = state.on_qc_formed(
            &topology_schedule,
            block_3_hash,
            &qc,
            &[],
            vec![],
            vec![],
            vec![],
            vec![],
        );

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
            AggregateSignature::ZERO,
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

        let first = state.try_propose(&topology_schedule, &[], vec![], vec![], vec![], vec![]);
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

        let second = state.try_propose(&topology_schedule, &[], vec![], vec![], vec![], vec![]);
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

        let third = state.try_propose(&topology_schedule, &[], vec![], vec![], vec![], vec![]);
        assert!(
            third.iter().any(
                |a| matches!(a, Action::BuildProposal { height, .. } if *height == BlockHeight::new(4))
            ),
            "third try_propose should dispatch the BuildProposal"
        );
    }

    /// A proposal whose reshape substate walk cannot resolve must park and
    /// resume the moment the walk's inputs land — here a byte frontier
    /// lagging the committed tip, reconciled from storage on persistence.
    /// Nothing else re-drives it: the parked height is the one whose QC
    /// would advance the chain, so no commit, QC, or admission follows to
    /// latch a retry, and the round would otherwise burn its full
    /// view-change timeout on a fallback.
    #[test]
    fn substate_walk_park_resumes_the_proposal_when_the_frontier_reconciles() {
        let (mut state, _) = make_test_state();
        // The walk is inert with reshaping disabled, so arm the thresholds.
        let snapshot = TopologySchedule::single(Arc::new(
            make_test_state()
                .1
                .head()
                .as_ref()
                .clone()
                .with_params(NetworkParams {
                    reshape_thresholds: ReshapeThresholds { split_bytes: 0 },
                    ..NetworkParams::default()
                }),
        ));
        state.set_time(LocalTimestamp::from_millis(100_000));

        // Rounds increase per block, so (h=4, r=4) puts ValidatorId(0) — the
        // local validator — in the proposer slot.
        let parent_block_hash = BlockHash::from_raw(Hash::from_bytes(b"lagging_frontier"));
        state.committed_height = BlockHeight::new(3);
        state.committed_hash = parent_block_hash;
        state.latest_qc = Some(make_test_qc(parent_block_hash, BlockHeight::new(3)));
        state.view_change.view = Round::new(4);
        // The frontier still sits at genesis while the chain committed to 3 —
        // the sync-commit shape, whose commits carry no byte delta.
        assert_ne!(state.substate_bytes_frontier.0, state.committed_height);

        let first = state.try_propose(&snapshot, &[], vec![], vec![], vec![], vec![]);
        assert!(
            first
                .iter()
                .all(|a| !matches!(a, Action::BuildProposal { .. })),
            "an unresolvable substate walk must park, not dispatch"
        );
        assert!(
            !state.take_ready_proposal(),
            "parking alone must not latch a retry"
        );

        // Persistence reconciles the frontier from storage.
        let _ = state.on_block_persisted(&snapshot, BlockHeight::new(3), 4_096);
        assert!(
            state.take_ready_proposal(),
            "the reconcile must latch a proposal retry"
        );

        let second = state.try_propose(&snapshot, &[], vec![], vec![], vec![], vec![]);
        assert!(
            second.iter().any(
                |a| matches!(a, Action::BuildProposal { height, .. } if *height == BlockHeight::new(4))
            ),
            "the retry must dispatch the BuildProposal the park was holding"
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
            BlockHeader::new(BlockHeaderParts {
                shard_id: __h.shard_id(),
                height: __h.height(),
                parent_block_hash,
                parent_qc: parent_qc.clone().into(),
                proposer: __h.proposer(),
                timestamp: __h.timestamp(),
                round: __h.round(),
                is_fallback: __h.is_fallback(),
                state_root: __h.state_root(),
                transaction_root: __h.transaction_root(),
                certificate_root: __h.certificate_root(),
                local_receipt_root: __h.local_receipt_root(),
                provision_root: __h.provision_root(),
                provision_tx_roots: __h.provision_tx_roots().clone(),
                work_in_flight: __h.work_in_flight(),
                ..Default::default()
            })
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
            BlockHeader::new(BlockHeaderParts {
                shard_id: __h.shard_id(),
                height: __h.height(),
                parent_block_hash,
                parent_qc: parent_qc.into(),
                proposer: ValidatorId::new(3),
                timestamp: __h.timestamp(),
                round: Round::new(1),
                is_fallback: __h.is_fallback(),
                state_root: __h.state_root(),
                transaction_root: __h.transaction_root(),
                certificate_root: __h.certificate_root(),
                local_receipt_root: __h.local_receipt_root(),
                provision_root: __h.provision_root(),
                provision_tx_roots: __h.provision_tx_roots().clone(),
                work_in_flight: __h.work_in_flight(),
                ..Default::default()
            })
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
            BlockHeader::new(BlockHeaderParts {
                shard_id: __h.shard_id(),
                height: __h.height(),
                parent_block_hash,
                parent_qc: forged_qc.into(),
                proposer: __h.proposer(),
                timestamp: __h.timestamp(),
                round: __h.round(),
                is_fallback: __h.is_fallback(),
                state_root: __h.state_root(),
                transaction_root: __h.transaction_root(),
                certificate_root: __h.certificate_root(),
                local_receipt_root: __h.local_receipt_root(),
                provision_root: __h.provision_root(),
                provision_tx_roots: __h.provision_tx_roots().clone(),
                work_in_flight: __h.work_in_flight(),
                ..Default::default()
            })
        };

        let actions = state.on_block_header(
            &topology_schedule,
            &forged_header,
            BlockManifest::default(),
            |_| None,
            |_| None,
            |_| None,
        );

        // The forged QC must trigger signature verification rather than being
        // accepted as a cache hit.
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::VerifyQcSignature { .. })),
            "forged QC reusing cached block_hash must still trigger signature verification"
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

    fn make_test_tx_with_seed(seed: u8) -> Arc<Verifiable<Transaction>> {
        Arc::new(Verifiable::from(test_utils::test_transaction(seed)))
    }

    fn sort_txs_by_hash(txs: &mut [Arc<Verifiable<Transaction>>]) {
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
        // The QC's block is the committed tip in this fixture; naming it
        // keeps the parent resolvable, as it always is on a live chain.
        state.committed_hash = state.latest_qc.as_ref().unwrap().block_hash();

        // Rounds increase per block: height 4 proposes at round 4
        // (proposer_for(4, 4) = validator 0).
        state.view_change.view = Round::new(4);
        state.set_block_syncing(true);
        assert!(state.is_block_syncing());

        // Ready txs must be dropped — sync blocks are always empty.
        let ready_txs = vec![Arc::new(test_utils::verified_test_transaction(1))];
        let actions = state.try_propose(
            &topology_schedule,
            &ready_txs,
            vec![],
            vec![],
            vec![],
            vec![],
        );

        let proposal = actions
            .iter()
            .find(|a| matches!(a, Action::BuildProposal { .. }))
            .expect("sync block should still produce BuildProposal");
        let Action::BuildProposal {
            is_fallback,
            transactions,
            finalizations,
            ..
        } = proposal
        else {
            unreachable!()
        };
        assert!(!is_fallback);
        assert!(transactions.is_empty());
        assert!(finalizations.is_empty());
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
        // The QC's block is the committed tip in this fixture; naming it
        // keeps the parent resolvable, as it always is on a live chain.
        state.committed_hash = state.latest_qc.as_ref().unwrap().block_hash();
        // Height 4 proposes at round 4 (rounds increase per block).
        state.view_change.view = Round::new(4);
        state.set_block_syncing(true);

        let actions = state.try_propose(&topology_schedule, &[], vec![], vec![], vec![], vec![]);
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
        // The QC's block is the committed tip in this fixture; naming it
        // keeps the parent resolvable, as it always is on a live chain.
        state.committed_hash = state.latest_qc.as_ref().unwrap().block_hash();
        // Height 4 proposes at round 4 (rounds increase per block).
        state.view_change.view = Round::new(4);

        let height = BlockHeight::new(4);
        let round = Round::new(4);
        let actions = state.try_propose(&topology_schedule, &[], vec![], vec![], vec![], vec![]);
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
        let retry = state.try_propose(&topology_schedule, &[], vec![], vec![], vec![], vec![]);
        assert!(retry.is_empty(), "retry built a sibling: {retry:?}");
    }

    #[test]
    fn build_proposal_classifies_against_the_anchored_committee_not_the_head() {
        // The proposed block anchors at its `parent_qc` weighted timestamp
        // (epoch 0, where ROOT is one shard). The schedule's head has
        // already flipped to the post-split window (two shards). The
        // verifier recomputes `ticks`/`provision_tx_roots` against the
        // anchored window, so the proposer must classify against it too —
        // never the flipped head — or every replica rejects the header.
        let (mut state, _) = make_test_state();
        state.set_time(LocalTimestamp::from_millis(100_000));
        let parent = BlockHash::from_raw(Hash::from_bytes(b"block_3"));
        state.committed_height = BlockHeight::new(3);
        state.committed_hash = parent;
        state.committed_block_anchor_wt = WeightedTimestamp::from_millis(500);
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
        let keys: Vec<BlsSigner> = (0..4).map(|_| BlsSigner::generate()).collect();
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

        let actions = state.try_propose(&sched, &[], vec![], vec![], vec![], vec![]);
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
                public_key: BlsSigner::generate().public_key(),
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
                public_key: BlsSigner::generate().public_key(),
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
            Arc::new(BlsVerifier),
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
            AggregateSignature::ZERO,
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
            Arc::new(BlsVerifier),
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
        // The block's committee anchors on its parent, so it is the parent's
        // anchor that has to sit above the schedule head for the committee to
        // be unresolvable.
        state.committed_block_anchor_wt = WeightedTimestamp::from_millis(5 * ED);

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
                AggregateSignature::ZERO,
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
                AggregateSignature::ZERO,
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

    /// A block the vote fence withheld does not buy the progress
    /// window.
    ///
    /// The window is for work this replica finishes on its own. A block
    /// held at the fence waits on a counterpart to answer for a claim
    /// its proposer made, and a silent counterpart never answers — so
    /// the wait is bounded by the round timer, as every other wait on
    /// somebody else is. Priced the other way, one claim nobody can
    /// check stalls every transaction beside it for three rounds.
    #[test]
    fn a_block_held_at_the_fence_times_out_on_the_round_and_not_the_window() {
        let (mut state, _) = make_test_state();
        let round = state.view_change.view;
        let height = BlockHeight::new(state.committed_height.inner() + 1);
        let header = BlockHeader::new(BlockHeaderParts {
            shard_id: state.local_shard,
            height,
            round,
            ..Default::default()
        });
        let hash = header.hash();
        state.pending_blocks.insert(PendingBlock::from_manifest(
            header,
            BlockManifest::default(),
            LocalTimestamp::ZERO,
        ));

        // Past the round timeout, inside the progress window.
        state.view_change.last_leader_activity = Some(LocalTimestamp::ZERO);
        state.set_time(LocalTimestamp::ZERO.plus(VIEW_CHANGE_TIMEOUT + Duration::from_millis(1)));
        assert!(
            !state.should_advance_round(),
            "content still landing here is worth the window",
        );

        state
            .pending_blocks
            .get_mut(hash)
            .expect("the block was just inserted")
            .set_awaiting_counterpart(true);
        assert!(
            state.should_advance_round(),
            "a block waiting on a counterpart is not, and the round timer bounds it",
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
        // signature-only `VerifyQcSignature` action. Without this gate a Byzantine
        // peer can fork the local chain by serving a self-signed block.
        let (mut state, topology_schedule) = make_test_state();
        state.set_time(LocalTimestamp::from_millis(100_000));

        let block = Block::Live {
            header: {
                let __h = make_header_at_height(BlockHeight::new(1), 1000);
                BlockHeader::new(BlockHeaderParts {
                    shard_id: __h.shard_id(),
                    height: __h.height(),
                    parent_block_hash: BlockHash::ZERO,
                    parent_qc: __h.parent_qc().clone().into(),
                    proposer: __h.proposer(),
                    timestamp: ProposerTimestamp::from_millis(1000),
                    round: __h.round(),
                    is_fallback: __h.is_fallback(),
                    state_root: __h.state_root(),
                    transaction_root: __h.transaction_root(),
                    certificate_root: __h.certificate_root(),
                    local_receipt_root: __h.local_receipt_root(),
                    provision_root: __h.provision_root(),
                    provision_tx_roots: __h.provision_tx_roots().clone(),
                    work_in_flight: __h.work_in_flight(),
                    ..Default::default()
                })
            },
            transactions: Arc::new(Vec::new()),
            certificates: Arc::new(Vec::new()),
            provisions: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
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
            "must not reach signature verification with sub-quorum signers"
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
                BlockHeader::new(BlockHeaderParts {
                    shard_id: __h.shard_id(),
                    height: __h.height(),
                    parent_block_hash: BlockHash::from_raw(Hash::from_bytes(b"wrong-parent")),
                    parent_qc: __h.parent_qc().clone().into(),
                    proposer: __h.proposer(),
                    timestamp: ProposerTimestamp::from_millis(1000),
                    round: __h.round(),
                    is_fallback: __h.is_fallback(),
                    state_root: __h.state_root(),
                    transaction_root: __h.transaction_root(),
                    certificate_root: __h.certificate_root(),
                    local_receipt_root: __h.local_receipt_root(),
                    provision_root: __h.provision_root(),
                    provision_tx_roots: __h.provision_tx_roots().clone(),
                    work_in_flight: __h.work_in_flight(),
                    ..Default::default()
                })
            },
            transactions: Arc::new(Vec::new()),
            certificates: Arc::new(Vec::new()),
            provisions: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
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
                BlockHeader::new(BlockHeaderParts {
                    shard_id: __h.shard_id(),
                    height: __h.height(),
                    parent_block_hash: BlockHash::ZERO,
                    parent_qc: __h.parent_qc().clone().into(),
                    proposer: __h.proposer(),
                    timestamp: ProposerTimestamp::from_millis(1000),
                    round: __h.round(),
                    is_fallback: __h.is_fallback(),
                    state_root: __h.state_root(),
                    transaction_root: __h.transaction_root(),
                    certificate_root: __h.certificate_root(),
                    local_receipt_root: __h.local_receipt_root(),
                    provision_root: __h.provision_root(),
                    provision_tx_roots: __h.provision_tx_roots().clone(),
                    work_in_flight: __h.work_in_flight(),
                    ..Default::default()
                })
            },
            transactions: Arc::new(Vec::new()),
            certificates: Arc::new(Vec::new()),
            provisions: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
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
        // The QC's block is the committed tip in this fixture; naming it
        // keeps the parent resolvable, as it always is on a live chain.
        state.committed_hash = state.latest_qc.as_ref().unwrap().block_hash();
        // Height 4 proposes at round 4 (rounds increase per block).
        state.view_change.view = Round::new(4);
        state.set_block_syncing(true);
        let _ = state.try_propose(&topology_schedule, &[], vec![], vec![], vec![], vec![]);

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
        // The QC's block is the committed tip in this fixture; naming it
        // keeps the parent resolvable, as it always is on a live chain.
        state.committed_hash = state.latest_qc.as_ref().unwrap().block_hash();

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
        // The QC's block is the committed tip in this fixture; naming it
        // keeps the parent resolvable, as it always is on a live chain.
        state.committed_hash = state.latest_qc.as_ref().unwrap().block_hash();
        // Height 4 proposes at round 4 (rounds increase per block).
        state.view_change.view = Round::new(4);
        state.set_block_syncing(true);

        let actions = state.try_propose(&topology_schedule, &[], vec![], vec![], vec![], vec![]);
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::BuildProposal { .. }))
        );
    }

    #[test]
    fn test_validate_no_duplicate_transactions_rejects_cross_block_dup() {
        let (mut state, topology) = make_test_state();
        state.committed_height = BlockHeight::new(3);

        let tx1 = make_test_tx_with_seed(10);
        let tx2 = make_test_tx_with_seed(20);
        // Ancestor block at height 5 contains tx1
        let ancestor_block = Block::Live {
            header: {
                let __h = make_header_at_height(BlockHeight::new(5), 100_000);
                BlockHeader::new(BlockHeaderParts {
                    shard_id: __h.shard_id(),
                    height: __h.height(),
                    parent_block_hash: BlockHash::from_raw(Hash::from_bytes(b"grandparent")),
                    parent_qc: __h.parent_qc().clone().into(),
                    proposer: __h.proposer(),
                    timestamp: __h.timestamp(),
                    round: __h.round(),
                    is_fallback: __h.is_fallback(),
                    state_root: __h.state_root(),
                    transaction_root: __h.transaction_root(),
                    certificate_root: __h.certificate_root(),
                    local_receipt_root: __h.local_receipt_root(),
                    provision_root: __h.provision_root(),
                    provision_tx_roots: __h.provision_tx_roots().clone(),
                    work_in_flight: __h.work_in_flight(),
                    ..Default::default()
                })
            },
            transactions: Arc::new(vec![tx1.clone()]),
            certificates: Arc::new(Vec::new()),
            provisions: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
        };
        let ancestor_hash = ancestor_block.hash();
        install_complete_block(&mut state, &ancestor_block);

        // New block at height 6, parent = ancestor, contains tx1 (duplicate) + tx2
        let mut txs = vec![tx1, tx2];
        sort_txs_by_hash(&mut txs);
        let block = Block::Live {
            header: {
                let __h = make_header_at_height(BlockHeight::new(6), 100_001);
                BlockHeader::new(BlockHeaderParts {
                    shard_id: __h.shard_id(),
                    height: __h.height(),
                    parent_block_hash: ancestor_hash,
                    parent_qc: __h.parent_qc().clone().into(),
                    proposer: __h.proposer(),
                    timestamp: __h.timestamp(),
                    round: __h.round(),
                    is_fallback: __h.is_fallback(),
                    state_root: __h.state_root(),
                    transaction_root: __h.transaction_root(),
                    certificate_root: __h.certificate_root(),
                    local_receipt_root: __h.local_receipt_root(),
                    provision_root: __h.provision_root(),
                    provision_tx_roots: __h.provision_tx_roots().clone(),
                    work_in_flight: __h.work_in_flight(),
                    ..Default::default()
                })
            },
            transactions: Arc::new(txs),
            certificates: Arc::new(Vec::new()),
            provisions: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
        };

        let result = state.admit_transactions(&topology, &block);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already in QC chain ancestor"));
    }

    #[test]
    fn test_validate_no_duplicate_transactions_ignores_committed_ancestors() {
        let (mut state, topology) = make_test_state();
        state.committed_height = BlockHeight::new(5);

        let tx1 = make_test_tx_with_seed(10);

        // Ancestor at height 5 (== committed_height) contains tx1
        let ancestor_block = Block::Live {
            header: {
                let __h = make_header_at_height(BlockHeight::new(5), 100_000);
                BlockHeader::new(BlockHeaderParts {
                    shard_id: __h.shard_id(),
                    height: __h.height(),
                    parent_block_hash: BlockHash::from_raw(Hash::from_bytes(b"grandparent")),
                    parent_qc: __h.parent_qc().clone().into(),
                    proposer: __h.proposer(),
                    timestamp: __h.timestamp(),
                    round: __h.round(),
                    is_fallback: __h.is_fallback(),
                    state_root: __h.state_root(),
                    transaction_root: __h.transaction_root(),
                    certificate_root: __h.certificate_root(),
                    local_receipt_root: __h.local_receipt_root(),
                    provision_root: __h.provision_root(),
                    provision_tx_roots: __h.provision_tx_roots().clone(),
                    work_in_flight: __h.work_in_flight(),
                    ..Default::default()
                })
            },
            transactions: Arc::new(vec![tx1.clone()]),
            certificates: Arc::new(Vec::new()),
            provisions: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
        };
        let ancestor_hash = ancestor_block.hash();

        // Block at height 6, parent = ancestor. tx1 is in ancestor but ancestor
        // is at committed height so the walk stops — this should be allowed.
        let block = Block::Live {
            header: {
                let __h = make_header_at_height(BlockHeight::new(6), 100_001);
                BlockHeader::new(BlockHeaderParts {
                    shard_id: __h.shard_id(),
                    height: __h.height(),
                    parent_block_hash: ancestor_hash,
                    parent_qc: __h.parent_qc().clone().into(),
                    proposer: __h.proposer(),
                    timestamp: __h.timestamp(),
                    round: __h.round(),
                    is_fallback: __h.is_fallback(),
                    state_root: __h.state_root(),
                    transaction_root: __h.transaction_root(),
                    certificate_root: __h.certificate_root(),
                    local_receipt_root: __h.local_receipt_root(),
                    provision_root: __h.provision_root(),
                    provision_tx_roots: __h.provision_tx_roots().clone(),
                    work_in_flight: __h.work_in_flight(),
                    ..Default::default()
                })
            },
            transactions: Arc::new(vec![tx1]),
            certificates: Arc::new(Vec::new()),
            provisions: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
        };

        // Ancestor is at committed height, so walk stops before checking it
        assert!(state.admit_transactions(&topology, &block).is_ok());
    }

    /// Schedule whose window 0 carries `ROOT` (the coordinator's shard,
    /// with the full validator set) and whose window 1 carries its two
    /// children instead — `ROOT`'s terminal window is 0 and any weighted
    /// timestamp past 1000ms is coast territory.
    fn make_terminating_schedule(n: usize) -> TopologySchedule {
        let keys: Vec<BlsSigner> = (0..n).map(|_| BlsSigner::generate()).collect();
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| ValidatorInfo {
                validator_id: ValidatorId::new(i as u64),
                public_key: k.public_key(),
            })
            .collect();
        // The cut is carried by the final window's own entry, scheduled
        // there by an earlier fold — the boundary predicates read it
        // rather than comparing tries.
        let final_window = Arc::new(
            TopologySnapshot::new(
                NetworkDefinition::simulator(),
                1,
                ValidatorSet::new(validators.clone()),
            )
            .with_scheduled_terminals(BTreeMap::from([(ShardId::ROOT, Epoch::new(0))])),
        );
        let post_split = Arc::new(
            TopologySnapshot::new(
                NetworkDefinition::simulator(),
                2,
                ValidatorSet::new(validators),
            )
            .with_boundaries(HashMap::from([(
                ShardId::ROOT,
                ShardAnchor {
                    state_root: StateRoot::ZERO,
                    block_hash: BlockHash::from_raw(Hash::from_bytes(b"terminal")),
                    height: BlockHeight::new(9),
                    weighted_timestamp: WeightedTimestamp::from_millis(1_000),
                    witness_base: BeaconWitnessLeafCount::ZERO,
                    terminal_roots: None,
                    handoff_complete: None,
                },
            )])),
        );
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
                    public_key: BlsSigner::generate().public_key(),
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

    fn coordinator_with_committed_anchor(anchor_ms: u64) -> ShardCoordinator {
        let recovered = RecoveredState {
            committed_block_anchor_wt: Some(WeightedTimestamp::from_millis(anchor_ms)),
            ..RecoveredState::default()
        };
        ShardCoordinator::new(
            Arc::new(BlsVerifier),
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

    // ─── Split-boundary fence ────────────────────────────────────────────

    /// A live child coordinator (`leaf(1,0)`) of a `ROOT` that terminated
    /// at wt 1000 — so `ROOT` is past-terminal at any later anchor.
    impl ShardCoordinator {
        /// Admit `block`'s transactions against the chain behind its
        /// parent, the way the vote does.
        fn admit_transactions(
            &self,
            topology_schedule: &TopologySchedule,
            block: &Block,
        ) -> Result<(), String> {
            let parent = block.header().parent_block_hash();
            let chain = QcChainSets::behind(&self.chain_view(), parent);
            let ctx = self.admission(
                topology_schedule.head(),
                topology_schedule,
                &chain,
                parent,
                block.header().parent_qc().weighted_timestamp(),
                block.header().parent_qc().is_genesis(),
            );
            let provisions = ProvisionsFold::default();
            admit_all::<TransactionsSection<'_>>(
                &ctx,
                &mut TransactionsFold::beside(&provisions),
                block.transactions().iter().map(unwrapped),
            )
        }

        /// Admit `block`'s records against the schedule, the way the
        /// vote does, with no finalization beside them.
        fn admit_records(
            &self,
            topology_schedule: &TopologySchedule,
            block: &Block,
        ) -> Result<(), String> {
            let parent = block.header().parent_block_hash();
            let chain = QcChainSets::behind(&self.chain_view(), parent);
            let ctx = self.admission(
                topology_schedule.head(),
                topology_schedule,
                &chain,
                parent,
                block.header().parent_qc().weighted_timestamp(),
                block.header().parent_qc().is_genesis(),
            );
            let finalizations = FinalizationsFold::from(&ctx);
            admit_all::<RecordsSection<'_>>(
                &ctx,
                &mut RecordsFold::after(&finalizations),
                block.abandonment_records(),
            )
        }
    }

    fn fence_coordinator() -> ShardCoordinator {
        ShardCoordinator::new(
            Arc::new(BlsVerifier),
            ValidatorId::new(0),
            ShardId::leaf(1, 0),
            ShardConsensusConfig::default(),
            RecoveredState::default(),
        )
    }

    /// A finalization whose certificate carries this validator's local
    /// EC plus a remote EC on `remote` — the cross-shard shape the fence
    /// inspects.
    fn cross_shard_tick(
        local: ShardId,
        remote: ShardId,
        height: u64,
    ) -> Arc<Verifiable<Finalization>> {
        use hyperscale_types::{
            ExecutionCertificate, ExecutionOutcome, GlobalReceiptHash, GlobalReceiptRoot,
            SignerBitfield, TickHalf, TickId, TxOutcome,
        };
        let ec = |shard: ShardId| {
            let tick = TickId::new(shard, BlockHeight::new(height));
            ExecutionCertificate::new(
                tick,
                WeightedTimestamp::from_millis(height),
                GlobalReceiptRoot::ZERO,
                vec![TxOutcome::new(
                    TxHash::from(Hash::from_bytes(b"tx")),
                    ExecutionOutcome::Succeeded {
                        receipt_hash: GlobalReceiptHash::ZERO,
                    },
                )],
                AggregateSignature::ZERO,
                SignerBitfield::new(4),
            )
        };
        let local_tick = TickId::new(local, BlockHeight::new(height));
        // A counterpart's certificate rides beside this shard's, which is
        // the legs half by construction.
        Arc::new(Verifiable::from(Finalization::new(
            local_tick,
            TickHalf::Legs,
            vec![Arc::new(ec(local)), Arc::new(ec(remote))],
            vec![],
        )))
    }

    /// A block carrying boundary records, anchored at `anchor_ms` — the
    /// clock the fence reads each named departure against.
    fn block_with_records(anchor_ms: u64, records: Vec<AbandonmentRecord>) -> Block {
        let parent = BlockHash::from_raw(Hash::from_bytes(b"parent"));
        Block::Live {
            header: BlockHeader::new(BlockHeaderParts {
                height: BlockHeight::new(1),
                parent_block_hash: parent,
                parent_qc: QuorumCertificate::new(
                    parent,
                    ShardId::ROOT,
                    BlockHeight::new(0),
                    BlockHash::ZERO,
                    Round::new(0),
                    SignerBitfield::empty(),
                    AggregateSignature::ZERO,
                    WeightedTimestamp::from_millis(anchor_ms),
                )
                .into(),
                abandonment_root: AbandonmentRoot::over(&records),
                ..Default::default()
            }),
            transactions: Arc::new(Vec::new()),
            certificates: Arc::new(Vec::new()),
            provisions: Arc::new(Vec::new()),
            abandonment_records: Arc::new(records),
            state_claims: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
        }
    }

    /// A block carrying `bundles`, committed under their root.
    fn block_with_state_claims(bundles: Vec<StateClaim>) -> Block {
        Block::Live {
            header: BlockHeader::new(BlockHeaderParts {
                height: BlockHeight::new(1),
                state_claims_root: StateClaimsRoot::over(&bundles),
                ..Default::default()
            }),
            transactions: Arc::new(Vec::new()),
            certificates: Arc::new(Vec::new()),
            provisions: Arc::new(Vec::new()),
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(bundles),
            witness_sources: Arc::new(WitnessSources::empty()),
        }
    }

    /// A claim against `shard` at height 5 under the root `root` names,
    /// claiming the anchor's clock is `ts_ms`.
    fn bundle_against(shard: ShardId, root: &[u8], ts_ms: u64) -> StateClaim {
        use hyperscale_types::Inclusion;
        StateClaim::new(
            Anchor {
                shard,
                height: BlockHeight::new(5),
                state_root: StateRoot::from_raw(Hash::from_bytes(root)),
                ts: WeightedTimestamp::from_millis(ts_ms),
            },
            [(stub_abort_charge(1).vault, Inclusion::Absent)],
        )
    }

    /// A bundle names a counterpart's height this voter has not
    /// commit-proven: the vote defers and asks for the commit proof,
    /// as a provision on an unproven source block does.
    #[test]
    fn a_state_proof_against_an_unproven_height_defers_and_asks_for_its_proof() {
        let coord = fence_coordinator();
        let peer = ShardId::leaf(1, 1);
        let block = block_with_state_claims(vec![bundle_against(peer, b"root", 5_000)]);
        let Err(Withheld::Deferred { wanted, .. }) = coord.vote_fence().state_claims(&block) else {
            panic!("the vote is withheld");
        };
        assert!(
            matches!(
                wanted.as_slice(),
                [Action::Continuation(ProtocolEvent::CommitProofNeeded {
                    source_shard,
                    block_height,
                })] if *source_shard == peer && *block_height == BlockHeight::new(5)
            ),
            "{wanted:?}"
        );
    }

    /// A claim whose root or clock disagrees with the commit-proven
    /// header this voter holds is refused outright: its reading would
    /// have been taken against a root the chain never committed, or
    /// dated to a clock the chain never carried. An anchor that agrees
    /// leaves the reading itself to answer for.
    #[test]
    fn a_state_claim_disagreeing_with_the_held_header_is_refused() {
        let mut coord = fence_coordinator();
        let peer = ShardId::leaf(1, 1);
        coord.record_proven_anchor(Anchor {
            shard: peer,
            height: BlockHeight::new(5),
            state_root: StateRoot::from_raw(Hash::from_bytes(b"root")),
            ts: WeightedTimestamp::from_millis(5_000),
        });

        let other_root = block_with_state_claims(vec![bundle_against(peer, b"other", 5_000)]);
        assert!(
            matches!(
                coord.vote_fence().state_claims(&other_root),
                Err(Withheld::Refused(_))
            ),
            "refused, with nothing to wait for"
        );
        let other_clock = block_with_state_claims(vec![bundle_against(peer, b"root", 5_001)]);
        assert!(matches!(
            coord.vote_fence().state_claims(&other_clock),
            Err(Withheld::Refused(_))
        ),);

        let agreeing = block_with_state_claims(vec![bundle_against(peer, b"root", 5_000)]);
        let claim = &agreeing.state_claims()[0];
        assert!(
            matches!(
                coord.vote_fence().state_claims(&agreeing),
                Err(Withheld::Deferred { .. })
            ),
            "the anchor the chain committed stands, and the reading is still owed"
        );
        coord
            .proven_cells()
            .proven(claim.anchor, claim.cells.clone());
        assert!(
            coord.vote_fence().state_claims(&agreeing).is_ok(),
            "and passes once this validator has proven the cell for itself"
        );
    }

    /// What abandoning `tx` takes, as the transaction fixes it.
    fn figures_of(tx: &[u8]) -> UnsettledTx {
        UnsettledTx {
            tx_hash: TxHash::from(Hash::from_bytes(tx)),
            deadline: Deadline::of(WeightedTimestamp::from_millis(60_000)),
            declared_work: 5,
            charge: stub_abort_charge(5),
            committed: CommittedAt {
                height: BlockHeight::new(1),
                anchor: WeightedTimestamp::ZERO,
            },
            reach: vec![route(0xAA)],
        }
    }

    /// The route of an address whose top byte is `tag`: owned by this
    /// validator's shard, `leaf(1, 0)`, exactly when the top bit is
    /// clear, and by `ROOT` always.
    fn route(tag: u8) -> RoutePrefix {
        RoutePrefix::of(Address::new([tag; 31], AddressClass::Principal))
    }

    /// A record claiming `shard` left `tx` unsettled when it terminated at
    /// `terminal_wt`, restating the figures [`figures_of`] fixes.
    fn record_naming(shard: ShardId, terminal_wt: u64, tx: &[u8]) -> AbandonmentRecord {
        AbandonmentRecord::new(
            shard,
            WeightedTimestamp::from_millis(terminal_wt),
            [figures_of(tx)],
        )
    }

    /// The settled set `ROOT` left, naming `settled` and nothing else.
    fn root_settled(settled: &[u8]) -> SettledTxSet {
        SettledTxSet {
            txs: std::iter::once(TxHash::from(Hash::from_bytes(settled))).collect(),
            terminal_wt: WeightedTimestamp::from_millis(ROOT_CUT_MS),
        }
    }

    /// `ROOT` terminates at the close of window 0, so a record against it
    /// states that cut and nothing else. The schedule is the authority on
    /// both figures, and a voter checks them before asking what the
    /// departed shard settled.
    const ROOT_CUT_MS: u64 = 1_000;
    /// An anchor in window 1, after `ROOT` has left the trie.
    const AFTER_CUT_MS: u64 = 1_500;

    /// A record against a shard that has not left is refused. Its settled
    /// set does not exist and it can still settle anything the record
    /// names, so the claim is one no voter could ever check — and the
    /// verdict the record would license is the one that tears a
    /// cross-shard transaction in half.
    ///
    /// The delegate cannot catch this: a live shard is exactly what
    /// `settled_set_verdict` passes over, which is right for the question
    /// it asks and leaves this one unasked.
    #[test]
    fn a_record_against_a_live_shard_is_refused() {
        let coord = fence_coordinator();
        let sched = make_terminating_schedule(4);
        let live = ShardId::leaf(1, 1);
        let records = vec![record_naming(live, ROOT_CUT_MS, b"tx")];

        assert_eq!(
            settled_set_verdict(
                &coord.mirror().with_settled(Clone::clone),
                &sched,
                coord.local_shard,
                WeightedTimestamp::from_millis(AFTER_CUT_MS),
                records.iter().flat_map(|r| r.tx_hashes().map(move |tx| (
                    r.shard(),
                    tx,
                    TxClaim::Abandoned
                ))),
            ),
            SettledSetVerdict::Pass,
            "the delegate passes over a live shard, so the fence must ask first",
        );
        assert!(
            coord
                .vote_fence()
                .records(&block_with_records(AFTER_CUT_MS, records))
                .is_err()
        );
    }

    /// And one against this shard itself, which the delegate skips for the
    /// same reason: the fence asks only what a *counterpart* did.
    #[test]
    fn a_record_against_the_local_shard_is_refused() {
        let coord = fence_coordinator();
        let sched = make_terminating_schedule(4);
        let records = vec![record_naming(coord.local_shard, ROOT_CUT_MS, b"tx")];
        let err = coord
            .admit_records(&sched, &block_with_records(AFTER_CUT_MS, records))
            .unwrap_err();
        assert!(err.contains("schedule does not attest"), "{err}");
    }

    /// The stated cut is held to the schedule's own. It dates the record
    /// against the transactions it speaks for and nothing downstream
    /// re-derives it, so a restatement is the proposer's word alone.
    #[test]
    fn a_record_restating_the_wrong_cut_is_refused() {
        let coord = fence_coordinator();
        let sched = make_terminating_schedule(4);
        let records = vec![record_naming(ShardId::ROOT, ROOT_CUT_MS + 1, b"tx")];
        let err = coord
            .admit_records(&sched, &block_with_records(AFTER_CUT_MS, records))
            .unwrap_err();
        assert!(err.contains("schedule does not attest"), "{err}");
        let honest = vec![record_naming(ShardId::ROOT, ROOT_CUT_MS, b"tx")];
        assert!(
            coord
                .admit_records(&sched, &block_with_records(AFTER_CUT_MS, honest))
                .is_ok()
        );
    }

    /// The honest record still passes: a departure the schedule attests,
    /// at the cut it attests, naming a transaction the departed shard's
    /// own settled set does not.
    #[test]
    fn a_record_the_schedule_attests_is_voted_on() {
        let coord = fence_coordinator();
        coord
            .mirror()
            .record_settled(ShardId::ROOT, root_settled(b"other"));
        let records = vec![record_naming(ShardId::ROOT, ROOT_CUT_MS, b"tx")];
        assert!(
            coord
                .vote_fence()
                .records(&block_with_records(AFTER_CUT_MS, records))
                .is_ok()
        );
    }

    /// A record naming a transaction the departed shard was not party to
    /// is refused at admission: its absence from the settled set is
    /// trivial, and abandoning it would charge a payer for a transaction
    /// a live counterpart can still settle. Party is read off the
    /// figures the record restates — a name reaching no route the
    /// departed shard held, or only routes this shard holds itself, is a
    /// stranger on every replica alike. A voter holding no settled set
    /// for the departure still defers at the fence.
    #[test]
    fn a_record_naming_a_stranger_to_the_departed_shard_is_refused() {
        let coord = fence_coordinator();
        let sched = make_terminating_schedule(4);
        let naming = |reach: Vec<RoutePrefix>| {
            let mut figures = figures_of(b"tx");
            figures.reach = reach;
            vec![AbandonmentRecord::new(
                ShardId::ROOT,
                WeightedTimestamp::from_millis(ROOT_CUT_MS),
                [figures],
            )]
        };
        for reach in [Vec::new(), vec![route(0x11)]] {
            let err = coord
                .admit_records(&sched, &block_with_records(AFTER_CUT_MS, naming(reach)))
                .unwrap_err();
            assert!(err.contains("was not party to"), "{err}");
        }
        assert!(
            coord
                .admit_records(
                    &sched,
                    &block_with_records(AFTER_CUT_MS, naming(vec![route(0x11), route(0xAA)]))
                )
                .is_ok(),
            "one remote route the departed shard held is party"
        );

        let unmirrored = fence_coordinator();
        let records = vec![record_naming(ShardId::ROOT, ROOT_CUT_MS, b"tx")];
        assert!(
            unmirrored
                .vote_fence()
                .records(&block_with_records(AFTER_CUT_MS, records))
                .is_err(),
            "a voter that has mirrored no settled set defers"
        );
    }

    /// The figures each name restates are checked off the committed body
    /// by a delegated verification, whose three answers fold in
    /// A block whose anchor no retained window carries defers the check
    /// rather than answering it.
    ///
    /// The trie is what a delivery is classified against, and a stand-in
    /// is not neutral: under one shard nothing classifies as delivering
    /// here, so no delivery reads as lapsed and the block passes the arm
    /// that keeps a crossing from being claimed after its issuer may
    /// have taken it back. The mark is not taken either, so the next
    /// re-drive asks again once the beacon has caught up.
    #[test]
    fn a_block_anchored_outside_every_window_defers_its_resolutions_check() {
        let sched = make_terminating_schedule(4);
        let block = block_with_records(
            50_000,
            vec![record_naming(ShardId::ROOT, ROOT_CUT_MS, b"tx")],
        );
        let block_hash = block.hash();

        let mut coord = fence_coordinator();
        install_complete_block(&mut coord, &block);
        let actions = coord
            .verification
            .initiate_resolutions_verification(block_hash, &block, &sched);

        assert!(
            actions.is_empty(),
            "nothing is checked against a window nobody holds: {actions:?}",
        );
        assert!(
            !coord
                .verification
                .is_root_in_flight(block_hash, VerificationKind::Resolutions),
            "and the mark is left for the re-drive to take",
        );
    }

    /// differently: exact verifies the check, wrong refuses the block, and
    /// unknown clears the check's in-flight mark — the block pending, the
    /// vote deferred, and the check dispatched again on the next re-drive.
    #[test]
    fn a_records_figures_are_checked_off_the_body_and_folded_three_ways() {
        let sched = make_terminating_schedule(4);
        let block = block_with_records(
            AFTER_CUT_MS,
            vec![record_naming(ShardId::ROOT, ROOT_CUT_MS, b"tx")],
        );
        let block_hash = block.hash();
        let tx_hash = figures_of(b"tx").tx_hash;
        let kind = VerificationKind::Resolutions;

        let mut coord = fence_coordinator();
        install_complete_block(&mut coord, &block);
        let actions = coord
            .verification
            .initiate_resolutions_verification(block_hash, &block, &sched);
        assert!(
            matches!(
                actions.as_slice(),
                [Action::VerifyResolutions { entries, .. }] if *entries == vec![figures_of(b"tx")]
            ),
            "the names go to the store: {actions:?}"
        );
        assert!(coord.verification.is_root_in_flight(block_hash, kind));

        coord.on_block_check_completed(
            &sched,
            block_hash,
            kind,
            CheckOutcome::Deferred(DeferOn::Bodies(vec![tx_hash])),
        );
        assert!(
            !coord.verification.is_root_in_flight(block_hash, kind)
                && !coord.verification.is_root_verified(block_hash, kind),
            "an unknown name clears the in-flight mark, so a re-drive asks again"
        );
        assert!(
            coord.pending_blocks.get(block_hash).is_some(),
            "and the block pending"
        );

        coord.on_block_check_completed(&sched, block_hash, kind, CheckOutcome::Refused);
        assert!(
            coord.pending_blocks.get(block_hash).is_none(),
            "a wrong figure refuses the block"
        );

        let mut coord = fence_coordinator();
        install_complete_block(&mut coord, &block);
        coord
            .verification
            .initiate_resolutions_verification(block_hash, &block, &sched);
        coord.on_block_check_completed(&sched, block_hash, kind, CheckOutcome::Refused);
        assert!(
            coord.pending_blocks.get(block_hash).is_none(),
            "a delivery past its lapse refuses the block"
        );

        let mut coord = fence_coordinator();
        install_complete_block(&mut coord, &block);
        coord
            .verification
            .initiate_resolutions_verification(block_hash, &block, &sched);
        coord.on_block_check_completed(&sched, block_hash, kind, CheckOutcome::Refused);
        assert!(
            coord.pending_blocks.get(block_hash).is_none(),
            "a success past its deadline refuses the block"
        );

        let mut coord = fence_coordinator();
        install_complete_block(&mut coord, &block);
        coord
            .verification
            .initiate_resolutions_verification(block_hash, &block, &sched);
        coord.on_block_check_completed(
            &sched,
            block_hash,
            kind,
            CheckOutcome::Checked { bytes_delta: 0 },
        );
        assert!(
            coord.verification.is_root_verified(block_hash, kind),
            "an exact restatement verifies the root"
        );
    }

    /// Past the departure the record's own claim still stands or falls on
    /// the settled set: one naming a transaction `ROOT` did settle is
    /// refused by the delegate, which is the check the departure gate
    /// exists to let run.
    #[test]
    fn a_record_naming_what_the_departed_shard_settled_is_refused() {
        let coord = fence_coordinator();
        coord.mirror().record_settled(
            ShardId::ROOT,
            SettledTxSet {
                txs: std::iter::once(TxHash::from(Hash::from_bytes(b"tx"))).collect(),
                terminal_wt: WeightedTimestamp::from_millis(ROOT_CUT_MS),
            },
        );
        let records = vec![record_naming(ShardId::ROOT, ROOT_CUT_MS, b"tx")];
        assert!(
            coord
                .vote_fence()
                .records(&block_with_records(AFTER_CUT_MS, records))
                .is_err()
        );
    }

    fn block_with_certs(certs: Vec<Arc<Verifiable<Finalization>>>) -> Block {
        Block::Live {
            header: make_header_at_height(BlockHeight::new(1), 1500),
            transactions: Arc::new(Vec::new()),
            certificates: Arc::new(certs),
            provisions: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
        }
    }

    /// An abandonment: this shard's certificate alone, attesting the
    /// transaction aborted after awaiting `ShardId::ROOT`, with no
    /// counterpart certificate beside it.
    fn abandonment_tick(local: ShardId, height: u64) -> Arc<Verifiable<Finalization>> {
        use hyperscale_types::ExecutionOutcome;
        lone_tick(
            local,
            height,
            TxOutcome::new(
                TxHash::from(Hash::from_bytes(b"tx")),
                ExecutionOutcome::Aborted,
            )
            .awaiting([ShardId::ROOT]),
        )
    }

    /// A verdict that awaited nobody: this shard's certificate alone,
    /// attesting the transaction refused by a member with no counterpart
    /// to hear from — a leg's own verdict.
    fn lone_verdict_tick(local: ShardId, height: u64) -> Arc<Verifiable<Finalization>> {
        use hyperscale_types::ExecutionOutcome;
        lone_tick(
            local,
            height,
            TxOutcome::new(
                TxHash::from(Hash::from_bytes(b"tx")),
                ExecutionOutcome::Failed,
            ),
        )
    }

    fn lone_tick(local: ShardId, height: u64, outcome: TxOutcome) -> Arc<Verifiable<Finalization>> {
        use hyperscale_types::{
            ExecutionCertificate, GlobalReceiptRoot, SignerBitfield, TickHalf, TickId,
        };
        let tick = TickId::new(local, BlockHeight::new(height));
        Arc::new(Verifiable::from(Finalization::new(
            tick,
            TickHalf::Determined,
            vec![Arc::new(ExecutionCertificate::new(
                tick,
                WeightedTimestamp::from_millis(height),
                GlobalReceiptRoot::ZERO,
                vec![outcome],
                AggregateSignature::ZERO,
                SignerBitfield::new(4),
            ))],
            vec![],
        )))
    }

    /// A block abandoning a transaction a terminated shard settled is
    /// refused. The abort would tear the transaction in half, and the
    /// settled set is the evidence a voter can check without holding the
    /// transaction or knowing which shards were party to it.
    #[test]
    fn fence_rejects_an_abandonment_a_terminated_shard_settled() {
        let coord = fence_coordinator();
        let sched = make_terminating_schedule(4);
        coord.mirror().record_settled(
            ShardId::ROOT,
            SettledTxSet {
                txs: std::iter::once(TxHash::from(Hash::from_bytes(b"tx"))).collect(),
                terminal_wt: WeightedTimestamp::from_millis(1000),
            },
        );
        let block = block_with_certs(vec![abandonment_tick(ShardId::leaf(1, 0), 1)]);
        assert!(matches!(
            coord
                .vote_fence()
                .finalizations(&sched, &block, WeightedTimestamp::from_millis(1500)),
            Err(Withheld::Refused(_))
        ));
    }

    /// The same abandonment passes when the awaited shard's set is held
    /// and does not name the transaction: absence from a set is proof,
    /// so the partner never settled its half and the abort tears nothing.
    #[test]
    fn fence_admits_an_abandonment_the_settled_set_does_not_name() {
        let coord = fence_coordinator();
        let sched = make_terminating_schedule(4);
        coord.mirror().record_settled(
            ShardId::ROOT,
            SettledTxSet {
                txs: std::iter::once(TxHash::from(Hash::from_bytes(b"other"))).collect(),
                terminal_wt: WeightedTimestamp::from_millis(1000),
            },
        );
        let block = block_with_certs(vec![abandonment_tick(ShardId::leaf(1, 0), 1)]);
        assert!(matches!(
            coord
                .vote_fence()
                .finalizations(&sched, &block, WeightedTimestamp::from_millis(1500)),
            Ok(())
        ));
    }

    /// An abandonment whose awaited shard's set is not yet held defers,
    /// as the proposer's gate held it: a set nobody has read could still
    /// name the transaction, and the voter asks the same question the
    /// gate did rather than landing on what it happens to hold.
    #[test]
    fn fence_defers_an_abandonment_until_the_awaited_set_is_held() {
        let coord = fence_coordinator();
        let sched = make_terminating_schedule(4);
        let block = block_with_certs(vec![abandonment_tick(ShardId::leaf(1, 0), 1)]);
        assert!(matches!(
            coord
                .vote_fence()
                .finalizations(&sched, &block, WeightedTimestamp::from_millis(1500)),
            Err(Withheld::Deferred { .. })
        ));
    }

    /// An abandonment a committed record covers claims nothing of any
    /// set: the record established that no counterpart can settle the
    /// transaction, in a form that outlives the set, so the vote passes
    /// with the set unknown — and would pass with the set naming it,
    /// since the record is the chain's own answer.
    #[test]
    fn fence_admits_an_abandonment_a_committed_record_covers() {
        let coord = fence_coordinator();
        let sched = make_terminating_schedule(4);
        coord.mirror().cover(TxHash::from(Hash::from_bytes(b"tx")));
        let block = block_with_certs(vec![abandonment_tick(ShardId::leaf(1, 0), 1)]);
        assert!(matches!(
            coord
                .vote_fence()
                .finalizations(&sched, &block, WeightedTimestamp::from_millis(1500)),
            Ok(())
        ));
        coord.mirror().record_settled(
            ShardId::ROOT,
            SettledTxSet {
                txs: std::iter::once(TxHash::from(Hash::from_bytes(b"tx"))).collect(),
                terminal_wt: WeightedTimestamp::from_millis(1000),
            },
        );
        assert!(matches!(
            coord
                .vote_fence()
                .finalizations(&sched, &block, WeightedTimestamp::from_millis(1500)),
            Ok(())
        ));
    }

    /// A settlement is judged on the certificates it carries, not by this
    /// scan: the transaction appearing in the partner's settled set is
    /// exactly what a settlement needs, and reading it as an abandonment
    /// would refuse the outcome the fence exists to admit.
    #[test]
    fn the_abandonment_scan_leaves_a_settlement_alone() {
        let coord = fence_coordinator();
        let sched = make_terminating_schedule(4);
        coord.mirror().record_settled(
            ShardId::ROOT,
            SettledTxSet {
                txs: std::iter::once(TxHash::from(Hash::from_bytes(b"tx"))).collect(),
                terminal_wt: WeightedTimestamp::from_millis(1000),
            },
        );
        let block = block_with_certs(vec![cross_shard_tick(
            ShardId::leaf(1, 0),
            ShardId::ROOT,
            1,
        )]);
        assert!(matches!(
            coord
                .vote_fence()
                .finalizations(&sched, &block, WeightedTimestamp::from_millis(1500)),
            Ok(())
        ));
    }

    /// A verdict that awaited nobody is left alone too: a leg's own
    /// finalization carries only this shard's certificate, as an
    /// abandonment does, but it makes no claim about any counterpart's
    /// set — the core settles its half on the record cell — so the set
    /// naming the transaction refuses nothing.
    #[test]
    fn the_abandonment_scan_leaves_a_verdict_that_awaited_nobody_alone() {
        let coord = fence_coordinator();
        let sched = make_terminating_schedule(4);
        coord.mirror().record_settled(
            ShardId::ROOT,
            SettledTxSet {
                txs: std::iter::once(TxHash::from(Hash::from_bytes(b"tx"))).collect(),
                terminal_wt: WeightedTimestamp::from_millis(1000),
            },
        );
        let block = block_with_certs(vec![lone_verdict_tick(ShardId::leaf(1, 0), 1)]);
        assert!(matches!(
            coord
                .vote_fence()
                .finalizations(&sched, &block, WeightedTimestamp::from_millis(1500)),
            Ok(())
        ));
    }

    /// A finalization naming a past-terminal shard whose settled set is
    /// unknown defers the vote.
    #[test]
    fn fence_defers_when_settled_set_unknown() {
        let coord = fence_coordinator();
        let sched = make_terminating_schedule(4);
        let block = block_with_certs(vec![cross_shard_tick(
            ShardId::leaf(1, 0),
            ShardId::ROOT,
            1,
        )]);
        assert!(matches!(
            coord
                .vote_fence()
                .finalizations(&sched, &block, WeightedTimestamp::from_millis(1500)),
            Err(Withheld::Deferred { .. })
        ));
    }

    /// Once the past-terminal shard's settled set is known and contains
    /// the tick, the vote passes.
    #[test]
    fn fence_passes_when_tick_settled() {
        let coord = fence_coordinator();
        let sched = make_terminating_schedule(4);
        coord.mirror().record_settled(
            ShardId::ROOT,
            SettledTxSet {
                txs: std::iter::once(TxHash::from(Hash::from_bytes(b"tx"))).collect(),
                terminal_wt: WeightedTimestamp::from_millis(1000),
            },
        );
        let block = block_with_certs(vec![cross_shard_tick(
            ShardId::leaf(1, 0),
            ShardId::ROOT,
            1,
        )]);
        assert!(matches!(
            coord
                .vote_fence()
                .finalizations(&sched, &block, WeightedTimestamp::from_millis(1500)),
            Ok(())
        ));
    }

    /// A tick the past-terminal shard did not settle is rejected.
    #[test]
    fn fence_rejects_unsettled_tick() {
        let coord = fence_coordinator();
        let sched = make_terminating_schedule(4);
        coord.mirror().record_settled(
            ShardId::ROOT,
            SettledTxSet {
                txs: BTreeSet::new(),
                terminal_wt: WeightedTimestamp::from_millis(1000),
            },
        );
        let block = block_with_certs(vec![cross_shard_tick(
            ShardId::leaf(1, 0),
            ShardId::ROOT,
            1,
        )]);
        assert!(matches!(
            coord
                .vote_fence()
                .finalizations(&sched, &block, WeightedTimestamp::from_millis(1500)),
            Err(Withheld::Refused(_))
        ));
    }

    /// Past its evidence window, a tick naming the terminated shard is
    /// categorically unreachable and rejects, even if the (stale) settled
    /// set happens to contain it.
    #[test]
    fn fence_rejects_past_the_evidence_window() {
        let coord = fence_coordinator();
        let sched = make_terminating_schedule(4);
        coord.mirror().record_settled(
            ShardId::ROOT,
            SettledTxSet {
                txs: std::iter::once(TxHash::from(Hash::from_bytes(b"tx"))).collect(),
                terminal_wt: WeightedTimestamp::from_millis(1000),
            },
        );
        let block = block_with_certs(vec![cross_shard_tick(
            ShardId::leaf(1, 0),
            ShardId::ROOT,
            1,
        )]);
        let beyond = WeightedTimestamp::from_millis(6_001);
        assert!(matches!(
            coord.vote_fence().finalizations(&sched, &block, beyond),
            Err(Withheld::Refused(_))
        ));
    }

    /// A tick with no past-terminal-shard certificate passes regardless of
    /// any settled-set state — single-shard and live-cross-shard ticks are
    /// untouched.
    #[test]
    fn fence_ignores_live_shard_certificates() {
        let coord = fence_coordinator();
        let sched = make_terminating_schedule(4);
        // Both ECs name live shards (the local child and its live sibling).
        let block = block_with_certs(vec![cross_shard_tick(
            ShardId::leaf(1, 0),
            ShardId::leaf(1, 1),
            1,
        )]);
        assert!(matches!(
            coord
                .vote_fence()
                .finalizations(&sched, &block, WeightedTimestamp::from_millis(1500)),
            Ok(())
        ));
    }

    /// A height-1 block on `leaf(1,0)` anchored in epoch 1 (`parent_qc`
    /// weighted timestamp 1500, past ROOT's terminal window in
    /// [`make_terminating_schedule`]) carrying a finalization whose
    /// certificate names the past-terminal shard ROOT.
    fn straddling_block() -> Block {
        let parent_qc = QuorumCertificate::new(
            BlockHash::ZERO,
            ShardId::leaf(1, 0),
            BlockHeight::new(0),
            BlockHash::ZERO,
            Round::new(0),
            SignerBitfield::empty(),
            AggregateSignature::ZERO,
            WeightedTimestamp::from_millis(1500),
        );
        let header = BlockHeader::new(BlockHeaderParts {
            shard_id: ShardId::leaf(1, 0),
            height: BlockHeight::new(1),
            parent_block_hash: BlockHash::ZERO,
            parent_qc: parent_qc.into(),
            proposer: ValidatorId::new(1),
            timestamp: ProposerTimestamp::from_millis(1500),
            round: Round::new(1),
            ..Default::default()
        });
        Block::Live {
            header,
            transactions: Arc::new(Vec::new()),
            certificates: Arc::new(vec![cross_shard_tick(
                ShardId::leaf(1, 0),
                ShardId::ROOT,
                1,
            )]),
            provisions: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
        }
    }

    /// End to end through the real vote path: a block whose finalized
    /// tick names a past-terminal shard defers (no verification dispatched)
    /// while its settled set is unknown, then proceeds once the set is
    /// recorded and the vote is re-driven.
    #[test]
    fn vote_defers_at_fence_then_proceeds_once_settled_set_recorded() {
        // Local shard `leaf(1,0)` survives; ROOT is past-terminal at the
        // block's epoch-1 anchor.
        let mut coord = ShardCoordinator::new(
            Arc::new(BlsVerifier),
            ValidatorId::new(0),
            ShardId::leaf(1, 0),
            ShardConsensusConfig::default(),
            RecoveredState::default(),
        );
        let sched = make_terminating_schedule(4);
        let block = straddling_block();
        // The block's committee anchors on its parent, so seat that parent as
        // the committed tip and date it in the block's own window.
        coord.committed_hash = block.header().parent_block_hash();
        coord.committed_block_anchor_wt = block.header().parent_qc().weighted_timestamp();
        coord.committed_committee_anchor_wt = coord.committed_block_anchor_wt;
        let block_hash = block.hash();
        let height = block.height();
        let round = block.header().round();
        // Install with the block's finalizations threaded through, so the
        // constructed pending block carries its certificates (the default
        // `install_complete_block` helper drops them).
        let ticks: Vec<Arc<Verifiable<Finalization>>> =
            block.certificates().iter().cloned().collect();
        let mut pending =
            PendingBlock::from_complete_block(&block, ticks, vec![], LocalTimestamp::ZERO);
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

        // Record ROOT's settled set including the straddler's tick, then
        // re-drive: the fence now passes, so the block proceeds to
        // verification.
        coord.mirror().record_settled(
            ShardId::ROOT,
            SettledTxSet {
                txs: std::iter::once(TxHash::from(Hash::from_bytes(b"tx"))).collect(),
                terminal_wt: WeightedTimestamp::from_millis(1000),
            },
        );
        let released = coord.redrive_pending_votes(&sched);
        assert!(
            !released.is_empty(),
            "recording the settled set must release the deferred block into verification",
        );
    }

    /// A chain block for the fee-anchor walk: explicit round and parent
    /// linkage, everything else zeroed.
    fn round_chain_block(height: u64, round: u64, parent: &Block, parent_round: u64) -> Block {
        let parent_qc = QuorumCertificate::new(
            parent.hash(),
            ShardId::ROOT,
            parent.height(),
            parent.header().parent_block_hash(),
            Round::new(parent_round),
            SignerBitfield::new(4),
            AggregateSignature::ZERO,
            WeightedTimestamp::ZERO,
        );
        let header = BlockHeader::new(BlockHeaderParts {
            height: BlockHeight::new(height),
            parent_block_hash: parent.hash(),
            parent_qc: parent_qc.into(),
            timestamp: ProposerTimestamp::from_millis(height),
            round: Round::new(round),
            ..Default::default()
        });
        Block::Live {
            header,
            transactions: Arc::new(Vec::new()),
            certificates: Arc::new(Vec::new()),
            provisions: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
        }
    }

    /// The genesis-parented root of a fee-anchor test chain.
    fn round_chain_genesis_child(round: u64) -> Block {
        let genesis_qc = QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT);
        let header = BlockHeader::new(BlockHeaderParts {
            height: BlockHeight::new(1),
            parent_block_hash: BlockHash::ZERO,
            parent_qc: genesis_qc.into(),
            timestamp: ProposerTimestamp::from_millis(1),
            round: Round::new(round),
            ..Default::default()
        });
        Block::Live {
            header,
            transactions: Arc::new(Vec::new()),
            certificates: Arc::new(Vec::new()),
            provisions: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
        }
    }

    /// The fee anchor is a function of chain content alone: coordinators
    /// at different committed tips — one holding every ancestor in
    /// pending, the other having committed and pruned the anchor block
    /// into the round ring — derive the same balance-read height for the
    /// same block.
    #[test]
    fn fee_anchor_is_chain_derived_not_tip_derived() {
        let b1 = round_chain_genesis_child(1);
        let b2 = round_chain_block(2, 2, &b1, 1);
        let b3 = round_chain_block(3, 3, &b2, 2);
        // The QC a block at height 4 would carry: certifies b3.
        let parent_qc = QuorumCertificate::new(
            b3.hash(),
            ShardId::ROOT,
            b3.height(),
            b2.hash(),
            Round::new(3),
            SignerBitfield::new(4),
            AggregateSignature::ZERO,
            WeightedTimestamp::ZERO,
        );

        // Coordinator A: nothing committed, the whole chain pending.
        let (mut a, _) = make_test_state();
        for block in [&b1, &b2, &b3] {
            install_complete_block(&mut a, block);
        }

        // Coordinator B: b1 and b2 committed (pruned from pending, rounds
        // ringed), the rest pending.
        let (mut b, _) = make_test_state();
        b.committed_height = BlockHeight::new(2);
        b.committed_rounds
            .insert(BlockHeight::new(1), Round::new(1));
        b.committed_rounds
            .insert(BlockHeight::new(2), Round::new(2));
        install_complete_block(&mut b, &b3);

        let anchor_a = a.ancestry_committed_height(&parent_qc);
        let anchor_b = b.ancestry_committed_height(&parent_qc);
        assert_eq!(anchor_a, anchor_b, "the anchor must not depend on the tip");
        assert_eq!(
            anchor_a,
            BlockHeight::new(2),
            "contiguous rounds prove the parent QC's committable height"
        );
    }

    /// A view-change round gap defers the anchor to the first
    /// round-contiguous pair below it — the same height the two-chain
    /// commit rule proves, so the anchor is never ahead of what every
    /// replica processing the chain has committed.
    #[test]
    fn fee_anchor_descends_past_view_change_gaps() {
        let b1 = round_chain_genesis_child(1);
        let b2 = round_chain_block(2, 2, &b1, 1);
        // b3 proposed after view changes: rounds 3 and 4 burned.
        let b3 = round_chain_block(3, 5, &b2, 2);
        let parent_qc = QuorumCertificate::new(
            b3.hash(),
            ShardId::ROOT,
            b3.height(),
            b2.hash(),
            Round::new(5),
            SignerBitfield::new(4),
            AggregateSignature::ZERO,
            WeightedTimestamp::ZERO,
        );

        let (mut state, _) = make_test_state();
        for block in [&b1, &b2, &b3] {
            install_complete_block(&mut state, block);
        }
        assert_eq!(
            state.ancestry_committed_height(&parent_qc),
            BlockHeight::new(1),
            "the non-contiguous (b3, b2) pair proves nothing; (b2, b1) is \
             the first contiguous pair"
        );
    }

    /// A genesis parent QC anchors at the chain origin: nothing above it
    /// is proven, and the origin state is what every replica shares.
    #[test]
    fn fee_anchor_of_a_genesis_extending_block_is_the_origin() {
        let (state, _) = make_test_state();
        let genesis_qc = QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT);
        assert_eq!(
            state.ancestry_committed_height(&genesis_qc),
            BlockHeight::GENESIS
        );
    }
}
