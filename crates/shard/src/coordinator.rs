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

use hyperscale_core::{Action, CommitSource, FetchAbandon, ProtocolEvent, TimerId};
use hyperscale_types::{
    BlockHash, LocalTimestamp, MAX_FINALIZED_TX_PER_BLOCK, MAX_PROGRESS_WAIT,
    MAX_READY_SIGNALS_PER_BLOCK, MAX_TXS_PER_BLOCK, ProposerTimestamp, ProvisionHash, ReadySignal,
    ShardGroupId, StoredReceipt, WaveId, WeightedTimestamp,
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

use std::sync::Arc;
use std::time::Duration;

use hyperscale_storage::RecoveredState;
use hyperscale_types::{
    BeaconWitnessCommit, BeaconWitnessRoot, BeaconWitnessRootVerifyError, Block, BlockHeader,
    BlockHeight, BlockManifest, BlockVote, CertRootVerifyError, CertificateRoot, CertifiedBlock,
    CertifiedBlockHeader, FinalizedWave, LocalReceiptRoot, LocalReceiptRootVerifyError,
    ProvisionRootVerifyError, ProvisionTxRootsMap, ProvisionTxRootsVerifyError, Provisions,
    ProvisionsRoot, QcContext, QcVerifyError, QuorumCertificate, Round, RoutableTransaction,
    StateRoot, StateRootVerifyError, Timeout, TopologySnapshot, TransactionRoot, TxHash,
    TxRootVerifyError, ValidatorId, Verifiable, Verified, Verify, VotePower, derive_leaves,
    missed_proposals_since_prev_commit,
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
use crate::lookups::{committee_public_keys, committee_voting_powers, vote_recipients};
use crate::pending::{PendingBlock, PendingBlocks};
use crate::proposal::{
    ProposalKind, ProposalTracker, TakeResult, assemble_build_action, dispatch_or_defer,
    select_finalized_waves, select_provisions, select_transactions,
};
use crate::ready_signal_pool::{MIN_READY_SIGNAL_DWELL, ReadySignalPool};
use crate::timeout_keeper::TimeoutKeeper;
use crate::validation::{qc_has_local_quorum_power, validate_block_for_vote, validate_header};
use crate::verification::{
    InFlightCheck, ReadyStateRootVerification, VerificationKind, VerificationPipeline,
};
use crate::view_change::ViewChangeController;
use crate::vote_keeper::VoteKeeper;

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

    /// State root from the latest committed block header.
    /// Updated synchronously at commit time (not dependent on async JMT).
    committed_state_root: StateRoot,

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
    local_shard: ShardGroupId,
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
        local_shard: ShardGroupId,
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
        Self {
            view_change: ViewChangeController::new(initial_view),
            committed_height: recovered.committed_height,
            committed_hash: recovered.committed_hash.unwrap_or(BlockHash::ZERO),
            committed_ts: recovered.latest_qc.as_deref().map_or(
                WeightedTimestamp::ZERO,
                QuorumCertificate::weighted_timestamp,
            ),
            committed_state_root: recovered.jmt_root.unwrap_or(StateRoot::ZERO),
            latest_qc: recovered.latest_qc,
            deferred_qc: DeferredQc::new(),
            pending_blocks: PendingBlocks::new(),
            votes: VoteKeeper::new(),
            timeouts: TimeoutKeeper::new(),
            last_timed_out_round: None,
            // Recover the lock conservatively at the high QC's round: we never
            // regress below the chain we already certified, so the safe-vote
            // lock can't slip beneath a committed block after a restart.
            locked_round: high_qc_round,
            last_voted_round: high_qc_round,
            commits: CommitPipeline::new(),
            verification: VerificationPipeline::new(recovered.committed_height),
            block_sync: BlockSyncManager::new(),
            proposal: ProposalTracker::new(),
            dedup_index: CommitDedupIndex::new(),
            ready_signal_pool: ReadySignalPool::new(),
            beacon_witness_accumulator: BeaconWitnessAccumulator::from_leaves(
                recovered.beacon_witness_leaf_hashes,
            ),
            config,
            now: LocalTimestamp::ZERO,
            me,
            local_shard,
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
            self.committed_height,
            self.committed_hash,
            self.committed_state_root,
            self.latest_qc.as_ref(),
            &self.pending_blocks,
        )
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
        topology_snapshot: &TopologySnapshot,
        certified: CertifiedBlock,
    ) -> Vec<Action> {
        match self.block_sync.ingest(certified, self.committed_height) {
            IngestOutcome::Drop => vec![],
            IngestOutcome::Submit(certified) => {
                self.submit_synced_block_for_verification(topology_snapshot, *certified)
            }
            IngestOutcome::Buffered => self.try_drain_buffered_synced_blocks(topology_snapshot),
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
    pub fn on_block_sync_complete(&mut self) -> Vec<Action> {
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
        self.check_pending_block_fetches(true)
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
        topology_snapshot: &TopologySnapshot,
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
        let mut actions = self.broadcast_timeout(topology_snapshot, round);
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

    /// Handle committed state restored from storage (recovery).
    ///
    /// Called when the runner completes `Action::RestoreCommittedState`.
    #[instrument(skip(self, qc), fields(height = height.inner(), has_hash = hash.is_some(), has_qc = qc.is_some()))]
    pub fn on_committed_state_restored(
        &mut self,
        topology_snapshot: &TopologySnapshot,
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
        // Recover the safe-vote lock at the QC's round (conservative: never
        // below the chain we already certified). See `Self::new`.
        if let Some(qc_round) = qc.as_deref().map(QuorumCertificate::round) {
            self.locked_round = qc_round;
            self.last_voted_round = qc_round;
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
    #[instrument(skip(self, ready_txs, finalized_waves), fields(
        tx_count = ready_txs.len(),
        cert_count = finalized_waves.len(),
    ))]
    pub fn try_propose(
        &mut self,
        topology_snapshot: &TopologySnapshot,
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

        if !self.can_propose(topology_snapshot, next_height, round) {
            return vec![];
        }

        // Syncing validators propose an empty sync block to keep the chain
        // advancing while catching up on execution state.
        if self.block_sync.is_syncing() {
            return self.build_and_dispatch_proposal(
                topology_snapshot,
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
                topology_snapshot,
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
            topology_snapshot,
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

    /// Pre-build gate: we must be the proposer for this round and not already
    /// building (or parked on the verification pipeline for) the same
    /// height/round.
    fn can_propose(
        &self,
        topology_snapshot: &TopologySnapshot,
        next_height: BlockHeight,
        round: Round,
    ) -> bool {
        if topology_snapshot.proposer_for(self.local_shard, round) != self.me {
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
        topology_snapshot: &TopologySnapshot,
        height: BlockHeight,
        round: Round,
    ) -> Vec<Action> {
        self.build_and_dispatch_proposal(topology_snapshot, height, round, ProposalKind::Fallback)
    }

    /// Unified proposal build + dispatch.
    ///
    /// Resolves the parent from the chain view, assembles a `BuildProposal`
    /// action whose payload/timestamp/`is_fallback` bits come from `kind`,
    /// and dispatches via the `proposal` tracker (or defers via the
    /// verification pipeline when the parent JMT isn't ready yet).
    fn build_and_dispatch_proposal(
        &mut self,
        topology_snapshot: &TopologySnapshot,
        height: BlockHeight,
        round: Round,
        kind: ProposalKind,
    ) -> Vec<Action> {
        let (parent_block_hash, parent_qc) = self.chain_view().proposal_parent();
        let parent_round = parent_qc.round();
        let receipts: Vec<StoredReceipt> = match &kind {
            ProposalKind::Normal {
                finalized_waves, ..
            } => finalized_waves
                .iter()
                .flat_map(|fw| fw.receipts().iter().cloned())
                .collect(),
            ProposalKind::Fallback | ProposalKind::Sync => Vec::new(),
        };
        let missed = missed_proposals_since_prev_commit(
            self.local_shard,
            height,
            parent_round,
            round,
            topology_snapshot,
        );
        let ready_signals = self.ready_signal_pool.drain_eligible(
            height,
            self.now,
            MIN_READY_SIGNAL_DWELL,
            MAX_READY_SIGNALS_PER_BLOCK,
        );
        let new_leaves = derive_leaves(&receipts, &missed, &ready_signals);

        // Anchor the preview on the prefix the parent block leaves behind,
        // not the committed accumulator: the parent may be certified but not
        // yet committed, so its own witness leaves (e.g. a missed-proposal
        // leaf after a view change) aren't folded into `committed` yet. Every
        // verifier reconstructs this same prefix via
        // `prospective_parent_witness_leaves`, so previewing against the
        // committed accumulator alone would omit those leaves and produce a
        // root no validator accepts.
        let parent_leaves = prospective_parent_witness_leaves(
            &self.beacon_witness_accumulator,
            self.committed_hash,
            parent_block_hash,
            &self.pending_blocks,
            self.local_shard,
            topology_snapshot,
        )
        .unwrap_or_else(|blocking| {
            warn!(
                validator = ?self.me,
                ?blocking,
                "Beacon-witness ancestor walk blocked at proposal; previewing against committed prefix"
            );
            self.beacon_witness_accumulator.leaves().to_vec()
        });
        let (beacon_witness_root, beacon_witness_leaf_count) =
            BeaconWitnessAccumulator::from_leaves(parent_leaves).preview_append(&new_leaves);

        let plan = assemble_build_action(
            self.me,
            self.local_shard,
            &self.chain_view(),
            height,
            round,
            self.now,
            kind,
            ready_signals,
            beacon_witness_root,
            beacon_witness_leaf_count,
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
            plan.parent_block_hash,
            plan.parent_block_height,
            height,
            round,
            plan.action,
        )
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Header Reception
    // ═══════════════════════════════════════════════════════════════════════════

    /// Handle a received block header. Sender identity is taken from the
    /// header's signed `proposer` field — there's no separate peer-id
    /// parameter because sync detection doesn't need it.
    #[instrument(skip(self, header, manifest, lookup_tx, lookup_finalized_wave, lookup_provision), fields(
        height = header.height().inner(),
        round = header.round().inner(),
        proposer = ?header.proposer(),
        tx_count = manifest.transaction_count()
    ))]
    #[allow(clippy::too_many_arguments)]
    pub fn on_block_header(
        &mut self,
        topology_snapshot: &TopologySnapshot,
        header: &BlockHeader,
        manifest: BlockManifest,
        lookup_tx: impl Fn(&TxHash) -> Option<Arc<Verifiable<RoutableTransaction>>>,
        lookup_finalized_wave: impl Fn(&WaveId) -> Option<Arc<Verifiable<FinalizedWave>>>,
        lookup_provision: impl Fn(&ProvisionHash) -> Option<Arc<Verifiable<Provisions>>>,
    ) -> Vec<Action> {
        let block_hash = header.hash();
        let height = header.height();
        let round = header.round();

        debug!(
            validator = ?self.me,
            proposer = ?header.proposer(),
            height = height.inner(),
            round = round.inner(),
            block_hash = ?block_hash,
            "Received block header"
        );

        let sync_actions = self.absorb_parent_qc_from_header(header);

        if self.reject_invalid_header(topology_snapshot, header) {
            return vec![];
        }

        // View sync runs only after validation, so a header that fails the
        // proposer, timestamp, or quorum checks can't nudge the local view.
        self.sync_view_to_header_round(header);
        self.record_header_activity(height, round);

        if self.pending_blocks.contains_key(block_hash) {
            trace!("Already have pending block {}", block_hash);
            return vec![];
        }

        self.pending_blocks.assemble(
            header.clone(),
            manifest,
            self.now,
            lookup_tx,
            lookup_finalized_wave,
            lookup_provision,
        );
        self.adopt_deferred_qc_if_matches(block_hash);
        self.link_buffered_votes_to_header(block_hash, header);

        let mut actions =
            self.votes
                .maybe_trigger_verification(topology_snapshot, self.local_shard, block_hash);
        actions.extend(sync_actions);

        // If vote verification was triggered, return those actions. Still want
        // to fall through for sync-only extensions, so only short-circuit on
        // the verification-scheduling case.
        if actions
            .iter()
            .any(|a| matches!(a, Action::VerifyQcSignature { .. }))
        {
            return actions;
        }

        if self.finalize_complete_block(topology_snapshot, block_hash, &mut actions) {
            return actions;
        }

        self.log_incomplete_block(block_hash);
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
        self.advance_view_for_qc(qc.as_ref());
        // Non-proposers learn about QCs via block headers rather than
        // forming them locally — they need two-chain commit + a proposal
        // kick to advance the chain in the event-driven model.
        let actions = self.try_two_chain_commit(qc.as_ref(), CommitSource::Header);
        self.queue_ready_proposal();
        actions
    }

    /// Advance the local view toward the header's round if the header is
    /// ahead, so late joiners converge faster than QC-based view sync alone.
    /// The header is one validator's unverified round claim, so the advance
    /// is capped per [`ViewChangeController::sync_to_observed_round`].
    fn sync_view_to_header_round(&mut self, header: &BlockHeader) {
        let old_view = self.view_change.view;
        if self.view_change.sync_to_observed_round(header.round()) {
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
    /// reject (short-circuit with empty actions).
    fn reject_invalid_header(
        &self,
        topology_snapshot: &TopologySnapshot,
        header: &BlockHeader,
    ) -> bool {
        if let Err(e) = validate_header(
            topology_snapshot,
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

    /// Late-arriving header: votes may have already landed in the vote set.
    /// Stamp the header info into the set so QC aggregation has the
    /// `parent_block_hash` it needs.
    fn link_buffered_votes_to_header(&mut self, block_hash: BlockHash, header: &BlockHeader) {
        if self.votes.link_header(block_hash, header) {
            info!(
                block_hash = ?block_hash,
                "Updated VoteSet with header info via on_block_header"
            );
        }
    }

    /// If the pending block is complete, construct it and trigger QC
    /// verification / voting. Returns `true` if the block was handled (the
    /// caller should return the accumulated actions).
    fn finalize_complete_block(
        &mut self,
        topology_snapshot: &TopologySnapshot,
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

        actions.extend(self.trigger_qc_verification_or_vote(topology_snapshot, block_hash));
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
        topology_snapshot: &TopologySnapshot,
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
                return self.try_vote_on_block(topology_snapshot, block_hash, height, round);
            }

            // Check if we already have pending verification for this block
            if self.verification.has_pending_qc(&block_hash) {
                trace!("QC verification already pending for block {}", block_hash);
                return vec![];
            }

            // Collect public keys and voting powers for verification —
            // both halves of the QC's predicate (signature + quorum
            // power) need them.
            let Some(public_keys) = committee_public_keys(topology_snapshot, self.local_shard)
            else {
                warn!("Failed to collect public keys for QC verification");
                return vec![];
            };
            let Some(voting_powers) = committee_voting_powers(topology_snapshot, self.local_shard)
            else {
                warn!("Failed to collect voting powers for QC verification");
                return vec![];
            };
            let quorum_threshold = VotePower::quorum_threshold(
                topology_snapshot.voting_power_for_shard(self.local_shard),
            );

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
                voting_powers,
                quorum_threshold,
                block_hash,
            }];
        }

        // Genesis QC - vote directly (no signature to verify)
        self.try_vote_on_block(topology_snapshot, block_hash, height, round)
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
    fn try_vote_on_block(
        &mut self,
        topology_snapshot: &TopologySnapshot,
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

        // If the block is assembled, run validation + verification.
        // Otherwise fall through to the voting path directly — reachable only
        // from test fixtures; production always assembles before reaching
        // here.
        if let Some(block) = self.pending_blocks.get_block(block_hash) {
            if self.reject_invalid_block_contents(topology_snapshot, block_hash, block) {
                return vec![];
            }

            // Blocks the safe-vote rule declines must still run verification to
            // produce PreparedCommit. Parent-pruned blocks likewise run
            // verification but can't contribute in-flight accounting.
            let chain = ChainView::new(
                self.local_shard,
                self.committed_height,
                self.committed_hash,
                self.committed_state_root,
                self.latest_qc.as_ref(),
                &self.pending_blocks,
            );
            let skip_vote = match self
                .verification
                .classify_vote_in_flight(&chain, block_hash, block, !safe)
            {
                InFlightCheck::Proceed => false,
                InFlightCheck::SkipVote => true,
                InFlightCheck::Abort => return vec![],
            };

            let verification_actions = self.verification.initiate_block_verifications(
                topology_snapshot,
                self.local_shard,
                &self.pending_blocks,
                &self.beacon_witness_accumulator,
                self.committed_hash,
                block_hash,
                block,
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

        self.create_vote(topology_snapshot, block_hash, height, round)
    }

    /// Validate transaction ordering, waves, and cross-ancestor tx uniqueness
    /// against the QC chain + retention cache. Returns `true` when the caller
    /// should reject the block (logs the reason).
    fn reject_invalid_block_contents(
        &self,
        topology_snapshot: &TopologySnapshot,
        block_hash: BlockHash,
        block: &Block,
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
    #[tracing::instrument(level = "debug", skip(self), fields(
        height = height.inner(),
        round = round.inner(),
        sign_us = Empty,
    ))]
    fn create_vote(
        &mut self,
        topology_snapshot: &TopologySnapshot,
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

        let next_proposers = vote_recipients(topology_snapshot, self.local_shard, self.me, round);

        // Emit SignAndBroadcastBlockVote — the io_loop signs on the consensus
        // crypto pool, broadcasts, and feeds the signed vote back for local
        // VoteSet tracking via VerifiedBlockVoteReceived.
        vec![Action::SignAndBroadcastBlockVote {
            block_hash,
            parent_block_hash,
            height,
            round,
            timestamp,
            next_proposers,
        }]
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Vote Collection (Deferred Verification)
    // ═══════════════════════════════════════════════════════════════════════════

    /// Handle a locally-produced, pre-verified block vote. Skips the
    /// BLS batch path — the vote is admitted directly to the verified
    /// tally. Wire-arrived votes route through
    /// [`Self::on_unverified_block_vote`].
    #[instrument(skip(self, vote), fields(
        height = vote.height().inner(),
        voter = ?vote.voter(),
        block_hash = ?vote.block_hash()
    ))]
    pub fn on_verified_block_vote(
        &mut self,
        topology_snapshot: &TopologySnapshot,
        vote: Verified<BlockVote>,
    ) -> Vec<Action> {
        trace!(
            validator = ?self.me,
            voter = ?vote.voter(),
            block_hash = ?vote.block_hash(),
            "Received pre-verified block vote"
        );

        let header_for_vote = self.pending_blocks.get_header(vote.block_hash());
        self.votes.accept_verified_vote(
            topology_snapshot,
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
    #[instrument(skip(self, vote), fields(
        height = vote.height().inner(),
        voter = ?vote.voter(),
        block_hash = ?vote.block_hash()
    ))]
    pub fn on_unverified_block_vote(
        &mut self,
        topology_snapshot: &TopologySnapshot,
        vote: BlockVote,
    ) -> Vec<Action> {
        trace!(
            validator = ?self.me,
            voter = ?vote.voter(),
            block_hash = ?vote.block_hash(),
            "Received block vote"
        );

        let header_for_vote = self.pending_blocks.get_header(vote.block_hash());
        self.votes.accept_unverified_vote(
            topology_snapshot,
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
        topology_snapshot: &TopologySnapshot,
        signal: ReadySignal,
    ) {
        if topology_snapshot
            .committee_index_for_shard(self.local_shard, signal.validator_id())
            .is_none()
        {
            return;
        }
        if signal.height_window_end() < self.committed_height {
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
        topology_snapshot: &TopologySnapshot,
        block_hash: BlockHash,
        qc: Option<Verified<QuorumCertificate>>,
        verified_votes: Vec<(usize, Verified<BlockVote>, VotePower)>,
    ) -> Vec<Action> {
        if let Some(qc) = qc {
            info!(
                block_hash = ?block_hash,
                height = qc.height().inner(),
                signers = qc.signer_count(),
                "QC built successfully"
            );
            self.votes.mark_qc_built(block_hash);
            if let Some(block) = self.pending_blocks.get_block(block_hash) {
                self.populate_certified_for(block_hash, Arc::clone(block), qc.clone());
            }
            return vec![Action::Continuation(
                ProtocolEvent::QuorumCertificateFormed { block_hash, qc },
            )];
        }

        // Per-vote: view sync + equivocation tracking. Tracking runs only on
        // verified votes so a forged vote can't pre-empt a legitimate one.
        let validator_id = self.me;
        for (_, vote, _) in &verified_votes {
            let old_view = self.view_change.view;
            if self.view_change.sync_to_observed_round(vote.round()) {
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
        self.votes
            .maybe_trigger_verification(topology_snapshot, self.local_shard, block_hash)
    }

    /// Handle QC signature verification result.
    ///
    /// Called when the runner completes `Action::VerifyQcSignature`.
    /// On success, the verified QC rides in the event payload — no
    /// separate cache lookup needed.
    #[instrument(skip(self, result), fields(block_hash = ?block_hash, valid = result.is_ok()))]
    pub fn on_qc_signature_verified(
        &mut self,
        topology_snapshot: &TopologySnapshot,
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
                    self.try_apply_verified_synced_blocks(topology_snapshot)
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
                // Remove the pending block since we can't trust it; surface any
                // orphaned local-DA fetches so the FSM releases their slots.
                let _ = is_valid; // tracked by `verification.on_qc_verified` for diagnostics
                return self.remove_pending_block(block_hash).into_iter().collect();
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
        if let Some(parent_block) = self.pending_blocks.get_block(parent_block_hash) {
            let parent_block = Arc::clone(parent_block);
            self.populate_certified_for(parent_block_hash, parent_block, verified_qc.clone());
        }

        // The parent QC is now provably authentic; perform the adoption
        // that `absorb_parent_qc_from_header` deferred. Safe to run before
        // `try_vote_on_block` — adoption only mutates `latest_qc` /
        // commit-related state, not the per-block voting machinery.
        let mut actions = Vec::new();
        if self.has_complete_block_at_height(verified_qc.height()) {
            actions.extend(self.try_adopt_verified_qc(&verified_qc));
        }

        // QC is valid - proceed to vote on the block
        let height = header.height();
        let round = header.round();
        actions.extend(self.try_vote_on_block(topology_snapshot, block_hash, height, round));
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
        topology_snapshot: &TopologySnapshot,
        block_hash: BlockHash,
        result: Result<Verified<TransactionRoot>, TxRootVerifyError>,
    ) -> Vec<Action> {
        let valid = result.is_ok();
        if let Ok(verified) = result {
            self.verification
                .record_transaction_root_result(block_hash, verified);
        }
        self.on_root_verified_impl(
            topology_snapshot,
            VerificationKind::TransactionRoot,
            block_hash,
            valid,
        )
    }

    /// Handle a completed certificate-root verification.
    pub fn on_certificate_root_verified(
        &mut self,
        topology_snapshot: &TopologySnapshot,
        block_hash: BlockHash,
        result: Result<Verified<CertificateRoot>, CertRootVerifyError>,
    ) -> Vec<Action> {
        let valid = result.is_ok();
        if let Ok(verified) = result {
            self.verification
                .record_certificate_root_result(block_hash, verified);
        }
        self.on_root_verified_impl(
            topology_snapshot,
            VerificationKind::CertificateRoot,
            block_hash,
            valid,
        )
    }

    /// Handle a completed local-receipt-root verification.
    pub fn on_local_receipt_root_verified(
        &mut self,
        topology_snapshot: &TopologySnapshot,
        block_hash: BlockHash,
        result: Result<Verified<LocalReceiptRoot>, LocalReceiptRootVerifyError>,
    ) -> Vec<Action> {
        let valid = result.is_ok();
        if let Ok(verified) = result {
            self.verification
                .record_local_receipt_root_result(block_hash, verified);
        }
        self.on_root_verified_impl(
            topology_snapshot,
            VerificationKind::LocalReceiptRoot,
            block_hash,
            valid,
        )
    }

    /// Handle a completed provisions-root verification.
    pub fn on_provisions_root_verified(
        &mut self,
        topology_snapshot: &TopologySnapshot,
        block_hash: BlockHash,
        result: Result<Verified<ProvisionsRoot>, ProvisionRootVerifyError>,
    ) -> Vec<Action> {
        let valid = result.is_ok();
        if let Ok(verified) = result {
            self.verification
                .record_provisions_root_result(block_hash, verified);
        }
        self.on_root_verified_impl(
            topology_snapshot,
            VerificationKind::ProvisionRoot,
            block_hash,
            valid,
        )
    }

    /// Handle a completed provision-tx-roots verification.
    pub fn on_provision_tx_roots_verified(
        &mut self,
        topology_snapshot: &TopologySnapshot,
        block_hash: BlockHash,
        result: Result<Verified<ProvisionTxRootsMap>, ProvisionTxRootsVerifyError>,
    ) -> Vec<Action> {
        let valid = result.is_ok();
        if let Ok(verified) = result {
            self.verification
                .record_provision_tx_roots_result(block_hash, verified);
        }
        self.on_root_verified_impl(
            topology_snapshot,
            VerificationKind::ProvisionTxRoots,
            block_hash,
            valid,
        )
    }

    /// Handle a completed beacon-witness-root verification.
    pub fn on_beacon_witness_root_verified(
        &mut self,
        topology_snapshot: &TopologySnapshot,
        block_hash: BlockHash,
        result: Result<Verified<BeaconWitnessRoot>, BeaconWitnessRootVerifyError>,
    ) -> Vec<Action> {
        let valid = result.is_ok();
        if let Ok(verified) = result {
            self.verification
                .record_beacon_witness_root_result(block_hash, verified);
        }
        self.on_root_verified_impl(
            topology_snapshot,
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
        topology_snapshot: &TopologySnapshot,
        block_hash: BlockHash,
        result: Result<Verified<StateRoot>, StateRootVerifyError>,
    ) -> Vec<Action> {
        let valid = result.is_ok();
        if let Ok(verified) = result {
            self.verification
                .record_state_root_result(block_hash, verified);
        }
        self.on_root_verified_impl(
            topology_snapshot,
            VerificationKind::StateRoot,
            block_hash,
            valid,
        )
    }

    /// Shared completion logic for the per-kind root-verified handlers above.
    /// If invalid, the block is rejected. If valid and every other root for
    /// the block has been verified, proceeds to vote.
    #[instrument(skip(self), fields(block_hash = ?block_hash, ?kind, valid = valid))]
    fn on_root_verified_impl(
        &mut self,
        topology_snapshot: &TopologySnapshot,
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
            return self.remove_pending_block(block_hash).into_iter().collect();
        }

        let mut actions = Vec::new();
        if kind == VerificationKind::BeaconWitnessRoot {
            actions.extend(self.retry_deferred_beacon_witness(topology_snapshot, block_hash));
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
            actions.extend(self.create_vote(topology_snapshot, block_hash, height, round));
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
        self.try_two_chain_commit(qc.as_ref(), CommitSource::Aggregator)
    }

    /// Populate `verified_certified_blocks[block_hash]` so the 2-chain
    /// commit can thread a typed handle. Tries the local-assembly path
    /// first via [`VerificationPipeline::record_qc_assembly`]; falls
    /// back to [`Verified::<CertifiedBlock>::from_qc_attestation`] when
    /// the local per-root state isn't complete (typical for an
    /// aggregator that collected 2f+1 votes without voting itself, so
    /// never ran the per-root verifiers locally — the QC's BFT
    /// majority attests they pass).
    fn populate_certified_for(
        &mut self,
        block_hash: BlockHash,
        block: Arc<Block>,
        qc: Verified<QuorumCertificate>,
    ) {
        self.verification.track_pending_assembly(Arc::clone(&block));
        if self
            .verification
            .record_qc_assembly(block_hash, qc.clone())
            .is_some()
        {
            return;
        }
        // Local assembly couldn't complete — synthesize via the
        // BFT-transitive trust gate. SAFETY: `qc` is verified and
        // certifies `block_hash`; the QC's signers ran the per-root
        // verifiers at the source committee.
        let block = Arc::unwrap_or_clone(block);
        let certified_raw = CertifiedBlock::new_unchecked(block, qc.clone());
        match Verified::<CertifiedBlock>::from_qc_attestation(certified_raw, qc) {
            Ok(certified) => {
                self.verification
                    .insert_verified_certified_block(block_hash, Arc::new(certified));
            }
            Err(e) => {
                warn!(
                    ?block_hash,
                    ?e,
                    "Verified<CertifiedBlock> linkage check failed at populate"
                );
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
        topology_snapshot: &TopologySnapshot,
        parent_hash: BlockHash,
    ) -> Vec<Action> {
        let children = self
            .verification
            .take_deferred_beacon_witness_children(parent_hash);
        let mut actions = Vec::new();
        for child_hash in children {
            let Some(child_block) = self.pending_blocks.get_block(child_hash).map(Arc::clone)
            else {
                continue;
            };
            actions.extend(self.verification.initiate_beacon_witness_root_verification(
                child_hash,
                &child_block,
                &self.pending_blocks,
                &self.beacon_witness_accumulator,
                self.committed_hash,
                self.local_shard,
                topology_snapshot,
            ));
        }
        actions
    }

    /// Handle proposal built by the runner.
    ///
    /// Called when the runner completes `Action::BuildProposal`. The runner has
    /// computed the state root, built the complete block, and cached the `WriteBatch`
    /// for efficient commit later.
    #[instrument(skip(self, block, manifest, finalized_waves), fields(height = %height.inner(), round = round.inner()))]
    #[allow(clippy::too_many_arguments)]
    pub fn on_proposal_built(
        &mut self,
        topology_snapshot: &TopologySnapshot,
        height: BlockHeight,
        round: Round,
        block: &Block,
        block_hash: BlockHash,
        manifest: &BlockManifest,
        finalized_waves: Vec<Arc<Verifiable<FinalizedWave>>>,
        provisions: Vec<Arc<Verifiable<Provisions>>>,
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
        actions.extend(self.create_vote(topology_snapshot, block_hash, height, round));

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
    pub fn on_block_persisted(&mut self, block_height: BlockHeight) -> Vec<Action> {
        self.verification.on_block_persisted(block_height);

        // Auto-resume from sync the moment persistence catches up to the
        // sync target: a single event carries the signal, so there's no
        // room for ordering races between sync completion and persistence.
        if self.block_sync.is_syncing()
            && let Some(target) = self.block_sync.sync_target_height()
            && block_height >= target
        {
            return self.on_block_sync_complete();
        }
        vec![]
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
    #[instrument(skip(self, qc, ready_txs, finalized_waves), fields(
        height = qc.height().inner(),
        block_hash = ?block_hash
    ))]
    #[allow(clippy::too_many_arguments)]
    pub fn on_qc_formed(
        &mut self,
        topology_snapshot: &TopologySnapshot,
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
                self.advance_view_for_qc(qc.as_ref());
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

        actions.extend(self.try_two_chain_commit(qc.as_ref(), CommitSource::Aggregator));

        // Propose the next block immediately — under the 2-chain commit rule,
        // block N+1 is what certifies block N, so any gap in proposing N+1
        // stalls the finalization of N and everything pending behind it.
        // `try_propose` handles the proposer-rotation / backpressure checks.
        actions.extend(self.try_propose(topology_snapshot, ready_txs, finalized_waves, provisions));

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
    fn try_two_chain_commit(&self, qc: &QuorumCertificate, source: CommitSource) -> Vec<Action> {
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
    #[instrument(skip(self, certified), fields(
        height = certified.block().height().inner(),
        block_hash = ?certified.block().hash()
    ))]
    pub fn on_block_ready_to_commit(
        &mut self,
        topology_snapshot: &TopologySnapshot,
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
        self.commit_block_and_buffered(topology_snapshot, certified, source)
    }

    /// Common bookkeeping for committing a block (shared between consensus and
    /// sync paths). Updates `committed_height`/`hash`, registers committed
    /// artifacts in the dedup index, resets backoff tracking, and cleans up
    /// old state. Returns the abandon-fetch action from the post-commit
    /// sweep when there are orphaned pending-block fetches to cancel.
    fn record_block_committed(
        &mut self,
        topology_snapshot: &TopologySnapshot,
        block: &Block,
        block_hash: BlockHash,
        commit_ts: WeightedTimestamp,
    ) -> (Option<Action>, BeaconWitnessCommit) {
        let height = block.height();

        self.committed_height = height;
        self.committed_hash = block_hash;
        self.committed_ts = commit_ts;
        self.committed_state_root = block.header().state_root();

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
        let missed = missed_proposals_since_prev_commit(
            self.local_shard,
            height,
            parent_round,
            block.header().round(),
            topology_snapshot,
        );
        let new_leaves = derive_leaves(&receipts, &missed, manifest.ready_signals().as_slice());
        let starting_leaf_index = self.beacon_witness_accumulator.leaf_count();
        self.beacon_witness_accumulator.commit_append(&new_leaves);
        let leaf_count_at_block_end = self.beacon_witness_accumulator.leaf_count();
        let witness = BeaconWitnessCommit {
            starting_leaf_index,
            leaves: new_leaves,
            leaf_count_at_block_end,
        };
        self.ready_signal_pool.evict_expired(height);

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
        topology_snapshot: &TopologySnapshot,
        certified: Arc<Verified<CertifiedBlock>>,
        source: CommitSource,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        let mut next = Some((certified, source));

        while let Some((certified, source)) = next.take() {
            let Some(committed_height) =
                self.commit_one_buffered_block(topology_snapshot, &certified, source, &mut actions)
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
        actions.extend(self.try_drain_buffered_synced_blocks(topology_snapshot));

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
        topology_snapshot: &TopologySnapshot,
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
        let weighted_ts = certified.qc_verified().weighted_timestamp();

        let (abandon, witness) = self.record_block_committed(
            topology_snapshot,
            certified.block(),
            block_hash,
            weighted_ts,
        );
        if let Some(action) = abandon {
            actions.push(action);
        }
        // The just-committed block's leaves are now folded into the
        // committed accumulator and `committed_hash` advanced to it,
        // so any beacon-witness verifications previously parked on
        // this hash can re-walk past it.
        actions.extend(self.retry_deferred_beacon_witness(topology_snapshot, block_hash));
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
        topology_snapshot: &TopologySnapshot,
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
            let shard = certified.qc().shard_group_id();
            let (block, _) = certified.into_parts();
            let verified_qc = Verified::<QuorumCertificate>::genesis(shard);
            return self.apply_synced_block(topology_snapshot, block, verified_qc);
        }

        // Quorum-power gate: `VerifyQcSignature` only checks the BLS
        // aggregation, not whether the signers represent ≥ 2f+1 of voting
        // power. Without this check a single Byzantine signer suffices to
        // pass and fork the local chain. Mirrors the consensus-path gate
        // in `validate_header`.
        if !qc_has_local_quorum_power(topology_snapshot, self.local_shard, certified.qc()) {
            warn!(
                height = certified.block().height().inner(),
                signers = certified.qc().signers().count(),
                "Synced block QC lacks quorum power — rejecting"
            );
            return vec![];
        }

        let Some(public_keys) = committee_public_keys(topology_snapshot, self.local_shard) else {
            warn!("Failed to collect public keys for synced block QC verification");
            return vec![];
        };
        let Some(voting_powers) = committee_voting_powers(topology_snapshot, self.local_shard)
        else {
            warn!("Failed to collect voting powers for synced block QC verification");
            return vec![];
        };
        let quorum_threshold =
            VotePower::quorum_threshold(topology_snapshot.voting_power_for_shard(self.local_shard));

        vec![self.block_sync.register_for_verification(
            certified,
            public_keys,
            voting_powers,
            quorum_threshold,
        )]
    }

    /// Try to drain buffered synced blocks in sequential order. Asks
    /// [`BlockSyncManager::next_submitable`] which blocks are eligible — the
    /// coordinator just dispatches each for QC verification.
    fn try_drain_buffered_synced_blocks(
        &mut self,
        topology_snapshot: &TopologySnapshot,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        let blocks = self.block_sync.next_submitable(
            self.committed_height,
            self.config.max_parallel_sync_verifications,
        );
        for certified in blocks {
            actions.extend(self.submit_synced_block_for_verification(topology_snapshot, certified));
        }
        actions
    }

    /// Apply a synced block after QC verification (or for genesis QC).
    ///
    /// Commits the block immediately: advances `committed_height` and emits
    /// `CommitBlockByQcOnly` which the `io_loop` handles synchronously (inline
    /// JMT computation + persist + fsync). The synchronous path guarantees
    /// the parent's JMT snapshot is on disk before any child's state-root
    /// verification starts, so there's no async `VerifyStateRoot` dispatch or
    /// `PreparedCommit` rendezvous to coordinate.
    fn apply_synced_block(
        &mut self,
        topology_snapshot: &TopologySnapshot,
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
            "Applying synced block"
        );

        // Capture parent state BEFORE record_block_committed advances heights.
        let parent_state_root = self
            .chain_view()
            .parent_state_root(block.header().parent_block_hash());
        let parent_block_height = self.committed_height;

        // Advance committed_height. The QC is the proof of commit — same
        // timing as the consensus path.
        let (_, witness) = self.record_block_committed(
            topology_snapshot,
            &block,
            block_hash,
            verified_qc.weighted_timestamp(),
        );

        // Track sync progress for the loop iterator.
        self.block_sync.set_sync_applied_height(height);

        // Update latest QC if this one is newer (by round).
        if self
            .latest_qc
            .as_ref()
            .is_none_or(|existing| verified_qc.round() > existing.round())
        {
            self.advance_view_for_qc(verified_qc.as_ref());
            self.latest_qc = Some(verified_qc.clone());
        }

        // Adopt the parent_qc from the block header if it's newer still.
        // The synced block's QC BFT-transitively attests every embedded
        // wave's per-EC signature predicate via the source committee's
        // signature over `certificate_root` + `local_receipt_root`.
        let synced_waves: Vec<Arc<Verifiable<FinalizedWave>>> = block
            .certificates()
            .iter()
            .map(|fw| {
                let verified = Verifiable::verified(fw.as_ref())
                    .cloned()
                    .unwrap_or_else(|| {
                        Verified::<FinalizedWave>::from_committed_block(fw.as_unverified().clone())
                    });
                Arc::new(verified.into())
            })
            .collect();
        let parent_qc_round = block.header().parent_qc().round();
        let parent_qc_not_genesis = !block.header().parent_qc().is_genesis();

        // Assemble the synced block into a `Verified<CertifiedBlock>` via
        // the BFT-transitive trust gate: the source committee's QC
        // attests to the block's per-root verifications.
        let certified_raw = CertifiedBlock::new_unchecked(block, verified_qc.clone());
        let certified =
            match Verified::<CertifiedBlock>::from_qc_attestation(certified_raw, verified_qc) {
                Ok(c) => Arc::new(c),
                Err(e) => {
                    warn!(?block_hash, ?e, "synced block QC linkage failed");
                    return vec![];
                }
            };

        if parent_qc_not_genesis
            && self
                .latest_qc
                .as_ref()
                .is_none_or(|existing| parent_qc_round > existing.round())
        {
            let verified_parent = certified.parent_qc_attested();
            self.advance_view_for_qc(verified_parent.as_ref());
            self.latest_qc = Some(verified_parent);
        }

        let mut actions = vec![Action::CommitBlockByQcOnly {
            certified,
            parent_state_root,
            parent_block_height,
            source: CommitSource::Sync,
            witness,
        }];

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
        topology_snapshot: &TopologySnapshot,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        while let Some((block, verified_qc)) =
            self.block_sync.take_next_verified(self.committed_height)
        {
            actions.extend(self.apply_synced_block(topology_snapshot, block, verified_qc));
        }
        actions.extend(self.try_drain_buffered_synced_blocks(topology_snapshot));
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
    fn enter_round(&mut self, topology_snapshot: &TopologySnapshot) -> Vec<Action> {
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
        if topology_snapshot.proposer_for(self.local_shard, self.view_change.view) == self.me {
            info!(
                validator = ?self.me,
                height = height.inner(),
                new_round = self.view_change.view.inner(),
                "We are the new proposer after round advance - building block"
            );

            let mut actions = self.build_and_broadcast_fallback_block(
                topology_snapshot,
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
            .unwrap_or_else(|| QuorumCertificate::genesis(self.local_shard))
    }

    /// Broadcast our timeout for `round` (carrying our `high_qc`) to the
    /// committee, which tallies it. The round timer drives this on every fire,
    /// so a timeout lost to a partition is retransmitted until a 2f+1 quorum
    /// forms — without retransmission a healed partition never re-collects the
    /// shares it dropped and the chain wedges.
    fn broadcast_timeout(
        &mut self,
        topology_snapshot: &TopologySnapshot,
        round: Round,
    ) -> Vec<Action> {
        self.last_timed_out_round = Some(round);
        // A timed-out round is never voted: bump `last_voted_round` so the
        // safe-vote rule refuses any block that arrives at this round after we
        // gave up on it (Rule 1).
        self.last_voted_round = self.last_voted_round.max(round);
        let recipients: Vec<ValidatorId> = topology_snapshot
            .committee_for_shard(self.local_shard)
            .iter()
            .copied()
            .filter(|v| *v != self.me)
            .collect();
        vec![Action::SignAndBroadcastTimeout {
            round,
            high_qc: self.high_qc(),
            recipients,
        }]
    }

    /// Bracha-amplify: broadcast our own timeout for `round` the first time we
    /// hear f+1 of them, so every honest replica eventually times out. Unlike
    /// the timer-driven retransmit, this fires at most once per round — a
    /// replica that already broadcast (via its timer or an earlier amplify)
    /// stays quiet.
    fn amplify_timeout(
        &mut self,
        topology_snapshot: &TopologySnapshot,
        round: Round,
    ) -> Vec<Action> {
        if self.last_timed_out_round == Some(round) {
            return Vec::new();
        }
        self.broadcast_timeout(topology_snapshot, round)
    }

    /// Voting power of `voter` iff it belongs to the local shard committee —
    /// the bound the pacemaker tallies against, mirroring the vote path
    /// (`VoteKeeper`). `None` for any validator outside the committee, so a
    /// globally-registered validator from another shard never counts toward the
    /// timeout thresholds (whose total is committee-scoped).
    fn committee_timeout_power(
        &self,
        topology_snapshot: &TopologySnapshot,
        voter: ValidatorId,
    ) -> Option<VotePower> {
        topology_snapshot.committee_index_for_shard(self.local_shard, voter)?;
        topology_snapshot.voting_power(voter)
    }

    /// Screen a wire timeout, then delegate its BLS share verification to the
    /// consensus crypto pool. The verified share returns as
    /// `ProtocolEvent::VerifiedTimeoutReceived` and is tallied by
    /// [`Self::on_verified_timeout`] — keeping per-timeout pairing checks off
    /// the shard loop thread during a view change, as the vote path does.
    pub fn on_unverified_timeout(
        &mut self,
        topology_snapshot: &TopologySnapshot,
        timeout: &Timeout,
    ) -> Vec<Action> {
        if timeout.shard_group_id() != self.local_shard {
            return Vec::new();
        }
        // Only this shard's committee drives its pacemaker. Reject outsiders
        // before spending a BLS verify on them; `on_verified_timeout` re-checks
        // the same bound for locally echoed timeouts.
        if self
            .committee_timeout_power(topology_snapshot, timeout.voter())
            .is_none()
        {
            warn!(validator = ?self.me, voter = ?timeout.voter(), "Dropping timeout from non-committee validator");
            return Vec::new();
        }
        // Skip rounds we've advanced past and voters already tallied: such a
        // share would verify and then be dropped by `on_verified_timeout`, so
        // screen it here rather than spend a pairing check. Mirrors the vote
        // path, which drops a seen voter before delegating crypto.
        if timeout.round() < self.view_change.view
            || self.timeouts.contains(timeout.round(), timeout.voter())
        {
            return Vec::new();
        }
        let Some(voter_public_key) = topology_snapshot.public_key(timeout.voter()) else {
            return Vec::new();
        };
        vec![Action::VerifyTimeout {
            timeout: timeout.clone(),
            voter_public_key,
        }]
    }

    /// Tally a verified timeout: amplify at f+1 (Bracha), advance at 2f+1.
    pub fn on_verified_timeout(
        &mut self,
        topology_snapshot: &TopologySnapshot,
        timeout: Verified<Timeout>,
    ) -> Vec<Action> {
        let round = timeout.round();
        // Ignore timeouts for rounds we've already advanced past.
        if round < self.view_change.view {
            return Vec::new();
        }
        // A verified BLS share proves who signed, not that the signer sits in
        // the committee whose 2f+1 the pacemaker measures against. Restrict the
        // tally to the local committee: the quorum total is committee-scoped, so
        // a globally-registered validator from another shard must not count
        // toward the f+1 / 2f+1 thresholds.
        let Some(power) = self.committee_timeout_power(topology_snapshot, timeout.voter()) else {
            warn!(validator = ?self.me, voter = ?timeout.voter(), "Dropping timeout from non-committee validator");
            return Vec::new();
        };
        if !self.timeouts.record(timeout, power) {
            return Vec::new();
        }

        let total = topology_snapshot.voting_power_for_shard(self.local_shard);
        let seen = self.timeouts.power(round);
        let mut actions = Vec::new();

        // Bracha amplification: f+1 timeouts seen → broadcast our own.
        if VotePower::has_one_third(seen, total) {
            actions.extend(self.amplify_timeout(topology_snapshot, round));
        }

        // 2f+1 timeouts → adopt the quorum-max high_qc and advance together.
        if VotePower::has_quorum(seen, total) {
            actions.extend(self.advance_on_timeout_quorum(topology_snapshot, round));
        }

        actions
    }

    /// On a 2f+1 timeout quorum for `round`: adopt the quorum-max `high_qc`
    /// (verified) so the next leader extends it, then advance to `round + 1`.
    fn advance_on_timeout_quorum(
        &mut self,
        topology_snapshot: &TopologySnapshot,
        round: Round,
    ) -> Vec<Action> {
        let mut actions = self.adopt_timeout_quorum_high_qc(topology_snapshot, round);
        if self.view_change.advance_to(round.next()) {
            // Reset the timeout baseline so the new leader gets a full window.
            self.view_change.record_leader_activity(self.now);
            self.timeouts.prune_below(self.view_change.view);
            actions.extend(self.enter_round(topology_snapshot));
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
        topology_snapshot: &TopologySnapshot,
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
            let Some(verified) = self.verify_qc_sync(topology_snapshot, &candidate) else {
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
        topology_snapshot: &TopologySnapshot,
        qc: &QuorumCertificate,
    ) -> Option<Verified<QuorumCertificate>> {
        let public_keys = committee_public_keys(topology_snapshot, self.local_shard)?;
        let voting_powers = committee_voting_powers(topology_snapshot, self.local_shard)?;
        let ctx = QcContext {
            network: topology_snapshot.network(),
            public_keys: &public_keys,
            voting_powers: &voting_powers,
            quorum_threshold: topology_snapshot.quorum_threshold_for_shard(self.local_shard),
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
    fn advance_view_for_qc(&mut self, qc: &QuorumCertificate) {
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
    #[instrument(skip(self, topology_snapshot, txs), fields(count = txs.len()))]
    pub fn on_transactions_admitted(
        &mut self,
        topology_snapshot: &TopologySnapshot,
        txs: &[Arc<Verified<RoutableTransaction>>],
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        for tx in txs {
            let wrapped: Arc<Verifiable<RoutableTransaction>> =
                Arc::new(Verifiable::from((**tx).clone()));
            for block_hash in self.pending_blocks.receive_transaction(&wrapped) {
                actions.extend(self.dispatch_block_complete(topology_snapshot, block_hash));
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
        topology_snapshot: &TopologySnapshot,
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
                actions.extend(self.dispatch_block_complete(topology_snapshot, block_hash));
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
        topology_snapshot: &TopologySnapshot,
        provisions: &[Arc<Verifiable<Provisions>>],
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        for batch in provisions {
            for block_hash in self.pending_blocks.receive_provision(batch) {
                actions.extend(self.dispatch_block_complete(topology_snapshot, block_hash));
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
        topology_snapshot: &TopologySnapshot,
        block_hash: BlockHash,
    ) -> Vec<Action> {
        debug!(
            validator = ?self.me,
            block_hash = ?block_hash,
            "Pending block completed"
        );
        self.trigger_qc_verification_or_vote(topology_snapshot, block_hash)
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Cleanup
    // ═══════════════════════════════════════════════════════════════════════════

    /// Clean up old state after commit. Drops pending-block, vote, and
    /// commit-tracking entries at or below `committed_height`. Returns an
    /// optional `AbandonFetch` carrying the orphaned local-provision fetch
    /// ids from the dropped pending blocks so the FSM releases their slots.
    fn cleanup_old_state(&mut self, committed_height: BlockHeight) -> Option<Action> {
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

        (!orphaned.is_empty())
            .then(|| Action::AbandonFetch(FetchAbandon::LocalProvisions { hashes: orphaned }))
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
    pub fn check_sync_health(&mut self) -> Vec<Action> {
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
                self.start_block_sync(target_height)
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Accessors
    // ═══════════════════════════════════════════════════════════════════════════

    /// Drain state root verifications that are ready to dispatch. Thin
    /// wrapper over [`VerificationPipeline::drain_ready_state_root_verifications`]
    /// that supplies the chain view and pending-block map.
    pub fn drain_ready_state_root_verifications(
        &mut self,
        local_shard: ShardGroupId,
    ) -> Vec<ReadyStateRootVerification> {
        let chain = ChainView::new(
            local_shard,
            self.committed_height,
            self.committed_hash,
            self.committed_state_root,
            self.latest_qc.as_ref(),
            &self.pending_blocks,
        );
        self.verification
            .drain_ready_state_root_verifications(&chain)
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
    /// Returns an `AbandonFetch` for the dropped block's outstanding
    /// missing-provision fetches when there were any — without this the
    /// FSM's `in_flight` entries pinned for this block would linger past
    /// the block's lifetime, eating slots in the `max_in_flight` cap.
    fn remove_pending_block(&mut self, block_hash: BlockHash) -> Option<Action> {
        let pending = self.pending_blocks.remove(block_hash)?;
        let hashes = pending.missing_provisions();
        (!hashes.is_empty()).then(|| Action::AbandonFetch(FetchAbandon::LocalProvisions { hashes }))
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

    /// Check if we are the proposer for the current round.
    #[must_use]
    pub fn is_current_proposer(&self, topology_snapshot: &TopologySnapshot) -> bool {
        topology_snapshot.proposer_for(self.local_shard, self.view_change.view) == self.me
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
    pub fn will_propose_next(&self, topology_snapshot: &TopologySnapshot) -> bool {
        let round = self.view_change.view;
        topology_snapshot.proposer_for(self.local_shard, round) == self.me
            && self.last_voted_round < round
    }
}

#[cfg(test)]
mod tests {

    use hyperscale_core::Action;
    use hyperscale_types::{
        BeaconWitnessLeafCount, BeaconWitnessRoot, Bls12381G1PrivateKey, BoundedVec,
        CertificateRoot, Hash, InFlightCount, LocalReceiptRoot, NetworkDefinition, ProvisionsRoot,
        RoutableTransaction, ShardGroupId, SignerBitfield, TopologySnapshot, TransactionRoot,
        ValidatorId, ValidatorInfo, ValidatorSet, VotePower, WeightedTimestamp,
        generate_bls_keypair, test_utils, zero_bls_signature,
    };

    use super::*;
    use crate::validation::validate_no_duplicate_transactions;

    fn install_complete_block(state: &mut ShardCoordinator, block: &Block) {
        let mut pending =
            PendingBlock::from_complete_block(block, vec![], vec![], vec![], LocalTimestamp::ZERO);
        pending
            .construct_block()
            .expect("complete block constructs cleanly");
        state.pending_blocks.insert(pending);
    }

    fn make_test_state() -> (ShardCoordinator, TopologySnapshot) {
        make_test_state_with_validators(4)
    }

    fn make_test_state_with_validators(n: usize) -> (ShardCoordinator, TopologySnapshot) {
        make_test_state_with_config(n, ShardConsensusConfig::default())
    }

    fn make_test_state_with_config(
        n: usize,
        config: ShardConsensusConfig,
    ) -> (ShardCoordinator, TopologySnapshot) {
        let keys: Vec<Bls12381G1PrivateKey> = (0..n).map(|_| generate_bls_keypair()).collect();

        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| ValidatorInfo {
                validator_id: ValidatorId::new(i as u64),
                public_key: k.public_key(),
                voting_power: VotePower::new(1),
            })
            .collect();
        let validator_set = ValidatorSet::new(validators);
        let topology = TopologySnapshot::new(NetworkDefinition::simulator(), 1, validator_set);

        let state = ShardCoordinator::new(
            ValidatorId::new(0),
            ShardGroupId::new(0),
            config,
            RecoveredState::default(),
        );
        (state, topology)
    }

    #[test]
    fn test_proposer_rotation() {
        // proposer_for = round % committee_size
        let (_state, topology) = make_test_state();
        let shard = ShardGroupId::new(0);
        assert_eq!(
            topology.proposer_for(shard, Round::new(0)),
            ValidatorId::new(0)
        );
        assert_eq!(
            topology.proposer_for(shard, Round::new(1)),
            ValidatorId::new(1)
        );
        assert_eq!(
            topology.proposer_for(shard, Round::new(2)),
            ValidatorId::new(2)
        );
        assert_eq!(
            topology.proposer_for(shard, Round::new(3)),
            ValidatorId::new(3)
        );
    }

    #[test]
    fn test_should_propose() {
        // Local validator is ValidatorId::new(0) — only proposes when proposer_for = 0.
        let (state, topology) = make_test_state();
        let shard = state.local_shard;
        let me = state.me;
        assert_eq!(topology.proposer_for(shard, Round::new(0)), me);
        assert_ne!(topology.proposer_for(shard, Round::new(1)), me);
        assert_ne!(topology.proposer_for(shard, Round::new(2)), me);
    }

    fn make_header_at_height(height: BlockHeight, timestamp_ms: u64) -> BlockHeader {
        // Rounds increase per block, so the happy-path round equals the height;
        // the proposer is then committee[round % 4] = committee[height % 4].
        let round = Round::new(height.inner());
        BlockHeader::new(
            ShardGroupId::new(0),
            height,
            BlockHash::from_raw(Hash::from_bytes(b"parent")),
            QuorumCertificate::genesis(ShardGroupId::new(0)),
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
        )
    }

    fn make_test_qc(block_hash: BlockHash, height: BlockHeight) -> Verified<QuorumCertificate> {
        // SAFETY: synthetic test fixture, no real signature.
        Verified::<QuorumCertificate>::new_unchecked_for_test(QuorumCertificate::new(
            block_hash,
            ShardGroupId::new(0),
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
        let (mut state, topology) = make_multi_validator_state_at(1);
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
                __qc.shard_group_id(),
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
                __h.shard_group_id(),
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
            )
        };

        let actions = state.on_block_header(
            &topology,
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

    /// `absorb_parent_qc_from_header` must NOT mutate `latest_qc` until the
    /// parent QC's BLS signature has been verified — otherwise a Byzantine
    /// proposer can forge a signers-pass-but-signature-invalid QC and have
    /// us advance the chain (and the view, via `advance_view_for_qc`) on a
    /// non-existent quorum.
    #[test]
    fn test_header_with_unverified_parent_qc_does_not_update_latest_qc() {
        let (mut state, topology) = make_multi_validator_state_at(1);
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
                __qc.shard_group_id(),
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
                __h.shard_group_id(),
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
            )
        };

        let _ = state.on_block_header(
            &topology,
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
        let (mut state, topology) = make_multi_validator_state_at(1);
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
                __qc.shard_group_id(),
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
                __h.shard_group_id(),
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
            )
        };
        let block_hash = header.hash();

        let _ = state.on_block_header(
            &topology,
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
        let _ = state.on_qc_signature_verified(&topology, block_hash, Ok(verified));
        assert_eq!(
            state.latest_qc.as_deref().map(QuorumCertificate::height),
            Some(BlockHeight::new(1)),
            "successful verification must trigger the deferred adoption"
        );
    }

    #[test]
    fn test_qc_signature_verified_success_triggers_vote() {
        let (mut state, topology) = make_multi_validator_state_at(1);
        state.set_time(LocalTimestamp::from_millis(100_000));

        let parent_block = Block::Live {
            header: make_header_at_height(BlockHeight::new(1), 99_000),
            transactions: Arc::new(BoundedVec::new()),
            certificates: Arc::new(BoundedVec::new()),
            provisions: Arc::new(BoundedVec::new()),
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
                __qc.shard_group_id(),
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
                __h.shard_group_id(),
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
            )
        };
        let block_hash = header.hash();

        let _ = state.on_block_header(
            &topology,
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
        let after_qc = state.on_qc_signature_verified(&topology, block_hash, Ok(verified));
        assert!(
            !after_qc
                .iter()
                .any(|a| matches!(a, Action::SignAndBroadcastBlockVote { .. }))
        );

        // State root completes — beacon witness root still pending.
        let after_state = state.on_state_root_verified(
            &topology,
            block_hash,
            Ok(Verified::<StateRoot>::new_unchecked_for_test(
                StateRoot::ZERO,
            )),
        );
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
            &topology,
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
        let (mut state, topology) = make_multi_validator_state_at(1);
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
                __qc.shard_group_id(),
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
                __h.shard_group_id(),
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
            )
        };
        let block_hash = header.hash();

        let _ = state.on_block_header(
            &topology,
            &header,
            BlockManifest::default(),
            |_| None,
            |_| None,
            |_| None,
        );
        assert!(state.pending_blocks.contains_key(block_hash));

        let actions = state.on_qc_signature_verified(
            &topology,
            block_hash,
            Err(QcVerifyError::InvalidSignature),
        );
        assert!(actions.is_empty());
        assert!(!state.pending_blocks.contains_key(block_hash));
    }

    #[test]
    fn test_genesis_qc_skips_verification() {
        let (mut state, topology) = make_multi_validator_state_at(1);

        state.set_time(LocalTimestamp::from_millis(100_000));

        // Genesis QC has no signature — verification must be skipped, not queued.
        let header = {
            let __h = make_header_at_height(BlockHeight::new(1), 100_000);
            BlockHeader::new(
                __h.shard_group_id(),
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
            )
        };
        let actions = state.on_block_header(
            &topology,
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
    fn advance_one_round(state: &mut ShardCoordinator, topology: &TopologySnapshot) -> Vec<Action> {
        let next = state.view_change.view.next();
        state.view_change.advance_to(next);
        state.enter_round(topology)
    }

    #[test]
    fn test_enter_round_proposer_broadcasts() {
        // Rounds increase per block: a fresh state starts at view 1, and a
        // single advance moves to round 2. Local = ValidatorId::new(2) is the
        // proposer at round 2 since proposer_for(2) = committee[2 % 4] = 2.
        let (mut state, topology) = make_multi_validator_state_at(2);
        state.set_time(LocalTimestamp::from_millis(100_000));

        let actions = advance_one_round(&mut state, &topology);
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
    fn non_committee_timeout_is_not_tallied() {
        // The pacemaker's f+1 / 2f+1 thresholds are measured against the local
        // committee's power, so only committee members may contribute timeouts.
        // A globally-signed timeout from outside the committee must be dropped,
        // exactly as the vote path drops non-committee votes.
        let (mut state, topology) = make_test_state();
        let shard = ShardGroupId::new(0);
        let round = state.view();
        let net = NetworkDefinition::simulator();
        let mk = |voter: u64| {
            Verified::<Timeout>::sign_local(
                &net,
                shard,
                round,
                QuorumCertificate::genesis(shard),
                ValidatorId::new(voter),
                &generate_bls_keypair(),
            )
        };

        // Outsider (not in the 4-member committee): dropped, nothing recorded.
        assert!(state.on_verified_timeout(&topology, mk(9)).is_empty());
        assert_eq!(state.timeouts.power(round), VotePower::ZERO);

        // Committee member: recorded, power accrues.
        assert!(state.on_verified_timeout(&topology, mk(1)).is_empty());
        assert_eq!(state.timeouts.power(round), VotePower::new(1));

        // A second committee member reaches f+1 and amplifies. Had the outsider
        // counted, this threshold would have tripped one timeout earlier.
        let actions = state.on_verified_timeout(&topology, mk(2));
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::SignAndBroadcastTimeout { .. })),
            "f+1 committee timeouts should amplify",
        );
    }

    #[test]
    fn on_unverified_timeout_delegates_committee_share() {
        // Wire timeouts are screened on the shard loop thread, then their BLS
        // share is verified off-thread via `Action::VerifyTimeout`. Outsiders,
        // stale rounds, and already-tallied voters are dropped before delegating
        // — no pairing check is spent on a share that would be discarded.
        let (mut state, topology) = make_test_state();
        let shard = ShardGroupId::new(0);
        let round = state.view();
        let net = NetworkDefinition::simulator();
        let mk = |voter: u64, round: Round| {
            Timeout::new(
                &net,
                shard,
                round,
                QuorumCertificate::genesis(shard),
                ValidatorId::new(voter),
                &generate_bls_keypair(),
            )
        };

        // Committee member, current round: delegated for off-thread verify.
        let actions = state.on_unverified_timeout(&topology, &mk(1, round));
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::VerifyTimeout { .. })),
            "a fresh committee timeout should be delegated",
        );

        // Outsider and stale round: dropped without delegating crypto.
        assert!(
            state
                .on_unverified_timeout(&topology, &mk(9, round))
                .is_empty()
        );
        assert!(
            state
                .on_unverified_timeout(&topology, &mk(1, Round::INITIAL))
                .is_empty()
        );

        // Already tallied: a retransmit is screened out before re-verifying.
        state.timeouts.record(
            Verified::<Timeout>::sign_local(
                &net,
                shard,
                round,
                QuorumCertificate::genesis(shard),
                ValidatorId::new(2),
                &generate_bls_keypair(),
            ),
            VotePower::new(1),
        );
        assert!(
            state
                .on_unverified_timeout(&topology, &mk(2, round))
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
    fn make_multi_validator_state() -> (ShardCoordinator, TopologySnapshot) {
        make_multi_validator_state_at(0)
    }

    fn make_multi_validator_state_at(local_idx: u32) -> (ShardCoordinator, TopologySnapshot) {
        let (state, topology, _keys) = make_multi_validator_state_with_keys(local_idx);
        (state, topology)
    }

    fn make_multi_validator_state_with_keys(
        local_idx: u32,
    ) -> (
        ShardCoordinator,
        TopologySnapshot,
        Vec<Bls12381G1PrivateKey>,
    ) {
        let keys: Vec<Bls12381G1PrivateKey> = (0..4).map(|_| generate_bls_keypair()).collect();
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| ValidatorInfo {
                validator_id: ValidatorId::new(i as u64),
                public_key: k.public_key(),
                voting_power: VotePower::new(1),
            })
            .collect();
        let validator_set = ValidatorSet::new(validators);
        let topology = TopologySnapshot::new(NetworkDefinition::simulator(), 1, validator_set);
        let state = ShardCoordinator::new(
            ValidatorId::new(u64::from(local_idx)),
            ShardGroupId::new(0),
            ShardConsensusConfig::default(),
            RecoveredState::default(),
        );
        (state, topology, keys)
    }

    #[test]
    fn test_forged_vote_cannot_block_legitimate_validator() {
        // Forged votes are buffered pre-verification and never reach
        // received_votes_by_height, so a legitimate vote for a different block
        // from the same voter is not flagged as equivocation on verification.
        let (mut state, topology) = make_multi_validator_state();
        state.set_time(LocalTimestamp::from_millis(100_000));

        let height = BlockHeight::new(5);
        let voter = ValidatorId::new(2);
        let block_b = BlockHash::from_raw(Hash::from_bytes(b"legitimate_block"));
        let vote = BlockVote::from_parts(
            block_b,
            ShardGroupId::new(0),
            height,
            Round::new(0),
            voter,
            zero_bls_signature(),
            ProposerTimestamp::from_millis(100_000),
        );

        let _ = state.on_qc_result(
            &topology,
            block_b,
            None,
            vec![(
                0,
                Verified::<BlockVote>::new_unchecked_for_test(vote),
                VotePower::new(1),
            )],
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
        let (state, topology) = make_multi_validator_state();
        let header = make_header_at_height(BlockHeight::new(1), state.now.as_millis());

        assert!(
            validate_header(
                &topology,
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
        let (state, topology) = make_multi_validator_state();
        // proposer_for(1) = ValidatorId::new(1), but the header claims ValidatorId::new(3).
        let header = {
            let __h = make_header_at_height(BlockHeight::new(1), state.now.as_millis());
            BlockHeader::new(
                __h.shard_group_id(),
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
            )
        };

        let result = validate_header(
            &topology,
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
        let (mut state, topology) = make_test_state();
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
                __qc.shard_group_id(),
                __qc.height(),
                BlockHash::from_raw(Hash::from_bytes(b"block_2")),
                __qc.round(),
                __qc.signers().clone(),
                __qc.aggregated_signature(),
                __qc.weighted_timestamp(),
            ))
        };

        let actions = state.on_qc_formed(&topology, block_3_hash, &qc, &[], vec![], vec![]);

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
        let qc = QuorumCertificate::new(
            child_hash,
            ShardGroupId::new(0),
            BlockHeight::new(4),
            committable_hash,
            Round::new(0),
            SignerBitfield::empty(),
            zero_bls_signature(),
            WeightedTimestamp::from_millis(100_000),
        );

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

        let (mut state, topology) = make_test_state();
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

        let first = state.try_propose(&topology, &[], vec![], vec![]);
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

        let second = state.try_propose(&topology, &[], vec![], vec![]);
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

        let third = state.try_propose(&topology, &[], vec![], vec![]);
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

        let (mut state, topology) = make_multi_validator_state_at(0);
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
                __qc.shard_group_id(),
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
                __h.shard_group_id(),
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
            )
        };
        let actions1 = state.on_block_header(
            &topology,
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
                __h.shard_group_id(),
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
            )
        };
        let actions2 = state.on_block_header(
            &topology,
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

        let (mut state, topology) = make_multi_validator_state_at(0);
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
                __qc.shard_group_id(),
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
        // re-verifying a forged signature.
        let forged_qc = {
            let __qc = honest_qc;
            QuorumCertificate::new(
                __qc.block_hash(),
                __qc.shard_group_id(),
                __qc.height(),
                __qc.parent_block_hash(),
                __qc.round(),
                __qc.signers().clone(),
                __qc.aggregated_signature(),
                WeightedTimestamp::from_millis(123_456_789),
            )
        };
        let forged_header = {
            let __h = make_header_at_height(BlockHeight::new(2), 100_000);
            BlockHeader::new(
                __h.shard_group_id(),
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
            )
        };

        let actions = state.on_block_header(
            &topology,
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
        let (mut state, topology) = make_test_state();
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
                __qc.shard_group_id(),
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
        let actions = state.try_propose(&topology, &ready_txs, vec![], vec![]);

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
        let (mut state, topology) = make_test_state();
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
                __qc.shard_group_id(),
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

        let actions = state.try_propose(&topology, &[], vec![], vec![]);
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
    fn test_sync_complete_exits_sync_mode() {
        let (mut state, _topology) = make_test_state();
        state.set_block_syncing(true);
        assert!(state.is_block_syncing());

        // Fresh state has no pending blocks, so on_sync_complete returns
        // no actions — the remote-header / provision flushes happen in
        // NodeStateMachine's BlockSyncComplete arm.
        let actions = state.on_block_sync_complete();
        assert!(!state.is_block_syncing());
        assert!(actions.is_empty());
    }

    #[test]
    fn test_syncing_validator_can_vote_for_others_blocks() {
        // Syncing only blocks us from proposing content; we still vote on others'
        // blocks once verification completes.
        let (mut state, topology) = make_multi_validator_state();
        state.set_time(LocalTimestamp::from_millis(100_000));
        state.set_block_syncing(true);

        let block_hash = BlockHash::from_raw(Hash::from_bytes(b"other_proposer_block"));
        let height = BlockHeight::new(1);
        // A fresh state's current round is 1, so vote at the matching round.
        let round = Round::new(1);
        let actions = state.try_vote_on_block(&topology, block_hash, height, round);

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
        let (mut state, topology) = make_test_state();
        state.set_time(LocalTimestamp::from_millis(100_000));
        state.view_change.last_leader_activity = Some(LocalTimestamp::ZERO);

        assert!(state.should_advance_round());
        state.set_block_syncing(true);
        assert!(state.should_advance_round());
        assert!(state.check_round_timeout(&topology).is_some());
    }

    #[test]
    fn test_sync_mode_resets_leader_activity_on_exit() {
        // Leaving sync resets leader activity to `now` so the fresh round doesn't
        // immediately time out on stale activity from before sync started.
        let (mut state, _topology) = make_test_state();
        state.set_time(LocalTimestamp::from_millis(100_000));
        state.view_change.last_leader_activity = Some(LocalTimestamp::ZERO);

        state.set_block_syncing(true);
        state.on_block_sync_complete();

        assert_eq!(
            state.view_change.last_leader_activity,
            Some(LocalTimestamp::from_millis(100_000))
        );
    }

    #[test]
    fn test_start_sync_sets_syncing_flag() {
        // check_sync_health triggers StartBlockSync when the gap to latest_qc is
        // large (>3) without a pending commit.
        let (mut state, _topology) = make_test_state();
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
                __qc.shard_group_id(),
                __qc.height(),
                BlockHash::from_raw(Hash::from_bytes(b"block_4")),
                __qc.round(),
                __qc.signers().clone(),
                __qc.aggregated_signature(),
                WeightedTimestamp::from_millis(1000),
            ))
        });
        let actions = state.check_sync_health();

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
        let (mut state, topology) = make_test_state();
        state.set_time(LocalTimestamp::from_millis(100_000));

        let block = Block::Live {
            header: {
                let __h = make_header_at_height(BlockHeight::new(1), 1000);
                BlockHeader::new(
                    __h.shard_group_id(),
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
                )
            },
            transactions: Arc::new(BoundedVec::new()),
            certificates: Arc::new(BoundedVec::new()),
            provisions: Arc::new(BoundedVec::new()),
        };
        let mut sub_quorum_signers = SignerBitfield::new(4);
        sub_quorum_signers.set(0); // single signer — far below 2f+1 = 3
        let qc = {
            let __qc = make_test_qc(block.hash(), BlockHeight::new(1));
            QuorumCertificate::new(
                __qc.block_hash(),
                __qc.shard_group_id(),
                __qc.height(),
                __qc.parent_block_hash(),
                __qc.round(),
                sub_quorum_signers,
                __qc.aggregated_signature(),
                WeightedTimestamp::from_millis(1000),
            )
        };
        let certified = CertifiedBlock::new_unchecked(block, qc);

        let actions = state.on_sync_block_ready_to_apply(&topology, certified);
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
    fn test_stale_sync_block_ignored() {
        // A synced block below committed_height must be dropped without advancing
        // any state — including the syncing flag.
        let (mut state, topology) = make_test_state();
        state.set_time(LocalTimestamp::from_millis(100_000));
        state.committed_height = BlockHeight::new(10);

        let block = Block::Live {
            header: {
                let __h = make_header_at_height(BlockHeight::new(1), 1000);
                BlockHeader::new(
                    __h.shard_group_id(),
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
                )
            },
            transactions: Arc::new(BoundedVec::new()),
            certificates: Arc::new(BoundedVec::new()),
            provisions: Arc::new(BoundedVec::new()),
        };
        let qc = {
            let __qc = make_test_qc(block.hash(), BlockHeight::new(1));
            QuorumCertificate::new(
                __qc.block_hash(),
                __qc.shard_group_id(),
                __qc.height(),
                __qc.parent_block_hash(),
                __qc.round(),
                __qc.signers().clone(),
                __qc.aggregated_signature(),
                WeightedTimestamp::from_millis(1000),
            )
        };
        let certified = CertifiedBlock::new_unchecked(block, qc);

        let actions = state.on_sync_block_ready_to_apply(&topology, certified);
        assert!(actions.is_empty());
        assert!(!state.is_block_syncing());
    }

    #[test]
    fn test_sync_block_records_leader_activity() {
        // Dispatching a sync proposal is progress — it must reset the leader
        // activity timer so we don't immediately view-change out of it.
        let (mut state, topology) = make_test_state();
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
                __qc.shard_group_id(),
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
        let _ = state.try_propose(&topology, &[], vec![], vec![]);

        assert_eq!(
            state.view_change.last_leader_activity,
            Some(LocalTimestamp::from_millis(100_000))
        );
    }

    #[test]
    fn test_sync_block_vs_fallback_block_differences() {
        // Sync blocks use current time and is_fallback=false; fallback blocks
        // inherit the parent's weighted timestamp and set is_fallback=true.
        let (mut state, topology) = make_test_state();
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
                __qc.shard_group_id(),
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
            &topology,
            BlockHeight::new(4),
            Round::new(0),
            ProposalKind::Sync,
        );
        state.set_block_syncing(false);

        state.pending_blocks.clear();

        let fallback_actions =
            state.build_and_broadcast_fallback_block(&topology, BlockHeight::new(4), Round::new(1));

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
        let (mut state, topology) = make_test_state();
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
                __qc.shard_group_id(),
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

        let actions = state.try_propose(&topology, &[], vec![], vec![]);
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
                    __h.shard_group_id(),
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
                )
            },
            transactions: Arc::new(vec![tx1.clone()].into()),
            certificates: Arc::new(BoundedVec::new()),
            provisions: Arc::new(BoundedVec::new()),
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
                    __h.shard_group_id(),
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
                )
            },
            transactions: Arc::new(txs.into()),
            certificates: Arc::new(BoundedVec::new()),
            provisions: Arc::new(BoundedVec::new()),
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
                    __h.shard_group_id(),
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
                )
            },
            transactions: Arc::new(vec![tx1.clone()].into()),
            certificates: Arc::new(BoundedVec::new()),
            provisions: Arc::new(BoundedVec::new()),
        };
        let ancestor_hash = ancestor_block.hash();

        // Block at height 6, parent = ancestor. tx1 is in ancestor but ancestor
        // is at committed height so the walk stops — this should be allowed.
        let block = Block::Live {
            header: {
                let __h = make_header_at_height(BlockHeight::new(6), 100_001);
                BlockHeader::new(
                    __h.shard_group_id(),
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
                )
            },
            transactions: Arc::new(vec![tx1].into()),
            certificates: Arc::new(BoundedVec::new()),
            provisions: Arc::new(BoundedVec::new()),
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
}
