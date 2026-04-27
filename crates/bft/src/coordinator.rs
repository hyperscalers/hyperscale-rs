//! BFT consensus state machine.
//!
//! This module implements the BFT consensus state machine
//! as a synchronous, event-driven model.
//!
//! # Data Availability Guarantee
//!
//! Validators only vote for blocks after receiving ALL transaction and certificate
//! data. This is enforced in [`BftCoordinator::on_block_header`] which checks `is_complete()`
//! before voting. Incomplete blocks wait for data via gossip or fetch.
//!
//! This provides a strong DA guarantee: if a QC forms, at least 2f+1 validators have
//! the complete block data, making it recoverable from any honest validator in that set.

use hyperscale_core::{Action, CommitSource, ProtocolEvent, TimerId};
use hyperscale_types::{
    BlockHash, LocalTimestamp, ProposerTimestamp, ProvisionHash, WaveIdHash, WeightedTimestamp,
};

/// BFT statistics for monitoring.
#[derive(Clone, Copy, Debug, Default)]
pub struct BftStats {
    /// Total number of view changes (round advances due to local
    /// leader-activity timeout — i.e. *we* timed out).
    pub view_changes: u64,
    /// Total number of view syncs (rounds we jumped to because a header /
    /// vote / QC arrived carrying a higher round). Distinct from
    /// `view_changes` — a follower whose `view_changes` stays at zero can
    /// still see its `view` climb to thousands while peers churn. Watch
    /// both to see cluster-wide view-change activity.
    pub view_syncs: u64,
    /// Current round within the current height.
    pub current_round: u64,
    /// Current committed height.
    pub committed_height: BlockHeight,
}

/// BFT memory statistics for monitoring collection sizes.
#[derive(Clone, Copy, Debug, Default)]
pub struct BftMemoryStats {
    /// Pending blocks awaiting transaction / wave / provision arrival.
    pub pending_blocks: usize,
    /// Per-block vote sets aggregating received votes.
    pub vote_sets: usize,
    /// Certified blocks (have a QC) cached in the commit pipeline.
    pub certified_blocks: usize,
    /// Commits queued out-of-order (parent not yet committed).
    pub pending_commits: usize,
    /// Commits whose block data hasn't fully arrived yet.
    pub pending_commits_awaiting_data: usize,
    /// Heights at which the local validator has voted (own-vote lock entries).
    pub voted_heights: usize,
    /// Equivocation-detection records keyed by `(height, validator)`.
    pub received_votes_by_height: usize,
    /// Recently-committed tx-hash → height entries used for fast dedup lookup.
    pub committed_tx_lookup: usize,
    /// Recently-committed transaction hashes retained for proposal dedup.
    pub recently_committed_txs: usize,
    /// Recently-committed wave certificate hashes retained for proposal dedup.
    pub recently_committed_certs: usize,
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
}

/// Index type for simulation-only node routing.
/// Production uses `ValidatorId` (from message signatures) and `PeerId` (libp2p).
pub type NodeIndex = u32;
#[cfg(test)]
use hyperscale_types::Hash;
use hyperscale_types::{
    Block, BlockHeader, BlockHeight, BlockManifest, BlockVote, CertifiedBlock, FinalizedWave,
    Provisions, QuorumCertificate, Round, RoutableTransaction, StateRoot, TopologySnapshot, TxHash,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, instrument, trace, warn};

use crate::chain_view::ChainView;
use crate::commit_pipeline::CommitPipeline;
use crate::config::BftConfig;
use crate::pending::PendingBlock;
use crate::proposal::{ProposalKind, ProposalTracker, TakeResult};
use crate::sync::{SyncManager, SyncVerificationResult};
use crate::tx_cache::CommittedTxCache;
use crate::verification::{InFlightCheck, VerificationPipeline};
use crate::view_change::ViewChangeController;
use crate::vote_keeper::{LockDecision, VoteKeeper};

/// State recovered from storage on startup.
///
/// Passed to `BftCoordinator::new()` to restore consensus state after a crash/restart.
/// For a fresh start, use `RecoveredState::default()`.
#[derive(Debug, Clone, Default)]
pub struct RecoveredState {
    /// Last committed block height.
    pub committed_height: BlockHeight,

    /// Last committed block hash (None for fresh start).
    pub committed_hash: Option<BlockHash>,

    /// Latest QC (certifies the highest certified block).
    pub latest_qc: Option<QuorumCertificate>,

    /// Last committed JMT root hash.
    ///
    /// Restored from storage at startup so proposals use the correct parent
    /// state root instead of the default `StateRoot::ZERO`.
    ///
    /// If not provided (None), defaults to `StateRoot::ZERO` for fresh start.
    pub jmt_root: Option<StateRoot>,
}

/// BFT consensus state machine.
///
/// Handles block proposal, voting, QC formation, commitment, and view changes.
/// This is a synchronous implementation of BFT consensus.
///
/// # State Machine Flow
///
/// 1. **Proposal Timer** → If proposer, build and broadcast block header
/// 2. **Block Header Received** → Validate, track pending, vote if valid
/// 3. **Block Vote Received** → Collect votes, form QC when quorum reached
/// 4. **QC Formed** → Update chain state, commit if ready (two-chain rule)
/// 5. **View Change Timer** → Initiate view change if no progress
pub struct BftCoordinator {
    // ═══════════════════════════════════════════════════════════════════════════
    // Identity
    // ═══════════════════════════════════════════════════════════════════════════
    /// This node's index (deterministic ordering).
    node_index: NodeIndex,

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

    /// Latest QC (certifies the latest certified block).
    latest_qc: Option<QuorumCertificate>,

    /// QC deferred because the block header wasn't in memory when it formed.
    /// Adopted in `on_block_header` when the header arrives.
    deferred_qc: Option<(BlockHash, QuorumCertificate)>,

    /// Genesis block (needed for bootstrapping).
    genesis_block: Option<Block>,

    // ═══════════════════════════════════════════════════════════════════════════
    // Pending State
    // ═══════════════════════════════════════════════════════════════════════════
    /// Pending blocks being assembled (hash -> pending block).
    pending_blocks: HashMap<BlockHash, PendingBlock>,

    /// Vote accounting: per-block vote sets, own-vote locks, and
    /// received-vote equivocation tracking.
    votes: VoteKeeper,

    /// Certified blocks awaiting commit, out-of-order commit buffering, and
    /// awaiting-data commit buffering.
    commits: CommitPipeline,

    /// Async verification tracking (QC signatures, commitment proofs, state/tx roots).
    verification: VerificationPipeline,

    /// Sync coordination (block buffering, verification tracking, sync flag).
    sync: SyncManager,

    /// In-flight proposal awaiting `Event::ProposalBuilt` callback.
    proposal: ProposalTracker,

    /// Dedup cache for committed transaction and certificate hashes.
    /// Bridges synchronous BFT commits to async mempool processing, and
    /// provides a bounded retention window for historical dedup.
    tx_cache: CommittedTxCache,

    // ═══════════════════════════════════════════════════════════════════════════
    // Configuration
    // ═══════════════════════════════════════════════════════════════════════════
    config: BftConfig,

    // ═══════════════════════════════════════════════════════════════════════════
    // Time
    // ═══════════════════════════════════════════════════════════════════════════
    /// Local wall-clock time, set by the runner before each `handle()` call.
    /// Drives view-change timing, IO retry backoff, and the proposer-skew
    /// gate on incoming headers — never used as a deterministic consensus
    /// anchor (use `committed_ts: WeightedTimestamp` for that).
    now: LocalTimestamp,
}

impl std::fmt::Debug for BftCoordinator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BftCoordinator")
            .field("node_index", &self.node_index)
            .field("view", &self.view_change.view)
            .field("committed_height", &self.committed_height)
            .field("pending_blocks", &self.pending_blocks.len())
            .field("vote_sets", &self.votes.vote_sets_len())
            .finish_non_exhaustive()
    }
}

impl BftCoordinator {
    /// Create a new BFT state machine.
    ///
    /// # Arguments
    ///
    /// * `node_index` - Deterministic node index for ordering
    /// * `config` - BFT configuration
    /// * `recovered` - State recovered from storage. Use `RecoveredState::default()` for fresh start.
    #[must_use]
    pub fn new(node_index: NodeIndex, config: BftConfig, recovered: RecoveredState) -> Self {
        Self {
            node_index,
            view_change: ViewChangeController::new(),
            committed_height: recovered.committed_height,
            committed_hash: recovered.committed_hash.unwrap_or(BlockHash::ZERO),
            committed_ts: recovered
                .latest_qc
                .as_ref()
                .map_or(WeightedTimestamp::ZERO, |qc| qc.weighted_timestamp),
            committed_state_root: recovered.jmt_root.unwrap_or(StateRoot::ZERO),
            latest_qc: recovered.latest_qc,
            deferred_qc: None,
            genesis_block: None,
            pending_blocks: HashMap::new(),
            votes: VoteKeeper::new(),
            commits: CommitPipeline::new(),
            verification: VerificationPipeline::new(recovered.committed_height),
            sync: SyncManager::new(),
            proposal: ProposalTracker::new(),
            tx_cache: CommittedTxCache::new(),
            config,
            now: LocalTimestamp::ZERO,
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
    /// [`ChainView`] for the lookup API.
    const fn chain_view(&self) -> ChainView<'_> {
        ChainView {
            committed_height: self.committed_height,
            committed_hash: self.committed_hash,
            committed_state_root: self.committed_state_root,
            latest_qc: self.latest_qc.as_ref(),
            genesis: self.genesis_block.as_ref(),
            certified: &self.commits.certified_blocks,
            pending: &self.pending_blocks,
        }
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
    fn set_syncing(&mut self, topology: &TopologySnapshot, syncing: bool) {
        if syncing && !self.sync.is_syncing() {
            info!(
                validator = ?topology.local_validator_id(),
                "Entering sync mode - will propose empty blocks if selected"
            );
        } else if !syncing && self.sync.is_syncing() {
            info!(
                validator = ?topology.local_validator_id(),
                "Exiting sync mode - resuming normal block production"
            );
            // Reset leader activity timeout since we've caught up
            self.view_change.last_leader_activity = Some(self.now);
        }
        self.sync.set_syncing(syncing);
    }

    /// Check if this validator is currently syncing.
    #[must_use]
    pub const fn is_syncing(&self) -> bool {
        self.sync.is_syncing()
    }

    /// Start syncing to catch up to the network.
    ///
    /// This is the single entry point for initiating sync. It:
    /// 1. Sets the syncing flag immediately (enables sync block proposals, suppresses fetches)
    /// 2. Returns the `StartSync` action for the runner to begin fetching blocks
    ///
    /// Setting the syncing flag immediately (rather than waiting for the first synced block)
    /// ensures that:
    /// - `check_pending_block_fetches()` stops emitting fetch requests that would compete with sync
    /// - Proposers create empty sync blocks instead of full blocks
    /// - The state machine accurately reflects that we're waiting for sync data
    ///
    /// The syncing flag will be cleared when `Event::SyncComplete` arrives.
    fn start_sync(
        &mut self,
        topology: &TopologySnapshot,
        target_height: BlockHeight,
        target_hash: BlockHash,
    ) -> Vec<Action> {
        // Don't raise the target while already syncing. The io_loop's
        // SyncProtocol manages its own target internally. Once the current
        // sync completes and we resume consensus, a new start_sync will
        // fire naturally if we're still behind.
        if self.sync.is_syncing() {
            return vec![];
        }

        info!(
            validator = ?topology.local_validator_id(),
            target_height = target_height.0,
            target_hash = ?target_hash,
            committed_height = self.committed_height.0,
            "Starting sync - setting syncing flag and requesting blocks"
        );

        // Set syncing flag immediately - this:
        // - Enables sync block proposals if we're the proposer
        // - Suppresses fetch requests (check_pending_block_fetches returns empty)
        // - Signals to other code that we're catching up
        self.set_syncing(topology, true);
        self.sync.set_sync_target(target_height);

        vec![Action::StartSync {
            target_height,
            target_hash,
        }]
    }

    /// Handle a synced block ready to apply (from runner via
    /// `Event::SyncBlockReadyToApply`). Delegates the dedup/routing
    /// decision to [`SyncManager::ingest`] and translates the outcome into
    /// a submit dispatch or a buffer drain.
    pub fn on_sync_block_ready_to_apply(
        &mut self,
        topology: &TopologySnapshot,
        certified: CertifiedBlock,
    ) -> Vec<Action> {
        match self.sync.ingest(certified, self.committed_height) {
            crate::sync::IngestOutcome::Drop => vec![],
            crate::sync::IngestOutcome::Submit(certified) => {
                self.submit_synced_block_for_verification(topology, *certified)
            }
            crate::sync::IngestOutcome::Buffered => self.try_drain_buffered_synced_blocks(topology),
        }
    }

    /// Handle sync complete (from runner via `Event::SyncComplete`).
    ///
    /// Re-enables normal block proposals and view changes.
    /// Also triggers fetch requests for any pending blocks that still need data,
    /// since fetching was suppressed during sync.
    pub fn on_sync_complete(&mut self, topology: &TopologySnapshot) -> Vec<Action> {
        info!(
            validator = ?topology.local_validator_id(),
            "Sync complete, resuming normal consensus"
        );
        self.set_syncing(topology, false);

        // Resume fetching for any pending blocks that still need data.
        // During sync, check_pending_block_fetches() returns empty because we
        // don't want to compete with sync for network resources. Now that sync
        // is done, we need to fetch any missing transactions/certificates.
        // Use force_immediate=true to bypass the age timeout — blocks received
        // during sync shouldn't wait another timeout period to be fetched.
        let mut actions = self.check_pending_block_fetches(topology, true);

        // Notify NodeStateMachine to flush expected provisions and remote
        // headers immediately so we can participate in execution for recent
        // blocks within the WAVE_TIMEOUT window.
        actions.push(Action::Continuation(ProtocolEvent::SyncResumed));

        actions
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
        self.view_change.current_timeout(&self.config)
    }

    /// Time remaining until the view change timer should fire.
    #[must_use]
    pub fn remaining_view_change_timeout(&self) -> Duration {
        self.view_change.remaining_timeout(&self.config, self.now)
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
        // Don't view-change while we're actively processing the leader's
        // block — either assembling it (pending) or verifying it. The
        // timeout should detect leader failure, not slow processing.
        //
        // Only suppress for blocks at the current proposal height — pending
        // blocks at future heights (received early) are irrelevant to
        // whether the current leader proposed.
        let next_height = self
            .latest_qc
            .as_ref()
            .map_or(self.committed_height.0 + 1, |qc| qc.height.0 + 1);
        let has_incomplete_block_at_tip = self
            .pending_blocks
            .values()
            .any(|pb| pb.header().height.0 == next_height && !pb.is_complete());
        if self.verification.has_verification_in_flight()
            || has_incomplete_block_at_tip
            || self.sync.has_unverified_in_flight()
        {
            return false;
        }

        self.view_change.timeout_elapsed(&self.config, self.now)
    }

    /// Check for round timeout and advance if needed.
    ///
    /// This should be called before processing the proposal timer.
    /// Returns actions for view change if timeout triggered, or empty vec if not.
    ///
    /// If a view change occurs, the caller should NOT proceed to call
    /// `try_propose` in the same event handling cycle.
    pub fn check_round_timeout(&mut self, topology: &TopologySnapshot) -> Option<Vec<Action>> {
        if !self.should_advance_round() {
            return None;
        }

        // Reset the timeout so we don't immediately trigger another view change.
        self.view_change.record_leader_activity(self.now);
        self.view_change.last_header_reset = None;

        let timeout = self.current_view_change_timeout();
        let rounds_at_height = self
            .view_change
            .view
            .0
            .saturating_sub(self.view_change.view_at_height_start.0);

        info!(
            validator = ?topology.local_validator_id(),
            view = self.view_change.view.0,
            rounds_at_height = rounds_at_height,
            timeout_ms = timeout.as_millis(),
            "Round timeout - advancing round (implicit view change)"
        );

        Some(self.advance_round(topology))
    }

    /// Initialize with genesis block (for fresh start).
    pub fn initialize_genesis(
        &mut self,
        topology: &TopologySnapshot,
        genesis: &Block,
    ) -> Vec<Action> {
        let hash = genesis.hash();

        self.committed_hash = hash;
        self.committed_state_root = genesis.header().state_root;
        self.genesis_block = Some(genesis.clone());

        // Record genesis time as initial leader activity so that the view
        // change timeout counts from startup rather than being disabled.
        self.view_change.record_leader_activity(self.now);

        info!(
            validator = ?topology.local_validator_id(),
            genesis_hash = ?hash,
            "Initialized genesis block"
        );

        // Set initial timers and trigger first proposal attempt
        vec![
            Action::Continuation(ProtocolEvent::ContentAvailable),
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

    /// Request recovery from storage.
    ///
    /// Call this on startup to restore state from persistent storage.
    /// The runner will respond with `Event::ChainMetadataFetched`.
    pub fn request_recovery(&self, topology: &TopologySnapshot) -> Vec<Action> {
        info!(
            validator = ?topology.local_validator_id(),
            "Requesting chain metadata for recovery"
        );
        vec![Action::FetchChainMetadata]
    }

    /// Handle chain metadata fetched from storage (recovery).
    ///
    /// Called when the runner completes `Action::FetchChainMetadata`.
    #[instrument(skip(self, qc), fields(height = height.0, has_hash = hash.is_some(), has_qc = qc.is_some()))]
    pub fn on_chain_metadata_fetched(
        &mut self,
        topology: &TopologySnapshot,
        height: BlockHeight,
        hash: Option<BlockHash>,
        qc: Option<QuorumCertificate>,
    ) -> Vec<Action> {
        if height.0 == 0 && hash.is_none() {
            // No committed blocks - this is a fresh start
            info!(
                validator = ?topology.local_validator_id(),
                "No committed blocks found - fresh start"
            );
            return vec![];
        }

        // Restore committed state
        self.committed_height = height;
        if let Some(h) = hash {
            self.committed_hash = h;
        }
        let has_qc = qc.is_some();
        self.latest_qc = qc;

        // Reset backoff tracking - we're starting fresh at this height
        self.view_change.reset_for_height_advance();

        // Clean up any votes for heights at or below the committed height.
        // This handles the case where we loaded votes from storage that are now stale.
        self.cleanup_old_state(height);

        // Record recovery time as initial leader activity so that the view
        // change timeout counts from startup rather than being disabled.
        self.view_change.last_leader_activity = Some(self.now);

        info!(
            validator = ?topology.local_validator_id(),
            committed_height = self.committed_height.0,
            committed_hash = ?self.committed_hash,
            has_qc,
            "Recovered chain state from storage"
        );

        // Pending blocks at or below the recovered committed height self-evict
        // from fetch protocols on the next tick via the `is_stale` predicate.

        // Set timers to resume consensus and trigger first proposal attempt
        vec![
            Action::Continuation(ProtocolEvent::ContentAvailable),
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
    /// - `ContentAvailable` events (new transactions, waves, or provisions)
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
        topology: &TopologySnapshot,
        ready_txs: &[Arc<RoutableTransaction>],
        finalized_waves: Vec<Arc<FinalizedWave>>,
        provisions: Vec<Arc<Provisions>>,
    ) -> Vec<Action> {
        // The next height to propose is one above the highest certified block,
        // not the committed block — this lets the chain grow while the
        // two-chain commit rule is being satisfied.
        let next_height = self
            .latest_qc
            .as_ref()
            .map_or_else(|| self.committed_height.next(), |qc| qc.height.next());
        let round = self.view_change.view;

        if !self.can_propose(topology, next_height, round) {
            return vec![];
        }

        // Syncing validators propose an empty sync block to keep the chain
        // advancing while catching up on execution state.
        if self.sync.is_syncing() {
            return self.build_and_dispatch_proposal(
                topology,
                next_height,
                round,
                ProposalKind::Sync,
            );
        }

        // Walk the QC chain to find certificates, transactions, and
        // provisions already in pending/certified blocks above committed
        // height — the two-chain commit window leaves them visible and the
        // mempool doesn't clear its ready-set until commit, so we must dedup
        // here to avoid repeating items across consecutive blocks.
        let (parent_hash, parent_qc) = self.chain_view().proposal_parent();
        let (qc_chain_cert_hashes, qc_chain_tx_hashes, qc_chain_provision_hashes) =
            self.collect_qc_chain_hashes(parent_hash);

        // Anchor validity-window filtering on the parent QC's weighted
        // timestamp — the deterministic clock voters will use to verify
        // this block. The one-block lag (this block's own QC may carry a
        // slightly later timestamp) is bounded by MAX_VALIDITY_RANGE.
        let validity_anchor = parent_qc.weighted_timestamp;
        let transactions = crate::proposal::select_transactions(
            ready_txs,
            &qc_chain_tx_hashes,
            &self.tx_cache,
            validity_anchor,
        );
        let (finalized_waves, finalized_tx_count) = crate::proposal::select_finalized_waves(
            finalized_waves,
            &qc_chain_cert_hashes,
            self.config.max_finalized_transactions_per_block,
        );
        let provisions = crate::proposal::select_provisions(
            provisions,
            &qc_chain_provision_hashes,
            self.config.max_provision_transactions_per_block,
        );

        self.build_and_dispatch_proposal(
            topology,
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

    /// Pre-build gate: we must be the proposer, not already building the
    /// same height/round, and not locked on a vote at the target height.
    /// Re-proposing a height we've voted on would create a different block
    /// hash (timestamps differ), which the vote lock then prevents us from
    /// voting for — so skip.
    fn can_propose(
        &self,
        topology: &TopologySnapshot,
        next_height: BlockHeight,
        round: Round,
    ) -> bool {
        if !topology.should_propose(next_height, round) {
            return false;
        }

        if let Some(pending) = self.proposal.pending()
            && pending.height == next_height
            && pending.round == round
        {
            trace!(
                validator = ?topology.local_validator_id(),
                height = next_height.0,
                round = round.0,
                "Proposal build already in-flight, skipping"
            );
            return false;
        }

        // Suppress re-entry while a prior dispatch for the same target is
        // parked on the verification pipeline waiting for the parent JMT
        // tree. Without this, every `ContentAvailable` / `on_qc_formed` hit
        // re-runs `assemble_build_action` and re-registers the defer,
        // burning CPU and log bandwidth while peers time out on the
        // proposer slot.
        if let Some(deferred) = self.proposal.deferred()
            && deferred.height == next_height
            && deferred.round == round
        {
            trace!(
                validator = ?topology.local_validator_id(),
                height = next_height.0,
                round = round.0,
                "Proposal deferred pending parent tree, skipping"
            );
            return false;
        }

        if self.votes.is_locked_at(next_height) {
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
        topology: &TopologySnapshot,
        height: BlockHeight,
        round: Round,
    ) -> Vec<Action> {
        self.build_and_dispatch_proposal(topology, height, round, ProposalKind::Fallback)
    }

    /// Unified proposal build + dispatch.
    ///
    /// Resolves the parent from the chain view, assembles a `BuildProposal`
    /// action whose payload/timestamp/`is_fallback` bits come from `kind`,
    /// and dispatches via the `proposal` tracker (or defers via the
    /// verification pipeline when the parent JMT isn't ready yet).
    fn build_and_dispatch_proposal(
        &mut self,
        topology: &TopologySnapshot,
        height: BlockHeight,
        round: Round,
        kind: ProposalKind,
    ) -> Vec<Action> {
        let plan = crate::proposal::assemble_build_action(
            topology,
            &self.chain_view(),
            height,
            round,
            self.now,
            kind,
        );

        info!(
            validator = ?topology.local_validator_id(),
            height = height.0,
            round = round.0,
            plan.log_label,
        );

        if plan.record_leader_activity {
            self.record_leader_activity();
        }

        crate::proposal::dispatch_or_defer(
            &mut self.proposal,
            &mut self.verification,
            plan.parent_hash,
            plan.parent_block_height,
            height,
            round,
            plan.action,
        )
    }

    /// Re-propose a block we're vote-locked to after a view change.
    ///
    /// When we've already voted for a block at this height but become leader after
    /// a view change, we must re-propose the same block (with updated round) rather
    /// than creating a new fallback block. This allows other validators who may have
    /// missed the original proposal to receive and vote on it.
    ///
    /// # Safety
    ///
    /// This is safe because:
    /// - We already validated and voted for this block
    /// - The block hash remains the same (only round changes in header)
    /// - Other validators can now receive and vote for it
    /// - If enough validators vote, the block commits
    ///
    /// # Returns
    ///
    /// Actions to re-broadcast the block header. We do NOT create a new vote since
    /// we already voted for this block at this height.
    fn repropose_locked_block(
        &mut self,
        topology: &TopologySnapshot,
        block_hash: BlockHash,
        height: BlockHeight,
    ) -> Vec<Action> {
        let mut actions = vec![];

        // Try to get the pending block we voted for
        let Some(pending) = self.pending_blocks.get(&block_hash) else {
            // Block not in pending_blocks - might have been cleaned up or committed.
            // View change timer will handle further recovery.
            warn!(
                validator = ?topology.local_validator_id(),
                height = height.0,
                block_hash = ?block_hash,
                "Cannot re-propose: locked block not found in pending_blocks"
            );
            return vec![];
        };

        // IMPORTANT: Keep the original header unchanged, including the round.
        //
        // The block hash is computed from all header fields INCLUDING round.
        // If we change the round, we change the hash, which would break vote-locking
        // (validators voted for the original hash, not a new one).
        //
        // Receivers will accept this block with an older round because:
        // 1. The proposer is valid for (height, original_round)
        // 2. Their view >= original_round (they've also been through view change)
        // 3. validate_header allows blocks where proposer matches (height, header.round)
        let header = pending.header().clone();
        let original_round = header.round;

        let manifest = pending.manifest().clone();

        info!(
            validator = ?topology.local_validator_id(),
            height = height.0,
            original_round = original_round.0,
            block_hash = ?block_hash,
            tx_count = manifest.transaction_count(),
            cert_count = manifest.cert_hashes.len(),
            "Re-proposing vote-locked block after view change (keeping original round)"
        );

        // Broadcast the block header and manifest
        actions.push(Action::BroadcastBlockHeader {
            header: Box::new(header),
            manifest: Box::new(manifest),
        });

        // Note: We do NOT create a new vote here - we already voted for this block
        // at this height. The vote is recorded in voted_heights and our original
        // vote should still be valid (votes are for block_hash + height, not round).

        // Track proposal time for rate limiting

        // Record leader activity - we are producing blocks
        self.record_leader_activity();

        actions
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Header Reception
    // ═══════════════════════════════════════════════════════════════════════════

    /// Handle a received block header. Sender identity is taken from the
    /// header's signed `proposer` field — there's no separate peer-id
    /// parameter because sync detection doesn't need it.
    #[instrument(skip(self, header, manifest, lookup_tx, lookup_finalized_wave, lookup_provision), fields(
        height = header.height.0,
        round = header.round.0,
        proposer = ?header.proposer,
        tx_count = manifest.transaction_count()
    ))]
    #[allow(clippy::too_many_arguments)]
    pub fn on_block_header(
        &mut self,
        topology: &TopologySnapshot,
        header: &BlockHeader,
        manifest: BlockManifest,
        lookup_tx: impl Fn(&TxHash) -> Option<Arc<RoutableTransaction>>,
        lookup_finalized_wave: impl Fn(&WaveIdHash) -> Option<Arc<FinalizedWave>>,
        lookup_provision: impl Fn(&ProvisionHash) -> Option<Arc<Provisions>>,
    ) -> Vec<Action> {
        let block_hash = header.hash();
        let height = header.height;
        let round = header.round;

        debug!(
            validator = ?topology.local_validator_id(),
            proposer = ?header.proposer,
            height = height.0,
            round = round.0,
            block_hash = ?block_hash,
            "Received block header"
        );

        let mut sync_actions = self.absorb_parent_qc_from_header(topology, header);
        self.sync_view_to_header_round(topology, header);

        if self.reject_invalid_header(topology, header) {
            return vec![];
        }

        self.record_header_activity(height, round);

        if self.pending_blocks.contains_key(&block_hash) {
            trace!("Already have pending block {}", block_hash);
            return vec![];
        }

        self.assemble_pending_block(
            header.clone(),
            manifest,
            lookup_tx,
            lookup_finalized_wave,
            lookup_provision,
        );
        self.adopt_deferred_qc_if_matches(topology, block_hash, &mut sync_actions);
        self.link_buffered_votes_to_header(block_hash, header);

        let mut actions = self.votes.maybe_trigger_verification(topology, block_hash);
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

        if self.finalize_complete_block(topology, block_hash, &mut actions) {
            return actions;
        }

        self.log_incomplete_block(topology, block_hash);
        actions
    }

    /// If `header.parent_qc` moves the chain forward, adopt it: trigger sync
    /// when the parent is missing, update `latest_qc`, fire two-chain commit,
    /// and schedule a proposal attempt. Returns any sync/commit/continuation
    /// actions produced along the way.
    ///
    /// Crucially this does NOT return early when sync is needed — we keep
    /// processing the header so the validator can still participate in
    /// consensus at the tip while catching up on historical blocks.
    fn absorb_parent_qc_from_header(
        &mut self,
        topology: &TopologySnapshot,
        header: &BlockHeader,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        if header.parent_qc.is_genesis() {
            return actions;
        }

        let parent_height = header.parent_qc.height;
        let parent_block_hash = header.parent_qc.block_hash;

        // Check for a COMPLETE parent block; an incomplete pending block still
        // requires sync for the full data.
        let have_parent = self.has_complete_block_at_height(parent_height);

        if !have_parent {
            info!(
                validator = ?topology.local_validator_id(),
                committed_height = self.committed_height.0,
                parent_height = parent_height.0,
                target_height = parent_height.0,
                "Missing parent block, triggering sync (continuing to process header)"
            );
            actions = self.start_sync(topology, parent_height, parent_block_hash);
        }

        // Only adopt the QC if we have the parent it certifies — otherwise we
        // can't look up the parent's state_root when proposing, which would
        // yield blocks with state_root=Hash::ZERO.
        let should_update_qc = have_parent
            && self
                .latest_qc
                .as_ref()
                .is_none_or(|existing| header.parent_qc.height.0 > existing.height.0);
        if should_update_qc {
            debug!(
                validator = ?topology.local_validator_id(),
                qc_height = header.parent_qc.height.0,
                "Updated latest_qc from received block header"
            );
            self.latest_qc = Some(header.parent_qc.clone());
            self.maybe_unlock_for_qc(topology, &header.parent_qc);

            // Non-proposers learn about QCs via block headers rather than
            // forming them locally — they need two-chain commit + a proposal
            // kick to advance the chain in the event-driven model.
            actions.extend(self.try_two_chain_commit(
                topology,
                &header.parent_qc,
                CommitSource::Header,
            ));
            actions.push(Action::Continuation(ProtocolEvent::ContentAvailable));
        }

        actions
    }

    /// Advance the local view to the header's round if the header is ahead,
    /// so late joiners converge faster than QC-based view sync alone.
    fn sync_view_to_header_round(&mut self, topology: &TopologySnapshot, header: &BlockHeader) {
        let old_view = self.view_change.view;
        if self.view_change.sync_to_qc_round(header.round) {
            info!(
                validator = ?topology.local_validator_id(),
                old_view = old_view.0,
                new_view = header.round.0,
                header_height = header.height.0,
                "View synchronization: advancing view to match received block header"
            );
        }
    }

    /// Validate the header; logs and returns `true` if the caller should
    /// reject (short-circuit with empty actions).
    fn reject_invalid_header(&self, topology: &TopologySnapshot, header: &BlockHeader) -> bool {
        if let Err(e) = crate::validation::validate_header(
            topology,
            header,
            self.committed_height,
            &self.config,
            self.now,
        ) {
            warn!(
                validator = ?topology.local_validator_id(),
                error = %e,
                "Invalid block header"
            );
            true
        } else {
            false
        }
    }

    /// Build a `PendingBlock` from the header+manifest, eagerly pulling any
    /// transactions/waves/provisions already in local stores (mempool, wave
    /// cache, provision cache), and insert into `pending_blocks`.
    fn assemble_pending_block(
        &mut self,
        header: BlockHeader,
        manifest: BlockManifest,
        lookup_tx: impl Fn(&TxHash) -> Option<Arc<RoutableTransaction>>,
        lookup_finalized_wave: impl Fn(&WaveIdHash) -> Option<Arc<FinalizedWave>>,
        lookup_provision: impl Fn(&ProvisionHash) -> Option<Arc<Provisions>>,
    ) {
        let block_hash = header.hash();
        let mut pending = PendingBlock::from_manifest(header, manifest, self.now);

        for tx_hash in pending.manifest().tx_hashes.clone() {
            if let Some(tx) = lookup_tx(&tx_hash) {
                pending.add_transaction_arc(tx);
            }
        }
        for wave_hash in pending.manifest().cert_hashes.clone() {
            if let Some(fw) = lookup_finalized_wave(&wave_hash) {
                pending.add_finalized_wave(fw);
            }
        }
        for provision_hash in pending.manifest().provision_hashes.clone() {
            if let Some(p) = lookup_provision(&provision_hash) {
                pending.add_provision(p);
            }
        }

        self.pending_blocks.insert(block_hash, pending);
    }

    /// If we have a `deferred_qc` whose `block_hash` matches `block_hash`
    /// (votes arrived before this header), adopt it now. Appends a
    /// `ContentAvailable` continuation on adoption so the proposal path
    /// re-enters. If the deferred QC is for a different block, it's put back.
    fn adopt_deferred_qc_if_matches(
        &mut self,
        topology: &TopologySnapshot,
        block_hash: BlockHash,
        actions: &mut Vec<Action>,
    ) {
        let Some((deferred_hash, deferred_qc)) = self.deferred_qc.take() else {
            return;
        };

        if deferred_hash != block_hash {
            self.deferred_qc = Some((deferred_hash, deferred_qc));
            return;
        }

        let should_adopt = self
            .latest_qc
            .as_ref()
            .is_none_or(|existing| deferred_qc.height.0 > existing.height.0);
        if should_adopt {
            self.latest_qc = Some(deferred_qc.clone());
            self.maybe_unlock_for_qc(topology, &deferred_qc);
            actions.push(Action::Continuation(ProtocolEvent::ContentAvailable));
        }
    }

    /// Late-arriving header: votes may have already landed in the vote set.
    /// Stamp the header info into the set so QC aggregation has the
    /// `parent_block_hash` it needs.
    fn link_buffered_votes_to_header(&mut self, block_hash: BlockHash, header: &BlockHeader) {
        if let Some(vote_set) = self.votes.vote_sets.get_mut(&block_hash) {
            vote_set.set_header(header);
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
        topology: &TopologySnapshot,
        block_hash: BlockHash,
        actions: &mut Vec<Action>,
    ) -> bool {
        let is_complete = self
            .pending_blocks
            .get(&block_hash)
            .is_some_and(PendingBlock::is_complete);
        if !is_complete {
            return false;
        }

        if let Some(pending) = self.pending_blocks.get_mut(&block_hash)
            && pending.block().is_none()
            && let Err(e) = pending.construct_block()
        {
            warn!("Failed to construct block {}: {}", block_hash, e);
            return true;
        }

        actions.extend(self.trigger_qc_verification_or_vote(topology, block_hash));
        true
    }

    /// Log an incomplete block. The cleanup timer's
    /// `check_pending_block_fetches()` will eventually emit fetch requests;
    /// deferring here avoids unnecessary traffic when gossip or local cert
    /// creation fills in the data.
    fn log_incomplete_block(&self, topology: &TopologySnapshot, block_hash: BlockHash) {
        if let Some(pending) = self.pending_blocks.get(&block_hash) {
            debug!(
                validator = ?topology.local_validator_id(),
                block_hash = ?block_hash,
                missing_txs = pending.missing_transaction_count(),
                missing_waves = pending.missing_wave_count(),
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
        topology: &TopologySnapshot,
        block_hash: BlockHash,
    ) -> Vec<Action> {
        let Some(pending) = self.pending_blocks.get(&block_hash) else {
            warn!(
                "trigger_qc_verification_or_vote: no pending block for {}",
                block_hash
            );
            return vec![];
        };

        let header = pending.header().clone();
        let height = header.height;
        let round = header.round;

        // For non-genesis QC, delegate signature verification before voting.
        // This is CRITICAL for BFT safety - prevents Byzantine proposers from
        // including fake QCs with invalid signatures.
        if !header.parent_qc.is_genesis() {
            // Check if we've already verified this exact QC (by its block_hash).
            // This happens during view changes when multiple proposals at the same
            // height share the same parent_qc. Avoids redundant crypto work.
            let qc_block_hash = header.parent_qc.block_hash;
            if self.verification.is_qc_verified(&qc_block_hash) {
                trace!(
                    qc_block_hash = ?qc_block_hash,
                    block_hash = ?block_hash,
                    "QC already verified, skipping re-verification"
                );
                return self.try_vote_on_block(topology, block_hash, height, round);
            }

            // Check if we already have pending verification for this block
            if self.verification.has_pending_qc(&block_hash) {
                trace!("QC verification already pending for block {}", block_hash);
                return vec![];
            }

            // Collect public keys for verification
            let Some(public_keys) = crate::lookups::committee_public_keys(topology) else {
                warn!("Failed to collect public keys for QC verification");
                return vec![];
            };

            // Store pending verification info
            self.verification
                .track_pending_qc(block_hash, header.clone());

            // Delegate verification to runner
            return vec![Action::VerifyQcSignature {
                qc: header.parent_qc,
                public_keys,
                block_hash,
            }];
        }

        // Genesis QC - vote directly (no signature to verify)
        self.try_vote_on_block(topology, block_hash, height, round)
    }

    /// Try to vote on a block after it's complete and QC is verified.
    ///
    /// NOTE: This should only be called after QC verification completes.
    /// For the main entry point, use `trigger_qc_verification_or_vote`.
    fn try_vote_on_block(
        &mut self,
        topology: &TopologySnapshot,
        block_hash: BlockHash,
        height: BlockHeight,
        round: Round,
    ) -> Vec<Action> {
        // BFT safety: a validator must not vote for conflicting blocks at the
        // same height and round. Across rounds the lock may release on
        // timeout (no QC formed) or via QC-based unlock.
        let vote_locked = match self.votes.lock_decision(height, block_hash) {
            LockDecision::AlreadyVotedSameBlock { existing_round } => {
                trace!(
                    validator = ?topology.local_validator_id(),
                    block_hash = ?block_hash,
                    height = height.0,
                    round = round.0,
                    existing_round = existing_round.0,
                    "Already voted for this block"
                );
                return vec![];
            }
            LockDecision::Unlocked => false,
            LockDecision::LockedToOther {
                existing_block,
                existing_round,
            } => {
                // Fall through to the verification pipeline so that VerifyStateRoot
                // produces the PreparedCommit needed if this block commits via a
                // QC formed by other validators. Expected during view changes —
                // BFT safety working correctly, not a violation.
                warn!(
                    validator = ?topology.local_validator_id(),
                    existing = ?existing_block,
                    existing_round = existing_round.0,
                    new = ?block_hash,
                    new_round = round.0,
                    height = height.0,
                    "Vote locking: already voted for different block at this height (view change)"
                );
                true
            }
        };

        // If the block is assembled, run validation + verification.
        // Otherwise fall through to the voting path directly — reachable only
        // from test fixtures; production always assembles before reaching
        // here.
        if let Some(block) = self
            .pending_blocks
            .get(&block_hash)
            .and_then(PendingBlock::block)
        {
            if self.reject_invalid_block_contents(topology, block_hash, &block) {
                return vec![];
            }

            // Vote-locked validators must still run verification to produce
            // PreparedCommit. Parent-pruned blocks likewise run verification
            // but can't contribute in-flight accounting.
            let chain = ChainView {
                committed_height: self.committed_height,
                committed_hash: self.committed_hash,
                committed_state_root: self.committed_state_root,
                latest_qc: self.latest_qc.as_ref(),
                genesis: self.genesis_block.as_ref(),
                certified: &self.commits.certified_blocks,
                pending: &self.pending_blocks,
            };
            let skip_vote = match self.verification.classify_vote_in_flight(
                &chain,
                block_hash,
                &block,
                vote_locked,
            ) {
                InFlightCheck::Proceed => false,
                InFlightCheck::SkipVote => true,
                InFlightCheck::Abort => return vec![],
            };

            let verification_actions = self.verification.initiate_block_verifications(
                topology,
                &self.pending_blocks,
                block_hash,
                &block,
            );

            // Wait for initiated verifications, or exit early when we're
            // running verifications only (skip_vote) or the block isn't
            // fully verified yet.
            if skip_vote
                || !verification_actions.is_empty()
                || !self.verification.is_block_verified(&block)
            {
                return verification_actions;
            }
        }

        if vote_locked {
            return vec![];
        }

        self.create_vote(topology, block_hash, height, round)
    }

    /// Validate transaction ordering, waves, and cross-ancestor tx uniqueness
    /// against the QC chain + retention cache. Returns `true` when the caller
    /// should reject the block (logs the reason).
    fn reject_invalid_block_contents(
        &self,
        topology: &TopologySnapshot,
        block_hash: BlockHash,
        block: &Block,
    ) -> bool {
        let (_, qc_chain_tx_hashes, _) = self.collect_qc_chain_hashes(block.header().parent_hash);
        if let Err(e) = crate::validation::validate_block_for_vote(
            topology,
            block,
            &qc_chain_tx_hashes,
            &self.tx_cache,
        ) {
            warn!(
                validator = ?topology.local_validator_id(),
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
        height = height.0,
        round = round.0,
        sign_us = tracing::field::Empty,
    ))]
    fn create_vote(
        &mut self,
        topology: &TopologySnapshot,
        block_hash: BlockHash,
        height: BlockHeight,
        round: Round,
    ) -> Vec<Action> {
        // Record that we voted for this block at this height.
        // Core safety invariant: we will not vote for a different block at this height
        // unless the vote lock is released on timeout (see `advance_round`) or by
        // QC-based unlock (see `maybe_unlock_for_qc`).
        self.votes.record_own_vote(height, block_hash, round);

        // Reset the view change timer — voting proves the leader produced a
        // valid block. Non-proposers only learn about QC formation when the
        // next block header arrives (votes go to proposer only), so without
        // this reset the 5s timeout fires before the header arrives, causing
        // cascading view changes under normal load.
        self.record_leader_activity();

        let timestamp = ProposerTimestamp::from_local(self.now);

        debug!(
            validator = ?topology.local_validator_id(),
            height = height.0,
            round = round.0,
            block_hash = ?block_hash,
            "Emitting vote (signing delegated to crypto pool)"
        );

        let recipients = crate::lookups::vote_recipients(topology, height, round);

        // Emit SignAndBroadcastBlockVote — the io_loop signs on the consensus
        // crypto pool, broadcasts, and feeds the signed vote back for local
        // VoteSet tracking via BlockVoteReceived.
        vec![Action::SignAndBroadcastBlockVote {
            block_hash,
            height,
            round,
            timestamp,
            recipients,
        }]
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Vote Collection (Deferred Verification)
    // ═══════════════════════════════════════════════════════════════════════════

    /// Handle received block vote.
    ///
    /// Uses deferred verification: votes are buffered until we have enough
    /// voting power to possibly reach quorum. Only then do we batch-verify
    /// all buffered votes and build the QC in a single operation.
    ///
    /// Note: The sender identity comes from `vote.voter` (`ValidatorId`), which is
    /// signed and verified.
    #[instrument(skip(self, vote), fields(
        height = vote.height.0,
        voter = ?vote.voter,
        block_hash = ?vote.block_hash
    ))]
    pub fn on_block_vote(&mut self, topology: &TopologySnapshot, vote: BlockVote) -> Vec<Action> {
        trace!(
            validator = ?topology.local_validator_id(),
            voter = ?vote.voter,
            block_hash = ?vote.block_hash,
            "Received block vote"
        );

        self.on_block_vote_internal(topology, vote)
    }

    /// Internal vote processing. Delegates to [`VoteKeeper::accept_vote`]
    /// which runs the committee/power checks, buffers the signature, and
    /// fires batch verification once quorum is reachable.
    fn on_block_vote_internal(
        &mut self,
        topology: &TopologySnapshot,
        vote: BlockVote,
    ) -> Vec<Action> {
        let header_for_vote = self
            .pending_blocks
            .get(&vote.block_hash)
            .map(PendingBlock::header);
        self.votes
            .accept_vote(topology, vote, self.committed_height, header_for_vote)
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
        topology: &TopologySnapshot,
        block_hash: BlockHash,
        qc: Option<QuorumCertificate>,
        verified_votes: Vec<(usize, BlockVote, u64)>,
    ) -> Vec<Action> {
        if let Some(qc) = qc {
            info!(
                block_hash = ?block_hash,
                height = qc.height.0,
                signers = qc.signer_count(),
                "QC built successfully"
            );
            self.votes.mark_qc_built(block_hash);
            return vec![Action::Continuation(
                ProtocolEvent::QuorumCertificateFormed { block_hash, qc },
            )];
        }

        // Per-vote: view sync + equivocation tracking. Tracking runs only on
        // verified votes so a forged vote can't pre-empt a legitimate one.
        let validator_id = topology.local_validator_id();
        for (_, vote, _) in &verified_votes {
            let old_view = self.view_change.view;
            if self.view_change.sync_to_qc_round(vote.round) {
                info!(
                    validator = ?validator_id,
                    old_view = old_view.0,
                    new_view = vote.round.0,
                    vote_anchor_ts = vote.height.0,
                    voter = ?vote.voter,
                    "View synchronization: advancing view to match verified vote"
                );
            }
            self.votes.track_verified_received_vote(block_hash, vote);
        }

        self.votes
            .finalize_pending_batch(block_hash, verified_votes);
        self.votes.maybe_trigger_verification(topology, block_hash)
    }

    /// Handle QC signature verification result.
    ///
    /// Called when the runner completes `Action::VerifyQcSignature`.
    /// If valid, we proceed to vote on the block (for consensus) or apply the block (for sync).
    #[instrument(skip(self), fields(block_hash = ?block_hash, valid = valid))]
    pub fn on_qc_signature_verified(
        &mut self,
        topology: &TopologySnapshot,
        block_hash: BlockHash,
        valid: bool,
    ) -> Vec<Action> {
        // Check if this is a synced block verification
        info!(
            block_hash = ?block_hash,
            valid,
            pending_sync_count = self.sync.pending_verification_count(),
            pending_consensus_count = self.verification.pending_qc_count(),
            "on_qc_signature_verified: received callback"
        );
        if let Some(result) = self.sync.on_qc_verified(block_hash, valid) {
            return match result {
                // Even on failure, try applying verified blocks below the gap.
                // The failed block creates a gap that blocks further progress,
                // but blocks already verified at lower heights can still apply.
                SyncVerificationResult::Failed | SyncVerificationResult::Verified => {
                    self.try_apply_verified_synced_blocks(topology)
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

        // Check verification result
        if !is_valid {
            warn!(
                block_hash = ?block_hash,
                height = header.height.0,
                "QC signature verification FAILED - potential Byzantine attack! Rejecting block."
            );
            // Remove the pending block since we can't trust it
            self.remove_pending_block(block_hash);
            return vec![];
        }

        debug!(
            block_hash = ?block_hash,
            height = header.height.0,
            "QC signature verified successfully, proceeding to vote"
        );

        // Cache the verified QC so we don't re-verify it for other blocks
        // with the same parent_qc (e.g., during view changes).
        let qc_block_hash = header.parent_qc.block_hash;
        let qc_height = header.parent_qc.height;
        self.verification
            .cache_verified_qc(qc_block_hash, qc_height);

        // QC is valid - proceed to vote on the block
        let height = header.height;
        let round = header.round;
        self.try_vote_on_block(topology, block_hash, height, round)
    }

    /// Handle state root verification result.
    ///
    /// Called when the runner completes `Action::VerifyStateRoot`. If the state root
    /// Handle a block root verification result (unified handler).
    ///
    /// Called when any of the 5 verification actions complete (state root,
    /// transaction root, certificate root, local receipt root, conflict proofs).
    /// If invalid, the block is rejected. If valid and all other verifications are
    /// also complete, proceeds to vote for the block.
    #[instrument(skip(self), fields(block_hash = ?block_hash, ?kind, valid = valid))]
    pub fn on_block_root_verified(
        &mut self,
        topology: &TopologySnapshot,
        kind: hyperscale_core::VerificationKind,
        block_hash: BlockHash,
        valid: bool,
    ) -> Vec<Action> {
        use hyperscale_core::VerificationKind;

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
            self.remove_pending_block(block_hash);
            return vec![];
        }

        let Some(pending_block) = self.pending_blocks.get(&block_hash) else {
            // Block not in pending — likely already committed or evicted.
            debug!(
                block_hash = ?block_hash,
                ?kind,
                "Verification complete but block not found in pending or synced"
            );
            return vec![];
        };

        let Some(block) = pending_block.block() else {
            return vec![];
        };

        if !self.verification.is_block_verified(&block) {
            debug!(
                block_hash = ?block_hash,
                ?kind,
                "Verification done, waiting for other verifications"
            );
            return vec![];
        }

        let height = pending_block.header().height;
        let round = pending_block.header().round;

        self.create_vote(topology, block_hash, height, round)
    }

    /// Handle proposal built by the runner.
    ///
    /// Called when the runner completes `Action::BuildProposal`. The runner has
    /// computed the state root, built the complete block, and cached the `WriteBatch`
    /// for efficient commit later.
    #[instrument(skip(self, block, finalized_waves), fields(height = %height.0, round = round.0))]
    #[allow(clippy::too_many_arguments)]
    pub fn on_proposal_built(
        &mut self,
        topology: &TopologySnapshot,
        height: BlockHeight,
        round: Round,
        block: &Block,
        block_hash: BlockHash,
        finalized_waves: Vec<Arc<FinalizedWave>>,
        provisions: Vec<Arc<Provisions>>,
    ) -> Vec<Action> {
        match self.proposal.take_matching(height, round) {
            TakeResult::Matched => {}
            TakeResult::NotPending => {
                warn!(
                    height = height.0,
                    round = round.0,
                    "ProposalBuilt received but no pending proposal"
                );
                return vec![];
            }
            TakeResult::Mismatch { expected } => {
                warn!(
                    expected_height = expected.height.0,
                    expected_round = expected.round.0,
                    received_height = height.0,
                    received_round = round.0,
                    "ProposalBuilt mismatch - discarding stale result"
                );
                return vec![];
            }
        }

        let has_certificates = !block.certificates().is_empty();

        // Store our own block as pending (with all finalized waves + provisions).
        let mut pending_block =
            PendingBlock::from_complete_block(block, finalized_waves, provisions, self.now);

        let total_tx_count = pending_block.transaction_count();
        info!(
            validator = ?topology.local_validator_id(),
            height = height.0,
            round = round.0,
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

        self.pending_blocks.insert(block_hash, pending_block);
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
        actions.extend(self.create_vote(topology, block_hash, height, round));

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
        topology: &TopologySnapshot,
        block_height: BlockHeight,
    ) -> Vec<Action> {
        self.verification.on_block_persisted(block_height);

        // Auto-resume from sync the moment persistence catches up to the
        // sync target: a single event carries the signal, so there's no
        // room for ordering races between sync completion and persistence.
        if self.sync.is_syncing()
            && let Some(target) = self.sync.sync_target_height()
            && block_height >= target
        {
            return self.on_sync_complete(topology);
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
    pub fn pending_commit_counts(&self, qc: &QuorumCertificate) -> (usize, usize) {
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
        self.pending_blocks.get(&committable_hash).map_or_else(
            || {
                self.commits
                    .certified_blocks
                    .get(&committable_hash)
                    .map_or((0, 0), |block| {
                        (block.transactions().len(), block.certificates().len())
                    })
            },
            |pending| {
                pending.block().map_or((0, 0), |block| {
                    (block.transactions().len(), block.certificates().len())
                })
            },
        )
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
        let mut total_txs = 0;
        let mut total_certs = 0;

        for pending in self.pending_blocks.values() {
            // Use original_tx_order/original_cert_order which are available even
            // before the block is fully constructed (waiting for tx/cert data).
            // These give us the counts from the block header.
            total_txs += pending.transaction_count();
            total_certs += pending.certificate_count();
        }

        (total_txs, total_certs)
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
        height = qc.height.0,
        block_hash = ?block_hash
    ))]
    #[allow(clippy::too_many_arguments)]
    pub fn on_qc_formed(
        &mut self,
        topology: &TopologySnapshot,
        block_hash: BlockHash,
        qc: &QuorumCertificate,
        ready_txs: &[Arc<RoutableTransaction>],
        finalized_waves: Vec<Arc<FinalizedWave>>,
        provisions: Vec<Arc<Provisions>>,
    ) -> Vec<Action> {
        let height = qc.height;

        info!(
            validator = ?topology.local_validator_id(),
            block_hash = ?block_hash,
            height = height.0,
            "QC formed"
        );

        // Record leader activity - QC forming indicates progress
        self.record_leader_activity();

        // Update latest QC if this is newer
        let should_update = self
            .latest_qc
            .as_ref()
            .is_none_or(|existing| qc.height.0 > existing.height.0);

        if should_update {
            // Defer adoption if the header isn't in memory yet — we need it
            // to look up parent_state_root / parent_in_flight at proposal time.
            if self.chain_view().get_header(block_hash).is_some() {
                self.latest_qc = Some(qc.clone());
                self.maybe_unlock_for_qc(topology, qc);
            } else {
                debug!(
                    block_hash = ?block_hash,
                    height = height.0,
                    "Deferring QC adoption — block header not yet in memory"
                );
                self.deferred_qc = Some((block_hash, qc.clone()));
            }
        }

        // Reset the view change timer to count from now (leader progress).
        let mut actions = vec![Action::SetTimer {
            id: TimerId::ViewChange,
            duration: self.current_view_change_timeout(),
        }];

        actions.extend(self.try_two_chain_commit(topology, qc, CommitSource::Aggregator));

        // Propose the next block immediately — under the 2-chain commit rule,
        // block N+1 is what certifies block N, so any gap in proposing N+1
        // stalls the finalization of N and everything pending behind it.
        // `try_propose` handles the should_propose / backpressure checks.
        actions.extend(self.try_propose(topology, ready_txs, finalized_waves, provisions));

        actions
    }

    /// Two-chain commit rule: when we have QC for block N, commit block N-1.
    ///
    /// Called from both `on_qc_formed` (when we build the QC locally) and
    /// `on_block_header` (when we learn about a QC via the next block's
    /// `parent_qc`). This ensures all validators commit regardless of whether
    /// they received votes directly.
    fn try_two_chain_commit(
        &self,
        topology: &TopologySnapshot,
        qc: &QuorumCertificate,
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

        // The certifying QC for the committable block (block N-1) is the
        // parent_qc of the block whose QC this is (block N).
        let block_hash = qc.block_hash;
        let certifying_qc = self.pending_blocks.get(&block_hash).map_or_else(
            || {
                self.commits.certified_blocks.get(&block_hash).map_or_else(
                    || {
                        warn!(
                            validator = ?topology.local_validator_id(),
                            block_hash = ?block_hash,
                            committable_hash = ?committable_hash,
                            "Cannot find block to extract certifying QC for committable block"
                        );
                        qc.clone()
                    },
                    |block| block.header().parent_qc.clone(),
                )
            },
            |pending| pending.header().parent_qc.clone(),
        );

        vec![Action::Continuation(ProtocolEvent::BlockReadyToCommit {
            block_hash: committable_hash,
            qc: certifying_qc,
            source,
        })]
    }

    /// Handle block ready to commit.
    #[instrument(skip(self, qc), fields(
        height = qc.height.0,
        block_hash = ?block_hash
    ))]
    pub fn on_block_ready_to_commit(
        &mut self,
        topology: &TopologySnapshot,
        block_hash: BlockHash,
        qc: QuorumCertificate,
        source: CommitSource,
    ) -> Vec<Action> {
        // Get the block to commit
        let block = if let Some(pending) = self.pending_blocks.get(&block_hash) {
            pending.block().map(|b| (*b).clone())
        } else {
            self.commits.certified_blocks.get(&block_hash).cloned()
        };

        let Some(block) = block else {
            // Block not yet constructed - check if it's pending (waiting for transactions/certificates)
            if let Some(pending) = self.pending_blocks.get(&block_hash) {
                let height = pending.header().height;
                // Only buffer if not already committed
                if height > self.committed_height {
                    debug!(
                        validator = ?topology.local_validator_id(),
                        block_hash = ?block_hash,
                        height = height.0,
                        missing_txs = pending.missing_transaction_count(),
                        missing_waves = pending.missing_wave_count(),
                        "Block not yet complete, buffering commit until data arrives"
                    );
                    self.commits
                        .awaiting_data
                        .insert(block_hash, (height, qc, source));
                }
            } else {
                // Block not in pending_blocks - check if it's in certified_blocks
                let in_certified = self.commits.certified_blocks.contains_key(&block_hash);
                warn!(
                    validator = ?topology.local_validator_id(),
                    block_hash = ?block_hash,
                    qc_height = qc.height.0,
                    committed_height = self.committed_height.0,
                    in_certified_blocks = in_certified,
                    certified_blocks_count = self.commits.certified_blocks.len(),
                    pending_blocks_count = self.pending_blocks.len(),
                    "Block not found for commit"
                );
            }
            return vec![];
        };

        let height = block.height();

        // Check if we've already committed this or higher
        if height <= self.committed_height {
            trace!(
                "Block {} at height {} already committed",
                block_hash, height.0
            );
            return vec![];
        }

        // Buffer out-of-order commits for later processing
        // This handles the case where signature verification completes out of order,
        // causing BlockReadyToCommit events to arrive non-sequentially.
        if height != self.committed_height.next() {
            warn!(
                "Buffering out-of-order commit: expected height {}, got {}",
                self.committed_height.0 + 1,
                height.0
            );
            self.commits
                .out_of_order
                .insert(height, (block_hash, qc, source));
            return vec![];
        }

        // Commit this block and any buffered subsequent blocks
        self.commit_block_and_buffered(topology, block_hash, qc, source)
    }

    /// Check if a block that just became complete has a pending commit waiting for it.
    ///
    /// When `BlockReadyToCommit` fires but the block data (transactions/certificates) hasn't
    /// arrived yet, we buffer the commit in `pending_commits_awaiting_data`. This method
    /// checks that buffer and retries the commit now that the block is complete.
    fn try_commit_pending_data(
        &mut self,
        topology: &TopologySnapshot,
        block_hash: BlockHash,
    ) -> Vec<Action> {
        if let Some((height, qc, source)) = self.commits.take_awaiting_data(&block_hash) {
            info!(
                validator = ?topology.local_validator_id(),
                block_hash = ?block_hash,
                height = height.0,
                "Retrying commit after block data arrived"
            );
            self.on_block_ready_to_commit(topology, block_hash, qc, source)
        } else {
            vec![]
        }
    }

    /// Common bookkeeping for committing a block (shared between consensus and
    /// sync paths). Updates `committed_height`/`hash`, buffers recently
    /// committed hashes for dedup, resets backoff tracking, and cleans up old
    /// state.
    fn record_block_committed(
        &mut self,
        block: &Block,
        block_hash: BlockHash,
        commit_ts: WeightedTimestamp,
    ) {
        let height = block.height();

        self.committed_height = height;
        self.committed_hash = block_hash;
        self.committed_ts = commit_ts;
        self.committed_state_root = block.header().state_root;

        // Buffer committed hashes so collect_qc_chain_hashes can
        // exclude them even after cleanup_old_state removes the block.
        self.tx_cache.buffer_commit(
            block.transactions().iter().map(|tx| tx.hash()),
            block
                .certificates()
                .iter()
                .map(|cert| cert.wave_id().hash()),
        );

        // Reset backoff tracking — new height means fresh round counting.
        self.view_change.reset_for_height_advance();

        self.cleanup_old_state(height);
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
        topology: &TopologySnapshot,
        block_hash: BlockHash,
        certifying_qc: QuorumCertificate,
        source: CommitSource,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        let mut next = Some((block_hash, certifying_qc, source));

        while let Some((hash, qc, source)) = next.take() {
            let Some(committed_height) =
                self.commit_one_buffered_block(topology, hash, qc, source, &mut actions)
            else {
                break;
            };

            if let Some(buffered) = self.commits.take_out_of_order(committed_height.next()) {
                debug!(
                    "Processing buffered commit for height {} after committing {}",
                    committed_height.next().0,
                    committed_height.0
                );
                next = Some(buffered);
            }
        }

        // Consensus may have unblocked synced blocks that were waiting for a
        // predecessor — try to drain them now.
        actions.extend(self.try_drain_buffered_synced_blocks(topology));

        actions
    }

    /// Commit a single block in the chain and append the resulting actions
    /// (cancel-fetch for evicted pending blocks, the commit action itself,
    /// and a broadcast if we're the proposer).
    ///
    /// Returns `Some(committed_height)` if the commit succeeded and the
    /// caller should look for a buffered successor; returns `None` if the
    /// block is missing, unassembled, or arrives out of height order — the
    /// caller should stop driving the chain.
    fn commit_one_buffered_block(
        &mut self,
        topology: &TopologySnapshot,
        block_hash: BlockHash,
        qc: QuorumCertificate,
        source: CommitSource,
        actions: &mut Vec<Action>,
    ) -> Option<BlockHeight> {
        // `PendingBlock` gates itself on `is_complete()`; `construct_block`
        // attaches provisions inline on `Block::Live` — no external cache
        // lookup needed.
        let Some(pending) = self.pending_blocks.get(&block_hash) else {
            warn!(?block_hash, "Block not found in pending_blocks for commit");
            return None;
        };
        let Some(block) = pending.block().map(|b| (*b).clone()) else {
            warn!(
                ?block_hash,
                "PendingBlock not yet fully assembled at commit time"
            );
            return None;
        };

        let height = block.height();
        if height != self.committed_height.next() {
            warn!(
                "Unexpected height in commit_block_and_buffered: expected {}, got {}",
                self.committed_height.0 + 1,
                height.0
            );
            return None;
        }

        info!(
            validator = ?topology.local_validator_id(),
            height = height.0,
            block_hash = ?block_hash,
            transactions = block.transactions().len(),
            "Committing block"
        );

        // `CommitBlock` expects a cached PreparedCommit from `VerifyStateRoot`.
        // If we never verified (non-voter path), route through QcOnly so the
        // io_loop computes it inline. Capture parent state before
        // `record_block_committed` advances it.
        let state_root_verified = self.verification.is_state_root_verified(&block_hash);
        let parent_state_root = self.committed_state_root;
        let parent_block_height = self.committed_height;

        // Removed blocks self-evict from fetch protocols on the next tick
        // via the `is_stale` predicate.
        self.record_block_committed(&block, block_hash, qc.weighted_timestamp);
        self.record_leader_activity();

        actions.push(if state_root_verified {
            Action::CommitBlock {
                block: block.clone(),
                qc: qc.clone(),
                source,
            }
        } else {
            Action::CommitBlockByQcOnly {
                block: block.clone(),
                qc: qc.clone(),
                parent_state_root,
                parent_block_height,
                source,
            }
        });

        // Only the block proposer gossips the committed header globally.
        // Other validators rely on receiving it via gossip propagation. If the
        // proposer is Byzantine/slow, the RemoteHeaderCoordinator will detect
        // the liveness timeout and trigger a fallback fetch.
        if block.header().proposer == topology.local_validator_id() {
            let committed_header =
                hyperscale_types::CommittedBlockHeader::new(block.header().clone(), qc);
            actions.push(Action::BroadcastCommittedBlockHeader { committed_header });
        }

        Some(height)
    }

    /// Submit a synced block for QC signature verification. Genesis QCs
    /// skip verification and apply directly (no signature to check);
    /// everything else is registered with the sync manager and dispatched
    /// via a `VerifyQcSignature` action.
    fn submit_synced_block_for_verification(
        &mut self,
        topology: &TopologySnapshot,
        certified: CertifiedBlock,
    ) -> Vec<Action> {
        if certified.qc.is_genesis() {
            debug!(
                height = certified.block.height().0,
                "Synced block has genesis QC, applying directly"
            );
            return self.apply_synced_block(topology, certified);
        }

        let Some(public_keys) = crate::lookups::committee_public_keys(topology) else {
            warn!("Failed to collect public keys for synced block QC verification");
            return vec![];
        };

        vec![self.sync.register_for_verification(certified, public_keys)]
    }

    /// Try to drain buffered synced blocks in sequential order. Asks
    /// [`SyncManager::next_submitable`] which blocks are eligible — the
    /// coordinator just dispatches each for QC verification.
    fn try_drain_buffered_synced_blocks(&mut self, topology: &TopologySnapshot) -> Vec<Action> {
        let mut actions = Vec::new();
        let blocks = self.sync.next_submitable(
            self.committed_height,
            self.config.max_parallel_sync_verifications,
        );
        for certified in blocks {
            actions.extend(self.submit_synced_block_for_verification(topology, certified));
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
        topology: &TopologySnapshot,
        certified: CertifiedBlock,
    ) -> Vec<Action> {
        let CertifiedBlock { block, qc } = certified;
        let block_hash = block.hash();
        let height = block.height();

        info!(
            validator = ?topology.local_validator_id(),
            height = height.0,
            block_hash = ?block_hash,
            transactions = block.transactions().len(),
            certificates = block.certificates().len(),
            "Applying synced block"
        );

        // The sync peer can serve a block whose `FinalizedWave.receipts`
        // don't agree with their own EC (different shard-local execution,
        // bug, or byzantine serving). Applying such a block would feed the
        // peer's divergent `LocalReceipt.database_updates` into our
        // `pending_chain` overlay and substate DB, corrupting subsequent
        // reads. Reject at ingress; `SyncProtocol` re-attempts the height.
        for fw in block.certificates() {
            if let Err(err) = fw.validate_receipts_against_ec() {
                warn!(
                    ?block_hash,
                    height = height.0,
                    wave_id_hash = ?fw.wave_id_hash(),
                    ?err,
                    "Rejecting synced block: FinalizedWave receipts inconsistent with its EC"
                );
                return vec![];
            }
        }

        // Capture parent state BEFORE record_block_committed advances heights.
        let parent_state_root = self
            .chain_view()
            .parent_state_root(block.header().parent_hash);
        let parent_block_height = self.committed_height;

        // Advance committed_height. The QC is the proof of commit — same
        // timing as the consensus path.
        // Removed blocks self-evict from fetch protocols on the next tick
        // via the `is_stale` predicate.
        self.record_block_committed(&block, block_hash, qc.weighted_timestamp);

        // Track sync progress for the loop iterator.
        self.sync.set_sync_applied_height(height);

        // Update latest QC if this one is newer.
        if self
            .latest_qc
            .as_ref()
            .is_none_or(|existing| qc.height.0 > existing.height.0)
        {
            self.latest_qc = Some(qc.clone());
            self.maybe_unlock_for_qc(topology, &qc);
        }

        // Adopt the parent_qc from the block header if it's newer still.
        if !block.header().parent_qc.is_genesis()
            && self
                .latest_qc
                .as_ref()
                .is_none_or(|existing| block.header().parent_qc.height.0 > existing.height.0)
        {
            self.latest_qc = Some(block.header().parent_qc.clone());
            self.maybe_unlock_for_qc(topology, &block.header().parent_qc);
        }

        let mut actions = vec![Action::CommitBlockByQcOnly {
            block: block.clone(),
            qc,
            parent_state_root,
            parent_block_height,
            source: CommitSource::Sync,
        }];

        // Admit the synced block's wave certs through the canonical pathway
        // — io_loop's `Continuation(FinalizedWavesAdmitted)` interception
        // populates the serving cache so other peers can fetch from us.
        let synced_waves: Vec<_> = block.certificates().iter().map(Arc::clone).collect();
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
    fn try_apply_verified_synced_blocks(&mut self, topology: &TopologySnapshot) -> Vec<Action> {
        let mut actions = Vec::new();
        while let Some(certified) = self.sync.take_next_verified(self.committed_height) {
            actions.extend(self.apply_synced_block(topology, certified));
        }
        actions.extend(self.try_drain_buffered_synced_blocks(topology));
        actions
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // View Change
    // ═══════════════════════════════════════════════════════════════════════════
    // Implicit Round Advancement (HotStuff-2 Style)
    // ═══════════════════════════════════════════════════════════════════════════

    /// Advance the round locally (implicit view change).
    ///
    /// This is called when a timeout occurs and we need to try a new round.
    /// Unlike explicit view changes, this doesn't require coordinated voting -
    /// each validator advances locally.
    ///
    /// Returns actions to propose if we're the new proposer.
    #[instrument(skip(self), fields(new_round = self.view_change.view.0 + 1))]
    fn advance_round(&mut self, topology: &TopologySnapshot) -> Vec<Action> {
        // The next height to propose is one above the highest certified block,
        // NOT one above the committed block. This matches try_propose behavior.
        let height = self
            .latest_qc
            .as_ref()
            .map_or_else(|| self.committed_height.next(), |qc| qc.height.next());
        let old_round = self.view_change.view;
        self.view_change.advance();

        // Clear any in-flight proposal — a stale build from the previous
        // round should not block the new round's proposer. If the old build
        // completes later, on_proposal_built will see a NotPending result and
        // discard it.
        self.proposal.clear();

        info!(
            validator = ?topology.local_validator_id(),
            height = height.0,
            old_round = old_round.0,
            new_round = self.view_change.view.0,
            view_changes = self.view_change.view_changes,
            "Advancing round locally (implicit view change)"
        );

        // Log why any pending blocks at this height couldn't be verified in time.
        for pending in self.pending_blocks.values() {
            if pending.header().height == height {
                if let Some(block) = pending.block() {
                    if !self.verification.is_block_verified(&block) {
                        self.verification.log_incomplete_verification(&block);
                    }
                } else {
                    warn!(
                        block_hash = ?pending.header().hash(),
                        height = height.0,
                        missing_txs = pending.missing_transaction_count(),
                        missing_waves = pending.missing_wave_count(),
                        "View change — block still incomplete (missing data)"
                    );
                }
            }
        }

        // Timeout-based unlock: If no QC has formed at this height, we clear our
        // vote lock to allow voting for a new proposal in the next round. Safety is
        // maintained by quorum intersection — even if a QC did form but we haven't
        // seen it, a conflicting block can never reach quorum.
        // Note: this is more aggressive than HotStuff-2 (which requires a TC or
        // higher QC to unlock). See `maybe_unlock_for_qc` for QC-based unlocking.
        let latest_qc_height = self
            .latest_qc
            .as_ref()
            .map_or(BlockHeight::GENESIS, |qc| qc.height);
        if latest_qc_height < height {
            // No QC formed at current height - safe to unlock
            let had_vote = self.votes.unlock_at(height);
            let cleared_votes = self.clear_vote_tracking_for_height(height, self.view_change.view);

            if had_vote || cleared_votes > 0 {
                info!(
                    validator = ?topology.local_validator_id(),
                    height = height.0,
                    new_round = self.view_change.view.0,
                    latest_qc_height = latest_qc_height.0,
                    cleared_votes = cleared_votes,
                    "Unlocking vote at height (no QC formed, safe by quorum intersection)"
                );
            }
        }

        // Always schedule the next view change timer — proposers need it too
        // in case their block doesn't gather quorum (e.g., other validators are
        // vote-locked or offline). Without this, a proposer whose block fails to
        // reach quorum would never advance rounds again.
        let timer = Action::SetTimer {
            id: TimerId::ViewChange,
            duration: self.current_view_change_timeout(),
        };

        // Check if we're the new proposer for this height/round
        if topology.should_propose(height, self.view_change.view) {
            // Check if we've already voted at this height - if so, we're locked
            if let Some(existing_hash) = self.votes.locked_block(height) {
                info!(
                    validator = ?topology.local_validator_id(),
                    height = height.0,
                    new_round = self.view_change.view.0,
                    existing_block = ?existing_hash,
                    "Vote-locked at this height, re-proposing"
                );
                let mut actions = self.repropose_locked_block(topology, existing_hash, height);
                actions.push(timer);
                return actions;
            }

            info!(
                validator = ?topology.local_validator_id(),
                height = height.0,
                new_round = self.view_change.view.0,
                "We are the new proposer after round advance - building block"
            );

            // Build and broadcast a new block (use fallback block builder)
            let mut actions =
                self.build_and_broadcast_fallback_block(topology, height, self.view_change.view);
            actions.push(timer);
            return actions;
        }

        // Not the proposer
        vec![timer]
    }

    /// Called when we receive a QC from a block header that allows us to unlock.
    ///
    /// # HotStuff-2 Unlock Rule
    ///
    /// When we see a QC at height H, we can safely remove vote locks at heights ≤ H:
    ///
    /// - **Heights < H**: These are older heights where consensus has clearly moved past.
    ///   Any block we voted for at these heights either got committed or was abandoned.
    ///
    /// - **Height = H (same height as QC)**: If we voted for a different block B' at height H
    ///   but the QC is for block B, then B' can never get a QC (since 2f+1 already voted for B,
    ///   leaving at most f honest validators who could vote for B'). Our lock is now irrelevant.
    ///   If we voted for the same block B, unlocking is trivially safe.
    ///
    /// This enables voting for new blocks at height H+1 that extend the newly certified block,
    /// even if we previously voted for a different block at H+1 that didn't get a QC.
    ///
    /// # Safety Argument
    ///
    /// The key invariant is: once a QC exists for block B at height H, no conflicting block
    /// at height H can ever get a QC (quorum intersection). Therefore, unlocking vote locks
    /// at height H is safe - any conflicting vote would be "dead" anyway.
    ///
    /// # View Synchronization
    ///
    /// This method also synchronizes our view/round to match the QC. In HotStuff-2,
    /// liveness requires that nodes eventually reach the same view. When we see a QC
    /// formed at round R, we know the network has made progress, so we advance our
    /// view to at least R (ready to participate in round R or later).
    ///
    /// This is the key mechanism that prevents view divergence: nodes that fall behind
    /// (e.g., due to network partitions or slow clocks) will catch up when they see
    /// QCs from the rest of the network.
    fn maybe_unlock_for_qc(&mut self, topology: &TopologySnapshot, qc: &QuorumCertificate) {
        if qc.is_genesis() {
            return;
        }

        // View synchronization: advance our view to match the QC's round.
        // This ensures liveness by keeping nodes in sync with network progress.
        //
        // We sync to qc.round (not qc.round + 1) because:
        // - The QC proves consensus succeeded at this round
        // - We should be ready to participate in this round or later
        // - The proposer for the next height will use their current view
        let old_view = self.view_change.view;
        if self.view_change.sync_to_qc_round(qc.round) {
            info!(
                validator = ?topology.local_validator_id(),
                old_view = old_view.0,
                new_view = qc.round.0,
                qc_height = qc.height.0,
                "View synchronization: advancing view to match QC"
            );
        }

        // Remove vote locks for heights at or below the QC height.
        // This is safe because:
        // 1. Heights < H: consensus has moved past these heights
        // 2. Height = H: if we voted for a different block, it can never get a QC (quorum intersection)
        let qc_height = qc.height;
        let unlocked: Vec<BlockHeight> = self
            .votes
            .voted_heights
            .keys()
            .filter(|h| **h <= qc_height)
            .copied()
            .collect();

        for height in unlocked {
            if self.votes.unlock_at(height) {
                trace!(
                    validator = ?topology.local_validator_id(),
                    height = height.0,
                    qc_height = qc_height.0,
                    "Unlocked vote due to higher QC"
                );
            }
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
    /// reaches BFT here. Walks pending blocks, populates each one's
    /// `received_transactions` cache for hashes it was waiting on, and
    /// emits any unblocked vote / commit-resume actions via the shared
    /// `check_pending_blocks_for_arrival` machinery.
    #[instrument(skip(self, topology, txs), fields(count = txs.len()))]
    pub fn on_transactions_admitted(
        &mut self,
        topology: &TopologySnapshot,
        txs: &[Arc<RoutableTransaction>],
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        for tx in txs {
            let tx_hash = tx.hash();
            actions.extend(self.check_pending_blocks_for_arrival(
                topology,
                "transaction",
                |pending| pending.needs_transaction(&tx_hash),
                |pending| {
                    pending.add_transaction_arc(Arc::clone(tx));
                },
            ));
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
        topology: &TopologySnapshot,
        waves: &[Arc<FinalizedWave>],
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        for fw in waves {
            let wave_id_hash = fw.wave_id_hash();
            if let Err(err) = fw.validate_receipts_against_ec() {
                warn!(
                    ?wave_id_hash,
                    ?err,
                    "Rejecting FinalizedWave: receipts inconsistent with its EC"
                );
                continue;
            }
            actions.extend(self.check_pending_blocks_for_arrival(
                topology,
                "finalized wave",
                |pending| pending.needs_wave(&wave_id_hash),
                |pending| {
                    pending.add_finalized_wave(Arc::clone(fw));
                },
            ));
        }
        actions
    }

    /// React to provisions newly admitted to the canonical store.
    ///
    /// Called via state.rs when a `Continuation(ProvisionsVerified)` event
    /// reaches the dispatcher — same shape as `on_transactions_admitted`.
    /// Walks pending blocks, populates `received_provisions` for each block
    /// waiting on these hashes, and emits any unblocked vote / commit-resume
    /// actions.
    pub fn on_provisions_admitted(
        &mut self,
        topology: &TopologySnapshot,
        provisions: &[Arc<Provisions>],
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        for batch in provisions {
            let provisions_hash = batch.hash();
            actions.extend(self.check_pending_blocks_for_arrival(
                topology,
                "provisions",
                |pending| pending.needs_provision(&provisions_hash),
                |pending| {
                    pending.add_provision(Arc::clone(batch));
                },
            ));
        }
        actions
    }

    /// Shared machinery for post-arrival pending-block completion.
    ///
    /// Scans pending blocks in hash order (deterministic), applies `apply` to
    /// each one matching `needs`, and for any that become complete as a result
    /// emits QC-verification / vote actions plus any commits parked on the
    /// now-available block data. Triggering QC verification (rather than
    /// voting directly) is critical: signatures must be verified before
    /// voting even when data arrives late.
    fn check_pending_blocks_for_arrival<F, M>(
        &mut self,
        topology: &TopologySnapshot,
        arrival_kind: &'static str,
        needs: F,
        apply: M,
    ) -> Vec<Action>
    where
        F: Fn(&PendingBlock) -> bool,
        M: Fn(&mut PendingBlock),
    {
        let mut actions = Vec::new();
        let mut block_hashes: Vec<BlockHash> = self
            .pending_blocks
            .iter()
            .filter(|(_, pending)| needs(pending))
            .map(|(hash, _)| *hash)
            .collect();
        block_hashes.sort();

        for block_hash in block_hashes {
            let became_ready = self
                .pending_blocks
                .get_mut(&block_hash)
                .is_some_and(|pending| {
                    apply(pending);
                    if !pending.is_complete() {
                        false
                    } else if pending.block().is_some() {
                        true
                    } else {
                        match pending.construct_block() {
                            Ok(_) => true,
                            Err(e) => {
                                warn!(
                                    arrival_kind,
                                    error = %e,
                                    "Failed to construct block after arrival"
                                );
                                false
                            }
                        }
                    }
                });

            if became_ready {
                debug!(
                    validator = ?topology.local_validator_id(),
                    block_hash = ?block_hash,
                    arrival_kind,
                    "Pending block completed"
                );
                actions.extend(self.trigger_qc_verification_or_vote(topology, block_hash));
                actions.extend(self.try_commit_pending_data(topology, block_hash));
            }
        }

        actions
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Cleanup
    // ═══════════════════════════════════════════════════════════════════════════

    /// Clear vote tracking for a specific height (used during HotStuff-2 unlock).
    ///
    /// This removes all recorded votes for the given height, allowing validators
    /// to vote again after a view change proves no QC formed. This is safe because
    /// the view change certificate provides proof that consensus has moved on.
    ///
    /// The `new_round` parameter is used to selectively clear pending vote verifications:
    /// only verifications for votes at rounds LESS than the new round are cleared.
    /// This prevents a race condition where:
    /// 1. We receive a vote from another validator at round N
    /// 2. Before verification completes, we advance to round N
    /// 3. If we cleared ALL verifications, we'd lose the valid vote at round N
    ///
    /// Returns the number of vote entries cleared.
    fn clear_vote_tracking_for_height(&mut self, height: BlockHeight, new_round: Round) -> usize {
        self.votes.clear_for_height(height, new_round)
    }

    /// Clean up old state after commit. Pending blocks at or below the
    /// committed height self-evict from fetch protocols on the next tick via
    /// the `is_stale` predicate (`has_pending_block` returns false).
    fn cleanup_old_state(&mut self, committed_height: BlockHeight) {
        self.pending_blocks
            .retain(|_, pending| pending.header().height > committed_height);

        self.votes.cleanup_committed(committed_height);
        self.commits.cleanup_committed(committed_height);

        // Prune committed tx entries older than the retention window. Used
        // for proposal dedup — transactions committed far in the past will
        // have been evicted from mempool already, so stale entries just waste
        // memory.
        self.tx_cache.prune(self.committed_ts);

        // Remote headers are pruned per-shard-tip at insertion time, not by
        // local committed height (remote shards have independent heights).

        self.sync.cleanup(committed_height);
        self.verification
            .cleanup(&self.pending_blocks, committed_height);
    }

    /// Check pending blocks and emit fetch requests for those that have been
    /// waiting longer than the configured timeout.
    ///
    /// Suppressed while syncing so `SyncProtocol`'s block deliveries aren't
    /// starved by gossip-fetch requests competing for the same slots.
    #[must_use]
    pub fn check_pending_block_fetches(
        &self,
        topology: &TopologySnapshot,
        force_immediate: bool,
    ) -> Vec<Action> {
        if self.sync.is_syncing() {
            return vec![];
        }

        crate::pending::check_fetches(
            &self.pending_blocks,
            topology,
            self.now,
            self.config.transaction_fetch_timeout,
            force_immediate,
        )
    }

    /// Check if we're behind and need to catch up via sync. Called
    /// periodically by the cleanup timer. Delegates the decision to
    /// [`SyncManager::health_check`] and translates a trigger into a
    /// `start_sync`.
    pub fn check_sync_health(&mut self, topology: &TopologySnapshot) -> Vec<Action> {
        let next_needed_height = self.committed_height.next();
        let has_next_block = self.has_complete_block_at_height(next_needed_height);

        match self.sync.health_check(
            topology,
            self.committed_height,
            self.latest_qc.as_ref(),
            has_next_block,
            &self.commits,
            self.pending_blocks.len(),
        ) {
            crate::sync::SyncHealthDecision::Idle => vec![],
            crate::sync::SyncHealthDecision::TriggerSync {
                target_height,
                target_hash,
            } => self.start_sync(topology, target_height, target_hash),
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
    ) -> Vec<crate::verification::ReadyStateRootVerification> {
        let chain = ChainView {
            committed_height: self.committed_height,
            committed_hash: self.committed_hash,
            committed_state_root: self.committed_state_root,
            latest_qc: self.latest_qc.as_ref(),
            genesis: self.genesis_block.as_ref(),
            certified: &self.commits.certified_blocks,
            pending: &self.pending_blocks,
        };
        self.verification
            .drain_ready_state_root_verifications(&chain)
    }

    /// Check whether a deferred proposal was unblocked and should be retried.
    ///
    /// Returns `true` once when the parent tree becomes available. The caller
    /// emits `ContentAvailable` to re-enter `try_propose` with fresh tx
    /// selection — avoiding stale transactions from the original deferral.
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

    /// Register committed transactions for execution timeout validation.
    ///
    /// Called by the node state layer after mempool processes a committed block.
    /// Validators use this for proposal-side dedup so a tx hash already
    /// committed to the chain cannot be re-included while still in its
    /// `validity_range`. Each entry's lifetime is bounded by its own
    /// `end_timestamp_exclusive`.
    pub fn register_committed_transactions(&mut self, transactions: &[Arc<RoutableTransaction>]) {
        self.tx_cache.register_committed(transactions);
    }

    /// Remove a finalized transaction from the committed lookup.
    ///
    /// Called when a TC is committed, so the tx is no longer relevant for
    /// timeout validation.
    pub fn remove_committed_transaction(&mut self, tx_hash: &TxHash) {
        self.tx_cache.remove(tx_hash);
    }

    /// Get the current committed height.
    #[must_use]
    pub const fn committed_height(&self) -> BlockHeight {
        self.committed_height
    }

    /// Whether a pending block is currently being assembled for `block_hash`.
    #[must_use]
    pub fn has_pending_block(&self, block_hash: BlockHash) -> bool {
        self.pending_blocks.contains_key(&block_hash)
    }

    /// Single chokepoint for dropping a pending block. All single-block
    /// removals (failed verification, abort, view-change drop) go through
    /// here so future bookkeeping (metrics, indices, etc.) has one place to
    /// hook. Bulk pruning at commit time uses `cleanup_old_state` which
    /// retains in-place.
    fn remove_pending_block(&mut self, block_hash: BlockHash) -> Option<PendingBlock> {
        self.pending_blocks.remove(&block_hash)
    }

    /// Get the committed block hash.
    #[must_use]
    pub const fn committed_hash(&self) -> BlockHash {
        self.committed_hash
    }

    /// Get the latest QC.
    #[must_use]
    pub const fn latest_qc(&self) -> Option<&QuorumCertificate> {
        self.latest_qc.as_ref()
    }

    /// Get the current view/round.
    #[must_use]
    pub const fn view(&self) -> Round {
        self.view_change.view
    }

    /// Get BFT statistics for monitoring.
    #[must_use]
    pub const fn stats(&self) -> BftStats {
        BftStats {
            view_changes: self.view_change.view_changes,
            view_syncs: self.view_change.view_syncs,
            current_round: self.view_change.view.0,
            committed_height: self.committed_height,
        }
    }

    /// Get BFT memory statistics for monitoring collection sizes.
    #[must_use]
    pub fn memory_stats(&self) -> BftMemoryStats {
        BftMemoryStats {
            pending_blocks: self.pending_blocks.len(),
            vote_sets: self.votes.vote_sets_len(),
            certified_blocks: self.commits.certified_blocks_len(),
            pending_commits: self.commits.out_of_order_len(),
            pending_commits_awaiting_data: self.commits.awaiting_data_len(),
            voted_heights: self.votes.voted_heights_len(),
            received_votes_by_height: self.votes.received_votes_len(),
            committed_tx_lookup: self.tx_cache.tx_lookup_len(),
            recently_committed_txs: self.tx_cache.recent_txs_len(),
            recently_committed_certs: self.tx_cache.recent_certs_len(),
            pending_qc_verifications: self.verification.pending_qc_verifications_len(),
            verified_qcs: self.verification.verified_qcs_len(),
            pending_state_root_verifications: self
                .verification
                .pending_state_root_verifications_len(),
            buffered_synced_blocks: self.sync.buffered_synced_blocks_len(),
            pending_synced_block_verifications: self.sync.pending_verification_count(),
        }
    }

    /// Check if we are the proposer for the current height and round.
    #[must_use]
    pub fn is_current_proposer(&self, topology: &TopologySnapshot) -> bool {
        let next_height = self
            .latest_qc
            .as_ref()
            .map_or(self.committed_height.0 + 1, |qc| qc.height.0 + 1);
        topology.should_propose(BlockHeight(next_height), self.view_change.view)
    }

    /// Compute the parent hash for the next proposal.
    ///
    /// This is the latest certified block hash, or the committed hash if no QC
    /// exists yet (genesis case).
    #[must_use]
    pub fn proposal_parent_hash(&self) -> BlockHash {
        self.latest_qc
            .as_ref()
            .map_or(self.committed_hash, |qc| qc.block_hash)
    }

    /// Returns the number of transactions in the QC chain above committed height.
    ///
    /// Callers should request this many extra transactions from the mempool to
    /// compensate for duplicates that will be filtered during proposal building.
    /// This avoids the caller needing to call `collect_qc_chain_hashes` separately.
    #[must_use]
    pub fn dedup_overhead(&self) -> usize {
        let parent_hash = self.proposal_parent_hash();
        let (_, tx_hashes, _) = self.collect_qc_chain_hashes(parent_hash);
        tx_hashes.len()
    }

    /// Walk the QC chain from `parent_hash` back to committed height,
    /// collecting certificate, transaction, and provision hashes from
    /// ancestor blocks. Thin wrapper over [`ChainView::collect_ancestor_hashes`]
    /// that supplies the coordinator's `tx_cache`.
    #[must_use]
    pub fn collect_qc_chain_hashes(
        &self,
        parent_hash: BlockHash,
    ) -> (
        std::collections::HashSet<WaveIdHash>,
        std::collections::HashSet<TxHash>,
        std::collections::HashSet<ProvisionHash>,
    ) {
        self.chain_view()
            .collect_ancestor_hashes(parent_hash, &self.tx_cache)
    }

    /// Get the BFT configuration.
    #[must_use]
    pub const fn config(&self) -> &BftConfig {
        &self.config
    }

    /// Get the voted heights map (for testing/debugging).
    #[must_use]
    pub const fn voted_heights(&self) -> &HashMap<BlockHeight, (BlockHash, Round)> {
        self.votes.voted_heights()
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
    /// - Block is in `certified_blocks` (always complete)
    /// - Block is in `pending_synced_block_verifications` (synced blocks are always complete)
    /// - Block is in `buffered_synced_blocks` (synced blocks are always complete)
    fn has_complete_block_at_height(&self, height: BlockHeight) -> bool {
        // Already committed
        if height <= self.committed_height {
            return true;
        }

        // In pending blocks - but only if complete and constructed
        if self
            .pending_blocks
            .values()
            .any(|pb| pb.header().height == height && pb.is_complete() && pb.block().is_some())
        {
            return true;
        }

        // In certified blocks (always complete)
        if self
            .commits
            .certified_blocks
            .values()
            .any(|block| block.height() == height)
        {
            return true;
        }

        // In pending synced block verifications (synced blocks are always complete)
        if self.sync.has_pending_at_height(height) {
            return true;
        }

        // In buffered synced blocks (synced blocks are always complete)
        if self.sync.has_buffered_height(height) {
            return true;
        }

        false
    }

    /// Check if this node will propose at the next height.
    ///
    /// Returns true if:
    /// 1. We are the proposer for the next height/round
    /// 2. We haven't already voted at that height
    ///
    /// This is used to avoid destructively taking certificates from execution
    /// state when we won't actually be proposing a block.
    #[must_use]
    pub fn will_propose_next(&self, topology: &TopologySnapshot) -> bool {
        let next_height = self
            .latest_qc
            .as_ref()
            .map_or_else(|| self.committed_height.next(), |qc| qc.height.next());
        let round = self.view_change.view;

        topology.should_propose(next_height, round) && !self.votes.is_locked_at(next_height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{
        Bls12381G1PrivateKey, Bls12381G2Signature, CertificateRoot, GlobalReceiptHash,
        GlobalReceiptRoot, LocalReceiptRoot, ProvisionsRoot, ShardGroupId, SignerBitfield,
        TopologySnapshot, TransactionRoot, ValidatorId, ValidatorInfo, ValidatorSet,
        WeightedTimestamp, generate_bls_keypair, zero_bls_signature,
    };
    use std::collections::BTreeMap;

    fn make_test_state() -> (BftCoordinator, TopologySnapshot) {
        make_test_state_with_validators(4)
    }

    fn make_test_state_with_validators(n: usize) -> (BftCoordinator, TopologySnapshot) {
        make_test_state_with_config(n, BftConfig::default())
    }

    fn make_test_state_with_config(
        n: usize,
        config: BftConfig,
    ) -> (BftCoordinator, TopologySnapshot) {
        let keys: Vec<Bls12381G1PrivateKey> = (0..n).map(|_| generate_bls_keypair()).collect();

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
        let topology = TopologySnapshot::new(ValidatorId(0), 1, validator_set);

        let state = BftCoordinator::new(0, config, RecoveredState::default());
        (state, topology)
    }

    #[test]
    fn test_proposer_rotation() {
        // proposer_for = (height + round) % committee_size
        let (_state, topology) = make_test_state();
        assert_eq!(
            topology.proposer_for(BlockHeight(0), Round(0)),
            ValidatorId(0)
        );
        assert_eq!(
            topology.proposer_for(BlockHeight(1), Round(0)),
            ValidatorId(1)
        );
        assert_eq!(
            topology.proposer_for(BlockHeight(2), Round(0)),
            ValidatorId(2)
        );
        assert_eq!(
            topology.proposer_for(BlockHeight(0), Round(1)),
            ValidatorId(1)
        );
    }

    #[test]
    fn test_should_propose() {
        // Local validator is ValidatorId(0) — only proposes when proposer_for = 0.
        let (_state, topology) = make_test_state();
        assert!(topology.should_propose(BlockHeight(0), Round(0)));
        assert!(!topology.should_propose(BlockHeight(1), Round(0)));
        assert!(!topology.should_propose(BlockHeight(0), Round(1)));
    }

    fn make_header_at_height(height: BlockHeight, timestamp_ms: u64) -> BlockHeader {
        BlockHeader {
            shard_group_id: ShardGroupId(0),
            height,
            parent_hash: BlockHash::from_raw(Hash::from_bytes(b"parent")),
            parent_qc: QuorumCertificate::genesis(),
            proposer: ValidatorId(height.0 % 4), // Round-robin
            timestamp: ProposerTimestamp(timestamp_ms),
            round: Round(0),
            is_fallback: false,
            state_root: StateRoot::ZERO,
            transaction_root: TransactionRoot::ZERO,
            certificate_root: CertificateRoot::ZERO,
            local_receipt_root: LocalReceiptRoot::ZERO,
            provision_root: ProvisionsRoot::ZERO,
            waves: vec![],
            provision_tx_roots: BTreeMap::new(),
            in_flight: 0,
        }
    }

    fn make_empty_block(height: BlockHeight) -> Block {
        Block::Live {
            header: make_header_at_height(height, 1000),
            transactions: vec![],
            certificates: vec![],
            provisions: vec![],
        }
    }

    fn make_test_qc(block_hash: BlockHash, height: BlockHeight) -> QuorumCertificate {
        QuorumCertificate {
            block_hash,
            shard_group_id: ShardGroupId(0),
            height,
            parent_block_hash: BlockHash::ZERO,
            round: Round(0),
            signers: SignerBitfield::empty(),
            aggregated_signature: zero_bls_signature(),
            weighted_timestamp: WeightedTimestamp(100_000),
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // QC Signature Verification Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_qc_signature_verification_delegates_to_runner() {
        use hyperscale_core::Action;
        use hyperscale_types::SignerBitfield;

        let (mut state, topology) = make_multi_validator_state_at(1);
        state.set_time(LocalTimestamp::from_millis(100_000));

        // committed_height = 1 avoids triggering sync on the non-genesis parent QC.
        let parent_hash = BlockHash::from_raw(Hash::from_bytes(b"parent_block"));
        state.committed_height = BlockHeight(1);
        state.committed_hash = parent_hash;

        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        let parent_qc = QuorumCertificate {
            signers,
            weighted_timestamp: WeightedTimestamp(99_000),
            ..make_test_qc(parent_hash, BlockHeight(1))
        };
        let header = BlockHeader {
            parent_hash,
            parent_qc,
            ..make_header_at_height(BlockHeight(2), 100_000)
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

    #[test]
    fn test_qc_signature_verified_success_triggers_vote() {
        use hyperscale_core::Action;
        use hyperscale_types::SignerBitfield;

        let (mut state, topology) = make_multi_validator_state_at(1);
        state.set_time(LocalTimestamp::from_millis(100_000));

        let parent_hash = BlockHash::from_raw(Hash::from_bytes(b"parent_block"));
        state.committed_height = BlockHeight(1);
        state.committed_hash = parent_hash;
        state
            .commits
            .certified_blocks
            .insert(parent_hash, make_empty_block(BlockHeight(1)));

        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        let parent_qc = QuorumCertificate {
            signers,
            weighted_timestamp: WeightedTimestamp(99_000),
            ..make_test_qc(parent_hash, BlockHeight(1))
        };
        let header = BlockHeader {
            parent_hash,
            parent_qc,
            ..make_header_at_height(BlockHeight(2), 100_000)
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
        let after_qc = state.on_qc_signature_verified(&topology, block_hash, true);
        assert!(
            !after_qc
                .iter()
                .any(|a| matches!(a, Action::SignAndBroadcastBlockVote { .. }))
        );

        // State root completes — now we vote.
        let after_roots = state.on_block_root_verified(
            &topology,
            hyperscale_core::VerificationKind::StateRoot,
            block_hash,
            true,
        );
        assert!(
            after_roots
                .iter()
                .any(|a| matches!(a, Action::SignAndBroadcastBlockVote { .. }))
        );
    }

    #[test]
    fn test_qc_signature_verified_failure_rejects_block() {
        use hyperscale_types::SignerBitfield;

        let (mut state, topology) = make_multi_validator_state_at(1);
        state.set_time(LocalTimestamp::from_millis(100_000));

        let parent_hash = BlockHash::from_raw(Hash::from_bytes(b"parent_block"));
        state.committed_height = BlockHeight(1);
        state.committed_hash = parent_hash;

        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        let parent_qc = QuorumCertificate {
            signers,
            weighted_timestamp: WeightedTimestamp(99_000),
            ..make_test_qc(parent_hash, BlockHeight(1))
        };
        let header = BlockHeader {
            parent_hash,
            parent_qc,
            ..make_header_at_height(BlockHeight(2), 100_000)
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
        assert!(state.pending_blocks.contains_key(&block_hash));

        let actions = state.on_qc_signature_verified(&topology, block_hash, false);
        assert!(actions.is_empty());
        assert!(!state.pending_blocks.contains_key(&block_hash));
    }

    #[test]
    fn test_genesis_qc_skips_verification() {
        use hyperscale_core::Action;

        let (mut state, topology) = make_multi_validator_state_at(1);

        state.set_time(LocalTimestamp::from_millis(100_000));

        // Genesis QC has no signature — verification must be skipped, not queued.
        let header = BlockHeader {
            parent_hash: BlockHash::ZERO,
            ..make_header_at_height(BlockHeight(1), 100_000)
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

    #[test]
    fn test_advance_round_proposer_broadcasts() {
        use hyperscale_core::Action;

        // Local = ValidatorId(2) is proposer at (1, 1) since (1+1)%4 = 2.
        let (mut state, topology) = make_multi_validator_state_at(2);
        state.set_time(LocalTimestamp::from_millis(100_000));

        let actions = state.advance_round(&topology);
        assert!(actions.iter().any(|a| matches!(
            a,
            Action::BuildProposal {
                is_fallback: true,
                ..
            }
        )));
    }

    #[test]
    fn test_advance_round_unlocks_when_no_qc() {
        let (mut state, topology) = make_test_state();
        state.set_time(LocalTimestamp::from_millis(100_000));

        state.votes.voted_heights.insert(
            BlockHeight(1),
            (
                BlockHash::from_raw(Hash::from_bytes(b"voted_block")),
                Round(0),
            ),
        );
        let _ = state.advance_round(&topology);

        assert!(!state.votes.voted_heights.contains_key(&BlockHeight(1)));
    }

    #[test]
    fn test_maybe_unlock_for_qc() {
        // QC at height H unlocks vote locks at all heights ≤ H.
        let (mut state, topology) = make_test_state();
        for h in 1..=3 {
            state.votes.voted_heights.insert(
                BlockHeight(h),
                (
                    BlockHash::from_raw(Hash::from_bytes(format!("block{h}").as_bytes())),
                    Round(0),
                ),
            );
        }

        let qc = QuorumCertificate {
            parent_block_hash: BlockHash::from_raw(Hash::from_bytes(b"parent")),
            ..make_test_qc(
                BlockHash::from_raw(Hash::from_bytes(b"qc_block")),
                BlockHeight(2),
            )
        };
        state.maybe_unlock_for_qc(&topology, &qc);

        assert!(!state.votes.voted_heights.contains_key(&BlockHeight(1)));
        assert!(!state.votes.voted_heights.contains_key(&BlockHeight(2)));
        assert!(state.votes.voted_heights.contains_key(&BlockHeight(3)));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Vote Locking Safety Tests
    // ═══════════════════════════════════════════════════════════════════════════

    /// Build a fresh coordinator + 4-validator topology. Local validator sits at
    /// committee index 0. For tests that need a different local index, call
    /// [`make_multi_validator_state_at`]. For tests that need to sign votes
    /// themselves, call [`make_multi_validator_state_with_keys`].
    fn make_multi_validator_state() -> (BftCoordinator, TopologySnapshot) {
        make_multi_validator_state_at(0)
    }

    fn make_multi_validator_state_at(local_idx: u32) -> (BftCoordinator, TopologySnapshot) {
        let (state, topology, _keys) = make_multi_validator_state_with_keys(local_idx);
        (state, topology)
    }

    fn make_multi_validator_state_with_keys(
        local_idx: u32,
    ) -> (BftCoordinator, TopologySnapshot, Vec<Bls12381G1PrivateKey>) {
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
        let topology = TopologySnapshot::new(ValidatorId(u64::from(local_idx)), 1, validator_set);
        let state = BftCoordinator::new(local_idx, BftConfig::default(), RecoveredState::default());
        (state, topology, keys)
    }

    #[test]
    fn test_vote_locking_prevents_voting_for_different_block_at_same_height() {
        let (mut state, topology) = make_multi_validator_state();
        state.set_time(LocalTimestamp::from_millis(100_000));

        let height = BlockHeight(1);
        let round_0 = Round(0);
        let round_1 = Round(1);

        // Two headers at height 1: A at round 0, B at round 1 with different
        // proposer and timestamp — distinct hashes.
        let first_block = make_header_at_height(height, 100_000);
        let first_hash = first_block.hash();
        let second_block = BlockHeader {
            proposer: ValidatorId(2),
            round: round_1,
            ..make_header_at_height(height, 100_001)
        };
        let second_hash = second_block.hash();

        let actions = state.try_vote_on_block(&topology, first_hash, height, round_0);
        assert!(!actions.is_empty());
        assert_eq!(
            state.votes.voted_heights.get(&height).unwrap().0,
            first_hash
        );

        // Vote lock prevents voting for a different block at the same height,
        // even in a later round.
        let actions = state.try_vote_on_block(&topology, second_hash, height, round_1);
        assert!(actions.is_empty());
        assert_eq!(
            state.votes.voted_heights.get(&height).unwrap().0,
            first_hash
        );
    }

    #[test]
    fn test_vote_locking_allows_revoting_same_block() {
        // Re-voting for the same block at a later round is a no-op (no re-broadcast).
        let (mut state, topology) = make_multi_validator_state();
        state.set_time(LocalTimestamp::from_millis(100_000));

        let height = BlockHeight(1);
        let block_hash = make_header_at_height(height, 100_000).hash();

        let actions = state.try_vote_on_block(&topology, block_hash, height, Round(0));
        assert!(!actions.is_empty());

        let actions = state.try_vote_on_block(&topology, block_hash, height, Round(1));
        assert!(actions.is_empty());
        assert_eq!(
            state.votes.voted_heights.get(&height).unwrap().0,
            block_hash
        );
    }

    #[test]
    fn test_forged_vote_cannot_block_legitimate_validator() {
        // Forged votes are buffered pre-verification and never reach
        // received_votes_by_height, so a legitimate vote for a different block
        // from the same voter is not flagged as equivocation on verification.
        let (mut state, topology) = make_multi_validator_state();
        state.set_time(LocalTimestamp::from_millis(100_000));

        let height = BlockHeight(5);
        let voter = ValidatorId(2);
        let block_b = BlockHash::from_raw(Hash::from_bytes(b"legitimate_block"));
        let vote = BlockVote {
            block_hash: block_b,
            shard_group_id: ShardGroupId(0),
            height,
            round: Round(0),
            voter,
            signature: zero_bls_signature(),
            timestamp: ProposerTimestamp(100_000),
        };

        let _ = state.on_qc_result(&topology, block_b, None, vec![(0, vote, 1)]);

        let (recorded_hash, _) = state
            .votes
            .received_votes_by_height
            .get(&(height, voter))
            .expect("legitimate vote must be recorded");
        assert_eq!(*recorded_hash, block_b);
    }
    // ═══════════════════════════════════════════════════════════════════════════
    // Re-proposal After View Change Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_repropose_locked_block_keeps_original_round() {
        // After a view change lands us as leader for a height we've already voted
        // at, we must re-broadcast the *original* header — same round, proposer,
        // and block hash — otherwise our vote lock would prevent us from voting
        // for our own re-proposal.
        let (mut state, topology) = make_multi_validator_state();
        state.set_time(LocalTimestamp::from_millis(100_000));

        let height = BlockHeight(1);
        // proposer_for(1, 0) = ValidatorId(1)
        let original_header = make_header_at_height(height, 100_000);
        let original_block_hash = original_header.hash();

        let pending = PendingBlock::from_manifest(
            original_header,
            BlockManifest::default(),
            LocalTimestamp::ZERO,
        );
        state.pending_blocks.insert(original_block_hash, pending);
        state
            .votes
            .voted_heights
            .insert(height, (original_block_hash, Round(0)));

        let actions = state.repropose_locked_block(&topology, original_block_hash, height);

        let Some(Action::BroadcastBlockHeader { header: gossip, .. }) = actions
            .iter()
            .find(|a| matches!(a, Action::BroadcastBlockHeader { .. }))
        else {
            panic!("expected BroadcastBlockHeader");
        };
        let reproposed = gossip.as_ref();
        assert_eq!(reproposed.round, Round(0));
        assert_eq!(reproposed.hash(), original_block_hash);
        assert_eq!(reproposed.proposer, ValidatorId(1));
    }

    #[test]
    fn test_reproposed_block_passes_validation() {
        // A receiving validator (possibly already at view=31) must still accept a
        // re-proposal carrying the original round — validation only keys off
        // proposer_for(height, header.round), not the receiver's view.
        let (state, topology) = make_multi_validator_state();
        let header = make_header_at_height(BlockHeight(1), state.now.as_millis());

        assert!(
            crate::validation::validate_header(
                &topology,
                &header,
                state.committed_height,
                &state.config,
                state.now,
            )
            .is_ok()
        );
    }

    #[test]
    fn test_reproposed_block_with_wrong_proposer_fails_validation() {
        let (state, topology) = make_multi_validator_state();
        // proposer_for(1, 0) = ValidatorId(1), but the header claims ValidatorId(3).
        let header = BlockHeader {
            proposer: ValidatorId(3),
            ..make_header_at_height(BlockHeight(1), state.now.as_millis())
        };

        let result = crate::validation::validate_header(
            &topology,
            &header,
            state.committed_height,
            &state.config,
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
    fn test_multiple_consecutive_view_changes_unlock_and_revote() {
        // Three view changes with no QC: each must unlock the current vote. The
        // third advance lands us as proposer and must emit a fallback.
        // proposer_for(1, R) = (1 + R) % 4 — local is ValidatorId(0), so we're
        // proposer at R=3.
        let (mut state, topology) = make_test_state();
        state.set_time(LocalTimestamp::from_millis(100_000));
        let height = BlockHeight(1);

        let vote_and_advance = |state: &mut BftCoordinator, block: &[u8], round: Round| {
            state.votes.voted_heights.insert(
                height,
                (BlockHash::from_raw(Hash::from_bytes(block)), round),
            );
            state.advance_round(&topology)
        };

        // Rounds 1 and 2: not proposer, vote lock cleared on each advance.
        state.view_change.view = Round(0);
        let _ = vote_and_advance(&mut state, b"block_a", Round(0));
        assert_eq!(state.view_change.view, Round(1));
        assert!(!state.votes.voted_heights.contains_key(&height));

        let _ = vote_and_advance(&mut state, b"block_b", Round(1));
        assert_eq!(state.view_change.view, Round(2));
        assert!(!state.votes.voted_heights.contains_key(&height));

        // Round 3: we're proposer — advance emits a fallback BuildProposal.
        let actions = vote_and_advance(&mut state, b"block_c", Round(2));
        assert_eq!(state.view_change.view, Round(3));
        assert!(!state.votes.voted_heights.contains_key(&height));
        assert!(actions.iter().any(|a| matches!(
            a,
            Action::BuildProposal {
                is_fallback: true,
                ..
            }
        )));
    }

    #[test]
    fn test_view_change_does_not_unlock_lower_heights() {
        // advance_round only unlocks at the height we're now proposing for
        // (latest_qc.height + 1). Vote locks at lower heights are left for
        // cleanup_committed to remove on commit.
        let (mut state, topology) = make_test_state();
        state.set_time(LocalTimestamp::from_millis(100_000));

        let qc_block = BlockHash::from_raw(Hash::from_bytes(b"qc_block_at_1"));
        state.latest_qc = Some(make_test_qc(qc_block, BlockHeight(1)));
        state
            .votes
            .voted_heights
            .insert(BlockHeight(1), (qc_block, Round(0)));
        state.votes.voted_heights.insert(
            BlockHeight(2),
            (
                BlockHash::from_raw(Hash::from_bytes(b"block_at_2")),
                Round(0),
            ),
        );

        let _ = state.advance_round(&topology);

        assert!(state.votes.voted_heights.contains_key(&BlockHeight(1)));
        assert!(!state.votes.voted_heights.contains_key(&BlockHeight(2)));
    }

    #[test]
    fn test_unlock_for_qc_at_same_height_different_block() {
        // QC for block B proves A can never get a QC (quorum intersection), so
        // our vote lock on A is safe to release.
        let (mut state, topology) = make_test_state();
        let block_a = BlockHash::from_raw(Hash::from_bytes(b"block_a"));
        let block_b = BlockHash::from_raw(Hash::from_bytes(b"block_b"));
        let height = BlockHeight(5);

        state
            .votes
            .voted_heights
            .insert(height, (block_a, Round(0)));
        let qc = QuorumCertificate {
            parent_block_hash: BlockHash::from_raw(Hash::from_bytes(b"parent")),
            ..make_test_qc(block_b, height)
        };
        state.maybe_unlock_for_qc(&topology, &qc);

        assert!(!state.votes.voted_heights.contains_key(&height));
    }

    #[test]
    fn test_qc_formed_proposes_empty_block_for_finalization() {
        // Under the 2-chain commit rule, block N+1 is what certifies block N.
        // After a QC forms we must propose N+1 immediately — even with no
        // content — or finalization of N stalls.
        let (mut state, topology) = make_test_state();
        state.set_time(LocalTimestamp::from_millis(100_000));
        // Parent tree must be available or try_propose defers.
        state.committed_height = BlockHeight(3);
        state.verification.on_block_persisted(BlockHeight(3));

        let block_3_hash = BlockHash::from_raw(Hash::from_bytes(b"block_3"));
        state
            .commits
            .certified_blocks
            .insert(block_3_hash, make_empty_block(BlockHeight(3)));

        let qc = QuorumCertificate {
            parent_block_hash: BlockHash::from_raw(Hash::from_bytes(b"block_2")),
            ..make_test_qc(block_3_hash, BlockHeight(3))
        };

        let actions = state.on_qc_formed(&topology, block_3_hash, &qc, &[], vec![], vec![]);

        // Should emit BuildProposal for height 4 even with empty content.
        let has_build_proposal = actions.iter().any(
            |a| matches!(a, Action::BuildProposal { height, .. } if height == &BlockHeight(4)),
        );

        assert!(
            has_build_proposal,
            "Should propose empty block immediately after QC formation to advance finalization"
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

        // Local validator is ValidatorId(0). Proposer for (h=1, r=0) is
        // ValidatorId((1+0)%4)=ValidatorId(1) — not us. Point the chain at
        // (h=4, r=0) where proposer = (4+0)%4 = ValidatorId(0).
        let parent_hash = BlockHash::from_raw(Hash::from_bytes(b"parent_tree_missing"));
        state.committed_height = BlockHeight(3);
        state.committed_hash = parent_hash;
        state
            .commits
            .certified_blocks
            .insert(parent_hash, make_empty_block(BlockHeight(3)));
        state.latest_qc = Some(make_test_qc(parent_hash, BlockHeight(3)));
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
        state.verification.on_block_persisted(BlockHeight(3));
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
                |a| matches!(a, Action::BuildProposal { height, .. } if *height == BlockHeight(4))
            ),
            "third try_propose should dispatch the BuildProposal"
        );
    }

    #[test]
    fn test_qc_verification_caching_skips_redundant_verification() {
        // When the same parent QC appears in multiple block headers (e.g. after a
        // view change), we verify it once and hit the cache for subsequent blocks.
        use hyperscale_core::Action;
        use hyperscale_types::SignerBitfield;

        let (mut state, topology) = make_multi_validator_state_at(0);
        state.set_time(LocalTimestamp::from_millis(100_000));

        let parent_hash = BlockHash::from_raw(Hash::from_bytes(b"parent_block"));
        state.committed_height = BlockHeight(1);
        state.committed_hash = parent_hash;
        state
            .commits
            .certified_blocks
            .insert(parent_hash, make_empty_block(BlockHeight(1)));

        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        let parent_qc = QuorumCertificate {
            signers,
            weighted_timestamp: WeightedTimestamp(99_000),
            ..make_test_qc(parent_hash, BlockHeight(1))
        };

        let header1 = BlockHeader {
            parent_hash,
            parent_qc: parent_qc.clone(),
            ..make_header_at_height(BlockHeight(2), 100_000)
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
        state
            .verification
            .cache_verified_qc(parent_hash, BlockHeight(1));

        // Second block at round 1 sharing the same parent QC.
        let header2 = BlockHeader {
            parent_hash,
            parent_qc,
            proposer: ValidatorId(3),
            round: Round(1),
            ..make_header_at_height(BlockHeight(2), 100_001)
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

    // ═══════════════════════════════════════════════════════════════════════════
    // Helpers retained for no-duplicate-transactions walk tests below
    // ═══════════════════════════════════════════════════════════════════════════

    fn make_test_tx_with_seed(seed: u8) -> Arc<hyperscale_types::RoutableTransaction> {
        use hyperscale_types::test_utils;
        Arc::new(test_utils::test_transaction(seed))
    }

    fn sort_txs_by_hash(txs: &mut [Arc<hyperscale_types::RoutableTransaction>]) {
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
        state.committed_height = BlockHeight(3);
        state.verification.on_block_persisted(BlockHeight(3));

        // Validator 0 proposes for height 4 since (4+0)%4 = 0.
        state.latest_qc = Some(QuorumCertificate {
            parent_block_hash: BlockHash::from_raw(Hash::from_bytes(b"block_2")),
            ..make_test_qc(
                BlockHash::from_raw(Hash::from_bytes(b"block_3")),
                BlockHeight(3),
            )
        });

        state.set_syncing(&topology, true);
        assert!(state.is_syncing());

        // Ready txs must be dropped — sync blocks are always empty.
        let ready_txs = vec![Arc::new(hyperscale_types::test_utils::test_transaction(1))];
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
        state.committed_height = BlockHeight(3);
        state.verification.on_block_persisted(BlockHeight(3));

        let old_timestamp = 1000u64;
        state.latest_qc = Some(QuorumCertificate {
            parent_block_hash: BlockHash::from_raw(Hash::from_bytes(b"block_2")),
            weighted_timestamp: WeightedTimestamp(old_timestamp),
            ..make_test_qc(
                BlockHash::from_raw(Hash::from_bytes(b"block_3")),
                BlockHeight(3),
            )
        });
        state.set_syncing(&topology, true);

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
        let (mut state, topology) = make_test_state();
        state.set_syncing(&topology, true);
        assert!(state.is_syncing());

        // Fresh state has no pending blocks, so SyncResumed is the only action.
        let actions = state.on_sync_complete(&topology);
        assert!(!state.is_syncing());
        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            Action::Continuation(ProtocolEvent::SyncResumed)
        ));
    }

    #[test]
    fn test_syncing_validator_can_vote_for_others_blocks() {
        // Syncing only blocks us from proposing content; we still vote on others'
        // blocks once verification completes.
        let (mut state, topology) = make_multi_validator_state();
        state.set_time(LocalTimestamp::from_millis(100_000));
        state.set_syncing(&topology, true);

        let block_hash = BlockHash::from_raw(Hash::from_bytes(b"other_proposer_block"));
        let height = BlockHeight(1);
        let actions = state.try_vote_on_block(&topology, block_hash, height, Round(0));

        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::SignAndBroadcastBlockVote { .. }))
        );
        assert!(state.votes.voted_heights.contains_key(&height));
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
        state.set_syncing(&topology, true);
        assert!(state.should_advance_round());
        assert!(state.check_round_timeout(&topology).is_some());
    }

    #[test]
    fn test_sync_mode_resets_leader_activity_on_exit() {
        // Leaving sync resets leader activity to `now` so the fresh round doesn't
        // immediately time out on stale activity from before sync started.
        let (mut state, topology) = make_test_state();
        state.set_time(LocalTimestamp::from_millis(100_000));
        state.view_change.last_leader_activity = Some(LocalTimestamp::ZERO);

        state.set_syncing(&topology, true);
        state.on_sync_complete(&topology);

        assert_eq!(
            state.view_change.last_leader_activity,
            Some(LocalTimestamp::from_millis(100_000))
        );
    }

    #[test]
    fn test_syncing_validator_vote_locking_preserved() {
        // Vote locking applies during sync just as in normal operation.
        let (mut state, topology) = make_multi_validator_state();
        state.set_time(LocalTimestamp::from_millis(100_000));
        state.set_syncing(&topology, true);

        let height = BlockHeight(1);
        let block_a = BlockHash::from_raw(Hash::from_bytes(b"block_a"));
        let block_b = BlockHash::from_raw(Hash::from_bytes(b"block_b"));

        let actions = state.try_vote_on_block(&topology, block_a, height, Round(0));
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::SignAndBroadcastBlockVote { .. }))
        );

        let actions = state.try_vote_on_block(&topology, block_b, height, Round(1));
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::SignAndBroadcastBlockVote { .. }))
        );
        assert_eq!(
            state.votes.voted_heights.get(&height).map(|(h, _)| *h),
            Some(block_a)
        );
    }

    #[test]
    fn test_start_sync_sets_syncing_flag() {
        // check_sync_health triggers StartSync when the gap to latest_qc is
        // large (>3) without a pending commit.
        let (mut state, topology) = make_test_state();
        state.set_time(LocalTimestamp::from_millis(100_000));
        assert!(!state.is_syncing());

        state.latest_qc = Some(QuorumCertificate {
            parent_block_hash: BlockHash::from_raw(Hash::from_bytes(b"block_4")),
            weighted_timestamp: WeightedTimestamp(1000),
            ..make_test_qc(
                BlockHash::from_raw(Hash::from_bytes(b"block_5")),
                BlockHeight(5),
            )
        });
        let actions = state.check_sync_health(&topology);

        assert!(state.is_syncing());
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::StartSync { .. }))
        );
    }

    #[test]
    fn test_stale_sync_block_ignored() {
        // A synced block below committed_height must be dropped without advancing
        // any state — including the syncing flag.
        let (mut state, topology) = make_test_state();
        state.set_time(LocalTimestamp::from_millis(100_000));
        state.committed_height = BlockHeight(10);

        let block = Block::Live {
            header: BlockHeader {
                parent_hash: BlockHash::ZERO,
                timestamp: ProposerTimestamp(1000),
                ..make_header_at_height(BlockHeight(1), 1000)
            },
            transactions: vec![],
            certificates: vec![],
            provisions: vec![],
        };
        let qc = QuorumCertificate {
            weighted_timestamp: WeightedTimestamp(1000),
            ..make_test_qc(block.hash(), BlockHeight(1))
        };
        let certified = CertifiedBlock::new_unchecked(block, qc);

        let actions = state.on_sync_block_ready_to_apply(&topology, certified);
        assert!(actions.is_empty());
        assert!(!state.is_syncing());
    }

    #[test]
    fn test_sync_block_records_leader_activity() {
        // Dispatching a sync proposal is progress — it must reset the leader
        // activity timer so we don't immediately view-change out of it.
        let (mut state, topology) = make_test_state();
        state.set_time(LocalTimestamp::from_millis(100_000));
        state.view_change.last_leader_activity = Some(LocalTimestamp::ZERO);

        state.latest_qc = Some(QuorumCertificate {
            parent_block_hash: BlockHash::from_raw(Hash::from_bytes(b"block_2")),
            ..make_test_qc(
                BlockHash::from_raw(Hash::from_bytes(b"block_3")),
                BlockHeight(3),
            )
        });
        state.set_syncing(&topology, true);
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
        state.committed_height = BlockHeight(3);
        state.verification.on_block_persisted(BlockHeight(3));

        let parent_timestamp = 50_000u64;
        state.latest_qc = Some(QuorumCertificate {
            parent_block_hash: BlockHash::from_raw(Hash::from_bytes(b"block_2")),
            weighted_timestamp: WeightedTimestamp(parent_timestamp),
            ..make_test_qc(
                BlockHash::from_raw(Hash::from_bytes(b"block_3")),
                BlockHeight(3),
            )
        });

        state.set_syncing(&topology, true);
        let sync_actions = state.build_and_dispatch_proposal(
            &topology,
            BlockHeight(4),
            Round(0),
            ProposalKind::Sync,
        );
        state.set_syncing(&topology, false);

        state.pending_blocks.clear();
        state.commits.certified_blocks.clear();
        state.votes.voted_heights.clear();

        let fallback_actions =
            state.build_and_broadcast_fallback_block(&topology, BlockHeight(4), Round(1));

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
        assert_eq!(sync_ts, ProposerTimestamp(100_000));
        assert!(fb_fb);
        assert_eq!(fb_ts, ProposerTimestamp(parent_timestamp));
    }

    #[test]
    fn test_chain_advances_with_syncing_proposer() {
        // Sync mode must not suppress proposal — a syncing proposer still emits
        // BuildProposal (with an empty payload) so the chain keeps advancing.
        let (mut state, topology) = make_test_state();
        state.set_time(LocalTimestamp::from_millis(100_000));
        state.committed_height = BlockHeight(3);
        state.verification.on_block_persisted(BlockHeight(3));

        state.latest_qc = Some(QuorumCertificate {
            parent_block_hash: BlockHash::from_raw(Hash::from_bytes(b"block_2")),
            ..make_test_qc(
                BlockHash::from_raw(Hash::from_bytes(b"block_3")),
                BlockHeight(3),
            )
        });
        state.set_syncing(&topology, true);

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
        state.committed_height = BlockHeight(3);

        let tx1 = make_test_tx_with_seed(10);
        let tx2 = make_test_tx_with_seed(20);
        // Ancestor block at height 5 contains tx1
        let ancestor_block = Block::Live {
            header: BlockHeader {
                parent_hash: BlockHash::from_raw(Hash::from_bytes(b"grandparent")),
                ..make_header_at_height(BlockHeight(5), 100_000)
            },
            transactions: vec![tx1.clone()],
            certificates: vec![],
            provisions: vec![],
        };
        let ancestor_hash = ancestor_block.hash();
        state
            .commits
            .certified_blocks
            .insert(ancestor_hash, ancestor_block);

        // New block at height 6, parent = ancestor, contains tx1 (duplicate) + tx2
        let mut txs = vec![tx1, tx2];
        sort_txs_by_hash(&mut txs);
        let block = Block::Live {
            header: BlockHeader {
                parent_hash: ancestor_hash,
                ..make_header_at_height(BlockHeight(6), 100_001)
            },
            transactions: txs,
            certificates: vec![],
            provisions: vec![],
        };

        let result = {
            let (_, qc_chain, _) = state.collect_qc_chain_hashes(block.header().parent_hash);
            crate::validation::validate_no_duplicate_transactions(
                &block,
                &qc_chain,
                &state.tx_cache,
            )
        };
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already in QC chain ancestor"));
    }

    #[test]
    fn test_validate_no_duplicate_transactions_ignores_committed_ancestors() {
        let (mut state, _topology) = make_test_state();
        state.committed_height = BlockHeight(5);

        let tx1 = make_test_tx_with_seed(10);

        // Ancestor at height 5 (== committed_height) contains tx1
        let ancestor_block = Block::Live {
            header: BlockHeader {
                parent_hash: BlockHash::from_raw(Hash::from_bytes(b"grandparent")),
                ..make_header_at_height(BlockHeight(5), 100_000)
            },
            transactions: vec![tx1.clone()],
            certificates: vec![],
            provisions: vec![],
        };
        let ancestor_hash = ancestor_block.hash();
        state
            .commits
            .certified_blocks
            .insert(ancestor_hash, ancestor_block);

        // Block at height 6, parent = ancestor. tx1 is in ancestor but ancestor
        // is at committed height so the walk stops — this should be allowed.
        let block = Block::Live {
            header: BlockHeader {
                parent_hash: ancestor_hash,
                ..make_header_at_height(BlockHeight(6), 100_001)
            },
            transactions: vec![tx1],
            certificates: vec![],
            provisions: vec![],
        };

        // Ancestor is at committed height, so walk stops before checking it
        assert!(
            {
                let (_, qc_chain, _) = state.collect_qc_chain_hashes(block.header().parent_hash);
                crate::validation::validate_no_duplicate_transactions(
                    &block,
                    &qc_chain,
                    &state.tx_cache,
                )
            }
            .is_ok()
        );
    }

    #[test]
    fn test_apply_synced_block_rejects_inconsistent_wave_receipts() {
        use hyperscale_types::{
            ExecutionCertificate, ExecutionOutcome, FinalizedWave, LocalReceipt, ReceiptBundle,
            TransactionOutcome, TxOutcome, WaveCertificate, WaveId,
        };

        let (mut state, topology) = make_test_state();
        state.set_time(LocalTimestamp::from_millis(100_000));
        let committed_before = state.committed_height;

        // Build a FinalizedWave whose EC attests "success" but whose receipt
        // reports "failure" — the divergent-peer signature we want to reject.
        let tx_hash = TxHash::from_raw(Hash::from_bytes(b"tx_divergent"));
        let wave_id = WaveId::new(
            ShardGroupId(0),
            BlockHeight(1),
            std::collections::BTreeSet::new(),
        );
        let ec = ExecutionCertificate::new(
            wave_id.clone(),
            WeightedTimestamp(1),
            GlobalReceiptRoot::ZERO,
            vec![TxOutcome {
                tx_hash,
                outcome: ExecutionOutcome::Executed {
                    receipt_hash: GlobalReceiptHash::ZERO,
                    success: true,
                },
            }],
            Bls12381G2Signature([0u8; 96]),
            SignerBitfield::new(4),
        );
        let bad_wave = Arc::new(FinalizedWave {
            certificate: Arc::new(WaveCertificate {
                wave_id,
                execution_certificates: vec![Arc::new(ec)],
            }),
            receipts: vec![ReceiptBundle {
                tx_hash,
                local_receipt: Arc::new(LocalReceipt {
                    outcome: TransactionOutcome::Failure, // EC said Success
                    #[allow(clippy::default_trait_access)]
                    database_updates: Default::default(),
                    application_events: vec![],
                }),
                execution_output: None,
            }],
        });

        let block = Block::Live {
            header: BlockHeader {
                parent_hash: BlockHash::ZERO,
                ..make_header_at_height(BlockHeight(1), 1000)
            },
            transactions: vec![],
            certificates: vec![bad_wave],
            provisions: vec![],
        };
        let qc = QuorumCertificate {
            weighted_timestamp: WeightedTimestamp(1000),
            ..make_test_qc(block.hash(), BlockHeight(1))
        };

        let certified = CertifiedBlock::new_unchecked(block, qc);
        let actions = state.apply_synced_block(&topology, certified);

        assert!(
            actions.is_empty(),
            "apply_synced_block should reject a block whose wave receipts disagree with its EC"
        );
        assert_eq!(
            state.committed_height, committed_before,
            "rejected block must not advance committed_height"
        );
    }
}
