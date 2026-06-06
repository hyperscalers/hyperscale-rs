//! Sync coordination for catching up to the network.
//!
//! Manages the sync state flag, synced block buffering, and pending
//! synced block QC verifications. `ShardCoordinator` owns this as a field and
//! delegates sync-specific bookkeeping here.

use std::collections::{BTreeMap, HashMap};

use hyperscale_core::Action;
use hyperscale_types::{
    Block, BlockHash, BlockHeight, Bls12381G1PublicKey, CertifiedBlock, QuorumCertificate,
    ValidatorId, Verified, VotePower,
};
use tracing::{debug, info, warn};

use crate::commit_pipeline::CommitPipeline;

/// View-change spin tolerated before `health_check` escalates a partial-
/// isolation pattern to sync. Below the threshold we wait for normal
/// consensus or QC adoption to make progress.
const SPIN_WITHOUT_QC_ADVANCE_THRESHOLD: u64 = 3;

/// Per-height cap on the future-block buffer. Prevents a Byzantine peer
/// (or a small pool of them) from blowing up memory by pumping distinct
/// fake blocks at the same height: we accept up to this many distinct
/// hashes per height, then drop further arrivals. Honest blocks survive
/// because legitimate consensus produces one block per (height, round)
/// — even with extensive view changes you'd rarely exceed a handful of
/// candidates per height.
const MAX_BUFFERED_PER_HEIGHT: usize = 4;

/// Max distance ahead of `committed_height` at which a synced block is
/// accepted into the future-height buffer. Pairs with
/// `MAX_BUFFERED_PER_HEIGHT` to bound total buffered blocks: a Byzantine
/// peer could otherwise spread distinct heights across the entire
/// `BlockHeight` range and force the `BTreeMap` to grow without bound, since
/// the per-height cap only constrains a single height. Tied loosely to
/// `max_parallel_sync_verifications` × 16: leaves slack for the verify
/// pipeline plus arrival jitter while keeping worst-case buffered count
/// bounded.
const MAX_BUFFER_FUTURE_HORIZON: u64 = 256;

/// Synced block tracked by the sync manager, split by QC-verification stage.
///
/// `InFlight` covers the window between QC-signature dispatch and the
/// `on_qc_verified` callback. `QcVerified` carries the typestate witness
/// produced by the verifier; once a block reaches this variant it can be
/// handed to `apply_synced_block` without further re-wrapping.
#[derive(Debug, Clone)]
pub enum PendingSyncedBlockVerification {
    /// QC signature verification has been dispatched but not yet completed.
    InFlight(CertifiedBlock),
    /// QC signature has been verified. The paired `block`'s hash equals
    /// `qc.block_hash()` by [`CertifiedBlock`]'s pairing invariant.
    QcVerified {
        /// The synced block whose QC has been verified.
        block: Block,
        /// The verified QC; `qc.block_hash() == block.hash()`.
        qc: Verified<QuorumCertificate>,
    },
}

impl PendingSyncedBlockVerification {
    const fn block(&self) -> &Block {
        match self {
            Self::InFlight(c) => c.block(),
            Self::QcVerified { block, .. } => block,
        }
    }
}

/// Sync block coordination state.
///
/// `ShardCoordinator` owns this as a field and delegates sync-specific bookkeeping
/// to it. Core protocol state changes (`committed_height`, `latest_qc`) remain
/// on `ShardCoordinator`.
pub struct BlockSyncManager {
    /// Whether we are currently syncing (catching up to the network).
    syncing: bool,

    /// The sync target height — set at sync start, cleared on resume.
    /// Used by `on_block_persisted` to auto-resume when persistence catches up.
    sync_target_height: Option<BlockHeight>,

    /// Highest height handed to `apply_synced_block`, advancing together
    /// with `committed_height` inside that call. The sync apply loop keys
    /// off this marker rather than `committed_height` so it can pick the
    /// next height without racing the commit pipeline's own advancement.
    sync_applied_height: BlockHeight,

    /// Highest `latest_qc.height()` `health_check` has observed. Together with
    /// `view_changes_at_last_qc_advance` lets the health check distinguish
    /// "I'm spinning view changes but the chain is also moving" from
    /// "I'm spinning while the chain is stuck somewhere I can't see."
    last_qc_height_seen: BlockHeight,

    /// Snapshot of the view-change counter at the moment
    /// `last_qc_height_seen` last advanced. The delta against the current
    /// counter is "view changes spun without a QC advance" — the partial-
    /// isolation signal we want to catch with sync.
    view_changes_at_last_qc_advance: u64,

    /// Buffered out-of-order synced blocks waiting for earlier blocks.
    /// Maps `height` → `block_hash` → `CertifiedBlock`. Keying on hash (not
    /// height alone) prevents a slot-squat attack where a Byzantine peer
    /// races honest peers to plant a wrong-hash block at a future height
    /// and we'd `Drop` the honest arrival as duplicate. Per-height entry
    /// count is capped by `MAX_BUFFERED_PER_HEIGHT`.
    buffered_synced_blocks: BTreeMap<BlockHeight, HashMap<BlockHash, CertifiedBlock>>,

    /// Synced blocks pending QC signature verification.
    /// Maps `block_hash` -> pending synced block info.
    pending_synced_block_verifications: HashMap<BlockHash, PendingSyncedBlockVerification>,
}

impl BlockSyncManager {
    /// Create a new `BlockSyncManager`.
    pub fn new() -> Self {
        Self {
            syncing: false,
            sync_target_height: None,
            sync_applied_height: BlockHeight::GENESIS,
            last_qc_height_seen: BlockHeight::GENESIS,
            view_changes_at_last_qc_advance: 0,
            buffered_synced_blocks: BTreeMap::new(),
            pending_synced_block_verifications: HashMap::new(),
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Sync flag
    // ═══════════════════════════════════════════════════════════════════════

    /// Check if this validator is currently syncing.
    pub const fn is_syncing(&self) -> bool {
        self.syncing
    }

    /// Set the syncing flag.
    pub const fn set_syncing(&mut self, syncing: bool) {
        self.syncing = syncing;
        if !syncing {
            self.sync_target_height = None;
        }
    }

    /// Set the sync target height (called when sync starts).
    pub const fn set_sync_target(&mut self, height: BlockHeight) {
        self.sync_target_height = Some(height);
    }

    /// Get the sync target height, if syncing.
    pub const fn sync_target_height(&self) -> Option<BlockHeight> {
        self.sync_target_height
    }

    /// Record that a synced block at `height` has been submitted for
    /// state-root verification (but not yet committed).
    pub fn set_sync_applied_height(&mut self, height: BlockHeight) {
        self.sync_applied_height = self.sync_applied_height.max(height);
    }

    /// Highest synced height admitted to the chain state. Its round-contiguous
    /// commit may still be pending, so this can sit a block above
    /// `committed_height`; sync completion tracks it rather than the commit.
    pub const fn sync_applied_height(&self) -> BlockHeight {
        self.sync_applied_height
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Synced block receiving and buffering
    // ═══════════════════════════════════════════════════════════════════════

    /// Check if a synced block is already pending verification.
    pub fn has_pending_verification(&self, block_hash: &BlockHash) -> bool {
        self.pending_synced_block_verifications
            .contains_key(block_hash)
    }

    /// Check if `(height, block_hash)` is already buffered. Used by `ingest`
    /// to dedup arrivals; keying on hash means a Byzantine wrong-hash block
    /// at a future height doesn't shadow honest arrivals at the same height.
    pub fn has_buffered(&self, height: BlockHeight, block_hash: &BlockHash) -> bool {
        self.buffered_synced_blocks
            .get(&height)
            .is_some_and(|entries| entries.contains_key(block_hash))
    }

    /// Check if any candidate is buffered at `height`, regardless of hash.
    /// Used by the chain-progress query that just wants to know whether the
    /// next height has *some* block in the pipeline (it doesn't matter which
    /// candidate eventually wins QC verification).
    pub fn has_any_buffered_at_height(&self, height: BlockHeight) -> bool {
        self.buffered_synced_blocks
            .get(&height)
            .is_some_and(|entries| !entries.is_empty())
    }

    /// Whether the per-height buffer cap leaves room for another arrival
    /// at `height`. Returns `true` when no entries exist at `height` yet.
    fn has_capacity_at(&self, height: BlockHeight) -> bool {
        self.buffered_synced_blocks
            .get(&height)
            .is_none_or(|entries| entries.len() < MAX_BUFFERED_PER_HEIGHT)
    }

    /// Check if any pending verification has a block at the given height.
    pub fn has_pending_at_height(&self, height: BlockHeight) -> bool {
        self.pending_synced_block_verifications
            .values()
            .any(|p| p.block().height() == height)
    }

    /// Buffer a future synced block for later processing. Returns `false`
    /// (and silently drops the arrival) when the per-height entry cap is
    /// already saturated — the cap defends against memory exhaustion via
    /// many distinct fake blocks at the same height.
    pub fn buffer_block(&mut self, height: BlockHeight, certified: CertifiedBlock) -> bool {
        if !self.has_capacity_at(height) {
            warn!(
                height = height.inner(),
                cap = MAX_BUFFERED_PER_HEIGHT,
                "Synced-block buffer at per-height cap — dropping arrival"
            );
            return false;
        }
        let block_hash = certified.block().hash();
        debug!(
            height = height.inner(),
            ?block_hash,
            "Buffering future synced block for later"
        );
        self.buffered_synced_blocks
            .entry(height)
            .or_default()
            .insert(block_hash, certified);
        true
    }

    /// Plan the next batch of buffered synced blocks to dispatch for QC
    /// verification. Respects `max_parallel_sync_verifications` and starts
    /// from one above the highest already-handled height so we don't resubmit
    /// work already in flight.
    ///
    /// "Already-handled" is the max of the highest pending verification, the
    /// committed tip, and `sync_applied_height` — the last covers blocks
    /// admitted to the chain state but not yet finalized, since the
    /// round-contiguous commit lags admission by a block and `committed_height`
    /// alone would re-drain the gap.
    ///
    /// Returns empty when the pending set is already saturated or no
    /// sequentially-eligible buffered block is available.
    pub fn next_submitable(
        &mut self,
        committed_height: BlockHeight,
        max_parallel: usize,
    ) -> Vec<CertifiedBlock> {
        let pending_count = self.pending_verification_count();
        if pending_count >= max_parallel {
            return Vec::new();
        }
        let slots_available = max_parallel - pending_count;

        let highest_pending_height = self.highest_pending_height(committed_height);
        let start_height = highest_pending_height
            .max(committed_height)
            .max(self.sync_applied_height)
            + 1u64;

        self.drain_buffered(start_height, slots_available)
    }

    /// Classify a freshly received synced block against our current state:
    /// drop it as stale/duplicate, mark it for QC-verification dispatch, or
    /// stash it in the future-height buffer. Returns the outcome the
    /// coordinator should act on.
    pub fn ingest(
        &mut self,
        certified: CertifiedBlock,
        committed_height: BlockHeight,
    ) -> IngestOutcome {
        let block_hash = certified.block().hash();
        let height = certified.block().height();

        if height <= committed_height {
            info!(
                height = height.inner(),
                committed = committed_height.inner(),
                "Synced block already committed - filtering"
            );
            return IngestOutcome::Drop;
        }

        // Distinct-height horizon cap: even with `MAX_BUFFERED_PER_HEIGHT`
        // capping each slot, a Byzantine peer can spread arrivals across
        // arbitrary future heights and bloat the BTreeMap. Bound the
        // accepted future window to `committed_height + horizon`.
        let max_future_height = committed_height
            .inner()
            .saturating_add(MAX_BUFFER_FUTURE_HORIZON);
        if height.inner() > max_future_height {
            warn!(
                height = height.inner(),
                committed = committed_height.inner(),
                horizon = MAX_BUFFER_FUTURE_HORIZON,
                "Synced block beyond buffer horizon — dropping"
            );
            return IngestOutcome::Drop;
        }

        if self.has_pending_verification(&block_hash) {
            info!(
                height = height.inner(),
                "Synced block already pending verification - filtering"
            );
            return IngestOutcome::Drop;
        }

        if self.has_buffered(height, &block_hash) {
            info!(
                height = height.inner(),
                ?block_hash,
                "Synced block already buffered - filtering"
            );
            return IngestOutcome::Drop;
        }

        let next_needed = committed_height.next();
        if height == next_needed {
            return IngestOutcome::Submit(Box::new(certified));
        }

        if height > next_needed {
            if self.buffer_block(height, certified) {
                return IngestOutcome::Buffered;
            }
            return IngestOutcome::Drop;
        }

        warn!(
            height = height.inner(),
            next_needed = next_needed.inner(),
            committed = committed_height.inner(),
            "Unexpected synced block height - already have or past this"
        );
        IngestOutcome::Drop
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Pending synced block verification tracking
    // ═══════════════════════════════════════════════════════════════════════

    /// Record `certified` as awaiting QC verification and construct the
    /// corresponding [`Action::VerifyQcSignature`] to dispatch. The
    /// tracking insert is paired with the action emission so the two can
    /// never get out of sync; callers should check
    /// [`Self::has_pending_verification`] first to avoid clobbering an
    /// already-in-flight entry.
    pub fn register_for_verification(
        &mut self,
        certified: CertifiedBlock,
        public_keys: Vec<Bls12381G1PublicKey>,
        voting_powers: Vec<VotePower>,
        quorum_threshold: VotePower,
    ) -> Action {
        let block_hash = certified.block().hash();
        let height = certified.block().height();
        let qc = certified.qc_verifiable().clone();

        if self
            .pending_synced_block_verifications
            .contains_key(&block_hash)
        {
            warn!(
                height = height.inner(),
                ?block_hash,
                "Overwriting existing pending synced block verification — this is unexpected"
            );
        }
        info!(
            height = height.inner(),
            ?block_hash,
            signers = qc.signers().count(),
            "Submitting synced block for QC verification"
        );
        self.pending_synced_block_verifications.insert(
            block_hash,
            PendingSyncedBlockVerification::InFlight(certified),
        );

        Action::VerifyQcSignature {
            qc,
            public_keys,
            voting_powers,
            quorum_threshold,
            block_hash,
        }
    }

    /// Handle QC verification result for a synced block.
    ///
    /// On success, `verified_qc` carries the typestate witness produced by
    /// the verifier; the pending entry transitions from `InFlight` to
    /// `QcVerified`, pairing the block with the verified QC. On failure,
    /// the entry is dropped.
    ///
    /// Returns `Some(result)` if this was a synced block verification,
    /// `None` if the `block_hash` wasn't found.
    pub fn on_qc_verified(
        &mut self,
        block_hash: BlockHash,
        verified_qc: Option<Verified<QuorumCertificate>>,
    ) -> Option<BlockSyncVerificationResult> {
        let pending = self
            .pending_synced_block_verifications
            .remove(&block_hash)?;

        let Some(verified_qc) = verified_qc else {
            warn!(
                block_hash = ?block_hash,
                height = pending.block().height().inner(),
                "Synced block QC signature verification FAILED - rejecting block"
            );
            // Only this block is removed (already done above). Other pending
            // verifications are kept — a single bad peer shouldn't cascade
            // into losing all in-flight sync work. Blocks above this height
            // will be blocked by the gap until a re-sync fills it.
            return Some(BlockSyncVerificationResult::Failed);
        };

        info!(
            block_hash = ?block_hash,
            height = pending.block().height().inner(),
            "Synced block QC verified successfully"
        );

        let (block, _) = match pending {
            PendingSyncedBlockVerification::InFlight(c) => c.into_parts(),
            PendingSyncedBlockVerification::QcVerified { block, qc } => {
                // Duplicate verification callback — replace and continue.
                (block, qc.into())
            }
        };
        self.pending_synced_block_verifications.insert(
            block_hash,
            PendingSyncedBlockVerification::QcVerified {
                block,
                qc: verified_qc,
            },
        );

        Some(BlockSyncVerificationResult::Verified)
    }

    /// Number of pending synced block verifications (for logging).
    pub fn pending_verification_count(&self) -> usize {
        self.pending_synced_block_verifications.len()
    }

    /// Whether any sync block QC verification is still awaiting its result
    /// (submitted but not yet verified). Used by `should_advance_round` to
    /// suppress view changes while we're actively verifying sync blocks.
    ///
    /// Distinct from [`Self::has_pending_verification`], which asks whether
    /// one specific block is tracked regardless of verification status.
    pub fn has_unverified_in_flight(&self) -> bool {
        self.pending_synced_block_verifications
            .values()
            .any(|p| matches!(p, PendingSyncedBlockVerification::InFlight(_)))
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Drain verified blocks
    // ═══════════════════════════════════════════════════════════════════════

    /// Take the next consecutive verified block at the given height.
    ///
    /// Returns the (block, verified QC) pair if a QC-verified entry exists
    /// at `height`, otherwise `None`. The pairing invariant
    /// `qc.block_hash == block.hash()` is preserved across the move.
    pub fn take_verified_at_height(
        &mut self,
        height: BlockHeight,
    ) -> Option<(Block, Verified<QuorumCertificate>)> {
        let block_hash =
            self.pending_synced_block_verifications
                .iter()
                .find_map(|(h, p)| match p {
                    PendingSyncedBlockVerification::QcVerified { block, .. }
                        if block.height() == height =>
                    {
                        Some(*h)
                    }
                    _ => None,
                })?;

        let pending = self
            .pending_synced_block_verifications
            .remove(&block_hash)
            .unwrap();

        match pending {
            PendingSyncedBlockVerification::QcVerified { block, qc } => Some((block, qc)),
            PendingSyncedBlockVerification::InFlight(_) => {
                unreachable!("filter above selected only QcVerified entries")
            }
        }
    }

    /// Take the next block to apply in the consecutive-verified sequence.
    /// Computes the target height from `committed_height` and our own
    /// `sync_applied_height` marker (both advance together in apply), then
    /// pops the matching verified entry. Returns `None` once the chain
    /// catches up to the verified frontier; also logs the verified /
    /// unverified pending heights for diagnostics.
    pub fn take_next_verified(
        &mut self,
        committed_height: BlockHeight,
    ) -> Option<(Block, Verified<QuorumCertificate>)> {
        let base = committed_height.max(self.sync_applied_height);
        let next_height = base + 1u64;
        self.log_verification_state(committed_height, next_height);
        self.take_verified_at_height(next_height)
    }

    /// Log the current state of pending verifications (for debugging).
    pub fn log_verification_state(&self, committed_height: BlockHeight, next_height: BlockHeight) {
        let verified_heights: Vec<_> = self
            .pending_synced_block_verifications
            .values()
            .filter_map(|p| match p {
                PendingSyncedBlockVerification::QcVerified { block, .. } => {
                    Some(block.height().inner())
                }
                PendingSyncedBlockVerification::InFlight(_) => None,
            })
            .collect();
        let unverified_heights: Vec<_> = self
            .pending_synced_block_verifications
            .values()
            .filter_map(|p| match p {
                PendingSyncedBlockVerification::InFlight(c) => Some(c.block().height().inner()),
                PendingSyncedBlockVerification::QcVerified { .. } => None,
            })
            .collect();
        info!(
            committed_height = committed_height.inner(),
            next_height = next_height.inner(),
            verified_heights = ?verified_heights,
            unverified_heights = ?unverified_heights,
            "try_apply_verified_synced_blocks: checking"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Drain buffered blocks
    // ═══════════════════════════════════════════════════════════════════════

    /// Drain buffered blocks that can be submitted for verification.
    ///
    /// Walks contiguous heights starting at `start_height`. At each height,
    /// drains *every* buffered candidate (one Byzantine and several honest
    /// blocks may sit at the same height under the slot-squat defense);
    /// each gets dispatched for QC verification independently. Stops at the
    /// first height with no buffered entries OR once `max_count` is reached.
    /// May produce slightly more blocks than `max_count` so an entire
    /// height's candidate set is delivered atomically — the per-height cap
    /// (`MAX_BUFFERED_PER_HEIGHT`) bounds that overshoot.
    pub fn drain_buffered(
        &mut self,
        start_height: BlockHeight,
        max_count: usize,
    ) -> Vec<CertifiedBlock> {
        let mut result = Vec::new();
        let mut height = start_height;

        while result.len() < max_count {
            let Some(entries) = self.buffered_synced_blocks.remove(&height) else {
                break;
            };
            for (block_hash, certified) in entries {
                debug!(
                    height = height.inner(),
                    ?block_hash,
                    "Draining buffered synced block"
                );
                result.push(certified);
            }
            height += 1u64;
        }

        result
    }

    /// Get the highest height among pending verifications.
    pub fn highest_pending_height(&self, committed_height: BlockHeight) -> BlockHeight {
        self.pending_synced_block_verifications
            .values()
            .map(|p| p.block().height())
            .max()
            .unwrap_or(committed_height)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Cleanup
    // ═══════════════════════════════════════════════════════════════════════

    /// Remove sync state at or below committed height.
    ///
    /// Uses consensus committed height (not JMT-persisted height). These
    /// diverge during async persistence, but sync state tracks consensus
    /// progress — once a block is committed to consensus, its sync
    /// bookkeeping is no longer needed regardless of persistence state.
    pub fn cleanup(&mut self, committed_height: BlockHeight) {
        self.buffered_synced_blocks
            .retain(|height, _| *height > committed_height);

        self.pending_synced_block_verifications
            .retain(|_, pending| pending.block().height() > committed_height);
    }

    /// Total number of buffered candidates across all heights. May exceed
    /// the unique-height count when multiple distinct hashes are buffered
    /// at the same height (slot-squat defense).
    pub(crate) fn buffered_synced_blocks_len(&self) -> usize {
        self.buffered_synced_blocks.values().map(HashMap::len).sum()
    }
}

/// Classification of an incoming synced block. Returned by
/// [`BlockSyncManager::ingest`] so the coordinator doesn't have to replicate the
/// stale/duplicate/ordering branching.
pub enum IngestOutcome {
    /// Stale (already committed), duplicate of an in-flight verification,
    /// already-buffered, or arrived at a lower-than-needed height. The
    /// caller does nothing further. Reason is logged internally.
    Drop,
    /// Block is the next height we need. Caller should dispatch QC
    /// verification (or apply directly on genesis QC). Boxed to keep the
    /// enum compact across variants.
    Submit(Box<CertifiedBlock>),
    /// Block is a future height and has been stored internally. Caller
    /// should drive the buffer drain to see if anything is now submittable.
    Buffered,
}

/// Result of a synced block QC verification.
pub enum BlockSyncVerificationResult {
    /// QC verified successfully — ready to apply consecutive blocks.
    Verified,
    /// QC verification failed — the bad block is removed, other pending
    /// verifications are preserved. Blocks above the failed height are
    /// blocked by the gap until a re-sync fills it.
    Failed,
}

/// Decision returned by [`BlockSyncManager::health_check`].
pub enum BlockSyncHealthDecision {
    /// No action needed — already synced, already syncing, or making progress.
    Idle,
    /// Trigger catch-up sync to the named target.
    TriggerSync { target_height: BlockHeight },
}

impl BlockSyncManager {
    /// Decide whether we're stuck behind the latest QC and should fall back
    /// to catch-up sync. Called periodically by the cleanup timer.
    ///
    /// The caller supplies `has_next_block`, which is `true` iff a complete
    /// block is available at `committed_height + 1` across pending,
    /// certified, or sync-buffered storage. Three escalation levels fire:
    ///
    /// - No block at the next height → sync immediately.
    /// - Block present but no pending commit and the gap exceeds 3 → the
    ///   QC that would trigger the commit was likely dropped; sync.
    /// - Block present with a pending commit but the gap exceeds 10 → the
    ///   commit flow is stalled (block hashes may have diverged after a
    ///   prior sync); sync to recover.
    #[allow(clippy::too_many_arguments)] // `ShardCoordinator` owns each input; bundling them just adds a struct without consolidating ownership
    pub fn health_check(
        &mut self,
        me: ValidatorId,
        committed_height: BlockHeight,
        latest_qc: Option<&QuorumCertificate>,
        has_next_block: bool,
        commits: &CommitPipeline,
        pending_blocks_len: usize,
        view_changes: u64,
    ) -> BlockSyncHealthDecision {
        let Some(latest_qc) = latest_qc else {
            return BlockSyncHealthDecision::Idle;
        };

        let qc_height = latest_qc.height();

        // Snapshot the view-change counter every time the QC advances. The
        // delta against the current counter is "view changes spun without
        // a QC advance" — caught below as a partial-isolation signal.
        if qc_height > self.last_qc_height_seen {
            self.last_qc_height_seen = qc_height;
            self.view_changes_at_last_qc_advance = view_changes;
        }

        if committed_height >= qc_height {
            return BlockSyncHealthDecision::Idle;
        }

        if self.is_syncing() {
            return BlockSyncHealthDecision::Idle;
        }

        let next_needed_height = committed_height.next();
        let has_pending_commit = commits.has_out_of_order_at(next_needed_height);
        let gap = qc_height - committed_height;
        let view_changes_since_qc_advance =
            view_changes.saturating_sub(self.view_changes_at_last_qc_advance);

        // Partial-isolation escalation: if we've spun several view changes
        // without `latest_qc` moving — even when `gap` is small enough that
        // the gap-based heuristics below would stay Idle — peers are
        // forming QCs we aren't seeing in time. Drop into sync to fetch
        // the missing blocks (and their certifying QCs) directly rather
        // than burning more rounds reactively.
        if view_changes_since_qc_advance >= SPIN_WITHOUT_QC_ADVANCE_THRESHOLD {
            warn!(
                validator = ?me,
                committed_height = committed_height.inner(),
                qc_height = qc_height.inner(),
                gap = gap,
                view_changes_since_qc_advance,
                "Spinning view changes without QC advance — triggering sync to recover"
            );
            return BlockSyncHealthDecision::TriggerSync {
                target_height: qc_height,
            };
        }

        if gap > 5 {
            warn!(
                validator = ?me,
                committed_height = committed_height.inner(),
                next_needed_height = next_needed_height.inner(),
                qc_height = qc_height.inner(),
                gap = gap,
                has_next_complete = has_next_block,
                has_pending_commit = has_pending_commit,
                pending_commits = commits.out_of_order_len(),
                pending_blocks = pending_blocks_len,
                "Sync health check status"
            );
        }

        if has_next_block {
            if has_pending_commit {
                if gap > 10 {
                    warn!(
                        validator = ?me,
                        committed_height = committed_height.inner(),
                        next_needed_height = next_needed_height.inner(),
                        qc_height = qc_height.inner(),
                        gap = gap,
                        "Have complete block and pending commit but significantly behind - triggering sync to recover"
                    );
                    return BlockSyncHealthDecision::TriggerSync {
                        target_height: qc_height,
                    };
                }
                return BlockSyncHealthDecision::Idle;
            }

            if gap > 3 {
                warn!(
                    validator = ?me,
                    committed_height = committed_height.inner(),
                    next_needed_height = next_needed_height.inner(),
                    qc_height = qc_height.inner(),
                    gap = gap,
                    "Have complete block but no pending commit (missing QC) - triggering sync to recover"
                );
                return BlockSyncHealthDecision::TriggerSync {
                    target_height: qc_height,
                };
            }
            return BlockSyncHealthDecision::Idle;
        }

        info!(
            validator = ?me,
            committed_height = committed_height.inner(),
            next_needed_height = next_needed_height.inner(),
            qc_height = qc_height.inner(),
            "Sync health check: can't make progress, triggering catch-up sync"
        );

        BlockSyncHealthDecision::TriggerSync {
            target_height: qc_height,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use hyperscale_types::{
        BeaconWitnessLeafCount, BeaconWitnessRoot, Block, BlockHeader, BoundedVec, CertificateRoot,
        Hash, InFlightCount, LocalReceiptRoot, ProposerTimestamp, ProvisionsRoot, Round, ShardId,
        SignerBitfield, StateRoot, TransactionRoot, ValidatorId, WeightedTimestamp,
        zero_bls_signature,
    };

    use super::*;

    fn header(height: BlockHeight, tag: &[u8]) -> BlockHeader {
        BlockHeader::new(
            ShardId::ROOT,
            height,
            BlockHash::from_raw(Hash::from_bytes(tag)),
            QuorumCertificate::genesis(ShardId::ROOT),
            ValidatorId::new(0),
            ProposerTimestamp::from_millis(0),
            Round::INITIAL,
            false,
            StateRoot::ZERO,
            TransactionRoot::ZERO,
            CertificateRoot::ZERO,
            LocalReceiptRoot::ZERO,
            ProvisionsRoot::ZERO,
            Vec::new(),
            BTreeMap::new(),
            InFlightCount::ZERO,
            BeaconWitnessRoot::ZERO,
            BeaconWitnessLeafCount::ZERO,
        )
    }

    fn certified(height: BlockHeight, tag: &[u8]) -> CertifiedBlock {
        let block = Block::Live {
            header: header(height, tag),
            transactions: Arc::new(BoundedVec::new()),
            certificates: Arc::new(BoundedVec::new()),
            provisions: Arc::new(BoundedVec::new()),
        };
        let qc = QuorumCertificate::new(
            block.hash(),
            ShardId::ROOT,
            height,
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::empty(),
            zero_bls_signature(),
            WeightedTimestamp::ZERO,
        );
        CertifiedBlock::new_unchecked(block, qc)
    }

    // ─── ingest ──────────────────────────────────────────────────────────

    #[test]
    fn ingest_drops_stale_block_at_or_below_committed() {
        let mut sm = BlockSyncManager::new();
        let out = sm.ingest(certified(BlockHeight::new(3), b"s"), BlockHeight::new(5));
        assert!(matches!(out, IngestOutcome::Drop));
    }

    #[test]
    fn ingest_drops_block_already_pending_verification() {
        let mut sm = BlockSyncManager::new();
        let cb = certified(BlockHeight::new(6), b"p");
        sm.track_pending_verification_for_test(cb.clone());
        let out = sm.ingest(cb, BlockHeight::new(5));
        assert!(matches!(out, IngestOutcome::Drop));
    }

    #[test]
    fn ingest_drops_block_already_buffered() {
        let mut sm = BlockSyncManager::new();
        let cb = certified(BlockHeight::new(7), b"b");
        sm.buffer_block(BlockHeight::new(7), cb.clone());
        let out = sm.ingest(cb, BlockHeight::new(5));
        assert!(matches!(out, IngestOutcome::Drop));
    }

    #[test]
    fn ingest_submits_when_block_is_next_needed_height() {
        let mut sm = BlockSyncManager::new();
        let cb = certified(BlockHeight::new(6), b"next");
        let out = sm.ingest(cb, BlockHeight::new(5));
        assert!(matches!(out, IngestOutcome::Submit(_)));
    }

    #[test]
    fn ingest_buffers_future_block_and_stores_it() {
        let mut sm = BlockSyncManager::new();
        let cb = certified(BlockHeight::new(8), b"future");
        let block_hash = cb.block().hash();
        let out = sm.ingest(cb, BlockHeight::new(5));
        assert!(matches!(out, IngestOutcome::Buffered));
        assert!(sm.has_buffered(BlockHeight::new(8), &block_hash));
        assert!(sm.has_any_buffered_at_height(BlockHeight::new(8)));
    }

    #[test]
    fn ingest_distinct_hashes_at_same_height_both_buffered() {
        // Slot-squat defense: a Byzantine wrong-hash block at a future
        // height must not shadow honest arrivals at the same height.
        // Pre-fix `has_buffered_height(h)` keyed only on height, so the
        // honest block at `h` would have been dropped as duplicate.
        let mut sm = BlockSyncManager::new();
        let bogus = certified(BlockHeight::new(8), b"bogus");
        let honest = certified(BlockHeight::new(8), b"honest");
        let bogus_hash = bogus.block().hash();
        let honest_hash = honest.block().hash();
        assert!(matches!(
            sm.ingest(bogus, BlockHeight::new(5)),
            IngestOutcome::Buffered
        ));
        assert!(matches!(
            sm.ingest(honest, BlockHeight::new(5)),
            IngestOutcome::Buffered
        ));
        assert!(sm.has_buffered(BlockHeight::new(8), &bogus_hash));
        assert!(sm.has_buffered(BlockHeight::new(8), &honest_hash));
    }

    #[test]
    fn ingest_drops_when_per_height_cap_saturated() {
        let mut sm = BlockSyncManager::new();
        for i in 0u8..u8::try_from(MAX_BUFFERED_PER_HEIGHT).unwrap() {
            let cb = certified(BlockHeight::new(8), &[i; 4]);
            assert!(matches!(
                sm.ingest(cb, BlockHeight::new(5)),
                IngestOutcome::Buffered
            ));
        }
        // Past the cap — drop with `IngestOutcome::Drop`.
        let overflow = certified(BlockHeight::new(8), b"overflow");
        assert!(matches!(
            sm.ingest(overflow, BlockHeight::new(5)),
            IngestOutcome::Drop
        ));
    }

    #[test]
    fn ingest_drops_block_beyond_buffer_horizon() {
        let mut sm = BlockSyncManager::new();
        let committed = BlockHeight::new(100);
        let inside = BlockHeight::new(committed.inner() + MAX_BUFFER_FUTURE_HORIZON);
        let outside = BlockHeight::new(committed.inner() + MAX_BUFFER_FUTURE_HORIZON + 1);

        // Edge of the horizon is buffered; one past is dropped. Without the
        // distinct-height cap a Byzantine peer could spread arrivals across
        // arbitrary future heights and bloat the BTreeMap.
        assert!(matches!(
            sm.ingest(certified(inside, b"edge"), committed),
            IngestOutcome::Buffered
        ));
        assert!(matches!(
            sm.ingest(certified(outside, b"far"), committed),
            IngestOutcome::Drop
        ));
        assert!(sm.has_any_buffered_at_height(inside));
        assert!(!sm.has_any_buffered_at_height(outside));
    }

    // ─── next_submitable ────────────────────────────────────────────────

    #[test]
    fn next_submitable_is_empty_when_pending_saturates_parallelism() {
        let mut sm = BlockSyncManager::new();
        sm.track_pending_verification_for_test(certified(BlockHeight::new(6), b"a"));
        sm.track_pending_verification_for_test(certified(BlockHeight::new(7), b"b"));
        let out = sm.next_submitable(BlockHeight::new(5), 2);
        assert!(out.is_empty());
    }

    #[test]
    fn next_submitable_drains_slots_from_buffer_starting_above_pending() {
        let mut sm = BlockSyncManager::new();
        sm.track_pending_verification_for_test(certified(BlockHeight::new(6), b"pending"));
        sm.buffer_block(BlockHeight::new(7), certified(BlockHeight::new(7), b"buf1"));
        sm.buffer_block(BlockHeight::new(8), certified(BlockHeight::new(8), b"buf2"));
        sm.buffer_block(BlockHeight::new(9), certified(BlockHeight::new(9), b"buf3"));

        let out = sm.next_submitable(BlockHeight::new(5), 3);
        let heights: Vec<_> = out.iter().map(|c| c.block().height().inner()).collect();
        assert_eq!(heights, vec![7, 8]);
    }

    #[test]
    fn next_submitable_skips_non_contiguous_buffered_entries() {
        let mut sm = BlockSyncManager::new();
        sm.buffer_block(
            BlockHeight::new(8),
            certified(BlockHeight::new(8), b"later"),
        );
        let out = sm.next_submitable(BlockHeight::new(5), 4);
        assert!(
            out.is_empty(),
            "drain requires contiguous sequence from start_height"
        );
    }

    // ─── health_check ───────────────────────────────────────────────────

    #[test]
    fn health_check_idle_without_latest_qc() {
        let mut sm = BlockSyncManager::new();
        let commits = CommitPipeline::new();
        let decision = sm.health_check(
            ValidatorId::new(0),
            BlockHeight::new(0),
            None,
            false,
            &commits,
            0,
            0,
        );
        assert!(matches!(decision, BlockSyncHealthDecision::Idle));
    }

    #[test]
    fn health_check_idle_when_already_at_qc_height() {
        let mut sm = BlockSyncManager::new();
        let commits = CommitPipeline::new();
        let qc = qc_at(BlockHeight::new(10));
        let decision = sm.health_check(
            ValidatorId::new(0),
            BlockHeight::new(10),
            Some(&qc),
            true,
            &commits,
            0,
            0,
        );
        assert!(matches!(decision, BlockSyncHealthDecision::Idle));
    }

    #[test]
    fn health_check_idle_when_already_syncing() {
        let mut sm = BlockSyncManager::new();
        sm.set_syncing(true);
        let commits = CommitPipeline::new();
        let qc = qc_at(BlockHeight::new(10));
        let decision = sm.health_check(
            ValidatorId::new(0),
            BlockHeight::new(5),
            Some(&qc),
            false,
            &commits,
            0,
            0,
        );
        assert!(matches!(decision, BlockSyncHealthDecision::Idle));
    }

    #[test]
    fn health_check_triggers_sync_when_next_block_missing() {
        let mut sm = BlockSyncManager::new();
        let commits = CommitPipeline::new();
        let qc = qc_at(BlockHeight::new(10));
        let decision = sm.health_check(
            ValidatorId::new(0),
            BlockHeight::new(5),
            Some(&qc),
            false,
            &commits,
            0,
            0,
        );
        match decision {
            BlockSyncHealthDecision::TriggerSync { target_height } => {
                assert_eq!(target_height, BlockHeight::new(10));
            }
            BlockSyncHealthDecision::Idle => {
                panic!("expected TriggerSync for missing-next-block gap")
            }
        }
    }

    #[test]
    fn health_check_triggers_sync_when_block_present_but_qc_stalled() {
        // has_next_block=true but no pending commit → missing-QC escalation
        // fires when gap > 3.
        let mut sm = BlockSyncManager::new();
        let commits = CommitPipeline::new();
        let qc = qc_at(BlockHeight::new(10));
        let decision = sm.health_check(
            ValidatorId::new(0),
            BlockHeight::new(5),
            Some(&qc),
            true,
            &commits,
            0,
            0,
        );
        assert!(matches!(
            decision,
            BlockSyncHealthDecision::TriggerSync { .. }
        ));
    }

    #[test]
    fn health_check_idle_when_gap_is_small_and_block_present() {
        let mut sm = BlockSyncManager::new();
        let commits = CommitPipeline::new();
        let qc = qc_at(BlockHeight::new(7));
        // gap = 2, <= 3, view_changes=0 → wait for normal consensus.
        let decision = sm.health_check(
            ValidatorId::new(0),
            BlockHeight::new(5),
            Some(&qc),
            true,
            &commits,
            0,
            0,
        );
        assert!(matches!(decision, BlockSyncHealthDecision::Idle));
    }

    #[test]
    fn health_check_triggers_sync_on_view_change_spin_without_qc_advance() {
        // Partial-isolation pattern: gap is small (would otherwise stay
        // Idle), `latest_qc` hasn't advanced past the snapshot, and the
        // view-change counter has climbed by ≥ threshold. Reproduces V6's
        // post-recovery spin observed in cluster logs.
        let mut sm = BlockSyncManager::new();
        let commits = CommitPipeline::new();
        let qc = qc_at(BlockHeight::new(7));
        // First call snapshots view_changes=10 against qc=7.
        let _ = sm.health_check(
            ValidatorId::new(0),
            BlockHeight::new(5),
            Some(&qc),
            true,
            &commits,
            0,
            10,
        );
        // Second call: same QC, view_changes climbed by 3 → escalate.
        let decision = sm.health_check(
            ValidatorId::new(0),
            BlockHeight::new(5),
            Some(&qc),
            true,
            &commits,
            0,
            13,
        );
        match decision {
            BlockSyncHealthDecision::TriggerSync { target_height } => {
                assert_eq!(target_height, BlockHeight::new(7));
            }
            BlockSyncHealthDecision::Idle => panic!("expected spin escalation"),
        }
    }

    #[test]
    fn health_check_idle_when_view_change_spin_below_threshold() {
        let mut sm = BlockSyncManager::new();
        let commits = CommitPipeline::new();
        let qc = qc_at(BlockHeight::new(7));
        let _ = sm.health_check(
            ValidatorId::new(0),
            BlockHeight::new(5),
            Some(&qc),
            true,
            &commits,
            0,
            10,
        );
        // Only +2 view changes since snapshot — still under threshold.
        let decision = sm.health_check(
            ValidatorId::new(0),
            BlockHeight::new(5),
            Some(&qc),
            true,
            &commits,
            0,
            12,
        );
        assert!(matches!(decision, BlockSyncHealthDecision::Idle));
    }

    #[test]
    fn health_check_idle_when_qc_advances_alongside_view_changes() {
        // Healthy progress: view-changes climb but QC also climbs in step.
        // Snapshot resets each time — never escalates.
        let mut sm = BlockSyncManager::new();
        let commits = CommitPipeline::new();
        for h in 5..15u64 {
            let qc = qc_at(BlockHeight::new(h));
            let decision = sm.health_check(
                ValidatorId::new(0),
                BlockHeight::new(h - 1),
                Some(&qc),
                true,
                &commits,
                0,
                h * 2, // view_changes climb 2 per height
            );
            assert!(
                matches!(decision, BlockSyncHealthDecision::Idle),
                "spurious escalation when QC tracks view changes"
            );
        }
    }

    fn qc_at(height: BlockHeight) -> QuorumCertificate {
        QuorumCertificate::new(
            BlockHash::from_raw(Hash::from_bytes(b"qc")),
            ShardId::ROOT,
            height,
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::empty(),
            zero_bls_signature(),
            WeightedTimestamp::ZERO,
        )
    }

    // Test-only shim avoiding the `pub fn` gate on the tracked insertion,
    // which is otherwise reached only via `register_for_verification`.
    impl BlockSyncManager {
        fn track_pending_verification_for_test(&mut self, certified: CertifiedBlock) {
            let block_hash = certified.block().hash();
            self.pending_synced_block_verifications.insert(
                block_hash,
                PendingSyncedBlockVerification::InFlight(certified),
            );
        }
    }
}
