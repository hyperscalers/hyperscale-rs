//! Sync coordination for catching up to the network.
//!
//! Manages the sync state flag, synced block buffering, and pending
//! synced block QC verifications. `BftCoordinator` owns this as a field and
//! delegates sync-specific bookkeeping here.

use hyperscale_core::Action;
use hyperscale_types::{
    BlockHash, BlockHeight, Bls12381G1PublicKey, CertifiedBlock, QuorumCertificate,
    TopologySnapshot,
};
use std::collections::{BTreeMap, HashMap};
use tracing::{debug, info, warn};

use crate::commit_pipeline::CommitPipeline;

/// Synced block pending QC signature verification.
///
/// When we receive a synced block, we must verify its QC signature before
/// applying it to our state.
#[derive(Debug, Clone)]
pub struct PendingSyncedBlockVerification {
    /// The synced block + certifying QC awaiting QC-signature verification.
    pub certified: CertifiedBlock,
    /// Whether the QC signature has been verified.
    pub verified: bool,
}

/// Sync block coordination state.
///
/// `BftCoordinator` owns this as a field and delegates sync-specific bookkeeping
/// to it. Core protocol state changes (`committed_height`, `latest_qc`) remain
/// on `BftCoordinator`.
pub struct SyncManager {
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

    /// Buffered out-of-order synced blocks waiting for earlier blocks.
    /// Maps height -> `CertifiedBlock`.
    buffered_synced_blocks: BTreeMap<BlockHeight, CertifiedBlock>,

    /// Synced blocks pending QC signature verification.
    /// Maps `block_hash` -> pending synced block info.
    pending_synced_block_verifications: HashMap<BlockHash, PendingSyncedBlockVerification>,
}

impl SyncManager {
    /// Create a new `SyncManager`.
    pub fn new() -> Self {
        Self {
            syncing: false,
            sync_target_height: None,
            sync_applied_height: BlockHeight::GENESIS,
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

    // ═══════════════════════════════════════════════════════════════════════
    // Synced block receiving and buffering
    // ═══════════════════════════════════════════════════════════════════════

    /// Check if a synced block is already pending verification.
    pub fn has_pending_verification(&self, block_hash: &BlockHash) -> bool {
        self.pending_synced_block_verifications
            .contains_key(block_hash)
    }

    /// Check if a height is already buffered.
    pub fn has_buffered_height(&self, height: BlockHeight) -> bool {
        self.buffered_synced_blocks.contains_key(&height)
    }

    /// Check if any pending verification has a block at the given height.
    pub fn has_pending_at_height(&self, height: BlockHeight) -> bool {
        self.pending_synced_block_verifications
            .values()
            .any(|p| p.certified.block.height() == height)
    }

    /// Buffer a future synced block for later processing.
    pub fn buffer_block(&mut self, height: BlockHeight, certified: CertifiedBlock) {
        debug!(height = height.0, "Buffering future synced block for later");
        self.buffered_synced_blocks.insert(height, certified);
    }

    /// Plan the next batch of buffered synced blocks to dispatch for QC
    /// verification. Respects `max_parallel_sync_verifications` and starts
    /// from one above the highest currently-pending or committed height so
    /// we don't resubmit work already in flight.
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
        let start_height = highest_pending_height.max(committed_height) + 1u64;

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
        let block_hash = certified.block.hash();
        let height = certified.block.height();

        if height <= committed_height {
            info!(
                height = height.0,
                committed = committed_height.0,
                "Synced block already committed - filtering"
            );
            return IngestOutcome::Drop;
        }

        if self.has_pending_verification(&block_hash) {
            info!(
                height = height.0,
                "Synced block already pending verification - filtering"
            );
            return IngestOutcome::Drop;
        }

        if self.has_buffered_height(height) {
            info!(
                height = height.0,
                "Synced block already buffered - filtering"
            );
            return IngestOutcome::Drop;
        }

        let next_needed = committed_height.next();
        if height == next_needed {
            return IngestOutcome::Submit(Box::new(certified));
        }

        if height > next_needed {
            self.buffer_block(height, certified);
            return IngestOutcome::Buffered;
        }

        warn!(
            height = height.0,
            next_needed = next_needed.0,
            committed = committed_height.0,
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
    ) -> Action {
        let block_hash = certified.block.hash();
        let height = certified.block.height();
        let qc = certified.qc.clone();

        if self
            .pending_synced_block_verifications
            .contains_key(&block_hash)
        {
            warn!(
                height = height.0,
                ?block_hash,
                "Overwriting existing pending synced block verification — this is unexpected"
            );
        }
        info!(
            height = height.0,
            ?block_hash,
            signers = qc.signers.count(),
            "Submitting synced block for QC verification"
        );
        self.pending_synced_block_verifications.insert(
            block_hash,
            PendingSyncedBlockVerification {
                certified,
                verified: false,
            },
        );

        Action::VerifyQcSignature {
            qc,
            public_keys,
            block_hash,
        }
    }

    /// Handle QC verification result for a synced block.
    ///
    /// Returns `Some(pending)` if this was a synced block verification,
    /// `None` if the `block_hash` wasn't found in pending synced verifications.
    pub fn on_qc_verified(
        &mut self,
        block_hash: BlockHash,
        valid: bool,
    ) -> Option<SyncVerificationResult> {
        let mut pending = self
            .pending_synced_block_verifications
            .remove(&block_hash)?;

        if !valid {
            warn!(
                block_hash = ?block_hash,
                height = pending.certified.block.height().0,
                "Synced block QC signature verification FAILED - rejecting block"
            );
            // Only this block is removed (already done above). Other pending
            // verifications are kept — a single bad peer shouldn't cascade
            // into losing all in-flight sync work. Blocks above this height
            // will be blocked by the gap until a re-sync fills it.
            return Some(SyncVerificationResult::Failed);
        }

        info!(
            block_hash = ?block_hash,
            height = pending.certified.block.height().0,
            "Synced block QC verified successfully"
        );

        // Mark as verified and put back for ordering
        pending.verified = true;
        self.pending_synced_block_verifications
            .insert(block_hash, pending);

        Some(SyncVerificationResult::Verified)
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
            .any(|p| !p.verified)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Drain verified blocks
    // ═══════════════════════════════════════════════════════════════════════

    /// Take the next consecutive verified block at the given height.
    ///
    /// Returns the certified block if a verified entry exists at `height`,
    /// otherwise None.
    pub fn take_verified_at_height(&mut self, height: BlockHeight) -> Option<CertifiedBlock> {
        let block_hash = self
            .pending_synced_block_verifications
            .iter()
            .find(|(_, p)| p.verified && p.certified.block.height() == height)
            .map(|(h, _)| *h)?;

        let pending = self
            .pending_synced_block_verifications
            .remove(&block_hash)
            .unwrap();

        Some(pending.certified)
    }

    /// Take the next block to apply in the consecutive-verified sequence.
    /// Computes the target height from `committed_height` and our own
    /// `sync_applied_height` marker (both advance together in apply), then
    /// pops the matching verified entry. Returns `None` once the chain
    /// catches up to the verified frontier; also logs the verified /
    /// unverified pending heights for diagnostics.
    pub fn take_next_verified(&mut self, committed_height: BlockHeight) -> Option<CertifiedBlock> {
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
            .filter(|p| p.verified)
            .map(|p| p.certified.block.height().0)
            .collect();
        let unverified_heights: Vec<_> = self
            .pending_synced_block_verifications
            .values()
            .filter(|p| !p.verified)
            .map(|p| p.certified.block.height().0)
            .collect();
        info!(
            committed_height = committed_height.0,
            next_height = next_height.0,
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
    /// Returns blocks in sequential order starting from `start_height`,
    /// up to `max_count` blocks.
    pub fn drain_buffered(
        &mut self,
        start_height: BlockHeight,
        max_count: usize,
    ) -> Vec<CertifiedBlock> {
        let mut result = Vec::new();
        let mut height = start_height;

        while result.len() < max_count {
            if let Some(entry) = self.buffered_synced_blocks.remove(&height) {
                debug!(height = height.0, "Draining buffered synced block");
                result.push(entry);
                height += 1u64;
            } else {
                break;
            }
        }

        result
    }

    /// Get the highest height among pending verifications.
    pub fn highest_pending_height(&self, committed_height: BlockHeight) -> BlockHeight {
        self.pending_synced_block_verifications
            .values()
            .map(|p| p.certified.block.height())
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
            .retain(|_, pending| pending.certified.block.height() > committed_height);
    }

    /// Number of buffered out-of-order synced blocks.
    pub(crate) fn buffered_synced_blocks_len(&self) -> usize {
        self.buffered_synced_blocks.len()
    }
}

/// Classification of an incoming synced block. Returned by
/// [`SyncManager::ingest`] so the coordinator doesn't have to replicate the
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
pub enum SyncVerificationResult {
    /// QC verified successfully — ready to apply consecutive blocks.
    Verified,
    /// QC verification failed — the bad block is removed, other pending
    /// verifications are preserved. Blocks above the failed height are
    /// blocked by the gap until a re-sync fills it.
    Failed,
}

/// Decision returned by [`SyncManager::health_check`].
pub enum SyncHealthDecision {
    /// No action needed — already synced, already syncing, or making progress.
    Idle,
    /// Trigger catch-up sync to the named target.
    TriggerSync {
        target_height: BlockHeight,
        target_hash: BlockHash,
    },
}

impl SyncManager {
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
    pub fn health_check(
        &self,
        topology: &TopologySnapshot,
        committed_height: BlockHeight,
        latest_qc: Option<&QuorumCertificate>,
        has_next_block: bool,
        commits: &CommitPipeline,
        pending_blocks_len: usize,
    ) -> SyncHealthDecision {
        let Some(latest_qc) = latest_qc else {
            return SyncHealthDecision::Idle;
        };

        let qc_height = latest_qc.height;
        let qc_hash = latest_qc.block_hash;

        if committed_height >= qc_height {
            return SyncHealthDecision::Idle;
        }

        if self.is_syncing() {
            return SyncHealthDecision::Idle;
        }

        let next_needed_height = committed_height.next();
        let has_pending_commit = commits.out_of_order.contains_key(&next_needed_height);
        let gap = qc_height - committed_height;

        if gap > 5 {
            warn!(
                validator = ?topology.local_validator_id(),
                committed_height = committed_height.0,
                next_needed_height = next_needed_height.0,
                qc_height = qc_height.0,
                gap = gap,
                has_next_complete = has_next_block,
                has_pending_commit = has_pending_commit,
                pending_commits = commits.out_of_order.len(),
                pending_commits_awaiting_data = commits.awaiting_data.len(),
                certified_blocks = commits.certified_blocks.len(),
                pending_blocks = pending_blocks_len,
                "Sync health check status"
            );
        }

        if has_next_block {
            if has_pending_commit {
                if gap > 10 {
                    warn!(
                        validator = ?topology.local_validator_id(),
                        committed_height = committed_height.0,
                        next_needed_height = next_needed_height.0,
                        qc_height = qc_height.0,
                        gap = gap,
                        "Have complete block and pending commit but significantly behind - triggering sync to recover"
                    );
                    return SyncHealthDecision::TriggerSync {
                        target_height: qc_height,
                        target_hash: qc_hash,
                    };
                }
                return SyncHealthDecision::Idle;
            }

            if gap > 3 {
                warn!(
                    validator = ?topology.local_validator_id(),
                    committed_height = committed_height.0,
                    next_needed_height = next_needed_height.0,
                    qc_height = qc_height.0,
                    gap = gap,
                    "Have complete block but no pending commit (missing QC) - triggering sync to recover"
                );
                return SyncHealthDecision::TriggerSync {
                    target_height: qc_height,
                    target_hash: qc_hash,
                };
            }
            return SyncHealthDecision::Idle;
        }

        info!(
            validator = ?topology.local_validator_id(),
            committed_height = committed_height.0,
            next_needed_height = next_needed_height.0,
            qc_height = qc_height.0,
            "Sync health check: can't make progress, triggering catch-up sync"
        );

        SyncHealthDecision::TriggerSync {
            target_height: qc_height,
            target_hash: qc_hash,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_test_helpers::TestCommittee;
    use hyperscale_types::{
        Block, BlockHeader, CertificateRoot, Hash, LocalReceiptRoot, ProposerTimestamp,
        ProvisionsRoot, Round, ShardGroupId, StateRoot, TransactionRoot, ValidatorId,
        ValidatorInfo, ValidatorSet,
    };
    use std::collections::BTreeMap;

    fn topology() -> TopologySnapshot {
        let committee = TestCommittee::new(4, 42);
        let validators: Vec<ValidatorInfo> = (0..committee.size())
            .map(|i| ValidatorInfo {
                validator_id: committee.validator_id(i),
                public_key: *committee.public_key(i),
                voting_power: 1,
            })
            .collect();
        TopologySnapshot::new(ValidatorId(0), 1, ValidatorSet::new(validators))
    }

    fn header(height: BlockHeight, tag: &[u8]) -> BlockHeader {
        BlockHeader {
            shard_group_id: ShardGroupId(0),
            height,
            parent_block_hash: BlockHash::from_raw(Hash::from_bytes(tag)),
            parent_qc: QuorumCertificate::genesis(),
            proposer: ValidatorId(0),
            timestamp: ProposerTimestamp(0),
            round: Round::INITIAL,
            is_fallback: false,
            state_root: StateRoot::ZERO,
            transaction_root: TransactionRoot::ZERO,
            certificate_root: CertificateRoot::ZERO,
            local_receipt_root: LocalReceiptRoot::ZERO,
            provision_root: ProvisionsRoot::ZERO,
            waves: Vec::new(),
            provision_tx_roots: BTreeMap::new(),
            in_flight: 0,
        }
    }

    fn certified(height: BlockHeight, tag: &[u8]) -> CertifiedBlock {
        let block = Block::Live {
            header: header(height, tag),
            transactions: Vec::new(),
            certificates: Vec::new(),
            provisions: Vec::new(),
        };
        let mut qc = QuorumCertificate::genesis();
        qc.block_hash = block.hash();
        qc.height = height;
        CertifiedBlock::new_unchecked(block, qc)
    }

    // ─── ingest ──────────────────────────────────────────────────────────

    #[test]
    fn ingest_drops_stale_block_at_or_below_committed() {
        let mut sm = SyncManager::new();
        let out = sm.ingest(certified(BlockHeight(3), b"s"), BlockHeight(5));
        assert!(matches!(out, IngestOutcome::Drop));
    }

    #[test]
    fn ingest_drops_block_already_pending_verification() {
        let mut sm = SyncManager::new();
        let cb = certified(BlockHeight(6), b"p");
        sm.track_pending_verification_for_test(cb.clone());
        let out = sm.ingest(cb, BlockHeight(5));
        assert!(matches!(out, IngestOutcome::Drop));
    }

    #[test]
    fn ingest_drops_block_already_buffered() {
        let mut sm = SyncManager::new();
        let cb = certified(BlockHeight(7), b"b");
        sm.buffer_block(BlockHeight(7), cb.clone());
        let out = sm.ingest(cb, BlockHeight(5));
        assert!(matches!(out, IngestOutcome::Drop));
    }

    #[test]
    fn ingest_submits_when_block_is_next_needed_height() {
        let mut sm = SyncManager::new();
        let cb = certified(BlockHeight(6), b"next");
        let out = sm.ingest(cb, BlockHeight(5));
        assert!(matches!(out, IngestOutcome::Submit(_)));
    }

    #[test]
    fn ingest_buffers_future_block_and_stores_it() {
        let mut sm = SyncManager::new();
        let cb = certified(BlockHeight(8), b"future");
        let out = sm.ingest(cb, BlockHeight(5));
        assert!(matches!(out, IngestOutcome::Buffered));
        assert!(sm.has_buffered_height(BlockHeight(8)));
    }

    // ─── next_submitable ────────────────────────────────────────────────

    #[test]
    fn next_submitable_is_empty_when_pending_saturates_parallelism() {
        let mut sm = SyncManager::new();
        sm.track_pending_verification_for_test(certified(BlockHeight(6), b"a"));
        sm.track_pending_verification_for_test(certified(BlockHeight(7), b"b"));
        let out = sm.next_submitable(BlockHeight(5), 2);
        assert!(out.is_empty());
    }

    #[test]
    fn next_submitable_drains_slots_from_buffer_starting_above_pending() {
        let mut sm = SyncManager::new();
        sm.track_pending_verification_for_test(certified(BlockHeight(6), b"pending"));
        sm.buffer_block(BlockHeight(7), certified(BlockHeight(7), b"buf1"));
        sm.buffer_block(BlockHeight(8), certified(BlockHeight(8), b"buf2"));
        sm.buffer_block(BlockHeight(9), certified(BlockHeight(9), b"buf3"));

        let out = sm.next_submitable(BlockHeight(5), 3);
        let heights: Vec<_> = out.iter().map(|c| c.block.height().0).collect();
        assert_eq!(heights, vec![7, 8]);
    }

    #[test]
    fn next_submitable_skips_non_contiguous_buffered_entries() {
        let mut sm = SyncManager::new();
        sm.buffer_block(BlockHeight(8), certified(BlockHeight(8), b"later"));
        let out = sm.next_submitable(BlockHeight(5), 4);
        assert!(
            out.is_empty(),
            "drain requires contiguous sequence from start_height"
        );
    }

    // ─── health_check ───────────────────────────────────────────────────

    #[test]
    fn health_check_idle_without_latest_qc() {
        let sm = SyncManager::new();
        let commits = CommitPipeline::new();
        let decision = sm.health_check(&topology(), BlockHeight(0), None, false, &commits, 0);
        assert!(matches!(decision, SyncHealthDecision::Idle));
    }

    #[test]
    fn health_check_idle_when_already_at_qc_height() {
        let sm = SyncManager::new();
        let commits = CommitPipeline::new();
        let qc = qc_at(BlockHeight(10));
        let decision = sm.health_check(&topology(), BlockHeight(10), Some(&qc), true, &commits, 0);
        assert!(matches!(decision, SyncHealthDecision::Idle));
    }

    #[test]
    fn health_check_idle_when_already_syncing() {
        let mut sm = SyncManager::new();
        sm.set_syncing(true);
        let commits = CommitPipeline::new();
        let qc = qc_at(BlockHeight(10));
        let decision = sm.health_check(&topology(), BlockHeight(5), Some(&qc), false, &commits, 0);
        assert!(matches!(decision, SyncHealthDecision::Idle));
    }

    #[test]
    fn health_check_triggers_sync_when_next_block_missing() {
        let sm = SyncManager::new();
        let commits = CommitPipeline::new();
        let qc = qc_at(BlockHeight(10));
        let decision = sm.health_check(&topology(), BlockHeight(5), Some(&qc), false, &commits, 0);
        match decision {
            SyncHealthDecision::TriggerSync {
                target_height,
                target_hash,
            } => {
                assert_eq!(target_height, BlockHeight(10));
                assert_eq!(target_hash, qc.block_hash);
            }
            SyncHealthDecision::Idle => {
                panic!("expected TriggerSync for missing-next-block gap")
            }
        }
    }

    #[test]
    fn health_check_triggers_sync_when_block_present_but_qc_stalled() {
        // has_next_block=true but no pending commit → missing-QC escalation
        // fires when gap > 3.
        let sm = SyncManager::new();
        let commits = CommitPipeline::new();
        let qc = qc_at(BlockHeight(10));
        let decision = sm.health_check(&topology(), BlockHeight(5), Some(&qc), true, &commits, 0);
        assert!(matches!(decision, SyncHealthDecision::TriggerSync { .. }));
    }

    #[test]
    fn health_check_idle_when_gap_is_small_and_block_present() {
        let sm = SyncManager::new();
        let commits = CommitPipeline::new();
        let qc = qc_at(BlockHeight(7));
        // gap = 2, <= 3, so we wait for normal consensus.
        let decision = sm.health_check(&topology(), BlockHeight(5), Some(&qc), true, &commits, 0);
        assert!(matches!(decision, SyncHealthDecision::Idle));
    }

    fn qc_at(height: BlockHeight) -> QuorumCertificate {
        let mut qc = QuorumCertificate::genesis();
        qc.height = height;
        qc.block_hash = BlockHash::from_raw(Hash::from_bytes(b"qc"));
        qc
    }

    // Test-only shim avoiding the `pub fn` gate on the tracked insertion,
    // which is otherwise reached only via `register_for_verification`.
    impl SyncManager {
        fn track_pending_verification_for_test(&mut self, certified: CertifiedBlock) {
            let block_hash = certified.block.hash();
            self.pending_synced_block_verifications.insert(
                block_hash,
                PendingSyncedBlockVerification {
                    certified,
                    verified: false,
                },
            );
        }
    }
}
