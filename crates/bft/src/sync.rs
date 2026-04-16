//! Sync coordination for catching up to the network.
//!
//! Manages the sync state flag, synced block buffering, and pending
//! synced block QC verifications. BftState owns this as a field and
//! delegates sync-specific bookkeeping here.

use hyperscale_types::{Block, Hash, QuorumCertificate};
use std::collections::{BTreeMap, HashMap};
use tracing::{debug, info, warn};

/// Synced block pending QC signature verification.
///
/// When we receive a synced block, we must verify its QC signature before
/// applying it to our state. `block.certificates` already carries the receipts
/// inline (via `Arc<FinalizedWave>`), so no separate receipts payload is needed.
#[derive(Debug, Clone)]
pub(crate) struct PendingSyncedBlockVerification {
    /// The synced block awaiting QC verification.
    pub block: Block,
    /// The QC that certifies this block.
    pub qc: QuorumCertificate,
    /// Whether the QC signature has been verified.
    pub verified: bool,
}

/// Sync block coordination state.
///
/// BftState owns this as a field and delegates sync-specific bookkeeping
/// to it. Core protocol state changes (committed_height, latest_qc) remain
/// on BftState.
pub(crate) struct SyncManager {
    /// Whether we are currently syncing (catching up to the network).
    syncing: bool,

    /// The sync target height — set at sync start, cleared on resume.
    /// Used by `on_jvt_committed` to auto-resume when persistence catches up.
    sync_target_height: Option<u64>,

    /// Buffered out-of-order synced blocks waiting for earlier blocks.
    /// Maps height -> (Block, QC, receipts).
    buffered_synced_blocks: BTreeMap<u64, (Block, QuorumCertificate)>,

    /// Synced blocks pending QC signature verification.
    /// Maps block_hash -> pending synced block info.
    pending_synced_block_verifications: HashMap<Hash, PendingSyncedBlockVerification>,
}

impl SyncManager {
    /// Create a new SyncManager.
    pub fn new() -> Self {
        Self {
            syncing: false,
            sync_target_height: None,
            buffered_synced_blocks: BTreeMap::new(),
            pending_synced_block_verifications: HashMap::new(),
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Sync flag
    // ═══════════════════════════════════════════════════════════════════════

    /// Check if this validator is currently syncing.
    pub fn is_syncing(&self) -> bool {
        self.syncing
    }

    /// Set the syncing flag.
    pub fn set_syncing(&mut self, syncing: bool) {
        self.syncing = syncing;
        if !syncing {
            self.sync_target_height = None;
        }
    }

    /// Set the sync target height (called when sync starts).
    pub fn set_sync_target(&mut self, height: u64) {
        self.sync_target_height = Some(height);
    }

    /// Get the sync target height, if syncing.
    pub fn sync_target_height(&self) -> Option<u64> {
        self.sync_target_height
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Synced block receiving and buffering
    // ═══════════════════════════════════════════════════════════════════════

    /// Check if a synced block is already pending verification.
    pub fn has_pending_verification(&self, block_hash: &Hash) -> bool {
        self.pending_synced_block_verifications
            .contains_key(block_hash)
    }

    /// Check if a height is already buffered.
    pub fn has_buffered_height(&self, height: u64) -> bool {
        self.buffered_synced_blocks.contains_key(&height)
    }

    /// Check if any pending verification has a block at the given height.
    pub fn has_pending_at_height(&self, height: u64) -> bool {
        self.pending_synced_block_verifications
            .values()
            .any(|p| p.block.header.height.0 == height)
    }

    /// Buffer a future synced block for later processing.
    pub fn buffer_block(&mut self, height: u64, block: Block, qc: QuorumCertificate) {
        debug!(height, "Buffering future synced block for later");
        self.buffered_synced_blocks.insert(height, (block, qc));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Pending synced block verification tracking
    // ═══════════════════════════════════════════════════════════════════════

    /// Track a synced block pending QC verification.
    ///
    /// Callers should check `has_pending_verification` first to avoid
    /// silently overwriting an in-flight verification.
    pub fn track_pending_verification(
        &mut self,
        block_hash: Hash,
        block: Block,
        qc: QuorumCertificate,
    ) {
        let height = block.header.height.0;
        if self
            .pending_synced_block_verifications
            .contains_key(&block_hash)
        {
            warn!(
                height,
                block_hash = ?block_hash,
                "Overwriting existing pending synced block verification — this is unexpected"
            );
        }
        info!(
            height,
            block_hash = ?block_hash,
            "Inserting into pending_synced_block_verifications"
        );
        self.pending_synced_block_verifications.insert(
            block_hash,
            PendingSyncedBlockVerification {
                block,
                qc,
                verified: false,
            },
        );
    }

    /// Handle QC verification result for a synced block.
    ///
    /// Returns `Some(pending)` if this was a synced block verification,
    /// `None` if the block_hash wasn't found in pending synced verifications.
    pub fn on_qc_verified(
        &mut self,
        block_hash: Hash,
        valid: bool,
    ) -> Option<SyncVerificationResult> {
        let mut pending = self
            .pending_synced_block_verifications
            .remove(&block_hash)?;

        if !valid {
            warn!(
                block_hash = ?block_hash,
                height = pending.block.header.height.0,
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
            height = pending.block.header.height.0,
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

    /// Whether any sync block QC verification is in-flight (submitted but
    /// not yet verified). Used by `should_advance_round` to suppress view
    /// changes while we're actively verifying sync blocks.
    pub fn has_pending_verifications(&self) -> bool {
        self.pending_synced_block_verifications
            .values()
            .any(|p| !p.verified)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Drain verified blocks
    // ═══════════════════════════════════════════════════════════════════════

    /// Take the next consecutive verified block at the given height.
    ///
    /// Returns the block and QC if a verified block exists at `height`,
    /// otherwise None.
    pub fn take_verified_at_height(&mut self, height: u64) -> Option<(Block, QuorumCertificate)> {
        let block_hash = self
            .pending_synced_block_verifications
            .iter()
            .find(|(_, p)| p.verified && p.block.header.height.0 == height)
            .map(|(h, _)| *h)?;

        let pending = self
            .pending_synced_block_verifications
            .remove(&block_hash)
            .unwrap();

        Some((pending.block, pending.qc))
    }

    /// Log the current state of pending verifications (for debugging).
    pub fn log_verification_state(&self, committed_height: u64, next_height: u64) {
        let verified_heights: Vec<_> = self
            .pending_synced_block_verifications
            .values()
            .filter(|p| p.verified)
            .map(|p| p.block.header.height.0)
            .collect();
        let unverified_heights: Vec<_> = self
            .pending_synced_block_verifications
            .values()
            .filter(|p| !p.verified)
            .map(|p| p.block.header.height.0)
            .collect();
        info!(
            committed_height,
            next_height,
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
        start_height: u64,
        max_count: usize,
    ) -> Vec<(Block, QuorumCertificate)> {
        let mut result = Vec::new();
        let mut height = start_height;

        while result.len() < max_count {
            if let Some((block, qc)) = self.buffered_synced_blocks.remove(&height) {
                debug!(height, "Draining buffered synced block");
                result.push((block, qc));
                height += 1;
            } else {
                break;
            }
        }

        result
    }

    /// Get the highest height among pending verifications.
    pub fn highest_pending_height(&self, committed_height: u64) -> u64 {
        self.pending_synced_block_verifications
            .values()
            .map(|p| p.block.header.height.0)
            .max()
            .unwrap_or(committed_height)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Cleanup
    // ═══════════════════════════════════════════════════════════════════════

    /// Remove sync state at or below committed height.
    ///
    /// Uses consensus committed height (not JVT-persisted height). These
    /// diverge during async persistence, but sync state tracks consensus
    /// progress — once a block is committed to consensus, its sync
    /// bookkeeping is no longer needed regardless of persistence state.
    pub fn cleanup(&mut self, committed_height: u64) {
        self.buffered_synced_blocks
            .retain(|height, _| *height > committed_height);

        self.pending_synced_block_verifications
            .retain(|_, pending| pending.block.header.height.0 > committed_height);
    }

    /// Number of buffered out-of-order synced blocks.
    pub(crate) fn buffered_synced_blocks_len(&self) -> usize {
        self.buffered_synced_blocks.len()
    }
}

/// Result of a synced block QC verification.
pub(crate) enum SyncVerificationResult {
    /// QC verified successfully — ready to apply consecutive blocks.
    Verified,
    /// QC verification failed — the bad block is removed, other pending
    /// verifications are preserved. Blocks above the failed height are
    /// blocked by the gap until a re-sync fills it.
    Failed,
}
