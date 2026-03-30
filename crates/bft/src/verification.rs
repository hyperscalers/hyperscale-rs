//! Async verification pipeline for block voting.
//!
//! Tracks QC signature, state root, transaction root, and receipt root
//! verifications. BftState delegates verification bookkeeping here while
//! retaining control-flow decisions (voting, block rejection).

use hyperscale_types::{Block, BlockHeader, Hash};
use std::collections::{HashMap, HashSet};
use tracing::{debug, trace};

use hyperscale_core::Action;

/// Block header pending QC signature verification.
///
/// When we receive a block header with a non-genesis parent_qc, we need to
/// verify the QC's aggregated BLS signature before voting. This struct
/// tracks the block header while waiting for verification.
#[derive(Debug, Clone)]
pub(crate) struct PendingQcVerification {
    /// The block header we're considering voting on.
    pub header: BlockHeader,
}

/// Pending state root verification waiting for JVT to be ready.
///
/// When a block arrives but its parent block's state hasn't been committed to
/// the JVT yet, we queue the verification here. Once StateCommitComplete arrives
/// with a root matching required_root, we can proceed with verification.
#[derive(Debug, Clone)]
struct PendingStateRootVerification {
    /// The state root of the parent block. Verification waits until local JVT
    /// reaches this root, ensuring proposer and verifier compute from same base.
    required_root: Hash,
    /// The state root claimed by the proposer (to verify against).
    expected_root: Hash,
    /// Transaction hashes of the certificates in the block. Used to look up
    /// DatabaseUpdates from the execution cache when the JVT catches up.
    cert_tx_hashes: Vec<Hash>,
    /// Block height (used as JVT version).
    block_height: u64,
}

/// State root verification that is ready to dispatch (JVT is at the correct root).
///
/// The `NodeStateMachine` drains these after each BFT call, computes the
/// `merged_updates` from the execution cache, and emits `VerifyStateRoot` actions.
#[derive(Debug)]
pub struct ReadyStateRootVerification {
    pub block_hash: Hash,
    pub parent_state_root: Hash,
    pub expected_root: Hash,
    pub cert_tx_hashes: Vec<Hash>,
    pub block_height: u64,
}

// ═══════════════════════════════════════════════════════════════════════════
// VerificationPipeline
// ═══════════════════════════════════════════════════════════════════════════

/// Tracks all async verification state for block voting.
///
/// BftState owns this as a field and delegates verification bookkeeping
/// to it. Control-flow decisions (vote, reject block) remain in BftState.
pub(crate) struct VerificationPipeline {
    // === QC signature verification ===
    /// Block headers pending QC signature verification.
    /// Maps block_hash -> pending verification info.
    pending_qc_verifications: HashMap<Hash, PendingQcVerification>,

    /// Cache of already-verified QC signatures.
    /// Maps QC's block_hash (the block the QC certifies) -> height.
    verified_qcs: HashMap<Hash, u64>,

    // === State root verification ===
    /// Blocks where state root verification is currently in-flight.
    state_root_verifications_in_flight: HashSet<Hash>,

    /// Blocks waiting for JVT to reach the required version before verification.
    pending_state_root_verifications: HashMap<Hash, PendingStateRootVerification>,

    /// Last committed JVT root hash.
    last_committed_jvt_root: Hash,

    /// Blocks with verified state roots.
    verified_state_roots: HashSet<Hash>,

    /// State root verifications ready to dispatch (JVT root matches).
    /// Drained by NodeStateMachine which computes merged_updates from execution cache.
    ready_state_root_verifications: Vec<ReadyStateRootVerification>,

    // === Transaction root verification ===
    /// Blocks where transaction root verification is currently in-flight.
    transaction_root_verifications_in_flight: HashSet<Hash>,

    /// Blocks with verified transaction roots.
    verified_transaction_roots: HashSet<Hash>,

    // === Receipt root verification ===
    /// Blocks where receipt root verification is currently in-flight.
    receipt_root_verifications_in_flight: HashSet<Hash>,

    /// Blocks with verified receipt roots.
    verified_receipt_roots: HashSet<Hash>,
}

impl VerificationPipeline {
    /// Create a new verification pipeline.
    pub fn new(jvt_root: Hash) -> Self {
        Self {
            pending_qc_verifications: HashMap::new(),
            verified_qcs: HashMap::new(),
            state_root_verifications_in_flight: HashSet::new(),
            pending_state_root_verifications: HashMap::new(),
            last_committed_jvt_root: jvt_root,
            verified_state_roots: HashSet::new(),
            ready_state_root_verifications: Vec::new(),
            transaction_root_verifications_in_flight: HashSet::new(),
            verified_transaction_roots: HashSet::new(),
            receipt_root_verifications_in_flight: HashSet::new(),
            verified_receipt_roots: HashSet::new(),
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // QC signature verification
    // ═══════════════════════════════════════════════════════════════════════

    /// Track a block header pending QC signature verification.
    pub fn track_pending_qc(&mut self, block_hash: Hash, header: BlockHeader) {
        self.pending_qc_verifications
            .insert(block_hash, PendingQcVerification { header });
    }

    /// Check if a QC has already been verified (cache hit).
    pub fn is_qc_verified(&self, qc_block_hash: &Hash) -> bool {
        self.verified_qcs.contains_key(qc_block_hash)
    }

    /// Record a QC signature verification result. Returns the pending header if found.
    pub fn on_qc_verified(&mut self, block_hash: Hash, valid: bool) -> Option<(BlockHeader, bool)> {
        let pending = self.pending_qc_verifications.remove(&block_hash)?;
        Some((pending.header, valid))
    }

    /// Cache a verified QC to skip future re-verification.
    pub fn cache_verified_qc(&mut self, qc_block_hash: Hash, height: u64) {
        self.verified_qcs.insert(qc_block_hash, height);
        trace!(
            qc_block_hash = ?qc_block_hash,
            qc_height = height,
            "Cached verified QC"
        );
    }

    /// Check if a block has a pending QC verification in-flight.
    pub fn has_pending_qc(&self, block_hash: &Hash) -> bool {
        self.pending_qc_verifications.contains_key(block_hash)
    }

    /// Number of pending QC verifications (for logging).
    pub fn pending_qc_count(&self) -> usize {
        self.pending_qc_verifications.len()
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Block verification (state root, tx root, receipt root)
    // ═══════════════════════════════════════════════════════════════════════

    /// Check if all async verifications are complete for a block.
    ///
    /// Returns true if source attestation, state root, and transaction root
    /// verifications are all done (or not needed).
    pub fn is_block_verified(&self, block: &Block) -> bool {
        let block_hash = block.hash();

        let state_root_ok = if block.certificates.is_empty() {
            true
        } else {
            self.verified_state_roots.contains(&block_hash)
        };

        let transaction_root_ok = if block.transaction_count() == 0 {
            true
        } else {
            self.verified_transaction_roots.contains(&block_hash)
        };

        let receipt_root_ok = if block.certificates.is_empty() {
            true
        } else {
            self.verified_receipt_roots.contains(&block_hash)
        };

        state_root_ok && transaction_root_ok && receipt_root_ok
    }

    // ─── State root ──────────────────────────────────────────────────────

    /// Check if a block needs state root verification before voting.
    pub fn needs_state_root_verification(&self, block: &Block) -> bool {
        if block.certificates.is_empty() {
            return false;
        }

        let block_hash = block.hash();

        if self.verified_state_roots.contains(&block_hash)
            || self
                .state_root_verifications_in_flight
                .contains(&block_hash)
            || self
                .pending_state_root_verifications
                .contains_key(&block_hash)
        {
            return false;
        }

        true
    }

    /// Initiate state root verification for a block.
    ///
    /// `parent_state_root` is the state root of the parent block (base state).
    /// If JVT is ready, pushes to the ready queue for immediate dispatch.
    /// Otherwise, queues for later when JVT catches up.
    ///
    /// In both cases, the `NodeStateMachine` is responsible for draining
    /// `ready_state_root_verifications` and computing `merged_updates` from
    /// the execution cache before emitting the actual `VerifyStateRoot` action.
    pub fn initiate_state_root_verification(
        &mut self,
        block_hash: Hash,
        block: &Block,
        parent_state_root: Hash,
    ) {
        let current_root = self.last_committed_jvt_root;
        let cert_tx_hashes: Vec<Hash> = block
            .certificates
            .iter()
            .map(|c| c.transaction_hash)
            .collect();

        if current_root == parent_state_root {
            // JVT is ready - mark as ready for dispatch
            debug!(
                block_hash = ?block_hash,
                certificate_count = block.certificates.len(),
                expected_root = ?block.header.state_root,
                parent_state_root = ?parent_state_root,
                current_jvt_root = ?current_root,
                "JVT ready - state root verification ready for dispatch"
            );

            self.state_root_verifications_in_flight.insert(block_hash);
            self.ready_state_root_verifications
                .push(ReadyStateRootVerification {
                    block_hash,
                    parent_state_root,
                    expected_root: block.header.state_root,
                    cert_tx_hashes,
                    block_height: block.header.height.0,
                });
        } else {
            // JVT not ready - queue for later
            debug!(
                block_hash = ?block_hash,
                certificate_count = block.certificates.len(),
                expected_root = ?block.header.state_root,
                parent_state_root = ?parent_state_root,
                current_jvt_root = ?current_root,
                "JVT not ready - queueing state root verification"
            );

            self.pending_state_root_verifications.insert(
                block_hash,
                PendingStateRootVerification {
                    required_root: parent_state_root,
                    expected_root: block.header.state_root,
                    cert_tx_hashes,
                    block_height: block.header.height.0,
                },
            );
        }
    }

    /// Record a state root verification result. Returns whether the verification passed.
    pub fn on_state_root_verified(&mut self, block_hash: Hash, valid: bool) -> bool {
        self.state_root_verifications_in_flight.remove(&block_hash);

        if valid {
            self.verified_state_roots.insert(block_hash);
            debug!(
                block_hash = ?block_hash,
                "State root verified successfully"
            );
        }

        valid
    }

    // ─── Transaction root ────────────────────────────────────────────────

    /// Check if a block needs transaction root verification before voting.
    pub fn needs_transaction_root_verification(&self, block: &Block) -> bool {
        if block.transaction_count() == 0 {
            return false;
        }

        let block_hash = block.hash();

        if self.verified_transaction_roots.contains(&block_hash)
            || self
                .transaction_root_verifications_in_flight
                .contains(&block_hash)
        {
            return false;
        }

        true
    }

    /// Initiate transaction root verification for a block.
    pub fn initiate_transaction_root_verification(
        &mut self,
        block_hash: Hash,
        block: &Block,
    ) -> Vec<Action> {
        debug!(
            block_hash = ?block_hash,
            tx_count = block.transactions.len(),
            expected_root = ?block.header.transaction_root,
            "Initiating transaction root verification"
        );

        self.transaction_root_verifications_in_flight
            .insert(block_hash);

        vec![Action::VerifyTransactionRoot {
            block_hash,
            expected_root: block.header.transaction_root,
            transactions: block.transactions.clone(),
        }]
    }

    /// Record a transaction root verification result. Returns whether the verification passed.
    pub fn on_transaction_root_verified(&mut self, block_hash: Hash, valid: bool) -> bool {
        self.transaction_root_verifications_in_flight
            .remove(&block_hash);

        if valid {
            self.verified_transaction_roots.insert(block_hash);
            debug!(
                block_hash = ?block_hash,
                "Transaction root verified successfully"
            );
        }

        valid
    }

    // ─── Receipt root ─────────────────────────────────────────────────────

    /// Check if a block needs receipt root verification before voting.
    pub fn needs_receipt_root_verification(&self, block: &Block) -> bool {
        if block.certificates.is_empty() {
            return false;
        }

        let block_hash = block.hash();

        if self.verified_receipt_roots.contains(&block_hash)
            || self
                .receipt_root_verifications_in_flight
                .contains(&block_hash)
        {
            return false;
        }

        true
    }

    /// Initiate receipt root verification for a block.
    pub fn initiate_receipt_root_verification(
        &mut self,
        block_hash: Hash,
        block: &Block,
    ) -> Vec<Action> {
        debug!(
            block_hash = ?block_hash,
            cert_count = block.certificates.len(),
            expected_root = ?block.header.receipt_root,
            "Initiating receipt root verification"
        );

        self.receipt_root_verifications_in_flight.insert(block_hash);

        vec![Action::VerifyReceiptRoot {
            block_hash,
            expected_root: block.header.receipt_root,
            certificates: block.certificates.clone(),
        }]
    }

    /// Record a receipt root verification result. Returns whether the verification passed.
    pub fn on_receipt_root_verified(&mut self, block_hash: Hash, valid: bool) -> bool {
        self.receipt_root_verifications_in_flight
            .remove(&block_hash);

        if valid {
            self.verified_receipt_roots.insert(block_hash);
            debug!(
                block_hash = ?block_hash,
                "Receipt root verified successfully"
            );
        }

        valid
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Remote header QC verification
    // ═══════════════════════════════════════════════════════════════════════

    // ═══════════════════════════════════════════════════════════════════════
    // JVT state tracking
    // ═══════════════════════════════════════════════════════════════════════

    /// Get the current JVT root.
    pub fn jvt_root(&self) -> Hash {
        self.last_committed_jvt_root
    }

    /// JVT advanced — update root and unblock any waiting state root verifications.
    ///
    /// Unblocked verifications are pushed to the ready queue for
    /// `NodeStateMachine` to drain and enrich with `merged_updates`.
    pub fn on_jvt_advanced(&mut self, block_height: u64, new_root: Hash) {
        self.last_committed_jvt_root = new_root;

        // Find all pending verifications where the JVT now has the required base root.
        let unblocked: Vec<Hash> = self
            .pending_state_root_verifications
            .iter()
            .filter(|(_, pv)| pv.required_root == new_root)
            .map(|(hash, _)| *hash)
            .collect();

        if unblocked.is_empty() {
            return;
        }

        debug!(
            unblocked_count = unblocked.len(),
            block_height, "Unblocking pending state root verifications"
        );

        for block_hash in unblocked {
            if let Some(pv) = self.pending_state_root_verifications.remove(&block_hash) {
                self.state_root_verifications_in_flight.insert(block_hash);
                self.ready_state_root_verifications
                    .push(ReadyStateRootVerification {
                        block_hash,
                        parent_state_root: pv.required_root,
                        expected_root: pv.expected_root,
                        cert_tx_hashes: pv.cert_tx_hashes,
                        block_height: pv.block_height,
                    });
            }
        }
    }

    /// Drain state root verifications that are ready to dispatch.
    ///
    /// The caller (`NodeStateMachine`) computes `merged_updates` from the
    /// execution cache for each verification and emits the `VerifyStateRoot` action.
    pub fn drain_ready_state_root_verifications(&mut self) -> Vec<ReadyStateRootVerification> {
        std::mem::take(&mut self.ready_state_root_verifications)
    }

    /// Number of pending state root verifications (for logging).
    pub fn pending_state_root_count(&self) -> usize {
        self.pending_state_root_verifications.len()
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Cleanup
    // ═══════════════════════════════════════════════════════════════════════

    /// Remove verification state for blocks no longer in pending_blocks.
    ///
    /// Called by BftState::cleanup_old_state() after it has cleaned up
    /// pending_blocks. We use the surviving pending_blocks set to determine
    /// which verification state to keep.
    ///
    /// Most verification state is keyed by block hash and cleaned up based on
    /// pending_blocks membership (if the block is gone, its verification state
    /// is stale). The `verified_qcs` cache is the exception: it's keyed by the
    /// QC's certified block hash (not the proposing block), so it uses
    /// height-based retention with a 2-block buffer to support view-change
    /// scenarios where multiple proposals share the same parent QC.
    pub fn cleanup(
        &mut self,
        pending_blocks: &HashMap<Hash, crate::pending::PendingBlock>,
        committed_height: u64,
    ) {
        self.pending_qc_verifications
            .retain(|hash, _| pending_blocks.contains_key(hash));

        self.pending_state_root_verifications
            .retain(|hash, _| pending_blocks.contains_key(hash));

        self.state_root_verifications_in_flight
            .retain(|hash| pending_blocks.contains_key(hash));

        self.verified_state_roots
            .retain(|hash| pending_blocks.contains_key(hash));

        self.ready_state_root_verifications
            .retain(|r| pending_blocks.contains_key(&r.block_hash));

        self.transaction_root_verifications_in_flight
            .retain(|hash| pending_blocks.contains_key(hash));

        self.verified_transaction_roots
            .retain(|hash| pending_blocks.contains_key(hash));

        self.receipt_root_verifications_in_flight
            .retain(|hash| pending_blocks.contains_key(hash));

        self.verified_receipt_roots
            .retain(|hash| pending_blocks.contains_key(hash));

        // verified_qcs uses height-based retention (not pending_blocks membership)
        // because QC cache entries are keyed by the certified block's hash, which
        // differs from the proposing block's hash. A 2-block buffer below
        // committed_height covers view-change scenarios where multiple proposals
        // at the same height reference the same parent QC.
        self.verified_qcs
            .retain(|_, height| *height > committed_height.saturating_sub(2));
    }

    /// Number of pending QC verifications.
    pub(crate) fn pending_qc_verifications_len(&self) -> usize {
        self.pending_qc_verifications.len()
    }

    /// Number of cached verified QCs.
    pub(crate) fn verified_qcs_len(&self) -> usize {
        self.verified_qcs.len()
    }

    /// Number of pending state root verifications.
    pub(crate) fn pending_state_root_verifications_len(&self) -> usize {
        self.pending_state_root_verifications.len()
    }
}
