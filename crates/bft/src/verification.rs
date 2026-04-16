//! Async verification pipeline for block voting.
//!
//! Tracks QC signature, state root, transaction root, and receipt root
//! verifications. BftState delegates verification bookkeeping here while
//! retaining control-flow decisions (voting, block rejection).

use hyperscale_types::{Block, BlockHeader, BlockManifest, FinalizedWave, Hash, ReceiptBundle};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::{debug, trace, warn};

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

/// State root verification that is ready to dispatch (JVT is at the correct root).
///
/// The `NodeStateMachine` drains these after each BFT call and emits
/// `VerifyStateRoot` actions using the attached `FinalizedWave` data.
#[derive(Debug)]
pub struct ReadyStateRootVerification {
    pub block_hash: Hash,
    pub parent_block_hash: Hash,
    pub parent_state_root: Hash,
    /// The committed height of the parent block (stable JVT version for computation).
    pub parent_block_height: u64,
    pub expected_root: Hash,
    /// Finalized waves from the PendingBlock — these carry the proposer's receipts,
    /// ensuring all validators verify against the same execution outputs.
    pub finalized_waves: Vec<Arc<FinalizedWave>>,
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

    /// Blocks with verified state roots.
    verified_state_roots: HashSet<Hash>,

    /// Blocks waiting for their parent's tree nodes to become available (via
    /// commit or prior verification). Keyed by parent_block_hash.
    deferred_state_root_verifications: HashMap<Hash, Vec<ReadyStateRootVerification>>,

    /// BuildProposal action waiting for the parent's tree nodes to become
    /// available. At most one pending at a time (new proposals replace old).
    /// Keyed by parent_block_hash for unblocking.
    deferred_proposal: Option<(Hash, Action)>,

    /// Last committed JVT height — used only to decide whether to defer
    /// verification (parent's tree nodes need to be in the store or overlay).
    last_committed_height: u64,

    /// State root verifications ready to dispatch.
    /// Drained by NodeStateMachine which emits `VerifyStateRoot` actions.
    /// The dispatched handler runs against a `SubstateView` anchored at
    /// the parent block, which sees prior unpersisted JVT snapshots so
    /// verification can chain from prior results without waiting for
    /// actual JVT commits.
    ready_state_root_verifications: Vec<ReadyStateRootVerification>,

    /// BuildProposal action ready to dispatch (parent tree became available).
    ready_proposal: Option<Action>,

    // === Transaction root verification ===
    /// Blocks where transaction root verification is currently in-flight.
    transaction_root_verifications_in_flight: HashSet<Hash>,

    /// Blocks with verified transaction roots.
    verified_transaction_roots: HashSet<Hash>,

    // === Certificate root verification ===
    /// Blocks where receipt root verification is currently in-flight.
    certificate_root_verifications_in_flight: HashSet<Hash>,

    /// Blocks with verified receipt roots.
    verified_certificate_roots: HashSet<Hash>,

    // === Local receipt root verification ===
    /// Blocks where local receipt root verification is currently in-flight.
    local_receipt_root_verifications_in_flight: HashSet<Hash>,

    /// Blocks with verified local receipt roots.
    verified_local_receipt_roots: HashSet<Hash>,

    // === Provision root verification ===
    /// Blocks where provisions root verification is currently in-flight.
    provision_root_verifications_in_flight: HashSet<Hash>,

    /// Blocks with verified provisions roots.
    verified_provision_roots: HashSet<Hash>,

    // === In-flight count verification ===
    /// Blocks with verified in-flight counts (synchronous tolerance check).
    verified_in_flight: HashSet<Hash>,
}

impl VerificationPipeline {
    /// Create a new verification pipeline.
    pub fn new(committed_height: u64) -> Self {
        Self {
            pending_qc_verifications: HashMap::new(),
            verified_qcs: HashMap::new(),
            state_root_verifications_in_flight: HashSet::new(),
            verified_state_roots: HashSet::new(),
            deferred_state_root_verifications: HashMap::new(),
            deferred_proposal: None,
            ready_state_root_verifications: Vec::new(),
            ready_proposal: None,
            last_committed_height: committed_height,
            transaction_root_verifications_in_flight: HashSet::new(),
            verified_transaction_roots: HashSet::new(),
            certificate_root_verifications_in_flight: HashSet::new(),
            verified_certificate_roots: HashSet::new(),
            local_receipt_root_verifications_in_flight: HashSet::new(),
            verified_local_receipt_roots: HashSet::new(),
            provision_root_verifications_in_flight: HashSet::new(),
            verified_provision_roots: HashSet::new(),
            verified_in_flight: HashSet::new(),
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

    /// Whether any block verification is currently in-flight.
    ///
    /// Used by `should_advance_round` to suppress view changes while
    /// verification is running — the leader proposed, we received the block,
    /// the timeout should detect leader failure, not slow verification.
    pub fn has_verification_in_flight(&self) -> bool {
        !self.state_root_verifications_in_flight.is_empty()
            || !self.deferred_state_root_verifications.is_empty()
            || self.deferred_proposal.is_some()
            || !self.transaction_root_verifications_in_flight.is_empty()
            || !self.certificate_root_verifications_in_flight.is_empty()
            || !self.local_receipt_root_verifications_in_flight.is_empty()
            || !self.provision_root_verifications_in_flight.is_empty()
            || !self.pending_qc_verifications.is_empty()
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

        let state_root_ok = self.verified_state_roots.contains(&block_hash);

        let transaction_root_ok = if block.transaction_count() == 0 {
            true
        } else {
            self.verified_transaction_roots.contains(&block_hash)
        };

        let certificate_root_ok = if block.certificates.is_empty() {
            true
        } else {
            self.verified_certificate_roots.contains(&block_hash)
        };

        let local_receipt_root_ok = if block.certificates.is_empty() {
            true
        } else {
            self.verified_local_receipt_roots.contains(&block_hash)
        };

        let provision_root_ok = if block.header.provision_root == Hash::ZERO {
            true
        } else {
            self.verified_provision_roots.contains(&block_hash)
        };

        let in_flight_ok = self.verified_in_flight.contains(&block_hash);

        state_root_ok
            && transaction_root_ok
            && certificate_root_ok
            && local_receipt_root_ok
            && provision_root_ok
            && in_flight_ok
    }

    /// Log why a block's verification is incomplete. Called on view change
    /// to explain why the current block couldn't be voted on in time.
    pub fn log_incomplete_verification(&self, block: &Block) {
        let block_hash = block.hash();

        let state_root_status = if self.verified_state_roots.contains(&block_hash) {
            "verified"
        } else if self
            .state_root_verifications_in_flight
            .contains(&block_hash)
        {
            "in_flight"
        } else if self
            .deferred_state_root_verifications
            .values()
            .any(|v| v.iter().any(|r| r.block_hash == block_hash))
        {
            "deferred(parent)"
        } else {
            "NOT_STARTED"
        };

        let tx_root_status = if block.transaction_count() == 0 {
            "skipped(no_txs)"
        } else if self.verified_transaction_roots.contains(&block_hash) {
            "verified"
        } else if self
            .transaction_root_verifications_in_flight
            .contains(&block_hash)
        {
            "in_flight"
        } else {
            "NOT_STARTED"
        };

        let certificate_root_status = if block.certificates.is_empty() {
            "skipped(no_certs)"
        } else if self.verified_certificate_roots.contains(&block_hash) {
            "verified"
        } else if self
            .certificate_root_verifications_in_flight
            .contains(&block_hash)
        {
            "in_flight"
        } else {
            "NOT_STARTED"
        };

        let local_receipt_root_status = if block.certificates.is_empty() {
            "skipped(no_certs)"
        } else if self.verified_local_receipt_roots.contains(&block_hash) {
            "verified"
        } else if self
            .local_receipt_root_verifications_in_flight
            .contains(&block_hash)
        {
            "in_flight"
        } else {
            "NOT_STARTED"
        };

        let provision_root_status = if block.header.provision_root == Hash::ZERO {
            "skipped(no_provisions)"
        } else if self.verified_provision_roots.contains(&block_hash) {
            "verified"
        } else if self
            .provision_root_verifications_in_flight
            .contains(&block_hash)
        {
            "in_flight"
        } else {
            "NOT_STARTED"
        };

        let in_flight_status = if self.verified_in_flight.contains(&block_hash) {
            "verified"
        } else {
            "NOT_STARTED"
        };

        warn!(
            block_hash = ?block_hash,
            height = block.header.height.0,
            proposer = ?block.header.proposer,
            certs = block.certificates.len(),
            txs = block.transaction_count(),
            state_root = state_root_status,
            tx_root = tx_root_status,
            certificate_root = certificate_root_status,
            local_receipt_root = local_receipt_root_status,
            provision_root = provision_root_status,
            in_flight = in_flight_status,
            "View change — block verification was incomplete"
        );
    }

    // ─── State root ──────────────────────────────────────────────────────

    /// Check if a block needs state root verification before voting.
    ///
    /// Always returns true for blocks that haven't been verified yet —
    /// even cert-less blocks verify (trivially) so their PreparedCommit
    /// populates the overlay for child block verifications.
    pub fn needs_state_root_verification(&self, block: &Block) -> bool {
        let block_hash = block.hash();

        if self.verified_state_roots.contains(&block_hash)
            || self
                .state_root_verifications_in_flight
                .contains(&block_hash)
            || self
                .deferred_state_root_verifications
                .values()
                .any(|v| v.iter().any(|r| r.block_hash == block_hash))
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
        parent_block_height: u64,
        finalized_waves: Vec<Arc<FinalizedWave>>,
    ) {
        let parent_hash = block.header.parent_hash;
        let ready = ReadyStateRootVerification {
            block_hash,
            parent_block_hash: parent_hash,
            parent_state_root,
            parent_block_height,
            expected_root: block.header.state_root,
            finalized_waves,
            block_height: block.header.height.0,
        };

        // The parent's tree nodes must be available — either committed to
        // the tree store or in the snapshot cache (from a prior verification).
        // Defer if: parent height exceeds committed JVT AND parent hasn't
        // been verified (no snapshot in the overlay).
        let parent_tree_available = parent_block_height <= self.last_committed_height
            || self.verified_state_roots.contains(&parent_hash);

        if !parent_tree_available {
            debug!(
                block_hash = ?block_hash,
                parent_hash = ?parent_hash,
                "Deferring state root verification — parent not yet verified"
            );
            self.deferred_state_root_verifications
                .entry(parent_hash)
                .or_default()
                .push(ready);
        } else {
            self.state_root_verifications_in_flight.insert(block_hash);
            self.ready_state_root_verifications.push(ready);
        }
    }

    /// Record a state root verification result. Returns whether the verification passed.
    ///
    /// On success, unblocks any child blocks that were deferred waiting for
    /// this parent's verification to complete.
    pub fn on_state_root_verified(&mut self, block_hash: Hash, valid: bool) -> bool {
        self.state_root_verifications_in_flight.remove(&block_hash);

        if valid {
            self.verified_state_roots.insert(block_hash);
            debug!(block_hash = ?block_hash, "State root verified successfully");

            // Unblock children that were waiting for this parent.
            if let Some(deferred) = self.deferred_state_root_verifications.remove(&block_hash) {
                for ready in deferred {
                    debug!(
                        child = ?ready.block_hash,
                        parent = ?block_hash,
                        "Unblocking deferred state root verification"
                    );
                    self.state_root_verifications_in_flight
                        .insert(ready.block_hash);
                    self.ready_state_root_verifications.push(ready);
                }
            }

            // Unblock deferred proposal if it was waiting for this parent.
            self.try_unblock_proposal(block_hash);
        } else {
            warn!(block_hash = ?block_hash, "State root verification FAILED");

            // Clear deferred children — they can never unblock since the
            // parent failed. Without this, deferred entries are orphaned
            // and block verification indefinitely.
            if let Some(orphans) = self.deferred_state_root_verifications.remove(&block_hash) {
                warn!(
                    block_hash = ?block_hash,
                    orphaned_count = orphans.len(),
                    "Clearing deferred state root verifications — parent failed"
                );
            }
        }

        valid
    }

    /// Mark a block's state root as verified because the proposer built it.
    ///
    /// The proposer computed the state root during `BuildProposal`, so it is
    /// inherently correct. This populates the overlay chain so that child
    /// blocks can verify without waiting for the block to be committed.
    fn mark_proposal_state_root_verified(&mut self, block_hash: Hash) {
        self.verified_state_roots.insert(block_hash);

        // Unblock children deferred on this parent.
        if let Some(deferred) = self.deferred_state_root_verifications.remove(&block_hash) {
            for ready in deferred {
                debug!(
                    child = ?ready.block_hash,
                    parent = ?block_hash,
                    "Unblocking deferred state root verification (proposer verified)"
                );
                self.state_root_verifications_in_flight
                    .insert(ready.block_hash);
                self.ready_state_root_verifications.push(ready);
            }
        }

        // Unblock deferred proposal if it was waiting for this parent.
        self.try_unblock_proposal(block_hash);
    }

    /// Mark all roots as verified for the proposer's own block.
    ///
    /// The proposer built the block, so all merkle roots are inherently
    /// correct. This marks state root, transaction root, certificate root,
    /// local receipt root, provision root, and in-flight as verified so
    /// the verification pipeline is complete. Without this, a view change
    /// would report these as NOT_STARTED since the proposer path bypasses
    /// `try_vote_on_block`.
    pub fn mark_proposal_fully_verified(&mut self, block_hash: Hash) {
        self.mark_proposal_state_root_verified(block_hash);
        self.verified_transaction_roots.insert(block_hash);
        self.verified_certificate_roots.insert(block_hash);
        self.verified_local_receipt_roots.insert(block_hash);
        self.verified_provision_roots.insert(block_hash);
        self.verified_in_flight.insert(block_hash);
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

    // ─── Certificate root ─────────────────────────────────────────────────────

    /// Check if a block needs receipt root verification before voting.
    pub fn needs_certificate_root_verification(&self, block: &Block) -> bool {
        if block.certificates.is_empty() {
            return false;
        }

        let block_hash = block.hash();

        if self.verified_certificate_roots.contains(&block_hash)
            || self
                .certificate_root_verifications_in_flight
                .contains(&block_hash)
        {
            return false;
        }

        true
    }

    /// Initiate receipt root verification for a block.
    pub fn initiate_certificate_root_verification(
        &mut self,
        block_hash: Hash,
        block: &Block,
    ) -> Vec<Action> {
        debug!(
            block_hash = ?block_hash,
            cert_count = block.certificates.len(),
            expected_root = ?block.header.certificate_root,
            "Initiating receipt root verification"
        );

        self.certificate_root_verifications_in_flight
            .insert(block_hash);

        vec![Action::VerifyCertificateRoot {
            block_hash,
            expected_root: block.header.certificate_root,
            certificates: block.certificates.clone(),
        }]
    }

    /// Record a receipt root verification result. Returns whether the verification passed.
    pub fn on_certificate_root_verified(&mut self, block_hash: Hash, valid: bool) -> bool {
        self.certificate_root_verifications_in_flight
            .remove(&block_hash);

        if valid {
            self.verified_certificate_roots.insert(block_hash);
            debug!(
                block_hash = ?block_hash,
                "Certificate root verified successfully"
            );
        }

        valid
    }

    // ─── Local receipt root ─────────────────────────────────────────────

    /// Check if a block needs local receipt root verification before voting.
    pub fn needs_local_receipt_root_verification(&self, block: &Block) -> bool {
        if block.certificates.is_empty() {
            return false;
        }

        let block_hash = block.hash();

        if self.verified_local_receipt_roots.contains(&block_hash)
            || self
                .local_receipt_root_verifications_in_flight
                .contains(&block_hash)
        {
            return false;
        }

        true
    }

    /// Initiate local receipt root verification for a block.
    pub fn initiate_local_receipt_root_verification(
        &mut self,
        block_hash: Hash,
        block: &Block,
        receipts: Vec<ReceiptBundle>,
    ) -> Vec<Action> {
        debug!(
            block_hash = ?block_hash,
            receipt_count = receipts.len(),
            expected_root = ?block.header.local_receipt_root,
            "Initiating local receipt root verification"
        );

        self.local_receipt_root_verifications_in_flight
            .insert(block_hash);

        vec![Action::VerifyLocalReceiptRoot {
            block_hash,
            expected_root: block.header.local_receipt_root,
            receipts,
        }]
    }

    /// Record a local receipt root verification result. Returns whether the verification passed.
    pub fn on_local_receipt_root_verified(&mut self, block_hash: Hash, valid: bool) -> bool {
        self.local_receipt_root_verifications_in_flight
            .remove(&block_hash);

        if valid {
            self.verified_local_receipt_roots.insert(block_hash);
            debug!(
                block_hash = ?block_hash,
                "Local receipt root verified successfully"
            );
        }

        valid
    }

    // ─── Provision root ─────────────────────────────────────────────────

    /// Check if a block needs provisions root verification before voting.
    pub fn needs_provision_root_verification(&self, block: &Block) -> bool {
        if block.header.provision_root == Hash::ZERO {
            return false;
        }

        let block_hash = block.hash();

        if self.verified_provision_roots.contains(&block_hash)
            || self
                .provision_root_verifications_in_flight
                .contains(&block_hash)
        {
            return false;
        }

        true
    }

    /// Initiate provisions root verification for a block.
    pub fn initiate_provision_root_verification(
        &mut self,
        block_hash: Hash,
        block: &Block,
        manifest: &BlockManifest,
    ) -> Vec<Action> {
        debug!(
            block_hash = ?block_hash,
            batch_count = manifest.provision_hashes.len(),
            expected_root = ?block.header.provision_root,
            "Initiating provisions root verification"
        );

        self.provision_root_verifications_in_flight
            .insert(block_hash);

        vec![Action::VerifyProvisionRoot {
            block_hash,
            expected_root: block.header.provision_root,
            batch_hashes: manifest.provision_hashes.clone(),
        }]
    }

    /// Record a provisions root verification result.
    pub fn on_provision_root_verified(&mut self, block_hash: Hash, valid: bool) -> bool {
        self.provision_root_verifications_in_flight
            .remove(&block_hash);

        if valid {
            self.verified_provision_roots.insert(block_hash);
            debug!(
                block_hash = ?block_hash,
                "Provision root verified successfully"
            );
        }

        valid
    }

    // ═══════════════════════════════════════════════════════════════════════
    // In-flight count verification (synchronous)
    // ═══════════════════════════════════════════════════════════════════════

    /// Verify the proposed in-flight count is deterministically correct.
    ///
    /// in_flight = parent.in_flight + new_txs - finalized_txs
    ///
    /// All validators can compute this from chain state, so it must be exact.
    /// Certificates are only counted when actually included (JVT was ready).
    pub fn verify_in_flight(
        &mut self,
        block_hash: Hash,
        block: &Block,
        parent_in_flight: u32,
        finalized_tx_count: u32,
    ) -> bool {
        let proposed = block.header.in_flight;

        // Compute expected: only subtract finalized txs when certs are actually included.
        let certs_finalized = if block.certificates.is_empty() {
            0
        } else {
            finalized_tx_count
        };
        let expected = parent_in_flight
            .saturating_add(block.transaction_count() as u32)
            .saturating_sub(certs_finalized);

        if proposed == expected {
            self.verified_in_flight.insert(block_hash);
            true
        } else {
            warn!(
                block_hash = ?block_hash,
                height = block.header.height.0,
                proposed = proposed,
                expected = expected,
                parent_in_flight = parent_in_flight,
                new_txs = block.transaction_count(),
                finalized_txs = certs_finalized,
                "In-flight count verification failed — proposed value does not match expected"
            );
            false
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Remote header QC verification
    // ═══════════════════════════════════════════════════════════════════════

    /// Drain state root verifications that are ready to dispatch.
    ///
    /// The caller (`NodeStateMachine`) computes `merged_updates` from the
    /// execution cache for each verification and emits the `VerifyStateRoot` action.
    pub fn drain_ready_state_root_verifications(&mut self) -> Vec<ReadyStateRootVerification> {
        std::mem::take(&mut self.ready_state_root_verifications)
    }

    /// Take the ready BuildProposal action if one was unblocked.
    pub fn take_ready_proposal(&mut self) -> Option<Action> {
        self.ready_proposal.take()
    }

    /// Check if a parent's tree nodes are available (committed or verified).
    pub fn parent_tree_available(&self, parent_block_height: u64, parent_hash: Hash) -> bool {
        parent_block_height <= self.last_committed_height
            || self.verified_state_roots.contains(&parent_hash)
    }

    /// Defer a BuildProposal action until its parent's tree nodes are available.
    /// Replaces any previously deferred proposal (only one active at a time).
    pub fn defer_proposal(&mut self, parent_hash: Hash, action: Action) {
        debug!(
            parent_hash = ?parent_hash,
            "Deferring BuildProposal — parent tree not yet available"
        );
        self.deferred_proposal = Some((parent_hash, action));
    }

    /// If the deferred proposal was waiting for `unblocked_hash`, make it ready.
    fn try_unblock_proposal(&mut self, unblocked_hash: Hash) {
        if matches!(&self.deferred_proposal, Some((parent, _)) if *parent == unblocked_hash) {
            let (_, action) = self.deferred_proposal.take().unwrap();
            debug!(parent_hash = ?unblocked_hash, "Unblocking deferred BuildProposal");
            self.ready_proposal = Some(action);
        }
    }

    /// A block committed to the tree store. Unblock any deferred
    /// verifications and proposals whose parent's tree nodes are now available.
    pub fn on_jvt_committed(&mut self, block_height: u64) {
        if block_height <= self.last_committed_height {
            return;
        }
        self.last_committed_height = block_height;

        // Unblock deferred verifications whose parent height is now committed.
        let unblocked_parents: Vec<Hash> = self
            .deferred_state_root_verifications
            .iter()
            .filter(|(_, entries)| {
                entries
                    .iter()
                    .any(|r| r.parent_block_height <= block_height)
            })
            .map(|(parent_hash, _)| *parent_hash)
            .collect();

        for parent_hash in unblocked_parents {
            if let Some(entries) = self.deferred_state_root_verifications.remove(&parent_hash) {
                for ready in entries {
                    if ready.parent_block_height <= block_height {
                        self.state_root_verifications_in_flight
                            .insert(ready.block_hash);
                        self.ready_state_root_verifications.push(ready);
                    } else {
                        self.deferred_state_root_verifications
                            .entry(parent_hash)
                            .or_default()
                            .push(ready);
                    }
                }
            }
        }

        // Unblock deferred proposal if its parent height is now committed.
        if let Some((_, action)) = &self.deferred_proposal {
            let ready = matches!(
                action,
                Action::BuildProposal { parent_block_height, .. }
                    if *parent_block_height <= block_height
            );
            if ready {
                let (_, action) = self.deferred_proposal.take().unwrap();
                debug!("Unblocking deferred BuildProposal — parent committed");
                self.ready_proposal = Some(action);
            }
        }
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

        self.state_root_verifications_in_flight
            .retain(|hash| pending_blocks.contains_key(hash));

        self.verified_state_roots
            .retain(|hash| pending_blocks.contains_key(hash));

        self.ready_state_root_verifications
            .retain(|r| pending_blocks.contains_key(&r.block_hash));

        // Clean up deferred verifications: remove entries whose child blocks
        // are no longer pending, and remove parent keys with empty lists.
        for entries in self.deferred_state_root_verifications.values_mut() {
            entries.retain(|r| pending_blocks.contains_key(&r.block_hash));
        }
        self.deferred_state_root_verifications
            .retain(|_, entries| !entries.is_empty());

        // Clear deferred proposal if its parent is at or below committed height
        // (the proposal is stale — a new round/view will generate a fresh one).
        if let Some((_, action)) = &self.deferred_proposal {
            let stale = matches!(
                action,
                Action::BuildProposal { parent_block_height, .. }
                    if *parent_block_height <= committed_height
            );
            if stale {
                self.deferred_proposal = None;
            }
        }

        self.transaction_root_verifications_in_flight
            .retain(|hash| pending_blocks.contains_key(hash));

        self.verified_transaction_roots
            .retain(|hash| pending_blocks.contains_key(hash));

        self.certificate_root_verifications_in_flight
            .retain(|hash| pending_blocks.contains_key(hash));

        self.verified_certificate_roots
            .retain(|hash| pending_blocks.contains_key(hash));

        self.local_receipt_root_verifications_in_flight
            .retain(|hash| pending_blocks.contains_key(hash));

        self.verified_local_receipt_roots
            .retain(|hash| pending_blocks.contains_key(hash));

        self.provision_root_verifications_in_flight
            .retain(|hash| pending_blocks.contains_key(hash));

        self.verified_provision_roots
            .retain(|hash| pending_blocks.contains_key(hash));

        self.verified_in_flight
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

    /// Number of deferred state root verifications (waiting for parent).
    pub(crate) fn pending_state_root_verifications_len(&self) -> usize {
        self.deferred_state_root_verifications
            .values()
            .map(|v| v.len())
            .sum()
    }
}
