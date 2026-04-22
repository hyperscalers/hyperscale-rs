//! Async verification pipeline for block voting.
//!
//! Tracks QC signature, state root, transaction root, and receipt root
//! verifications. BftCoordinator delegates verification bookkeeping here while
//! retaining control-flow decisions (voting, block rejection).
//!
//! Pure pre-vote validation helpers (header structure, timestamp bounds,
//! transaction ordering, `waves` recomputation, cross-ancestor tx uniqueness)
//! live in [`crate::validation`].

#[cfg(test)]
use hyperscale_types::Hash;
use hyperscale_types::{
    Block, BlockHash, BlockHeader, BlockHeight, BlockManifest, FinalizedWave, ProvisionsRoot,
    ReceiptBundle, StateRoot, TopologySnapshot,
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::{debug, trace, warn};

use crate::chain_view::ChainView;
use crate::pending::PendingBlock;
use hyperscale_core::{Action, VerificationKind};

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

/// State root verification that is ready to dispatch (JMT is at the correct root).
///
/// The `NodeStateMachine` drains these after each BFT call and emits
/// `VerifyStateRoot` actions. `parent_state_root` and `finalized_waves` are
/// resolved at drain time from the current chain/pending-block state, not
/// captured at `initiate_state_root_verification` time — capturing at initiate
/// time produced a stale-snapshot race where an entry deferred before its
/// parent committed would dispatch with the wrong `parent_state_root`.
#[derive(Debug)]
pub struct ReadyStateRootVerification {
    pub block_hash: BlockHash,
    pub parent_block_hash: BlockHash,
    pub parent_state_root: StateRoot,
    /// The committed height of the parent block (stable anchor for JMT computation).
    pub parent_block_height: BlockHeight,
    pub expected_root: StateRoot,
    /// Finalized waves from the PendingBlock — these carry the proposer's receipts,
    /// ensuring all validators verify against the same execution outputs.
    pub finalized_waves: Vec<Arc<FinalizedWave>>,
    pub block_height: BlockHeight,
}

/// Classification of the in-flight check outcome for the vote path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InFlightCheck {
    /// In-flight count passes — proceed with voting.
    Proceed,
    /// Run verifications but do not vote (vote-locked, or parent pruned).
    SkipVote,
    /// In-flight count exceeds the allowed tolerance — abort entirely.
    Abort,
}

/// Internal queue entry for state root verification. Holds only block identity
/// — `parent_state_root` and `finalized_waves` are resolved freshly at drain
/// time against the current chain view.
#[derive(Debug, Clone)]
pub(crate) struct PendingStateRootVerification {
    pub block_hash: BlockHash,
    pub parent_block_hash: BlockHash,
    pub parent_block_height: BlockHeight,
    pub expected_root: StateRoot,
    pub block_height: BlockHeight,
}

// ═══════════════════════════════════════════════════════════════════════════
// VerificationPipeline
// ═══════════════════════════════════════════════════════════════════════════

/// Tracks all async verification state for block voting.
///
/// BftCoordinator owns this as a field and delegates verification bookkeeping
/// to it. Control-flow decisions (vote, reject block) remain in BftCoordinator.
pub(crate) struct VerificationPipeline {
    // === QC signature verification ===
    /// Block headers pending QC signature verification.
    /// Maps block_hash -> pending verification info.
    pending_qc_verifications: HashMap<BlockHash, PendingQcVerification>,

    /// Cache of already-verified QC signatures.
    /// Maps QC's block_hash (the block the QC certifies) -> height.
    verified_qcs: HashMap<BlockHash, BlockHeight>,

    // === State root verification ===
    /// Blocks where state root verification is currently in-flight.
    state_root_verifications_in_flight: HashSet<BlockHash>,

    /// Blocks with verified state roots.
    verified_state_roots: HashSet<BlockHash>,

    /// Blocks waiting for their parent's tree nodes to become available (via
    /// commit or prior verification). Keyed by parent_block_hash.
    deferred_state_root_verifications: HashMap<BlockHash, Vec<PendingStateRootVerification>>,

    /// Deferred proposal waiting for the parent's tree nodes to become
    /// available. At most one pending at a time (new proposals replace old).
    /// Stores `(parent_block_hash, parent_block_height)` for unblocking.
    /// When unblocked, we re-enter `try_propose` via `ContentAvailable`
    /// rather than dispatching a stale `BuildProposal` — transaction
    /// selection must use current state to avoid including txs that were
    /// committed between deferral and dispatch.
    deferred_proposal: Option<(BlockHash, BlockHeight)>,

    /// Highest persisted height — parent trees at or below this height
    /// are readable from disk, so child verifications for blocks beyond
    /// this height must defer until either parent persists, parent is
    /// locally verified, or parent is consensus-committed (which places
    /// its JMT snapshot in `PendingChain`).
    last_persisted_height: BlockHeight,

    /// State root verifications ready to dispatch.
    /// Drained by NodeStateMachine which emits `VerifyStateRoot` actions.
    /// The dispatched handler runs against a `SubstateView` anchored at
    /// the parent block, which sees prior unpersisted JMT snapshots so
    /// verification can chain from prior results without waiting for
    /// actual JMT commits.
    ready_state_root_verifications: Vec<PendingStateRootVerification>,

    /// Set when a deferred proposal's parent tree became available.
    /// Consumed by `take_ready_proposal` which emits `ContentAvailable`
    /// to re-enter `try_propose` with fresh transaction selection.
    proposal_unblocked: bool,

    // === Per-root merkle verification ===
    /// `(block_hash, kind)` pairs currently being verified (transaction,
    /// certificate, local-receipt, provision, provision-tx roots).
    /// State-root uses separate fields above because its lifecycle
    /// includes deferred/ready queues for parent-tree availability.
    in_flight_roots: HashSet<(BlockHash, VerificationKind)>,

    /// `(block_hash, kind)` pairs whose merkle root has been verified.
    verified_roots: HashSet<(BlockHash, VerificationKind)>,

    // === In-flight count verification ===
    /// Blocks with verified in-flight counts (synchronous tolerance check).
    verified_in_flight: HashSet<BlockHash>,
}

impl VerificationPipeline {
    /// Create a new verification pipeline.
    pub fn new(persisted_height: BlockHeight) -> Self {
        Self {
            pending_qc_verifications: HashMap::new(),
            verified_qcs: HashMap::new(),
            state_root_verifications_in_flight: HashSet::new(),
            verified_state_roots: HashSet::new(),
            deferred_state_root_verifications: HashMap::new(),
            deferred_proposal: None,
            ready_state_root_verifications: Vec::new(),
            proposal_unblocked: false,
            last_persisted_height: persisted_height,
            in_flight_roots: HashSet::new(),
            verified_roots: HashSet::new(),
            verified_in_flight: HashSet::new(),
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Per-root merkle state (shared helpers)
    // ═══════════════════════════════════════════════════════════════════════

    /// Whether the given merkle root has been verified for `block_hash`.
    /// State-root callers use [`Self::is_state_root_verified`] instead.
    fn is_root_verified(&self, block_hash: BlockHash, kind: VerificationKind) -> bool {
        self.verified_roots.contains(&(block_hash, kind))
    }

    /// Whether a merkle-root verification is currently in-flight for
    /// `(block_hash, kind)`.
    fn is_root_in_flight(&self, block_hash: BlockHash, kind: VerificationKind) -> bool {
        self.in_flight_roots.contains(&(block_hash, kind))
    }

    /// Skip the verification when the block carries no relevant content,
    /// has already been verified, or is already in-flight.
    fn needs_root(
        &self,
        block_hash: BlockHash,
        kind: VerificationKind,
        has_relevant_content: bool,
    ) -> bool {
        has_relevant_content
            && !self.is_root_verified(block_hash, kind)
            && !self.is_root_in_flight(block_hash, kind)
    }

    /// Mark the root verification as in-flight so duplicate dispatch is
    /// avoided until the result lands.
    fn mark_root_in_flight(&mut self, block_hash: BlockHash, kind: VerificationKind) {
        self.in_flight_roots.insert((block_hash, kind));
    }

    /// Record a merkle-root verification result for one of the per-kind
    /// merkle roots (transaction, certificate, local-receipt, provision,
    /// provision-tx). Returns `valid` so the caller can short-circuit.
    /// State-root results go through [`Self::on_state_root_verified`].
    pub fn on_root_verified(
        &mut self,
        block_hash: BlockHash,
        kind: VerificationKind,
        valid: bool,
    ) -> bool {
        self.in_flight_roots.remove(&(block_hash, kind));
        if valid {
            self.verified_roots.insert((block_hash, kind));
            debug!(?kind, ?block_hash, "Merkle root verified successfully");
        }
        valid
    }

    // ═══════════════════════════════════════════════════════════════════════
    // QC signature verification
    // ═══════════════════════════════════════════════════════════════════════

    /// Track a block header pending QC signature verification.
    pub fn track_pending_qc(&mut self, block_hash: BlockHash, header: BlockHeader) {
        self.pending_qc_verifications
            .insert(block_hash, PendingQcVerification { header });
    }

    /// Check if a QC has already been verified (cache hit).
    pub fn is_qc_verified(&self, qc_block_hash: &BlockHash) -> bool {
        self.verified_qcs.contains_key(qc_block_hash)
    }

    /// Record a QC signature verification result. Returns the pending header if found.
    pub fn on_qc_verified(
        &mut self,
        block_hash: BlockHash,
        valid: bool,
    ) -> Option<(BlockHeader, bool)> {
        let pending = self.pending_qc_verifications.remove(&block_hash)?;
        Some((pending.header, valid))
    }

    /// Cache a verified QC to skip future re-verification.
    pub fn cache_verified_qc(&mut self, qc_block_hash: BlockHash, height: BlockHeight) {
        self.verified_qcs.insert(qc_block_hash, height);
        trace!(
            qc_block_hash = ?qc_block_hash,
            qc_height = height.0,
            "Cached verified QC"
        );
    }

    /// Check if a block has a pending QC verification in-flight.
    pub fn has_pending_qc(&self, block_hash: &BlockHash) -> bool {
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
            || !self.in_flight_roots.is_empty()
            || !self.pending_qc_verifications.is_empty()
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Block verification (state root, tx root, receipt root)
    // ═══════════════════════════════════════════════════════════════════════

    /// Whether this node has verified the state root of a block itself
    /// (vs. trusting it purely via the QC chain).
    ///
    /// Used by the commit path to decide between `CommitBlock` (fast path —
    /// PreparedCommit from `VerifyStateRoot` already in the cache) and
    /// `CommitBlockByQcOnly` (slow path — compute inline at commit time).
    pub fn is_state_root_verified(&self, block_hash: &BlockHash) -> bool {
        self.verified_state_roots.contains(block_hash)
    }

    /// Check if all async verifications are complete for a block.
    ///
    /// Returns true if source attestation, state root, and transaction root
    /// verifications are all done (or not needed).
    pub fn is_block_verified(&self, block: &Block) -> bool {
        let block_hash = block.hash();
        let h = block.header();

        let root_ok =
            |kind, has_content: bool| !has_content || self.is_root_verified(block_hash, kind);

        self.verified_state_roots.contains(&block_hash)
            && root_ok(
                VerificationKind::TransactionRoot,
                block.transaction_count() > 0,
            )
            && root_ok(
                VerificationKind::CertificateRoot,
                !block.certificates().is_empty(),
            )
            && root_ok(
                VerificationKind::LocalReceiptRoot,
                !block.certificates().is_empty(),
            )
            && root_ok(
                VerificationKind::ProvisionRoot,
                h.provision_root != ProvisionsRoot::ZERO,
            )
            && root_ok(
                VerificationKind::ProvisionTxRoots,
                !h.provision_tx_roots.is_empty(),
            )
            && self.verified_in_flight.contains(&block_hash)
    }

    /// Log why a block's verification is incomplete. Called on view change
    /// to explain why the current block couldn't be voted on in time.
    pub fn log_incomplete_verification(&self, block: &Block) {
        let block_hash = block.hash();
        let h = block.header();

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

        let root_status = |kind: VerificationKind, skip_label: &'static str, has_content: bool| {
            if !has_content {
                skip_label
            } else if self.is_root_verified(block_hash, kind) {
                "verified"
            } else if self.is_root_in_flight(block_hash, kind) {
                "in_flight"
            } else {
                "NOT_STARTED"
            }
        };

        let tx_root_status = root_status(
            VerificationKind::TransactionRoot,
            "skipped(no_txs)",
            block.transaction_count() > 0,
        );
        let certificate_root_status = root_status(
            VerificationKind::CertificateRoot,
            "skipped(no_certs)",
            !block.certificates().is_empty(),
        );
        let local_receipt_root_status = root_status(
            VerificationKind::LocalReceiptRoot,
            "skipped(no_certs)",
            !block.certificates().is_empty(),
        );
        let provision_root_status = root_status(
            VerificationKind::ProvisionRoot,
            "skipped(no_provisions)",
            h.provision_root != ProvisionsRoot::ZERO,
        );
        let provision_tx_root_status = root_status(
            VerificationKind::ProvisionTxRoots,
            "skipped(no_provision_targets)",
            !h.provision_tx_roots.is_empty(),
        );

        let in_flight_status = if self.verified_in_flight.contains(&block_hash) {
            "verified"
        } else {
            "NOT_STARTED"
        };

        warn!(
            block_hash = ?block_hash,
            height = block.height().0,
            proposer = ?block.header().proposer,
            certs = block.certificates().len(),
            txs = block.transaction_count(),
            state_root = state_root_status,
            tx_root = tx_root_status,
            certificate_root = certificate_root_status,
            local_receipt_root = local_receipt_root_status,
            provision_root = provision_root_status,
            provision_tx_root = provision_tx_root_status,
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
    /// If JMT is ready, pushes to the ready queue for immediate dispatch.
    /// Otherwise, queues for later when JMT catches up. Only block identity
    /// is captured; `parent_state_root` and `finalized_waves` are resolved
    /// freshly at drain time to avoid stale-snapshot races where an entry
    /// deferred before its parent committed would dispatch with the wrong
    /// base state.
    pub fn initiate_state_root_verification(
        &mut self,
        block_hash: BlockHash,
        block: &Block,
        parent_block_height: BlockHeight,
    ) {
        let parent_hash = block.header().parent_hash;
        let ready = PendingStateRootVerification {
            block_hash,
            parent_block_hash: parent_hash,
            parent_block_height,
            expected_root: block.header().state_root,
            block_height: block.height(),
        };

        // The parent's tree nodes must be available — either committed to
        // the tree store or in the snapshot cache (from a prior verification).
        // Defer if: parent height exceeds committed JMT AND parent hasn't
        // been verified (no snapshot in the overlay).
        let parent_tree_available = parent_block_height <= self.last_persisted_height
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
    pub fn on_state_root_verified(&mut self, block_hash: BlockHash, valid: bool) -> bool {
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
    fn mark_proposal_state_root_verified(&mut self, block_hash: BlockHash) {
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
    pub fn mark_proposal_fully_verified(&mut self, block_hash: BlockHash) {
        self.mark_proposal_state_root_verified(block_hash);
        for kind in [
            VerificationKind::TransactionRoot,
            VerificationKind::CertificateRoot,
            VerificationKind::LocalReceiptRoot,
            VerificationKind::ProvisionRoot,
            VerificationKind::ProvisionTxRoots,
        ] {
            self.verified_roots.insert((block_hash, kind));
        }
        self.verified_in_flight.insert(block_hash);
    }

    // ─── Per-kind initiators ────────────────────────────────────────────
    //
    // One method per root kind; each emits its distinct `Action` variant
    // and records the in-flight marker via `mark_root_in_flight`. All
    // results flow back through [`Self::on_root_verified`].

    /// Initiate transaction root verification for a block.
    pub fn initiate_transaction_root_verification(
        &mut self,
        block_hash: BlockHash,
        block: &Block,
    ) -> Vec<Action> {
        debug!(
            ?block_hash,
            tx_count = block.transactions().len(),
            expected_root = ?block.header().transaction_root,
            "Initiating transaction root verification"
        );
        self.mark_root_in_flight(block_hash, VerificationKind::TransactionRoot);
        vec![Action::VerifyTransactionRoot {
            block_hash,
            expected_root: block.header().transaction_root,
            transactions: block.transactions().to_vec(),
        }]
    }

    /// Initiate receipt root verification for a block.
    pub fn initiate_certificate_root_verification(
        &mut self,
        block_hash: BlockHash,
        block: &Block,
    ) -> Vec<Action> {
        debug!(
            ?block_hash,
            cert_count = block.certificates().len(),
            expected_root = ?block.header().certificate_root,
            "Initiating receipt root verification"
        );
        self.mark_root_in_flight(block_hash, VerificationKind::CertificateRoot);
        vec![Action::VerifyCertificateRoot {
            block_hash,
            expected_root: block.header().certificate_root,
            certificates: block.certificates().to_vec(),
        }]
    }

    /// Initiate local receipt root verification for a block.
    pub fn initiate_local_receipt_root_verification(
        &mut self,
        block_hash: BlockHash,
        block: &Block,
        receipts: Vec<ReceiptBundle>,
    ) -> Vec<Action> {
        debug!(
            ?block_hash,
            receipt_count = receipts.len(),
            expected_root = ?block.header().local_receipt_root,
            "Initiating local receipt root verification"
        );
        self.mark_root_in_flight(block_hash, VerificationKind::LocalReceiptRoot);
        vec![Action::VerifyLocalReceiptRoot {
            block_hash,
            expected_root: block.header().local_receipt_root,
            receipts,
        }]
    }

    /// Initiate provisions root verification for a block.
    pub fn initiate_provision_root_verification(
        &mut self,
        block_hash: BlockHash,
        block: &Block,
        manifest: &BlockManifest,
    ) -> Vec<Action> {
        debug!(
            ?block_hash,
            batch_count = manifest.provision_hashes.len(),
            expected_root = ?block.header().provision_root,
            "Initiating provisions root verification"
        );
        self.mark_root_in_flight(block_hash, VerificationKind::ProvisionRoot);
        vec![Action::VerifyProvisionRoot {
            block_hash,
            expected_root: block.header().provision_root,
            batch_hashes: manifest.provision_hashes.clone(),
        }]
    }

    /// Initiate provision tx-root verification for a block.
    pub fn initiate_provision_tx_root_verification(
        &mut self,
        block_hash: BlockHash,
        block: &Block,
        topology: &TopologySnapshot,
    ) -> Vec<Action> {
        debug!(
            ?block_hash,
            target_count = block.header().provision_tx_roots.len(),
            "Initiating provision tx-root verification"
        );
        self.mark_root_in_flight(block_hash, VerificationKind::ProvisionTxRoots);
        vec![Action::VerifyProvisionTxRoots {
            block_hash,
            expected: block.header().provision_tx_roots.clone(),
            transactions: block.transactions().to_vec(),
            topology: topology.clone(),
        }]
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Async verification dispatch
    // ═══════════════════════════════════════════════════════════════════════

    /// Initiate every outstanding async verification for a candidate block in
    /// parallel: state root, transaction root, provision root, certificate
    /// root, local receipt root, and per-target provision tx roots. Returns
    /// the actions the caller should dispatch; state-root verification is
    /// queued into the ready list and drained separately.
    pub(crate) fn initiate_block_verifications(
        &mut self,
        topology: &TopologySnapshot,
        pending_blocks: &HashMap<BlockHash, PendingBlock>,
        block_hash: BlockHash,
        block: &Block,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        let h = block.header();

        if self.needs_state_root_verification(block) {
            let parent_block_height = h.parent_qc.height;
            self.initiate_state_root_verification(block_hash, block, parent_block_height);
        }

        if self.needs_root(
            block_hash,
            VerificationKind::TransactionRoot,
            block.transaction_count() > 0,
        ) {
            actions.extend(self.initiate_transaction_root_verification(block_hash, block));
        }

        if self.needs_root(
            block_hash,
            VerificationKind::ProvisionRoot,
            h.provision_root != ProvisionsRoot::ZERO,
        ) {
            if let Some(pending) = pending_blocks.get(&block_hash) {
                actions.extend(self.initiate_provision_root_verification(
                    block_hash,
                    block,
                    pending.manifest(),
                ));
            }
        }

        if self.needs_root(
            block_hash,
            VerificationKind::CertificateRoot,
            !block.certificates().is_empty(),
        ) {
            actions.extend(self.initiate_certificate_root_verification(block_hash, block));
        }

        if self.needs_root(
            block_hash,
            VerificationKind::LocalReceiptRoot,
            !block.certificates().is_empty(),
        ) {
            let receipts: Vec<_> = block
                .certificates()
                .iter()
                .flat_map(|fw| fw.receipts.iter().cloned())
                .collect();
            actions
                .extend(self.initiate_local_receipt_root_verification(block_hash, block, receipts));
        }

        if self.needs_root(
            block_hash,
            VerificationKind::ProvisionTxRoots,
            !h.provision_tx_roots.is_empty(),
        ) {
            actions
                .extend(self.initiate_provision_tx_root_verification(block_hash, block, topology));
        }

        actions
    }

    // ═══════════════════════════════════════════════════════════════════════
    // In-flight count verification (synchronous)
    // ═══════════════════════════════════════════════════════════════════════

    /// Classify a vote-path block against the in-flight count tolerance,
    /// resolving parent-in-flight from the chain view and finalized-tx count
    /// from the pending block. Callers use the returned [`InFlightCheck`] to
    /// decide between voting, running verifications only, or aborting.
    pub(crate) fn classify_vote_in_flight(
        &mut self,
        chain: &ChainView<'_>,
        block_hash: BlockHash,
        block: &Block,
        vote_locked: bool,
    ) -> InFlightCheck {
        if vote_locked {
            return InFlightCheck::SkipVote;
        }

        let parent_in_flight = if block.header().parent_qc.is_genesis() {
            0
        } else if let Some(h) = chain.get_header(block.header().parent_hash) {
            h.in_flight
        } else {
            trace!(
                block_hash = ?block_hash,
                "Skipping vote — parent pruned, still verifying for PreparedCommit"
            );
            return InFlightCheck::SkipVote;
        };

        let finalized_tx_count: u32 = chain
            .pending
            .get(&block_hash)
            .map(|p| {
                p.finalized_waves()
                    .iter()
                    .map(|fw| fw.tx_count() as u32)
                    .sum()
            })
            .unwrap_or(0);

        if self.verify_in_flight(block_hash, block, parent_in_flight, finalized_tx_count) {
            InFlightCheck::Proceed
        } else {
            InFlightCheck::Abort
        }
    }

    /// Verify the proposed in-flight count is deterministically correct.
    ///
    /// in_flight = parent.in_flight + new_txs - finalized_txs
    ///
    /// All validators can compute this from chain state, so it must be exact.
    /// Certificates are only counted when actually included (JMT was ready).
    pub fn verify_in_flight(
        &mut self,
        block_hash: BlockHash,
        block: &Block,
        parent_in_flight: u32,
        finalized_tx_count: u32,
    ) -> bool {
        let proposed = block.header().in_flight;

        // Compute expected: only subtract finalized txs when certs are actually included.
        let certs_finalized = if block.certificates().is_empty() {
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
                height = block.height().0,
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
    /// Each drained entry is enriched at drain time (not when it was queued)
    /// with a fresh `parent_state_root` and `finalized_waves` snapshot.
    /// Capturing these eagerly produced a stale-snapshot race: an entry
    /// deferred before its parent committed would still hold the
    /// pre-commit `parent_state_root`, causing the dispatched verification
    /// to compute against the grandparent's base state.
    pub(crate) fn drain_ready_state_root_verifications(
        &mut self,
        chain: &ChainView<'_>,
    ) -> Vec<ReadyStateRootVerification> {
        std::mem::take(&mut self.ready_state_root_verifications)
            .into_iter()
            .map(|pending| {
                let parent_state_root = chain.parent_state_root(pending.parent_block_hash);
                let finalized_waves = chain
                    .pending
                    .get(&pending.block_hash)
                    .and_then(|pb| pb.block())
                    .map(|b| b.certificates().to_vec())
                    .unwrap_or_default();
                ReadyStateRootVerification {
                    block_hash: pending.block_hash,
                    parent_block_hash: pending.parent_block_hash,
                    parent_state_root,
                    parent_block_height: pending.parent_block_height,
                    expected_root: pending.expected_root,
                    finalized_waves,
                    block_height: pending.block_height,
                }
            })
            .collect()
    }

    /// Check whether a deferred proposal was unblocked and should be retried.
    /// Returns `true` once, then resets. The caller emits `ContentAvailable`
    /// to re-enter `try_propose` with fresh transaction selection.
    pub fn take_ready_proposal(&mut self) -> bool {
        std::mem::take(&mut self.proposal_unblocked)
    }

    /// Check if a parent's tree nodes are available (persisted or verified
    /// or consensus-committed — all three place the parent's JMT snapshot
    /// either on disk or in the `PendingChain` overlay).
    pub fn parent_tree_available(
        &self,
        parent_block_height: BlockHeight,
        parent_hash: BlockHash,
    ) -> bool {
        parent_block_height <= self.last_persisted_height
            || self.verified_state_roots.contains(&parent_hash)
    }

    /// Record that a proposal is deferred until the parent's tree nodes are
    /// available. Only the parent identity is stored — when unblocked, the
    /// caller re-enters `try_propose` with fresh state rather than replaying
    /// a stale `BuildProposal` action.
    pub fn defer_proposal(&mut self, parent_hash: BlockHash, parent_block_height: BlockHeight) {
        debug!(
            parent_hash = ?parent_hash,
            parent_block_height = parent_block_height.0,
            "Deferring proposal — parent tree not yet available"
        );
        self.deferred_proposal = Some((parent_hash, parent_block_height));
    }

    /// If the deferred proposal was waiting for `unblocked_hash`, mark it ready.
    fn try_unblock_proposal(&mut self, unblocked_hash: BlockHash) {
        if matches!(&self.deferred_proposal, Some((parent, _)) if *parent == unblocked_hash) {
            self.deferred_proposal.take();
            debug!(parent_hash = ?unblocked_hash, "Unblocking deferred proposal");
            self.proposal_unblocked = true;
        }
    }

    /// A block's state is now persisted to disk. Advances
    /// `last_persisted_height` and unblocks any deferred verifications
    /// or proposals whose parent is at or below the new persisted tip.
    ///
    /// This is the persistence-catch-up path — mainly relevant on boot
    /// (parent on disk but never locally verified in this process) and
    /// as a safety net if the consensus-commit path didn't fire for
    /// some reason. Steady-state unblocking happens via
    /// [`Self::on_block_committed`].
    pub fn on_block_persisted(&mut self, block_height: BlockHeight) {
        if block_height <= self.last_persisted_height {
            return;
        }
        self.last_persisted_height = block_height;

        // Unblock deferred verifications whose parent height is now persisted.
        let unblocked_parents: Vec<BlockHash> = self
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

        // Unblock deferred proposal if its parent height is now persisted.
        if let Some((_, parent_block_height)) = &self.deferred_proposal {
            if *parent_block_height <= block_height {
                self.deferred_proposal.take();
                debug!("Unblocking deferred proposal — parent persisted");
                self.proposal_unblocked = true;
            }
        }
    }

    /// A block has been committed by consensus (QC). Its JMT snapshot is
    /// in `PendingChain` — either from a completed local `VerifyStateRoot`
    /// or from the `CommitBlockByQcOnly` inline computation. Mark its
    /// state root as available for child verifications and unblock any
    /// deferred children or proposals waiting on this block.
    ///
    /// Unblocking on commit (rather than persistence) lets deferred
    /// verifications proceed as soon as the parent's tree is readable from
    /// the overlay, without waiting for `BlockPersisted`.
    pub fn on_block_committed(&mut self, block_hash: BlockHash) {
        if !self.verified_state_roots.insert(block_hash) {
            return;
        }

        if let Some(deferred) = self.deferred_state_root_verifications.remove(&block_hash) {
            for ready in deferred {
                debug!(
                    child = ?ready.block_hash,
                    parent = ?block_hash,
                    "Unblocking deferred state root verification (parent committed)"
                );
                self.state_root_verifications_in_flight
                    .insert(ready.block_hash);
                self.ready_state_root_verifications.push(ready);
            }
        }

        self.try_unblock_proposal(block_hash);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Cleanup
    // ═══════════════════════════════════════════════════════════════════════

    /// Remove verification state for blocks no longer in pending_blocks.
    ///
    /// Called by BftCoordinator::cleanup_old_state() after it has cleaned up
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
        pending_blocks: &HashMap<BlockHash, crate::pending::PendingBlock>,
        committed_height: BlockHeight,
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
        if let Some((_, parent_block_height)) = &self.deferred_proposal {
            if *parent_block_height <= committed_height {
                self.deferred_proposal = None;
            }
        }

        self.in_flight_roots
            .retain(|(hash, _)| pending_blocks.contains_key(hash));
        self.verified_roots
            .retain(|(hash, _)| pending_blocks.contains_key(hash));

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pending::PendingBlock;
    use hyperscale_types::{
        CertificateRoot, LocalReceiptRoot, ProposerTimestamp, QuorumCertificate, Round,
        RoutableTransaction, ShardGroupId, TransactionRoot, ValidatorId,
    };
    use std::collections::BTreeMap;
    use std::time::Duration;

    fn header(height: BlockHeight, parent_hash: BlockHash, in_flight: u32) -> BlockHeader {
        BlockHeader {
            shard_group_id: ShardGroupId(0),
            height,
            parent_hash,
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
            in_flight,
        }
    }

    fn block_with(
        height: BlockHeight,
        parent_hash: BlockHash,
        in_flight: u32,
        transactions: Vec<Arc<RoutableTransaction>>,
    ) -> Block {
        Block::Live {
            header: header(height, parent_hash, in_flight),
            transactions,
            certificates: Vec::new(),
            provisions: Vec::new(),
        }
    }

    fn chain_view<'a>(
        committed_height: BlockHeight,
        committed_hash: BlockHash,
        latest_qc: Option<&'a QuorumCertificate>,
        certified: &'a HashMap<BlockHash, Block>,
        pending: &'a HashMap<BlockHash, PendingBlock>,
    ) -> ChainView<'a> {
        ChainView {
            committed_height,
            committed_hash,
            committed_state_root: StateRoot::ZERO,
            latest_qc,
            genesis: None,
            certified,
            pending,
        }
    }

    fn bh(tag: &[u8]) -> BlockHash {
        BlockHash::from_raw(Hash::from_bytes(tag))
    }

    // ─── classify_vote_in_flight ────────────────────────────────────────

    #[test]
    fn classify_vote_in_flight_skips_vote_when_locked() {
        let mut vp = VerificationPipeline::new(BlockHeight::GENESIS);
        let block = block_with(BlockHeight(1), BlockHash::ZERO, 0, vec![]);
        let block_hash = block.hash();
        let certified = HashMap::new();
        let pending = HashMap::new();
        let chain = chain_view(
            BlockHeight::GENESIS,
            BlockHash::ZERO,
            None,
            &certified,
            &pending,
        );

        let out = vp.classify_vote_in_flight(&chain, block_hash, &block, true);
        assert!(matches!(out, InFlightCheck::SkipVote));
    }

    #[test]
    fn classify_vote_in_flight_skips_vote_when_parent_pruned() {
        // Non-genesis parent QC that isn't in the chain view: parent is
        // effectively pruned, so we skip voting but still keep verifying.
        let mut vp = VerificationPipeline::new(BlockHeight::GENESIS);
        let parent = bh(b"parent");
        let mut h = header(BlockHeight(5), parent, 0);
        let mut parent_qc = QuorumCertificate::genesis();
        parent_qc.height = BlockHeight(4);
        parent_qc.block_hash = parent;
        h.parent_qc = parent_qc;
        let block = Block::Live {
            header: h,
            transactions: Vec::new(),
            certificates: Vec::new(),
            provisions: Vec::new(),
        };
        let block_hash = block.hash();
        let certified = HashMap::new();
        let pending = HashMap::new();
        let chain = chain_view(BlockHeight(3), BlockHash::ZERO, None, &certified, &pending);

        let out = vp.classify_vote_in_flight(&chain, block_hash, &block, false);
        assert!(matches!(out, InFlightCheck::SkipVote));
    }

    #[test]
    fn classify_vote_in_flight_proceeds_when_genesis_parent_and_counts_match() {
        let mut vp = VerificationPipeline::new(BlockHeight::GENESIS);
        let block = block_with(BlockHeight(1), BlockHash::ZERO, 0, vec![]);
        let block_hash = block.hash();
        let certified = HashMap::new();
        let pending = HashMap::new();
        let chain = chain_view(
            BlockHeight::GENESIS,
            BlockHash::ZERO,
            None,
            &certified,
            &pending,
        );

        let out = vp.classify_vote_in_flight(&chain, block_hash, &block, false);
        assert!(matches!(out, InFlightCheck::Proceed));
    }

    #[test]
    fn classify_vote_in_flight_aborts_on_in_flight_mismatch() {
        // Genesis parent → parent_in_flight = 0. Block claims in_flight = 5
        // with 0 transactions: proposed doesn't match expected → Abort.
        let mut vp = VerificationPipeline::new(BlockHeight::GENESIS);
        let block = block_with(BlockHeight(1), BlockHash::ZERO, 5, vec![]);
        let block_hash = block.hash();
        let certified = HashMap::new();
        let pending = HashMap::new();
        let chain = chain_view(
            BlockHeight::GENESIS,
            BlockHash::ZERO,
            None,
            &certified,
            &pending,
        );

        let out = vp.classify_vote_in_flight(&chain, block_hash, &block, false);
        assert!(matches!(out, InFlightCheck::Abort));
    }

    // ─── drain_ready_state_root_verifications ───────────────────────────

    #[test]
    fn drain_ready_state_root_verifications_returns_empty_when_nothing_ready() {
        let mut vp = VerificationPipeline::new(BlockHeight::GENESIS);
        let certified = HashMap::new();
        let pending = HashMap::new();
        let chain = chain_view(
            BlockHeight::GENESIS,
            BlockHash::ZERO,
            None,
            &certified,
            &pending,
        );

        let out = vp.drain_ready_state_root_verifications(&chain);
        assert!(out.is_empty());
    }

    #[test]
    fn drain_ready_state_root_verifications_enriches_from_chain_view() {
        // Parent is at GENESIS height ≤ last_persisted_height, so initiate
        // queues this entry directly into ready_state_root_verifications.
        let mut vp = VerificationPipeline::new(BlockHeight::GENESIS);
        let parent_hash = bh(b"parent");
        let block = block_with(BlockHeight(1), parent_hash, 0, vec![]);
        let block_hash = block.hash();

        vp.initiate_state_root_verification(block_hash, &block, BlockHeight::GENESIS);

        let pb = PendingBlock::from_complete_block(&block, vec![], vec![], Duration::ZERO);
        let mut pending_with_block = HashMap::new();
        pending_with_block.insert(block_hash, pb);
        let certified = HashMap::new();
        let chain = chain_view(
            BlockHeight::GENESIS,
            BlockHash::ZERO,
            None,
            &certified,
            &pending_with_block,
        );

        let out = vp.drain_ready_state_root_verifications(&chain);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].block_hash, block_hash);
        assert_eq!(out[0].parent_block_hash, parent_hash);
        assert_eq!(out[0].parent_block_height, BlockHeight::GENESIS);

        // Draining again without another initiate yields nothing.
        let empty_pending: HashMap<BlockHash, PendingBlock> = HashMap::new();
        let chain2 = chain_view(
            BlockHeight::GENESIS,
            BlockHash::ZERO,
            None,
            &certified,
            &empty_pending,
        );
        assert!(vp.drain_ready_state_root_verifications(&chain2).is_empty());
    }
}
