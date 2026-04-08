//! Async verification pipeline for block voting.
//!
//! Tracks QC signature, state root, transaction root, and receipt root
//! verifications. BftState delegates verification bookkeeping here while
//! retaining control-flow decisions (voting, block rejection).

use hyperscale_types::{
    AbortIntent, AbortReason, Block, BlockHeader, BlockHeight, CommittedBlockHeader, Hash,
    ReceiptBundle, ShardGroupId,
};
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
    /// Wave ID hashes — the node state machine uses these to look up FinalizedWaves.
    wave_id_hashes: Vec<Hash>,
    /// Block height (used as JVT version).
    block_height: u64,
}

/// State root verification that is ready to dispatch (JVT is at the correct root).
///
/// The `NodeStateMachine` drains these after each BFT call, attaches the
/// `Arc<FinalizedWave>` data from execution state, and emits `VerifyStateRoot` actions.
#[derive(Debug)]
pub struct ReadyStateRootVerification {
    pub block_hash: Hash,
    pub parent_state_root: Hash,
    pub expected_root: Hash,
    /// Wave ID hashes for this block's certificates — the node state machine
    /// uses these to look up the corresponding `Arc<FinalizedWave>` from execution state.
    pub wave_id_hashes: Vec<Hash>,
    pub block_height: u64,
}

/// Abort intent verification waiting for remote headers to arrive.
///
/// When a block has livelock cycle abort intents but the remote committed
/// header for the source shard/height hasn't been received yet, the
/// verification is parked here. Once `on_remote_header_arrived` is called
/// with the matching key, the verification is unblocked and dispatched.
#[derive(Debug, Clone)]
struct PendingAbortIntentVerification {
    /// The livelock cycle abort intents that need proof verification.
    livelock_intents: Vec<AbortIntent>,
    /// Proof inputs already resolved (intent, transaction_root).
    resolved: Vec<(AbortIntent, Hash)>,
    /// Remote header keys still needed before dispatch.
    waiting_on: HashSet<(ShardGroupId, BlockHeight)>,
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

    // === Abort intent proof verification ===
    /// Blocks where abort intent proof verification is currently in-flight.
    abort_intent_verifications_in_flight: HashSet<Hash>,

    /// Blocks with verified abort intent proofs.
    verified_abort_intents: HashSet<Hash>,

    /// Abort intent verifications waiting for remote headers.
    /// Keyed by block_hash. Unblocked by `on_remote_header_arrived`.
    pending_abort_intent_verifications: HashMap<Hash, PendingAbortIntentVerification>,
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
            certificate_root_verifications_in_flight: HashSet::new(),
            verified_certificate_roots: HashSet::new(),
            local_receipt_root_verifications_in_flight: HashSet::new(),
            verified_local_receipt_roots: HashSet::new(),
            abort_intent_verifications_in_flight: HashSet::new(),
            verified_abort_intents: HashSet::new(),
            pending_abort_intent_verifications: HashMap::new(),
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

        let abort_intents_ok = if !Self::has_livelock_abort_intents(block) {
            true
        } else {
            self.verified_abort_intents.contains(&block_hash)
        };

        state_root_ok
            && transaction_root_ok
            && certificate_root_ok
            && local_receipt_root_ok
            && abort_intents_ok
    }

    /// Log why a block's verification is incomplete. Called on view change
    /// to explain why the current block couldn't be voted on in time.
    pub fn log_incomplete_verification(&self, block: &Block) {
        let block_hash = block.hash();

        let state_root_status = if block.certificates.is_empty() {
            "skipped(no_certs)"
        } else if self.verified_state_roots.contains(&block_hash) {
            "verified"
        } else if self
            .state_root_verifications_in_flight
            .contains(&block_hash)
        {
            "in_flight"
        } else if self
            .pending_state_root_verifications
            .contains_key(&block_hash)
        {
            "pending_jvt"
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

        let abort_status = if !Self::has_livelock_abort_intents(block) {
            "skipped(no_livelock)"
        } else if self.verified_abort_intents.contains(&block_hash) {
            "verified"
        } else if self
            .abort_intent_verifications_in_flight
            .contains(&block_hash)
        {
            "in_flight"
        } else if self
            .pending_abort_intent_verifications
            .contains_key(&block_hash)
        {
            "pending_remote_headers"
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
            abort_intents = abort_status,
            "View change — block verification was incomplete"
        );
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

        // Collect wave_id hashes from the block's certificates. The node state
        // machine uses these to look up Arc<FinalizedWave> from execution state
        // when constructing the VerifyStateRoot action.
        let wave_id_hashes: Vec<Hash> = block
            .certificates
            .iter()
            .map(|c| c.wave_id.hash())
            .collect();

        if current_root == parent_state_root {
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
                    wave_id_hashes,
                    block_height: block.header.height.0,
                });
        } else {
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
                    wave_id_hashes,
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

    // ─── Abort intent proofs ────────────────────────────────────────────

    /// Check whether a block has any livelock cycle abort intents that require
    /// merkle inclusion proof verification.
    fn has_livelock_abort_intents(block: &Block) -> bool {
        block
            .abort_intents
            .iter()
            .any(|a| matches!(a.reason, AbortReason::LivelockCycle { .. }))
    }

    /// Check if a block needs abort intent proof verification before voting.
    pub fn needs_abort_intent_verification(&self, block: &Block) -> bool {
        if !Self::has_livelock_abort_intents(block) {
            return false;
        }

        let block_hash = block.hash();

        if self.verified_abort_intents.contains(&block_hash)
            || self
                .abort_intent_verifications_in_flight
                .contains(&block_hash)
        {
            return false;
        }

        true
    }

    /// Initiate abort intent proof verification for a block.
    ///
    /// Resolves remote header `transaction_root` values from `remote_headers`.
    /// If all headers are available, emits `Action::VerifyAbortIntentProofs`
    /// immediately. If any are missing, parks the verification in
    /// `pending_abort_intent_verifications` until `on_remote_header_arrived`
    /// supplies the missing header.
    pub fn initiate_abort_intent_verification(
        &mut self,
        block_hash: Hash,
        block: &Block,
        remote_headers: &HashMap<(ShardGroupId, BlockHeight), Arc<CommittedBlockHeader>>,
    ) -> Vec<Action> {
        let livelock_intents: Vec<AbortIntent> = block
            .abort_intents
            .iter()
            .filter(|a| matches!(a.reason, AbortReason::LivelockCycle { .. }))
            .cloned()
            .collect();

        if livelock_intents.is_empty() {
            return vec![];
        }

        debug!(
            block_hash = ?block_hash,
            intent_count = livelock_intents.len(),
            "Initiating abort intent proof verification"
        );

        self.try_resolve_abort_intents(block_hash, livelock_intents, remote_headers)
    }

    /// Try to resolve all livelock abort intents against available remote headers.
    ///
    /// Returns `Action::VerifyAbortIntentProofs` if all headers are present,
    /// otherwise parks in `pending_abort_intent_verifications`.
    fn try_resolve_abort_intents(
        &mut self,
        block_hash: Hash,
        intents: Vec<AbortIntent>,
        remote_headers: &HashMap<(ShardGroupId, BlockHeight), Arc<CommittedBlockHeader>>,
    ) -> Vec<Action> {
        let mut resolved = Vec::new();
        let mut waiting_on = HashSet::new();

        for intent in &intents {
            if let AbortReason::LivelockCycle {
                source_shard,
                source_block_height,
                ..
            } = &intent.reason
            {
                let key = (*source_shard, *source_block_height);
                if let Some(header) = remote_headers.get(&key) {
                    resolved.push((intent.clone(), header.header.transaction_root));
                } else {
                    waiting_on.insert(key);
                }
            }
        }

        if waiting_on.is_empty() {
            // All headers available — dispatch immediately.
            self.abort_intent_verifications_in_flight.insert(block_hash);
            vec![Action::VerifyAbortIntentProofs {
                block_hash,
                proof_inputs: resolved,
            }]
        } else {
            // Park until missing headers arrive.
            debug!(
                block_hash = ?block_hash,
                missing = waiting_on.len(),
                "Abort intent verification waiting for remote headers"
            );
            self.pending_abort_intent_verifications.insert(
                block_hash,
                PendingAbortIntentVerification {
                    livelock_intents: intents,
                    resolved,
                    waiting_on,
                },
            );
            vec![]
        }
    }

    /// A remote header has arrived — unblock any pending abort intent verifications
    /// that were waiting for it.
    pub fn on_remote_header_arrived(
        &mut self,
        shard: ShardGroupId,
        height: BlockHeight,
        header: &CommittedBlockHeader,
    ) -> Vec<Action> {
        let key = (shard, height);
        let transaction_root = header.header.transaction_root;

        // Find all pending verifications waiting on this key.
        let unblocked: Vec<Hash> = self
            .pending_abort_intent_verifications
            .iter()
            .filter(|(_, pv)| pv.waiting_on.contains(&key))
            .map(|(block_hash, _)| *block_hash)
            .collect();

        if unblocked.is_empty() {
            return vec![];
        }

        let mut actions = Vec::new();

        for block_hash in unblocked {
            let pv = self
                .pending_abort_intent_verifications
                .get_mut(&block_hash)
                .unwrap();

            // Resolve the intents that were waiting on this header.
            for intent in &pv.livelock_intents {
                if let AbortReason::LivelockCycle {
                    source_shard,
                    source_block_height,
                    ..
                } = &intent.reason
                {
                    if (*source_shard, *source_block_height) == key {
                        pv.resolved.push((intent.clone(), transaction_root));
                    }
                }
            }
            pv.waiting_on.remove(&key);

            if pv.waiting_on.is_empty() {
                // Fully resolved — dispatch.
                let pv = self
                    .pending_abort_intent_verifications
                    .remove(&block_hash)
                    .unwrap();
                self.abort_intent_verifications_in_flight.insert(block_hash);
                debug!(
                    block_hash = ?block_hash,
                    "Abort intent verification unblocked by remote header"
                );
                actions.push(Action::VerifyAbortIntentProofs {
                    block_hash,
                    proof_inputs: pv.resolved,
                });
            }
        }

        actions
    }

    /// Record an abort intent proof verification result.
    /// Returns whether the verification passed.
    pub fn on_abort_intents_verified(&mut self, block_hash: Hash, valid: bool) -> bool {
        self.abort_intent_verifications_in_flight
            .remove(&block_hash);

        if valid {
            self.verified_abort_intents.insert(block_hash);
            debug!(
                block_hash = ?block_hash,
                "Abort intent proofs verified successfully"
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
                        wave_id_hashes: pv.wave_id_hashes,
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

        self.certificate_root_verifications_in_flight
            .retain(|hash| pending_blocks.contains_key(hash));

        self.verified_certificate_roots
            .retain(|hash| pending_blocks.contains_key(hash));

        self.local_receipt_root_verifications_in_flight
            .retain(|hash| pending_blocks.contains_key(hash));

        self.verified_local_receipt_roots
            .retain(|hash| pending_blocks.contains_key(hash));

        self.abort_intent_verifications_in_flight
            .retain(|hash| pending_blocks.contains_key(hash));

        self.verified_abort_intents
            .retain(|hash| pending_blocks.contains_key(hash));

        self.pending_abort_intent_verifications
            .retain(|hash, _| pending_blocks.contains_key(hash));

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
