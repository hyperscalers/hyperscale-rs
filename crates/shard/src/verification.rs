//! Async verification pipeline for block voting.
//!
//! Tracks QC signature, state root, transaction root, and receipt root
//! verifications. `ShardCoordinator` delegates verification bookkeeping here while
//! retaining control-flow decisions (voting, block rejection).
//!
//! Pure pre-vote validation helpers (header structure, timestamp bounds,
//! transaction ordering, `waves` recomputation, cross-ancestor tx uniqueness)
//! live in [`crate::validation`].

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use hyperscale_core::Action;
#[cfg(test)]
use hyperscale_types::BeaconWitnessLeafCount;
use hyperscale_types::{
    BeaconWitnessRoot, Block, BlockHash, BlockHeader, BlockHeight, BlockManifest, CertificateRoot,
    CertifiedBlock, FinalizedWave, InFlightCount, LinkageError, LocalReceiptRoot,
    ProvisionTxRootsMap, ProvisionsRoot, QuorumCertificate, StateRoot, TopologySnapshot,
    TransactionRoot, Verified, VerifiedBlockAssembleError,
};
use thiserror::Error;
use tracing::{debug, trace, warn};

use crate::beacon_witnesses::{BeaconWitnessAccumulator, prospective_parent_witness_leaves};
use crate::chain_view::ChainView;
use crate::pending::{PendingBlock, PendingBlocks};

/// Discriminant for the verification pipeline's per-root bookkeeping
/// (in-flight set, verified set, parametric helpers). The corresponding
/// `ProtocolEvent::*Verified` variants are the per-kind result events;
/// the coordinator's per-kind public methods thread the matching kind
/// here for the shared completion logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerificationKind {
    /// State root computed by replaying the block's database updates against the JMT.
    StateRoot,
    /// Merkle root over the block's transactions plus per-tx validity-window check.
    TransactionRoot,
    /// Merkle root over included wave certificates' receipt hashes.
    CertificateRoot,
    /// Merkle root over the block's local receipts.
    LocalReceiptRoot,
    /// Merkle root over the block's provision-batch hashes.
    ProvisionRoot,
    /// Per-target-shard provision-tx merkle roots map.
    ProvisionTxRoots,
    /// Merkle root over the per-shard beacon-witness accumulator after this
    /// block's appended leaves.
    BeaconWitnessRoot,
}

/// Lifecycle position for a verification entry. `InFlight` covers the
/// window between dispatch and result; `Verified` is the terminal-success
/// stage. Failure removes the entry (returning to "not tracked"), so the
/// stage stays a closed pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RootStage {
    /// Verification has been dispatched but not yet completed.
    InFlight,
    /// Verification completed successfully.
    Verified,
}

/// Block header pending QC signature verification.
///
/// When we receive a block header with a non-genesis `parent_qc`, we need to
/// verify the QC's aggregated BLS signature before voting. This struct
/// tracks the block header while waiting for verification.
#[derive(Debug, Clone)]
pub struct PendingQcVerification {
    /// The block header we're considering voting on.
    pub header: BlockHeader,
}

/// State root verification that is ready to dispatch (JMT is at the correct root).
///
/// The `NodeStateMachine` drains these after each shard consensus call and emits
/// `VerifyStateRoot` actions. `parent_state_root` and `finalized_waves` are
/// resolved at drain time from the current chain/pending-block state, not
/// captured at `initiate_state_root_verification` time — capturing at initiate
/// time produced a stale-snapshot race where an entry deferred before its
/// parent committed would dispatch with the wrong `parent_state_root`.
///
/// Carries `expected_local_receipt_root` so the verifier runs receipt-root
/// validation as a pre-flight before the JMT computation: if the receipts
/// don't reproduce the QC'd `local_receipt_root`, the JMT recomputation
/// can't match `state_root` either (receipts ARE the JMT input), so the
/// handler short-circuits and emits both root events with `valid=false`.
#[derive(Debug)]
pub struct ReadyStateRootVerification {
    /// Block whose state and receipt roots are being verified.
    pub block_hash: BlockHash,
    /// Parent block hash; the JMT computation chains on top of this parent's snapshot.
    pub parent_block_hash: BlockHash,
    /// State root at the parent block, anchoring the JMT computation.
    pub parent_state_root: StateRoot,
    /// The committed height of the parent block (stable anchor for JMT computation).
    pub parent_block_height: BlockHeight,
    /// State root the proposer claimed; the verifier rejects on mismatch.
    pub expected_root: StateRoot,
    /// Local-receipt root from the block header (pre-flight check).
    pub expected_local_receipt_root: LocalReceiptRoot,
    /// Finalized waves from the `PendingBlock` — these carry the proposer's receipts,
    /// ensuring all validators verify against the same execution outputs.
    pub finalized_waves: Vec<Arc<Verified<FinalizedWave>>>,
    /// Height of the block being verified.
    pub block_height: BlockHeight,
}

/// Classification of the in-flight check outcome for the vote path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InFlightCheck {
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
pub struct PendingStateRootVerification {
    pub block_hash: BlockHash,
    pub parent_block_hash: BlockHash,
    pub parent_block_height: BlockHeight,
    pub expected_root: StateRoot,
    pub expected_local_receipt_root: LocalReceiptRoot,
    pub block_height: BlockHeight,
}

/// Why [`VerificationPipeline::try_complete_assembly`] rejected the
/// completed slot set. All variants are defensive — a coordinator bug
/// is the only way any of them is reachable at runtime.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum AssemblyError {
    /// [`Verified::<Block>::assemble`] rejected the (block, header) pair.
    /// Structurally impossible: `block.hash()` is defined as
    /// `block.header().hash()`, so they always agree on a well-formed
    /// `Block`.
    #[error(transparent)]
    Block(VerifiedBlockAssembleError),
    /// [`Verified::<CertifiedBlock>::assemble`] rejected the (block, qc)
    /// pair. Structurally impossible: the QC was associated with this
    /// block's hash via the slot-keying invariant of `record_qc_assembly`.
    #[error(transparent)]
    Linkage(LinkageError),
    /// The header's `parent_qc` had no entry in `verified_qcs` at
    /// assembly time. Structurally impossible: per-root dispatch is
    /// gated on `try_vote_on_block`, which only runs after
    /// `on_qc_signature_verified` cached the parent QC.
    #[error("parent QC not verified at assembly time")]
    ParentQcUnverified,
    /// The cached `Verified<QuorumCertificate>` differed from the
    /// header's claimed `parent_qc`. Structurally impossible: the
    /// cache is keyed by `qc.block_hash` and the
    /// `absorb_parent_qc_from_header` cache lookup already enforces
    /// byte-equality before treating an entry as a hit.
    #[error("parent QC byte-mismatch against verified cache")]
    ParentQcMismatch,
}

/// A block awaiting the sub-results required to produce a
/// [`Verified<CertifiedBlock>`]: a verified QC paired with the block, plus
/// per-root verification outcomes for the block's internal commitments.
///
/// Each per-root slot is `Some(value)` either because the verification
/// succeeded (carrying the typed verified value) or because the block
/// carries no relevant content for that root (skip case, prefilled by
/// [`VerificationPipeline::track_pending_assembly`] with
/// `new_unchecked(header.x_root())` — the empty-input compute is
/// trivially equal to the header's claim). A slot is `None` only while
/// the verification is outstanding. The assembly is complete when every
/// slot is `Some`; on completion the pipeline's per-root and per-QC
/// setters return the linked block.
#[derive(Debug)]
pub struct PendingAssembly {
    /// Block whose commitments are being verified.
    pub block: Arc<Block>,
    /// Verified QC for [`Self::block`], populated when QC signature
    /// verification completes.
    pub qc_result: Option<Verified<QuorumCertificate>>,
    /// Transaction-root verification outcome.
    pub tx_root_result: Option<Verified<TransactionRoot>>,
    /// Certificate-root verification outcome.
    pub certificate_root_result: Option<Verified<CertificateRoot>>,
    /// Local-receipt-root verification outcome.
    pub local_receipt_root_result: Option<Verified<LocalReceiptRoot>>,
    /// Provisions-root verification outcome.
    pub provision_root_result: Option<Verified<ProvisionsRoot>>,
    /// Provision-tx-roots map verification outcome.
    pub provision_tx_roots_result: Option<Verified<ProvisionTxRootsMap>>,
    /// Beacon-witness-root verification outcome.
    pub beacon_witness_root_result: Option<Verified<BeaconWitnessRoot>>,
    /// State-root verification outcome.
    pub state_root_result: Option<Verified<StateRoot>>,
}

impl PendingAssembly {
    /// Every required sub-result is present.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.qc_result.is_some()
            && self.tx_root_result.is_some()
            && self.certificate_root_result.is_some()
            && self.local_receipt_root_result.is_some()
            && self.provision_root_result.is_some()
            && self.provision_tx_roots_result.is_some()
            && self.beacon_witness_root_result.is_some()
            && self.state_root_result.is_some()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// VerificationPipeline
// ═══════════════════════════════════════════════════════════════════════════

/// Tracks all async verification state for block voting.
///
/// `ShardCoordinator` owns this as a field and delegates verification bookkeeping
/// to it. Control-flow decisions (vote, reject block) remain in `ShardCoordinator`.
pub struct VerificationPipeline {
    // === QC signature verification ===
    /// Block headers pending QC signature verification.
    /// Maps `block_hash` -> pending verification info.
    pending_qc_verifications: HashMap<BlockHash, PendingQcVerification>,

    /// Cache of already-verified QCs, keyed by the QC's `block_hash` (the
    /// block the QC certifies). Stores the full canonical QC so cache hits
    /// can confirm the candidate QC is byte-equal to the verified one before
    /// skipping BLS verification — without this, a Byzantine peer could
    /// reuse a known-cached `block_hash` while fabricating `signers`,
    /// `round`, or `parent_block_hash` and have those fields adopted into
    /// `latest_qc` / drive view sync without re-verification.
    verified_qcs: HashMap<BlockHash, Verified<QuorumCertificate>>,

    // === State root verification ===
    /// State-root verification stage per block. Entries appear when the
    /// verification is queued or completes; absence means "not tracked"
    /// (either never started or failed).
    state_roots: HashMap<BlockHash, RootStage>,

    /// Blocks waiting for their parent's tree nodes to become available (via
    /// commit or prior verification). Keyed by `parent_block_hash`.
    deferred_state_root_verifications: HashMap<BlockHash, Vec<PendingStateRootVerification>>,

    /// Deferred proposal waiting for the parent's tree nodes to become
    /// available. At most one pending at a time (new proposals replace old).
    /// Stores `(parent_block_hash, parent_block_height)` for unblocking.
    /// When unblocked, we re-enter `try_propose` via the proposal-retry latch
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
    /// Drained by `NodeStateMachine` which emits `VerifyStateRoot` actions.
    /// The dispatched handler runs against a `SubstateView` anchored at
    /// the parent block, which sees prior unpersisted JMT snapshots so
    /// verification can chain from prior results without waiting for
    /// actual JMT commits.
    ready_state_root_verifications: Vec<PendingStateRootVerification>,

    /// Set when a deferred proposal's parent tree became available.
    /// Consumed by `take_ready_proposal`, which the state machine drains post-dispatch
    /// to re-enter `try_propose` with fresh transaction selection.
    proposal_unblocked: bool,

    // === Per-root merkle verification ===
    /// Verification stage per `(block_hash, kind)` (transaction,
    /// certificate, local-receipt, provision, provision-tx, beacon-
    /// witness). State-root rides [`Self::state_roots`] above because
    /// its lifecycle includes deferred/ready queues for parent-tree
    /// availability.
    roots: HashMap<(BlockHash, VerificationKind), RootStage>,

    /// Beacon-witness verifications waiting for a missing/unassembled
    /// ancestor to become available. Keyed by the blocking ancestor's
    /// hash; values are the deferred child block hashes. A retry runs
    /// when [`Self::take_deferred_beacon_witness_children`] is drained
    /// after the ancestor's beacon-witness verification completes (or
    /// when the ancestor commits past `committed_hash`, see
    /// [`Self::take_committed_beacon_witness_children`]).
    deferred_beacon_witness_verifications: HashMap<BlockHash, Vec<BlockHash>>,

    // === In-flight count verification ===
    /// Blocks with verified in-flight counts (synchronous tolerance check).
    verified_in_flight: HashSet<BlockHash>,

    // === Composite assembly ===
    /// Blocks awaiting all sub-results required to produce a
    /// [`Verified<CertifiedBlock>`]. Keyed by `block.hash()`. Entries are
    /// inserted via [`Self::track_pending_assembly`] and removed when the
    /// completion check fires inside [`Self::record_qc_assembly`].
    pending_assemblies: HashMap<BlockHash, PendingAssembly>,

    /// Fully-assembled `Verified<CertifiedBlock>` handles keyed by
    /// `block.hash()`. Populated when [`Self::try_complete_assembly`]
    /// finishes; consumed by the commit path via
    /// [`Self::take_verified_certified_block`] so the typed handle rides
    /// straight into `Action::CommitBlock` and `BlockCommitted` without
    /// being reconstructed.
    verified_certified_blocks: HashMap<BlockHash, Arc<Verified<CertifiedBlock>>>,
}

impl VerificationPipeline {
    /// Create a new verification pipeline.
    pub fn new(persisted_height: BlockHeight) -> Self {
        Self {
            pending_qc_verifications: HashMap::new(),
            verified_qcs: HashMap::new(),
            state_roots: HashMap::new(),
            deferred_state_root_verifications: HashMap::new(),
            deferred_proposal: None,
            ready_state_root_verifications: Vec::new(),
            proposal_unblocked: false,
            last_persisted_height: persisted_height,
            roots: HashMap::new(),
            deferred_beacon_witness_verifications: HashMap::new(),
            verified_in_flight: HashSet::new(),
            pending_assemblies: HashMap::new(),
            verified_certified_blocks: HashMap::new(),
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Per-root merkle state (shared helpers)
    // ═══════════════════════════════════════════════════════════════════════

    /// Whether the given merkle root has been verified for `block_hash`.
    /// State-root callers use [`Self::is_state_root_verified`] instead.
    fn is_root_verified(&self, block_hash: BlockHash, kind: VerificationKind) -> bool {
        matches!(
            self.roots.get(&(block_hash, kind)),
            Some(RootStage::Verified)
        )
    }

    /// Whether a merkle-root verification is currently in-flight for
    /// `(block_hash, kind)`.
    fn is_root_in_flight(&self, block_hash: BlockHash, kind: VerificationKind) -> bool {
        matches!(
            self.roots.get(&(block_hash, kind)),
            Some(RootStage::InFlight)
        )
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
        self.roots.insert((block_hash, kind), RootStage::InFlight);
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
        if valid {
            self.roots.insert((block_hash, kind), RootStage::Verified);
            debug!(?kind, ?block_hash, "Merkle root verified successfully");
        } else {
            self.roots.remove(&(block_hash, kind));
            if kind == VerificationKind::BeaconWitnessRoot {
                self.discard_deferred_beacon_witness_children(block_hash);
            }
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

    /// Look up the canonical verified QC for `qc_block_hash`. Returns `None`
    /// when no QC for that block has been verified yet. Callers MUST compare
    /// the candidate QC to the cached value byte-for-byte before treating it
    /// as a cache hit — see the field doc on [`Self::verified_qcs`].
    pub fn cached_qc(&self, qc_block_hash: &BlockHash) -> Option<&Verified<QuorumCertificate>> {
        self.verified_qcs.get(qc_block_hash)
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
    pub fn cache_verified_qc(&mut self, qc: Verified<QuorumCertificate>) {
        let qc_block_hash = qc.block_hash();
        let qc_height = qc.height();
        self.verified_qcs.insert(qc_block_hash, qc);
        trace!(
            qc_block_hash = ?qc_block_hash,
            qc_height = qc_height.inner(),
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

    // ═══════════════════════════════════════════════════════════════════════
    // Composite assembly
    // ═══════════════════════════════════════════════════════════════════════

    /// Start tracking `block` as awaiting the sub-results required for
    /// [`Verified<CertifiedBlock>`] assembly. The QC slot starts empty.
    /// Per-root slots reflect the current pipeline state:
    ///
    /// - if the block carries no relevant content for a kind, the slot
    ///   is prefilled with `VerifiedXRoot::new_unchecked(header.x_root())`
    ///   — for empty inputs the header's claimed root must equal the
    ///   empty-input compute, so the predicate is trivially satisfied;
    /// - if the verification has already completed (its `(block_hash,
    ///   kind)` entry in [`Self::roots`] is `RootStage::Verified`) the
    ///   slot is prefilled with the same `new_unchecked` wrap of the
    ///   header's claim — the verifier produced exactly that value on
    ///   success and that map entry is the audit source;
    /// - otherwise the slot starts `None` and lands via the matching
    ///   `record_<kind>_root_result` setter.
    pub fn track_pending_assembly(&mut self, block: Arc<Block>) {
        let block_hash = block.hash();
        let h = block.header();

        let tx_done = block.transaction_count() == 0
            || self.is_root_verified(block_hash, VerificationKind::TransactionRoot);
        let cert_done = block.certificates().is_empty()
            || self.is_root_verified(block_hash, VerificationKind::CertificateRoot);
        let receipt_done = block.certificates().is_empty()
            || self.is_root_verified(block_hash, VerificationKind::LocalReceiptRoot);
        let provision_done = h.provision_root() == ProvisionsRoot::ZERO
            || self.is_root_verified(block_hash, VerificationKind::ProvisionRoot);
        let provision_tx_done = h.provision_tx_roots().is_empty()
            || self.is_root_verified(block_hash, VerificationKind::ProvisionTxRoots);
        let beacon_done = self.is_root_verified(block_hash, VerificationKind::BeaconWitnessRoot);
        let state_done = self.is_state_root_verified(&block_hash);

        let tx_root_result = tx_done
            .then(|| Verified::<TransactionRoot>::from_pipeline_attestation(h.transaction_root()));
        let certificate_root_result = cert_done
            .then(|| Verified::<CertificateRoot>::from_pipeline_attestation(h.certificate_root()));
        let local_receipt_root_result = receipt_done.then(|| {
            Verified::<LocalReceiptRoot>::from_pipeline_attestation(h.local_receipt_root())
        });
        let provision_root_result = provision_done
            .then(|| Verified::<ProvisionsRoot>::from_pipeline_attestation(h.provision_root()));
        let provision_tx_roots_result = provision_tx_done.then(|| {
            Verified::<ProvisionTxRootsMap>::from_pipeline_attestation(
                h.provision_tx_roots().clone(),
            )
        });
        let beacon_witness_root_result = beacon_done.then(|| {
            Verified::<BeaconWitnessRoot>::from_pipeline_attestation(h.beacon_witness_root())
        });
        let state_root_result =
            state_done.then(|| Verified::<StateRoot>::from_pipeline_attestation(h.state_root()));

        self.pending_assemblies.insert(
            block_hash,
            PendingAssembly {
                qc_result: None,
                tx_root_result,
                certificate_root_result,
                local_receipt_root_result,
                provision_root_result,
                provision_tx_roots_result,
                beacon_witness_root_result,
                state_root_result,
                block,
            },
        );
    }

    /// Populate the QC slot for `block_hash`'s pending assembly. When the
    /// last outstanding slot lands as a result, the entry is removed and
    /// a [`Verified<CertifiedBlock>`] is produced by feeding the verified
    /// header + typed per-root witnesses into [`Verified::<Block>::assemble`]
    /// then linking the resulting verified block with the QC via
    /// [`Verified::<CertifiedBlock>::assemble`]. Returns `None` when no
    /// assembly is tracked for `block_hash`, or when more sub-results are
    /// still outstanding.
    pub fn record_qc_assembly(
        &mut self,
        block_hash: BlockHash,
        qc: Verified<QuorumCertificate>,
    ) -> Option<Result<Arc<Verified<CertifiedBlock>>, AssemblyError>> {
        let entry = self.pending_assemblies.get_mut(&block_hash)?;
        entry.qc_result = Some(qc);
        self.try_complete_assembly(block_hash)
    }

    /// Populate the transaction-root slot.
    pub fn record_transaction_root_result(
        &mut self,
        block_hash: BlockHash,
        verified: Verified<TransactionRoot>,
    ) -> Option<Result<Arc<Verified<CertifiedBlock>>, AssemblyError>> {
        let entry = self.pending_assemblies.get_mut(&block_hash)?;
        entry.tx_root_result = Some(verified);
        self.try_complete_assembly(block_hash)
    }

    /// Populate the certificate-root slot.
    pub fn record_certificate_root_result(
        &mut self,
        block_hash: BlockHash,
        verified: Verified<CertificateRoot>,
    ) -> Option<Result<Arc<Verified<CertifiedBlock>>, AssemblyError>> {
        let entry = self.pending_assemblies.get_mut(&block_hash)?;
        entry.certificate_root_result = Some(verified);
        self.try_complete_assembly(block_hash)
    }

    /// Populate the local-receipt-root slot.
    pub fn record_local_receipt_root_result(
        &mut self,
        block_hash: BlockHash,
        verified: Verified<LocalReceiptRoot>,
    ) -> Option<Result<Arc<Verified<CertifiedBlock>>, AssemblyError>> {
        let entry = self.pending_assemblies.get_mut(&block_hash)?;
        entry.local_receipt_root_result = Some(verified);
        self.try_complete_assembly(block_hash)
    }

    /// Populate the provisions-root slot.
    pub fn record_provisions_root_result(
        &mut self,
        block_hash: BlockHash,
        verified: Verified<ProvisionsRoot>,
    ) -> Option<Result<Arc<Verified<CertifiedBlock>>, AssemblyError>> {
        let entry = self.pending_assemblies.get_mut(&block_hash)?;
        entry.provision_root_result = Some(verified);
        self.try_complete_assembly(block_hash)
    }

    /// Populate the provision-tx-roots slot.
    pub fn record_provision_tx_roots_result(
        &mut self,
        block_hash: BlockHash,
        verified: Verified<ProvisionTxRootsMap>,
    ) -> Option<Result<Arc<Verified<CertifiedBlock>>, AssemblyError>> {
        let entry = self.pending_assemblies.get_mut(&block_hash)?;
        entry.provision_tx_roots_result = Some(verified);
        self.try_complete_assembly(block_hash)
    }

    /// Populate the beacon-witness-root slot.
    pub fn record_beacon_witness_root_result(
        &mut self,
        block_hash: BlockHash,
        verified: Verified<BeaconWitnessRoot>,
    ) -> Option<Result<Arc<Verified<CertifiedBlock>>, AssemblyError>> {
        let entry = self.pending_assemblies.get_mut(&block_hash)?;
        entry.beacon_witness_root_result = Some(verified);
        self.try_complete_assembly(block_hash)
    }

    /// Populate the state-root slot.
    pub fn record_state_root_result(
        &mut self,
        block_hash: BlockHash,
        verified: Verified<StateRoot>,
    ) -> Option<Result<Arc<Verified<CertifiedBlock>>, AssemblyError>> {
        let entry = self.pending_assemblies.get_mut(&block_hash)?;
        entry.state_root_result = Some(verified);
        self.try_complete_assembly(block_hash)
    }

    fn try_complete_assembly(
        &mut self,
        block_hash: BlockHash,
    ) -> Option<Result<Arc<Verified<CertifiedBlock>>, AssemblyError>> {
        if !self.pending_assemblies.get(&block_hash)?.is_complete() {
            return None;
        }
        let entry = self.pending_assemblies.remove(&block_hash)?;
        let block = Arc::try_unwrap(entry.block).unwrap_or_else(|arc| (*arc).clone());
        let qc = entry
            .qc_result
            .expect("completion check just confirmed qc_result is Some");
        let tx_root = entry
            .tx_root_result
            .expect("completion check just confirmed tx_root_result is Some");
        let certificate_root = entry
            .certificate_root_result
            .expect("completion check just confirmed certificate_root_result is Some");
        let local_receipt_root = entry
            .local_receipt_root_result
            .expect("completion check just confirmed local_receipt_root_result is Some");
        let provision_root = entry
            .provision_root_result
            .expect("completion check just confirmed provision_root_result is Some");
        let provision_tx_roots = entry
            .provision_tx_roots_result
            .expect("completion check just confirmed provision_tx_roots_result is Some");
        let beacon_witness_root = entry
            .beacon_witness_root_result
            .expect("completion check just confirmed beacon_witness_root_result is Some");

        let parent_qc_raw = block.header().parent_qc();
        let parent_qc_verified = if parent_qc_raw.is_genesis() {
            Verified::<QuorumCertificate>::genesis(parent_qc_raw.shard_group_id())
        } else {
            let Some(cached) = self.verified_qcs.get(&parent_qc_raw.block_hash()).cloned() else {
                warn!(
                    ?block_hash,
                    parent_qc_block_hash = ?parent_qc_raw.block_hash(),
                    "Verified parent_qc missing from cache at assembly time"
                );
                return Some(Err(AssemblyError::ParentQcUnverified));
            };
            cached
        };
        let Ok(verified_header) = Verified::<BlockHeader>::with_verified_parent_qc(
            block.header().clone(),
            parent_qc_verified,
        ) else {
            return Some(Err(AssemblyError::ParentQcMismatch));
        };

        let verified_block = match Verified::<Block>::assemble(
            block,
            verified_header,
            tx_root,
            certificate_root,
            local_receipt_root,
            provision_root,
            provision_tx_roots,
            beacon_witness_root,
        ) {
            Ok(v) => v,
            Err(e) => return Some(Err(AssemblyError::Block(e))),
        };

        match Verified::<CertifiedBlock>::assemble(verified_block, qc) {
            Ok(certified) => {
                let certified = Arc::new(certified);
                self.verified_certified_blocks
                    .insert(block_hash, Arc::clone(&certified));
                Some(Ok(certified))
            }
            Err(e) => Some(Err(AssemblyError::Linkage(e))),
        }
    }

    /// Borrow the assembled `Verified<CertifiedBlock>` for `block_hash`,
    /// if assembly has completed. The commit path Arc-clones from this
    /// borrow to thread the typed handle through
    /// [`Action::CommitBlock`](hyperscale_core::Action::CommitBlock).
    /// Entries are evicted from the cache by [`Self::cleanup`] once the
    /// block leaves `pending_blocks`, so callers don't need to take by
    /// value.
    pub fn cached_verified_certified_block(
        &self,
        block_hash: BlockHash,
    ) -> Option<&Arc<Verified<CertifiedBlock>>> {
        self.verified_certified_blocks.get(&block_hash)
    }

    /// Insert a `Verified<CertifiedBlock>` keyed by `block_hash`. Used
    /// by paths that produce the typed handle via
    /// [`Verified::<CertifiedBlock>::from_qc_attestation`] (sync, or
    /// aggregator-without-local-verification) rather than by full
    /// per-root assembly through [`Self::try_complete_assembly`].
    pub fn insert_verified_certified_block(
        &mut self,
        block_hash: BlockHash,
        certified: Arc<Verified<CertifiedBlock>>,
    ) {
        self.verified_certified_blocks.insert(block_hash, certified);
    }

    /// Number of in-flight composite assemblies.
    #[must_use]
    pub fn pending_assembly_count(&self) -> usize {
        self.pending_assemblies.len()
    }

    /// Whether any block verification is currently in-flight.
    ///
    /// Used by `should_advance_round` to suppress view changes while
    /// verification is running — the leader proposed, we received the block,
    /// the timeout should detect leader failure, not slow verification.
    pub fn has_verification_in_flight(&self) -> bool {
        self.state_roots
            .values()
            .any(|stage| *stage == RootStage::InFlight)
            || !self.deferred_state_root_verifications.is_empty()
            || !self.deferred_beacon_witness_verifications.is_empty()
            || self.deferred_proposal.is_some()
            || self
                .roots
                .values()
                .any(|stage| *stage == RootStage::InFlight)
            || !self.pending_qc_verifications.is_empty()
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Block verification (state root, tx root, receipt root)
    // ═══════════════════════════════════════════════════════════════════════

    /// Whether this node has verified the state root of a block itself
    /// (vs. trusting it purely via the QC chain).
    ///
    /// Used by the commit path to decide between `CommitBlock` (fast path —
    /// `PreparedCommit` from `VerifyStateRoot` already in the cache) and
    /// `CommitBlockByQcOnly` (slow path — compute inline at commit time).
    pub fn is_state_root_verified(&self, block_hash: &BlockHash) -> bool {
        matches!(self.state_roots.get(block_hash), Some(RootStage::Verified))
    }

    /// Whether state-root verification is currently in-flight for `block_hash`.
    fn is_state_root_in_flight(&self, block_hash: &BlockHash) -> bool {
        matches!(self.state_roots.get(block_hash), Some(RootStage::InFlight))
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

        self.is_state_root_verified(&block_hash)
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
                h.provision_root() != ProvisionsRoot::ZERO,
            )
            && root_ok(
                VerificationKind::ProvisionTxRoots,
                !h.provision_tx_roots().is_empty(),
            )
            && root_ok(VerificationKind::BeaconWitnessRoot, true)
            && self.verified_in_flight.contains(&block_hash)
    }

    /// Log why a block's verification is incomplete. Called on view change
    /// to explain why the current block couldn't be voted on in time.
    pub fn log_incomplete_verification(&self, block: &Block) {
        let block_hash = block.hash();
        let h = block.header();

        let state_root_status = if self.is_state_root_verified(&block_hash) {
            "verified"
        } else if self.is_state_root_in_flight(&block_hash) {
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
            h.provision_root() != ProvisionsRoot::ZERO,
        );
        let provision_tx_root_status = root_status(
            VerificationKind::ProvisionTxRoots,
            "skipped(no_provision_targets)",
            !h.provision_tx_roots().is_empty(),
        );
        let beacon_witness_root_status = if self.is_beacon_witness_deferred(block_hash) {
            "deferred(ancestor)"
        } else {
            root_status(VerificationKind::BeaconWitnessRoot, "skipped", true)
        };

        let in_flight_status = if self.verified_in_flight.contains(&block_hash) {
            "verified"
        } else {
            "NOT_STARTED"
        };

        warn!(
            block_hash = ?block_hash,
            height = block.height().inner(),
            proposer = ?block.header().proposer(),
            certs = block.certificates().len(),
            txs = block.transaction_count(),
            state_root = state_root_status,
            tx_root = tx_root_status,
            certificate_root = certificate_root_status,
            local_receipt_root = local_receipt_root_status,
            provision_root = provision_root_status,
            provision_tx_root = provision_tx_root_status,
            beacon_witness_root = beacon_witness_root_status,
            in_flight = in_flight_status,
            "View change — block verification was incomplete"
        );
    }

    // ─── State root ──────────────────────────────────────────────────────

    /// Check if a block needs state root verification before voting.
    ///
    /// Always returns true for blocks that haven't been verified yet —
    /// even cert-less blocks verify (trivially) so their `PreparedCommit`
    /// populates the overlay for child block verifications.
    pub fn needs_state_root_verification(&self, block: &Block) -> bool {
        let block_hash = block.hash();

        if self.state_roots.contains_key(&block_hash)
            || self
                .deferred_state_root_verifications
                .values()
                .any(|v| v.iter().any(|r| r.block_hash == block_hash))
        {
            return false;
        }

        true
    }

    /// Push a `PendingStateRootVerification` onto the ready queue and mark
    /// both state-root and receipt-root as in-flight. The receipt-root
    /// in-flight marker tracks the same dispatch lifecycle as state-root —
    /// the unified `VerifyStateRoot` handler emits both events.
    fn enqueue_ready_state_root(&mut self, ready: PendingStateRootVerification) {
        self.state_roots
            .insert(ready.block_hash, RootStage::InFlight);
        self.roots.insert(
            (ready.block_hash, VerificationKind::LocalReceiptRoot),
            RootStage::InFlight,
        );
        self.ready_state_root_verifications.push(ready);
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
        let parent_block_hash = block.header().parent_block_hash();
        let ready = PendingStateRootVerification {
            block_hash,
            parent_block_hash,
            parent_block_height,
            expected_root: block.header().state_root(),
            expected_local_receipt_root: block.header().local_receipt_root(),
            block_height: block.height(),
        };

        // The parent's tree nodes must be available — either committed to
        // the tree store or in the snapshot cache (from a prior verification).
        // Defer if: parent height exceeds committed JMT AND parent hasn't
        // been verified (no snapshot in the overlay).
        let parent_tree_available = parent_block_height <= self.last_persisted_height
            || self.is_state_root_verified(&parent_block_hash);

        if parent_tree_available {
            self.enqueue_ready_state_root(ready);
        } else {
            debug!(
                block_hash = ?block_hash,
                parent_block_hash = ?parent_block_hash,
                "Deferring state root verification — parent not yet verified"
            );
            self.deferred_state_root_verifications
                .entry(parent_block_hash)
                .or_default()
                .push(ready);
        }
    }

    /// Record a state root verification result. Returns whether the verification passed.
    ///
    /// On success, unblocks any child blocks that were deferred waiting for
    /// this parent's verification to complete.
    pub fn on_state_root_verified(&mut self, block_hash: BlockHash, valid: bool) -> bool {
        if valid {
            self.state_roots.insert(block_hash, RootStage::Verified);
            debug!(block_hash = ?block_hash, "State root verified successfully");

            // Unblock children that were waiting for this parent.
            if let Some(deferred) = self.deferred_state_root_verifications.remove(&block_hash) {
                for ready in deferred {
                    debug!(
                        child = ?ready.block_hash,
                        parent = ?block_hash,
                        "Unblocking deferred state root verification"
                    );
                    self.enqueue_ready_state_root(ready);
                }
            }

            // Unblock deferred proposal if it was waiting for this parent.
            self.try_unblock_proposal(block_hash);
        } else {
            self.state_roots.remove(&block_hash);
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
        self.state_roots.insert(block_hash, RootStage::Verified);

        // Unblock children deferred on this parent.
        if let Some(deferred) = self.deferred_state_root_verifications.remove(&block_hash) {
            for ready in deferred {
                debug!(
                    child = ?ready.block_hash,
                    parent = ?block_hash,
                    "Unblocking deferred state root verification (proposer verified)"
                );
                self.enqueue_ready_state_root(ready);
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
    /// would report these as `NOT_STARTED` since the proposer path bypasses
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
            self.roots.insert((block_hash, kind), RootStage::Verified);
        }
        self.verified_in_flight.insert(block_hash);
    }

    // ─── Per-kind initiators ────────────────────────────────────────────
    //
    // One method per root kind; each emits its distinct `Action` variant
    // and records the in-flight marker via `mark_root_in_flight`. All
    // results flow back through [`Self::on_root_verified`].

    /// Initiate transaction root verification for a block.
    ///
    /// The handler also enforces per-tx `validity_range`, anchored on the
    /// parent QC's `weighted_timestamp` carried on the block header. Same
    /// expression voters and the proposer apply.
    pub fn initiate_transaction_root_verification(
        &mut self,
        block_hash: BlockHash,
        block: &Block,
    ) -> Vec<Action> {
        debug!(
            ?block_hash,
            tx_count = block.transactions().len(),
            expected_root = ?block.header().transaction_root(),
            "Initiating transaction root verification"
        );
        self.mark_root_in_flight(block_hash, VerificationKind::TransactionRoot);
        vec![Action::VerifyTransactionRoot {
            block_hash,
            expected_root: block.header().transaction_root(),
            transactions: block.transactions().clone(),
            validity_anchor: block.header().parent_qc().weighted_timestamp(),
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
            expected_root = ?block.header().certificate_root(),
            "Initiating receipt root verification"
        );
        self.mark_root_in_flight(block_hash, VerificationKind::CertificateRoot);
        vec![Action::VerifyCertificateRoot {
            block_hash,
            expected_root: block.header().certificate_root(),
            certificates: block.certificates().clone(),
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
            batch_count = manifest.provision_hashes().len(),
            expected_root = ?block.header().provision_root(),
            "Initiating provisions root verification"
        );
        self.mark_root_in_flight(block_hash, VerificationKind::ProvisionRoot);
        vec![Action::VerifyProvisionRoot {
            block_hash,
            expected_root: block.header().provision_root(),
            batch_hashes: manifest.provision_hashes().0.clone(),
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
            target_count = block.header().provision_tx_roots().len(),
            "Initiating provision tx-root verification"
        );
        self.mark_root_in_flight(block_hash, VerificationKind::ProvisionTxRoots);
        vec![Action::VerifyProvisionTxRoots {
            block_hash,
            expected: block.header().provision_tx_roots().clone(),
            transactions: block.transactions().clone(),
            topology_snapshot: topology.clone(),
        }]
    }

    /// Initiate beacon-witness root verification for a block, or defer
    /// it if the prospective-parent walk hits a missing/unassembled
    /// ancestor.
    ///
    /// Pure CPU check that runs in parallel with the other per-root
    /// verifiers. Pulls the deterministic inputs (`parent_witness_leaves`
    /// from the in-chain pending-block walk, `ready_signals` from the
    /// pending block's manifest, `finalized_waves` from the block's
    /// own certificates) so callers only thread the parts they own.
    /// The handler re-derives the leaf list and emits
    /// `BeaconWitnessRootVerified { block_hash, valid }`.
    ///
    /// When [`prospective_parent_witness_leaves`] returns `Err`, the
    /// verification is parked on the blocking ancestor's hash and the
    /// returned action list is empty. The coordinator drives the retry
    /// via [`Self::take_deferred_beacon_witness_children`] when that
    /// ancestor's own beacon-witness verification completes, or via
    /// [`Self::take_committed_beacon_witness_children`] when it
    /// commits.
    pub(crate) fn initiate_beacon_witness_root_verification(
        &mut self,
        block_hash: BlockHash,
        block: &Block,
        pending_blocks: &PendingBlocks,
        accumulator: &BeaconWitnessAccumulator,
        committed_hash: BlockHash,
        topology: &TopologySnapshot,
    ) -> Vec<Action> {
        let header = block.header();
        let parent_witness_leaves = match prospective_parent_witness_leaves(
            accumulator,
            committed_hash,
            header.parent_block_hash(),
            pending_blocks,
            topology,
        ) {
            Ok(leaves) => leaves,
            Err(blocking_hash) => {
                debug!(
                    ?block_hash,
                    ?blocking_hash,
                    "Deferring beacon-witness verification — ancestor not yet available"
                );
                self.deferred_beacon_witness_verifications
                    .entry(blocking_hash)
                    .or_default()
                    .push(block_hash);
                return Vec::new();
            }
        };
        let ready_signals = pending_blocks
            .get(block_hash)
            .map_or_else(Vec::new, |pending| {
                pending.manifest().ready_signals().as_slice().to_vec()
            });
        let finalized_waves: Vec<Arc<Verified<FinalizedWave>>> = block
            .certificates()
            .iter()
            .map(|fw| Arc::new(Verified::<FinalizedWave>::seal((**fw).clone())))
            .collect();
        debug!(
            ?block_hash,
            expected_leaf_count = header.beacon_witness_leaf_count().inner(),
            parent_leaf_count = parent_witness_leaves.len(),
            "Initiating beacon-witness root verification"
        );
        self.mark_root_in_flight(block_hash, VerificationKind::BeaconWitnessRoot);
        vec![Action::VerifyBeaconWitnessRoot {
            block_hash,
            expected_root: header.beacon_witness_root(),
            expected_leaf_count: header.beacon_witness_leaf_count(),
            parent_witness_leaves,
            parent_round: header.parent_qc().round(),
            height: header.height(),
            round: header.round(),
            ready_signals,
            finalized_waves,
            topology_snapshot: topology.clone(),
        }]
    }

    /// Drain children deferred on `parent_hash`. Caller re-initiates
    /// verification for each (typically via
    /// [`Self::initiate_beacon_witness_root_verification`]).
    ///
    /// Two upstream triggers drain this queue: a successful
    /// [`VerificationKind::BeaconWitnessRoot`] for `parent_hash`
    /// (its leaves are now derivable, so the child's walk can pass
    /// through it), and a commit advancing `committed_hash` to
    /// `parent_hash` (the walk now terminates at it).
    pub(crate) fn take_deferred_beacon_witness_children(
        &mut self,
        parent_hash: BlockHash,
    ) -> Vec<BlockHash> {
        self.deferred_beacon_witness_verifications
            .remove(&parent_hash)
            .unwrap_or_default()
    }

    /// Drop deferred beacon-witness verifications keyed on a
    /// `parent_hash` whose own beacon-witness verification failed.
    /// Children waiting on a failed parent can never produce a matching
    /// root, so they're orphaned with a single warn-level log.
    fn discard_deferred_beacon_witness_children(&mut self, parent_hash: BlockHash) {
        if let Some(orphans) = self
            .deferred_beacon_witness_verifications
            .remove(&parent_hash)
        {
            warn!(
                ?parent_hash,
                orphaned_count = orphans.len(),
                "Clearing deferred beacon-witness verifications — parent failed"
            );
        }
    }

    /// Whether a block's beacon-witness verification is currently
    /// parked on a missing/unassembled ancestor.
    fn is_beacon_witness_deferred(&self, block_hash: BlockHash) -> bool {
        self.deferred_beacon_witness_verifications
            .values()
            .any(|children| children.contains(&block_hash))
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Async verification dispatch
    // ═══════════════════════════════════════════════════════════════════════

    /// Initiate every outstanding async verification for a candidate block in
    /// parallel: state root, transaction root, provision root, certificate
    /// root, local receipt root, per-target provision tx roots, and
    /// beacon-witness root. Returns the actions the caller should dispatch;
    /// state-root verification is queued into the ready list and drained
    /// separately.
    ///
    /// `accumulator` and `committed_hash` come from the shard coordinator
    /// so the beacon-witness initiator can resolve `parent_witness_leaves`
    /// by walking the pending chain — beacon-witness is the only root
    /// verifier whose inputs span the in-flight chain prefix.
    pub(crate) fn initiate_block_verifications(
        &mut self,
        topology: &TopologySnapshot,
        pending_blocks: &PendingBlocks,
        accumulator: &BeaconWitnessAccumulator,
        committed_hash: BlockHash,
        block_hash: BlockHash,
        block: &Block,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        let h = block.header();

        if self.needs_state_root_verification(block) {
            let parent_block_height = h.parent_qc().height();
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
            h.provision_root() != ProvisionsRoot::ZERO,
        ) && let Some(pending) = pending_blocks.get(block_hash)
        {
            actions.extend(self.initiate_provision_root_verification(
                block_hash,
                block,
                pending.manifest(),
            ));
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
            VerificationKind::ProvisionTxRoots,
            !h.provision_tx_roots().is_empty(),
        ) {
            actions
                .extend(self.initiate_provision_tx_root_verification(block_hash, block, topology));
        }

        if self.needs_root(block_hash, VerificationKind::BeaconWitnessRoot, true)
            && !self.is_beacon_witness_deferred(block_hash)
        {
            actions.extend(self.initiate_beacon_witness_root_verification(
                block_hash,
                block,
                pending_blocks,
                accumulator,
                committed_hash,
                topology,
            ));
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

        let parent_in_flight = if block.header().parent_qc().is_genesis() {
            InFlightCount::ZERO
        } else if let Some(h) = chain.get_header(block.header().parent_block_hash()) {
            h.in_flight()
        } else {
            trace!(
                block_hash = ?block_hash,
                "Skipping vote — parent pruned, still verifying for PreparedCommit"
            );
            return InFlightCheck::SkipVote;
        };

        let finalized_tx_count: u32 = chain.get_pending(block_hash).map_or(0, |p| {
            p.finalized_waves()
                .iter()
                .map(|fw| u32::try_from(fw.tx_count()).unwrap_or(u32::MAX))
                .sum()
        });

        if self.verify_in_flight(block_hash, block, parent_in_flight, finalized_tx_count) {
            InFlightCheck::Proceed
        } else {
            InFlightCheck::Abort
        }
    }

    /// Verify the proposed in-flight count is deterministically correct.
    ///
    /// `in_flight` = `parent.in_flight()` + `new_txs` - `finalized_txs`
    ///
    /// All validators can compute this from chain state, so it must be exact.
    /// Certificates are only counted when actually included (JMT was ready).
    pub fn verify_in_flight(
        &mut self,
        block_hash: BlockHash,
        block: &Block,
        parent_in_flight: InFlightCount,
        finalized_tx_count: u32,
    ) -> bool {
        let proposed = block.header().in_flight();

        // Compute expected: only subtract finalized txs when certs are actually included.
        let certs_finalized = if block.certificates().is_empty() {
            0
        } else {
            finalized_tx_count
        };
        let expected = parent_in_flight
            .saturating_add(u32::try_from(block.transaction_count()).unwrap_or(u32::MAX))
            .saturating_sub(certs_finalized);

        if proposed == expected {
            self.verified_in_flight.insert(block_hash);
            true
        } else {
            warn!(
                block_hash = ?block_hash,
                height = block.height().inner(),
                proposed = proposed.inner(),
                expected = expected.inner(),
                parent_in_flight = parent_in_flight.inner(),
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
            .filter_map(|pending| {
                // The pending block can be removed between queue-up and drain
                // (a sibling verification fails, view change, etc.); the next
                // `cleanup_old_state` evicts the stale entry but the drain may
                // run first. Dispatching with empty `finalized_waves` would
                // recompute the wrong state root against ghost inputs — skip.
                let block = chain
                    .get_pending(pending.block_hash)
                    .and_then(PendingBlock::block)
                    .or_else(|| {
                        debug!(
                            block_hash = ?pending.block_hash,
                            "Skipping state root verification — pending block no longer present"
                        );
                        None
                    })?;
                let parent_state_root = chain.parent_state_root(pending.parent_block_hash);
                let finalized_waves: Vec<Arc<Verified<FinalizedWave>>> = block
                    .certificates()
                    .iter()
                    .map(|fw| Arc::new(Verified::<FinalizedWave>::seal((**fw).clone())))
                    .collect();
                Some(ReadyStateRootVerification {
                    block_hash: pending.block_hash,
                    parent_block_hash: pending.parent_block_hash,
                    parent_state_root,
                    parent_block_height: pending.parent_block_height,
                    expected_root: pending.expected_root,
                    expected_local_receipt_root: pending.expected_local_receipt_root,
                    finalized_waves,
                    block_height: pending.block_height,
                })
            })
            .collect()
    }

    /// Check whether a deferred proposal was unblocked and should be retried.
    /// Returns `true` once, then resets. Caller re-enters `try_propose` with
    /// fresh transaction selection.
    pub fn take_ready_proposal(&mut self) -> bool {
        std::mem::take(&mut self.proposal_unblocked)
    }

    /// Latch a proposal-retry attempt for after the current dispatch.
    /// Idempotent within a single dispatch; the post-dispatch drain calls
    /// `try_propose` once regardless of how many times this is set.
    pub const fn queue_ready_proposal(&mut self) {
        self.proposal_unblocked = true;
    }

    /// Check if a parent's tree nodes are available (persisted or verified
    /// or consensus-committed — all three place the parent's JMT snapshot
    /// either on disk or in the `PendingChain` overlay).
    pub fn parent_tree_available(
        &self,
        parent_block_height: BlockHeight,
        parent_block_hash: BlockHash,
    ) -> bool {
        parent_block_height <= self.last_persisted_height
            || self.is_state_root_verified(&parent_block_hash)
    }

    /// Record that a proposal is deferred until the parent's tree nodes are
    /// available. Only the parent identity is stored — when unblocked, the
    /// caller re-enters `try_propose` with fresh state rather than replaying
    /// a stale `BuildProposal` action.
    pub fn defer_proposal(
        &mut self,
        parent_block_hash: BlockHash,
        parent_block_height: BlockHeight,
    ) {
        debug!(
            parent_block_hash = ?parent_block_hash,
            parent_block_height = parent_block_height.inner(),
            "Deferring proposal — parent tree not yet available"
        );
        self.deferred_proposal = Some((parent_block_hash, parent_block_height));
    }

    /// If the deferred proposal was waiting for `unblocked_hash`, mark it ready.
    fn try_unblock_proposal(&mut self, unblocked_hash: BlockHash) {
        if matches!(&self.deferred_proposal, Some((parent, _)) if *parent == unblocked_hash) {
            self.deferred_proposal.take();
            debug!(parent_block_hash = ?unblocked_hash, "Unblocking deferred proposal");
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
            .map(|(parent_block_hash, _)| *parent_block_hash)
            .collect();

        for parent_block_hash in unblocked_parents {
            if let Some(entries) = self
                .deferred_state_root_verifications
                .remove(&parent_block_hash)
            {
                for ready in entries {
                    if ready.parent_block_height <= block_height {
                        self.enqueue_ready_state_root(ready);
                    } else {
                        self.deferred_state_root_verifications
                            .entry(parent_block_hash)
                            .or_default()
                            .push(ready);
                    }
                }
            }
        }

        // Unblock deferred proposal if its parent height is now persisted.
        if let Some((_, parent_block_height)) = &self.deferred_proposal
            && *parent_block_height <= block_height
        {
            self.deferred_proposal.take();
            debug!("Unblocking deferred proposal — parent persisted");
            self.proposal_unblocked = true;
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
        let was_verified = matches!(
            self.state_roots.insert(block_hash, RootStage::Verified),
            Some(RootStage::Verified)
        );
        if was_verified {
            return;
        }

        if let Some(deferred) = self.deferred_state_root_verifications.remove(&block_hash) {
            for ready in deferred {
                debug!(
                    child = ?ready.block_hash,
                    parent = ?block_hash,
                    "Unblocking deferred state root verification (parent committed)"
                );
                self.enqueue_ready_state_root(ready);
            }
        }

        self.try_unblock_proposal(block_hash);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Cleanup
    // ═══════════════════════════════════════════════════════════════════════

    /// Remove verification state for blocks no longer in `pending_blocks`.
    ///
    /// Called by `ShardCoordinator::cleanup_old_state()` after it has cleaned up
    /// `pending_blocks`. We use the surviving `pending_blocks` set to determine
    /// which verification state to keep.
    ///
    /// Most verification state is keyed by block hash and cleaned up based on
    /// `pending_blocks` membership (if the block is gone, its verification state
    /// is stale). The `verified_qcs` cache is the exception: it's keyed by the
    /// QC's certified block hash (not the proposing block), so it uses
    /// height-based retention with a 2-block buffer to support view-change
    /// scenarios where multiple proposals share the same parent QC.
    pub fn cleanup(&mut self, pending_blocks: &PendingBlocks, committed_height: BlockHeight) {
        self.pending_qc_verifications
            .retain(|hash, _| pending_blocks.contains_key(*hash));

        self.state_roots
            .retain(|hash, _| pending_blocks.contains_key(*hash));

        self.ready_state_root_verifications
            .retain(|r| pending_blocks.contains_key(r.block_hash));

        // Clean up deferred verifications: remove entries whose child blocks
        // are no longer pending, and remove parent keys with empty lists.
        for entries in self.deferred_state_root_verifications.values_mut() {
            entries.retain(|r| pending_blocks.contains_key(r.block_hash));
        }
        self.deferred_state_root_verifications
            .retain(|_, entries| !entries.is_empty());

        // Clear deferred proposal if its parent is at or below committed height
        // (the proposal is stale — a new round/view will generate a fresh one).
        if let Some((_, parent_block_height)) = &self.deferred_proposal
            && *parent_block_height <= committed_height
        {
            self.deferred_proposal = None;
        }

        self.roots
            .retain(|(hash, _), _| pending_blocks.contains_key(*hash));

        // Drop deferred beacon-witness entries whose child has been
        // pruned. Parent keys whose values empty out are removed too.
        for children in self.deferred_beacon_witness_verifications.values_mut() {
            children.retain(|child| pending_blocks.contains_key(*child));
        }
        self.deferred_beacon_witness_verifications
            .retain(|_, children| !children.is_empty());

        self.verified_in_flight
            .retain(|hash| pending_blocks.contains_key(*hash));

        // verified_qcs uses height-based retention (not pending_blocks membership)
        // because QC cache entries are keyed by the certified block's hash, which
        // differs from the proposing block's hash. A 2-block buffer below
        // committed_height covers view-change scenarios where multiple proposals
        // at the same height reference the same parent QC.
        self.verified_qcs
            .retain(|_, qc| qc.height() > committed_height.saturating_sub(2));

        self.pending_assemblies
            .retain(|hash, _| pending_blocks.contains_key(*hash));

        // Drop completed-assembly handles whose blocks are no longer in
        // `pending_blocks` (block evicted, or commit drained the
        // handle). Lifecycle mirrors `pending_assemblies`.
        self.verified_certified_blocks
            .retain(|hash, _| pending_blocks.contains_key(*hash));
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
            .map(Vec::len)
            .sum()
    }
}

#[cfg(test)]
mod tests {

    use hyperscale_types::{
        BoundedVec, CertificateRoot, Hash, LocalReceiptRoot, LocalTimestamp, ProposerTimestamp,
        QuorumCertificate, Round, RoutableTransaction, ShardGroupId, SignerBitfield,
        TransactionRoot, ValidatorId, WeightedTimestamp, zero_bls_signature,
    };

    use super::*;
    use crate::pending::PendingBlock;

    fn header(height: BlockHeight, parent_block_hash: BlockHash, in_flight: u32) -> BlockHeader {
        BlockHeader::new(
            ShardGroupId::new(0),
            height,
            parent_block_hash,
            QuorumCertificate::genesis(ShardGroupId::new(0)),
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
            std::collections::BTreeMap::new(),
            InFlightCount::new(in_flight),
            BeaconWitnessRoot::ZERO,
            BeaconWitnessLeafCount::ZERO,
        )
    }

    fn header_with_parent_qc(
        height: BlockHeight,
        parent_block_hash: BlockHash,
        in_flight: u32,
        parent_qc: QuorumCertificate,
    ) -> BlockHeader {
        BlockHeader::new(
            ShardGroupId::new(0),
            height,
            parent_block_hash,
            parent_qc,
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
            std::collections::BTreeMap::new(),
            InFlightCount::new(in_flight),
            BeaconWitnessRoot::ZERO,
            BeaconWitnessLeafCount::ZERO,
        )
    }

    fn block_with(
        height: BlockHeight,
        parent_block_hash: BlockHash,
        in_flight: u32,
        transactions: Vec<Arc<RoutableTransaction>>,
    ) -> Block {
        Block::Live {
            header: header(height, parent_block_hash, in_flight),
            transactions: Arc::new(transactions.into()),
            certificates: Arc::new(BoundedVec::new()),
            provisions: Arc::new(BoundedVec::new()),
        }
    }

    fn chain_view<'a>(
        committed_height: BlockHeight,
        committed_hash: BlockHash,
        latest_qc: Option<&'a Verified<QuorumCertificate>>,
        pending: &'a PendingBlocks,
    ) -> ChainView<'a> {
        ChainView::new(
            ShardGroupId::new(0),
            committed_height,
            committed_hash,
            StateRoot::ZERO,
            latest_qc,
            pending,
        )
    }

    fn bh(tag: &[u8]) -> BlockHash {
        BlockHash::from_raw(Hash::from_bytes(tag))
    }

    // ─── classify_vote_in_flight ────────────────────────────────────────

    #[test]
    fn classify_vote_in_flight_skips_vote_when_locked() {
        let mut vp = VerificationPipeline::new(BlockHeight::GENESIS);
        let block = block_with(BlockHeight::new(1), BlockHash::ZERO, 0, vec![]);
        let block_hash = block.hash();
        let pending = PendingBlocks::new();
        let chain = chain_view(BlockHeight::GENESIS, BlockHash::ZERO, None, &pending);

        let out = vp.classify_vote_in_flight(&chain, block_hash, &block, true);
        assert!(matches!(out, InFlightCheck::SkipVote));
    }

    #[test]
    fn classify_vote_in_flight_skips_vote_when_parent_pruned() {
        // Non-genesis parent QC that isn't in the chain view: parent is
        // effectively pruned, so we skip voting but still keep verifying.
        let mut vp = VerificationPipeline::new(BlockHeight::GENESIS);
        let parent = bh(b"parent");
        let parent_qc = QuorumCertificate::new(
            parent,
            ShardGroupId::new(0),
            BlockHeight::new(4),
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::empty(),
            zero_bls_signature(),
            WeightedTimestamp::ZERO,
        );
        let h = header_with_parent_qc(BlockHeight::new(5), parent, 0, parent_qc);
        let block = Block::Live {
            header: h,
            transactions: Arc::new(BoundedVec::new()),
            certificates: Arc::new(BoundedVec::new()),
            provisions: Arc::new(BoundedVec::new()),
        };
        let block_hash = block.hash();
        let pending = PendingBlocks::new();
        let chain = chain_view(BlockHeight::new(3), BlockHash::ZERO, None, &pending);

        let out = vp.classify_vote_in_flight(&chain, block_hash, &block, false);
        assert!(matches!(out, InFlightCheck::SkipVote));
    }

    #[test]
    fn classify_vote_in_flight_proceeds_when_genesis_parent_and_counts_match() {
        let mut vp = VerificationPipeline::new(BlockHeight::GENESIS);
        let block = block_with(BlockHeight::new(1), BlockHash::ZERO, 0, vec![]);
        let block_hash = block.hash();
        let pending = PendingBlocks::new();
        let chain = chain_view(BlockHeight::GENESIS, BlockHash::ZERO, None, &pending);

        let out = vp.classify_vote_in_flight(&chain, block_hash, &block, false);
        assert!(matches!(out, InFlightCheck::Proceed));
    }

    #[test]
    fn classify_vote_in_flight_aborts_on_in_flight_mismatch() {
        // Genesis parent → parent_in_flight = 0. Block claims in_flight = 5
        // with 0 transactions: proposed doesn't match expected → Abort.
        let mut vp = VerificationPipeline::new(BlockHeight::GENESIS);
        let block = block_with(BlockHeight::new(1), BlockHash::ZERO, 5, vec![]);
        let block_hash = block.hash();
        let pending = PendingBlocks::new();
        let chain = chain_view(BlockHeight::GENESIS, BlockHash::ZERO, None, &pending);

        let out = vp.classify_vote_in_flight(&chain, block_hash, &block, false);
        assert!(matches!(out, InFlightCheck::Abort));
    }

    // ─── drain_ready_state_root_verifications ───────────────────────────

    #[test]
    fn drain_ready_state_root_verifications_returns_empty_when_nothing_ready() {
        let mut vp = VerificationPipeline::new(BlockHeight::GENESIS);
        let pending = PendingBlocks::new();
        let chain = chain_view(BlockHeight::GENESIS, BlockHash::ZERO, None, &pending);

        let out = vp.drain_ready_state_root_verifications(&chain);
        assert!(out.is_empty());
    }

    #[test]
    fn drain_ready_state_root_verifications_enriches_from_chain_view() {
        // Parent is at GENESIS height ≤ last_persisted_height, so initiate
        // queues this entry directly into ready_state_root_verifications.
        let mut vp = VerificationPipeline::new(BlockHeight::GENESIS);
        let parent_block_hash = bh(b"parent");
        let block = block_with(BlockHeight::new(1), parent_block_hash, 0, vec![]);
        let block_hash = block.hash();

        vp.initiate_state_root_verification(block_hash, &block, BlockHeight::GENESIS);

        let mut pb =
            PendingBlock::from_complete_block(&block, vec![], vec![], vec![], LocalTimestamp::ZERO);
        pb.construct_block()
            .expect("complete block constructs cleanly");
        let mut pending_with_block = PendingBlocks::new();
        pending_with_block.insert(pb);
        let chain = chain_view(
            BlockHeight::GENESIS,
            BlockHash::ZERO,
            None,
            &pending_with_block,
        );

        let out = vp.drain_ready_state_root_verifications(&chain);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].block_hash, block_hash);
        assert_eq!(out[0].parent_block_hash, parent_block_hash);
        assert_eq!(out[0].parent_block_height, BlockHeight::GENESIS);

        // Draining again without another initiate yields nothing.
        let empty_pending = PendingBlocks::new();
        let chain2 = chain_view(BlockHeight::GENESIS, BlockHash::ZERO, None, &empty_pending);
        assert!(vp.drain_ready_state_root_verifications(&chain2).is_empty());
    }

    #[test]
    fn drain_skips_entries_whose_pending_block_is_gone() {
        // A sibling verification can call `remove_pending_block` between
        // queue-up and drain. Drain must skip the orphaned entry rather than
        // dispatch with empty `finalized_waves` against the wrong inputs.
        let mut vp = VerificationPipeline::new(BlockHeight::GENESIS);
        let parent_block_hash = bh(b"parent");
        let block = block_with(BlockHeight::new(1), parent_block_hash, 0, vec![]);
        let block_hash = block.hash();

        vp.initiate_state_root_verification(block_hash, &block, BlockHeight::GENESIS);

        let empty_pending = PendingBlocks::new();
        let chain = chain_view(BlockHeight::GENESIS, BlockHash::ZERO, None, &empty_pending);

        let out = vp.drain_ready_state_root_verifications(&chain);
        assert!(
            out.is_empty(),
            "entry must be skipped when its pending block was removed"
        );
    }

    // ─── beacon-witness deferral ────────────────────────────────────────

    /// A block whose parent is missing from `pending_blocks` must defer
    /// beacon-witness verification (no `VerifyBeaconWitnessRoot` action
    /// emitted) and park itself on the missing ancestor's hash.
    #[test]
    fn beacon_witness_verification_defers_on_missing_ancestor() {
        use hyperscale_test_helpers::TestCommittee;

        use crate::beacon_witnesses::BeaconWitnessAccumulator;

        let mut vp = VerificationPipeline::new(BlockHeight::GENESIS);
        let topology = TestCommittee::new(4, 7).topology_snapshot(0, 1);
        let accumulator = BeaconWitnessAccumulator::new();
        let pending = PendingBlocks::new();

        // Parent block hash isn't in `pending` — walk will fail at it.
        let parent_block_hash = bh(b"missing-parent");
        let block = block_with(BlockHeight::new(5), parent_block_hash, 0, vec![]);
        let block_hash = block.hash();

        let actions = vp.initiate_beacon_witness_root_verification(
            block_hash,
            &block,
            &pending,
            &accumulator,
            BlockHash::ZERO,
            &topology,
        );

        assert!(
            actions.is_empty(),
            "deferral must not emit a VerifyBeaconWitnessRoot action"
        );
        assert!(vp.is_beacon_witness_deferred(block_hash));
        assert!(!vp.is_root_in_flight(block_hash, VerificationKind::BeaconWitnessRoot));
    }

    /// Draining the deferred queue keyed on the blocking ancestor's
    /// hash yields the child hashes that had been parked on it.
    /// Re-running the verification once the ancestor is committed (or
    /// otherwise resolved) is the caller's responsibility.
    #[test]
    fn deferred_beacon_witness_children_drain_by_parent_hash() {
        use hyperscale_test_helpers::TestCommittee;

        use crate::beacon_witnesses::BeaconWitnessAccumulator;

        let mut vp = VerificationPipeline::new(BlockHeight::GENESIS);
        let topology = TestCommittee::new(4, 7).topology_snapshot(0, 1);
        let accumulator = BeaconWitnessAccumulator::new();
        let pending = PendingBlocks::new();
        let parent_block_hash = bh(b"missing-parent");

        let block_a = block_with(BlockHeight::new(5), parent_block_hash, 0, vec![]);
        let hash_a = block_a.hash();
        let block_b = block_with(BlockHeight::new(5), parent_block_hash, 1, vec![]);
        let hash_b = block_b.hash();

        for (h, b) in [(hash_a, &block_a), (hash_b, &block_b)] {
            let _ = vp.initiate_beacon_witness_root_verification(
                h,
                b,
                &pending,
                &accumulator,
                BlockHash::ZERO,
                &topology,
            );
        }

        let drained = vp.take_deferred_beacon_witness_children(parent_block_hash);
        assert_eq!(drained.len(), 2);
        assert!(drained.contains(&hash_a));
        assert!(drained.contains(&hash_b));

        // Second drain yields nothing.
        assert!(
            vp.take_deferred_beacon_witness_children(parent_block_hash)
                .is_empty()
        );
    }

    /// A failed beacon-witness verification orphans any children that
    /// were parked on the failed block: the chain can't reconstruct
    /// matching leaves through a parent whose own root was wrong.
    #[test]
    fn failed_beacon_witness_clears_dependent_children() {
        use hyperscale_test_helpers::TestCommittee;

        use crate::beacon_witnesses::BeaconWitnessAccumulator;

        let mut vp = VerificationPipeline::new(BlockHeight::GENESIS);
        let topology = TestCommittee::new(4, 7).topology_snapshot(0, 1);
        let accumulator = BeaconWitnessAccumulator::new();
        let pending = PendingBlocks::new();
        let parent_block_hash = bh(b"to-fail");

        let child = block_with(BlockHeight::new(5), parent_block_hash, 0, vec![]);
        let child_hash = child.hash();
        let _ = vp.initiate_beacon_witness_root_verification(
            child_hash,
            &child,
            &pending,
            &accumulator,
            BlockHash::ZERO,
            &topology,
        );
        assert!(vp.is_beacon_witness_deferred(child_hash));

        vp.on_root_verified(
            parent_block_hash,
            VerificationKind::BeaconWitnessRoot,
            false,
        );
        assert!(!vp.is_beacon_witness_deferred(child_hash));
        assert!(
            vp.take_deferred_beacon_witness_children(parent_block_hash)
                .is_empty()
        );
    }

    // ─── PendingAssembly multi-slot completion ──────────────────────────

    fn assembly_block() -> Block {
        Block::genesis(ShardGroupId::new(0), ValidatorId::new(0), StateRoot::ZERO)
    }

    fn assembly_qc_for(block: &Block) -> QuorumCertificate {
        QuorumCertificate::new(
            block.hash(),
            ShardGroupId::new(0),
            BlockHeight::GENESIS,
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::empty(),
            zero_bls_signature(),
            WeightedTimestamp::ZERO,
        )
    }

    /// Completion fires only when every outstanding slot is `Some`.
    /// For a genesis block the per-root content slots auto-skip (empty
    /// txs / certs / provisions), so beacon-witness and state-root are
    /// the two slots that must arrive via `record_*_root_result` before
    /// QC completes the assembly.
    #[test]
    fn record_assembly_waits_for_every_outstanding_slot() {
        let mut vp = VerificationPipeline::new(BlockHeight::GENESIS);
        let block = assembly_block();
        let block_hash = block.hash();
        let header = block.header().clone();
        let verified_qc =
            Verified::<QuorumCertificate>::new_unchecked_for_test(assembly_qc_for(&block));

        vp.track_pending_assembly(Arc::new(block));
        assert_eq!(vp.pending_assembly_count(), 1);

        // QC arrives — beacon-witness + state root still outstanding.
        assert!(vp.record_qc_assembly(block_hash, verified_qc).is_none());
        assert_eq!(vp.pending_assembly_count(), 1);

        // Beacon-witness arrives — state root still outstanding.
        let beacon_verified =
            Verified::<BeaconWitnessRoot>::new_unchecked_for_test(header.beacon_witness_root());
        assert!(
            vp.record_beacon_witness_root_result(block_hash, beacon_verified)
                .is_none()
        );
        assert_eq!(vp.pending_assembly_count(), 1);

        // State root closes out the last slot; completion fires from the
        // per-root setter (not from `record_qc_assembly`), proving either
        // path can be the trigger.
        let linked = vp
            .record_state_root_result(
                block_hash,
                Verified::<StateRoot>::new_unchecked_for_test(StateRoot::ZERO),
            )
            .expect("completion fires when every slot is Some")
            .expect("linkage check passes for the matching qc.block_hash");
        assert_eq!(linked.qc().block_hash(), block_hash);
        assert_eq!(vp.pending_assembly_count(), 0);
    }

    /// Per-root verifications that complete before `track_pending_assembly`
    /// runs are reflected in the initial slot state — pre-existing
    /// `RootStage::Verified` entries in `roots` / `state_roots` prefill
    /// matching slots so the assembly doesn't deadlock waiting for events
    /// that already fired.
    #[test]
    fn track_pending_assembly_prefills_already_verified_slots() {
        let mut vp = VerificationPipeline::new(BlockHeight::GENESIS);
        let block = assembly_block();
        let block_hash = block.hash();
        let verified_qc =
            Verified::<QuorumCertificate>::new_unchecked_for_test(assembly_qc_for(&block));

        // Beacon-witness + state root verify before the QC arrives.
        vp.roots.insert(
            (block_hash, VerificationKind::BeaconWitnessRoot),
            RootStage::Verified,
        );
        vp.state_roots.insert(block_hash, RootStage::Verified);

        vp.track_pending_assembly(Arc::new(block));

        // QC is the only outstanding slot — completion fires immediately.
        let linked = vp
            .record_qc_assembly(block_hash, verified_qc)
            .expect("completion fires when every slot is Some")
            .expect("linkage check passes for the matching qc.block_hash");
        assert_eq!(linked.qc().block_hash(), block_hash);
        assert_eq!(vp.pending_assembly_count(), 0);
    }

    /// `record_qc_assembly` against a block hash with no tracked assembly
    /// is a no-op returning `None`.
    #[test]
    fn record_qc_assembly_returns_none_for_unknown_block() {
        let mut vp = VerificationPipeline::new(BlockHeight::GENESIS);
        let block = assembly_block();
        let verified_qc =
            Verified::<QuorumCertificate>::new_unchecked_for_test(assembly_qc_for(&block));
        assert!(vp.record_qc_assembly(block.hash(), verified_qc).is_none());
        assert_eq!(vp.pending_assembly_count(), 0);
    }

    /// `record_root_assembly` against an unknown block is a no-op too.
    #[test]
    fn record_root_assembly_returns_none_for_unknown_block() {
        let mut vp = VerificationPipeline::new(BlockHeight::GENESIS);
        assert!(
            vp.record_state_root_result(
                bh(b"no-such-block"),
                Verified::<StateRoot>::new_unchecked_for_test(StateRoot::ZERO),
            )
            .is_none()
        );
    }
}
