//! Async verification pipeline for block voting.
//!
//! Tracks QC signature, state root, transaction root, and receipt root
//! verifications. `ShardCoordinator` delegates verification bookkeeping here while
//! retaining control-flow decisions (voting, block rejection).
//!
//! Pure pre-vote validation helpers (header structure, timestamp bounds,
//! transaction ordering, `ticks` recomputation, cross-ancestor tx uniqueness)
//! live in [`crate::validation`].

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use hyperscale_core::{Action, FeeDemand};
use hyperscale_storage::committed_tx_cells;
use hyperscale_types::{
    AbandonmentRecord, Block, BlockHash, BlockHeader, BlockHeight, BlockManifest, CertifiedBlock,
    ChainOrigin, Demands, Finalization, LinkageError, LocalReceiptRoot, QuorumCertificate,
    ReshapeThresholds, RevealChain, ScheduleLookup, ShardId, SplitChildRoots, StateRoot,
    SubstateKey, SweepFrontier, TerminalRoots, TopologySchedule, TopologySnapshot, TxHash,
    TxsInFlight, UnsettledTx, Verifiable, VerificationKind, Verified, VerifiedBlockAssembleError,
    WeightedTimestamp,
};
use thiserror::Error;
use tracing::{debug, trace, warn};

use crate::beacon_witnesses::{BeaconWitnessAccumulator, prospective_parent_witness_leaves};
use crate::chain_view::ChainView;
use crate::pending::{PendingBlock, PendingBlocks};
use crate::proposal::late_deliveries;

/// `anchor`'s window — the trie a delivered body is classified against
/// and the table its price is weighed at — or `None` where no retained
/// window carries the anchor.
///
/// A stand-in would not be a neutral answer. Under one shard every
/// prefix resolves to it, so no body classifies as delivering here, no
/// delivery is ever read as lapsed, and the block passes the arm the
/// abandonment fence rests on — a permissive answer to the question that
/// keeps a crossing from being claimed after its issuer may have taken it
/// back. A window this cannot read is one to wait for.
pub fn anchor_window(
    schedule: &TopologySchedule,
    anchor: WeightedTimestamp,
) -> Option<&TopologySnapshot> {
    match schedule.lookup(anchor) {
        ScheduleLookup::Committee(snapshot) => Some(snapshot),
        _ => None,
    }
}

/// The committed cells `block` writes.
///
/// One per transaction it carries, under the block's own shard. Every
/// reader of the block's root — the proposer's voters, a replica
/// committing it on its certificate alone, a split child following it —
/// derives the same set from the same two facts, and no window enters
/// it.
#[must_use]
pub fn committed_cells_for(block: &Block) -> Vec<(SubstateKey, Vec<u8>)> {
    committed_tx_cells(
        block.header().shard_id(),
        block.transactions().iter().map(|tx| tx.as_unverified()),
    )
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
/// verify the QC's aggregated signature before voting. This struct
/// tracks the block header while waiting for verification.
#[derive(Debug, Clone)]
pub struct PendingQcVerification {
    /// The block header we're considering voting on.
    pub header: BlockHeader,
}

/// State root verification that is ready to dispatch (JMT is at the correct root).
///
/// The `NodeStateMachine` drains these after each shard consensus call and emits
/// `VerifyStateRoot` actions. `parent_state_root` and `finalizations` are
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
    /// Finalizations from the `PendingBlock` — these carry the proposer's receipts,
    /// ensuring all validators verify against the same execution outputs.
    pub finalizations: Vec<Arc<Verifiable<Finalization>>>,
    /// Hashes of the block's own transactions — its contribution to the
    /// committed-transaction window a terminating boundary header roots.
    pub block_tx_hashes: Vec<TxHash>,
    /// The committed cells the block writes, derived under its window,
    /// folded under the root being verified.
    pub creations: Vec<(SubstateKey, Vec<u8>)>,
    /// Height of the block being verified.
    pub block_height: BlockHeight,
    /// The header's `split_child_roots` claim, verified beside the
    /// state root.
    pub claimed_split_child_roots: Option<SplitChildRoots>,
    /// Whether the block's window requires the claim (the shard's final
    /// epoch before a split).
    pub split_child_roots_required: bool,
    /// Whether the block's window requires terminal roots — set on any
    /// terminating boundary header (a split parent's or a merge child's
    /// final epoch), broader than [`Self::split_child_roots_required`].
    pub terminal_roots_required: bool,
    /// The header's `terminal_roots` claim, verified beside the state root
    /// over the committed retention window.
    pub claimed_terminal_roots: Option<TerminalRoots>,
    /// The block's parent-QC weighted timestamp — the settled-transaction window
    /// anchor.
    pub parent_weighted_timestamp: WeightedTimestamp,
    /// The schedule's settled-window floor at the anchor — extends the
    /// window back to the reshape's admission.
    pub settled_txs_window_floor: Option<WeightedTimestamp>,
    /// Where the parent's sweep stopped — the lower end of the interval
    /// this block's removals fill.
    pub parent_sweep_frontier: SweepFrontier,
    /// The header's own `sweep_frontier` claim, recomputed beside the
    /// state root.
    pub claimed_sweep_frontier: SweepFrontier,
}

/// Classification of the in-flight check outcome for the vote path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InFlightCheck {
    /// The drain total checks out — proceed with voting.
    Proceed,
    /// Run verifications but do not vote (safe-vote rule declined, or parent pruned).
    SkipVote,
    /// The drain total is not the one the block's own content
    /// produces — abort entirely.
    Abort,
}

/// Internal queue entry for state root verification. Holds only block identity
/// — `parent_state_root` and `finalizations` are resolved freshly at drain
/// time against the current chain view.
#[derive(Debug, Clone)]
pub struct PendingStateRootVerification {
    pub block_hash: BlockHash,
    pub parent_block_hash: BlockHash,
    pub parent_block_height: BlockHeight,
    pub expected_root: StateRoot,
    pub expected_local_receipt_root: LocalReceiptRoot,
    pub block_height: BlockHeight,
    pub claimed_split_child_roots: Option<SplitChildRoots>,
    pub split_child_roots_required: bool,
    pub terminal_roots_required: bool,
    pub claimed_terminal_roots: Option<TerminalRoots>,
    pub parent_weighted_timestamp: WeightedTimestamp,
    pub settled_txs_window_floor: Option<WeightedTimestamp>,
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

/// A block awaiting what a [`Verified<CertifiedBlock>`] needs: its
/// verified QC, and every check it demands answered. Which checks are
/// outstanding is read off [`VerificationPipeline::outstanding`] at
/// each completion rather than held here, so the assembly and the vote
/// read one answer.
#[derive(Debug)]
pub struct PendingAssembly {
    /// Block whose commitments are being verified.
    pub block: Arc<Block>,
    /// Verified QC for [`Self::block`], populated when QC signature
    /// verification completes.
    pub qc: Option<Verified<QuorumCertificate>>,
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
    /// skipping signature verification — without this, a Byzantine peer could
    /// reuse a known-cached `block_hash` while fabricating `signers`,
    /// `round`, or `parent_block_hash` and have those fields adopted into
    /// `latest_qc` / drive view sync without re-verification.
    verified_qcs: HashMap<BlockHash, Verified<QuorumCertificate>>,

    // === State root verification ===
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

    /// Ancestor whose substate byte delta a deferred proposal is parked on.
    ///
    /// The reshape load predicate sums per-block deltas along the pending
    /// chain behind the proposal parent, and a block whose state root has
    /// not verified locally yet contributes none, so the build defers.
    /// Nothing else re-drives it: the parked height is the one whose QC
    /// would commit that ancestor, so no commit, QC, or admission follows
    /// to latch a retry and the round runs out its view-change timeout
    /// instead. Released when the delta lands, when the ancestor commits,
    /// or when the byte frontier reconciles from storage.
    deferred_substate_ancestor: Option<BlockHash>,

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

    // === Per-check stage ===
    /// Stage per `(block_hash, kind)` for every check a block demands.
    /// Absence means "not dispatched" — never started, refused, or
    /// deferred; [`Self::outstanding`] reads a block's demands against
    /// this to say what is still owed.
    roots: HashMap<(BlockHash, VerificationKind), RootStage>,

    /// Beacon-witness verifications waiting for a missing/unassembled
    /// ancestor to become available. Keyed by the blocking ancestor's
    /// hash; values are the deferred child block hashes, each tagged with
    /// which walk parked it. A retry runs when
    /// [`Self::take_deferred_beacon_witness_children`] drains the entry —
    /// on the ancestor's own beacon-witness verification completing, or
    /// on a commit advancing `committed_hash` to it.
    deferred_beacon_witness_verifications: HashMap<BlockHash, Vec<(BlockHash, BeaconWitnessDefer)>>,

    /// Beacon-witness verifications whose block's governing committee is not
    /// yet resolvable because this node's beacon is behind — the topology
    /// schedule has not committed the epoch that seats the block's committee.
    /// Unlike [`Self::deferred_beacon_witness_verifications`], the blocker is
    /// beacon progress, not a shard ancestor, so no shard-side event drains it;
    /// it is retried when the beacon advances (`on_beacon_block_persisted`).
    /// Without this a block dropped during a transient beacon lag would stay
    /// `NOT_STARTED` forever and wedge the shard on a view-change loop.
    beacon_witness_awaiting_committee: HashSet<BlockHash>,

    // === Drain total verification ===
    /// Blocks whose claimed drain total was re-derived and matched.
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

    /// The chain's origin (genesis height plus start-time anchor).
    /// Assembly reconstructs the canonical genesis QC from this value
    /// when a header claims a genesis `parent_qc`; the byte-equality
    /// check in `with_verified_parent_qc` then rejects any claimed
    /// genesis QC whose height or anchor differs from the chain's.
    chain_origin: ChainOrigin,
}

impl VerificationPipeline {
    /// Create a new verification pipeline.
    pub fn new(persisted_height: BlockHeight, chain_origin: ChainOrigin) -> Self {
        Self {
            pending_qc_verifications: HashMap::new(),
            verified_qcs: HashMap::new(),
            deferred_state_root_verifications: HashMap::new(),
            deferred_proposal: None,
            deferred_substate_ancestor: None,
            ready_state_root_verifications: Vec::new(),
            proposal_unblocked: false,
            last_persisted_height: persisted_height,
            roots: HashMap::new(),
            deferred_beacon_witness_verifications: HashMap::new(),
            beacon_witness_awaiting_committee: HashSet::new(),
            verified_in_flight: HashSet::new(),
            pending_assemblies: HashMap::new(),
            verified_certified_blocks: HashMap::new(),
            chain_origin,
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Per-root merkle state (shared helpers)
    // ═══════════════════════════════════════════════════════════════════════

    /// Whether `kind` has been checked for `block_hash`.
    pub(crate) fn is_root_verified(&self, block_hash: BlockHash, kind: VerificationKind) -> bool {
        matches!(
            self.roots.get(&(block_hash, kind)),
            Some(RootStage::Verified)
        )
    }

    /// Whether a merkle-root verification is currently in-flight for
    /// `(block_hash, kind)`.
    pub(crate) fn is_root_in_flight(&self, block_hash: BlockHash, kind: VerificationKind) -> bool {
        matches!(
            self.roots.get(&(block_hash, kind)),
            Some(RootStage::InFlight)
        )
    }

    /// Mark the root verification as in-flight so duplicate dispatch is
    /// avoided until the result lands.
    fn mark_root_in_flight(&mut self, block_hash: BlockHash, kind: VerificationKind) {
        self.roots.insert((block_hash, kind), RootStage::InFlight);
    }

    /// Whether a verification of `kind` was ever dispatched for
    /// `block_hash` — in flight or complete. [`Self::is_block_verified`]
    /// keys demand-dependent kinds on this, since the requirement is
    /// derived at dispatch time from inputs the pipeline does not hold.
    fn is_root_tracked(&self, block_hash: BlockHash, kind: VerificationKind) -> bool {
        self.roots.contains_key(&(block_hash, kind))
    }

    /// One check on `block_hash` answered in the block's favour.
    ///
    /// The state root's completion is also what makes the block's tree
    /// readable, so it releases the children deferred on it, the
    /// proposal parked on its tree, and the walk parked on its substate
    /// delta. Any completion may be the last the assembly waits on.
    pub fn checked(&mut self, block_hash: BlockHash, kind: VerificationKind) {
        self.roots.insert((block_hash, kind), RootStage::Verified);
        debug!(?kind, ?block_hash, "Block check passed");
        if kind == VerificationKind::StateRoot {
            self.release_deferred_children(block_hash);
            self.try_unblock_proposal(block_hash);
            self.release_substate_park(block_hash);
        }
        self.try_complete_assembly(block_hash);
    }

    /// One check on `block_hash` answered against it. The stage is
    /// dropped, and so is whatever was parked on the block's success:
    /// a refused beacon-witness root drops the children whose walk
    /// deferred on it, a refused state root drops the verifications
    /// deferred on its tree, since neither can ever unblock.
    pub fn refused(&mut self, block_hash: BlockHash, kind: VerificationKind) {
        self.roots.remove(&(block_hash, kind));
        match kind {
            VerificationKind::BeaconWitnessRoot => {
                self.discard_deferred_beacon_witness_children(block_hash);
            }
            VerificationKind::StateRoot => {
                if let Some(orphans) = self.deferred_state_root_verifications.remove(&block_hash) {
                    warn!(
                        block_hash = ?block_hash,
                        orphaned_count = orphans.len(),
                        "Clearing deferred state root verifications — parent failed"
                    );
                }
            }
            _ => {}
        }
    }

    /// One check on `block_hash` could not be answered here yet. The
    /// in-flight mark clears, so the next re-drive of the vote
    /// dispatches it again rather than reading it as still running.
    pub fn deferred(&mut self, block_hash: BlockHash, kind: VerificationKind) {
        self.roots.remove(&(block_hash, kind));
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

    /// Start tracking `block` as awaiting a [`Verified<CertifiedBlock>`]:
    /// its QC, and every check it demands. A block already tracked keeps
    /// the QC it has.
    pub fn track_pending_assembly(&mut self, block: Arc<Block>) {
        self.pending_assemblies
            .entry(block.hash())
            .or_insert(PendingAssembly { block, qc: None });
    }

    /// Populate the QC slot for `block_hash`'s pending assembly. When the
    /// last outstanding check has already landed, the entry is removed
    /// and a [`Verified<CertifiedBlock>`] is produced by feeding the
    /// verified header and the demands witness into
    /// [`Verified::<Block>::assemble`], then linking the verified block
    /// with the QC via [`Verified::<CertifiedBlock>::assemble`]. Returns
    /// `None` when no assembly is tracked for `block_hash`, or when a
    /// check is still outstanding.
    pub fn record_qc_assembly(
        &mut self,
        block_hash: BlockHash,
        qc: Verified<QuorumCertificate>,
    ) -> Option<Result<Arc<Verified<CertifiedBlock>>, AssemblyError>> {
        let entry = self.pending_assemblies.get_mut(&block_hash)?;
        entry.qc = Some(qc);
        self.try_complete_assembly(block_hash)
    }

    fn try_complete_assembly(
        &mut self,
        block_hash: BlockHash,
    ) -> Option<Result<Arc<Verified<CertifiedBlock>>, AssemblyError>> {
        let entry = self.pending_assemblies.get(&block_hash)?;
        if entry.qc.is_none() || !self.outstanding(&entry.block).is_empty() {
            return None;
        }
        let entry = self.pending_assemblies.remove(&block_hash)?;
        let demands = self.demands_of(&entry.block);
        let block = Arc::try_unwrap(entry.block).unwrap_or_else(|arc| (*arc).clone());
        let qc = entry
            .qc
            .expect("completion check just confirmed the QC is held");

        let parent_qc_raw = block.header().parent_qc();
        let parent_qc_verified = if parent_qc_raw.is_genesis() {
            Verified::<QuorumCertificate>::genesis(parent_qc_raw.shard_id(), self.chain_origin)
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
            Verified::<Demands>::from_pipeline_attestation(demands),
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

    /// The whole verified-certified cache, for the beacon-witness
    /// ancestor walk's fallback over sync-admitted uncommitted blocks.
    pub(crate) const fn verified_certified_blocks(
        &self,
    ) -> &HashMap<BlockHash, Arc<Verified<CertifiedBlock>>> {
        &self.verified_certified_blocks
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
        !self.deferred_state_root_verifications.is_empty()
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
        self.is_root_verified(*block_hash, VerificationKind::StateRoot)
    }

    /// Every check `block` demands: its own, plus the reservations the
    /// coordinator derived for it, which are a fact of this shard's
    /// payers rather than of the block and so are known only once
    /// dispatched.
    fn demands_of(&self, block: &Block) -> Demands {
        let demands = block.demands();
        if self.is_root_tracked(block.hash(), VerificationKind::Reservations) {
            demands.with(VerificationKind::Reservations)
        } else {
            demands
        }
    }

    /// The checks `block` demands that have not passed.
    pub fn outstanding(&self, block: &Block) -> BTreeSet<VerificationKind> {
        let block_hash = block.hash();
        self.demands_of(block)
            .outstanding(|kind| self.is_root_verified(block_hash, kind))
    }

    /// Whether every check `block` demands has passed, and its drain
    /// total was re-derived and matched.
    pub fn is_block_verified(&self, block: &Block) -> bool {
        self.outstanding(block).is_empty() && self.verified_in_flight.contains(&block.hash())
    }

    /// Log why a block's verification is incomplete. Called on view change
    /// to explain why the current block couldn't be voted on in time.
    pub fn log_incomplete_verification(&self, block: &Block) {
        let block_hash = block.hash();
        let stage = |kind: VerificationKind| -> &'static str {
            if self.is_root_verified(block_hash, kind) {
                "verified"
            } else if self.is_root_in_flight(block_hash, kind) {
                "in_flight"
            } else {
                match kind {
                    VerificationKind::StateRoot
                        if self
                            .deferred_state_root_verifications
                            .values()
                            .any(|v| v.iter().any(|r| r.block_hash == block_hash)) =>
                    {
                        "deferred(parent)"
                    }
                    VerificationKind::BeaconWitnessRoot => match self
                        .beacon_witness_defer(block_hash)
                    {
                        Some((_, BeaconWitnessDefer::WitnessAncestor)) => {
                            "deferred(witness_ancestor)"
                        }
                        Some((_, BeaconWitnessDefer::SubstateCount)) => "deferred(substate_count)",
                        Some((_, BeaconWitnessDefer::ParentRevealChain)) => {
                            "deferred(parent_reveal_chain)"
                        }
                        None => "NOT_STARTED",
                    },
                    _ => "NOT_STARTED",
                }
            }
        };
        let checks: Vec<(VerificationKind, &'static str)> = self
            .demands_of(block)
            .iter()
            .map(|kind| (kind, stage(kind)))
            .collect();
        let beacon_witness_blocker = self
            .beacon_witness_defer(block_hash)
            .map(|(blocker, _)| blocker);
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
            ?checks,
            ?beacon_witness_blocker,
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

        !self.is_root_tracked(block_hash, VerificationKind::StateRoot)
            && !self
                .deferred_state_root_verifications
                .values()
                .any(|v| v.iter().any(|r| r.block_hash == block_hash))
    }

    /// Push a `PendingStateRootVerification` onto the ready queue and mark
    /// both state-root and receipt-root as in-flight. The receipt-root
    /// in-flight marker tracks the same dispatch lifecycle as state-root —
    /// the unified `VerifyStateRoot` handler emits both events.
    fn enqueue_ready_state_root(&mut self, ready: PendingStateRootVerification) {
        self.roots.insert(
            (ready.block_hash, VerificationKind::StateRoot),
            RootStage::InFlight,
        );
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
    /// is captured; `parent_state_root` and `finalizations` are resolved
    /// freshly at drain time to avoid stale-snapshot races where an entry
    /// deferred before its parent committed would dispatch with the wrong
    /// base state.
    #[allow(clippy::too_many_arguments)] // block identity + per-window verdict bits
    pub fn initiate_state_root_verification(
        &mut self,
        block_hash: BlockHash,
        block: &Block,
        parent_block_height: BlockHeight,
        split_child_roots_required: bool,
        terminal_roots_required: bool,
        settled_txs_window_floor: Option<WeightedTimestamp>,
    ) {
        let parent_block_hash = block.header().parent_block_hash();
        let ready = PendingStateRootVerification {
            block_hash,
            parent_block_hash,
            parent_block_height,
            expected_root: block.header().state_root(),
            expected_local_receipt_root: block.header().local_receipt_root(),
            block_height: block.height(),
            claimed_split_child_roots: block.header().split_child_roots(),
            split_child_roots_required,
            terminal_roots_required,
            claimed_terminal_roots: block.header().terminal_roots(),
            parent_weighted_timestamp: block.header().parent_qc().weighted_timestamp(),
            settled_txs_window_floor,
        };

        // The parent's tree nodes must be available — either committed to
        // the tree store or in the snapshot cache (from a prior verification).
        // Defer if: parent height exceeds committed JMT AND parent hasn't
        // been verified (no snapshot in the overlay).
        if self.parent_tree_available(parent_block_height, parent_block_hash) {
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

    /// Mark every check the proposer's own block demands as passed.
    ///
    /// The proposer built the block, so every root it claims — the
    /// beacon witness root it derived from its own accumulator among
    /// them — is inherently correct, and its state root is what
    /// populates the overlay chain for child blocks to verify against
    /// before it commits. Without this a view change would report the
    /// checks as `NOT_STARTED`, since the proposer path bypasses
    /// `try_vote_on_block`.
    pub fn mark_proposal_fully_verified(&mut self, block: &Block) {
        let block_hash = block.hash();
        for kind in block.demands().iter() {
            self.roots.insert((block_hash, kind), RootStage::Verified);
        }
        self.release_deferred_children(block_hash);
        self.try_unblock_proposal(block_hash);
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
        late_deliveries: HashSet<TxHash>,
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
            late_deliveries,
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
            batch_hashes: manifest.provision_hashes().clone(),
        }]
    }

    /// Initiate provision tx-root verification for a block.
    pub fn initiate_provision_tx_root_verification(
        &mut self,
        block_hash: BlockHash,
        block: &Block,
        topology_snapshot: &TopologySnapshot,
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
            certificates: block.certificates().clone(),
            topology_snapshot: topology_snapshot.clone(),
        }]
    }

    /// Initiate payer-shard fee-reservation verification for a block.
    /// `demands` comes from the coordinator's chain-content derivation;
    /// callers skip the dispatch entirely when it is empty. `read_height`
    /// is the balance-read anchor: the height the block's own ancestry
    /// proves committed, so every replica verifying the block reads the
    /// same vault version. `clock` is the block's own parent-QC weighted
    /// timestamp — the transaction clock its members execute under if it
    /// commits them — which is what the payer binding's maturity
    /// comparison is judged at.
    pub fn initiate_reservations_verification(
        &mut self,
        block_hash: BlockHash,
        demands: Vec<FeeDemand>,
        read_height: BlockHeight,
        clock: WeightedTimestamp,
    ) -> Vec<Action> {
        debug!(
            ?block_hash,
            payer_count = demands.len(),
            read_height = read_height.inner(),
            "Initiating VM fee-reservation verification"
        );
        self.mark_root_in_flight(block_hash, VerificationKind::Reservations);
        vec![Action::VerifyReservations {
            block_hash,
            demands,
            read_height,
            clock,
        }]
    }

    /// Initiate the check of a block's resolutions against the bodies
    /// they name: the figures its abandonment records restate, and the
    /// deliveries its finalizations carry against the lapse at the
    /// block's anchor. Callers skip the dispatch when there is nothing to
    /// check. The handler reads each named transaction off the store and
    /// answers with a [`Resolutions`](hyperscale_types::Resolutions), which
    /// the coordinator folds into the pipeline: exact verifies, wrong or
    /// lapsed refuses, and unknown leaves the root in flight — the vote
    /// deferred, the block pending.
    pub fn initiate_resolutions_verification(
        &mut self,
        block_hash: BlockHash,
        block: &Block,
        schedule: &TopologySchedule,
    ) -> Vec<Action> {
        let anchor = block.header().parent_qc().weighted_timestamp();
        // No window, no check: the mark is not taken and no action goes
        // out, so the block stays pending and the next re-drive asks
        // again — the same shape an unknown name takes.
        let Some(window) = anchor_window(schedule, anchor) else {
            warn!(
                ?block_hash,
                ?anchor,
                "Deferring resolutions verification — no retained window carries the anchor"
            );
            return Vec::new();
        };
        let (trie, prices) = (window.shard_trie().clone(), window.prices());
        let entries: Vec<UnsettledTx> = block
            .abandonment_records()
            .iter()
            .flat_map(AbandonmentRecord::unsettled)
            .cloned()
            .collect();
        let deliveries = block.undecided_names();
        let successes = block.successes_decided_alone();
        debug!(
            ?block_hash,
            names = entries.len(),
            deliveries = deliveries.len(),
            successes = successes.len(),
            "Initiating resolutions verification"
        );
        self.mark_root_in_flight(block_hash, VerificationKind::Resolutions);
        vec![Action::VerifyResolutions {
            block_hash,
            entries,
            deliveries,
            successes,
            anchor,
            trie,
            prices,
        }]
    }

    /// Initiate beacon-witness root verification for a block, or defer
    /// it if the prospective-parent walk hits a missing/unassembled
    /// ancestor.
    ///
    /// Pure CPU check that runs in parallel with the other per-root
    /// verifiers. Pulls the deterministic inputs (`parent_witness_leaves`
    /// from the in-chain pending-block walk, `witness_sources` and
    /// `finalizations` from the block itself) so callers only thread
    /// the parts they own.
    /// The handler re-derives the leaf list and emits
    /// `BlockCheckCompleted` for the beacon witness root.
    ///
    /// When [`prospective_parent_witness_leaves`] returns `Err`, the
    /// verification is parked on the blocking ancestor's hash and the
    /// returned action list is empty. The coordinator drives the retry
    /// via [`Self::take_deferred_beacon_witness_children`] when that
    /// ancestor's own beacon-witness verification completes or when it
    /// commits.
    #[allow(clippy::too_many_arguments)] // beacon-witness verification needs the chain prefix
    pub(crate) fn initiate_beacon_witness_root_verification(
        &mut self,
        block_hash: BlockHash,
        block: &Block,
        pending_blocks: &PendingBlocks,
        accumulator: &BeaconWitnessAccumulator,
        committed_hash: BlockHash,
        committed_reveal_chain: Option<RevealChain>,
        committed_block_anchor_wt: WeightedTimestamp,
        committed_committee_anchor_wt: WeightedTimestamp,
        local_shard: ShardId,
        topology_snapshot: &TopologySnapshot,
        schedule: &TopologySchedule,
        count_source: SubstateCountSource<'_>,
    ) -> Vec<Action> {
        let header = block.header();
        let (parent_leaves_start, parent_witness_leaves) = match prospective_parent_witness_leaves(
            accumulator,
            committed_hash,
            committed_block_anchor_wt,
            header.parent_block_hash(),
            header.parent_qc().weighted_timestamp(),
            pending_blocks,
            &self.verified_certified_blocks,
            local_shard,
            schedule,
        ) {
            Ok(window) => window,
            Err(blocking_hash) => {
                self.park_beacon_witness(
                    blocking_hash,
                    block_hash,
                    BeaconWitnessDefer::WitnessAncestor,
                );
                return Vec::new();
            }
        };
        let thresholds = count_source.thresholds;
        let substate_bytes = match self.witness_substate_bytes(
            committed_hash,
            header.parent_block_hash(),
            pending_blocks,
            local_shard,
            schedule,
            &count_source,
        ) {
            Ok(bytes) => bytes,
            Err(blocking_hash) => {
                self.park_beacon_witness(
                    blocking_hash,
                    block_hash,
                    BeaconWitnessDefer::SubstateCount,
                );
                return Vec::new();
            }
        };
        let finalizations: Vec<Arc<Verifiable<Finalization>>> =
            block.certificates().iter().cloned().collect();
        debug!(
            ?block_hash,
            expected_leaf_count = header.beacon_witness_leaf_count().inner(),
            parent_leaf_count = parent_witness_leaves.len(),
            "Initiating beacon-witness root verification"
        );
        // The parent's chain and anchor, for the reveal-chain recompute. An
        // unresolvable parent parks like a blocked leaf walk rather than
        // verifying against a guessed chain.
        let parent_hash = header.parent_block_hash();
        let Some((parent_reveal_chain, committee_anchor_wt, parent_committee_anchor_wt)) = self
            .parent_reveal_anchors(
                parent_hash,
                committed_hash,
                committed_reveal_chain,
                committed_block_anchor_wt,
                committed_committee_anchor_wt,
                pending_blocks,
            )
        else {
            self.park_beacon_witness(
                parent_hash,
                block_hash,
                BeaconWitnessDefer::ParentRevealChain,
            );
            return Vec::new();
        };

        self.mark_root_in_flight(block_hash, VerificationKind::BeaconWitnessRoot);
        vec![Action::VerifyBeaconWitnessRoot {
            block_hash,
            expected_root: header.beacon_witness_root(),
            expected_leaf_count: header.beacon_witness_leaf_count(),
            claimed_base: header.beacon_witness_base(),
            claimed_reveal_chain: header.reveal_chain(),
            parent_reveal_chain,
            parent_committee_anchor_epoch: schedule.epoch_for(parent_committee_anchor_wt),
            committee_anchor_epoch: schedule.epoch_for(committee_anchor_wt),
            parent_leaves_start,
            parent_witness_leaves,
            parent_round: header.parent_qc().round(),
            height: header.height(),
            round: header.round(),
            witness_sources: Arc::clone(block.witness_sources()),
            substate_bytes,
            claimed_substate_bytes: header.load().substate_bytes,
            thresholds,
            finalizations,
            topology_snapshot: topology_snapshot.clone(),
        }]
    }

    /// Substate byte total behind the block's parent state, for the reshape
    /// predicate. `Err(blocking_hash)` when the caller must park.
    ///
    /// With reshaping disabled the predicate can never fire, so the count is
    /// irrelevant and verification proceeds without it — bit-identical to a
    /// network without the feature. Enabled, a missing ancestor delta parks
    /// the verification exactly like a missing witness ancestor — except when
    /// the walk crosses a halt recovery's sync-admitted suffix: those blocks
    /// are QC-attested but never locally executed, so no delta can ever land,
    /// and the halted tip's commit needs the successor QC this very
    /// verification gates. There the predicate is out of play (`None`) and the
    /// required assertion is absent; every replica that synced the suffix
    /// agrees byte-for-byte on its absence. The band holds through the
    /// completed recovery record — a member whose walk still crosses the
    /// suffix after the pending record clears on the first crossing must not
    /// start parking, or the circular drain wedges it permanently. A
    /// sync-admitted block outside the band — an ordinary lagging replica's
    /// local state, whatever the shard's recovery history — parks as usual and
    /// commits from the live quorum drain it.
    fn witness_substate_bytes(
        &self,
        committed_hash: BlockHash,
        parent_block_hash: BlockHash,
        pending_blocks: &PendingBlocks,
        local_shard: ShardId,
        schedule: &TopologySchedule,
        count_source: &SubstateCountSource<'_>,
    ) -> Result<Option<u64>, BlockHash> {
        if count_source.thresholds == ReshapeThresholds::DISABLED {
            return Ok(None);
        }
        match count_source.count_behind(
            committed_hash,
            parent_block_hash,
            pending_blocks,
            &self.verified_certified_blocks,
        ) {
            Ok(count) => Ok(count),
            Err(SubstateCountBlocked::SyncAdmitted(blocking_hash))
                if self
                    .verified_certified_blocks
                    .get(&blocking_hash)
                    .is_some_and(|certified| {
                        schedule.recovery_suffix_band(
                            local_shard,
                            certified.block().header().parent_qc().weighted_timestamp(),
                            certified.qc().weighted_timestamp(),
                        )
                    }) =>
            {
                Ok(None)
            }
            Err(blocked) => Err(blocked.blocking_hash()),
        }
    }

    /// The parent header's reveal chain and the two committee anchors the
    /// reveal-chain recompute keys on: the block's own (the parent's
    /// [`block_anchor`](Self::block_anchor)) and its parent's (the
    /// grandparent's).
    ///
    /// Resolves through the same two caches the leaf walk uses; when a block
    /// is the committed tip (pruned from both) the coordinator's scalars
    /// answer. `None` when no route resolves either.
    fn parent_reveal_anchors(
        &self,
        parent_hash: BlockHash,
        committed_hash: BlockHash,
        committed_reveal_chain: Option<RevealChain>,
        committed_block_anchor_wt: WeightedTimestamp,
        committed_committee_anchor_wt: WeightedTimestamp,
        pending_blocks: &PendingBlocks,
    ) -> Option<(RevealChain, WeightedTimestamp, WeightedTimestamp)> {
        if let Some(parent) = self.held_header(parent_hash, pending_blocks) {
            let grandparent_anchor = self.block_anchor(
                parent.parent_block_hash(),
                committed_hash,
                committed_block_anchor_wt,
                pending_blocks,
            )?;
            return Some((
                parent.reveal_chain(),
                parent.parent_qc().weighted_timestamp(),
                grandparent_anchor,
            ));
        }
        (parent_hash == committed_hash)
            .then_some(committed_reveal_chain)
            .flatten()
            .map(|chain| {
                (
                    chain,
                    committed_block_anchor_wt,
                    committed_committee_anchor_wt,
                )
            })
    }

    /// A block's own position on the weighted-time grid — its parent QC's
    /// weighted timestamp, read off a held header or the committed-tip
    /// scalar. Mirrors the coordinator's helper of the same name.
    fn block_anchor(
        &self,
        block_hash: BlockHash,
        committed_hash: BlockHash,
        committed_block_anchor_wt: WeightedTimestamp,
        pending_blocks: &PendingBlocks,
    ) -> Option<WeightedTimestamp> {
        if block_hash == committed_hash {
            return Some(committed_block_anchor_wt);
        }
        self.held_header(block_hash, pending_blocks)
            .map(|header| header.parent_qc().weighted_timestamp())
    }

    /// A header from the pending map, falling back to the verified-certified
    /// cache where a sync-admitted block sits.
    fn held_header<'a>(
        &'a self,
        block_hash: BlockHash,
        pending_blocks: &'a PendingBlocks,
    ) -> Option<&'a BlockHeader> {
        pending_blocks
            .get(block_hash)
            .map(PendingBlock::header)
            .or_else(|| {
                self.verified_certified_blocks
                    .get(&block_hash)
                    .map(|certified| certified.block().header())
            })
    }

    /// Park `block_hash`'s beacon-witness verification on `blocking_hash`,
    /// tagged with which walk parked it. A persistent blocker surfaces at
    /// warn level through the view-change incomplete report, which names
    /// the kind and the blocker.
    fn park_beacon_witness(
        &mut self,
        blocking_hash: BlockHash,
        block_hash: BlockHash,
        kind: BeaconWitnessDefer,
    ) {
        debug!(
            ?block_hash,
            ?blocking_hash,
            ?kind,
            "Deferring beacon-witness verification — blocker not yet available"
        );
        self.deferred_beacon_witness_verifications
            .entry(blocking_hash)
            .or_default()
            .push((block_hash, kind));
    }

    /// Parents with children parked on them. The coordinator retries
    /// every entry when the byte frontier reconciles from persistence
    /// — the blocker for a frontier-lagged park is the committed tip,
    /// which no per-block completion event names.
    pub(crate) fn deferred_beacon_witness_parents(&self) -> Vec<BlockHash> {
        self.deferred_beacon_witness_verifications
            .keys()
            .copied()
            .collect()
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
            .into_iter()
            .map(|(child, _)| child)
            .collect()
    }

    /// Park `block_hash`'s beacon-witness verification until the beacon
    /// advances far enough to resolve its governing committee. The blocker
    /// is beacon progress, not a shard ancestor, so no shard event drains
    /// this — [`Self::take_beacon_witness_awaiting_committee`] does, on
    /// beacon advance.
    pub(crate) fn park_beacon_witness_awaiting_committee(&mut self, block_hash: BlockHash) {
        self.beacon_witness_awaiting_committee.insert(block_hash);
    }

    /// Drain the blocks parked awaiting a beacon-resolvable committee. The
    /// caller re-initiates each; any still beacon-behind re-parks itself.
    pub(crate) fn take_beacon_witness_awaiting_committee(&mut self) -> Vec<BlockHash> {
        self.beacon_witness_awaiting_committee.drain().collect()
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

    /// The blocker and walk kind a block's beacon-witness verification is
    /// currently parked on, if any.
    fn beacon_witness_defer(
        &self,
        block_hash: BlockHash,
    ) -> Option<(BlockHash, BeaconWitnessDefer)> {
        self.deferred_beacon_witness_verifications
            .iter()
            .find_map(|(blocker, children)| {
                children
                    .iter()
                    .find(|(child, _)| *child == block_hash)
                    .map(|(_, kind)| (*blocker, *kind))
            })
    }

    /// Whether a block's beacon-witness verification is currently
    /// parked on a missing/unassembled ancestor.
    fn is_beacon_witness_deferred(&self, block_hash: BlockHash) -> bool {
        self.beacon_witness_defer(block_hash).is_some()
    }
}

/// Which verification walk parked a block on a blocking ancestor. The two
/// wedge differently — a witness ancestor resolves when its own
/// verification or commit lands; a substate byte delta can be permanently
/// unobtainable for a sync-admitted block — so the incomplete-verification
/// report names the kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BeaconWitnessDefer {
    /// [`prospective_parent_witness_leaves`] could not produce the parent
    /// leaf window.
    WitnessAncestor,
    /// The reshape predicate's substate byte walk crossed a block with no
    /// known delta (see [`SubstateCountBlocked`]).
    SubstateCount,
    /// The parent header carrying the reveal chain this block extends is
    /// held by neither cache, and is not the committed tip whose scalar
    /// would answer.
    ParentRevealChain,
}

/// Inputs for resolving the substate byte total behind a block's parent —
/// the load the reshape predicate evaluates. Borrowed from the shard
/// coordinator's byte frontier and per-block delta tracking.
#[derive(Clone, Copy)]
pub struct SubstateCountSource<'a> {
    /// Network reshape thresholds, from the schedule's chain config.
    pub thresholds: ReshapeThresholds,
    /// Highest height with a known committed substate byte total, and that
    /// count.
    pub frontier: (BlockHeight, u64),
    /// The committed tip the pending chain hangs off.
    pub committed_height: BlockHeight,
    /// Net substate delta per uncommitted block.
    pub deltas: &'a HashMap<BlockHash, i64>,
}

/// Why a substate-byte resolution blocked
/// ([`SubstateCountSource::count_behind`]).
///
/// Neither arm covers an *absent* total: a parent whose own resolution was
/// out of play is answered `Ok(None)` instead, because that is a settled
/// fact rather than something a caller can wait out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubstateCountBlocked {
    /// The parent's content or execution delta is still in flight — the
    /// caller parks on it; its completion (or its commit) re-drives the
    /// resolution.
    Outstanding(BlockHash),
    /// The parent is a sync-admitted certified block: QC-attested but never
    /// locally executed, so no byte delta can ever land for it — only its
    /// commit (whose persistence reconciles the frontier from storage)
    /// resolves it. For a block inside a halt
    /// recovery's suffix band (pending or completed —
    /// `TopologySchedule::recovery_suffix_band`), every replica that
    /// synced the suffix agrees on the absent delta, so the caller
    /// suppresses the reshape assertion; outside the band it is one
    /// lagging replica's local state, and the caller parks as for
    /// [`Self::Outstanding`].
    SyncAdmitted(BlockHash),
}

impl SubstateCountBlocked {
    /// The block whose progress unblocks the resolution, whichever way it
    /// blocked — the hash callers park on.
    pub const fn blocking_hash(self) -> BlockHash {
        match self {
            Self::Outstanding(hash) | Self::SyncAdmitted(hash) => hash,
        }
    }
}

impl SubstateCountSource<'_> {
    /// Substate count behind `parent_hash`'s post-state.
    ///
    /// A one-step recurrence rather than a walk: every header attests the
    /// byte total behind *its* parent, so the total behind `parent_hash` is
    /// the parent's own attested claim advanced by the parent's byte delta.
    /// A committed parent skips even that and reads the reconciled frontier.
    /// Only the parent is consulted; a block never waits on deltas for
    /// ancestors above it.
    ///
    /// Trusting the parent's claim rests on the parent's own vote having
    /// checked it against this same recurrence: a poisoned claim never
    /// certifies, so no descendant of one commits, and descendants agree
    /// with each other regardless because they read the same field. This is
    /// the argument `beacon_witness_base` already makes for reading the
    /// window base off the header instead of rebuilding beacon state.
    ///
    /// `Err` classifies the blocked resolution — the parent's delta still
    /// outstanding (or, for a frontier lagging the tip, the tip's
    /// persistence reconcile), or a parent whose delta can never land.
    pub fn count_behind(
        &self,
        committed_hash: BlockHash,
        parent_hash: BlockHash,
        pending_blocks: &PendingBlocks,
        certified_blocks: &HashMap<BlockHash, Arc<Verified<CertifiedBlock>>>,
    ) -> Result<Option<u64>, SubstateCountBlocked> {
        if parent_hash == committed_hash {
            if self.frontier.0 != self.committed_height {
                return Err(SubstateCountBlocked::Outstanding(committed_hash));
            }
            return Ok(Some(self.frontier.1));
        }
        let Some(parent) = pending_blocks
            .get(parent_hash)
            .map(PendingBlock::header)
            .or_else(|| {
                certified_blocks
                    .get(&parent_hash)
                    .map(|certified| certified.block().header())
            })
        else {
            return Err(SubstateCountBlocked::Outstanding(parent_hash));
        };
        // The parent's own claim is the total behind *its* parent, already
        // checked against this same recurrence when the parent was voted —
        // so one delta closes the gap and no ancestor beyond the parent is
        // consulted.
        //
        // An absent claim is a resolved fact, not a gap: the parent's own
        // resolution was out of play, so every descendant's is too until a
        // committed parent reads the reconciled frontier instead. Answering
        // `Ok(None)` rather than blocking matters — a caller that parked
        // here would wait on a value that can never arrive.
        let Some(behind_parent) = parent.load().substate_bytes else {
            return Ok(None);
        };
        let Some(delta) = self.deltas.get(&parent_hash) else {
            // A certified block that was never executed locally has no delta
            // and never will; only its commit resolves the walk.
            if certified_blocks.contains_key(&parent_hash) {
                return Err(SubstateCountBlocked::SyncAdmitted(parent_hash));
            }
            return Err(SubstateCountBlocked::Outstanding(parent_hash));
        };
        Ok(Some(
            behind_parent
                .checked_add_signed(*delta)
                .expect("substate byte total must not go negative"),
        ))
    }
}

impl VerificationPipeline {
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
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)] // one dispatch over the per-root verifiers
    pub(crate) fn initiate_block_verifications(
        &mut self,
        topology_snapshot: &TopologySnapshot,
        schedule: &TopologySchedule,
        local_shard: ShardId,
        pending_blocks: &PendingBlocks,
        accumulator: &BeaconWitnessAccumulator,
        committed_hash: BlockHash,
        committed_reveal_chain: Option<RevealChain>,
        committed_block_anchor_wt: WeightedTimestamp,
        committed_committee_anchor_wt: WeightedTimestamp,
        block_hash: BlockHash,
        block: &Block,
        count_source: SubstateCountSource<'_>,
        split_child_roots_required: bool,
        terminal_roots_required: bool,
        fee_demands: Vec<FeeDemand>,
        fee_read_height: BlockHeight,
        fee_read_ready: bool,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        let h = block.header();
        let anchor = h.parent_qc().weighted_timestamp();
        let wanted: Vec<VerificationKind> = self
            .outstanding(block)
            .into_iter()
            .filter(|&kind| !self.is_root_in_flight(block_hash, kind))
            .collect();

        for kind in wanted {
            match kind {
                // The state root's own deferred queue is the second
                // place it may already be waiting.
                VerificationKind::StateRoot => {
                    if self.needs_state_root_verification(block) {
                        self.initiate_state_root_verification(
                            block_hash,
                            block,
                            h.parent_qc().height(),
                            split_child_roots_required,
                            terminal_roots_required,
                            schedule.settled_window_floor(local_shard, anchor),
                        );
                    }
                }
                VerificationKind::TransactionRoot => {
                    let late = late_deliveries(block.transactions(), schedule, anchor, local_shard);
                    actions.extend(
                        self.initiate_transaction_root_verification(block_hash, block, late),
                    );
                }
                VerificationKind::ProvisionRoot => {
                    if let Some(pending) = pending_blocks.get(block_hash) {
                        actions.extend(self.initiate_provision_root_verification(
                            block_hash,
                            block,
                            pending.manifest(),
                        ));
                    }
                }
                VerificationKind::CertificateRoot => {
                    actions.extend(self.initiate_certificate_root_verification(block_hash, block));
                }
                VerificationKind::ProvisionTxRoots => {
                    actions.extend(self.initiate_provision_tx_root_verification(
                        block_hash,
                        block,
                        topology_snapshot,
                    ));
                }
                // The state root's replay checks the receipts first and
                // answers for both; reservations are demanded only once
                // dispatched below, so neither is ever dispatched here.
                VerificationKind::LocalReceiptRoot | VerificationKind::Reservations => {}
                VerificationKind::Resolutions => {
                    actions.extend(
                        self.initiate_resolutions_verification(block_hash, block, schedule),
                    );
                }
                VerificationKind::BeaconWitnessRoot => {
                    if !self.is_beacon_witness_deferred(block_hash) {
                        actions.extend(self.initiate_beacon_witness_root_verification(
                            block_hash,
                            block,
                            pending_blocks,
                            accumulator,
                            committed_hash,
                            committed_reveal_chain,
                            committed_block_anchor_wt,
                            committed_committee_anchor_wt,
                            local_shard,
                            topology_snapshot,
                            schedule,
                            count_source,
                        ));
                    }
                }
            }
        }

        // Reservations are demanded by the coordinator's derivation
        // rather than by the block, and only once: the first dispatch
        // tracks the kind, and every later pass reads it as outstanding
        // through the ordinary rule.
        if !fee_demands.is_empty()
            && !self.is_root_tracked(block_hash, VerificationKind::Reservations)
        {
            if fee_read_ready {
                actions.extend(self.initiate_reservations_verification(
                    block_hash,
                    fee_demands,
                    fee_read_height,
                    anchor,
                ));
            } else {
                // The anchor height isn't materialized locally yet — the
                // ancestry proves its commit but the commit pipeline
                // hasn't landed it. Mark the check in flight so the block
                // stays unvotable; the coordinator holds the demands and
                // re-dispatches when the commit that materializes the
                // anchor lands.
                self.mark_root_in_flight(block_hash, VerificationKind::Reservations);
            }
        }

        actions
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Drain total verification (synchronous)
    // ═══════════════════════════════════════════════════════════════════════

    /// Classify a vote-path block against the drain total it claims.
    /// The caller pre-resolves `parent_in_flight` from its chain view
    /// (`None` = parent pruned) and the finalized-tx count from the pending
    /// block, then uses the returned [`InFlightCheck`] to decide between
    /// voting, running verifications only, or aborting.
    pub(crate) fn classify_vote_terms(
        &mut self,
        parent_in_flight: Option<TxsInFlight>,
        parent_settled_frontier: Option<BlockHeight>,
        block_hash: BlockHash,
        block: &Block,
        safe_vote_declined: bool,
    ) -> InFlightCheck {
        if safe_vote_declined {
            return InFlightCheck::SkipVote;
        }

        let (Some(parent_in_flight), Some(parent_settled_frontier)) =
            (parent_in_flight, parent_settled_frontier)
        else {
            trace!(
                block_hash = ?block_hash,
                "Skipping vote — parent pruned, still verifying for PreparedCommit"
            );
            return InFlightCheck::SkipVote;
        };

        if self.verify_in_flight(block_hash, block, parent_in_flight)
            && Self::verify_settled_order(block_hash, block, parent_settled_frontier)
        {
            InFlightCheck::Proceed
        } else {
            InFlightCheck::Abort
        }
    }

    /// Verify the block claims the settlement frontier its determined
    /// halves leave: where the last of them settles, or the parent's
    /// frontier where it carries none. That the halves rise strictly
    /// above the parent's frontier is admission's rule, judged before
    /// this.
    pub fn verify_settled_order(
        block_hash: BlockHash,
        block: &Block,
        parent_settled_frontier: BlockHeight,
    ) -> bool {
        let frontier = block
            .certificates()
            .iter()
            .map(|fw| fw.as_unverified())
            .filter(|fw| fw.is_determined())
            .map(|fw| fw.tick_id().block_height())
            .max()
            .unwrap_or(parent_settled_frontier);
        let proposed = block.header().settled_tick_frontier();
        if proposed == frontier {
            true
        } else {
            warn!(
                block_hash = ?block_hash,
                height = block.height().inner(),
                proposed = proposed.inner(),
                expected = frontier.inner(),
                parent_settled_frontier = parent_settled_frontier.inner(),
                "Settlement frontier verification failed — proposed value does not match expected"
            );
            false
        }
    }

    /// Verify the proposed drain total is deterministically correct.
    ///
    /// `txs_in_flight` = parent's + what this block's transactions
    /// reserve - what its certificates return.
    ///
    /// Both terms are read off the block itself, so every validator
    /// reaches the same figure with no history behind it — including one
    /// that snap-synced past the transactions being released.
    pub fn verify_in_flight(
        &mut self,
        block_hash: BlockHash,
        block: &Block,
        parent_in_flight: TxsInFlight,
    ) -> bool {
        let proposed = block.header().txs_in_flight();
        let expected = parent_in_flight
            .saturating_add(block.transactions().len() as u64)
            .saturating_sub(block.certificates().iter().fold(0u64, |total, fw| {
                total.saturating_add(fw.as_unverified().released())
            }));

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
                "Drain total verification failed — proposed value does not match expected"
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
    /// with a fresh `parent_state_root` and `finalizations` snapshot.
    /// Capturing these eagerly produced a stale-snapshot race: an entry
    /// deferred before its parent committed would still hold the
    /// pre-commit `parent_state_root`, causing the dispatched verification
    /// to compute against the grandparent's base state.
    pub(crate) fn take_ready_state_root_verifications(
        &mut self,
    ) -> Vec<PendingStateRootVerification> {
        std::mem::take(&mut self.ready_state_root_verifications)
    }

    /// Resolve one taken entry's dispatch inputs against the caller's chain
    /// view — `parent_state_root` and `finalizations` freshly at drain
    /// time, avoiding stale-snapshot races where an entry deferred before
    /// its parent committed would dispatch with the wrong base state.
    /// `None` when the pending block was removed between queue-up and drain
    /// (a sibling verification fails, view change, etc.) — dispatching with
    /// empty `finalizations` would recompute the wrong state root against
    /// ghost inputs.
    pub(crate) fn resolve_ready_state_root_verification(
        pending: &PendingStateRootVerification,
        chain: &ChainView<'_>,
    ) -> Option<ReadyStateRootVerification> {
        let block = chain.get_block(pending.block_hash).or_else(|| {
            debug!(
                block_hash = ?pending.block_hash,
                "Skipping state root verification — block no longer present"
            );
            None
        })?;
        let parent_state_root = chain.parent_state_root(pending.parent_block_hash);
        let finalizations: Vec<Arc<Verifiable<Finalization>>> =
            block.certificates().iter().cloned().collect();
        let block_tx_hashes: Vec<TxHash> =
            block.transactions().iter().map(|tx| tx.hash()).collect();
        let creations = committed_cells_for(block);
        Some(ReadyStateRootVerification {
            block_hash: pending.block_hash,
            parent_block_hash: pending.parent_block_hash,
            parent_state_root,
            parent_block_height: pending.parent_block_height,
            expected_root: pending.expected_root,
            expected_local_receipt_root: pending.expected_local_receipt_root,
            finalizations,
            block_tx_hashes,
            creations,
            block_height: pending.block_height,
            claimed_split_child_roots: pending.claimed_split_child_roots,
            split_child_roots_required: pending.split_child_roots_required,
            terminal_roots_required: pending.terminal_roots_required,
            claimed_terminal_roots: pending.claimed_terminal_roots,
            parent_weighted_timestamp: pending.parent_weighted_timestamp,
            settled_txs_window_floor: pending.settled_txs_window_floor,
            parent_sweep_frontier: chain.parent_sweep_frontier(pending.parent_block_hash),
            claimed_sweep_frontier: block.header().sweep_frontier(),
        })
    }

    /// Check whether a deferred proposal was unblocked and should be retried.
    /// Returns `true` once, then resets. Caller re-enters `try_propose` with
    /// fresh transaction selection.
    pub fn take_ready_proposal(&mut self) -> bool {
        let ready = std::mem::take(&mut self.proposal_unblocked);
        if ready {
            // The re-entry re-runs the substate walk from the committed tip
            // and parks again on whatever is still outstanding, so any
            // existing park is stale.
            self.deferred_substate_ancestor = None;
        }
        ready
    }

    /// Latch a proposal-retry attempt for after the current dispatch.
    /// Idempotent within a single dispatch; the post-dispatch drain calls
    /// `try_propose` once regardless of how many times this is set.
    pub const fn queue_ready_proposal(&mut self) {
        self.proposal_unblocked = true;
    }

    /// Check if a parent's tree nodes are available: persisted, or
    /// verified with its JMT snapshot in the `PendingChain` overlay.
    /// Verification is the same act on a live block and a sync-admitted
    /// one, so a verified parent always has a tree to build on.
    pub fn parent_tree_available(
        &self,
        parent_block_height: BlockHeight,
        parent_block_hash: BlockHash,
    ) -> bool {
        parent_block_height <= self.last_persisted_height
            || self.is_state_root_verified(&parent_block_hash)
    }

    /// Release the children deferred on `parent_block_hash` now that its
    /// tree is in the overlay.
    fn release_deferred_children(&mut self, parent_block_hash: BlockHash) {
        let Some(deferred) = self
            .deferred_state_root_verifications
            .remove(&parent_block_hash)
        else {
            return;
        };
        for ready in deferred {
            debug!(
                child = ?ready.block_hash,
                parent = ?parent_block_hash,
                "Unblocking deferred state root verification"
            );
            self.enqueue_ready_state_root(ready);
        }
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

    /// Record that a proposal is parked on `ancestor`'s substate byte delta.
    /// Replaces any prior park: a released walk re-runs from the committed
    /// tip and blocks on whichever ancestor is still outstanding, which may
    /// be an earlier one than last time.
    pub fn defer_proposal_on_substate(&mut self, ancestor: BlockHash) {
        debug!(
            ancestor = ?ancestor,
            "Parking proposal — substate byte delta outstanding"
        );
        self.deferred_substate_ancestor = Some(ancestor);
    }

    /// `block_hash`'s substate byte delta is now resolvable — its state root
    /// verified, or it committed. Release a proposal parked on it.
    fn release_substate_park(&mut self, block_hash: BlockHash) {
        if self.deferred_substate_ancestor == Some(block_hash) {
            self.deferred_substate_ancestor = None;
            debug!(ancestor = ?block_hash, "Unparking proposal — substate delta landed");
            self.proposal_unblocked = true;
        }
    }

    /// The substate byte frontier reconciled from storage. Releases the park
    /// unconditionally: a walk blocked on a frontier lagging the committed
    /// tip names that tip, not a block whose delta this could be matched
    /// against. Sync commits carry no delta, so this is the only edge that
    /// resolves a proposal parked behind one.
    pub fn release_substate_park_on_reconcile(&mut self) {
        if self.deferred_substate_ancestor.take().is_some() {
            debug!("Unparking proposal — substate frontier reconciled");
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
        if self.is_state_root_verified(&block_hash) {
            return;
        }
        self.roots.insert(
            (block_hash, VerificationKind::StateRoot),
            RootStage::Verified,
        );
        self.release_deferred_children(block_hash);

        self.try_unblock_proposal(block_hash);
        // A sync-admitted block is never locally executed, so no delta can
        // land for it; its commit reconciles the frontier from storage
        // instead, which is the only edge that resolves a walk parked there.
        self.release_substate_park(block_hash);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Cleanup
    // ═══════════════════════════════════════════════════════════════════════

    /// Remove verification state for blocks no longer in `pending_blocks`
    /// or in the certified cache.
    ///
    /// Called by `ShardCoordinator::cleanup_old_state()` after it has cleaned up
    /// `pending_blocks`. We use the surviving `pending_blocks` set to determine
    /// which verification state to keep.
    ///
    /// Most verification state is keyed by block hash and cleaned up based on
    /// `pending_blocks` membership (if the block is gone, its verification state
    /// is stale). State-root state also lives for a sync-admitted block,
    /// which is never pending: it is retained with the certified cache,
    /// whose entries outlive their commit. The `verified_qcs` cache is the
    /// other exception: it's keyed by the QC's certified block hash (not
    /// the proposing block), so it uses height-based retention with a
    /// 2-block buffer to support view-change scenarios where multiple
    /// proposals share the same parent QC.
    pub fn cleanup(&mut self, pending_blocks: &PendingBlocks, committed_height: BlockHeight) {
        self.pending_qc_verifications
            .retain(|hash, _| pending_blocks.contains_key(*hash));

        // The certified cache prunes first, so what it keeps is what a
        // state-root entry may still serve.
        self.verified_certified_blocks.retain(|hash, certified| {
            pending_blocks.contains_key(*hash) || certified.block().height() > committed_height
        });
        let certified = &self.verified_certified_blocks;
        let tracked =
            |hash: BlockHash| pending_blocks.contains_key(hash) || certified.contains_key(&hash);

        self.ready_state_root_verifications
            .retain(|r| tracked(r.block_hash));

        // Clean up deferred verifications: remove entries whose child blocks
        // are no longer tracked, and remove parent keys with empty lists.
        for entries in self.deferred_state_root_verifications.values_mut() {
            entries.retain(|r| tracked(r.block_hash));
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

        // A state-root stage also lives for a sync-admitted block, which
        // is never pending: it is retained with the certified cache.
        self.roots.retain(|(hash, kind), _| {
            if *kind == VerificationKind::StateRoot {
                tracked(*hash)
            } else {
                pending_blocks.contains_key(*hash)
            }
        });

        // Drop deferred beacon-witness entries whose child has been
        // pruned. Parent keys whose values empty out are removed too.
        for children in self.deferred_beacon_witness_verifications.values_mut() {
            children.retain(|(child, _)| pending_blocks.contains_key(*child));
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

        // Retain a completed-assembly handle while its block is still pending
        // (consensus path) or still above the committed tip (sync path, which
        // caches the handle without a `pending_blocks` entry and needs it kept
        // until the round-contiguous two-chain commit drains it).
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
    use hyperscale_types::test_utils::{
        TestCommittee, make_finalization, make_finalization_awaiting, make_leg_finalization,
        make_settling_finalization, test_transaction,
    };
    use hyperscale_types::{
        AggregateSignature, DeclaredWork, TransactionDecision, Verifiable, WitnessSources,
    };

    fn disabled_count_source() -> SubstateCountSource<'static> {
        static EMPTY: std::sync::OnceLock<HashMap<BlockHash, i64>> = std::sync::OnceLock::new();
        SubstateCountSource {
            thresholds: ReshapeThresholds::DISABLED,
            frontier: (BlockHeight::GENESIS, 0),
            committed_height: BlockHeight::GENESIS,
            deltas: EMPTY.get_or_init(HashMap::new),
        }
    }
    use hyperscale_types::{
        BlockHeaderParts, Epoch, ExecutionCertificate, GlobalReceiptRoot, Hash, LocalTimestamp,
        ProposerTimestamp, QuorumCertificate, Round, ShardId, ShardLoad, SignerBitfield, TickHalf,
        TickId, Transaction, TransactionRoot, ValidatorId, WeightedTimestamp,
    };

    use super::*;
    use crate::pending::PendingBlock;

    /// The deadline holds only an execution's success decided alone. A
    /// member with a sibling to stay atomic with settles on the sibling's
    /// clock, a refusal writes no claim to reclaim against, a member
    /// settling what an execution left is past the deadline by
    /// construction, and a leg's own success decides nothing — that one
    /// is a delivery's question.
    #[test]
    fn only_an_executions_success_decided_alone_is_held_to_the_deadline() {
        let alone = test_transaction(1).hash();
        let with_sibling = test_transaction(2).hash();
        let refused = test_transaction(3).hash();
        let leg = test_transaction(4).hash();
        let settled = test_transaction(5).hash();
        let height = BlockHeight::new(3);
        let certificates: Vec<Arc<Verifiable<Finalization>>> = vec![
            Arc::new(make_finalization(height, alone, TransactionDecision::Accept).into()),
            Arc::new(
                make_finalization_awaiting(height, with_sibling, [ShardId::leaf(1, 1)]).into(),
            ),
            Arc::new(make_finalization(height, refused, TransactionDecision::Reject).into()),
            Arc::new(make_leg_finalization(height, leg).into()),
            Arc::new(make_settling_finalization(height, settled).into()),
        ];
        let block = Block::Live {
            header: BlockHeader::new(BlockHeaderParts {
                height,
                ..Default::default()
            }),
            transactions: Arc::new(Vec::new()),
            certificates: Arc::new(certificates),
            provisions: Arc::new(Vec::new()),
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
        };

        assert_eq!(block.successes_decided_alone(), vec![alone]);
        assert_eq!(block.undecided_names(), vec![leg]);
    }

    /// A single-entry schedule wrapping `snapshot` — the deferral tests
    /// never reach a per-ancestor committee resolution (the walk stops at
    /// the missing parent), so the grid contents are immaterial.
    fn dummy_schedule(snapshot: &TopologySnapshot) -> TopologySchedule {
        TopologySchedule::new(1_000, Epoch::GENESIS, Arc::new(snapshot.clone()))
    }

    /// A header stating `substate_bytes` as the total behind its parent —
    /// the claim a descendant's one-step recurrence reads.
    fn header_claiming(
        height: BlockHeight,
        parent_block_hash: BlockHash,
        in_flight: u32,
        substate_bytes: Option<u64>,
    ) -> BlockHeader {
        BlockHeader::new(BlockHeaderParts {
            height,
            parent_block_hash,
            parent_qc: QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT).into(),
            timestamp: ProposerTimestamp::from_millis(0),
            provision_tx_roots: std::collections::BTreeMap::new(),
            txs_in_flight: TxsInFlight::new(u64::from(in_flight)),
            load: ShardLoad::ZERO.advance(0, DeclaredWork::ZERO, substate_bytes),
            ..Default::default()
        })
    }

    fn block_with(
        height: BlockHeight,
        parent_block_hash: BlockHash,
        in_flight: u32,
        transactions: Vec<Arc<Verifiable<Transaction>>>,
    ) -> Block {
        block_claiming(height, parent_block_hash, in_flight, transactions, None)
    }

    fn block_claiming(
        height: BlockHeight,
        parent_block_hash: BlockHash,
        in_flight: u32,
        transactions: Vec<Arc<Verifiable<Transaction>>>,
        substate_bytes: Option<u64>,
    ) -> Block {
        Block::Live {
            header: header_claiming(height, parent_block_hash, in_flight, substate_bytes),
            transactions: Arc::new(transactions),
            certificates: Arc::new(Vec::new()),
            provisions: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
        }
    }

    /// A block settling `determined` (as determined halves) and `legs`
    /// (as legs halves), claiming `frontier`.
    fn block_settling(determined: &[u64], legs: &[u64], frontier: u64) -> Block {
        let half = |height: u64, half: TickHalf| {
            let tick_id = TickId::new(ShardId::ROOT, BlockHeight::new(height));
            let ec = ExecutionCertificate::new(
                tick_id,
                WeightedTimestamp::from_millis(height),
                GlobalReceiptRoot::ZERO,
                Vec::new(),
                AggregateSignature::ZERO,
                SignerBitfield::new(4),
            );
            Arc::new(Verifiable::from(Finalization::new(
                tick_id,
                half,
                vec![Arc::new(ec)],
                Vec::new(),
            )))
        };
        let certificates: Vec<_> = determined
            .iter()
            .map(|h| half(*h, TickHalf::Determined))
            .chain(legs.iter().map(|h| half(*h, TickHalf::Legs)))
            .collect();
        let header = BlockHeader::new(BlockHeaderParts {
            height: BlockHeight::new(100),
            parent_block_hash: BlockHash::ZERO,
            parent_qc: QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT).into(),
            timestamp: ProposerTimestamp::from_millis(0),
            provision_tx_roots: std::collections::BTreeMap::new(),
            settled_tick_frontier: BlockHeight::new(frontier),
            ..Default::default()
        });
        Block::Live {
            header,
            transactions: Arc::new(Vec::new()),
            certificates: Arc::new(certificates),
            provisions: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
        }
    }

    /// The claimed frontier is where the determined halves end, and a
    /// block claiming otherwise is refused — including one that settles
    /// nothing and claims an advance.
    #[test]
    fn the_claimed_frontier_must_be_where_the_determined_halves_end() {
        let overclaimed = block_settling(&[4], &[], 9);
        assert!(!VerificationPipeline::verify_settled_order(
            overclaimed.hash(),
            &overclaimed,
            BlockHeight::new(3)
        ));

        let idle = block_settling(&[], &[], 5);
        assert!(
            !VerificationPipeline::verify_settled_order(idle.hash(), &idle, BlockHeight::new(3)),
            "a block settling no determined half carries its parent's frontier",
        );

        let carried = block_settling(&[], &[], 3);
        assert!(VerificationPipeline::verify_settled_order(
            carried.hash(),
            &carried,
            BlockHeight::new(3)
        ));
    }

    /// Gaps are ordinary: a commit that admits nothing composes no tick,
    /// so the heights that produce determined halves are sparse and the
    /// frontier jumps over the rest.
    #[test]
    fn the_frontier_jumps_over_heights_that_composed_no_tick() {
        let block = block_settling(&[9], &[], 9);
        assert!(VerificationPipeline::verify_settled_order(
            block.hash(),
            &block,
            BlockHeight::new(2)
        ));
    }

    /// A legs half is unconstrained. It waits on a counterpart and may
    /// land arbitrarily late; its declared cells are claimed against
    /// every later tick from the moment it executes, so it has nothing
    /// to invert against — and holding it to the frontier would wedge a
    /// tick composed entirely of legs, which never advances one.
    #[test]
    fn a_legs_half_settles_whatever_the_frontier_says() {
        let stale_leg = block_settling(&[], &[1], 7);
        assert!(VerificationPipeline::verify_settled_order(
            stale_leg.hash(),
            &stale_leg,
            BlockHeight::new(7)
        ));

        let with_determined = block_settling(&[8], &[1], 8);
        assert!(VerificationPipeline::verify_settled_order(
            with_determined.hash(),
            &with_determined,
            BlockHeight::new(7)
        ));
    }

    fn empty_certified() -> &'static HashMap<BlockHash, Arc<Verified<CertifiedBlock>>> {
        static EMPTY: std::sync::OnceLock<HashMap<BlockHash, Arc<Verified<CertifiedBlock>>>> =
            std::sync::OnceLock::new();
        EMPTY.get_or_init(HashMap::new)
    }

    fn chain_view<'a>(
        committed_height: BlockHeight,
        committed_hash: BlockHash,
        latest_qc: Option<&'a Verified<QuorumCertificate>>,
        pending: &'a PendingBlocks,
    ) -> ChainView<'a> {
        ChainView::new(
            ShardId::ROOT,
            ChainOrigin::ROOT,
            committed_height,
            committed_hash,
            StateRoot::ZERO,
            None,
            latest_qc,
            pending,
            empty_certified(),
        )
    }

    fn bh(tag: &[u8]) -> BlockHash {
        BlockHash::from_raw(Hash::from_bytes(tag))
    }

    // ─── classify_vote_terms ────────────────────────────────────────

    #[test]
    fn classify_vote_terms_skips_vote_when_locked() {
        let mut vp = VerificationPipeline::new(BlockHeight::GENESIS, ChainOrigin::ROOT);
        let block = block_with(BlockHeight::new(1), BlockHash::ZERO, 0, vec![]);
        let block_hash = block.hash();

        let out = vp.classify_vote_terms(
            Some(TxsInFlight::ZERO),
            Some(BlockHeight::GENESIS),
            block_hash,
            &block,
            true,
        );
        assert!(matches!(out, InFlightCheck::SkipVote));
    }

    #[test]
    fn classify_vote_terms_skips_vote_when_parent_pruned() {
        // A pruned parent resolves no drain total: skip voting but
        // still keep verifying.
        let mut vp = VerificationPipeline::new(BlockHeight::GENESIS, ChainOrigin::ROOT);
        let block = block_with(BlockHeight::new(5), bh(b"parent"), 0, vec![]);
        let block_hash = block.hash();

        let out = vp.classify_vote_terms(None, None, block_hash, &block, false);
        assert!(matches!(out, InFlightCheck::SkipVote));
    }

    #[test]
    fn classify_vote_terms_proceeds_when_genesis_parent_and_totals_match() {
        let mut vp = VerificationPipeline::new(BlockHeight::GENESIS, ChainOrigin::ROOT);
        let block = block_with(BlockHeight::new(1), BlockHash::ZERO, 0, vec![]);
        let block_hash = block.hash();

        let out = vp.classify_vote_terms(
            Some(TxsInFlight::ZERO),
            Some(BlockHeight::GENESIS),
            block_hash,
            &block,
            false,
        );
        assert!(matches!(out, InFlightCheck::Proceed));
    }

    #[test]
    fn classify_vote_terms_aborts_on_in_flight_mismatch() {
        // Genesis parent → parent_in_flight = 0. Block claims in_flight = 5
        // with 0 transactions: proposed doesn't match expected → Abort.
        let mut vp = VerificationPipeline::new(BlockHeight::GENESIS, ChainOrigin::ROOT);
        let block = block_with(BlockHeight::new(1), BlockHash::ZERO, 5, vec![]);
        let block_hash = block.hash();

        let out = vp.classify_vote_terms(
            Some(TxsInFlight::ZERO),
            Some(BlockHeight::GENESIS),
            block_hash,
            &block,
            false,
        );
        assert!(matches!(out, InFlightCheck::Abort));
    }

    /// The drain is the count of what the block carries: a block
    /// carrying one transaction claims one place, and a block claiming
    /// any other figure is refused.
    #[test]
    fn the_drain_states_what_the_block_reserved() {
        let mut vp = VerificationPipeline::new(BlockHeight::GENESIS, ChainOrigin::ROOT);
        let tx = Arc::new(Verifiable::from(test_transaction(1)));
        let reserved = 1u32;

        let honest = block_claiming(
            BlockHeight::new(1),
            BlockHash::ZERO,
            reserved,
            vec![Arc::clone(&tx)],
            None,
        );
        let hash = honest.hash();
        assert!(matches!(
            vp.classify_vote_terms(
                Some(TxsInFlight::ZERO),
                Some(BlockHeight::GENESIS),
                hash,
                &honest,
                false
            ),
            InFlightCheck::Proceed
        ));

        // Overstating or understating it would let a shard hold places
        // the drain never saw taken or given back, so the claim has to
        // be exact rather than a bound.
        let understated = block_with(BlockHeight::new(1), BlockHash::ZERO, 2, vec![tx]);
        let hash = understated.hash();
        assert!(matches!(
            vp.classify_vote_terms(
                Some(TxsInFlight::ZERO),
                Some(BlockHeight::GENESIS),
                hash,
                &understated,
                false
            ),
            InFlightCheck::Abort
        ));
    }

    // ─── drain_ready_state_root_verifications ───────────────────────────

    #[test]
    fn drain_ready_state_root_verifications_returns_empty_when_nothing_ready() {
        let mut vp = VerificationPipeline::new(BlockHeight::GENESIS, ChainOrigin::ROOT);

        assert!(vp.take_ready_state_root_verifications().is_empty());
    }

    #[test]
    fn drain_ready_state_root_verifications_enriches_from_chain_view() {
        // Parent is at GENESIS height ≤ last_persisted_height, so initiate
        // queues this entry directly into ready_state_root_verifications.
        let mut vp = VerificationPipeline::new(BlockHeight::GENESIS, ChainOrigin::ROOT);
        let parent_block_hash = bh(b"parent");
        let block = block_with(BlockHeight::new(1), parent_block_hash, 0, vec![]);
        let block_hash = block.hash();

        vp.initiate_state_root_verification(
            block_hash,
            &block,
            BlockHeight::GENESIS,
            false,
            false,
            None,
        );

        let mut pb =
            PendingBlock::from_complete_block(&block, vec![], vec![], LocalTimestamp::ZERO);
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

        let taken = vp.take_ready_state_root_verifications();
        let out: Vec<_> = taken
            .into_iter()
            .filter_map(|pending| {
                VerificationPipeline::resolve_ready_state_root_verification(&pending, &chain)
            })
            .collect();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].block_hash, block_hash);
        assert_eq!(out[0].parent_block_hash, parent_block_hash);
        assert_eq!(out[0].parent_block_height, BlockHeight::GENESIS);

        // Taking again without another initiate yields nothing.
        assert!(vp.take_ready_state_root_verifications().is_empty());
    }

    #[test]
    fn a_synced_block_verifies_out_of_the_certified_cache() {
        // A sync-admitted block is never pending: its verification is
        // queued at admission and resolves its inputs off the certified
        // cache, so its tree lands in the overlay like a live block's.
        let mut vp = VerificationPipeline::new(BlockHeight::GENESIS, ChainOrigin::ROOT);
        let synced = block_with(BlockHeight::new(1), BlockHash::ZERO, 0, vec![]);
        let synced_hash = synced.hash();
        let qc = QuorumCertificate::new(
            synced_hash,
            ShardId::ROOT,
            BlockHeight::new(1),
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::empty(),
            AggregateSignature::ZERO,
            WeightedTimestamp::ZERO,
        );
        vp.insert_verified_certified_block(
            synced_hash,
            Arc::new(Verified::new_unchecked_for_test(
                CertifiedBlock::new_unchecked(synced.clone(), qc),
            )),
        );
        vp.initiate_state_root_verification(
            synced_hash,
            &synced,
            BlockHeight::GENESIS,
            false,
            false,
            None,
        );

        let pending = PendingBlocks::new();
        let certified = vp.verified_certified_blocks().clone();
        let chain = ChainView::new(
            ShardId::ROOT,
            ChainOrigin::ROOT,
            BlockHeight::GENESIS,
            BlockHash::ZERO,
            StateRoot::ZERO,
            None,
            None,
            &pending,
            &certified,
        );
        let resolved: Vec<_> = vp
            .take_ready_state_root_verifications()
            .into_iter()
            .filter_map(|pending| {
                VerificationPipeline::resolve_ready_state_root_verification(&pending, &chain)
            })
            .collect();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].block_hash, synced_hash);

        // Its completion is what makes a child's parent tree available.
        assert!(!vp.parent_tree_available(BlockHeight::new(1), synced_hash));
        vp.checked(synced_hash, VerificationKind::StateRoot);
        assert!(vp.parent_tree_available(BlockHeight::new(1), synced_hash));
    }

    #[test]
    fn drain_skips_entries_whose_pending_block_is_gone() {
        // A sibling verification can call `remove_pending_block` between
        // queue-up and drain. Drain must skip the orphaned entry rather than
        // dispatch with empty `finalizations` against the wrong inputs.
        let mut vp = VerificationPipeline::new(BlockHeight::GENESIS, ChainOrigin::ROOT);
        let parent_block_hash = bh(b"parent");
        let block = block_with(BlockHeight::new(1), parent_block_hash, 0, vec![]);
        let block_hash = block.hash();

        vp.initiate_state_root_verification(
            block_hash,
            &block,
            BlockHeight::GENESIS,
            false,
            false,
            None,
        );

        let empty_pending = PendingBlocks::new();
        let chain = chain_view(BlockHeight::GENESIS, BlockHash::ZERO, None, &empty_pending);

        let resolved = vp
            .take_ready_state_root_verifications()
            .into_iter()
            .filter_map(|pending| {
                VerificationPipeline::resolve_ready_state_root_verification(&pending, &chain)
            })
            .count();
        assert_eq!(
            resolved, 0,
            "entry must be skipped when its pending block was removed"
        );
    }

    // ─── substate count walk ────────────────────────────────────────────

    /// The walk classifies its blockers: an ancestor held nowhere (or a
    /// pending ancestor missing its execution delta) is `Outstanding` —
    /// the caller parks and the ancestor's completion re-drives the walk
    /// — while an ancestor found only in the verified-certified cache is
    /// `SyncAdmitted`: QC-attested, never locally executed, so no delta
    /// ever lands for it. A fully delta'd pending chain resolves to the
    /// frontier count plus the deltas.
    #[test]
    fn count_behind_classifies_walk_blockers() {
        let committed_hash = bh(b"committed");

        // The block states the total behind its own parent; the recurrence
        // advances that claim by the block's own delta.
        let block = block_claiming(BlockHeight::new(1), committed_hash, 0, vec![], Some(100));
        let block_hash = block.hash();
        let mut pb =
            PendingBlock::from_complete_block(&block, vec![], vec![], LocalTimestamp::ZERO);
        pb.construct_block()
            .expect("complete block constructs cleanly");
        let mut pending = PendingBlocks::new();
        pending.insert(pb);

        let deltas = HashMap::from([(block_hash, 7i64)]);
        let source = SubstateCountSource {
            thresholds: ReshapeThresholds { split_bytes: 1_000 },
            frontier: (BlockHeight::GENESIS, 100),
            committed_height: BlockHeight::GENESIS,
            deltas: &deltas,
        };

        // A committed parent reads the reconciled frontier and consults no
        // header at all.
        assert_eq!(
            source.count_behind(committed_hash, committed_hash, &pending, empty_certified()),
            Ok(Some(100)),
        );

        // An uncommitted parent: its attested claim plus its own delta, with
        // no ancestor above it consulted.
        assert_eq!(
            source.count_behind(committed_hash, block_hash, &pending, empty_certified()),
            Ok(Some(107)),
        );

        let missing = bh(b"missing");
        assert_eq!(
            source.count_behind(committed_hash, missing, &pending, empty_certified()),
            Err(SubstateCountBlocked::Outstanding(missing)),
        );

        // The same chain shape, but with the ancestor held only in the
        // verified-certified cache — a sync-admitted block awaiting its
        // round-contiguous commit.
        // A real header states a resolved total; what a sync-admitted block
        // lacks is the *delta*, because it was never executed locally.
        let synced = block_claiming(BlockHeight::new(1), committed_hash, 1, vec![], Some(100));
        let synced_hash = synced.hash();
        let qc = QuorumCertificate::new(
            synced_hash,
            ShardId::ROOT,
            BlockHeight::new(1),
            committed_hash,
            Round::INITIAL,
            SignerBitfield::empty(),
            AggregateSignature::ZERO,
            WeightedTimestamp::ZERO,
        );
        let certified = HashMap::from([(
            synced_hash,
            Arc::new(Verified::new_unchecked_for_test(
                CertifiedBlock::new_unchecked(synced, qc),
            )),
        )]);
        assert_eq!(
            source.count_behind(committed_hash, synced_hash, &pending, &certified),
            Err(SubstateCountBlocked::SyncAdmitted(synced_hash)),
        );

        // A parent whose own total was out of play answers `None` rather
        // than blocking: the absence is a resolved fact that propagates
        // forward, and a caller parking on it would wait for a value that
        // can never arrive.
        let out_of_play = block_claiming(BlockHeight::new(1), committed_hash, 9, vec![], None);
        let out_of_play_hash = out_of_play.hash();
        let mut opb =
            PendingBlock::from_complete_block(&out_of_play, vec![], vec![], LocalTimestamp::ZERO);
        opb.construct_block()
            .expect("complete block constructs cleanly");
        let mut with_out_of_play = PendingBlocks::new();
        with_out_of_play.insert(opb);
        assert_eq!(
            source.count_behind(
                committed_hash,
                out_of_play_hash,
                &with_out_of_play,
                empty_certified()
            ),
            Ok(None),
        );

        // A pending ancestor whose delta hasn't landed is outstanding —
        // its state-root verification is still in flight.
        let empty_deltas = HashMap::new();
        let undelta_source = SubstateCountSource {
            deltas: &empty_deltas,
            ..source
        };
        assert_eq!(
            undelta_source.count_behind(committed_hash, block_hash, &pending, empty_certified()),
            Err(SubstateCountBlocked::Outstanding(block_hash)),
        );
    }

    // ─── beacon-witness deferral ────────────────────────────────────────

    /// A block whose parent is missing from `pending_blocks` must defer
    /// beacon-witness verification (no `VerifyBeaconWitnessRoot` action
    /// emitted) and park itself on the missing ancestor's hash.
    #[test]
    fn beacon_witness_verification_defers_on_missing_ancestor() {
        use crate::beacon_witnesses::BeaconWitnessAccumulator;

        let mut vp = VerificationPipeline::new(BlockHeight::GENESIS, ChainOrigin::ROOT);
        let topology_snapshot = TestCommittee::new(4, 7).topology_snapshot(1);
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
            None,
            WeightedTimestamp::ZERO,
            WeightedTimestamp::ZERO,
            ShardId::ROOT,
            &topology_snapshot,
            &dummy_schedule(&topology_snapshot),
            disabled_count_source(),
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
        use crate::beacon_witnesses::BeaconWitnessAccumulator;

        let mut vp = VerificationPipeline::new(BlockHeight::GENESIS, ChainOrigin::ROOT);
        let topology_snapshot = TestCommittee::new(4, 7).topology_snapshot(1);
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
                None,
                WeightedTimestamp::ZERO,
                WeightedTimestamp::ZERO,
                ShardId::ROOT,
                &topology_snapshot,
                &dummy_schedule(&topology_snapshot),
                disabled_count_source(),
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
        use crate::beacon_witnesses::BeaconWitnessAccumulator;

        let mut vp = VerificationPipeline::new(BlockHeight::GENESIS, ChainOrigin::ROOT);
        let topology_snapshot = TestCommittee::new(4, 7).topology_snapshot(1);
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
            None,
            WeightedTimestamp::ZERO,
            WeightedTimestamp::ZERO,
            ShardId::ROOT,
            &topology_snapshot,
            &dummy_schedule(&topology_snapshot),
            disabled_count_source(),
        );
        assert!(vp.is_beacon_witness_deferred(child_hash));

        vp.refused(parent_block_hash, VerificationKind::BeaconWitnessRoot);
        assert!(!vp.is_beacon_witness_deferred(child_hash));
        assert!(
            vp.take_deferred_beacon_witness_children(parent_block_hash)
                .is_empty()
        );
    }

    // ─── PendingAssembly multi-slot completion ──────────────────────────

    fn assembly_block() -> Block {
        Block::genesis(
            ShardId::ROOT,
            ValidatorId::new(0),
            StateRoot::ZERO,
            ChainOrigin::ROOT,
        )
    }

    fn assembly_qc_for(block: &Block) -> QuorumCertificate {
        QuorumCertificate::new(
            block.hash(),
            ShardId::ROOT,
            BlockHeight::GENESIS,
            BlockHash::ZERO,
            Round::INITIAL,
            SignerBitfield::empty(),
            AggregateSignature::ZERO,
            WeightedTimestamp::ZERO,
        )
    }

    /// Completion fires only when the QC is held and every check the
    /// block demands has passed. A genesis block demands only the beacon
    /// witness root and the state root, so those two must land through
    /// `checked` before the QC completes the assembly.
    #[test]
    fn assembly_waits_for_every_outstanding_check() {
        let mut vp = VerificationPipeline::new(BlockHeight::GENESIS, ChainOrigin::ROOT);
        let block = assembly_block();
        let block_hash = block.hash();
        let verified_qc =
            Verified::<QuorumCertificate>::new_unchecked_for_test(assembly_qc_for(&block));

        vp.track_pending_assembly(Arc::new(block));
        assert_eq!(vp.pending_assembly_count(), 1);

        // QC arrives — beacon-witness + state root still outstanding.
        assert!(vp.record_qc_assembly(block_hash, verified_qc).is_none());
        assert_eq!(vp.pending_assembly_count(), 1);

        // Beacon-witness arrives — state root still outstanding.
        vp.checked(block_hash, VerificationKind::BeaconWitnessRoot);
        assert_eq!(vp.pending_assembly_count(), 1);
        assert!(vp.cached_verified_certified_block(block_hash).is_none());

        // State root closes out the last check; completion fires from
        // the check (not from `record_qc_assembly`), proving either path
        // can be the trigger.
        vp.checked(block_hash, VerificationKind::StateRoot);
        let linked = vp
            .cached_verified_certified_block(block_hash)
            .expect("completion fires when every check has passed");
        assert_eq!(linked.qc().block_hash(), block_hash);
        assert_eq!(vp.pending_assembly_count(), 0);
    }

    /// Checks that complete before `track_pending_assembly` runs count
    /// the same as ones that complete after: the stages are the one
    /// record, so the assembly doesn't deadlock waiting for events that
    /// already fired.
    #[test]
    fn assembly_reads_checks_that_passed_before_it_was_tracked() {
        let mut vp = VerificationPipeline::new(BlockHeight::GENESIS, ChainOrigin::ROOT);
        let block = assembly_block();
        let block_hash = block.hash();
        let verified_qc =
            Verified::<QuorumCertificate>::new_unchecked_for_test(assembly_qc_for(&block));

        // Beacon-witness + state root verify before the QC arrives.
        vp.checked(block_hash, VerificationKind::BeaconWitnessRoot);
        vp.checked(block_hash, VerificationKind::StateRoot);

        vp.track_pending_assembly(Arc::new(block));

        // QC is the only outstanding piece — completion fires immediately.
        let linked = vp
            .record_qc_assembly(block_hash, verified_qc)
            .expect("completion fires when every check has passed")
            .expect("linkage check passes for the matching qc.block_hash");
        assert_eq!(linked.qc().block_hash(), block_hash);
        assert_eq!(vp.pending_assembly_count(), 0);
    }

    /// A block with empty content but a forged non-`ZERO` root demands
    /// the check over that root: the empty-content shortcut trusts the
    /// claim only when it equals the canonical empty root, so a forged
    /// root is verified over the empty section and refused rather than
    /// passing on the proposer's say-so. A genuinely-empty sibling root
    /// demands nothing.
    #[test]
    fn a_forged_root_over_empty_content_is_demanded() {
        let forged_header = BlockHeader::new(BlockHeaderParts {
            height: BlockHeight::new(1),
            parent_block_hash: BlockHash::ZERO,
            parent_qc: QuorumCertificate::genesis(ShardId::ROOT, ChainOrigin::ROOT).into(),
            timestamp: ProposerTimestamp::from_millis(0),
            transaction_root: TransactionRoot::from_raw(Hash::from_bytes(b"forged-tx-root")),
            provision_tx_roots: std::collections::BTreeMap::new(),
            ..Default::default()
        });
        let block = Block::Live {
            header: forged_header,
            transactions: Arc::new(Vec::new()),
            certificates: Arc::new(Vec::new()),
            provisions: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
        };
        let demands = block.demands();
        assert!(demands.contains(VerificationKind::TransactionRoot));
        assert!(!demands.contains(VerificationKind::CertificateRoot));
    }

    /// `record_qc_assembly` against a block hash with no tracked assembly
    /// is a no-op returning `None`.
    #[test]
    fn record_qc_assembly_returns_none_for_unknown_block() {
        let mut vp = VerificationPipeline::new(BlockHeight::GENESIS, ChainOrigin::ROOT);
        let block = assembly_block();
        let verified_qc =
            Verified::<QuorumCertificate>::new_unchecked_for_test(assembly_qc_for(&block));
        assert!(vp.record_qc_assembly(block.hash(), verified_qc).is_none());
        assert_eq!(vp.pending_assembly_count(), 0);
    }

    // ─── substate-walk proposal park ────────────────────────────────────

    /// A proposal parked on an ancestor's substate byte delta resumes when
    /// that block's state root verifies. Nothing else re-drives it: the
    /// parked height is the one whose QC would commit the ancestor, so
    /// without this edge the round runs out its view-change timeout.
    #[test]
    fn substate_park_releases_when_the_ancestor_state_root_verifies() {
        let mut vp = VerificationPipeline::new(BlockHeight::GENESIS, ChainOrigin::ROOT);
        let ancestor = bh(b"outstanding-delta");

        vp.defer_proposal_on_substate(ancestor);
        assert!(
            !vp.take_ready_proposal(),
            "parking alone must not latch a retry"
        );

        vp.checked(bh(b"some-other-block"), VerificationKind::StateRoot);
        assert!(
            !vp.take_ready_proposal(),
            "an unrelated state root leaves the park in place"
        );

        vp.checked(ancestor, VerificationKind::StateRoot);
        assert!(
            vp.take_ready_proposal(),
            "the parked ancestor's delta must latch a retry"
        );
        assert!(
            !vp.take_ready_proposal(),
            "the latch is consumed once, and the park with it"
        );
    }

    /// A sync-admitted ancestor is never executed locally, so no delta can
    /// land for it — its commit is the release.
    #[test]
    fn substate_park_releases_when_the_ancestor_commits() {
        let mut vp = VerificationPipeline::new(BlockHeight::GENESIS, ChainOrigin::ROOT);
        let ancestor = bh(b"sync-admitted");

        vp.defer_proposal_on_substate(ancestor);
        vp.on_block_committed(ancestor);

        assert!(
            vp.take_ready_proposal(),
            "committing the parked ancestor must latch a retry"
        );
    }

    /// A walk blocked on a frontier lagging the committed tip names that
    /// tip, not a block whose delta could be matched — the storage
    /// reconcile releases the park unconditionally.
    #[test]
    fn substate_park_releases_when_the_frontier_reconciles() {
        let mut vp = VerificationPipeline::new(BlockHeight::GENESIS, ChainOrigin::ROOT);

        vp.release_substate_park_on_reconcile();
        assert!(
            !vp.take_ready_proposal(),
            "a reconcile with nothing parked latches nothing"
        );

        vp.defer_proposal_on_substate(bh(b"lagging-frontier-tip"));
        vp.release_substate_park_on_reconcile();
        assert!(
            vp.take_ready_proposal(),
            "the reconcile must latch a retry for the parked proposal"
        );
    }
}
