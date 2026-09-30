//! Sans-io observer bootstrap sequencer.
//!
//! A cohort observer of a pending child syncs exactly the child's key
//! span out of the splitting shard's beacon-attested boundary anchor:
//! the child span is partitioned into parallel sub-range fetches served
//! by the splitting shard's committee, every chunk is verified into the
//! parent's attested `state_root` and staged into the observer's
//! child-rooted store as it arrives, and the finalize builds the child
//! subtree from the staged leaves.
//!
//! No anchor exists to compare the imported root against while the
//! bootstrap runs — the beacon holds only the parent's root, a one-way
//! hash over the child subtrees. Within the import, then, the trust
//! source is the chunks: each proves its leaves into the attested parent
//! root with completeness, so the imported set is exactly the tree's
//! leaves under the child prefix, and prefix-rooted hashing makes the
//! resulting store root the parent tree's subtree node at that prefix by
//! construction.
//!
//! The root is checked later all the same. Adoption requires the store's
//! root to equal the one the child's genesis names, which is the
//! terminal's `split_child_roots` half — itself checked to compose to
//! that block's own committed state root. Completeness is what makes the
//! import correct, not what makes it safe to seat on.
//!
//! Sans-io like [`ShardBootstrap`](crate::bootstrap::ShardBootstrap): drivers own
//! transport, peer selection, and the staging and finalize writes, and
//! pump it through the same [`BootstrapRequest`] surface (the
//! witness-history variant never appears — the pending child's
//! accumulator starts empty).

use std::collections::VecDeque;
use std::sync::Arc;

use hyperscale_hbor::Capped;
use hyperscale_types::network::request::{
    BlockIntent, GetBlockRequest, GetRemoteHeadersRequest, MAX_REMOTE_HEADERS_PER_REQUEST,
};
use hyperscale_types::network::response::{GetBlockResponse, GetStateRangeResponse};
use hyperscale_types::{
    Anchor, Block, BlockHash, BlockHeader, BlockHeight, CertifiedBlockHeader, ChainOrigin,
    CommitProof, MAX_COMMIT_PROOF_ANCESTRY, NetworkDefinition, QuorumCertificate, ReadySignal,
    ResolvedCommittee, ShardAnchor, ShardId, SignError, Signer, StateRoot, ValidatorId, Verifier,
    WeightedTimestamp, ready_signal_window, shard_prefix_path,
};

use crate::bootstrap::snap_sync::{SnapSync, StateRangeOutcome};
use crate::bootstrap::{BootstrapRequest, SPLIT_BITS, STATE_CHUNK_LIMIT};
use crate::reshape::view::CommitteeLookup;

/// The self-signed ready signal an observer broadcasts to the
/// splitting shard's committee on completing its child-span bootstrap.
///
/// Windowed from the splitting shard's attested anchor weighted
/// timestamp — the freshest committed clock the observer holds an
/// authenticated view of. The anchor refreshes every epoch boundary, so
/// the [`ready_signal_window`] span (scaled to `epoch_duration_ms`)
/// comfortably covers the chain's progress since; a signal that somehow
/// passes uncollected is re-emitted against a newer anchor. At the
/// committee, the signal classifies as a `ReshapeReady` witness leaf —
/// the sender's observer seat rides the window's topology snapshot.
/// # Errors
///
/// Propagates [`SignError`] when the signer cannot sign.
pub fn observer_ready_signal(
    network: &NetworkDefinition,
    validator: ValidatorId,
    child: ShardId,
    signer: &dyn Signer,
    anchor: ShardAnchor,
    epoch_duration_ms: u64,
) -> Result<ReadySignal, SignError> {
    let start = anchor.weighted_timestamp;
    let end = start.plus(ready_signal_window(epoch_duration_ms));
    ReadySignal::sign(network, validator, child, start, end, signer)
}

enum Phase {
    /// Assembling the child span of the parent's committed state; every
    /// verified chunk is staged by the driver as it arrives. Boxed: the
    /// sync state dwarfs every other variant.
    State(Box<SnapSync>),
    /// Every sub-range staged, waiting for the driver to take the
    /// finalize.
    FinalizeReady,
    /// Driver took the finalize; waiting for the imported root.
    Finalizing,
    /// Imported: the child store holds the parent tree's child subtree.
    Complete(StateRoot),
}

/// Sequencing state for one observer's pending-child bootstrap.
pub struct ObserverBootstrap {
    anchor: ShardAnchor,
    child: ShardId,
    phase: Phase,
    /// Total value bytes across the chunks handed to the driver for
    /// staging — the child half's substate byte total, seeding the
    /// byte frontier the child chain starts from.
    imported_substate_bytes: u64,
}

impl ObserverBootstrap {
    /// Start a bootstrap of `child`'s span against `parent`'s attested
    /// boundary `anchor`.
    ///
    /// # Panics
    ///
    /// Panics unless `child` is a child of `parent` — an observer seat
    /// only ever names one of the splitting shard's two children.
    #[must_use]
    pub fn new(parent: ShardId, anchor: ShardAnchor, child: ShardId) -> Self {
        assert_eq!(
            child.parent(),
            Some(parent),
            "observer bootstrap target {child:?} is not a child of {parent:?}",
        );
        Self {
            anchor,
            child,
            phase: Phase::State(Box::new(SnapSync::spanning(
                anchor,
                shard_prefix_path(parent),
                &shard_prefix_path(child),
                SPLIT_BITS,
                STATE_CHUNK_LIMIT,
            ))),
            imported_substate_bytes: 0,
        }
    }

    /// The parent-shard anchor this bootstrap verifies against.
    #[must_use]
    pub const fn anchor(&self) -> ShardAnchor {
        self.anchor
    }

    /// The pending child whose span this bootstrap assembles.
    #[must_use]
    pub const fn child(&self) -> ShardId {
        self.child
    }

    /// Every request the current phase wants in flight. Empty while
    /// requests are outstanding, a finalize is pending, or the
    /// bootstrap is complete. Only [`BootstrapRequest::StateRange`]
    /// ever appears.
    pub fn next_requests(&mut self) -> Vec<BootstrapRequest> {
        match &mut self.phase {
            Phase::State(snap) => snap
                .next_requests()
                .into_iter()
                .map(|(id, request)| BootstrapRequest::StateRange(id, request))
                .collect(),
            Phase::FinalizeReady | Phase::Finalizing | Phase::Complete(_) => Vec::new(),
        }
    }

    /// Feed one state range response for `sub_range`. A staged outcome
    /// must be persisted by the driver before it pumps further
    /// responses; after the final chunk the finalize becomes available
    /// via [`Self::take_finalize`].
    pub fn on_state_range(
        &mut self,
        sub_range: usize,
        response: &GetStateRangeResponse,
    ) -> StateRangeOutcome {
        let Phase::State(snap) = &mut self.phase else {
            return StateRangeOutcome::Rejected("state response outside the state phase");
        };
        let outcome = snap.on_response(sub_range, response);
        if let StateRangeOutcome::Staged { .. } = &outcome {
            self.imported_substate_bytes = snap.staged_bytes();
            if snap.is_complete() {
                self.phase = Phase::FinalizeReady;
            }
        }
        outcome
    }

    /// Re-arm a state sub-range after a transport-level failure.
    pub fn on_state_range_failure(&mut self, sub_range: usize) {
        if let Phase::State(snap) = &mut self.phase {
            snap.on_failure(sub_range);
        }
    }

    /// The staged assembly's finalize height, ready for
    /// `BoundaryStore::finalize_boundary_import` on the observer's
    /// child-rooted store. `Some` exactly once; the driver answers with
    /// the imported root via [`Self::on_imported`].
    pub fn take_finalize(&mut self) -> Option<BlockHeight> {
        if !matches!(self.phase, Phase::FinalizeReady) {
            return None;
        }
        self.phase = Phase::Finalizing;
        Some(self.anchor.height)
    }

    /// Record the imported child-subtree root and complete.
    ///
    /// # Panics
    ///
    /// Panics unless the finalize was taken via [`Self::take_finalize`].
    pub fn on_imported(&mut self, root: StateRoot) {
        assert!(
            matches!(self.phase, Phase::Finalizing),
            "on_imported outside the finalize phase",
        );
        self.phase = Phase::Complete(root);
    }

    /// Whether the bootstrap is still assembling state — the only
    /// phase that depends on serving peers retaining the targeted
    /// boundary pin, and the last at which restarting against a newer
    /// anchor is sound (nothing has been imported into the store yet).
    #[must_use]
    pub const fn is_assembling_state(&self) -> bool {
        matches!(self.phase, Phase::State(_))
    }

    /// Whether the child span is imported.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        matches!(self.phase, Phase::Complete(_))
    }

    /// The imported child-subtree root — the parent tree's node at the
    /// child prefix as of the anchor. `None` until complete.
    #[must_use]
    pub const fn imported_root(&self) -> Option<StateRoot> {
        match self.phase {
            Phase::Complete(root) => Some(root),
            _ => None,
        }
    }

    /// The imported substate byte total of the child half — the byte
    /// frontier the child chain starts from. Accrues per staged chunk.
    #[must_use]
    pub const fn imported_substate_bytes(&self) -> u64 {
        self.imported_substate_bytes
    }
}

/// Outcome of feeding one fetch response to [`ObserverTail`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TailOutcome {
    /// The response chains. A recognizing walk has absorbed it; a following
    /// tail holds it until [`ObserverTail::prove`] shows it committed.
    Accepted,
    /// The peer doesn't hold the requested height — the parent chain
    /// hasn't reached it yet, or the peer is behind. Re-arm and retry.
    NotYetAvailable,
    /// The response is invalid for this follow; the driver rotates peers.
    Rejected(&'static str),
}

/// Outcome of one [`ObserverTail::prove`] pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProveOutcome {
    /// Nothing new is proven: the unproven run holds no round-contiguous
    /// pair yet, or the committee its QCs verify against is not yet
    /// resolvable here.
    Unproven,
    /// A verified two-chain proved this many blocks committed; they are
    /// queued for application in height order.
    Released(usize),
    /// The unproven run cannot be the parent's committed chain. It is
    /// dropped, and the follow refetches above the last proven block.
    Refuted(&'static str),
}

/// Most fetched blocks a following tail holds, proven or not, before it
/// stops fetching.
///
/// A block commits as the prefix of a later two-chain only across a view
/// change gap no longer than [`MAX_COMMIT_PROOF_ANCESTRY`], so an honest
/// run proves its lower blocks before reaching this: the ancestry, the
/// pair above it, and one block fetched ahead. A run that reaches it
/// unproven is not the committed chain and is dropped.
const MAX_UNPROVEN_RUN: usize = MAX_COMMIT_PROOF_ANCESTRY + 3;

/// The parent's terminal block, recognised by a follower as it passes,
/// with the child genesis derived from it.
///
/// A block `B` is the terminal when it is the first block whose parent
/// QC sits past the cut: the one header carrying the terminal settled
/// root, since no block before it could know it was the last. The certifying
/// QC used here is the *canonical* one — carried as the `parent_qc` of
/// `B`'s committed child, the next block the follow absorbs — never the
/// QC served alongside `B`, which may be a higher-round re-certification
/// from the parent's coast and stamps a different weighted timestamp.
///
/// The genesis is derived from `B` alone: its `split_child_roots` pair
/// verified to compose to its own committed `state_root`, so a parent
/// cannot name a child subtree its terminal root doesn't contain, and
/// the canonical timestamp as the child clock's start anchor. That is
/// the same derivation the beacon fold performs an epoch later when it
/// seeds the child's anchor.
#[derive(Debug, Clone)]
pub struct TerminalSighting {
    /// The terminal block's header. A split child reads its
    /// `split_child_roots`; a merged parent composes its `state_root`
    /// with the sibling terminal's.
    pub header: BlockHeader,
    /// The canonical certificate over the terminal — the `parent_qc` of
    /// its committed successor. Its weighted timestamp is the child
    /// clock's start anchor.
    pub canonical_qc: QuorumCertificate,
    /// The derived child genesis, absent when the terminal carried no
    /// `split_child_roots` pair or one that fails to compose to its own
    /// state root.
    pub genesis: Option<DerivedGenesis>,
    /// The proof that the terminal *committed* rather than merely
    /// certified, with the committee its QCs verify against — for a
    /// recognizing walk, which absorbs headers as served. Built from the
    /// first round-contiguous pair at or above the terminal — its own
    /// successor when no view change intervened, a later coast pair with
    /// an ancestry link down to it otherwise. Absent until such a pair
    /// arrives, and permanently when the walk never captured the parent's
    /// committee or the gap outgrew [`MAX_COMMIT_PROOF_ANCESTRY`].
    ///
    /// Always absent for a following tail, which absorbs only blocks a
    /// verified two-chain has already proven committed.
    pub commit_proof: Option<(CommitProof, ResolvedCommittee)>,
}

/// A child genesis derived locally from the parent's terminal block.
#[derive(Debug, Clone)]
pub struct DerivedGenesis {
    /// The genesis block the child adopts.
    pub block: Block,
    /// The chain origin it starts from.
    pub origin: ChainOrigin,
    /// The parent terminal this child succeeds, carried off the same
    /// header the genesis derives from. `None` when that header carries
    /// no terminal settled root.
    pub predecessor: Option<Anchor>,
}

/// Derive `child`'s genesis from the parent's terminal header.
///
/// Thin over [`Block::split_child_genesis_from_terminal`], which is the
/// one derivation the beacon fold and every successor share.
fn derive_child_genesis(child: ShardId, terminal: &BlockHeader) -> Option<DerivedGenesis> {
    let (block, origin) = Block::split_child_genesis_from_terminal(child, terminal)?;
    Some(DerivedGenesis {
        block,
        origin,
        predecessor: terminal.as_terminal_anchor(),
    })
}

/// Sans-io tail-follower keeping an observer's synced child store
/// current with the splitting parent's chain.
///
/// The child-span bootstrap imports the parent's child subtree as of an
/// epoch anchor `A`, but the child genesis adopts the subtree of the
/// parent's *terminal* root `B` — every parent commit between them
/// moves the child half. The follower fetches the parent's blocks above
/// `A` in height order and hands each to the driver to apply through
/// `BoundaryStore::follow_block_writes` (the store-prefix subset of the
/// block's writes; partition independence keeps the store's root exactly
/// the parent tree's child subtree node).
///
/// Trust: the store cannot roll back, so it takes only blocks this host
/// has proven committed. A fetched block joins an unproven run that must
/// extend, by parent hash, the chain seeded by the beacon-attested
/// anchor's block hash. It leaves the run only when a round-contiguous
/// pair at or above it forms and both of the pair's QCs verify against
/// the parent's committee for their windows ([`Self::prove`]) — the
/// HotStuff-2 direct commit, whose prefix is committed with it. A served
/// block that never commits, a losing sibling or a fabricated extension,
/// is therefore held at most until a contradicting answer or a failed
/// verification drops the run, and is never applied. The serving peer is
/// trusted for nothing but availability.
///
/// In the parent's final epoch every header also carries
/// `split_child_roots`, and the follower checks its own applied root
/// against its side after each application.
pub struct ObserverTail {
    child: ShardId,
    /// Height of the attested anchor the follow starts above.
    anchor_height: BlockHeight,
    /// The anchor block's own anchor: the window key of the committee that
    /// certified the first block above it.
    anchor_wt: WeightedTimestamp,
    /// Hash-chain cursor: the last absorbed block's hash, seeded by the
    /// attested anchor's.
    last_hash: BlockHash,
    /// Next parent height to absorb.
    next: BlockHeight,
    /// The parent's scheduled cut, once the beacon has published one.
    /// `None` while the split is admitted but unscheduled.
    terminal_cut: Option<WeightedTimestamp>,
    /// The previously absorbed block's header. The crossing test for a
    /// block needs the QC that certifies it, which only arrives with the
    /// next block — and the genesis derivation needs the terminal header
    /// itself, so the follow keeps one block of history.
    prev: Option<BlockHeader>,
    /// The parent's consensus committee, captured while it was still
    /// live so the terminal's QCs stay verifiable after the head moves on.
    /// Read by a recognizing walk's terminal proof only.
    parent_committee: Option<ResolvedCommittee>,
    /// The terminal block, once the follow has walked past it.
    terminal: Option<TerminalSighting>,
    /// The terminal and the coast blocks above it, ascending — the run a
    /// prefix commitment proof walks back down. Seeded when the crossing is
    /// sighted and dropped once the proof is built or the gap outgrows what
    /// one can carry.
    since_terminal: Vec<BlockHeader>,
    /// Height of the last block the driver applied into the child store.
    /// The genesis adopts the child subtree as of the *terminal* root, so
    /// a flip before the store has applied through it would adopt the
    /// wrong subtree.
    applied: Option<BlockHeight>,
    /// Walk headers without applying anything. A parent half already holds
    /// the parent's state and seeds its child by cloning it, so it needs
    /// the walk only to find which of the parent's blocks is the terminal
    /// and to derive the genesis from it.
    recognition_only: bool,
    in_flight: bool,
    /// Fetched blocks above the cursor that no verified two-chain has
    /// proven committed yet, ascending, each extending the one below and
    /// the lowest extending the cursor.
    unproven: Vec<FetchedBlock>,
    /// Proven blocks waiting for the driver to apply and answer, in height
    /// order.
    proven: VecDeque<PendingFollow>,
    /// Set while a taken application is out for the driver to apply,
    /// cleared on [`Self::on_applied`]. Guards [`Self::take_apply`] against
    /// re-emitting the same application when the driver re-polls before the
    /// apply answers — the production pump ticks on a timer, so a `step`
    /// can land between the take and its answer.
    apply_in_flight: bool,
}

/// A block as served, with the QC that came with it.
struct FetchedBlock {
    block: Arc<Block>,
    qc: QuorumCertificate,
}

struct PendingFollow {
    block: Arc<Block>,
    /// The block's `split_child_roots` slot for this child, when the
    /// header carried the pair — the applied root must reproduce it.
    expected_root: Option<StateRoot>,
}

impl ObserverTail {
    /// Start following the parent chain above the `anchor` a completed
    /// [`ObserverBootstrap`] imported at.
    #[must_use]
    pub const fn new(anchor: ShardAnchor, child: ShardId) -> Self {
        Self {
            child,
            anchor_height: anchor.height,
            anchor_wt: anchor.weighted_timestamp,
            last_hash: anchor.block_hash,
            next: anchor.height.next(),
            in_flight: false,
            unproven: Vec::new(),
            proven: VecDeque::new(),
            apply_in_flight: false,
            terminal_cut: None,
            prev: None,
            parent_committee: None,
            terminal: None,
            since_terminal: Vec::new(),
            applied: None,
            recognition_only: false,
        }
    }

    /// A follow that only recognises the terminal, applying nothing.
    ///
    /// For a parent half: it was on the parent, so its child store is a
    /// clone of state it already holds rather than something the follow
    /// builds. It walks the same headers for the same reason an observer
    /// does — to find the terminal crossing and derive the child genesis
    /// from it — and skips every write.
    #[must_use]
    pub fn recognizing(anchor: ShardAnchor, child: ShardId) -> Self {
        Self {
            recognition_only: true,
            ..Self::new(anchor, child)
        }
    }

    /// Publish the parent's scheduled cut, so the follow can recognise the
    /// terminal crossing as it walks past it.
    ///
    /// The driver re-supplies it every step and the last published value
    /// is retained, for the same reason [`Self::capture_committee`]
    /// latches: a cut never moves, but it is *projected* for one window
    /// only. The fold that applies the reshape consumes the record at the
    /// top of the parent's final window, so the next promotion freezes an
    /// empty projection — while the crossing this identifies is only
    /// recognisable once the terminal's successor arrives, at the close of
    /// that same window. Clearing on `None` would drop the cut exactly as
    /// the block that needs it lands.
    pub const fn set_terminal_cut(&mut self, cut: Option<WeightedTimestamp>) {
        if cut.is_some() {
            self.terminal_cut = cut;
        }
    }

    /// The latched cut, for a driver that needs the instant itself rather
    /// than the crossing it identifies — a merged parent's clock anchors
    /// there. Reading it back here rather than from the projection is what
    /// keeps one latch instead of two.
    #[must_use]
    pub const fn terminal_cut(&self) -> Option<WeightedTimestamp> {
        self.terminal_cut
    }

    /// Capture the parent's consensus committee while it is still live, so
    /// a recognizing walk can verify the terminal's QCs after the head has
    /// moved on.
    ///
    /// The driver re-supplies it every step and the last non-empty capture
    /// wins: a split parent leaves the head's committee set the moment its
    /// applying fold lands, which is around when the walk reaches its
    /// terminal, so resolving on demand would come up empty exactly when
    /// the proof is needed. Committees are frozen per window, so the copy
    /// taken during the final window is the set that signed it.
    pub fn capture_committee(&mut self, committee: Option<ResolvedCommittee>) {
        if let Some(committee) = committee {
            self.parent_committee = Some(committee);
        }
    }

    /// The terminal sighting, but only once the follow has reached the
    /// block *after* the terminal — applied for a following tail, walked
    /// past for a recognizing one.
    ///
    /// Two reasons it is the successor and not the terminal itself. A
    /// followed store's root must be the child subtree as of the terminal
    /// root, which applying the terminal establishes — and the successor is
    /// a coast block past the cut, empty by rule, so it moves no state. But
    /// the adopt reads the child's substate byte total at the genesis
    /// height, which is `terminal + 1`, so that version has to exist. A
    /// recognizing tail writes nothing, and needs the successor anyway: its
    /// `parent_qc` is the only canonical source of the genesis clock.
    ///
    /// A following tail applies only proven blocks, so a sighting it
    /// returns is of a terminal proven committed, certified canonically by
    /// a successor proven committed too.
    #[must_use]
    pub fn settled_terminal(&self) -> Option<&TerminalSighting> {
        let terminal = self.terminal.as_ref()?;
        (self.applied? >= terminal.header.height().next()).then_some(terminal)
    }

    /// The next block fetch for a following tail, which needs each block's
    /// body to apply its child-half writes. `None` while one is outstanding
    /// or the tail already holds as many blocks as it may.
    ///
    /// Asks for the block above the unproven run, not above the proven
    /// cursor: a block is proven only by the pair above it, so the follow
    /// runs ahead of what it applies.
    pub fn next_request(&mut self) -> Option<GetBlockRequest> {
        if self.in_flight || self.unproven.len() + self.proven.len() >= MAX_UNPROVEN_RUN {
            return None;
        }
        self.in_flight = true;
        Some(GetBlockRequest::new(self.run_tip().0, BlockIntent::Execute))
    }

    /// The height the next fetched block must sit at and the hash it must
    /// extend: the top of the unproven run, or the proven cursor when the
    /// run is empty.
    fn run_tip(&self) -> (BlockHeight, BlockHash) {
        self.unproven
            .last()
            .map_or((self.next, self.last_hash), |top| {
                (top.block.height().next(), top.block.hash())
            })
    }

    /// The next certified-header fetch from `source`, for a recognizing
    /// tail — which discards bodies, so it walks headers instead.
    ///
    /// Batched to [`MAX_REMOTE_HEADERS_PER_REQUEST`]. The walk starts cold
    /// at a boundary anchor an epoch or more behind a chain that is still
    /// producing, so one block per round trip closes the gap only while a
    /// round trip is shorter than a block time. A batch closes it
    /// regardless.
    pub const fn next_header_request(
        &mut self,
        source: ShardId,
    ) -> Option<GetRemoteHeadersRequest> {
        if self.in_flight {
            return None;
        }
        self.in_flight = true;
        Some(GetRemoteHeadersRequest {
            source_shard: source,
            from_height: self.next,
            count: MAX_REMOTE_HEADERS_PER_REQUEST,
        })
    }

    /// Absorb one committed header: advance the chain cursor, run the
    /// terminal crossing test, and extend a recognizing walk's commitment
    /// proof.
    ///
    /// The shared core of both feeds, so a recognizing walk over headers
    /// and a following walk over blocks cannot drift on which block is the
    /// terminal. Callers have already checked that `header` extends the
    /// cursor.
    fn absorb_header(&mut self, header: &BlockHeader, qc: &QuorumCertificate) {
        // This block's parent QC is the canonical certificate over its
        // predecessor, so absorbing it is what seals that predecessor as
        // the terminal: the first block past the cut, the one header
        // carrying the terminal settled root.
        if self.terminal_cut.is_some()
            && self.terminal.is_none()
            && let Some(terminal) = &self.prev
            && terminal.settled_txs_root().is_some()
        {
            // The run the commitment proof walks back down starts at the
            // terminal itself; the coast blocks above it are appended as
            // they arrive.
            if self.recognition_only {
                self.since_terminal = vec![terminal.clone()];
            }
            self.terminal = Some(TerminalSighting {
                header: terminal.clone(),
                canonical_qc: header.parent_qc().clone(),
                genesis: derive_child_genesis(self.child, terminal),
                commit_proof: None,
            });
        }
        if self.recognition_only {
            self.advance_commit_proof(header, qc);
            self.applied = Some(header.height());
        }
        self.prev = Some(header.clone());
        self.last_hash = header.hash();
        self.next = self.next.next();
    }

    /// Feed a batch of consecutive certified headers to a recognizing
    /// walk. Stops at the first header the walk rejects, keeping whatever
    /// the prefix established.
    pub fn on_certified_headers(&mut self, headers: &[CertifiedBlockHeader]) -> TailOutcome {
        if !self.in_flight {
            return TailOutcome::Rejected("unsolicited header response");
        }
        self.in_flight = false;
        if headers.is_empty() {
            return TailOutcome::NotYetAvailable;
        }
        for certified in headers {
            let header = certified.header();
            if header.height() != self.next {
                return TailOutcome::Rejected("block height does not match the requested height");
            }
            if header.parent_block_hash() != self.last_hash {
                return TailOutcome::Rejected("block does not extend the attested anchor chain");
            }
            self.absorb_header(header, certified.qc());
        }
        TailOutcome::Accepted
    }

    /// Feed a following tail the response for its outstanding fetch.
    ///
    /// A block that chains joins the unproven run; nothing is applied until
    /// [`Self::prove`] shows it committed.
    pub fn on_response(&mut self, response: &GetBlockResponse) -> TailOutcome {
        if !self.in_flight {
            return TailOutcome::Rejected("unsolicited block response");
        }
        self.in_flight = false;
        let Some(elided) = &response.certified else {
            return TailOutcome::NotYetAvailable;
        };
        // The follower advertises no inventory, so every body is inline
        // and rehydration resolves nothing; this also pins the QC to the
        // header.
        let Ok(certified) = elided.try_rehydrate(|_| None, |_| None, |_| None) else {
            return TailOutcome::Rejected("elided or mispaired block body");
        };
        let header = certified.block().header();
        let (height, tip) = self.run_tip();
        if header.height() != height {
            return TailOutcome::Rejected("block height does not match the requested height");
        }
        if header.parent_block_hash() != tip {
            // Either this answer or the unproven run beneath it is off the
            // committed chain, and nothing held says which. Neither is
            // proven, so dropping the run costs a refetch and keeps nothing
            // an answer has contradicted.
            let reason = if self.unproven.is_empty() {
                "block does not extend the proven chain"
            } else {
                "block contradicts the unproven run it was fetched above"
            };
            self.unproven.clear();
            return TailOutcome::Rejected(reason);
        }
        self.unproven.push(FetchedBlock {
            block: Arc::new(certified.block().clone()),
            qc: certified.qc().clone(),
        });
        TailOutcome::Accepted
    }

    /// Prove what the unproven run can: find its highest round-contiguous
    /// pair, verify both QCs against the parent committee `committee`
    /// resolves for their windows, and release every block beneath the
    /// pair's upper block — the pair's lower block is directly committed,
    /// and the run below it is its hash-linked prefix.
    ///
    /// `committee` takes the anchor of the certified block's parent and the
    /// QC's own weighted timestamp. A committee not yet resolvable leaves
    /// the run for a later pass; a QC that fails, or a window no honest QC
    /// resolves to, drops it.
    pub fn prove(
        &mut self,
        verifier: &dyn Verifier,
        network: &NetworkDefinition,
        committee: impl Fn(WeightedTimestamp, WeightedTimestamp) -> CommitteeLookup,
    ) -> ProveOutcome {
        let pair = (1..self.unproven.len()).rev().find(|&upper| {
            self.unproven[upper].block.header().round()
                == self.unproven[upper - 1].block.header().round().next()
        });
        let Some(upper) = pair else {
            if self.unproven.len() >= MAX_UNPROVEN_RUN {
                self.unproven.clear();
                return ProveOutcome::Refuted("the run outgrew any commit a view change can defer");
            }
            return ProveOutcome::Unproven;
        };
        let lower = &self.unproven[upper - 1];
        let child = &self.unproven[upper];
        // The committee certifying a block is keyed on its parent's anchor.
        let lower_parent_anchor = match upper.checked_sub(2) {
            Some(below) => self.unproven[below]
                .block
                .header()
                .parent_qc()
                .weighted_timestamp(),
            None => self
                .prev
                .as_ref()
                .map_or(self.anchor_wt, |prev| prev.parent_qc().weighted_timestamp()),
        };
        let lower_qc = child.block.header().parent_qc();
        let lookups = [
            committee(lower_parent_anchor, lower_qc.weighted_timestamp()),
            committee(
                lower.block.header().parent_qc().weighted_timestamp(),
                child.qc.weighted_timestamp(),
            ),
        ];
        let committees = match lookups {
            [
                CommitteeLookup::Resolved(first),
                CommitteeLookup::Resolved(second),
            ] => [first, second],
            [CommitteeLookup::Unresolvable, _] | [_, CommitteeLookup::Unresolvable] => {
                self.unproven.clear();
                return ProveOutcome::Refuted("the run's two-chain names no resolvable committee");
            }
            _ => return ProveOutcome::Unproven,
        };
        let proof = CommitProof::direct(
            CertifiedBlockHeader::new(lower.block.header().clone(), lower_qc.clone()),
            CertifiedBlockHeader::new(child.block.header().clone(), child.qc.clone()),
            None,
        );
        if proof
            .verify_resolved(verifier, network, &committees)
            .is_err()
        {
            self.unproven.clear();
            return ProveOutcome::Refuted("the run's two-chain fails verification");
        }
        let released: Vec<FetchedBlock> = self.unproven.drain(..upper).collect();
        let count = released.len();
        for fetched in released {
            let header = fetched.block.header();
            let expected_root = header.split_child_roots().map(|pair| {
                if self.child.path() & 1 == 0 {
                    pair.left
                } else {
                    pair.right
                }
            });
            self.absorb_header(header, &fetched.qc);
            self.proven.push_back(PendingFollow {
                block: fetched.block,
                expected_root,
            });
        }
        ProveOutcome::Released(count)
    }

    /// Extend the terminal's commitment proof with `header`, the newest
    /// block of the parent's coast.
    ///
    /// A block commits when a round-contiguous pair forms at or above it,
    /// so the terminal's own successor proves it only when no view change
    /// intervened. The coast supplies as many further blocks as needed —
    /// and the terminal committed at all only if some such pair exists — so
    /// the walk keeps going and proves the terminal as the *prefix* of
    /// whichever pair arrives, the shape [`CommitProof`]'s ancestry link
    /// carries.
    ///
    /// The gap is bounded: past [`MAX_COMMIT_PROOF_ANCESTRY`] no proof can
    /// carry it, so the run is abandoned and the duty falls back to the
    /// anchor path.
    fn advance_commit_proof(&mut self, header: &BlockHeader, qc: &QuorumCertificate) {
        if self
            .terminal
            .as_ref()
            .is_none_or(|s| s.commit_proof.is_some())
        {
            return;
        }
        // An abandoned run stays abandoned. Restarting it would build a
        // direct proof over two coast blocks, which commits one of them and
        // not the terminal below.
        if self.since_terminal.is_empty() {
            return;
        }
        if self.since_terminal.len() > MAX_COMMIT_PROOF_ANCESTRY + 1 {
            // The gap outgrew what an ancestry link can carry; stop
            // retaining it and leave the duty to the anchor path.
            self.since_terminal = Vec::new();
            return;
        }
        self.since_terminal.push(header.clone());
        let run = &self.since_terminal;
        let n = run.len();
        // `n >= 2` holds: the run is seeded with the terminal before the
        // first push. The pair is the two newest blocks.
        let Some(prev) = run.get(n.wrapping_sub(2)) else {
            return;
        };
        if header.round() != prev.round().next() {
            return;
        }
        let Some(committee) = self.parent_committee.clone() else {
            return;
        };
        // Descending from `prev`'s parent to the terminal, which the proof
        // requires as the link's last element. Empty when `prev` is the
        // terminal — the direct commit.
        let ancestry: Vec<BlockHeader> = run[..n - 2].iter().rev().cloned().collect();
        // The certified block's parent, when the run reaches it. A direct
        // commit over the terminal does not: the run starts there, and the
        // block below is the snap-sync anchor, whose header never arrives.
        // This proof's consumer resolves its own committee, so `None` costs
        // it nothing.
        let certified_parent = run.get(n.wrapping_sub(3)).cloned();
        let proof = CommitProof::new(
            CertifiedBlockHeader::new(prev.clone(), header.parent_qc().clone()),
            CertifiedBlockHeader::new(header.clone(), qc.clone()),
            certified_parent,
            Capped::new(ancestry).expect("a rebuilt block keeps the caps its source met"),
        );
        if let Some(sighting) = &mut self.terminal {
            sighting.commit_proof = Some((proof, committee));
        }
        self.since_terminal = Vec::new();
    }

    /// Re-arm after a transport-level failure.
    pub const fn on_failure(&mut self) {
        self.in_flight = false;
    }

    /// The oldest proven block, ready for `BoundaryStore::follow_block_writes`
    /// on the observer's store. `Some` once per proven block; the driver
    /// answers with the resulting root via [`Self::on_applied`].
    pub fn take_apply(&mut self) -> Option<Arc<Block>> {
        if self.apply_in_flight {
            return None;
        }
        let pending = self.proven.front()?;
        self.apply_in_flight = true;
        Some(Arc::clone(&pending.block))
    }

    /// Record the applied root, checking it against the header's
    /// `split_child_roots` slot when the block carried the pair.
    ///
    /// # Errors
    ///
    /// Returns a description when the applied root contradicts the
    /// followed header — the store has diverged from the parent's child
    /// subtree and the duty must fail closed (the flip falls back to a
    /// fresh snap-sync).
    ///
    /// # Panics
    ///
    /// Panics unless an application was taken via [`Self::take_apply`].
    pub fn on_applied(&mut self, root: StateRoot) -> Result<(), String> {
        assert!(
            self.apply_in_flight,
            "on_applied outside a taken application"
        );
        self.apply_in_flight = false;
        let pending = self
            .proven
            .pop_front()
            .expect("a taken application is the oldest proven block");
        if let Some(expected) = pending.expected_root
            && expected != root
        {
            return Err(format!(
                "followed store diverged at height {}: applied root {root:?} ≠ carried {expected:?}",
                pending.block.height(),
            ));
        }
        self.applied = Some(pending.block.height());
        Ok(())
    }

    /// The next parent height the store needs applied: one above the last
    /// application, or above the anchor before the first.
    #[must_use]
    pub fn next_height(&self) -> BlockHeight {
        self.applied.unwrap_or(self.anchor_height).next()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hyperscale_crypto_bls::BlsVerifier;
    use hyperscale_hbor::Capped;
    use hyperscale_jmt::{Blake3Hasher, Hasher};
    use hyperscale_storage::test_helpers::pin_snap_sync_replica;
    use hyperscale_storage::{BoundaryStore, SubstateStore, WitnessSeed};
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::test_utils::{TestCommittee, signed_child_block};
    use hyperscale_types::{
        AggregateSignature, BeaconWitnessLeafCount, BlockHeaderParts, CommitProofVerifyError,
        ElidedCertifiedBlock, Hash, Inventory, Round, SettledTxsRoot, SignerBitfield,
        SplitChildRoots, VoteCount, WitnessSources,
    };

    use super::*;
    use crate::bootstrap::state_range_serve::serve_state_range_request;

    const ENTRIES: u8 = 12;

    /// A committed parent replica (whole-keyspace root shard), pinned at
    /// its boundary for serving.
    fn parent_replica() -> (Arc<SimShardStorage>, ShardAnchor) {
        let storage = SimShardStorage::default();
        let anchor = pin_snap_sync_replica(&storage, ENTRIES, &[]);
        (Arc::new(storage), anchor)
    }

    /// Drive one observer bootstrap to completion against `serving`,
    /// importing into a fresh store rooted at the child's prefix.
    /// Returns the child store and its imported root.
    fn observe(
        serving: &Arc<SimShardStorage>,
        anchor: ShardAnchor,
        child: ShardId,
    ) -> (SimShardStorage, StateRoot) {
        let store = SimShardStorage::new(shard_prefix_path(child));
        let mut bootstrap = ObserverBootstrap::new(ShardId::ROOT, anchor, child);
        for _ in 0..1_000 {
            if bootstrap.is_complete() {
                let root = bootstrap.imported_root().expect("complete");
                return (store, root);
            }
            for request in bootstrap.next_requests() {
                let BootstrapRequest::StateRange(id, request) = request else {
                    panic!("observer bootstrap emitted a non-state request");
                };
                let response = serve_state_range_request(serving, &request);
                match bootstrap.on_state_range(id, &response) {
                    StateRangeOutcome::Staged { leaves, progress } => {
                        store.stage_import_chunk(&progress, &leaves).unwrap();
                    }
                    StateRangeOutcome::Rejected(reason) => {
                        panic!("state range rejected: {reason}")
                    }
                }
            }
            if let Some(height) = bootstrap.take_finalize() {
                let root = store
                    .finalize_boundary_import(height, WitnessSeed::default())
                    .unwrap();
                bootstrap.on_imported(root);
            }
        }
        panic!("observer bootstrap did not complete");
    }

    /// The keystone identity, end to end: each child store adopts
    /// exactly the parent tree's subtree at its prefix, the two halves
    /// partition the parent's substates, and the parent's attested root
    /// recomposes from the two imported roots.
    #[test]
    fn observer_bootstraps_adopt_the_child_subtrees() {
        let (serving, anchor) = parent_replica();
        let (left, right) = ShardId::ROOT.children();

        let (left_store, left_root) = observe(&serving, anchor, left);
        let (right_store, right_root) = observe(&serving, anchor, right);

        assert_eq!(left_store.state_root(), left_root);
        assert_eq!(right_store.state_root(), right_root);
        assert_eq!(
            StateRoot::from_raw(Hash::from_hash_bytes(&Blake3Hasher::hash_internal(&[
                *left_root.as_raw().as_bytes(),
                *right_root.as_raw().as_bytes(),
            ]))),
            anchor.state_root,
            "imported child roots must recompose to the parent's attested root",
        );
    }

    /// Both halves together hold every parent substate exactly once.
    #[test]
    fn child_spans_partition_the_parent_population() {
        let (serving, anchor) = parent_replica();
        let children: [ShardId; 2] = ShardId::ROOT.children().into();

        let mut counts = Vec::new();
        for child in children {
            let mut bootstrap = ObserverBootstrap::new(ShardId::ROOT, anchor, child);
            for _ in 0..1_000 {
                if bootstrap.take_finalize().is_some() {
                    break;
                }
                for request in bootstrap.next_requests() {
                    if let BootstrapRequest::StateRange(id, request) = request {
                        let response = serve_state_range_request(&serving, &request);
                        bootstrap.on_state_range(id, &response);
                    }
                }
            }
            counts.push(bootstrap.imported_substate_bytes());
        }
        let parent_bytes = serving
            .substate_bytes_at_version(anchor.height.inner())
            .expect("parent byte total");
        assert_eq!(
            counts.iter().sum::<u64>(),
            parent_bytes,
            "the two halves' byte totals must sum to the parent's, no leaf lost or duplicated",
        );
        assert!(
            counts.iter().all(|&c| c > 0),
            "fixture population must straddle the split bit; got {counts:?}",
        );
    }

    /// A tampered leaf value fails the chunk verification and rejects.
    #[test]
    fn tampered_chunk_is_rejected() {
        let (serving, anchor) = parent_replica();
        let (left, _) = ShardId::ROOT.children();
        let mut bootstrap = ObserverBootstrap::new(ShardId::ROOT, anchor, left);

        let mut rejected = false;
        'outer: for _ in 0..1_000 {
            for request in bootstrap.next_requests() {
                let BootstrapRequest::StateRange(id, request) = request else {
                    unreachable!();
                };
                let mut response = serve_state_range_request(&serving, &request);
                if let Some(chunk) = &mut response.chunk
                    && !chunk.leaves.is_empty()
                {
                    let mut leaves: Vec<_> = chunk.leaves.clone().into_inner();
                    let mut value = leaves[0].value.clone();
                    value[0] ^= 1;
                    leaves[0].value = value;
                    chunk.leaves =
                        Capped::new(leaves).expect("the tampered chunk keeps its length");
                    rejected = matches!(
                        bootstrap.on_state_range(id, &response),
                        StateRangeOutcome::Rejected(_),
                    );
                    break 'outer;
                }
                bootstrap.on_state_range(id, &response);
            }
        }
        assert!(rejected, "tampered chunk must reject");
    }

    /// An observer seat only ever names a child of the splitting shard.
    #[test]
    #[should_panic(expected = "is not a child of")]
    fn rejects_a_target_outside_the_split() {
        let (_, anchor) = parent_replica();
        let _ = ObserverBootstrap::new(ShardId::ROOT, anchor, ShardId::leaf(2, 0b11));
    }

    // ─── terminal recognition ───────────────────────────────────────────

    const CUT_MS: u64 = 6_000;

    /// A QC over `block` stamping `wt` — the value a follower reads when
    /// this QC arrives as the *next* block's `parent_qc`.
    fn qc_over(header: &BlockHeader, wt: u64) -> QuorumCertificate {
        QuorumCertificate::new(
            header.hash(),
            header.shard_id(),
            header.height(),
            header.parent_block_hash(),
            Round::new(header.round().inner()),
            SignerBitfield::new(4),
            AggregateSignature::ZERO,
            WeightedTimestamp::from_millis(wt),
        )
    }

    /// One parent-chain block. `pred_wt` is the stamp on its own
    /// `parent_qc` — the value the crossing test compares against the cut
    /// — and `pair` its `split_child_roots`, carried by every final-window
    /// header.
    fn parent_block(
        height: u64,
        round: u64,
        parent: BlockHash,
        pred_wt: u64,
        state_root: StateRoot,
        pair: Option<SplitChildRoots>,
    ) -> Block {
        parent_block_settling(height, round, parent, pred_wt, state_root, pair, None)
    }

    /// [`parent_block`] carrying `terminal_settled_txs`, as the terminal
    /// alone does.
    fn parent_block_settling(
        height: u64,
        round: u64,
        parent: BlockHash,
        pred_wt: u64,
        state_root: StateRoot,
        pair: Option<SplitChildRoots>,
        terminal_settled_txs: Option<SettledTxsRoot>,
    ) -> Block {
        let parent_qc = QuorumCertificate::new(
            parent,
            ShardId::ROOT,
            BlockHeight::new(height.saturating_sub(1)),
            BlockHash::ZERO,
            Round::new(round.saturating_sub(1)),
            SignerBitfield::new(4),
            AggregateSignature::ZERO,
            WeightedTimestamp::from_millis(pred_wt),
        );
        block_on(
            parent_qc,
            height,
            round,
            parent,
            state_root,
            pair,
            terminal_settled_txs,
        )
    }

    /// A parent-chain block over `parent_qc`, the certificate on its
    /// predecessor.
    fn block_on(
        parent_qc: QuorumCertificate,
        height: u64,
        round: u64,
        parent: BlockHash,
        state_root: StateRoot,
        pair: Option<SplitChildRoots>,
        terminal_settled_txs: Option<SettledTxsRoot>,
    ) -> Block {
        let header = BlockHeader::new(BlockHeaderParts {
            height: BlockHeight::new(height),
            parent_block_hash: parent,
            parent_qc: parent_qc.into(),
            round: Round::new(round),
            state_root,
            provision_tx_roots: Capped::default(),
            split_child_roots: pair,
            terminal_settled_txs,
            ..Default::default()
        });
        Block::Live {
            header,
            transactions: Arc::new(Capped::empty()),
            certificates: Arc::new(Capped::empty()),
            provisions: Arc::new(Capped::empty()),
            abandonment_records: Arc::new(Capped::empty()),
            state_claims: Arc::new(Capped::empty()),
            tick_manifest: Arc::new(Capped::empty()),
            witness_sources: Arc::new(WitnessSources::empty()),
        }
    }

    /// Walk a recognizing tail over `block`'s header, certified by a QC
    /// stamping a clock deliberately *not* the one the derivation may use,
    /// so a test that reads the served QC's clock fails.
    fn walk(tail: &mut ObserverTail, block: &Block) -> TailOutcome {
        let _ = tail
            .next_header_request(ShardId::ROOT)
            .expect("the walk has no fetch outstanding");
        tail.on_certified_headers(&[CertifiedBlockHeader::new(
            block.header().clone(),
            qc_over(block.header(), 9_999),
        )])
    }

    /// A parent chain across the cut: the anchor block at height 1 is the
    /// crossing, the terminal at height 2 is the first block whose
    /// `parent_qc` lands past the cut, and the coast block at height 3
    /// certifies it. The terminal carries the terminal settled root and
    /// the child-root pair composing to its own state root.
    ///
    /// Returns the anchor the follow starts from and the two blocks.
    fn straddling_chain() -> (ShardAnchor, Block, Block, SplitChildRoots) {
        let left = StateRoot::from_raw(Hash::from_bytes(b"left subtree"));
        let right = StateRoot::from_raw(Hash::from_bytes(b"right subtree"));
        let pair = SplitChildRoots { left, right };
        let terminal_root = pair.composed_root();

        let anchor_block = parent_block(1, 1, BlockHash::ZERO, 4_000, StateRoot::ZERO, None);
        let anchor = ShardAnchor {
            state_root: StateRoot::ZERO,
            block_hash: anchor_block.hash(),
            height: BlockHeight::new(1),
            weighted_timestamp: WeightedTimestamp::from_millis(4_000),
            witness_base: BeaconWitnessLeafCount::ZERO,
            terminal_settled_txs: None,
            handoff_complete: None,
            terminal_epoch: None,
        };
        // The terminal's parent QC certifies the crossing past the cut.
        let terminal = parent_block_settling(
            2,
            2,
            anchor.block_hash,
            CUT_MS + 250,
            terminal_root,
            Some(pair),
            Some(SettledTxsRoot::ZERO),
        );
        // The coast block's parent QC is the canonical certificate over
        // the terminal, stamped past the cut.
        let coast = parent_block(
            3,
            3,
            terminal.hash(),
            CUT_MS + 500,
            terminal_root,
            Some(pair),
        );
        (anchor, terminal, coast, pair)
    }

    /// A recognizing follow walks the parent chain, spots the terminal
    /// once the coast block's `parent_qc` certifies it, and derives the
    /// child genesis the beacon fold composes from the same terminal.
    ///
    /// The canonical certificate is the coast block's `parent_qc`, never
    /// the QC served alongside either block — a terminal re-certified at a
    /// higher round during the coast carries a divergent stamp — and the
    /// child's clock is the terminal's own `parent_qc`.
    #[test]
    fn recognizing_follow_derives_the_child_genesis_from_the_terminal() {
        let (anchor, terminal, coast, pair) = straddling_chain();
        let (child, _) = ShardId::ROOT.children();

        let mut tail = ObserverTail::recognizing(anchor, child);
        tail.set_terminal_cut(Some(WeightedTimestamp::from_millis(CUT_MS)));

        assert_eq!(walk(&mut tail, &terminal), TailOutcome::Accepted);
        assert!(
            tail.settled_terminal().is_none(),
            "the terminal is not recognised until its successor arrives",
        );

        assert_eq!(walk(&mut tail, &coast), TailOutcome::Accepted);

        let sighting = tail.settled_terminal().expect("the crossing is recognised");
        assert_eq!(sighting.header.hash(), terminal.hash());
        assert_eq!(
            sighting.canonical_qc.weighted_timestamp(),
            WeightedTimestamp::from_millis(CUT_MS + 500),
            "the certificate is the coast block's parent QC, not either served QC",
        );

        // The child's clock is the terminal's own parent QC.
        let derived = sighting.genesis.as_ref().expect("the pair composes");
        let expected = Block::split_child_genesis(
            child,
            pair.left,
            terminal.header(),
            WeightedTimestamp::from_millis(CUT_MS + 250),
        );
        assert_eq!(derived.block.hash(), expected.hash());
        assert_eq!(derived.origin.genesis_height, BlockHeight::new(3));
    }

    /// The cut is projected for one window, and the block that resolves
    /// the crossing arrives at its close. A `None` published after the
    /// projection drops it must not clear what the follow already holds,
    /// or the recognition is lost exactly when it becomes possible.
    #[test]
    fn a_withdrawn_projection_does_not_clear_the_published_cut() {
        let (anchor, terminal, coast, _) = straddling_chain();
        let (child, _) = ShardId::ROOT.children();

        let mut tail = ObserverTail::recognizing(anchor, child);
        tail.set_terminal_cut(Some(WeightedTimestamp::from_millis(CUT_MS)));
        assert_eq!(walk(&mut tail, &terminal), TailOutcome::Accepted);

        // The applying fold consumed the reshape record, so the head
        // projection no longer names a cut for the parent.
        tail.set_terminal_cut(None);

        assert_eq!(walk(&mut tail, &coast), TailOutcome::Accepted);
        assert!(
            tail.settled_terminal().is_some(),
            "the latched cut must still recognise the crossing",
        );
    }

    /// Without a cut the follow is a plain tail: it walks the same blocks
    /// and recognises nothing, which is what a duty discovered too late
    /// falls back from.
    #[test]
    fn a_follow_with_no_cut_recognises_nothing() {
        let (anchor, terminal, coast, _) = straddling_chain();
        let (child, _) = ShardId::ROOT.children();

        let mut tail = ObserverTail::recognizing(anchor, child);
        for block in [&terminal, &coast] {
            assert_eq!(walk(&mut tail, block), TailOutcome::Accepted);
        }
        assert!(tail.settled_terminal().is_none());
    }

    /// A committee the tail only stores — it verifies nothing itself, so
    /// the contents are irrelevant to what these tests assert.
    fn stub_committee() -> ResolvedCommittee {
        ResolvedCommittee {
            public_keys: Vec::new(),
            quorum_threshold: VoteCount::new(0),
        }
    }

    /// The terminal's own successor is round-contiguous with it, so the
    /// proof is direct and carries no ancestry link.
    #[test]
    fn a_contiguous_successor_proves_the_terminal_directly() {
        let (anchor, terminal, coast, _) = straddling_chain();
        let (child, _) = ShardId::ROOT.children();

        let mut tail = ObserverTail::recognizing(anchor, child);
        tail.set_terminal_cut(Some(WeightedTimestamp::from_millis(CUT_MS)));
        tail.capture_committee(Some(stub_committee()));
        for block in [&terminal, &coast] {
            assert_eq!(walk(&mut tail, block), TailOutcome::Accepted);
        }

        let (proof, _) = tail
            .settled_terminal()
            .expect("recognised")
            .commit_proof
            .as_ref()
            .expect("a contiguous pair proves the terminal");
        assert_eq!(proof.proven_block_hash(), terminal.hash());
        assert_eq!(proof.proven_height(), BlockHeight::new(2));
    }

    /// A view change at the coast breaks round contiguity with the
    /// terminal's own successor. The terminal still committed — some pair
    /// above it formed — so the walk keeps going and proves it as the
    /// prefix of the pair that does arrive.
    #[test]
    fn a_view_change_at_the_coast_still_proves_the_terminal() {
        let (anchor, terminal, _, pair) = straddling_chain();
        let (child, _) = ShardId::ROOT.children();
        let terminal_root = pair.composed_root();

        // Round 3 is skipped: the coast block at height 3 lands at round 4,
        // so it is not contiguous with the terminal at round 2.
        let gap = parent_block(
            3,
            4,
            terminal.hash(),
            CUT_MS + 500,
            terminal_root,
            Some(pair),
        );
        // The next block is contiguous with *that* one, committing it — and
        // the terminal below it as the branch's prefix.
        let pairing = parent_block(4, 5, gap.hash(), CUT_MS + 900, terminal_root, Some(pair));

        let mut tail = ObserverTail::recognizing(anchor, child);
        tail.set_terminal_cut(Some(WeightedTimestamp::from_millis(CUT_MS)));
        tail.capture_committee(Some(stub_committee()));

        assert_eq!(walk(&mut tail, &terminal), TailOutcome::Accepted);
        assert_eq!(walk(&mut tail, &gap), TailOutcome::Accepted);
        assert!(
            tail.settled_terminal()
                .expect("recognised")
                .commit_proof
                .is_none(),
            "a view change leaves the terminal's own successor unable to prove it",
        );

        assert_eq!(walk(&mut tail, &pairing), TailOutcome::Accepted);
        let (proof, _) = tail
            .settled_terminal()
            .expect("recognised")
            .commit_proof
            .as_ref()
            .expect("the later coast pair proves the terminal");
        assert_eq!(
            proof.proven_block_hash(),
            terminal.hash(),
            "the ancestry link must bottom out at the terminal",
        );
        // Every structural check passes — linkage, the round-contiguous
        // two-chain, and the ancestry link chaining down to the terminal.
        // Only the signature work fails, against a committee holding no keys.
        let err = proof
            .verify_resolved(
                &BlsVerifier,
                &NetworkDefinition::simulator(),
                &[stub_committee(), stub_committee()],
            )
            .expect_err("a keyless committee cannot satisfy the QCs");
        assert!(
            matches!(err, CommitProofVerifyError::Qc(_)),
            "the prefix proof must be structurally well formed; got {err:?}",
        );
    }

    /// A coast that never pairs for longer than an ancestry link can carry
    /// abandons the proof permanently. Resuming later would prove one of
    /// the coast blocks rather than the terminal beneath them.
    #[test]
    fn a_coast_gap_past_the_ancestry_cap_abandons_the_proof() {
        let (anchor, terminal, _, pair) = straddling_chain();
        let (child, _) = ShardId::ROOT.children();
        let root = pair.composed_root();

        let mut tail = ObserverTail::recognizing(anchor, child);
        tail.set_terminal_cut(Some(WeightedTimestamp::from_millis(CUT_MS)));
        tail.capture_committee(Some(stub_committee()));
        assert_eq!(walk(&mut tail, &terminal), TailOutcome::Accepted);

        // Every coast block skips a round, so no pair is ever contiguous.
        //
        // The run holds the terminal plus its successor after the sighting,
        // and grows by one per block; the cap clears it on the call that
        // finds it already at `MAX + 2`. Exactly this many blocks therefore
        // leaves it cleared, which is the state the resumption guard covers.
        let mut parent = terminal.hash();
        let mut round = 4;
        for i in 0..=MAX_COMMIT_PROOF_ANCESTRY as u64 {
            let block = parent_block(3 + i, round, parent, CUT_MS + 1 + i, root, Some(pair));
            assert_eq!(walk(&mut tail, &block), TailOutcome::Accepted);
            parent = block.hash();
            round += 2;
        }
        assert!(
            tail.settled_terminal()
                .expect("recognised")
                .commit_proof
                .is_none(),
            "no pair ever formed, so nothing proves the terminal",
        );

        // Three more blocks. The first is the call that finds the run over
        // the cap and clears it; the next two are round contiguous, which is
        // what a resumed run would build a direct proof from — committing
        // the second of them, not the terminal far below.
        let next = 4 + MAX_COMMIT_PROOF_ANCESTRY as u64;
        let a = parent_block(next, round, parent, CUT_MS + next, root, Some(pair));
        let b = parent_block(
            next + 1,
            round + 2,
            a.hash(),
            CUT_MS + next + 1,
            root,
            Some(pair),
        );
        let c = parent_block(
            next + 2,
            round + 3,
            b.hash(),
            CUT_MS + next + 2,
            root,
            Some(pair),
        );
        for block in [&a, &b, &c] {
            assert_eq!(walk(&mut tail, block), TailOutcome::Accepted);
        }
        assert!(
            tail.settled_terminal()
                .expect("recognised")
                .commit_proof
                .is_none(),
            "an abandoned run must not resume and commit a coast block",
        );
    }

    // ─── following: committed blocks only ───────────────────────────────

    /// A parent chain whose QCs a real committee signs, for the tests that
    /// verify them.
    struct SignedChain {
        committee: TestCommittee,
    }

    impl SignedChain {
        fn new() -> Self {
            Self {
                committee: TestCommittee::new(4, 7),
            }
        }

        /// A quorum's QC over `header`, stamping `wt`.
        fn qc(&self, header: &BlockHeader, wt: u64) -> QuorumCertificate {
            sign_by(&self.committee, header, wt)
        }

        /// A block extending `parent` at `round`, its parent QC a genuine
        /// certificate over `parent` stamping `pred_wt`.
        fn child(&self, parent: &Block, round: u64, pred_wt: u64) -> Block {
            signed_child_block(
                &self.committee,
                parent,
                Round::new(round),
                WeightedTimestamp::from_millis(pred_wt),
            )
        }

        fn child_carrying(
            &self,
            parent: &Block,
            round: u64,
            pred_wt: u64,
            state_root: StateRoot,
            pair: Option<SplitChildRoots>,
            terminal_settled_txs: Option<SettledTxsRoot>,
        ) -> Block {
            block_on(
                self.qc(parent.header(), pred_wt),
                parent.height().inner() + 1,
                round,
                parent.hash(),
                state_root,
                pair,
                terminal_settled_txs,
            )
        }

        /// `block` as a peer serves it, with a genuine QC over it.
        fn served(&self, block: &Block) -> GetBlockResponse {
            served_with(block, self.qc(block.header(), 9_999))
        }

        /// What the follow's schedule resolves for every QC: this committee.
        fn resolved(&self) -> CommitteeLookup {
            CommitteeLookup::Resolved(ResolvedCommittee {
                public_keys: self.committee.public_keys().to_vec(),
                quorum_threshold: VoteCount::of(self.committee.quorum_threshold()),
            })
        }

        /// One proving pass against this committee.
        fn prove(&self, tail: &mut ObserverTail) -> ProveOutcome {
            tail.prove(&BlsVerifier, &NetworkDefinition::simulator(), |_, _| {
                self.resolved()
            })
        }
    }

    fn sign_by(committee: &TestCommittee, header: &BlockHeader, wt: u64) -> QuorumCertificate {
        committee.sign_qc(
            header,
            &committee.quorum_indices(),
            WeightedTimestamp::from_millis(wt),
        )
    }

    fn served_with(block: &Block, qc: QuorumCertificate) -> GetBlockResponse {
        GetBlockResponse::found(ElidedCertifiedBlock::elide(block, qc, &Inventory::empty()))
    }

    /// The anchor block a follow starts above, and the anchor naming it.
    fn signed_anchor() -> (Block, ShardAnchor) {
        let block = parent_block(1, 1, BlockHash::ZERO, 4_000, StateRoot::ZERO, None);
        let anchor = ShardAnchor {
            state_root: StateRoot::ZERO,
            block_hash: block.hash(),
            height: BlockHeight::new(1),
            weighted_timestamp: WeightedTimestamp::from_millis(4_000),
            witness_base: BeaconWitnessLeafCount::ZERO,
            terminal_settled_txs: None,
            handoff_complete: None,
            terminal_epoch: None,
        };
        (block, anchor)
    }

    /// Fetch the next block and feed it `response`.
    fn feed(tail: &mut ObserverTail, response: &GetBlockResponse) -> TailOutcome {
        let _ = tail.next_request().expect("the follow has room to fetch");
        tail.on_response(response)
    }

    /// Apply every proven block the tail offers, answering with `root`,
    /// and return their hashes in the order applied.
    fn apply_all(tail: &mut ObserverTail, root: StateRoot) -> Vec<BlockHash> {
        let mut applied = Vec::new();
        while let Some(block) = tail.take_apply() {
            applied.push(block.hash());
            tail.on_applied(root)
                .expect("the applied root is not checked");
        }
        applied
    }

    /// A block is applied only once the block above it arrives and the two
    /// form a verified round-contiguous two-chain — the next block's
    /// fetch runs ahead of what the store takes.
    #[test]
    fn a_following_tail_applies_a_block_only_once_a_two_chain_proves_it() {
        let chain = SignedChain::new();
        let (anchor_block, anchor) = signed_anchor();
        let b2 = chain.child(&anchor_block, 2, 4_100);
        let b3 = chain.child(&b2, 3, 4_200);
        let (child, _) = ShardId::ROOT.children();
        let mut tail = ObserverTail::new(anchor, child);

        assert_eq!(feed(&mut tail, &chain.served(&b2)), TailOutcome::Accepted);
        assert_eq!(chain.prove(&mut tail), ProveOutcome::Unproven);
        assert!(
            tail.take_apply().is_none(),
            "a lone certified block proves nothing"
        );

        assert_eq!(feed(&mut tail, &chain.served(&b3)), TailOutcome::Accepted);
        assert_eq!(chain.prove(&mut tail), ProveOutcome::Released(1));
        assert_eq!(apply_all(&mut tail, StateRoot::ZERO), vec![b2.hash()]);
        assert_eq!(tail.next_height(), BlockHeight::new(3));
    }

    /// A losing sibling carries a genuine QC — two blocks can be certified
    /// at one height — so nothing about it alone gives it away. It waits
    /// unproven until the committed chain's next block contradicts it, and
    /// is dropped without ever reaching the store.
    #[test]
    fn a_served_losing_sibling_is_never_applied() {
        let chain = SignedChain::new();
        let (anchor_block, anchor) = signed_anchor();
        let committed = chain.child(&anchor_block, 2, 4_100);
        let sibling = chain.child(&anchor_block, 3, 4_150);
        // Certified above the sibling, but a round short of committing it.
        let sibling_child = chain.child(&sibling, 5, 4_300);
        let b3 = chain.child(&committed, 3, 4_200);
        let b4 = chain.child(&b3, 4, 4_400);
        let (child, _) = ShardId::ROOT.children();
        let mut tail = ObserverTail::new(anchor, child);

        assert_eq!(
            feed(&mut tail, &chain.served(&sibling)),
            TailOutcome::Accepted
        );
        assert_eq!(
            feed(&mut tail, &chain.served(&sibling_child)),
            TailOutcome::Accepted
        );
        assert_eq!(
            chain.prove(&mut tail),
            ProveOutcome::Unproven,
            "no round-contiguous pair stands over the sibling",
        );
        assert!(tail.take_apply().is_none());

        // An honest peer answers the next height from the committed chain.
        assert!(matches!(
            feed(&mut tail, &chain.served(&b4)),
            TailOutcome::Rejected(_)
        ));
        assert_eq!(
            tail.next_request().map(|request| request.height),
            Some(BlockHeight::new(2)),
            "the contradicted run is dropped and the follow refetches above the anchor",
        );
        tail.on_failure();

        for block in [&committed, &b3] {
            assert_eq!(feed(&mut tail, &chain.served(block)), TailOutcome::Accepted);
        }
        assert_eq!(chain.prove(&mut tail), ProveOutcome::Released(1));
        assert_eq!(
            apply_all(&mut tail, StateRoot::ZERO),
            vec![committed.hash()],
            "only the committed block reaches the store",
        );
    }

    /// A fabricated extension is shaped like a commit — hash linked and
    /// round contiguous — but its QCs are not the parent committee's. The
    /// proof fails, the run is dropped, and nothing is applied.
    #[test]
    fn a_fabricated_extension_with_a_forged_qc_is_never_applied() {
        let chain = SignedChain::new();
        let impostors = TestCommittee::new(4, 99);
        let (anchor_block, anchor) = signed_anchor();
        let forged = block_on(
            sign_by(&impostors, anchor_block.header(), 4_100),
            2,
            2,
            anchor_block.hash(),
            StateRoot::from_raw(Hash::from_bytes(b"forged root")),
            None,
            None,
        );
        let forged_child = block_on(
            sign_by(&impostors, forged.header(), 4_200),
            3,
            3,
            forged.hash(),
            StateRoot::ZERO,
            None,
            None,
        );
        let (child, _) = ShardId::ROOT.children();
        let mut tail = ObserverTail::new(anchor, child);

        assert_eq!(
            feed(
                &mut tail,
                &served_with(&forged, sign_by(&impostors, forged.header(), 9_999))
            ),
            TailOutcome::Accepted,
        );
        assert_eq!(
            feed(
                &mut tail,
                &served_with(
                    &forged_child,
                    sign_by(&impostors, forged_child.header(), 9_999)
                ),
            ),
            TailOutcome::Accepted,
        );
        assert!(matches!(chain.prove(&mut tail), ProveOutcome::Refuted(_)));
        assert!(
            tail.take_apply().is_none(),
            "a forged two-chain releases nothing"
        );

        // The follow starts over above the anchor, where the honest chain
        // proves out as usual.
        let b2 = chain.child(&anchor_block, 2, 4_100);
        let b3 = chain.child(&b2, 3, 4_200);
        for block in [&b2, &b3] {
            assert_eq!(feed(&mut tail, &chain.served(block)), TailOutcome::Accepted);
        }
        assert_eq!(chain.prove(&mut tail), ProveOutcome::Released(1));
        assert_eq!(apply_all(&mut tail, StateRoot::ZERO), vec![b2.hash()]);
    }

    /// A served QC over a genuine block that the committee never signed
    /// is caught by the same proof, even when every header is real.
    #[test]
    fn a_genuine_block_served_with_a_forged_qc_is_refuted() {
        let chain = SignedChain::new();
        let impostors = TestCommittee::new(4, 99);
        let (anchor_block, anchor) = signed_anchor();
        let b2 = chain.child(&anchor_block, 2, 4_100);
        let b3 = chain.child(&b2, 3, 4_200);
        let (child, _) = ShardId::ROOT.children();
        let mut tail = ObserverTail::new(anchor, child);

        assert_eq!(feed(&mut tail, &chain.served(&b2)), TailOutcome::Accepted);
        assert_eq!(
            feed(
                &mut tail,
                &served_with(&b3, sign_by(&impostors, b3.header(), 9_999))
            ),
            TailOutcome::Accepted,
        );
        assert!(matches!(chain.prove(&mut tail), ProveOutcome::Refuted(_)));
        assert!(tail.take_apply().is_none());
    }

    /// A committee this host's beacon has not folded yet leaves the run in
    /// place for a later pass; one no honest QC resolves to drops it.
    #[test]
    fn an_unresolved_committee_defers_and_an_unresolvable_one_refutes() {
        let chain = SignedChain::new();
        let (anchor_block, anchor) = signed_anchor();
        let b2 = chain.child(&anchor_block, 2, 4_100);
        let b3 = chain.child(&b2, 3, 4_200);
        let (child, _) = ShardId::ROOT.children();
        let network = NetworkDefinition::simulator();
        let mut tail = ObserverTail::new(anchor, child);
        for block in [&b2, &b3] {
            assert_eq!(feed(&mut tail, &chain.served(block)), TailOutcome::Accepted);
        }

        assert_eq!(
            tail.prove(&BlsVerifier, &network, |_, _| CommitteeLookup::Pending),
            ProveOutcome::Unproven,
        );
        assert_eq!(chain.prove(&mut tail), ProveOutcome::Released(1));

        let b4 = chain.child(&b3, 4, 4_300);
        assert_eq!(feed(&mut tail, &chain.served(&b4)), TailOutcome::Accepted);
        assert!(matches!(
            tail.prove(&BlsVerifier, &network, |_, _| CommitteeLookup::Unresolvable),
            ProveOutcome::Refuted(_),
        ));
    }

    /// A view change leaves a certified block without a contiguous child;
    /// it commits as the prefix of the next pair above it, and both are
    /// released together, lowest first.
    #[test]
    fn a_view_change_releases_the_prefix_with_the_next_pair() {
        let chain = SignedChain::new();
        let (anchor_block, anchor) = signed_anchor();
        let b2 = chain.child(&anchor_block, 2, 4_100);
        let b3 = chain.child(&b2, 4, 4_200);
        let b4 = chain.child(&b3, 5, 4_300);
        let (child, _) = ShardId::ROOT.children();
        let mut tail = ObserverTail::new(anchor, child);

        for block in [&b2, &b3] {
            assert_eq!(feed(&mut tail, &chain.served(block)), TailOutcome::Accepted);
        }
        assert_eq!(chain.prove(&mut tail), ProveOutcome::Unproven);
        assert_eq!(feed(&mut tail, &chain.served(&b4)), TailOutcome::Accepted);
        assert_eq!(chain.prove(&mut tail), ProveOutcome::Released(2));
        assert_eq!(
            apply_all(&mut tail, StateRoot::ZERO),
            vec![b2.hash(), b3.hash()],
        );
    }

    /// A following tail recognises the same crossing, but withholds the
    /// sighting until the store has applied through the terminal's
    /// successor — the genesis adopts the child subtree as of the
    /// terminal's root, and both must be proven committed to be applied.
    #[test]
    fn a_following_tail_follows_to_the_terminal() {
        let chain = SignedChain::new();
        let (anchor_block, anchor) = signed_anchor();
        let left = StateRoot::from_raw(Hash::from_bytes(b"left subtree"));
        let right = StateRoot::from_raw(Hash::from_bytes(b"right subtree"));
        let pair = SplitChildRoots { left, right };
        let root = pair.composed_root();
        let terminal = chain.child_carrying(
            &anchor_block,
            2,
            CUT_MS + 250,
            root,
            Some(pair),
            Some(SettledTxsRoot::ZERO),
        );
        let coast = chain.child_carrying(&terminal, 3, CUT_MS + 500, root, Some(pair), None);
        let beyond = chain.child_carrying(&coast, 4, CUT_MS + 750, root, Some(pair), None);
        let (child, _) = ShardId::ROOT.children();

        let mut tail = ObserverTail::new(anchor, child);
        tail.set_terminal_cut(Some(WeightedTimestamp::from_millis(CUT_MS)));

        for block in [&terminal, &coast] {
            assert_eq!(feed(&mut tail, &chain.served(block)), TailOutcome::Accepted);
        }
        assert_eq!(chain.prove(&mut tail), ProveOutcome::Released(1));
        assert_eq!(apply_all(&mut tail, left), vec![terminal.hash()]);
        assert!(
            tail.settled_terminal().is_none(),
            "the terminal's successor is fetched but not yet proven",
        );

        assert_eq!(
            feed(&mut tail, &chain.served(&beyond)),
            TailOutcome::Accepted
        );
        assert_eq!(chain.prove(&mut tail), ProveOutcome::Released(1));
        assert!(
            tail.settled_terminal().is_none(),
            "the successor is proven but not yet applied",
        );
        assert_eq!(apply_all(&mut tail, left), vec![coast.hash()]);

        let sighting = tail
            .settled_terminal()
            .expect("applying through the successor releases the sighting");
        assert_eq!(sighting.header.hash(), terminal.hash());
        assert_eq!(
            sighting.canonical_qc.weighted_timestamp(),
            WeightedTimestamp::from_millis(CUT_MS + 500),
            "the certificate is the committed successor's parent QC",
        );
        assert!(sighting.genesis.is_some(), "the pair composes");
    }

    /// The applied root must reproduce the child's half of the pair the
    /// followed header carries; a store that does not has diverged.
    #[test]
    fn an_applied_root_off_the_carried_half_fails_closed() {
        let chain = SignedChain::new();
        let (anchor_block, anchor) = signed_anchor();
        let pair = SplitChildRoots {
            left: StateRoot::from_raw(Hash::from_bytes(b"left subtree")),
            right: StateRoot::from_raw(Hash::from_bytes(b"right subtree")),
        };
        let b2 = chain.child_carrying(
            &anchor_block,
            2,
            4_100,
            pair.composed_root(),
            Some(pair),
            None,
        );
        let b3 = chain.child(&b2, 3, 4_200);
        let (child, _) = ShardId::ROOT.children();
        let mut tail = ObserverTail::new(anchor, child);
        for block in [&b2, &b3] {
            assert_eq!(feed(&mut tail, &chain.served(block)), TailOutcome::Accepted);
        }
        assert_eq!(chain.prove(&mut tail), ProveOutcome::Released(1));
        let _ = tail.take_apply().expect("b2 is proven");
        assert!(tail.on_applied(pair.right).is_err());
    }
}
