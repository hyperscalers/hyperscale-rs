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

use std::sync::Arc;

use hyperscale_hbor::Capped;
use hyperscale_types::network::request::{
    BlockIntent, GetBlockRequest, GetRemoteHeadersRequest, MAX_REMOTE_HEADERS_PER_REQUEST,
};
use hyperscale_types::network::response::{GetBlockResponse, GetStateRangeResponse};
use hyperscale_types::{
    Anchor, Block, BlockHash, BlockHeader, BlockHeight, CertifiedBlockHeader, ChainOrigin,
    CommitProof, MAX_COMMIT_PROOF_ANCESTRY, NetworkDefinition, QuorumCertificate, ReadySignal,
    ResolvedCommittee, ShardAnchor, ShardId, SignError, Signer, StateRoot, ValidatorId,
    WeightedTimestamp, ready_signal_window, shard_prefix_path,
};

use crate::bootstrap::snap_sync::{SnapSync, StateRangeOutcome};
use crate::bootstrap::{BootstrapRequest, SPLIT_BITS, STATE_CHUNK_LIMIT};

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

/// Outcome of feeding one block-sync response to [`ObserverTail`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TailOutcome {
    /// The block chains and is queued for application via
    /// [`ObserverTail::take_apply`].
    Accepted,
    /// The peer doesn't hold the requested height — the parent chain
    /// hasn't reached it yet, or the peer is behind. Re-arm and retry.
    NotYetAvailable,
    /// The response is invalid for this follow; the driver rotates peers.
    Rejected(&'static str),
}

/// The parent's terminal block, recognised by a follower as it passes,
/// with the child genesis derived from it.
///
/// A block `B` is the terminal crossing when its parent QC sits at or
/// before the cut and the QC certifying `B` sits past it. The certifying
/// QC used here is the *canonical* one — carried as the `parent_qc` of
/// `B`'s committed child, the next block the follow accepts — never the
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
    /// certified, with the committee its QCs verify against. Built from
    /// the first round-contiguous pair at or above the terminal — its own
    /// successor when no view change intervened, a later coast pair with
    /// an ancestry link down to it otherwise. Absent until such a pair
    /// arrives, and permanently when the follow never captured the
    /// parent's committee or the gap outgrew [`MAX_COMMIT_PROOF_ANCESTRY`].
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
fn derive_child_genesis(
    child: ShardId,
    terminal: &BlockHeader,
    canonical_wt: WeightedTimestamp,
) -> Option<DerivedGenesis> {
    let (block, origin) = Block::split_child_genesis_from_terminal(child, terminal, canonical_wt)?;
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
/// moves the child half. The follower fetches the parent's committed
/// blocks above `A` one at a time and hands each to the driver to apply
/// through `BoundaryStore::follow_block_writes` (the store-prefix
/// subset of the block's writes; partition independence keeps the
/// store's root exactly the parent tree's child subtree node).
///
/// Trust: each accepted block must extend a hash chain seeded by the
/// beacon-attested anchor's block hash, and in the parent's final epoch
/// every header carries `split_child_roots` — the follower checks its
/// own applied root against its side after each application. Neither
/// authenticates a forged *extension* of the chain on its own (the
/// driver may additionally verify the served QCs); the flip's
/// fail-closed equality against the beacon-seeded child anchor is the
/// end-to-end check, and a corrupted follow costs the duty, never
/// safety.
pub struct ObserverTail {
    child: ShardId,
    /// Hash-chain cursor: the last accepted block's hash, seeded by the
    /// attested anchor's.
    last_hash: BlockHash,
    /// Next parent height to fetch.
    next: BlockHeight,
    /// The parent's scheduled cut, once the beacon has published one.
    /// `None` while the split is admitted but unscheduled.
    terminal_cut: Option<WeightedTimestamp>,
    /// The previously accepted block's header. The crossing test for a
    /// block needs the QC that certifies it, which only arrives with the
    /// next block — and the genesis derivation needs the terminal header
    /// itself, so the follow keeps one block of history.
    prev: Option<BlockHeader>,
    /// The parent's consensus committee, captured while it was still
    /// live so the terminal's QCs stay verifiable after the head moves on.
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
    /// Accepted block waiting for the driver to apply and answer.
    pending: Option<PendingFollow>,
    /// Set while a taken application is out for the driver to apply,
    /// cleared on [`Self::on_applied`]. Guards [`Self::take_apply`] against
    /// re-emitting the same application when the driver re-polls before the
    /// apply answers — the production pump ticks on a timer, so a `step`
    /// can land between the take and its answer.
    apply_in_flight: bool,
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
            last_hash: anchor.block_hash,
            next: anchor.height.next(),
            in_flight: false,
            pending: None,
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
    /// the terminal's QCs can be verified after the head has moved on.
    ///
    /// The driver re-supplies it every step and the last non-empty capture
    /// wins: a split parent leaves the head's committee set the moment its
    /// applying fold lands, which is around when the follow reaches its
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
    #[must_use]
    pub fn settled_terminal(&self) -> Option<&TerminalSighting> {
        let terminal = self.terminal.as_ref()?;
        (self.applied? >= terminal.header.height().next()).then_some(terminal)
    }

    /// The next block fetch, when none is outstanding and nothing is
    /// waiting to be applied. For a following tail, which needs each
    /// block's body to apply its child-half writes.
    pub fn next_request(&mut self) -> Option<GetBlockRequest> {
        if self.in_flight || self.pending.is_some() {
            return None;
        }
        self.in_flight = true;
        Some(GetBlockRequest::new(self.next, BlockIntent::Execute))
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
        if self.in_flight || self.pending.is_some() {
            return None;
        }
        self.in_flight = true;
        Some(GetRemoteHeadersRequest {
            source_shard: source,
            from_height: self.next,
            count: MAX_REMOTE_HEADERS_PER_REQUEST,
        })
    }

    /// Absorb one certified header: the chain link, the terminal crossing
    /// test, and the commitment proof.
    ///
    /// The shared core of both feeds, so a recognizing walk over headers
    /// and a following walk over blocks cannot drift on which block is the
    /// terminal or what proves it.
    fn absorb_header(&mut self, header: &BlockHeader, qc: &QuorumCertificate) -> TailOutcome {
        if header.height() != self.next {
            return TailOutcome::Rejected("block height does not match the requested height");
        }
        if header.parent_block_hash() != self.last_hash {
            return TailOutcome::Rejected("block does not extend the attested anchor chain");
        }
        // This block's parent QC is the canonical certificate over its
        // predecessor, so accepting it is what decides whether that
        // predecessor was the terminal crossing: the predecessor's own
        // parent QC sits at or before the cut, and this one past it.
        let parent_qc_wt = header.parent_qc().weighted_timestamp();
        if let Some(cut) = self.terminal_cut
            && self.terminal.is_none()
            && let Some(terminal) = &self.prev
            && terminal.parent_qc().weighted_timestamp().as_millis() <= cut.as_millis()
            && parent_qc_wt.as_millis() > cut.as_millis()
        {
            // The run the commitment proof walks back down starts at the
            // terminal itself; the coast blocks above it are appended as
            // they arrive.
            self.since_terminal = vec![terminal.clone()];
            self.terminal = Some(TerminalSighting {
                header: terminal.clone(),
                canonical_qc: header.parent_qc().clone(),
                genesis: derive_child_genesis(self.child, terminal, parent_qc_wt),
                commit_proof: None,
            });
        }
        self.advance_commit_proof(header, qc);
        self.prev = Some(header.clone());
        if self.recognition_only {
            self.applied = Some(header.height());
        }
        self.last_hash = header.hash();
        self.next = self.next.next();
        TailOutcome::Accepted
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
            let outcome = self.absorb_header(certified.header(), certified.qc());
            if outcome != TailOutcome::Accepted {
                return outcome;
            }
        }
        TailOutcome::Accepted
    }

    /// Feed the response for the outstanding fetch.
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
        // header. The QC's signature is the driver's to verify.
        let Ok(certified) = elided.try_rehydrate(|_| None, |_| None, |_| None) else {
            return TailOutcome::Rejected("elided or mispaired block body");
        };
        let header = certified.block().header();
        let expected_root = header.split_child_roots().map(|pair| {
            if self.child.path() & 1 == 0 {
                pair.left
            } else {
                pair.right
            }
        });
        let outcome = self.absorb_header(header, certified.qc());
        if outcome != TailOutcome::Accepted {
            return outcome;
        }
        if !self.recognition_only {
            self.pending = Some(PendingFollow {
                block: Arc::new(certified.block().clone()),
                expected_root,
            });
        }
        TailOutcome::Accepted
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

    /// The accepted block, ready for `BoundaryStore::follow_block_writes`
    /// on the observer's store. `Some` once per accepted block; the driver
    /// answers with the resulting root via [`Self::on_applied`].
    pub fn take_apply(&mut self) -> Option<Arc<Block>> {
        if self.apply_in_flight {
            return None;
        }
        let pending = self.pending.as_ref()?;
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
        self.apply_in_flight = false;
        let pending = self
            .pending
            .take()
            .expect("on_applied outside a taken application");
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

    /// The next parent height the follower wants.
    #[must_use]
    pub const fn next_height(&self) -> BlockHeight {
        self.next
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
    use hyperscale_types::{
        AggregateSignature, BeaconWitnessLeafCount, BlockHeaderParts, CommitProofVerifyError,
        ElidedCertifiedBlock, Hash, Inventory, Round, SignerBitfield, SplitChildRoots, VoteCount,
        WitnessSources,
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
        let header = BlockHeader::new(BlockHeaderParts {
            height: BlockHeight::new(height),
            parent_block_hash: parent,
            parent_qc: parent_qc.into(),
            round: Round::new(round),
            state_root,
            provision_tx_roots: Capped::default(),
            split_child_roots: pair,
            ..Default::default()
        });
        Block::Live {
            header,
            transactions: Arc::new(Capped::empty()),
            certificates: Arc::new(Capped::empty()),
            provisions: Arc::new(Capped::empty()),
            abandonment_records: Arc::new(Capped::empty()),
            state_claims: Arc::new(Capped::empty()),
            witness_sources: Arc::new(WitnessSources::empty()),
        }
    }

    /// The response a follower gets for `block`, certified by a QC
    /// stamping `served_wt` — deliberately *not* the stamp the derivation
    /// may use, so a test that reads the served QC's clock fails.
    fn response(block: &Block, served_wt: u64) -> GetBlockResponse {
        GetBlockResponse::found(ElidedCertifiedBlock::elide(
            block,
            qc_over(block.header(), served_wt),
            &Inventory::empty(),
        ))
    }

    /// A parent chain straddling the cut: the terminal at height 2 (its
    /// own `parent_qc` at or before the cut) and the coast block at
    /// height 3 whose `parent_qc` lands past it. The terminal carries the
    /// child-root pair composing to its own state root.
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
        };
        // The terminal's own parent QC sits at the cut exactly — the
        // boundary instant counts as not yet crossed.
        let terminal = parent_block(2, 2, anchor.block_hash, CUT_MS, terminal_root, Some(pair));
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

    /// A recognizing follow walks the parent chain, spots the crossing
    /// when the coast block's `parent_qc` lands past the cut, and derives
    /// the child genesis the beacon fold composes from the same terminal.
    ///
    /// The canonical clock is the coast block's `parent_qc`, never the QC
    /// served alongside either block — a terminal re-certified at a higher
    /// round during the coast carries a divergent stamp.
    #[test]
    fn recognizing_follow_derives_the_child_genesis_from_the_terminal() {
        let (anchor, terminal, coast, pair) = straddling_chain();
        let (child, _) = ShardId::ROOT.children();

        let mut tail = ObserverTail::recognizing(anchor, child);
        tail.set_terminal_cut(Some(WeightedTimestamp::from_millis(CUT_MS)));

        assert!(
            tail.next_request().is_some(),
            "the walk starts above the anchor"
        );
        assert_eq!(
            tail.on_response(&response(&terminal, 9_999)),
            TailOutcome::Accepted
        );
        assert!(
            tail.settled_terminal().is_none(),
            "the terminal is not recognised until its successor arrives",
        );

        assert!(tail.next_request().is_some());
        assert_eq!(
            tail.on_response(&response(&coast, 9_999)),
            TailOutcome::Accepted
        );

        let sighting = tail.settled_terminal().expect("the crossing is recognised");
        assert_eq!(sighting.header.hash(), terminal.hash());
        assert_eq!(
            sighting.canonical_qc.weighted_timestamp(),
            WeightedTimestamp::from_millis(CUT_MS + 500),
            "the clock is the coast block's parent QC, not either served QC",
        );

        let derived = sighting.genesis.as_ref().expect("the pair composes");
        let expected = Block::split_child_genesis(
            child,
            pair.left,
            terminal.header(),
            WeightedTimestamp::from_millis(CUT_MS + 500),
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
        let _ = tail.next_request();
        assert_eq!(
            tail.on_response(&response(&terminal, 9_999)),
            TailOutcome::Accepted
        );

        // The applying fold consumed the reshape record, so the head
        // projection no longer names a cut for the parent.
        tail.set_terminal_cut(None);

        let _ = tail.next_request();
        assert_eq!(
            tail.on_response(&response(&coast, 9_999)),
            TailOutcome::Accepted
        );
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
            let _ = tail.next_request();
            assert_eq!(
                tail.on_response(&response(block, 9_999)),
                TailOutcome::Accepted
            );
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
            let _ = tail.next_request();
            assert_eq!(
                tail.on_response(&response(block, 9_999)),
                TailOutcome::Accepted
            );
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

        let _ = tail.next_request();
        assert_eq!(
            tail.on_response(&response(&terminal, 9_999)),
            TailOutcome::Accepted
        );
        let _ = tail.next_request();
        assert_eq!(
            tail.on_response(&response(&gap, 9_999)),
            TailOutcome::Accepted
        );
        assert!(
            tail.settled_terminal()
                .expect("recognised")
                .commit_proof
                .is_none(),
            "a view change leaves the terminal's own successor unable to prove it",
        );

        let _ = tail.next_request();
        assert_eq!(
            tail.on_response(&response(&pairing, 9_999)),
            TailOutcome::Accepted
        );
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
        let _ = tail.next_request();
        assert_eq!(
            tail.on_response(&response(&terminal, 9_999)),
            TailOutcome::Accepted
        );

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
            let _ = tail.next_request();
            assert_eq!(
                tail.on_response(&response(&block, 9_999)),
                TailOutcome::Accepted
            );
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
            let _ = tail.next_request();
            assert_eq!(
                tail.on_response(&response(block, 9_999)),
                TailOutcome::Accepted
            );
        }
        assert!(
            tail.settled_terminal()
                .expect("recognised")
                .commit_proof
                .is_none(),
            "an abandoned run must not resume and commit a coast block",
        );
    }

    /// A following tail recognises the same crossing, but withholds the
    /// sighting until the store has applied through the terminal — the
    /// genesis adopts the child subtree as of *its* root.
    #[test]
    fn a_following_tail_withholds_the_sighting_until_it_has_applied() {
        let (anchor, terminal, coast, _) = straddling_chain();
        let (child, _) = ShardId::ROOT.children();

        let mut tail = ObserverTail::new(anchor, child);
        tail.set_terminal_cut(Some(WeightedTimestamp::from_millis(CUT_MS)));

        let _ = tail.next_request();
        assert_eq!(
            tail.on_response(&response(&terminal, 9_999)),
            TailOutcome::Accepted
        );
        let block = tail
            .take_apply()
            .expect("the terminal is pending application");
        assert_eq!(block.height(), BlockHeight::new(2));
        // The terminal carries the pair, so the applied root must reproduce
        // this child's half.
        tail.on_applied(StateRoot::from_raw(Hash::from_bytes(b"left subtree")))
            .expect("the applied root matches the carried half");

        let _ = tail.next_request();
        assert_eq!(
            tail.on_response(&response(&coast, 9_999)),
            TailOutcome::Accepted
        );
        assert!(
            tail.settled_terminal().is_none(),
            "the successor is accepted but not yet applied",
        );

        let block = tail
            .take_apply()
            .expect("the coast block is pending application");
        assert_eq!(block.height(), BlockHeight::new(3));
        tail.on_applied(StateRoot::from_raw(Hash::from_bytes(b"left subtree")))
            .expect("a coast block moves no state under the prefix");
        assert!(
            tail.settled_terminal().is_some(),
            "applying through the successor releases the sighting",
        );
    }
}
