//! The merge keeper duty: re-assert ready, recognise both children's
//! terminals, build the merged store, and adopt the reformed parent's
//! genesis.

use hyperscale_types::network::request::{BlockIntent, GetBlockRequest};
use hyperscale_types::{
    BlockHash, BlockHeader, LocalTimestamp, QuorumCertificate, ShardAnchor, ShardId, ValidatorId,
    Verifier, WeightedTimestamp,
};

use super::Advance;
use super::io::{AdoptKind, FetchKind, FetchedKind, ReshapeEvent, ReshapeRequest};
use super::shared::{
    REFETCH_WAIT, ReadyAssert, SeatTail, StageQueue, TerminalAsk, paced, recipients_for, seats_on,
    terminal_commit,
};
use crate::bootstrap::{SpanCollect, StateRangeOutcome};
use crate::reshape::genesis::DerivedGenesis;
use crate::reshape::merge_flip::merge_genesis_from_terminals;
use crate::reshape::observer::{ObserverTail, TerminalSighting, TwoChainCheck};
use crate::reshape::view::ReshapeView;

/// One keeper seat this host runs in a pending merge.
pub(super) struct KeeperMember {
    pub(super) validator: ValidatorId,
    pub(super) own_child: ShardId,
    /// Ready re-assertion schedule for this seat.
    pub(super) ready_assert: Option<ReadyAssert>,
}

/// One child half's progress in a keeper's merged-store build: its
/// span assembly (staged into the parent store as chunks arrive) and
/// its certified terminal.
pub(super) struct KeeperHalf {
    child: ShardId,
    span: Box<SpanCollect>,
    terminal: Option<(BlockHeader, QuorumCertificate)>,
    /// The anchored terminal the fetch in flight names.
    terminal_requested: Option<BlockHash>,
    terminal_ask: TerminalAsk,
}

impl KeeperHalf {
    pub(super) fn new(child: ShardId, anchor: ShardAnchor) -> Self {
        Self {
            child,
            span: Box::new(SpanCollect::new(child, anchor)),
            terminal: None,
            terminal_requested: None,
            terminal_ask: TerminalAsk::NOW,
        }
    }

    /// A half whose terminal the keeper already recognised on the child's
    /// own chain, so its span assembles against that terminal rather than
    /// against whichever crossing the beacon last anchored.
    fn recognized(child: ShardId, sighting: &TerminalSighting) -> Self {
        let header = &sighting.header;
        Self {
            child,
            span: Box::new(SpanCollect::new(child, terminal_anchor(header))),
            terminal: Some((header.clone(), sighting.terminal_qc.clone())),
            terminal_requested: None,
            terminal_ask: TerminalAsk::NOW,
        }
    }

    /// Advance the half: forward its snap-sync state ranges (each
    /// verified chunk stages into the parent store through the duty's
    /// queue), and fetch its certified terminal until it arrives.
    pub(super) fn advance(
        &mut self,
        duty: ShardId,
        view: &ReshapeView,
        now: LocalTimestamp,
        out: &mut Vec<ReshapeRequest>,
    ) {
        for (sub_range, request) in self.span.next_requests() {
            out.push(ReshapeRequest::Fetch {
                duty,
                from: self.child,
                kind: FetchKind::StateRange { sub_range, request },
            });
        }
        if self.terminal.is_none()
            && let Some(anchor) = view.boundary(self.child)
            && self.terminal_ask.begin(now)
        {
            // A merging child's boundary anchors its terminal crossing directly —
            // the block whose hash and height the beacon composed the parent from —
            // so the certified terminal sits at the anchor height itself, and is
            // the anchored block: a certified sibling at that height does not
            // answer.
            out.push(ReshapeRequest::Fetch {
                duty,
                from: self.child,
                kind: FetchKind::Block {
                    request: GetBlockRequest::new(anchor.height, BlockIntent::Execute)
                        .naming(anchor.block_hash),
                },
            });
            self.terminal_requested = Some(anchor.block_hash);
        }
    }
}

/// One child's terminal walk in a keeper's merge duty: the follow that
/// finds which of the child's blocks ends its chain, applying nothing.
pub(super) struct KeeperRecognition {
    child: ShardId,
    tail: Box<ObserverTail>,
    /// The terminal once found and commit-proven. Retained so the proof
    /// is verified once rather than on every advance the sibling half
    /// still has to catch up over.
    proven: Option<TerminalSighting>,
}

/// The anchor a recognised terminal stands in for — the record the beacon
/// writes for that same block when its contribution folds an epoch later.
/// Mirrors `record_boundaries`' field-for-field construction, so a half
/// assembled against it verifies exactly as one assembled against the
/// beacon's.
pub(super) fn terminal_anchor(header: &BlockHeader) -> ShardAnchor {
    ShardAnchor {
        state_root: header.state_root(),
        block_hash: header.hash(),
        height: header.height(),
        weighted_timestamp: header.parent_qc().weighted_timestamp(),
        witness_base: header.beacon_witness_base(),
        terminal_settled_txs: header.settled_txs_root(),
        handoff_complete: None,
        terminal_epoch: None,
    }
}

/// The recognition walk covering `from`, when a keeper is still finding
/// its children's terminals.
pub(super) fn recognition_for<'a>(
    left: &'a mut KeeperRecognition,
    right: &'a mut KeeperRecognition,
    from: ShardId,
) -> Option<&'a mut KeeperRecognition> {
    if left.child == from {
        Some(left)
    } else if right.child == from {
        Some(right)
    } else {
        None
    }
}

/// The keeper half `from` addresses, when it is one of the duty's children.
pub(super) fn half_for<'a>(
    left: &'a mut KeeperHalf,
    right: &'a mut KeeperHalf,
    from: ShardId,
) -> Option<&'a mut KeeperHalf> {
    if from == left.child {
        Some(left)
    } else if from == right.child {
        Some(right)
    } else {
        None
    }
}

/// One keeper's progress through its merge duty.
pub(super) enum KeeperPhase {
    /// Re-asserting ready until the cut is in reach.
    ReassertingReady,
    /// Walking both children's chains to find the terminals that end them,
    /// so the parent reforms at the cut rather than an epoch later when the
    /// beacon composes its anchor. Applies nothing — the merged store is
    /// built from the halves' spans in `Building`.
    Recognizing {
        left: Box<KeeperRecognition>,
        right: Box<KeeperRecognition>,
    },
    /// Both terminals in hand; collecting both halves' spans, deriving the
    /// merged genesis, and finalizing the staged union.
    Building {
        /// The instant the children terminate at, and the merged chain's
        /// clock anchor.
        cut_wt: WeightedTimestamp,
        /// The beacon's composed parent anchor, when this duty reached
        /// `Building` by the fallback rather than the cut-over. Present
        /// means the derivation is checked against it. Boxed: the anchor
        /// dwarfs every other variant of the phase.
        anchor: Option<Box<ShardAnchor>>,
        left: Box<KeeperHalf>,
        right: Box<KeeperHalf>,
        derived: Option<Box<DerivedGenesis>>,
        finalize_requested: bool,
    },
    /// Union imported; adopting the merged genesis and seating the keepers.
    Seat(SeatTail),
}

/// One merge keeper duty, keyed by the parent it reforms.
pub(super) struct KeeperDuty {
    parent: ShardId,
    pub(super) members: Vec<KeeperMember>,
    phase: KeeperPhase,
    open_requested: bool,
    store_opened: bool,
    /// Verified chunks from either half — their spans are disjoint.
    stages: StageQueue,
}

impl KeeperDuty {
    pub(super) const fn new(parent: ShardId) -> Self {
        Self {
            parent,
            members: Vec::new(),
            phase: KeeperPhase::ReassertingReady,
            open_requested: false,
            store_opened: false,
            stages: StageQueue {
                pending: Vec::new(),
                unacked: 0,
            },
        }
    }

    /// Whether the duty still has a seat to take, pruning the seats it no
    /// longer holds — the merge counterpart of [`ObserverDuty::held`](super::observer_duty::ObserverDuty::held). A
    /// member this host no longer runs is gone; until the merge is
    /// irrevocable a seat stands only while the keeper cohort names it;
    /// past that point the duty runs on while one of its members sits on
    /// the reformed parent's committee, or the parent has none yet.
    pub(super) fn held(&mut self, view: &ReshapeView, me: &[ValidatorId]) -> bool {
        let parent = self.parent;
        let irrevocable = view.merge_irrevocable(parent);
        self.members.retain(|member| {
            me.contains(&member.validator)
                && (irrevocable
                    || view.keeper_parent(member.own_child, member.validator) == Some(parent))
        });
        !self.members.is_empty()
            && (!irrevocable
                || seats_on(
                    view,
                    parent,
                    self.members.iter().map(|member| &member.validator),
                ))
    }

    /// Route one io result to the half or walk awaiting it.
    pub(super) fn apply(&mut self, event: ReshapeEvent, now: LocalTimestamp) {
        match event {
            ReshapeEvent::Opened { .. } => self.store_opened = true,
            ReshapeEvent::Fetched { from, kind, .. } => self.on_fetched(from, kind, now),
            ReshapeEvent::FetchFailed { from, kind, .. } => self.on_fetch_failed(from, &kind, now),
            ReshapeEvent::Staged { .. } => self.stages.on_staged(),
            ReshapeEvent::StageFailed {
                progress, leaves, ..
            } => self.stages.on_stage_failed(progress, leaves),
            ReshapeEvent::Imported { .. } => {
                // The merged union imported; emit the adopt next.
                if let KeeperPhase::Building { derived, .. } = &mut self.phase
                    && let Some(genesis) = derived.take()
                {
                    self.phase = KeeperPhase::Seat(SeatTail::Adopting(genesis));
                }
            }
            ReshapeEvent::Adopted { .. } => {
                if let KeeperPhase::Seat(tail) = &mut self.phase {
                    tail.on_adopted();
                }
            }
            ReshapeEvent::Applied { .. }
            | ReshapeEvent::SeedDeferred { .. }
            | ReshapeEvent::SeedUnavailable { .. } => {}
        }
    }

    /// Re-arm a failed fetch on the half or walk awaiting it.
    fn on_fetch_failed(&mut self, from: ShardId, kind: &FetchKind, now: LocalTimestamp) {
        match &mut self.phase {
            KeeperPhase::Recognizing { left, right } => {
                if let Some(half) = recognition_for(left, right, from) {
                    half.tail.on_failure();
                }
            }
            KeeperPhase::Building { left, right, .. } => {
                if let Some(half) = half_for(left, right, from) {
                    match kind {
                        FetchKind::StateRange { sub_range, .. } => {
                            half.span.on_state_range_failure(*sub_range);
                        }
                        FetchKind::Block { .. } => {
                            half.terminal_requested = None;
                            half.terminal_ask.missed(now);
                        }
                        // A building half walks no headers.
                        FetchKind::Headers { .. } => {}
                    }
                }
            }
            KeeperPhase::ReassertingReady | KeeperPhase::Seat(_) => {}
        }
    }

    /// Route a half's fetch response, recording its terminal once served.
    fn on_fetched(&mut self, from: ShardId, kind: FetchedKind, now: LocalTimestamp) {
        let parent = self.parent;
        if let KeeperPhase::Recognizing { left, right } = &mut self.phase {
            if let FetchedKind::Headers { response } = &kind
                && let Some(half) = recognition_for(left, right, from)
            {
                let outcome = half.tail.on_certified_headers(&response.headers);
                paced(&mut half.tail, outcome, now, parent);
            }
            return;
        }
        let KeeperPhase::Building { left, right, .. } = &mut self.phase else {
            return;
        };
        let Some(half) = half_for(left, right, from) else {
            return;
        };
        match kind {
            FetchedKind::StateRange {
                sub_range,
                response,
            } => {
                if let StateRangeOutcome::Staged { leaves, progress } =
                    half.span.on_state_range(sub_range, &response)
                {
                    self.stages.push(progress, leaves);
                }
            }
            // A building half walks no headers.
            FetchedKind::Headers { .. } => {}
            // Only the anchored terminal is recorded; anything else leaves
            // the half without one, and the next advance asks again.
            FetchedKind::Block { response } => {
                let expected = half.terminal_requested.take();
                half.terminal_ask.missed(now);
                if let Some(elided) = response.block() {
                    let served = elided.header().hash();
                    if expected == Some(served) {
                        half.terminal = Some((elided.header().clone(), elided.qc().clone()));
                    } else {
                        tracing::warn!(
                            child = ?half.child,
                            ?served,
                            ?expected,
                            "a keeper's terminal fetch returned a block other than the anchored terminal"
                        );
                    }
                }
            }
        }
    }

    /// Advance the duty, emitting its current io.
    #[allow(clippy::too_many_lines)] // single dispatch over KeeperPhase
    pub(super) fn advance(
        &mut self,
        view: &ReshapeView,
        verifier: &dyn Verifier,
        now: LocalTimestamp,
        out: &mut Vec<ReshapeRequest>,
    ) -> Advance {
        let parent = self.parent;
        match &mut self.phase {
            KeeperPhase::ReassertingReady => {
                let (left, right) = parent.children();
                // With both cuts scheduled a window ahead, the children's own
                // chains say which of their blocks end them — no need to wait
                // for the beacon to compose the parent's anchor. Only when
                // genuinely early: once that anchor projects the children have
                // terminated and may already have dissolved, so a walk of
                // their chains would never resolve.
                if !view.merge_composed(parent)
                    && view.terminal_cut(left).is_some()
                    && view.terminal_cut(right).is_some()
                    && let Some(left_anchor) = view.boundary(left)
                    && let Some(right_anchor) = view.boundary(right)
                {
                    self.phase = KeeperPhase::Recognizing {
                        left: Box::new(KeeperRecognition {
                            child: left,
                            tail: Box::new(ObserverTail::recognizing(left_anchor, left)),
                            proven: None,
                        }),
                        right: Box::new(KeeperRecognition {
                            child: right,
                            tail: Box::new(ObserverTail::recognizing(right_anchor, right)),
                            proven: None,
                        }),
                    };
                    return Advance::Continue;
                }
                // Fallback: build once the merge has executed — the beacon
                // seated a live committee on the reformed parent and composed
                // its anchor. A bare `boundary(parent)` would also match the
                // parent's own pre-merge terminal record (a grow-then-merge
                // reforms a shard that split earlier), firing the build against
                // the wrong anchor and quitting the ready re-assert before the
                // gate fires.
                if view.merge_composed(parent)
                    && let Some(parent_anchor) = view.boundary(parent)
                    && let Some(left_anchor) = view.boundary(left)
                    && let Some(right_anchor) = view.boundary(right)
                {
                    self.phase = KeeperPhase::Building {
                        cut_wt: parent_anchor.weighted_timestamp,
                        // The fallback holds the composed anchor, so the
                        // derivation is checked against it. The cut-over path
                        // below has none yet — its guard is the pair of
                        // commitment proofs it built the terminals from.
                        anchor: Some(Box::new(parent_anchor)),
                        left: Box::new(KeeperHalf::new(left, left_anchor)),
                        right: Box::new(KeeperHalf::new(right, right_anchor)),
                        derived: None,
                        finalize_requested: false,
                    };
                    return Advance::Continue;
                }
                for member in &mut self.members {
                    let Some(anchor) = view.boundary(member.own_child) else {
                        continue;
                    };
                    if view.keeper_ready(member.own_child, member.validator) {
                        // Credited: the merge gate has this seat's readiness.
                        member.ready_assert = None;
                        continue;
                    }
                    let recipients = recipients_for(view, member.own_child, member.validator);
                    if !ReadyAssert::should_assert(
                        &mut member.ready_assert,
                        anchor.weighted_timestamp,
                        &recipients,
                        now,
                    ) {
                        continue;
                    }
                    out.push(ReshapeRequest::BroadcastReady {
                        validator: member.validator,
                        child: member.own_child,
                        anchor,
                        recipients,
                    });
                }
            }
            KeeperPhase::Recognizing { left, right } => {
                for half in [&mut *left, &mut *right] {
                    if half.proven.is_some() {
                        continue;
                    }
                    half.tail.set_terminal_cut(view.terminal_cut(half.child));
                    let check = half
                        .tail
                        .settled_terminal()
                        .map(|sighting| terminal_commit(half.child, sighting, verifier, view));
                    if matches!(check, Some(TwoChainCheck::Refuted(_))) {
                        half.tail.restart();
                        half.tail.defer(now.plus(REFETCH_WAIT));
                    }
                    if check == Some(TwoChainCheck::Verified) {
                        half.proven = half.tail.settled_terminal().cloned();
                    } else if let Some(request) = half.tail.next_header_request(half.child, now) {
                        out.push(ReshapeRequest::Fetch {
                            duty: parent,
                            from: half.child,
                            kind: FetchKind::Headers { request },
                        });
                    }
                }
                // Both children's terminals are commit-proven, so the merged
                // root composes from a pair neither chain can have forged.
                // Both terminate on one cut — a merge stamps its two children
                // in a single step — so either child's resolves it. Read from
                // the tail's latch, not the projection: the applying fold has
                // consumed the record by the time both walks finish, so the
                // view no longer names the cut this parent's clock anchors at.
                if let (Some(left_sighting), Some(right_sighting)) = (&left.proven, &right.proven)
                    && let Some(cut_wt) = left.tail.terminal_cut()
                {
                    tracing::info!(
                        ?parent,
                        left_terminal = left_sighting.header.height().inner(),
                        right_terminal = right_sighting.header.height().inner(),
                        "reforming the merged parent from both children's own chains"
                    );
                    self.phase = KeeperPhase::Building {
                        cut_wt,
                        anchor: None,
                        left: Box::new(KeeperHalf::recognized(left.child, left_sighting)),
                        right: Box::new(KeeperHalf::recognized(right.child, right_sighting)),
                        derived: None,
                        finalize_requested: false,
                    };
                } else if view.merge_composed(parent) {
                    // The walk ran out of time: the beacon has composed the
                    // parent's anchor, so the children have terminated and may
                    // already have dissolved — nothing further will arrive to
                    // prove. Hand back to the re-assert, whose compose branch
                    // builds against that anchor.
                    tracing::debug!(
                        ?parent,
                        "merge terminal walk did not resolve before the parent composed; \
                         falling back to the attested anchor"
                    );
                    self.phase = KeeperPhase::ReassertingReady;
                }
            }
            KeeperPhase::Building {
                cut_wt,
                anchor,
                left,
                right,
                derived,
                finalize_requested,
            } => {
                if !self.open_requested {
                    out.push(ReshapeRequest::OpenStore { shard: parent });
                    self.open_requested = true;
                }
                self.stages.emit(parent, out);
                // The halves stage straight into the parent store, so their
                // fetches wait for it to open.
                if self.store_opened {
                    left.advance(parent, view, now, out);
                    right.advance(parent, view, now, out);
                }
                if derived.is_none()
                    && let (Some((left_h, left_qc)), Some((right_h, right_qc))) =
                        (&left.terminal, &right.terminal)
                    && let Ok(genesis) = merge_genesis_from_terminals(
                        parent,
                        (left_h, left_qc),
                        (right_h, right_qc),
                        *cut_wt,
                    )
                {
                    // On the fallback the beacon has already composed this
                    // parent, so the derivation is checked against it —
                    // agreement is free, and disagreement means the local
                    // child chains and the network disagree about a committed
                    // block. The terminals are the anchored blocks and the
                    // clock is the anchor's, so deriving again disagrees the
                    // same way: the duty ends, and the parent's seat is the
                    // ordinary join's, which snap-syncs against that anchor.
                    if let Some(anchored) = anchor.as_deref().map(|a| a.block_hash)
                        && genesis.block.hash() != anchored
                    {
                        tracing::error!(
                            ?parent,
                            derived = ?genesis.block.hash(),
                            ?anchored,
                            "derived merged-parent genesis does not reconstruct \
                             the beacon anchor; leaving the parent to the join"
                        );
                        return Advance::Done;
                    }
                    *derived = Some(Box::new(genesis));
                }
                if !*finalize_requested
                    && self.stages.is_durable()
                    && left.span.is_staged()
                    && right.span.is_staged()
                    && let Some(genesis) = derived.as_deref()
                {
                    out.push(ReshapeRequest::FinalizeImport {
                        shard: parent,
                        height: genesis.origin.genesis_height,
                    });
                    *finalize_requested = true;
                }
            }
            KeeperPhase::Seat(tail) => {
                tail.advance(
                    parent,
                    AdoptKind::Merge,
                    self.members.iter().map(|member| &member.validator),
                    view,
                    out,
                );
                if matches!(tail, SeatTail::Seated) {
                    return Advance::Done;
                }
            }
        }
        Advance::Continue
    }
}

#[cfg(test)]
mod tests {

    use hyperscale_crypto_bls::BlsVerifier;
    use hyperscale_storage::test_helpers::{
        make_test_block, make_test_block_with_anchor_wt, make_test_certified,
    };
    use hyperscale_types::network::response::GetBlockResponse;
    use hyperscale_types::test_utils::StubVmStatics;
    use hyperscale_types::{
        Block, BlockHeight, ElidedCertifiedBlock, Inventory, ShardAnchor, ShardId,
    };

    use super::*;
    use crate::reshape::observer::ObserverTail;
    use crate::reshape::orchestrator::ReshapeOrchestrator;
    use crate::reshape::orchestrator::io::{FetchKind, FetchedKind, ReshapeEvent, ReshapeRequest};
    use crate::reshape::orchestrator::shared::{REFETCH_WAIT, SeatTail, StageQueue};
    use crate::reshape::orchestrator::test_support::*;
    use crate::reshape::view::ReshapeView;

    /// The keeper half of the same rule: a keeper the merge gate has already
    /// counted stops re-asserting.
    #[test]
    fn a_credited_keeper_seat_stops_asserting() {
        let parent = ShardId::ROOT;
        let (own_child, _) = parent.children();
        let snap = snapshot_keepers_with_ready(
            &[(own_child, &[1, 2, 3, 5])],
            &[(own_child, 5, parent, true)],
            &[own_child],
        );
        let schedule = windowed(&snap);
        let view = ReshapeView::new(&schedule);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);

        for step in 0..8 {
            let requests = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));
            assert!(
                !requests
                    .iter()
                    .any(|r| matches!(r, ReshapeRequest::BroadcastReady { .. })),
                "step {step}: a credited keeper must not assert; got {requests:?}",
            );
        }
    }

    /// A merge the beacon cancels — a half went quiet — ends the keeper
    /// duty re-asserting ready for it.
    #[test]
    fn a_cancelled_merge_ends_its_keeper_duty() {
        let parent = ShardId::ROOT;
        let (own_child, _) = parent.children();
        let pending = snapshot_keepers(
            &[(own_child, &[1, 2, 3, 5])],
            &[(own_child, 5, parent)],
            &[own_child],
        );
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);
        let _ = orch.step(
            &ReshapeView::new(&windowed(&pending)),
            &BlsVerifier,
            &StubVmStatics,
            Vec::new(),
            at(0),
        );
        assert!(orch.is_seating(parent));

        let cancelled = snapshot_keepers(&[(own_child, &[1, 2, 3, 5])], &[], &[own_child]);
        let requests = orch.step(
            &ReshapeView::new(&windowed(&cancelled)),
            &BlsVerifier,
            &StubVmStatics,
            Vec::new(),
            at(60_000),
        );
        assert!(
            !orch.is_seating(parent),
            "a cancelled merge's duty must end"
        );
        let requests = [
            requests,
            orch.step(
                &ReshapeView::new(&windowed(&cancelled)),
                &BlsVerifier,
                &StubVmStatics,
                Vec::new(),
                at(120_000),
            ),
        ]
        .concat();
        assert!(
            !requests
                .iter()
                .any(|r| matches!(r, ReshapeRequest::BroadcastReady { .. })),
            "nothing is asserted once the merge is cancelled; got {requests:?}",
        );
    }

    /// A prepared keeper none of whose members the reformed parent's
    /// committee seated has nothing to seat, and ends.
    #[test]
    fn a_prepared_keeper_the_parent_did_not_seat_ends() {
        let parent = ShardId::ROOT;
        let (own_child, _) = parent.children();
        let snap = snapshot_keepers(&[(parent, &[1, 2])], &[], &[]);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);
        insert_keeper(
            &mut orch,
            parent,
            KeeperDuty {
                parent,
                members: vec![KeeperMember {
                    validator: vid(5),
                    own_child,
                    ready_assert: None,
                }],
                phase: KeeperPhase::Seat(SeatTail::Prepared),
                open_requested: true,
                store_opened: true,
                stages: StageQueue::default(),
            },
        );

        let requests = orch.step(
            &ReshapeView::new(&windowed(&snap)),
            &BlsVerifier,
            &StubVmStatics,
            Vec::new(),
            at(0),
        );
        assert!(requests.is_empty());
        assert!(!orch.is_seating(parent));
    }

    #[test]
    fn detects_a_keeper_seat_and_reasserts_ready() {
        let parent = ShardId::ROOT;
        let (own_child, _) = parent.children();
        // The keeper runs `own_child` and reforms `parent`; the parent has not
        // composed yet, so it re-asserts ready to the own-child committee.
        let snap = snapshot_keepers(
            &[(own_child, &[1, 2, 3, 5])],
            &[(own_child, 5, parent)],
            &[own_child],
        );
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);

        let requests = orch.step(
            &ReshapeView::new(&windowed(&snap)),
            &BlsVerifier,
            &StubVmStatics,
            Vec::new(),
            at(0),
        );

        assert!(
            requests.iter().any(|r| matches!(
                r,
                ReshapeRequest::BroadcastReady { validator, recipients, .. }
                    if *validator == vid(5) && !recipients.contains(&vid(5)) && recipients.len() == 3
            )),
            "a keeper must re-assert ready to its own-child committee minus self; got {requests:?}",
        );
    }

    #[test]
    fn the_keeper_gate_opens_the_parent_store_and_collects_both_halves() {
        let parent = ShardId::ROOT;
        let (left, right) = parent.children();
        // The merge reformed the parent — a live parent committee plus both
        // children's terminal anchors → the gate fires.
        let snap = snapshot_keepers(
            &[(parent, &[5, 6]), (left, &[1, 2]), (right, &[3, 4])],
            &[(left, 5, parent)],
            &[parent, left, right],
        );
        let schedule = windowed(&snap);
        let view = ReshapeView::new(&schedule);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);

        // First step fires the gate (ReassertingReady → Building); the second
        // opens the parent store. The halves stage straight into that store,
        // so their fetches wait for the open to land.
        let _ = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));
        let requests = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));

        assert!(
            requests
                .iter()
                .any(|r| matches!(r, ReshapeRequest::OpenStore { shard } if *shard == parent)),
            "the keeper gate must open the parent store; got {requests:?}",
        );
        assert!(
            !requests
                .iter()
                .any(|r| matches!(r, ReshapeRequest::Fetch { .. })),
            "no half may fetch before the parent store opens; got {requests:?}",
        );

        let requests = orch.step(
            &view,
            &BlsVerifier,
            &StubVmStatics,
            vec![ReshapeEvent::Opened { shard: parent }],
            at(0),
        );
        for half in [left, right] {
            assert!(
                requests.iter().any(|r| matches!(
                    r,
                    ReshapeRequest::Fetch { from, kind: FetchKind::StateRange { .. }, .. } if *from == half
                )),
                "the keeper must snap-sync the {half:?} half; got {requests:?}",
            );
        }
    }

    #[test]
    fn a_prepared_keeper_seats_when_placed_on_the_parent() {
        let parent = ShardId::ROOT;
        let (own_child, _) = parent.children();
        // The keeper is now seated on the reformed parent committee.
        let snap = snapshot_keepers(&[(parent, &[1, 5])], &[], &[]);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);
        insert_keeper(
            &mut orch,
            parent,
            KeeperDuty {
                parent,
                members: vec![KeeperMember {
                    validator: vid(5),
                    own_child,
                    ready_assert: None,
                }],
                phase: KeeperPhase::Seat(SeatTail::Prepared),
                open_requested: true,
                store_opened: true,
                stages: StageQueue::default(),
            },
        );

        let requests = orch.step(
            &ReshapeView::new(&windowed(&snap)),
            &BlsVerifier,
            &StubVmStatics,
            Vec::new(),
            at(0),
        );

        assert!(
            matches!(requests.as_slice(), [ReshapeRequest::Seat { shard }] if *shard == parent),
            "a prepared keeper must seat once placed on the parent; got {requests:?}",
        );
    }

    /// A keeper whose walks never resolve hands back to the re-assert once
    /// the beacon composes the parent, so the compose branch can build
    /// against the attested anchor.
    #[test]
    fn a_keeper_walk_falls_back_once_the_parent_composes() {
        let parent = ShardId::ROOT;
        let (left, right) = parent.children();
        // A live committee on a seeded parent is a composed merge.
        let snap = snapshot_keepers(
            &[(parent, &[1, 5]), (left, &[1]), (right, &[1])],
            &[(left, 5, parent)],
            &[parent, left, right],
        );
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);
        insert_keeper(
            &mut orch,
            parent,
            KeeperDuty {
                parent,
                members: vec![KeeperMember {
                    validator: vid(5),
                    own_child: left,
                    ready_assert: None,
                }],
                phase: KeeperPhase::Recognizing {
                    left: Box::new(KeeperRecognition {
                        child: left,
                        tail: Box::new(ObserverTail::recognizing(anchor(), left)),
                        proven: None,
                    }),
                    right: Box::new(KeeperRecognition {
                        child: right,
                        tail: Box::new(ObserverTail::recognizing(anchor(), right)),
                        proven: None,
                    }),
                },
                open_requested: false,
                store_opened: false,
                stages: StageQueue::default(),
            },
        );

        let schedule = windowed(&snap);
        let view = ReshapeView::new(&schedule);
        let _ = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));
        assert!(
            matches!(
                keeper(&orch, parent).phase,
                KeeperPhase::ReassertingReady | KeeperPhase::Building { .. }
            ),
            "the walk must hand back to the re-assert, which builds on the anchor",
        );
    }

    /// A fallback keeper whose derivation disagrees with the composed
    /// anchor ends its duty, leaving the parent to the join, rather than
    /// deriving the same disagreement on every step.
    #[test]
    fn a_keeper_whose_genesis_disagrees_with_the_anchor_ends() {
        let parent = ShardId::ROOT;
        let (left, right) = parent.children();
        let terminal = make_test_block(BlockHeight::new(8));
        let snap = build(
            &[(parent, &[5, 6]), (left, &[1, 2]), (right, &[3, 4])],
            &[],
            &uncredited(&[(left, 5, parent)]),
            &[],
            &[parent, left, right],
            ShardAnchor {
                block_hash: terminal.hash(),
                ..anchor()
            },
        );
        let schedule = windowed(&snap);
        let view = ReshapeView::new(&schedule);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);
        let _ = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));
        let duty = keeper_mut(&mut orch, parent);
        let KeeperPhase::Building {
            left: left_half,
            right: right_half,
            ..
        } = &mut duty.phase
        else {
            panic!("the composed parent builds");
        };
        let certified = make_test_certified(terminal.clone());
        for half in [left_half, right_half] {
            half.terminal = Some((terminal.header().clone(), certified.qc().clone()));
        }

        let _ = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));
        assert!(!orch.is_seating(parent), "the disagreeing keeper must end");
        assert!(
            orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0))
                .is_empty()
        );
    }

    /// A keeper records only the anchored terminal: a fetch answered with
    /// another block at the height leaves the half without a terminal and
    /// asks again once the refetch wait has passed, and the anchored block
    /// ends the fetching.
    #[test]
    fn a_keeper_records_only_the_anchored_terminal() {
        let parent = ShardId::ROOT;
        let (left, right) = parent.children();
        let terminal = make_test_block(BlockHeight::new(8));
        let sibling = make_test_block_with_anchor_wt(BlockHeight::new(8), 5);
        assert_ne!(terminal.hash(), sibling.hash());
        let served = |block: &Block| ReshapeEvent::Fetched {
            duty: parent,
            from: left,
            kind: FetchedKind::Block {
                response: Box::new(GetBlockResponse::found(ElidedCertifiedBlock::elide(
                    block,
                    make_test_certified(block.clone()).qc().clone(),
                    &Inventory::empty(),
                ))),
            },
        };
        let snap = build(
            &[(parent, &[5, 6]), (left, &[1, 2]), (right, &[3, 4])],
            &[],
            &uncredited(&[(left, 5, parent)]),
            &[],
            &[parent, left, right],
            ShardAnchor {
                block_hash: terminal.hash(),
                ..anchor()
            },
        );
        let schedule = windowed(&snap);
        let view = ReshapeView::new(&schedule);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);
        let _ = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));
        let _ = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));
        let requests = orch.step(
            &view,
            &BlsVerifier,
            &StubVmStatics,
            vec![ReshapeEvent::Opened { shard: parent }],
            at(0),
        );
        let fetches = block_fetches(&requests, left);
        assert_eq!(fetches.len(), 1, "got {requests:?}");
        assert_eq!(fetches[0].hash, Some(terminal.hash()));

        let requests = orch.step(
            &view,
            &BlsVerifier,
            &StubVmStatics,
            vec![served(&sibling)],
            at(0),
        );
        assert!(
            block_fetches(&requests, left).is_empty(),
            "a sibling answer is dropped and not asked again at once; got {requests:?}",
        );
        let refetch = u64::try_from(REFETCH_WAIT.as_millis()).expect("fits");
        let requests = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(refetch));
        assert_eq!(
            block_fetches(&requests, left).len(),
            1,
            "the terminal is asked for again after the wait; got {requests:?}",
        );

        let requests = orch.step(
            &view,
            &BlsVerifier,
            &StubVmStatics,
            vec![served(&terminal)],
            at(refetch),
        );
        assert!(
            block_fetches(&requests, left).is_empty(),
            "the anchored terminal is recorded; got {requests:?}",
        );
        let KeeperPhase::Building { left: half, .. } = &keeper(&orch, parent).phase else {
            panic!("the keeper builds the parent");
        };
        assert_eq!(
            half.terminal.as_ref().map(|(header, _)| header.hash()),
            Some(terminal.hash())
        );
    }
}
