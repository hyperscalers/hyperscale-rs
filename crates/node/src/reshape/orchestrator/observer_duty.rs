//! The split observer duty: sync the child span, follow the parent to its
//! terminal crossing, and adopt the child's genesis.

use std::collections::BTreeMap;

use hyperscale_shard::committed_cells_for;
use hyperscale_types::{
    BlockHash, Derivation, FrontierInputs, LocalTimestamp, ShardId, StateRoot, ValidatorId,
    Verifier, derive_block_transactions,
};

use super::Advance;
use super::io::{AdoptKind, FetchKind, FetchedKind, ReshapeEvent, ReshapeRequest};
use super::shared::{
    REFETCH_WAIT, ReadyAssert, SeatTail, StageQueue, TerminalAnswer, TerminalFetch, paced,
    recipients_for, seats_on,
};
use crate::bootstrap::{BootstrapRequest, StateRangeOutcome};
use crate::reshape::observer::{ObserverBootstrap, ObserverTail, ProveOutcome};
use crate::reshape::view::ReshapeView;

/// One observer's progress through its split duty.
pub(super) enum ObserverPhase {
    /// Awaiting the child store open.
    Opening,
    /// Syncing the child span from the parent's attested anchor.
    Syncing(Box<ObserverBootstrap>),
    /// Synced; re-asserting ready and following the parent toward its terminal
    /// crossing, until the children seed.
    Following(Box<ObserverTail>),
    /// The follow cannot finish: the child anchored before it applied the
    /// parent's terminal — the parent's blocks above the terminal that
    /// would prove it are no longer served under the child's id — or past
    /// its genesis, the store it applied into diverged from the parent's,
    /// or the parent's recorded terminal derives a genesis other than the
    /// anchor's. A parent-half seat
    /// this host holds on the child takes the seat over and seeds it from
    /// the local parent; with none, the seat is the ordinary join's, which
    /// snap-syncs against the child's anchor. Inert, and kept so the
    /// observer is not rediscovered, until the committed projection
    /// releases it.
    Relinquished,
    /// The children seeded; fetching the certified terminal to derive genesis.
    FetchingTerminal(Box<TerminalFetch>),
    /// Genesis derived, adopted, and seated. Once seated the duty is inert
    /// until the committed projection releases it, and stays in the map so
    /// `discover_parent_half_duties` keeps deferring a co-hosted parent half
    /// of this child to the observer's seat — which installs every homed
    /// committee member, parent halves included — rather than opening a
    /// second duty that would re-seat the child from genesis.
    Seat(SeatTail),
}

/// One split observer duty, keyed by the child it syncs. A host may hold more
/// than one cohort seat for the same child (multiple co-hosted validators drawn
/// into it); they share the one child-span sync and store, each re-asserting its
/// own ready signal and seating under the one placement.
pub(super) struct ObserverDuty {
    pub(super) parent: ShardId,
    pub(super) child: ShardId,
    pub(super) validators: Vec<ValidatorId>,
    pub(super) phase: ObserverPhase,
    pub(super) open_requested: bool,
    pub(super) store_opened: bool,
    pub(super) stages: StageQueue,
    /// Hash of the genesis this duty adopted from its own follow, before
    /// the beacon's anchor existed. Checked against that anchor when it
    /// lands; a mismatch means the parent chain this host followed is not
    /// the one the network committed.
    pub(super) adopted_genesis: Option<BlockHash>,
    /// Per-seat ready re-assertion schedules. A seat the beacon has already
    /// credited is absent — it stops asserting for good.
    pub(super) ready_asserts: BTreeMap<ValidatorId, Option<ReadyAssert>>,
}

impl ObserverDuty {
    pub(super) const fn new(parent: ShardId, child: ShardId) -> Self {
        Self {
            parent,
            child,
            validators: Vec::new(),
            phase: ObserverPhase::Opening,
            open_requested: false,
            store_opened: false,
            stages: StageQueue {
                pending: Vec::new(),
                unacked: 0,
            },
            adopted_genesis: None,
            ready_asserts: BTreeMap::new(),
        }
    }

    pub(super) const fn relinquished(&self) -> bool {
        matches!(self.phase, ObserverPhase::Relinquished)
    }

    /// Whether the duty still has a seat to take, pruning the seats it
    /// no longer holds. A seat whose validator this host no longer runs
    /// is gone in every phase.
    ///
    /// Until the split is irrevocable the beacon may cancel or lapse it, or
    /// re-staff a seat onto the sibling child, and the cohort projection is
    /// the only record of which seats stand: one it no longer names is gone,
    /// and a duty with none left ends. Past that point the cohort clears as
    /// the split executes, and the duty runs on while one of its seats sits
    /// on the child's committee, or the child has none yet.
    ///
    /// A seated or relinquished observer lingers while its cohort or the
    /// parent-half phase still names the child, so the child is not
    /// rediscovered; a seated one also defers any co-hosted parent half to
    /// the seat already issued. Once the projection releases the child the
    /// duty ends.
    pub(super) fn held(&mut self, view: &ReshapeView, me: &[ValidatorId]) -> bool {
        let (parent, child) = (self.parent, self.child);
        self.validators.retain(|validator| me.contains(validator));
        if matches!(
            self.phase,
            ObserverPhase::Seat(SeatTail::Seated) | ObserverPhase::Relinquished
        ) {
            let named = self
                .validators
                .iter()
                .any(|&validator| view.observer_child(parent, validator) == Some(child));
            return named || view.parent_half_cohorts().contains_key(&child);
        }
        let irrevocable = view.split_irrevocable(parent, child);
        if !irrevocable {
            self.validators
                .retain(|&validator| view.observer_child(parent, validator) == Some(child));
        }
        let validators = &self.validators;
        self.ready_asserts
            .retain(|validator, _| validators.contains(validator));
        !self.validators.is_empty()
            && (!irrevocable || seats_on(view, child, self.validators.iter()))
    }

    /// Route one io result to the sequencer awaiting it. A relinquished
    /// observer is inert.
    pub(super) fn apply(&mut self, event: ReshapeEvent, now: LocalTimestamp) {
        if self.relinquished() {
            return;
        }
        match event {
            ReshapeEvent::Opened { .. } => self.store_opened = true,
            ReshapeEvent::Fetched { kind, .. } => self.on_fetched(kind, now),
            ReshapeEvent::FetchFailed { kind, .. } => match (&mut self.phase, kind) {
                (ObserverPhase::Syncing(bootstrap), FetchKind::StateRange { sub_range, .. }) => {
                    bootstrap.on_state_range_failure(sub_range);
                }
                (ObserverPhase::Following(tail), FetchKind::Block { .. }) => tail.on_failure(),
                (ObserverPhase::FetchingTerminal(fetch), _) => fetch.on_failure(now),
                _ => {}
            },
            ReshapeEvent::Staged { .. } => self.stages.on_staged(),
            ReshapeEvent::StageFailed {
                progress, leaves, ..
            } => self.stages.on_stage_failed(progress, leaves),
            ReshapeEvent::Imported { root, .. } => {
                if let ObserverPhase::Syncing(bootstrap) = &mut self.phase {
                    bootstrap.on_imported(root);
                }
            }
            ReshapeEvent::Applied { root, .. } => self.on_applied(root),
            ReshapeEvent::Adopted { .. } => {
                if let ObserverPhase::Seat(tail) = &mut self.phase {
                    tail.on_adopted();
                }
            }
            ReshapeEvent::SeedDeferred { .. } | ReshapeEvent::SeedUnavailable { .. } => {}
        }
    }

    /// Route a follow application's root to the tail awaiting it.
    fn on_applied(&mut self, root: StateRoot) {
        if let ObserverPhase::Following(tail) = &mut self.phase
            && let Err(error) = tail.on_applied(root)
        {
            // A diverged follow fails closed: the store cannot seat,
            // and following again from the same anchor diverges the
            // same way. The seat goes to the ordinary join, which
            // snap-syncs the child against its own anchor.
            tracing::warn!(
                child = ?self.child,
                error,
                "split follow diverged; relinquishing the observer's seat"
            );
            self.phase = ObserverPhase::Relinquished;
        }
    }

    /// Route a fetch response to its sequencer, deriving genesis once the
    /// terminal arrives.
    fn on_fetched(&mut self, kind: FetchedKind, now: LocalTimestamp) {
        let child = self.child;
        match (&mut self.phase, kind) {
            (
                ObserverPhase::Syncing(bootstrap),
                FetchedKind::StateRange {
                    sub_range,
                    response,
                },
            ) => {
                if let StateRangeOutcome::Staged { leaves, progress } =
                    bootstrap.on_state_range(sub_range, &response)
                {
                    self.stages.push(progress, leaves);
                }
            }
            (ObserverPhase::Following(tail), FetchedKind::Block { response }) => {
                let outcome = tail.on_response(&response);
                paced(tail, outcome, now, child);
            }
            (ObserverPhase::FetchingTerminal(fetch), FetchedKind::Block { response }) => {
                match fetch.on_block(child, &response, now) {
                    TerminalAnswer::Derived(genesis) => {
                        self.phase = ObserverPhase::Seat(SeatTail::Adopting(genesis));
                    }
                    TerminalAnswer::Missed => {}
                    TerminalAnswer::Disagrees => self.phase = ObserverPhase::Relinquished,
                }
            }
            _ => {}
        }
    }

    /// Advance the duty, emitting its current io.
    #[allow(clippy::too_many_lines)] // single dispatch over ObserverPhase
    pub(super) fn advance(
        &mut self,
        view: &ReshapeView,
        verifier: &dyn Verifier,
        derivation: &dyn Derivation,
        now: LocalTimestamp,
        out: &mut Vec<ReshapeRequest>,
    ) -> Advance {
        let (parent, child) = (self.parent, self.child);
        // A duty that flipped from its own follow adopted a genesis before
        // the beacon published one. The seeded anchor is the same block
        // derived twice — once by this host from the chain it tailed, once
        // by the fold from the terminal contribution it committed — so the
        // two must agree.
        //
        // Only against the *seeded* anchor. `seed_split_children` fills a
        // child's record only while it is still the zero placeholder, so a
        // child whose own first crossing folds first keeps that crossing as
        // its anchor and is never seeded. Comparing a genesis hash against
        // a crossing hash can only mismatch, and the child is correct.
        // `advanced_past_genesis` is exactly that distinction: the fold
        // sets it on a real crossing and never on a seed.
        if let Some(adopted) = self.adopted_genesis {
            if view.advanced_past_genesis(child) {
                // The comparison window closed with no disagreement to see.
                self.adopted_genesis = None;
            } else if let Some(anchor) = view.boundary(child) {
                self.adopted_genesis = None;
                if anchor.block_hash != adopted {
                    // The local parent chain and the network disagree about a
                    // committed block. Nothing here can repair that: the store
                    // may already be seated under a running replica, so wiping it
                    // would take the shard down to fix a fault it cannot fix.
                    // Surface it and stop — the duty is done either way, and
                    // the split's cohort projection has already released, so no
                    // rediscovery re-opens it.
                    tracing::error!(
                        ?child,
                        ?adopted,
                        anchored = ?anchor.block_hash,
                        "adopted split-child genesis disagrees with the beacon anchor; \
                         the followed parent chain is not the one the network committed"
                    );
                    return Advance::Done;
                }
            }
        }
        match &mut self.phase {
            ObserverPhase::Opening => {
                if !self.open_requested {
                    out.push(ReshapeRequest::OpenStore { shard: child });
                    self.open_requested = true;
                }
                if self.store_opened
                    && let Some(anchor) = view.boundary(parent)
                {
                    self.phase = ObserverPhase::Syncing(Box::new(ObserverBootstrap::new(
                        parent, anchor, child,
                    )));
                }
            }
            ObserverPhase::Syncing(bootstrap) => {
                self.stages.emit(child, out);
                for request in bootstrap.next_requests() {
                    // The pending child's witness accumulator starts empty, so
                    // an observer bootstrap only ever emits state ranges.
                    let BootstrapRequest::StateRange(sub_range, request) = request else {
                        continue;
                    };
                    out.push(ReshapeRequest::Fetch {
                        duty: child,
                        from: parent,
                        kind: FetchKind::StateRange { sub_range, request },
                    });
                }
                if self.stages.is_durable()
                    && let Some(height) = bootstrap.take_finalize()
                {
                    out.push(ReshapeRequest::FinalizeImport {
                        shard: child,
                        height,
                    });
                }
                if bootstrap.imported_root().is_some() {
                    let anchor = bootstrap.anchor();
                    self.phase =
                        ObserverPhase::Following(Box::new(ObserverTail::new(anchor, child)));
                }
            }
            ObserverPhase::Following(tail) => {
                // Publish the parent's cut as soon as the beacon schedules
                // one, so the follow recognises the terminal crossing as it
                // walks past it rather than being told which crossing was
                // terminal an epoch later.
                tail.set_terminal_cut(view.terminal_cut(parent));
                // Release whatever the fetched run now proves committed,
                // each QC verified against the parent committee of its own
                // window.
                let proved = tail.prove(verifier, view.network(), |anchor_wt, qc_wt| {
                    view.certifying_committee(parent, anchor_wt, qc_wt)
                });
                if let ProveOutcome::Refuted(reason) = proved {
                    tracing::warn!(?child, reason, "dropped an unproven run of parent blocks");
                    tail.defer(now.plus(REFETCH_WAIT));
                }
                // Flip at the cut, from the chain this host followed,
                // rather than an epoch later when the beacon publishes the
                // anchor. The store must have applied through the terminal
                // — the genesis adopts the child subtree as of *its* root.
                // A settled sighting is of a terminal proven committed, since
                // the follow applies nothing else.
                if let Some(sighting) = tail.settled_terminal()
                    && let Some(derived) = &sighting.genesis
                {
                    tracing::info!(
                        ?child,
                        terminal_height = sighting.header.height().inner(),
                        "flipping the split child from its own follow of the parent"
                    );
                    self.adopted_genesis = Some(derived.block.hash());
                    self.phase = ObserverPhase::Seat(SeatTail::Adopting(Box::new(derived.clone())));
                    return Advance::Continue;
                }
                // Once this child's boundary seeds, the parent terminated. A
                // tail that already applied the terminal derives genesis from
                // it. One that did not cannot: proving the terminal takes the
                // parent's blocks above it, and the child's committee serves
                // its own chain at those heights — the follow would refuse
                // every answer. Nor can any tail once the child crossed on its
                // own chain: the anchor then names a block of that chain, which
                // no genesis derived from the parent's terminal reconstructs.
                // A parent-half seat this host holds on the child takes the
                // seat over, cloning the local parent; with none, the seat
                // goes to the join.
                if let Some(anchor) = view.boundary(child) {
                    if view.advanced_past_genesis(child) {
                        tracing::info!(
                            ?child,
                            anchor_height = anchor.height.inner(),
                            "split child anchored past its genesis; relinquishing the observer's seat"
                        );
                        self.phase = ObserverPhase::Relinquished;
                    } else if tail.next_height() >= anchor.height {
                        self.phase =
                            ObserverPhase::FetchingTerminal(Box::new(TerminalFetch::new(anchor)));
                    } else {
                        tracing::info!(
                            ?child,
                            followed_to = tail.next_height().inner(),
                            anchor_height = anchor.height.inner(),
                            "split child anchored before the follow reached the parent's \
                             terminal; relinquishing the observer's seat"
                        );
                        self.phase = ObserverPhase::Relinquished;
                    }
                    return Advance::Continue;
                }
                // Assert ready to the splitting parent's committee until the
                // beacon credits the seat. Every co-hosted seat for this child
                // asserts its own signal, on its own schedule.
                if let Some(anchor) = view.boundary(parent) {
                    for &validator in &self.validators {
                        if view.observer_ready(parent, validator) {
                            // The gate has banked this seat's readiness; a
                            // further signal cannot change the count.
                            self.ready_asserts.remove(&validator);
                            continue;
                        }
                        let recipients = recipients_for(view, parent, validator);
                        let slot = self.ready_asserts.entry(validator).or_default();
                        if !ReadyAssert::should_assert(
                            slot,
                            anchor.weighted_timestamp,
                            &recipients,
                            now,
                        ) {
                            continue;
                        }
                        out.push(ReshapeRequest::BroadcastReady {
                            validator,
                            child,
                            anchor,
                            recipients,
                        });
                    }
                }
                if let Some(request) = tail.next_request(now) {
                    out.push(ReshapeRequest::Fetch {
                        duty: child,
                        from: parent,
                        kind: FetchKind::Block { request },
                    });
                }
                if let Some(block) = tail.take_apply() {
                    derive_block_transactions(&block, derivation);
                    let creations = committed_cells_for(&block);
                    let frontier = FrontierInputs::of_block(&block, view.schedule().windows());
                    out.push(ReshapeRequest::ApplyFollow {
                        shard: child,
                        block,
                        creations,
                        frontier,
                    });
                }
            }
            ObserverPhase::FetchingTerminal(fetch) => {
                // The terminal is the parent's tip, which its members serve
                // until the children go live and they leave it; from then a
                // child member that flipped holds it, as the block its
                // genesis follows. Neither alone holds it throughout, so each
                // round asks both and the first answer that derives the
                // genesis takes it.
                if let Some(request) = fetch.next_request(view, parent, now) {
                    for from in [parent, child] {
                        out.push(ReshapeRequest::Fetch {
                            duty: child,
                            from,
                            kind: FetchKind::Block {
                                request: request.clone(),
                            },
                        });
                    }
                }
            }
            ObserverPhase::Relinquished => {}
            ObserverPhase::Seat(tail) => {
                tail.advance(child, AdoptKind::Split, &self.validators, view, out);
            }
        }
        Advance::Continue
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use hyperscale_crypto_bls::BlsVerifier;
    use hyperscale_hbor::Bytes;
    use hyperscale_types::network::response::GetBlockResponse;
    use hyperscale_types::test_utils::{
        StubVmStatics, TestCommittee, signed_child_block, signed_split_terminal, test_key,
    };
    use hyperscale_types::{
        Block, BlockHash, BlockHeight, ElidedCertifiedBlock, Hash, Inventory, Round, ShardId,
        SplitChildRoots, StateRoot, ValidatorId, WeightedTimestamp,
    };

    use super::*;
    use crate::reshape::observer::{ObserverBootstrap, ObserverTail};
    use crate::reshape::orchestrator::io::{FetchKind, FetchedKind, ReshapeEvent, ReshapeRequest};
    use crate::reshape::orchestrator::shared::SeatTail;
    use crate::reshape::orchestrator::test_support::*;
    use crate::reshape::orchestrator::{Duty, ReshapeOrchestrator};
    use crate::reshape::view::ReshapeView;

    /// An observer following a parent whose committee is `committee`,
    /// driven end to end through the orchestrator: a losing sibling a peer
    /// serves is held unproven and never applied, the answer that
    /// contradicts it holds the next fetch back by the refetch wait, and
    /// the committed chain is applied once each block's two-chain verifies
    /// against the committee the schedule resolves.
    #[test]
    fn a_follower_applies_only_what_the_parent_committee_proves() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let committee = TestCommittee::new(4, 3);
        let schedule = committee_schedule(parent, &committee, &[(50, child)]);
        let view = ReshapeView::new(&schedule);

        let wt = WeightedTimestamp::from_millis;
        let (anchor_block, anchor) = anchored_block();
        let b2 = signed_child_block(&committee, &anchor_block, Round::new(2), wt(100));
        let sibling = signed_child_block(&committee, &anchor_block, Round::new(3), wt(150));
        let b3 = signed_child_block(&committee, &b2, Round::new(3), wt(200));
        let served = |block: &Block| ReshapeEvent::Fetched {
            duty: child,
            from: parent,
            kind: FetchedKind::Block {
                response: Box::new(GetBlockResponse::found(ElidedCertifiedBlock::elide(
                    block,
                    committee.sign_qc(block.header(), &committee.quorum_indices(), wt(900)),
                    &Inventory::empty(),
                ))),
            },
        };

        let mut orch = ReshapeOrchestrator::new(vec![vid(50)]);
        insert_observer(
            &mut orch,
            child,
            observer_duty(
                parent,
                child,
                50,
                following(ObserverTail::new(anchor, child)),
            ),
        );

        let requests = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));
        assert_eq!(follow_fetch(&requests), Some(BlockHeight::new(2)));
        let requests = orch.step(
            &view,
            &BlsVerifier,
            &StubVmStatics,
            vec![served(&sibling)],
            at(0),
        );
        assert_eq!(
            follow_fetch(&requests),
            Some(BlockHeight::new(3)),
            "the follow fetches ahead of what it can prove",
        );
        assert!(follow_applies(&requests).is_empty());

        // The committed chain's next block contradicts the sibling.
        let requests = orch.step(
            &view,
            &BlsVerifier,
            &StubVmStatics,
            vec![served(&b3)],
            at(0),
        );
        assert!(follow_applies(&requests).is_empty());
        assert_eq!(
            follow_fetch(&requests),
            None,
            "a refused answer holds the next fetch back"
        );
        let refetch = refetch_ms();
        let requests = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(refetch));
        assert_eq!(follow_fetch(&requests), Some(BlockHeight::new(2)));

        let requests = orch.step(
            &view,
            &BlsVerifier,
            &StubVmStatics,
            vec![served(&b2)],
            at(refetch),
        );
        assert!(follow_applies(&requests).is_empty());
        let requests = orch.step(
            &view,
            &BlsVerifier,
            &StubVmStatics,
            vec![served(&b3)],
            at(refetch),
        );
        assert_eq!(
            follow_applies(&requests),
            vec![b2.hash()],
            "the committed block is applied once its two-chain verifies",
        );
    }

    /// A follow whose store diverges from the parent's relinquishes the
    /// seat to the join, and stays relinquished while the cohort still
    /// names it: rediscovering it would re-open the store over the one the
    /// adapter still holds and diverge again from the same anchor.
    #[test]
    fn a_diverged_follow_relinquishes_without_re_opening() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let committee = TestCommittee::new(4, 3);
        let schedule = committee_schedule(parent, &committee, &[(50, child)]);
        let view = ReshapeView::new(&schedule);

        let wt = WeightedTimestamp::from_millis;
        let (anchor_block, anchor) = anchored_block();
        let pair = SplitChildRoots {
            left: StateRoot::from_raw(Hash::from_bytes(b"left subtree")),
            right: StateRoot::from_raw(Hash::from_bytes(b"right subtree")),
        };
        let b2 = signed_split_terminal(&committee, &anchor_block, Round::new(2), wt(100), pair);
        let b3 = signed_child_block(&committee, &b2, Round::new(3), wt(200));
        let served = |block: &Block| ReshapeEvent::Fetched {
            duty: child,
            from: parent,
            kind: FetchedKind::Block {
                response: Box::new(GetBlockResponse::found(ElidedCertifiedBlock::elide(
                    block,
                    committee.sign_qc(block.header(), &committee.quorum_indices(), wt(900)),
                    &Inventory::empty(),
                ))),
            },
        };

        let mut orch = ReshapeOrchestrator::new(vec![vid(50)]);
        insert_observer(
            &mut orch,
            child,
            observer_duty(
                parent,
                child,
                50,
                following(ObserverTail::new(anchor, child)),
            ),
        );
        let mut applies = Vec::new();
        for event in [Vec::new(), vec![served(&b2)], vec![served(&b3)]] {
            let requests = orch.step(&view, &BlsVerifier, &StubVmStatics, event, at(0));
            applies.extend(follow_applies(&requests));
        }
        assert_eq!(applies, vec![b2.hash()]);

        let requests = orch.step(
            &view,
            &BlsVerifier,
            &StubVmStatics,
            vec![ReshapeEvent::Applied {
                shard: child,
                root: pair.right,
            }],
            at(0),
        );
        assert!(orch.relinquished(child));
        assert!(!orch.is_seating(child));
        for requests in [
            requests,
            orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(5_000)),
        ] {
            assert!(
                !requests
                    .iter()
                    .any(|r| matches!(r, ReshapeRequest::OpenStore { .. })),
                "a diverged follow must not re-open the store; got {requests:?}",
            );
        }
        assert!(orch.relinquished(child), "the cohort still names the seat");
    }

    /// A follower applies a block whose transactions it fetched with
    /// nothing derived.
    ///
    /// A block a peer serves out of its store, or one decoded off the
    /// wire, carries no derivations: deriving is the receiving node's own
    /// answer. The committed cells the follow writes are each
    /// transaction's validity window, which only a derivation seats, so a
    /// follow that read them as the block came would panic.
    #[test]
    fn a_follower_derives_the_transactions_it_fetched() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let committee = TestCommittee::new(4, 3);
        let schedule = committee_schedule(parent, &committee, &[(50, child)]);
        let view = ReshapeView::new(&schedule);

        let wt = WeightedTimestamp::from_millis;
        let (anchor_block, anchor) = anchored_block();
        let b2 = carrying_an_underived_transaction(signed_child_block(
            &committee,
            &anchor_block,
            Round::new(2),
            wt(100),
        ));
        let b3 = signed_child_block(&committee, &b2, Round::new(3), wt(200));
        let served = |block: &Block| ReshapeEvent::Fetched {
            duty: child,
            from: parent,
            kind: FetchedKind::Block {
                response: Box::new(GetBlockResponse::found(ElidedCertifiedBlock::elide(
                    block,
                    committee.sign_qc(block.header(), &committee.quorum_indices(), wt(900)),
                    &Inventory::empty(),
                ))),
            },
        };

        let mut orch = ReshapeOrchestrator::new(vec![vid(50)]);
        insert_observer(
            &mut orch,
            child,
            observer_duty(
                parent,
                child,
                50,
                following(ObserverTail::new(anchor, child)),
            ),
        );

        orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));
        orch.step(
            &view,
            &BlsVerifier,
            &StubVmStatics,
            vec![served(&b2)],
            at(0),
        );
        let requests = orch.step(
            &view,
            &BlsVerifier,
            &StubVmStatics,
            vec![served(&b3)],
            at(0),
        );
        assert_eq!(
            follow_applies(&requests),
            vec![b2.hash()],
            "the fetched block is applied with its committed cells",
        );
    }

    /// A follow at the parent's tip asks for a height nothing holds yet.
    /// That answer holds the next ask back by the refetch wait rather than
    /// re-asking as fast as the peer replies, while an answer that delivers
    /// a block asks on at once.
    #[test]
    fn an_empty_answer_at_the_tip_defers_the_next_follow_fetch() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let committee = TestCommittee::new(4, 3);
        let schedule = committee_schedule(parent, &committee, &[(50, child)]);
        let view = ReshapeView::new(&schedule);
        let (anchor_block, anchor) = anchored_block();
        let b2 = signed_child_block(
            &committee,
            &anchor_block,
            Round::new(2),
            WeightedTimestamp::from_millis(100),
        );
        let answer = |response: GetBlockResponse| ReshapeEvent::Fetched {
            duty: child,
            from: parent,
            kind: FetchedKind::Block {
                response: Box::new(response),
            },
        };

        let mut orch = ReshapeOrchestrator::new(vec![vid(50)]);
        insert_observer(
            &mut orch,
            child,
            observer_duty(
                parent,
                child,
                50,
                following(ObserverTail::new(anchor, child)),
            ),
        );
        let requests = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));
        assert_eq!(follow_fetch(&requests), Some(BlockHeight::new(2)));

        let requests = orch.step(
            &view,
            &BlsVerifier,
            &StubVmStatics,
            vec![answer(GetBlockResponse::not_found())],
            at(0),
        );
        assert_eq!(
            follow_fetch(&requests),
            None,
            "nothing at the tip holds the next ask back",
        );
        let refetch = refetch_ms();
        let requests = orch.step(
            &view,
            &BlsVerifier,
            &StubVmStatics,
            Vec::new(),
            at(refetch - 1),
        );
        assert_eq!(follow_fetch(&requests), None);
        let requests = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(refetch));
        assert_eq!(follow_fetch(&requests), Some(BlockHeight::new(2)));

        let found = GetBlockResponse::found(ElidedCertifiedBlock::elide(
            &b2,
            committee.sign_qc(
                b2.header(),
                &committee.quorum_indices(),
                WeightedTimestamp::from_millis(900),
            ),
            &Inventory::empty(),
        ));
        let requests = orch.step(
            &view,
            &BlsVerifier,
            &StubVmStatics,
            vec![answer(found)],
            at(refetch),
        );
        assert_eq!(
            follow_fetch(&requests),
            Some(BlockHeight::new(3)),
            "a delivered block asks on at once",
        );
    }

    #[test]
    fn detects_a_cohort_seat_and_opens_the_store() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let snap = snapshot(&[], &[(parent, 5, child)], &[]);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);

        let requests = orch.step(
            &ReshapeView::new(&windowed(&snap)),
            &BlsVerifier,
            &StubVmStatics,
            Vec::new(),
            at(0),
        );

        assert!(
            matches!(requests.as_slice(), [ReshapeRequest::OpenStore { shard }] if *shard == child),
            "a held cohort seat must open the child store; got {requests:?}",
        );
    }

    #[test]
    fn ignores_a_cohort_seat_this_host_does_not_hold() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let snap = snapshot(&[], &[(parent, 9, child)], &[]);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);

        assert!(
            orch.step(
                &ReshapeView::new(&windowed(&snap)),
                &BlsVerifier,
                &StubVmStatics,
                Vec::new(),
                at(0)
            )
            .is_empty()
        );
    }

    #[test]
    fn syncing_forwards_the_bootstrap_state_ranges() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let snap = snapshot(&[(parent, &[1, 2, 3, 4])], &[(parent, 5, child)], &[parent]);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);
        insert_observer(
            &mut orch,
            child,
            observer_duty(
                parent,
                child,
                5,
                ObserverPhase::Syncing(Box::new(ObserverBootstrap::new(parent, anchor(), child))),
            ),
        );

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
                ReshapeRequest::Fetch { from, kind: FetchKind::StateRange { .. }, .. } if *from == parent
            )),
            "a syncing duty must forward the bootstrap's state ranges; got {requests:?}",
        );
    }

    #[test]
    fn a_failed_stage_re_queues_and_re_emits_the_chunk() {
        use hyperscale_storage::test_helpers::completed_import_progress;
        use hyperscale_types::SubstateLeaf;

        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let snap = snapshot(&[(parent, &[1, 2, 3, 4])], &[(parent, 5, child)], &[parent]);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);
        let mut duty = observer_duty(
            parent,
            child,
            5,
            ObserverPhase::Syncing(Box::new(ObserverBootstrap::new(parent, anchor(), child))),
        );
        let progress = completed_import_progress(BlockHeight::new(1), 0);
        let leaves = vec![SubstateLeaf {
            key: test_key(7u8),
            value: Bytes::from_array([7]),
        }];
        duty.stages.push(progress.clone(), leaves.clone());
        insert_observer(&mut orch, child, duty);

        let requests = orch.step(
            &ReshapeView::new(&windowed(&snap)),
            &BlsVerifier,
            &StubVmStatics,
            Vec::new(),
            at(0),
        );
        assert!(
            requests
                .iter()
                .any(|r| matches!(r, ReshapeRequest::StageChunk { shard, .. } if *shard == child)),
            "a pending chunk must emit; got {requests:?}",
        );
        assert_eq!(observer(&orch, child).stages.unacked, 1);

        // The durable write failed: the chunk comes back and the same
        // step's advance re-emits it, leaving it unacked again — the
        // finalize gate stays closed until a Staged ack lands.
        let requests = orch.step(
            &ReshapeView::new(&windowed(&snap)),
            &BlsVerifier,
            &StubVmStatics,
            vec![ReshapeEvent::StageFailed {
                shard: child,
                progress,
                leaves,
            }],
            at(0),
        );
        assert!(
            requests
                .iter()
                .any(|r| matches!(r, ReshapeRequest::StageChunk { shard, .. } if *shard == child)),
            "a failed stage must re-emit its chunk; got {requests:?}",
        );
        let duty = &observer(&orch, child);
        assert_eq!(duty.stages.unacked, 1);
        assert!(duty.stages.pending.is_empty());
    }

    #[test]
    fn following_reasserts_ready_to_the_parent_committee() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let snap = snapshot(&[(parent, &[1, 2, 3, 5])], &[(parent, 5, child)], &[parent]);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);
        insert_observer(
            &mut orch,
            child,
            observer_duty(
                parent,
                child,
                5,
                following(ObserverTail::new(anchor(), child)),
            ),
        );

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
            "a following duty must re-assert ready to the parent committee minus self; got {requests:?}",
        );
    }

    /// Ready assertions carry a window cut from the parent's boundary anchor,
    /// so nothing new can be said until that anchor turns over. Pumping
    /// against one anchor must back off in real time rather than assert once
    /// per pump.
    #[test]
    fn ready_assertions_back_off_within_one_anchor_window() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let snap = snapshot(&[(parent, &[1, 2, 3, 5])], &[(parent, 5, child)], &[parent]);
        let schedule = windowed(&snap);
        let view = ReshapeView::new(&schedule);
        let mut orch = following_observer(parent, child);

        // A minute of pumping at the production tick's cadence.
        let asserts = (0..60_000)
            .step_by(1_000)
            .filter(|&ms| {
                orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(ms))
                    .iter()
                    .any(|r| matches!(r, ReshapeRequest::BroadcastReady { .. }))
            })
            .count();

        // Geometric backoff to the ceiling: assertions at 0, 1, 3 and 7
        // seconds, then every four — seventeen inside the minute, against the
        // sixty a per-pump assertion would cost.
        assert_eq!(
            asserts, 17,
            "one anchor window must cost a bounded number of assertions",
        );
    }

    /// The pump rate must not change the assertion rate: the simulation drives
    /// the orchestrator to a fixpoint, so a schedule counting steps rather
    /// than time would burn a whole window's backoff inside one slice and go
    /// quiet — a divergence between the harnesses that only shows up as a
    /// stalled reshape.
    #[test]
    fn pumping_without_the_clock_advancing_asserts_once() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let snap = snapshot(&[(parent, &[1, 2, 3, 5])], &[(parent, 5, child)], &[parent]);
        let schedule = windowed(&snap);
        let view = ReshapeView::new(&schedule);
        let mut orch = following_observer(parent, child);

        let asserts = (0..64)
            .filter(|_| {
                orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(5_000))
                    .iter()
                    .any(|r| matches!(r, ReshapeRequest::BroadcastReady { .. }))
            })
            .count();

        assert_eq!(
            asserts, 1,
            "a fixpoint that passes no time must cost exactly one assertion",
        );
    }

    /// A fresh anchor window is a genuinely new signal — the previous one is
    /// on its way to expiring — so the backoff restarts and the duty asserts
    /// immediately rather than waiting out the old schedule.
    #[test]
    fn a_new_anchor_window_re_arms_the_assertion() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let snap = snapshot(&[(parent, &[1, 2, 3, 5])], &[(parent, 5, child)], &[parent]);
        let mut orch = following_observer(parent, child);

        // Run the first window out to where it has backed off well past the
        // tick.
        let schedule = windowed(&snap);
        let view = ReshapeView::new(&schedule);
        for ms in (0..60_000).step_by(1_000) {
            let _ = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(ms));
        }
        assert!(
            !orch
                .step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(60_000))
                .iter()
                .any(|r| matches!(r, ReshapeRequest::BroadcastReady { .. })),
            "the window must be deep into its backoff",
        );

        let rolled = build(
            &[(parent, &[1, 2, 3, 5])],
            &uncredited(&[(parent, 5, child)]),
            &[],
            &[],
            &[parent],
            anchor_at(WeightedTimestamp::from_millis(30_000)),
        );
        let requests = orch.step(
            &ReshapeView::new(&windowed(&rolled)),
            &BlsVerifier,
            &StubVmStatics,
            Vec::new(),
            at(60_000),
        );

        assert!(
            requests
                .iter()
                .any(|r| matches!(r, ReshapeRequest::BroadcastReady { .. })),
            "a rolled anchor window must assert at once; got {requests:?}",
        );
    }

    /// Once the beacon has folded the seat's `ReshapeReady`, the gate has
    /// banked it and a further signal cannot change the count. The duty must
    /// fall silent for good rather than assert until the split executes.
    #[test]
    fn a_credited_observer_seat_stops_asserting() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let snap = snapshot_with_ready(
            &[(parent, &[1, 2, 3, 5])],
            &[(parent, 5, child, true)],
            &[parent],
        );
        let schedule = windowed(&snap);
        let view = ReshapeView::new(&schedule);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);
        insert_observer(
            &mut orch,
            child,
            observer_duty(
                parent,
                child,
                5,
                following(ObserverTail::new(anchor(), child)),
            ),
        );

        for step in 0..8 {
            let requests = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));
            assert!(
                !requests
                    .iter()
                    .any(|r| matches!(r, ReshapeRequest::BroadcastReady { .. })),
                "step {step}: a credited seat must not assert; got {requests:?}",
            );
        }
    }

    #[test]
    fn the_gate_advances_a_follower_to_the_terminal_fetch() {
        let parent = ShardId::ROOT;
        let (child, sibling) = parent.children();
        // Both children seeded → the gate fires; the terminal fetch addresses
        // the parent, whose tip it is, and the child, whose flipped members
        // hold it once the parent's have left.
        let snap = snapshot(&[(child, &[1, 5])], &[], &[parent, child, sibling]);
        let schedule = windowed(&snap);
        let view = ReshapeView::new(&schedule);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);
        insert_observer(
            &mut orch,
            child,
            observer_duty(
                parent,
                child,
                5,
                following(ObserverTail::new(anchor(), child)),
            ),
        );

        // First step fires the gate (Following → FetchingTerminal); the second
        // emits the terminal fetch.
        let _ = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));
        let requests = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));

        for source in [parent, child] {
            assert!(
                requests.iter().any(|r| matches!(
                    r,
                    ReshapeRequest::Fetch { duty, from, kind: FetchKind::Block { .. }, .. }
                        if *duty == child && *from == source
                )),
                "the gate must drive a terminal fetch from {source:?}; got {requests:?}",
            );
        }
    }

    /// A child already crossing on its own chain is anchored at a block of
    /// that chain, which no terminal of the parent's reconstructs, so a
    /// follower that reached the anchor's height relinquishes rather than
    /// fetching a terminal against it.
    #[test]
    fn a_follower_of_a_child_past_its_genesis_relinquishes() {
        let parent = ShardId::ROOT;
        let (child, sibling) = parent.children();
        let snap = snapshot(&[(child, &[1, 5])], &[], &[parent, child, sibling])
            .with_advanced(BTreeSet::from([child]));
        let schedule = windowed(&snap);
        let view = ReshapeView::new(&schedule);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);
        insert_observer(
            &mut orch,
            child,
            observer_duty(
                parent,
                child,
                5,
                following(ObserverTail::new(anchor(), child)),
            ),
        );

        let mut requests = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));
        assert!(orch.relinquished(child), "the seat is the join's");
        requests.extend(orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0)));
        assert!(
            block_fetches(&requests, parent).is_empty()
                && block_fetches(&requests, child).is_empty(),
            "no terminal fetch against a crossing anchor; got {requests:?}"
        );
    }

    /// A follower the child's anchor overtook before it applied the parent's
    /// terminal cannot prove that terminal from anything the child serves.
    /// With no parent-half seat on the host it relinquishes the seat to the
    /// join and fetches nothing more.
    #[test]
    fn a_follower_the_child_anchor_overtakes_relinquishes_the_seat() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        // Validator 6 seats the child from the parent, on another host.
        let schedule = overtaking_view(&[(child, 6, parent)]);
        let view = ReshapeView::new(&schedule);
        let mut orch = overtaken_follower(&[5]);
        assert!(orch.is_seating(child));

        for _ in 0..2 {
            let requests = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));
            assert!(
                requests.is_empty(),
                "a relinquished follower asks for nothing; got {requests:?}"
            );
        }
        assert!(matches!(
            observer(&orch, child).phase,
            ObserverPhase::Relinquished
        ));
        assert!(orch.relinquished(child));
        assert!(
            !orch.is_seating(child),
            "the relinquished seat is the join's to take"
        );

        let released = snapshot(&[(child, &[1, 5, 6])], &[], &[]);
        let _ = orch.step(
            &ReshapeView::new(&windowed(&released)),
            &BlsVerifier,
            &StubVmStatics,
            Vec::new(),
            at(0),
        );
        assert!(
            orch.duties.is_empty(),
            "the released cohort ends the relinquished duty"
        );
    }

    #[test]
    fn a_prepared_duty_seats_once_the_placement_lands() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        // The observer is now seated on the child committee.
        let snap = snapshot(&[(child, &[1, 5])], &[], &[]);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);
        insert_observer(
            &mut orch,
            child,
            observer_duty(parent, child, 5, ObserverPhase::Seat(SeatTail::Prepared)),
        );

        let requests = orch.step(
            &ReshapeView::new(&windowed(&snap)),
            &BlsVerifier,
            &StubVmStatics,
            Vec::new(),
            at(0),
        );

        assert!(
            matches!(requests.as_slice(), [ReshapeRequest::Seat { shard }] if *shard == child),
            "a prepared duty must seat once placed on the child; got {requests:?}",
        );
    }

    #[test]
    fn a_prepared_duty_waits_until_placed() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        // The cut is scheduled but the child has no committee yet.
        let snap = scheduled_split(&[(parent, &[1, 2])], &[], &[], parent);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);
        insert_observer(
            &mut orch,
            child,
            observer_duty(parent, child, 5, ObserverPhase::Seat(SeatTail::Prepared)),
        );

        assert!(
            orch.step(
                &ReshapeView::new(&windowed(&snap)),
                &BlsVerifier,
                &StubVmStatics,
                Vec::new(),
                at(0)
            )
            .is_empty()
        );
        assert!(
            orch.is_seating(child),
            "a placement still to come keeps the duty"
        );
    }

    /// A validator moved to another host stops asserting here, and a duty
    /// left with no seat of this host's ends.
    #[test]
    fn a_removed_validator_leaves_this_hosts_duties() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let snap = snapshot(
            &[(parent, &[1, 2, 3, 4])],
            &[(parent, 5, child), (parent, 6, child)],
            &[parent],
        );
        let schedule = windowed(&snap);
        let view = ReshapeView::new(&schedule);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5), vid(6)]);
        let mut duty = observer_duty(
            parent,
            child,
            5,
            following(ObserverTail::new(anchor(), child)),
        );
        duty.validators.push(vid(6));
        insert_observer(&mut orch, child, duty);
        orch.remove_me(vid(6));

        let requests = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));
        let asserted: Vec<ValidatorId> = requests
            .iter()
            .filter_map(|r| match r {
                ReshapeRequest::BroadcastReady { validator, .. } => Some(*validator),
                _ => None,
            })
            .collect();
        assert_eq!(asserted, vec![vid(5)]);

        orch.remove_me(vid(5));
        let _ = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));
        assert!(!orch.is_seating(child), "a duty with no seat here ends");
    }

    /// A split the beacon cancels or lapses before its cut is scheduled
    /// leaves only its cohort's absence: the observer duty ends with it, so
    /// the host stops asserting ready and its prepared store is released.
    #[test]
    fn a_cancelled_split_ends_its_observer_duty() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let pending = snapshot(&[(parent, &[1, 2, 3, 4])], &[(parent, 5, child)], &[parent]);
        let mut orch = following_observer(parent, child);
        let _ = orch.step(
            &ReshapeView::new(&windowed(&pending)),
            &BlsVerifier,
            &StubVmStatics,
            Vec::new(),
            at(0),
        );
        assert!(orch.is_seating(child));

        let cancelled = snapshot(&[(parent, &[1, 2, 3, 4])], &[], &[parent]);
        let _ = orch.step(
            &ReshapeView::new(&windowed(&cancelled)),
            &BlsVerifier,
            &StubVmStatics,
            Vec::new(),
            at(1_000),
        );
        assert!(!orch.is_seating(child), "a cancelled split's duty must end");
        assert!(
            orch.step(
                &ReshapeView::new(&windowed(&cancelled)),
                &BlsVerifier,
                &StubVmStatics,
                Vec::new(),
                at(60_000),
            )
            .is_empty(),
            "nothing is asserted for a cancelled split",
        );
    }

    /// A seat the beacon re-staffs onto the sibling child leaves the duty
    /// for the child it no longer syncs.
    #[test]
    fn a_seat_re_staffed_onto_the_sibling_moves_its_duty() {
        let parent = ShardId::ROOT;
        let (child, sibling) = parent.children();
        let mut orch = following_observer(parent, child);
        let restaffed = snapshot(
            &[(parent, &[1, 2, 3, 4])],
            &[(parent, 5, sibling)],
            &[parent],
        );
        let _ = orch.step(
            &ReshapeView::new(&windowed(&restaffed)),
            &BlsVerifier,
            &StubVmStatics,
            Vec::new(),
            at(0),
        );
        assert!(!orch.is_seating(child));
        assert!(orch.is_seating(sibling));
    }

    /// Once the cut is scheduled the cohort clears as the split executes,
    /// and the duty runs on; once the child's committee forms without any
    /// of the duty's seats, nothing is left for it to seat.
    #[test]
    fn a_scheduled_split_keeps_its_duty_until_the_child_forms_without_it() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let mut orch = following_observer(parent, child);
        let scheduled = scheduled_split(&[(parent, &[1, 2, 3, 4])], &[], &[parent], parent);
        let _ = orch.step(
            &ReshapeView::new(&windowed(&scheduled)),
            &BlsVerifier,
            &StubVmStatics,
            Vec::new(),
            at(0),
        );
        assert!(orch.is_seating(child), "a scheduled cut is irrevocable");

        let executed = snapshot(&[(child, &[1, 5])], &[], &[]);
        let _ = orch.step(
            &ReshapeView::new(&windowed(&executed)),
            &BlsVerifier,
            &StubVmStatics,
            Vec::new(),
            at(0),
        );
        assert!(
            orch.is_seating(child),
            "a seat on the formed child keeps the duty"
        );

        let without = snapshot(&[(child, &[1, 2])], &[], &[]);
        let _ = orch.step(
            &ReshapeView::new(&windowed(&without)),
            &BlsVerifier,
            &StubVmStatics,
            Vec::new(),
            at(0),
        );
        assert!(
            !orch.is_seating(child),
            "a child formed without the duty's seats ends it"
        );
    }

    /// The seeded anchor agrees with what the host derived: the check
    /// clears and the duty carries on untouched.
    #[test]
    fn a_matching_seeded_anchor_clears_the_cross_check() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        // The parent-half projection still lists the child, so a seated
        // duty is not yet released — the state the seed lands in.
        let snap = snapshot_parent_halves(&[(child, &[5])], &[(child, 5, parent)], &[child]);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);
        insert_observer(
            &mut orch,
            child,
            adopted_duty(parent, child, anchor().block_hash),
        );

        let requests = orch.step(
            &ReshapeView::new(&windowed(&snap)),
            &BlsVerifier,
            &StubVmStatics,
            Vec::new(),
            at(0),
        );

        assert!(
            requests.is_empty(),
            "a matching anchor emits nothing; got {requests:?}"
        );
        assert!(
            matches!(orch.duties.get(&child), Some(Duty::Observer(_))),
            "a matching anchor leaves the duty in place",
        );
        assert!(
            observer(&orch, child).adopted_genesis.is_none(),
            "the check is consumed once it has agreed",
        );
    }

    /// The child folded a crossing of its own before its parent's terminal
    /// folded, so the beacon never wrote the seed and the anchor is that
    /// crossing. A genesis hash cannot match a crossing hash, and the child
    /// is correct — the comparison window has closed, not been failed.
    #[test]
    fn a_crossing_anchor_closes_the_cross_check_without_wiping() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let snap = snapshot_parent_halves(&[(child, &[5])], &[(child, 5, parent)], &[child])
            .with_advanced(BTreeSet::from([child]));
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);
        let derived = BlockHash::from_raw(Hash::from_bytes(b"locally-derived-genesis"));
        insert_observer(&mut orch, child, adopted_duty(parent, child, derived));

        let requests = orch.step(
            &ReshapeView::new(&windowed(&snap)),
            &BlsVerifier,
            &StubVmStatics,
            Vec::new(),
            at(0),
        );

        assert!(
            !requests
                .iter()
                .any(|r| matches!(r, ReshapeRequest::OpenStore { .. })),
            "a producing child must never have its store re-opened; got {requests:?}",
        );
        assert!(
            matches!(orch.duties.get(&child), Some(Duty::Observer(_))),
            "a producing child's duty survives the closed window",
        );
    }

    /// A genuine disagreement against the seeded anchor: the followed parent
    /// chain is not the one the network committed. The duty stops without
    /// touching the store, which a seated replica is running on.
    #[test]
    fn a_disagreeing_seeded_anchor_stops_without_re_opening_the_store() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let snap = snapshot_parent_halves(&[(child, &[5])], &[(child, 5, parent)], &[child]);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);
        let forged = BlockHash::from_raw(Hash::from_bytes(b"forged"));
        insert_observer(&mut orch, child, adopted_duty(parent, child, forged));

        let requests = orch.step(
            &ReshapeView::new(&windowed(&snap)),
            &BlsVerifier,
            &StubVmStatics,
            Vec::new(),
            at(0),
        );

        assert!(
            !requests
                .iter()
                .any(|r| matches!(r, ReshapeRequest::OpenStore { .. })),
            "a disagreement must not wipe the store; got {requests:?}",
        );
        assert!(
            !matches!(orch.duties.get(&child), Some(Duty::Observer(_))),
            "a disagreeing duty stops rather than re-seeding",
        );
    }

    // ─── recognition walks fall back ────────────────────────────────────
}
