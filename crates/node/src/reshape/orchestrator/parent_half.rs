//! The split parent-half duty: seed the child store by cloning the host's
//! local parent, and adopt the child's genesis.

use std::time::Duration;

use hyperscale_types::{LocalTimestamp, ShardId, ValidatorId, Verifier};

use super::io::{AdoptKind, FetchKind, FetchedKind, ReshapeEvent, ReshapeRequest};
use super::shared::{REFETCH_WAIT, SeatTail, TerminalFetch, paced, seats_on, terminal_commit};
use crate::reshape::genesis::DerivedGenesis;
use crate::reshape::observer::{ObserverTail, TwoChainCheck};
use crate::reshape::view::ReshapeView;

/// Wait before re-requesting a seed the local parent was not ready for
/// ([`ReshapeEvent::SeedDeferred`]). Half the adapters' one-second step
/// cadence, so the retry goes out on the next step even when the step's
/// local clock runs slightly slow.
pub(super) const SEED_RETRY: Duration = Duration::from_millis(500);

/// A parent half's seed of the child store from the host's local parent:
/// one in flight at a time, and a deferred one asked again only after
/// [`SEED_RETRY`].
#[derive(Default)]
pub(super) struct SeedRequest {
    /// Whether the seed request is in flight.
    requested: bool,
    /// When a deferred seed may be requested again.
    retry_at: Option<LocalTimestamp>,
}

impl SeedRequest {
    /// Whether a seed goes out at `now`, marking it in flight if so.
    pub(super) fn begin(&mut self, now: LocalTimestamp) -> bool {
        let due = !self.requested && self.retry_at.is_none_or(|at| now >= at);
        if due {
            self.requested = true;
        }
        due
    }

    /// The local parent was not ready for the seed in flight.
    fn deferred(&mut self, now: LocalTimestamp) {
        self.requested = false;
        self.retry_at = Some(now.plus(SEED_RETRY));
    }
}

/// One parent half's progress through its split duty.
pub(super) enum ParentHalfPhase {
    /// Awaiting the child anchor, then seeding the child store by cloning the
    /// host's local parent once it has committed through the terminal crossing.
    /// The fallback entry, for a duty with no scheduled cut to recognise.
    Seeding(SeedRequest),
    /// Walking the parent's own committed chain to find its terminal
    /// crossing, so the child can be seeded and adopted at the cut rather
    /// than an epoch later when the beacon publishes the child's anchor.
    /// Applies nothing — the store comes from cloning the local parent.
    Recognizing(Box<ObserverTail>),
    /// Terminal recognised and genesis derived; cloning the local parent
    /// through the child's genesis height.
    SeedingAt {
        /// The derived genesis.
        genesis: Box<DerivedGenesis>,
        seed: SeedRequest,
    },
    /// Store seeded; fetching the parent's certified terminal to derive the
    /// child genesis.
    FetchingTerminal(TerminalFetch),
    /// Genesis derived, adopted, and seated; once seated, inert until the
    /// committed projection releases the duty.
    Seat(SeatTail),
    /// The host holds no parent store to seed the child from, so the child's
    /// seat is the adapter's ordinary join's. Inert, and kept only so the
    /// duty is not rediscovered, until the committed projection releases it.
    Relinquished,
}

/// One split parent-half duty, keyed by the child it seats. As with an observer
/// duty, a host may hold more than one parent-half seat for the same child; they
/// share the one cloned store and seat under the one placement.
pub(super) struct ParentHalfDuty {
    pub(super) parent: ShardId,
    pub(super) child: ShardId,
    pub(super) validators: Vec<ValidatorId>,
    pub(super) phase: ParentHalfPhase,
    pub(super) store_seeded: bool,
}

impl ParentHalfDuty {
    pub(super) const fn new(parent: ShardId, child: ShardId) -> Self {
        Self {
            parent,
            child,
            validators: Vec::new(),
            phase: ParentHalfPhase::Seeding(SeedRequest {
                requested: false,
                retry_at: None,
            }),
            store_seeded: false,
        }
    }

    pub(super) const fn relinquished(&self) -> bool {
        matches!(self.phase, ParentHalfPhase::Relinquished)
    }

    /// Whether the duty still has a seat to take, pruning the seats whose
    /// validators this host no longer runs. A parent half is discovered
    /// only once its split has executed, so it runs on while one of its
    /// seats sits on the child's committee, or the child has none yet.
    ///
    /// A seated or relinquished parent half lingers only to keep its child
    /// from being re-discovered; once the projection releases it (the child
    /// committed past genesis) the duty is done.
    pub(super) fn held(&mut self, view: &ReshapeView, me: &[ValidatorId]) -> bool {
        self.validators.retain(|validator| me.contains(validator));
        if matches!(
            self.phase,
            ParentHalfPhase::Seat(SeatTail::Seated) | ParentHalfPhase::Relinquished
        ) {
            return view.parent_half_cohorts().contains_key(&self.child);
        }
        !self.validators.is_empty() && seats_on(view, self.child, self.validators.iter())
    }

    /// Route one io result to the phase awaiting it.
    pub(super) fn apply(&mut self, event: ReshapeEvent, now: LocalTimestamp) {
        match event {
            ReshapeEvent::Opened { .. } => self.store_seeded = true,
            ReshapeEvent::Fetched { kind, .. } => self.on_fetched(kind, now),
            ReshapeEvent::FetchFailed { .. } => match &mut self.phase {
                ParentHalfPhase::Recognizing(tail) => tail.on_failure(),
                ParentHalfPhase::FetchingTerminal(fetch) => fetch.on_failure(now),
                _ => {}
            },
            ReshapeEvent::Adopted { .. } => {
                if let ParentHalfPhase::Seat(tail) = &mut self.phase {
                    tail.on_adopted();
                }
            }
            ReshapeEvent::SeedDeferred { .. } => {
                if let ParentHalfPhase::Seeding(seed) | ParentHalfPhase::SeedingAt { seed, .. } =
                    &mut self.phase
                {
                    seed.deferred(now);
                }
            }
            ReshapeEvent::SeedUnavailable { .. } => {
                if matches!(
                    self.phase,
                    ParentHalfPhase::Seeding(_) | ParentHalfPhase::SeedingAt { .. }
                ) {
                    self.phase = ParentHalfPhase::Relinquished;
                }
            }
            ReshapeEvent::Staged { .. }
            | ReshapeEvent::StageFailed { .. }
            | ReshapeEvent::Imported { .. }
            | ReshapeEvent::Applied { .. } => {}
        }
    }

    /// Feed a walk's headers, or derive the child genesis once the terminal
    /// fetch returns.
    fn on_fetched(&mut self, kind: FetchedKind, now: LocalTimestamp) {
        let child = self.child;
        match (&mut self.phase, kind) {
            (ParentHalfPhase::Recognizing(tail), FetchedKind::Headers { response }) => {
                let outcome = tail.on_certified_headers(&response.headers);
                paced(tail, outcome, now, child);
            }
            (ParentHalfPhase::FetchingTerminal(fetch), FetchedKind::Block { response }) => {
                if let Some(genesis) = fetch.on_block(child, &response, now) {
                    self.phase = ParentHalfPhase::Seat(SeatTail::Adopting(Box::new(genesis)));
                }
            }
            _ => {}
        }
    }

    /// Advance the duty, emitting its current io.
    pub(super) fn advance(
        &mut self,
        view: &ReshapeView,
        verifier: &dyn Verifier,
        now: LocalTimestamp,
        out: &mut Vec<ReshapeRequest>,
    ) {
        let (parent, child) = (self.parent, self.child);
        match &mut self.phase {
            ParentHalfPhase::Seeding(seed) => {
                // With the cut scheduled a window ahead, the parent's own
                // chain says which of its blocks is the terminal — no need
                // to wait for the beacon to publish the child's anchor.
                // Only when genuinely early: once the child's anchor
                // projects, the parent has terminated and may already have
                // dissolved, so a walk of its chain would never resolve.
                // Late-discovered duties take the anchor path below.
                if !seed.requested
                    && view.boundary(child).is_none()
                    && view.terminal_cut(parent).is_some()
                    && let Some(parent_anchor) = view.boundary(parent)
                {
                    self.phase = ParentHalfPhase::Recognizing(Box::new(ObserverTail::recognizing(
                        parent_anchor,
                        child,
                    )));
                }
                // Fallback: the child anchor seeds once the parent's terminal
                // folds; it is the version the clone must reach and the
                // derivation verifies against.
                else if let Some(anchor) = view.boundary(child) {
                    if view.advanced_past_genesis(child) {
                        // The child crossed since its genesis, so its anchor
                        // names a block of the child's own chain: no clone of
                        // the parent reaches it, and no genesis derived from the
                        // parent's terminal reconstructs it. The seat is the
                        // join's, which snap-syncs against that anchor.
                        tracing::info!(
                            ?child,
                            anchor_height = anchor.height.inner(),
                            "split child anchored past its genesis; relinquishing the parent half's seat"
                        );
                        self.phase = ParentHalfPhase::Relinquished;
                    } else if self.store_seeded {
                        self.phase = ParentHalfPhase::FetchingTerminal(TerminalFetch::new(anchor));
                    } else if seed.begin(now) {
                        out.push(ReshapeRequest::SeedFromParent {
                            parent,
                            child,
                            through: anchor.height,
                        });
                    }
                }
            }
            ParentHalfPhase::Recognizing(tail) => {
                tail.set_terminal_cut(view.terminal_cut(parent));
                let check = tail
                    .settled_terminal()
                    .map(|sighting| terminal_commit(parent, sighting, verifier, view));
                if matches!(check, Some(TwoChainCheck::Refuted(_))) {
                    tail.restart();
                    tail.defer(now.plus(REFETCH_WAIT));
                }
                if check == Some(TwoChainCheck::Verified)
                    && let Some(sighting) = tail.settled_terminal()
                    && let Some(derived) = &sighting.genesis
                {
                    tracing::info!(
                        ?child,
                        terminal_height = sighting.header.height().inner(),
                        "seating the split child's parent half from the local parent chain"
                    );
                    self.phase = ParentHalfPhase::SeedingAt {
                        genesis: Box::new(derived.clone()),
                        seed: SeedRequest::default(),
                    };
                } else if view.boundary(child).is_some() {
                    // The walk ran out of time: the beacon published the
                    // child's anchor, so the parent has terminated and may
                    // already have dissolved — nothing further will arrive to
                    // prove. Hand back to the seed, whose anchor branch clones
                    // the local parent against that height.
                    tracing::debug!(
                        ?child,
                        "parent terminal walk did not resolve before the child anchored; \
                         falling back to the attested anchor"
                    );
                    self.phase = ParentHalfPhase::Seeding(SeedRequest::default());
                } else if let Some(request) = tail.next_header_request(parent, now) {
                    out.push(ReshapeRequest::Fetch {
                        duty: child,
                        from: parent,
                        kind: FetchKind::Headers { request },
                    });
                }
            }
            ParentHalfPhase::SeedingAt { genesis, seed } => {
                if self.store_seeded {
                    self.phase = ParentHalfPhase::Seat(SeatTail::Adopting(genesis.clone()));
                } else if seed.begin(now) {
                    out.push(ReshapeRequest::SeedFromParent {
                        parent,
                        child,
                        through: genesis.origin.genesis_height,
                    });
                }
            }
            ParentHalfPhase::FetchingTerminal(fetch) => {
                // The seed gates on the local parent reaching the terminal, so
                // the host's own retained chain serves the certified terminal.
                if let Some(request) = fetch.next_request(view, parent, now) {
                    out.push(ReshapeRequest::Fetch {
                        duty: child,
                        from: parent,
                        kind: FetchKind::Block { request },
                    });
                }
            }
            ParentHalfPhase::Relinquished => {}
            ParentHalfPhase::Seat(tail) => {
                tail.advance(child, AdoptKind::ParentHalf, &self.validators, view, out);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use hyperscale_crypto_bls::BlsVerifier;
    use hyperscale_types::test_utils::{
        StubVmStatics, TestCommittee, signed_child_block, signed_split_terminal,
    };
    use hyperscale_types::{
        BlockHeight, Epoch, Hash, LocalTimestamp, Round, ShardAnchor, ShardId, SplitChildRoots,
        StateRoot, WeightedTimestamp,
    };

    use super::*;
    use crate::reshape::observer::ObserverTail;
    use crate::reshape::orchestrator::io::{ReshapeEvent, ReshapeRequest};
    use crate::reshape::orchestrator::shared::SeatTail;
    use crate::reshape::orchestrator::test_support::*;
    use crate::reshape::orchestrator::{Duty, ReshapeOrchestrator};
    use crate::reshape::view::ReshapeView;

    /// A parent half walks its parent's committed headers as a server
    /// hands them over, and seeds the child only from a terminal whose
    /// commit the parent committee's own QCs prove, each against the
    /// committee its window resolves. A successor the committee never
    /// certified leaves the walk unresolved, so the anchor path still
    /// covers it; the genuine successor seeds the child at the genesis
    /// height above the terminal.
    #[test]
    fn a_parent_half_seeds_only_from_a_terminal_its_committee_proves() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let committee = TestCommittee::new(4, 3);
        let impostors = TestCommittee::new(4, 99);
        let schedule = committee_schedule(parent, &committee, &[]);
        let view = ReshapeView::new(&schedule);
        let (anchor_block, anchor) = anchored_block();
        let pair = SplitChildRoots {
            left: StateRoot::from_raw(Hash::from_bytes(b"left subtree")),
            right: StateRoot::from_raw(Hash::from_bytes(b"right subtree")),
        };
        let terminal = signed_split_terminal(
            &committee,
            &anchor_block,
            Round::new(2),
            WeightedTimestamp::from_millis(200),
            pair,
        );
        let successor = signed_child_block(
            &committee,
            &terminal,
            Round::new(3),
            WeightedTimestamp::from_millis(300),
        );

        let mut orch = recognizing_parent_half(parent, child, anchor);
        let requests = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));
        assert_eq!(header_fetches_from(&requests), vec![BlockHeight::new(2)]);
        let requests = orch.step(
            &view,
            &BlsVerifier,
            &StubVmStatics,
            vec![walked(child, parent, &committee, &[&terminal])],
            at(0),
        );
        assert_eq!(header_fetches_from(&requests), vec![BlockHeight::new(3)]);
        let requests = orch.step(
            &view,
            &BlsVerifier,
            &StubVmStatics,
            vec![walked(child, parent, &impostors, &[&successor])],
            at(0),
        );
        assert_eq!(seeds_through(&requests), None);
        assert!(
            header_fetches_from(&requests).is_empty(),
            "a refuted proof holds the walk back",
        );
        assert!(
            matches!(
                parent_half(&orch, child).phase,
                ParentHalfPhase::Recognizing(_)
            ),
            "a successor the committee never certified proves nothing",
        );

        // The walk starts over above the anchor, where the committee's own
        // certificates prove the terminal.
        let refetch = refetch_ms();
        let requests = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(refetch));
        assert_eq!(header_fetches_from(&requests), vec![BlockHeight::new(2)]);
        let _ = orch.step(
            &view,
            &BlsVerifier,
            &StubVmStatics,
            vec![walked(child, parent, &committee, &[&terminal, &successor])],
            at(refetch),
        );
        let requests = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(refetch));
        assert_eq!(
            seeds_through(&requests),
            Some(terminal.height().next()),
            "a proven terminal seeds the child through its genesis height",
        );
    }

    /// A recognizing walk at its chain's tip gets an empty batch; the next
    /// ask waits out the refetch wait, and a batch that delivers headers
    /// asks on at once.
    #[test]
    fn an_empty_answer_at_the_tip_defers_the_next_walk_fetch() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let committee = TestCommittee::new(4, 3);
        let schedule = committee_schedule(parent, &committee, &[]);
        let view = ReshapeView::new(&schedule);
        let (anchor_block, anchor) = anchored_block();
        let b2 = signed_child_block(
            &committee,
            &anchor_block,
            Round::new(2),
            WeightedTimestamp::from_millis(100),
        );

        let mut orch = recognizing_parent_half(parent, child, anchor);
        let requests = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));
        assert_eq!(header_fetches_from(&requests), vec![BlockHeight::new(2)]);
        let requests = orch.step(
            &view,
            &BlsVerifier,
            &StubVmStatics,
            vec![walked(child, parent, &committee, &[])],
            at(0),
        );
        assert_eq!(
            header_fetches_from(&requests),
            Vec::new(),
            "an empty batch holds the next ask back",
        );
        let refetch = refetch_ms();
        let requests = orch.step(
            &view,
            &BlsVerifier,
            &StubVmStatics,
            Vec::new(),
            at(refetch - 1),
        );
        assert!(header_fetches_from(&requests).is_empty());
        let requests = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(refetch));
        assert_eq!(header_fetches_from(&requests), vec![BlockHeight::new(2)]);
        let requests = orch.step(
            &view,
            &BlsVerifier,
            &StubVmStatics,
            vec![walked(child, parent, &committee, &[&b2])],
            at(refetch),
        );
        assert_eq!(
            header_fetches_from(&requests),
            vec![BlockHeight::new(3)],
            "a delivered batch asks on at once"
        );
    }

    #[test]
    fn detects_a_parent_half_seat_and_seeds_from_the_parent() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        // The child anchor has seeded, so the duty seeds the child store from
        // the host's local parent.
        let snap = snapshot_parent_halves(&[(child, &[1, 5])], &[(child, 5, parent)], &[child]);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);

        let requests = orch.step(
            &ReshapeView::new(&windowed(&snap)),
            &BlsVerifier,
            &StubVmStatics,
            Vec::new(),
            at(0),
        );

        assert!(
            matches!(
                requests.as_slice(),
                [ReshapeRequest::SeedFromParent { parent: p, child: c, .. }]
                    if *p == parent && *c == child
            ),
            "a held parent-half seat must seed from the parent; got {requests:?}",
        );
    }

    #[test]
    fn a_deferred_seed_re_arms_and_retries() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let snap = snapshot_parent_halves(&[(child, &[1, 5])], &[(child, 5, parent)], &[child]);
        let schedule = windowed(&snap);
        let view = ReshapeView::new(&schedule);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);

        // The first step seeds; the seed is one-shot, so the next is quiet.
        let _ = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));
        assert!(
            orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0))
                .is_empty()
        );

        // A deferral (the local parent is still behind) re-arms the seed,
        // but not at the deferral's own instant: an adapter feeds it straight
        // back, and a re-request then would spin against a cause that stands.
        let seeds = |requests: &[ReshapeRequest]| {
            requests.iter().any(
                |r| matches!(r, ReshapeRequest::SeedFromParent { child: c, .. } if *c == child),
            )
        };
        let requests = orch.step(
            &view,
            &BlsVerifier,
            &StubVmStatics,
            vec![ReshapeEvent::SeedDeferred { child }],
            at(0),
        );
        assert!(
            !seeds(&requests),
            "a deferred seed must wait before retrying; got {requests:?}",
        );
        let early = at(u64::try_from(SEED_RETRY.as_millis()).expect("fits u64") - 1);
        let requests = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), early);
        assert!(
            !seeds(&requests),
            "a deferred seed must wait out its retry; got {requests:?}",
        );
        let due = LocalTimestamp::ZERO.plus(SEED_RETRY);
        let requests = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), due);
        assert!(
            seeds(&requests),
            "a deferred seed must retry once its wait is out; got {requests:?}",
        );
        assert!(
            orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), due)
                .is_empty(),
            "the retried seed is one-shot again",
        );
    }

    /// A seed with no parent store to clone relinquishes the seat: the duty
    /// stops seeding and no longer claims the child, but stays until the
    /// projection releases the cohort, so it is not rediscovered into the
    /// same missing store.
    #[test]
    fn an_unavailable_seed_relinquishes_the_seat_until_the_projection_releases_it() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let snap = snapshot_parent_halves(&[(child, &[1, 5])], &[(child, 5, parent)], &[child]);
        let schedule = windowed(&snap);
        let view = ReshapeView::new(&schedule);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);

        let _ = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));
        assert!(
            orch.is_seating(child),
            "the discovered duty claims the child"
        );

        let requests = orch.step(
            &view,
            &BlsVerifier,
            &StubVmStatics,
            vec![ReshapeEvent::SeedUnavailable { child }],
            at(0),
        );
        assert!(
            requests.is_empty(),
            "a relinquished duty emits nothing; got {requests:?}"
        );
        assert!(orch.relinquished(child));
        assert!(
            !orch.is_seating(child),
            "a relinquished seat is the join's to take"
        );
        assert!(
            orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0))
                .is_empty(),
            "the duty is not rediscovered while the cohort stands"
        );

        let released = snapshot_parent_halves(&[(child, &[1, 5])], &[], &[child]);
        let _ = orch.step(
            &ReshapeView::new(&windowed(&released)),
            &BlsVerifier,
            &StubVmStatics,
            Vec::new(),
            at(0),
        );
        assert!(
            !orch.relinquished(child)
                && !matches!(orch.duties.get(&child), Some(Duty::ParentHalf(_))),
            "the released cohort ends the relinquished duty"
        );
    }

    /// A parent half seeds against its child's genesis anchor, one above the
    /// parent's terminal record; once the child has crossed past its genesis,
    /// no clone of the parent reaches the anchor and the seat is the join's.
    #[test]
    fn a_parent_half_relinquishes_a_child_anchored_past_its_genesis() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let terminal = ShardAnchor {
            height: BlockHeight::new(7),
            terminal_epoch: Some(Epoch::new(3)),
            ..anchor()
        };
        let seeding_with = |child_anchor: ShardAnchor, advanced: BTreeSet<ShardId>| {
            let snap = snapshot_parent_halves(&[(child, &[1, 5])], &[(child, 5, parent)], &[])
                .with_boundaries(BTreeMap::from([(parent, terminal), (child, child_anchor)]))
                .with_advanced(advanced);
            let schedule = windowed(&snap);
            let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);
            let requests = orch.step(
                &ReshapeView::new(&schedule),
                &BlsVerifier,
                &StubVmStatics,
                Vec::new(),
                at(0),
            );
            (orch, requests)
        };
        let seeding = |child_anchor| seeding_with(child_anchor, BTreeSet::new());
        let seeding_advanced = |child_anchor| seeding_with(child_anchor, BTreeSet::from([child]));

        let (orch, requests) = seeding(anchor());
        assert!(
            matches!(
                requests.as_slice(),
                [ReshapeRequest::SeedFromParent { through, .. }] if *through == BlockHeight::new(8)
            ),
            "a genesis anchor seeds from the parent; got {requests:?}"
        );
        assert!(orch.is_seating(child));

        let crossed = ShardAnchor {
            height: BlockHeight::new(12),
            ..anchor()
        };
        let (orch, requests) = seeding_advanced(crossed);
        assert!(
            requests.is_empty(),
            "an anchor past the genesis seeds nothing; got {requests:?}"
        );
        assert!(orch.relinquished(child));
        assert!(
            !orch.is_seating(child),
            "the relinquished seat is the join's to take"
        );
    }

    /// A child crossing on its own chain relinquishes the parent half's seat
    /// even once the parent's terminal record is gone, which leaves nothing
    /// to place the genesis by height.
    #[test]
    fn a_parent_half_relinquishes_a_child_past_its_genesis_without_a_parent_record() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let snap = snapshot_parent_halves(&[(child, &[1, 5])], &[(child, 5, parent)], &[child])
            .with_advanced(BTreeSet::from([child]));
        let schedule = windowed(&snap);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);
        let requests = orch.step(
            &ReshapeView::new(&schedule),
            &BlsVerifier,
            &StubVmStatics,
            Vec::new(),
            at(0),
        );
        assert!(
            requests.is_empty(),
            "a crossing anchor seeds nothing; got {requests:?}"
        );
        assert!(orch.relinquished(child));
    }

    #[test]
    fn a_prepared_parent_half_seats_then_releases_with_the_projection() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let snap = snapshot_parent_halves(&[(child, &[1, 5])], &[(child, 5, parent)], &[child]);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);
        insert_parent_half(
            &mut orch,
            child,
            ParentHalfDuty {
                parent,
                child,
                validators: vec![vid(5)],
                phase: ParentHalfPhase::Seat(SeatTail::Prepared),
                store_seeded: true,
            },
        );

        // Placed on the child committee → seat, then persist while the
        // projection still lists the cohort.
        let requests = orch.step(
            &ReshapeView::new(&windowed(&snap)),
            &BlsVerifier,
            &StubVmStatics,
            Vec::new(),
            at(0),
        );
        assert!(
            matches!(requests.as_slice(), [ReshapeRequest::Seat { shard }] if *shard == child),
            "a prepared parent half seats once placed; got {requests:?}",
        );
        assert!(
            matches!(orch.duties.get(&child), Some(Duty::ParentHalf(_))),
            "a seated parent half persists while the projection lists it",
        );

        // Once the child commits past genesis the projection releases the
        // cohort, and the seated duty is dropped.
        let released = snapshot_parent_halves(&[(child, &[1, 5])], &[], &[child]);
        let _ = orch.step(
            &ReshapeView::new(&windowed(&released)),
            &BlsVerifier,
            &StubVmStatics,
            Vec::new(),
            at(0),
        );
        assert!(
            !matches!(orch.duties.get(&child), Some(Duty::ParentHalf(_))),
            "a released seated parent half is dropped",
        );
    }

    // ─── the derived-versus-attested cross-check ────────────────────────

    /// A parent half whose walk never resolves a commit-provable terminal
    /// hands back to the anchor path once the child's anchor lands, rather
    /// than fetching heights past a tip that will never advance.
    #[test]
    fn a_parent_half_walk_falls_back_once_the_child_anchors() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        // The child's anchor projects, so the parent has terminated: the
        // walk cannot resolve and the seed is the way through.
        let snap = snapshot_parent_halves(&[(child, &[1, 5])], &[(child, 5, parent)], &[child]);
        let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);
        insert_parent_half(
            &mut orch,
            child,
            ParentHalfDuty {
                parent,
                child,
                validators: vec![vid(5)],
                phase: ParentHalfPhase::Recognizing(Box::new(ObserverTail::recognizing(
                    anchor(),
                    child,
                ))),
                store_seeded: false,
            },
        );

        let schedule = windowed(&snap);
        let view = ReshapeView::new(&schedule);
        // The first step leaves `Recognizing`; the second emits the seed the
        // anchor path opens with.
        let _ = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));
        assert!(
            matches!(
                parent_half(&orch, child).phase,
                ParentHalfPhase::Seeding { .. }
            ),
            "the walk must hand back to the seed",
        );
        let requests = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));
        assert!(
            requests.iter().any(
                |r| matches!(r, ReshapeRequest::SeedFromParent { child: c, .. } if *c == child)
            ),
            "the fallback must emit the anchor path's seed; got {requests:?}",
        );
    }
}
