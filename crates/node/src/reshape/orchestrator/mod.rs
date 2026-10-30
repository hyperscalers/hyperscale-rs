//! The sans-io reshape orchestrator.
//!
//! One per host. It owns the per-duty sequencing decisions of a split or merge —
//! when to sync, re-assert ready, follow, adopt, and seat — and drives them by
//! reading the committed-state projection ([`ReshapeView`]) and reacting to io
//! results. It holds the sans-io sequencers ([`ObserverBootstrap`],
//! [`ObserverTail`]) so both harnesses run the *same* sequencing; the adapter
//! owns all io (`RocksDB` opens, network fetch/notify, store writes, timers) and
//! the wall-clock pacing of [`ReshapeOrchestrator::step`].
//!
//! Each duty lives in its own module — [`observer_duty`], [`parent_half`],
//! [`keeper`] — over the pieces they share in [`shared`]; [`io`] holds the
//! requests and events exchanged with the adapter.
//!
//! [`ObserverBootstrap`]: crate::reshape::observer::ObserverBootstrap
//! [`ObserverTail`]: crate::reshape::observer::ObserverTail
//!
//! Each `step` reads the view, applies the io results the adapter feeds back,
//! advances every duty, and returns the io the adapter should perform. It is
//! idempotent: one-shot requests are guarded by duty flags, the sequencers gate
//! their own in-flight fetches, and the ready re-assert backs off on the local
//! clock (`ReadyAssert`), so however often the adapter pumps a step it
//! asserts at the same pace.
//!
//! It covers all three reshape duties — the **split observer**, the **split
//! parent half**, and the **merge keeper** — each discovered from its own cohort
//! projection and sequenced to the shared adopt and seat tail.

mod io;
mod keeper;
mod observer_duty;
mod parent_half;
mod shared;
#[cfg(test)]
mod test_support;

use std::collections::BTreeMap;

use hyperscale_types::{Derivation, LocalTimestamp, ShardId, ValidatorId, Verifier};

pub use self::io::{
    AdoptKind, FetchKind, FetchedKind, OverRunning, ReshapeEvent, ReshapeRequest, seed_gate,
};
use self::keeper::{KeeperDuty, KeeperMember};
use self::observer_duty::ObserverDuty;
use self::parent_half::ParentHalfDuty;
use crate::reshape::view::ReshapeView;

/// What an advance leaves of a duty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Advance {
    /// The duty runs on.
    Continue,
    /// The duty is done and leaves the map.
    Done,
}

/// One in-flight reshape duty, keyed in [`ReshapeOrchestrator`] by the
/// store it prepares: a split child's for an observer or a parent half, the
/// reformed parent's for a keeper.
enum Duty {
    Observer(ObserverDuty),
    ParentHalf(ParentHalfDuty),
    Keeper(KeeperDuty),
}

impl Duty {
    /// Whether the duty still has a seat to take, pruning the seats it no
    /// longer holds.
    fn held(&mut self, view: &ReshapeView, me: &[ValidatorId]) -> bool {
        match self {
            Self::Observer(duty) => duty.held(view, me),
            Self::ParentHalf(duty) => duty.held(view, me),
            Self::Keeper(duty) => duty.held(view, me),
        }
    }

    /// Whether the duty gave the store's seat up to the adapter's join.
    const fn relinquished(&self) -> bool {
        match self {
            Self::Observer(duty) => duty.relinquished(),
            Self::ParentHalf(duty) => duty.relinquished(),
            Self::Keeper(_) => false,
        }
    }

    fn apply(&mut self, event: ReshapeEvent, now: LocalTimestamp) {
        match self {
            Self::Observer(duty) => duty.apply(event, now),
            Self::ParentHalf(duty) => duty.apply(event, now),
            Self::Keeper(duty) => duty.apply(event, now),
        }
    }

    fn advance(
        &mut self,
        view: &ReshapeView,
        verifier: &dyn Verifier,
        derivation: &dyn Derivation,
        now: LocalTimestamp,
        out: &mut Vec<ReshapeRequest>,
    ) -> Advance {
        match self {
            Self::Observer(duty) => duty.advance(view, verifier, derivation, now, out),
            Self::ParentHalf(duty) => {
                duty.advance(view, verifier, now, out);
                Advance::Continue
            }
            Self::Keeper(duty) => duty.advance(view, verifier, now, out),
        }
    }
}

impl ReshapeEvent {
    /// The duty this event answers, by the store shard the duty is keyed by.
    const fn duty(&self) -> ShardId {
        match self {
            Self::Opened { shard }
            | Self::Staged { shard }
            | Self::StageFailed { shard, .. }
            | Self::Imported { shard, .. }
            | Self::Applied { shard, .. }
            | Self::Adopted { shard } => *shard,
            Self::Fetched { duty, .. } | Self::FetchFailed { duty, .. } => *duty,
            Self::SeedDeferred { child } | Self::SeedUnavailable { child } => *child,
        }
    }
}

/// The per-host reshape orchestrator. See the module docs.
#[derive(Default)]
pub struct ReshapeOrchestrator {
    /// This host's validator ids — the seats it may hold.
    me: Vec<ValidatorId>,
    /// In-flight duties, keyed by the store each prepares.
    duties: BTreeMap<ShardId, Duty>,
}

impl ReshapeOrchestrator {
    /// A fresh orchestrator for a host running `me`.
    #[must_use]
    pub const fn new(me: Vec<ValidatorId>) -> Self {
        Self {
            me,
            duties: BTreeMap::new(),
        }
    }

    /// Count `validator` among this host's from now on: a validator added
    /// to the running host, whose cohort and keeper seats it may hold.
    pub fn add_me(&mut self, validator: ValidatorId) {
        if !self.me.contains(&validator) {
            self.me.push(validator);
        }
    }

    /// Stop counting `validator` among this host's: a validator that moved
    /// to another host, which discovers its cohort and keeper seats there.
    /// The next step drops its seats from the duties here, and a duty left
    /// with none ends, unless it already seated or relinquished.
    pub fn remove_me(&mut self, validator: ValidatorId) {
        self.me.retain(|&kept| kept != validator);
    }

    /// Whether an in-flight duty owns seating `shard` — a merging parent a
    /// keeper reforms, or a splitting child an observer syncs or a parent
    /// half seeds. The adapter's placement join skips such a shard so the
    /// orchestrator seats it from the duty's prepared store, rather than the
    /// join racing a redundant fresh snap-sync against it.
    #[must_use]
    pub fn is_seating(&self, shard: ShardId) -> bool {
        self.duties
            .get(&shard)
            .is_some_and(|duty| !duty.relinquished())
    }

    /// Whether this host's split duty for `shard` relinquished the child's
    /// seat to the adapter's ordinary join — a parent half with no parent
    /// store to seed from (see [`ReshapeEvent::SeedUnavailable`]) or whose
    /// child anchored past its genesis, or an observer whose follow the
    /// child's anchor overtook, whose child anchored past its genesis, or
    /// that diverged, and that no parent half
    /// took over from. The adapter reads the committed cohort as reshape
    /// ownership; a relinquished seat is not, and a store the duty prepared
    /// for it is the adapter's to discard.
    #[must_use]
    pub fn relinquished(&self, shard: ShardId) -> bool {
        self.duties.get(&shard).is_some_and(Duty::relinquished)
    }

    /// Advance every duty one step: apply the io results in `events`, discover
    /// new duties from `view`, and return the io the adapter should perform.
    ///
    /// `derivation` is this node's: a followed block arrives off the wire
    /// or out of a peer's store with none of its transactions derived, and
    /// the committed cells a follow writes are read off what deriving them
    /// seats.
    pub fn step(
        &mut self,
        view: &ReshapeView,
        verifier: &dyn Verifier,
        derivation: &dyn Derivation,
        events: Vec<ReshapeEvent>,
        now: LocalTimestamp,
    ) -> Vec<ReshapeRequest> {
        for event in events {
            if let Some(duty) = self.duties.get_mut(&event.duty()) {
                duty.apply(event, now);
            }
        }
        self.discover_observer_duties(view);
        self.discover_keeper_duties(view);
        // Before any duty advances, so one whose seats are gone emits
        // nothing more.
        let me = &self.me;
        self.duties.retain(|_, duty| duty.held(view, me));

        let mut requests = Vec::new();
        let observers = |duty: &Duty| matches!(duty, Duty::Observer(_));
        self.advance_each(observers, view, verifier, derivation, now, &mut requests);
        // After the observers advance, so a parent half takes over an
        // observer that relinquished in this very step: between steps the
        // adapter would otherwise read the seat as the join's, drop the
        // observer's store and start a join nothing may be able to serve.
        self.discover_parent_half_duties(view);
        let keepers = |duty: &Duty| matches!(duty, Duty::Keeper(_));
        self.advance_each(keepers, view, verifier, derivation, now, &mut requests);
        let halves = |duty: &Duty| matches!(duty, Duty::ParentHalf(_));
        self.advance_each(halves, view, verifier, derivation, now, &mut requests);
        requests
    }

    /// Advance every duty `pick` selects, dropping the ones that finish.
    fn advance_each(
        &mut self,
        pick: impl Fn(&Duty) -> bool,
        view: &ReshapeView,
        verifier: &dyn Verifier,
        derivation: &dyn Derivation,
        now: LocalTimestamp,
        out: &mut Vec<ReshapeRequest>,
    ) {
        let picked: Vec<ShardId> = self
            .duties
            .iter()
            .filter(|(_, duty)| pick(duty))
            .map(|(&shard, _)| shard)
            .collect();
        for shard in picked {
            if let Some(duty) = self.duties.get_mut(&shard)
                && duty.advance(view, verifier, derivation, now, out) == Advance::Done
            {
                self.duties.remove(&shard);
            }
        }
    }

    /// Open an observer duty for every cohort seat this host holds that it
    /// isn't already running.
    fn discover_observer_duties(&mut self, view: &ReshapeView) {
        for (&parent, cohort) in view.observer_cohorts() {
            for (&validator, seat) in cohort {
                if !self.me.contains(&validator) {
                    continue;
                }
                let child = seat.shard;
                let duty = self
                    .duties
                    .entry(child)
                    .or_insert_with(|| Duty::Observer(ObserverDuty::new(parent, child)));
                if let Duty::Observer(duty) = duty
                    && !duty.validators.contains(&validator)
                {
                    duty.validators.push(validator);
                }
            }
        }
    }

    /// Open a keeper duty for every cohort seat this host holds, accumulating
    /// the members it runs for each merging parent.
    fn discover_keeper_duties(&mut self, view: &ReshapeView) {
        for (&child, cohort) in view.keeper_cohorts() {
            for (&validator, seat) in cohort {
                if !self.me.contains(&validator) {
                    continue;
                }
                let parent = seat.shard;
                let duty = self
                    .duties
                    .entry(parent)
                    .or_insert_with(|| Duty::Keeper(KeeperDuty::new(parent)));
                if let Duty::Keeper(duty) = duty
                    && !duty
                        .members
                        .iter()
                        .any(|m| m.validator == validator && m.own_child == child)
                {
                    duty.members.push(KeeperMember {
                        validator,
                        own_child: child,
                        ready_assert: None,
                    });
                }
            }
        }
    }

    /// Open a parent-half duty for every cohort seat this host holds that it
    /// isn't already running. A child already covered by an observer duty is
    /// left to it — the observer's seat installs every homed committee member,
    /// the parent halves among them — until the observer relinquishes. Then
    /// the parent half takes the child over in place and seeds it from the
    /// host's own parent chain: the join that takes a relinquished seat
    /// snap-syncs from the child's committee, and when every host on that
    /// committee relinquished, none of them serves it.
    fn discover_parent_half_duties(&mut self, view: &ReshapeView) {
        for (&child, cohort) in view.parent_half_cohorts() {
            for (&validator, &parent) in cohort {
                if !self.me.contains(&validator) {
                    continue;
                }
                let duty = self
                    .duties
                    .entry(child)
                    .or_insert_with(|| Duty::ParentHalf(ParentHalfDuty::new(parent, child)));
                if let Duty::Observer(observer) = duty
                    && observer.relinquished()
                {
                    *duty = Duty::ParentHalf(ParentHalfDuty::new(parent, child));
                }
                if let Duty::ParentHalf(half) = duty
                    && !half.validators.contains(&validator)
                {
                    half.validators.push(validator);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use hyperscale_crypto_bls::BlsVerifier;
    use hyperscale_storage::ImportProgress;
    use hyperscale_storage::test_helpers::make_test_block;
    use hyperscale_types::network::request::{BlockIntent, GetBlockRequest};
    use hyperscale_types::test_utils::StubVmStatics;
    use hyperscale_types::{
        BlockHash, BlockHeight, ChainOrigin, Epoch, FrontierInputs, Hash, ShardAnchor, ShardId,
        StateRoot, WeightedTimestamp,
    };

    use super::*;
    use crate::reshape::genesis::DerivedGenesis;
    use crate::reshape::orchestrator::io::{
        AdoptKind, FetchKind, OverRunning, ReshapeEvent, ReshapeRequest, seed_gate,
    };
    use crate::reshape::orchestrator::observer_duty::ObserverPhase;
    use crate::reshape::orchestrator::shared::{TerminalFetch, split_terminal_request};
    use crate::reshape::orchestrator::test_support::*;
    use crate::reshape::view::ReshapeView;

    /// An overtaken follower on a host that also holds a parent-half seat
    /// on the child hands the seat to that parent half in the same step,
    /// so the child is seeded from the host's own parent chain rather than
    /// joined from a committee that may hold no copy of it. The io the
    /// parent half asks for reaches it, not the inert observer.
    #[test]
    fn an_overtaken_follower_hands_the_seat_to_its_co_hosted_parent_half() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let schedule = overtaking_view(&[(child, 6, parent)]);
        let view = ReshapeView::new(&schedule);
        let mut orch = overtaken_follower(&[5, 6]);

        let requests = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));
        assert!(
            matches!(orch.duties.get(&child), Some(Duty::ParentHalf(_))),
            "the relinquished observer hands the child to the parent half in place"
        );
        assert_eq!(
            seeds_through(&requests),
            Some(BlockHeight::new(20)),
            "the parent half seeds the child at its anchor; got {requests:?}"
        );
        assert!(!orch.relinquished(child));
        assert!(
            orch.is_seating(child),
            "the parent half owns the seat, so placement leaves it alone"
        );

        let _ = orch.step(
            &view,
            &BlsVerifier,
            &StubVmStatics,
            vec![ReshapeEvent::Opened { shard: child }],
            at(0),
        );
        assert!(
            parent_half(&orch, child).store_seeded,
            "the seeded store is the parent half's"
        );
        let requests = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));
        assert!(
            !block_fetches(&requests, parent).is_empty(),
            "the seeded parent half fetches the parent's terminal; got {requests:?}"
        );
    }

    /// Every store-prep request names the store it prepares and what it
    /// answers over a shard already running here; no other request does.
    #[test]
    fn only_store_preps_prepare_a_shard_or_answer_over_a_running_one() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let open = ReshapeRequest::OpenStore { shard: parent };
        let seed = ReshapeRequest::SeedFromParent {
            parent,
            child,
            through: BlockHeight::new(8),
        };
        assert_eq!(open.prepared_shard(), Some(parent));
        assert!(matches!(open.over_running(), Some(OverRunning::Nothing)));
        assert_eq!(seed.prepared_shard(), Some(child));
        assert!(matches!(
            seed.over_running(),
            Some(OverRunning::Answer(ReshapeEvent::SeedUnavailable { child: c })) if c == child
        ));

        let block = make_test_block(BlockHeight::new(1));
        let others = [
            ReshapeRequest::Fetch {
                duty: child,
                from: parent,
                kind: FetchKind::Block {
                    request: GetBlockRequest::new(BlockHeight::new(1), BlockIntent::Execute),
                },
            },
            ReshapeRequest::StageChunk {
                shard: child,
                progress: ImportProgress {
                    anchor_height: BlockHeight::new(8),
                    anchor_state_root: StateRoot::ZERO,
                    split_bits: 0,
                    chunk_limit: 1,
                    staged_bytes: 0,
                    cursors: Vec::new(),
                },
                leaves: Vec::new(),
            },
            ReshapeRequest::FinalizeImport {
                shard: child,
                height: BlockHeight::new(8),
            },
            ReshapeRequest::ApplyFollow {
                shard: child,
                block: Arc::new(block.clone()),
                creations: Vec::new(),
                frontier: FrontierInputs::still(child),
            },
            ReshapeRequest::BroadcastReady {
                validator: vid(1),
                child,
                anchor: anchor(),
                recipients: vec![vid(2)],
            },
            ReshapeRequest::Adopt {
                shard: child,
                kind: AdoptKind::ParentHalf,
                genesis: Box::new(DerivedGenesis {
                    block,
                    origin: ChainOrigin::root(WeightedTimestamp::ZERO),
                    predecessors: Vec::new(),
                }),
            },
            ReshapeRequest::Seat { shard: child },
        ];
        for request in others {
            assert_eq!(request.prepared_shard(), None, "{request:?}");
            assert!(request.over_running().is_none(), "{request:?}");
        }
    }

    /// A seed with no parent store is unavailable, one whose parent is below
    /// `through` is deferred, and one whose parent reached it may clone.
    #[test]
    fn the_seed_gate_reads_the_parent_height_against_through() {
        let (child, _) = ShardId::ROOT.children();
        let through = BlockHeight::new(8);
        assert!(matches!(
            seed_gate(None, child, through),
            Some(ReshapeEvent::SeedUnavailable { child: c }) if c == child
        ));
        assert!(matches!(
            seed_gate(Some(BlockHeight::new(7)), child, through),
            Some(ReshapeEvent::SeedDeferred { child: c }) if c == child
        ));
        assert!(seed_gate(Some(through), child, through).is_none());
    }

    #[test]
    fn a_parent_half_is_left_to_an_active_observer_duty() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        // The host holds an observer seat (validator 5, syncing the child) and a
        // parent-half seat (validator 6) for the same child.
        let snap = build(
            &[(parent, &[1, 2])],
            &[(parent, 5, child, false)],
            &[],
            &[(child, 6, parent)],
            &[],
            anchor(),
        );
        let mut orch = ReshapeOrchestrator::new(vec![vid(5), vid(6)]);

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
                .any(|r| matches!(r, ReshapeRequest::OpenStore { shard } if *shard == child)),
            "the observer duty opens the child store; got {requests:?}",
        );
        assert!(
            !requests
                .iter()
                .any(|r| matches!(r, ReshapeRequest::SeedFromParent { .. })),
            "no parent-half seed is emitted while an observer covers the child; got {requests:?}",
        );
    }

    /// A split's terminal fetch names the parent's terminal crossing, the
    /// block the parent's own boundary records one below the child's
    /// seeded genesis; a record at another height is not that crossing,
    /// and the fetch asks by height alone.
    #[test]
    fn a_split_terminal_fetch_names_the_parents_terminal_crossing() {
        let parent = ShardId::ROOT;
        let (child, _) = parent.children();
        let terminal_hash = BlockHash::from_raw(Hash::from_bytes(b"terminal"));
        let parent_record = |height| ShardAnchor {
            block_hash: terminal_hash,
            height: BlockHeight::new(height),
            terminal_epoch: Some(Epoch::new(3)),
            ..anchor()
        };
        let observing = |record: ShardAnchor| {
            let snap = snapshot(&[(child, &[1, 5])], &[], &[])
                .with_boundaries(BTreeMap::from([(parent, record), (child, anchor())]));
            let schedule = windowed(&snap);
            let view = ReshapeView::new(&schedule);
            assert_eq!(
                split_terminal_request(&view, parent, &anchor()).hash,
                (record.height == BlockHeight::new(7)).then_some(terminal_hash),
                "the parent half's fetch names the same block",
            );
            let mut orch = ReshapeOrchestrator::new(vec![vid(5)]);
            insert_observer(
                &mut orch,
                child,
                observer_duty(
                    parent,
                    child,
                    5,
                    ObserverPhase::FetchingTerminal(TerminalFetch::new(anchor())),
                ),
            );
            let requests = orch.step(&view, &BlsVerifier, &StubVmStatics, Vec::new(), at(0));
            let fetches = block_fetches(&requests, child);
            assert_eq!(fetches.len(), 1, "got {requests:?}");
            assert_eq!(fetches[0].height, BlockHeight::new(7));
            fetches[0].hash
        };
        assert_eq!(observing(parent_record(7)), Some(terminal_hash));
        assert_eq!(observing(parent_record(5)), None);
    }
}
