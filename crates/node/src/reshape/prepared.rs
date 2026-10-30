//! The stores reshape duties prepare, held by the adapter between the
//! orchestrator's store-prep and seat requests.
//!
//! Both adapters keep one [`PreparedStores`] per host, pass every store prep
//! through [`PreparedStores::prep`] and settle every io completion through
//! [`PreparedStores::settle`], so the lifecycle of a prepared store — opened,
//! adopted, then seated, released, removed by a seed, or drained by a crash —
//! is written once. The simulation settles inline; production settles on its
//! loop when the off-loop work reports back.
//!
//! Two rules keep the map in step with the orchestrator. A completion that
//! carries store state lands only when the orchestrator awaits its ticket,
//! so the map never holds a store its duty did not take. And a shard has at
//! most one prep in flight: a later prep waits until the earlier one lands,
//! and the earlier store, which no duty then awaits, is closed before the
//! later prep wipes the directory.

use std::collections::BTreeMap;

use hyperscale_storage::RecoveredState;
use hyperscale_types::{Block, ShardId};
use tracing::{debug, warn};

use crate::reshape::orchestrator::{ReshapeEvent, ReshapeRequest, Ticket};

/// How far a prepared store has come.
enum Stage {
    /// Opened or seeded; the duty imports, follows or waits on its adopt.
    Opened,
    /// The derived genesis is adopted into the store; the seat installs it.
    Adopted { genesis: Box<Block> },
}

/// One duty's in-flight store.
struct PreparedStore<S> {
    storage: S,
    /// The recovered state the seat boots from, rebuilt at the adopt.
    recovered: RecoveredState,
    stage: Stage,
}

/// Every store this host's reshape duties prepared, keyed by the shard each
/// will seat, and the preps still preparing one.
pub struct PreparedStores<S> {
    stores: BTreeMap<ShardId, PreparedStore<S>>,
    /// The ticket of the prep in flight on each shard's directory.
    preparing: BTreeMap<ShardId, Ticket>,
    /// The latest prep for a shard issued while an earlier one was in
    /// flight, waiting for that one to land.
    held: BTreeMap<ShardId, ReshapeRequest>,
}

/// A reshape io completion as an adapter reports it: the two that carry
/// store state the map holds, a failed prep, and every other event as is.
pub enum ReshapeCompletion<S> {
    /// A store open or parent seed landed.
    Opened {
        /// The prepared shard.
        shard: ShardId,
        /// The opened store.
        storage: S,
        /// Its recovered state.
        recovered: RecoveredState,
        /// The open's or seed's ticket.
        ticket: Ticket,
    },
    /// A store open or parent seed failed; its duty is stranded, and the
    /// shard's directory is free for the next prep.
    PrepFailed {
        /// The shard the prep was preparing.
        shard: ShardId,
        /// The open's or seed's ticket.
        ticket: Ticket,
    },
    /// A genesis adoption landed, its root verified against the genesis's.
    Adopted {
        /// The prepared shard.
        shard: ShardId,
        /// The adopted genesis the seat installs.
        genesis: Box<Block>,
        /// The recovered state rebuilt over the adopted genesis.
        recovered: RecoveredState,
        /// The adopt's ticket.
        ticket: Ticket,
    },
    /// Any other completion, which touches no prepared store.
    Event(ReshapeEvent),
}

/// What a seat installs, taken out of the map.
pub struct Seating<S> {
    /// The adopted store.
    pub storage: S,
    /// The genesis adopted into it.
    pub genesis: Block,
    /// The recovered state the seated replica boots from.
    pub recovered: RecoveredState,
}

/// The shard a store-prep request prepares and its ticket.
const fn prep_of(request: &ReshapeRequest) -> Option<(ShardId, Ticket)> {
    match request {
        ReshapeRequest::OpenStore { shard, ticket } => Some((*shard, *ticket)),
        ReshapeRequest::SeedFromParent { child, ticket, .. } => Some((*child, *ticket)),
        _ => None,
    }
}

impl<S> Default for PreparedStores<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> PreparedStores<S> {
    /// No store prepared.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            stores: BTreeMap::new(),
            preparing: BTreeMap::new(),
            held: BTreeMap::new(),
        }
    }

    /// Admit `request` for the adapter to perform, or hold it.
    ///
    /// A store prep for a shard with another prep in flight is held until
    /// that one lands (see [`Self::ready_preps`]), so two preps never touch
    /// one directory at once. An admitted prep closes any store an earlier
    /// duty prepared for the shard, since the prep replaces the directory,
    /// and is in flight until its completion settles. Every other request
    /// passes through.
    pub fn prep(&mut self, request: ReshapeRequest) -> Option<ReshapeRequest> {
        let Some((shard, ticket)) = prep_of(&request) else {
            return Some(request);
        };
        if self.preparing.contains_key(&shard) {
            debug!(shard = ?shard, "Reshape store-prep held behind the shard's prep in flight");
            self.held.insert(shard, request);
            return None;
        }
        self.stores.remove(&shard);
        self.preparing.insert(shard, ticket);
        Some(request)
    }

    /// Take every held prep whose shard has no prep in flight any more,
    /// ascending by shard, dropping the ones no duty awaits — `awaits` is
    /// the orchestrator's.
    pub fn ready_preps(&mut self, awaits: impl Fn(ShardId, Ticket) -> bool) -> Vec<ReshapeRequest> {
        let (ready, waiting): (BTreeMap<_, _>, BTreeMap<_, _>) = std::mem::take(&mut self.held)
            .into_iter()
            .partition(|(shard, _)| !self.preparing.contains_key(shard));
        self.held = waiting;
        ready
            .into_values()
            .filter(|request| prep_of(request).is_some_and(|(shard, ticket)| awaits(shard, ticket)))
            .collect()
    }

    /// Settle one completion and answer the event the orchestrator consumes.
    ///
    /// `awaits` is the orchestrator's: a duty takes a completion only for a
    /// ticket it awaits, and the map follows it. A prep's completion ends
    /// the prep in flight on its shard. An awaited open inserts its store
    /// and answers [`ReshapeEvent::Opened`]; an unawaited one closes its
    /// store and answers nothing. An awaited adopt moves a held store from opened to
    /// adopted and answers [`ReshapeEvent::Adopted`]; an unawaited one, or
    /// one whose store is gone, answers nothing, since every path that drops
    /// a store mid-flight acts on a duty that no longer owns the shard. Any
    /// other event passes through.
    pub fn settle(
        &mut self,
        completion: ReshapeCompletion<S>,
        awaits: impl Fn(ShardId, Ticket) -> bool,
    ) -> Option<ReshapeEvent> {
        match completion {
            ReshapeCompletion::Opened {
                shard,
                storage,
                recovered,
                ticket,
            } => {
                self.landed(shard, ticket);
                if !awaits(shard, ticket) {
                    debug!(shard = ?shard, ?ticket, "Reshape store no duty awaits; closed");
                    return None;
                }
                self.stores.insert(
                    shard,
                    PreparedStore {
                        storage,
                        recovered,
                        stage: Stage::Opened,
                    },
                );
                Some(ReshapeEvent::Opened { shard, ticket })
            }
            ReshapeCompletion::PrepFailed { shard, ticket } => {
                self.landed(shard, ticket);
                None
            }
            ReshapeCompletion::Adopted {
                shard,
                genesis,
                recovered,
                ticket,
            } => {
                if !awaits(shard, ticket) {
                    return None;
                }
                let store = self.stores.get_mut(&shard)?;
                debug_assert!(
                    matches!(store.stage, Stage::Opened),
                    "a reshape adopt for {shard:?} landed on a store already adopted",
                );
                store.stage = Stage::Adopted { genesis };
                store.recovered = recovered;
                Some(ReshapeEvent::Adopted { shard, ticket })
            }
            ReshapeCompletion::Event(event) => {
                debug_assert!(
                    !matches!(
                        event,
                        ReshapeEvent::Opened { .. } | ReshapeEvent::Adopted { .. }
                    ),
                    "a store-carrying completion passed as a bare event: {event:?}",
                );
                if let ReshapeEvent::SeedDeferred { child, ticket }
                | ReshapeEvent::SeedUnavailable { child, ticket } = event
                {
                    self.landed(child, ticket);
                }
                Some(event)
            }
        }
    }

    /// End the prep `ticket` names on `shard`, if it is the one in flight.
    fn landed(&mut self, shard: ShardId, ticket: Ticket) {
        if self.preparing.get(&shard) == Some(&ticket) {
            self.preparing.remove(&shard);
        }
    }

    /// The store prepared for `shard`.
    #[must_use]
    pub fn storage(&self, shard: ShardId) -> Option<&S> {
        self.stores.get(&shard).map(|store| &store.storage)
    }

    /// Whether a store is prepared for `shard`.
    #[must_use]
    pub fn contains(&self, shard: ShardId) -> bool {
        self.stores.contains_key(&shard)
    }

    /// Drop the store prepared for `shard`, handing it back.
    pub fn remove(&mut self, shard: ShardId) -> Option<S> {
        self.stores.remove(&shard).map(|store| store.storage)
    }

    /// Take `shard`'s store for its seat. `None`, with a warn, when no store
    /// is prepared, or when the shard is already `hosted` here, in which case
    /// the store is dropped.
    ///
    /// # Panics
    ///
    /// Panics if the store was never adopted: a seat follows the duty's
    /// prepared phase, which follows a delivered [`ReshapeEvent::Adopted`].
    pub fn take_for_seat(&mut self, shard: ShardId, hosted: bool) -> Option<Seating<S>> {
        let Some(store) = self.stores.remove(&shard) else {
            warn!(shard = ?shard, "Reshape seat for an unprepared store; dropped");
            return None;
        };
        if hosted {
            warn!(shard = ?shard, "Reshape seat for an already-hosted shard; dropped");
            return None;
        }
        let Stage::Adopted { genesis } = store.stage else {
            panic!("reshape seat for {shard:?} before its adopt");
        };
        Some(Seating {
            storage: store.storage,
            genesis: *genesis,
            recovered: store.recovered,
        })
    }

    /// Drop every store no live duty owns — `owned` is the orchestrator's
    /// `is_seating` — whether its duty relinquished the seat or was dropped,
    /// and return those shards ascending.
    pub fn release(&mut self, owned: impl Fn(ShardId) -> bool) -> Vec<ShardId> {
        let released: Vec<ShardId> = self
            .stores
            .keys()
            .copied()
            .filter(|&shard| !owned(shard))
            .collect();
        for shard in &released {
            self.stores.remove(shard);
        }
        released
    }

    /// Take every prepared store, ascending by shard, and forget every prep
    /// in flight or held: the host and its orchestrator go down together.
    pub fn drain(&mut self) -> impl Iterator<Item = (ShardId, S)> + use<S> {
        self.preparing.clear();
        self.held.clear();
        std::mem::take(&mut self.stores)
            .into_iter()
            .map(|(shard, store)| (shard, store.storage))
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_storage::RecoveredState;
    use hyperscale_storage::test_helpers::make_test_block;
    use hyperscale_types::{BlockHeight, ShardId};

    use super::{PreparedStores, ReshapeCompletion};
    use crate::reshape::orchestrator::{ReshapeEvent, ReshapeRequest, Ticket};

    const OPEN: Ticket = Ticket::new(0);
    const ADOPT: Ticket = Ticket::new(1);

    fn open_request(shard: ShardId, ticket: Ticket) -> ReshapeRequest {
        ReshapeRequest::OpenStore { shard, ticket }
    }

    fn land(
        stores: &mut PreparedStores<u32>,
        shard: ShardId,
        storage: u32,
        ticket: Ticket,
        awaits: impl Fn(ShardId, Ticket) -> bool,
    ) -> Option<ReshapeEvent> {
        stores.settle(
            ReshapeCompletion::Opened {
                shard,
                storage,
                recovered: RecoveredState::default(),
                ticket,
            },
            awaits,
        )
    }

    /// The orchestrator's `awaits` for duties awaiting exactly `awaited`.
    fn awaiting(awaited: &[(ShardId, Ticket)]) -> impl Fn(ShardId, Ticket) -> bool + use<> {
        let awaited = awaited.to_vec();
        move |shard, ticket| awaited.contains(&(shard, ticket))
    }

    fn opened(stores: &mut PreparedStores<u32>, shard: ShardId, storage: u32) {
        let orch = awaiting(&[(shard, OPEN)]);
        assert!(stores.prep(open_request(shard, OPEN)).is_some());
        let event = land(stores, shard, storage, OPEN, &orch);
        assert!(matches!(event, Some(ReshapeEvent::Opened { shard: s, .. }) if s == shard));
    }

    fn adopt(stores: &mut PreparedStores<u32>, shard: ShardId) -> Option<ReshapeEvent> {
        stores.settle(
            ReshapeCompletion::Adopted {
                shard,
                genesis: Box::new(make_test_block(BlockHeight::new(8))),
                recovered: RecoveredState::default(),
                ticket: ADOPT,
            },
            awaiting(&[(shard, ADOPT)]),
        )
    }

    #[test]
    fn an_adopted_store_is_taken_for_its_seat() {
        let shard = ShardId::leaf(1, 0);
        let mut stores = PreparedStores::new();
        opened(&mut stores, shard, 7);
        assert!(
            matches!(adopt(&mut stores, shard), Some(ReshapeEvent::Adopted { shard: s, .. }) if s == shard)
        );
        let seating = stores.take_for_seat(shard, false).expect("adopted");
        assert_eq!(seating.storage, 7);
        assert_eq!(seating.genesis.height(), BlockHeight::new(8));
        assert!(!stores.contains(shard));
    }

    #[test]
    fn a_seat_with_no_store_takes_nothing() {
        let mut stores = PreparedStores::<u32>::new();
        assert!(stores.take_for_seat(ShardId::leaf(1, 0), false).is_none());
    }

    #[test]
    fn a_seat_over_a_hosted_shard_drops_the_store() {
        let shard = ShardId::leaf(1, 0);
        let mut stores = PreparedStores::new();
        opened(&mut stores, shard, 7);
        let _ = adopt(&mut stores, shard);
        assert!(stores.take_for_seat(shard, true).is_none());
        assert!(!stores.contains(shard));
    }

    #[test]
    #[should_panic(expected = "before its adopt")]
    fn a_seat_before_the_adopt_panics() {
        let shard = ShardId::leaf(1, 0);
        let mut stores = PreparedStores::new();
        opened(&mut stores, shard, 7);
        let _ = stores.take_for_seat(shard, false);
    }

    #[test]
    fn an_adopt_for_a_released_store_answers_nothing() {
        let shard = ShardId::leaf(1, 0);
        let mut stores = PreparedStores::new();
        opened(&mut stores, shard, 7);
        assert_eq!(stores.release(|_| false), vec![shard]);
        assert!(adopt(&mut stores, shard).is_none());
        assert!(!stores.contains(shard));
    }

    /// The release reads ownership alone, so a store whose duty was dropped
    /// goes as surely as one whose duty relinquished, and every store a live
    /// duty owns stays.
    #[test]
    fn release_drops_every_unowned_store_and_keeps_the_owned() {
        let relinquished = ShardId::leaf(2, 0);
        let dropped = ShardId::leaf(2, 1);
        let live = ShardId::leaf(2, 2);
        let mut stores = PreparedStores::new();
        opened(&mut stores, live, 3);
        opened(&mut stores, dropped, 2);
        opened(&mut stores, relinquished, 1);
        assert_eq!(
            stores.release(|shard| shard == live),
            vec![relinquished, dropped]
        );
        assert_eq!(stores.storage(live), Some(&3));
        assert!(!stores.contains(relinquished) && !stores.contains(dropped));
        assert!(stores.release(|shard| shard == live).is_empty());
    }

    #[test]
    fn drain_takes_every_store_ascending() {
        let mut stores = PreparedStores::new();
        opened(&mut stores, ShardId::leaf(1, 1), 2);
        opened(&mut stores, ShardId::leaf(1, 0), 1);
        let drained: Vec<_> = stores.drain().collect();
        assert_eq!(
            drained,
            vec![(ShardId::leaf(1, 0), 1), (ShardId::leaf(1, 1), 2)]
        );
        assert!(!stores.contains(ShardId::leaf(1, 0)));
    }

    /// An open landing after a newer open of the same shard answers a
    /// request no duty awaits: it closes its own store and leaves the newer
    /// one, which the orchestrator took, in the map.
    #[test]
    fn a_stale_open_leaves_the_newer_store_in_place() {
        let shard = ShardId::leaf(1, 0);
        let (older, newer) = (Ticket::new(3), Ticket::new(4));
        let orch = awaiting(&[(shard, newer)]);
        let mut stores = PreparedStores::new();
        assert!(land(&mut stores, shard, 2, newer, &orch).is_some());
        assert!(land(&mut stores, shard, 1, older, &orch).is_none());
        assert_eq!(stores.storage(shard), Some(&2));
    }

    /// An adopt no duty awaits leaves the store as the duty holds it, so the
    /// duty's own adopt still lands on an opened store.
    #[test]
    fn a_stale_adopt_leaves_the_store_unadopted() {
        let shard = ShardId::leaf(1, 0);
        let mut stores = PreparedStores::new();
        opened(&mut stores, shard, 7);
        let stale = stores.settle(
            ReshapeCompletion::Adopted {
                shard,
                genesis: Box::new(make_test_block(BlockHeight::new(5))),
                recovered: RecoveredState::default(),
                ticket: Ticket::new(9),
            },
            awaiting(&[(shard, ADOPT)]),
        );
        assert!(stale.is_none());
        assert!(adopt(&mut stores, shard).is_some());
        let seating = stores.take_for_seat(shard, false).expect("adopted");
        assert_eq!(seating.genesis.height(), BlockHeight::new(8));
    }

    /// A second prep of a shard waits for the first to land, so no two
    /// preps hold one directory at once; the first, landing unawaited,
    /// closes its store, and only then is the second released.
    #[test]
    fn a_second_prep_of_a_shard_waits_for_the_first_to_land() {
        let shard = ShardId::leaf(1, 0);
        let (first, second) = (Ticket::new(3), Ticket::new(4));
        let orch = awaiting(&[(shard, second)]);
        let mut stores = PreparedStores::new();
        assert!(stores.prep(open_request(shard, first)).is_some());
        let seed = ReshapeRequest::SeedFromParent {
            parent: ShardId::ROOT,
            child: shard,
            through: BlockHeight::new(8),
            ticket: second,
        };
        assert!(stores.prep(seed).is_none(), "the first prep is in flight");
        assert!(stores.ready_preps(&orch).is_empty());

        assert!(land(&mut stores, shard, 1, first, &orch).is_none());
        assert!(!stores.contains(shard), "the stale store is closed");
        let ready = stores.ready_preps(&orch);
        assert!(
            matches!(ready.as_slice(), [ReshapeRequest::SeedFromParent { ticket, .. }] if *ticket == second)
        );
        let released = ready.into_iter().next().expect("one ready prep");
        assert!(stores.prep(released).is_some());
        assert!(land(&mut stores, shard, 2, second, &orch).is_some());
        assert_eq!(stores.storage(shard), Some(&2));
    }

    /// A failed prep frees the shard's directory, and a held prep no duty
    /// awaits any more is dropped rather than released.
    #[test]
    fn a_failed_prep_frees_the_shard_and_unawaited_held_preps_drop() {
        let shard = ShardId::leaf(1, 0);
        let (first, second) = (Ticket::new(3), Ticket::new(4));
        let mut stores = PreparedStores::<u32>::new();
        assert!(stores.prep(open_request(shard, first)).is_some());
        assert!(stores.prep(open_request(shard, second)).is_none());
        let orch = awaiting(&[]);
        assert!(
            stores
                .settle(
                    ReshapeCompletion::PrepFailed {
                        shard,
                        ticket: first
                    },
                    &orch
                )
                .is_none()
        );
        assert!(stores.ready_preps(&orch).is_empty(), "no duty awaits it");
        assert!(stores.prep(open_request(shard, Ticket::new(5))).is_some());
    }

    /// A deferred seed lands like an open: the shard is free for its retry.
    #[test]
    fn a_deferred_seed_ends_its_prep() {
        let child = ShardId::leaf(1, 0);
        let ticket = Ticket::new(3);
        let mut stores = PreparedStores::<u32>::new();
        let seed = |ticket| ReshapeRequest::SeedFromParent {
            parent: ShardId::ROOT,
            child,
            through: BlockHeight::new(8),
            ticket,
        };
        assert!(stores.prep(seed(ticket)).is_some());
        let orch = awaiting(&[(child, ticket)]);
        let event = stores.settle(
            ReshapeCompletion::Event(ReshapeEvent::SeedDeferred { child, ticket }),
            &orch,
        );
        assert!(matches!(event, Some(ReshapeEvent::SeedDeferred { .. })));
        assert!(stores.prep(seed(Ticket::new(4))).is_some());
    }

    /// An admitted prep closes the store an earlier duty prepared, since
    /// the prep replaces its directory.
    #[test]
    fn an_admitted_prep_closes_the_earlier_store() {
        let shard = ShardId::leaf(1, 0);
        let mut stores = PreparedStores::new();
        opened(&mut stores, shard, 7);
        assert!(stores.prep(open_request(shard, Ticket::new(5))).is_some());
        assert!(!stores.contains(shard));
    }
}
