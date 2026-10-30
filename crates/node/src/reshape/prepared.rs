//! The stores reshape duties prepare, held by the adapter between the
//! orchestrator's store-prep and seat requests.
//!
//! Both adapters keep one [`PreparedStores`] per host and settle every io
//! completion through it, so the lifecycle of a prepared store — opened,
//! adopted, then seated, released, removed by a seed, or drained by a crash —
//! is written once. The simulation settles inline; production settles on its
//! loop when the off-loop work reports back.

use std::collections::BTreeMap;

use hyperscale_storage::RecoveredState;
use hyperscale_types::{Block, ShardId};
use tracing::warn;

use crate::reshape::orchestrator::{ReshapeEvent, Ticket};

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
/// will seat.
pub struct PreparedStores<S>(BTreeMap<ShardId, PreparedStore<S>>);

/// A reshape io completion as an adapter reports it: the two that carry
/// store state the map holds, and every other event as is.
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

impl<S> Default for PreparedStores<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> PreparedStores<S> {
    /// No store prepared.
    #[must_use]
    pub const fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Settle one completion and answer the event the orchestrator consumes.
    ///
    /// An open inserts its store and answers [`ReshapeEvent::Opened`]. An
    /// adopt moves a held store from opened to adopted and answers
    /// [`ReshapeEvent::Adopted`]; with the store gone it answers nothing,
    /// since every path that drops a store mid-flight acts on a duty that no
    /// longer owns the shard. Any other event passes through.
    pub fn settle(&mut self, completion: ReshapeCompletion<S>) -> Option<ReshapeEvent> {
        match completion {
            ReshapeCompletion::Opened {
                shard,
                storage,
                recovered,
                ticket,
            } => {
                self.0.insert(
                    shard,
                    PreparedStore {
                        storage,
                        recovered,
                        stage: Stage::Opened,
                    },
                );
                Some(ReshapeEvent::Opened { shard, ticket })
            }
            ReshapeCompletion::Adopted {
                shard,
                genesis,
                recovered,
                ticket,
            } => {
                let store = self.0.get_mut(&shard)?;
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
                Some(event)
            }
        }
    }

    /// The store prepared for `shard`.
    #[must_use]
    pub fn storage(&self, shard: ShardId) -> Option<&S> {
        self.0.get(&shard).map(|store| &store.storage)
    }

    /// Whether a store is prepared for `shard`.
    #[must_use]
    pub fn contains(&self, shard: ShardId) -> bool {
        self.0.contains_key(&shard)
    }

    /// Drop the store prepared for `shard`, handing it back.
    pub fn remove(&mut self, shard: ShardId) -> Option<S> {
        self.0.remove(&shard).map(|store| store.storage)
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
        let Some(store) = self.0.remove(&shard) else {
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
            .0
            .keys()
            .copied()
            .filter(|&shard| !owned(shard))
            .collect();
        for shard in &released {
            self.0.remove(shard);
        }
        released
    }

    /// Take every prepared store, ascending by shard.
    pub fn drain(&mut self) -> impl Iterator<Item = (ShardId, S)> + use<S> {
        std::mem::take(&mut self.0)
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
    use crate::reshape::orchestrator::{ReshapeEvent, Ticket};

    fn opened(stores: &mut PreparedStores<u32>, shard: ShardId, storage: u32) {
        let event = stores.settle(ReshapeCompletion::Opened {
            shard,
            storage,
            recovered: RecoveredState::default(),
            ticket: Ticket::new(0),
        });
        assert!(matches!(event, Some(ReshapeEvent::Opened { shard: s, .. }) if s == shard));
    }

    fn adopt(stores: &mut PreparedStores<u32>, shard: ShardId) -> Option<ReshapeEvent> {
        stores.settle(ReshapeCompletion::Adopted {
            shard,
            genesis: Box::new(make_test_block(BlockHeight::new(8))),
            recovered: RecoveredState::default(),
            ticket: Ticket::new(1),
        })
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
}
