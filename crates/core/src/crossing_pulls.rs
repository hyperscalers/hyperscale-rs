//! Asking a producer for a crossing's record, and how often to ask again.
//!
//! A shard that needs a record it has no bundle for asks the shard
//! holding it, at an anchor of that shard's it has already commit-proven
//! — the pull [`FetchIds::CrossingPulls`] carries. Two places compose
//! one: a body parked before admission for want of its bundle, and a
//! delivery admitted and still waiting. What they share is everything
//! except which bodies they read, so the pacing lives here and each
//! names its own set.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_types::{
    Anchor, BlockHeight, MAX_FINALIZATION_DELAY, ProvenAnchors, ShardId, SubstateKey,
    WeightedTimestamp,
};

use crate::{Action, FetchIds, FetchRequest};

/// The record pulls this node has put, and what decides whether to put
/// one again.
///
/// Node-local, like the asking itself: what a validator asks for is its
/// own business, and what the answer licenses is a bundle riding into a
/// block where every replica absorbs the same bytes.
#[derive(Debug, Default)]
pub struct CrossingPulls {
    /// The anchor height each record was last asked at, and when.
    ///
    /// The only thing that remembers the question was put: a pull's
    /// fetch id is released the moment its answer arrives, so nothing
    /// downstream holds it between askings.
    asked: BTreeMap<SubstateKey, (BlockHeight, WeightedTimestamp)>,
}

impl CrossingPulls {
    /// Nothing asked yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Ask each producer for the records `wanted` names, at the newest
    /// anchor of that producer this node has proven.
    ///
    /// **Both halves of the pacing, because either alone over-asks.** A
    /// producer whose proven anchor has not advanced past the one last
    /// asked is asked once — the answer would be the same reading of the
    /// same state. And one that has advanced is still not asked again
    /// inside [`MAX_FINALIZATION_DELAY`], because a chain that is running
    /// lands anchors here far faster than a round trip resolves, and
    /// paced on the anchor alone the same question goes out many times
    /// over before its first answer.
    ///
    /// A record `wanted` stops naming is forgotten: it has been carried,
    /// or nothing here waits on it any more, and either way its stamp
    /// has no reader left.
    pub fn ask(
        &mut self,
        anchors: &ProvenAnchors,
        now: WeightedTimestamp,
        wanted: impl IntoIterator<Item = (ShardId, SubstateKey)>,
    ) -> Vec<Action> {
        let mut live: BTreeSet<SubstateKey> = BTreeSet::new();
        let mut asks: BTreeMap<(ShardId, Anchor), Vec<SubstateKey>> = BTreeMap::new();
        for (producer, key) in wanted {
            live.insert(key);
            let Some(anchor) = anchors.newest_licensed(producer, now, |_| true) else {
                continue;
            };
            if self.asked.get(&key).is_some_and(|&(at, when)| {
                at >= anchor.height || now.elapsed_since(when) < MAX_FINALIZATION_DELAY
            }) {
                continue;
            }
            self.asked.insert(key, (anchor.height, now));
            asks.entry((producer, anchor)).or_default().push(key);
        }
        self.asked.retain(|key, _| live.contains(key));
        asks.into_iter()
            .map(|((shard, anchor), keys)| {
                Action::Fetch(FetchRequest::Ask {
                    ids: FetchIds::CrossingPulls(
                        keys.into_iter().map(|key| (anchor, key)).collect(),
                    ),
                    shard,
                    preferred: None,
                    class: None,
                })
            })
            .collect()
    }
}
