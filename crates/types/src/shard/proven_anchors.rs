//! The commit-proven remote headers this node holds, as one mirror.
//!
//! A header this node has a commit proof for is a fact two consumers ask
//! about, and they must not be able to disagree. The vote fence holds a
//! block's state proofs to the anchors this validator has proven; the
//! execution coordinator gates a cross-shard execution certificate on
//! its source block being proven, and anchors a reclaim probe at the
//! newest proven header a window licenses that stands at the chain's
//! clock. Two mirrors of one fact would let a bundle pass the fence
//! against an anchor the prober would never have chosen, and the
//! difference between them would be nobody's to notice.
//!
//! # Why a projection rather than the header store
//!
//! `REMOTE_HEADER_RETENTION` is the store's, and both consumers here need
//! [`RETENTION_HORIZON`] — the span a probe or a provision may still be
//! licensed across, which is five times as long. Keeping whole certified
//! headers that long to answer a question about forty bytes is the wrong
//! half of the trade, and the fork-sibling and commit-proof machinery
//! hanging off the store has no reason to live that long either. So this
//! is a deliberate projection that outlives what it projects from, and
//! this paragraph is where the asymmetry is stated rather than
//! rediscovered.
//!
//! # Node-local, and shared
//!
//! Which headers a node has proven is that node's own view — it is why
//! the fence defers rather than refusing — so nothing here is consensus
//! content and there is no determinism to preserve. One instance is
//! shared by handle, on [`TopologySnapshot`](crate::TopologySnapshot)'s
//! terms: one per host, read wherever it is needed.

use std::collections::BTreeMap;
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::{Anchor, BlockHeight, RETENTION_HORIZON, ShardId, WeightedTimestamp};

/// Every commit-proven remote header this node holds, by shard and
/// height.
#[derive(Debug, Default)]
pub struct ProvenAnchors {
    by_height: RwLock<BTreeMap<(ShardId, BlockHeight), Anchor>>,
    /// Advanced by every anchor recorded, so a vote deferred for want
    /// of one is re-driven when the count has moved.
    generation: AtomicU64,
}

impl ProvenAnchors {
    /// An empty mirror.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a header this node has commit-proven.
    ///
    /// # Panics
    ///
    /// If the lock is poisoned, which means a consumer panicked holding
    /// it — the node is already unsound at that point.
    pub fn record(&self, anchor: Anchor) {
        self.by_height
            .write()
            .expect("proven anchors lock poisoned")
            .insert((anchor.shard, anchor.height), anchor);
        self.generation.fetch_add(1, Ordering::AcqRel);
    }

    /// How many anchors have been recorded, ever.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// The anchor at `(shard, height)`, if this node has proven it.
    ///
    /// # Panics
    ///
    /// As [`Self::record`].
    #[must_use]
    pub fn at(&self, shard: ShardId, height: BlockHeight) -> Option<Anchor> {
        self.by_height
            .read()
            .expect("proven anchors lock poisoned")
            .get(&(shard, height))
            .copied()
    }

    /// The highest anchor of `shard` this node has proven that `licensed`
    /// accepts, of those standing at `at`.
    ///
    /// The ceiling is what makes the choice agreed. Which headers a node
    /// holds is its own view, and a counterpart's land a block apart, so
    /// "the highest held" names a different header on each member of a
    /// committee at any instant. Pass the chain's committed clock and it
    /// names one header for all of them: every member is holding it,
    /// since it is a header old enough for the local chain to have
    /// committed past it, and none has a newer one to prefer.
    ///
    /// Highest under the ceiling rather than lowest in the window, so
    /// the anchor stays near the counterpart's tip: a proof comes from a
    /// bounded history behind it, and a window outruns that history by
    /// an order of magnitude.
    ///
    /// # Panics
    ///
    /// As [`Self::record`].
    #[must_use]
    pub fn newest_licensed(
        &self,
        shard: ShardId,
        at: WeightedTimestamp,
        licensed: impl Fn(WeightedTimestamp) -> bool,
    ) -> Option<Anchor> {
        self.by_height
            .read()
            .expect("proven anchors lock poisoned")
            .values()
            .filter(|anchor| anchor.shard == shard && anchor.ts <= at && licensed(anchor.ts))
            .max_by_key(|anchor| anchor.height)
            .copied()
    }

    /// How many anchors are held, for the metric that reports it.
    ///
    /// # Panics
    ///
    /// As [`Self::record`].
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_height
            .read()
            .expect("proven anchors lock poisoned")
            .len()
    }

    /// Whether nothing is held.
    ///
    /// # Panics
    ///
    /// As [`Self::record`].
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Retire every anchor a probe can no longer be taken against.
    ///
    /// One rule for both consumers, on the clock the committed block
    /// carries: past [`RETENTION_HORIZON`] no window licenses an answer
    /// at the anchor and no execution certificate against the block is
    /// consumable anywhere.
    ///
    /// # Panics
    ///
    /// As [`Self::record`].
    pub fn retire_below(&self, now: WeightedTimestamp) {
        let floor = now.minus(RETENTION_HORIZON);
        self.by_height
            .write()
            .expect("proven anchors lock poisoned")
            .retain(|_, anchor| anchor.ts >= floor);
    }

    /// Forget every anchor `fenced` names: a height a shard's recovery
    /// has fenced is one no block admits a claim at, so a composer
    /// offering a claim there would offer what every voter refuses.
    ///
    /// # Panics
    ///
    /// As [`Self::record`].
    pub fn forget_fenced(&self, fenced: impl Fn(ShardId, BlockHeight) -> bool) {
        self.by_height
            .write()
            .expect("proven anchors lock poisoned")
            .retain(|_, anchor| !fenced(anchor.shard, anchor.height));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Hash, StateRoot};

    fn root(seed: u8) -> StateRoot {
        StateRoot::from_raw(Hash::from_bytes(&[seed; 32]))
    }

    fn ms(at: u64) -> WeightedTimestamp {
        WeightedTimestamp::from_millis(at)
    }

    fn anchor(shard: ShardId, height: u64, seed: u8, ts: WeightedTimestamp) -> Anchor {
        Anchor {
            shard,
            height: BlockHeight::new(height),
            state_root: root(seed),
            ts,
        }
    }

    /// One mirror answers both questions of it: whether a height is
    /// proven, and which of a shard's proven heights a window reaches.
    #[test]
    fn one_mirror_answers_the_fence_and_the_prober() {
        let anchors = ProvenAnchors::new();
        let shard = ShardId::leaf(1, 1);
        anchors.record(anchor(shard, 4, 4, ms(4_000)));
        anchors.record(anchor(shard, 9, 9, ms(9_000)));
        anchors.record(anchor(ShardId::leaf(1, 0), 9, 1, ms(9_000)));

        assert_eq!(
            anchors.at(shard, BlockHeight::new(4)).unwrap().state_root,
            root(4)
        );
        assert_eq!(anchors.at(shard, BlockHeight::new(5)), None);
        assert_eq!(
            anchors
                .newest_licensed(shard, ms(99_000), |_| true)
                .unwrap()
                .height,
            BlockHeight::new(9),
            "the highest of that shard's, and never another shard's",
        );
        assert_eq!(
            anchors
                .newest_licensed(shard, ms(99_000), |ts| ts <= ms(5_000))
                .unwrap()
                .height,
            BlockHeight::new(4),
            "and the highest the window reaches, not the highest held",
        );
    }

    /// The ceiling is what two nodes holding different headers agree on:
    /// each names the highest standing at the clock, and the one that
    /// holds a newer header does not prefer it.
    #[test]
    fn the_clock_names_one_anchor_for_a_node_holding_more() {
        let shard = ShardId::leaf(1, 1);
        let behind = ProvenAnchors::new();
        behind.record(anchor(shard, 4, 4, ms(4_000)));
        let ahead = ProvenAnchors::new();
        ahead.record(anchor(shard, 4, 4, ms(4_000)));
        ahead.record(anchor(shard, 9, 9, ms(9_000)));

        let at = ms(5_000);
        assert_eq!(
            ahead.newest_licensed(shard, at, |_| true),
            behind.newest_licensed(shard, at, |_| true),
            "the header past the clock is not the one either asks of",
        );
        assert_eq!(
            ahead.newest_licensed(shard, at, |_| true).unwrap().height,
            BlockHeight::new(4),
        );
        assert_eq!(
            ahead
                .newest_licensed(shard, ms(9_000), |_| true)
                .unwrap()
                .height,
            BlockHeight::new(9),
            "and the clock reaching it is what lets it be asked of",
        );
    }

    /// One retirement rule, so the fence and the prober lose an anchor at
    /// the same moment.
    #[test]
    fn an_anchor_retires_for_both_consumers_at_once() {
        let anchors = ProvenAnchors::new();
        let shard = ShardId::leaf(1, 1);
        let old = ms(1_000);
        let horizon = u64::try_from(RETENTION_HORIZON.as_millis()).expect("fits");
        // Exactly a horizon back is still reachable; a millisecond past
        // it is not, which is the edge the retirement is stated at.
        anchors.record(anchor(shard, 1, 1, old));
        anchors.record(anchor(shard, 2, 2, ms(1_001)));

        anchors.retire_below(ms(1_000 + horizon));
        assert!(anchors.at(shard, BlockHeight::new(1)).is_some());

        anchors.retire_below(ms(1_001 + horizon));
        assert_eq!(anchors.at(shard, BlockHeight::new(1)), None);
        assert!(anchors.at(shard, BlockHeight::new(2)).is_some());
        assert_eq!(anchors.len(), 1);
    }

    #[test]
    fn a_fenced_anchor_is_forgotten_and_the_rest_stand() {
        let anchors = ProvenAnchors::new();
        let shard = ShardId::leaf(1, 0);
        for height in [8, 9, 10] {
            anchors.record(Anchor {
                shard,
                height: BlockHeight::new(height),
                state_root: StateRoot::ZERO,
                ts: WeightedTimestamp::from_millis(height * 1_000),
            });
        }
        anchors.forget_fenced(|s, height| s == shard && height >= BlockHeight::new(9));
        assert!(anchors.at(shard, BlockHeight::new(8)).is_some());
        assert!(anchors.at(shard, BlockHeight::new(9)).is_none());
        assert!(anchors.at(shard, BlockHeight::new(10)).is_none());
    }
}
