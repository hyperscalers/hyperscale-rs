//! The commit-proven remote headers this node holds, as one mirror.
//!
//! A header this node has a commit proof for is a fact two consumers ask
//! about, and they must not be able to disagree. The vote fence holds a
//! block's state proofs to the anchors this validator has proven; the
//! execution coordinator gates a cross-shard execution certificate on
//! its source block being proven, and anchors a question to a core
//! member's sibling at the newest proven header a window licenses that
//! stands at the chain's clock. Two mirrors of one fact would let a
//! bundle pass the fence against an anchor the prober would never have
//! chosen, and the difference between them would be nobody's to notice.
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
use std::ops::Bound;
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::{Anchor, BlockHeight, RETENTION_HORIZON, ShardId, TopologySchedule, WeightedTimestamp};

/// Every commit-proven remote header this node holds, by shard and
/// height.
///
/// An anchor's `ts` is its header's parent-QC clock, which a QC never
/// sets below its parent's, so within a shard `ts` never falls as the
/// height rises: the anchors a horizon retires are always a shard's
/// lowest, and retiring them walks only what it removes.
#[derive(Debug, Default)]
pub struct ProvenAnchors {
    by_shard: RwLock<BTreeMap<ShardId, BTreeMap<BlockHeight, Anchor>>>,
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
        self.by_shard
            .write()
            .expect("proven anchors lock poisoned")
            .entry(anchor.shard)
            .or_default()
            .insert(anchor.height, anchor);
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
        self.by_shard
            .read()
            .expect("proven anchors lock poisoned")
            .get(&shard)
            .and_then(|heights| heights.get(&height))
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
        self.by_shard
            .read()
            .expect("proven anchors lock poisoned")
            .get(&shard)?
            .values()
            .rev()
            .find(|anchor| anchor.ts <= at && licensed(anchor.ts))
            .copied()
    }

    /// How many anchors are held, for the metric that reports it.
    ///
    /// # Panics
    ///
    /// As [`Self::record`].
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_shard
            .read()
            .expect("proven anchors lock poisoned")
            .values()
            .map(BTreeMap::len)
            .sum()
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
        let mut by_shard = self.by_shard.write().expect("proven anchors lock poisoned");
        by_shard.retain(|_, heights| {
            while let Some(entry) = heights.first_entry() {
                if entry.get().ts >= floor {
                    break;
                }
                entry.remove();
            }
            !heights.is_empty()
        });
    }

    /// Forget every anchor in the band of a recovery `schedule` holds for
    /// its shard ([`TopologySchedule::recovery_orphaned`]): a block the
    /// recovered chain does not keep, whose height a block it keeps takes
    /// over. A claim at it is one no block admits, so a composer offering
    /// it would offer what every voter refuses, and a fresh block's own
    /// proof at that height lands in its place.
    ///
    /// The fresh chain's blocks are anchored at or past the bridge, so
    /// their proofs stand while the recovery is pending; a harvested or
    /// coast block's proof is forgotten for good, since the band reads
    /// every binding the history keeps.
    ///
    /// # Panics
    ///
    /// As [`Self::record`].
    pub fn forget_orphaned(&self, schedule: &TopologySchedule) {
        let mut by_shard = self.by_shard.write().expect("proven anchors lock poisoned");
        by_shard.retain(|&shard, heights| {
            if let Some(floor) = schedule.recovery_orphan_floor(shard) {
                heights
                    .extract_if(
                        (Bound::Excluded(floor), Bound::Unbounded),
                        |&height, anchor| schedule.recovery_orphaned(shard, anchor.ts, height),
                    )
                    .for_each(drop);
            }
            !heights.is_empty()
        });
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use proptest::collection::vec;
    use proptest::prelude::*;

    use super::*;
    use crate::{
        Epoch, Hash, NetworkDefinition, RecoveryBinding, RecoveryCause, ShardRecovery, StateRoot,
        TopologySnapshot, ValidatorSet,
    };

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

    /// Anchors of `shard` at heights 8, 9 and 10, anchored in epochs 2,
    /// 3 and 4 of one-second epochs: a block at a recovery's frontier,
    /// one the replaced committee harvested above it, and the fresh
    /// committee's first past the bridge.
    fn across_a_recovery(shard: ShardId) -> ProvenAnchors {
        let anchors = ProvenAnchors::new();
        for height in [8, 9, 10] {
            anchors.record(anchor(shard, height, 0, ms((height - 6) * 1_000)));
        }
        anchors
    }

    /// A schedule over one-second epochs whose head records a halt
    /// recovery of `shard` seated at epoch 3, bridge 4, frozen at height
    /// 8, pending or completed.
    fn recovered(shard: ShardId, pending: bool) -> TopologySchedule {
        let mut head = TopologySnapshot::new(
            NetworkDefinition::simulator(),
            1,
            ValidatorSet::new(Vec::new()),
        )
        .with_recoveries(BTreeMap::from([(
            shard,
            vec![RecoveryBinding {
                rotated_at: Epoch::new(3),
                attested_frontier: BlockHeight::new(8),
                completed: !pending,
            }],
        )]));
        if pending {
            head = head.with_pending_recoveries(BTreeMap::from([(
                shard,
                ShardRecovery {
                    cause: RecoveryCause::Halt,
                    rotated_at: Epoch::new(3),
                    retained: Vec::new(),
                    attested_frontier: BlockHeight::new(8),
                },
            )]));
        }
        TopologySchedule::new(1_000, Epoch::new(4), Arc::new(head))
    }

    /// A fresh block's commit proof stands while its recovery is pending:
    /// it is anchored at the bridge, so only the harvested block's proof
    /// above the frontier is forgotten, and the frontier's own stands.
    #[test]
    fn a_fresh_blocks_commit_proof_outlives_the_pending_record() {
        let shard = ShardId::leaf(1, 0);
        let anchors = across_a_recovery(shard);
        anchors.forget_orphaned(&recovered(shard, true));
        assert!(anchors.at(shard, BlockHeight::new(8)).is_some());
        assert!(anchors.at(shard, BlockHeight::new(9)).is_none());
        assert!(anchors.at(shard, BlockHeight::new(10)).is_some());
        // Another shard's anchors stand.
        let other = ShardId::leaf(1, 1);
        let elsewhere = across_a_recovery(other);
        elsewhere.forget_orphaned(&recovered(shard, true));
        assert_eq!(elsewhere.len(), 3);
    }

    proptest! {
        /// Forgetting touches only heights above a shard's lowest
        /// recovery frontier, and forgets exactly what testing every
        /// anchor of every shard would.
        #[test]
        fn forgetting_matches_testing_every_anchor(
            bindings in vec((1u64..6, 0u64..20, any::<bool>()), 0..4),
            held in vec((0u64..3, 0u64..24, 0u64..8_000), 0..40),
        ) {
            let shards = [ShardId::leaf(2, 0), ShardId::leaf(2, 1), ShardId::leaf(2, 2)];
            let mut rotated = 0;
            let history: Vec<RecoveryBinding> = bindings
                .iter()
                .map(|&(step, frontier, completed)| {
                    rotated += step;
                    RecoveryBinding {
                        rotated_at: Epoch::new(rotated),
                        attested_frontier: BlockHeight::new(frontier),
                        completed,
                    }
                })
                .collect();
            let head = TopologySnapshot::new(
                NetworkDefinition::simulator(),
                1,
                ValidatorSet::new(Vec::new()),
            )
            .with_recoveries(BTreeMap::from([(shards[0], history)]));
            let schedule = TopologySchedule::new(1_000, Epoch::new(rotated + 1), Arc::new(head));

            let anchors = ProvenAnchors::new();
            for &(shard, height, ts) in &held {
                let shard = shards[usize::try_from(shard).expect("fits")];
                anchors.record(anchor(shard, height, 0, ms(ts)));
            }
            let mut expected = anchors.by_shard.read().expect("unpoisoned").clone();
            expected.retain(|&shard, heights| {
                heights.retain(|&height, anchor| {
                    !schedule.recovery_orphaned(shard, anchor.ts, height)
                });
                !heights.is_empty()
            });
            anchors.forget_orphaned(&schedule);
            prop_assert_eq!(&*anchors.by_shard.read().expect("unpoisoned"), &expected);
        }
    }

    /// A harvested block's proof stays forgotten once the record clears:
    /// one proven again afterwards is forgotten at the next retirement,
    /// and the fresh block's stands.
    #[test]
    fn a_harvested_anchor_stays_forgotten_after_the_record_clears() {
        let shard = ShardId::leaf(1, 0);
        let anchors = across_a_recovery(shard);
        anchors.forget_orphaned(&recovered(shard, false));
        assert!(anchors.at(shard, BlockHeight::new(9)).is_none());
        anchors.record(anchor(shard, 9, 0, ms(3_000)));
        anchors.forget_orphaned(&recovered(shard, false));
        assert!(anchors.at(shard, BlockHeight::new(8)).is_some());
        assert!(anchors.at(shard, BlockHeight::new(9)).is_none());
        assert!(anchors.at(shard, BlockHeight::new(10)).is_some());
    }
}
