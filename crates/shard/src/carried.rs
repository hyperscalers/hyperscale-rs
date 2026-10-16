//! What the committed blocks carry in their claims.
//!
//! Kept for every block execution's commit fold, which can trail the
//! shard's committed tip, has not reached, and for the few below it a
//! committed block's claims are counted against.

use std::collections::BTreeMap;

use hyperscale_types::{BlockHeight, CarriedClaims, Recarried};

/// How many committed blocks at or below execution's folded height are
/// kept: the blocks a committed block's claims are counted as repeating.
pub const RECARRIED_WINDOW: u64 = 4;

/// What each committed block carries in its claims, by height: every
/// block above execution's folded height, and the last
/// [`RECARRIED_WINDOW`] at or below it.
#[derive(Debug, Default)]
pub struct CommittedCarried {
    by_height: BTreeMap<BlockHeight, CarriedClaims>,
}

impl CommittedCarried {
    /// Keep what the block committed at `height` carries, and count how
    /// much of it one of the [`RECARRIED_WINDOW`] committed blocks below
    /// it carried too.
    ///
    /// The committed chain is linear, so `height` is one above the last
    /// entry kept.
    pub fn record(&mut self, height: BlockHeight, carried: CarriedClaims) -> Recarried {
        debug_assert!(
            self.by_height
                .last_key_value()
                .is_none_or(|(last, _)| last.next() == height),
            "committed heights rise by one: {height:?} after {:?}",
            self.by_height.last_key_value().map(|(last, _)| last),
        );
        let from = BlockHeight::new(height.inner().saturating_sub(RECARRIED_WINDOW));
        let mut earlier = CarriedClaims::default();
        for before in self.by_height.range(from..).map(|(_, carried)| carried) {
            earlier.extend(before);
        }
        let recarried = carried.recarried(&earlier);
        self.by_height.insert(height, carried);
        recarried
    }

    /// Drop the entries execution has folded, but the last
    /// [`RECARRIED_WINDOW`] of them.
    pub fn retire_through(&mut self, folded: BlockHeight) {
        let keep_from = folded
            .inner()
            .saturating_sub(RECARRIED_WINDOW)
            .saturating_add(1);
        self.by_height = self.by_height.split_off(&BlockHeight::new(keep_from));
    }

    #[cfg(test)]
    pub fn heights(&self) -> Vec<BlockHeight> {
        self.by_height.keys().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::test_utils::test_key;
    use hyperscale_types::{
        Anchor, Hash, Inclusion, MerkleInclusionProof, ShardId, StateClaim, StateRoot,
        WeightedTimestamp,
    };

    use super::*;

    const OWN: ShardId = ShardId::leaf(1, 0);

    /// What a block carries that reads `keys` at one anchor of another
    /// shard's.
    fn reading(keys: &[u8]) -> CarriedClaims {
        let anchor = Anchor {
            shard: ShardId::leaf(1, 1),
            height: BlockHeight::new(3),
            state_root: StateRoot::from_raw(Hash::from_bytes(b"root")),
            ts: WeightedTimestamp::from_millis(3_000),
        };
        let claim = StateClaim::new(
            anchor,
            keys.iter()
                .map(|seed| (test_key(*seed), Inclusion::Present([1; 32]))),
            MerkleInclusionProof::dummy(),
        );
        CarriedClaims::of(OWN, &[claim])
    }

    /// A committed block's cells are counted against the four committed
    /// blocks below it and no further, each repeat once.
    #[test]
    fn a_repeat_is_counted_against_the_four_blocks_below() {
        let mut committed = CommittedCarried::default();
        assert_eq!(
            committed.record(BlockHeight::new(1), reading(&[1])).cells,
            0
        );
        for height in 2..=4 {
            assert_eq!(
                committed
                    .record(BlockHeight::new(height), reading(&[9]))
                    .cells,
                usize::from(height > 2),
            );
        }
        assert_eq!(
            committed
                .record(BlockHeight::new(5), reading(&[1, 9]))
                .cells,
            2,
            "block 1 is four below block 5",
        );
        for height in 6..=9 {
            committed.record(BlockHeight::new(height), reading(&[]));
        }
        assert_eq!(
            committed.record(BlockHeight::new(10), reading(&[1])).cells,
            0,
            "block 5 is five below block 10",
        );
    }

    /// Every entry above the folded height is kept however far execution
    /// lags, and the last four at or below it.
    #[test]
    fn what_execution_has_not_folded_is_kept() {
        let mut committed = CommittedCarried::default();
        for height in 1..=12 {
            committed.record(BlockHeight::new(height), reading(&[]));
        }
        committed.retire_through(BlockHeight::new(2));
        assert_eq!(
            committed.heights().len(),
            12,
            "nothing at or below 2 is past the window"
        );
        committed.retire_through(BlockHeight::new(9));
        assert_eq!(
            committed.heights(),
            (6..=12).map(BlockHeight::new).collect::<Vec<_>>(),
        );
    }
}
