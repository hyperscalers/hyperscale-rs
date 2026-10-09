//! How far down a shard's committed chain a store keeps its blocks.
//!
//! The floor is the lowest of what this store's readers reach below the
//! tip, and every one of them is a span of weighted time read off the
//! chain:
//!
//! - **The history walk below the oldest retained pin.** A joiner that
//!   snap-syncs at a pin this store keeps walks the chain down from it to
//!   the first block whose parent QC predates [`history_floor`], and keeps
//!   that block. The same walk is what tail sync and history backfill
//!   serve, and the settled window it is min'd with is what settled-window
//!   serving reads. The binding term.
//! - **The restart replay**, which reads back
//!   [`REPLAY_REACH`] from the tip and the block below that for its clock;
//!   the dedup rebuild reads less.
//!
//! The state retention floor is not a term. Provision bodies sit in their
//! own rows, which this floor does not touch, and the floor is a version
//! floor that moves only when a commit writes state — a chain of empty
//! blocks would hold every block it ever committed.
//!
//! The pin term is anchored at a pin's own block, never dated off the
//! tip's clock alone: a halt-recovery commit jumps the clock by the whole
//! halt, and a floor read off it would retire the heights the harvest
//! still reads. A chain with no attested pin keeps everything from the
//! block its genesis follows, and nothing beneath that is this chain's.
//!
//! Beneath the floor a store still keeps what an unresolved transaction
//! is checked against, at any depth: the [`ChainHold`], read off the tick
//! membership family the store itself commits.

use std::collections::BTreeSet;

use hyperscale_types::{
    BlockHeight, ChainOrigin, RETENTION_HORIZON, ShardId, TxHash, WeightedTimestamp,
};

use super::chain_reader::ShardChainReader;
use super::members::MemberIndex;
use super::unresolved::REPLAY_REACH;
use crate::Substates;

/// What a store keeps beneath its chain floor: for every member row
/// standing in its committed state, the transaction's body and the
/// metadata rows of the height that committed it and of the height below.
///
/// A record naming the transaction restates the block that committed it
/// and two anchors: that block's own, and the one its classification and
/// price were frozen at, which is the anchor of the block below. Each is
/// a parent-QC clock read off the header at its own height.
///
/// Read off committed state alone, so every replica at one tip holds the
/// same rows whatever it has run since it opened, and a store that holds
/// no member rows holds nothing. A row naming a height the store never
/// held a block at keeps nothing there.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChainHold {
    bodies: BTreeSet<TxHash>,
    rows: BTreeSet<BlockHeight>,
}

impl ChainHold {
    /// The hold `state` states for `shard`'s chain.
    ///
    /// A hold read before the heights it is applied to were chosen keeps
    /// no less than one read after: a row that has since settled is kept
    /// one pass longer, and a row committed since names a height above
    /// any floor chosen before it.
    #[must_use]
    pub fn load(state: &(impl Substates + ?Sized), shard: ShardId) -> Self {
        Self::of(&MemberIndex::load(state, shard))
    }

    /// The hold of the member rows in `members`.
    #[must_use]
    pub fn of(members: &MemberIndex) -> Self {
        let mut hold = Self::default();
        for row in members.members.values() {
            hold.bodies.insert(row.tx);
            hold.rows.insert(row.height);
            hold.rows.extend(row.height.prev());
        }
        hold
    }

    /// Whether `tx`'s body is kept.
    #[must_use]
    pub fn keeps_body(&self, tx: TxHash) -> bool {
        self.bodies.contains(&tx)
    }

    /// Whether the metadata row at `height` is kept.
    #[must_use]
    pub fn keeps_row(&self, height: BlockHeight) -> bool {
        self.rows.contains(&height)
    }
}

/// The weighted-time floor a joiner's history has to reach for the
/// attested folds to complete, given the window floor its schedule
/// records for the shard.
///
/// Two reaches, and the lower of them wins. [`RETENTION_HORIZON`] below
/// the anchor is what the committed fold asks for and what a reshape
/// admitted *after* this bootstrap can ask of the settled one: such a
/// reshape's floor is the start of its own admitting epoch backed off by
/// the horizon, and the anchor cannot sit above that epoch's start. A
/// reshape already admitted names its floor outright, and it is deeper.
#[must_use]
pub fn history_floor(
    anchor_wt: WeightedTimestamp,
    settled_window_floor: Option<WeightedTimestamp>,
) -> WeightedTimestamp {
    let horizon = WeightedTimestamp::from_millis(
        anchor_wt
            .as_millis()
            .saturating_sub(RETENTION_HORIZON.as_secs() * 1000),
    );
    settled_window_floor.map_or(horizon, |floor| floor.min(horizon))
}

/// What the store cannot see for itself when its floor is computed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FloorInputs {
    /// Where this chain begins.
    pub origin: ChainOrigin,
    /// The oldest boundary this store keeps pinned, the attested one
    /// included; `None` until the beacon attests one.
    pub oldest_pin: Option<BlockHeight>,
    /// The settled window's floor the committed topology states for the
    /// shard, while it has one.
    pub settled_window_floor: Option<WeightedTimestamp>,
}

/// The lowest height `reader` must keep a block at, never below the floor
/// it already keeps nor the block its chain's genesis follows.
///
/// That block is the predecessor's terminal on a successor's store, which
/// begins as its predecessor's: an observer of a split that applied the
/// terminal asks the child's committee for it, certified, to derive the
/// child's genesis from. Every height beneath it is the predecessor's
/// alone.
#[must_use]
pub fn chain_floor<R: ShardChainReader + ?Sized>(reader: &R, inputs: FloorInputs) -> BlockHeight {
    let predecessor_terminal = inputs
        .origin
        .genesis_height
        .prev()
        .unwrap_or(BlockHeight::GENESIS);
    let low = reader.chain_floor().max(predecessor_terminal);
    let tip = reader.committed_height();
    let Some(pin) = inputs.oldest_pin.filter(|pin| *pin >= low && *pin <= tip) else {
        return low;
    };
    let Some(pin_wt) = anchor_at(reader, pin) else {
        return low;
    };
    let Some(tip_wt) = anchor_at(reader, tip) else {
        return low;
    };

    // A store that began at an imported anchor holds nothing beneath its
    // first block, and the floor never names a height it has no block at.
    let below_if_held = |first: BlockHeight| {
        first
            .prev()
            .filter(|below| *below >= low && reader.get_block_metadata(*below).is_some())
            .unwrap_or(first)
    };

    // The walk keeps the block it stops at: the highest one dated below
    // the history floor, which is the pin itself when the pin is.
    let history = history_floor(pin_wt, inputs.settled_window_floor);
    let walked = first_dated_from(reader, low, pin, history).map_or(pin, below_if_held);

    // The replay reads from the first block inside its reach, and the
    // block below that for the clock it carries forward.
    let reach = tip_wt.minus(REPLAY_REACH);
    let replayed = first_dated_from(reader, low, tip, reach).map_or(low, below_if_held);

    walked.min(replayed).max(low)
}

/// The parent-QC timestamp of the block at `height`: what dates it.
fn anchor_at<R: ShardChainReader + ?Sized>(
    reader: &R,
    height: BlockHeight,
) -> Option<WeightedTimestamp> {
    reader
        .get_block_metadata(height)
        .map(|metadata| metadata.header().parent_qc().weighted_timestamp())
}

/// The lowest height in `[low, high]` dated at or after `at`, by binary
/// search: a chain's parent-QC timestamps never fall with height. `None`
/// when even `high` is dated before it. A height whose row is absent is
/// read as dated before anything, which is where an absent row sits.
fn first_dated_from<R: ShardChainReader + ?Sized>(
    reader: &R,
    low: BlockHeight,
    high: BlockHeight,
    at: WeightedTimestamp,
) -> Option<BlockHeight> {
    let dated_from = |height: u64| {
        anchor_at(reader, BlockHeight::new(height)).is_some_and(|anchor| anchor >= at)
    };
    let (mut lo, mut hi) = (low.inner(), high.inner());
    if !dated_from(hi) {
        return None;
    }
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if dated_from(mid) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    Some(BlockHeight::new(lo))
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{Deadline, Hash};

    use super::*;
    use crate::MemberInputs;

    /// A standing row holds its body and the rows at its height and the
    /// one below; a row at the first height holds no row beneath it; and
    /// an index with no rows holds nothing.
    #[test]
    fn a_member_row_holds_its_body_and_two_rows() {
        let shard = ShardId::ROOT;
        let tx = |seed: u8| TxHash::from(Hash::from_bytes(&[seed; 32]));
        let committing = |height: u64, seed: u8| MemberInputs {
            height: BlockHeight::new(height),
            transactions: vec![(tx(seed), Deadline::of(WeightedTimestamp::ZERO))],
            ..MemberInputs::still(shard)
        };
        let mut members = MemberIndex::empty(shard);
        assert_eq!(ChainHold::of(&members), ChainHold::default());

        members.advance(&committing(0, 1));
        members.advance(&committing(7, 2));
        let hold = ChainHold::of(&members);
        assert!(hold.keeps_body(tx(1)) && hold.keeps_body(tx(2)) && !hold.keeps_body(tx(3)));
        let rows: Vec<u64> = (0..=9)
            .filter(|height| hold.keeps_row(BlockHeight::new(*height)))
            .collect();
        assert_eq!(rows, [0, 6, 7]);
    }

    /// The floor is the deeper of the two reaches, and a shard with no
    /// window floor recorded still reaches the retention horizon.
    #[test]
    fn the_floor_takes_the_deeper_of_the_two_reaches() {
        let anchor = WeightedTimestamp::from_millis(1_000_000);
        let horizon = 1_000_000 - RETENTION_HORIZON.as_secs() * 1000;
        assert_eq!(history_floor(anchor, None).as_millis(), horizon);
        assert_eq!(
            history_floor(anchor, Some(WeightedTimestamp::from_millis(10_000))).as_millis(),
            10_000,
        );
        assert_eq!(
            history_floor(anchor, Some(WeightedTimestamp::from_millis(999_999))).as_millis(),
            horizon,
        );
    }

    /// A shard whose chain is younger than the horizon floors at zero
    /// rather than wrapping.
    #[test]
    fn a_young_chain_floors_at_zero() {
        assert_eq!(
            history_floor(WeightedTimestamp::from_millis(500), None).as_millis(),
            0,
        );
    }
}
