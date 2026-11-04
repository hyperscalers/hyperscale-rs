//! The committed queue index beside the member rows: where each member
//! stands on the keys it pins, and which members are head.
//!
//! Five collections of the member family, each derived from committed
//! row state and the tick rows alone:
//!
//! - `Queue`: one entry per pin and class of each placed row a
//!   counterpart shares the verdict on, from its place until the row is
//!   accepted, deleted, released or aborted; and of each leg in flight
//!   on awaited terms, from the line running it until it leaves its tick.
//! - `Waiters`: the same per pin of each determined row standing
//!   `Pending` with a place, until a line names it or it leaves.
//! - `TickPins`: the pins a tick's determined lines take, unioned per
//!   key, while its determined half is owed.
//! - `Behind`: each placed shared row not yet head.
//! - `Serves`: each keyed shared row made head, while it stands placed.
//!
//! Entries are a function of a row's own fields, so every collection but
//! `TickPins` is written wherever a row's entries change, as a seat is.

use std::collections::BTreeMap;

use hyperscale_hbor::{Capped, Hbor};
use hyperscale_types::{
    BlockHeight, MAX_HOLDS_PER_MEMBER, MAX_TICK_LINES_PER_BLOCK, MAX_TXS_PER_BLOCK,
    MAX_UNSETTLED_PER_BLOCK, Pin, PinClass, PinKey, Pins, Settlement, ShardId, TxHash,
    WeightedTimestamp, member_order, pins_of,
};

use crate::shard::members::{MemberRow, RowState};

/// Where a member stands in its shard's queue: the block that placed it
/// and its rank there. Shared members a block places take ranks first,
/// in hash order; the block's determined waiters follow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
pub struct Place {
    /// The block that placed it.
    pub height: BlockHeight,
    /// Its rank among the places that block takes.
    pub rank: u16,
}

/// The most height bits a queue order key carries.
const PLACE_HEIGHT_BITS: u32 = 46;

impl Place {
    /// The place in 62 bits, height over rank, in place order.
    ///
    /// # Panics
    ///
    /// Past 2^46 blocks, which no chain reaches.
    #[must_use]
    pub fn packed(self) -> u64 {
        let height = self.height.inner();
        assert!(
            height < 1 << PLACE_HEIGHT_BITS,
            "a place's height fits 46 bits"
        );
        (height << 16) | u64::from(self.rank)
    }
}

/// The block whose fold first found every place of a shared row clear.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Hbor)]
pub struct Head {
    /// That block's height.
    pub height: BlockHeight,
    /// The row's `Serves` key under that height: its packed place, so
    /// the rows a block makes head are ranked in place order whichever
    /// fold of the block made each one head.
    pub rank: u64,
    /// That block's parent-QC clock.
    pub clock: WeightedTimestamp,
}

/// The most pins one `TickPins` entry holds: the pins of 4,096 three-key
/// transfers, within a cell's value cap.
pub const MAX_PINS_PER_ENTRY: usize = 12_288;

/// One `TickPins` entry: a run of a tick's pins, ascending by key.
pub type PinsChunk = Capped<Vec<Pin>, MAX_PINS_PER_ENTRY>;

/// One `Queue` or `Waiters` entry: the member's pins under one order
/// key, which the pins of two keys sharing a bucket can share.
pub type QueueValue = Capped<Vec<(PinKey, TxHash)>, MAX_HOLDS_PER_MEMBER>;

/// The order key of `key`'s entry in `class` at `place`:
/// `bucket:64 ‖ class:2 ‖ height:46 ‖ rank:16`.
#[must_use]
pub fn queue_order(key: PinKey, class: PinClass, place: Place) -> u128 {
    class_base(key, class) | u128::from(place.packed())
}

/// The order keys of every place `key` holds in `class`.
#[must_use]
pub fn class_span(key: PinKey, class: PinClass) -> (u128, u128) {
    let base = class_base(key, class);
    (base, base | ((1u128 << 62) - 1))
}

fn class_base(key: PinKey, class: PinClass) -> u128 {
    (u128::from(key.bucket()) << 64) | ((class as u128) << 62)
}

/// The order key of a row's `Serves` entry: `height:64 ‖ rank:64`.
#[must_use]
pub fn serves_order(head: Head) -> u128 {
    (u128::from(head.height.inner()) << 64) | u128::from(head.rank)
}

/// The order key of the `chunk`th `TickPins` entry of the tick at
/// `height`.
#[must_use]
pub fn tick_pins_order(height: BlockHeight, chunk: u64) -> u128 {
    (u128::from(height.inner()) << 64) | u128::from(chunk)
}

/// The order keys every `TickPins` entry of the tick at `height` lies in.
#[must_use]
pub fn tick_pins_span(height: BlockHeight) -> (u128, u128) {
    (
        tick_pins_order(height, 0),
        tick_pins_order(height, u64::MAX),
    )
}

/// The tick a `TickPins` order key belongs to.
#[must_use]
pub fn tick_of_pins(order: u128) -> BlockHeight {
    BlockHeight::new(u64::try_from(order >> 64).expect("the high half is a height"))
}

/// `pins` cut into entries, in order.
///
/// # Panics
///
/// Never: each run is within the entry cap.
#[must_use]
pub fn pin_chunks(pins: &[Pin]) -> Vec<PinsChunk> {
    pins.chunks(MAX_PINS_PER_ENTRY)
        .map(|run| Capped::new(run.to_vec()).expect("a run within the entry cap"))
        .collect()
}

/// What a row declares on `local`, as its pins: what it waits on while
/// `Pending`, and what it holds after.
#[must_use]
pub fn row_pins(row: &MemberRow, local: ShardId) -> Pins {
    match (&row.state, &row.waiting) {
        (RowState::Pending, Some(waiting)) => pins_of(&waiting.declared, local),
        _ => pins_of(&row.holds, local),
    }
}

/// Whether `row` stands in the queue as a placed member a counterpart
/// shares the verdict on: placed, and waiting, running or stated on
/// those terms.
#[must_use]
pub fn shared_standing(row: &MemberRow) -> bool {
    row.queued.is_some()
        && match row.state {
            RowState::Pending => row
                .waiting
                .as_ref()
                .is_some_and(|waiting| waiting.settlement == Settlement::Shared),
            RowState::InFlight { settlement, .. } => settlement == Settlement::Shared,
            RowState::Stated { .. } => true,
            RowState::Released { .. } | RowState::Accepted => false,
        }
}

/// The first rank a block gives the legs its lines run on awaited terms:
/// past every shared place and determined waiter the block takes, so a
/// leg stands behind them on its block's height.
pub const AWAITED_RANK: u16 = 1 << 15;

const _: () = assert!(
    MAX_UNSETTLED_PER_BLOCK + MAX_TXS_PER_BLOCK <= AWAITED_RANK as usize
        && MAX_TICK_LINES_PER_BLOCK <= (u16::MAX - AWAITED_RANK) as usize
);

/// Whether `row` stands in the queue as a leg in flight on awaited
/// terms: placed by the line running it, and holding what it declared
/// until it leaves its tick.
#[must_use]
pub const fn awaited_holding(row: &MemberRow) -> bool {
    row.queued.is_some()
        && matches!(
            row.state,
            RowState::InFlight {
                settlement: Settlement::Awaited,
                ..
            }
        )
}

/// Whether `row` stands as a determined waiter: placed and `Pending` on
/// terms its own certificate settles.
#[must_use]
pub fn determined_waiting(row: &MemberRow) -> bool {
    row.queued.is_some()
        && row.state == RowState::Pending
        && row
            .waiting
            .as_ref()
            .is_some_and(|waiting| waiting.settlement == Settlement::Alone)
}

/// Whether a row pinning `pins` is keyed: it reads or writes a key this
/// shard serves.
#[must_use]
pub fn keyed(pins: &[Pin]) -> bool {
    pins.iter().any(|pin| !pin.modes.served().is_empty())
}

/// The entries one row implies in the row-derived collections.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RowEntries {
    /// Its `Queue` entries.
    pub queue: BTreeMap<u128, QueueValue>,
    /// Its `Waiters` entries.
    pub waiters: BTreeMap<u128, QueueValue>,
    /// Its `Behind` entry.
    pub behind: Option<(u128, TxHash)>,
    /// Its `Serves` entry.
    pub serves: Option<(u128, TxHash)>,
}

impl RowEntries {
    /// What `row` implies on `local`; nothing where no row stands or the
    /// row has no place.
    ///
    /// # Panics
    ///
    /// Never: a member's entries under one key are at most its pins.
    #[must_use]
    pub fn of(row: Option<&MemberRow>, local: ShardId) -> Self {
        let Some(row) = row.filter(|row| row.queued.is_some()) else {
            return Self::default();
        };
        let (shared, holding, waiting) = (
            shared_standing(row),
            awaited_holding(row),
            determined_waiting(row),
        );
        if !shared && !holding && !waiting {
            return Self::default();
        }
        let place = row.queued.expect("filtered on a place");
        let pins = row_pins(row, local);
        let mut keyed_entries: BTreeMap<u128, Vec<(PinKey, TxHash)>> = BTreeMap::new();
        for pin in pins.iter() {
            for class in PinClass::ALL {
                if pin.modes.stands_in(class) {
                    keyed_entries
                        .entry(queue_order(pin.key, class, place))
                        .or_default()
                        .push((pin.key, row.tx));
                }
            }
        }
        let entries: BTreeMap<u128, QueueValue> = keyed_entries
            .into_iter()
            .map(|(order, value)| {
                (
                    order,
                    Capped::new(value).expect("one entry per pin at most"),
                )
            })
            .collect();
        if waiting {
            return Self {
                waiters: entries,
                ..Self::default()
            };
        }
        if holding {
            return Self {
                queue: entries,
                ..Self::default()
            };
        }
        Self {
            queue: entries,
            behind: row.head.is_none().then(|| (member_order(row.tx), row.tx)),
            serves: row
                .head
                .filter(|_| keyed(&pins))
                .map(|head| (serves_order(head), row.tx)),
            waiters: BTreeMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::to_vec;
    use hyperscale_types::{EntryKey, MAX_CELL_VALUE_LEN, MemberCollection, Modes};

    use super::*;
    use crate::shard::writes::entry_leaf_value;

    /// A `TickPins` entry at its cap, every pin at its widest, is one
    /// leaf snap sync can ship.
    #[test]
    fn a_full_pins_entry_encodes_within_a_cells_value() {
        let pins: Vec<Pin> = (0..MAX_PINS_PER_ENTRY)
            .map(|at| {
                let mut key = [0xFF; 16];
                key[..8].copy_from_slice(&(at as u64).to_be_bytes());
                Pin {
                    key: PinKey(key),
                    modes: Modes(0xFF),
                }
            })
            .collect();
        let chunks = pin_chunks(&pins);
        assert_eq!(chunks.len(), 1);
        let (owner, collection) = MemberCollection::TickPins.of(ShardId::ROOT);
        let key = EntryKey {
            owner,
            collection,
            order: tick_pins_order(BlockHeight::new(u64::MAX), u64::MAX),
        };
        let leaf = entry_leaf_value(&key, &to_vec(&chunks[0]).expect("a chunk encodes"));
        assert!(
            leaf.len() <= MAX_CELL_VALUE_LEN,
            "a full entry's leaf is {} bytes, over {MAX_CELL_VALUE_LEN}",
            leaf.len()
        );
        assert_eq!(pin_chunks(&[pins.clone(), pins].concat()).len(), 2);
    }

    #[test]
    fn queue_keys_order_by_bucket_then_class_then_place() {
        let key = PinKey([7; 16]);
        let at = |height: u64, rank: u16| Place {
            height: BlockHeight::new(height),
            rank,
        };
        let early = queue_order(key, PinClass::Read, at(5, 9));
        let late = queue_order(key, PinClass::Read, at(6, 0));
        assert!(early < late);
        let (lo, hi) = class_span(key, PinClass::Read);
        assert!((lo..=hi).contains(&early) && (lo..=hi).contains(&late));
        let (next, _) = class_span(key, PinClass::Movement);
        assert!(hi < next);
    }
}
