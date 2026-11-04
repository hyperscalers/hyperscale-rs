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

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_hbor::{Capped, Hbor, from_slice};
use hyperscale_types::{
    Address, BlockHeight, CollectionId, MAX_HOLDS_PER_MEMBER, MAX_TICK_LINES_PER_BLOCK,
    MAX_TXS_PER_BLOCK, MAX_UNSETTLED_PER_BLOCK, MemberCollection, MemberFamily, Pin, PinClass,
    PinKey, Pins, Settlement, ShardId, TxHash, WeightedTimestamp, member_order, pins_of,
};

use crate::Substates;
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

/// The most entries of one pin collection a fold reads whole, in one
/// range read, rather than seeking each key it asks about.
const WHOLE_READ: usize = 4_096;

/// The entries one seek reads at a time, walking past entries of keys
/// sharing a bucket and entries the fold overwrote.
const PAGE: usize = 8;

/// One of the queue's pin collections, `Queue` or `Waiters`, as a fold
/// leaves it so far: the stored entries under the fold's own writes.
///
/// A fold asks of a key and class either for its earliest entry or for
/// every entry below a place. The earliest stored entry is found once
/// per key and class and kept; the fold only ever overwrites more, so a
/// kept answer moves forward and never back, and the stored entries of
/// one key are walked at most once per fold. A collection holding at
/// most [`WHOLE_READ`] entries is read whole the first time it is asked
/// about, so a quiet queue costs one read however many keys a block
/// touches.
pub struct PinIndex {
    owner: Address,
    collection: CollectionId,
    /// Entries the fold wrote.
    live: BTreeMap<u128, QueueValue>,
    /// Entries the fold deleted.
    gone: BTreeSet<u128>,
    /// The stored collection, where it was read whole.
    whole: Whole,
    /// Per key and class, the earliest stored entry naming the key that
    /// the fold had not overwritten when last asked; `None` where none
    /// stands.
    first: BTreeMap<(PinKey, PinClass), Option<u128>>,
}

/// What a fold holds of a stored pin collection read whole.
enum Whole {
    /// Not read yet.
    Unread,
    /// Every entry, encoded.
    Read(BTreeMap<u128, Vec<u8>>),
    /// More than [`WHOLE_READ`] entries, so each read seeks.
    TooMany,
}

/// Whether `value` holds an entry of `key`'s.
fn names(value: &QueueValue, key: PinKey) -> bool {
    value.iter().any(|(at, _)| *at == key)
}

impl PinIndex {
    /// The family's `kind` collection, as the state holds it.
    #[must_use]
    pub const fn new(family: &MemberFamily, kind: MemberCollection) -> Self {
        Self {
            owner: family.owner(),
            collection: family.id(kind),
            live: BTreeMap::new(),
            gone: BTreeSet::new(),
            whole: Whole::Unread,
            first: BTreeMap::new(),
        }
    }

    /// Write the entry at `order`, or delete it with `None`.
    pub fn set(&mut self, order: u128, value: Option<QueueValue>) {
        if let Some(value) = value {
            self.gone.remove(&order);
            self.live.insert(order, value);
        } else {
            self.live.remove(&order);
            self.gone.insert(order);
        }
    }

    fn overlaid(&self, order: u128) -> bool {
        self.live.contains_key(&order) || self.gone.contains(&order)
    }

    /// The stored entries in `from..=hi`, at most `limit` of them.
    fn stored(
        &mut self,
        state: &(impl Substates + ?Sized),
        from: u128,
        hi: u128,
        limit: usize,
    ) -> Vec<(u128, Vec<u8>)> {
        if matches!(self.whole, Whole::Unread) {
            let read =
                state.entries_in_range(self.owner, self.collection, 0, u128::MAX, WHOLE_READ + 1);
            self.whole = if read.len() <= WHOLE_READ {
                Whole::Read(read.into_iter().collect())
            } else {
                Whole::TooMany
            };
        }
        match &self.whole {
            Whole::Read(whole) => whole
                .range(from..=hi)
                .take(limit)
                .map(|(order, bytes)| (*order, bytes.clone()))
                .collect(),
            Whole::Unread | Whole::TooMany => {
                state.entries_in_range(self.owner, self.collection, from, hi, limit)
            }
        }
    }

    /// The earliest stored entry in `from..=hi` naming `key` that the
    /// fold has not overwritten.
    fn seek(
        &mut self,
        state: &(impl Substates + ?Sized),
        key: PinKey,
        mut from: u128,
        hi: u128,
    ) -> Option<u128> {
        loop {
            let page = self.stored(state, from, hi, PAGE);
            for (order, bytes) in &page {
                if !self.overlaid(*order)
                    && from_slice::<QueueValue>(bytes).is_ok_and(|value| names(&value, key))
                {
                    return Some(*order);
                }
            }
            if page.len() < PAGE {
                return None;
            }
            from = page.last()?.0.checked_add(1)?;
        }
    }

    /// The order key of the earliest entry naming `key` in `class`.
    pub fn first(
        &mut self,
        state: &(impl Substates + ?Sized),
        key: PinKey,
        class: PinClass,
    ) -> Option<u128> {
        let (lo, hi) = class_span(key, class);
        let stored = match self.first.get(&(key, class)) {
            Some(&Some(order)) if !self.overlaid(order) => Some(order),
            Some(None) => None,
            Some(&Some(order)) => order
                .checked_add(1)
                .and_then(|from| self.seek(state, key, from, hi)),
            None => self.seek(state, key, lo, hi),
        };
        self.first.insert((key, class), stored);
        let live = self
            .live
            .range(lo..=hi)
            .find(|(_, value)| names(value, key))
            .map(|(order, _)| *order);
        match (stored, live) {
            (Some(stored), Some(live)) => Some(stored.min(live)),
            (stored, live) => stored.or(live),
        }
    }

    /// Every member with an entry naming `key` in `class`, below the
    /// order key `below` where one is given.
    pub fn naming(
        &mut self,
        state: &(impl Substates + ?Sized),
        key: PinKey,
        class: PinClass,
        below: Option<u128>,
    ) -> BTreeSet<TxHash> {
        let (lo, mut hi) = class_span(key, class);
        if let Some(below) = below {
            if below <= lo {
                return BTreeSet::new();
            }
            hi = hi.min(below - 1);
        }
        let mut found = BTreeSet::new();
        let Some(lo) = self.first(state, key, class).filter(|first| *first <= hi) else {
            return found;
        };
        for (order, bytes) in self.stored(state, lo, hi, usize::MAX) {
            if self.overlaid(order) {
                continue;
            }
            if let Ok(value) = from_slice::<QueueValue>(&bytes) {
                found.extend(value.iter().filter(|(at, _)| *at == key).map(|(_, tx)| *tx));
            }
        }
        for value in self.live.range(lo..=hi).map(|(_, value)| value) {
            found.extend(value.iter().filter(|(at, _)| *at == key).map(|(_, tx)| *tx));
        }
        found
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
