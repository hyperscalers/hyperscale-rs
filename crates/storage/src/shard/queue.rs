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
//! - `Waiters`: one entry per pin of each determined row or leg standing
//!   `Pending` with a place, until a line names it or it leaves. A line
//!   running a leg moves it from here to its `Queue` place.
//! - `TickPins`: the pins a tick's determined lines take, unioned per
//!   key, while its determined half is owed.
//! - `Behind`: each placed shared row not yet head, by place, so the
//!   rows behind are tested again in place order.
//! - `Serves`: each keyed shared row made head, while it stands placed.
//!
//! Entries are a function of a row's own fields, so every collection but
//! `TickPins` is written wherever a row's entries change, as a seat is.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_hbor::{Capped, Hbor, from_slice};
use hyperscale_types::{
    Address, BlockHeight, CollectionId, Holds, MAX_HOLDS_PER_MEMBER, MAX_TICK_LINES_PER_BLOCK,
    MAX_TXS_PER_BLOCK, MAX_UNSETTLED_PER_BLOCK, MemberCollection, MemberFamily, Pin, PinClass,
    PinKey, Pins, Settlement, ShardId, TxHash, WeightedTimestamp, member_order, pins_of,
};

use crate::Substates;
use crate::shard::members::{MemberIndex, MemberRow, RowState};

/// Where a member stands in its shard's queue: the block that placed it
/// and its rank there.
///
/// Shared members a block places take ranks first, in hash order; the
/// block's waiters follow, then the legs its lines run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
pub struct Place {
    /// The block that placed it.
    pub height: BlockHeight,
    /// Its rank among the places that block takes.
    pub rank: u16,
}

/// The bits a queue order key gives its class.
const CLASS_BITS: u32 = 3;

/// The most height bits a queue order key carries: about 11,000 years
/// at 100 blocks a second.
const PLACE_HEIGHT_BITS: u32 = 45;

/// The bits a packed place takes, height over rank.
const PLACE_BITS: u32 = PLACE_HEIGHT_BITS + 16;

const _: () =
    assert!(PinClass::ALL.len() <= 1 << CLASS_BITS && CLASS_BITS + PLACE_HEIGHT_BITS + 16 == 64);

impl Place {
    /// The place in 61 bits, height over rank, in place order.
    ///
    /// # Panics
    ///
    /// Past 2^45 blocks, which no chain reaches.
    #[must_use]
    pub fn packed(self) -> u64 {
        let height = self.height.inner();
        assert!(
            height < 1 << PLACE_HEIGHT_BITS,
            "a place's height fits 45 bits"
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
/// `bucket:64 ‖ class:3 ‖ height:45 ‖ rank:16`.
#[must_use]
pub fn queue_order(key: PinKey, class: PinClass, place: Place) -> u128 {
    class_base(key, class) | u128::from(place.packed())
}

/// The order keys of every place `key` holds in `class`.
#[must_use]
pub fn class_span(key: PinKey, class: PinClass) -> (u128, u128) {
    let base = class_base(key, class);
    (base, base | ((1u128 << PLACE_BITS) - 1))
}

fn class_base(key: PinKey, class: PinClass) -> u128 {
    (u128::from(key.bucket()) << 64) | ((class as u128) << PLACE_BITS)
}

/// The class a `Queue` order key stands in, or `None` where its class
/// bits name none.
fn class_of(order: u128) -> Option<PinClass> {
    let bits = (order >> PLACE_BITS) & ((1 << CLASS_BITS) - 1);
    PinClass::from_bits(u8::try_from(bits).expect("three bits fit a byte"))
}

/// The order key of a waiter's `Waiters` entry for `key` at `place`:
/// `bucket:64 ‖ 0:3 ‖ height:45 ‖ rank:16`, one per pin whatever its
/// modes, since what a waiter is refused on is read off its row.
#[must_use]
pub fn waiter_order(key: PinKey, place: Place) -> u128 {
    (u128::from(key.bucket()) << 64) | u128::from(place.packed())
}

/// The order keys of every waiter's place on `key`.
#[must_use]
pub fn waiter_span(key: PinKey) -> (u128, u128) {
    let base = u128::from(key.bucket()) << 64;
    (base, base | ((1u128 << PLACE_BITS) - 1))
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

/// What a row's pins are taken off: what it waits on while `Pending`,
/// and what it holds after.
#[must_use]
pub const fn pinned_holds(row: &MemberRow) -> &Holds {
    match (&row.state, &row.waiting) {
        (RowState::Pending, Some(waiting)) => &waiting.declared,
        _ => &row.holds,
    }
}

/// Each row's pins as a fold derives them, kept per row beside what
/// they were derived from: a row is rewritten several times a fold, and
/// its pins move only where what they are taken off does.
pub struct PinMemo {
    local: ShardId,
    held: BTreeMap<u128, (Holds, Pins)>,
}

impl PinMemo {
    /// No pins derived yet, on `local`.
    #[must_use]
    pub const fn new(local: ShardId) -> Self {
        Self {
            local,
            held: BTreeMap::new(),
        }
    }

    /// `row`'s pins.
    pub fn pins(&mut self, row: &MemberRow) -> Pins {
        let source = pinned_holds(row);
        let order = member_order(row.tx);
        if let Some((held, pins)) = self.held.get(&order)
            && held == source
        {
            return pins.clone();
        }
        let pins = pins_of(source, self.local);
        self.held.insert(order, (source.clone(), pins.clone()));
        pins
    }

    /// The entries `row` implies.
    pub fn entries(&mut self, row: Option<&MemberRow>) -> RowEntries {
        let pins = row
            .filter(|row| row.queued.is_some())
            .map(|row| self.pins(row));
        RowEntries::of_pinned(row, pins.as_ref())
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
            RowState::Released { .. } | RowState::Accepted { .. } => false,
        }
}

/// The first rank a block gives the legs its lines run on awaited terms:
/// past every shared place and waiter the block takes, so a leg stands
/// behind them on its block's height.
pub const AWAITED_RANK: u16 = 1 << 15;

/// The first rank a block gives the determined members and legs it
/// commits and leaves waiting: past every shared place the block takes,
/// which are at most the rows standing and the block's own commits, so a
/// waiter's rank is the same whichever fold of the block places it. A
/// block commits a transaction once, so its waiters fit below
/// [`AWAITED_RANK`].
pub const WAITER_RANK: u16 = 1 << 14;

const _: () = assert!(
    MAX_UNSETTLED_PER_BLOCK + MAX_TXS_PER_BLOCK <= WAITER_RANK as usize
        && WAITER_RANK as usize + MAX_TXS_PER_BLOCK <= AWAITED_RANK as usize
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

/// Whether `row` stands as a waiter: placed and `Pending` on terms no
/// counterpart shares the verdict on, a determined member's or a leg's.
#[must_use]
pub fn standing_waiter(row: &MemberRow) -> bool {
    row.queued.is_some()
        && row.state == RowState::Pending
        && row
            .waiting
            .as_ref()
            .is_some_and(|waiting| waiting.settlement != Settlement::Shared)
}

/// Whether a row pinning `pins` is keyed: it reads or writes a key this
/// shard serves.
#[must_use]
pub fn keyed(pins: &[Pin]) -> bool {
    pins.iter().any(|pin| !pin.modes.served().is_empty())
}

/// Whether a member settling on `settlement` and pinning `pins` here is
/// served from its head: shared and keyed.
///
/// The one rule both serves read. The committing block's serve leaves
/// out the targets such a member shares its verdict with, and its
/// `Serves` entry, standing from its head, serves exactly those, so each
/// target is served once.
#[must_use]
pub fn served_from_head(settlement: Settlement, pins: &[Pin]) -> bool {
    settlement == Settlement::Shared && keyed(pins)
}

/// The order keys every `Serves` entry under `height` lies in.
fn serves_span(height: BlockHeight) -> (u128, u128) {
    let base = u128::from(height.inner()) << 64;
    (base, base | u128::from(u64::MAX))
}

/// The rows the block at `height` made head on `shard` that it serves
/// from there: those whose `Serves` entry stands under `height` in
/// `state`, in rank order, each read out of `state`.
///
/// `state` is the one the block left, or any later one the rows still
/// stand in: an entry stands while its row stands placed.
#[must_use]
pub fn served_rows(
    state: &(impl Substates + ?Sized),
    shard: ShardId,
    height: BlockHeight,
) -> Vec<MemberRow> {
    let (owner, serves) = MemberCollection::Serves.of(shard);
    let (lo, hi) = serves_span(height);
    state
        .entries_in_range(owner, serves, lo, hi, usize::MAX)
        .into_iter()
        .filter_map(|(_, bytes)| from_slice::<TxHash>(&bytes).ok())
        .filter_map(|tx| {
            let entry = MemberCollection::Members.entry(shard, tx);
            state
                .entries_in_range(entry.owner, entry.collection, entry.order, entry.order, 1)
                .into_iter()
                .next()
                .and_then(|(_, bytes)| from_slice::<MemberRow>(&bytes).ok())
                .filter(|row| row.tx == tx)
        })
        .collect()
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
    /// What `row` implies where `pins` are its pins; nothing where no
    /// row stands or the row has no place.
    ///
    /// # Panics
    ///
    /// Never: a member's entries under one key are at most its pins.
    #[must_use]
    pub fn of_pinned(row: Option<&MemberRow>, pins: Option<&Pins>) -> Self {
        let (Some(row), Some(pins)) = (row.filter(|row| row.queued.is_some()), pins) else {
            return Self::default();
        };
        let (shared, holding, waiting) = (
            shared_standing(row),
            awaited_holding(row),
            standing_waiter(row),
        );
        if !shared && !holding && !waiting {
            return Self::default();
        }
        let place = row.queued.expect("filtered on a place");
        let mut keyed_entries: BTreeMap<u128, Vec<(PinKey, TxHash)>> = BTreeMap::new();
        for pin in pins.iter() {
            if waiting {
                keyed_entries
                    .entry(waiter_order(pin.key, place))
                    .or_default()
                    .push((pin.key, row.tx));
                continue;
            }
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
            behind: row
                .head
                .is_none()
                .then(|| (u128::from(place.packed()), row.tx)),
            serves: row
                .head
                .filter(|_| served_from_head(Settlement::Shared, pins))
                .map(|head| (serves_order(head), row.tx)),
            waiters: BTreeMap::new(),
        }
    }
}

/// What the queue holds on each key, as naming reads it: per key, the
/// classes the standing `Queue` entries and the walk's lines stand in.
///
/// Those of rows holding what they declared stand apart from those of
/// shared rows still waiting, and the pins the lines a walk has named on
/// abortable terms hold stand apart from both.
///
/// Every row that holds what it declared stands in `Queue`, a shared row
/// in flight or stated at its place and a leg in flight from the line
/// running it, so the holding half refuses exactly what their holds
/// refuse, on the keys this shard owns. A shared row waiting stands
/// there from its place, ahead of its line.
///
/// Which halves refuse a candidate depends on how it settles
/// ([`Self::refuses`]). A determined member is read one way against all
/// of it: its output enters the view at its naming, so a member placed
/// ahead of it is judged over the view it leaves. A leg is read one way
/// against what holds and both ways against the shared rows waiting: of
/// two abortable members on one key, neither may run ahead of an earlier
/// one it would refuse, since neither one's writes are in a view until
/// it resolves. A shared member is judged by its head against the
/// queue, and here only against what the walk holds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QueueHolds {
    holding: BTreeMap<PinKey, u8>,
    waiting: BTreeMap<PinKey, u8>,
    walked: BTreeMap<PinKey, u8>,
}

/// Whether the classes `held` stands in on `pin`'s key refuse it, or,
/// read `both` ways, are refused by it.
fn classes_refuse(held: &BTreeMap<PinKey, u8>, pin: &Pin, both: bool) -> bool {
    held.get(&pin.key).is_some_and(|classes| {
        PinClass::ALL.into_iter().any(|class| {
            classes & (1 << class as u8) != 0
                && (pin.modes.refused_by(class) || (both && pin.modes.refuses_class(class)))
        })
    })
}

impl QueueHolds {
    /// The `Queue` collection `rows` hold.
    #[must_use]
    pub fn of(rows: &MemberIndex) -> Self {
        let family = MemberFamily::of(rows.shard());
        let mut held = Self::default();
        for (order, bytes) in rows.entries_in_range(
            family.owner(),
            family.id(MemberCollection::Queue),
            0,
            u128::MAX,
            usize::MAX,
        ) {
            let Some(class) = class_of(order) else {
                continue;
            };
            let Ok(value) = from_slice::<QueueValue>(&bytes) else {
                continue;
            };
            for (key, tx) in value.iter() {
                let waits = rows
                    .members
                    .get(tx)
                    .is_some_and(|row| row.state == RowState::Pending);
                let side = if waits {
                    &mut held.waiting
                } else {
                    &mut held.holding
                };
                *side.entry(*key).or_default() |= 1 << class as u8;
            }
        }
        held
    }

    /// Whether nothing stands.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.holding.is_empty() && self.waiting.is_empty() && self.walked.is_empty()
    }

    /// Take `pins` as held for the rest of the walk, as a line named to
    /// run on abortable terms holds them.
    pub fn hold(&mut self, pins: &[Pin]) {
        for pin in pins {
            for class in PinClass::ALL {
                if pin.modes.stands_in(class) {
                    *self.walked.entry(pin.key).or_default() |= 1 << class as u8;
                }
            }
        }
    }

    /// Whether a candidate settling on `settlement` and pinning `pins` is
    /// refused: one way by what holds and by what the walk holds, and by
    /// the shared rows waiting one way for a determined member, both ways
    /// for a leg, and not at all for a shared member, whose head answers
    /// for them.
    ///
    /// A shared member is in practice never refused here: a line the
    /// walk runs on abortable terms is a head, compatible both ways with
    /// every other head, or a leg, which any conflicting shared row
    /// waiting refuses before it holds. What the walk holds keeps out
    /// the determined members named after an abortable line.
    #[must_use]
    pub fn refuses(&self, pins: &[Pin], settlement: Settlement) -> bool {
        pins.iter().any(|pin| {
            classes_refuse(&self.walked, pin, false)
                || match settlement {
                    Settlement::Shared => false,
                    Settlement::Awaited => {
                        classes_refuse(&self.holding, pin, false)
                            || classes_refuse(&self.waiting, pin, true)
                    }
                    Settlement::Alone => {
                        classes_refuse(&self.holding, pin, false)
                            || classes_refuse(&self.waiting, pin, false)
                    }
                }
        })
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
/// A fold asks of a key's span, one class of it in `Queue` and the whole
/// of it in `Waiters`, either for its earliest entry or for every entry
/// below a place. The earliest stored entry is found once per key and
/// span and kept; the fold only ever overwrites more, so a kept answer
/// moves forward and never back, and the stored entries of one span are
/// walked at most once per fold. A collection holding at
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
    /// Per key and span, by the span's first order key, the earliest
    /// stored entry naming the key that the fold had not overwritten
    /// when last asked; `None` where none stands.
    first: BTreeMap<(PinKey, u128), Option<u128>>,
    /// Per bucket asked about, whether the stored collection holds no
    /// entry in it.
    bare: BTreeMap<u64, bool>,
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
            bare: BTreeMap::new(),
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

    /// The stored entries in `from..=hi`, at most `limit` of them: none
    /// where `from` is past `hi`, as [`Substates::entries_in_range`]
    /// answers.
    fn stored(
        &mut self,
        state: &(impl Substates + ?Sized),
        from: u128,
        hi: u128,
        limit: usize,
    ) -> Vec<(u128, Vec<u8>)> {
        if from > hi {
            return Vec::new();
        }
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

    /// Whether the stored collection holds no entry in `key`'s bucket:
    /// one read per bucket a fold asks about, answering every span of
    /// it, which is how a key nobody else stands on is answered.
    fn bare(&mut self, state: &(impl Substates + ?Sized), key: PinKey) -> bool {
        let bucket = key.bucket();
        if let Some(&bare) = self.bare.get(&bucket) {
            return bare;
        }
        let lo = u128::from(bucket) << 64;
        let bare = self
            .stored(state, lo, lo | u128::from(u64::MAX), 1)
            .is_empty();
        self.bare.insert(bucket, bare);
        bare
    }

    /// Whether the collection holds no entry at all, as the fold leaves
    /// it so far.
    pub fn is_empty(&mut self, state: &(impl Substates + ?Sized)) -> bool {
        self.live.is_empty() && self.stored(state, 0, u128::MAX, 1).is_empty()
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

    /// The order key of the earliest entry naming `key` in `span`, one
    /// of `key`'s spans.
    pub fn first(
        &mut self,
        state: &(impl Substates + ?Sized),
        key: PinKey,
        span: (u128, u128),
    ) -> Option<u128> {
        let (lo, hi) = span;
        let stored = if self.bare(state, key) {
            None
        } else {
            let stored = match self.first.get(&(key, lo)) {
                Some(&Some(order)) if !self.overlaid(order) => Some(order),
                Some(None) => None,
                Some(&Some(order)) => order
                    .checked_add(1)
                    .and_then(|from| self.seek(state, key, from, hi)),
                None => self.seek(state, key, lo, hi),
            };
            self.first.insert((key, lo), stored);
            stored
        };
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

    /// Every member with an entry naming `key` in `span`, one of `key`'s
    /// spans, below the order key `below` where one is given.
    pub fn naming(
        &mut self,
        state: &(impl Substates + ?Sized),
        key: PinKey,
        span: (u128, u128),
        below: Option<u128>,
    ) -> BTreeSet<TxHash> {
        let (lo, mut hi) = span;
        if let Some(below) = below {
            if below <= lo {
                return BTreeSet::new();
            }
            hi = hi.min(below - 1);
        }
        let mut found = BTreeSet::new();
        let Some(lo) = self.first(state, key, span).filter(|first| *first <= hi) else {
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
    use hyperscale_types::{
        EntryKey, Hash, MAX_CELL_VALUE_LEN, MemberCollection, Modes, SubstateKey,
    };

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
        let last = at((1 << PLACE_HEIGHT_BITS) - 1, u16::MAX);
        for pair in PinClass::ALL.windows(2) {
            let (class, next) = (pair[0], pair[1]);
            let early = queue_order(key, class, at(5, 9));
            let late = queue_order(key, class, last);
            assert!(early < late);
            let (lo, hi) = class_span(key, class);
            assert!((lo..=hi).contains(&early) && (lo..=hi).contains(&late));
            assert_eq!(class_of(late), Some(class));
            let (after, _) = class_span(key, next);
            assert_eq!(hi + 1, after, "the class bits sit right above the place");
        }
        let (_, hi) = class_span(key, PinClass::Debit);
        assert!(hi < u128::from(key.bucket() + 1) << 64);
        assert_eq!(
            waiter_order(key, last),
            queue_order(key, PinClass::Read, last),
            "a waiter's key carries zero class bits"
        );
    }

    /// An entry whose class bits name no class is skipped, never indexed.
    #[test]
    fn a_class_past_the_last_decodes_as_malformed() {
        /// One `Queue` collection's entries, and nothing else.
        struct Queued(BTreeMap<u128, Vec<u8>>);

        impl Substates for Queued {
            fn cell(&self, _key: SubstateKey) -> Option<Vec<u8>> {
                None
            }

            fn entries_in_range(
                &self,
                _owner: Address,
                collection: CollectionId,
                lo: u128,
                hi: u128,
                limit: usize,
            ) -> Vec<(u128, Vec<u8>)> {
                if collection != MemberFamily::of(ShardId::ROOT).id(MemberCollection::Queue)
                    || lo > hi
                {
                    return Vec::new();
                }
                self.0
                    .range(lo..=hi)
                    .take(limit)
                    .map(|(order, bytes)| (*order, bytes.clone()))
                    .collect()
            }
        }

        let key = PinKey([7; 16]);
        let tx = TxHash::from(Hash::from_bytes(&[1; 32]));
        let value = to_vec(&QueueValue::new(vec![(key, tx)]).expect("one entry")).expect("encodes");
        let place = Place {
            height: BlockHeight::new(3),
            rank: 0,
        };
        for bits in 5u128..=7 {
            let order = (u128::from(key.bucket()) << 64)
                | (bits << PLACE_BITS)
                | u128::from(place.packed());
            assert_eq!(class_of(order), None);
            let rows = MemberIndex::load(
                &Queued(BTreeMap::from([(order, value.clone())])),
                ShardId::ROOT,
            );
            assert!(QueueHolds::of(&rows).is_empty(), "class bits {bits}");
        }
        let order = queue_order(key, PinClass::Write, place);
        let rows = MemberIndex::load(&Queued(BTreeMap::from([(order, value)])), ShardId::ROOT);
        assert!(
            !QueueHolds::of(&rows).is_empty(),
            "a class within the table is read"
        );
    }

    mod pin_index {
        use hyperscale_types::{Hash, SubstateKey};
        use proptest::collection::vec;
        use proptest::option;
        use proptest::prelude::*;

        use super::*;

        /// One collection's entries, read by range.
        struct Stored(BTreeMap<u128, Vec<u8>>);

        impl Substates for Stored {
            fn cell(&self, _key: SubstateKey) -> Option<Vec<u8>> {
                None
            }

            fn entries_in_range(
                &self,
                _owner: Address,
                _collection: CollectionId,
                lo: u128,
                hi: u128,
                limit: usize,
            ) -> Vec<(u128, Vec<u8>)> {
                if lo > hi {
                    return Vec::new();
                }
                self.0
                    .range(lo..=hi)
                    .take(limit)
                    .map(|(order, bytes)| (*order, bytes.clone()))
                    .collect()
            }
        }

        /// Three keys: the first two share a bucket, the third has its
        /// own.
        fn key(at: u8) -> PinKey {
            let mut key = [0x40; 16];
            if at == 2 {
                key[0] = 0x41;
            }
            key[15] = at;
            PinKey(key)
        }

        fn tx(at: u8) -> TxHash {
            TxHash::from(Hash::from_bytes(&[at; 32]))
        }

        /// An entry: which key, class and place, and which members it
        /// names, by a mask over the keys sharing its bucket.
        type Drawn = (u8, u8, u8, u8, u8);

        fn entry((at, class, height, rank, member): Drawn) -> (u128, QueueValue) {
            let class = PinClass::ALL[usize::from(class) % PinClass::ALL.len()];
            let place = Place {
                height: BlockHeight::new(u64::from(height % 4)),
                rank: u16::from(rank % 4),
            };
            let key = key(at % 3);
            let mut named = vec![(key, tx(member))];
            if at % 3 < 2 && member % 2 == 0 {
                // The bucket's other key, beside it in one value.
                named.push((self::key(1 - at % 3), tx(member)));
            }
            named.sort();
            (
                queue_order(key, class, place),
                Capped::new(named).expect("two at most"),
            )
        }

        /// A range whose start is past its end holds nothing, whether the
        /// collection was read whole or is sought.
        #[test]
        fn a_range_past_its_end_is_empty() {
            for sought in [false, true] {
                let mut held = BTreeMap::from([(5u128, Vec::new())]);
                if sought {
                    for at in 0..=WHOLE_READ as u128 {
                        held.insert((0xF0u128 << 120) | at, Vec::new());
                    }
                }
                let state = Stored(held);
                let mut index =
                    PinIndex::new(&MemberFamily::of(ShardId::ROOT), MemberCollection::Queue);
                assert_eq!(index.stored(&state, 0, 5, usize::MAX).len(), 1);
                assert!(index.stored(&state, 6, 5, usize::MAX).is_empty());
            }
        }

        proptest! {
            /// Over any stored entries and any writes over them, the
            /// earliest entry naming a key and every member named below
            /// a place are what a scan of the merged collection reads,
            /// whether the collection is read whole or sought, and keys
            /// sharing a bucket never answer for each other.
            #[test]
            fn probes_match_a_scan(
                stored in vec((0u8..3, 0u8..5, 0u8..4, 0u8..4, 0u8..4), 0..12),
                writes in vec(((0u8..3, 0u8..5, 0u8..4, 0u8..4, 0u8..4), any::<bool>()), 0..12),
                asks in vec((0u8..3, 0u8..5, option::of((0u8..4, 0u8..4))), 1..12),
                sought in any::<bool>(),
            ) {
                let mut held: BTreeMap<u128, Vec<u8>> = stored
                    .into_iter()
                    .map(entry)
                    .map(|(order, value)| (order, to_vec(&value).expect("encodes")))
                    .collect();
                if sought {
                    // Past what a fold reads whole, far from every key.
                    for at in 0..=WHOLE_READ as u128 {
                        held.insert((0xF0u128 << 120) | at, Vec::new());
                    }
                }
                let state = Stored(held.clone());
                let mut index = PinIndex::new(
                    &MemberFamily::of(ShardId::ROOT),
                    MemberCollection::Queue,
                );
                let mut merged: BTreeMap<u128, QueueValue> = held
                    .iter()
                    .filter_map(|(order, bytes)| Some((*order, from_slice(bytes).ok()?)))
                    .collect();
                let mut asks = asks.into_iter();
                for (drawn, keep) in writes {
                    let (order, value) = entry(drawn);
                    if keep {
                        index.set(order, Some(value.clone()));
                        merged.insert(order, value);
                    } else {
                        index.set(order, None);
                        merged.remove(&order);
                    }
                    // Ask between writes too, so kept answers are moved on.
                    if let Some((at, class, _)) = asks.next() {
                        let key = key(at);
                        let span = class_span(key, PinClass::ALL[usize::from(class)]);
                        let scanned = merged
                            .range(span.0..=span.1)
                            .find(|(_, value)| value.iter().any(|(at, _)| *at == key))
                            .map(|(order, _)| *order);
                        prop_assert_eq!(index.first(&state, key, span), scanned);
                    }
                }
                for (at, class, below) in asks {
                    let key = key(at);
                    let class = PinClass::ALL[usize::from(class)];
                    let span = class_span(key, class);
                    let below = below.map(|(height, rank)| {
                        queue_order(
                            key,
                            class,
                            Place {
                                height: BlockHeight::new(u64::from(height)),
                                rank: u16::from(rank),
                            },
                        )
                    });
                    let scanned: BTreeSet<TxHash> = merged
                        .range(span.0..=span.1)
                        .filter(|(order, _)| below.is_none_or(|below| **order < below))
                        .flat_map(|(_, value)| value.iter().filter(|(at, _)| *at == key).map(|(_, tx)| *tx).collect::<Vec<_>>())
                        .collect();
                    prop_assert_eq!(index.naming(&state, key, span, below), scanned);
                }
            }
        }
    }
}
