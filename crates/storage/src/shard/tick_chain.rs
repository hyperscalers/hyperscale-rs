//! Execution-tick output chain.
//!
//! One tick per committed block that carries executable work: the block's
//! single-shard transactions plus every cross-shard tick whose provisions
//! completed at that commit, executed as one batch. Each tick's output is
//! the next tick's baseline, overlaid on the persisted base — execution
//! dispatch reads through [`TickChain::view_at`] instead of the
//! settlement-derived [`crate::PendingChain`] overlay.
//!
//! A tick is clocked by commits, never by time. It is one execution
//! batch, and a block carrying no work produces none — so the ticks a
//! chain holds are neither periodic nor one per height, and the timer the
//! word suggests elsewhere in this workspace has nothing to do with it.
//!
//! A tick's output is a pure function of the committed chain prefix, so
//! the chain is a deterministic cache: any replica rebuilds it by
//! replaying committed blocks forward from the persisted tip.
//!
//! **A leg reads as its verdict left it only from the verdict's own
//! height.** A cross-shard transaction's local writes sit beside the
//! determined fold as per-tick provisional entries, holding the cells they
//! reserve, until a verdict on them commits. Resolution promotes the
//! surviving side into the readable fold or drops it, without recomputing
//! any tick output. A tick below the height that verdict committed at
//! reads the leg pending, its holds included, however late it runs: a
//! replica whose tick queue lags its commits applies the verdict before
//! that tick runs, and another runs it first, and both have to compute
//! the receipts the committee certified.
//!
//! **A contribution is readable until the base carries it, and never
//! both.** A receipt says what an exclusive write left and what a
//! commutative access moved, and the second of those does not survive
//! being applied twice. So each contribution records the height its
//! tick's settlement reaches the base at, and a read folds it only while
//! its anchor sits below that height. Overlap is not idempotent and is
//! therefore not permitted.
//!
//! **This overlay never feeds state-root computation.** State roots stay
//! settlement-derived through `PendingChain`; `TickChain` deliberately
//! implements none of the commit-pipeline surfaces (`ShardChainWriter`,
//! `TreeReader`), so the two overlays cannot be cross-fed.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, RwLock};

use hyperscale_jmt::NibblePath;
use hyperscale_types::{
    BlockHeight, DeclaredKey, Mode, Movement, ProvisionalHolds, ShardId, StateWrites, SubstateKey,
    TickId, TxHash, amount_cell, read_amount,
};
use hyperscale_vm_types::{Address, CollectionId};

use crate::lock_recover::{read_or_recover, write_or_recover};
use crate::shard::fee_holds::{FeeTerms, HeldByTx, StandingFeeHolds, release_of};
use crate::shard::members::{MemberIndex, RowState, row_state};
use crate::shard::writes::{entry_overlay_range, fold_state_writes, merge_entry_overlay};
use crate::{Substates, VersionedStore};

/// One cross-shard transaction's provisional contribution to a tick.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvisionalTx {
    /// Transaction whose tick verdict decides which side settles.
    pub tx_hash: TxHash,
    /// Local execution writes; promoted when the tick settles this
    /// transaction as accepted. `None` for a failed attempt, which
    /// produced no effects.
    pub writes: Option<StateWrites>,
    /// The payer-vault charge held beside the effects — the abort floor a
    /// completed leg owes if its tick aborts, or the class charge of a
    /// failed attempt. Promoted when the tick settles this transaction as
    /// aborted (the substitute receipt), dropped with everything else if
    /// the tick never finalizes.
    pub reserve: Option<StateWrites>,
    /// What this leg holds against each amount cell while its tick is
    /// unresolved — its declared reservations.
    ///
    /// Recorded here rather than tracked beside the chain so the hold and
    /// the writes it stands for share one lifetime: both are promoted or
    /// dropped by the same resolution, and a reader can never see a
    /// balance with the debit already in it while the hold still says the
    /// value is spoken for.
    pub reserved: BTreeMap<SubstateKey, u128>,
}

/// What a leg declaring `declared` holds by cell once it completes.
///
/// A reservation targets an amount cell, which is a point, so an
/// owner-granular declaration is never one. Cells this shard does not own
/// ride along and are dropped where locality is known — a declaration
/// spans every participating shard, and this one does not.
#[must_use]
pub fn declared_reservations(declared: &[(DeclaredKey, Mode)]) -> BTreeMap<SubstateKey, u128> {
    let mut reserved = BTreeMap::new();
    for (key, mode) in declared {
        if let (DeclaredKey::Cell(cell), Mode::Reserve { amount }) = (key, mode) {
            *reserved.entry(*cell).or_default() += *amount;
        }
    }
    reserved
}

/// The reservation of a stated row whose leg no entry holds: one the
/// floor dropped, or one this replica never ran.
///
/// Whether it holds is read off the row in the base. It holds against a
/// view at a height whose base holds the row stated in `tick`, and goes
/// once the eviction floor reaches a height whose base holds the row in
/// no tick of its own: the legs half or the abort that ends the row
/// commits its writes, or their absence, into the base at that same
/// height.
#[derive(Clone, Debug, PartialEq, Eq)]
struct StatedHold {
    /// The tick holding the row.
    tick: BlockHeight,
    /// The shard whose family holds the row.
    shard: ShardId,
    /// What the row holds against each amount cell.
    reserved: BTreeMap<SubstateKey, u128>,
}

impl StatedHold {
    /// Whether `state` holds the row stated in its tick.
    fn stated_in(&self, state: &(impl Substates + ?Sized), tx_hash: TxHash) -> bool {
        matches!(
            row_state(state, self.shard, tx_hash),
            Some(RowState::Stated { tick, .. }) if tick == self.tick
        )
    }

    /// Whether `state` holds the row in its tick, in flight or stated.
    fn held_in(&self, state: &(impl Substates + ?Sized), tx_hash: TxHash) -> bool {
        row_state(state, self.shard, tx_hash)
            .and_then(RowState::held)
            .is_some_and(|(tick, ..)| tick == self.tick)
    }
}

/// The execution output of one tick.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TickOutput {
    /// What each member reaching no further than this shard left, in the
    /// canonical order the batch fold produced them in — absolutes where
    /// an exclusive write stated the value, movements where a commutative
    /// access said what it moved, unconditional fee burns included.
    /// Readable by every subsequent tick immediately.
    pub determined: Vec<(TxHash, StateWrites)>,
    /// What its cross-shard legs left, unreadable until the tick's
    /// certificate commits and says which side of each survives.
    pub provisional: Vec<ProvisionalTx>,
}

/// How some of a tick's members became resolved from chain content.
///
/// A tick settles in halves — its determined members on its own
/// certificate, its cross-shard legs once a counterpart certifies — so a
/// resolution names the members it speaks for rather than the whole tick.
#[derive(Clone, Debug)]
pub enum TickResolution {
    /// A committed finalization resolved `members`. Those in `aborted`
    /// settle their reserve charge; the rest settle their execution
    /// writes.
    Settled {
        /// Height of the block that committed the finalization.
        height: BlockHeight,
        /// The members it reached a verdict for.
        members: BTreeSet<TxHash>,
        /// Which of them had their execution effects discarded.
        aborted: BTreeSet<TxHash>,
    },
    /// These members will never finalize — the tick holding them was
    /// discarded after one of them was abandoned at its deadline.
    /// Nothing settles; their provisional entries drop.
    Abandoned {
        /// Height of the block at which the chain let them go.
        height: BlockHeight,
        /// The members that will never reach a verdict.
        members: BTreeSet<TxHash>,
    },
    /// A settled tick this replica never ran, taken from the receipts
    /// that committed it.
    ///
    /// A replay reaches further back than the store answers a historical
    /// read at, so the ticks below that reach compose and none of them
    /// runs. What such a tick left is still owed to every tick the replay
    /// *does* run below the height it settled at —
    /// the base does not carry it yet, and a baseline missing it is a
    /// baseline no other replica computed. The receipts state it exactly,
    /// so the entry is seated from them and stamped where they committed.
    ///
    /// It holds what a run appends and nothing else. A member that
    /// reached no engine has a receipt and no contribution: what it
    /// settles reaches every baseline through the base, from `height`.
    Restored {
        /// Height of the block that committed the receipts.
        height: BlockHeight,
        /// What each member a run executes left, as its receipt states
        /// it.
        writes: Vec<(TxHash, StateWrites)>,
    },
    /// A held tick's legs, seated as a run would have left them and
    /// settled by the finalization committed at `height`.
    ///
    /// A replica that never ran the tick holds none of its legs, yet every
    /// tick below `height` reads them pending, holds included, and every
    /// tick from it reads them settled. Seating them and settling them in
    /// one step leaves exactly the entry a run would have, under the same
    /// read rule.
    RestoredLegs {
        /// Height of the block that committed the legs' finalization.
        height: BlockHeight,
        /// Each leg, its surviving side as its receipt states it and its
        /// holds as its declaration names them.
        legs: Vec<ProvisionalTx>,
        /// Which of them had their execution effects discarded.
        aborted: BTreeSet<TxHash>,
    },
}

/// One transaction's readable contribution to a tick.
struct Contribution {
    /// What the transaction left, in the form its receipt states it.
    writes: StateWrites,
    /// The height the settled base gains these writes at, known once the
    /// tick's fate commits.
    ///
    /// A read anchored below it needs the fold; at or above it the base
    /// already carries the same change. Folding both would leave an
    /// exclusive write unchanged and a movement applied twice, which is
    /// why this is a height rather than a flag.
    in_base_from: Option<BlockHeight>,
    /// The first tick that reads it: the height a leg's verdict committed
    /// at. `None` for a contribution readable from the append on.
    readable_from: Option<BlockHeight>,
}

/// One tick's readable contributions folded into a single write set, and
/// the span of base heights that fold is the answer for.
///
/// A fold leaves out whatever the base already carries, so it answers
/// only while the same contributions are left out — an interval running
/// from the highest stamp it treats as carried up to the lowest it still
/// folds. Every base height in that interval partitions the entry's
/// contributions identically, and most of the heights a chain passes
/// through cross no stamp of any given tick.
struct CachedFold {
    /// The contributions this fold applies, composed in entry order.
    writes: Arc<StateWrites>,
    /// The fee holds those contributions delete that the base still
    /// holds: each one's burn is in `writes` while the base's total for
    /// its vault still counts its ceiling.
    ///
    /// It holds across the whole span the fold answers for. A folded
    /// contribution's member was committed at or below its tick, so the
    /// hold stands at every base height from there, and the block that
    /// deletes it is the one that carries the contribution into the
    /// base, which ends the span.
    released: HeldByTx,
    /// Lowest base height this fold answers for: the highest stamp it
    /// treats as already carried by the base.
    from: BlockHeight,
    /// One past the highest base height it answers for: the lowest stamp
    /// among the contributions it still folds. `None` when none of them
    /// is stamped, so no base height above `from` changes the partition.
    until: Option<BlockHeight>,
    /// Lowest reading tick this fold answers for: the highest
    /// `readable_from` among the contributions it reads.
    read_from: BlockHeight,
    /// One past the highest reading tick it answers for: the lowest
    /// `readable_from` among the contributions it leaves unread.
    read_until: Option<BlockHeight>,
}

impl CachedFold {
    /// Whether the partition this fold was built for is the partition at
    /// `base_at`, for the tick `reader`.
    fn answers_for(&self, base_at: BlockHeight, reader: BlockHeight) -> bool {
        self.from <= base_at
            && self.until.is_none_or(|until| base_at < until)
            && self.read_from <= reader
            && self.read_until.is_none_or(|until| reader < until)
    }

    /// The layer a view reads through, absent when the fold applies
    /// nothing — the shape a tick takes once the base carries everything
    /// it held and eviction is still waiting on the execution floor.
    /// Layering that would cost every read a step for nothing.
    fn layer(&self) -> Option<Arc<StateWrites>> {
        let carries_something = !self.writes.cells.is_empty()
            || !self.writes.movements.is_empty()
            || !self.writes.entries.is_empty();
        carries_something.then(|| Arc::clone(&self.writes))
    }
}

/// One tick's retained state.
struct TickEntry {
    /// Readable contributions in canonical transaction order — the order
    /// the batch fold that produced them ran in. The members reaching no
    /// further than this shard are here from the append; a cross-shard
    /// leg's arrive when the tick's verdict promotes them.
    readable: BTreeMap<TxHash, Contribution>,
    /// The tick's provisional legs, by member, until a verdict promotes
    /// or drops each one. Keyed rather than listed because a tick's legs
    /// resolve independently of its determined members and, at a
    /// terminal, of each other.
    pending: BTreeMap<TxHash, ProvisionalTx>,
    /// The holds of legs a verdict has resolved, with the height it
    /// committed at: a tick below that height reads them still held.
    retiring: BTreeMap<TxHash, (BlockHeight, BTreeMap<SubstateKey, u128>)>,
    /// This tick's contributions pre-folded, held across every read it
    /// answers for. A view layers one of these per tick rather than
    /// merging every tick's contributions into one map, which is what
    /// keeps a read's cost off the whole content of the retained chain.
    folded: Option<CachedFold>,
}

impl TickEntry {
    /// An entry holding nothing, for a tick whose contributions arrive
    /// from the chain rather than from a run.
    const fn empty() -> Self {
        Self {
            readable: BTreeMap::new(),
            pending: BTreeMap::new(),
            retiring: BTreeMap::new(),
            folded: None,
        }
    }

    /// Seat what the receipts committed at `height` say each member left,
    /// already stamped: the base gains them there, so a read anchored
    /// below it folds them and one at or above it does not.
    ///
    /// A member the entry already holds is left alone — a run of this
    /// replica's produced it, and the receipts restate the same writes.
    fn restore(&mut self, height: BlockHeight, writes: &[(TxHash, StateWrites)]) {
        for (tx_hash, writes) in writes {
            self.readable
                .entry(*tx_hash)
                .or_insert_with(|| Contribution {
                    writes: writes.clone(),
                    in_base_from: Some(height),
                    readable_from: None,
                });
        }
        self.folded = None;
    }

    /// The entry one tick's run produces.
    fn from_output(output: TickOutput) -> Self {
        Self {
            readable: output
                .determined
                .into_iter()
                .map(|(tx_hash, writes)| {
                    (
                        tx_hash,
                        Contribution {
                            writes,
                            in_base_from: None,
                            readable_from: None,
                        },
                    )
                })
                .collect(),
            pending: output
                .provisional
                .into_iter()
                .map(|tx| (tx.tx_hash, tx))
                .collect(),
            retiring: BTreeMap::new(),
            folded: None,
        }
    }

    /// This entry's fold for a base at `base_at` read by the tick
    /// `reader`, rebuilt only when the one in hand answers for a
    /// different partition. `release` answers what hold a deleted cell
    /// releases, as the base at `base_at` holds it.
    fn fold_at(
        &mut self,
        base_at: BlockHeight,
        reader: BlockHeight,
        release: &mut dyn FnMut(SubstateKey) -> Option<(SubstateKey, TxHash, u128)>,
    ) -> &CachedFold {
        if !self
            .folded
            .as_ref()
            .is_some_and(|fold| fold.answers_for(base_at, reader))
        {
            let rebuilt = self.build_fold(base_at, reader, release);
            self.folded = Some(rebuilt);
        }
        self.folded.as_ref().expect("the fold was just built")
    }

    /// Compose the contributions a base at `base_at` does not carry and
    /// the tick `reader` reads, recording the stamps either side of the
    /// partition so a later read can tell whether it still holds, and the
    /// fee holds those contributions release.
    ///
    /// Ascending in entry order, because an exclusive write supersedes
    /// what stood before it and a movement composes onto it — an order
    /// the fold has to respect even though movements commute among
    /// themselves.
    fn build_fold(
        &self,
        base_at: BlockHeight,
        reader: BlockHeight,
        release: &mut dyn FnMut(SubstateKey) -> Option<(SubstateKey, TxHash, u128)>,
    ) -> CachedFold {
        let mut writes = StateWrites::default();
        let mut released = HeldByTx::new();
        let mut from = BlockHeight::GENESIS;
        let mut until: Option<BlockHeight> = None;
        let mut read_from = BlockHeight::GENESIS;
        let mut read_until: Option<BlockHeight> = None;
        for contribution in self.readable.values() {
            if let Some(height) = contribution.readable_from {
                if height > reader {
                    read_until = Some(read_until.map_or(height, |lowest| lowest.min(height)));
                    continue;
                }
                read_from = read_from.max(height);
            }
            if let Some(height) = contribution.in_base_from {
                if height <= base_at {
                    from = from.max(height);
                    continue;
                }
                until = Some(until.map_or(height, |lowest| lowest.min(height)));
            }
            fold_state_writes(&mut writes, &contribution.writes);
            let deleted = contribution
                .writes
                .cells
                .iter()
                .filter(|(_, change)| change.is_none());
            for (key, _) in deleted {
                if let Some((vault, tx_hash, ceiling)) = release(*key) {
                    released.entry(vault).or_default().insert(tx_hash, ceiling);
                }
            }
        }
        CachedFold {
            writes: Arc::new(writes),
            released,
            from,
            until,
            read_from,
            read_until,
        }
    }

    /// Apply a verdict for the members it names: promote each one's
    /// surviving side into the readable fold, or drop it outright, and
    /// record the height the base gains whatever survives at. A promoted
    /// leg is read only by ticks from that height on, and the cells it
    /// held stay held for every tick below it.
    ///
    /// Scoped to the named members because a tick settles in halves. Its
    /// determined members are readable from the append and are stamped
    /// when their own half commits; its legs are unreadable until a
    /// verdict promotes them, which is a later block and sometimes never.
    /// Idempotent per member — a member already resolved is not in
    /// `pending` and its contribution is already stamped. A restore seats
    /// what a tick no run of this replica's produced left instead.
    fn resolve(&mut self, tick: BlockHeight, resolution: &TickResolution) {
        // A verdict changes both what the entry holds and which stamps
        // bound the partition, so the fold in hand answers for nothing.
        self.folded = None;
        match resolution {
            TickResolution::Settled {
                height,
                members,
                aborted,
            } => self.settle(*height, members.iter(), aborted),
            // A leg a run of this replica's already holds, pending or
            // promoted, is left to it: the run is the same function of
            // the same chain prefix.
            TickResolution::RestoredLegs {
                height,
                legs,
                aborted,
            } => {
                for leg in legs {
                    if !self.readable.contains_key(&leg.tx_hash) {
                        self.pending
                            .entry(leg.tx_hash)
                            .or_insert_with(|| leg.clone());
                    }
                }
                self.settle(*height, legs.iter().map(|leg| &leg.tx_hash), aborted);
            }
            TickResolution::Restored { height, writes } => self.restore(*height, writes),
            // Nothing settles, so nothing enters the base and no height
            // is recorded. Only a provisional contribution can take this
            // path: it was never readable, so dropping it changes no
            // baseline any tick has already read.
            //
            // A readable contribution here would have no correct
            // handling. Later ticks have read those writes and no base
            // will ever carry them, so stamping a height would drop them
            // from a later baseline while an earlier one kept them, and
            // leaving them unstamped would pin the entry forever. The
            // rule is upstream, and it is what the halves are for: a
            // determined member settles on its tick's own certificate, so
            // it is never waiting on the counterpart whose absence
            // abandons its tick-mates.
            TickResolution::Abandoned { height, members } => {
                for tx_hash in members {
                    if let Some(tx) = self.pending.remove(tx_hash) {
                        self.retire(tx.tx_hash, *height, tx.reserved);
                    }
                    // Fail-stop rather than fold on. Leaving the
                    // contribution in place keeps *this* node's reads
                    // agreeing with each other while the base never gains
                    // the writes, so a replica that snap-syncs the base
                    // computes different state from the same chain — a
                    // silent fork, and an entry that never evicts. A node
                    // that reaches this is already producing state no
                    // fresh node can reproduce.
                    //
                    // Unreachable on a healthy replica: a determined
                    // member settles on its own tick's certificate, and a
                    // tick on a shard still committing blocks always
                    // certifies. What is left is a replica whose own
                    // execution diverged, which never settles anything
                    // and is unrecoverable by design.
                    assert!(
                        self.readable
                            .get(tx_hash)
                            .is_none_or(|c| c.in_base_from.is_some()),
                        "tick {tick}: abandoned {tx_hash:?}, whose fold later ticks have read"
                    );
                }
            }
        }
    }

    /// Settle `members` on a verdict committed at `height`, those in
    /// `aborted` on their reserve charge and the rest on their writes.
    fn settle<'a>(
        &mut self,
        height: BlockHeight,
        members: impl IntoIterator<Item = &'a TxHash>,
        aborted: &BTreeSet<TxHash>,
    ) {
        for tx_hash in members {
            // A leg's surviving side becomes readable here; a determined
            // member has been readable since the append and only needs
            // its height.
            if let Some(tx) = self.pending.remove(tx_hash) {
                self.retire(tx.tx_hash, height, tx.reserved);
                let promoted = if aborted.contains(tx_hash) {
                    tx.reserve
                } else {
                    tx.writes
                };
                if let Some(writes) = promoted {
                    self.readable.insert(
                        *tx_hash,
                        Contribution {
                            writes,
                            in_base_from: None,
                            readable_from: Some(height),
                        },
                    );
                }
            }
            if let Some(contribution) = self.readable.get_mut(tx_hash) {
                contribution.in_base_from = Some(height);
            }
        }
    }

    /// Keep a resolved leg's holds for the ticks below `height`, the
    /// height its verdict committed at.
    fn retire(
        &mut self,
        tx_hash: TxHash,
        height: BlockHeight,
        reserved: BTreeMap<SubstateKey, u128>,
    ) {
        if !reserved.is_empty() {
            self.retiring.insert(tx_hash, (height, reserved));
        }
    }

    /// Whether this entry holds `tx_hash`'s leg, pending, retiring or
    /// promoted.
    fn holds_leg(&self, tx_hash: TxHash) -> bool {
        self.pending.contains_key(&tx_hash)
            || self.retiring.contains_key(&tx_hash)
            || self.readable.contains_key(&tx_hash)
    }

    /// Whether the settled base at `floor` already carries everything
    /// this entry holds, so no future read can still need it.
    fn covered_by(&self, floor: BlockHeight) -> bool {
        self.pending.is_empty()
            && self.retiring.values().all(|(height, _)| *height <= floor)
            && self
                .readable
                .values()
                .all(|c| c.in_base_from.is_some_and(|height| height <= floor))
    }
}

/// Deterministic chain of tick outputs, shared between the shard loop and
/// dispatch closures via `Arc`.
///
/// Ticks are keyed by the committing block's height. Blocks that carry no
/// executable work produce no entry; [`Self::view_at`] layers every
/// retained tick at or below its anchor.
pub struct TickChain<S> {
    base: Arc<S>,
    entries: RwLock<BTreeMap<BlockHeight, TickEntry>>,
    /// The highest height the settled base is known to carry: the
    /// highest a tick's baseline is read at, and with the lowest
    /// baseline still to be read, what bounds eviction.
    persisted: RwLock<BlockHeight>,
    /// No tick above this reads a contribution at or below it: the
    /// parent height of a halt recovery's crossing block, at or below
    /// which every contribution is in the base or discarded.
    floor: RwLock<BlockHeight>,
    /// The holds of stated rows whose legs no entry holds, by
    /// transaction. A transaction's reservation is held by its entry's
    /// pending leg, by that entry's `retiring`, or here, and never by two
    /// of them. Taken after `entries` wherever both are.
    stated: RwLock<BTreeMap<TxHash, StatedHold>>,
}

impl<S> TickChain<S>
where
    S: VersionedStore,
{
    /// Create an empty tick chain over the given base storage.
    ///
    /// Seeded from the store's committed tip, not from genesis: a
    /// restarted node's base already carries everything up to it, and a
    /// read anchored below the store's retention floor is a panic.
    pub fn new(base: Arc<S>) -> Self {
        let persisted = base.jmt_height();
        Self {
            base,
            entries: RwLock::new(BTreeMap::new()),
            persisted: RwLock::new(persisted),
            floor: RwLock::new(BlockHeight::GENESIS),
            stated: RwLock::new(BTreeMap::new()),
        }
    }

    /// Hold the reservation of every stated row of `rows` whose leg no
    /// entry holds: a replica resuming on a store, or seated over one it
    /// imported, ran none of the ticks that stated them, and at a
    /// recovery's crossing a replica may hold no run of a tick at or below
    /// the floor that stated a row the crossing keeps. The loop seeds
    /// from its replica's member rows when it builds and on each floor
    /// raise.
    ///
    /// Rows read ahead of the chain's base are safe to seed from: a hold
    /// counts only against a view whose base holds its row stated in its
    /// tick.
    ///
    /// What a completed member holds is what it declared, so the row's
    /// own holds state it exactly. A row already held here is left as it
    /// is.
    pub fn seed_stated(&self, rows: &MemberIndex) {
        let shard = rows.shard();
        let entries = write_or_recover(&self.entries);
        let mut stated = write_or_recover(&self.stated);
        for row in rows.members.values() {
            let RowState::Stated { tick, .. } = row.state else {
                continue;
            };
            if entries.values().any(|entry| entry.holds_leg(row.tx)) {
                continue;
            }
            let reserved = declared_reservations(&row.holds);
            if reserved.is_empty() {
                continue;
            }
            stated.entry(row.tx).or_insert(StatedHold {
                tick,
                shard,
                reserved,
            });
        }
        drop(stated);
        drop(entries);
    }

    /// Hand each stated hold of the tick at `height` whose leg `entry`
    /// now holds over to it.
    fn yield_stated_to(&self, height: BlockHeight, entry: &TickEntry) {
        write_or_recover(&self.stated)
            .retain(|tx_hash, hold| hold.tick != height || !entry.holds_leg(*tx_hash));
    }

    /// Append the output of the tick at `height`, as the shard's replica
    /// ran it.
    ///
    /// A tick's output is a pure function of the committed chain prefix,
    /// so a repeat append of a height carries byte-identical content and
    /// the first append is the whole of it — which is why a repeat is
    /// dropped rather than folded. Folding it would leave an exclusive
    /// write unchanged and apply every movement it carries a second
    /// time, and it would re-add ticks the chain has since resolved.
    ///
    /// Dropped too at or below the floor: a tick there is one a
    /// recovery's crossing let go of, its run in flight when the floor
    /// rose.
    ///
    /// `fates` are the resolutions the replica held for the tick when it
    /// dispatched the run, applied under the acquisition that seats the
    /// output. A tick can run after its fate committed — a lagging tick
    /// queue — and the base then already carries what the run leaves.
    /// Every later read ranges over this entry, so one landing unstamped,
    /// to be resolved by a later call, would be folded over that base by
    /// any read in between.
    pub fn append(&self, height: BlockHeight, output: TickOutput, fates: &[TickResolution]) {
        let mut entries = write_or_recover(&self.entries);
        let floor = *read_or_recover(&self.floor);
        if height <= floor {
            return;
        }
        let entry = entries
            .entry(height)
            .or_insert_with(|| TickEntry::from_output(output));
        for fate in fates {
            entry.resolve(height, fate);
        }
        self.yield_stated_to(height, entry);
        drop(entries);
    }

    /// Withdraw every contribution at or below `floor` from the reads of
    /// every tick above it: the parent height of a halt recovery's
    /// crossing block, a block of `shard`'s.
    ///
    /// Every entry at or below the floor goes whole, readable or pending,
    /// and nothing else: every contribution at or below it is in the base
    /// or discarded, and no run above it is under way yet. The base is
    /// held at the floor, so the first tick past the crossing reads a
    /// baseline still there.
    ///
    /// The holds of the pending legs it drops stay, as stated holds: the
    /// crossing keeps each stated row, and a legs half above the floor
    /// still settles it. A leg whose row the crossing releases holds
    /// nothing against any view past the floor, since no base there holds
    /// its row stated. A kept row whose leg no entry here held is
    /// [`seed_stated`](Self::seed_stated)'s to hold.
    ///
    /// A floor at or below the current one does nothing, so a repeated
    /// raise applies once.
    pub fn raise_floor(&self, floor: BlockHeight, shard: ShardId) {
        let mut entries = write_or_recover(&self.entries);
        {
            let mut current = write_or_recover(&self.floor);
            if floor <= *current {
                return;
            }
            *current = floor;
        }
        debug_assert!(
            entries.range(floor.next()..).next().is_none(),
            "a run above the floor is under way at its first raise",
        );
        let kept = entries.split_off(&floor.next());
        let dropped = std::mem::replace(&mut *entries, kept);
        {
            let mut stated = write_or_recover(&self.stated);
            for (tick, entry) in dropped {
                for (tx_hash, leg) in entry.pending {
                    if leg.reserved.is_empty() {
                        continue;
                    }
                    stated.entry(tx_hash).or_insert(StatedHold {
                        tick,
                        shard,
                        reserved: leg.reserved,
                    });
                }
            }
        }
        drop(entries);
        let persisted = *read_or_recover(&self.persisted);
        self.base.hold_retention_at(persisted.min(floor));
    }

    /// Resolve a tick's fate: a settled verdict promotes each member's
    /// surviving side into the readable fold, an abort drops its entries.
    ///
    /// The entry is the one at the tick's own height, because a tick's
    /// output is appended there and nowhere else — which it is because a
    /// tick attests exactly what it ran.
    ///
    /// Idempotent and tolerant of unknown ticks: the entry may already be
    /// evicted (resolved and persisted) or torn down at a reshape
    /// boundary.
    ///
    /// A [`TickResolution::Restored`] or [`TickResolution::RestoredLegs`]
    /// seats an entry rather than only resolving one, because the tick it
    /// speaks for is one no run of this replica's produced. It never
    /// overwrites what a run did produce: where both exist the run is the
    /// same function of the same chain prefix, and the receipts add
    /// nothing to it.
    pub fn resolve(&self, tick_id: &TickId, resolution: &TickResolution) {
        let mut entries = write_or_recover(&self.entries);
        let tick = tick_id.block_height();
        let entry = match resolution {
            TickResolution::Restored { .. } | TickResolution::RestoredLegs { .. } => {
                if tick <= *read_or_recover(&self.floor) {
                    return;
                }
                entries.entry(tick).or_insert_with(TickEntry::empty)
            }
            TickResolution::Settled { .. } | TickResolution::Abandoned { .. } => {
                let Some(entry) = entries.get_mut(&tick) else {
                    return;
                };
                entry
            }
        };
        entry.resolve(tick, resolution);
        if matches!(resolution, TickResolution::RestoredLegs { .. }) {
            self.yield_stated_to(tick, entry);
        }
        drop(entries);
    }

    /// Record what the base now carries and drop every tick a future read
    /// can no longer need. Called on `BlockPersisted`, and once when the
    /// loop opens the chain.
    ///
    /// `executed` is the lowest baseline the shard's replica still reads,
    /// its execution coordinator's `baseline_floor()`. The chain cannot
    /// learn it from its appends, which say only how far execution has
    /// run, not which baselines queued ticks still read from.
    ///
    /// The eviction floor is the lower of what has persisted and
    /// `executed`, and the second half is load-bearing. A contribution
    /// enters the base at the height its tick *settled*, which can be
    /// above the anchor a still-queued tick will read from — so dropping
    /// on persistence alone lets eviction outrun a lagging tick queue,
    /// and that tick then finds neither the fold nor a base old enough to
    /// hold it. Two replicas at different execution positions would
    /// derive different receipts from one committed chain.
    ///
    /// The base is held at that same floor. A fold resolves against the
    /// base as of [`Self::view_at`]'s anchor, which is never below it, so
    /// retaining the fold and letting the history under it be collected
    /// answers a queued tick with a panic rather than a baseline — and
    /// the retention horizon alone permits exactly that, because it is
    /// measured against a tip clock that a halt recovery moves by the
    /// whole halt.
    ///
    /// A stated hold drops at the same floor, once the base there holds
    /// its row in no tick of its own: every view at or above the floor
    /// reads the row's end through the base, and a tick still queued
    /// below the end reads the hold.
    pub fn prune_persisted(&self, persisted: BlockHeight, executed: BlockHeight) {
        {
            let mut recorded = write_or_recover(&self.persisted);
            *recorded = (*recorded).max(persisted);
        }
        let floor = persisted.min(executed);
        self.base.hold_retention_at(floor);
        let mut entries = write_or_recover(&self.entries);
        entries.retain(|_, entry| !entry.covered_by(floor));
        let mut stated = write_or_recover(&self.stated);
        // Taken only for a hold at or below the floor: a floor below every
        // hold's tick may sit under the store's retention.
        let mut base = None;
        stated.retain(|tx_hash, hold| {
            floor < hold.tick
                || hold.held_in(
                    base.get_or_insert_with(|| self.base.snapshot_at(floor)),
                    *tx_hash,
                )
        });
        drop(stated);
        drop(entries);
    }

    /// The highest height the settled base is known to carry: the
    /// highest a tick's baseline may be read at.
    #[must_use]
    pub fn persisted(&self) -> BlockHeight {
        *read_or_recover(&self.persisted)
    }

    /// Tear the chain down. A reshape boundary terminates the shard's
    /// chain; successors seed from settled state, never from tick
    /// outputs.
    pub fn clear(&self) {
        let mut entries = write_or_recover(&self.entries);
        entries.clear();
        write_or_recover(&self.stated).clear();
        drop(entries);
    }

    /// Number of retained ticks (diagnostics).
    #[must_use]
    pub fn len(&self) -> usize {
        read_or_recover(&self.entries).len()
    }

    /// Whether any tick is retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        read_or_recover(&self.entries).is_empty()
    }

    /// Build the baseline view for the tick after `tick`: every retained
    /// contribution at or below `tick` the base does not already carry,
    /// over the base as of `tick`.
    ///
    /// The base is read at `tick` rather than at the live tip. Execution
    /// runs behind consensus, so a replica whose tick queue lags has
    /// already persisted settlements belonging to *later* ticks, which
    /// 2f+1 other replicas certified without waiting for it; reading the
    /// live base would fold those into this tick's baseline and split its
    /// receipts from the committee's.
    ///
    /// It is read at `tick` and never below it, so the base has to carry
    /// `tick` already. A block's commit writes into the base what no
    /// entry here carries — an owed credit, a retired crossing record,
    /// an abandonment's charge, the fee holds of the transactions it
    /// includes — and settles an unjudged debit against what its vault
    /// held at that commit. The overlay restates none of that, so over a
    /// base short of `tick` the view would be another baseline than the
    /// one a replica that had written `tick` reads.
    /// The caller waits for the write instead: a tick is dispatched only
    /// once the block below it is persisted.
    ///
    /// Anchoring alone is not enough, because the base as of `tick`
    /// holds every contribution settled at or below it while the entry
    /// may still hold the same one — harmless for an absolute and wrong
    /// for a movement. So the two are made disjoint instead: the base
    /// covers every contribution settled at or below `tick`, and the
    /// overlay covers the rest.
    ///
    /// The view is one layer per tick rather than one merged write set,
    /// and the chain holds those layers rather than the view: a tick's
    /// fold is composed once per partition it is read under, not once
    /// per dispatch. The reader resolves a key across the layers, which
    /// costs it the retained tick count on the keys it actually asks for
    /// instead of costing every dispatch the whole retained content.
    ///
    /// Takes the write lock because refreshing those folds is part of the
    /// read. A fold being refreshed reads the base as of `tick` for each
    /// cell its contributions delete, to tell which of them release a
    /// fee hold the base still counts; no path of the base takes this
    /// lock.
    ///
    /// # Panics
    ///
    /// Panics if the base is not known to carry `tick`.
    pub fn view_at(&self, tick: BlockHeight) -> TickView<S> {
        let mut overlays: Vec<Arc<StateWrites>> = Vec::new();
        let mut holds = ProvisionalHolds::new();
        let mut released = HeldByTx::new();
        // Taken by the first fold that has a deletion to ask about, and
        // shared by the rest.
        let mut base_at_tick: Option<S::Snapshot<'_>> = None;
        let mut release = |key: SubstateKey| {
            let base = base_at_tick.get_or_insert_with(|| self.base.snapshot_at(tick));
            release_of(base, key)
        };
        // One acquisition for the layers and the holds. A resolution
        // landing between two reads would drop a leg's hold without the
        // debit it stood for reaching the overlay, and the reader would
        // spend a balance twice.
        let mut entries = write_or_recover(&self.entries);
        let persisted = *read_or_recover(&self.persisted);
        assert!(
            tick <= persisted,
            "BFT CRITICAL: a baseline read at {tick} over a base written through {persisted}"
        );
        // Ascending, so a later tick's layer sits above an earlier one's
        // and the reader can walk them back.
        // The tick this view is the baseline for: a verdict committed
        // at its height is one it reads resolved.
        let reader = tick.next();
        for (_, entry) in entries.range_mut(..=tick) {
            let fold = entry.fold_at(tick, reader, &mut release);
            overlays.extend(fold.layer());
            for (vault, by_tx) in &fold.released {
                released
                    .entry(*vault)
                    .or_default()
                    .extend(by_tx.iter().map(|(tx_hash, ceiling)| (*tx_hash, *ceiling)));
            }
            let pending = entry
                .pending
                .values()
                .map(|leg| (leg.tx_hash, &leg.reserved));
            let retiring = entry
                .retiring
                .iter()
                .filter(|(_, (height, _))| reader < *height)
                .map(|(tx_hash, (_, reserved))| (*tx_hash, reserved));
            for (tx_hash, reserved) in pending.chain(retiring) {
                for (cell, amount) in reserved {
                    *holds.entry(*cell).or_default().entry(tx_hash).or_default() += *amount;
                }
            }
        }
        // A stated hold holds while the base at `tick` holds its row
        // stated: from that height on the base carries the row's end. The
        // stating half commits above its tick, so no base at or below the
        // tick holds the row stated.
        let stated = read_or_recover(&self.stated);
        for (tx_hash, hold) in stated.iter().filter(|(_, hold)| hold.tick < tick) {
            let base = base_at_tick.get_or_insert_with(|| self.base.snapshot_at(tick));
            if !hold.stated_in(base, *tx_hash) {
                continue;
            }
            for (cell, amount) in &hold.reserved {
                *holds.entry(*cell).or_default().entry(*tx_hash).or_default() += *amount;
            }
        }
        drop(stated);
        drop(entries);
        TickView {
            base: Arc::clone(&self.base),
            anchor: tick,
            overlays: Arc::new(overlays),
            holds: Arc::new(holds),
            released: Arc::new(released),
        }
    }
}

/// Read view over the tick chain's folds at one anchor.
///
/// Falls through to the base as of that anchor. The engine's eager
/// pre-read consumes this via [`Self::snapshot`], which is the view's
/// only read path — a baseline that could be read unanchored would not
/// be deterministic.
pub struct TickView<S> {
    base: Arc<S>,
    anchor: BlockHeight,
    /// One retained tick's fold per layer, ascending — a later tick's
    /// writes sit above an earlier tick's.
    overlays: Arc<Vec<Arc<StateWrites>>>,
    holds: Arc<ProvisionalHolds>,
    /// The fee holds the layers delete that the base at the anchor
    /// still holds.
    released: Arc<HeldByTx>,
}

impl<S: VersionedStore> TickView<S> {
    /// Snapshot for batch execution: the folds over the base as of this
    /// view's anchor height.
    #[must_use]
    pub fn snapshot(&self) -> TickViewSnapshot<S::Snapshot<'_>> {
        TickViewSnapshot {
            base_snapshot: self.base.snapshot_at(self.anchor),
            overlays: Arc::clone(&self.overlays),
        }
    }

    /// What unresolved legs hold against the cells this view reads.
    ///
    /// The companion to the overlay: the overlay is what a reader may
    /// see, and this is what it may not spend of what it sees. A leg
    /// holds a debit it was granted; the ceilings transactions hold for
    /// their fees are [`Self::fee_holds`].
    #[must_use]
    pub fn holds(&self) -> Arc<ProvisionalHolds> {
        Arc::clone(&self.holds)
    }

    /// The fee holds standing for the tick this view is the baseline
    /// of, whose block carries `included`, under `prefix`.
    ///
    /// Off the same anchor and the same layers as [`Self::snapshot`], so
    /// a burn the layers carry and the hold it came out of are never
    /// both counted against one vault.
    #[must_use]
    pub fn fee_holds(
        &self,
        included: &[FeeTerms],
        prefix: &NibblePath,
    ) -> StandingFeeHolds<S::Snapshot<'_>> {
        StandingFeeHolds::new(
            self.base.snapshot_at(self.anchor),
            Arc::clone(&self.released),
            included,
            prefix,
        )
    }
}

/// Snapshot from a [`TickView`] — the same layers on the base storage's
/// snapshot.
pub struct TickViewSnapshot<Snap> {
    base_snapshot: Snap,
    overlays: Arc<Vec<Arc<StateWrites>>>,
}

impl<Snap: Substates> Substates for TickViewSnapshot<Snap> {
    fn cell(&self, key: SubstateKey) -> Option<Vec<u8>> {
        // Topmost layer down to the first exclusive write: that write
        // states the cell outright, so nothing below it is still
        // reachable through it. A movement in the same layer sits above
        // that write.
        let mut from = 0;
        let mut written: Option<&Option<Vec<u8>>> = None;
        let mut moved = false;
        for (index, overlay) in self.overlays.iter().enumerate().rev() {
            moved |= overlay.movements.contains_key(&key);
            if let Some(change) = overlay.cells.get(&key) {
                from = index;
                written = Some(change);
                break;
            }
        }
        if !moved {
            return written.map_or_else(|| self.base_snapshot.cell(key), Clone::clone);
        }
        // A cell the layers only moved resolves here, where the base it
        // moved from is finally in reach; one an exclusive write also
        // reached moves from that write instead.
        let mut held = written
            .cloned()
            .unwrap_or_else(|| self.base_snapshot.cell(key))
            .as_deref()
            .and_then(read_amount)
            .unwrap_or(0);
        // One layer at a time and bottom up, each layer's judged credit
        // landing what fits under the ceiling before the next layer's
        // judged debit is taken, then every layer's unjudged charge taken
        // once from what that leaves. The layers a view holds settle
        // whole and in tick order, several to a block, and settlement
        // nets a block's layers before it caps or floors. So the read is
        // a lower bound on what settlement leaves for any grouping of
        // these layers into blocks: landing a credit before a later
        // debit leaves no more than netting the two first, a cap taken
        // before an unjudged charge leaves no more than one taken after
        // it, and a floor only raises what settlement leaves. A kernel
        // judging a debit against this read never admits one settlement
        // cannot pay. The read is exact wherever neither the cap nor the
        // floor bites.
        let mut unjudged: u128 = 0;
        for overlay in &self.overlays[from..] {
            let Some(movement) = overlay.movements.get(&key) else {
                continue;
            };
            unjudged = unjudged.saturating_add(movement.unjudged_debit);
            let judged = Movement {
                unjudged_debit: 0,
                ..*movement
            };
            held = judged.apply(held).unwrap_or_else(|| {
                panic!(
                    "BFT CRITICAL: a certified debit runs past what {key:?} holds: held {held}, \
                     moved {movement:?}"
                )
            });
        }
        amount_cell(held.saturating_sub(unjudged)).map(|cell| cell.to_vec())
    }

    fn entries_in_range(
        &self,
        owner: Address,
        collection: CollectionId,
        lo: u128,
        hi: u128,
        limit: usize,
    ) -> Vec<(u128, Vec<u8>)> {
        // Collapsed bottom layer up, so a later tick's write wins the
        // order key — the widening rule the merge applies needs one
        // overlay, and only the interval asked for is ever collapsed.
        let mut overlay: BTreeMap<u128, Option<Vec<u8>>> = BTreeMap::new();
        for layer in self.overlays.iter() {
            overlay.extend(entry_overlay_range(
                &layer.entries,
                owner,
                collection,
                lo,
                hi,
            ));
        }
        merge_entry_overlay(
            &self.base_snapshot,
            overlay.into_iter().collect(),
            owner,
            collection,
            lo,
            hi,
            limit,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use hyperscale_hbor::{Capped, to_vec};
    use hyperscale_types::{
        AbortCharge, Address, AddressClass, Deadline, DeclaredRange, EntryKey, GlobalReceiptHash,
        Hash, Joins, LocalKey, MemberCollection, Movement, Owes, ResourceAddr, Settlement,
        StateRoot, WeightedTimestamp, encode_amount,
    };
    use hyperscale_vm_effects::{FeeHold, ProtocolHasher, fee_hold_total_key};

    use super::*;
    use crate::SubstateStore;
    use crate::shard::fee_holds::FeeHoldReading;
    use crate::shard::members::MemberRow;
    use crate::shard::writes::settle_writes;

    /// What every cell these fixtures move holds.
    const RESOURCE: ResourceAddr = ResourceAddr::new([0xE1; 31]);
    use crate::lock_recover::lock_or_recover;

    /// One height's entry writes, a `None` deleting its entry.
    type EntryWrites = Vec<(EntryKey, Option<Vec<u8>>)>;

    /// A base built from settled write sets at heights, readable as of
    /// any anchor — the store's history without the JMT.
    struct StubStore {
        history: BTreeMap<BlockHeight, HashMap<SubstateKey, Vec<u8>>>,
        tip: BlockHeight,
        /// Anchor heights `snapshot_at` was asked for, so a test can pin
        /// which version a tick read the base at.
        anchors: Mutex<Vec<BlockHeight>>,
        /// Heights the chain held history at, so a test can pin the
        /// floor a pruning publishes.
        holds: Mutex<Vec<BlockHeight>>,
        /// The entries each height writes.
        entries: BTreeMap<BlockHeight, EntryWrites>,
    }

    impl StubStore {
        /// The height [`Self::with_cell`] is written through: above every
        /// tick a fixture over it reads.
        const WRITTEN: BlockHeight = BlockHeight::new(16);

        /// A base holding `value` at `key` from genesis, with nothing
        /// settled since, written through [`Self::WRITTEN`].
        fn with_cell(key: SubstateKey, value: &[u8]) -> Self {
            Self {
                history: BTreeMap::from([(
                    BlockHeight::GENESIS,
                    HashMap::from([(key, value.to_vec())]),
                )]),
                tip: Self::WRITTEN,
                anchors: Mutex::new(Vec::new()),
                holds: Mutex::new(Vec::new()),
                entries: BTreeMap::new(),
            }
        }

        /// A base holding `genesis` at `key`, which a settlement replaces
        /// with `settled` at `height` — the store's tip.
        fn settling(key: SubstateKey, genesis: &[u8], height: BlockHeight, settled: &[u8]) -> Self {
            Self {
                history: BTreeMap::from([
                    (
                        BlockHeight::GENESIS,
                        HashMap::from([(key, genesis.to_vec())]),
                    ),
                    (height, HashMap::from([(key, settled.to_vec())])),
                ]),
                tip: height,
                anchors: Mutex::new(Vec::new()),
                holds: Mutex::new(Vec::new()),
                entries: BTreeMap::new(),
            }
        }

        fn cells_at(&self, height: BlockHeight) -> HashMap<SubstateKey, Vec<u8>> {
            let mut cells = HashMap::new();
            for (_, settled) in self.history.range(..=height) {
                cells.extend(settled.iter().map(|(k, v)| (*k, v.clone())));
            }
            cells
        }

        fn entries_at(&self, height: BlockHeight) -> BTreeMap<EntryKey, Vec<u8>> {
            let mut entries = BTreeMap::new();
            for (_, written) in self.entries.range(..=height) {
                for (key, value) in written {
                    match value {
                        Some(bytes) => entries.insert(*key, bytes.clone()),
                        None => entries.remove(key),
                    };
                }
            }
            entries
        }

        fn at(&self, height: BlockHeight) -> StubSnapshot {
            StubSnapshot(self.cells_at(height), self.entries_at(height))
        }
    }

    impl Substates for StubStore {
        fn cell(&self, key: SubstateKey) -> Option<Vec<u8>> {
            self.cells_at(self.tip).get(&key).cloned()
        }

        fn entries_in_range(
            &self,
            _owner: Address,
            _collection: CollectionId,
            _lo: u128,
            _hi: u128,
            _limit: usize,
        ) -> Vec<(u128, Vec<u8>)> {
            Vec::new()
        }
    }

    struct StubSnapshot(HashMap<SubstateKey, Vec<u8>>, BTreeMap<EntryKey, Vec<u8>>);
    use crate::Anchored;

    impl Anchored for StubSnapshot {
        fn anchor(&self) -> BlockHeight {
            BlockHeight::GENESIS
        }
    }

    impl Substates for StubSnapshot {
        fn cell(&self, key: SubstateKey) -> Option<Vec<u8>> {
            self.0.get(&key).cloned()
        }

        fn entries_in_range(
            &self,
            owner: Address,
            collection: CollectionId,
            lo: u128,
            hi: u128,
            limit: usize,
        ) -> Vec<(u128, Vec<u8>)> {
            self.1
                .iter()
                .filter(|(key, _)| {
                    key.owner == owner
                        && key.collection == collection
                        && (lo..=hi).contains(&key.order)
                })
                .take(limit)
                .map(|(key, bytes)| (key.order, bytes.clone()))
                .collect()
        }
    }

    impl VersionedStore for StubStore {
        fn retention_floor(&self) -> u64 {
            0
        }

        fn snapshot_held_at(&self, height: BlockHeight) -> Option<Self::Snapshot<'_>> {
            (height <= self.tip).then(|| self.snapshot_at(height))
        }

        fn snapshot_at(&self, height: BlockHeight) -> Self::Snapshot<'_> {
            lock_or_recover(&self.anchors).push(height);
            self.at(height)
        }
        fn substate_bytes_at(&self, _height: BlockHeight) -> Option<u64> {
            None
        }

        fn hold_retention_at(&self, height: BlockHeight) {
            lock_or_recover(&self.holds).push(height);
        }
    }

    impl SubstateStore for StubStore {
        type Snapshot<'a> = StubSnapshot;
        fn snapshot(&self) -> Self::Snapshot<'_> {
            self.at(self.tip)
        }
        fn jmt_height(&self) -> BlockHeight {
            self.tip
        }
        fn state_root(&self) -> StateRoot {
            StateRoot::ZERO
        }
        fn get_entries_at_height(
            &self,
            _range: DeclaredRange,
            _block_height: BlockHeight,
        ) -> Option<Vec<(u128, Vec<u8>)>> {
            // Stub state holds no entries at any height.
            Some(Vec::new())
        }

        fn get_substate_at_height(
            &self,
            _key: SubstateKey,
            _block_height: BlockHeight,
        ) -> Option<Option<Vec<u8>>> {
            None
        }
    }

    fn key(byte: u8) -> SubstateKey {
        SubstateKey {
            owner: Address::new([byte; 31], AddressClass::Component),
            local: LocalKey([byte; 16]),
        }
    }

    fn writes(cells: &[(SubstateKey, Option<&[u8]>)]) -> StateWrites {
        StateWrites {
            cells: cells
                .iter()
                .map(|(k, v)| (*k, v.map(<[u8]>::to_vec)))
                .collect(),
            movements: BTreeMap::new(),
            entries: BTreeMap::new(),
        }
    }

    /// A receipt that debits `amount` from `cell` — what every fee burn
    /// and every commutative balance change actually carries.
    fn debit(cell: SubstateKey, amount: u128) -> StateWrites {
        let mut moved = StateWrites::default();
        moved.movements.insert(
            cell,
            Movement {
                resource: RESOURCE,
                credit: 0,
                debit: amount,
                unjudged_debit: 0,
            },
        );
        moved
    }

    /// A receipt that credits `amount` to `cell`.
    fn credit(cell: SubstateKey, amount: u128) -> StateWrites {
        let mut moved = StateWrites::default();
        moved.movements.insert(
            cell,
            Movement {
                resource: RESOURCE,
                credit: amount,
                debit: 0,
                unjudged_debit: 0,
            },
        );
        moved
    }

    fn amount(cell: &[u8]) -> u128 {
        read_amount(cell).expect("an amount cell")
    }

    /// The shard every fixture's ticks are of.
    const SHARD: ShardId = ShardId::leaf(0, 0);

    fn tick(height: u64) -> TickId {
        TickId::new(SHARD, BlockHeight::new(height))
    }

    fn tx(byte: u8) -> TxHash {
        TxHash::from(Hash::from_bytes(&[byte]))
    }

    #[test]
    fn determined_writes_chain_and_shadow_base() {
        let chain = TickChain::new(Arc::new(StubStore::with_cell(key(1), b"base")));
        chain.append(
            BlockHeight::new(1),
            TickOutput {
                determined: vec![(
                    tx(1),
                    writes(&[(key(1), Some(b"one")), (key(2), Some(b"two"))]),
                )],
                provisional: Vec::new(),
            },
            &[],
        );
        chain.append(
            BlockHeight::new(2),
            TickOutput {
                determined: vec![(tx(2), writes(&[(key(1), None)]))],
                provisional: Vec::new(),
            },
            &[],
        );

        // Anchored below tick 2: tick 1's write shadows base.
        let view = chain.view_at(BlockHeight::new(1));
        assert_eq!(view.snapshot().cell(key(1)), Some(b"one".to_vec()));
        assert_eq!(view.snapshot().cell(key(2)), Some(b"two".to_vec()));

        // Anchored at tick 2: the removal wins; untouched key falls through.
        let view = chain.view_at(BlockHeight::new(2));
        assert_eq!(view.snapshot().cell(key(1)), None);
        assert_eq!(view.snapshot().cell(key(2)), Some(b"two".to_vec()));
    }

    /// A determined fold carries what its receipts carry, movements
    /// included. A fee burn is a debit and every payment moves a balance,
    /// so a fold that kept only the absolutes would hold nothing at all
    /// for ordinary traffic — and the next tick would read a balance its
    /// predecessor had already spent.
    #[test]
    fn a_determined_movement_reaches_the_next_tick() {
        let store = Arc::new(StubStore::with_cell(key(1), encode_amount(1_000).as_ref()));
        let chain = TickChain::new(store);
        chain.append(
            BlockHeight::new(1),
            TickOutput {
                determined: vec![(tx(1), debit(key(1), 300))],
                provisional: Vec::new(),
            },
            &[],
        );

        let view = chain.view_at(BlockHeight::new(1));
        assert_eq!(amount(&view.snapshot().cell(key(1)).unwrap()), 700);
    }

    /// Two ticks crediting one vault, each within `u128` on its own,
    /// read the vault at `u128::MAX`, as settlement lands them.
    #[test]
    fn credits_past_u128_across_ticks_read_at_u128_max() {
        let store = Arc::new(StubStore::with_cell(
            key(1),
            encode_amount(u128::MAX - 10).as_ref(),
        ));
        let chain = TickChain::new(store);
        for member in [1, 2] {
            chain.append(
                BlockHeight::new(u64::from(member)),
                TickOutput {
                    determined: vec![(tx(member), credit(key(1), 6))],
                    provisional: Vec::new(),
                },
                &[],
            );
        }

        let view = chain.view_at(BlockHeight::new(2));
        assert_eq!(amount(&view.snapshot().cell(key(1)).unwrap()), u128::MAX);
    }

    /// Over a full base, a tick's credit and a later tick's debit of the
    /// same amount read the vault below the ceiling: the credit burns
    /// before the debit is taken, as settlement lands them, so the next
    /// tick never sees a balance settlement does not leave.
    #[test]
    fn a_burned_credit_leaves_a_later_debit_below_the_ceiling() {
        let store = Arc::new(StubStore::with_cell(
            key(1),
            encode_amount(u128::MAX).as_ref(),
        ));
        let chain = TickChain::new(store);
        for (member, moved) in [(1, credit(key(1), 5)), (2, debit(key(1), 5))] {
            chain.append(
                BlockHeight::new(u64::from(member)),
                TickOutput {
                    determined: vec![(tx(member), moved)],
                    provisional: Vec::new(),
                },
                &[],
            );
        }

        let view = chain.view_at(BlockHeight::new(2));
        assert_eq!(
            amount(&view.snapshot().cell(key(1)).unwrap()),
            u128::MAX - 5
        );
    }

    /// A tick's credit into a vault the base already holds full reads
    /// the vault full: the credit burns rather than halting the read.
    #[test]
    fn a_credit_over_a_full_vault_reads_it_full() {
        let store = Arc::new(StubStore::with_cell(
            key(1),
            encode_amount(u128::MAX).as_ref(),
        ));
        let chain = TickChain::new(store);
        chain.append(
            BlockHeight::new(1),
            TickOutput {
                determined: vec![(tx(1), credit(key(1), 5))],
                provisional: Vec::new(),
            },
            &[],
        );

        let view = chain.view_at(BlockHeight::new(1));
        assert_eq!(amount(&view.snapshot().cell(key(1)).unwrap()), u128::MAX);
    }

    /// An exclusive write states the cell outright, so the movements of
    /// every tick beneath it are out of reach — reading through to them
    /// would apply a debit the write has already accounted for.
    #[test]
    fn a_later_ticks_write_supersedes_an_earlier_ticks_movement() {
        let store = Arc::new(StubStore::with_cell(key(1), encode_amount(1_000).as_ref()));
        let chain = TickChain::new(store);
        chain.append(
            BlockHeight::new(1),
            TickOutput {
                determined: vec![(tx(1), debit(key(1), 300))],
                provisional: Vec::new(),
            },
            &[],
        );
        chain.append(
            BlockHeight::new(2),
            TickOutput {
                determined: vec![(
                    tx(2),
                    writes(&[(key(1), Some(encode_amount(500).as_ref()))]),
                )],
                provisional: Vec::new(),
            },
            &[],
        );

        let view = chain.view_at(BlockHeight::new(2));
        assert_eq!(amount(&view.snapshot().cell(key(1)).unwrap()), 500);
    }

    /// The other order: a movement above an exclusive write moves from
    /// that write rather than from the base, so the read has to reach the
    /// write beneath it and stop exactly there.
    #[test]
    fn a_movement_moves_from_an_earlier_ticks_write() {
        let store = Arc::new(StubStore::with_cell(key(1), encode_amount(1_000).as_ref()));
        let chain = TickChain::new(store);
        chain.append(
            BlockHeight::new(1),
            TickOutput {
                determined: vec![(
                    tx(1),
                    writes(&[(key(1), Some(encode_amount(500).as_ref()))]),
                )],
                provisional: Vec::new(),
            },
            &[],
        );
        chain.append(
            BlockHeight::new(2),
            TickOutput {
                determined: vec![(tx(2), debit(key(1), 200))],
                provisional: Vec::new(),
            },
            &[],
        );

        let view = chain.view_at(BlockHeight::new(2));
        assert_eq!(amount(&view.snapshot().cell(key(1)).unwrap()), 300);
    }

    #[test]
    fn movements_compose_across_ticks() {
        let store = Arc::new(StubStore::with_cell(key(1), encode_amount(1_000).as_ref()));
        let chain = TickChain::new(store);
        for (height, member, moved) in [(1u64, 1u8, 100u128), (2, 2, 200)] {
            chain.append(
                BlockHeight::new(height),
                TickOutput {
                    determined: vec![(tx(member), debit(key(1), moved))],
                    provisional: Vec::new(),
                },
                &[],
            );
        }

        let view = chain.view_at(BlockHeight::new(2));
        assert_eq!(amount(&view.snapshot().cell(key(1)).unwrap()), 700);
    }

    /// A tick settles in halves, so one entry holds contributions the
    /// base gains at different heights. What a read derives is the same
    /// wherever persistence sits among them: a tick reads each leg settled
    /// at or below its own height, from the fold below the leg's settling
    /// height and from the base at or above it, and never from both.
    #[test]
    fn each_contribution_leaves_the_fold_at_its_own_settling_height() {
        let store = Arc::new(StubStore {
            history: [
                (BlockHeight::GENESIS, 1_000u128),
                (BlockHeight::new(5), 900),
                (BlockHeight::new(9), 700),
            ]
            .into_iter()
            .map(|(height, held)| {
                (
                    height,
                    HashMap::from([(key(1), encode_amount(held).as_ref().to_vec())]),
                )
            })
            .collect(),
            tip: BlockHeight::new(9),
            anchors: Mutex::new(Vec::new()),
            holds: Mutex::new(Vec::new()),
            entries: BTreeMap::new(),
        });
        let chain = TickChain::new(store);
        let w = tick(3);
        chain.append(
            BlockHeight::new(3),
            TickOutput {
                determined: Vec::new(),
                provisional: [(tx(7), 100u128), (tx(8), 200)]
                    .into_iter()
                    .map(|(tx_hash, moved)| ProvisionalTx {
                        tx_hash,
                        writes: Some(debit(key(1), moved)),
                        reserve: None,
                        reserved: BTreeMap::new(),
                    })
                    .collect(),
            },
            &[],
        );
        // Each leg's counterpart certifies in a block of its own.
        for (member, height) in [(tx(7), 5u64), (tx(8), 9)] {
            chain.resolve(
                &w,
                &TickResolution::Settled {
                    height: BlockHeight::new(height),
                    members: BTreeSet::from([member]),
                    aborted: BTreeSet::new(),
                },
            );
        }
        chain.prune_persisted(BlockHeight::new(10), BlockHeight::new(3));

        // The tick at the first settlement, between them, above both —
        // then back down, because a queued tick anchors below a
        // persistence that has already moved past it.
        for (anchor, held) in [(4u64, 900), (6, 900), (10, 700), (6, 900), (4, 900)] {
            let view = chain.view_at(BlockHeight::new(anchor));
            assert_eq!(
                amount(&view.snapshot().cell(key(1)).unwrap()),
                held,
                "anchored at {anchor}"
            );
        }
    }

    /// A tick the chain never ran folds from the receipts that settled
    /// it, and only below the height they committed at.
    ///
    /// The case is a replay reaching further back than the store answers
    /// a historical read at: those ticks compose and none of them runs,
    /// so a tick the replay does run below the height one of them settled
    /// at reads a baseline the base has not caught up to. The receipts
    /// state what it is missing.
    #[test]
    fn a_restored_tick_folds_until_the_base_carries_it() {
        let store = Arc::new(StubStore {
            history: [
                (BlockHeight::GENESIS, 1_000u128),
                (BlockHeight::new(9), 700),
            ]
            .into_iter()
            .map(|(height, held)| {
                (
                    height,
                    HashMap::from([(key(1), encode_amount(held).as_ref().to_vec())]),
                )
            })
            .collect(),
            tip: BlockHeight::new(9),
            anchors: Mutex::new(Vec::new()),
            holds: Mutex::new(Vec::new()),
            entries: BTreeMap::new(),
        });
        let chain = TickChain::new(store);
        chain.resolve(
            &tick(3),
            &TickResolution::Restored {
                height: BlockHeight::new(9),
                writes: vec![(tx(7), debit(key(1), 300))],
            },
        );
        chain.prune_persisted(BlockHeight::new(9), BlockHeight::GENESIS);

        // Below the settlement and at it, in both directions: one answer.
        for anchor in [4u64, 8, 9, 8, 4] {
            let view = chain.view_at(BlockHeight::new(anchor));
            assert_eq!(
                amount(&view.snapshot().cell(key(1)).unwrap()),
                700,
                "anchored at {anchor}"
            );
        }
    }

    /// A restore never displaces what a run of this replica's produced:
    /// both are the same function of the same chain prefix, so the first
    /// one seated is the whole of it.
    #[test]
    fn a_restore_leaves_a_tick_this_replica_ran_alone() {
        let chain = TickChain::new(Arc::new(StubStore::with_cell(key(1), b"base")));
        chain.append(
            BlockHeight::new(3),
            TickOutput {
                determined: vec![(tx(7), writes(&[(key(1), Some(b"ran"))]))],
                provisional: Vec::new(),
            },
            &[],
        );
        chain.resolve(
            &tick(3),
            &TickResolution::Restored {
                height: BlockHeight::new(9),
                writes: vec![(tx(7), writes(&[(key(1), Some(b"restored"))]))],
            },
        );
        let view = chain.view_at(BlockHeight::new(3));
        assert_eq!(view.snapshot().cell(key(1)).unwrap(), b"ran".to_vec());
    }

    /// An ordered-collection entry is an exclusive write like any other,
    /// so the topmost tick that reached the order key owns it — including
    /// when what it wrote there is a removal.
    #[test]
    fn a_later_tick_owns_an_entry_an_earlier_one_wrote() {
        let chain = TickChain::new(Arc::new(StubStore::with_cell(key(1), b"base")));
        let owner = Address::new([3; 31], AddressClass::Component);
        let collection = CollectionId([4; 16]);
        let entry = |order: u128, value: Option<&[u8]>| {
            let mut written = StateWrites::default();
            written.entries.insert(
                EntryKey {
                    owner,
                    collection,
                    order,
                },
                value.map(<[u8]>::to_vec),
            );
            written
        };
        chain.append(
            BlockHeight::new(1),
            TickOutput {
                determined: vec![
                    (tx(1), entry(1, Some(b"one"))),
                    (tx(2), entry(2, Some(b"two"))),
                ],
                provisional: Vec::new(),
            },
            &[],
        );
        chain.append(
            BlockHeight::new(2),
            TickOutput {
                determined: vec![
                    (tx(3), entry(1, Some(b"rewritten"))),
                    (tx(4), entry(2, None)),
                ],
                provisional: Vec::new(),
            },
            &[],
        );

        let view = chain.view_at(BlockHeight::new(2));
        assert_eq!(
            view.snapshot()
                .entries_in_range(owner, collection, 0, 10, 10),
            vec![(1, b"rewritten".to_vec())],
            "the rewrite wins its key and the removal takes the other",
        );
    }

    /// A tick reads the base at its own height, wherever persistence
    /// sits above it. That keeps a lagging replica — which has already
    /// persisted settlements belonging to ticks it has not run — from
    /// folding them into an earlier tick's baseline.
    #[test]
    fn a_tick_reads_the_base_at_its_own_height() {
        let store = Arc::new(StubStore::settling(
            key(1),
            b"base",
            BlockHeight::new(9),
            b"settled",
        ));
        let chain = TickChain::new(Arc::clone(&store));
        chain.prune_persisted(BlockHeight::new(9), BlockHeight::GENESIS);

        let _ = chain.view_at(BlockHeight::new(4)).snapshot();
        let _ = chain.view_at(BlockHeight::new(9)).snapshot();

        assert_eq!(
            *lock_or_recover(&store.anchors),
            vec![BlockHeight::new(4), BlockHeight::new(9)],
            "the anchor is the tick"
        );
    }

    /// A baseline is never built over a base short of its tick: what the
    /// missing blocks wrote is in no entry, so the view would be another
    /// baseline than the one a replica that had written them reads.
    #[test]
    #[should_panic(expected = "a baseline read at Block(10) over a base written through Block(9)")]
    fn a_baseline_over_a_base_short_of_its_tick_is_refused() {
        let store = Arc::new(StubStore::settling(
            key(1),
            b"base",
            BlockHeight::new(9),
            b"settled",
        ));
        let chain = TickChain::new(store);
        let _ = chain.view_at(BlockHeight::new(10));
    }

    /// The base is held at the floor the folds are evicted at, so no
    /// anchor a queued tick can still name is collected out from under
    /// it. Execution behind the persisted tip is what makes the two
    /// numbers differ, and the hold takes the lower of them.
    #[test]
    fn the_base_is_held_at_the_floor_the_folds_are_evicted_at() {
        let store = Arc::new(StubStore::settling(
            key(1),
            b"base",
            BlockHeight::new(9),
            b"settled",
        ));
        let chain = TickChain::new(Arc::clone(&store));
        chain.append(BlockHeight::new(4), TickOutput::default(), &[]);
        chain.prune_persisted(BlockHeight::new(9), BlockHeight::new(4));

        assert_eq!(
            *lock_or_recover(&store.holds),
            vec![BlockHeight::new(4)],
            "the hold is what has executed, which trails what has persisted"
        );

        chain.append(BlockHeight::new(9), TickOutput::default(), &[]);
        chain.prune_persisted(BlockHeight::new(9), BlockHeight::new(9));

        assert_eq!(
            lock_or_recover(&store.holds).last().copied(),
            Some(BlockHeight::new(9)),
            "execution catching up releases the history it was holding"
        );
    }

    fn determined(cells: &[(SubstateKey, Option<&[u8]>)], by: u8) -> TickOutput {
        TickOutput {
            determined: vec![(tx(by), writes(cells))],
            provisional: Vec::new(),
        }
    }

    fn read_at(chain: &TickChain<StubStore>, tick: u64, cell: SubstateKey) -> Option<Vec<u8>> {
        chain.view_at(BlockHeight::new(tick)).snapshot().cell(cell)
    }

    /// Everything at or below a raised floor goes: no tick above it reads
    /// a contribution the recovery's fresh committee cannot hold.
    #[test]
    fn a_raised_floor_drops_every_entry_at_or_below_it() {
        let chain = TickChain::new(Arc::new(StubStore::with_cell(key(1), b"base")));
        chain.append(
            BlockHeight::new(2),
            determined(&[(key(1), Some(b"two"))], 2),
            &[],
        );
        chain.append(
            BlockHeight::new(3),
            determined(&[(key(2), Some(b"three"))], 3),
            &[],
        );
        assert_eq!(read_at(&chain, 5, key(1)), Some(b"two".to_vec()));

        chain.raise_floor(BlockHeight::new(3), SHARD);
        assert!(
            chain.is_empty(),
            "nothing at or below the floor is retained"
        );
        assert_eq!(read_at(&chain, 5, key(1)), Some(b"base".to_vec()));
        assert_eq!(read_at(&chain, 5, key(2)), None);
    }

    /// The first tick past a recovery's crossing reads the base alone.
    /// The chain holds runs a replica made before the halt, of a tick at
    /// or below the frontier and of one above it, and over the coast
    /// blocks; the crossing raises the floor to its parent, so a read at
    /// the parent sees none of them, a run of a discarded tick landing
    /// after the raise is dropped, and the crossing tick's own run lands.
    #[test]
    fn the_first_tick_past_the_crossing_reads_the_base_alone() {
        let chain = TickChain::new(Arc::new(StubStore::with_cell(key(1), b"base")));
        for (height, value) in [(2u8, &b"frontier"[..]), (4, b"harvested"), (6, b"coast")] {
            chain.append(
                BlockHeight::new(u64::from(height)),
                determined(&[(key(1), Some(value))], height),
                &[],
            );
        }
        assert_eq!(read_at(&chain, 6, key(1)), Some(b"coast".to_vec()));

        let crossing_parent = BlockHeight::new(6);
        chain.raise_floor(crossing_parent, SHARD);
        chain.append(
            BlockHeight::new(5),
            determined(&[(key(1), Some(b"in flight"))], 5),
            &[],
        );
        assert!(chain.is_empty(), "nothing below the crossing is retained");
        assert_eq!(read_at(&chain, 6, key(1)), Some(b"base".to_vec()));

        chain.append(
            BlockHeight::new(7),
            determined(&[(key(2), Some(b"crossing"))], 7),
            &[],
        );
        assert_eq!(read_at(&chain, 7, key(2)), Some(b"crossing".to_vec()));
        assert_eq!(read_at(&chain, 7, key(1)), Some(b"base".to_vec()));
    }

    /// Nothing above the floor is under way at its first raise, and a
    /// later raise drops nothing above it: an entry a run appended and
    /// one receipts seated both stay.
    #[test]
    fn a_later_raise_keeps_every_entry_above_the_floor() {
        let floor = BlockHeight::new(3);
        let chain = TickChain::new(Arc::new(StubStore::with_cell(key(1), b"base")));
        chain.raise_floor(floor, SHARD);
        chain.append(
            BlockHeight::new(5),
            determined(&[(key(1), Some(b"five"))], 5),
            &[],
        );
        chain.resolve(
            &tick(6),
            &TickResolution::Restored {
                height: BlockHeight::new(20),
                writes: vec![(tx(6), writes(&[(key(2), Some(b"six"))]))],
            },
        );
        chain.raise_floor(floor, SHARD);
        chain.raise_floor(BlockHeight::new(2), SHARD);
        assert_eq!(chain.len(), 2, "both entries stay");
        assert_eq!(read_at(&chain, 7, key(1)), Some(b"five".to_vec()));
        assert_eq!(read_at(&chain, 7, key(2)), Some(b"six".to_vec()));
    }

    /// A run at or below the floor lands nothing: its tick is one a
    /// recovery's crossing let go of while the run was in flight. One
    /// above the floor lands.
    #[test]
    fn an_append_at_or_below_the_floor_lands_nothing() {
        let floor = BlockHeight::new(3);
        let chain = TickChain::new(Arc::new(StubStore::with_cell(key(1), b"base")));
        chain.raise_floor(floor, SHARD);
        chain.append(
            BlockHeight::new(3),
            determined(&[(key(1), Some(b"three"))], 3),
            &[],
        );
        assert!(chain.is_empty(), "nothing lands at the floor");
        chain.append(
            BlockHeight::new(5),
            determined(&[(key(1), Some(b"five"))], 5),
            &[],
        );
        assert_eq!(read_at(&chain, 5, key(1)), Some(b"five".to_vec()));
    }

    /// A raise applies once: a second raise at the same floor, or a lower
    /// one, drops nothing appended above it.
    #[test]
    fn raising_the_floor_twice_is_one_raise() {
        let floor = BlockHeight::new(3);
        let chain = TickChain::new(Arc::new(StubStore::with_cell(key(1), b"base")));
        chain.raise_floor(floor, SHARD);
        chain.append(
            BlockHeight::new(5),
            determined(&[(key(1), Some(b"five"))], 5),
            &[],
        );
        chain.raise_floor(floor, SHARD);
        chain.raise_floor(BlockHeight::new(2), SHARD);
        assert_eq!(read_at(&chain, 5, key(1)), Some(b"five".to_vec()));
    }

    /// The base is held at the floor, so the first tick past the
    /// crossing reads a baseline still there.
    #[test]
    fn a_raised_floor_holds_retention_at_it() {
        let store = Arc::new(StubStore::with_cell(key(1), b"base"));
        let chain = TickChain::new(Arc::clone(&store));
        chain.prune_persisted(BlockHeight::new(9), BlockHeight::GENESIS);
        chain.raise_floor(BlockHeight::new(3), SHARD);
        assert_eq!(
            lock_or_recover(&store.holds).last().copied(),
            Some(BlockHeight::new(3)),
        );
    }

    #[test]
    fn provisional_entries_unreadable_until_settled() {
        let chain = TickChain::new(Arc::new(StubStore::with_cell(key(1), b"base")));
        let w = tick(1);
        chain.append(
            BlockHeight::new(1),
            TickOutput {
                determined: Vec::new(),
                provisional: vec![ProvisionalTx {
                    tx_hash: tx(7),
                    writes: Some(writes(&[(key(1), Some(b"provisional"))])),
                    reserve: None,
                    reserved: BTreeMap::new(),
                }],
            },
            &[],
        );

        let view = chain.view_at(BlockHeight::new(1));
        assert_eq!(view.snapshot().cell(key(1)), Some(b"base".to_vec()));

        chain.resolve(
            &w,
            &TickResolution::Settled {
                height: BlockHeight::new(3),
                members: BTreeSet::from([tx(7)]),
                aborted: BTreeSet::new(),
            },
        );
        let view = chain.view_at(BlockHeight::new(1));
        assert_eq!(
            view.snapshot().cell(key(1)),
            Some(b"base".to_vec()),
            "a tick below the settling height reads the leg pending",
        );
        let view = chain.view_at(BlockHeight::new(2));
        assert_eq!(view.snapshot().cell(key(1)), Some(b"provisional".to_vec()));
    }

    /// A tick's output lives at its own height and nowhere else, because
    /// a tick attests exactly what it ran. So a resolution reaches one
    /// entry, and a second tick over the same cell is untouched by it —
    /// which is what lets `resolve` be a lookup rather than a search.
    #[test]
    fn a_resolution_reaches_the_tick_it_names_and_no_other() {
        let chain = TickChain::new(Arc::new(StubStore::with_cell(key(1), b"base")));
        for (height, cell, member) in [(4u64, key(1), 7u8), (6, key(2), 8)] {
            chain.append(
                BlockHeight::new(height),
                TickOutput {
                    determined: Vec::new(),
                    provisional: vec![ProvisionalTx {
                        tx_hash: tx(member),
                        writes: Some(writes(&[(cell, Some(b"promoted"))])),
                        reserve: None,
                        reserved: BTreeMap::new(),
                    }],
                },
                &[],
            );
        }

        chain.resolve(
            &tick(4),
            &TickResolution::Settled {
                height: BlockHeight::new(7),
                members: BTreeSet::from([tx(7)]),
                aborted: BTreeSet::new(),
            },
        );

        let view = chain.view_at(BlockHeight::new(6));
        assert_eq!(view.snapshot().cell(key(1)), Some(b"promoted".to_vec()));
        assert_eq!(
            view.snapshot().cell(key(2)),
            None,
            "the tick at 6 is unresolved, so nothing of it is readable"
        );

        chain.prune_persisted(BlockHeight::new(7), BlockHeight::new(7));
        assert_eq!(chain.len(), 1, "only the resolved tick evicts");
    }

    #[test]
    fn aborted_member_settles_reserve_not_writes() {
        let chain = TickChain::new(Arc::new(StubStore::with_cell(key(1), b"base")));
        let w = tick(1);
        chain.append(
            BlockHeight::new(1),
            TickOutput {
                determined: Vec::new(),
                provisional: vec![ProvisionalTx {
                    tx_hash: tx(7),
                    writes: Some(writes(&[(key(1), Some(b"effects"))])),
                    reserve: Some(writes(&[(key(9), Some(b"floor"))])),
                    reserved: BTreeMap::new(),
                }],
            },
            &[],
        );

        chain.resolve(
            &w,
            &TickResolution::Settled {
                height: BlockHeight::new(3),
                members: BTreeSet::from([tx(7)]),
                aborted: BTreeSet::from([tx(7)]),
            },
        );
        let view = chain.view_at(BlockHeight::new(2));
        assert_eq!(view.snapshot().cell(key(1)), Some(b"base".to_vec()));
        assert_eq!(view.snapshot().cell(key(9)), Some(b"floor".to_vec()));
    }

    /// An abandoned leg holds what it reserved for every tick below the
    /// height the chain let it go at, and nothing from that height on;
    /// the entry stays until no read below it can come.
    #[test]
    fn an_abandoned_legs_hold_stands_below_its_height() {
        let chain = TickChain::new(Arc::new(StubStore::with_cell(key(1), b"base")));
        chain.append(
            BlockHeight::new(1),
            TickOutput {
                determined: Vec::new(),
                provisional: vec![ProvisionalTx {
                    tx_hash: tx(7),
                    writes: Some(debit(key(2), 60)),
                    reserve: None,
                    reserved: BTreeMap::from([(key(2), 60)]),
                }],
            },
            &[],
        );
        chain.resolve(
            &tick(1),
            &TickResolution::Abandoned {
                height: BlockHeight::new(4),
                members: BTreeSet::from([tx(7)]),
            },
        );
        let held = |anchor: u64| {
            chain
                .view_at(BlockHeight::new(anchor))
                .holds()
                .get(&key(2))
                .map_or(0, |legs| legs.values().sum::<u128>())
        };
        assert_eq!(held(2), 60, "a tick below the abandonment reads the hold");
        assert_eq!(held(3), 0, "the tick at it does not");

        chain.prune_persisted(BlockHeight::new(4), BlockHeight::new(2));
        assert_eq!(
            chain.len(),
            1,
            "a read below the abandonment can still come"
        );
        chain.prune_persisted(BlockHeight::new(4), BlockHeight::new(4));
        assert!(chain.is_empty());
    }

    #[test]
    fn wholesale_abort_drops_everything() {
        let chain = TickChain::new(Arc::new(StubStore::with_cell(key(1), b"base")));
        let w = tick(1);
        chain.append(
            BlockHeight::new(1),
            TickOutput {
                determined: Vec::new(),
                provisional: vec![ProvisionalTx {
                    tx_hash: tx(7),
                    writes: Some(writes(&[(key(1), Some(b"effects"))])),
                    reserve: Some(writes(&[(key(9), Some(b"floor"))])),
                    reserved: BTreeMap::new(),
                }],
            },
            &[],
        );

        chain.resolve(
            &w,
            &TickResolution::Abandoned {
                height: BlockHeight::new(2),
                members: BTreeSet::from([tx(7)]),
            },
        );
        let view = chain.view_at(BlockHeight::new(1));
        assert_eq!(view.snapshot().cell(key(1)), Some(b"base".to_vec()));
        assert_eq!(view.snapshot().cell(key(9)), None);
    }

    /// A tick that mixes a determined member with a leg is the shape the
    /// halves exist for. Its determined member settles on the tick's own
    /// certificate; when the leg is later abandoned, the abandonment
    /// meets a fold that is already stamped and drops only the leg.
    ///
    /// Before the split this was the corruption case: one resolution
    /// covered the whole tick, so abandoning the leg left the determined
    /// member's writes folded forever and never in the base — visible to
    /// a long-running replica and absent from one that snap-synced.
    #[test]
    fn abandoning_a_leg_leaves_its_settled_tick_mate_alone() {
        let chain = TickChain::new(Arc::new(StubStore::with_cell(key(1), b"base")));
        let w = tick(1);
        chain.append(
            BlockHeight::new(1),
            TickOutput {
                determined: vec![(tx(1), writes(&[(key(1), Some(b"determined"))]))],
                provisional: vec![ProvisionalTx {
                    tx_hash: tx(7),
                    writes: Some(writes(&[(key(2), Some(b"leg"))])),
                    reserve: Some(writes(&[(key(9), Some(b"floor"))])),
                    reserved: BTreeMap::new(),
                }],
            },
            &[],
        );

        // The determined half settles on its own; the leg is untouched.
        chain.resolve(
            &w,
            &TickResolution::Settled {
                height: BlockHeight::new(2),
                members: BTreeSet::from([tx(1)]),
                aborted: BTreeSet::new(),
            },
        );
        let view = chain.view_at(BlockHeight::new(1));
        assert_eq!(view.snapshot().cell(key(1)), Some(b"determined".to_vec()),);
        assert_eq!(view.snapshot().cell(key(2)), None, "the leg is unread");

        // The counterpart never certifies, so the leg is abandoned.
        chain.resolve(
            &w,
            &TickResolution::Abandoned {
                height: BlockHeight::new(3),
                members: BTreeSet::from([tx(7)]),
            },
        );
        let view = chain.view_at(BlockHeight::new(1));
        assert_eq!(
            view.snapshot().cell(key(1)),
            Some(b"determined".to_vec()),
            "the settled tick-mate is untouched by its leg's abandonment",
        );
        assert_eq!(view.snapshot().cell(key(2)), None);
        assert_eq!(view.snapshot().cell(key(9)), None);

        // And the entry can now evict rather than pin: nothing pends and
        // the fold is stamped, so the base carries everything it held.
        chain.prune_persisted(BlockHeight::new(2), BlockHeight::new(2));
        assert_eq!(chain.len(), 0);
    }

    /// A tick appended twice carries byte-identical outputs, so the
    /// second is dropped: refolding it would leave an absolute unchanged
    /// and apply every movement a second time.
    #[test]
    fn a_repeated_append_is_dropped_rather_than_refolded() {
        let store = Arc::new(StubStore::with_cell(key(1), encode_amount(1_000).as_ref()));
        let chain = TickChain::new(store);
        let output = || TickOutput {
            determined: vec![(tx(1), debit(key(1), 100))],
            provisional: Vec::new(),
        };
        chain.append(BlockHeight::new(1), output(), &[]);
        chain.append(BlockHeight::new(1), output(), &[]);

        let view = chain.view_at(BlockHeight::new(1));
        assert_eq!(amount(&view.snapshot().cell(key(1)).unwrap()), 900);
    }

    /// A run of a tick the chain evicted lands already settled.
    ///
    /// One executor ran the tick, its fate committed, the base took it
    /// and the entry went. An executor seated since re-runs the tick from
    /// below, and the entry it appends holds what the base has carried
    /// from the settling height. Appended with the fate its executor
    /// holds, it folds for the reads below that height and for none
    /// above; a read above it between the append and a later resolution
    /// would otherwise apply the movement to a base that already has it.
    #[test]
    fn a_run_of_an_evicted_tick_lands_with_its_fate() {
        let cell = key(1);
        let store = Arc::new(StubStore::settling(
            cell,
            encode_amount(1_000).as_ref(),
            BlockHeight::new(8),
            encode_amount(900).as_ref(),
        ));
        let chain = TickChain::new(store);
        let ran = || TickOutput {
            determined: vec![(tx(1), debit(cell, 100))],
            provisional: Vec::new(),
        };
        let settled = TickResolution::Settled {
            height: BlockHeight::new(8),
            members: BTreeSet::from([tx(1)]),
            aborted: BTreeSet::new(),
        };
        let read = |at: u64| amount(&read_at(&chain, at, cell).expect("the cell"));

        // The first executor runs the tick, and the chain lets it go
        // once the base carries it and that executor is past it.
        chain.append(BlockHeight::new(3), ran(), &[]);
        chain.resolve(&tick(3), &settled);
        chain.prune_persisted(BlockHeight::new(8), BlockHeight::new(8));
        assert!(chain.is_empty());
        assert_eq!(read(8), 900);

        // A second executor is seated below it and runs the tick again.
        chain.prune_persisted(BlockHeight::new(8), BlockHeight::new(2));
        assert_eq!(read(2), 1_000);
        chain.append(BlockHeight::new(3), ran(), std::slice::from_ref(&settled));

        assert_eq!(read(8), 900, "the base carries the debit from 8");
        assert_eq!(read(5), 900, "and the entry carries it below");
    }

    /// A fold and the base must never both carry one contribution. The
    /// eviction floor holds a settled fold while execution lags, and the
    /// base gains the same writes as soon as the settling block persists
    /// — so the two windows overlap, and the reader has to pick exactly
    /// one of them.
    #[test]
    fn a_retained_fold_stops_applying_once_the_base_carries_it() {
        let store = Arc::new(StubStore::settling(
            key(1),
            encode_amount(1_000).as_ref(),
            BlockHeight::new(8),
            encode_amount(900).as_ref(),
        ));
        let chain = TickChain::new(Arc::clone(&store));

        let w = tick(3);
        chain.append(
            BlockHeight::new(3),
            TickOutput {
                determined: Vec::new(),
                provisional: vec![ProvisionalTx {
                    tx_hash: tx(7),
                    writes: Some(debit(key(1), 100)),
                    reserve: None,
                    reserved: BTreeMap::new(),
                }],
            },
            &[],
        );
        chain.resolve(
            &w,
            &TickResolution::Settled {
                height: BlockHeight::new(8),
                members: BTreeSet::from([tx(7)]),
                aborted: BTreeSet::new(),
            },
        );
        chain.prune_persisted(BlockHeight::new(11), BlockHeight::new(3));
        assert_eq!(
            chain.len(),
            1,
            "execution has only reached tick 3, so the fold is retained"
        );

        // A queued tick below the settlement reads the leg pending.
        let view = chain.view_at(BlockHeight::new(5));
        assert_eq!(amount(&view.snapshot().cell(key(1)).unwrap()), 1_000);

        // The tick at the settlement reads it from the fold.
        let view = chain.view_at(BlockHeight::new(7));
        assert_eq!(amount(&view.snapshot().cell(key(1)).unwrap()), 900);

        // A later tick reads a base that already holds it, and must not
        // apply the debit again.
        let view = chain.view_at(BlockHeight::new(11));
        assert_eq!(amount(&view.snapshot().cell(key(1)).unwrap()), 900);
    }

    /// A fold survives until nothing can still need it: every tick in it
    /// resolved, the settlement persisted, and execution advanced past the
    /// settling height. The last is what keeps eviction from outrunning a
    /// queued tick, whose anchor can sit below the height the base gained
    /// the write at.
    #[test]
    fn eviction_waits_for_resolution_persistence_and_execution() {
        let chain = TickChain::new(Arc::new(StubStore::with_cell(key(1), b"base")));
        let w = tick(1);
        chain.append(
            BlockHeight::new(1),
            TickOutput {
                determined: vec![(tx(1), writes(&[(key(1), Some(b"one"))]))],
                provisional: Vec::new(),
            },
            &[],
        );

        // Unresolved: survives any persistence progress.
        chain.prune_persisted(BlockHeight::new(10), BlockHeight::new(1));
        assert_eq!(chain.len(), 1);

        chain.resolve(
            &w,
            &TickResolution::Settled {
                height: BlockHeight::new(3),
                members: BTreeSet::from([tx(1)]),
                aborted: BTreeSet::new(),
            },
        );

        // Resolved and persisted, but execution has only reached tick 1 —
        // the next tick anchors there, and the base gained the write at 3.
        chain.prune_persisted(BlockHeight::new(3), BlockHeight::new(1));
        assert_eq!(
            chain.len(),
            1,
            "a fold a queued tick still anchors below must not evict"
        );

        // Execution reaches the settling height: nothing anchors below it
        // any more.
        chain.append(
            BlockHeight::new(3),
            TickOutput {
                determined: vec![(tx(3), writes(&[(key(1), Some(b"three"))]))],
                provisional: Vec::new(),
            },
            &[],
        );
        chain.prune_persisted(BlockHeight::new(2), BlockHeight::new(3));
        assert_eq!(chain.len(), 2, "persistence has not caught up");
        chain.prune_persisted(BlockHeight::new(3), BlockHeight::new(3));
        assert_eq!(chain.len(), 1, "only the settled tick evicts");
    }

    /// What the kernel judges a debit against: the balance less every
    /// outstanding hold on it.
    fn available(view: &TickView<StubStore>, cell: SubstateKey) -> u128 {
        let balance = amount(&view.snapshot().cell(cell).expect("an amount cell"));
        let held: u128 = view
            .holds()
            .get(&cell)
            .map_or(0, |legs| legs.values().sum());
        balance - held
    }

    /// Two honest replicas commit the same chain: tick 2 holds two
    /// cross-shard legs, tick 3 commits, and block 4 commits the
    /// finalization settling tick 2's legs — one completed (a credit), one
    /// aborted (its reservation released, its charge burned). Tick 3 reads
    /// `view_at(2)`. One replica runs it before block 4 commits; a lagging
    /// one runs it after, with the resolution already applied. Nothing at
    /// or below height 2 differs between them, so tick 3's baseline must
    /// not either.
    #[test]
    fn a_tick_baseline_ignores_a_leg_settled_above_it() {
        let run = |lagging: bool| {
            let store = Arc::new(StubStore {
                history: BTreeMap::from([(
                    BlockHeight::GENESIS,
                    HashMap::from([
                        (key(1), encode_amount(100).to_vec()),
                        (key(2), encode_amount(100).to_vec()),
                    ]),
                )]),
                tip: BlockHeight::new(2),
                anchors: Mutex::new(Vec::new()),
                holds: Mutex::new(Vec::new()),
                entries: BTreeMap::new(),
            });
            let chain = TickChain::new(store);
            let mut credit = StateWrites::default();
            credit.movements.insert(
                key(1),
                Movement {
                    resource: RESOURCE,
                    credit: 50,
                    debit: 0,
                    unjudged_debit: 0,
                },
            );
            chain.append(
                BlockHeight::new(2),
                TickOutput {
                    determined: Vec::new(),
                    provisional: vec![
                        ProvisionalTx {
                            tx_hash: tx(7),
                            writes: Some(credit),
                            reserve: Some(debit(key(9), 1)),
                            reserved: BTreeMap::new(),
                        },
                        ProvisionalTx {
                            tx_hash: tx(8),
                            writes: Some(debit(key(2), 60)),
                            reserve: Some(debit(key(2), 5)),
                            reserved: BTreeMap::from([(key(2), 60)]),
                        },
                    ],
                },
                &[],
            );
            if lagging {
                chain.resolve(
                    &tick(2),
                    &TickResolution::Settled {
                        height: BlockHeight::new(4),
                        members: BTreeSet::from([tx(7), tx(8)]),
                        aborted: BTreeSet::from([tx(8)]),
                    },
                );
                chain.prune_persisted(BlockHeight::new(4), BlockHeight::new(2));
            }
            let view = chain.view_at(BlockHeight::new(2));
            (available(&view, key(1)), available(&view, key(2)))
        };
        assert_eq!(
            run(true),
            run(false),
            "tick 3's baseline moved with when it ran relative to block 4"
        );
    }

    /// A leg restored from its settling finalization reads exactly as a
    /// run's leg settled there: every tick below the settlement is held
    /// off what it reserved and sees none of its writes, and every tick
    /// from it reads the debit with the hold gone.
    #[test]
    fn restored_legs_read_as_a_run_settled_at_the_same_height() {
        let leg = || ProvisionalTx {
            tx_hash: tx(7),
            writes: Some(debit(key(1), 300)),
            reserve: None,
            reserved: BTreeMap::from([(key(1), 300)]),
        };
        let chain = |ran: bool| {
            let store = Arc::new(StubStore {
                history: [
                    (BlockHeight::GENESIS, 1_000u128),
                    (BlockHeight::new(6), 700),
                ]
                .into_iter()
                .map(|(height, held)| {
                    (
                        height,
                        HashMap::from([(key(1), encode_amount(held).to_vec())]),
                    )
                })
                .collect(),
                tip: BlockHeight::new(7),
                anchors: Mutex::new(Vec::new()),
                holds: Mutex::new(Vec::new()),
                entries: BTreeMap::new(),
            });
            let chain = TickChain::new(store);
            if ran {
                chain.append(
                    BlockHeight::new(3),
                    TickOutput {
                        determined: Vec::new(),
                        provisional: vec![leg()],
                    },
                    &[],
                );
                chain.resolve(
                    &tick(3),
                    &TickResolution::Settled {
                        height: BlockHeight::new(6),
                        members: BTreeSet::from([tx(7)]),
                        aborted: BTreeSet::new(),
                    },
                );
            } else {
                chain.resolve(
                    &tick(3),
                    &TickResolution::RestoredLegs {
                        height: BlockHeight::new(6),
                        legs: vec![leg()],
                        aborted: BTreeSet::new(),
                    },
                );
            }
            chain
        };
        let (ran, restored) = (chain(true), chain(false));
        let read = |chain: &TickChain<StubStore>, at: u64| {
            let view = chain.view_at(BlockHeight::new(at));
            let balance = amount(&view.snapshot().cell(key(1)).expect("an amount cell"));
            (balance, available(&view, key(1)))
        };
        for at in 3..=7 {
            assert_eq!(
                read(&restored, at),
                read(&ran, at),
                "the tick after {at} reads the restored leg as the run's",
            );
        }
        assert_eq!(
            read(&restored, 4),
            (1_000, 700),
            "held below the settlement"
        );
        assert_eq!(read(&restored, 5), (700, 700), "settled from it");
    }

    #[test]
    fn resolution_is_idempotent_and_tolerates_unknown_ticks() {
        let chain = TickChain::new(Arc::new(StubStore::with_cell(key(1), b"base")));
        let settled = TickResolution::Settled {
            height: BlockHeight::new(1),
            members: BTreeSet::from([tx(7), tx(1)]),
            aborted: BTreeSet::new(),
        };
        // Unknown tick: no entry at its height.
        chain.resolve(&tick(5), &settled);

        let w = tick(1);
        chain.append(
            BlockHeight::new(1),
            TickOutput {
                determined: Vec::new(),
                provisional: Vec::new(),
            },
            &[],
        );
        chain.resolve(&w, &settled);
        chain.resolve(&w, &settled);
        chain.prune_persisted(BlockHeight::new(1), BlockHeight::new(1));
        assert!(chain.is_empty());
    }

    /// The vault every fee hold fixture stands on.
    fn vault() -> SubstateKey {
        key(1)
    }

    /// The hold `tx` places on [`vault`] for `ceiling`: its cell and the
    /// bytes the commit fold writes there.
    fn hold(by: TxHash, ceiling: u128) -> (SubstateKey, Vec<u8>) {
        let hold = FeeHold {
            vault: vault().local,
            tx: by,
            fee: ceiling,
        };
        (hold.key(&ProtocolHasher, vault().owner), hold.to_bytes())
    }

    /// The base cells of a vault holding `balance` under `holds`, with
    /// the total the commit fold keeps beside them.
    fn held_vault(balance: u128, holds: &[(TxHash, u128)]) -> HashMap<SubstateKey, Vec<u8>> {
        let total: u128 = holds.iter().map(|(_, ceiling)| ceiling).sum();
        let mut cells = HashMap::from([
            (vault(), encode_amount(balance).as_ref().to_vec()),
            (
                fee_hold_total_key(&ProtocolHasher, vault()),
                total.to_le_bytes().to_vec(),
            ),
        ]);
        cells.extend(holds.iter().map(|(by, ceiling)| hold(*by, *ceiling)));
        cells
    }

    /// A base holding `genesis` from the start and `settled` over it from
    /// `height`, its tip.
    fn base_settling(
        genesis: HashMap<SubstateKey, Vec<u8>>,
        height: BlockHeight,
        settled: HashMap<SubstateKey, Vec<u8>>,
    ) -> StubStore {
        StubStore {
            history: BTreeMap::from([(BlockHeight::GENESIS, genesis), (height, settled)]),
            tip: height,
            anchors: Mutex::new(Vec::new()),
            holds: Mutex::new(Vec::new()),
            entries: BTreeMap::new(),
        }
    }

    /// What a member that burned `burn` leaves: the debit and the end of
    /// its hold, in one write set.
    fn burning(by: TxHash, ceiling: u128, burn: u128) -> StateWrites {
        let mut left = debit(vault(), burn);
        left.cells.insert(hold(by, ceiling).0, None);
        left
    }

    /// The fee holds standing on [`vault`] for the tick after `at`, and
    /// what `member` holds of them.
    fn standing_after(chain: &TickChain<StubStore>, at: u64, member: TxHash) -> (u128, u128) {
        let view = chain.view_at(BlockHeight::new(at));
        let reading = view.fee_holds(&[], &NibblePath::empty());
        (reading.standing(vault()), reading.own(vault(), member))
    }

    /// A layer that deletes a hold the base still holds carries that
    /// member's burn, so the tick reading it leaves the ceiling out of
    /// what stands; a tick anchored below the layer still counts it.
    #[test]
    fn a_fold_reports_the_holds_its_layers_release() {
        let store = StubStore {
            history: BTreeMap::from([(
                BlockHeight::GENESIS,
                held_vault(1_000, &[(tx(7), 100), (tx(8), 30)]),
            )]),
            tip: StubStore::WRITTEN,
            anchors: Mutex::new(Vec::new()),
            holds: Mutex::new(Vec::new()),
            entries: BTreeMap::new(),
        };
        let chain = TickChain::new(Arc::new(store));
        chain.append(
            BlockHeight::new(2),
            TickOutput {
                determined: vec![(tx(7), burning(tx(7), 100, 12))],
                provisional: Vec::new(),
            },
            &[],
        );

        assert_eq!(standing_after(&chain, 1, tx(7)), (130, 100));
        for at in [2, 5, 2] {
            assert_eq!(standing_after(&chain, at, tx(7)), (30, 0), "after {at}");
            assert_eq!(standing_after(&chain, at, tx(8)), (30, 30), "after {at}");
            let balance = chain.view_at(BlockHeight::new(at)).snapshot().cell(vault());
            assert_eq!(amount(&balance.expect("the vault")), 988);
        }
    }

    /// Once the base carries the contribution it carries the release
    /// too: the hold is gone from it and the total is lowered, so the
    /// fold names nothing and the ceiling is not taken out twice.
    #[test]
    fn a_release_the_base_carries_is_not_the_folds() {
        let mut settled = held_vault(988, &[(tx(8), 30)]);
        // The store's history holds no deletion, so the hold's cell is
        // left as bytes that are no hold.
        settled.insert(hold(tx(7), 100).0, Vec::new());
        let store = base_settling(
            held_vault(1_000, &[(tx(7), 100), (tx(8), 30)]),
            BlockHeight::new(4),
            settled,
        );
        let chain = TickChain::new(Arc::new(store));
        chain.append(
            BlockHeight::new(2),
            TickOutput {
                determined: vec![(tx(7), burning(tx(7), 100, 12))],
                provisional: Vec::new(),
            },
            &[],
        );
        chain.resolve(
            &tick(2),
            &TickResolution::Settled {
                height: BlockHeight::new(4),
                members: BTreeSet::from([tx(7)]),
                aborted: BTreeSet::new(),
            },
        );

        // Either side of the settlement and back: one answer, read off
        // the fold below it and off the base from it.
        for at in [3, 4, 3, 2, 4] {
            assert_eq!(standing_after(&chain, at, tx(7)), (30, 0), "after {at}");
        }
    }

    /// A deletion of a hold that does not stand, a finalization naming a
    /// transaction this shard never held a fee for, releases nothing.
    #[test]
    fn a_deletion_of_a_cell_the_base_lacks_is_no_release() {
        let store = StubStore {
            history: BTreeMap::from([(BlockHeight::GENESIS, held_vault(1_000, &[(tx(8), 30)]))]),
            tip: StubStore::WRITTEN,
            anchors: Mutex::new(Vec::new()),
            holds: Mutex::new(Vec::new()),
            entries: BTreeMap::new(),
        };
        let chain = TickChain::new(Arc::new(store));
        chain.append(
            BlockHeight::new(2),
            TickOutput {
                determined: vec![(tx(7), burning(tx(7), 100, 12))],
                provisional: Vec::new(),
            },
            &[],
        );
        assert_eq!(standing_after(&chain, 2, tx(7)), (30, 0));
    }

    /// Only a hold sitting at its own key is released by its deletion: a
    /// deleted cell of anything else, a hold's bytes under another key
    /// among them, moves nothing.
    #[test]
    fn a_deletion_of_a_cell_that_is_no_hold_is_no_release() {
        let mut genesis = held_vault(1_000, &[(tx(7), 100)]);
        genesis.insert(key(5), b"data".to_vec());
        genesis.insert(key(6), hold(tx(7), 100).1);
        let store = StubStore {
            history: BTreeMap::from([(BlockHeight::GENESIS, genesis)]),
            tip: StubStore::WRITTEN,
            anchors: Mutex::new(Vec::new()),
            holds: Mutex::new(Vec::new()),
            entries: BTreeMap::new(),
        };
        let chain = TickChain::new(Arc::new(store));
        chain.append(
            BlockHeight::new(2),
            determined(&[(key(5), None), (key(6), None)], 9),
            &[],
        );
        assert_eq!(standing_after(&chain, 2, tx(7)), (100, 100));
    }

    /// A tick seated from the receipts that settled it releases what a
    /// run of it releases, below the height they committed at, and
    /// nothing from it.
    #[test]
    fn a_restored_layer_releases_as_a_run_does() {
        let chain_over = || {
            let mut settled = held_vault(988, &[(tx(8), 30)]);
            settled.insert(hold(tx(7), 100).0, Vec::new());
            TickChain::new(Arc::new(base_settling(
                held_vault(1_000, &[(tx(7), 100), (tx(8), 30)]),
                BlockHeight::new(4),
                settled,
            )))
        };
        let ran = chain_over();
        ran.append(
            BlockHeight::new(2),
            TickOutput {
                determined: vec![(tx(7), burning(tx(7), 100, 12))],
                provisional: Vec::new(),
            },
            &[],
        );
        ran.resolve(
            &tick(2),
            &TickResolution::Settled {
                height: BlockHeight::new(4),
                members: BTreeSet::from([tx(7)]),
                aborted: BTreeSet::new(),
            },
        );
        let restored = chain_over();
        restored.resolve(
            &tick(2),
            &TickResolution::Restored {
                height: BlockHeight::new(4),
                writes: vec![(tx(7), burning(tx(7), 100, 12))],
            },
        );

        for at in [2, 3, 4] {
            assert_eq!(
                standing_after(&restored, at, tx(7)),
                standing_after(&ran, at, tx(7)),
                "after {at}",
            );
            assert_eq!(standing_after(&restored, at, tx(7)), (30, 0), "after {at}");
        }
        assert_eq!(standing_after(&restored, 1, tx(7)), (130, 100));
    }

    /// A view over `base` for `key(1)` with `layers` above it, bottom up.
    fn view_over(base: u128, layers: &[StateWrites]) -> TickViewSnapshot<StubSnapshot> {
        TickViewSnapshot {
            base_snapshot: StubSnapshot(
                HashMap::from([(key(1), encode_amount(base).to_vec())]),
                BTreeMap::new(),
            ),
            overlays: Arc::new(layers.iter().cloned().map(Arc::new).collect()),
        }
    }

    fn read_over(base: u128, layers: &[StateWrites]) -> u128 {
        view_over(base, layers)
            .cell(key(1))
            .map_or(0, |cell| amount(&cell))
    }

    fn moving(credit: u128, debit: u128, unjudged_debit: u128) -> StateWrites {
        let mut moved = StateWrites::default();
        moved.movements.insert(
            key(1),
            Movement {
                resource: RESOURCE,
                credit,
                debit,
                unjudged_debit,
            },
        );
        moved
    }

    /// What `key(1)` holds after one block settles `layers` over `held`,
    /// through settlement itself.
    fn settled_in_one_block(held: u128, layers: &[&StateWrites]) -> u128 {
        let mut block = StateWrites::default();
        for layer in layers {
            fold_state_writes(&mut block, layer);
        }
        let prior = StubSnapshot(
            HashMap::from([(key(1), encode_amount(held).to_vec())]),
            BTreeMap::new(),
        );
        settle_writes(&block, &prior)
            .cells()
            .get(&key(1))
            .map_or(held, |cell| cell.as_deref().map_or(0, amount))
    }

    /// An unjudged charge under a later layer's credit is taken after
    /// the credit caps, as one block settling both takes it: over
    /// `MAX - 10`, a charge of 6 and a credit of 16 read `MAX - 6`, so a
    /// debit judged against the view never runs past settlement.
    #[test]
    fn an_unjudged_charge_is_taken_after_a_later_credit_caps() {
        let charge = moving(0, 0, 6);
        let credit = moving(16, 0, 0);
        let settled = settled_in_one_block(u128::MAX - 10, &[&charge, &credit]);
        assert_eq!(settled, u128::MAX - 6);
        assert_eq!(read_over(u128::MAX - 10, &[charge, credit]), settled);
    }

    /// An unjudged charge past the balance floors once, after a later
    /// layer's credit lands, as one block settling both floors it: over
    /// an empty vault, a charge of 10 and a credit of 10 read empty.
    #[test]
    fn an_unjudged_charge_past_the_balance_floors_after_a_later_credit() {
        let charge = moving(0, 0, 10);
        let credit = moving(10, 0, 0);
        let settled = settled_in_one_block(0, &[&charge, &credit]);
        assert_eq!(settled, 0);
        assert_eq!(read_over(0, &[charge, credit]), settled);
    }

    /// Xorshift, so the grouping model replays the same histories.
    struct XorShift(u64);

    impl XorShift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        /// Uniform in `0..=bound`.
        fn up_to(&mut self, bound: u128) -> u128 {
            if bound == 0 {
                return 0;
            }
            let wide = (u128::from(self.next()) << 64) | u128::from(self.next());
            wide % (bound + u128::from(bound < u128::MAX))
        }

        fn small(&mut self) -> u128 {
            u128::from(self.next() % 64)
        }
    }

    fn index(height: u64) -> usize {
        usize::try_from(height).expect("a model height fits usize")
    }

    /// Ticks run in order, each over the base settled through the block
    /// below it plus every earlier layer not yet settled, judging its
    /// debits and capping its unjudged charge against that view and its
    /// credits under `u128` there (the kernel's `CellOverflow`). Each
    /// layer settles whole in one block above its tick, in tick order,
    /// several to a block at random, beside random fold credits. No
    /// settlement over-debits, and no view at any anchor reads above
    /// what the blocks settling its layers leave.
    #[test]
    fn no_view_reads_above_what_any_grouping_of_its_layers_settles_at() {
        let mut rng = XorShift(0x9E37_79B9_7F4A_7C15);
        for trial in 0..20_000 {
            let ticks: u64 = 2 + rng.next() % 8;
            let start = if rng.next().is_multiple_of(2) {
                u128::MAX - rng.small()
            } else {
                rng.small()
            };
            // `settled[h]`: what the cell holds after block `h`.
            let mut settled: Vec<u128> = vec![start];
            let mut layers: Vec<StateWrites> = Vec::new();
            // The block each tick's layer settles in.
            let mut settles_at: Vec<u64> = Vec::new();
            let mut next_group_at = 1u64;
            for tick in 1..=ticks {
                let unsettled: Vec<StateWrites> = (0..layers.len())
                    .filter(|&i| settles_at[i] > tick - 1)
                    .map(|i| layers[i].clone())
                    .collect();
                let v = read_over(settled[index(tick - 1)], &unsettled);
                let layer = match rng.next() % 6 {
                    0 => moving(rng.up_to(u128::MAX - v), 0, 0),
                    1 => moving(0, rng.up_to(v), 0),
                    2 => {
                        let c = rng.up_to(u128::MAX - v);
                        moving(c, rng.up_to(v + c), 0)
                    }
                    3 => moving(rng.small().min(u128::MAX - v), 0, 0),
                    4 => {
                        let d = rng.up_to(v);
                        moving(0, d, rng.up_to(v - d))
                    }
                    _ => writes(&[(key(1), Some(encode_amount(rng.up_to(u128::MAX)).as_ref()))]),
                };
                layers.push(layer);
                next_group_at = next_group_at.max(tick + 1) + rng.next() % 3;
                settles_at.push(next_group_at);
                // Block `tick`: a fold credit beside the layers settling here.
                let fold = moving(
                    if rng.next().is_multiple_of(3) {
                        rng.up_to(u128::MAX)
                    } else {
                        0
                    },
                    0,
                    0,
                );
                let mut block: Vec<&StateWrites> = (0..layers.len())
                    .filter(|&i| settles_at[i] == tick)
                    .map(|i| &layers[i])
                    .collect();
                block.push(&fold);
                settled.push(settled_in_one_block(settled[index(tick - 1)], &block));
            }
            let last = *settles_at.iter().max().unwrap();
            for height in (ticks + 1)..=last {
                let block: Vec<&StateWrites> = (0..layers.len())
                    .filter(|&i| settles_at[i] == height)
                    .map(|i| &layers[i])
                    .collect();
                settled.push(settled_in_one_block(*settled.last().unwrap(), &block));
            }
            for anchor in 0..=ticks {
                let base = settled[index(anchor)];
                let pending: Vec<usize> = (0..index(anchor))
                    .filter(|&i| settles_at[i] > anchor)
                    .collect();
                let unsettled: Vec<StateWrites> =
                    pending.iter().map(|&i| layers[i].clone()).collect();
                let v = read_over(base, &unsettled);
                let mut heights: Vec<u64> = pending.iter().map(|&i| settles_at[i]).collect();
                heights.dedup();
                let mut s = base;
                for height in heights {
                    let block: Vec<&StateWrites> = pending
                        .iter()
                        .filter(|&&i| settles_at[i] == height)
                        .map(|&i| &layers[i])
                        .collect();
                    s = settled_in_one_block(s, &block);
                }
                assert!(
                    v <= s,
                    "trial {trial}: view {v} above settled {s} at anchor {anchor}; base {base}, \
                     pending {pending:?}, settles_at {settles_at:?}, settled {settled:?}, \
                     layers {:?}",
                    layers
                        .iter()
                        .map(|l| (
                            l.cells.get(&key(1)).cloned(),
                            l.movements.get(&key(1)).copied()
                        ))
                        .collect::<Vec<_>>()
                );
            }
        }
    }

    /// What a stated row in these fixtures reserves of `key(1)`.
    const RESERVED: u128 = 40;

    /// `tx`'s row standing as `state`, declaring a reservation of
    /// `RESERVED` against `key(1)`.
    fn row(tx_hash: TxHash, state: RowState) -> MemberRow {
        MemberRow {
            tx: tx_hash,
            deadline: Deadline::of(WeightedTimestamp::from_millis(1_000_000)),
            committed: WeightedTimestamp::ZERO,
            height: BlockHeight::new(1),
            state,
            holds: Capped::from_array([(
                DeclaredKey::Cell(key(1)),
                Mode::Reserve { amount: RESERVED },
            )]),
            reach: Capped::from_array([ShardId::leaf(1, 1)]),
            awaits: Capped::from_array([ShardId::leaf(1, 1)]),
            charge: AbortCharge {
                vault: key(9),
                amount: 0,
            },
            share: 0,
            reserves: Capped::empty(),
            crossings: Capped::empty(),
            owes: Owes::default(),
            waiting: None,
            covered: false,
            executed: true,
            hearing: Capped::empty(),
        }
    }

    fn in_flight(tick: u64) -> RowState {
        RowState::InFlight {
            tick: BlockHeight::new(tick),
            joins: Joins::Executes,
            settlement: Settlement::Shared,
        }
    }

    fn stated(tick: u64) -> RowState {
        RowState::Stated {
            tick: BlockHeight::new(tick),
            receipt: GlobalReceiptHash::ZERO,
        }
    }

    /// Write `tx`'s row at `height` in `store`'s history, standing as
    /// `state`, or gone.
    fn writing(store: &mut StubStore, height: u64, tx_hash: TxHash, state: Option<RowState>) {
        store
            .entries
            .entry(BlockHeight::new(height))
            .or_default()
            .push((
                MemberCollection::Members.entry(SHARD, tx_hash),
                state.map(|state| to_vec(&row(tx_hash, state)).expect("a row encodes")),
            ));
    }

    /// A base holding 100 at `key(1)` and `tx`'s row run in the tick
    /// at 2 and stated at 3.
    fn stated_at_three(tx_hash: TxHash) -> StubStore {
        let mut store = StubStore::with_cell(key(1), &encode_amount(100));
        writing(&mut store, 2, tx_hash, Some(in_flight(2)));
        writing(&mut store, 3, tx_hash, Some(stated(2)));
        store
    }

    /// The rows of `SHARD`'s family holding `tx` stated in the tick at 2.
    fn rows_stating(tx_hash: TxHash) -> MemberIndex {
        let mut rows = MemberIndex::empty(SHARD);
        rows.members.insert(tx_hash, row(tx_hash, stated(2)));
        rows
    }

    /// The tick output whose only member is `tx`'s leg, holding
    /// `RESERVED` of `key(1)`.
    fn leg(tx_hash: TxHash) -> TickOutput {
        TickOutput {
            determined: Vec::new(),
            provisional: vec![ProvisionalTx {
                tx_hash,
                writes: Some(debit(key(1), RESERVED)),
                reserve: None,
                reserved: BTreeMap::from([(key(1), RESERVED)]),
            }],
        }
    }

    /// What the view at `tick` holds of `key(1)`, by transaction.
    fn held<S: VersionedStore>(chain: &TickChain<S>, tick: u64) -> BTreeMap<TxHash, u128> {
        chain
            .view_at(BlockHeight::new(tick))
            .holds()
            .get(&key(1))
            .cloned()
            .unwrap_or_default()
    }

    /// A stated row's reservation is held once whichever of its leg and
    /// its row the chain takes first: a seed finding the leg in an entry
    /// adds nothing, and an entry appended over a seeded hold takes it
    /// over.
    #[test]
    fn a_stated_rows_reserve_is_held_once() {
        let once = BTreeMap::from([(tx(1), RESERVED)]);

        let ran = TickChain::new(Arc::new(stated_at_three(tx(1))));
        ran.append(BlockHeight::new(2), leg(tx(1)), &[]);
        ran.seed_stated(&rows_stating(tx(1)));
        assert_eq!(
            held(&ran, 3),
            once,
            "the leg holds it, and the seed adds nothing"
        );

        let seeded = TickChain::new(Arc::new(stated_at_three(tx(1))));
        seeded.seed_stated(&rows_stating(tx(1)));
        assert_eq!(held(&seeded, 3), once, "the seed holds it");
        seeded.append(BlockHeight::new(2), leg(tx(1)), &[]);
        assert_eq!(held(&seeded, 3), once, "and the leg takes it over");
    }

    /// The floor raise of a recovery's crossing keeps the reservation of
    /// the stated row whose leg it drops, and lets go of the one whose
    /// row the crossing releases in flight: the crossing tick's baseline
    /// and every one past it hold the stated row's reservation and not
    /// the other.
    #[test]
    fn a_stated_rows_reservation_holds_across_the_floor_raise() {
        let mut store = stated_at_three(tx(1));
        writing(&mut store, 3, tx(2), Some(in_flight(3)));
        writing(
            &mut store,
            5,
            tx(2),
            Some(RowState::Released {
                settlement: Settlement::Shared,
            }),
        );
        let chain = TickChain::new(Arc::new(store));
        chain.append(BlockHeight::new(2), leg(tx(1)), &[]);
        chain.append(BlockHeight::new(3), leg(tx(2)), &[]);
        assert_eq!(
            held(&chain, 3),
            BTreeMap::from([(tx(1), RESERVED), (tx(2), RESERVED)]),
        );

        chain.raise_floor(BlockHeight::new(4), SHARD);
        assert!(chain.is_empty(), "every entry at or below the floor goes");
        for tick in [4, 5, 8] {
            assert_eq!(
                held(&chain, tick),
                BTreeMap::from([(tx(1), RESERVED)]),
                "the view at {tick} holds the stated row's reservation alone",
            );
        }
    }

    /// A replica that ran none of the ticks its store's rows were stated
    /// in holds each stated row's reservation from the row's own holds.
    #[test]
    fn a_fresh_replica_seats_a_stated_rows_reservation_from_its_row() {
        let chain = TickChain::new(Arc::new(stated_at_three(tx(1))));
        assert!(held(&chain, 3).is_empty());
        chain.seed_stated(&rows_stating(tx(1)));
        assert_eq!(held(&chain, 3), BTreeMap::from([(tx(1), RESERVED)]));
    }

    /// A stated hold holds for every view whose base holds the row stated
    /// and none from the height the row leaves at: that base carries
    /// what the row's end writes.
    #[test]
    fn a_stated_hold_is_not_read_at_or_above_its_release() {
        let mut store = stated_at_three(tx(1));
        writing(&mut store, 6, tx(1), Some(RowState::Accepted));
        let chain = TickChain::new(Arc::new(store));
        chain.seed_stated(&rows_stating(tx(1)));
        for tick in [3, 5] {
            assert_eq!(held(&chain, tick), BTreeMap::from([(tx(1), RESERVED)]));
        }
        for tick in [6, 7] {
            assert!(held(&chain, tick).is_empty(), "released by {tick}");
        }
    }

    /// A stated hold stays while the eviction floor is below the height
    /// its row leaves at, a lagging executor holding it there though the
    /// base has persisted past, and goes once the floor reaches it.
    #[test]
    fn a_stated_hold_drops_once_the_eviction_floor_passes_its_release() {
        let mut store = stated_at_three(tx(1));
        writing(&mut store, 6, tx(1), None);
        let chain = TickChain::new(Arc::new(store));
        chain.seed_stated(&rows_stating(tx(1)));

        chain.prune_persisted(BlockHeight::new(8), BlockHeight::new(5));
        assert_eq!(
            held(&chain, 5),
            BTreeMap::from([(tx(1), RESERVED)]),
            "a tick still queued below the release reads the hold",
        );

        chain.prune_persisted(BlockHeight::new(8), BlockHeight::new(6));
        assert!(
            held(&chain, 5).is_empty(),
            "the hold dropped once the eviction floor reached the release",
        );
    }

    /// A legs half committed above the floor reaches every tick at or
    /// above its height through the base: the view below it reads the
    /// balance undebited with the stated row's reservation held, and the
    /// view at it reads the debit and no hold.
    #[test]
    fn a_legs_half_above_the_floor_reaches_readers_through_the_base() {
        let mut store = stated_at_three(tx(1));
        store.history.insert(
            BlockHeight::new(6),
            HashMap::from([(key(1), encode_amount(100 - RESERVED).to_vec())]),
        );
        writing(&mut store, 6, tx(1), Some(RowState::Accepted));
        let chain = TickChain::new(Arc::new(store));
        chain.append(BlockHeight::new(2), leg(tx(1)), &[]);
        chain.raise_floor(BlockHeight::new(4), SHARD);

        let below = chain.view_at(BlockHeight::new(5));
        let balance = |view: &TickView<StubStore>| {
            amount(&view.snapshot().cell(key(1)).expect("the vault stands"))
        };
        assert_eq!(balance(&below), 100);
        assert_eq!(held(&chain, 5), BTreeMap::from([(tx(1), RESERVED)]));
        let at = chain.view_at(BlockHeight::new(6));
        assert_eq!(balance(&at), 100 - RESERVED);
        assert!(held(&chain, 6).is_empty());
    }

    /// A crossing seeds the reservation of a row it keeps stated where no
    /// entry holds the leg: a replica that never ran the stating tick, or
    /// whose run of it lands at or below the floor, holds the reservation
    /// past the crossing as one that ran it does.
    #[test]
    fn a_stated_row_no_run_holds_is_seeded_at_the_crossing() {
        let chain = TickChain::new(Arc::new(stated_at_three(tx(1))));
        chain.raise_floor(BlockHeight::new(4), SHARD);
        assert!(held(&chain, 4).is_empty(), "no run held the leg");
        chain.seed_stated(&rows_stating(tx(1)));
        chain.append(BlockHeight::new(2), leg(tx(1)), &[]);
        assert!(chain.is_empty(), "the late run lands at or below the floor");
        for tick in [4, 5] {
            assert_eq!(held(&chain, tick), BTreeMap::from([(tx(1), RESERVED)]));
        }
    }

    /// A prune whose eviction floor sits below every stated hold's tick
    /// reads no base: a replica booting with nothing executed prunes at a
    /// floor the store may no longer retain.
    #[test]
    fn a_prune_below_every_stated_hold_reads_no_base() {
        let store = Arc::new(stated_at_three(tx(1)));
        let chain = TickChain::new(Arc::clone(&store));
        chain.seed_stated(&rows_stating(tx(1)));
        chain.prune_persisted(BlockHeight::new(8), BlockHeight::GENESIS);
        assert!(
            lock_or_recover(&store.anchors).is_empty(),
            "no base was read at the floor",
        );
        assert_eq!(held(&chain, 3), BTreeMap::from([(tx(1), RESERVED)]));
    }
}
