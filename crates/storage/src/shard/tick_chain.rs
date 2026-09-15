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
//! **Provisional entries are never readable.** A cross-shard
//! transaction's local writes sit beside the determined fold as per-tick
//! provisional entries until the tick's certificate commits. Resolution
//! either promotes them into the readable fold (settled) or drops them
//! (aborted) without recomputing any tick output — no chained output ever
//! depends on an entry that resolution changes.
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

use hyperscale_types::{
    BlockHeight, Movement, ProvisionalHolds, StateWrites, SubstateKey, TickId, TxHash, amount_cell,
    read_amount,
};
use hyperscale_vm_types::{Address, CollectionId};

use crate::lock_recover::{read_or_recover, write_or_recover};
use crate::shard::writes::{
    compose_movements, entry_overlay_range, fold_state_writes, merge_entry_overlay,
};
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
    Restored {
        /// Height of the block that committed the receipts.
        height: BlockHeight,
        /// What each member left, as its receipt states it.
        writes: Vec<(TxHash, StateWrites)>,
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
    /// Lowest base height this fold answers for: the highest stamp it
    /// treats as already carried by the base.
    from: BlockHeight,
    /// One past the highest base height it answers for: the lowest stamp
    /// among the contributions it still folds. `None` when none of them
    /// is stamped, so no base height above `from` changes the partition.
    until: Option<BlockHeight>,
}

impl CachedFold {
    /// Whether the partition this fold was built for is the partition at
    /// `base_at`.
    fn answers_for(&self, base_at: BlockHeight) -> bool {
        self.from <= base_at && self.until.is_none_or(|until| base_at < until)
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
                });
        }
        self.folded = None;
    }

    /// The entry one tick's output produces.
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
                        },
                    )
                })
                .collect(),
            pending: output
                .provisional
                .into_iter()
                .map(|tx| (tx.tx_hash, tx))
                .collect(),
            folded: None,
        }
    }

    /// This entry's fold for a base at `base_at`, rebuilt only when the
    /// one in hand answers for a different partition.
    fn fold_at(&mut self, base_at: BlockHeight) -> &CachedFold {
        if !self
            .folded
            .as_ref()
            .is_some_and(|fold| fold.answers_for(base_at))
        {
            let rebuilt = self.build_fold(base_at);
            self.folded = Some(rebuilt);
        }
        self.folded.as_ref().expect("the fold was just built")
    }

    /// Compose the contributions a base at `base_at` does not carry,
    /// recording the stamps either side of the partition so a later read
    /// can tell whether it still holds.
    ///
    /// Ascending in entry order, because an exclusive write supersedes
    /// what stood before it and a movement composes onto it — an order
    /// the fold has to respect even though movements commute among
    /// themselves.
    fn build_fold(&self, base_at: BlockHeight) -> CachedFold {
        let mut writes = StateWrites::default();
        let mut from = BlockHeight::GENESIS;
        let mut until: Option<BlockHeight> = None;
        for contribution in self.readable.values() {
            if let Some(height) = contribution.in_base_from {
                if height <= base_at {
                    from = from.max(height);
                    continue;
                }
                until = Some(until.map_or(height, |lowest| lowest.min(height)));
            }
            fold_state_writes(&mut writes, &contribution.writes);
        }
        CachedFold {
            writes: Arc::new(writes),
            from,
            until,
        }
    }

    /// Apply a verdict for the members it names: promote each one's
    /// surviving side into the readable fold, or drop it outright, and
    /// record the height the base gains whatever survives at.
    ///
    /// Scoped to the named members because a tick settles in halves. Its
    /// determined members are readable from the append and are stamped
    /// when their own half commits; its legs are unreadable until a
    /// verdict promotes them, which is a later block and sometimes never.
    /// Idempotent per member — a member already resolved is not in
    /// `pending` and its contribution is already stamped.
    fn resolve(&mut self, tick_id: &TickId, resolution: &TickResolution) {
        // A verdict changes both what the entry holds and which stamps
        // bound the partition, so the fold in hand answers for nothing.
        self.folded = None;
        match resolution {
            TickResolution::Settled {
                height,
                members,
                aborted,
            } => {
                for tx_hash in members {
                    // A leg's surviving side becomes readable here; a
                    // determined member has been readable since the
                    // append and only needs its height.
                    if let Some(tx) = self.pending.remove(tx_hash) {
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
                                },
                            );
                        }
                    }
                    if let Some(contribution) = self.readable.get_mut(tx_hash) {
                        contribution.in_base_from = Some(*height);
                    }
                }
            }
            // Seated by the chain rather than applied here: an entry
            // exists only where a tick ran, and the whole point of a
            // restore is that none did.
            TickResolution::Restored { .. } => {}
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
            TickResolution::Abandoned { members } => {
                for tx_hash in members {
                    self.pending.remove(tx_hash);
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
                        "tick {tick_id}: abandoned {tx_hash:?}, whose fold later ticks have read"
                    );
                }
            }
        }
    }

    /// Whether the settled base at `floor` already carries everything
    /// this entry holds, so no future read can still need it.
    fn covered_by(&self, floor: BlockHeight) -> bool {
        self.pending.is_empty()
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
    /// The highest tick whose output has been appended. Ticks execute
    /// serially in height order, so the next tick to run anchors at or
    /// above this — which is what makes it the floor eviction may not
    /// outrun.
    executed: RwLock<BlockHeight>,
    /// The highest height the settled base is known to carry. Read
    /// beside the entries so a contribution is folded exactly while the
    /// base is missing it, and evicted once the base is not.
    persisted: RwLock<BlockHeight>,
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
            executed: RwLock::new(BlockHeight::GENESIS),
            persisted: RwLock::new(persisted),
        }
    }

    /// Append the output of the tick at `height`.
    ///
    /// Same-shard vnodes share one chain and each executes the tick under
    /// its own validator identity, so a height can be appended more than
    /// once. A tick's output is a pure function of the committed chain
    /// prefix, so every repeat carries byte-identical content and the
    /// first append is the whole of it — which is why a repeat is
    /// dropped rather than folded. Folding it would leave an exclusive
    /// write unchanged and apply every movement it carries a second
    /// time, and it would re-add ticks the chain has since resolved.
    pub fn append(&self, height: BlockHeight, output: TickOutput) {
        write_or_recover(&self.entries)
            .entry(height)
            .or_insert_with(|| TickEntry::from_output(output));
        let mut executed = write_or_recover(&self.executed);
        *executed = (*executed).max(height);
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
    /// A [`TickResolution::Restored`] is the one that seats an entry
    /// rather than resolving one, because the tick it speaks for is one
    /// no run of this replica's produced. It never overwrites an entry a
    /// run did produce: where both exist the run is the same function of
    /// the same chain prefix, and the receipts add nothing to it.
    pub fn resolve(&self, tick_id: &TickId, resolution: &TickResolution) {
        let mut entries = write_or_recover(&self.entries);
        if let TickResolution::Restored { height, writes } = resolution {
            let entry = entries
                .entry(tick_id.block_height())
                .or_insert_with(TickEntry::empty);
            entry.restore(*height, writes);
            return;
        }
        if let Some(entry) = entries.get_mut(&tick_id.block_height()) {
            entry.resolve(tick_id, resolution);
        }
    }

    /// Record what the base now carries and drop every tick a future read
    /// can no longer need. Called on `BlockPersisted`.
    ///
    /// The eviction floor is the lower of what has persisted and what has
    /// executed, and the second half is load-bearing. A contribution
    /// enters the base at the height its tick *settled*, which can be
    /// above the anchor a still-queued tick will read from — so dropping
    /// on persistence alone lets eviction outrun a lagging tick queue,
    /// and that tick then finds neither the fold nor a base old enough to
    /// hold it. Two replicas at different execution positions would
    /// derive different receipts from one committed chain.
    pub fn prune_persisted(&self, persisted: BlockHeight) {
        {
            let mut recorded = write_or_recover(&self.persisted);
            *recorded = (*recorded).max(persisted);
        }
        let floor = persisted.min(*read_or_recover(&self.executed));
        write_or_recover(&self.entries).retain(|_, entry| !entry.covered_by(floor));
    }

    /// Tear the chain down. A reshape boundary terminates the shard's
    /// chain; successors seed from settled state, never from tick
    /// outputs.
    pub fn clear(&self) {
        write_or_recover(&self.entries).clear();
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
    /// over the base as of the height it is read at.
    ///
    /// The base is read at `min(tick, persisted)` rather than at the live
    /// tip. Execution runs behind consensus, so a replica whose tick
    /// queue lags has already persisted settlements belonging to *later*
    /// ticks, which 2f+1 other replicas certified without waiting for it;
    /// reading the live base would fold those into this tick's baseline
    /// and split its receipts from the committee's.
    ///
    /// Anchoring alone is not enough, because a read at or above the
    /// persisted tip sees everything the base holds while the overlay may
    /// still hold the same contribution — harmless for an absolute and
    /// wrong for a movement. So the two are made disjoint instead: the
    /// base covers every contribution settled at or below the read
    /// height, the overlay covers the rest, and the answer is the same
    /// whichever side of that line a replica's persistence happens to
    /// sit.
    ///
    /// The view is one layer per tick rather than one merged write set,
    /// and the chain holds those layers rather than the view: a tick's
    /// fold is composed once per partition it is read under, not once
    /// per dispatch. The reader resolves a key across the layers, which
    /// costs it the retained tick count on the keys it actually asks for
    /// instead of costing every dispatch the whole retained content.
    ///
    /// Takes the write lock because refreshing those folds is part of the
    /// read.
    pub fn view_at(&self, tick: BlockHeight) -> TickView<S> {
        let mut overlays: Vec<Arc<StateWrites>> = Vec::new();
        let mut holds = ProvisionalHolds::new();
        // One acquisition for the base height, the layers and the holds.
        // A resolution landing between two reads would drop a leg's hold
        // without the debit it stood for reaching the overlay, and the
        // reader would spend a balance twice.
        let mut entries = write_or_recover(&self.entries);
        let base_at = tick.min(*read_or_recover(&self.persisted));
        // Ascending, so a later tick's layer sits above an earlier one's
        // and the reader can walk them back.
        for (_, entry) in entries.range_mut(..=tick) {
            overlays.extend(entry.fold_at(base_at).layer());
            for leg in entry.pending.values() {
                for (cell, amount) in &leg.reserved {
                    *holds
                        .entry(*cell)
                        .or_default()
                        .entry(leg.tx_hash)
                        .or_default() += *amount;
                }
            }
        }
        drop(entries);
        TickView {
            base: Arc::clone(&self.base),
            anchor: base_at,
            overlays: Arc::new(overlays),
            holds: Arc::new(holds),
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
    /// see, and this is what it may not spend of what it sees.
    #[must_use]
    pub fn holds(&self) -> Arc<ProvisionalHolds> {
        Arc::clone(&self.holds)
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
        // Topmost layer down, stopping at the first exclusive write:
        // that write states the cell outright, so nothing below it is
        // still reachable through it. A movement in the same layer sits
        // above that write and composes onto it, as do the movements of
        // every layer already passed — an order the composition itself
        // is indifferent to, since movements commute.
        let mut moved: Option<Movement> = None;
        let mut written: Option<&Option<Vec<u8>>> = None;
        for overlay in self.overlays.iter().rev() {
            if let Some(movement) = overlay.movements.get(&key) {
                moved =
                    Some(moved.map_or(*movement, |above| compose_movements(key, *movement, above)));
            }
            if let Some(change) = overlay.cells.get(&key) {
                written = Some(change);
                break;
            }
        }
        let Some(moved) = moved else {
            return written.map_or_else(|| self.base_snapshot.cell(key), Clone::clone);
        };
        // A cell the layers only moved resolves here, where the base it
        // moved from is finally in reach; one an exclusive write also
        // reached moves from that write instead.
        let before = written
            .cloned()
            .unwrap_or_else(|| self.base_snapshot.cell(key))
            .as_deref()
            .and_then(read_amount)
            .unwrap_or(0);
        let after = moved.apply(before).unwrap_or_else(|| {
            panic!(
                "BFT CRITICAL: a certified debit runs past what {key:?} holds: held {before}, \
                 moved {moved:?}"
            )
        });
        amount_cell(after).map(|cell| cell.to_vec())
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

    use hyperscale_types::{
        Address, AddressClass, DeclaredRange, EntryKey, Hash, LocalKey, ResourceAddr, ShardId,
        StateRoot, encode_amount,
    };

    use super::*;
    use crate::SubstateStore;

    /// What every cell these fixtures move holds.
    const RESOURCE: ResourceAddr = ResourceAddr::new([0xE1; 31]);
    use crate::lock_recover::lock_or_recover;

    /// A base built from settled write sets at heights, readable as of
    /// any anchor — the store's history without the JMT.
    struct StubStore {
        history: BTreeMap<BlockHeight, HashMap<SubstateKey, Vec<u8>>>,
        tip: BlockHeight,
        /// Anchor heights `snapshot_at` was asked for, so a test can pin
        /// which version a tick read the base at.
        anchors: Mutex<Vec<BlockHeight>>,
    }

    impl StubStore {
        /// A base holding `value` at `key` from genesis, with nothing
        /// settled since.
        fn with_cell(key: SubstateKey, value: &[u8]) -> Self {
            Self::settling(key, value, BlockHeight::GENESIS, value)
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
            }
        }

        fn cells_at(&self, height: BlockHeight) -> HashMap<SubstateKey, Vec<u8>> {
            let mut cells = HashMap::new();
            for (_, settled) in self.history.range(..=height) {
                cells.extend(settled.iter().map(|(k, v)| (*k, v.clone())));
            }
            cells
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

    struct StubSnapshot(HashMap<SubstateKey, Vec<u8>>);
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
            _owner: Address,
            _collection: CollectionId,
            _lo: u128,
            _hi: u128,
            _limit: usize,
        ) -> Vec<(u128, Vec<u8>)> {
            Vec::new()
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
            StubSnapshot(self.cells_at(height))
        }
        fn substate_bytes_at(&self, _height: BlockHeight) -> Option<u64> {
            None
        }
    }

    impl SubstateStore for StubStore {
        type Snapshot<'a> = StubSnapshot;
        fn snapshot(&self) -> Self::Snapshot<'_> {
            StubSnapshot(self.cells_at(self.tip))
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

    fn amount(cell: &[u8]) -> u128 {
        read_amount(cell).expect("an amount cell")
    }

    fn tick(height: u64) -> TickId {
        TickId::new(ShardId::leaf(0, 0), BlockHeight::new(height))
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
        );
        chain.append(
            BlockHeight::new(2),
            TickOutput {
                determined: vec![(tx(2), writes(&[(key(1), None)]))],
                provisional: Vec::new(),
            },
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
        );

        let view = chain.view_at(BlockHeight::new(1));
        assert_eq!(amount(&view.snapshot().cell(key(1)).unwrap()), 700);
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
        );
        chain.append(
            BlockHeight::new(2),
            TickOutput {
                determined: vec![(tx(2), debit(key(1), 200))],
                provisional: Vec::new(),
            },
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
            );
        }

        let view = chain.view_at(BlockHeight::new(2));
        assert_eq!(amount(&view.snapshot().cell(key(1)).unwrap()), 700);
    }

    /// A tick settles in halves, so one entry holds contributions the
    /// base gains at different heights. What a read derives is the same
    /// wherever persistence sits among them: each contribution comes from
    /// the fold below its own settling height and from the base at or
    /// above it, and never from both.
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
        chain.prune_persisted(BlockHeight::new(10));

        // Below both settlements, between them, above both — then back
        // down, because a queued tick anchors below a persistence that
        // has already moved past it.
        for anchor in [4u64, 6, 10, 6, 4] {
            let view = chain.view_at(BlockHeight::new(anchor));
            assert_eq!(
                amount(&view.snapshot().cell(key(1)).unwrap()),
                700,
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
        });
        let chain = TickChain::new(store);
        chain.resolve(
            &tick(3),
            &TickResolution::Restored {
                height: BlockHeight::new(9),
                writes: vec![(tx(7), debit(key(1), 300))],
            },
        );
        chain.prune_persisted(BlockHeight::new(9));

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
        );

        let view = chain.view_at(BlockHeight::new(2));
        assert_eq!(
            view.snapshot()
                .entries_in_range(owner, collection, 0, 10, 10),
            vec![(1, b"rewritten".to_vec())],
            "the rewrite wins its key and the removal takes the other",
        );
    }

    /// A tick reads the base no later than its own height, and no later
    /// than what has persisted. The first keeps a lagging replica — which
    /// has already persisted settlements belonging to ticks it has not
    /// run — from folding them into an earlier tick's baseline. The
    /// second is what makes the base and the overlay disjoint: a read
    /// above the persisted tip sees everything the base holds, so the
    /// overlay has to know exactly where that line is.
    #[test]
    fn a_tick_reads_the_base_no_later_than_its_own_height() {
        let store = Arc::new(StubStore::settling(
            key(1),
            b"base",
            BlockHeight::new(9),
            b"settled",
        ));
        let chain = TickChain::new(Arc::clone(&store));
        chain.prune_persisted(BlockHeight::new(9));

        let _ = chain.view_at(BlockHeight::new(4)).snapshot();
        let _ = chain.view_at(BlockHeight::new(12)).snapshot();

        assert_eq!(
            *lock_or_recover(&store.anchors),
            vec![BlockHeight::new(4), BlockHeight::new(9)],
            "the anchor is the tick, clamped to what has persisted"
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
            );
        }

        chain.resolve(
            &tick(4),
            &TickResolution::Settled {
                height: BlockHeight::new(6),
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

        chain.prune_persisted(BlockHeight::new(6));
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
        );

        chain.resolve(
            &w,
            &TickResolution::Settled {
                height: BlockHeight::new(3),
                members: BTreeSet::from([tx(7)]),
                aborted: BTreeSet::from([tx(7)]),
            },
        );
        let view = chain.view_at(BlockHeight::new(1));
        assert_eq!(view.snapshot().cell(key(1)), Some(b"base".to_vec()));
        assert_eq!(view.snapshot().cell(key(9)), Some(b"floor".to_vec()));
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
        );

        chain.resolve(
            &w,
            &TickResolution::Abandoned {
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
        );

        // The determined half settles on its own; the leg is untouched.
        chain.resolve(
            &w,
            &TickResolution::Settled {
                height: BlockHeight::new(1),
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
        chain.prune_persisted(BlockHeight::new(1));
        assert_eq!(chain.len(), 0);
    }

    /// Same-shard vnodes share one chain and each appends the tick it
    /// executed. The outputs are byte-identical, so the second is
    /// dropped: refolding it would leave an absolute unchanged and apply
    /// every movement a second time.
    #[test]
    fn a_repeated_append_is_dropped_rather_than_refolded() {
        let store = Arc::new(StubStore::with_cell(key(1), encode_amount(1_000).as_ref()));
        let chain = TickChain::new(store);
        let output = || TickOutput {
            determined: vec![(tx(1), debit(key(1), 100))],
            provisional: Vec::new(),
        };
        chain.append(BlockHeight::new(1), output());
        chain.append(BlockHeight::new(1), output());

        let view = chain.view_at(BlockHeight::new(1));
        assert_eq!(amount(&view.snapshot().cell(key(1)).unwrap()), 900);
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
        );
        chain.resolve(
            &w,
            &TickResolution::Settled {
                height: BlockHeight::new(8),
                members: BTreeSet::from([tx(7)]),
                aborted: BTreeSet::new(),
            },
        );
        chain.prune_persisted(BlockHeight::new(10));
        assert_eq!(
            chain.len(),
            1,
            "execution has only reached tick 3, so the fold is retained"
        );

        // A queued tick anchored below the settlement needs the fold.
        let view = chain.view_at(BlockHeight::new(5));
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
        );

        // Unresolved: survives any persistence progress.
        chain.prune_persisted(BlockHeight::new(10));
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
        chain.prune_persisted(BlockHeight::new(3));
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
        );
        chain.prune_persisted(BlockHeight::new(2));
        assert_eq!(chain.len(), 2, "persistence has not caught up");
        chain.prune_persisted(BlockHeight::new(3));
        assert_eq!(chain.len(), 1, "only the settled tick evicts");
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
        );
        chain.resolve(&w, &settled);
        chain.resolve(&w, &settled);
        chain.prune_persisted(BlockHeight::new(1));
        assert!(chain.is_empty());
    }
}
