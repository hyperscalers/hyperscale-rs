//! What a sweep retires, and how a leaf says so.
//!
//! A sweepable cell answers "am I still needed" from itself: its value
//! carries the expiry it stops being needed at, and its key derives from
//! that expiry. Nothing weaker travels. A rule keyed off the transaction
//! needs the body retention drops; a rule keyed off a side index needs
//! an index a split child does not inherit. The prefix is the only thing
//! guaranteed to arrive, so the cell has to carry the answer.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use hyperscale_jmt::NibblePath;
use hyperscale_types::{
    Address, Block, Finalization, LocalKey, MAX_SWEEP_PER_BLOCK, SWEEP_BUCKET_BYTES, SettledWrites,
    ShardId, ShardTrie, StoredReceipt, SubstateKey, SweepBucket, SweepFrontier, Transaction,
    TxHash, Verifiable, WeightedTimestamp, protocol_statics, protocol_statics_installed,
};
use hyperscale_vm_effects::{Marked, Marker, ProtocolHasher, committed_tx_key};

use crate::tree::JmtSnapshot;
use crate::{
    Anchored, filter_state_writes_to_prefix, filter_writes_to_prefix, key_under_prefix,
    merge_receipts, settle_writes,
};

/// When a committed cell stops being needed, or `None` for every cell a
/// sweep does not reach.
///
/// The judgement is the VM's, for the reason it is the VM's for a
/// package cell: the value re-derives the key under its family's own
/// domain, so no tag and no trust in the writer enters into it. Every
/// backend indexes through here — the commit batch and the import that
/// rebuilds a store from leaves alike — because an index built one way
/// at commit and another at import is an index two replicas would sweep
/// different sets from.
///
/// Without the protocol answers installed (bare storage tests) nothing
/// is sweepable, matching the package index's seam.
#[must_use]
pub fn sweepable_expiry(key: SubstateKey, value: &[u8]) -> Option<u64> {
    if !protocol_statics_installed() {
        return None;
    }
    protocol_statics().sweepable_cell(key.owner.to_bytes(), key.local.0, value)
}

/// Whether a committed cell is an escrow record — value the shard holds
/// for a crossing it issued.
///
/// The same seam as [`sweepable_expiry`] and its complement: a record is
/// outside every sweep's reach by construction, so a store that inherits
/// a prefix whole has nothing else to tell it that the leaf it just
/// imported is an obligation. Lives here because both questions are the
/// same question about a leaf — which family wrote it — asked of the one
/// authority that can answer from the bytes.
#[must_use]
pub fn is_record_cell(key: SubstateKey, value: &[u8]) -> bool {
    protocol_statics_installed()
        && protocol_statics().record_cell(key.owner.to_bytes(), key.local.0, value)
}

/// One row of the sweep index: an owner holding sweepable cells in a
/// bucket.
pub type SweepRow = (SweepBucket, Address);

/// The sweep index's rows: how many live sweepable cells each owner
/// holds in each expiry bucket, bucket-major so a sweep walks by expiry
/// over a keyspace that is owner-major.
///
/// Derived state — the leaves are the authority — kept because nothing
/// about a leaf key lets a walk find the next cell to expire. What a
/// row answers is which owners hold cells in which bucket; which cells
/// is the leaves' own answer, since the bucket leads a sweepable cell's
/// local half and one row's cells are a contiguous leaf-key range.
///
/// Signed, because one shape carries both what a batch moves and what a
/// store holds: the movement folds into the total through
/// [`SweepRows::fold`], which is where a row that would go negative —
/// an index disagreeing with the leaves it derives from — is caught.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SweepRows(BTreeMap<SweepRow, i64>);

impl SweepRows {
    /// Move one cell's write across the rows: `was` is the expiry the
    /// prior value carried, `now` the one the written value carries. A
    /// value sweepable in the same row as its prior moves nothing, which
    /// is why the no-op writes a backend skips need no entry here either.
    pub fn delta(&mut self, owner: Address, was: Option<u64>, now: Option<u64>) {
        if was == now {
            return;
        }
        if let Some(expiry) = was {
            self.add((SweepBucket::of(expiry), owner), -1);
        }
        if let Some(expiry) = now {
            self.add((SweepBucket::of(expiry), owner), 1);
        }
    }

    fn add(&mut self, row: SweepRow, by: i64) {
        let count = self.0.entry(row).or_default();
        *count += by;
        if *count == 0 {
            self.0.remove(&row);
        }
    }

    /// Whether no row moved, or none is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The rows in walk order, each with its count.
    pub fn iter(&self) -> impl Iterator<Item = (SweepRow, i64)> + '_ {
        self.0.iter().map(|(row, count)| (*row, *count))
    }

    /// The rows from `bucket` on, in walk order.
    pub fn from_bucket(&self, bucket: SweepBucket) -> impl Iterator<Item = SweepRow> + '_ {
        self.0.range((bucket, Address::MIN)..).map(|(row, _)| *row)
    }

    /// Fold what a batch `moved` into this total. A row that empties is
    /// dropped, so the index holds exactly the pairs that have something
    /// in them and a walk visits nothing empty.
    ///
    /// # Panics
    ///
    /// If a row would go negative; see [`SweepRows::fold_row`].
    pub fn fold(&mut self, moved: &Self) {
        for (row, delta) in moved.iter() {
            let held = self.0.get(&row).copied().unwrap_or(0);
            match Self::fold_row(row, held, delta) {
                0 => {
                    self.0.remove(&row);
                }
                count => {
                    self.0.insert(row, count);
                }
            }
        }
    }

    /// The count `row` holds once `delta` moves `held`; zero means the
    /// row empties.
    ///
    /// # Panics
    ///
    /// If the count would go negative, which means the index disagrees
    /// with the leaves it is derived from — the same class of fault as
    /// the byte total's checked add, and caught here rather than allowed
    /// to under-report a sweep's candidates.
    #[must_use]
    pub fn fold_row(row: SweepRow, held: i64, delta: i64) -> i64 {
        let count = held
            .checked_add(delta)
            .expect("a sweep-index count stays inside i64");
        assert!(
            count >= 0,
            "sweep index for {row:?} went to {count}, so it disagrees with the leaves"
        );
        count
    }

    /// Keep the rows of owners under `prefix`, returning the rows
    /// dropped.
    ///
    /// A reshape adoption re-roots the tree at a subtree but leaves the
    /// cell column whole, so a split child's cells are a superset of its
    /// own leaves — the sibling's are still sitting in it. Every other
    /// index survives that because every other index is read
    /// owner-scoped, and a transaction on a child names only owners the
    /// child holds. A sweep is the one walk that enumerates the whole
    /// shard, so it is the one to meet them.
    ///
    /// Rows are keyed by owner, which makes the drop exact: an owner is
    /// wholly one child's or the other's, so dropping its row drops the
    /// sibling's cells from the walk and leaves the counts of what
    /// remains untouched. A replica that snap-syncs the same child
    /// instead of cloning it rebuilds the index from the leaves it
    /// imported and so holds these rows and no others; that the two
    /// agree is what makes a removal set a function of committed state
    /// rather than of how a node got there.
    pub fn retain_under(&mut self, prefix: &NibblePath) -> Vec<SweepRow> {
        if prefix.is_empty() {
            return Vec::new();
        }
        let (kept, dropped): (BTreeMap<_, _>, BTreeMap<_, _>) = std::mem::take(&mut self.0)
            .into_iter()
            .partition(|((_, owner), _)| owner_under(*owner, prefix));
        self.0 = kept;
        dropped.into_keys().collect()
    }

    /// The sweep walk, over rows and leaves read however a backend reads
    /// them: the sweepable cells strictly after `after` and in buckets
    /// strictly below `below`, in sweep order, at most `limit` of them,
    /// each with the expiry its value carries.
    ///
    /// Index rows from `after`'s bucket in `(bucket, owner)` order, then
    /// that pair's leaves in local order. The two walks composed are
    /// already sweep order, so nothing sorts and stopping at `limit` is
    /// stopping rather than discarding — what makes the cap a bound on
    /// work and not only on output. `rows_from(bucket)` reads the rows
    /// from `bucket` on; `leaves_between(lo, hi, each)` visits one row's
    /// leaves in `lo..=hi` until `each` answers `false`.
    pub fn walk<Rows>(
        after: SweepFrontier,
        below: SweepBucket,
        limit: usize,
        rows_from: impl FnOnce(SweepBucket) -> Rows,
        mut leaves_between: impl FnMut(
            SubstateKey,
            SubstateKey,
            &mut dyn FnMut(SubstateKey, &[u8]) -> bool,
        ),
    ) -> Vec<(SubstateKey, u64)>
    where
        Rows: IntoIterator<Item = SweepRow>,
    {
        if limit == 0 || after.bucket() >= below {
            return Vec::new();
        }
        let mut found = Vec::new();
        for (bucket, owner) in rows_from(after.bucket()) {
            if bucket >= below || found.len() >= limit {
                break;
            }
            let (lo, hi) = leaf_span(owner, bucket);
            leaves_between(lo, hi, &mut |key, value| {
                if SweepFrontier::of_leaf(key) > after
                    && let Some(expiry) = sweepable_expiry(key, value)
                {
                    found.push((key, expiry));
                }
                found.len() < limit
            });
        }
        found
    }
}

impl FromIterator<(SweepRow, i64)> for SweepRows {
    fn from_iter<I: IntoIterator<Item = (SweepRow, i64)>>(rows: I) -> Self {
        Self(rows.into_iter().filter(|(_, count)| *count != 0).collect())
    }
}

/// Whether every cell of `owner` sits under `prefix`: a leaf key leads
/// with its owner, so an owner is wholly one prefix's.
fn owner_under(owner: Address, prefix: &NibblePath) -> bool {
    let leaf = SubstateKey {
        owner,
        local: LocalKey([0; 16]),
    };
    key_under_prefix(&leaf.to_bytes(), prefix)
}

/// The lowest and highest keys one owner's cells in one bucket can
/// take: the bucket leads a sweepable cell's local half, so the pair is
/// a prefix of the leaf key and the span is that prefix with the rest of
/// the local half at its two extremes.
fn leaf_span(owner: Address, bucket: SweepBucket) -> (SubstateKey, SubstateKey) {
    let bounded = |fill: u8| {
        let mut local = [fill; 16];
        local[..SWEEP_BUCKET_BYTES].copy_from_slice(&bucket.to_bytes());
        SubstateKey {
            owner,
            local: LocalKey(local),
        }
    };
    (bounded(0x00), bounded(0xFF))
}

/// Read access to the sweepable cells this store's committed state
/// holds, in sweep order.
///
/// The default is the empty index, for stores that never commit one
/// (test doubles, ephemeral views).
pub trait SweepIndex {
    /// The sweepable cells strictly after `after` and in buckets
    /// strictly below `below`, in sweep order, at most `limit` of them,
    /// each with the expiry its value carries — [`SweepRows::walk`] over
    /// this store's rows and leaves.
    ///
    /// `below` is a bucket rather than a position because a block's
    /// ceiling is always a bucket boundary: every cell this returns is
    /// in a bucket wholly in the past.
    fn sweep_candidates(
        &self,
        after: SweepFrontier,
        below: SweepBucket,
        limit: usize,
    ) -> Vec<(SubstateKey, u64)> {
        let _ = (after, below, limit);
        Vec::new()
    }
}

/// The cells a block anchored at `clock` removes, and where its frontier
/// lands.
///
/// The pair is the whole of a block's sweep. Removals are the sweepable
/// cells strictly above the parent's frontier and strictly below the
/// ceiling `clock` allows, in sweep order, at most
/// [`MAX_SWEEP_PER_BLOCK`]; the frontier is where the walk stopped.
///
/// It stops in one of two places, and which one is the block's claim
/// about whether it finished:
///
/// - **At the ceiling**, when fewer than the cap remained. Nothing
///   sweepable is left below the clock's own bucket, so the frontier
///   takes the ceiling itself and the next block starts from there.
/// - **On the last cell removed**, when the cap is what stopped it. The
///   frontier names that cell's position, so the next block resumes at
///   exactly the next one — a same-instant pile drains across blocks
///   rather than landing whole on whichever block straddles it.
///
/// A block whose ceiling has not moved past its parent's frontier
/// removes nothing and repeats the frontier it inherited. That is the
/// ordinary case at sub-second block times against a bucket spanning a
/// minute, which is why the frontier's own rule is monotone rather than
/// strictly advancing — the obligation that bites is reaching the
/// ceiling, not moving at all.
#[must_use]
pub fn sweep_for_block(
    store: &(impl SweepIndex + ?Sized),
    parent_frontier: SweepFrontier,
    clock: WeightedTimestamp,
) -> (Vec<SubstateKey>, SweepFrontier) {
    let ceiling = SweepFrontier::ceiling_at(clock);
    if parent_frontier >= ceiling {
        return (Vec::new(), parent_frontier);
    }
    let found = store.sweep_candidates(parent_frontier, ceiling.bucket(), MAX_SWEEP_PER_BLOCK);
    let capped = found.len() >= MAX_SWEEP_PER_BLOCK;
    let frontier = match found.last() {
        Some((key, _)) if capped => SweepFrontier::of_leaf(*key),
        _ => ceiling,
    };
    (found.into_iter().map(|(key, _)| key).collect(), frontier)
}

/// The layered sweep walk every overlay reader shares: the base's
/// candidates at a limit widened by what the overlay retires, then the
/// overlay's own sweepable cells folded in and its removals taken out.
///
/// The widening is what lets an interval the overlay has mostly retired
/// still fill `limit` from the cells behind it — the shape
/// [`merge_entry_overlay_with`](crate::merge_entry_overlay_with) already
/// has, and for the same reason.
///
/// Both directions matter and both break state if missed. A cell an
/// unpersisted ancestor created reads as absent from the base, so a
/// removal the chain owes would go unmade; a cell one retired reads as
/// live, so a removal would be made twice — and the second lands on a
/// key the tree no longer holds.
#[must_use]
pub fn merge_sweep_overlay(
    base: impl FnOnce(usize) -> Vec<(SubstateKey, u64)>,
    overlay: &[Arc<JmtSnapshot>],
    after: SweepFrontier,
    below: SweepBucket,
    limit: usize,
) -> Vec<(SubstateKey, u64)> {
    if limit == 0 || after.bucket() >= below {
        return Vec::new();
    }
    // What the unpersisted chain says about cells in the interval, latest
    // write per key, `None` where it retired one.
    let mut touched: BTreeMap<SubstateKey, Option<u64>> = BTreeMap::new();
    for snapshot in overlay {
        for (key, change) in snapshot.settled.cells() {
            let position = SweepFrontier::of_leaf(*key);
            if position <= after || position.bucket() >= below {
                continue;
            }
            touched.insert(
                *key,
                change
                    .as_deref()
                    .and_then(|bytes| sweepable_expiry(*key, bytes)),
            );
        }
    }
    let retired = touched.values().filter(|expiry| expiry.is_none()).count();
    let mut merged: BTreeMap<SweepFrontier, (SubstateKey, u64)> =
        base(limit.saturating_add(retired))
            .into_iter()
            .map(|(key, expiry)| (SweepFrontier::of_leaf(key), (key, expiry)))
            .collect();
    for (key, expiry) in touched {
        let position = SweepFrontier::of_leaf(key);
        match expiry {
            Some(expiry) => {
                merged.insert(position, (key, expiry));
            }
            None => {
                merged.remove(&position);
            }
        }
    }
    merged.into_values().take(limit).collect()
}

/// Fold what the block itself writes — the committed-transaction cells
/// it creates, and the sweep's removals with the refusals' retractions
/// — into the settled set its receipts produced.
///
/// All are ordinary writes, a value at the key or `None` at it, so
/// none needs a commit path of its own: they fold with everything else
/// and land under `state_root` like any other change. That is the fact
/// that makes this tractable rather than novel.
///
/// # Panics
///
/// If a creation or a removal names a cell the block's own receipts
/// also write, or a removal is named twice. The two would be one entry
/// in the settled map, so one of them would silently not happen — and
/// which one is decided by insertion order, which is not something a
/// validator can check. A creation sits under the shard's own owner,
/// which no receipt writes, validation refuses a block sweeping what it
/// writes before anything reaches here, and [`removals_of`] names each
/// removal once; this is the assertion that all three hold.
#[must_use]
pub fn with_sweep(
    settled: SettledWrites,
    creations: &[(SubstateKey, Vec<u8>)],
    removals: &[SubstateKey],
) -> SettledWrites {
    if creations.is_empty() && removals.is_empty() {
        return settled;
    }
    let (mut cells, entries) = settled.into_parts();
    for (key, value) in creations {
        assert!(
            cells.insert(*key, Some(value.clone())).is_none(),
            "the chain created {key:?}, which this block's receipts also write",
        );
    }
    for key in removals {
        assert!(
            cells.insert(*key, None).is_none(),
            "a sweep removed {key:?}, which this block's receipts also write",
        );
    }
    SettledWrites::from_parts(cells, entries)
}

/// Everything a block removes, each once: what its sweep retires, and
/// the committed cells its finalizations' refusals retract.
///
/// One set, because a refused transaction's cell can fall to the sweep
/// in the block that retracts it, and a removal named twice would be
/// two `None`s at one key. Ascending, so the fold walks one order.
#[must_use]
pub fn removals_of(
    swept: &[SubstateKey],
    finalizations: &[Arc<Verifiable<Finalization>>],
) -> Vec<SubstateKey> {
    let mut removals: BTreeSet<SubstateKey> = swept.iter().copied().collect();
    removals.extend(finalizations.iter().flat_map(|fw| fw.retractions()));
    removals.into_iter().collect()
}

/// The cells a followed block removed: everything sweepable strictly
/// after `parent_frontier` and at or below `frontier`, the position the
/// block's header claims its sweep landed on.
///
/// A follower holds a prefix of the chain's tree and no cap of its own:
/// it removes exactly what the header's interval names, whether that
/// interval ended at a ceiling or on the last cell a capped walk took.
#[must_use]
pub fn sweep_through(
    store: &(impl SweepIndex + ?Sized),
    parent_frontier: SweepFrontier,
    frontier: SweepFrontier,
) -> Vec<SubstateKey> {
    if parent_frontier >= frontier {
        return Vec::new();
    }
    let past = SweepBucket(frontier.bucket().0.saturating_add(1));
    store
        .sweep_candidates(parent_frontier, past, usize::MAX)
        .into_iter()
        .map(|(key, _)| key)
        .filter(|key| SweepFrontier::of_leaf(*key) <= frontier)
        .collect()
}

/// What a followed block writes under `prefix`, composed as the chain
/// composed it.
///
/// The receipts its ticks settled, the committed cells its committer
/// derived, the sweep its header names, and the cells its refusals
/// retract.
///
/// The removals read `store` as it stands before the block, from the
/// bottom of the sweep order: a follower mirrors the chain's state, so
/// every live cell at or below the header's frontier is one the block
/// removed, and one the block created sits far above it. The creations
/// are the caller's, derived under the block's own window as the
/// committer derived them.
#[must_use]
pub fn followed_block_writes(
    store: &(impl SweepIndex + ?Sized),
    prior: &dyn Anchored,
    block: &Block,
    creations: &[(SubstateKey, Vec<u8>)],
    prefix: &NibblePath,
) -> SettledWrites {
    let settling: Vec<StoredReceipt> = block
        .certificates()
        .iter()
        .flat_map(|fw| fw.settling_receipts())
        .collect();
    // Restricted before resolving: a follower holds its prefix of the
    // tree and nothing else, so a movement on any other cell reads an
    // empty prior here and is the owning store's to judge, not this one's.
    let merged = settle_writes(
        &filter_state_writes_to_prefix(&merge_receipts(&settling), prefix),
        prior,
    );
    let swept = sweep_through(store, SweepFrontier::ZERO, block.header().sweep_frontier());
    let removals = removals_of(&swept, block.certificates());
    filter_writes_to_prefix(&with_sweep(merged, creations, &removals), prefix)
}

/// The committed-transaction cells `local_shard` writes for
/// `transactions`: one each, under the shard's own owner, expiring at
/// the transaction's validity end plus the grace.
///
/// What makes a shard's committed set provable and refutable against the
/// state root every header carries. Derived from the transactions and
/// the shard's identity, so every replica folds the same cells and a
/// prober holding the transaction derives the same key from nothing
/// else.
///
/// Every transaction a block carries, and no reading of placement. A
/// rule that gave only some of them would make a block's creations a
/// function of the trie the reader classified under, and a split child
/// following its parent's block classifies under the cut — so the halves
/// would not recompose the parent's root. Which absences *answer* is a
/// separate rule, and lives where the probe is composed.
#[must_use]
pub fn committed_tx_cells<'a>(
    local_shard: ShardId,
    transactions: impl IntoIterator<Item = &'a Transaction>,
) -> Vec<(SubstateKey, Vec<u8>)> {
    transactions
        .into_iter()
        .map(|tx| {
            let validity_end = tx.validity_range().end_timestamp_exclusive;
            let cell = Marker::of(tx.hash(), validity_end.as_millis(), Marked::Committed);
            (
                committed_tx_cell_key(local_shard, cell.tx, validity_end),
                cell.to_bytes(),
            )
        })
        .collect()
}

/// The key `shard` writes its committed cell for `tx` under.
///
/// Derived from signed content and the shard alone, so a prober asking
/// whether a shard committed a transaction names the same cell the
/// shard's own commit wrote, from nothing but the transaction and the
/// shard.
#[must_use]
pub fn committed_tx_cell_key(
    shard: ShardId,
    tx: TxHash,
    validity_end: WeightedTimestamp,
) -> SubstateKey {
    committed_tx_key(
        &ProtocolHasher,
        ShardTrie::shard_owner(shard),
        tx,
        Marked::Committed.expiry_ms(validity_end.as_millis()),
    )
}

#[cfg(test)]
mod tests {
    use hyperscale_types::test_utils::{install_stub_protocol_statics, stub_sweepable_cell};
    use hyperscale_types::{AddressClass, BlockHeight, SWEEP_BUCKET_MS, StateRoot};

    use super::*;
    use crate::CollectedWrites;

    fn owner(tag: u8) -> Address {
        Address::new([tag; 31], AddressClass::Principal)
    }

    /// A sweepable cell of `owner`, expiring in `bucket`.
    fn cell(tag: u8, bucket: u32, body: u8) -> (SubstateKey, u64, Vec<u8>) {
        let expiry = u64::from(bucket) * SWEEP_BUCKET_MS;
        let (local, value) = stub_sweepable_cell(expiry, body);
        (
            SubstateKey {
                owner: owner(tag),
                local,
            },
            expiry,
            value,
        )
    }

    /// A pending ancestor whose settled writes are `cells`.
    fn ancestor(cells: Vec<(SubstateKey, Option<Vec<u8>>)>) -> Arc<JmtSnapshot> {
        Arc::new(JmtSnapshot::from_collected_writes(
            CollectedWrites::default(),
            SettledWrites::from_absolutes(cells.into_iter().collect()),
            StateRoot::ZERO,
            BlockHeight::GENESIS,
            StateRoot::ZERO,
            BlockHeight::new(1),
        ))
    }

    fn all() -> SweepBucket {
        SweepBucket(u32::MAX)
    }

    /// The span covers exactly the bucket's leaves of one owner: every
    /// body inside, neither neighbouring bucket, and no other owner —
    /// which is what makes the pair the unit the index rows count.
    #[test]
    fn a_leaf_span_covers_a_buckets_leaves_and_no_others() {
        let (lo, hi) = leaf_span(owner(3), SweepBucket(9));
        let leaf = |bucket: u32, body: u8| {
            let mut local = [body; 16];
            local[..SWEEP_BUCKET_BYTES].copy_from_slice(&bucket.to_be_bytes());
            SubstateKey {
                owner: owner(3),
                local: LocalKey(local),
            }
        };
        for body in [0x00, 0x7F, 0xFF] {
            let inside = leaf(9, body);
            assert!(lo <= inside && inside <= hi, "body {body:02x}");
        }
        assert!(leaf(8, 0xFF) < lo);
        assert!(leaf(10, 0x00) > hi);
        let elsewhere = SubstateKey {
            owner: owner(4),
            local: LocalKey([0; 16]),
        };
        assert!(elsewhere > hi);
    }

    /// One shape carries a batch's movement and a store's total: a
    /// cell's write moves a row by one, a rewrite in the same row moves
    /// nothing, and folding the movement empties the row it drains.
    #[test]
    fn rows_move_by_what_a_write_changes_and_fold_into_the_total() {
        let mut total = SweepRows::default();
        let mut moved = SweepRows::default();
        moved.delta(owner(1), None, Some(3 * SWEEP_BUCKET_MS));
        moved.delta(owner(1), None, Some(3 * SWEEP_BUCKET_MS + 1));
        moved.delta(
            owner(2),
            Some(5 * SWEEP_BUCKET_MS),
            Some(5 * SWEEP_BUCKET_MS + 9),
        );
        assert_eq!(
            moved.iter().collect::<Vec<_>>(),
            vec![((SweepBucket(3), owner(1)), 2)],
            "a rewrite inside one bucket moves nothing",
        );
        total.fold(&moved);

        let mut retired = SweepRows::default();
        retired.delta(owner(1), Some(3 * SWEEP_BUCKET_MS), None);
        total.fold(&retired);
        assert_eq!(
            total.from_bucket(SweepBucket(0)).collect::<Vec<_>>(),
            vec![(SweepBucket(3), owner(1))],
        );
        total.fold(&retired);
        assert!(total.is_empty(), "the row that drained is gone");
    }

    #[test]
    #[should_panic(expected = "disagrees with the leaves")]
    fn a_row_folding_below_zero_is_a_fault() {
        let mut retired = SweepRows::default();
        retired.delta(owner(1), Some(3 * SWEEP_BUCKET_MS), None);
        SweepRows::default().fold(&retired);
    }

    /// Rows keep or go by their owner's prefix alone, and the rows that
    /// went are handed back for a store whose index lives elsewhere.
    #[test]
    fn rows_outside_the_prefix_are_dropped_and_named() {
        let mut left = NibblePath::empty();
        left.push_bits(0, 1);
        let under = Address::new([0x00; 31], AddressClass::Principal);
        let outside = Address::new([0x80; 31], AddressClass::Principal);
        let mut rows: SweepRows = [
            ((SweepBucket(1), under), 1),
            ((SweepBucket(1), outside), 1),
            ((SweepBucket(2), outside), 3),
        ]
        .into_iter()
        .collect();
        let dropped = rows.retain_under(&left);
        assert_eq!(
            dropped,
            vec![(SweepBucket(1), outside), (SweepBucket(2), outside)]
        );
        assert_eq!(
            rows.iter().collect::<Vec<_>>(),
            vec![((SweepBucket(1), under), 1)]
        );
        assert!(
            SweepRows::default()
                .retain_under(&NibblePath::empty())
                .is_empty()
        );
    }

    /// A cell an unpersisted ancestor created is one this block owes a
    /// removal for, and the persisted store does not know it exists.
    #[test]
    fn the_overlay_adds_what_an_ancestor_created() {
        install_stub_protocol_statics();
        let (key, expiry, value) = cell(1, 3, 0x11);
        let merged = merge_sweep_overlay(
            |_| Vec::new(),
            &[ancestor(vec![(key, Some(value))])],
            SweepFrontier::ZERO,
            all(),
            10,
        );
        assert_eq!(merged, vec![(key, expiry)]);
    }

    /// And one an ancestor retired is not swept a second time — the
    /// second removal would land on a key the tree no longer holds.
    #[test]
    fn the_overlay_drops_what_an_ancestor_retired() {
        install_stub_protocol_statics();
        let (key, expiry, _) = cell(1, 3, 0x11);
        let merged = merge_sweep_overlay(
            |_| vec![(key, expiry)],
            &[ancestor(vec![(key, None)])],
            SweepFrontier::ZERO,
            all(),
            10,
        );
        assert!(merged.is_empty());
    }

    /// The base fetch widens by what the overlay retires, so an interval
    /// the overlay has mostly emptied still fills the limit from the
    /// cells behind it.
    #[test]
    fn the_base_fetch_widens_by_what_the_overlay_retired() {
        install_stub_protocol_statics();
        let (gone, gone_expiry, _) = cell(1, 3, 0x11);
        let (kept, kept_expiry, _) = cell(1, 3, 0x22);
        let asked = std::cell::Cell::new(0usize);
        let merged = merge_sweep_overlay(
            |widened| {
                asked.set(widened);
                vec![(gone, gone_expiry), (kept, kept_expiry)]
            },
            &[ancestor(vec![(gone, None)])],
            SweepFrontier::ZERO,
            all(),
            1,
        );
        assert_eq!(asked.get(), 2, "one retired, so one more was asked for");
        assert_eq!(merged, vec![(kept, kept_expiry)]);
    }

    /// A write outside the interval changes nothing, whichever side of
    /// it the write falls on.
    #[test]
    fn the_overlay_ignores_writes_outside_the_interval() {
        install_stub_protocol_statics();
        let (below, _, below_value) = cell(1, 2, 0x11);
        let (above, _, above_value) = cell(1, 9, 0x22);
        let merged = merge_sweep_overlay(
            |_| Vec::new(),
            &[ancestor(vec![
                (below, Some(below_value)),
                (above, Some(above_value)),
            ])],
            SweepFrontier::start_of(SweepBucket(3)),
            SweepBucket(9),
            10,
        );
        assert!(merged.is_empty());
    }

    /// The chain's own creations fold in beside the sweep's removals, as
    /// ordinary writes under the same root.
    #[test]
    fn creations_fold_in_beside_removals() {
        let (created, _, value) = cell(1, 3, 0xC1);
        let (removed, _, _) = cell(2, 1, 0xD1);
        let settled = with_sweep(
            SettledWrites::default(),
            &[(created, value.clone())],
            &[removed],
        );
        assert_eq!(settled.cells().get(&created), Some(&Some(value)));
        assert_eq!(settled.cells().get(&removed), Some(&None));
    }

    /// A refusal's retraction removes the cell beside the sweep, and a
    /// cell both name is removed once.
    #[test]
    fn a_refusals_retraction_removes_beside_the_sweep_once() {
        use hyperscale_types::test_utils::finalization_of;
        use hyperscale_types::{BlockHeight, ExecutionOutcome, Hash, TxOutcome};

        let tx = |seed: u8| TxHash::from(Hash::from_bytes(&[seed; 32]));
        let (swept, _, _) = cell(1, 1, 0xD1);
        let (retracted, _, _) = cell(2, 3, 0xC2);
        let finalizations = vec![Arc::new(Verifiable::from(finalization_of(
            BlockHeight::new(1),
            vec![
                TxOutcome::new(tx(1), ExecutionOutcome::Failed).retracting(Some(retracted)),
                TxOutcome::new(tx(2), ExecutionOutcome::Aborted).retracting(Some(swept)),
            ],
        )))];
        let mut expected = vec![swept, retracted];
        expected.sort_unstable();
        assert_eq!(removals_of(&[swept], &finalizations), expected);
        let settled = with_sweep(
            SettledWrites::default(),
            &[],
            &removals_of(&[swept], &finalizations),
        );
        assert_eq!(settled.cells().get(&retracted), Some(&None));
        assert_eq!(settled.cells().get(&swept), Some(&None));
    }

    /// One committed cell per transaction given, under the shard's own
    /// owner, self-describing as sweepable at the transaction's validity
    /// end plus the grace — the same cells whether a proposer or a
    /// verifier derives them.
    #[test]
    fn a_block_creates_one_committed_cell_per_transaction() {
        use hyperscale_hbor::from_slice;
        use hyperscale_types::test_utils::{install_stub_protocol_statics, test_transaction};
        use hyperscale_vm_effects::Marker;
        use hyperscale_vm_types::ARTIFACT_GRACE_MS;

        install_stub_protocol_statics();
        let shard = ShardId::leaf(1, 1);
        let txs = [test_transaction(1), test_transaction(2)];
        let cells = committed_tx_cells(shard, txs.iter());
        assert_eq!(cells.len(), 2);
        for ((key, value), tx) in cells.iter().zip(&txs) {
            assert!(ShardTrie::shard_owns_prefix(shard, key.owner));
            let decoded: Marker = from_slice(value).expect("decodes");
            assert_eq!(decoded.tx, tx.hash());
            assert_eq!(
                decoded.expiry_ms,
                tx.validity_range().end_timestamp_exclusive.as_millis() + ARTIFACT_GRACE_MS
            );
        }
        assert_eq!(
            cells,
            committed_tx_cells(shard, txs.iter()),
            "derived the same way on every replica"
        );
    }
}
