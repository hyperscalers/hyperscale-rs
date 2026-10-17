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

use hyperscale_hbor::Capped;
use hyperscale_jmt::NibblePath;
use hyperscale_types::{
    Address, Block, FrontierInputs, LocalKey, MAX_SWEEP_PER_BLOCK, SWEEP_BUCKET_BYTES,
    SettledWrites, ShardId, ShardTrie, StoredReceipt, SubstateKey, SweepBucket, SweepFrontier,
    Transaction, TxHash, Verified, WeightedTimestamp, protocol_statics, protocol_statics_installed,
};
use hyperscale_vm_effects::{Marked, Marker, ProtocolHasher, committed_tx_key};

use crate::shard::crossings::{
    crossing_settlements, owed_credits, reclaim_writes, reclaimed, unclaimed_declines,
};
use crate::shard::fee_holds::with_fee_holds;
use crate::shard::members::{MemberInputs, fate_writes, member_writes};
use crate::shard::read_frontier::{read_frontier_writes, with_frontier};
use crate::tree::JmtSnapshot;
use crate::{
    Anchored, Substates, filter_state_writes_to_prefix, filter_writes_to_prefix, fold_state_writes,
    key_under_prefix, merge_receipts, settle_writes,
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

/// Where a block's sweep starts, and whether the block sweeps at all:
/// the rule a block being built or voted on is held to.
///
/// Which arm applies is a reading of the schedule at the moment the
/// block is made, so it is asked where a block is built and where one
/// arrives as a proposal and is checked, voted on or not. A certified
/// block states where its sweep landed in its header, and a replica
/// committing it on that certificate removes the interval the header
/// names: see [`sweep_through`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockSweep {
    /// Walk the expired cells from the parent's frontier up to the block's
    /// clock.
    From(SweepFrontier),
    /// Remove nothing and keep the parent's frontier. A coasting block
    /// holds its parent's root frozen past the terminal, so a successor
    /// extracts the same half from whichever coast block its copy of the
    /// parent sits at; the cells the coast would have swept are the
    /// successors' to sweep from the terminal's frontier.
    Held(SweepFrontier),
}

impl BlockSweep {
    /// The sweep of a block whose parent's stopped at `parent_frontier`:
    /// held there when the block coasts, walked from there otherwise.
    #[must_use]
    pub const fn of_child(parent_frontier: SweepFrontier, coasting: bool) -> Self {
        if coasting {
            Self::Held(parent_frontier)
        } else {
            Self::From(parent_frontier)
        }
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
///
/// A coasting block sweeps nothing: see [`BlockSweep::Held`].
#[must_use]
pub(crate) fn sweep_for_block(
    store: &(impl SweepIndex + ?Sized),
    sweep: BlockSweep,
    clock: WeightedTimestamp,
) -> (Vec<SubstateKey>, SweepFrontier) {
    let parent_frontier = match sweep {
        BlockSweep::From(frontier) => frontier,
        BlockSweep::Held(frontier) => return (Vec::new(), frontier),
    };
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
/// it creates, the cells its claims settle away, and its sweep — into
/// the settled set its receipts produced.
///
/// All are ordinary writes, a value at the key or `None` at it, so
/// none needs a commit path of its own: they fold with everything else
/// and land under `state_root` like any other change. That is the fact
/// that makes this tractable rather than novel.
///
/// The sweep is closed over the block's own writes. `swept` is what the
/// walk over the parent's state removed, up to `frontier`; a sweepable
/// value the block writes at or below `frontier` is not written at all,
/// since no later walk reads there and the cell would stand past its
/// expiry. So the state every block leaves holds no sweepable cell at
/// or below its frontier: the parent held none at or below its own,
/// the walk removed every one between the two, and the block wrote none
/// there. That is what lets a walk from the chain's start stand in for
/// one from the parent's frontier, which a follower and a replica that
/// never learned the parent's frontier both do. A removal also wins
/// over any write the block makes to the same cell.
///
/// Dropping such a write takes nothing a reader needs. A receipt can
/// settle long after it ran, so a nullifier lands past its expiry when
/// its tick finalizes late, but no member binding its intent runs at a
/// tick anchored at or above this block: the block's clock is past the
/// intent's window, which bounds every deadline that binds it. A tick
/// anchored below reads its anchor's state and the contributions above
/// it, which the late spend is one of. A committed cell is written at
/// inclusion, inside its transaction's window, and its grace puts it
/// above every frontier that block can reach.
///
/// # Panics
///
/// If a creation or a settled crossing names a cell the block's own
/// receipts also write, a sweep removes a creation, or a creation sits
/// at or below the frontier. The two would be
/// one entry in the settled map, so one of them would silently not
/// happen, and which one is decided by insertion order, which is not
/// something a validator can check. A creation sits under the shard's
/// own owner, which no receipt writes, a creation the parent already
/// holds is refused at the vote, and a creation's grace puts it above
/// every frontier its block can reach; this is the assertion that all
/// three hold.
#[must_use]
pub fn with_sweep(
    settled: SettledWrites,
    creations: &[(SubstateKey, Vec<u8>)],
    settled_removals: &[SubstateKey],
    swept: &[SubstateKey],
    frontier: SweepFrontier,
) -> SettledWrites {
    let (mut cells, entries) = settled.into_parts();
    for (key, value) in creations {
        assert!(
            cells.insert(*key, Some(value.clone())).is_none(),
            "the chain created {key:?}, which this block's receipts also write",
        );
    }
    for key in settled_removals {
        assert!(
            cells.insert(*key, None).is_none(),
            "a claim settled {key:?} away, which this block's receipts also write",
        );
    }
    let created: BTreeSet<SubstateKey> = creations.iter().map(|(key, _)| *key).collect();
    cells.retain(|key, change| {
        let passed = SweepFrontier::of_leaf(*key) <= frontier
            && change
                .as_deref()
                .is_some_and(|bytes| sweepable_expiry(*key, bytes).is_some());
        assert!(
            !(passed && created.contains(key)),
            "the chain created {key:?} at or below its own frontier",
        );
        !passed
    });
    for key in swept {
        assert!(
            !created.contains(key),
            "a sweep removed {key:?}, which this block creates",
        );
        cells.insert(*key, None);
    }
    SettledWrites::from_parts(cells, entries)
}

/// The cells a certified block removed: everything sweepable strictly
/// after `parent_frontier` and at or below `frontier`, the position the
/// block's header claims its sweep landed on.
///
/// The two headers are the whole of the answer, whichever way the block
/// came by its frontier. A walk that stopped at its ceiling and one the
/// cap stopped on its last cell both removed every cell up to the
/// position they name, and a block that kept its parent's frontier —
/// its ceiling had not moved, or it coasts — names an empty interval. So
/// a replica committing a block on its certificate, and a follower
/// holding a prefix of the chain's tree, read the removals here and ask
/// nothing of a schedule that may have moved since the block was built.
///
/// The read is the walk's own. The buckets below the frontier's are read
/// whole, as a walk reading up to a ceiling reads them, and the
/// frontier's own bucket is opened only for a frontier standing inside
/// it, which is the last cell a capped walk took: a frontier at its
/// bucket's start is a ceiling, below every cell the bucket holds. At
/// most [`MAX_SWEEP_PER_BLOCK`] candidates are read in all, the most a
/// walk removes, counted as the walk counts them — from the first cell
/// above `parent_frontier`. So a block is read back holding the cells it
/// removed and no others, and a header naming an interval wider than
/// any walk produces is read to the cap, where the root it claims
/// answers for it.
#[must_use]
pub fn sweep_through(
    store: &(impl SweepIndex + ?Sized),
    parent_frontier: SweepFrontier,
    frontier: SweepFrontier,
) -> Vec<SubstateKey> {
    if parent_frontier >= frontier {
        return Vec::new();
    }
    let last = frontier.bucket();
    let mut found = store.sweep_candidates(parent_frontier, last, MAX_SWEEP_PER_BLOCK);
    let left = MAX_SWEEP_PER_BLOCK - found.len();
    if left > 0 && frontier > SweepFrontier::start_of(last) {
        let resume = found
            .last()
            .map_or(parent_frontier, |(key, _)| SweepFrontier::of_leaf(*key));
        let past = SweepBucket(last.0.saturating_add(1));
        found.extend(
            store
                .sweep_candidates(resume, past, left)
                .into_iter()
                .take_while(|(key, _)| SweepFrontier::of_leaf(*key) <= frontier),
        );
    }
    found.into_iter().map(|(key, _)| key).collect()
}

/// What a followed block writes under `prefix`, composed as the chain
/// composed it.
///
/// The receipts its ticks settled, the owed credits and the declines
/// its claims license, the records it takes back, the committed cells
/// its committer derived, the sweep its header names, the crossing
/// settlements its claims license, the read frontier its claims raise,
/// and the tick membership its content moves.
///
/// The removals read `store` as it stands before the block, from the
/// bottom of the sweep order: a follower mirrors the chain's state, and
/// that state holds no sweepable cell at or below the parent's frontier
/// (see [`with_sweep`]), so every live cell at or below the header's
/// frontier is one the block removed. The block's own sweepable writes
/// at or below it are dropped as the chain dropped them, per key and
/// before the prefix keeps this half's, so the halves recompose the
/// chain's root. The creations are the caller's, derived under the
/// block's own window as the committer derived them. The settlements
/// read this half of the state:
/// a key under the other half reads absent here and falls out, and is
/// the other follower's. A decline reads its answers the same way and
/// its row in the block, so the half without the consumer's cells
/// derives a `Never` its prefix drops, and the half holding them writes
/// what the committer wrote whichever half holds the rows. A record
/// taken back is removed unread and credited at its target by the half
/// holding it, which holds the target too and reads it as the committer
/// did ([`reclaim_writes`]); every voter held the block to the return
/// being taken. The frontier's writes read the copy of the table this
/// half holds, which is the whole table, and are written for both halves
/// before the prefix keeps this one's.
#[must_use]
pub fn followed_block_writes(
    store: &(impl SweepIndex + ?Sized),
    prior: &dyn Anchored,
    block: &Block,
    creations: &[(SubstateKey, Vec<u8>)],
    frontier: &FrontierInputs,
    prefix: &NibblePath,
) -> SettledWrites {
    let settling: Vec<StoredReceipt> = block
        .certificates()
        .iter()
        .flat_map(|fw| fw.settling_receipts())
        .collect();
    let members = MemberInputs::of(block, frontier.windows);
    let mut writes = merge_receipts(&settling);
    let owed = owed_credits(block.state_claims(), &writes, prior);
    fold_state_writes(&mut writes, &owed);
    fold_state_writes(
        &mut writes,
        &unclaimed_declines(
            block.state_claims(),
            members.shard,
            members.committed,
            prior,
        ),
    );
    fold_state_writes(&mut writes, &fate_writes(block.tick_manifest()));
    let returned = reclaim_writes(
        &reclaimed(block.state_claims(), members.shard, frontier.anchor),
        members.shard,
        &writes,
        prior,
    );
    fold_state_writes(&mut writes, &returned);
    // Restricted before resolving: a follower holds its prefix of the
    // tree and nothing else, so a movement on any other cell reads an
    // empty prior here and is the owning store's to judge, not this one's.
    let merged = with_fee_holds(
        settle_writes(&filter_state_writes_to_prefix(&writes, prefix), prior),
        &members.fees,
        prior,
        prefix,
    );
    let swept = sweep_through(store, SweepFrontier::ZERO, block.header().sweep_frontier());
    let settled = crossing_settlements(
        block.state_claims(),
        members.shard,
        frontier.anchor,
        &merged,
        prior,
    );
    let creations: Vec<(SubstateKey, Vec<u8>)> =
        creations.iter().cloned().chain(settled.seen).collect();
    let mut raised = read_frontier_writes(prior, frontier);
    raised.extend(member_writes(prior, &members));
    let folded = with_sweep(
        merged,
        &creations,
        &settled.removed,
        &swept,
        block.header().sweep_frontier(),
    );
    filter_writes_to_prefix(&with_frontier(folded, raised), prefix)
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
        .map(|tx| committed_tx_cell(local_shard, tx))
        .collect()
}

fn committed_tx_cell(local_shard: ShardId, tx: &Transaction) -> (SubstateKey, Vec<u8>) {
    let validity_end = tx.validity_range().end_timestamp_exclusive;
    let cell = Marker::of(tx.hash(), validity_end.as_millis(), Marked::Committed);
    (
        committed_tx_cell_key(local_shard, cell.tx, validity_end),
        cell.to_bytes(),
    )
}

/// One transaction's committed marker as a block that carries it writes
/// it, and every key whose presence says the transaction was already
/// committed on this chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedHere {
    /// The marker this shard writes, under its own owner.
    pub key: SubstateKey,
    /// The marker's bytes.
    pub value: Vec<u8>,
    /// For a transaction whose range opened before the chain's origin,
    /// the marker key under the owner of the shard's right half.
    ///
    /// A shard's owner is its path padded with zeros, so a left
    /// predecessor wrote under this chain's own owner and `key` already
    /// answers for it. A merged parent's right predecessor wrote here, in
    /// the parent's own state. On a chain not born by a merge nothing
    /// sits at it, so reading it needs no knowledge of how the chain was
    /// born.
    pub inherited: Option<SubstateKey>,
}

impl CommittedHere {
    /// The write the block folds.
    #[must_use]
    pub fn creation(&self) -> (SubstateKey, Vec<u8>) {
        (self.key, self.value.clone())
    }
}

/// [`committed_tx_cells`], with each row carrying the inherited key a
/// transaction older than `origin` is also judged by.
#[must_use]
pub fn committed_here<'a>(
    local_shard: ShardId,
    origin: WeightedTimestamp,
    transactions: impl IntoIterator<Item = &'a Transaction>,
) -> Vec<CommittedHere> {
    transactions
        .into_iter()
        .map(|tx| {
            let (key, value) = committed_tx_cell(local_shard, tx);
            let range = tx.validity_range();
            let inherited = (range.start_timestamp_inclusive < origin).then(|| {
                committed_tx_cell_key(
                    local_shard.children().1,
                    tx.hash(),
                    range.end_timestamp_exclusive,
                )
            });
            CommittedHere {
                key,
                value,
                inherited,
            }
        })
        .collect()
}

/// The creations a block's rows fold.
#[must_use]
pub fn creations_of(rows: &[CommittedHere]) -> Vec<(SubstateKey, Vec<u8>)> {
    rows.iter().map(CommittedHere::creation).collect()
}

/// Whether `row` may not be carried over `state`: its own marker or its
/// inherited one is present, or its own key is in `named` already.
/// Presence is the answer, whatever value sits at the key.
fn committed_already(
    row: &CommittedHere,
    named: &mut BTreeSet<SubstateKey>,
    state: &(impl Substates + ?Sized),
) -> bool {
    !named.insert(row.key)
        || state.cell(row.key).is_some()
        || row.inherited.is_some_and(|key| state.cell(key).is_some())
}

/// The first row a block may not carry.
///
/// A transaction this chain already committed, by its own marker or an
/// inherited one present in the parent state, or one whose marker
/// another transaction in the block names.
///
/// One rule, both halves: a block carries no transaction whose committed
/// key is present in its parent state or named by another transaction in
/// the same block. Presence is read through `state`, the anchored view,
/// so a marker an unpersisted ancestor created counts, and a restarted or
/// snap-synced voter answers as a live one does. A sweep removes only
/// what is live in the parent, so a creation that is also a removal
/// breaks the first half on its own and needs no clause.
///
/// What the rule buys is that a transaction is committed once per chain
/// lineage, and that a live committed cell always names the transaction
/// that created it, so a probe reading the cell reads about the
/// transaction it asked about. A verifier refuses a block that breaks it
/// at vote time, before the in-block pair reaches [`with_sweep`]'s assert
/// and halts every replica, and a proposer keeps the first of each
/// colliding set.
#[must_use]
pub fn colliding_committed_cell(
    rows: &[CommittedHere],
    state: &(impl Substates + ?Sized),
) -> Option<SubstateKey> {
    let mut named: BTreeSet<SubstateKey> = BTreeSet::new();
    rows.iter()
        .find(|row| committed_already(row, &mut named, state))
        .map(|row| row.key)
}

/// Drop from `transactions` every one [`colliding_committed_cell`] would
/// refuse: the first of each set sharing a key is kept, and one this
/// chain already committed goes.
///
/// What a proposer builds from. A colliding transaction is deferred to a
/// block whose parent no longer holds the cell rather than built into a
/// block every verifier refuses, one round after another; it stays
/// pooled meanwhile. A grinder who finds a collision defers only his own
/// later transaction.
pub fn without_colliding_committed_cells<const N: usize>(
    local_shard: ShardId,
    origin: WeightedTimestamp,
    transactions: &mut Capped<Vec<Arc<Verified<Transaction>>>, N>,
    state: &(impl Substates + ?Sized),
) {
    let mut named: BTreeSet<SubstateKey> = BTreeSet::new();
    transactions.retain(|tx| {
        let row = committed_here(local_shard, origin, [&***tx]);
        !committed_already(&row[0], &mut named, state)
    });
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
    use std::ops::{Bound, RangeInclusive};

    use hyperscale_types::test_utils::{
        install_stub_protocol_statics, make_live_block, stating_half_on, stub_abort_charge,
        stub_sweepable_cell,
    };
    use hyperscale_types::{
        AddressClass, BlockHeight, CollectionId, Deadline, ExecutionOutcome, GlobalReceiptHash,
        Hash, Joins, MemberCollection, Role, SWEEP_BUCKET_MS, SettledEntries, Settlement,
        StateClaim, StateRoot, TickLine, TxOutcome, ValidatorId, Verifiable, entry_leaf_key,
        shard_prefix_path, verdict_leaf,
    };
    use hyperscale_vm_effects::Answered;
    use proptest::prelude::*;

    use super::*;
    use crate::CollectedWrites;
    use crate::shard::chain_writer::ChainWrites;
    use crate::shard::members::MemberIndex;
    use crate::shard::writes::{CreditBurns, settled_block_at, settled_writes_at};
    use crate::test_helpers::{
        CountedSweep, declining_block, replayed_sweep_reads_what_the_block_removed,
        unclaimed_issuer, with_state_claims, yes_receipt,
    };

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

    /// A sweep index over cells held in sweep order.
    struct Cells(BTreeMap<SweepFrontier, SubstateKey>);

    impl SweepIndex for Cells {
        fn sweep_candidates(
            &self,
            after: SweepFrontier,
            below: SweepBucket,
            limit: usize,
        ) -> Vec<(SubstateKey, u64)> {
            self.0
                .range((Bound::Excluded(after), Bound::Unbounded))
                .take_while(|(position, _)| position.bucket() < below)
                .take(limit)
                .map(|(position, key)| (*key, u64::from(position.bucket().0) * SWEEP_BUCKET_MS))
                .collect()
        }
    }

    /// The interval between a block's frontier and its parent's names
    /// exactly the cells the block's own walk removed, wherever the walk
    /// stopped: on the last cell the cap let it take, at its ceiling, or
    /// where it began because the block held. So a replica holding the
    /// two headers removes what the proposer did without being told
    /// which of the three the block was.
    #[test]
    fn the_interval_two_headers_name_is_the_sweep_the_block_walked() {
        install_stub_protocol_statics();
        let mut cells = Cells(
            (1..=2u32)
                .flat_map(|bucket| (0..=u8::MAX).map(move |tag| (bucket, tag)))
                .flat_map(|(bucket, tag)| (0..90u8).map(move |body| cell(tag, bucket, body).0))
                .map(|key| (SweepFrontier::of_leaf(key), key))
                .collect(),
        );
        assert!(cells.0.len() > MAX_SWEEP_PER_BLOCK && cells.0.len() < 2 * MAX_SWEEP_PER_BLOCK);
        let clock = WeightedTimestamp::from_millis(10 * SWEEP_BUCKET_MS);

        let held = SweepFrontier::ZERO;
        assert_eq!(
            sweep_for_block(&cells, BlockSweep::Held(held), clock),
            (Vec::new(), held),
        );
        assert!(sweep_through(&cells, held, held).is_empty());

        let mut parent = SweepFrontier::ZERO;
        let mut walks = Vec::new();
        loop {
            let (removed, frontier) = sweep_for_block(&cells, BlockSweep::From(parent), clock);
            assert_eq!(sweep_through(&cells, parent, frontier), removed);
            if removed.is_empty() {
                assert_eq!(frontier, parent, "a walk with nothing left stands still");
                break;
            }
            for key in &removed {
                cells.0.remove(&SweepFrontier::of_leaf(*key));
            }
            walks.push((removed.len(), frontier));
            parent = frontier;
        }
        assert_eq!(walks.len(), 2, "one walk the cap stops, one that finishes");
        assert_eq!(walks[0].0, MAX_SWEEP_PER_BLOCK);
        assert!(walks[0].1 < SweepFrontier::ceiling_at(clock));
        assert_eq!(walks[1].1, SweepFrontier::ceiling_at(clock));
        assert!(cells.0.is_empty());
    }

    /// `count` cells of owner `tag` in `bucket`, each beside its owner.
    fn pile_of(tag: u8, bucket: u32, count: u8) -> impl Iterator<Item = (u8, SubstateKey)> {
        (0..count).map(move |body| (tag, cell(tag, bucket, body).0))
    }

    /// `per_owner` cells under each of 256 owners in each of `buckets`.
    fn pile(buckets: RangeInclusive<u32>, per_owner: u8) -> Cells {
        Cells(
            buckets
                .flat_map(|bucket| (0..=u8::MAX).map(move |tag| (bucket, tag)))
                .flat_map(|(bucket, tag)| pile_of(tag, bucket, per_owner))
                .map(|(_, key)| (SweepFrontier::of_leaf(key), key))
                .collect(),
        )
    }

    /// A pile several caps deep in one bucket drains over as many
    /// blocks, and reading any one of them back holds that block's
    /// removals alone: never more than the cap, however much of the pile
    /// still stands above the block's frontier.
    #[test]
    fn a_capped_drain_is_read_back_a_cap_at_a_time() {
        install_stub_protocol_statics();
        let mut cells = pile(1..=1, 255);
        // The same cells again under a second class of owner.
        for (tag, mut key) in (0..=u8::MAX).flat_map(|tag| pile_of(tag, 1, 255)) {
            key.owner = Address::new([tag; 31], AddressClass::Component);
            cells.0.insert(SweepFrontier::of_leaf(key), key);
        }
        let total = cells.0.len();
        assert_eq!(total, 2 * 256 * 255);
        assert!(total > 3 * MAX_SWEEP_PER_BLOCK);
        let clock = WeightedTimestamp::from_millis(10 * SWEEP_BUCKET_MS);

        let mut parent = SweepFrontier::ZERO;
        let mut drained = Vec::new();
        loop {
            let (removed, frontier) =
                replayed_sweep_reads_what_the_block_removed(&cells, parent, clock);
            if removed.is_empty() {
                break;
            }
            // A follower reads the same block from the chain's start.
            let follower = CountedSweep::over(&cells);
            assert_eq!(
                sweep_through(&follower, SweepFrontier::ZERO, frontier),
                removed
            );
            assert_eq!(follower.read(), removed.len());
            for key in &removed {
                cells.0.remove(&SweepFrontier::of_leaf(*key));
            }
            drained.push(removed.len());
            parent = frontier;
        }
        assert_eq!(drained.iter().sum::<usize>(), total);
        assert_eq!(drained.iter().max(), Some(&MAX_SWEEP_PER_BLOCK));
        assert_eq!(drained.len(), total.div_ceil(MAX_SWEEP_PER_BLOCK));
    }

    /// A header naming more cells than a block may remove is read back
    /// to the cap and no further: an interval no walk produced does not
    /// set what a replica reads.
    #[test]
    fn an_interval_wider_than_the_cap_is_read_to_the_cap() {
        install_stub_protocol_statics();
        let cells = pile(1..=2, 90);
        assert!(cells.0.len() > MAX_SWEEP_PER_BLOCK);
        let named = SweepFrontier::start_of(SweepBucket(5));
        let read = CountedSweep::over(&cells);
        let removals = sweep_through(&read, SweepFrontier::ZERO, named);
        assert_eq!(read.read(), MAX_SWEEP_PER_BLOCK);
        assert_eq!(
            removals,
            cells
                .0
                .values()
                .copied()
                .take(MAX_SWEEP_PER_BLOCK)
                .collect::<Vec<_>>(),
        );
    }

    /// The chain's start stands in for a parent's frontier only over a
    /// parent state holding nothing sweepable at or below that frontier.
    /// Over such a state the two name one interval. A cell standing at
    /// or below the parent's frontier is one the block's walk left, and
    /// the interval from the chain's start takes it.
    #[test]
    fn the_chains_start_names_a_blocks_interval_only_over_a_swept_parent() {
        install_stub_protocol_statics();
        let stale = cell(1, 2, 0).0;
        let due = cell(1, 6, 0).0;
        let parent = SweepFrontier::start_of(SweepBucket(5));
        let clock = WeightedTimestamp::from_millis(8 * SWEEP_BUCKET_MS);
        let holding = |keys: &[SubstateKey]| {
            Cells(
                keys.iter()
                    .map(|key| (SweepFrontier::of_leaf(*key), *key))
                    .collect(),
            )
        };

        let swept = holding(&[due]);
        let (walked, frontier) = sweep_for_block(&swept, BlockSweep::From(parent), clock);
        assert_eq!(walked, vec![due]);
        assert_eq!(sweep_through(&swept, parent, frontier), walked);
        assert_eq!(sweep_through(&swept, SweepFrontier::ZERO, frontier), walked);
        assert!(sweep_through(&swept, SweepFrontier::ZERO, parent).is_empty());

        let unswept = holding(&[stale, due]);
        assert_eq!(
            sweep_for_block(&unswept, BlockSweep::From(parent), clock),
            (walked.clone(), frontier),
        );
        assert_eq!(sweep_through(&unswept, parent, frontier), walked);
        assert_eq!(
            sweep_through(&unswept, SweepFrontier::ZERO, frontier),
            vec![stale, due],
        );
        assert_eq!(
            sweep_through(&unswept, SweepFrontier::ZERO, parent),
            vec![stale],
            "a block that held its parent's frontier, read from the chain's start",
        );
    }

    /// The member rows one half of a followed chain holds, anchored.
    struct Rows(MemberIndex);

    impl Substates for Rows {
        fn cell(&self, key: SubstateKey) -> Option<Vec<u8>> {
            self.0.cell(key)
        }

        fn entries_in_range(
            &self,
            owner: Address,
            collection: CollectionId,
            lo: u128,
            hi: u128,
            limit: usize,
        ) -> Vec<(u128, Vec<u8>)> {
            self.0.entries_in_range(owner, collection, lo, hi, limit)
        }
    }

    impl Anchored for Rows {
        fn anchor(&self) -> BlockHeight {
            BlockHeight::new(2)
        }
    }

    impl SweepIndex for Rows {}

    /// A followed block's stating half writes a verdict leaf and stages
    /// its yes receipt only where the follower holds the row it moves,
    /// and only under the prefix the family sits in: the half of a split
    /// that does not hold the rows reads them absent, folds no move and
    /// writes neither.
    #[test]
    fn a_follower_of_the_half_without_the_rows_writes_no_staged_entry() {
        install_stub_protocol_statics();
        let shard = ShardId::ROOT;
        let peer = ShardId::leaf(1, 1);
        let tx = TxHash::from(Hash::from_bytes(b"stated"));
        let leaf = verdict_leaf(shard, tx);
        let staged = entry_leaf_key(&ProtocolHasher, MemberCollection::Staged.entry(shard, tx));
        assert_eq!(
            leaf.to_bytes()[0] >> 7,
            staged.to_bytes()[0] >> 7,
            "the family sits under one prefix",
        );
        let (left, right) = shard.children();
        let (holding, other) = if leaf.to_bytes()[0] >> 7 == 0 {
            (left, right)
        } else {
            (right, left)
        };

        let deadline = Deadline::of(WeightedTimestamp::from_millis(90_000));
        let mut rows = MemberIndex::empty(shard);
        rows.advance(&MemberInputs {
            height: BlockHeight::new(2),
            transactions: vec![(tx, deadline)],
            manifest: Arc::new(Capped::from_array([TickLine::Member {
                staged: 0,
                tx,
                joins: Joins::Executes,
                settlement: Settlement::Shared,
                holds: Capped::empty(),
                reach: Capped::from_array([peer]),
                awaits: Capped::from_array([peer]),
                charge: stub_abort_charge(1),
                share: 1,
                reserves: Capped::empty(),
                deadline,
                crossings: Capped::empty(),
            }])),
            ..MemberInputs::still(shard)
        });
        assert!(rows.members[&tx].state.seated());

        let yes = TxOutcome::new(
            tx,
            ExecutionOutcome::Succeeded {
                receipt_hash: GlobalReceiptHash::ZERO,
            },
        )
        .charging(1)
        .awaiting([peer])
        .as_role(Role::Core);
        let half = stating_half_on(
            shard,
            BlockHeight::new(2),
            vec![yes],
            vec![yes_receipt(tx, GlobalReceiptHash::ZERO)],
        );
        let block = make_live_block(
            shard,
            BlockHeight::new(3),
            0,
            ValidatorId::new(0),
            Vec::new(),
            vec![Arc::new(Verifiable::from(half))],
        );
        let leaves = |prior: &Rows, half: ShardId| -> Vec<Option<Vec<u8>>> {
            followed_block_writes(
                prior,
                prior,
                &block,
                &[],
                &FrontierInputs::still(shard),
                &shard_prefix_path(half),
            )
            .entries()
            .iter()
            .filter(|(key, _)| {
                let at = entry_leaf_key(&ProtocolHasher, **key);
                at == leaf || at == staged
            })
            .map(|(_, change)| change.clone())
            .collect()
        };
        let (with_rows, without) = (Rows(rows), Rows(MemberIndex::empty(shard)));

        let written = leaves(&with_rows, holding);
        assert!(
            matches!(&written[..], [Some(_), Some(_)]),
            "the half holding the row writes its leaf and stages its receipt: {written:?}",
        );
        assert!(leaves(&without, other).is_empty());
        assert!(leaves(&without, holding).is_empty());
        assert!(leaves(&with_rows, other).is_empty());
    }

    /// One half of a followed chain's cells, anchored.
    #[derive(Default)]
    struct Half(BTreeMap<SubstateKey, Vec<u8>>);

    impl Substates for Half {
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

    impl Anchored for Half {
        fn anchor(&self) -> BlockHeight {
            BlockHeight::new(2)
        }
    }

    impl SweepIndex for Half {}

    /// What the root chain's own commit of `block` writes to its cells
    /// over `state`.
    fn committed_cells(block: &Block, state: &Half) -> BTreeMap<SubstateKey, Option<Vec<u8>>> {
        let still = FrontierInputs::still(ShardId::ROOT);
        settled_writes_at(
            &[],
            state,
            BlockHeight::new(2),
            ChainWrites {
                creations: &[],
                removals: &[],
                sweep_frontier: SweepFrontier::ZERO,
                frontier: &still,
                state_claims: block.state_claims(),
                members: &MemberInputs::of(block, still.windows),
            },
            SettledEntries::new(),
            &shard_prefix_path(ShardId::ROOT),
        )
        .cells()
        .clone()
    }

    /// What a follower of `half` writes to its cells for `block` over
    /// `state`.
    fn followed_cells(
        block: &Block,
        state: &Half,
        half: ShardId,
    ) -> BTreeMap<SubstateKey, Option<Vec<u8>>> {
        followed_block_writes(
            state,
            state,
            block,
            &[],
            &FrontierInputs::still(ShardId::ROOT),
            &shard_prefix_path(half),
        )
        .cells()
        .clone()
    }

    /// A split child following its parent's declining block writes the
    /// `Never` the parent's own commit writes, on the half holding the
    /// consumer and on no other, with no row of the family in its
    /// store: the row's absence is a reading the block carries.
    #[test]
    fn a_follower_of_a_declining_block_writes_the_never_under_its_half() {
        install_stub_protocol_statics();
        let (id, block) = declining_block(BlockHeight::new(3));
        let never = id.answer_key(&ProtocolHasher, Answered::Never);
        let decline = id.answer(unclaimed_issuer(), Answered::Never, 0).to_bytes();
        let (left, right) = ShardId::ROOT.children();
        assert!(ShardTrie::shard_owns_prefix(left, id.consumer));
        let empty = Half::default();

        let committed = committed_cells(&block, &empty);
        assert_eq!(committed, BTreeMap::from([(never, Some(decline))]));
        assert_eq!(followed_cells(&block, &empty, left), committed);
        assert!(followed_cells(&block, &empty, right).is_empty());
    }

    /// A follower writes no decline its committer did not. The chain
    /// holds a `Taken` of the record's transaction, so its commit
    /// declines nothing; the right half holds none of the consumer's
    /// cells and reads no `Taken`, and what it derives falls outside its
    /// prefix; the left half holds the `Taken` and declines nothing.
    #[test]
    fn a_right_half_follower_declines_nothing_its_committer_did_not() {
        install_stub_protocol_statics();
        let (id, block) = declining_block(BlockHeight::new(3));
        let (left, right) = ShardId::ROOT.children();
        let taken = id.answer_key(&ProtocolHasher, Answered::Taken);
        let whole = Half(BTreeMap::from([(
            taken,
            id.answer(unclaimed_issuer(), Answered::Taken, 0).to_bytes(),
        )]));
        assert!(ShardTrie::shard_owns_prefix(left, taken.owner));

        assert!(committed_cells(&block, &whole).is_empty());
        assert!(followed_cells(&block, &Half::default(), right).is_empty());
        assert!(followed_cells(&block, &whole, left).is_empty());
    }

    /// The root chain's state holding an escrowed record on its left
    /// half, crediting a cell on its right, with its consumer's `Never`
    /// beside it; and the claim reading the record and the `Never` at the
    /// parent of a block at height 3, which takes the record back. With
    /// the record's key and its credit cell.
    fn returning_at_the_parent() -> (Half, StateClaim, SubstateKey, SubstateKey) {
        use hyperscale_hbor::Bytes;
        use hyperscale_types::state_key::jmt_value_hash;
        use hyperscale_types::{
            Anchor, Inclusion, LocalKey, MerkleInclusionProof, ResourceAddr, Stated, encode_amount,
        };
        use hyperscale_vm_effects::{CrossingId, Hash32, IntentHash, Terms};

        let id = CrossingId {
            producer: Address::new([0x21; 31], AddressClass::Component),
            consumer: Address::new([0x22; 31], AddressClass::Component),
            intent: IntentHash(Hash32([0x23; 32])),
            local: 0,
            output: 0,
        };
        let (left, right) = ShardId::ROOT.children();
        let credit = SubstateKey {
            owner: Address::new([0xA1; 31], AddressClass::Component),
            local: LocalKey([0x77; 16]),
        };
        assert!(ShardTrie::shard_owns_prefix(left, id.producer));
        assert!(ShardTrie::shard_owns_prefix(right, credit.owner));
        let tx = TxHash::from(Hash::from_bytes(b"refused"));
        let record = id.record_key(&ProtocolHasher);
        let never = id.answer_key(&ProtocolHasher, Answered::Never);
        let cell = id.cell(
            tx,
            ResourceAddr::new([0xE1; 31]),
            250,
            0,
            Terms::Escrowed { credit },
        );
        let answer = id.answer(tx, Answered::Never, 0).to_bytes();
        let state = Half(BTreeMap::from([
            (record, cell.to_bytes()),
            (never, answer.clone()),
            (credit, encode_amount(40).to_vec()),
        ]));
        let parent = StateClaim::new(
            Anchor {
                shard: ShardId::ROOT,
                height: BlockHeight::new(2),
                state_root: StateRoot::ZERO,
                ts: WeightedTimestamp::ZERO,
            },
            [
                (
                    record,
                    Stated::Held(Bytes::new(cell.to_bytes()).expect("a record fits")),
                ),
                (never, Inclusion::Present(jmt_value_hash(&answer)).into()),
            ],
            MerkleInclusionProof::new(Vec::new()),
        )
        .naming([(record, id), (never, id)]);
        (state, parent, record, credit)
    }

    /// A block taking a record back returns it in its own commit,
    /// whatever halves it carries: none, a determined half, a legs half,
    /// or both. The return is no member of any tick, so no half settles
    /// it and none holds it back; and a follower holding the record or
    /// the credit cell writes what the committer wrote.
    #[test]
    fn a_reclaim_settles_in_the_block_that_licenses_it_whatever_halves_it_carries() {
        use hyperscale_types::test_utils::{make_finalization_on, make_leg_finalization};
        use hyperscale_types::{TransactionDecision, read_amount};

        install_stub_protocol_statics();
        let (state, parent, record, credit) = returning_at_the_parent();
        let (left, right) = ShardId::ROOT.children();
        let determined = || {
            Arc::new(Verifiable::from(make_finalization_on(
                ShardId::ROOT,
                BlockHeight::new(1),
                TxHash::from(Hash::from_bytes(b"a member")),
                TransactionDecision::Accept,
            )))
        };
        let legs = || {
            Arc::new(Verifiable::from(make_leg_finalization(
                BlockHeight::new(1),
                TxHash::from(Hash::from_bytes(b"a leg")),
            )))
        };
        for halves in [
            vec![],
            vec![determined()],
            vec![legs()],
            vec![determined(), legs()],
        ] {
            let carried = halves.len();
            let block = with_state_claims(
                make_live_block(
                    ShardId::ROOT,
                    BlockHeight::new(3),
                    0,
                    ValidatorId::new(0),
                    Vec::new(),
                    halves,
                ),
                vec![parent.clone()],
            );
            let still = FrontierInputs::still(ShardId::ROOT);
            let written = settled_writes_at(
                block.certificates(),
                &state,
                BlockHeight::new(2),
                ChainWrites {
                    creations: &[],
                    removals: &[],
                    sweep_frontier: SweepFrontier::ZERO,
                    frontier: &still,
                    state_claims: block.state_claims(),
                    members: &MemberInputs::of(&block, still.windows),
                },
                SettledEntries::new(),
                &shard_prefix_path(ShardId::ROOT),
            );
            let cells = written.cells();
            assert_eq!(
                cells.get(&record),
                Some(&None),
                "{carried} halves: returned"
            );
            assert_eq!(
                cells
                    .get(&credit)
                    .cloned()
                    .flatten()
                    .and_then(|bytes| read_amount(&bytes)),
                Some(290),
                "{carried} halves: credited",
            );
            assert_eq!(
                followed_cells(&block, &state, left).get(&record),
                Some(&None),
                "{carried} halves: the half holding the record removes it",
            );
            assert_eq!(
                followed_cells(&block, &state, right).get(&credit),
                cells.get(&credit),
                "{carried} halves: the half holding the credit cell credits it",
            );
        }
    }

    /// The chain of `ShardId::leaf(1, 0)` holding an escrowed record on
    /// its left half, crediting a cell on its right; the claim reading the
    /// record at the parent of a block at height 3; and the consumer's
    /// `Never` of the record's transaction read on `ShardId::leaf(1, 1)`
    /// at the epoch's start. With the record's key and its credit cell.
    fn returning_at_a_boundary() -> (Half, [StateClaim; 2], SubstateKey, SubstateKey) {
        use hyperscale_hbor::Bytes;
        use hyperscale_types::state_key::jmt_value_hash;
        use hyperscale_types::{
            Anchor, Inclusion, LocalKey, MerkleInclusionProof, ResourceAddr, Stated, encode_amount,
        };
        use hyperscale_vm_effects::{CrossingId, Hash32, IntentHash, Terms};

        let producing = ShardId::leaf(1, 0);
        let consuming = ShardId::leaf(1, 1);
        let (left, right) = producing.children();
        let id = CrossingId {
            producer: Address::new([0x21; 31], AddressClass::Component),
            consumer: Address::new([0xA2; 31], AddressClass::Component),
            intent: IntentHash(Hash32([0x25; 32])),
            local: 0,
            output: 0,
        };
        let credit = SubstateKey {
            owner: Address::new([0x61; 31], AddressClass::Component),
            local: LocalKey([0x77; 16]),
        };
        assert!(ShardTrie::shard_owns_prefix(left, id.producer));
        assert!(ShardTrie::shard_owns_prefix(right, credit.owner));
        assert!(ShardTrie::shard_owns_prefix(consuming, id.consumer));
        let tx = TxHash::from(Hash::from_bytes(b"declined elsewhere"));
        let record = id.record_key(&ProtocolHasher);
        let never = id.answer_key(&ProtocolHasher, Answered::Never);
        let cell = id.cell(
            tx,
            ResourceAddr::new([0xE1; 31]),
            250,
            0,
            Terms::Escrowed { credit },
        );
        let answer = id.answer(tx, Answered::Never, 0).to_bytes();
        let state = Half(BTreeMap::from([
            (record, cell.to_bytes()),
            (credit, encode_amount(40).to_vec()),
        ]));
        let parent = StateClaim::new(
            Anchor {
                shard: producing,
                height: BlockHeight::new(2),
                state_root: StateRoot::ZERO,
                ts: WeightedTimestamp::from_millis(10_000),
            },
            [(
                record,
                Stated::Held(Bytes::new(cell.to_bytes()).expect("a record fits")),
            )],
            MerkleInclusionProof::new(Vec::new()),
        )
        .naming([(record, id)]);
        let declined = StateClaim::new(
            Anchor {
                shard: consuming,
                height: BlockHeight::new(7),
                state_root: StateRoot::ZERO,
                ts: WeightedTimestamp::ZERO,
            },
            [(
                never,
                Stated::Inclusion(Inclusion::Present(jmt_value_hash(&answer))),
            )],
            MerkleInclusionProof::new(Vec::new()),
        )
        .naming([(never, id)]);
        (state, [parent, declined], record, credit)
    }

    /// A split follower takes a record back on its consumer's `Never`
    /// read at a boundary of the consumer's shard, at the anchor its
    /// block's parent QC states, as its committer does: the half holding
    /// the record removes it and the half holding the credit cell credits
    /// it. The same `Never` read at an anchor still fresh to the block
    /// takes nothing back on either side.
    #[test]
    fn a_split_follower_takes_back_on_a_never_read_at_a_boundary() {
        use hyperscale_types::test_utils::certify;
        use hyperscale_types::{EpochWindows, RETENTION_HORIZON, read_amount};

        install_stub_protocol_statics();
        let (state, claims, record, credit) = returning_at_a_boundary();
        let producing = ShardId::leaf(1, 0);
        let (left, right) = producing.children();
        let windows = EpochWindows::new(0);
        let fresh = WeightedTimestamp::ZERO.plus(RETENTION_HORIZON);
        let credited = |cells: &BTreeMap<SubstateKey, Option<Vec<u8>>>| {
            cells
                .get(&credit)
                .cloned()
                .flatten()
                .and_then(|bytes| read_amount(&bytes))
        };
        for (anchor, returned) in [
            (fresh.plus(std::time::Duration::from_millis(1)), true),
            (fresh, false),
        ] {
            let block = certify(
                with_state_claims(
                    make_live_block(
                        producing,
                        BlockHeight::new(3),
                        0,
                        ValidatorId::new(0),
                        Vec::new(),
                        Vec::new(),
                    ),
                    claims.to_vec(),
                ),
                anchor.as_millis(),
            )
            .block()
            .clone();
            let frontier = FrontierInputs::of_block(&block, windows);
            assert_eq!(frontier.anchor, anchor);
            let committed = settled_writes_at(
                block.certificates(),
                &state,
                BlockHeight::new(2),
                ChainWrites {
                    creations: &[],
                    removals: &[],
                    sweep_frontier: SweepFrontier::ZERO,
                    frontier: &frontier,
                    state_claims: block.state_claims(),
                    members: &MemberInputs::of(&block, windows),
                },
                SettledEntries::new(),
                &shard_prefix_path(producing),
            )
            .cells()
            .clone();
            let followed = |half: ShardId| {
                followed_block_writes(
                    &state,
                    &state,
                    &block,
                    &[],
                    &frontier,
                    &shard_prefix_path(half),
                )
                .cells()
                .clone()
            };
            let (removed, credit) = if returned {
                (Some(&None), Some(290))
            } else {
                (None, None)
            };
            assert_eq!(committed.get(&record), removed, "{anchor:?}: committer");
            assert_eq!(credited(&committed), credit, "{anchor:?}: committer");
            assert_eq!(
                followed(left).get(&record),
                removed,
                "{anchor:?}: the half holding the record",
            );
            assert_eq!(
                credited(&followed(right)),
                credit,
                "{anchor:?}: the half holding the credit cell",
            );
        }
    }

    /// The chain of `ShardId::leaf(1, 0)` holding an escrowed record of
    /// 250 on its left half, returning it to `credit`, which holds
    /// `held`; and the block at height 3 reading the record at its parent
    /// and the consumer's `Never` of its transaction at a boundary of
    /// `ShardId::leaf(1, 1)`. With each half's cells, the chain's whole
    /// state and the record's key.
    fn returning_to(
        credit: SubstateKey,
        held: Vec<u8>,
    ) -> ([(ShardId, Half); 2], Half, Block, SubstateKey) {
        use hyperscale_hbor::Bytes;
        use hyperscale_types::state_key::jmt_value_hash;
        use hyperscale_types::test_utils::certify;
        use hyperscale_types::{
            Anchor, Inclusion, MerkleInclusionProof, RETENTION_HORIZON, ResourceAddr, Stated,
        };
        use hyperscale_vm_effects::{CrossingId, Hash32, IntentHash, Terms};

        let producing = ShardId::leaf(1, 0);
        let consuming = ShardId::leaf(1, 1);
        let (left, right) = producing.children();
        let id = CrossingId {
            producer: Address::new([0x21; 31], AddressClass::Component),
            consumer: Address::new([0xA2; 31], AddressClass::Component),
            intent: IntentHash(Hash32([0x26; 32])),
            local: 0,
            output: 0,
        };
        assert!(ShardTrie::shard_owns_prefix(left, id.producer));
        let tx = TxHash::from(Hash::from_bytes(b"declined away"));
        let record = id.record_key(&ProtocolHasher);
        let never = id.answer_key(&ProtocolHasher, Answered::Never);
        let cell = id.cell(
            tx,
            ResourceAddr::new([0xE1; 31]),
            250,
            0,
            Terms::Escrowed { credit },
        );
        let answer = id.answer(tx, Answered::Never, 0).to_bytes();
        let whole = BTreeMap::from([(record, cell.to_bytes()), (credit, held)]);
        let half = |half: ShardId| {
            Half(
                whole
                    .iter()
                    .filter(|(key, _)| ShardTrie::shard_owns_prefix(half, key.owner))
                    .map(|(key, value)| (*key, value.clone()))
                    .collect(),
            )
        };
        let parent = StateClaim::new(
            Anchor {
                shard: producing,
                height: BlockHeight::new(2),
                state_root: StateRoot::ZERO,
                ts: WeightedTimestamp::from_millis(10_000),
            },
            [(
                record,
                Stated::Held(Bytes::new(cell.to_bytes()).expect("a record fits")),
            )],
            MerkleInclusionProof::new(Vec::new()),
        )
        .naming([(record, id)]);
        let declined = StateClaim::new(
            Anchor {
                shard: consuming,
                height: BlockHeight::new(7),
                state_root: StateRoot::ZERO,
                ts: WeightedTimestamp::ZERO,
            },
            [(
                never,
                Stated::Inclusion(Inclusion::Present(jmt_value_hash(&answer))),
            )],
            MerkleInclusionProof::new(Vec::new()),
        )
        .naming([(never, id)]);
        let anchor = WeightedTimestamp::ZERO
            .plus(RETENTION_HORIZON)
            .plus(std::time::Duration::from_millis(1));
        let block = certify(
            with_state_claims(
                make_live_block(
                    producing,
                    BlockHeight::new(3),
                    0,
                    ValidatorId::new(0),
                    Vec::new(),
                    Vec::new(),
                ),
                vec![parent, declined],
            ),
            anchor.as_millis(),
        )
        .block()
        .clone();
        (
            [(left, half(left)), (right, half(right))],
            Half(whole),
            block,
            record,
        )
    }

    /// What `ShardId::leaf(1, 0)`'s own commit of `block` writes to its
    /// cells over `state`, and what it burns.
    fn committed_on_the_producer(
        block: &Block,
        state: &Half,
    ) -> (BTreeMap<SubstateKey, Option<Vec<u8>>>, CreditBurns) {
        use hyperscale_types::EpochWindows;

        let windows = EpochWindows::new(0);
        let frontier = FrontierInputs::of_block(block, windows);
        let settled = settled_block_at(
            block.certificates(),
            state,
            BlockHeight::new(2),
            ChainWrites {
                creations: &[],
                removals: &[],
                sweep_frontier: SweepFrontier::ZERO,
                frontier: &frontier,
                state_claims: block.state_claims(),
                members: &MemberInputs::of(block, windows),
            },
            SettledEntries::new(),
            &shard_prefix_path(ShardId::leaf(1, 0)),
        );
        (settled.writes.cells().clone(), settled.burned)
    }

    /// What a follower of `half` of `ShardId::leaf(1, 0)`'s chain writes
    /// to its cells for `block` over `state`, its own cells.
    fn followed_on_the_producer(
        block: &Block,
        state: &Half,
        half: ShardId,
    ) -> BTreeMap<SubstateKey, Option<Vec<u8>>> {
        use hyperscale_types::EpochWindows;

        followed_block_writes(
            state,
            state,
            block,
            &[],
            &FrontierInputs::of_block(block, EpochWindows::new(0)),
            &shard_prefix_path(half),
        )
        .cells()
        .clone()
    }

    /// A follower holding the half with the record, its credit cell and
    /// its owner's principal vault writes the return where the committer
    /// landed it, over its own cells: at the credit cell where it takes
    /// the return whole, and at the vault where the cell holds bytes that
    /// are no amount or has no room. The other half writes nothing.
    #[test]
    fn a_follower_holding_the_records_half_lands_where_the_committer_did() {
        use hyperscale_types::{LocalKey, ResourceAddr, encode_amount};
        use hyperscale_vm_effects::vocabulary::vault_cell;

        install_stub_protocol_statics();
        let owner = Address::new([0x21; 31], AddressClass::Component);
        let credit = SubstateKey {
            owner,
            local: LocalKey([0x77; 16]),
        };
        let vault = vault_cell(&ProtocolHasher, owner, ResourceAddr::new([0xE1; 31]));
        let amount = |value: u128| Some(encode_amount(value).to_vec());
        for (held, at, landed) in [
            (encode_amount(40).to_vec(), credit, amount(290)),
            (b"no amount".to_vec(), vault, amount(250)),
            (encode_amount(u128::MAX).to_vec(), vault, amount(250)),
        ] {
            let ([(left, left_cells), (right, right_cells)], whole, block, record) =
                returning_to(credit, held.clone());
            assert_eq!(record.owner, owner);
            let (committed, burned) = committed_on_the_producer(&block, &whole);
            assert_eq!(
                committed,
                BTreeMap::from([(record, None), (at, landed)]),
                "{held:?}: the committer",
            );
            assert!(burned.is_empty(), "{held:?}: nothing burns");
            assert_eq!(
                followed_on_the_producer(&block, &left_cells, left),
                committed,
                "{held:?}: the half holding the record",
            );
            assert!(
                followed_on_the_producer(&block, &right_cells, right).is_empty(),
                "{held:?}: the other half",
            );
        }
    }

    /// A record crediting its owner's principal vault, which holds bytes
    /// that are no amount, is removed with nothing landed: the committer
    /// counts its whole amount burned on the vault and leaves the bytes,
    /// and the half holding the record writes the same.
    #[test]
    fn a_return_its_owners_vault_cannot_take_burns_whole() {
        use hyperscale_types::ResourceAddr;
        use hyperscale_vm_effects::vocabulary::vault_cell;

        install_stub_protocol_statics();
        let owner = Address::new([0x21; 31], AddressClass::Component);
        let vault = vault_cell(&ProtocolHasher, owner, ResourceAddr::new([0xE1; 31]));
        let ([(left, left_cells), _], whole, block, record) =
            returning_to(vault, b"no amount".to_vec());
        let (committed, burned) = committed_on_the_producer(&block, &whole);
        assert_eq!(committed, BTreeMap::from([(record, None)]));
        assert_eq!(burned.at(vault), 250);
        assert_eq!(
            followed_on_the_producer(&block, &left_cells, left),
            committed
        );
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
            &[],
            &[removed],
            SweepFrontier::ZERO,
        );
        assert_eq!(settled.cells().get(&created), Some(&Some(value)));
        assert_eq!(settled.cells().get(&removed), Some(&None));
    }

    /// A cell both a claim and the sweep remove is removed once.
    #[test]
    fn a_cell_settled_and_swept_is_removed_once() {
        let (swept, _, _) = cell(1, 1, 0xD1);
        let settled = with_sweep(
            SettledWrites::default(),
            &[],
            &[swept],
            &[swept],
            SweepFrontier::ZERO,
        );
        assert_eq!(settled.cells().get(&swept), Some(&None));
        assert_eq!(settled.cells().len(), 1);
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
        use hyperscale_vm_types::COMMITTED_GRACE_MS;

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
                tx.validity_range().end_timestamp_exclusive.as_millis() + COMMITTED_GRACE_MS
            );
        }
        assert_eq!(
            cells,
            committed_tx_cells(shard, txs.iter()),
            "derived the same way on every replica"
        );
    }

    /// A hand-built committed key: no test can grind the collision the
    /// rule refuses, so the pair is written out.
    fn committed(tag: u8) -> SubstateKey {
        SubstateKey {
            owner: owner(9),
            local: LocalKey([tag; 16]),
        }
    }

    /// A row that inherits nothing.
    fn own(key: SubstateKey, value: Vec<u8>) -> CommittedHere {
        CommittedHere {
            key,
            value,
            inherited: None,
        }
    }

    /// A parent state holding exactly `present`, each at a value that
    /// names no transaction.
    struct Holding(BTreeSet<SubstateKey>);

    impl Substates for Holding {
        fn cell(&self, key: SubstateKey) -> Option<Vec<u8>> {
            self.0.contains(&key).then(|| vec![1])
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

    /// The backstop: two creations at one key are one entry in the
    /// settled map, and which survives is insertion order, which no
    /// validator can check. Refused at validation before it gets here.
    #[test]
    #[should_panic(expected = "which this block's receipts also write")]
    fn with_sweep_refuses_two_creations_at_one_key() {
        let key = committed(1);
        let _ = with_sweep(
            SettledWrites::default(),
            &[(key, vec![1]), (key, vec![2])],
            &[],
            &[],
            SweepFrontier::ZERO,
        );
    }

    /// The other backstop: a transaction created in the block that
    /// removes a colliding cell a parent wrote.
    #[test]
    #[should_panic(expected = "a sweep removed")]
    fn with_sweep_refuses_a_creation_that_is_also_a_removal() {
        let key = committed(2);
        let _ = with_sweep(
            SettledWrites::default(),
            &[(key, vec![1])],
            &[],
            &[key],
            SweepFrontier::ZERO,
        );
    }

    /// The rule the backstops stand behind: a key named twice in one
    /// block, or once over a cell the parent holds — a cell an
    /// unpersisted ancestor created reads present through the anchored
    /// view the caller hands in — and nothing for distinct absent keys.
    #[test]
    fn a_colliding_committed_cell_is_found_in_the_block_and_in_the_parent() {
        let (a, b, c) = (committed(1), committed(2), committed(3));
        let absent = Holding(BTreeSet::new());
        assert_eq!(
            colliding_committed_cell(
                &[own(a, vec![1]), own(b, vec![1]), own(a, vec![2])],
                &absent
            ),
            Some(a),
            "named twice in the block",
        );
        let holding = Holding(BTreeSet::from([b]));
        assert_eq!(
            colliding_committed_cell(&[own(a, vec![1]), own(b, vec![1])], &holding),
            Some(b),
            "present in the parent",
        );
        assert_eq!(
            colliding_committed_cell(&[own(a, vec![1]), own(c, vec![1])], &holding),
            None,
            "distinct absent keys",
        );
    }

    /// A proposer keeps the first transaction of a colliding set and
    /// drops one whose cell the parent already holds; both stay pooled.
    #[test]
    fn a_proposer_keeps_the_first_of_a_colliding_set() {
        use hyperscale_types::test_utils::{install_stub_protocol_statics, test_transaction};

        install_stub_protocol_statics();
        let shard = ShardId::leaf(1, 1);
        let verified = |n: u8| Arc::new(Verified::new_unchecked_for_test(test_transaction(n)));
        let (first, second) = (verified(1), verified(2));
        let key_of = |tx: &Transaction| {
            committed_tx_cell_key(
                shard,
                tx.hash(),
                tx.validity_range().end_timestamp_exclusive,
            )
        };

        // The same transaction listed twice is the in-block pair; the
        // second listing goes.
        let mut listed: Capped<Vec<_>, 4> =
            Capped::new(vec![first.clone(), first.clone(), second.clone()]).expect("three");
        without_colliding_committed_cells(
            shard,
            WeightedTimestamp::ZERO,
            &mut listed,
            &Holding(BTreeSet::new()),
        );
        assert_eq!(
            listed.iter().map(|tx| tx.hash()).collect::<Vec<_>>(),
            vec![first.hash(), second.hash()],
        );

        // A cell the parent holds defers the transaction that would
        // write it, and leaves the other.
        let mut listed: Capped<Vec<_>, 4> =
            Capped::new(vec![first.clone(), second.clone()]).expect("two");
        without_colliding_committed_cells(
            shard,
            WeightedTimestamp::ZERO,
            &mut listed,
            &Holding(BTreeSet::from([key_of(&first)])),
        );
        assert_eq!(
            listed.iter().map(|tx| tx.hash()).collect::<Vec<_>>(),
            vec![second.hash()],
        );
    }

    /// A transaction older than the chain's origin is also judged by the
    /// marker a merged parent's right predecessor wrote, under the owner
    /// of the right half; one the chain has seen open is judged by its
    /// own marker alone. The proposer drops what the voter refuses.
    #[test]
    fn an_inherited_marker_refuses_a_transaction_older_than_the_chain() {
        use hyperscale_types::test_utils::{install_stub_protocol_statics, test_transaction};

        install_stub_protocol_statics();
        let shard = ShardId::leaf(1, 0);
        let tx = test_transaction(1);
        let validity_end = tx.validity_range().end_timestamp_exclusive;
        let right = committed_tx_cell_key(shard.children().1, tx.hash(), validity_end);
        let holding = Holding(BTreeSet::from([right]));
        let origin = tx
            .validity_range()
            .start_timestamp_inclusive
            .plus(std::time::Duration::from_millis(1));

        let older = committed_here(shard, origin, [&tx]);
        assert_eq!(older[0].inherited, Some(right));
        assert_eq!(
            colliding_committed_cell(&older, &holding),
            Some(older[0].key),
            "the right predecessor committed it",
        );
        let newer = committed_here(shard, WeightedTimestamp::ZERO, [&tx]);
        assert_eq!(newer[0].inherited, None);
        assert_eq!(colliding_committed_cell(&newer, &holding), None);

        let verified = Arc::new(Verified::new_unchecked_for_test(tx));
        let mut listed: Capped<Vec<_>, 1> = Capped::new(vec![verified]).expect("one");
        without_colliding_committed_cells(shard, origin, &mut listed, &holding);
        assert!(listed.is_empty(), "the proposer drops it too");
    }

    /// Presence refuses, whatever the value at the key: a marker naming
    /// another transaction at T's key is still T's refusal, so no
    /// collision can make a committed transaction read absent.
    #[test]
    fn presence_refuses_whatever_the_marker_names() {
        struct Naming(SubstateKey, Vec<u8>);
        impl Substates for Naming {
            fn cell(&self, key: SubstateKey) -> Option<Vec<u8>> {
                (key == self.0).then(|| self.1.clone())
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

        let key = committed(5);
        let other = TxHash::from(Hash::from_bytes(&[0xC; 32]));
        let state = Naming(key, Marker::of(other, 1_000, Marked::Committed).to_bytes());
        assert_eq!(
            colliding_committed_cell(&[own(key, vec![1])], &state),
            Some(key)
        );
    }

    /// A state holding exactly the keys given, for the properties below.
    fn holding_keys(keys: impl IntoIterator<Item = SubstateKey>) -> Holding {
        Holding(keys.into_iter().collect())
    }

    proptest! {
        /// The builder and the voter read one rule: whatever the builder
        /// keeps, the voter admits, and whatever it drops, the voter
        /// refuses — alone, or beside a kept twin.
        #[test]
        fn the_builder_keeps_exactly_what_the_voter_admits(
            picks in prop::collection::vec(0u8..6, 0..10),
            marked in prop::collection::vec((0u8..6, any::<bool>()), 0..6),
            older_than_the_chain in any::<bool>(),
        ) {
            use hyperscale_types::test_utils::{install_stub_protocol_statics, test_transaction};

            install_stub_protocol_statics();
            let shard = ShardId::leaf(1, 0);
            let origin = if older_than_the_chain {
                WeightedTimestamp::from_millis(1)
            } else {
                WeightedTimestamp::ZERO
            };
            let state = holding_keys(marked.iter().filter_map(|(seed, inherited)| {
                let row = committed_here(shard, WeightedTimestamp::from_millis(1), [&test_transaction(*seed)]).remove(0);
                if *inherited { row.inherited } else { Some(row.key) }
            }));
            let listed: Vec<_> = picks
                .iter()
                .map(|seed| Arc::new(Verified::new_unchecked_for_test(test_transaction(*seed))))
                .collect();
            let mut kept: Capped<Vec<_>, 16> = Capped::new(listed.clone()).expect("under the cap");
            without_colliding_committed_cells(shard, origin, &mut kept, &state);

            let kept_rows: Vec<CommittedHere> =
                kept.iter().map(|tx| rows_of_tx(shard, origin, tx)).collect();
            prop_assert_eq!(colliding_committed_cell(&kept_rows, &state), None);
            for tx in &listed {
                let twin_kept = kept.iter().any(|k| k.hash() == tx.hash());
                let alone = colliding_committed_cell(&[rows_of_tx(shard, origin, tx)], &state);
                prop_assert!(twin_kept || alone.is_some(), "a dropped transaction the voter admits alone");
            }
        }

        /// A transaction admitted inside its own range creates its marker
        /// above anything the block's sweep can reach: the sweep stops at
        /// the anchor's bucket, and the marker expires a grace past the
        /// range's end.
        #[test]
        fn a_creation_sits_above_the_sweep(
            end_ms in 1u64..10_000_000_000,
            back_ms in 1u64..10_000_000_000,
            seed in any::<u8>(),
        ) {
            use hyperscale_types::test_utils::install_stub_protocol_statics;

            install_stub_protocol_statics();
            let anchor = WeightedTimestamp::from_millis(end_ms.saturating_sub(back_ms));
            let tx = TxHash::from(Hash::from_bytes(&[seed; 32]));
            let key = committed_tx_cell_key(
                ShardId::leaf(1, 0),
                tx,
                WeightedTimestamp::from_millis(end_ms),
            );
            prop_assert!(SweepFrontier::of_leaf(key) > SweepFrontier::ceiling_at(anchor));
        }
    }

    /// One transaction's row.
    fn rows_of_tx(
        shard: ShardId,
        origin: WeightedTimestamp,
        tx: &Verified<Transaction>,
    ) -> CommittedHere {
        committed_here(shard, origin, [&**tx]).remove(0)
    }

    /// A live committed cell names the transaction whose key it sits
    /// at, across a creation, a removal and a fresh creation in
    /// consecutive blocks: once the first is removed the key is
    /// absent, so a second transaction may create it, and the marker
    /// then names the second.
    #[test]
    fn a_live_committed_cell_names_its_creator() {
        use hyperscale_hbor::from_slice;

        let key = committed(4);
        let (a, b) = (
            TxHash::from(Hash::from_bytes(&[0xA; 32])),
            TxHash::from(Hash::from_bytes(&[0xB; 32])),
        );
        let marker = |tx: TxHash| Marker::of(tx, 1_000, Marked::Committed).to_bytes();
        let cell_after = |writes: SettledWrites| writes.into_parts().0.remove(&key).flatten();

        let created = cell_after(with_sweep(
            SettledWrites::default(),
            &[(key, marker(a))],
            &[],
            &[],
            SweepFrontier::ZERO,
        ));
        let named: Marker = from_slice(&created.expect("created")).expect("a marker");
        assert_eq!(named.tx, a);

        let holding = Holding(BTreeSet::from([key]));
        assert_eq!(
            colliding_committed_cell(&[own(key, marker(b))], &holding),
            Some(key),
            "while the first stands, the second is refused",
        );
        assert!(
            cell_after(with_sweep(
                SettledWrites::default(),
                &[],
                &[],
                &[key],
                SweepFrontier::ZERO
            ))
            .is_none(),
            "the sweep removes it",
        );
        let recreated = cell_after(with_sweep(
            SettledWrites::default(),
            &[(key, marker(b))],
            &[],
            &[],
            SweepFrontier::ZERO,
        ));
        let named: Marker = from_slice(&recreated.expect("created again")).expect("a marker");
        assert_eq!(named.tx, b, "and the cell names its creator");
    }

    /// The settled set `receipt` leaves once [`with_sweep`] folds a
    /// sweep that removed `swept` and landed on `frontier`.
    fn folded_over(
        receipt: Vec<(SubstateKey, Option<Vec<u8>>)>,
        swept: &[SubstateKey],
        frontier: SweepFrontier,
    ) -> BTreeMap<SubstateKey, Option<Vec<u8>>> {
        with_sweep(
            SettledWrites::from_absolutes(receipt.into_iter().collect()),
            &[],
            &[],
            swept,
            frontier,
        )
        .into_parts()
        .0
    }

    /// A sweepable value the block writes at or below its own frontier
    /// is not written, on a frontier a ceiling leaves and on one a
    /// capped walk leaves; one past it, and a value no sweep reaches,
    /// are written as any other.
    #[test]
    fn a_sweepable_write_at_or_below_the_frontier_is_not_written() {
        install_stub_protocol_statics();
        let (below, _, below_value) = cell(1, 4, 0x11);
        let (at, _, at_value) = cell(1, 7, 0x12);
        let (above, _, above_value) = cell(1, 7, 0x13);
        let (plain, _, _) = cell(1, 4, 0x14);
        let ceiling = SweepFrontier::start_of(SweepBucket(7));
        let written = folded_over(
            vec![
                (below, Some(below_value)),
                (at, Some(at_value.clone())),
                (above, Some(above_value.clone())),
                (plain, Some(b"plain".to_vec())),
            ],
            &[],
            ceiling,
        );
        assert_eq!(
            written.keys().copied().collect::<Vec<_>>(),
            {
                let mut kept = vec![at, above, plain];
                kept.sort_unstable();
                kept
            },
            "only the cell in a bucket below the ceiling goes",
        );
        let capped = SweepFrontier::of_leaf(at);
        // A capped frontier names the last cell the walk removed, so
        // the block's write there meets that removal.
        let written = folded_over(
            vec![(at, Some(at_value)), (above, Some(above_value.clone()))],
            &[at],
            capped,
        );
        assert_eq!(
            written,
            BTreeMap::from([(at, None), (above, Some(above_value))]),
            "the cell on a capped frontier is removed, the one past it stays",
        );
    }

    /// A removal wins over any write the block makes to the same cell:
    /// a deletion, a value no sweep reaches and a sweepable value alike
    /// leave the cell removed.
    #[test]
    fn a_removal_wins_over_a_write_to_its_cell() {
        install_stub_protocol_statics();
        let (swept, _, value) = cell(2, 3, 0x21);
        let frontier = SweepFrontier::start_of(SweepBucket(4));
        for write in [None, Some(b"plain".to_vec()), Some(value)] {
            assert_eq!(
                folded_over(vec![(swept, write)], &[swept], frontier),
                BTreeMap::from([(swept, None)]),
            );
        }
    }

    /// A creation at or below the frontier is the closure meeting what no
    /// block creates: a committed cell's grace puts it above every
    /// frontier its block can reach.
    #[test]
    #[should_panic(expected = "at or below its own frontier")]
    fn with_sweep_refuses_a_creation_at_or_below_the_frontier() {
        install_stub_protocol_statics();
        let (key, _, value) = cell(4, 2, 0x41);
        let _ = with_sweep(
            SettledWrites::default(),
            &[(key, value)],
            &[],
            &[],
            SweepFrontier::start_of(SweepBucket(3)),
        );
    }

    /// A claim settling away a cell the block's receipts write is still
    /// the order question the fold cannot answer.
    #[test]
    #[should_panic(expected = "a claim settled")]
    fn with_sweep_refuses_a_settled_cell_its_receipts_write() {
        let (key, _, _) = cell(3, 2, 0x31);
        let _ = with_sweep(
            SettledWrites::from_absolutes(BTreeMap::from([(key, Some(vec![1]))])),
            &[],
            &[key],
            &[],
            SweepFrontier::ZERO,
        );
    }
}
