//! Where the read frontier lives in state, and how a block writes it.
//!
//! The table is an ordered collection under the shard's own owner at
//! [`READ_FRONTIER_SLOT`], one entry per producer keyed by the
//! producer's heap index and holding its [`ReadMark`]. It is state, so a
//! restart, a snap-sync and the state root carry it with no extra work,
//! and it sits under no sweep bucket, so no sweep reaches it.
//!
//! **It is kept under both children's owners, in every block.** A
//! shard's owner address is its path bits followed by zeros, so a
//! parent's owner is byte for byte its left child's, and the left child
//! inherits the table where it stands. The right child's half holds no
//! such address, so the table is written under the right child's owner
//! too, at every raise: at the terminal both halves hold it, each child
//! boots with it, and a split observer following the parent's blocks
//! into one half rebuilds every write from the copy on that half alone.
//! A merged parent's state then holds each child's pair; its first block
//! folds the four by maximum, keeps the pair its own children name, and
//! removes the two its grandchildren did.

use hyperscale_hbor::{from_slice, to_vec};
use hyperscale_types::{
    Address, CollectionId, EntryKey, FrontierInputs, ReadFrontier, ReadMark, SettledEntries,
    SettledWrites, ShardId, ShardTrie,
};
use hyperscale_vm_effects::{ProtocolHasher, READ_FRONTIER_SLOT, collection_id};

use crate::Substates;

/// The owners `shard` keeps its table under: its own, which is its left
/// child's, and its right child's.
fn copies(shard: ShardId) -> [Address; 2] {
    [
        ShardTrie::shard_owner(shard),
        ShardTrie::shard_owner(shard.children().1),
    ]
}

/// The owners a merge leaves a child's right-hand copy stranded under:
/// each grandchild's right owner.
fn strays(shard: ShardId) -> [Address; 2] {
    let (left, right) = shard.children();
    [
        ShardTrie::shard_owner(left.children().1),
        ShardTrie::shard_owner(right.children().1),
    ]
}

fn collection_of(owner: Address) -> CollectionId {
    collection_id(&ProtocolHasher, owner, READ_FRONTIER_SLOT, &[])
}

fn entry_of(owner: Address, producer: ShardId) -> EntryKey {
    EntryKey {
        owner,
        collection: collection_of(owner),
        order: u128::from(producer.inner()),
    }
}

/// The table as it stands under one owner.
fn table_under(substates: &(impl Substates + ?Sized), owner: Address) -> ReadFrontier {
    ReadFrontier::from_entries(
        substates
            .entries_in_range(owner, collection_of(owner), 0, u128::MAX, usize::MAX)
            .into_iter()
            .filter_map(|(order, bytes)| {
                let index = u64::try_from(order).ok().filter(|index| *index >= 1)?;
                let mark: ReadMark = from_slice(&bytes).ok()?;
                Some((ShardId::from_heap_index(index), mark))
            }),
    )
}

/// The read frontier `shard` holds in `substates`: the maximum over
/// every owner it is kept under, its own pair and the pair a merge
/// leaves behind, which its next block folds in.
pub fn load_read_frontier(substates: &(impl Substates + ?Sized), shard: ShardId) -> ReadFrontier {
    let mut table = ReadFrontier::default();
    for owner in copies(shard).into_iter().chain(strays(shard)) {
        table.fold_max(&table_under(substates, owner));
    }
    table
}

/// The entry writes one block makes to the table: the table as `baseline`
/// left it, advanced by `inputs`, written wherever a copy differs, with
/// the copies a merge stranded folded in and removed.
///
/// `baseline` is the state the block's writes land on, read through the
/// same view the block's movements resolve against, so every replica
/// reads one parent table and writes one set.
///
/// # Panics
///
/// If a mark fails to encode, which two integers cannot.
#[must_use]
pub fn read_frontier_writes(
    baseline: &(impl Substates + ?Sized),
    inputs: &FrontierInputs,
) -> SettledEntries {
    let copies = copies(inputs.local);
    let strays = strays(inputs.local);
    let held: Vec<ReadFrontier> = copies
        .iter()
        .chain(&strays)
        .map(|owner| table_under(baseline, *owner))
        .collect();
    let mut table = ReadFrontier::default();
    for copy in &held {
        table.fold_max(copy);
    }
    table.advance(inputs);
    let mut writes = SettledEntries::new();
    for (owner, before) in copies.iter().zip(&held) {
        for (producer, mark) in table.entries() {
            if before.entry(producer) != Some(mark) {
                writes.insert(
                    entry_of(*owner, producer),
                    Some(to_vec(&mark).expect("a read mark encodes")),
                );
            }
        }
        for (producer, _) in before.entries() {
            if table.entry(producer).is_none() {
                writes.insert(entry_of(*owner, producer), None);
            }
        }
    }
    for (owner, stray) in strays.iter().zip(&held[copies.len()..]) {
        for (producer, _) in stray.entries() {
            writes.insert(entry_of(*owner, producer), None);
        }
    }
    writes
}

/// Fold the frontier's entry writes into a block's settled writes.
///
/// # Panics
///
/// If the frontier names an entry the block's receipts also write. The
/// table sits under the shard's own owner at a slot no session reaches,
/// so a receipt writing one is a receipt writing a cell nobody's
/// declaration names.
#[must_use]
pub fn with_frontier(settled: SettledWrites, frontier: SettledEntries) -> SettledWrites {
    if frontier.is_empty() {
        return settled;
    }
    let (cells, mut entries) = settled.into_parts();
    for (key, change) in frontier {
        assert!(
            entries.insert(key, change).is_none(),
            "the chain wrote the read frontier at {key:?}, which this block's receipts also write",
        );
    }
    SettledWrites::from_parts(cells, entries)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use hyperscale_types::{
        BlockHeight, Epoch, EpochWindows, RETENTION_HORIZON, SubstateKey, WeightedTimestamp,
    };

    use super::*;

    /// A store of entries alone, for the fold to read and write.
    #[derive(Default)]
    struct Entries(BTreeMap<EntryKey, Vec<u8>>);

    impl Entries {
        fn apply(&mut self, writes: &SettledEntries) {
            for (key, change) in writes {
                match change {
                    Some(bytes) => {
                        self.0.insert(*key, bytes.clone());
                    }
                    None => {
                        self.0.remove(key);
                    }
                }
            }
        }
    }

    impl Substates for Entries {
        fn cell(&self, _key: SubstateKey) -> Option<Vec<u8>> {
            None
        }

        fn entries_in_range(
            &self,
            owner: Address,
            collection: CollectionId,
            lo: u128,
            hi: u128,
            limit: usize,
        ) -> Vec<(u128, Vec<u8>)> {
            self.0
                .iter()
                .filter(|(key, _)| {
                    key.owner == owner
                        && key.collection == collection
                        && (lo..=hi).contains(&key.order)
                })
                .map(|(key, bytes)| (key.order, bytes.clone()))
                .take(limit)
                .collect()
        }
    }

    const WINDOW_MS: u64 = 1_000_000;

    fn mark(epoch: u64, height: u64) -> ReadMark {
        ReadMark {
            epoch: Epoch::new(epoch),
            height: BlockHeight::new(height),
        }
    }

    fn inputs(local: ShardId, anchor_ms: u64, marks: &[(ShardId, ReadMark)]) -> FrontierInputs {
        FrontierInputs {
            local,
            anchor: WeightedTimestamp::from_millis(anchor_ms),
            windows: EpochWindows::new(WINDOW_MS),
            marks: marks.iter().copied().collect(),
        }
    }

    /// A raise writes the entry under both copies, a block that raises
    /// nothing writes nothing, and both children read the parent's table.
    #[test]
    fn a_raise_lands_under_both_copies_and_a_still_block_writes_nothing() {
        let local = ShardId::leaf(1, 0);
        let (left, right) = local.children();
        let producer = ShardId::leaf(1, 1);
        let mut store = Entries::default();
        let writes = read_frontier_writes(&store, &inputs(local, 100, &[(producer, mark(0, 7))]));
        assert_eq!(writes.len(), 2, "one entry under each copy");
        assert!(writes.values().all(Option::is_some));
        store.apply(&writes);
        assert!(
            read_frontier_writes(&store, &inputs(local, 200, &[(producer, mark(0, 7))])).is_empty(),
            "the same mark again writes nothing",
        );
        assert!(read_frontier_writes(&store, &inputs(local, 200, &[])).is_empty());
        let expected = ReadFrontier::from_entries([(producer, mark(0, 7))]);
        assert_eq!(load_read_frontier(&store, local), expected);
        assert_eq!(
            load_read_frontier(&store, left),
            expected,
            "the left child inherits the table"
        );
        assert_eq!(
            load_read_frontier(&store, right),
            expected,
            "and the right child its copy"
        );
    }

    /// An entry whose window closed more than a horizon before the block
    /// is dropped from both copies, and one inside the horizon stands.
    #[test]
    fn an_entry_a_horizon_past_its_window_is_dropped() {
        let local = ShardId::ROOT;
        let producer = ShardId::leaf(1, 1);
        let mut store = Entries::default();
        store.apply(&read_frontier_writes(
            &store,
            &inputs(local, 100, &[(producer, mark(0, 7))]),
        ));
        let close = EpochWindows::new(WINDOW_MS).window_of(Epoch::new(0)).end;
        let at_horizon = close.plus(RETENTION_HORIZON).as_millis();
        assert!(read_frontier_writes(&store, &inputs(local, at_horizon, &[])).is_empty());
        let past = read_frontier_writes(&store, &inputs(local, at_horizon + 1, &[]));
        assert_eq!(past.len(), 2);
        assert!(past.values().all(Option::is_none));
        store.apply(&past);
        assert!(load_read_frontier(&store, local).is_empty());
    }

    /// A merged parent's first block folds its children's pairs by
    /// maximum into its own pair and removes the grandchildren's copies.
    #[test]
    fn a_merged_parents_first_block_folds_its_childrens_tables() {
        let parent = ShardId::leaf(1, 0);
        let (left, right) = parent.children();
        let producer = ShardId::leaf(1, 1);
        let other = ShardId::leaf(2, 3);
        let mut store = Entries::default();
        // Each child wrote its own pair while it ran.
        store.apply(&read_frontier_writes(
            &store,
            &inputs(left, 100, &[(producer, mark(1, 40))]),
        ));
        store.apply(&read_frontier_writes(
            &store,
            &inputs(right, 100, &[(producer, mark(1, 55)), (other, mark(1, 9))]),
        ));
        let folded = ReadFrontier::from_entries([(producer, mark(1, 55)), (other, mark(1, 9))]);
        assert_eq!(
            load_read_frontier(&store, parent),
            folded,
            "the seat reads the maximum"
        );
        let writes = read_frontier_writes(&store, &inputs(parent, 200, &[]));
        store.apply(&writes);
        assert_eq!(load_read_frontier(&store, parent), folded);
        for owner in strays(parent) {
            assert!(
                table_under(&store, owner).is_empty(),
                "the grandchildren's copies are gone"
            );
        }
        for owner in copies(parent) {
            assert_eq!(
                table_under(&store, owner),
                folded,
                "and both of the parent's hold the fold"
            );
        }
        assert!(read_frontier_writes(&store, &inputs(parent, 300, &[])).is_empty());
    }
}
