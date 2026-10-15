//! The crossing index a shard's execution asks its questions from, read
//! at the chain's persisted tip.

use std::sync::Arc;

use hyperscale_execution::{CrossingIndex, CrossingRead};
use hyperscale_storage::{CrossingCursor, PendingChain, ShardStorage, SubstateStore, Substates};
use hyperscale_types::{ShardId, SubstateKey, shard_prefix_path};

/// The persisted index's rows, or those its store's journal names as
/// put or removed since the reader's cursor, each point-read at the
/// persisted tip and dropped where it reads absent there.
///
/// A block committed but not yet persisted is not seen: a cell it writes
/// is missed and a cell it removes still reads present until it
/// persists. That costs latency only: nothing an asker returns reaches a
/// block without the voter re-proving it.
pub struct ChainCrossings<S: ShardStorage>(pub Arc<PendingChain<S>>);

impl<S: ShardStorage> CrossingIndex for ChainCrossings<S> {
    fn crossing_changes(
        &self,
        shard: ShardId,
        since: Option<CrossingCursor>,
    ) -> (CrossingRead, Option<CrossingCursor>) {
        let view = self.0.view_at_persisted_tip();
        let tip = view.snapshot();
        let under = shard_prefix_path(shard);
        let (changed, cursor) = view
            .base()
            .crossing_changes(&under, since, view.anchor_height());
        let read = changed.map_or_else(
            || {
                CrossingRead::Whole(
                    view.base()
                        .crossing_rows(&under)
                        .into_iter()
                        .filter_map(|key| tip.cell(key).map(|value| (key, value)))
                        .collect(),
                )
            },
            |keys| {
                CrossingRead::Changed(keys.into_iter().map(|key| (key, tip.cell(key))).collect())
            },
        );
        (read, Some(cursor))
    }

    fn cell(&self, key: SubstateKey) -> Option<Vec<u8>> {
        self.0.view_at_persisted_tip().snapshot().cell(key)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use hyperscale_storage::test_helpers::{
        StatedRowChain, commit_settled_at, make_test_block, make_test_certified,
    };
    use hyperscale_storage::{
        ChainEntry, ChainWrites, MemberInputs, ParentAnchor, ShardChainWriter, SubstateStore,
        VersionedStore, member_row_leaf,
    };
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::{
        Address, AddressClass, BeaconWitnessCommit, BeaconWitnessLeafCount, BlockHeight,
        ChainOrigin, FrontierInputs, ResourceAddr, SweepFrontier, SyncHint,
    };
    use hyperscale_vm_effects::{CrossingId, Hash32, IntentHash, ProtocolHasher, Terms, TxHash};

    use super::*;

    fn record(seed: u8) -> (SubstateKey, Vec<u8>) {
        let id = CrossingId {
            producer: Address::new([seed; 31], AddressClass::Component),
            consumer: Address::new([seed + 1; 31], AddressClass::Component),
            intent: IntentHash(Hash32([seed; 32])),
            local: 0,
            output: 0,
        };
        let cell = id.cell(
            TxHash(Hash32([seed; 32])),
            ResourceAddr::new([0xE0; 31]),
            5,
            9_000,
            Terms::Owed,
        );
        (id.record_key(&ProtocolHasher), cell.to_bytes())
    }

    /// The index reads at the persisted tip: a block committed to the
    /// chain but not yet persisted is not seen, neither the record it
    /// writes nor the one it removes, and both are seen once it
    /// persists.
    #[test]
    fn the_index_sees_a_block_once_it_persists() {
        let witness = BeaconWitnessCommit::empty(BeaconWitnessLeafCount::ZERO);
        let store = SimShardStorage::default();
        let (a, a_bytes) = record(0x41);
        let (b, b_bytes) = record(0x51);
        commit_settled_at(
            &store,
            &make_test_certified(make_test_block(BlockHeight::new(1))),
            &[(a, a_bytes)],
            &[],
            &witness,
        );
        let chain = Arc::new(PendingChain::new(
            Arc::new(store.clone()),
            ChainOrigin::ROOT,
        ));
        let index = ChainCrossings(Arc::clone(&chain));
        let rows = |index: &ChainCrossings<SimShardStorage>| match index
            .crossing_changes(ShardId::ROOT, None)
            .0
        {
            CrossingRead::Whole(rows) => rows.into_iter().map(|(key, _)| key).collect::<Vec<_>>(),
            CrossingRead::Changed(_) => panic!("no cursor reads the rows whole"),
        };
        assert!(index.present(a));
        assert_eq!(rows(&index), vec![a]);

        let second = make_test_certified(make_test_block(BlockHeight::new(2)));
        let base = Arc::new(store);
        let (_, jmt_snapshot, commit) = base.prepare_block_commit(
            ParentAnchor {
                state_root: base.state_root(),
                height: BlockHeight::new(1),
                state: &base.snapshot(),
                pending: &[],
                base_reads: None,
            },
            &[],
            ChainWrites {
                creations: &[(b, b_bytes)],
                removals: &[a],
                sweep_frontier: SweepFrontier::ZERO,
                frontier: &FrontierInputs::still(ShardId::ROOT),
                state_claims: &[],
                members: &MemberInputs::still(ShardId::ROOT),
            },
            BlockHeight::new(2),
        );
        chain.insert(
            second.block().hash(),
            ChainEntry {
                parent_block_hash: second.block().header().parent_block_hash(),
                height: BlockHeight::new(2),
                settled_txs: Vec::new(),
                jmt_snapshot,
                certified_block: None,
            },
        );
        assert!(
            index.present(a),
            "the removal is not seen before it persists"
        );
        assert!(!index.present(b), "nor the write");
        assert_eq!(rows(&index), vec![a]);

        commit(SyncHint::FlushNow, &second, &witness);
        assert!(!index.present(a));
        assert!(index.present(b));
        assert_eq!(rows(&index), vec![b]);
    }

    /// The index answers for a member's row as the persisted tip holds
    /// its leaf: standing on a replica that has flushed the block that
    /// ran the member and not yet the block that ended it, and absent
    /// on one short of the first or past the second, whatever its
    /// pending chain holds.
    #[test]
    fn the_index_reads_a_member_row_at_the_persisted_tip() {
        let row = member_row_leaf(ShardId::ROOT, StatedRowChain::<SimShardStorage>::member());
        for (persisted, stands) in [(0, false), (1, true), (2, true), (3, true), (4, false)] {
            let replica = StatedRowChain::at_depth(SimShardStorage::default(), persisted);
            let index = ChainCrossings(Arc::clone(replica.chain()));
            assert_eq!(
                index.present(row),
                stands,
                "with {persisted} blocks persisted",
            );
        }
    }

    /// A reader following the index's changes across commits, and across
    /// a store restored from an older image, holds after every commit the
    /// rows a whole read finds.
    #[test]
    fn a_reader_following_the_changes_holds_the_rows_a_whole_read_finds() {
        let witness = BeaconWitnessCommit::empty(BeaconWitnessLeafCount::ZERO);
        let store = SimShardStorage::default();
        let chain = Arc::new(PendingChain::new(
            Arc::new(store.clone()),
            ChainOrigin::ROOT,
        ));
        let index = ChainCrossings(Arc::clone(&chain));
        let whole = || match index.crossing_changes(ShardId::ROOT, None).0 {
            CrossingRead::Whole(rows) => rows.into_iter().collect::<BTreeMap<_, _>>(),
            CrossingRead::Changed(_) => panic!("no cursor reads the rows whole"),
        };
        let mut followed: BTreeMap<SubstateKey, Vec<u8>> = BTreeMap::new();
        let mut cursor = None;
        let mut images = Vec::new();
        let mut draw = 0x2545_F491_4F6C_DD1Du64;
        let mut next = |below: u64| {
            draw ^= draw << 13;
            draw ^= draw >> 7;
            draw ^= draw << 17;
            draw % below
        };
        for height in 1..=120u64 {
            if next(15) == 0 && !images.is_empty() {
                let at = usize::try_from(next(images.len() as u64)).expect("small");
                store.restore(&images[at]);
            } else {
                let rows = whole();
                let creations: Vec<(SubstateKey, Vec<u8>)> = (0..next(4))
                    .map(|_| record(u8::try_from(next(40)).expect("small") * 2 + 1))
                    .filter(|(key, _)| !rows.contains_key(key))
                    .collect::<BTreeMap<_, _>>()
                    .into_iter()
                    .collect();
                let removals: Vec<SubstateKey> = rows
                    .keys()
                    .filter(|_| next(4) == 0)
                    .copied()
                    .filter(|key| creations.iter().all(|(created, _)| created != key))
                    .collect();
                commit_settled_at(
                    &store,
                    &make_test_certified(make_test_block(store.jmt_height().next())),
                    &creations,
                    &removals,
                    &witness,
                );
                images.push(store.image());
            }
            let (read, moved) = index.crossing_changes(ShardId::ROOT, cursor);
            cursor = moved;
            match read {
                CrossingRead::Whole(rows) => followed = rows.into_iter().collect(),
                CrossingRead::Changed(rows) => {
                    for (key, value) in rows {
                        match value {
                            Some(value) => followed.insert(key, value),
                            None => followed.remove(&key),
                        };
                    }
                }
            }
            assert_eq!(followed, whole(), "at height {height}");
        }
    }

    /// A reader following the changes through `ChainCrossings` while
    /// another thread commits to the store holds the rows a whole read
    /// finds once the commits stop: it never stands past the height it
    /// read the rows at.
    #[test]
    fn a_reader_following_beside_concurrent_commits_holds_the_rows_a_whole_read_finds() {
        let witness = BeaconWitnessCommit::empty(BeaconWitnessLeafCount::ZERO);
        let store = SimShardStorage::default();
        // The writer stamps its blocks a second apart and runs far ahead
        // of a reader the machine stalls, so the retention floor would
        // pass a tip the reader captured within a horizon's worth of
        // commits. A node's tick chain holds retention at or below any
        // tip its readers take; here the hold is genesis, for the run.
        store.hold_retention_at(BlockHeight::new(0));
        let chain = Arc::new(PendingChain::new(
            Arc::new(store.clone()),
            ChainOrigin::ROOT,
        ));
        let index = ChainCrossings(Arc::clone(&chain));
        let done = std::sync::atomic::AtomicBool::new(false);
        let follow = |cursor: Option<CrossingCursor>, rows: &mut BTreeMap<SubstateKey, Vec<u8>>| {
            let (read, moved) = index.crossing_changes(ShardId::ROOT, cursor);
            match read {
                CrossingRead::Whole(whole) => *rows = whole.into_iter().collect(),
                CrossingRead::Changed(changed) => {
                    for (key, value) in changed {
                        match value {
                            Some(value) => rows.insert(key, value),
                            None => rows.remove(&key),
                        };
                    }
                }
            }
            moved
        };
        let mut followed = BTreeMap::new();
        let mut reads = 0u32;
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let mut draw = 0x2545_F491_4F6C_DD1Du64;
                let mut next = |below: u64| {
                    draw ^= draw << 13;
                    draw ^= draw >> 7;
                    draw ^= draw << 17;
                    draw % below
                };
                let mut standing: Vec<SubstateKey> = Vec::new();
                for _ in 0..400 {
                    let creations: Vec<(SubstateKey, Vec<u8>)> = (0..next(4))
                        .map(|_| record(u8::try_from(next(40)).expect("small") * 2 + 1))
                        .filter(|(key, _)| !standing.contains(key))
                        .collect::<BTreeMap<_, _>>()
                        .into_iter()
                        .collect();
                    let removals: Vec<SubstateKey> =
                        standing.iter().filter(|_| next(4) == 0).copied().collect();
                    standing.retain(|key| !removals.contains(key));
                    standing.extend(creations.iter().map(|(key, _)| *key));
                    commit_settled_at(
                        &store,
                        &make_test_certified(make_test_block(store.jmt_height().next())),
                        &creations,
                        &removals,
                        &witness,
                    );
                }
                done.store(true, std::sync::atomic::Ordering::SeqCst);
            });
            let mut cursor = None;
            while !done.load(std::sync::atomic::Ordering::SeqCst) {
                cursor = follow(cursor, &mut followed);
                reads += 1;
            }
            follow(cursor, &mut followed);
        });
        let mut whole = BTreeMap::new();
        follow(None, &mut whole);
        assert!(reads > 10, "the reader ran beside the commits: {reads}");
        assert_eq!(followed, whole, "after {reads} reads");
    }
}
