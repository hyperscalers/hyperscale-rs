//! In-memory boundary pins for snap-sync serving.
//!
//! The simulated store retains every JMT version and the full
//! state-history log, so pinning a boundary copies nothing: a pin is a
//! recorded height, and an opened boundary reads the live tree store at
//! that version. Retention mirrors the production checkpoint ring so
//! eviction behaviour is exercised in simulation too.

use std::sync::{Arc, RwLock};

use hyperscale_jmt::{NibblePath, Node, NodeKey, TreeReader};
use hyperscale_storage::lock_recover::{read_or_recover, write_or_recover};
use hyperscale_storage::tree::import_leaf_updates;
use hyperscale_storage::{
    AdoptSource, BOUNDARY_RETAIN, BoundaryStore, ImportProgress, LeafRows, SubstateStore,
    Substates, SweepRows, WitnessSeed, followed_block_writes, holds_state, is_record_cell,
    key_under_prefix, prefix_low_key,
};
use hyperscale_types::{
    Block, BlockHeight, ChainOrigin, EntryKey, ShardId, StateRoot, SubstateKey, SubstateLeaf,
    shard_prefix_path,
};
use hyperscale_vm_types::{Address, CollectionId};

use super::core::SimShardStorage;
use super::snapshot::{entries_in_range_at, value_at_version};
use super::state::{SharedState, apply_state_writes};

/// A pinned boundary served from the live versioned store.
///
/// JMT reads see every retained version; substate reads resolve at the
/// pinned height through the state-history log. No data is copied — the
/// handle shares the store's state behind its lock.
pub struct SimBoundary {
    state: Arc<RwLock<SharedState>>,
    version: u64,
}

impl TreeReader for SimBoundary {
    fn get_node(&self, key: &NodeKey) -> Option<Arc<Node>> {
        read_or_recover(&self.state).tree_store.get_node(key)
    }

    fn get_root_key(&self, version: u64) -> Option<NodeKey> {
        read_or_recover(&self.state)
            .tree_store
            .get_root_key(version)
    }

    fn root_path(&self) -> NibblePath {
        read_or_recover(&self.state).tree_store.root_path()
    }
}

impl Substates for SimBoundary {
    fn cell(&self, key: SubstateKey) -> Option<Vec<u8>> {
        let state = read_or_recover(&self.state);
        value_at_version(
            &state.current_state,
            &state.state_history,
            key,
            self.version,
            state.current_block_height.inner(),
        )
    }

    fn entries_in_range(
        &self,
        owner: Address,
        collection: CollectionId,
        lo: u128,
        hi: u128,
        limit: usize,
    ) -> Vec<(u128, Vec<u8>)> {
        let state = read_or_recover(&self.state);
        entries_in_range_at(
            &state.current_entries,
            &state.entries_history,
            EntryKey {
                owner,
                collection,
                order: lo,
            },
            EntryKey {
                owner,
                collection,
                order: hi,
            },
            limit,
            self.version,
            state.current_block_height.inner(),
        )
    }
}

impl BoundaryStore for SimShardStorage {
    type Boundary = SimBoundary;

    fn escrow_records(&self, shard: ShardId) -> Vec<(SubstateKey, Vec<u8>)> {
        let prefix = shard_prefix_path(shard);
        read_or_recover(&self.state)
            .current_state
            .range(prefix_low_key(&prefix)..)
            .take_while(|(key, _)| key_under_prefix(&key.to_bytes(), &prefix))
            .filter(|(key, value)| is_record_cell(**key, value))
            .map(|(key, value)| (*key, value.to_vec()))
            .collect()
    }

    fn pin_boundary(&self, height: BlockHeight) -> Result<(), String> {
        let mut pins = write_or_recover(&self.boundary_pins);
        pins.insert(height);
        while pins.len() > BOUNDARY_RETAIN {
            pins.pop_first();
        }
        drop(pins);
        Ok(())
    }

    fn open_boundary(&self, height: BlockHeight) -> Option<SimBoundary> {
        read_or_recover(&self.boundary_pins)
            .contains(&height)
            .then(|| SimBoundary {
                state: Arc::clone(&self.state),
                version: height.inner(),
            })
    }

    fn stage_import_chunk(
        &self,
        progress: &ImportProgress,
        leaves: &[SubstateLeaf],
    ) -> Result<(), String> {
        let state = read_or_recover(&self.state);
        if holds_state(state.current_block_height, state.current_root_hash) {
            return Err("snap-sync staging requires an empty store".to_string());
        }
        drop(state);

        let mut staging = write_or_recover(&self.import_staging);
        for leaf in leaves {
            staging.leaves.insert(leaf.key, leaf.value.clone());
        }
        staging.progress = Some(progress.clone());
        drop(staging);
        Ok(())
    }

    fn read_import_progress(&self) -> Option<ImportProgress> {
        read_or_recover(&self.import_staging).progress.clone()
    }

    fn wipe_import_staging(&self) -> Result<(), String> {
        let mut staging = write_or_recover(&self.import_staging);
        staging.leaves.clear();
        staging.progress = None;
        drop(staging);
        Ok(())
    }

    fn finalize_boundary_import(
        &self,
        height: BlockHeight,
        witnesses: WitnessSeed,
    ) -> Result<StateRoot, String> {
        let mut state = write_or_recover(&self.state);
        if holds_state(state.current_block_height, state.current_root_hash) {
            return Err("snap-sync import requires an empty store".to_string());
        }

        let mut staging = write_or_recover(&self.import_staging);
        // The drivers gate finalize on assembly completeness; a progress
        // record still binding this height with open cursors means a
        // caller slipped past that gate. Refusing here beats sealing a
        // root that can never verify.
        if let Some(progress) = &staging.progress
            && progress.anchor_height == height
            && !progress.cursors.iter().all(|cursor| cursor.done)
        {
            return Err("snap-sync finalize on an incomplete assembly".to_string());
        }
        // The checks passed: the staging area empties into the build by
        // move — the memory equivalent of the sealed final batch's
        // staging wipe.
        let staged = std::mem::take(&mut staging.leaves);
        staging.progress = None;
        drop(staging);
        let leaves: Vec<SubstateLeaf> = staged
            .into_iter()
            .map(|(key, value)| SubstateLeaf { key, value })
            .collect();

        let root_path = state.tree_store.root_path();
        let (root, result) =
            import_leaf_updates(&state.tree_store, &root_path, None, height.inner(), &leaves)?;
        for (key, node) in result.batch.new_nodes {
            state.tree_store.insert(key, Arc::new(node));
        }
        let mut sweep_rows = SweepRows::default();
        for leaf in leaves {
            // Every index is derived state, rebuilt from the leaves
            // themselves: a row exists exactly where a leaf re-derives
            // it. A successor holds the prefix and no history, so the
            // leaves it just imported are the only honest source for
            // what it owes a sweep, and for the artifacts a foreign
            // shard can still fetch from it once its committee turns
            // over.
            let LeafRows {
                entry,
                package,
                sweep,
            } = LeafRows::of(leaf.key, &leaf.value);
            if let Some((entry_key, value)) = entry {
                state.current_entries.insert(entry_key, Arc::from(value));
            }
            if let Some(package) = package {
                state.package_artifacts.insert(package, leaf.value.clone());
            }
            sweep_rows.delta(leaf.key.owner, None, sweep);
            state.current_state.insert(leaf.key, Arc::from(leaf.value));
        }
        state.sweep_index.fold(&sweep_rows);

        // Seed the substate byte total: a fresh-tree import's byte delta IS
        // the imported leaves' value bytes.
        let bytes = u64::try_from(result.batch.bytes_delta)
            .map_err(|_| "snap-sync import produced a negative byte total".to_string())?;
        state.substate_bytes.insert(height.inner(), bytes);

        state.current_block_height = height;
        state.current_root_hash = root;
        drop(state);

        // Seed the anchor window's witness payloads at their absolute leaf
        // indices, mirroring the RocksDB import: the accumulator rebuilds
        // and the beacon fold's fetches answer from this column.
        let mut consensus = write_or_recover(&self.consensus);
        for (offset, payload) in witnesses.payloads.into_iter().enumerate() {
            consensus
                .beacon_witnesses
                .insert(witnesses.base.inner() + offset as u64, payload);
        }
        if let Some(boundary) = witnesses.boundary {
            consensus.boundary_headers.insert(height, boundary);
        }
        drop(consensus);
        // The store now holds exactly the boundary's state, as one that
        // committed through it would, and that one pinned it.
        self.pin_boundary(height)?;
        Ok(root)
    }

    fn follow_block_writes(
        &self,
        block: &Block,
        creations: &[(SubstateKey, Vec<u8>)],
    ) -> Result<StateRoot, String> {
        let height = block.height();
        let prefix = read_or_recover(&self.state).tree_store.root_path();
        // Anchored at this store's own tip, which the check above holds
        // only to being behind the followed block rather than one short
        // of it. A follow that skips a height resolves its movements
        // against a baseline missing what the gap left, and fails against
        // the child roots rather than committing quietly.
        let filtered = followed_block_writes(self, &self.snapshot(), block, creations, &prefix);
        let mut state = write_or_recover(&self.state);
        if height <= state.current_block_height {
            return Err(format!(
                "follow at height {height} does not advance the store's version {}",
                state.current_block_height,
            ));
        }
        if filtered.is_empty() {
            return Ok(state.current_root_hash);
        }
        let root = apply_state_writes(&mut state, &filtered, height);
        drop(state);
        Ok(root)
    }

    fn adopt_genesis(
        &self,
        origin: ChainOrigin,
        genesis: &Block,
        source: AdoptSource,
    ) -> Result<StateRoot, String> {
        Self::adopt_genesis(self, origin, genesis, source)
    }

    fn substate_bytes_at_version(&self, version: u64) -> Option<u64> {
        Self::substate_bytes_at_version(self, version)
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_jmt::{Blake3Hasher, KEY_BYTES, Tree};
    use hyperscale_storage::test_helpers::{
        block_settling, commit_one, commit_writes, make_settled_writes, make_state_writes,
        test_boundary_import_roundtrip, test_boundary_retention_evicts_oldest,
        test_boundary_unpinned_height_not_served, test_escrow_records_are_read_off_the_state,
        test_import_gate_reads_the_trie,
    };
    use hyperscale_storage::{SubstateStore, Substates, committed_tx_cell_key, committed_tx_cells};
    use hyperscale_types::test_utils::{
        install_stub_protocol_statics, stub_sweepable_cell, test_key, test_transaction,
    };
    use hyperscale_types::{
        AddressClass, Block, BlockHeader, BlockHeaderParts, BlockHeight, ConsensusReceipt,
        GlobalReceiptHash, Hash, SettledWrites, ShardId, SplitChildRoots, StateWrites,
        StoredReceipt, SubstateKey, SweepBucket, SweepFrontier, Transaction, TxHash, Verifiable,
        WitnessSources, shard_prefix_path,
    };

    use super::*;

    type Jmt = Tree<Blake3Hasher, 1>;

    #[test]
    fn finalize_refuses_an_incomplete_assembly_bound_to_the_height() {
        use hyperscale_storage::test_helpers::completed_import_progress;

        let storage = SimShardStorage::default();
        let mut progress = completed_import_progress(BlockHeight::new(3), 1);
        progress.cursors[0].done = false;
        let leaf = SubstateLeaf {
            key: test_key(0x42),
            value: vec![1],
        };
        storage.stage_import_chunk(&progress, &[leaf]).unwrap();

        let err = storage
            .finalize_boundary_import(BlockHeight::new(3), WitnessSeed::default())
            .unwrap_err();
        assert!(err.contains("incomplete assembly"), "{err}");
        // Staging survives and nothing landed in the store.
        assert!(storage.read_import_progress().is_some());
        assert_eq!(storage.state_root(), StateRoot::ZERO);
    }

    #[test]
    fn pinned_boundary_serves_verified_range_after_later_commits() {
        let storage = SimShardStorage::default();
        commit_one(&storage, 1);
        let pinned_root = storage.state_root();
        storage.pin_boundary(BlockHeight::new(1)).unwrap();

        // The live store moves on; the pin still serves height 1.
        commit_one(&storage, 2);
        assert_ne!(storage.state_root(), pinned_root);

        let boundary = storage.open_boundary(BlockHeight::new(1)).expect("pinned");
        let root_key = boundary.get_root_key(1).expect("pinned root resolves");

        let start = [0u8; KEY_BYTES];
        let end = [0xFFu8; KEY_BYTES];
        let chunk = Jmt::collect_range(&boundary, &root_key, &start, &end, 1_000).unwrap();
        assert!(!chunk.leaves.is_empty());
        let proof = Jmt::prove_range(&boundary, &root_key, &start, &end, &chunk).unwrap();
        Jmt::verify_range(
            &proof,
            *pinned_root.as_raw().as_bytes(),
            &NibblePath::empty(),
            &start,
            &end,
            &chunk,
        )
        .unwrap();
    }

    #[test]
    fn boundary_leaf_reads_resolve_at_pinned_version() {
        let storage = SimShardStorage::default();
        let old = make_settled_writes(7, 7, vec![1]);
        commit_writes(&storage, &old);
        storage.pin_boundary(BlockHeight::new(1)).unwrap();

        // Overwrite the same substate at height 2.
        let new = make_settled_writes(7, 7, vec![2]);
        commit_writes(&storage, &new);

        let boundary = storage.open_boundary(BlockHeight::new(1)).expect("pinned");
        let root_key = boundary.get_root_key(1).expect("pinned root resolves");
        let chunk = Jmt::collect_range(
            &boundary,
            &root_key,
            &[0u8; KEY_BYTES],
            &[0xFF; KEY_BYTES],
            10,
        )
        .unwrap();
        let (leaf, _) = chunk.leaves.first().expect("one substate committed");
        let value = boundary
            .cell(SubstateKey::from_bytes(*leaf).expect("a stored leaf key names an address"))
            .expect("leaf resolves");
        assert_eq!(value, vec![1]);
    }

    #[test]
    fn retention_evicts_oldest_pin() {
        let storage = SimShardStorage::default();
        test_boundary_retention_evicts_oldest(&storage);
    }

    #[test]
    fn unpinned_height_is_not_served() {
        let storage = SimShardStorage::default();
        test_boundary_unpinned_height_not_served(&storage);
    }

    /// Full serve → import round trip: leaves enumerated and resolved
    /// from a pinned boundary rebuild an identical store, with the raw
    /// substates readable.
    #[test]
    fn imported_boundary_state_reproduces_the_root() {
        let storage = SimShardStorage::default();
        let fresh = SimShardStorage::default();
        test_boundary_import_roundtrip(&storage, &fresh);
    }

    /// A store answers for the escrow records its state holds, which is
    /// what a merge successor's adoption reads its obligations off.
    #[test]
    fn escrow_records_are_read_off_the_state() {
        let storage = SimShardStorage::default();
        test_escrow_records_are_read_off_the_state(&storage);
    }

    #[test]
    fn the_import_gate_reads_the_trie_not_the_chain() {
        test_import_gate_reads_the_trie(&SimShardStorage::default(), &SimShardStorage::default());
    }

    /// One write under the owner prefix `[seed; 16]` wrapped as a synced
    /// receipt — the shape a followed parent block's writes arrive in.
    /// The same one-cell write in both forms: what the receipt carries,
    /// and what the store commits.
    fn follow_receipt(seed: u8) -> (SettledWrites, StoredReceipt) {
        let writes = make_state_writes(seed, seed, vec![seed; 4]);
        let receipt = StoredReceipt::synced(
            TxHash::from(Hash::from_bytes(&[seed])),
            Arc::new(ConsensusReceipt::Succeeded {
                receipt_hash: GlobalReceiptHash::ZERO,
                writes,
                beacon_witness_events: Vec::new(),
                events: Vec::new(),
            }),
        );
        (make_settled_writes(seed, seed, vec![seed; 4]), receipt)
    }

    /// Which child of the root the owner prefix `[seed; 16]` routes to —
    /// the leading bit of its leaf key, which is what a depth-1 shard
    /// prefix tests.
    fn child_of(seed: u8) -> ShardId {
        let (left, right) = ShardId::ROOT.children();
        if seed >> 7 == 0 { left } else { right }
    }

    /// Owner seeds paired with the height that writes them, alternating
    /// the leading bit so the fixture's writes straddle the root split.
    fn straddling_seeds() -> impl Iterator<Item = (u64, u8)> {
        (1u8..=12).map(|i| (u64::from(i), if i % 2 == 0 { i } else { i | 0x80 }))
    }

    /// Partition independence over follows, the keystone: two child
    /// stores each following only their half of a parent chain's writes
    /// assemble exactly the parent tree's two child subtrees — their
    /// roots recompose to the parent's, their byte totals partition its
    /// population, and a block with no writes under a store's prefix is
    /// a no-op that leaves its version line sparse.
    #[test]
    fn followed_children_partition_and_recompose_the_parent_root() {
        let parent = SimShardStorage::default();
        let (left, right) = ShardId::ROOT.children();
        let left_store = SimShardStorage::new(shard_prefix_path(left));
        let right_store = SimShardStorage::new(shard_prefix_path(right));

        let mut counts = [0u64, 0];
        for (height, seed) in straddling_seeds() {
            let (writes, receipt) = follow_receipt(seed);
            commit_writes(&parent, &writes);
            let height = BlockHeight::new(height);
            let receipts = [receipt];

            let left_before = left_store.state_root();
            let right_before = right_store.state_root();
            let block = block_settling(height, receipts.to_vec());
            let left_after = left_store.follow_block_writes(&block, &[]).unwrap();
            let right_after = right_store.follow_block_writes(&block, &[]).unwrap();

            // Exactly the routed side's root moves; the other side's
            // follow is a no-op.
            if child_of(seed) == left {
                counts[0] += 1;
                assert_ne!(left_after, left_before);
                assert_eq!(right_after, right_before);
            } else {
                counts[1] += 1;
                assert_eq!(left_after, left_before);
                assert_ne!(right_after, right_before);
            }
        }
        assert!(
            counts[0] > 0 && counts[1] > 0,
            "fixture seeds must straddle the split bit; got {counts:?}",
        );

        let pair = SplitChildRoots {
            left: left_store.state_root(),
            right: right_store.state_root(),
        };
        assert!(
            pair.composes_to(parent.state_root()),
            "followed child roots must recompose to the parent's root",
        );

        // Byte totals partition the parent population, recorded at each
        // store's own (sparse) tip version. Each follow seeds one leaf
        // with a 4-byte value (`follow_receipt`'s `vec![seed; 4]`), so a
        // side's byte total is its leaf count times four.
        for (store, count) in [(&left_store, counts[0]), (&right_store, counts[1])] {
            let tip = read_or_recover(&store.state).current_block_height;
            assert_eq!(
                store.substate_bytes_at_version(tip.inner()),
                Some(count * 4)
            );
        }
    }

    /// A live block at `height` whose header names `frontier` as its
    /// sweep, carrying `txs` and one tick settling `receipts`.
    fn followed_block(
        height: u64,
        frontier: SweepFrontier,
        txs: Vec<Transaction>,
        receipts: Vec<StoredReceipt>,
    ) -> Block {
        let Block::Live { certificates, .. } = block_settling(BlockHeight::new(height), receipts)
        else {
            unreachable!("the fixture builds a live block");
        };
        Block::Live {
            header: BlockHeader::new(BlockHeaderParts {
                height: BlockHeight::new(height),
                sweep_frontier: frontier,
                ..Default::default()
            }),
            transactions: Arc::new(
                txs.into_iter()
                    .map(|tx| Arc::new(Verifiable::from(tx)))
                    .collect(),
            ),
            certificates,
            provisions: Arc::new(Vec::new()),
            abandonment_records: Arc::new(Vec::new()),
            state_claims: Arc::new(Vec::new()),
            witness_sources: Arc::new(WitnessSources::empty()),
        }
    }

    /// A followed block is applied as the chain applied it, not as its
    /// receipts alone say: the committed cell of a transaction it carries
    /// lands on the child whose half holds it, and nowhere else.
    #[test]
    fn a_followed_block_writes_its_committed_cells_on_their_half() {
        let (left, right) = ShardId::ROOT.children();
        let left_store = SimShardStorage::new(shard_prefix_path(left));
        let right_store = SimShardStorage::new(shard_prefix_path(right));

        let tx = test_transaction(1);
        let cell = committed_tx_cell_key(
            ShardId::ROOT,
            tx.hash(),
            tx.validity_range().end_timestamp_exclusive,
        );
        let (routed, other) = if cell.to_bytes()[0] >> 7 == 0 {
            (&left_store, &right_store)
        } else {
            (&right_store, &left_store)
        };
        let creations = committed_tx_cells(ShardId::ROOT, std::iter::once(&tx));
        let carrying = followed_block(1, SweepFrontier::ZERO, vec![tx], Vec::new());
        let other_before = other.state_root();
        routed.follow_block_writes(&carrying, &creations).unwrap();
        other.follow_block_writes(&carrying, &creations).unwrap();
        assert!(
            routed.cell(cell).is_some(),
            "the committed cell lands on its half"
        );
        assert_eq!(
            other.state_root(),
            other_before,
            "the other half is untouched"
        );
    }

    /// A followed block sweeps what its header names: a frontier past an
    /// expired cell's bucket retires it, one short of it leaves it.
    #[test]
    fn a_followed_block_applies_the_sweep_its_header_names() {
        install_stub_protocol_statics();
        let (left, _) = ShardId::ROOT.children();
        let store = SimShardStorage::new(shard_prefix_path(left));

        let (local, value) = stub_sweepable_cell(5_000, 0x11);
        let sweepable = SubstateKey {
            owner: Address::new([0x01; 31], AddressClass::Component),
            local,
        };
        let mut writes = StateWrites::default();
        writes.cells.insert(sweepable, Some(value));
        let receipt = StoredReceipt::synced(
            TxHash::from(Hash::from_bytes(b"sweepable")),
            Arc::new(ConsensusReceipt::Succeeded {
                receipt_hash: GlobalReceiptHash::ZERO,
                writes,
                beacon_witness_events: Vec::new(),
                events: Vec::new(),
            }),
        );
        store
            .follow_block_writes(
                &followed_block(1, SweepFrontier::ZERO, Vec::new(), vec![receipt]),
                &[],
            )
            .unwrap();
        assert!(store.cell(sweepable).is_some());

        let bucket = SweepFrontier::of_leaf(sweepable).bucket();
        let short = SweepFrontier::start_of(bucket);
        store
            .follow_block_writes(&followed_block(2, short, Vec::new(), Vec::new()), &[])
            .unwrap();
        assert!(
            store.cell(sweepable).is_some(),
            "a frontier short of the cell leaves it"
        );

        let past = SweepFrontier::start_of(SweepBucket(bucket.0 + 1));
        store
            .follow_block_writes(&followed_block(3, past, Vec::new(), Vec::new()), &[])
            .unwrap();
        assert!(
            store.cell(sweepable).is_none(),
            "the sweep the header names retires it"
        );
    }

    /// A follow must advance the store's version; replaying a height the
    /// store already applied is rejected.
    #[test]
    fn follow_rejects_a_non_advancing_height() {
        let store = SimShardStorage::new(shard_prefix_path(child_of(1)));
        let (_, receipt) = follow_receipt(1);
        let block = block_settling(BlockHeight::new(5), vec![receipt]);
        store.follow_block_writes(&block, &[]).unwrap();
        assert!(store.follow_block_writes(&block, &[]).is_err());
    }
}
