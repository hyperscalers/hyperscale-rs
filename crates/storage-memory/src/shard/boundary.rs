//! In-memory boundary pins for snap-sync serving.
//!
//! The simulated store retains every JMT version and the full
//! state-history log, so pinning a boundary copies nothing: a pin is a
//! recorded height, and an opened boundary reads the live tree store at
//! that version. Retention mirrors the production checkpoint ring so
//! eviction behaviour is exercised in simulation too.

use std::sync::{Arc, RwLock};

use hyperscale_jmt::{Key, NibblePath, Node, NodeKey, TreeReader};
use hyperscale_storage::lock_recover::{read_or_recover, write_or_recover};
use hyperscale_storage::tree::import_leaf_updates;
use hyperscale_storage::{
    BOUNDARY_RETAIN, BoundaryStore, ImportLeaf, ResolveLeaf, filter_updates_to_prefix,
    merge_owned_nodes, merge_updates_from_receipts,
};
use hyperscale_types::{BlockHeight, StateRoot, StoredReceipt};

use super::core::SimShardStorage;
use super::snapshot::value_at_version;
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

impl ResolveLeaf for SimBoundary {
    fn resolve_leaf(&self, leaf_key: &Key) -> Option<(Vec<u8>, Vec<u8>)> {
        let state = read_or_recover(&self.state);
        let storage_key = state.associations.get(leaf_key)?.clone();
        let value = value_at_version(
            &state.current_state,
            &state.state_history,
            &storage_key,
            self.version,
            state.current_block_height.inner(),
        )?;
        drop(state);
        Some((storage_key, value))
    }
}

impl BoundaryStore for SimShardStorage {
    type Boundary = SimBoundary;

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

    fn import_boundary_state(
        &self,
        height: BlockHeight,
        leaves: Vec<ImportLeaf>,
    ) -> Result<StateRoot, String> {
        let mut state = write_or_recover(&self.state);
        if state.current_block_height != BlockHeight::GENESIS
            || state.current_root_hash != StateRoot::ZERO
        {
            return Err("snap-sync import requires an empty store".to_string());
        }

        let root_path = state.tree_store.root_path();
        let (root, result) = import_leaf_updates(&state.tree_store, &root_path, height, &leaves)?;
        for (key, node) in result.batch.new_nodes {
            state.tree_store.insert(key, Arc::new(node));
        }
        for leaf in leaves {
            state
                .associations
                .insert(leaf.leaf_key, leaf.storage_key.clone());
            state.current_state.insert(leaf.storage_key, leaf.value);
        }

        // Seed the substate byte total: a fresh-tree import's byte delta IS
        // the imported leaves' value bytes.
        let bytes = u64::try_from(result.batch.bytes_delta)
            .map_err(|_| "snap-sync import produced a negative byte total".to_string())?;
        state.substate_bytes.insert(height.inner(), bytes);

        state.current_block_height = height;
        state.current_root_hash = root;
        drop(state);
        Ok(root)
    }

    fn follow_block_writes(
        &self,
        height: BlockHeight,
        receipts: &[StoredReceipt],
    ) -> Result<StateRoot, String> {
        let owner_map = merge_owned_nodes(receipts);
        let merged = merge_updates_from_receipts(receipts);
        let mut state = write_or_recover(&self.state);
        if height <= state.current_block_height {
            return Err(format!(
                "follow at height {height} does not advance the store's version {}",
                state.current_block_height,
            ));
        }
        let filtered = filter_updates_to_prefix(&merged, &owner_map, &state.tree_store.root_path());
        if filtered.node_updates.is_empty() {
            return Ok(state.current_root_hash);
        }
        let root = apply_state_writes(&mut state, &filtered, &owner_map, height);
        drop(state);
        Ok(root)
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_jmt::{Blake3Hasher, Tree};
    use hyperscale_storage::test_helpers::{
        db_node_key, make_database_update, test_boundary_import_roundtrip,
        test_boundary_retention_evicts_oldest, test_boundary_unpinned_height_not_served,
    };
    use hyperscale_storage::{DatabaseUpdates, SubstateStore};
    use hyperscale_types::state_key::node_routing_hash;
    use hyperscale_types::{
        BoundedVec, ConsensusReceipt, GlobalReceiptHash, Hash, NodeId, ShardId, SplitChildRoots,
        TxHash, shard_prefix_path,
    };

    use super::*;

    type Jmt = Tree<Blake3Hasher, 1>;

    fn commit_one(storage: &SimShardStorage, seed: u8) {
        let updates = make_database_update(vec![seed; 50], 0, vec![seed], vec![seed, seed, seed]);
        storage.commit_shared(&updates);
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

        let start = [0u8; 32];
        let end = [0xFFu8; 32];
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
        let node_key = vec![7u8; 50];
        let old = make_database_update(node_key.clone(), 0, vec![7], vec![1]);
        storage.commit_shared(&old);
        storage.pin_boundary(BlockHeight::new(1)).unwrap();

        // Overwrite the same substate at height 2.
        let new = make_database_update(node_key, 0, vec![7], vec![2]);
        storage.commit_shared(&new);

        let boundary = storage.open_boundary(BlockHeight::new(1)).expect("pinned");
        let root_key = boundary.get_root_key(1).expect("pinned root resolves");
        let chunk = Jmt::collect_range(&boundary, &root_key, &[0u8; 32], &[0xFF; 32], 10).unwrap();
        let (leaf, _) = chunk.leaves.first().expect("one substate committed");
        let (_, value) = boundary.resolve_leaf(leaf).expect("leaf resolves");
        assert_eq!(value, vec![1]);
    }

    #[test]
    fn retention_evicts_oldest_pin() {
        let storage = SimShardStorage::default();
        test_boundary_retention_evicts_oldest(&storage, |seed| commit_one(&storage, seed));
    }

    #[test]
    fn unpinned_height_is_not_served() {
        let storage = SimShardStorage::default();
        test_boundary_unpinned_height_not_served(&storage, |seed| commit_one(&storage, seed));
    }

    /// Full serve → import round trip: leaves enumerated and resolved
    /// from a pinned boundary rebuild an identical store, with the raw
    /// substates readable.
    #[test]
    fn imported_boundary_state_reproduces_the_root() {
        let storage = SimShardStorage::default();
        let fresh = SimShardStorage::default();
        test_boundary_import_roundtrip(&storage, &fresh, |seed| commit_one(&storage, seed));
    }

    /// One write to the logical node `[seed; 30]` wrapped as a synced
    /// receipt — the shape a followed parent block's writes arrive in.
    fn follow_receipt(seed: u8) -> (DatabaseUpdates, StoredReceipt) {
        let updates = make_database_update(db_node_key(seed), 0, vec![seed], vec![seed; 4]);
        let receipt = StoredReceipt::synced(
            TxHash::from_raw(Hash::from_bytes(&[seed])),
            Arc::new(ConsensusReceipt::Succeeded {
                receipt_hash: GlobalReceiptHash::ZERO,
                database_updates: updates.clone(),
                owned_nodes: BoundedVec::new(),
                application_events: Vec::new(),
                beacon_witness_events: Vec::new(),
            }),
        );
        (updates, receipt)
    }

    /// Which child of the root the logical node `[seed; 30]` routes to —
    /// the first bit of its routing hash.
    fn child_of(seed: u8) -> ShardId {
        let (left, right) = ShardId::ROOT.children();
        if node_routing_hash(&NodeId([seed; 30]))[0] >> 7 == 0 {
            left
        } else {
            right
        }
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
        for seed in 1u8..=12 {
            let (updates, receipt) = follow_receipt(seed);
            parent.commit_shared(&updates);
            let height = BlockHeight::new(u64::from(seed));
            let receipts = [receipt];

            let left_before = left_store.state_root();
            let right_before = right_store.state_root();
            let left_after = left_store.follow_block_writes(height, &receipts).unwrap();
            let right_after = right_store.follow_block_writes(height, &receipts).unwrap();

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

    /// A follow must advance the store's version; replaying a height the
    /// store already applied is rejected.
    #[test]
    fn follow_rejects_a_non_advancing_height() {
        let store = SimShardStorage::new(shard_prefix_path(child_of(1)));
        let (_, receipt) = follow_receipt(1);
        let receipts = [receipt];
        store
            .follow_block_writes(BlockHeight::new(5), &receipts)
            .unwrap();
        assert!(
            store
                .follow_block_writes(BlockHeight::new(5), &receipts)
                .is_err(),
        );
    }
}
