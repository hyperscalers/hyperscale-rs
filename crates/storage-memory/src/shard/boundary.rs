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
use hyperscale_storage::shard::keys;
use hyperscale_storage::{
    BOUNDARY_RETAIN, BoundaryStore, DbPartitionKey, DbSortKey, SubstateLookup,
};
use hyperscale_types::BlockHeight;

use super::core::SimShardStorage;
use super::snapshot::value_at_version;
use super::state::SharedState;

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

impl SubstateLookup for SimBoundary {
    fn lookup_substate(
        &self,
        partition_key: &DbPartitionKey,
        sort_key: &DbSortKey,
    ) -> Option<Vec<u8>> {
        let storage_key = keys::to_storage_key(partition_key, sort_key);
        let state = read_or_recover(&self.state);
        value_at_version(
            &state.current_state,
            &state.state_history,
            &storage_key,
            self.version,
            state.current_block_height.inner(),
        )
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

    fn latest_boundary(&self) -> Option<BlockHeight> {
        read_or_recover(&self.boundary_pins).last().copied()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_jmt::{Blake3Hasher, Tree};
    use hyperscale_storage::SubstateStore;
    use hyperscale_storage::test_helpers::make_database_update;

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
        let chunk = Jmt::collect_range(&boundary, &root_key, &start, 1_000).unwrap();
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
    fn boundary_substate_reads_resolve_at_pinned_version() {
        let storage = SimShardStorage::default();
        let node_key = vec![7u8; 50];
        let old = make_database_update(node_key.clone(), 0, vec![7], vec![1]);
        storage.commit_shared(&old);
        storage.pin_boundary(BlockHeight::new(1)).unwrap();

        // Overwrite the same substate at height 2.
        let new = make_database_update(node_key.clone(), 0, vec![7], vec![2]);
        storage.commit_shared(&new);

        let boundary = storage.open_boundary(BlockHeight::new(1)).expect("pinned");
        let partition_key = DbPartitionKey {
            node_key,
            partition_num: 0,
        };
        let value = boundary.lookup_substate(&partition_key, &DbSortKey(vec![7]));
        assert_eq!(value, Some(vec![1]));
    }

    #[test]
    fn retention_evicts_oldest_pin() {
        let storage = SimShardStorage::default();
        for height in 1..=4u64 {
            commit_one(&storage, u8::try_from(height).unwrap());
            storage.pin_boundary(BlockHeight::new(height)).unwrap();
        }
        assert!(storage.open_boundary(BlockHeight::new(1)).is_none());
        assert!(storage.open_boundary(BlockHeight::new(2)).is_some());
        assert_eq!(storage.latest_boundary(), Some(BlockHeight::new(4)));
    }

    #[test]
    fn unpinned_height_is_not_served() {
        let storage = SimShardStorage::default();
        commit_one(&storage, 1);
        assert!(storage.open_boundary(BlockHeight::new(1)).is_none());
        assert_eq!(storage.latest_boundary(), None);
    }
}
