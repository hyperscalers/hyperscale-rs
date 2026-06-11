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
use hyperscale_storage::{BOUNDARY_RETAIN, BoundaryStore, ImportLeaf, ResolveLeaf};
use hyperscale_types::{BlockHeight, StateRoot};

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

        state.current_block_height = height;
        state.current_root_hash = root;
        drop(state);
        Ok(root)
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
        for height in 1..=4u64 {
            commit_one(&storage, u8::try_from(height).unwrap());
            storage.pin_boundary(BlockHeight::new(height)).unwrap();
        }
        assert!(storage.open_boundary(BlockHeight::new(1)).is_none());
        assert!(storage.open_boundary(BlockHeight::new(2)).is_some());
        assert!(storage.open_boundary(BlockHeight::new(4)).is_some());
    }

    #[test]
    fn unpinned_height_is_not_served() {
        let storage = SimShardStorage::default();
        commit_one(&storage, 1);
        assert!(storage.open_boundary(BlockHeight::new(1)).is_none());
    }

    /// Full serve → import round trip: leaves enumerated and resolved
    /// from a pinned boundary rebuild an identical store, with the raw
    /// substates readable.
    #[test]
    fn imported_boundary_state_reproduces_the_root() {
        let storage = SimShardStorage::default();
        for seed in 1..=6u8 {
            commit_one(&storage, seed);
        }
        let source_root = storage.state_root();
        storage.pin_boundary(BlockHeight::new(6)).unwrap();

        let boundary = storage.open_boundary(BlockHeight::new(6)).expect("pinned");
        let root_key = boundary.get_root_key(6).expect("root resolves");
        let chunk =
            Jmt::collect_range(&boundary, &root_key, &[0u8; 32], &[0xFF; 32], 1_000).unwrap();
        let leaves: Vec<ImportLeaf> = chunk
            .leaves
            .iter()
            .map(|(leaf_key, _)| {
                let (storage_key, value) = boundary.resolve_leaf(leaf_key).expect("resolves");
                ImportLeaf {
                    leaf_key: *leaf_key,
                    storage_key,
                    value,
                }
            })
            .collect();
        assert_eq!(leaves.len(), 6);
        let probe = leaves
            .iter()
            .find(|l| l.value == vec![3, 3, 3])
            .map(|l| (l.leaf_key, l.storage_key.clone()))
            .expect("seed-3 leaf present");

        let fresh = SimShardStorage::default();
        let imported_root = fresh
            .import_boundary_state(BlockHeight::new(6), leaves)
            .unwrap();
        assert_eq!(imported_root, source_root);
        assert_eq!(fresh.state_root(), source_root);

        // Imported raw substates read back at the imported state.
        let fresh_boundary = {
            fresh.pin_boundary(BlockHeight::new(6)).unwrap();
            fresh.open_boundary(BlockHeight::new(6)).expect("pinned")
        };
        assert_eq!(
            fresh_boundary.resolve_leaf(&probe.0),
            Some((probe.1, vec![3, 3, 3])),
        );

        // A second import is rejected — the store is no longer empty.
        assert!(
            fresh
                .import_boundary_state(BlockHeight::new(6), Vec::new())
                .is_err()
        );
    }
}
