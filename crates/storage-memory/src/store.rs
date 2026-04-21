//! `SubstateStore` implementation for `SimStorage`.

use crate::core::SimStorage;
use crate::snapshot::SimSnapshot;

use hyperscale_storage::{DbSortKey, SubstateStore, VersionedStore};
use hyperscale_types::{BlockHeight, Hash, NodeId};

impl SubstateStore for SimStorage {
    type Snapshot<'a> = SimSnapshot;

    fn snapshot(&self) -> Self::Snapshot<'_> {
        // Default height = current committed tip. Equivalent to reading
        // latest state but uniform snapshot type across all call sites.
        self.snapshot_at(self.jmt_height())
    }

    fn jmt_height(&self) -> BlockHeight {
        self.state.read().unwrap().current_block_height
    }

    fn state_root_hash(&self) -> Hash {
        self.state.read().unwrap().current_root_hash
    }

    fn list_substates_for_node_at_height(
        &self,
        node_id: &NodeId,
        block_height: BlockHeight,
    ) -> Option<Vec<(u8, DbSortKey, Vec<u8>)>> {
        let current_version = self.state.read().unwrap().current_block_height.0;
        if block_height.0 > current_version {
            return None;
        }
        let floor = current_version.saturating_sub(self.jmt_history_length);
        if block_height.0 < floor {
            // Below retention — historical state no longer recoverable.
            // External API: return None (network-supplied heights may
            // legitimately fall out of range; `snapshot_at` would panic,
            // so don't delegate for this case).
            return None;
        }
        Some(
            self.snapshot_at(block_height)
                .list_raw_values_for_node(node_id),
        )
    }

    fn generate_merkle_proofs(
        &self,
        storage_keys: &[Vec<u8>],
        block_height: BlockHeight,
    ) -> Option<hyperscale_types::MerkleInclusionProof> {
        let s = self.state.read().unwrap();
        hyperscale_storage::tree::proofs::generate_proof(&s.tree_store, storage_keys, block_height)
    }
}

impl VersionedStore for SimStorage {
    fn snapshot_at(&self, height: BlockHeight) -> Self::Snapshot<'_> {
        // Retention invariant: see `RocksDbStorage::snapshot_at` for the
        // full reasoning. Below the floor we can't serve historical
        // reads; hitting this is a DA-assumption bug in the caller.
        let guard = self.state.read().unwrap();
        let current_version = guard.current_block_height.0;
        let floor = current_version.saturating_sub(self.jmt_history_length);
        assert!(
            height.0 >= floor,
            "snapshot_at({height}) below retention floor {floor} \
             (current_version={current_version}, jmt_history_length={}) — \
             BFT/DA invariant broken; caller must anchor within retention",
            self.jmt_history_length,
        );
        // Clone state + state-history for snapshot isolation. Memory
        // snapshots are point-in-time copies — they don't observe later
        // mutations of the backing store.
        SimSnapshot {
            current_state: guard.current_state.clone(),
            state_history: guard.state_history.clone(),
            version: height.0,
            current_version,
        }
    }
}

impl hyperscale_jmt::TreeReader for SimStorage {
    fn get_node(
        &self,
        key: &hyperscale_jmt::NodeKey,
    ) -> Option<std::sync::Arc<hyperscale_jmt::Node>> {
        self.state.read().unwrap().tree_store.get_node(key)
    }

    fn get_root_key(&self, version: u64) -> Option<hyperscale_jmt::NodeKey> {
        self.state.read().unwrap().tree_store.get_root_key(version)
    }
}
