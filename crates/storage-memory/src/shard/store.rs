//! `SubstateStore` implementation for `SimShardStorage`.

use std::sync::Arc;

use hyperscale_jmt::{NibblePath, Node as JmtNode, NodeKey as JmtNodeKey, TreeReader};
use hyperscale_storage::lock_recover::read_or_recover;
use hyperscale_storage::{
    PackageArtifactStore, SubstateStore, Substates, SweepIndex, SweepRows, VersionedStore,
};
use hyperscale_types::{
    BlockHeight, DeclaredRange, Hash, StateRoot, SubstateKey, SweepBucket, SweepFrontier,
};

use super::core::SimShardStorage;
use super::snapshot::SimSnapshot;
use super::state::SharedState;

impl SubstateStore for SimShardStorage {
    type Snapshot<'a> = SimSnapshot;

    fn snapshot(&self) -> Self::Snapshot<'_> {
        // Default height = current committed tip. Equivalent to reading
        // latest state but uniform snapshot type across all call sites.
        self.snapshot_at(self.jmt_height())
    }

    fn jmt_height(&self) -> BlockHeight {
        read_or_recover(&self.state).current_block_height
    }

    fn state_root(&self) -> StateRoot {
        read_or_recover(&self.state).current_root_hash
    }

    fn get_substate_at_height(
        &self,
        key: SubstateKey,
        block_height: BlockHeight,
    ) -> Option<Option<Vec<u8>>> {
        Some(self.snapshot_held_at(block_height)?.cell(key))
    }

    fn get_entries_at_height(
        &self,
        range: DeclaredRange,
        block_height: BlockHeight,
    ) -> Option<Vec<(u128, Vec<u8>)>> {
        Some(self.snapshot_held_at(block_height)?.entries_in_range(
            range.owner,
            range.collection,
            range.lo,
            range.hi,
            range.cap as usize,
        ))
    }
}

/// A point-in-time copy of `state` reading at `version`. Memory
/// snapshots are copies — they do not observe later mutations of the
/// backing store.
fn snapshot_of(state: &SharedState, version: u64) -> SimSnapshot {
    SimSnapshot {
        current_state: state.current_state.clone(),
        state_history: state.state_history.clone(),
        current_entries: state.current_entries.clone(),
        entries_history: state.entries_history.clone(),
        version,
        current_version: state.current_block_height.inner(),
    }
}

impl VersionedStore for SimShardStorage {
    fn retention_floor(&self) -> u64 {
        Self::retention_floor(self)
    }

    fn snapshot_held_at(&self, height: BlockHeight) -> Option<Self::Snapshot<'_>> {
        let state = read_or_recover(&self.state);
        let held = height <= state.current_block_height && height.inner() >= state.retention_floor;
        let snapshot = held.then(|| snapshot_of(&state, height.inner()));
        drop(state);
        snapshot
    }

    fn snapshot_at(&self, height: BlockHeight) -> Self::Snapshot<'_> {
        let state = read_or_recover(&self.state);
        let (floor, tip) = (state.retention_floor, state.current_block_height);
        let snapshot = snapshot_of(&state, height.inner());
        drop(state);
        assert!(
            height.inner() >= floor,
            "snapshot_at({height}) below retention floor {floor} \
             (current_version={tip}) — \
             Shard consensus + DA invariant broken; caller must anchor within retention",
        );
        snapshot
    }

    fn substate_bytes_at(&self, height: BlockHeight) -> Option<u64> {
        read_or_recover(&self.state)
            .substate_bytes
            .get(&height.inner())
            .copied()
    }
}

impl TreeReader for SimShardStorage {
    fn get_node(&self, key: &JmtNodeKey) -> Option<Arc<JmtNode>> {
        read_or_recover(&self.state).tree_store.get_node(key)
    }

    fn get_root_key(&self, version: u64) -> Option<JmtNodeKey> {
        read_or_recover(&self.state)
            .tree_store
            .get_root_key(version)
    }

    fn root_path(&self) -> NibblePath {
        read_or_recover(&self.state).tree_store.root_path()
    }
}

impl SweepIndex for SimShardStorage {
    fn sweep_candidates(
        &self,
        after: SweepFrontier,
        below: SweepBucket,
        limit: usize,
    ) -> Vec<(SubstateKey, u64)> {
        let state = read_or_recover(&self.state);
        SweepRows::walk(
            after,
            below,
            limit,
            |bucket| state.sweep_index.from_bucket(bucket),
            |lo, hi, each| {
                for (&key, value) in state.current_state.range(lo..=hi) {
                    if !each(key, &value[..]) {
                        break;
                    }
                }
            },
        )
    }
}

impl PackageArtifactStore for SimShardStorage {
    fn package_artifacts(&self) -> Vec<Vec<u8>> {
        read_or_recover(&self.state)
            .package_artifacts
            .values()
            .cloned()
            .collect()
    }

    fn package_artifact(&self, package: Hash) -> Option<Vec<u8>> {
        read_or_recover(&self.state)
            .package_artifacts
            .get(&package)
            .cloned()
    }
}
