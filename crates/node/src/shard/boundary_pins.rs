//! The node's boundary retention rule over one shard's store.

use std::sync::Arc;

use hyperscale_storage::{BoundaryRetention, ShardStorage};
use hyperscale_types::{BeaconChainConfig, BlockHeight, ShardId};
use tracing::warn;

use crate::shard::SharedTopologySnapshot;

/// Pins a shard's boundaries and trims its store to the retention rule.
///
/// Both halves of the rule are derived from committed chain state, so
/// every store this node opens keeps the same pins whichever runtime
/// opened it: the count from the chain config's
/// `boundary_retention_epochs`, and the held anchor from the boundary the
/// committed topology attests for the shard — the anchor a joiner is told
/// to snap-sync from.
pub struct BoundaryPins<S> {
    storage: Arc<S>,
    shard: ShardId,
    newest: usize,
    topology: SharedTopologySnapshot,
}

impl<S: ShardStorage> BoundaryPins<S> {
    pub fn new(
        storage: Arc<S>,
        shard: ShardId,
        chain_config: &BeaconChainConfig,
        topology: SharedTopologySnapshot,
    ) -> Self {
        Self {
            storage,
            shard,
            newest: usize::try_from(chain_config.boundary_retention_epochs()).unwrap_or(usize::MAX),
            topology,
        }
    }

    /// Pin the committed state at `height`, then evict whatever the rule
    /// no longer keeps. A failed pin degrades serving, never correctness,
    /// so it is logged and the trim still runs.
    pub fn pin(&self, height: BlockHeight) {
        if let Err(error) = self.storage.pin_boundary(height) {
            warn!(
                shard = ?self.shard,
                height = height.inner(),
                error,
                "boundary pin failed; this node won't serve this boundary"
            );
        }
        self.storage.trim_boundaries(self.retention());
    }

    fn retention(&self) -> BoundaryRetention {
        BoundaryRetention {
            newest: self.newest,
            attested: self
                .topology
                .load()
                .boundary(self.shard)
                .map(|anchor| anchor.height),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use arc_swap::ArcSwap;
    use hyperscale_storage::BoundaryStore;
    use hyperscale_storage::test_helpers::commit_one;
    use hyperscale_storage_memory::SimShardStorage;
    use hyperscale_types::test_utils::TestCommittee;
    use hyperscale_types::{
        BeaconWitnessLeafCount, BlockHash, Hash, ShardAnchor, StateRoot, TopologySnapshot,
        WeightedTimestamp,
    };

    use super::*;

    fn anchored_at(height: u64) -> Arc<TopologySnapshot> {
        let anchor = ShardAnchor {
            state_root: StateRoot::ZERO,
            block_hash: BlockHash::from_raw(Hash::from_bytes(b"anchor")),
            height: BlockHeight::new(height),
            weighted_timestamp: WeightedTimestamp::ZERO,
            witness_base: BeaconWitnessLeafCount::ZERO,
            terminal_settled_txs: None,
            handoff_complete: None,
            terminal_epoch: None,
        };
        Arc::new(
            TestCommittee::new(4, 1)
                .topology_snapshot(1)
                .with_boundaries(BTreeMap::from([(ShardId::ROOT, anchor)])),
        )
    }

    /// The anchor the committed topology attests outlives the count for
    /// as long as it stays attested, and the count governs it once the
    /// attestation moves on.
    #[test]
    fn the_attested_anchor_outlives_the_count() {
        let storage = Arc::new(SimShardStorage::default());
        let topology: SharedTopologySnapshot = Arc::new(ArcSwap::new(anchored_at(1)));
        let chain_config = BeaconChainConfig::default();
        let newest = chain_config.boundary_retention_epochs();
        let pins = BoundaryPins::new(
            Arc::clone(&storage),
            ShardId::ROOT,
            &chain_config,
            Arc::clone(&topology),
        );

        let last = newest + 3;
        for height in 1..=last {
            commit_one(&*storage, u8::try_from(height).unwrap());
            pins.pin(BlockHeight::new(height));
        }
        assert!(storage.open_boundary(BlockHeight::new(1)).is_some());
        assert!(storage.open_boundary(BlockHeight::new(2)).is_none());
        assert!(storage.open_boundary(BlockHeight::new(last)).is_some());

        topology.store(anchored_at(last));
        commit_one(&*storage, u8::try_from(last + 1).unwrap());
        pins.pin(BlockHeight::new(last + 1));
        assert!(storage.open_boundary(BlockHeight::new(1)).is_none());
        assert!(storage.open_boundary(BlockHeight::new(last)).is_some());
    }
}
