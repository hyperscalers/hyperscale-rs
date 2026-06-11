//! Test fixtures shared across shard integration tests.

use hyperscale_storage::SubstateStore;
use hyperscale_storage_memory::SimShardStorage;
use hyperscale_types::{Block, ChainOrigin, ShardId, ValidatorId};

/// Deterministic shard-0 genesis block over `storage`'s current
/// JMT root. A fresh `SimShardStorage::new()` returns the empty
/// JMT root, so genesis is byte-identical across replicas.
#[must_use]
pub fn build_genesis_block(storage: &SimShardStorage, proposer: ValidatorId) -> Block {
    let state_root = storage.state_root();
    Block::genesis(ShardId::ROOT, proposer, state_root, ChainOrigin::ROOT)
}
