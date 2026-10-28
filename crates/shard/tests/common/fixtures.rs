//! Test fixtures shared across shard integration tests.

use hyperscale_storage::SubstateStore;
use hyperscale_storage_memory::SimShardStorage;
use hyperscale_types::{Block, ChainOrigin, ShardId, ValidatorId, WeightedTimestamp};

/// Deterministic genesis block of `shard` over `storage`'s current
/// JMT root. Replicas whose fresh stores hold one genesis state build
/// one byte-identical block.
#[must_use]
pub fn build_genesis_block(
    storage: &SimShardStorage,
    proposer: ValidatorId,
    shard: ShardId,
) -> Block {
    let state_root = storage.state_root();
    Block::genesis(
        shard,
        proposer,
        state_root,
        ChainOrigin::root(WeightedTimestamp::ZERO),
    )
}
