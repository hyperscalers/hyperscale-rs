//! The crossing index a shard's execution asks its questions from, read
//! through the chain's committed tip.

use std::sync::Arc;

use hyperscale_execution::CrossingIndex;
use hyperscale_storage::{PendingChain, ShardStorage, SubstateStore, Substates};
use hyperscale_types::{ShardId, SubstateKey, shard_prefix_path};

/// The persisted index's rows, each point-read through the committed-tip
/// overlay and dropped where it reads absent there.
///
/// A cell the overlay holds and the persisted index does not yet is
/// missed until it persists, which costs latency only: nothing an asker
/// returns reaches a block without the voter re-proving it.
pub struct ChainCrossings<S: ShardStorage>(pub Arc<PendingChain<S>>);

impl<S: ShardStorage> CrossingIndex for ChainCrossings<S> {
    fn crossing_rows(&self, shard: ShardId) -> Vec<(SubstateKey, Vec<u8>)> {
        let view = self.0.view_at_committed_tip();
        let tip = view.snapshot();
        view.base()
            .crossing_rows(&shard_prefix_path(shard))
            .into_iter()
            .filter_map(|key| tip.cell(key).map(|value| (key, value)))
            .collect()
    }

    fn present(&self, key: SubstateKey) -> bool {
        self.0
            .view_at_committed_tip()
            .snapshot()
            .cell(key)
            .is_some()
    }
}
