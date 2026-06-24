//! The liveness baseline scenario.

use hyperscale_types::ShardId;

use crate::query::beacon_epoch;
use crate::wait::{await_beacon_epoch, await_height};
use crate::{Cluster, epochs};

/// Single shard, resharding disarmed: assert the beacon folds epochs and the
/// root shard commits blocks. The smoke test that an assembled node makes
/// progress, run identically on both harnesses.
///
/// # Panics
///
/// Panics if the beacon does not reach epoch 3 or the root shard does not reach
/// height 3 within budget.
pub fn liveness_baseline(c: &mut impl Cluster) {
    let budget = epochs(8);
    assert!(
        await_beacon_epoch(c, 3, budget),
        "beacon did not reach epoch 3 within budget; latest = {:?}",
        beacon_epoch(c),
    );
    assert!(
        await_height(c, ShardId::ROOT, 3, budget),
        "root shard did not reach height 3 within budget; latest = {:?}",
        c.committed_height(ShardId::ROOT),
    );
}
