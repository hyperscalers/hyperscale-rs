//! Shared scaffolding for the relocation simulation tests.
//!
//! `rotation_config` drives `vnode_relocation` and `pool_reseat`, which need a
//! paced-epoch, refillable-pool network reachable to the committee shuffle. Both
//! build a [`SimCluster`](super::support::sim_cluster::SimCluster) from it and
//! drive the underlying runner for the white-box vnode lifecycle they exercise.

use std::time::Duration;

use hyperscale_scenarios::ScenarioConfig;

/// Committee validators per shard — the production `shard_size`. The split
/// seats each child at full strength (`2+2` parent half plus cohort), so the
/// committee top-up never fires here: this exercises the shuffle, not top-up.
const PER_SHARD: u32 = 4;

/// `Pooled` validators left over once `grow_to(2)` has seated its cohort.
/// Exactly one: the shuffle processes the two shards in order, so shard 0
/// refills from this lone surplus, leaving only shard 0's just-rotated victim
/// in the pool for shard 1 to re-draw — a *direct* cross-shard move every seed.
/// An empty pool would skip the rotation entirely.
const POOL_EXTRAS: u32 = 1;

/// Single-shard, paced-epoch config both relocation tests grow to two shards
/// (`grow_to(2)`) before exercising the committee shuffle. The split trigger is
/// armed from genesis; the pool carries one cohort (`PER_SHARD`) for the grow
/// plus `POOL_EXTRAS` surplus for the shuffle to refill from. The relocation
/// tests build this through [`SimCluster::with_dedicated_pool_hosts`], seating
/// each pool extra on its own beacon-follower host so every committee member
/// ends on a single shard and a rotated vnode moves onto an otherwise-idle host.
#[must_use]
pub const fn rotation_config() -> ScenarioConfig {
    ScenarioConfig {
        validators_per_shard: PER_SHARD,
        vnodes_per_host: 1,
        pool_surplus: PER_SHARD + POOL_EXTRAS,
        num_shards: 1,
        split_bytes: 0,
        latency: Duration::from_millis(150),
    }
}
