//! Test support for the simulation test binaries: the [`SimCluster`] adaptor
//! the portable scenarios run on, plus the shared scaffolding of the
//! relocation tests (`vnode_relocation`, `pool_reseat`), which need a
//! paced-epoch, refillable-pool network reachable to the committee shuffle.

// Each test binary compiles its own copy of this module and exercises a
// different subset, so a helper unused in any one binary isn't dead code.
#![allow(dead_code)]

pub mod sim_cluster;

use std::time::Duration;

use hyperscale_network_memory::NodeIndex;
use hyperscale_scenarios::ScenarioConfig;
use hyperscale_simulation::SimulationRunner;
use hyperscale_types::{ShardId, ValidatorId};
pub use sim_cluster::SimCluster;

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
        shard_size: PER_SHARD,
        vnodes_per_host: 1,
        pool_surplus: PER_SHARD + POOL_EXTRAS,
        num_shards: 1,
        split_bytes: 0,
        latency: Duration::from_millis(150),
    }
}

/// A host running a current consensus member of `shard` (skipping `except`,
/// if given), and that member's validator id — read from the committee so a
/// post-grow placement is found without assuming the host layout. A shuffle
/// rotates members out, but an ex-member's host keeps running the shard as a
/// stalled non-member, so membership must be read from the committee, not
/// from "hosts a `shard` vnode".
pub fn committee_member_host(
    runner: &SimulationRunner,
    shard: ShardId,
    except: Option<NodeIndex>,
) -> (NodeIndex, ValidatorId) {
    let (_, state) = runner
        .beacon_storage(0)
        .expect("host 0 exists")
        .latest_committed()
        .expect("beacon committed");
    let members = state
        .shard_consensus_members
        .get(&shard)
        .expect("shard has a consensus committee");
    members
        .iter()
        .map(|m| (runner.network().validator_to_node(*m), *m))
        .find(|(node, _)| except != Some(*node) && runner.vnode_state_in(*node, shard).is_some())
        .expect("a current member of the shard is hosted")
}
