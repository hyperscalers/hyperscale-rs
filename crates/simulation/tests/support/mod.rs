//! Test support for the simulation test binaries: the [`SimCluster`] adaptor
//! the portable scenarios run on, plus the shared scaffolding of the
//! relocation tests (`vnode_relocation`, `pool_reseat`), which need a
//! paced-epoch, refillable-pool network reachable to the committee shuffle.

// Each test binary compiles its own copy of this module and exercises a
// different subset, so a helper unused in any one binary isn't dead code.
#![allow(dead_code)]

pub mod sim_cluster;

use std::env;
use std::time::Duration;

use hyperscale_network_memory::NodeIndex;
use hyperscale_scenarios::ScenarioConfig;
use hyperscale_simulation::SimulationRunner;
use hyperscale_types::{ShardId, ValidatorId};
#[allow(unused_imports)] // same per-binary subset as the dead_code allow above
pub use sim_cluster::SimCluster;

/// One `#[test]` per seed for a `fn(u64)` scenario, in a module named after
/// it: `seeded!(scenario: seed_7 = 7, seed_11 = 11)` gives `scenario::seed_7`
/// and `scenario::seed_11`, which nextest runs in parallel and reports one
/// by one.
#[allow(unused_macros)] // same per-binary subset as the dead_code allow above
macro_rules! seeded {
    ($scenario:ident: $($cell:ident = $seed:literal),+ $(,)?) => {
        mod $scenario {
            $(
                #[test]
                fn $cell() {
                    super::$scenario($seed);
                }
            )+
        }
    };
}
#[allow(unused_imports)] // same per-binary subset as the dead_code allow above
pub(crate) use seeded;

/// Environment variable that replaces every test's seed, so any test can be
/// swept or replayed at any seed without editing it.
pub const SEED_VAR: &str = "HYPERSCALE_SIM_SEED";

/// The seed a test runs at: `default`, unless [`SEED_VAR`] names another.
///
/// # Panics
///
/// Panics if [`SEED_VAR`] is set to something other than a `u64`.
#[must_use]
pub fn sim_seed(default: u64) -> u64 {
    env::var(SEED_VAR).map_or(default, |seed| {
        seed.parse()
            .unwrap_or_else(|_| panic!("{SEED_VAR}={seed} is not a u64 seed"))
    })
}

/// Discard the run, rather than fail it, when a seed does not produce the
/// setup a test needs. Only for preconditions checked before the first fault
/// or workload op: past that point a broken expectation is a failure. A sweep
/// classifies a panic carrying [`DISCARD`] as a discard.
///
/// # Panics
///
/// Panics with [`DISCARD`] when `condition` does not hold.
pub fn assume(condition: bool, what: &str) {
    assert!(condition, "{DISCARD} {what}");
}

/// Discard the run unconditionally: [`assume`] for a value the seed did
/// not produce.
///
/// # Panics
///
/// Always, with [`DISCARD`].
pub fn discard(what: &str) -> ! {
    panic!("{DISCARD} {what}");
}

/// Prefix of the panic [`assume`] and [`discard`] raise.
pub const DISCARD: &str = "SIM-DISCARD:";

/// Committee validators per shard — the production `shard_size`. The split
/// seats each child at full strength (`2+2` parent half plus cohort), so the
/// committee top-up never fires here: this exercises the shuffle, not top-up.
pub const PER_SHARD: u32 = 4;

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
