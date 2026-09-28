//! Seeded runs under a nemesis: faults drawn from the seed within every
//! committee's quorum, then healed, then judged for liveness and
//! conservation. Each cell is one seed; a sweep runs any other.

mod support;

use std::time::Duration;

use hyperscale_scenarios::tx::genesis_accounts;
use hyperscale_scenarios::{SWARM_ACCOUNTS, ScenarioConfig, transfers_survive_a_nemesis};
use support::{SimCluster, seeded};

/// Two shards grown from genesis, so transfers cross between them.
const fn swarm_config() -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 4,
        vnodes_per_host: 1,
        pool_surplus: 4,
        num_shards: 2,
        split_bytes: u64::MAX,
        latency: Duration::from_millis(150),
    }
}

/// Rounds of transfers the nemesis faults, one epoch each.
const ROUNDS: u8 = 12;

fn transfers_under_a_nemesis(seed: u64) {
    let mut cluster = SimCluster::with_grown_accounts(
        &swarm_config(),
        seed,
        &genesis_accounts(SWARM_ACCOUNTS, SWARM_ACCOUNTS),
    );
    let seed = cluster.runner().seed();
    cluster.run_faultable(|c| transfers_survive_a_nemesis(c, seed, ROUNDS));
}

seeded!(
    transfers_under_a_nemesis:
    seed_1 = 1,
    seed_2 = 2,
    seed_3 = 3,
);
