//! Portable scenarios run on the simulation harness.
//!
//! Each `#[test]` builds a [`SimCluster`] and drives a `hyperscale_scenarios`
//! body. The identical body runs on production under `#[cfg(feature = "ci")]`.

mod support;

use std::time::Duration;

use hyperscale_scenarios::{ScenarioConfig, liveness_baseline};
use support::sim_cluster::SimCluster;

/// Baseline single-shard config: resharding disarmed, four-validator committee.
const fn liveness_config() -> ScenarioConfig {
    ScenarioConfig {
        validators_per_shard: 4,
        vnodes_per_host: 1,
        pool_surplus: 0,
        num_shards: 1,
        split_bytes: u64::MAX,
        latency: Duration::from_millis(150),
        dedicated_hosts: false,
    }
}

#[test]
fn liveness_baseline_sim() {
    let mut cluster = SimCluster::new(&liveness_config(), 11);
    liveness_baseline(&mut cluster);
}
