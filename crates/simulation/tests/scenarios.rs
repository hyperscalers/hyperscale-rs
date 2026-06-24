//! Portable scenarios run on the simulation harness.
//!
//! Each `#[test]` builds a [`SimCluster`] and drives a `hyperscale_scenarios`
//! body. The identical body runs on production under `#[cfg(feature = "ci")]`.

mod support;

use std::time::Duration;

use hyperscale_scenarios::tx::split_straddler_setup;
use hyperscale_scenarios::{
    ScenarioConfig, cross_shard_tx, livelock_resolves_promptly, liveness_baseline, merge_lifecycle,
    multi_vnode_progress, single_shard_tx, split_lifecycle, split_straddler_atomic,
};
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

#[test]
fn single_shard_tx_sim() {
    let mut cluster = SimCluster::new(&liveness_config(), 42);
    single_shard_tx(&mut cluster);
}

/// Single-shard config with the split trigger armed (`split_bytes = 0`) and one
/// cohort of pool surplus — drives an organic root split.
const fn split_config() -> ScenarioConfig {
    ScenarioConfig {
        validators_per_shard: 4,
        vnodes_per_host: 1,
        pool_surplus: 4,
        num_shards: 1,
        split_bytes: 0,
        latency: Duration::from_millis(150),
        dedicated_hosts: false,
    }
}

#[test]
fn split_lifecycle_sim() {
    let mut cluster = SimCluster::new(&split_config(), 11);
    split_lifecycle(&mut cluster);
}

#[test]
fn cross_shard_tx_sim() {
    let mut cluster = SimCluster::new(&split_config(), 11);
    cross_shard_tx(&mut cluster);
}

#[test]
fn livelock_resolves_promptly_sim() {
    let mut cluster = SimCluster::new(&split_config(), 11);
    livelock_resolves_promptly(&mut cluster);
}

#[test]
fn merge_lifecycle_sim() {
    let mut cluster = SimCluster::new(&split_config(), 11);
    merge_lifecycle(&mut cluster);
}

/// Single-shard genesis with the grow trigger armed (`split_bytes` above each
/// child but below ROOT) and two cohorts of pool surplus — one grows ROOT to the
/// two siblings, the other splits the heavier one after the vote.
const fn straddler_config() -> ScenarioConfig {
    ScenarioConfig {
        validators_per_shard: 4,
        vnodes_per_host: 1,
        pool_surplus: 8,
        num_shards: 1,
        split_bytes: 800_000,
        latency: Duration::from_millis(150),
        dedicated_hosts: false,
    }
}

#[test]
fn split_straddler_atomic_sim() {
    let setup = split_straddler_setup();
    let mut cluster = SimCluster::with_balances(&straddler_config(), 11, &setup.balances);
    split_straddler_atomic(&mut cluster);
}

/// Multi-vnode config: two vnodes per host (same-shard multi-vnode hosting), the
/// split disarmed, no pool surplus — a single shard whose committee is hosted at
/// two vnodes per host.
const fn multi_vnode_config() -> ScenarioConfig {
    ScenarioConfig {
        validators_per_shard: 4,
        vnodes_per_host: 2,
        pool_surplus: 0,
        num_shards: 1,
        split_bytes: u64::MAX,
        latency: Duration::from_millis(150),
        dedicated_hosts: false,
    }
}

#[test]
fn multi_vnode_progress_sim() {
    let mut cluster = SimCluster::new(&multi_vnode_config(), 11);
    multi_vnode_progress(&mut cluster);
}
