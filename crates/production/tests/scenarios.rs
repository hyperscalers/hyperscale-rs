//! Portable scenarios run on the production QUIC + `RocksDB` harness.
//!
//! Each `#[test]` builds a [`ProdCluster`] and drives the identical
//! `hyperscale_scenarios` body the simulation harness runs. These exercise a
//! real multi-host cluster at wall-clock, so they are a nightly/manual job: run
//! under `--features ci` (5-minute production epochs) or explicitly with
//! `-- --ignored` (a 30-second epoch, the simulation default). Default
//! `cargo test` skips them.

mod cluster;
mod prod_cluster;

use std::time::Duration;

use hyperscale_scenarios::tx::split_straddler_setup;
use hyperscale_scenarios::{
    ScenarioConfig, cross_shard_tx, livelock_resolves_promptly, liveness_baseline, merge_lifecycle,
    multi_vnode_progress, single_shard_tx, split_lifecycle, split_straddler_atomic,
};
use prod_cluster::ProdCluster;
use serial_test::serial;
use tracing_subscriber::fmt;

/// Production epoch length: the real 5-minute deployment epoch under `ci`, a
/// 30-second epoch otherwise — mirroring `simulation`'s `EPOCH_MS` so a budget
/// carries the same epoch semantics on both harnesses.
#[cfg(feature = "ci")]
const EPOCH_MS: u64 = 300_000;
#[cfg(not(feature = "ci"))]
const EPOCH_MS: u64 = 30_000;

/// Baseline single-shard config: resharding disarmed, four-validator committee,
/// two vnodes per host, zero injected latency.
const fn liveness_config() -> ScenarioConfig {
    ScenarioConfig {
        validators_per_shard: 4,
        vnodes_per_host: 2,
        pool_surplus: 0,
        num_shards: 1,
        split_bytes: u64::MAX,
        latency: Duration::ZERO,
        dedicated_hosts: false,
    }
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn liveness_baseline_prod() {
    let _ = fmt().with_test_writer().try_init();
    let mut cluster = ProdCluster::start(&liveness_config(), 7, EPOCH_MS);
    liveness_baseline(&mut cluster);
    cluster.shutdown();
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn single_shard_tx_prod() {
    let _ = fmt().with_test_writer().try_init();
    let mut cluster = ProdCluster::start(&liveness_config(), 7, EPOCH_MS);
    single_shard_tx(&mut cluster);
    cluster.shutdown();
}

/// Single-shard config with the split trigger armed (`split_bytes = 0`), one
/// cohort of pool surplus, one validator per host (each reshape seat needs its
/// own store), and a paced inter-host latency so the loadless committee tracks
/// wall-clock through the multi-epoch grow.
const fn split_config() -> ScenarioConfig {
    ScenarioConfig {
        validators_per_shard: 4,
        vnodes_per_host: 1,
        pool_surplus: 4,
        num_shards: 1,
        split_bytes: 0,
        latency: Duration::from_millis(60),
        dedicated_hosts: true,
    }
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn split_lifecycle_prod() {
    let _ = fmt().with_test_writer().try_init();
    let mut cluster = ProdCluster::start(&split_config(), 11, EPOCH_MS);
    split_lifecycle(&mut cluster);
    cluster.shutdown();
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn cross_shard_tx_prod() {
    let _ = fmt().with_test_writer().try_init();
    let mut cluster = ProdCluster::start(&split_config(), 11, EPOCH_MS);
    cross_shard_tx(&mut cluster);
    cluster.shutdown();
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn livelock_resolves_promptly_prod() {
    let _ = fmt().with_test_writer().try_init();
    let mut cluster = ProdCluster::start(&split_config(), 11, EPOCH_MS);
    livelock_resolves_promptly(&mut cluster);
    cluster.shutdown();
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn merge_lifecycle_prod() {
    let _ = fmt().with_test_writer().try_init();
    let mut cluster = ProdCluster::start(&split_config(), 11, EPOCH_MS);
    merge_lifecycle(&mut cluster);
    cluster.shutdown();
}

/// Two cohorts of pool surplus and a grow trigger above each child but below
/// ROOT: one cohort grows ROOT to the two siblings, the other splits the heavier
/// one after the vote. One validator per host (each reshape seat its own store).
const fn straddler_config() -> ScenarioConfig {
    ScenarioConfig {
        validators_per_shard: 4,
        vnodes_per_host: 1,
        pool_surplus: 8,
        num_shards: 1,
        split_bytes: 800_000,
        latency: Duration::from_millis(60),
        dedicated_hosts: true,
    }
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn split_straddler_atomic_prod() {
    let _ = fmt().with_test_writer().try_init();
    let setup = split_straddler_setup();
    let mut cluster =
        ProdCluster::start_with_balances(&straddler_config(), 11, EPOCH_MS, setup.balances);
    split_straddler_atomic(&mut cluster);
    cluster.shutdown();
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn multi_vnode_progress_prod() {
    let _ = fmt().with_test_writer().try_init();
    // `liveness_config` already hosts the committee at two vnodes per host — the
    // same-shard multi-vnode hosting under test.
    let mut cluster = ProdCluster::start(&liveness_config(), 7, EPOCH_MS);
    multi_vnode_progress(&mut cluster);
    cluster.shutdown();
}
