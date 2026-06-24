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

use hyperscale_scenarios::{ScenarioConfig, liveness_baseline, single_shard_tx};
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
    let mut cluster = ProdCluster::start(&liveness_config(), EPOCH_MS);
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
    let mut cluster = ProdCluster::start(&liveness_config(), EPOCH_MS);
    single_shard_tx(&mut cluster);
    cluster.shutdown();
}
