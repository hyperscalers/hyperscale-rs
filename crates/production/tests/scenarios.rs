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

use hyperscale_scenarios::tx::{
    merge_straddler_setup, split_straddler_setup, witness_genesis_balances,
};
use hyperscale_scenarios::{
    ScenarioConfig, cross_shard_tx, grow_reaches_four_shard_topology,
    grow_reaches_two_shard_topology, livelock_resolves_promptly, liveness_baseline,
    merge_lifecycle, merge_seats_full_keeper_committee, merge_straddler_atomic,
    multi_vnode_progress, pool_capacity_caps_registrations,
    re_registration_of_a_live_validator_is_a_no_op, register_validator_pools_a_node,
    register_without_capacity_is_rejected, registered_validator_activates_onto_a_shard,
    single_shard_tx, split_lifecycle, split_straddler_atomic,
    stake_deposit_folds_into_beacon_state, stake_withdraw_drops_effective_stake,
    surviving_sibling_split_seats_full_committees,
    withdrawal_ejects_a_validator_that_a_deposit_reactivates,
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

/// Four-shard topology whose `split_bytes` derives a `merge_bytes` bracketing
/// the genesis byte skew: the survivor pair (`leaf(2,0)`/`leaf(2,1)`, the latter
/// bulk-funded) over it, the light merging pair (`leaf(2,2)`/`leaf(2,3)`) under
/// it, so only the merging pair auto-merges into `leaf(1,1)`. One validator per
/// host (each reshape seat its own store), three cohorts of pool surplus to
/// staff the two split generations the grow walks through, a paced inter-host
/// latency so the loadless committees track wall-clock through the merge.
const fn merge_straddler_config() -> ScenarioConfig {
    ScenarioConfig {
        validators_per_shard: 4,
        vnodes_per_host: 1,
        pool_surplus: 12,
        num_shards: 4,
        split_bytes: 2_880_000,
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
fn merge_straddler_atomic_prod() {
    let _ = fmt().with_test_writer().try_init();
    let setup = merge_straddler_setup();
    let mut cluster =
        ProdCluster::with_grown_balances(&merge_straddler_config(), 11, EPOCH_MS, setup.balances);
    merge_straddler_atomic(&mut cluster);
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

/// Single-shard witness config: the committee equals the whole validator set
/// (`pool_surplus = 0`, so the shuffle never fires) with resharding disarmed —
/// the stable ground the beacon-witness scenarios fold system actions against.
/// `validators` sizes the committee; two vnodes per host keep quorum while a
/// member deactivates or ejects.
const fn witness_config(validators: u32) -> ScenarioConfig {
    ScenarioConfig {
        validators_per_shard: validators,
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
fn stake_deposit_folds_into_beacon_state_prod() {
    let _ = fmt().with_test_writer().try_init();
    let mut cluster = ProdCluster::start_with_balances(
        &witness_config(4),
        0x57AC,
        EPOCH_MS,
        witness_genesis_balances(),
    );
    stake_deposit_folds_into_beacon_state(&mut cluster);
    cluster.shutdown();
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn register_validator_pools_a_node_prod() {
    let _ = fmt().with_test_writer().try_init();
    let mut cluster = ProdCluster::start_with_balances(
        &witness_config(4),
        0x5EED,
        EPOCH_MS,
        witness_genesis_balances(),
    );
    register_validator_pools_a_node(&mut cluster);
    cluster.shutdown();
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn register_without_capacity_is_rejected_prod() {
    let _ = fmt().with_test_writer().try_init();
    let mut cluster = ProdCluster::start_with_balances(
        &witness_config(4),
        0x0CA9,
        EPOCH_MS,
        witness_genesis_balances(),
    );
    register_without_capacity_is_rejected(&mut cluster);
    cluster.shutdown();
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn stake_withdraw_drops_effective_stake_prod() {
    let _ = fmt().with_test_writer().try_init();
    let mut cluster = ProdCluster::start_with_balances(
        &witness_config(4),
        0xD7A1,
        EPOCH_MS,
        witness_genesis_balances(),
    );
    stake_withdraw_drops_effective_stake(&mut cluster);
    cluster.shutdown();
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn registered_validator_activates_onto_a_shard_prod() {
    let _ = fmt().with_test_writer().try_init();
    let mut cluster = ProdCluster::start_with_balances(
        &witness_config(4),
        0xAC11,
        EPOCH_MS,
        witness_genesis_balances(),
    );
    registered_validator_activates_onto_a_shard(&mut cluster);
    cluster.shutdown();
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn withdrawal_ejects_a_validator_that_a_deposit_reactivates_prod() {
    let _ = fmt().with_test_writer().try_init();
    // Seven validators give the committee slack to keep quorum while a couple
    // eject.
    let mut cluster = ProdCluster::start_with_balances(
        &witness_config(7),
        0xE1EC,
        EPOCH_MS,
        witness_genesis_balances(),
    );
    withdrawal_ejects_a_validator_that_a_deposit_reactivates(&mut cluster);
    cluster.shutdown();
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn re_registration_of_a_live_validator_is_a_no_op_prod() {
    let _ = fmt().with_test_writer().try_init();
    let mut cluster = ProdCluster::start_with_balances(
        &witness_config(4),
        0xDEAD,
        EPOCH_MS,
        witness_genesis_balances(),
    );
    re_registration_of_a_live_validator_is_a_no_op(&mut cluster);
    cluster.shutdown();
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn pool_capacity_caps_registrations_prod() {
    let _ = fmt().with_test_writer().try_init();
    let mut cluster = ProdCluster::start_with_balances(
        &witness_config(4),
        0xCA9A,
        EPOCH_MS,
        witness_genesis_balances(),
    );
    pool_capacity_caps_registrations(&mut cluster);
    cluster.shutdown();
}

/// Single-shard genesis with the split armed and exactly `(target - 1)` cohorts
/// of pool surplus to staff the grow's split generations. One validator per host
/// (each reshape seat needs its own store) and a paced inter-host latency so the
/// loadless committees track wall-clock through the multi-epoch grow.
const fn grow_config(target_shards: u32) -> ScenarioConfig {
    ScenarioConfig {
        validators_per_shard: 4,
        vnodes_per_host: 2,
        pool_surplus: (target_shards - 1) * 4,
        num_shards: 1,
        split_bytes: 0,
        latency: Duration::from_millis(60),
        dedicated_hosts: false,
    }
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn grow_reaches_two_shard_topology_prod() {
    let _ = fmt().with_test_writer().try_init();
    let mut cluster = ProdCluster::start(&grow_config(2), 11, EPOCH_MS);
    grow_reaches_two_shard_topology(&mut cluster);
    cluster.shutdown();
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn grow_reaches_four_shard_topology_prod() {
    let _ = fmt().with_test_writer().try_init();
    let mut cluster = ProdCluster::start(&grow_config(4), 11, EPOCH_MS);
    grow_reaches_four_shard_topology(&mut cluster);
    cluster.shutdown();
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn merge_seats_full_keeper_committee_prod() {
    let _ = fmt().with_test_writer().try_init();
    let mut cluster = ProdCluster::start(&split_config(), 11, EPOCH_MS);
    merge_seats_full_keeper_committee(&mut cluster);
    cluster.shutdown();
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn surviving_sibling_split_seats_full_committees_prod() {
    let _ = fmt().with_test_writer().try_init();
    let setup = split_straddler_setup();
    let mut cluster =
        ProdCluster::start_with_balances(&straddler_config(), 11, EPOCH_MS, setup.balances);
    surviving_sibling_split_seats_full_committees(&mut cluster);
    cluster.shutdown();
}
