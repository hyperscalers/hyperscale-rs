//! Portable scenarios run on the production QUIC + `RocksDB` harness.
//!
//! Each `#[test]` builds a [`ProdCluster`] and drives the identical
//! `hyperscale_scenarios` body the simulation harness runs. These exercise a
//! real multi-host cluster at wall-clock, so they are a nightly/manual job: run
//! under `--features ci` (5-minute production epochs) or explicitly with
//! `-- --ignored` (a 30-second epoch, the simulation default). Default
//! `cargo test` skips them.

mod support;

use std::time::Duration;

use hyperscale_scenarios::tx::{
    intershard_partition_genesis_balances, merge_straddler_setup, split_straddler_setup,
    witness_genesis_balances,
};
use hyperscale_scenarios::{
    ScenarioConfig, beacon_pool_partition_stalls_epoch_production,
    cross_shard_compound_drop_fetch_fallback, cross_shard_exec_cert_drop_fetch_fallback,
    cross_shard_header_fetch_fallback, cross_shard_provisions_drop_fetch_fallback,
    cross_shard_provisions_fetch_with_request_loss,
    cross_shard_provisions_recovers_after_transient_outage,
    cross_shard_transaction_da_fetch_fallback, cross_shard_tx, gossip_drop_engages_fetch_fallback,
    grow_reaches_four_shard_topology, grow_reaches_two_shard_topology,
    inter_shard_partition_aborts_waves_at_deadline, isolated_validator_still_settles,
    livelock_resolves_promptly, liveness_baseline, merge_lifecycle,
    merge_seats_full_keeper_committee, merge_straddler_atomic,
    minority_fragment_rejoins_after_partition, multi_vnode_progress, partition_halts_and_heals,
    partition_heals_at_exact_quorum, pool_capacity_caps_registrations,
    re_registration_of_a_live_validator_is_a_no_op, register_validator_pools_a_node,
    register_without_capacity_is_rejected, registered_validator_activates_onto_a_shard,
    single_shard_tx, split_lifecycle, split_straddler_atomic, split_straddler_ec_partition_atomic,
    stake_deposit_folds_into_beacon_state, stake_withdraw_drops_effective_stake,
    surviving_sibling_split_seats_full_committees,
    withdrawal_ejects_a_validator_that_a_deposit_reactivates,
};
use serial_test::serial;
use support::ProdCluster;

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
        shard_size: 4,
        vnodes_per_host: 2,
        pool_surplus: 0,
        num_shards: 1,
        split_bytes: u64::MAX,
        latency: Duration::ZERO,
    }
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn liveness_baseline_prod() {
    let mut cluster = ProdCluster::start(&liveness_config(), 7, EPOCH_MS);
    liveness_baseline(&mut cluster);
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn single_shard_tx_prod() {
    let mut cluster = ProdCluster::start(&liveness_config(), 7, EPOCH_MS);
    single_shard_tx(&mut cluster);
}

/// Fault-scenario config: four single-vnode hosts, so a `transaction.gossip`
/// drop forces the remote hosts to fetch the transaction rather than receive it
/// on a co-hosted mempool.
const fn fault_config() -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 4,
        vnodes_per_host: 1,
        pool_surplus: 0,
        num_shards: 1,
        split_bytes: u64::MAX,
        latency: Duration::from_millis(60),
    }
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn gossip_drop_engages_fetch_fallback_prod() {
    let mut cluster = ProdCluster::start(&fault_config(), 7, EPOCH_MS);
    cluster.run_faultable(gossip_drop_engages_fetch_fallback);
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn partition_halts_and_heals_prod() {
    let mut cluster = ProdCluster::start(&fault_config(), 7, EPOCH_MS);
    cluster.run_faultable(partition_halts_and_heals);
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn isolated_validator_still_settles_prod() {
    let mut cluster = ProdCluster::start(&fault_config(), 7, EPOCH_MS);
    cluster.run_faultable(isolated_validator_still_settles);
}

/// Seven single-vnode hosts: quorum is five, so a connected two-host fragment
/// can partition off while the majority keeps consensus live.
const fn seven_host_fault_config() -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 7,
        vnodes_per_host: 1,
        pool_surplus: 0,
        num_shards: 1,
        split_bytes: u64::MAX,
        latency: Duration::from_millis(60),
    }
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn minority_fragment_rejoins_after_partition_prod() {
    let mut cluster = ProdCluster::start(&seven_host_fault_config(), 7, EPOCH_MS);
    cluster.run_faultable(minority_fragment_rejoins_after_partition);
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn partition_heals_at_exact_quorum_prod() {
    let mut cluster = ProdCluster::start(&fault_config(), 7, EPOCH_MS);
    cluster.run_faultable(partition_heals_at_exact_quorum);
}

/// Single-shard config with the split trigger armed (`split_bytes = 0`), one
/// cohort of pool surplus, one validator per host (each reshape seat needs its
/// own store), and a paced inter-host latency so the loadless committee tracks
/// wall-clock through the multi-epoch grow.
const fn split_config() -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 4,
        vnodes_per_host: 1,
        pool_surplus: 4,
        num_shards: 1,
        split_bytes: 0,
        latency: Duration::from_millis(60),
    }
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn split_lifecycle_prod() {
    let mut cluster = ProdCluster::start(&split_config(), 11, EPOCH_MS);
    split_lifecycle(&mut cluster);
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn cross_shard_tx_prod() {
    let mut cluster = ProdCluster::start(&split_config(), 11, EPOCH_MS);
    cross_shard_tx(&mut cluster);
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn cross_shard_provisions_drop_fetch_fallback_prod() {
    let mut cluster = ProdCluster::start(&split_config(), 11, EPOCH_MS);
    cluster.run_faultable(cross_shard_provisions_drop_fetch_fallback);
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn cross_shard_exec_cert_drop_fetch_fallback_prod() {
    let mut cluster = ProdCluster::start(&split_config(), 11, EPOCH_MS);
    cluster.run_faultable(cross_shard_exec_cert_drop_fetch_fallback);
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn cross_shard_compound_drop_fetch_fallback_prod() {
    let mut cluster = ProdCluster::start(&split_config(), 11, EPOCH_MS);
    cluster.run_faultable(cross_shard_compound_drop_fetch_fallback);
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn cross_shard_transaction_da_fetch_fallback_prod() {
    let mut cluster = ProdCluster::start(&split_config(), 11, EPOCH_MS);
    cluster.run_faultable(cross_shard_transaction_da_fetch_fallback);
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn cross_shard_header_fetch_fallback_prod() {
    let mut cluster = ProdCluster::start(&split_config(), 11, EPOCH_MS);
    cluster.run_faultable(cross_shard_header_fetch_fallback);
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn cross_shard_provisions_recovers_after_transient_outage_prod() {
    let mut cluster = ProdCluster::start(&split_config(), 11, EPOCH_MS);
    cluster.run_faultable(cross_shard_provisions_recovers_after_transient_outage);
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn inter_shard_partition_aborts_waves_at_deadline_prod() {
    let mut cluster = ProdCluster::start_with_balances(
        &split_config(),
        11,
        EPOCH_MS,
        intershard_partition_genesis_balances(),
    );
    cluster.run_faultable(inter_shard_partition_aborts_waves_at_deadline);
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn beacon_pool_partition_stalls_epoch_production_prod() {
    let mut cluster = ProdCluster::start_with_balances(
        &split_config(),
        11,
        EPOCH_MS,
        intershard_partition_genesis_balances(),
    );
    cluster.run_faultable(beacon_pool_partition_stalls_epoch_production);
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn cross_shard_provisions_fetch_with_request_loss_prod() {
    let mut cluster = ProdCluster::start(&split_config(), 42, EPOCH_MS);
    // The body's liveness invariants are the prod assertion; the returned drop
    // count (deterministic only on the sim) is not asserted here.
    let _request_drops = cluster.run_faultable(cross_shard_provisions_fetch_with_request_loss);
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn livelock_resolves_promptly_prod() {
    let mut cluster = ProdCluster::start(&split_config(), 11, EPOCH_MS);
    livelock_resolves_promptly(&mut cluster);
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn merge_lifecycle_prod() {
    let mut cluster = ProdCluster::start(&split_config(), 11, EPOCH_MS);
    merge_lifecycle(&mut cluster);
}

/// Two cohorts of pool surplus and a grow trigger above each child but below
/// ROOT: one cohort grows ROOT to the two siblings, the other splits the heavier
/// one after the vote. One validator per host (each reshape seat its own store).
const fn straddler_config() -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 4,
        vnodes_per_host: 1,
        pool_surplus: 8,
        num_shards: 1,
        split_bytes: 800_000,
        latency: Duration::from_millis(60),
    }
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn split_straddler_atomic_prod() {
    let setup = split_straddler_setup();
    let mut cluster =
        ProdCluster::start_with_balances(&straddler_config(), 11, EPOCH_MS, setup.balances);
    split_straddler_atomic(&mut cluster);
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn split_straddler_ec_partition_atomic_prod() {
    let setup = split_straddler_setup();
    let mut cluster =
        ProdCluster::start_with_balances(&straddler_config(), 11, EPOCH_MS, setup.balances);
    split_straddler_ec_partition_atomic(&mut cluster);
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
        shard_size: 4,
        vnodes_per_host: 1,
        pool_surplus: 12,
        num_shards: 4,
        split_bytes: 2_880_000,
        latency: Duration::from_millis(60),
    }
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn merge_straddler_atomic_prod() {
    let setup = merge_straddler_setup();
    let mut cluster = ProdCluster::start_with_grown_balances(
        &merge_straddler_config(),
        11,
        EPOCH_MS,
        setup.balances,
    );
    merge_straddler_atomic(&mut cluster);
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn multi_vnode_progress_prod() {
    // `liveness_config` already hosts the committee at two vnodes per host — the
    // same-shard multi-vnode hosting under test.
    let mut cluster = ProdCluster::start(&liveness_config(), 7, EPOCH_MS);
    multi_vnode_progress(&mut cluster);
}

/// Single-shard witness config: the committee equals the whole validator set
/// (`pool_surplus = 0`, so the shuffle never fires) with resharding disarmed —
/// the stable ground the beacon-witness scenarios fold system actions against.
/// `validators` sizes the committee; two vnodes per host keep quorum while a
/// member deactivates or ejects.
const fn witness_config(validators: u32) -> ScenarioConfig {
    ScenarioConfig {
        shard_size: validators,
        vnodes_per_host: 2,
        pool_surplus: 0,
        num_shards: 1,
        split_bytes: u64::MAX,
        latency: Duration::ZERO,
    }
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn stake_deposit_folds_into_beacon_state_prod() {
    let mut cluster = ProdCluster::start_with_balances(
        &witness_config(4),
        0x57AC,
        EPOCH_MS,
        witness_genesis_balances(),
    );
    stake_deposit_folds_into_beacon_state(&mut cluster);
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn register_validator_pools_a_node_prod() {
    let mut cluster = ProdCluster::start_with_balances(
        &witness_config(4),
        0x5EED,
        EPOCH_MS,
        witness_genesis_balances(),
    );
    register_validator_pools_a_node(&mut cluster);
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn register_without_capacity_is_rejected_prod() {
    let mut cluster = ProdCluster::start_with_balances(
        &witness_config(4),
        0x0CA9,
        EPOCH_MS,
        witness_genesis_balances(),
    );
    register_without_capacity_is_rejected(&mut cluster);
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn stake_withdraw_drops_effective_stake_prod() {
    let mut cluster = ProdCluster::start_with_balances(
        &witness_config(4),
        0xD7A1,
        EPOCH_MS,
        witness_genesis_balances(),
    );
    stake_withdraw_drops_effective_stake(&mut cluster);
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn registered_validator_activates_onto_a_shard_prod() {
    let mut cluster = ProdCluster::start_with_balances(
        &witness_config(4),
        0xAC11,
        EPOCH_MS,
        witness_genesis_balances(),
    );
    registered_validator_activates_onto_a_shard(&mut cluster);
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn withdrawal_ejects_a_validator_that_a_deposit_reactivates_prod() {
    // Seven validators give the committee slack to keep quorum while a couple
    // eject.
    let mut cluster = ProdCluster::start_with_balances(
        &witness_config(7),
        0xE1EC,
        EPOCH_MS,
        witness_genesis_balances(),
    );
    withdrawal_ejects_a_validator_that_a_deposit_reactivates(&mut cluster);
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn re_registration_of_a_live_validator_is_a_no_op_prod() {
    let mut cluster = ProdCluster::start_with_balances(
        &witness_config(4),
        0xDEAD,
        EPOCH_MS,
        witness_genesis_balances(),
    );
    re_registration_of_a_live_validator_is_a_no_op(&mut cluster);
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn pool_capacity_caps_registrations_prod() {
    let mut cluster = ProdCluster::start_with_balances(
        &witness_config(4),
        0xCA9A,
        EPOCH_MS,
        witness_genesis_balances(),
    );
    pool_capacity_caps_registrations(&mut cluster);
}

/// Single-shard genesis with the split armed and exactly `(target - 1)` cohorts
/// of pool surplus to staff the grow's split generations. One validator per host
/// (each reshape seat needs its own store) and a paced inter-host latency so the
/// loadless committees track wall-clock through the multi-epoch grow.
const fn grow_config(target_shards: u32) -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 4,
        vnodes_per_host: 2,
        pool_surplus: (target_shards - 1) * 4,
        num_shards: 1,
        split_bytes: 0,
        latency: Duration::from_millis(60),
    }
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn grow_reaches_two_shard_topology_prod() {
    let mut cluster = ProdCluster::start(&grow_config(2), 11, EPOCH_MS);
    grow_reaches_two_shard_topology(&mut cluster);
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn grow_reaches_four_shard_topology_prod() {
    let mut cluster = ProdCluster::start(&grow_config(4), 11, EPOCH_MS);
    grow_reaches_four_shard_topology(&mut cluster);
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn merge_seats_full_keeper_committee_prod() {
    let mut cluster = ProdCluster::start(&split_config(), 11, EPOCH_MS);
    merge_seats_full_keeper_committee(&mut cluster);
}

#[test]
#[serial]
#[cfg_attr(
    not(feature = "ci"),
    ignore = "real-QUIC production scenario; run with --features ci or -- --ignored"
)]
fn surviving_sibling_split_seats_full_committees_prod() {
    let setup = split_straddler_setup();
    let mut cluster =
        ProdCluster::start_with_balances(&straddler_config(), 11, EPOCH_MS, setup.balances);
    surviving_sibling_split_seats_full_committees(&mut cluster);
}
