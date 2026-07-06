//! Portable scenarios run on the simulation harness.
//!
//! Each `#[test]` builds a [`SimCluster`] and drives a `hyperscale_scenarios`
//! body. The identical body runs on production under `#[cfg(feature = "ci")]`.

mod support;

use std::time::Duration;

use hyperscale_scenarios::tx::{
    merge_straddler_setup, split_straddler_setup, witness_genesis_balances,
};
use hyperscale_scenarios::{
    ScenarioConfig, cross_shard_compound_drop_fetch_fallback,
    cross_shard_exec_cert_drop_fetch_fallback, cross_shard_header_fetch_fallback,
    cross_shard_provisions_drop_fetch_fallback, cross_shard_provisions_fetch_with_request_loss,
    cross_shard_provisions_recovers_after_transient_outage,
    cross_shard_transaction_da_fetch_fallback, cross_shard_tx, gossip_drop_engages_fetch_fallback,
    grow_reaches_four_shard_topology, grow_reaches_two_shard_topology,
    isolated_validator_still_settles, livelock_resolves_promptly, liveness_baseline,
    merge_lifecycle, merge_seats_full_keeper_committee, merge_straddler_atomic,
    minority_fragment_rejoins_after_partition, multi_vnode_progress, partition_halts_and_heals,
    partition_heals_at_exact_quorum, pool_capacity_caps_registrations,
    re_registration_of_a_live_validator_is_a_no_op, register_validator_pools_a_node,
    register_without_capacity_is_rejected, registered_validator_activates_onto_a_shard,
    single_shard_tx, split_lifecycle, split_straddler_atomic, split_straddler_ec_partition_atomic,
    stake_deposit_folds_into_beacon_state, stake_withdraw_drops_effective_stake,
    surviving_sibling_split_seats_full_committees,
    withdrawal_ejects_a_validator_that_a_deposit_reactivates,
};
use support::sim_cluster::SimCluster;

/// Baseline single-shard config: resharding disarmed, four-validator committee.
const fn liveness_config() -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 4,
        vnodes_per_host: 1,
        pool_surplus: 0,
        num_shards: 1,
        split_bytes: u64::MAX,
        latency: Duration::from_millis(150),
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

#[test]
fn gossip_drop_engages_fetch_fallback_sim() {
    let mut cluster = SimCluster::new(&liveness_config(), 42);
    cluster.run_faultable(gossip_drop_engages_fetch_fallback);
}

#[test]
fn partition_halts_and_heals_sim() {
    let mut cluster = SimCluster::new(&liveness_config(), 42);
    cluster.run_faultable(partition_halts_and_heals);
}

#[test]
fn isolated_validator_still_settles_sim() {
    let mut cluster = SimCluster::new(&liveness_config(), 42);
    cluster.run_faultable(isolated_validator_still_settles);
}

/// Seven-host single-shard config: quorum is five, so a connected two-host
/// fragment can partition off while the majority keeps consensus live.
const fn seven_host_config() -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 7,
        vnodes_per_host: 1,
        pool_surplus: 0,
        num_shards: 1,
        split_bytes: u64::MAX,
        latency: Duration::from_millis(150),
    }
}

#[test]
fn minority_fragment_rejoins_after_partition_sim() {
    let mut cluster = SimCluster::new(&seven_host_config(), 42);
    cluster.run_faultable(minority_fragment_rejoins_after_partition);
}

#[test]
fn partition_heals_at_exact_quorum_sim() {
    let mut cluster = SimCluster::new(&liveness_config(), 42);
    cluster.run_faultable(partition_heals_at_exact_quorum);
}

/// Single-shard config with the split trigger armed (`split_bytes = 0`) and one
/// cohort of pool surplus — drives an organic root split.
const fn split_config() -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 4,
        vnodes_per_host: 1,
        pool_surplus: 4,
        num_shards: 1,
        split_bytes: 0,
        latency: Duration::from_millis(150),
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
fn cross_shard_provisions_drop_fetch_fallback_sim() {
    let mut cluster = SimCluster::new(&split_config(), 11);
    cluster.run_faultable(cross_shard_provisions_drop_fetch_fallback);
}

#[test]
fn cross_shard_exec_cert_drop_fetch_fallback_sim() {
    let mut cluster = SimCluster::new(&split_config(), 11);
    cluster.run_faultable(cross_shard_exec_cert_drop_fetch_fallback);
}

#[test]
fn cross_shard_transaction_da_fetch_fallback_sim() {
    let mut cluster = SimCluster::new(&split_config(), 11);
    cluster.run_faultable(cross_shard_transaction_da_fetch_fallback);
}

#[test]
fn cross_shard_header_fetch_fallback_sim() {
    let mut cluster = SimCluster::new(&split_config(), 11);
    cluster.run_faultable(cross_shard_header_fetch_fallback);
}

#[test]
fn cross_shard_compound_drop_fetch_fallback_sim() {
    let mut cluster = SimCluster::new(&split_config(), 11);
    cluster.run_faultable(cross_shard_compound_drop_fetch_fallback);
}

#[test]
fn cross_shard_provisions_recovers_after_transient_outage_sim() {
    let mut cluster = SimCluster::new(&split_config(), 11);
    cluster.run_faultable(cross_shard_provisions_recovers_after_transient_outage);
}

/// Assert the seeded 50%-request-loss scenario at `seed`: the shared body's
/// liveness invariants plus the sim-deterministic engagement — at least one
/// `provision.request` leg drop landed at this seed. Production can't assert
/// engagement (its async retry path is nondeterministic), so that check lives
/// here, keyed on the exact seed.
fn request_loss_engages_at_seed(seed: u64) {
    let mut cluster = SimCluster::new(&split_config(), seed);
    let request_drops = cluster.run_faultable(cross_shard_provisions_fetch_with_request_loss);
    assert!(
        request_drops >= 1,
        "the 50% provision.request loss must engage at seed {seed}; drops = {request_drops}",
    );
}

#[test]
fn cross_shard_provisions_fetch_with_request_loss_seed_42_sim() {
    request_loss_engages_at_seed(42);
}

#[test]
fn cross_shard_provisions_fetch_with_request_loss_seed_1337_sim() {
    request_loss_engages_at_seed(1337);
}

#[test]
fn cross_shard_provisions_fetch_with_request_loss_seed_2026_sim() {
    request_loss_engages_at_seed(2026);
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
        shard_size: 4,
        vnodes_per_host: 1,
        pool_surplus: 8,
        num_shards: 1,
        split_bytes: 800_000,
        latency: Duration::from_millis(150),
    }
}

#[test]
fn split_straddler_atomic_sim() {
    let setup = split_straddler_setup();
    let mut cluster = SimCluster::with_balances(&straddler_config(), 11, &setup.balances);
    split_straddler_atomic(&mut cluster);
}

/// Straddler atomicity under an asymmetric EC partition across a split boundary.
///
/// Drives the portable [`split_straddler_ec_partition_atomic`] scenario across a
/// seed sweep, seating disjoint splitter/survivor committees via dedicated pool
/// hosts so no co-hosted vnode bridges the EC cut in-process. The seeds vary how
/// the survivor's finalization races its own counterpart-abort sweep; none may
/// resolve one-sided.
#[test]
fn split_straddler_asymmetric_ec_partition() {
    for seed in [7u64, 11, 42, 2026, 1337] {
        let setup = split_straddler_setup();
        let mut cluster =
            SimCluster::with_dedicated_pool_hosts(&straddler_config(), seed, &setup.balances);
        split_straddler_ec_partition_atomic(&mut cluster);
    }
}

/// Four-shard topology whose `split_bytes` derives a `merge_bytes` bracketing
/// the genesis byte skew: the survivor pair (`leaf(2,0)`/`leaf(2,1)`, the latter
/// bulk-funded) sits above it, the light merging pair (`leaf(2,2)`/`leaf(2,3)`)
/// below it, so only the merging pair auto-merges into `leaf(1,1)`. Three cohorts
/// of pool surplus staff the two split generations the grow walks through; the
/// merge keepers then come from the merging children's own committees.
const fn merge_straddler_config() -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 4,
        vnodes_per_host: 1,
        pool_surplus: 12,
        num_shards: 4,
        split_bytes: 2_880_000,
        latency: Duration::from_millis(150),
    }
}

#[test]
fn merge_straddler_atomic_sim() {
    let setup = merge_straddler_setup();
    let mut cluster =
        SimCluster::with_grown_balances(&merge_straddler_config(), 11, &setup.balances);
    merge_straddler_atomic(&mut cluster);
}

/// Multi-vnode config: two vnodes per host (same-shard multi-vnode hosting), the
/// split disarmed, no pool surplus — a single shard whose committee is hosted at
/// two vnodes per host.
const fn multi_vnode_config() -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 4,
        vnodes_per_host: 2,
        pool_surplus: 0,
        num_shards: 1,
        split_bytes: u64::MAX,
        latency: Duration::from_millis(150),
    }
}

#[test]
fn multi_vnode_progress_sim() {
    let mut cluster = SimCluster::new(&multi_vnode_config(), 11);
    multi_vnode_progress(&mut cluster);
}

/// Single-shard witness config: the committee equals the whole validator set
/// (`pool_surplus = 0`, so the shuffle has no stock and never fires) with
/// resharding disarmed — the stable ground the beacon-witness scenarios fold
/// system actions against. `validators` sizes the committee.
const fn witness_config(validators: u32) -> ScenarioConfig {
    ScenarioConfig {
        shard_size: validators,
        vnodes_per_host: 1,
        pool_surplus: 0,
        num_shards: 1,
        split_bytes: u64::MAX,
        latency: Duration::from_millis(150),
    }
}

#[test]
fn stake_deposit_folds_into_beacon_state_sim() {
    let mut cluster =
        SimCluster::with_balances(&witness_config(4), 0x57AC, &witness_genesis_balances());
    stake_deposit_folds_into_beacon_state(&mut cluster);
}

#[test]
fn register_validator_pools_a_node_sim() {
    let mut cluster =
        SimCluster::with_balances(&witness_config(4), 0x5EED, &witness_genesis_balances());
    register_validator_pools_a_node(&mut cluster);
}

#[test]
fn register_without_capacity_is_rejected_sim() {
    let mut cluster =
        SimCluster::with_balances(&witness_config(4), 0x0CA9, &witness_genesis_balances());
    register_without_capacity_is_rejected(&mut cluster);
}

#[test]
fn stake_withdraw_drops_effective_stake_sim() {
    let mut cluster =
        SimCluster::with_balances(&witness_config(4), 0xD7A1, &witness_genesis_balances());
    stake_withdraw_drops_effective_stake(&mut cluster);
}

#[test]
fn registered_validator_activates_onto_a_shard_sim() {
    let mut cluster =
        SimCluster::with_balances(&witness_config(4), 0xAC11, &witness_genesis_balances());
    registered_validator_activates_onto_a_shard(&mut cluster);
}

#[test]
fn withdrawal_ejects_a_validator_that_a_deposit_reactivates_sim() {
    // Seven validators give the committee slack to keep quorum while a couple
    // eject; `pool_surplus = 0` keeps the shuffle dormant.
    let mut cluster =
        SimCluster::with_balances(&witness_config(7), 0xE1EC, &witness_genesis_balances());
    withdrawal_ejects_a_validator_that_a_deposit_reactivates(&mut cluster);
}

#[test]
fn re_registration_of_a_live_validator_is_a_no_op_sim() {
    let mut cluster =
        SimCluster::with_balances(&witness_config(4), 0xDEAD, &witness_genesis_balances());
    re_registration_of_a_live_validator_is_a_no_op(&mut cluster);
}

#[test]
fn pool_capacity_caps_registrations_sim() {
    let mut cluster =
        SimCluster::with_balances(&witness_config(4), 0xCA9A, &witness_genesis_balances());
    pool_capacity_caps_registrations(&mut cluster);
}

/// Single-shard genesis with the split armed (`split_bytes = 0`) and exactly
/// `(target - 1)` cohorts of pool surplus to staff the split generations the
/// grow walks through — no surplus left over, so the partition stabilizes at
/// `target` leaves.
const fn grow_config(target_shards: u32) -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 4,
        vnodes_per_host: 1,
        pool_surplus: (target_shards - 1) * 4,
        num_shards: 1,
        split_bytes: 0,
        latency: Duration::from_millis(150),
    }
}

#[test]
fn grow_reaches_two_shard_topology_sim() {
    let mut cluster = SimCluster::new(&grow_config(2), 11);
    grow_reaches_two_shard_topology(&mut cluster);
}

#[test]
fn grow_reaches_four_shard_topology_sim() {
    let mut cluster = SimCluster::new(&grow_config(4), 11);
    grow_reaches_four_shard_topology(&mut cluster);
}

#[test]
fn merge_seats_full_keeper_committee_sim() {
    let mut cluster = SimCluster::new(&split_config(), 11);
    merge_seats_full_keeper_committee(&mut cluster);
}

#[test]
fn surviving_sibling_split_seats_full_committees_sim() {
    let setup = split_straddler_setup();
    let mut cluster = SimCluster::with_balances(&straddler_config(), 11, &setup.balances);
    surviving_sibling_split_seats_full_committees(&mut cluster);
}
