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
        // Each pool observer gets its own host so a freshly split committee
        // spreads one validator per host, as production seats it. Co-hosting a
        // committee onto too few hosts wedges BFT when one host falls a block
        // behind.
        dedicated_hosts: true,
    }
}

#[test]
fn split_straddler_atomic_sim() {
    let setup = split_straddler_setup();
    let mut cluster = SimCluster::with_balances(&straddler_config(), 11, &setup.balances);
    split_straddler_atomic(&mut cluster);
}

/// Four-shard topology whose `split_bytes` derives a `merge_bytes` bracketing
/// the genesis byte skew: the survivor pair (`leaf(2,0)`/`leaf(2,1)`, the latter
/// bulk-funded) sits above it, the light merging pair (`leaf(2,2)`/`leaf(2,3)`)
/// below it, so only the merging pair auto-merges into `leaf(1,1)`. Three cohorts
/// of pool surplus staff the two split generations the grow walks through; the
/// merge keepers then come from the merging children's own committees.
const fn merge_straddler_config() -> ScenarioConfig {
    ScenarioConfig {
        validators_per_shard: 4,
        vnodes_per_host: 1,
        pool_surplus: 12,
        num_shards: 4,
        split_bytes: 2_880_000,
        latency: Duration::from_millis(150),
        // One host per pool observer; see `straddler_config`.
        dedicated_hosts: true,
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

/// Single-shard witness config: the committee equals the whole validator set
/// (`pool_surplus = 0`, so the shuffle has no stock and never fires) with
/// resharding disarmed — the stable ground the beacon-witness scenarios fold
/// system actions against. `validators` sizes the committee.
const fn witness_config(validators: u32) -> ScenarioConfig {
    ScenarioConfig {
        validators_per_shard: validators,
        vnodes_per_host: 1,
        pool_surplus: 0,
        num_shards: 1,
        split_bytes: u64::MAX,
        latency: Duration::from_millis(150),
        dedicated_hosts: false,
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
        validators_per_shard: 4,
        vnodes_per_host: 1,
        pool_surplus: (target_shards - 1) * 4,
        num_shards: 1,
        split_bytes: 0,
        latency: Duration::from_millis(150),
        dedicated_hosts: false,
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
