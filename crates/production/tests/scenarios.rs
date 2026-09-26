//! Portable scenarios run on the production QUIC + `RocksDB` harness.
//!
//! Each `#[test]` builds a [`ProdCluster`] and drives the identical
//! `hyperscale_scenarios` body the simulation harness runs. These exercise a
//! real multi-host cluster at wall-clock, so they are a nightly/manual job that
//! default `cargo test` skips: run them with `-- --ignored`, adding
//! `--features short-epochs` to trade production parity for a quick answer.

mod support;

use std::time::Duration;

use hyperscale_engine::genesis::GenesisPackages;
use hyperscale_scenarios::tx::{
    CROSS_FRACTION_SENDERS, armed_split_bytes, cross_fraction_genesis_accounts,
    cross_shard_fault_genesis_accounts, cross_shard_genesis_accounts, genesis_accounts,
    halt_recovery_split_bytes, halt_straddler_setup, livelock_genesis_accounts, merge_split_bytes,
    merge_straddler_setup, participant_sweep_genesis_accounts, remote_delegator,
    reshape_lifecycle_accounts, split_straddler_setup,
};
use hyperscale_scenarios::{
    ScenarioConfig, a_delivery_cut_off_past_its_window_is_owed,
    a_delivery_is_owed_when_its_deliverer_splits,
    a_delivery_lands_past_every_window_once_its_record_arrives,
    a_healed_network_delivers_past_the_old_window,
    a_leg_whose_core_never_answers_refuses_at_the_deadline,
    a_skip_deferred_split_keeps_every_settlement_in_its_window, abort_converges,
    beacon_pool_partition_stalls_epoch_production, cross_shard_compound_drop_fetch_fallback,
    cross_shard_exec_cert_drop_is_inert, cross_shard_fraction, cross_shard_header_fetch_fallback,
    cross_shard_provisions_drop_fetch_fallback, cross_shard_provisions_fetch_with_request_loss,
    cross_shard_provisions_recovers_after_transient_outage,
    cross_shard_transaction_da_fetch_fallback, delegation_folds_into_beacon_state,
    gossip_drop_engages_fetch_fallback, grow_reaches_four_shard_topology,
    grow_reaches_two_shard_topology, halted_shard_recovers_by_committee_redraw,
    halted_shard_straddler_atomic, hot_recipient,
    inter_shard_partition_strands_ticks_until_it_heals, isolated_validator_still_settles,
    livelock_resolves_promptly, liveness_baseline, merge_lifecycle,
    merge_seats_full_keeper_committee, merge_straddler_atomic,
    minority_fragment_rejoins_after_partition, multi_vnode_progress, participant_count_sweep,
    partition_halts_and_heals, partition_heals_at_exact_quorum, pool_capacity_caps_registrations,
    re_registration_of_a_live_validator_is_a_no_op, register_validator_pools_a_node,
    register_without_capacity_is_rejected, registered_validator_activates_onto_a_shard,
    single_transfer, split_lifecycle, split_straddler_atomic, split_straddler_ec_partition_atomic,
    stake_withdraw_drops_effective_stake, surviving_sibling_split_seats_full_committees,
    withdrawal_ejects_a_validator_that_a_deposit_reactivates, zipf_payments,
};
use hyperscale_types::PrincipalAddr;
use serial_test::serial;
use support::ProdCluster;

/// Production epoch length: the real 5-minute deployment epoch, or the
/// 30-second one under `short-epochs` — mirroring `simulation`'s `EPOCH_MS` so
/// a budget carries the same epoch semantics on both harnesses.
#[cfg(not(feature = "short-epochs"))]
const EPOCH_MS: u64 = 300_000;
#[cfg(feature = "short-epochs")]
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
#[ignore = "real-QUIC production scenario; run with -- --ignored"]
fn liveness_baseline_prod() {
    let mut cluster = ProdCluster::start(&liveness_config(), 7, EPOCH_MS);
    liveness_baseline(&mut cluster);
}

#[test]
#[serial]
#[ignore = "real-QUIC production scenario; run with -- --ignored"]
fn single_transfer_prod() {
    let mut cluster =
        ProdCluster::start_with_accounts(&liveness_config(), 7, EPOCH_MS, genesis_accounts(1, 1));
    single_transfer(&mut cluster);
}

#[test]
#[serial]
#[ignore = "real-QUIC production scenario; run with -- --ignored"]
fn abort_converges_prod() {
    let mut cluster =
        ProdCluster::start_with_accounts(&liveness_config(), 7, EPOCH_MS, genesis_accounts(1, 1));
    abort_converges(&mut cluster);
}

/// Everything `livelock_resolves_promptly` needs funded: it composes
/// `split_lifecycle`, so the probe transfer's accounts come along with
/// the conflicting pair's.
fn livelock_accounts() -> Vec<(PrincipalAddr, u128)> {
    let mut accounts = genesis_accounts(1, 1);
    accounts.extend(livelock_genesis_accounts());
    accounts
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
#[ignore = "real-QUIC production scenario; run with -- --ignored"]
fn gossip_drop_engages_fetch_fallback_prod() {
    let mut cluster =
        ProdCluster::start_with_accounts(&fault_config(), 7, EPOCH_MS, genesis_accounts(1, 1));
    cluster.run_faultable(gossip_drop_engages_fetch_fallback);
}

#[test]
#[serial]
#[ignore = "real-QUIC production scenario; run with -- --ignored"]
fn partition_halts_and_heals_prod() {
    let mut cluster = ProdCluster::start(&fault_config(), 7, EPOCH_MS);
    cluster.run_faultable(partition_halts_and_heals);
}

#[test]
#[serial]
#[ignore = "real-QUIC production scenario; run with -- --ignored"]
fn isolated_validator_still_settles_prod() {
    let mut cluster =
        ProdCluster::start_with_accounts(&fault_config(), 7, EPOCH_MS, genesis_accounts(1, 1));
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
#[ignore = "real-QUIC production scenario; run with -- --ignored"]
fn minority_fragment_rejoins_after_partition_prod() {
    let mut cluster = ProdCluster::start(&seven_host_fault_config(), 7, EPOCH_MS);
    cluster.run_faultable(minority_fragment_rejoins_after_partition);
}

#[test]
#[serial]
#[ignore = "real-QUIC production scenario; run with -- --ignored"]
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
#[ignore = "real-QUIC production scenario; run with -- --ignored"]
fn split_lifecycle_prod() {
    let mut cluster =
        ProdCluster::start_with_accounts(&split_config(), 11, EPOCH_MS, genesis_accounts(1, 1));
    split_lifecycle(&mut cluster);
}

#[test]
#[serial]
#[ignore = "real-QUIC production scenario; run with -- --ignored"]
fn zipf_payments_prod() {
    let mut cluster =
        ProdCluster::start_with_accounts(&liveness_config(), 42, EPOCH_MS, genesis_accounts(24, 6));
    let report = zipf_payments(&mut cluster, 24, 6, 1.0);
    println!("zipf_payments s=1.0 senders=24 recipients=6: {report:?}");
}

#[test]
#[serial]
#[ignore = "real-QUIC production scenario; run with -- --ignored"]
fn hot_recipient_prod() {
    let mut cluster =
        ProdCluster::start_with_accounts(&liveness_config(), 42, EPOCH_MS, genesis_accounts(12, 1));
    let (report, height_span) = hot_recipient(&mut cluster, 12);
    println!("hot_recipient senders=12 height_span={height_span}: {report:?}");
}

#[test]
#[serial]
#[ignore = "real-QUIC production scenario; run with -- --ignored"]
fn cross_shard_fraction_prod() {
    let mut cluster = ProdCluster::start_with_accounts(
        &split_config(),
        11,
        EPOCH_MS,
        cross_fraction_genesis_accounts(CROSS_FRACTION_SENDERS),
    );
    let report = cross_shard_fraction(&mut cluster, CROSS_FRACTION_SENDERS, 500);
    println!("cross_shard_fraction total=16 cross=50%: {report:?}");
}

/// Two shards with the reshape threshold disarmed after the grow — the
/// simulation's cross-shard shape on the production harness.
const fn cross_shard_config() -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 4,
        vnodes_per_host: 1,
        pool_surplus: 4,
        num_shards: 2,
        split_bytes: u64::MAX,
        latency: Duration::from_millis(60),
    }
}

#[test]
#[serial]
#[ignore = "real-QUIC production scenario; run with -- --ignored"]
fn a_delivery_cut_off_past_its_window_is_owed_prod() {
    let mut cluster = ProdCluster::start_with_grown_accounts(
        &cross_shard_config(),
        42,
        EPOCH_MS,
        cross_shard_genesis_accounts(),
    );
    cluster.run_faultable(a_delivery_cut_off_past_its_window_is_owed);
}

#[test]
#[serial]
#[ignore = "real-QUIC production scenario; run with -- --ignored"]
fn a_delivery_lands_past_every_window_once_its_record_arrives_prod() {
    let mut cluster = ProdCluster::start_with_grown_accounts(
        &cross_shard_config(),
        42,
        EPOCH_MS,
        cross_shard_genesis_accounts(),
    );
    cluster.run_faultable(a_delivery_lands_past_every_window_once_its_record_arrives);
}

#[test]
#[serial]
#[ignore = "real-QUIC production scenario; run with -- --ignored"]
fn a_healed_network_delivers_past_the_old_window_prod() {
    let mut cluster = ProdCluster::start_with_grown_accounts(
        &cross_shard_config(),
        42,
        EPOCH_MS,
        cross_shard_genesis_accounts(),
    );
    cluster.run_faultable(a_healed_network_delivers_past_the_old_window);
}

#[test]
#[serial]
#[ignore = "real-QUIC production scenario; run with -- --ignored"]
fn a_leg_whose_core_never_answers_refuses_at_the_deadline_prod() {
    let mut cluster = ProdCluster::start_with_grown_accounts(
        &cross_shard_config(),
        42,
        EPOCH_MS,
        vec![(remote_delegator().1, 1_000_000)],
    );
    cluster.run_faultable(a_leg_whose_core_never_answers_refuses_at_the_deadline);
}

#[test]
#[serial]
#[ignore = "real-QUIC production scenario; run with -- --ignored"]
fn participant_count_sweep_prod() {
    let mut cluster = ProdCluster::start_with_accounts(
        &split_config(),
        11,
        EPOCH_MS,
        participant_sweep_genesis_accounts(2),
    );
    let latencies = participant_count_sweep(&mut cluster, 2, 2);
    println!("participant_count_sweep shards=2: {latencies:?}");
}

#[test]
#[serial]
#[ignore = "real-QUIC production scenario; run with -- --ignored"]
fn cross_shard_provisions_drop_fetch_fallback_prod() {
    let mut cluster = ProdCluster::start_with_accounts(
        &split_config(),
        11,
        EPOCH_MS,
        cross_shard_fault_genesis_accounts(),
    );
    cluster.run_faultable(cross_shard_provisions_drop_fetch_fallback);
}

#[test]
#[serial]
#[ignore = "real-QUIC production scenario; run with -- --ignored"]
fn cross_shard_exec_cert_drop_is_inert_prod() {
    let mut cluster = ProdCluster::start_with_accounts(
        &split_config(),
        11,
        EPOCH_MS,
        cross_shard_fault_genesis_accounts(),
    );
    cluster.run_faultable(cross_shard_exec_cert_drop_is_inert);
}

#[test]
#[serial]
#[ignore = "real-QUIC production scenario; run with -- --ignored"]
fn cross_shard_compound_drop_fetch_fallback_prod() {
    let mut cluster = ProdCluster::start_with_accounts(
        &split_config(),
        11,
        EPOCH_MS,
        cross_shard_fault_genesis_accounts(),
    );
    cluster.run_faultable(cross_shard_compound_drop_fetch_fallback);
}

#[test]
#[serial]
#[ignore = "real-QUIC production scenario; run with -- --ignored"]
fn cross_shard_transaction_da_fetch_fallback_prod() {
    let mut cluster = ProdCluster::start_with_accounts(
        &split_config(),
        11,
        EPOCH_MS,
        cross_shard_fault_genesis_accounts(),
    );
    cluster.run_faultable(cross_shard_transaction_da_fetch_fallback);
}

#[test]
#[serial]
#[ignore = "real-QUIC production scenario; run with -- --ignored"]
fn cross_shard_header_fetch_fallback_prod() {
    let mut cluster = ProdCluster::start_with_accounts(
        &split_config(),
        11,
        EPOCH_MS,
        cross_shard_fault_genesis_accounts(),
    );
    cluster.run_faultable(cross_shard_header_fetch_fallback);
}

#[test]
#[serial]
#[ignore = "real-QUIC production scenario; run with -- --ignored"]
fn cross_shard_provisions_recovers_after_transient_outage_prod() {
    let mut cluster = ProdCluster::start_with_accounts(
        &split_config(),
        11,
        EPOCH_MS,
        cross_shard_fault_genesis_accounts(),
    );
    cluster.run_faultable(cross_shard_provisions_recovers_after_transient_outage);
}

#[test]
#[serial]
#[ignore = "real-QUIC production scenario; run with -- --ignored"]
fn inter_shard_partition_strands_ticks_until_it_heals_prod() {
    let mut cluster = ProdCluster::start_with_accounts(
        &split_config(),
        11,
        EPOCH_MS,
        cross_shard_fault_genesis_accounts(),
    );
    cluster.run_faultable(inter_shard_partition_strands_ticks_until_it_heals);
}

#[test]
#[serial]
#[ignore = "real-QUIC production scenario; run with -- --ignored"]
fn beacon_pool_partition_stalls_epoch_production_prod() {
    let mut cluster = ProdCluster::start(&split_config(), 11, EPOCH_MS);
    cluster.run_faultable(beacon_pool_partition_stalls_epoch_production);
}

#[test]
#[serial]
#[ignore = "real-QUIC production scenario; run with -- --ignored"]
fn cross_shard_provisions_fetch_with_request_loss_prod() {
    let mut cluster = ProdCluster::start_with_accounts(
        &split_config(),
        42,
        EPOCH_MS,
        cross_shard_fault_genesis_accounts(),
    );
    // The body's liveness invariants are the prod assertion; the returned drop
    // count (deterministic only on the sim) is not asserted here.
    let _request_drops = cluster.run_faultable(cross_shard_provisions_fetch_with_request_loss);
}

#[test]
#[serial]
#[ignore = "real-QUIC production scenario; run with -- --ignored"]
fn livelock_resolves_promptly_prod() {
    let mut cluster =
        ProdCluster::start_with_accounts(&split_config(), 11, EPOCH_MS, livelock_accounts());
    livelock_resolves_promptly(&mut cluster);
}

#[test]
#[serial]
#[ignore = "real-QUIC production scenario; run with -- --ignored"]
fn merge_lifecycle_prod() {
    let mut cluster = ProdCluster::start_with_accounts(
        &split_config(),
        11,
        EPOCH_MS,
        reshape_lifecycle_accounts(),
    );
    merge_lifecycle(&mut cluster);
}

/// Two cohorts of pool surplus plus the shuffle's headroom, and a grow
/// trigger above each child of the ballasted root but below the root
/// itself: one cohort grows ROOT to the two siblings, the other splits
/// the heavier one after the vote. One validator per host (each reshape
/// seat its own store).
///
/// The headroom is what makes the second split reachable at all. A split
/// is admitted only while the pool holds a whole committee, and the
/// shuffle draws its entrants from that same pool with no such gate —
/// one per live shard, so two here.
fn straddler_config() -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 4,
        vnodes_per_host: 1,
        pool_surplus: 10,
        num_shards: 1,
        split_bytes: armed_split_bytes(&GenesisPackages::protocol()),
        latency: Duration::from_millis(60),
    }
}

#[test]
#[serial]
#[ignore = "real-QUIC production scenario; run with -- --ignored"]
fn split_straddler_atomic_prod() {
    let setup = split_straddler_setup();
    let mut cluster =
        ProdCluster::start_with_accounts(&straddler_config(), 11, EPOCH_MS, setup.accounts);
    split_straddler_atomic(&mut cluster);
}

#[test]
#[serial]
#[ignore = "real-QUIC production scenario; run with -- --ignored"]
fn a_delivery_is_owed_when_its_deliverer_splits_prod() {
    let setup = split_straddler_setup();
    let mut cluster =
        ProdCluster::start_with_accounts(&straddler_config(), 11, EPOCH_MS, setup.accounts);
    cluster.run_faultable(a_delivery_is_owed_when_its_deliverer_splits);
}

#[test]
#[serial]
#[ignore = "real-QUIC production scenario; run with -- --ignored"]
fn split_straddler_ec_partition_atomic_prod() {
    let setup = split_straddler_setup();
    let mut cluster =
        ProdCluster::start_with_accounts(&straddler_config(), 11, EPOCH_MS, setup.accounts);
    split_straddler_ec_partition_atomic(&mut cluster);
}

#[test]
#[serial]
#[ignore = "real-QUIC production scenario; run with -- --ignored"]
fn a_skip_deferred_split_keeps_every_settlement_in_its_window_prod() {
    let setup = split_straddler_setup();
    let mut cluster =
        ProdCluster::start_with_accounts(&straddler_config(), 11, EPOCH_MS, setup.accounts);
    cluster.run_faultable(a_skip_deferred_split_keeps_every_settlement_in_its_window);
}

/// Four-shard topology whose `split_bytes` derives a `merge_bytes` bracketing
/// the genesis byte skew: the surviving pair (`leaf(2,2)`/`leaf(2,3)`, ballasted
/// clear of the floor) over it, the light merging pair (`leaf(2,0)`/`leaf(2,1)`)
/// under it, so only the merging pair auto-merges into `leaf(1,0)`. One
/// validator per host (each reshape seat its own store), three cohorts of pool
/// surplus to staff the two split generations the grow walks through, a paced
/// inter-host latency so the loadless committees track wall-clock through the
/// merge.
fn merge_straddler_config() -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 4,
        vnodes_per_host: 1,
        pool_surplus: 12,
        num_shards: 4,
        split_bytes: merge_split_bytes(&GenesisPackages::protocol()),
        latency: Duration::from_millis(60),
    }
}

#[test]
#[serial]
#[ignore = "real-QUIC production scenario; run with -- --ignored"]
fn merge_straddler_atomic_prod() {
    let setup = merge_straddler_setup();
    let mut cluster = ProdCluster::start_with_grown_accounts(
        &merge_straddler_config(),
        11,
        EPOCH_MS,
        setup.accounts,
    );
    merge_straddler_atomic(&mut cluster);
}

/// Single-shard genesis whose funded root (~43.9 KB) splits once into a
/// holding pair (~29.0 KB and ~14.6 KB, both inside the band), with two pool
/// cohorts — one grows the root, the other is the halted shard's recovery
/// committee — plus jail slack so an organic performance jail over the long
/// run can refill from the pool without starving the recovery draw. Mirrors
/// the simulation's `halt_recovery_config`. The halt takes `HALT_THRESHOLD`
/// epochs to detect, so these run tens of epochs — hours at the ci epoch
/// length, the slowest scenarios in this suite.
fn halt_recovery_config() -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 4,
        vnodes_per_host: 1,
        pool_surplus: 10,
        num_shards: 1,
        split_bytes: halt_recovery_split_bytes(),
        latency: Duration::from_millis(150),
    }
}

#[test]
#[serial]
#[ignore = "real-QUIC production scenario; run with -- --ignored"]
fn halted_shard_recovers_by_committee_redraw_prod() {
    let setup = halt_straddler_setup();
    let mut cluster =
        ProdCluster::start_with_accounts(&halt_recovery_config(), 11, EPOCH_MS, setup.accounts);
    cluster.run_faultable(halted_shard_recovers_by_committee_redraw);
}

#[test]
#[serial]
#[ignore = "real-QUIC production scenario; run with -- --ignored"]
fn halted_shard_straddler_atomic_prod() {
    let setup = halt_straddler_setup();
    let mut cluster =
        ProdCluster::start_with_accounts(&halt_recovery_config(), 11, EPOCH_MS, setup.accounts);
    cluster.run_faultable(halted_shard_straddler_atomic);
}

#[test]
#[serial]
#[ignore = "real-QUIC production scenario; run with -- --ignored"]
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
#[ignore = "real-QUIC production scenario; run with -- --ignored"]
fn delegation_folds_into_beacon_state_prod() {
    let mut cluster =
        ProdCluster::start_with_accounts(&witness_config(4), 0x57AC, EPOCH_MS, Vec::new());
    delegation_folds_into_beacon_state(&mut cluster);
}

#[test]
#[serial]
#[ignore = "real-QUIC production scenario; run with -- --ignored"]
fn register_validator_pools_a_node_prod() {
    let mut cluster =
        ProdCluster::start_with_accounts(&witness_config(4), 0x5EED, EPOCH_MS, Vec::new());
    register_validator_pools_a_node(&mut cluster);
}

#[test]
#[serial]
#[ignore = "real-QUIC production scenario; run with -- --ignored"]
fn register_without_capacity_is_rejected_prod() {
    let mut cluster =
        ProdCluster::start_with_accounts(&witness_config(4), 0x0CA9, EPOCH_MS, Vec::new());
    register_without_capacity_is_rejected(&mut cluster);
}

#[test]
#[serial]
#[ignore = "real-QUIC production scenario; run with -- --ignored"]
fn stake_withdraw_drops_effective_stake_prod() {
    let mut cluster =
        ProdCluster::start_with_accounts(&witness_config(4), 0xD7A1, EPOCH_MS, Vec::new());
    stake_withdraw_drops_effective_stake(&mut cluster);
}

#[test]
#[serial]
#[ignore = "real-QUIC production scenario; run with -- --ignored"]
fn withdrawal_ejects_a_validator_that_a_deposit_reactivates_prod() {
    let mut cluster =
        ProdCluster::start_with_accounts(&witness_config(4), 0xE1EC, EPOCH_MS, Vec::new());
    withdrawal_ejects_a_validator_that_a_deposit_reactivates(&mut cluster);
}

#[test]
#[serial]
#[ignore = "real-QUIC production scenario; run with -- --ignored"]
fn registered_validator_activates_onto_a_shard_prod() {
    let mut cluster =
        ProdCluster::start_with_accounts(&witness_config(4), 0xAC11, EPOCH_MS, Vec::new());
    registered_validator_activates_onto_a_shard(&mut cluster);
}

#[test]
#[serial]
#[ignore = "real-QUIC production scenario; run with -- --ignored"]
fn re_registration_of_a_live_validator_is_a_no_op_prod() {
    let mut cluster =
        ProdCluster::start_with_accounts(&witness_config(4), 0xDEAD, EPOCH_MS, Vec::new());
    re_registration_of_a_live_validator_is_a_no_op(&mut cluster);
}

#[test]
#[serial]
#[ignore = "real-QUIC production scenario; run with -- --ignored"]
fn pool_capacity_caps_registrations_prod() {
    let mut cluster =
        ProdCluster::start_with_accounts(&witness_config(4), 0xCA9A, EPOCH_MS, Vec::new());
    pool_capacity_caps_registrations(&mut cluster);
}

/// Single-shard genesis with the split armed and `(target - 1)` cohorts of
/// pool surplus to staff the grow's split generations, plus two spares of
/// jail slack: an organic `Performance` jail refills its committee seat from
/// the pool, which with zero slack would leave a leaf short of full strength
/// with nothing to refill from. The leftover stays below a committee's
/// worth, so split admission's pool gate can't staff another cohort and the
/// partition still stabilizes at `target` leaves. One validator per host
/// (each reshape seat needs its own store) and a paced inter-host latency so
/// the loadless committees track wall-clock through the multi-epoch grow.
const fn grow_config(target_shards: u32) -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 4,
        vnodes_per_host: 2,
        pool_surplus: (target_shards - 1) * 4 + 2,
        num_shards: 1,
        split_bytes: 0,
        latency: Duration::from_millis(60),
    }
}

#[test]
#[serial]
#[ignore = "real-QUIC production scenario; run with -- --ignored"]
fn grow_reaches_two_shard_topology_prod() {
    let mut cluster = ProdCluster::start_with_accounts(
        &grow_config(2),
        11,
        EPOCH_MS,
        reshape_lifecycle_accounts(),
    );
    grow_reaches_two_shard_topology(&mut cluster);
}

#[test]
#[serial]
#[ignore = "real-QUIC production scenario; run with -- --ignored"]
fn grow_reaches_four_shard_topology_prod() {
    let mut cluster = ProdCluster::start_with_accounts(
        &grow_config(4),
        11,
        EPOCH_MS,
        reshape_lifecycle_accounts(),
    );
    grow_reaches_four_shard_topology(&mut cluster);
}

#[test]
#[serial]
#[ignore = "real-QUIC production scenario; run with -- --ignored"]
fn merge_seats_full_keeper_committee_prod() {
    let mut cluster = ProdCluster::start_with_accounts(
        &split_config(),
        11,
        EPOCH_MS,
        reshape_lifecycle_accounts(),
    );
    merge_seats_full_keeper_committee(&mut cluster);
}

#[test]
#[serial]
#[ignore = "real-QUIC production scenario; run with -- --ignored"]
fn surviving_sibling_split_seats_full_committees_prod() {
    let setup = split_straddler_setup();
    let mut cluster =
        ProdCluster::start_with_accounts(&straddler_config(), 11, EPOCH_MS, setup.accounts);
    surviving_sibling_split_seats_full_committees(&mut cluster);
}
