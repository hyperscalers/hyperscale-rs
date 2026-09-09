//! Portable scenarios run on the simulation harness.
//!
//! Each `#[test]` builds a [`SimCluster`] and drives a `hyperscale_scenarios`
//! body. The identical body runs on production behind `#[ignore]`.

mod support;

use std::sync::Arc;
use std::time::Duration;

use hyperscale_core::ProtocolEvent;
use hyperscale_engine::genesis::GenesisPackages;
use hyperscale_node::shard::{HostEvent, ShardScopedInput};
use hyperscale_scenarios::tx::{
    CROSS_FRACTION_SENDERS, STRADDLER_SPLITTER, STRADDLER_SURVIVOR, badge_buyer,
    cross_fraction_genesis_accounts, cross_shard_fault_genesis_accounts,
    cross_shard_genesis_accounts, fixture_flash_bytes, genesis_accounts, halt_straddler_setup,
    insolvent_genesis_accounts, livelock_genesis_accounts, merge_straddler_setup,
    native_pq_genesis_accounts, nullifier_race_genesis_accounts, overdraw_genesis_accounts,
    participant_sweep_genesis_accounts, probe_train_genesis_accounts, remote_delegator,
    reshape_lifecycle_accounts, securify_genesis_accounts, shared_recipient_genesis_accounts,
    split_issuer_straddler_setup, split_straddler_setup, staking_genesis_accounts,
    stdlib_flash_bytes, storm_genesis_accounts, unbound_genesis_accounts,
    unbound_remote_genesis_accounts, withdrawal_burst_genesis_accounts,
};
use hyperscale_scenarios::{
    Cluster, FaultableCluster, MAX_REPLAY_PROBES, ScenarioConfig, WIDE_VENUE_SHARD,
    a_delivery_cut_off_past_its_window_is_reclaimed,
    a_delivery_is_reclaimed_when_its_deliverer_splits,
    a_departing_venue_clears_swaps_and_carries_on,
    a_departing_venues_terminal_hands_on_what_it_never_took, a_failed_attempt_still_attests_work,
    a_healed_network_does_not_revive_a_closed_delivery,
    a_leg_issued_on_a_departing_shard_reaches_its_venue,
    a_leg_issued_on_a_merging_shard_reaches_its_venue,
    a_leg_whose_core_never_answers_refuses_at_the_deadline,
    a_native_post_quantum_account_pays_its_own_way, a_payer_cannot_spend_one_balance_twice,
    a_published_package_matures_before_it_runs,
    a_record_is_decided_by_the_successor_when_its_issuer_splits,
    a_route_cut_off_across_its_deadline_is_not_reclaimed,
    a_route_into_a_departing_venue_releases_the_survivors_hold,
    a_route_refused_at_its_second_venue_gives_back_what_the_first_took,
    a_route_settles_across_two_venues, a_route_settles_when_its_venues_certificates_are_dropped,
    a_route_the_departing_venue_settled_is_settled_by_the_survivor,
    a_spent_nullifier_is_swept_once_unreachable, a_swap_by_a_caller_on_the_venues_shard_runs_whole,
    a_swap_charges_its_caller_its_input_and_one_price,
    a_swap_committed_after_the_venues_cut_is_disposed_once,
    a_swap_refused_at_its_inbound_leg_never_reaches_the_venue,
    a_swap_the_venue_refuses_gives_its_caller_back_its_leg,
    a_train_into_a_merging_shard_strands_nothing, a_train_into_a_splitter_strands_nothing,
    abort_converges, attested_load_reaches_the_beacon,
    beacon_lag_drops_skipped_epochs_reveal_chains, beacon_pool_partition_stalls_epoch_production,
    cross_shard_compound_drop_fetch_fallback, cross_shard_credit_survives_a_later_local_credit,
    cross_shard_exec_cert_drop_is_inert, cross_shard_fraction, cross_shard_header_fetch_fallback,
    cross_shard_provisions_drop_fetch_fallback, cross_shard_provisions_fetch_with_request_loss,
    cross_shard_provisions_recovers_after_transient_outage,
    cross_shard_transaction_da_fetch_fallback, cross_shard_transfer,
    delegation_folds_into_beacon_state, departing_caller_ballast, departing_route_genesis_accounts,
    departing_venue_ballast, departing_venue_split_bytes, deploy_storm_rides_out, epochs,
    events_land_on_their_emitters_home_shard, failure_charges_its_payer,
    gossip_drop_engages_fetch_fallback, grow_reaches_four_shard_topology,
    grow_reaches_two_shard_topology, halted_shard_recovers_by_committee_redraw,
    halted_shard_straddler_atomic, hot_recipient, hot_venue_clears_swaps,
    hot_venue_clears_swaps_on, insolvent_payer_engages_nothing,
    inter_shard_partition_strands_ticks_until_it_heals, isolated_validator_still_settles,
    livelock_resolves_promptly, liveness_baseline, merge_boundary_admits_an_uncommitted_precut_tx,
    merge_lifecycle, merge_seats_full_keeper_committee, merge_straddler_atomic,
    merge_train_genesis_accounts, merging_caller_genesis_accounts,
    minority_fragment_rejoins_after_partition, multi_vnode_progress,
    nullifier_race_admits_exactly_one, participant_count_sweep, partition_halts_and_heals,
    partition_heals_at_exact_quorum, pool_capacity_caps_registrations,
    pool_transfer_moves_operatorship, preview_reports_resource_changes,
    re_registration_of_a_live_validator_is_a_no_op, reads_the_committed_baseline,
    register_validator_pools_a_node, register_without_capacity_is_rejected,
    registered_validator_activates_onto_a_shard, route_genesis_accounts,
    sealed_rounds_settle_on_the_seed_they_committed_to,
    securify_retires_the_key_at_the_payer_shard, single_transfer,
    split_boundary_admits_an_uncommitted_precut_tx,
    split_boundary_hands_back_what_it_never_included, split_boundary_refuses_a_replay,
    split_lifecycle, split_straddler_atomic, split_straddler_ec_partition_atomic,
    split_train_genesis_accounts, stake_withdraw_drops_effective_stake,
    surviving_sibling_split_seats_full_committees, unbound_payer_engages_nothing,
    unbound_remote_payer_engages_nothing, venue_genesis_accounts, venue_genesis_accounts_on,
    wide_swapper_shards, withdrawal_ejects_a_validator_that_a_deposit_reactivates,
    withdrawals_compose_over_one_vault, zipf_payments,
};
use hyperscale_simulation::ExecutionMode;
use hyperscale_storage::ShardChainReader;
use hyperscale_types::test_utils::shard_fork_proof_signed_by;
use hyperscale_types::{
    BlockHash, BlockHeight, NetworkDefinition, PrincipalAddr, RecoveryCause, Round, ShardForkProof,
    ShardId, Timeout,
};
use support::SimCluster;

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
fn gossip_drop_engages_fetch_fallback_sim() {
    let mut cluster = SimCluster::with_accounts(&liveness_config(), 42, &genesis_accounts(1, 1));
    cluster.run_faultable(gossip_drop_engages_fetch_fallback);
}

#[test]
fn partition_halts_and_heals_sim() {
    let mut cluster = SimCluster::new(&liveness_config(), 42);
    cluster.run_faultable(partition_halts_and_heals);
}

#[test]
fn isolated_validator_still_settles_sim() {
    let mut cluster = SimCluster::with_accounts(&liveness_config(), 42, &genesis_accounts(1, 1));
    cluster.run_faultable(isolated_validator_still_settles);
}

/// Everything `livelock_resolves_promptly` needs funded: it composes
/// `split_lifecycle`, so the probe transfer's accounts come along with
/// the conflicting pair's.
fn livelock_accounts() -> Vec<(PrincipalAddr, u128)> {
    let mut accounts = genesis_accounts(1, 1);
    accounts.extend(livelock_genesis_accounts());
    accounts
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
    let mut cluster = SimCluster::with_accounts(&split_config(), 11, &genesis_accounts(1, 1));
    split_lifecycle(&mut cluster);
}

#[test]
fn split_boundary_refuses_a_replay_sim() {
    let mut cluster = SimCluster::with_accounts(
        &split_config(),
        11,
        &probe_train_genesis_accounts(MAX_REPLAY_PROBES),
    );
    split_boundary_refuses_a_replay(&mut cluster);
}

#[test]
fn split_boundary_hands_back_what_it_never_included_sim() {
    let mut cluster =
        SimCluster::with_accounts(&split_config(), 11, &probe_train_genesis_accounts(4));
    split_boundary_hands_back_what_it_never_included(&mut cluster);
}

#[test]
fn split_boundary_admits_an_uncommitted_precut_tx_sim() {
    let mut cluster = SimCluster::with_accounts(
        &split_config(),
        11,
        &probe_train_genesis_accounts(MAX_REPLAY_PROBES),
    );
    split_boundary_admits_an_uncommitted_precut_tx(&mut cluster);
}

// ─── Engine scenarios ───────────────────────────────────────────────
// The single-shard catalogue on the engine: signed manifest graphs
// through the live pipeline, receipts from the batch executor.

#[test]
fn single_transfer_sim() {
    let mut cluster = SimCluster::with_accounts(&liveness_config(), 42, &genesis_accounts(1, 1));
    single_transfer(&mut cluster);
}

#[test]
fn a_spent_nullifier_is_swept_once_unreachable_sim() {
    let mut cluster =
        SimCluster::with_accounts(&liveness_config(), 42, &nullifier_race_genesis_accounts());
    a_spent_nullifier_is_swept_once_unreachable(&mut cluster);
}

#[test]
fn nullifier_race_admits_exactly_one_sim() {
    let mut cluster =
        SimCluster::with_accounts(&liveness_config(), 42, &nullifier_race_genesis_accounts());
    nullifier_race_admits_exactly_one(&mut cluster);
}

#[test]
fn a_failed_attempt_still_attests_work_sim() {
    let mut cluster = SimCluster::with_accounts(&liveness_config(), 42, &genesis_accounts(1, 1));
    a_failed_attempt_still_attests_work(&mut cluster);
}

#[test]
fn failure_charges_its_payer_sim() {
    let mut cluster = SimCluster::with_accounts(&liveness_config(), 42, &genesis_accounts(1, 1));
    failure_charges_its_payer(&mut cluster);
}

#[test]
fn preview_reports_resource_changes_sim() {
    let mut cluster = SimCluster::with_accounts(&liveness_config(), 42, &genesis_accounts(1, 1));
    preview_reports_resource_changes(&mut cluster);
}

#[test]
fn abort_converges_sim() {
    let mut cluster = SimCluster::with_accounts(&liveness_config(), 42, &genesis_accounts(1, 1));
    abort_converges(&mut cluster);
}

#[test]
fn reads_the_committed_baseline_sim() {
    let mut cluster = SimCluster::with_accounts(&liveness_config(), 42, &genesis_accounts(2, 1));
    reads_the_committed_baseline(&mut cluster);
}

#[test]
fn zipf_payments_sim() {
    let mut cluster = SimCluster::with_accounts(&liveness_config(), 42, &genesis_accounts(24, 6));
    let report = cluster.run_faultable(|c| zipf_payments(c, 24, 6, 1.0));
    let executed = cluster.metric("transactions_executed", None);
    println!("zipf_payments s=1.0 senders=24 recipients=6 executed={executed}: {report:?}");
}

/// Two shards, no reshape pressure: one split generation seats the
/// second committee from the pool surplus, then the threshold disarms.
const fn cross_shard_config() -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 4,
        vnodes_per_host: 1,
        pool_surplus: 4,
        num_shards: 2,
        split_bytes: u64::MAX,
        latency: Duration::from_millis(150),
    }
}

#[test]
fn cross_shard_transfer_sim() {
    let mut cluster =
        SimCluster::with_grown_accounts(&cross_shard_config(), 42, &cross_shard_genesis_accounts());
    cross_shard_transfer(&mut cluster);
}

#[test]
fn cross_shard_credit_survives_a_later_local_credit_sim() {
    let mut cluster = SimCluster::with_grown_accounts(
        &cross_shard_config(),
        42,
        &shared_recipient_genesis_accounts(),
    );
    cross_shard_credit_survives_a_later_local_credit(&mut cluster);
}

#[test]
fn a_payer_cannot_spend_one_balance_twice_sim() {
    let mut cluster =
        SimCluster::with_grown_accounts(&cross_shard_config(), 42, &overdraw_genesis_accounts());
    a_payer_cannot_spend_one_balance_twice(&mut cluster);
}

#[test]
fn a_published_package_matures_before_it_runs_sim() {
    let mut cluster =
        SimCluster::with_grown_accounts(&cross_shard_config(), 42, &storm_genesis_accounts());
    a_published_package_matures_before_it_runs(&mut cluster);
}

#[test]
fn deploy_storm_rides_out_sim() {
    let mut cluster =
        SimCluster::with_grown_accounts(&cross_shard_config(), 42, &storm_genesis_accounts());
    deploy_storm_rides_out(&mut cluster);
}

#[test]
fn events_land_on_their_emitters_home_shard_sim() {
    let mut cluster =
        SimCluster::with_grown_accounts(&cross_shard_config(), 42, &cross_shard_genesis_accounts());
    events_land_on_their_emitters_home_shard(&mut cluster);
}

#[test]
fn attested_load_reaches_the_beacon_sim() {
    let mut cluster =
        SimCluster::with_grown_accounts(&cross_shard_config(), 42, &cross_shard_genesis_accounts());
    attested_load_reaches_the_beacon(&mut cluster);
}

#[test]
fn sealed_rounds_settle_on_the_seed_they_committed_to_sim() {
    // The one scenario that calls a fixture package, so the one network
    // born running it.
    let mut cluster = SimCluster::with_grown_packages(
        &cross_shard_config(),
        42,
        &cross_shard_genesis_accounts(),
        GenesisPackages::with_fixtures(),
    );
    sealed_rounds_settle_on_the_seed_they_committed_to(&mut cluster);
}

/// A venue on one shard and its callers on the other, over a network
/// born running the fixture packages the venue is built from.
fn venue_cluster(seed: u64) -> SimCluster {
    SimCluster::with_grown_packages(
        &cross_shard_config(),
        seed,
        &venue_genesis_accounts(),
        GenesisPackages::with_fixtures(),
    )
}

/// Two venues on two shards and the traders on a third.
fn route_cluster() -> SimCluster {
    SimCluster::with_grown_packages(
        &ScenarioConfig {
            num_shards: 4,
            pool_surplus: 14,
            ..cross_shard_config()
        },
        42,
        &route_genesis_accounts(),
        GenesisPackages::with_fixtures(),
    )
}

/// A venue on one quarter of a four-shard world and its callers spread
/// over the other three.
fn wide_venue_cluster(seed: u64) -> SimCluster {
    SimCluster::with_grown_packages(
        &ScenarioConfig {
            num_shards: 4,
            pool_surplus: 14,
            ..cross_shard_config()
        },
        seed,
        &venue_genesis_accounts_on(WIDE_VENUE_SHARD, &wide_swapper_shards()),
        GenesisPackages::with_fixtures(),
    )
}

/// TEMPORARY seed sweep over the fan-in bar.
/// The seeds the fan-in bar is read over.
///
/// One reading is not a measurement. Per seed the fanned-in queue lands
/// anywhere from eight blocks under the single-caller one to sixteen
/// over, because what either queue costs in blocks depends on where the
/// last swap falls against the venue's cadence. A bar one seed satisfies
/// says nothing about the next. Summed, the readings settle — and the
/// sum is what the claim is about anyway, since a per-caller cost would
/// show on every seed rather than on some.
const FAN_IN_SEEDS: [u64; 4] = [42, 7, 11, 1337];

/// The fan-in bar: a venue priced from three caller shards clears its
/// queue no slower than one priced from a single caller shard. A venue's
/// cost is the hold on its own cells, not a round trip per caller, and
/// this is the property a regression eats first.
///
/// Measured in the venue's own blocks, not in clock readings. The
/// harness samples once a second and each queue drains in six to eight
/// of those, so a clock bar loose enough to survive the two epoch clocks
/// is loose enough to admit the whole regression it exists to catch. The
/// venue's chain commits many times a second, so its own height is the
/// finer instrument.
///
/// The bar is the design table's own figure: a round trip per caller
/// would cost a third of the queue, and three callers would show it
/// three times over. What the four seeds read is under a fifth of that.
#[test]
fn a_hot_venue_clears_swaps_no_slower_fanned_in_sim() {
    let mut single = 0;
    let mut fanned = 0;
    for seed in FAN_IN_SEEDS {
        let mut narrow = venue_cluster(seed);
        single += hot_venue_clears_swaps(&mut narrow, epochs(40)).blocks;
        let mut wide = wide_venue_cluster(seed);
        fanned += hot_venue_clears_swaps_on(
            &mut wide,
            WIDE_VENUE_SHARD,
            &wide_swapper_shards(),
            epochs(40),
        )
        .blocks;
    }
    assert!(
        fanned * 3 <= single * 4,
        "fan-in from three caller shards must not cost a third of the queue: \
         {fanned} blocks against {single} over {} seeds",
        FAN_IN_SEEDS.len(),
    );
}

#[test]
fn a_swap_charges_its_caller_its_input_and_one_price_sim() {
    let mut cluster = venue_cluster(42);
    a_swap_charges_its_caller_its_input_and_one_price(&mut cluster, epochs(40));
}

#[test]
fn a_swap_by_a_caller_on_the_venues_shard_runs_whole_sim() {
    let mut cluster = venue_cluster(42);
    a_swap_by_a_caller_on_the_venues_shard_runs_whole(&mut cluster, epochs(40));
}

#[test]
fn a_swap_the_venue_refuses_gives_its_caller_back_its_leg_sim() {
    let mut cluster = venue_cluster(42);
    a_swap_the_venue_refuses_gives_its_caller_back_its_leg(&mut cluster, epochs(40));
}

#[test]
fn a_swap_refused_at_its_inbound_leg_never_reaches_the_venue_sim() {
    let mut cluster = venue_cluster(42);
    a_swap_refused_at_its_inbound_leg_never_reaches_the_venue(&mut cluster, epochs(40));
}

#[test]
fn a_route_settles_across_two_venues_sim() {
    let mut cluster = route_cluster();
    let report = a_route_settles_across_two_venues(&mut cluster, epochs(40));
    println!(
        "two-venue route: {} routes settled in {:?}",
        report.submitted, report.elapsed,
    );
}

#[test]
fn a_route_settles_when_its_venues_certificates_are_dropped_sim() {
    let mut cluster = route_cluster();
    cluster.run_faultable(a_route_settles_when_its_venues_certificates_are_dropped);
}

/// [`route_cluster`] with every committee on hosts of its own, for a cut
/// keyed on the venues' hosts.
fn route_cluster_on_dedicated_hosts() -> SimCluster {
    SimCluster::with_grown_packages_on_dedicated_pool_hosts(
        &ScenarioConfig {
            num_shards: 4,
            pool_surplus: 14,
            ..cross_shard_config()
        },
        42,
        &route_genesis_accounts(),
        GenesisPackages::with_fixtures(),
    )
}

#[test]
fn a_route_cut_off_across_its_deadline_is_not_reclaimed_sim() {
    let mut cluster = route_cluster_on_dedicated_hosts();
    cluster.run_faultable(a_route_cut_off_across_its_deadline_is_not_reclaimed);
}

/// A second seat of [`a_route_cut_off_across_its_deadline_is_not_reclaimed`].
///
/// Whether the first venue obtains its core sibling's verdict before the
/// retirement is certified is a race the cluster's seat decides, and 42
/// wins it. This seed loses it, which is what a transaction index holding
/// one certificate per transaction turns into a permanent strand of the
/// route's input.
#[test]
fn a_route_cut_off_across_its_deadline_is_not_reclaimed_seed_19_sim() {
    let mut cluster = SimCluster::with_grown_packages_on_dedicated_pool_hosts(
        &ScenarioConfig {
            num_shards: 4,
            pool_surplus: 14,
            ..cross_shard_config()
        },
        19,
        &route_genesis_accounts(),
        GenesisPackages::with_fixtures(),
    );
    cluster.run_faultable(a_route_cut_off_across_its_deadline_is_not_reclaimed);
}

#[test]
fn a_route_refused_at_its_second_venue_gives_back_what_the_first_took_sim() {
    let mut cluster = route_cluster();
    a_route_refused_at_its_second_venue_gives_back_what_the_first_took(&mut cluster, epochs(40));
}

#[test]
fn a_delivery_cut_off_past_its_window_is_reclaimed_sim() {
    let mut cluster =
        SimCluster::with_grown_accounts(&cross_shard_config(), 42, &cross_shard_genesis_accounts());
    cluster.run_faultable(a_delivery_cut_off_past_its_window_is_reclaimed);
}

#[test]
fn a_healed_network_does_not_revive_a_closed_delivery_sim() {
    let mut cluster =
        SimCluster::with_grown_accounts(&cross_shard_config(), 42, &cross_shard_genesis_accounts());
    cluster.run_faultable(a_healed_network_does_not_revive_a_closed_delivery);
}

#[test]
fn a_leg_whose_core_never_answers_refuses_at_the_deadline_sim() {
    let mut cluster = SimCluster::with_grown_accounts(
        &cross_shard_config(),
        42,
        &[(remote_delegator().1, 1_000_000)],
    );
    cluster.run_faultable(a_leg_whose_core_never_answers_refuses_at_the_deadline);
}

#[test]
fn insolvent_payer_engages_nothing_sim() {
    let mut cluster =
        SimCluster::with_grown_accounts(&cross_shard_config(), 42, &insolvent_genesis_accounts());
    insolvent_payer_engages_nothing(&mut cluster);
}

#[test]
fn unbound_payer_engages_nothing_sim() {
    let mut cluster =
        SimCluster::with_grown_accounts(&cross_shard_config(), 42, &unbound_genesis_accounts());
    unbound_payer_engages_nothing(&mut cluster);
}

#[test]
fn unbound_remote_payer_engages_nothing_sim() {
    let mut cluster = SimCluster::with_grown_accounts(
        &cross_shard_config(),
        42,
        &unbound_remote_genesis_accounts(),
    );
    unbound_remote_payer_engages_nothing(&mut cluster);
}

#[test]
fn securify_retires_the_key_at_the_payer_shard_sim() {
    let mut cluster =
        SimCluster::with_grown_accounts(&cross_shard_config(), 42, &securify_genesis_accounts());
    securify_retires_the_key_at_the_payer_shard(&mut cluster);
}

#[test]
fn a_native_post_quantum_account_pays_its_own_way_sim() {
    let mut cluster =
        SimCluster::with_grown_accounts(&cross_shard_config(), 42, &native_pq_genesis_accounts());
    a_native_post_quantum_account_pays_its_own_way(&mut cluster);
}

#[test]
fn hot_recipient_sim() {
    let mut cluster = SimCluster::with_accounts(&liveness_config(), 42, &genesis_accounts(12, 1));
    let (report, height_span) = cluster.run_faultable(|c| hot_recipient(c, 12));
    let executed = cluster.metric("transactions_executed", None);
    println!("hot_recipient senders=12 height_span={height_span} executed={executed}: {report:?}");
}

#[test]
fn withdrawals_compose_over_one_vault_sim() {
    let mut cluster = SimCluster::with_accounts(
        &liveness_config(),
        42,
        &withdrawal_burst_genesis_accounts(50),
    );
    let blocks = cluster.run_faultable(|c| withdrawals_compose_over_one_vault(c, 50));
    println!("withdrawals_compose_over_one_vault count=50 blocks={blocks}");
}

/// Deterministic parallel tick execution on committed blocks: one seed,
/// serial vs parallel batch scheduling, identical committed state
/// roots. Receipts are
/// schedule-invariant by kernel construction; this pins that the
/// property survives the whole pipeline — fold, receipt hashing, JMT
/// build, commit.
#[test]
fn serial_parallel_state_roots_agree_sim() {
    let run = |mode| {
        let mut cluster =
            SimCluster::with_execution_mode(&liveness_config(), 42, &genesis_accounts(8, 2), mode);
        let report = zipf_payments(&mut cluster, 8, 2, 1.0);
        println!("vm d16 mode={mode:?}: {report:?}");
        (
            cluster.committed_height(ShardId::ROOT),
            cluster.committed_state_root(ShardId::ROOT),
        )
    };
    let serial = run(ExecutionMode::Serial);
    let parallel = run(ExecutionMode::Parallel);
    assert_eq!(
        serial, parallel,
        "serial and parallel VM scheduling must commit identical chains",
    );
    assert!(
        serial.1.is_some(),
        "the seeded run must commit a state root"
    );
}

// ─── Contention scenarios ──────────────────────────────────────────────
// CI pins one point per family; the parameterized bodies carry the full
// sweeps for workstation runs. Reports print for the phase record.

#[test]
fn cross_shard_fraction_sim() {
    let mut cluster = SimCluster::with_accounts(
        &split_config(),
        11,
        &cross_fraction_genesis_accounts(CROSS_FRACTION_SENDERS),
    );
    let report = cluster.run_faultable(|c| cross_shard_fraction(c, CROSS_FRACTION_SENDERS, 500));
    let executed = cluster.metric("transactions_executed", None);
    println!("cross_shard_fraction total=16 cross=50% executed={executed}: {report:?}");
}

/// Four stable leaves for the participant sweep: grown like
/// [`grow_config`] seats it, then the threshold disarms so the sweep
/// runs on a settled topology rather than a hair-trigger one.
const fn sweep_config() -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 4,
        vnodes_per_host: 1,
        pool_surplus: 14,
        num_shards: 4,
        split_bytes: u64::MAX,
        latency: Duration::from_millis(150),
    }
}

#[test]
fn participant_count_sweep_sim() {
    // The lifecycle ballast keeps the grow's split generations in step
    // (the sweep accounts alone would skew the byte spread); the sweep
    // walk funds the payer plus one recipient per leaf. Four leaves so
    // the sweep reaches a genuine fan-out — three recipients on three
    // counterparty shards — rather than stopping at the pairwise case.
    let accounts = [
        reshape_lifecycle_accounts(),
        participant_sweep_genesis_accounts(4),
    ]
    .concat();
    let mut cluster = SimCluster::with_grown_accounts(&sweep_config(), 11, &accounts);
    let latencies = participant_count_sweep(&mut cluster, 4, 4);
    println!("participant_count_sweep shards=4: {latencies:?}");
}

#[test]
fn cross_shard_provisions_drop_fetch_fallback_sim() {
    let mut cluster = SimCluster::with_execution_mode(
        &split_config(),
        11,
        &cross_shard_fault_genesis_accounts(),
        ExecutionMode::Serial,
    );
    cluster.run_faultable(cross_shard_provisions_drop_fetch_fallback);
}

#[test]
fn cross_shard_exec_cert_drop_is_inert_sim() {
    let mut cluster = SimCluster::with_execution_mode(
        &split_config(),
        11,
        &cross_shard_fault_genesis_accounts(),
        ExecutionMode::Serial,
    );
    cluster.run_faultable(cross_shard_exec_cert_drop_is_inert);
}

#[test]
fn cross_shard_transaction_da_fetch_fallback_sim() {
    let mut cluster = SimCluster::with_execution_mode(
        &split_config(),
        11,
        &cross_shard_fault_genesis_accounts(),
        ExecutionMode::Serial,
    );
    cluster.run_faultable(cross_shard_transaction_da_fetch_fallback);
}

#[test]
fn cross_shard_header_fetch_fallback_sim() {
    let mut cluster = SimCluster::with_execution_mode(
        &split_config(),
        11,
        &cross_shard_fault_genesis_accounts(),
        ExecutionMode::Serial,
    );
    cluster.run_faultable(cross_shard_header_fetch_fallback);
}

#[test]
fn cross_shard_compound_drop_fetch_fallback_sim() {
    let mut cluster = SimCluster::with_execution_mode(
        &split_config(),
        11,
        &cross_shard_fault_genesis_accounts(),
        ExecutionMode::Serial,
    );
    cluster.run_faultable(cross_shard_compound_drop_fetch_fallback);
}

#[test]
fn cross_shard_provisions_recovers_after_transient_outage_sim() {
    let mut cluster = SimCluster::with_execution_mode(
        &split_config(),
        11,
        &cross_shard_fault_genesis_accounts(),
        ExecutionMode::Serial,
    );
    cluster.run_faultable(cross_shard_provisions_recovers_after_transient_outage);
}

#[test]
fn inter_shard_partition_strands_ticks_until_it_heals_sim() {
    // A dedicated host per pool validator, so the split seats the two children on
    // disjoint host sets — matching production's one-validator-per-host layout —
    // and a host partition can sever every inter-shard edge without cutting
    // intra-shard consensus.
    let mut cluster = SimCluster::with_accounts_and_dedicated_pool_hosts(
        &split_config(),
        11,
        &cross_shard_fault_genesis_accounts(),
    );
    cluster.run_faultable(inter_shard_partition_strands_ticks_until_it_heals);
}

#[test]
fn beacon_pool_partition_stalls_epoch_production_sim() {
    let mut cluster = SimCluster::with_dedicated_pool_hosts(&split_config(), 11);
    cluster.run_faultable(beacon_pool_partition_stalls_epoch_production);
}

/// Single-shard genesis wide enough that the members off the beacon committee
/// still form the pool quorum a skip block needs — the beacon must keep
/// committing (as skips) while its commit channels are down, so the shard
/// stays live and keeps crossing epoch cuts through the outage.
const fn beacon_lag_config() -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 8,
        vnodes_per_host: 1,
        pool_surplus: 0,
        num_shards: 1,
        split_bytes: u64::MAX,
        latency: Duration::from_millis(150),
    }
}

#[test]
fn beacon_lag_drops_skipped_epochs_reveal_chains_sim() {
    let mut cluster = SimCluster::new(&beacon_lag_config(), 42);
    cluster.run_faultable(beacon_lag_drops_skipped_epochs_reveal_chains);
}

/// Single-shard genesis armed so the funded root (~43.9 KB) splits exactly
/// once and the grown pair holds — each child (~29.0 KB and ~14.6 KB) sits
/// between the derived merge floor and the split threshold — with two
/// cohorts of pool surplus — one grows the root,
/// the other is the halted shard's recovery committee — plus two spares of
/// jail slack: the recovery draw needs a full free committee, and over the
/// scenario's ~40 epochs an organic `Performance` jail on the healthy shard
/// refills its seat from the pool, which with zero slack would starve the
/// draw and park the recovery.
fn halt_recovery_config() -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 4,
        vnodes_per_host: 1,
        pool_surplus: 14,
        num_shards: 1,
        // Above the flash-holding child's ballast-plus-flash total and
        // below the root's sum, so the root splits exactly once and the
        // grown pair holds through the halt.
        split_bytes: stdlib_flash_bytes() + 20_000,
        latency: Duration::from_millis(150),
    }
}

#[test]
fn halted_shard_recovers_by_committee_redraw_sim() {
    let setup = halt_straddler_setup();
    let mut cluster = SimCluster::with_accounts_and_dedicated_pool_hosts(
        &halt_recovery_config(),
        11,
        &setup.accounts,
    );
    cluster.run_faultable(halted_shard_recovers_by_committee_redraw);
}

/// Assert straddler atomicity across a halted shard's recovery at `seed`. The
/// seed draws both the committees and the network ordering, so each one races
/// the straddler's settlement against the re-draw differently.
fn halted_shard_straddler_atomic_at_seed(seed: u64) {
    let setup = halt_straddler_setup();
    let mut cluster = SimCluster::with_accounts_and_dedicated_pool_hosts(
        &halt_recovery_config(),
        seed,
        &setup.accounts,
    );
    cluster.run_faultable(halted_shard_straddler_atomic);
}

#[test]
fn halted_shard_straddler_atomic_seed_7_sim() {
    halted_shard_straddler_atomic_at_seed(7);
}

#[test]
fn halted_shard_straddler_atomic_seed_11_sim() {
    halted_shard_straddler_atomic_at_seed(11);
}

#[test]
fn halted_shard_straddler_atomic_seed_42_sim() {
    halted_shard_straddler_atomic_at_seed(42);
}

#[test]
fn halted_shard_straddler_atomic_seed_1337_sim() {
    halted_shard_straddler_atomic_at_seed(1337);
}

#[test]
fn halted_shard_straddler_atomic_seed_2026_sim() {
    halted_shard_straddler_atomic_at_seed(2026);
}

/// A provable committee-level fork drives the same full re-draw a halt does,
/// and the fresh committee seeds from the beacon-attested frontier while both
/// branches' retained signals stay live.
///
/// There is no Byzantine consensus stack in the harness to run two live heads
/// (deferred, as the halt plan defers its local-orphan gap), so the loud path
/// is exercised by synthesizing a `ConflictingCommits` proof — signed by the
/// shard's *live* committee keys so it authenticates against the running
/// topology exactly as an organically assembled one would — and injecting it
/// on the real gossip ingress. From there it rides the production pipeline:
/// verify, engage the local fences, re-gossip, the beacon buffers and folds
/// it, and `RecoveryCause::Fork` re-draws the committee.
///
/// The forked committee is *not* silenced. Its halves are vote-partitioned so
/// neither can certify (the fork's real aftermath — a committee split across
/// two branches makes no further progress), but every member keeps gossiping
/// timeouts, and after the re-draw the retained members' timeouts are
/// re-injected carrying the two branch-head QCs from the proof itself — the
/// divergent retained tips a real fork leaves behind. The incomers must
/// refuse both (a forked retained committee has no unique tip), seed from the
/// attested frontier, and converge: the fresh chain's first block extends the
/// beacon-attested anchor, not either branch and not the unattested retained
/// suffix above the frontier.
#[test]
#[allow(clippy::too_many_lines)] // one scripted fault scenario end to end
fn shard_fork_drives_committee_recovery_sim() {
    let setup = halt_straddler_setup();
    let mut cluster = SimCluster::with_accounts_and_dedicated_pool_hosts(
        &halt_recovery_config(),
        11,
        &setup.accounts,
    );
    // Grow to two children before injecting the fork. Recovering the sole
    // ROOT committee would starve beacon epoch production: in a single-shard
    // topology the beacon committee *is* the ROOT committee, so re-drawing it
    // leaves no seated validator to ratify the next epoch and the whole chain
    // wedges. A child fork keeps the beacon — seated across the other active
    // validators — live to drive the recovery to completion, and is the
    // realistic shape besides (the loud path funnels a child's fork proof).
    split_lifecycle(&mut cluster);
    let (shard, _sibling) = ShardId::ROOT.children();

    // Warm up until the beacon has folded a real boundary for the shard, not
    // just until it commits a few blocks. The fork-caused re-draw seats the
    // fresh committee against the shard's attested boundary anchor and skips a
    // shard still on its genesis ZERO placeholder (a shard that never
    // produced needs an operator, not a rotation). A committed-height check
    // alone races ahead of the first epoch crossing's fold, so the proof would
    // fold while the boundary is still ZERO and the recovery would never arm.
    assert!(
        cluster.run_until(epochs(8), |c| c.beacon_state().is_some_and(|s| s
            .boundaries
            .get(&shard)
            .is_some_and(|b| b.block_hash != BlockHash::ZERO))),
        "the shard must fold a real boundary before the fork is injected"
    );
    let frozen = cluster
        .committed_height(shard)
        .expect("root committed")
        .inner();
    let member = cluster
        .committee_hosts(shard)
        .into_iter()
        .next()
        .expect("root has a committee host");
    let member = u32::try_from(member).expect("host index fits a node index");

    // Build a proof that authenticates against the live committee: resolve the
    // seated committee (and the anchor weighted timestamp that resolves it)
    // from a real committed tip, sign both branches with those seats' keys,
    // and confirm it verifies against the running schedule before injecting —
    // a wrong committee or timestamp would silently never fold.
    let proof = {
        let runner = cluster.runner();
        let vnode = runner
            .first_vnode_state(member)
            .expect("committee host runs a vnode");
        let schedule = vnode.beacon_coordinator().topology_schedule();
        let storage = runner
            .hosts_shard(member, shard)
            .expect("committee host serves the shard");
        let tip = storage
            .get_certified_header(storage.committed_height())
            .expect("committed tip header");
        let wt = tip.header().parent_qc().weighted_timestamp();
        let (snapshot, _bridged) = schedule
            .at_for_shard_certified(shard, wt, wt)
            .expect("the committed tip's committee resolves");
        let keys: Vec<_> = snapshot
            .consensus_committee_for_shard(shard)
            .iter()
            .map(|v| {
                runner
                    .validator_signer(*v)
                    .expect("seated validator has a signing key")
            })
            .collect();
        let verifier = runner.verifier();
        let proof = shard_fork_proof_signed_by(
            verifier.as_ref(),
            &keys,
            shard,
            BlockHeight::new(frozen + 1),
            wt,
        );
        proof
            .verify(verifier.as_ref(), schedule)
            .expect("synthesized fork proof verifies against the live schedule");
        proof
    };
    // The proof's two branch heads are the divergent retained tips the
    // ex-members' timeouts will carry after the re-draw.
    let branch_qcs = {
        let ShardForkProof::ConflictingCommits { a, b } = &proof;
        [a.certified().qc().clone(), b.certified().qc().clone()]
    };

    // Split the committee's votes down the middle so neither half reaches
    // quorum — the fork's aftermath, a committee whose halves back different
    // branches and can certify on neither. Nothing else is cut: headers,
    // timeouts, and the global fork-proof gossip keep flowing, so the forked
    // committee stays loud while the recovery runs.
    let committee = cluster.committee_hosts(shard);
    let half_a: Vec<usize> = committee[..2].to_vec();
    let rest: Vec<usize> = (0..cluster.host_count())
        .filter(|h| !half_a.contains(h))
        .collect();
    cluster.drop_type_between(&rest, &half_a, "block.vote");
    cluster.drop_type_between(&half_a, &rest, "block.vote");
    cluster.run_until(epochs(1), |_| false);

    // Inject on the real gossip ingress of a committee member. The fork-proof
    // gossip is global scope, so the silenced committee still relays it to the
    // beacon proposers that fold the recovery.
    cluster.runner_mut().schedule_initial_event(
        member,
        Duration::ZERO,
        HostEvent::shard(
            shard,
            ShardScopedInput::ShardForkProofGossipReceived {
                proof: Arc::new(proof),
            },
        ),
    );

    // The beacon folds a fork-caused recovery.
    assert!(
        cluster.run_until(epochs(30), |c| c.beacon_state().is_some_and(|s| s
            .pending_recoveries
            .get(&shard)
            .map(|r| r.cause)
            == Some(RecoveryCause::Fork))),
        "the fork proof must fold a RecoveryCause::Fork recovery"
    );

    // The fold pinned the recovery to the beacon-attested frontier. Capture
    // the anchor the fresh chain must extend and the retained membership the
    // incomers' refusal is keyed on.
    let (frontier, anchor, retained) = {
        let state = cluster.beacon_state().expect("beacon state committed");
        let recovery = state
            .pending_recoveries
            .get(&shard)
            .expect("fork recovery pending");
        let boundary = state.boundaries.get(&shard).expect("boundary recorded");
        assert_eq!(
            boundary.height, recovery.attested_frontier,
            "the fork fence must hold the boundary at the attested frontier",
        );
        (
            recovery.attested_frontier,
            boundary.block_hash,
            recovery.retained.clone(),
        )
    };

    // Keep the forked committee loud through the seeding window: every epoch,
    // re-deliver retained-member timeouts carrying the two branch-head QCs on
    // the production gossip ingress — the divergent tips a real fork leaves
    // in its ex-members' pacemakers. Delivery is audience-separated (each
    // host hears only one branch's carriers), the split-audience shape in
    // which harvesting a retained tip would seed the incomers onto divergent
    // branches. The incomers must refuse the retained suffix wholesale and
    // still resume past the frozen suffix from the frontier alone.
    let net = NetworkDefinition::simulator();
    let timeouts: Vec<Timeout> = retained
        .iter()
        .zip(branch_qcs.iter().cycle())
        .map(|(&voter, qc)| {
            let key = cluster
                .runner()
                .validator_signer(voter)
                .expect("retained validator has a signing key");
            Timeout::new(&net, shard, Round::new(1), qc.clone(), voter, key.as_ref()).expect("sign")
        })
        .collect();
    let resumed = (0..10).any(|_| {
        for (branch, timeout) in timeouts.iter().enumerate() {
            for host in (0..cluster.host_count()).filter(|host| host % 2 == branch % 2) {
                cluster.runner_mut().schedule_initial_event(
                    u32::try_from(host).expect("host index fits a node index"),
                    Duration::ZERO,
                    HostEvent::shard(
                        shard,
                        ShardScopedInput::Protocol(Box::new(
                            ProtocolEvent::UnverifiedTimeoutReceived {
                                timeout: timeout.clone(),
                            },
                        )),
                    ),
                );
            }
        }
        cluster.run_until(epochs(4), |c| {
            c.committed_height(shard)
                .is_some_and(|h| h.inner() > frozen + 1)
        })
    });
    assert!(
        resumed,
        "the recovered shard must resume committing under its fresh committee"
    );
    assert!(
        cluster.run_until(epochs(30), |c| c
            .beacon_state()
            .is_some_and(|s| !s.pending_recoveries.contains_key(&shard))),
        "the fresh committee's crossing must clear the fork recovery"
    );

    // The fresh chain's first block extends the beacon-attested anchor — not
    // either branch head, and not the retained committee's unattested suffix
    // above the frontier.
    let fresh_host = cluster
        .committee_hosts(shard)
        .into_iter()
        .next()
        .expect("recovered shard has a live committee host");
    let storage = cluster
        .runner()
        .hosts_shard(
            u32::try_from(fresh_host).expect("host index fits a node index"),
            shard,
        )
        .expect("fresh committee host serves the shard");
    let bridge = storage
        .get_certified_header(BlockHeight::new(frontier.inner() + 1))
        .expect("fresh chain holds its first block past the frontier");
    assert_eq!(
        bridge.header().parent_block_hash(),
        anchor,
        "the fresh chain must extend the beacon-attested anchor"
    );

    // The retained committee's own real suffix above the frontier is refused
    // like the branch heads: the fresh chain re-produces `frontier + 1`
    // rather than adopting the old committee's block there. A retained head
    // above the beacon-attested anchor is unattestable — the incomers cannot
    // know it is the branches' common prefix rather than one side's forgery.
    let old_storage = cluster
        .runner()
        .hosts_shard(
            u32::try_from(committee[0]).expect("host index fits a node index"),
            shard,
        )
        .expect("old committee host still serves its stalled chain");
    let old_block = old_storage
        .get_certified_header(BlockHeight::new(frontier.inner() + 1))
        .expect("the old chain committed past the frontier before the fork");
    assert_ne!(
        old_block.block_hash(),
        bridge.block_hash(),
        "the fresh chain must not adopt the retained suffix above the frontier"
    );
}

/// Assert the seeded 50%-request-loss scenario at `seed`: the shared body's
/// liveness invariants plus the sim-deterministic engagement — at least one
/// `provision.request` leg drop landed at this seed. Production can't assert
/// engagement (its async retry path is nondeterministic), so that check lives
/// here, keyed on the exact seed.
fn request_loss_engages_at_seed(seed: u64) {
    let mut cluster = SimCluster::with_execution_mode(
        &split_config(),
        seed,
        &cross_shard_fault_genesis_accounts(),
        ExecutionMode::Serial,
    );
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
    let mut cluster = SimCluster::with_accounts(&split_config(), 11, &livelock_accounts());
    livelock_resolves_promptly(&mut cluster);
}

#[test]
fn merge_lifecycle_sim() {
    let mut cluster = SimCluster::with_accounts(&split_config(), 11, &reshape_lifecycle_accounts());
    merge_lifecycle(&mut cluster);
}

/// A pre-cut transaction neither child committed reaches an outcome on
/// the reunified parent, and every crossing the merge carried over is
/// accounted for.
///
/// Two things at once, and the second is why the cell is here. The
/// scenario's own subject is the admission: a transaction that opened
/// before the cut is admissible only once proven absent from both
/// children. Beside it runs the conservation probe, which reads the
/// crossings the merge inherited — seventeen at this seed, sixteen taken
/// by their consumer and one never taken. The successor holds the record
/// and the claim alike, so it retires the sixteen and credits the
/// seventeenth back to the cell it left.
#[test]
fn merge_boundary_admits_an_uncommitted_precut_tx_sim() {
    // The merge's own ballast plus the probe train's funding: the
    // scenario needs both the reshape to fire and the train to pay.
    let mut accounts = reshape_lifecycle_accounts();
    accounts.extend(probe_train_genesis_accounts(MAX_REPLAY_PROBES));
    let mut cluster = SimCluster::with_accounts(&split_config(), 11, &accounts);
    merge_boundary_admits_an_uncommitted_precut_tx(&mut cluster);
}

/// Single-shard genesis with the grow trigger armed — `split_bytes` above
/// each child of the ballasted root (the splitter's flash-led ballast and
/// the survivor's ballast-plus-flash) and below the root itself, so the
/// root splits once and the pair holds — and two cohorts of pool surplus
/// plus the shuffle's headroom: one cohort grows ROOT to the two
/// siblings, the other splits the heavier one after the vote.
///
/// The headroom is what makes the second split reachable at all. A split
/// is admitted only while the pool holds a whole committee, and the
/// shuffle draws its entrants from that same pool with no such gate —
/// one per live shard, so two here. Sized for the cohorts alone, whether
/// the vote's assertion reaches the beacon before the shuffle's next
/// interval is a race the seed decides, and a shard that loses it never
/// splits: the entrants that took its seats are jailed unready and the
/// pool never refills.
fn straddler_config() -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 4,
        vnodes_per_host: 1,
        pool_surplus: 10,
        num_shards: 1,
        split_bytes: stdlib_flash_bytes() + 30_000,
        latency: Duration::from_millis(150),
    }
}

/// Single-shard genesis born running the fixture packages, with the grow
/// trigger armed on the fixture flash's scale — above each child of the
/// ballasted root and below the root itself — and two cohorts of pool
/// surplus: one grows ROOT to the two siblings, the other splits the
/// venue's shard after the vote.
fn departing_venue_config() -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 4,
        vnodes_per_host: 1,
        pool_surplus: 8,
        num_shards: 1,
        split_bytes: departing_venue_split_bytes(),
        latency: Duration::from_millis(150),
    }
}

#[test]
fn a_departing_venue_clears_swaps_and_carries_on_sim() {
    let mut accounts = departing_venue_ballast();
    accounts.extend(venue_genesis_accounts_on(
        STRADDLER_SPLITTER,
        &[STRADDLER_SURVIVOR],
    ));
    let mut cluster = SimCluster::with_packages(
        &departing_venue_config(),
        11,
        &accounts,
        GenesisPackages::with_fixtures(),
    );
    a_departing_venue_clears_swaps_and_carries_on(&mut cluster, epochs(12));
}

/// The split-straddler pair with the venue on the surviving side and its
/// callers on the splitter: the callers' shard is the one that leaves.
#[test]
fn a_leg_issued_on_a_departing_shard_reaches_its_venue_sim() {
    let mut accounts = departing_caller_ballast();
    accounts.extend(venue_genesis_accounts_on(
        STRADDLER_SURVIVOR,
        &[STRADDLER_SPLITTER],
    ));
    let mut cluster = SimCluster::with_packages(
        &departing_venue_config(),
        11,
        &accounts,
        GenesisPackages::with_fixtures(),
    );
    a_leg_issued_on_a_departing_shard_reaches_its_venue(&mut cluster, epochs(12));
}

#[test]
fn a_departing_venues_terminal_hands_on_what_it_never_took_sim() {
    let mut accounts = departing_venue_ballast();
    accounts.extend(venue_genesis_accounts_on(
        STRADDLER_SPLITTER,
        &[STRADDLER_SURVIVOR],
    ));
    let mut cluster = SimCluster::with_packages(
        &departing_venue_config(),
        11,
        &accounts,
        GenesisPackages::with_fixtures(),
    );
    a_departing_venues_terminal_hands_on_what_it_never_took(&mut cluster, epochs(24));
}

#[test]
fn a_swap_committed_after_the_venues_cut_is_disposed_once_sim() {
    let mut accounts = departing_venue_ballast();
    accounts.extend(venue_genesis_accounts_on(
        STRADDLER_SPLITTER,
        &[STRADDLER_SURVIVOR],
    ));
    let mut cluster = SimCluster::with_packages(
        &departing_venue_config(),
        11,
        &accounts,
        GenesisPackages::with_fixtures(),
    );
    cluster.run_faultable(a_swap_committed_after_the_venues_cut_is_disposed_once);
}

// TEMPSWEEP
// TEMPSWEEP
// TEMPSWEEP
// TEMPSWEEP
#[test]
fn a_route_into_a_departing_venue_releases_the_survivors_hold_sim() {
    let mut cluster = departing_route_cluster();
    cluster.run_faultable(a_route_into_a_departing_venue_releases_the_survivors_hold);
}

/// The route topology grown to four shards on dedicated pool hosts, with
/// a cohort to spare for the first venue's split and the reshape trigger
/// armed above every quarter until the scenario votes it down.
fn departing_route_cluster() -> SimCluster {
    SimCluster::with_grown_packages_on_dedicated_pool_hosts(
        &ScenarioConfig {
            num_shards: 4,
            pool_surplus: 18,
            split_bytes: departing_venue_split_bytes(),
            ..cross_shard_config()
        },
        42,
        &departing_route_genesis_accounts(),
        GenesisPackages::with_fixtures(),
    )
}

#[test]
fn a_route_the_departing_venue_settled_is_settled_by_the_survivor_sim() {
    let mut cluster = departing_route_cluster();
    cluster.run_faultable(a_route_the_departing_venue_settled_is_settled_by_the_survivor);
}

/// Drive a train of transfers into the splitter across its split at `seed`.
fn a_train_into_a_splitter_strands_nothing_at_seed(seed: u64) {
    let mut cluster =
        SimCluster::with_accounts(&straddler_config(), seed, &split_train_genesis_accounts());
    a_train_into_a_splitter_strands_nothing(&mut cluster);
}

#[test]
fn a_train_into_a_splitter_strands_nothing_sim() {
    a_train_into_a_splitter_strands_nothing_at_seed(11);
}

#[test]
fn a_train_into_a_splitter_strands_nothing_seed_3_sim() {
    a_train_into_a_splitter_strands_nothing_at_seed(3);
}
#[test]
fn a_train_into_a_splitter_strands_nothing_seed_5_sim() {
    a_train_into_a_splitter_strands_nothing_at_seed(5);
}
#[test]
fn a_train_into_a_splitter_strands_nothing_seed_7_sim() {
    a_train_into_a_splitter_strands_nothing_at_seed(7);
}
#[test]
fn a_train_into_a_splitter_strands_nothing_seed_13_sim() {
    a_train_into_a_splitter_strands_nothing_at_seed(13);
}
#[test]
fn a_train_into_a_splitter_strands_nothing_seed_17_sim() {
    a_train_into_a_splitter_strands_nothing_at_seed(17);
}

#[test]
fn split_straddler_atomic_sim() {
    let setup = split_straddler_setup();
    let mut cluster = SimCluster::with_execution_mode(
        &straddler_config(),
        11,
        &setup.accounts,
        ExecutionMode::Serial,
    );
    split_straddler_atomic(&mut cluster);
}

/// Assert straddler atomicity under an asymmetric EC partition across a split
/// boundary at `seed`.
///
/// Drives the portable [`split_straddler_ec_partition_atomic`] scenario, seating
/// disjoint splitter/survivor committees via dedicated pool hosts so no
/// co-hosted vnode bridges the EC cut in-process. The seed varies how the
/// survivor's finalization races the settled-set fence deciding it; none
/// may resolve one-sided.
fn split_straddler_ec_partition_atomic_at_seed(seed: u64) {
    let setup = split_straddler_setup();
    let mut cluster = SimCluster::with_accounts_and_dedicated_pool_hosts(
        &straddler_config(),
        seed,
        &setup.accounts,
    );
    split_straddler_ec_partition_atomic(&mut cluster);
}

#[test]
fn a_delivery_is_reclaimed_when_its_deliverer_splits_sim() {
    let setup = split_straddler_setup();
    let mut cluster = SimCluster::with_accounts(&straddler_config(), 11, &setup.accounts);
    cluster.run_faultable(a_delivery_is_reclaimed_when_its_deliverer_splits);
}

/// A record inherited across its issuer's split, decided by the child
/// that took the payer's prefix — the case the terminal evidence span
/// buys and the inherited seat spends.
#[test]
fn a_record_is_decided_by_the_successor_when_its_issuer_splits_sim() {
    let setup = split_issuer_straddler_setup();
    let mut cluster = SimCluster::with_accounts(&straddler_config(), 11, &setup.accounts);
    cluster.run_faultable(a_record_is_decided_by_the_successor_when_its_issuer_splits);
}

#[test]
fn split_straddler_ec_partition_atomic_seed_7_sim() {
    split_straddler_ec_partition_atomic_at_seed(7);
}

#[test]
fn split_straddler_ec_partition_atomic_seed_11_sim() {
    split_straddler_ec_partition_atomic_at_seed(11);
}

#[test]
fn split_straddler_ec_partition_atomic_seed_42_sim() {
    split_straddler_ec_partition_atomic_at_seed(42);
}

#[test]
fn split_straddler_ec_partition_atomic_seed_1337_sim() {
    split_straddler_ec_partition_atomic_at_seed(1337);
}

#[test]
fn split_straddler_ec_partition_atomic_seed_2026_sim() {
    split_straddler_ec_partition_atomic_at_seed(2026);
}

/// Four-shard topology whose `split_bytes` derives a `merge_bytes` bracketing
/// the genesis byte skew: the survivor pair (`leaf(2,0)`/`leaf(2,1)`, the latter
/// bulk-funded) sits above it, the light merging pair (`leaf(2,2)`/`leaf(2,3)`)
/// below it, so only the merging pair auto-merges into `leaf(1,1)`. Three cohorts
/// of pool surplus staff the two split generations the grow walks through; the
/// merge keepers then come from the merging children's own committees.
fn merge_straddler_config() -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 4,
        vnodes_per_host: 1,
        pool_surplus: 12,
        num_shards: 4,
        // Above the flash-holding survivor quarter, with the derived
        // merge floor (an eighth) between the merging pair's totals and
        // the surviving pair's bulk funding.
        split_bytes: stdlib_flash_bytes() + 18_000,
        latency: Duration::from_millis(150),
    }
}

#[test]
fn merge_straddler_atomic_sim() {
    let setup = merge_straddler_setup();
    let mut cluster =
        SimCluster::with_grown_accounts(&merge_straddler_config(), 11, &setup.accounts);
    merge_straddler_atomic(&mut cluster);
}

/// The merge-straddler topology sized around the fixture flash, so the
/// venue's packages are on it: the callers sit on the merge-left child,
/// which pairs with its sibling from the grow alone.
fn merging_caller_config() -> ScenarioConfig {
    ScenarioConfig {
        split_bytes: fixture_flash_bytes() + 18_000,
        ..merge_straddler_config()
    }
}

#[test]
fn a_leg_issued_on_a_merging_shard_reaches_its_venue_sim() {
    let mut cluster = SimCluster::with_grown_packages(
        &merging_caller_config(),
        11,
        &merging_caller_genesis_accounts(),
        GenesisPackages::with_fixtures(),
    );
    a_leg_issued_on_a_merging_shard_reaches_its_venue(&mut cluster, epochs(12));
}

#[test]
fn a_train_into_a_merging_shard_strands_nothing_sim() {
    let mut cluster = SimCluster::with_grown_accounts(
        &merge_straddler_config(),
        11,
        &merge_train_genesis_accounts(),
    );
    a_train_into_a_merging_shard_strands_nothing(&mut cluster);
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
fn delegation_folds_into_beacon_state_sim() {
    let mut cluster =
        SimCluster::with_accounts(&witness_config(4), 0x57AC, &staking_genesis_accounts());
    delegation_folds_into_beacon_state(&mut cluster);
}

#[test]
fn pool_transfer_moves_operatorship_sim() {
    let mut cluster = SimCluster::with_grown_accounts(
        &cross_shard_config(),
        0xBAD9E,
        &[(badge_buyer().1, 1_000_000)],
    );
    pool_transfer_moves_operatorship(&mut cluster);
}

#[test]
fn register_validator_pools_a_node_sim() {
    let mut cluster =
        SimCluster::with_accounts(&witness_config(4), 0x5EED, &staking_genesis_accounts());
    register_validator_pools_a_node(&mut cluster);
}

#[test]
fn register_without_capacity_is_rejected_sim() {
    let mut cluster =
        SimCluster::with_accounts(&witness_config(4), 0x0CA9, &staking_genesis_accounts());
    register_without_capacity_is_rejected(&mut cluster);
}

#[test]
fn stake_withdraw_drops_effective_stake_sim() {
    let mut cluster =
        SimCluster::with_accounts(&witness_config(4), 0xD7A1, &staking_genesis_accounts());
    stake_withdraw_drops_effective_stake(&mut cluster);
}

#[test]
fn withdrawal_ejects_a_validator_that_a_deposit_reactivates_sim() {
    let mut cluster =
        SimCluster::with_accounts(&witness_config(4), 0xE1EC, &staking_genesis_accounts());
    withdrawal_ejects_a_validator_that_a_deposit_reactivates(&mut cluster);
}

#[test]
fn registered_validator_activates_onto_a_shard_sim() {
    let mut cluster =
        SimCluster::with_accounts(&witness_config(4), 0xAC11, &staking_genesis_accounts());
    registered_validator_activates_onto_a_shard(&mut cluster);
}

#[test]
fn re_registration_of_a_live_validator_is_a_no_op_sim() {
    let mut cluster =
        SimCluster::with_accounts(&witness_config(4), 0xDEAD, &staking_genesis_accounts());
    re_registration_of_a_live_validator_is_a_no_op(&mut cluster);
}

#[test]
fn pool_capacity_caps_registrations_sim() {
    let mut cluster =
        SimCluster::with_accounts(&witness_config(4), 0xCA9A, &staking_genesis_accounts());
    pool_capacity_caps_registrations(&mut cluster);
}

/// Single-shard genesis with the split armed (`split_bytes = 0`) and
/// `(target - 1)` cohorts of pool surplus to staff the split generations the
/// grow walks through, plus two spares of jail slack: an organic
/// `Performance` jail refills its committee seat from the pool, which with
/// zero slack would leave a leaf short of full strength with nothing to
/// refill from. The leftover stays below a committee's worth, so split
/// admission's pool gate can't staff another cohort and the partition still
/// stabilizes at `target` leaves.
const fn grow_config(target_shards: u32) -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 4,
        vnodes_per_host: 1,
        pool_surplus: (target_shards - 1) * 4 + 2,
        num_shards: 1,
        split_bytes: 0,
        latency: Duration::from_millis(150),
    }
}

#[test]
fn grow_reaches_two_shard_topology_sim() {
    let mut cluster = SimCluster::with_accounts(&grow_config(2), 11, &reshape_lifecycle_accounts());
    grow_reaches_two_shard_topology(&mut cluster);
}

#[test]
fn grow_reaches_four_shard_topology_sim() {
    let mut cluster = SimCluster::with_accounts(&grow_config(4), 11, &reshape_lifecycle_accounts());
    grow_reaches_four_shard_topology(&mut cluster);
}

#[test]
fn merge_seats_full_keeper_committee_sim() {
    let mut cluster = SimCluster::with_accounts(&split_config(), 11, &reshape_lifecycle_accounts());
    merge_seats_full_keeper_committee(&mut cluster);
}

#[test]
fn surviving_sibling_split_seats_full_committees_sim() {
    let setup = split_straddler_setup();
    let mut cluster = SimCluster::with_execution_mode(
        &straddler_config(),
        11,
        &setup.accounts,
        ExecutionMode::Serial,
    );
    surviving_sibling_split_seats_full_committees(&mut cluster);
}
