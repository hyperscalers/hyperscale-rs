//! Portable node-behavioral scenarios.
//!
//! A *scenario* is a plain synchronous function over an abstract [`Cluster`]:
//! it drives the cluster from a precondition to a postcondition and asserts the
//! postcondition. The same function body runs on both harnesses — the
//! simulation's logical clock and production's wall-clock QUIC + `RocksDB`
//! cluster — via two thin adaptors that each implement [`Cluster`]. A scenario
//! that passes on one harness and fails on the other is then a real divergence,
//! not a test-authoring artefact.
//!
//! Each module at the crate root is one such scenario (or a small family of
//! them). The harness-agnostic vocabulary they are written against — the
//! [`Cluster`] trait, [`ScenarioConfig`], [`Budget`], and the [`query`],
//! [`wait`], [`tx`], and [`grow_to`] helpers — lives in [`support`]. The two
//! adaptors (`SimCluster`, `ProdCluster`) are supplied by the test crates that
//! depend on this one.

mod support;

mod contention;
mod execution;
mod faults;
mod liveness;
mod multi_vnode;
mod reshape;
mod route;
mod route_reshape;
mod straddler;
mod transactions;
mod venue;
mod witnesses;

pub use contention::{ContentionReport, cross_shard_fraction, participant_count_sweep};
pub use execution::{
    a_delivery_cut_off_past_its_window_is_reclaimed, a_failed_attempt_still_attests_work,
    a_healed_network_does_not_revive_a_closed_delivery,
    a_leg_whose_core_never_answers_refuses_at_the_deadline,
    a_native_post_quantum_account_pays_its_own_way, a_payer_cannot_spend_one_balance_twice,
    a_published_package_matures_before_it_runs, a_spent_nullifier_is_swept_once_unreachable,
    abort_converges, attested_load_reaches_the_beacon,
    cross_shard_credit_survives_a_later_local_credit, cross_shard_transfer, deploy_storm_rides_out,
    events_land_on_their_emitters_home_shard, failure_charges_its_payer, hot_recipient,
    insolvent_payer_engages_nothing, nullifier_race_admits_exactly_one,
    preview_reports_resource_changes, reads_the_committed_baseline,
    sealed_rounds_settle_on_the_seed_they_committed_to,
    securify_retires_the_key_at_the_payer_shard, single_transfer, unbound_payer_engages_nothing,
    unbound_remote_payer_engages_nothing, withdrawals_compose_over_one_vault, zipf_payments,
};
pub use faults::{
    beacon_lag_drops_skipped_epochs_reveal_chains, beacon_pool_partition_stalls_epoch_production,
    cross_shard_compound_drop_fetch_fallback, cross_shard_exec_cert_drop_is_inert,
    cross_shard_header_fetch_fallback, cross_shard_provisions_drop_fetch_fallback,
    cross_shard_provisions_fetch_with_request_loss,
    cross_shard_provisions_recovers_after_transient_outage,
    cross_shard_transaction_da_fetch_fallback, gossip_drop_engages_fetch_fallback,
    halted_shard_recovers_by_committee_redraw, halted_shard_straddler_atomic,
    inter_shard_partition_strands_ticks_until_it_heals, isolated_validator_still_settles,
    minority_fragment_rejoins_after_partition, partition_halts_and_heals,
    partition_heals_at_exact_quorum,
};
pub use liveness::liveness_baseline;
pub use multi_vnode::multi_vnode_progress;
pub use reshape::{
    MAX_REPLAY_PROBES, grow_reaches_four_shard_topology, grow_reaches_two_shard_topology,
    merge_boundary_admits_an_uncommitted_precut_tx, merge_lifecycle,
    merge_seats_full_keeper_committee, split_boundary_admits_an_uncommitted_precut_tx,
    split_boundary_hands_back_what_it_never_included, split_boundary_refuses_a_replay,
    split_lifecycle,
};
pub use route::{
    FIRST_VENUE_SHARD, ROUTE_INPUT, ROUTES, RouteReport, SECOND_VENUE_SHARD, TRADER_SHARD,
    a_route_cut_off_across_its_deadline_is_not_reclaimed,
    a_route_refused_at_its_second_venue_gives_back_what_the_first_took,
    a_route_settles_across_two_venues, a_route_settles_when_its_venues_certificates_are_dropped,
    route_genesis_accounts,
};
pub use route_reshape::{
    MERGE_TRAIN, SPLIT_TRAIN, a_departing_venue_clears_swaps_and_carries_on,
    a_departing_venues_terminal_hands_on_what_it_never_took,
    a_leg_issued_on_a_departing_shard_reaches_its_venue,
    a_leg_issued_on_a_merging_shard_reaches_its_venue,
    a_route_into_a_departing_venue_releases_the_survivors_hold,
    a_route_the_departing_venue_settled_is_settled_by_the_survivor,
    a_swap_committed_after_the_venues_cut_is_disposed_once,
    a_train_into_a_merging_shard_strands_nothing, a_train_into_a_splitter_strands_nothing,
    departing_caller_ballast, departing_route_genesis_accounts, departing_venue_ballast,
    departing_venue_split_bytes, merge_train_genesis_accounts, merging_caller_genesis_accounts,
    split_train_genesis_accounts,
};
pub use straddler::{
    a_delivery_is_reclaimed_when_its_deliverer_splits,
    a_record_is_decided_by_the_successor_when_its_issuer_splits, isolate_ec_intake,
    merge_straddler_atomic, split_straddler_atomic, split_straddler_ec_partition_atomic,
    split_straddler_run, straddler_one_sided_count, surviving_sibling_split_seats_full_committees,
};
pub use support::{
    Budget, Cluster, FaultHandle, FaultableCluster, ScenarioConfig, conservation, epochs, grow_to,
    query, submission_shards, tx, vote_reshape_threshold, wait,
};
pub use transactions::livelock_resolves_promptly;
pub use venue::{
    SWAP_INPUT, SWAPPER_SHARD, SWAPPERS, VENUE_SHARD, VenueReport, WIDE_VENUE_SHARD,
    a_swap_by_a_caller_on_the_venues_shard_runs_whole,
    a_swap_charges_its_caller_its_input_and_one_price,
    a_swap_refused_at_its_inbound_leg_never_reaches_the_venue,
    a_swap_the_venue_refuses_gives_its_caller_back_its_leg, grind_onto, hot_venue_clears_swaps,
    hot_venue_clears_swaps_on, stand_up_venue, venue_genesis_accounts, venue_genesis_accounts_on,
    wide_swapper_shards,
};
pub use witnesses::{
    delegation_folds_into_beacon_state, pool_capacity_caps_registrations,
    pool_transfer_moves_operatorship, re_registration_of_a_live_validator_is_a_no_op,
    register_validator_pools_a_node, register_without_capacity_is_rejected,
    registered_validator_activates_onto_a_shard, stake_withdraw_drops_effective_stake,
    withdrawal_ejects_a_validator_that_a_deposit_reactivates,
};
