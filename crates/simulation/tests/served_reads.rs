//! What a shared member's queue place costs the members behind it, and
//! how its naming window bounds that cost.
//!
//! A member whose verdict a counterpart shares stands in its shard's
//! queue from its place, and nothing placed after it on a key it pins
//! runs ahead of it. A head that refuses someone and stays unnamed is
//! aborted once its naming window closes, so a counterpart that never
//! answers freezes the keys it holds for no longer than that.
//!
//! Sim-only. The cuts hook the in-memory transport.

mod support;

use std::time::Duration;

use hyperscale_engine::genesis::GenesisPackages;
use hyperscale_scenarios::{
    BookRoute, Cluster, ScenarioConfig, a_cycle_through_a_payer_core_aborts_at_the_window,
    a_hot_venue_runs_every_swap_where_it_commits,
    a_leg_reserving_a_read_vault_settles_before_the_read,
    a_member_named_in_its_head_block_reads_one_part,
    a_reclaim_onto_a_served_till_reads_one_balance_on_both_shards,
    a_route_whose_venue_never_commits_frees_the_ladder,
    a_stalled_venue_aborts_its_route_at_the_window,
    a_whole_members_part_is_served_by_the_block_settling_an_earlier_writer,
    an_owed_credit_onto_a_served_vault_composes, book_route_genesis_accounts,
    contested_publish_genesis_accounts, departing_venue_split_bytes, epochs,
    payer_cycle_genesis_accounts, served_reads_genesis_accounts,
    sponsored_routes_crossed_through_their_legs_abort_at_the_window,
    two_members_reading_what_the_other_reserves_both_settle, venue_genesis_accounts,
};
use hyperscale_simulation::ProcessingTimes;
use support::{SimCluster, sim_seed};

/// The book route's four quarters, grown on dedicated pool hosts.
fn book_route_cluster(seed: u64) -> SimCluster {
    SimCluster::with_grown_packages_on_dedicated_pool_hosts(
        &ScenarioConfig {
            shard_size: 4,
            vnodes_per_host: 1,
            pool_surplus: 18,
            num_shards: 4,
            split_bytes: departing_venue_split_bytes(),
            latency: Duration::from_millis(150),
        },
        seed,
        &book_route_genesis_accounts(),
        GenesisPackages::with_fixtures(),
    )
}

/// A venue on each of four quarters and the routes' cast, every
/// committee on hosts of its own, for the cuts that order the commits.
fn payer_cycle_cluster(seed: u64) -> SimCluster {
    SimCluster::with_grown_packages_on_dedicated_pool_hosts(
        &ScenarioConfig {
            shard_size: 4,
            vnodes_per_host: 1,
            pool_surplus: 14,
            num_shards: 4,
            split_bytes: u64::MAX,
            latency: Duration::from_millis(150),
        },
        seed,
        &payer_cycle_genesis_accounts(),
        GenesisPackages::with_fixtures(),
    )
}

/// A payer core heads ahead of a member that heads ahead of the core's
/// own leg: the cycle ends at a naming window, with no more than two
/// aborts and nothing moved for them but their charges.
#[test]
fn a_cycle_through_a_payer_core_ends_at_the_window() {
    let mut cluster = payer_cycle_cluster(sim_seed(42));
    cluster.run_faultable(a_cycle_through_a_payer_core_aborts_at_the_window);
}

/// Two sponsored routes whose payer cores each hold the other's leg off
/// end at a naming window, as the three-member cycle does.
#[test]
fn two_sponsored_routes_crossed_through_their_legs_end_at_the_window() {
    let mut cluster = payer_cycle_cluster(sim_seed(42));
    cluster.run_faultable(sponsored_routes_crossed_through_their_legs_abort_at_the_window);
}

/// Routes back to back through a venue that never commits them: each
/// holds the book's ladder for no more than its naming window, and its
/// payer pays its charge for it.
#[test]
fn a_route_whose_venue_never_commits_frees_the_ladder_within_the_window() {
    let mut cluster = book_route_cluster(sim_seed(42));
    cluster.run_faultable(a_route_whose_venue_never_commits_frees_the_ladder);
}

/// A venue that commits a route and then leaves its part to the book
/// undelivered past the window: the book's head aborts at its window
/// and nothing moves but the payer's charge.
#[test]
fn a_counterpart_stalled_past_the_window_aborts_without_minting() {
    let mut cluster = book_route_cluster(sim_seed(42));
    cluster.run_faultable(a_stalled_venue_aborts_its_route_at_the_window);
}

/// Every cross-shard taker on a hot venue runs there in the first block
/// that has committed it and read its caller's record: the queue holds
/// no determined core back.
#[test]
fn a_hot_venue_names_every_swap_once_it_is_ready() {
    let mut cluster = SimCluster::with_grown_packages(
        &ScenarioConfig {
            shard_size: 4,
            vnodes_per_host: 1,
            pool_surplus: 4,
            num_shards: 2,
            split_bytes: u64::MAX,
            latency: Duration::from_millis(150),
        },
        sim_seed(42),
        &venue_genesis_accounts(),
        GenesisPackages::with_fixtures(),
    );
    a_hot_venue_runs_every_swap_where_it_commits(&mut cluster, epochs(40));
}

/// A venue on three quarters and two holders of stake units beside the
/// first, every committee on hosts of its own.
fn served_reads_cluster(seed: u64) -> SimCluster {
    SimCluster::with_grown_packages_on_dedicated_pool_hosts(
        &served_reads_config(),
        seed,
        &served_reads_genesis_accounts(),
        GenesisPackages::with_fixtures(),
    )
}

/// Four quarters with no reshape in sight.
const fn served_reads_config() -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 4,
        vnodes_per_host: 1,
        pool_surplus: 14,
        num_shards: 4,
        split_bytes: u64::MAX,
        latency: Duration::from_millis(150),
    }
}

/// Two members each reading the vault the other reserves settle in the
/// order they were placed, each served from its own head.
#[test]
fn two_members_reading_what_the_other_reserves_both_settle_sim() {
    let mut cluster = served_reads_cluster(sim_seed(42));
    cluster.run_faultable(two_members_reading_what_the_other_reserves_both_settle);
}

/// A reclaim onto a vault a head reads and reserves leaves both shards
/// reading one balance.
#[test]
fn a_reclaim_onto_a_served_till_reads_one_balance_on_both_shards_sim() {
    let mut cluster = served_reads_cluster(sim_seed(42));
    cluster.run_faultable(a_reclaim_onto_a_served_till_reads_one_balance_on_both_shards);
}

/// An owed credit onto a vault a head debits composes with the debit.
#[test]
fn an_owed_credit_onto_a_served_vault_composes_sim() {
    let mut cluster = served_reads_cluster(sim_seed(42));
    cluster.run_faultable(an_owed_credit_onto_a_served_vault_composes);
}

/// A member named in its head block waits for that block's write, on a
/// disk that trails every commit, and reads the part its counterpart
/// reads.
#[test]
fn a_member_named_in_its_head_block_reads_one_part_sim() {
    let mut cluster = SimCluster::with_grown_packages_and_processing(
        &served_reads_config(),
        sim_seed(42),
        &served_reads_genesis_accounts(),
        GenesisPackages::with_fixtures(),
        ProcessingTimes {
            consensus: Duration::from_millis(1),
            throughput: Duration::from_millis(1),
            io: Duration::from_millis(600),
            tail_per_million: 0,
            tail: Duration::ZERO,
        },
    );
    cluster.run_faultable(a_member_named_in_its_head_block_reads_one_part);
}

/// A member reading a vault a leg reserves heads once the leg settles,
/// and reads what the leg left.
#[test]
fn a_leg_reserving_a_read_vault_settles_before_the_read_sim() {
    let mut cluster = served_reads_cluster(sim_seed(42));
    cluster.run_faultable(a_leg_reserving_a_read_vault_settles_before_the_read);
}

/// A whole member behind an earlier writer is served from the block that
/// settles the writer. Dedicated hosts, so the cut has a road to sit on.
#[test]
fn a_whole_members_part_is_served_by_the_block_settling_an_earlier_writer_sim() {
    let mut cluster = SimCluster::with_grown_accounts_on_dedicated_pool_hosts(
        &ScenarioConfig {
            shard_size: 4,
            vnodes_per_host: 1,
            pool_surplus: 4,
            num_shards: 2,
            split_bytes: u64::MAX,
            latency: Duration::from_millis(150),
        },
        sim_seed(42),
        &contested_publish_genesis_accounts(),
    );
    cluster.run_faultable(|c| {
        a_whole_members_part_is_served_by_the_block_settling_an_earlier_writer(c, epochs(16));
    });
}

/// Local fills streaming onto the book one a block while a route waits
/// on it: the route accepts within its budget, at the closed form over
/// the ladder the block making it head left.
#[test]
fn a_route_is_served_on_a_book_filled_every_block() {
    let mut cluster = book_route_cluster(sim_seed(42));
    cluster.run_faultable(|c| {
        let mut route = BookRoute::stand_up(c);
        let fill = route.run_with_fills_every_block(c, epochs(12), "a book filled every block", 6);
        route.assert_conserved(c, epochs(12));
        c.assert_effects_agreed(fill.hash);
    });
}
