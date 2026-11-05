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

use hyperscale_engine::genesis::GenesisPackages;
use hyperscale_scenarios::{
    ScenarioConfig, a_hot_venue_runs_every_swap_where_it_commits,
    a_route_whose_venue_never_commits_frees_the_ladder,
    a_stalled_venue_aborts_its_route_at_the_window, book_route_genesis_accounts,
    departing_venue_split_bytes, epochs, venue_genesis_accounts,
};
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
            latency: std::time::Duration::from_millis(150),
        },
        seed,
        &book_route_genesis_accounts(),
        GenesisPackages::with_fixtures(),
    )
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
            latency: std::time::Duration::from_millis(150),
        },
        sim_seed(42),
        &venue_genesis_accounts(),
        GenesisPackages::with_fixtures(),
    );
    a_hot_venue_runs_every_swap_where_it_commits(&mut cluster, epochs(40));
}
