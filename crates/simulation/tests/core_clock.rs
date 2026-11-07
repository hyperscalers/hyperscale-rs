//! What the members of a multi-shard core read, and whether they read
//! the same thing.
//!
//! A core spanning two shards runs every core node on each of them, and
//! each shard applies its own projection of its own run. The book route
//! is such a core: the book's fill on the book's shard and the venue's
//! swap on the venue's. The venue's shard runs the fill over the ladder
//! the book's committing block left, served in the book's bundle; the
//! book's shard runs it over its own ladder as its tick reads it.
//!
//! Sim-only. The delay hooks the in-memory transport's notification leg.

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use hyperscale_engine::genesis::GenesisPackages;
use hyperscale_scenarios::{
    BOOK_SHARD, BOOK_VENUE_SHARD, BookRoute, FaultableCluster, ScenarioConfig,
    a_divided_core_pays_out_under_one_clock, book_route_genesis_accounts, cutoff_genesis_accounts,
    departing_venue_split_bytes, epochs,
};
use support::{SimCluster, sim_seed};

/// Four quarters on hosts of their own: the cutoffs on two, the payer on
/// a third.
fn cutoff_cluster(seed: u64) -> SimCluster {
    SimCluster::with_grown_packages_on_dedicated_pool_hosts(
        &ScenarioConfig {
            shard_size: 4,
            vnodes_per_host: 1,
            pool_surplus: 14,
            num_shards: 4,
            split_bytes: 0,
            latency: std::time::Duration::from_millis(150),
        },
        seed,
        &cutoff_genesis_accounts(),
        GenesisPackages::with_fixtures(),
    )
}

/// Two core shards that commit a payment on either side of its deadline
/// run its core under one clock, the earliest of theirs, so the payment
/// lands in one cutoff.
#[test]
fn a_divided_core_runs_under_its_earliest_clock() {
    let mut cluster = cutoff_cluster(sim_seed(42));
    cluster.run_faultable(a_divided_core_pays_out_under_one_clock);
    cluster.assert_effects_compared();
}

/// Execution votes the book's committee sends that are lost before the
/// rest go through: enough that the local fills beside a route certify
/// only after the route has committed on the book's shard.
const LOST_VOTES: usize = 120;

/// The book route's four quarters, grown on dedicated pool hosts, the
/// reshape trigger armed above every quarter and never voted down.
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

/// A local fill the book's shard has run but not yet settled when it
/// commits a route leaves the route's book member behind the fill's
/// tick, and both core members walk the ladder the block making it head
/// left.
///
/// The book's committee loses its first execution votes, so the fills
/// beside the route run in their own block's tick and certify only after
/// the route commits. The book's member reads the ladder, so it heads
/// only once the fills' ticks have settled, and the book's shard serves
/// the venue's its part from that block: the ladder it left holds the
/// fills' output, which is what the book's member reads through its
/// tick.
///
/// The route must settle at the closed form over the ladder that block
/// left, with the quote and the base conserved, as one run of the core
/// would.
#[test]
fn a_core_member_reads_its_own_cells_as_its_bundle_served_them() {
    let mut cluster = book_route_cluster(sim_seed(42));
    cluster.run_faultable(|c| {
        let mut route = BookRoute::stand_up(c);
        let lost = Arc::new(AtomicUsize::new(0));
        for host in c.committee_hosts(BOOK_SHARD) {
            let lost = Arc::clone(&lost);
            let _ = c.rewrite_notifications(
                host,
                "execution.vote",
                Arc::new(move |_asked: &[u8], honest: &[u8]| {
                    if lost.fetch_add(1, Ordering::Relaxed) < LOST_VOTES {
                        Vec::new()
                    } else {
                        honest.to_vec()
                    }
                }),
            );
        }

        let fill = route.run(c, epochs(12), "fills certified after the route");
        assert!(
            lost.load(Ordering::Relaxed) > LOST_VOTES,
            "the book's votes have to have been lost and then flowed, or nothing raced: {fill:?}",
        );
        route.assert_conserved(c, epochs(12));
    });
    cluster.assert_effects_compared();
}

/// Provision broadcasts the venue's committee sends that are lost before
/// the rest go through: every one the route's core sends, so the book's
/// shard holds the route pending until it fetches the venue's part.
const LOST_PROVISIONS: usize = 64;

/// A local fill the book's shard commits after a route, while the route
/// waits on the venue's part, settles before the route reads the ladder.
///
/// The venue's committee loses its first provision broadcasts, so the
/// book's shard holds the route pending until it fetches the venue's
/// part. A local fill submitted once the book's shard has committed the
/// route commits after it. The book's member of the route pays nowhere
/// and consumes the trader's escrow, so the book places it only at the
/// block whose claims read the trader's record, which may land before or
/// after the fill commits. Either way the route heads only once nothing
/// placed ahead of it, and no tick below its place, still moves the
/// ladder, and the book's shard serves the venue's member its part from
/// that block: both walk one ladder.
///
/// The route must bank one base on both shards, as one run of the core
/// would.
#[test]
fn a_route_placed_after_a_fill_waits_for_the_fill() {
    let mut cluster = book_route_cluster(sim_seed(42));
    cluster.run_faultable(|c| {
        let mut route = BookRoute::stand_up(c);
        let lost = Arc::new(AtomicUsize::new(0));
        for host in c.committee_hosts(BOOK_VENUE_SHARD) {
            let lost = Arc::clone(&lost);
            let _ = c.rewrite_notifications(
                host,
                "provisions.broadcast",
                Arc::new(move |_asked: &[u8], honest: &[u8]| {
                    if lost.fetch_add(1, Ordering::Relaxed) < LOST_PROVISIONS {
                        Vec::new()
                    } else {
                        honest.to_vec()
                    }
                }),
            );
        }

        let fill = route.run_with_a_later_fill(c, epochs(12), "a fill committed after the route");
        assert!(
            lost.load(Ordering::Relaxed) > 0,
            "the venue's broadcasts have to have been lost, or the route never waited: {fill:?}",
        );
        route.assert_conserved(c, epochs(12));
    });
    cluster.assert_effects_compared();
}
