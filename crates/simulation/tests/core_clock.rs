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
/// commits a route leaves the route's two core members walking two
/// ladders.
///
/// The book's committee loses its first execution votes, so the fills
/// beside the route run in their own block's tick and certify only after
/// the route commits. The book's bundle serves the ladder its committing
/// block left, which is the settled base and holds none of the fills.
/// The book's own member reads the ladder through its tick, which layers
/// every tick before it, the fills' included. Nothing holds the ladder
/// for a pending core member either: a pending row holds nothing, and a
/// fill committed after the route reads the same way. So the venue's
/// shard prices the walk over one ladder and the book's shard over
/// another, and each applies its own half: the book's change goes to the
/// trader off the walk the book's shard ran, and the venue banks the
/// base off the walk the venue's shard ran.
///
/// The route must settle at the closed form over the ladder the book's
/// committing block left, with the quote and the base conserved, as one
/// run of the core would.
#[test]
#[ignore = "a core member's tick view of its own cells is not what its bundle served"]
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
}

/// Provision broadcasts the venue's committee sends that are lost before
/// the rest go through: every one the route's core sends, so the book's
/// shard holds the route pending until it fetches the venue's part.
const LOST_PROVISIONS: usize = 64;

/// A local fill the book's shard commits after a route and runs while the
/// route waits on the venue's part leaves the route's two core members
/// walking two ladders.
///
/// The venue's committee loses its first provision broadcasts, so the
/// book's shard holds the route pending until it fetches the venue's
/// part. A local fill submitted once the book's shard has committed the
/// route commits after it, and a pending row holds nothing, so the fill
/// is named and runs in the meantime. The book's bundle serves the
/// ladder its committing block left, which the later fill never touched;
/// the book's own member reads the ladder through its tick, which layers
/// the fill's output. So the venue banks the base of one walk and the
/// book's vault gives up the base of another.
///
/// The route must bank one base on both shards, the one the walk over
/// the ladder the book's committing block left buys, as one run of the
/// core would.
#[test]
#[ignore = "a member committed after a core member runs before it on the cells the core's part served"]
fn a_fill_committed_after_the_route_waits_for_the_route() {
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
}
