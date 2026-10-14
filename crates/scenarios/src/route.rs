//! A route through two venues on two shards, and whether it settles.
//!
//! One venue is a core of one shard. Two of them on separate shards is a
//! core that spans both: neither swap is reservation shaped nor total,
//! so both are core, and the route's atomicity has to cover them
//! together while nothing about their execution is shared. Each venue
//! awaits the other's certificate, which is what makes this the first
//! shape whose settlement waits on a certificate from across a shard
//! boundary — a transfer never does, its recipient claims a bundle.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::{self, Display, Formatter, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hyperscale_effects_bridge::ProtocolHasher;
use hyperscale_engine::PROTOCOL_RESOURCE;
use hyperscale_storage::{FeeTerms, RowState};
use hyperscale_types::test_utils::Withheld;
use hyperscale_types::{
    Address, BlockHeight, Deadline, Ed25519PrivateKey, Joins, MAX_CLAIMS_BYTES,
    MAX_CLAIMS_PER_BLOCK, MAX_FINALIZATION_DELAY, MAX_STANDING_TOWARD_SHARD,
    MAX_STATE_CLAIMS_BYTES, MAX_STATE_CLAIMS_PER_BLOCK, MAX_VALIDITY_RANGE, PrincipalAddr,
    ResourceAddr, Said, ShardId, ShardTrie, SubstateKey, Transaction, TransactionDecision,
    TransactionStatus, TxHash, ValidatorId, WeightedTimestamp, Window,
};
use hyperscale_vm_effects::{Answered, CrossingAnswer, CrossingId, Kind, fee_hold_total_key};
use hyperscale_vm_types::{LegRole, LegShape};

use crate::straddler::{
    isolate_crossing_intake, isolate_ec_intake, isolate_provision_intake, isolate_pushed_readings,
    isolate_state_reads,
};
use crate::support::conservation::{Charges, World};
use crate::support::faultable::{report_accepted_measures, report_crossing_measures};
use crate::support::query::{
    ChainMentions, ClaimsSection, Readings, assert_reclaimed_leg, await_reclaim_that_burns_nothing,
    await_reclaimed_leg_fated, declared_price, held, held_at, stands_at, vault_balance,
};
use crate::support::tx::{
    build_route_tx, build_sponsored_route_tx, build_swap_tx, build_transfer_tx, validity_around,
};
use crate::support::wait::{await_blocks, await_tx_terminal};
use crate::support::{Budget, Cluster, FaultHandle, FaultableCluster, epochs};
use crate::venue::{
    PROVIDER_FUNDING, SWAP_INPUT, SWAPPER_FUNDING, StockedVenue, grind_onto, reserve_cell,
    stand_up_venue, stand_up_venues_on,
};

/// Where the route's first hop prices.
pub const FIRST_VENUE_SHARD: ShardId = ShardId::leaf(2, 0);

/// Where its second prices — not the first's, or the route would have a
/// core of one shard and await nobody across a boundary.
pub const SECOND_VENUE_SHARD: ShardId = ShardId::leaf(2, 1);

/// Where the trader sits: neither venue's, so its withdraw is a leg and
/// its deposit a delivery.
pub const TRADER_SHARD: ShardId = ShardId::leaf(2, 2);

/// What one route pays in.
pub const ROUTE_INPUT: u128 = 2_000_000;

/// Where a second trader sits, for a scenario cutting each trader's
/// record off from a different venue: a shard of its own, so the cut
/// stops one route and not the other.
pub const SECOND_TRADER_SHARD: ShardId = ShardId::leaf(2, 3);

/// Where a third venue prices, for a ring of routes through three.
pub const THIRD_VENUE_SHARD: ShardId = ShardId::leaf(2, 3);

/// Blocks each ring venue commits once the cut lifts, time enough for the
/// bundles it missed to be fetched and its waiting route made ready.
const RING_SETTLE_BLOCKS: u64 = 16;

/// The venues of a ring, in its order: each route runs from one venue to
/// the next, and the last back to the first.
const RING: [ShardId; 3] = [FIRST_VENUE_SHARD, SECOND_VENUE_SHARD, THIRD_VENUE_SHARD];

/// How many routes run at once.
pub const ROUTES: usize = 4;

/// A floor the second hop cannot meet: two swaps of [`ROUTE_INPUT`] pay
/// out less than they took in, so anything above the input refuses, and
/// this is well clear of it.
const REFUSED_FLOOR: u128 = ROUTE_INPUT * 100;

/// A provider on each venue's shard, the traders, and a sponsor on the
/// first venue's shard, each funded for what it does.
///
/// Stocking is local to its venue, so it costs no crossing and is not
/// part of the shape under test.
#[must_use]
pub fn route_genesis_accounts() -> Vec<(PrincipalAddr, u128)> {
    route_accounts(&mut Vec::new())
}

/// [`route_genesis_accounts`] and a trader on [`SECOND_TRADER_SHARD`],
/// ground last so every other account lands where it lands there.
#[must_use]
pub fn crossed_route_genesis_accounts() -> Vec<(PrincipalAddr, u128)> {
    let mut taken = Vec::new();
    let mut accounts = route_accounts(&mut taken);
    accounts.push((second_trader(&mut taken).1, SWAPPER_FUNDING));
    accounts
}

fn route_accounts(taken: &mut Vec<u8>) -> Vec<(PrincipalAddr, u128)> {
    let mut accounts = vec![
        (grind_onto(FIRST_VENUE_SHARD, taken).1, PROVIDER_FUNDING),
        (grind_onto(SECOND_VENUE_SHARD, taken).1, PROVIDER_FUNDING),
    ];
    accounts.extend(
        traders(taken)
            .into_iter()
            .map(|(_, account)| (account, SWAPPER_FUNDING)),
    );
    accounts.push((sponsor(taken).1, SWAPPER_FUNDING));
    accounts
}

/// A provider on each ring venue's shard, then a trader on each, each
/// funded for what it does.
#[must_use]
pub fn ring_route_genesis_accounts() -> Vec<(PrincipalAddr, u128)> {
    let mut taken = Vec::new();
    let mut accounts: Vec<(PrincipalAddr, u128)> = RING
        .iter()
        .map(|&venue| (grind_onto(venue, &mut taken).1, PROVIDER_FUNDING))
        .collect();
    accounts.extend(
        ring_traders(&mut taken)
            .into_iter()
            .map(|(_, account)| (account, SWAPPER_FUNDING)),
    );
    accounts
}

/// A trader on each ring venue's shard, in the ring's order: each route's
/// trader sits on its first venue's shard.
fn ring_traders(taken: &mut Vec<u8>) -> Vec<(Ed25519PrivateKey, PrincipalAddr)> {
    RING.iter().map(|&venue| grind_onto(venue, taken)).collect()
}

/// The trader on [`SECOND_TRADER_SHARD`], ground after the sponsor.
fn second_trader(taken: &mut Vec<u8>) -> (Ed25519PrivateKey, PrincipalAddr) {
    grind_onto(SECOND_TRADER_SHARD, taken)
}

/// An account on the first venue's shard that pays a sponsored route's
/// fee, ground after the traders.
pub fn sponsor(taken: &mut Vec<u8>) -> (Ed25519PrivateKey, PrincipalAddr) {
    grind_onto(FIRST_VENUE_SHARD, taken)
}

pub fn traders(taken: &mut Vec<u8>) -> Vec<(Ed25519PrivateKey, PrincipalAddr)> {
    (0..ROUTES)
        .map(|_| grind_onto(TRADER_SHARD, taken))
        .collect()
}

/// Both venues, stood up in the order the genesis accounts were dealt.
pub fn stand_up_venues<C: Cluster>(c: &mut C, taken: &mut Vec<u8>) -> (StockedVenue, StockedVenue) {
    let first = stand_up_venue(c, FIRST_VENUE_SHARD, taken);
    let second = stand_up_venue(c, SECOND_VENUE_SHARD, taken);
    (first, second)
}

/// What one route run observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteReport {
    /// How many routes were submitted together.
    pub submitted: usize,
    /// From the first submission to the last settlement.
    pub elapsed: Duration,
}

/// Stand two venues up on two shards and drive every trader through
/// both.
///
/// # Panics
///
/// Panics if either venue misses its budget standing up, or if any route
/// fails to accept — a refused route would mean a pool ran dry rather
/// than that the shape does not settle, which is not what this asks.
pub fn a_route_settles_across_two_venues<C: FaultableCluster>(
    c: &mut C,
    budget: Budget,
) -> RouteReport {
    let mut taken = Vec::new();
    let (first, second) = stand_up_venues(c, &mut taken);
    let traders = traders(&mut taken);
    let report = drive_routes(c, &first, &second, &traders, budget);
    report_crossing_measures(c, "a_route_settles_across_two_venues");
    report
}

/// Each venue of a healthy route holds the trader's record inside one
/// finalization delay of committing the route.
///
/// The record the trader's inbound leg writes is consumed by the core,
/// which both venue shards run, so each of them waits on a reading of it
/// before its member can join a tick. Nothing is cut here: the trader's
/// shard finalizes its leg and proves the record a few blocks after the
/// route commits, and a venue that holds no reading of it until a clock
/// of its own runs out has made the whole route wait on that clock.
///
/// Requires disjoint committees: a host seated on both venues hands the
/// second what was sent to the first.
///
/// # Panics
///
/// Panics if either venue misses its budget standing up, if the route
/// writes no record into the core, if either venue's chain carries no
/// reading of it within budget, or if either carried it a finalization
/// delay or more past its own commit of the route.
pub fn both_venues_read_a_routes_record_inside_the_finalization_delay<C: Cluster>(
    c: &mut C,
    budget: Budget,
) {
    let mut taken = Vec::new();
    let (first, second) = stand_up_venues(c, &mut taken);
    let traders = traders(&mut taken);
    let (key, account) = &traders[0];
    let tx = build_route_tx(
        key,
        *account,
        (&first.meta, &second.meta),
        *PROTOCOL_RESOURCE,
        ROUTE_INPUT,
        0,
        validity_around(c.now()),
    );
    let records: Vec<SubstateKey> = records_by_road(
        &tx.try_derived(c.derivation().as_ref())
            .expect("a scenario route derives")
            .legs,
    )
    .into_iter()
    .filter(|(_, road)| *road == RecordRoad::IntoTheCore)
    .map(|(record, _)| record)
    .collect();
    assert!(
        !records.is_empty(),
        "a route through two venues writes a record into its core",
    );
    let route = Charges::default().submit(c, tx);

    let waits = |c: &C| -> Vec<(ShardId, Option<Duration>)> {
        [FIRST_VENUE_SHARD, SECOND_VENUE_SHARD]
            .into_iter()
            .flat_map(|venue| {
                records
                    .iter()
                    .map(move |record| (venue, c.record_wait(venue, route, *record)))
            })
            .collect()
    };
    assert!(
        c.run_until(budget, |c| waits(c).iter().all(|(_, wait)| wait.is_some())),
        "each venue's chain must carry a reading of the trader's record within budget: {:?}",
        waits(c),
    );
    for (venue, wait) in waits(c) {
        assert!(
            wait.is_some_and(|wait| wait < MAX_FINALIZATION_DELAY),
            "venue {venue:?} must hold the trader's record inside one finalization delay of \
             committing the route, and waited {wait:?}: {:?}",
            waits(c),
        );
    }
}

/// The same route with the certificate channel cut: each venue's
/// certificate is dropped on its way to the other, so the core settles
/// only if the fetch fallback answers for it.
///
/// A transfer never waits on a certificate from across a boundary — its
/// recipient claims a bundle — so this is the shape that keeps the
/// fallback exercised.
///
/// # Panics
///
/// As [`a_route_settles_across_two_venues`], and if the drop never fires
/// — a cut nothing tried to cross exercises nothing.
pub fn a_route_settles_when_its_venues_certificates_are_dropped<C: FaultableCluster>(c: &mut C) {
    let mut taken = Vec::new();
    let (first, second) = stand_up_venues(c, &mut taken);
    let traders = traders(&mut taken);
    let dropped = c.drop_type("execution.cert.batch");
    drive_routes(c, &first, &second, &traders, epochs(40));
    assert!(
        dropped.fired() > 0,
        "the certificate channel must actually have been exercised and cut",
    );
}

/// Two venues that have each said yes to a route hear the other's yes by
/// asking for it.
///
/// Each venue is cut off from the other's certificate, so each states
/// its own yes and neither can settle; and from the other's pushed
/// readings, so nothing tells it what the other's chain wrote. Each
/// venue's row then stands stated, asks the other venue for the route's
/// verdict cell, carries the reading it fetches in a block, and its fold
/// records the yes on the row. The cuts lift and the route settles as it
/// does on certificates, which is all a hearing may change: nothing.
///
/// Requires disjoint committees, as the cuts are keyed on the hosts.
///
/// # Panics
///
/// Panics if either venue misses its budget standing up, if either cut
/// of the certificates never fires, if either venue's row does not hear
/// the other's yes while it stands stated, if the route does not accept
/// once the cuts lift, or if either side of the pair is not conserved.
pub fn stated_venues_hear_each_others_yes_by_asking<C: FaultableCluster>(c: &mut C) {
    stated_venues_hear_each_other(c, Road::Asked);
}

/// Two venues that have each said yes to a route hear the other's yes
/// from the push of the block that wrote it.
///
/// As [`stated_venues_hear_each_others_yes_by_asking`], with the other
/// road cut: neither venue can read the other's state, so no ask of
/// either is ever answered, and each hears the other's yes only because
/// the block that wrote the leaf pushed it.
///
/// # Panics
///
/// As [`stated_venues_hear_each_others_yes_by_asking`], and if no read
/// of the other venue's state was ever cut.
pub fn stated_venues_hear_each_others_yes_by_push<C: FaultableCluster>(c: &mut C) {
    stated_venues_hear_each_other(c, Road::Pushed);
}

/// The road a venue's reading of its sibling is left to travel in
/// [`stated_venues_hear_each_other`].
#[derive(Clone, Copy, PartialEq, Eq)]
enum Road {
    /// Its own read of the sibling's state: the sibling's pushes are
    /// cut.
    Asked,
    /// The sibling's push: its own reads of the sibling's state are cut.
    Pushed,
}

fn stated_venues_hear_each_other<C: FaultableCluster>(c: &mut C, road: Road) {
    let mut taken = Vec::new();
    let (first, second) = stand_up_venues(c, &mut taken);
    let traders = traders(&mut taken);
    let certificates = [
        isolate_ec_intake(c, FIRST_VENUE_SHARD, SECOND_VENUE_SHARD),
        isolate_ec_intake(c, SECOND_VENUE_SHARD, FIRST_VENUE_SHARD),
    ];
    let isolate = match road {
        Road::Asked => isolate_pushed_readings,
        Road::Pushed => isolate_state_reads,
    };
    let other_road = [
        isolate(c, FIRST_VENUE_SHARD, SECOND_VENUE_SHARD),
        isolate(c, SECOND_VENUE_SHARD, FIRST_VENUE_SHARD),
    ];
    let (key, account) = &traders[0];
    let (protocol_resource, units) = route_worlds(c, &first, &second, [*account]);
    let mut charges = Charges::default();
    let route = charges.submit(
        c,
        build_route_tx(
            key,
            *account,
            (&first.meta, &second.meta),
            *PROTOCOL_RESOURCE,
            ROUTE_INPUT,
            0,
            validity_around(c.now()),
        ),
    );

    let hears_yes = |c: &C, venue: ShardId, sibling: ShardId| {
        c.heard(venue, route)
            .iter()
            .any(|heard| heard.shard == sibling && heard.said == Some(Said::Yes))
            && c.member_rows(venue)
                .is_some_and(|rows| matches!(rows.get(&route), Some(RowState::Stated { .. })))
    };
    assert!(
        c.run_until(epochs(8), |c| {
            hears_yes(c, FIRST_VENUE_SHARD, SECOND_VENUE_SHARD)
                && hears_yes(c, SECOND_VENUE_SHARD, FIRST_VENUE_SHARD)
        }),
        "each venue's stated row must hear the other's yes: first heard {:?} at {:?}, \
         second heard {:?} at {:?}",
        c.heard(FIRST_VENUE_SHARD, route),
        c.member_rows(FIRST_VENUE_SHARD)
            .and_then(|rows| rows.get(&route).copied()),
        c.heard(SECOND_VENUE_SHARD, route),
        c.member_rows(SECOND_VENUE_SHARD)
            .and_then(|rows| rows.get(&route).copied()),
    );
    assert!(
        certificates.iter().all(|handle| handle.fired() > 0),
        "each venue must actually have been cut off from the other's certificate",
    );
    assert!(
        other_road.iter().all(|handle| handle.fired() > 0),
        "each venue must actually have been cut off from the other road",
    );
    c.clear_drops();

    assert!(
        c.run_until(epochs(8), |c| c
            .tx_status(route)
            .is_some_and(|status| status.is_final())),
        "the route must settle once the cuts lift: {:?}",
        c.tx_status(route),
    );
    assert_eq!(
        c.tx_status(route),
        Some(TransactionStatus::Completed(TransactionDecision::Accept)),
        "what the rows heard changes nothing: the certificates accept the route",
    );
    protocol_resource.assert_settles_within(c, &charges, epochs(8), "heard routes");
    units.assert_settles_within(c, &Charges::default(), epochs(8), "heard routes");
    assert!(
        c.metric_count("blocks_from_stated_to_heard", None) > 0
            && c.metric("verdict_cells_changed", None) > 0
            && c.metric("verdict_cells_carried", None) == c.metric("verdict_cells_changed", None),
        "a row that heard every sibling is measured, and no cell a hearing row read was a \
         copy of one it had heard: carried {}, changed {}",
        c.metric("verdict_cells_carried", None),
        c.metric("verdict_cells_changed", None),
    );
    report_crossing_measures(
        c,
        match road {
            Road::Asked => "stated_venues_hear_each_others_yes_by_asking",
            Road::Pushed => "stated_venues_hear_each_others_yes_by_push",
        },
    );
}

/// Two routes each venue seats in the other's order lose the later of the
/// two to the cycle, and the other settles, before their deadline.
///
/// Each route's trader sits on a shard of its own, and each venue is cut
/// off from one trader's record: the second venue from the first route's,
/// the first venue from the second route's. Every other input flows, so
/// the first venue seats the first route, the second venue seats the
/// second, and each holds its venue's reserve while it waits on the other
/// venue's certificate — which neither can produce, since each refuses
/// the other route behind the one it holds. The venue where the later
/// route in hash order waits reads the other venue's seats, aborts that
/// route on the reading, and its abort settles it on both venues, which
/// frees the earlier route to run where it waited. Then the cut lifts.
///
/// Requires disjoint committees, as the cut is keyed on the hosts.
///
/// # Panics
///
/// Panics if either venue misses its budget standing up, if the cut never
/// fires, if the venues do not seat the routes in opposite order, if
/// either route is still unresolved at the deadline, if any route but
/// the later aborts or the earlier does not accept, if no block aborts a
/// proven victim, or if either side of the pair is not conserved.
pub fn routes_seated_in_opposite_order_lose_the_later_to_the_cycle<C: FaultableCluster>(c: &mut C) {
    crossed_routes(c, Seating::AsSubmitted);
}

/// The same cycle with each venue seating the other's route.
///
/// As [`routes_seated_in_opposite_order_lose_the_later_to_the_cycle`],
/// but the later route now waits on the other venue, so the other venue
/// reads the seats and aborts it.
///
/// # Panics
///
/// As [`routes_seated_in_opposite_order_lose_the_later_to_the_cycle`].
pub fn routes_seated_the_other_way_lose_the_later_to_the_cycle<C: FaultableCluster>(c: &mut C) {
    crossed_routes(c, Seating::Swapped);
}

/// Which route each venue seats in [`crossed_routes`].
#[derive(Clone, Copy, PartialEq, Eq)]
enum Seating {
    /// The first venue the first route, the second venue the second.
    AsSubmitted,
    /// The first venue the second route, the second venue the first.
    Swapped,
}

/// Two routes seated in opposite order on the two venues as `seating`
/// says, the cycle between them resolved by its later route's abort.
fn crossed_routes<C: FaultableCluster>(c: &mut C, seating: Seating) {
    let mut taken = Vec::new();
    let (first, second) = stand_up_venues(c, &mut taken);
    let traders = traders(&mut taken);
    sponsor(&mut taken);
    let crossed = second_trader(&mut taken);
    let cast = [&traders[0], &crossed];
    // A venue seats the route whose record it hears, so each is cut off
    // from the trader of the route the other venue seats.
    let (first_hears, second_hears) = match seating {
        Seating::AsSubmitted => (TRADER_SHARD, SECOND_TRADER_SHARD),
        Seating::Swapped => (SECOND_TRADER_SHARD, TRADER_SHARD),
    };
    let cut = [
        isolate_crossing_intake(c, SECOND_VENUE_SHARD, first_hears),
        isolate_crossing_intake(c, FIRST_VENUE_SHARD, second_hears),
    ];
    let (protocol_resource, units) =
        route_worlds(c, &first, &second, cast.iter().map(|(_, account)| *account));

    let mut charges = Charges::default();
    let validity = validity_around(c.now());
    let routes = cast.map(|(key, account)| {
        let route = build_route_tx(
            key,
            *account,
            (&first.meta, &second.meta),
            *PROTOCOL_RESOURCE,
            ROUTE_INPUT,
            0,
            validity,
        );
        charges.submit(c, route)
    });
    let [held_first, held_second] = match seating {
        Seating::AsSubmitted => routes,
        Seating::Swapped => [routes[1], routes[0]],
    };
    let proven = c.metric("hold_inversions_proven", None);

    // The venue holding the later route keeps it seated, the earlier one
    // standing committed and unseated beside it, until the cycle resolves.
    // The other venue's half lasts only from its seat to the abort, which
    // can fall between two polls, so it is read off the committed proof
    // instead: a victim is named only on a reading of the cycle.
    let later = held_first.max(held_second);
    let (victim_venue, earlier) = if later == held_first {
        (FIRST_VENUE_SHARD, held_second)
    } else {
        (SECOND_VENUE_SHARD, held_first)
    };
    assert!(
        c.run_until(epochs(8), |c| {
            c.member_rows(victim_venue).is_some_and(|rows| {
                matches!(
                    rows.get(&later),
                    Some(RowState::InFlight { .. } | RowState::Stated { .. })
                ) && rows.get(&earlier) == Some(&RowState::Pending)
            })
        }),
        "the venue that heard the later route's record must seat it, and hold it",
    );
    assert!(
        c.run_until(epochs(8), |c| c.metric("hold_inversions_proven", None)
            > proven),
        "the other venue must seat the earlier route and prove the cycle off the first's seats",
    );
    assert!(
        cut.iter().all(|handle| handle.fired() > 0),
        "each venue must actually have been cut off from one route's record",
    );
    c.clear_drops();

    let resolved = c.run_until(epochs(8), |c| {
        routes
            .iter()
            .all(|hash| c.tx_status(*hash).is_some_and(|status| status.is_final()))
    });
    let deadline = Deadline::of(validity.end_timestamp_exclusive).at();
    assert!(
        resolved && WeightedTimestamp::ZERO.plus(c.now()) < deadline,
        "the cycle must resolve before the deadline: {:?}",
        routes.map(|hash| c.tx_status(hash)),
    );
    for hash in routes {
        let expected = if hash == later {
            TransactionDecision::Aborted
        } else {
            TransactionDecision::Accept
        };
        let status = c.tx_status(hash);
        assert_eq!(
            status,
            Some(TransactionStatus::Completed(expected)),
            "the later route in hash order is the victim, and the earlier settles",
        );
    }
    protocol_resource.assert_settles_within(c, &charges, epochs(8), "crossed holds");
    units.assert_settles_within(c, &Charges::default(), epochs(8), "crossed holds");
}

/// Three routes held in a ring of three venues wait for their deadline.
///
/// Each route runs from one venue to the next round the ring, its trader
/// on its first venue's shard, so it reaches its two venues and nothing
/// else. It commits on its first venue and reaches its second by that
/// venue's bundle, and is ready on a venue once the other venue's bundle
/// for it arrives. The bundles a venue's successor in the ring sends back
/// speak for one route alone, the one the venue runs first, so cutting
/// each venue off from them leaves every venue ready for the route
/// arriving from its predecessor and nothing else. Each seats that route
/// and holds its reserve while it waits on the venue before it, which
/// refuses it behind the route that venue holds. No two of
/// the routes await a shard in common, so no venue can read the cycle off
/// one counterpart's seats: the ring stands until the deadline aborts all
/// three. This pins the bound a longer cycle is left to.
///
/// Requires disjoint committees, as the cut is keyed on the hosts.
///
/// # Panics
///
/// Panics if a venue misses its budget standing up, if the cut never
/// fires, if the venues do not seat the routes round the ring, if a venue
/// stops committing once the cut lifts, if any route resolves before the
/// deadline or does not abort after it, if a block aborts any as a proven
/// victim or counts a contention, or if either side is not conserved.
pub fn routes_held_in_a_ring_wait_for_their_deadline<C: FaultableCluster>(c: &mut C) {
    let mut taken = Vec::new();
    let venues = RING.map(|venue| stand_up_venue(c, venue, &mut taken));
    let traders = ring_traders(&mut taken);
    let next = |at: usize| (at + 1) % RING.len();
    let prev = |at: usize| (at + RING.len() - 1) % RING.len();
    let cut: Vec<FaultHandle> = (0..RING.len())
        .map(|at| isolate_provision_intake(c, RING[at], RING[next(at)]))
        .collect();
    let holders: Vec<PrincipalAddr> = traders.iter().map(|(_, account)| *account).collect();
    let world = |resource, unit_side: bool| {
        World::open(
            c,
            resource,
            holders.iter().map(|account| account.address()),
            venues.iter().map(|venue| {
                reserve_cell(&venue.meta, if unit_side { venue.unit } else { resource })
            }),
        )
    };
    let protocol_resource = world(*PROTOCOL_RESOURCE, false);
    let units = world(venues[0].unit, true);

    let mut charges = Charges::default();
    let validity = validity_around(c.now());
    let routes: Vec<TxHash> = (0..RING.len())
        .map(|at| {
            let (key, account) = &traders[at];
            let route = build_route_tx(
                key,
                *account,
                (&venues[at].meta, &venues[next(at)].meta),
                *PROTOCOL_RESOURCE,
                ROUTE_INPUT,
                0,
                validity,
            );
            charges.submit(c, route)
        })
        .collect();
    let proven = c.metric("hold_inversions_proven", None);

    // Each venue holds the route arriving from the venue before it, and
    // the route it runs first stands committed and unseated beside it.
    let ring_holds = |c: &C| {
        (0..RING.len()).all(|at| {
            c.member_rows(RING[at]).is_some_and(|rows| {
                matches!(
                    rows.get(&routes[prev(at)]),
                    Some(RowState::InFlight { .. } | RowState::Stated { .. })
                ) && rows.get(&routes[at]) == Some(&RowState::Pending)
            })
        })
    };
    assert!(
        c.run_until(epochs(8), ring_holds),
        "each venue must seat the route arriving from the venue before it, and hold it",
    );
    assert!(
        cut.iter().all(|handle| handle.fired() > 0),
        "each venue must actually have been cut off from its successor's bundles",
    );

    // Lifted: each venue's bundles come back and its waiting route is
    // ready, and refused. No two routes await a shard in common, so the
    // contention count, which pairs members that do, sees none of it.
    let contended = c.metric("hold_contentions", None);
    c.clear_drops();
    for venue in RING {
        assert!(
            await_blocks(c, venue, RING_SETTLE_BLOCKS, epochs(2)),
            "venue {venue} must keep committing once the cut lifts",
        );
    }

    // Read short of the deadline: past it each venue aborts its waiting
    // route, and the first poll there can already see one gone. Nothing
    // else moves a ring, so standing just short of it is standing to it.
    let deadline = Deadline::of(validity.end_timestamp_exclusive).at();
    let short_of = deadline.minus(Duration::from_secs(2));
    let clock = |c: &C| WeightedTimestamp::ZERO.plus(c.now());
    c.run_until(epochs(8), |c| clock(c) >= short_of || !ring_holds(c));
    assert!(
        clock(c) >= short_of && clock(c) < deadline && ring_holds(c),
        "the ring must stand to the deadline: no venue reads it off one counterpart",
    );

    let resolved = c.run_until(epochs(8), |c| {
        routes
            .iter()
            .all(|hash| c.tx_status(*hash).is_some_and(|status| status.is_final()))
    });
    assert!(resolved, "the deadline must resolve every route");
    for hash in &routes {
        assert_eq!(
            c.tx_status(*hash),
            Some(TransactionStatus::Completed(TransactionDecision::Aborted)),
            "a route held in the ring to its deadline aborts",
        );
    }
    assert_eq!(
        c.metric("hold_inversions_proven", None),
        proven,
        "no block can prove a ring off one counterpart's seats",
    );
    assert_eq!(
        c.metric("hold_contentions", None),
        contended,
        "a ring pairs no members awaiting a shard in common",
    );
    protocol_resource.assert_settles_within(c, &charges, epochs(8), "a ring of holds");
    units.assert_settles_within(c, &Charges::default(), epochs(8), "a ring of holds");
}

/// One route with the certificate channel cut across the trader's
/// deadline, and the trader's paid leg not reclaimed at it.
///
/// Neither venue can hear the other, pushes and pulls alike, so the
/// two-shard core commits the route and cannot settle it while the cut
/// stands. The trader's leg meanwhile pays its input, reaches its
/// deadline with the core silent, and asks the core's chain whether it
/// committed the transaction — a leg's crossing is reclaimed only on
/// proof the core never did, and a core that committed and cannot yet
/// answer is exactly what that probe must not mistake for absence. So
/// the leg stays paid. The cut lifts inside the delivery window, the
/// core settles, and the route accepts: paid once, delivered once.
///
/// One route rather than the usual four: the core's tick for the first
/// holds the venues' reserves as provisional claims until its
/// counterpart's certificate arrives, so a second route could not
/// compose while the cut stood and would be abandoned at the deadline
/// instead — a refusal the leg's reclaim rightly follows, and not the
/// boundary this pins.
///
/// Requires disjoint committees — a host serving both venues, or a venue
/// and the trader, would carry certificates in-process past the cut or
/// be cut off from its own shard by it.
///
/// # Panics
///
/// Panics if either venue misses its budget standing up, if the trader's
/// leg never pays, if the cut never fires or lifts outside the delivery
/// window, if the trader is refunded while the cut stands past the
/// probe's anchor, if the route does not accept once the cut lifts, or
/// if either side of the pair is not conserved.
pub fn a_route_cut_off_across_its_deadline_is_not_reclaimed<C: FaultableCluster>(c: &mut C) {
    let mut taken = Vec::new();
    let (first, second) = stand_up_venues(c, &mut taken);
    let traders = traders(&mut taken);
    let (key, trader) = &traders[0];
    // Neither venue can obtain the other's certificate by any path, push
    // or pull; the trader's shard is untouched, and its leg awaits nobody.
    let cut = [
        isolate_ec_intake(c, FIRST_VENUE_SHARD, SECOND_VENUE_SHARD),
        isolate_ec_intake(c, SECOND_VENUE_SHARD, FIRST_VENUE_SHARD),
    ];
    let (protocol_resource, units) = route_worlds(c, &first, &second, accounts(&traders));

    let mut charges = Charges::default();
    let validity = validity_around(c.now());
    let route = build_route_tx(
        key,
        *trader,
        (&first.meta, &second.meta),
        *PROTOCOL_RESOURCE,
        ROUTE_INPUT,
        0,
        validity,
    );
    let hash = charges.submit(c, route);

    // The trader's withdraw is a leg, its own to reach: it pays the input
    // and the price whatever the core does after.
    assert!(
        c.run_until(epochs(8), |c| held(c, trader.address(), *PROTOCOL_RESOURCE)
            < SWAPPER_FUNDING - ROUTE_INPUT),
        "the trader's leg must pay before the core is asked anything",
    );
    let paid = held(c, trader.address(), *PROTOCOL_RESOURCE);

    // Past the anchor a probe of the core is licensed at, and held there
    // until the probe has read the core's cell: the reading is `Present`
    // — the core's block is on its chain, its member still pending — and
    // that answers nothing, so the reclaim is not licensed. Read off the
    // probe rather than off a settling delay, so the scenario fails where
    // the evidence is instead of wherever a timer happened to land.
    let validity_end = validity.end_timestamp_exclusive;
    let anchor = Deadline::of(validity_end).at();
    let clock = |c: &C| WeightedTimestamp::ZERO.plus(c.now());
    assert!(
        c.run_until(epochs(8), |c| clock(c) >= anchor),
        "the cut must stand past the reclaim probe's anchor",
    );
    let probed = c.metric("reclaim_probes_pending", None);
    let reclaimed = c.metric("reclaims_admitted", None);
    assert!(
        c.run_until(epochs(8), |c| c.metric("reclaim_probes_pending", None)
            > probed),
        "the trader's leg must probe the core past its deadline and read \
         that the core's block is there",
    );
    assert!(
        cut.iter().any(|handle| handle.fired() > 0),
        "the certificate channel must actually have been exercised and cut",
    );
    for shard in [FIRST_VENUE_SHARD, SECOND_VENUE_SHARD] {
        assert!(
            c.chain_fate(shard, hash).1.is_none(),
            "the core must still be waiting on its certificates when the cut lifts, \
             or the reclaim below is answered by its verdict rather than by the probe",
        );
    }
    assert_eq!(
        held(c, trader.address(), *PROTOCOL_RESOURCE),
        paid,
        "a leg whose core committed the transaction must stay paid at its deadline: \
         the probe finds the core's block, and the reclaim is refused",
    );
    assert_eq!(
        c.metric("reclaims_admitted", None),
        reclaimed,
        "a present answer licenses no reclaim anywhere in the cluster",
    );

    // Whole network from here: the certificates flow, the core settles,
    // and the trader banks the route's output.
    c.clear_drops();
    assert!(
        c.run_until(epochs(8), |c| held(c, trader.address(), *PROTOCOL_RESOURCE)
            > paid),
        "the core must settle once its certificates flow, and the route bank its output",
    );
    let status = c.tx_status(hash);
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "a route cut off across its deadline must still settle whole; status = {status:?}",
    );
    protocol_resource.assert_settles_within(
        c,
        &charges,
        epochs(8),
        "a route cut off across the deadline",
    );
    units.assert_settles_within(
        c,
        &Charges::default(),
        epochs(8),
        "a route cut off across the deadline",
    );
}

/// How far past a waiting member's abandon window the halt stands, so
/// the first anchor the resumed shard certifies lies beyond the window
/// whichever round its votes were cast in.
const HALT_PAST_WINDOW: Duration = Duration::from_secs(60);

/// Blocks the resumed shard commits before fresh work is submitted: the
/// first block past a halt is anchored at the certificate the halt
/// froze, and a transaction opened after the halt is admissible only at
/// an anchor past it.
const RESUMED_BLOCKS: u64 = 3;

/// How many transfers ask the resumed shard for an outcome.
const RESUMED_TRANSFERS: u8 = 3;

/// A shard halted across a waiting member's whole abandon window still
/// settles what it commits once it resumes.
///
/// A route's core holds the first venue's reserves while its sibling's
/// certificate is cut, so a swap by a caller on that venue's shard
/// commits and waits behind the hold. The shard then certifies nothing
/// until the swap's deadline and the validity range past it are both
/// behind the cluster clock: no block's anchor lands inside the swap's
/// abandon window, so the block that names its abort is one whose
/// commit holds no execution ledger entry for it. The votes return, the
/// cut lifts, and every transfer local to the shard reaches an outcome.
///
/// Requires disjoint committees, as its neighbours do.
///
/// # Panics
///
/// Panics if either venue misses its budget standing up, if a transfer
/// local to the first venue's shard does not accept before the halt, if
/// the route's core is never held or the swap never waits behind it, if
/// the shard commits through the halt or does not commit again after
/// it, or if a transfer submitted to the resumed shard reaches no
/// outcome.
pub fn a_shard_halted_across_an_abandon_window_settles_again<C: FaultableCluster>(c: &mut C) {
    let shard = FIRST_VENUE_SHARD;
    let mut taken = Vec::new();
    let (first, second) = stand_up_venues(c, &mut taken);
    let traders = traders(&mut taken);
    let (caller_key, caller) = sponsor(&mut taken);
    let (payer_key, payer) = grind_onto(shard, &mut Vec::new());
    let (key, trader) = &traders[0];
    let row = |c: &C, tx: TxHash| c.member_rows(shard).and_then(|rows| rows.get(&tx).copied());
    let local_transfer = |c: &mut C, amount: u128| {
        let tx = build_transfer_tx(&payer_key, payer, caller, amount, validity_around(c.now()));
        let hash = tx.hash();
        c.submit(Arc::new(tx));
        hash
    };

    let healthy = local_transfer(c, 1);
    let status = await_tx_terminal(c, healthy, epochs(8));
    assert_eq!(
        status,
        Some(TransactionStatus::Completed(TransactionDecision::Accept)),
        "a transfer local to {shard:?} must accept while nothing is cut",
    );

    let cut = [
        isolate_ec_intake(c, FIRST_VENUE_SHARD, SECOND_VENUE_SHARD),
        isolate_ec_intake(c, SECOND_VENUE_SHARD, FIRST_VENUE_SHARD),
    ];
    let route = build_route_tx(
        key,
        *trader,
        (&first.meta, &second.meta),
        *PROTOCOL_RESOURCE,
        ROUTE_INPUT,
        0,
        validity_around(c.now()),
    );
    let route_hash = route.hash();
    c.submit(Arc::new(route));
    assert!(
        c.run_until(epochs(8), |c| matches!(
            row(c, route_hash),
            Some(RowState::InFlight { .. } | RowState::Stated { .. })
        )),
        "the route's core must be held on {shard:?}; its row stands {:?}",
        row(c, route_hash),
    );

    let validity = validity_around(c.now());
    let swap = build_swap_tx(
        &caller_key,
        caller,
        &first.meta,
        *PROTOCOL_RESOURCE,
        SWAP_INPUT,
        0,
        validity,
    );
    let swap_hash = swap.hash();
    c.submit(Arc::new(swap));
    assert!(
        c.run_until(epochs(2), |c| row(c, swap_hash) == Some(RowState::Pending)),
        "the swap must commit and wait behind the held reserves; its row stands {:?}",
        row(c, swap_hash),
    );

    let window = Deadline::of(validity.end_timestamp_exclusive)
        .at()
        .plus(MAX_VALIDITY_RANGE);
    let halt = Halt::of(c, shard);
    let frozen = halt.stand_until(c, window.plus(HALT_PAST_WINDOW));
    assert!(
        cut.iter().any(|handle| handle.fired() > 0),
        "the certificate channel must actually have been exercised and cut",
    );
    assert_eq!(
        row(c, swap_hash),
        Some(RowState::Pending),
        "the swap must still wait when the shard resumes",
    );

    halt.lift(c);
    c.clear_drops();
    let target = BlockHeight::new(frozen.inner() + RESUMED_BLOCKS);
    assert!(
        c.run_until(epochs(4), |c| c.committed_height(shard) >= Some(target)),
        "{shard:?} must commit again once its votes return; it stands at {:?}",
        c.committed_height(shard),
    );

    let transfers: Vec<TxHash> = (0..RESUMED_TRANSFERS)
        .map(|index| local_transfer(c, 2 + u128::from(index)))
        .collect();
    for hash in transfers {
        let status = await_tx_terminal(c, hash, epochs(8));
        assert!(
            matches!(status, Some(TransactionStatus::Completed(_))),
            "a transfer local to {shard:?} must reach an outcome after the halt; status = \
             {status:?}, its row stands {:?}, the swap's {:?}, the route's {:?}, and {shard:?} \
             at {:?}",
            row(c, hash),
            row(c, swap_hash),
            row(c, route_hash),
            c.committed_height(shard),
        );
    }
}

/// A shard held below quorum: half its committee withholds its block
/// votes, so no certificate forms while its proposals and timeouts
/// still flow.
struct Halt {
    shard: ShardId,
    withholding: Vec<ValidatorId>,
    votes_withheld: FaultHandle,
}

impl Halt {
    /// Halt `shard` from now.
    fn of<C: FaultableCluster>(c: &mut C, shard: ShardId) -> Self {
        let members: Vec<ValidatorId> = c
            .beacon_state()
            .and_then(|state| state.shard_consensus_members.get(&shard).cloned())
            .expect("the halting shard has a consensus committee");
        let withholding = members[..members.len() / 2].to_vec();
        let votes_withheld = c.withhold(&withholding, Withheld::Votes);
        Self {
            shard,
            withholding,
            votes_withheld,
        }
    }

    /// Let the rounds in flight drain, then hold the shard at the height
    /// it froze at until the cluster clock reaches `until`, and return
    /// that height.
    fn stand_until<C: FaultableCluster>(&self, c: &mut C, until: WeightedTimestamp) -> BlockHeight {
        c.run_until(epochs(1), |_| false);
        let frozen = c.committed_height(self.shard).expect("the shard committed");
        assert!(
            c.run_until(epochs(12), |c| WeightedTimestamp::ZERO.plus(c.now())
                >= until),
            "the halt must stand until {until:?}",
        );
        assert!(
            self.votes_withheld.fired() > 0,
            "the withheld votes must actually be refused",
        );
        assert_eq!(
            c.committed_height(self.shard),
            Some(frozen),
            "half the committee withholding leaves no quorum, so the shard must halt",
        );
        frozen
    }

    /// Give the committee its votes back.
    fn lift<C: FaultableCluster>(&self, c: &mut C) {
        c.withhold(&self.withholding, Withheld::Nothing);
    }
}

/// Blocks each venue commits between the reclaim landing and the reserves
/// being read again — a second reclaim of the same transaction would ride
/// one of the next few.
const RECLAIM_TAIL_BLOCKS: u64 = 16;

/// Assert both venues hold exactly what they held before a refused
/// route, and hold it once.
///
/// Driven until the reclaim lands rather than read once: the verdict
/// comes from the hop that declined and the reclaim is a block of the
/// first venue's own, so it follows the trader's refund. Then read
/// again after each venue has committed [`RECLAIM_TAIL_BLOCKS`] more —
/// the equality is reached on the way past if the shard keeps
/// reclaiming the same transaction, so sampling it once says nothing
/// about how many times the claim came back.
fn assert_venues_gave_back<C: Cluster>(
    c: &mut C,
    (first_cell, second_cell): (SubstateKey, SubstateKey),
    (first_before, second_before): (u128, u128),
    budget: Budget,
) {
    let reclaimed = c.run_until(budget, |c| {
        held_at(c, first_cell) == first_before && held_at(c, second_cell) == second_before
    });
    let (first_after, second_after) = (held_at(c, first_cell), held_at(c, second_cell));
    assert!(
        reclaimed,
        "a refused route leaves neither venue holding a claim of it: \
         first {first_before} before and {first_after} after, \
         second {second_before} before and {second_after} after, \
         on an input of {ROUTE_INPUT}",
    );

    for venue in [FIRST_VENUE_SHARD, SECOND_VENUE_SHARD] {
        assert!(
            await_blocks(c, venue, RECLAIM_TAIL_BLOCKS, epochs(1)),
            "venue {venue} must keep committing after the reclaim",
        );
    }
    assert_eq!(
        (held_at(c, first_cell), held_at(c, second_cell)),
        (first_before, second_before),
        "a claim comes back once: {first_before} and {second_before} before \
         the route, {} and {} after the chain ran on",
        held_at(c, first_cell),
        held_at(c, second_cell),
    );
}

/// Who pays a held route's fee.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FeePayer {
    /// The trader, whose own leg charges it.
    Trader,
    /// A sponsor on the first venue's shard, whose core member charges it.
    Sponsor,
}

/// A core whose siblings never combine holds its input, and settles
/// whole once they do.
///
/// [`a_route_cut_off_across_its_deadline_is_not_reclaimed`] holds the
/// same cut and lifts it before the producer's leaf can read anything.
/// This one holds it past the close of [`Window::Core`], and pins that
/// nothing speaks there: the trader's input is neither refunded nor
/// banked, neither venue writes a `Never`, and the one escrowed record
/// stands locked at [`ROUTE_INPUT`], named by the world's report. A
/// member awaiting a sibling is never released for being wedged and
/// never abandoned while uncovered, so once the cut lifts the core
/// combines, the route settles whole, the resource is conserved and the
/// report is empty. The trader's leg burns the price before the core is
/// held, and the burn, not the verdict the core still owes, ends the fee
/// hold.
///
/// **The verdict is a presence, and only the consumer speaks it.** A
/// claim's absence answers nothing at any anchor, and a core member held
/// by a silent sibling has no answer to give: its certificate may be
/// out, and the sibling may yet combine an accept with it. What the
/// producer waits on is the member's own verdict, whenever it comes.
///
/// Requires disjoint committees, as its neighbour does.
///
/// # Panics
///
/// Panics if either venue misses its budget standing up, if the trader's
/// leg never pays, if the cut never fires, if anything moves the input
/// while the cut stands, if a venue writes a `Never` for a crossing its
/// member may still take, if the fee hold outlives the leg's burn, if
/// the route does not settle whole once the cut lifts, or if the
/// resource is not conserved.
pub fn a_route_whose_core_never_combines_holds_its_input<C: FaultableCluster>(c: &mut C) {
    route_held_by_a_silent_sibling(c, FeePayer::Trader);
}

/// A core member its silent sibling holds keeps its sponsor's fee hold
/// for as long as the strand lasts, and settles it once with the route.
///
/// [`a_route_whose_core_never_combines_holds_its_input`] with the fee
/// paid by a sponsor on the first venue's shard, so the charge is the
/// held core member's rather than the trader's leg's. The hold and the
/// vault's total stand under the member while its sibling is silent past
/// the close of [`Window::Core`]: an unsettled member is released only
/// beside a charge, and nothing charges it there. Once the cut lifts the
/// route settles whole and the sponsor is charged its price once.
///
/// # Panics
///
/// As [`a_route_whose_core_never_combines_holds_its_input`], and if the
/// sponsor's hold does not stand while the core is held or the sponsor
/// is not charged its price once.
pub fn a_route_whose_held_core_keeps_its_sponsors_hold<C: FaultableCluster>(c: &mut C) {
    route_held_by_a_silent_sibling(c, FeePayer::Sponsor);
}

/// Hold one route's core by cutting its siblings' certificates past the
/// close of [`Window::Core`], then lift the cut and settle it, its fee
/// paid by `payer`.
fn route_held_by_a_silent_sibling<C: FaultableCluster>(c: &mut C, payer: FeePayer) {
    let mut taken = Vec::new();
    let (first, second) = stand_up_venues(c, &mut taken);
    let traders = traders(&mut taken);
    let sponsor = sponsor(&mut taken);
    let (key, trader) = &traders[0];
    let cut = [
        isolate_ec_intake(c, FIRST_VENUE_SHARD, SECOND_VENUE_SHARD),
        isolate_ec_intake(c, SECOND_VENUE_SHARD, FIRST_VENUE_SHARD),
    ];
    let (protocol_resource, units) =
        route_worlds(c, &first, &second, accounts(&traders).chain([sponsor.1]));

    let mut charges = Charges::default();
    let validity = validity_around(c.now());
    let funded = held(c, trader.address(), *PROTOCOL_RESOURCE);
    let venues = (&first.meta, &second.meta);
    let route = match payer {
        FeePayer::Trader => build_route_tx(
            key,
            *trader,
            venues,
            *PROTOCOL_RESOURCE,
            ROUTE_INPUT,
            0,
            validity,
        ),
        FeePayer::Sponsor => {
            build_sponsored_route_tx(&sponsor.0, key, *trader, venues, ROUTE_INPUT, validity)
        }
    };
    let fee = FeeHeld::of(c, &route, sponsor.1);
    let hash = charges.submit(c, route);

    assert!(
        c.run_until(epochs(8), |c| held(c, trader.address(), *PROTOCOL_RESOURCE)
            <= funded - ROUTE_INPUT),
        "the trader's leg must pay the input before the core is asked anything",
    );
    let paid = held(c, trader.address(), *PROTOCOL_RESOURCE);

    let deadline = Deadline::of(validity.end_timestamp_exclusive);
    hold_past_the_core_window(c, deadline);
    assert!(
        cut.iter().any(|handle| handle.fired() > 0),
        "the certificate channel must actually have been exercised and cut",
    );
    assert_nothing_spoke(c, hash, *trader, paid);
    fee.assert_while_held(c, payer);
    let locked = protocol_resource.locked(c, &charges);
    assert_eq!(
        locked.len(),
        1,
        "the one escrowed record stands locked: {locked:?}"
    );
    assert_eq!(
        (locked[0].kind, locked[0].amount),
        (Kind::Escrowed, ROUTE_INPUT),
        "and it is the trader's input: {locked:?}",
    );

    // The siblings combine, and the route settles whole.
    c.clear_drops();
    assert!(
        c.run_until(epochs(12), |c| held(
            c,
            trader.address(),
            *PROTOCOL_RESOURCE
        ) > paid),
        "once the cut lifts the core must combine and the route bank its output: \
         trader holds {} against {paid}",
        held(c, trader.address(), *PROTOCOL_RESOURCE),
    );
    let status = c.tx_status(hash);
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "a route whose core was held must still settle whole; status = {status:?}",
    );
    let locked = protocol_resource.assert_settles_within(
        c,
        &charges,
        epochs(10),
        "a route whose core never combined",
    );
    assert!(
        locked.is_empty(),
        "nothing stays locked once the route settled: {locked:?}"
    );
    units.assert_settles_within(
        c,
        &Charges::default(),
        epochs(10),
        "a route whose core never combined",
    );
    if payer == FeePayer::Sponsor {
        fee.assert_sponsor_charged_once(c);
    }
}

/// A held route's fee hold, and what its sponsor held before.
struct FeeHeld {
    hold: SubstateKey,
    total: SubstateKey,
    sponsor: PrincipalAddr,
    funded: u128,
    price: u128,
}

impl FeeHeld {
    fn of<C: Cluster>(c: &C, route: &Transaction, sponsor: PrincipalAddr) -> Self {
        route
            .try_declared(c.derivation().as_ref())
            .expect("a route declares its terms");
        let fee = FeeTerms::of(route);
        Self {
            hold: fee.hold_key(),
            total: fee_hold_total_key(&ProtocolHasher, fee.vault),
            sponsor,
            funded: held(c, sponsor.address(), *PROTOCOL_RESOURCE),
            price: declared_price(c, route),
        }
    }

    /// While the core is held: the trader's leg burned the price, and the
    /// burn ends the hold, since a reservation lasts until the payer's
    /// shard charges; a sponsor's hold stands under the held core member,
    /// which nothing charges.
    fn assert_while_held<C: Cluster>(&self, c: &C, payer: FeePayer) {
        match payer {
            FeePayer::Trader => assert!(
                !stands_at(c, self.hold),
                "the leg's burn ends its payer's fee hold whatever the core still owes",
            ),
            FeePayer::Sponsor => assert!(
                stands_at(c, self.hold) && stands_at(c, self.total),
                "a core member its sibling holds keeps its sponsor's hold and total",
            ),
        }
    }

    fn assert_sponsor_charged_once<C: Cluster>(&self, c: &C) {
        assert_eq!(
            held(c, self.sponsor.address(), *PROTOCOL_RESOURCE),
            self.funded - self.price,
            "the sponsor pays the route's price once",
        );
    }
}

/// Run past the close of the core window and hold there for the tail a
/// refund would land in: no clock of any shard's speaks for a member
/// awaiting its sibling, so what a wrong clock would do is given room
/// to show.
///
/// # Panics
///
/// Panics if the clock never reaches the close, or a venue stops
/// committing past it.
fn hold_past_the_core_window<C: Cluster>(c: &mut C, deadline: Deadline) {
    let close = Window::Core.of(deadline).end;
    let clock = |c: &C| WeightedTimestamp::ZERO.plus(c.now());
    assert!(
        c.run_until(epochs(70), |c| clock(c) >= close),
        "the cut must stand past the close of the core window; clock {:?} against {close:?}",
        clock(c),
    );
    for venue in [FIRST_VENUE_SHARD, SECOND_VENUE_SHARD] {
        assert!(
            await_blocks(c, venue, RECLAIM_TAIL_BLOCKS, epochs(2)),
            "venue {venue} must keep committing past the close",
        );
    }
}

/// Assert that nothing has spoken for the route `hash` while its core is
/// held by a silent sibling: the trader still holds exactly `paid`, and
/// neither venue has certified or written a `Never`.
///
/// # Panics
///
/// Panics if the input moved, or a venue certified or answered.
fn assert_nothing_spoke<C: Cluster>(c: &C, hash: TxHash, trader: PrincipalAddr, paid: u128) {
    assert_eq!(
        held(c, trader.address(), *PROTOCOL_RESOURCE),
        paid,
        "while the core is held by its silent sibling the input is neither refunded nor banked",
    );
    for shard in [FIRST_VENUE_SHARD, SECOND_VENUE_SHARD] {
        assert!(
            c.chain_fate(shard, hash).1.is_none(),
            "neither venue may certify while its sibling is silent",
        );
        assert!(
            c.declined(shard, hash).is_empty(),
            "and neither may write a Never for a crossing its member may still take",
        );
    }
}

/// Whether the first venue's shard holds an unseen `Never` at `decline`.
fn unseen_never_at<C: Cluster>(c: &C, decline: SubstateKey) -> bool {
    c.substate(FIRST_VENUE_SHARD, decline.owner, decline.local.0)
        .as_deref()
        .and_then(CrossingAnswer::from_bytes)
        .is_some_and(|answer| answer.answered == Answered::Never && !answer.seen)
}

/// An unseen decline goes once its producer's leg is fated, and not at
/// that leg's reclaim.
///
/// The route's second venue never engages: every bundle it would need is
/// cut away from it, so the route never enters a block there. The
/// trader's leg waits on both venues' bundles and so never runs, and
/// never writes the record of its escrowed input. The first venue commits
/// the route, stands past its deadline with its sibling silent, and is
/// aborted, declining the input's crossing unseen, since its member never
/// read the record. An absence alone must not delete such a decline,
/// which might predate the record's write: it goes only once the
/// producer's member row is read absent.
///
/// The trader's shard reads the decline and reclaims: with no record to
/// take back the reclaim is refused, charges nothing, and releases the
/// leg's row, which stands. So the decline stands past the reclaim, and
/// the first venue keeps asking for the row beside the record. The block
/// anchored at the close of the leg entry window fates the row, burning
/// the trader's declared price once; the first venue then reads the row
/// absent and deletes the decline. The trader's input never left, and
/// both worlds settle with nothing locked.
///
/// Requires disjoint committees, as its neighbours do.
///
/// # Panics
///
/// Panics if either venue misses its budget standing up, if the first
/// venue never commits the route or never declines the crossing unseen,
/// if the second venue engages, if the reclaim moves the trader's vault
/// or ends the decline, if the decline goes before the trader's leg is
/// fated or outlives its fate, if the leg is fated short of its window's
/// close, if the trader is not charged its price once, or if either world
/// is not conserved.
pub fn an_unseen_never_goes_once_its_producers_leg_is_fated<C: FaultableCluster>(c: &mut C) {
    let mut taken = Vec::new();
    let (first, second) = stand_up_venues(c, &mut taken);
    let traders = traders(&mut taken);
    let (key, trader) = &traders[0];
    let second_hosts = c.committee_hosts(SECOND_VENUE_SHARD);
    let others: Vec<usize> = (0..c.host_count())
        .filter(|host| !second_hosts.contains(host))
        .collect();
    let cut = [
        c.drop_type_between(&others, &second_hosts, "provisions.broadcast"),
        c.drop_type_between(&second_hosts, &others, "provision.request"),
    ];
    let (mut protocol_resource, units) = route_worlds(c, &first, &second, accounts(&traders));

    let mut charges = Charges::default();
    let funded = held(c, trader.address(), *PROTOCOL_RESOURCE);
    let validity = validity_around(c.now());
    let route = build_route_tx(
        key,
        *trader,
        (&first.meta, &second.meta),
        *PROTOCOL_RESOURCE,
        ROUTE_INPUT,
        0,
        validity,
    );
    let price = declared_price(c, &route);
    let hold = FeeTerms::of(&route).hold_key();
    let decline = crossing_between(c, &route, TRADER_SHARD, FIRST_VENUE_SHARD)
        .answer_key(&ProtocolHasher, Answered::Never);
    let hash = charges.submit(c, route);
    protocol_resource.owing(charges.records(c));

    assert!(
        c.run_until(epochs(8), |c| c
            .chain_fate(FIRST_VENUE_SHARD, hash)
            .0
            .is_some()),
        "the first venue must commit the route",
    );
    assert!(
        c.run_until(epochs(12), |c| stands_at(c, decline)),
        "the first venue must decline the input it stood past its deadline for",
    );
    assert!(
        unseen_never_at(c, decline),
        "and the decline is the abandonment's, unseen"
    );

    // The trader's shard reclaims on the decline. Its leg never ran, so
    // the reclaim finds no record, charges nothing and deletes no row.
    await_reclaim_that_burns_nothing(c, TRADER_SHARD, hash, hold, epochs(12));
    assert_eq!(
        (
            held(c, trader.address(), *PROTOCOL_RESOURCE),
            unseen_never_at(c, decline),
        ),
        (funded, true),
        "the reclaim must leave the trader's vault as it was and the decline standing: the \
         leg's row stands until its fate",
    );

    // The decline stands until the leg's row is fated at the close of
    // its leg entry window, and goes once the first venue reads the row
    // absent.
    await_reclaimed_leg_fated(
        c,
        TRADER_SHARD,
        hash,
        validity.end_timestamp_exclusive,
        |c| !stands_at(c, decline),
    );
    assert!(
        c.run_until(epochs(12), |c| !stands_at(c, decline)),
        "the decline must go once its producer's member row is read absent",
    );
    assert!(
        c.chain_fate(SECOND_VENUE_SHARD, hash).0.is_none(),
        "the second venue must never have engaged",
    );
    assert!(
        cut.iter().any(|handle| handle.fired() > 0),
        "the bundles must actually have been cut",
    );
    c.clear_drops();

    assert!(
        c.run_until(epochs(12), |c| held(
            c,
            trader.address(),
            *PROTOCOL_RESOURCE
        ) == funded - price),
        "the trader's input never left, and the fate burns its price once: holds {} against {}",
        held(c, trader.address(), *PROTOCOL_RESOURCE),
        funded - price,
    );
    let locked = protocol_resource.assert_settles_within(
        c,
        &charges,
        epochs(8),
        "an unseen decline past its producer's fate",
    );
    assert!(locked.is_empty(), "nothing stays locked: {locked:?}");
    units.assert_settles_within(
        c,
        &Charges::default(),
        epochs(8),
        "an unseen decline past its producer's fate",
    );
}

/// The crossing a route hands from its node on `producer` to its node on
/// `consumer`.
///
/// # Panics
///
/// Panics if the route does not derive, or crosses no edge between the
/// two.
fn crossing_between<C: Cluster>(
    c: &C,
    route: &Transaction,
    producer: ShardId,
    consumer: ShardId,
) -> CrossingId {
    let legs = &route
        .try_derived(c.derivation().as_ref())
        .expect("a scenario route derives")
        .legs;
    let trie = ShardTrie::uniform(2);
    legs.iter()
        .flat_map(|to| to.edges.iter().map(move |edge| (to, edge)))
        .find_map(|(to, edge)| {
            let from = &legs[edge.source as usize];
            (trie.shard_for_prefix(from.target) == producer
                && trie.shard_for_prefix(to.target) == consumer)
                .then(|| CrossingId::of_edge(from, to.target, edge.output))
        })
        .expect("the route crosses from the producer's venue to the consumer's")
}

/// A crossing whose consumer has refused it is declined by the
/// consumer's own finalization.
///
/// The ordinary refusal. A venue asked for a price no pool this size can
/// pay refuses its member, and a refused member's writes are discarded —
/// so the claim is never written and the record stands. What the venue's
/// refusal receipt writes instead is `Never` at the crossing's decline
/// key, and it lands with the rejecting finalization itself: on no
/// clock, past no deadline, waiting on no member. With the venue's
/// verdict cut off from the shard that staged the value, the producer
/// cannot reclaim off it until the cut lifts, and the `Never` is what
/// it then reclaims off.
///
/// Its pair is [`a_route_whose_core_never_combines_holds_its_input`],
/// where a venue holds a member it cannot run and says nothing at all.
///
/// Requires disjoint committees, as its neighbours do.
///
/// # Panics
///
/// Panics if either venue misses its budget standing up, if the caller's
/// leg never pays, if the venue does not refuse, if the `Never` does not
/// land with the refusing finalization, if the cut never fires, if the
/// input never comes home, or if either side of the pair is not
/// conserved.
pub fn a_crossing_the_consumer_refuses_is_declined<C: FaultableCluster>(c: &mut C) {
    let mut taken = Vec::new();
    let (first, second) = stand_up_venues(c, &mut taken);
    let traders = traders(&mut taken);
    let (key, trader) = &traders[0];
    // The venue's own committee certifies its refusal; what is cut is
    // the road that verdict takes to the shard holding the record, so
    // the producer has nothing to reclaim off while the cut stands.
    let cut = isolate_ec_intake(c, TRADER_SHARD, FIRST_VENUE_SHARD);
    let (protocol_resource, units) = route_worlds(c, &first, &second, accounts(&traders));

    let mut charges = Charges::default();
    let validity = validity_around(c.now());
    let swap = build_swap_tx(
        key,
        *trader,
        &first.meta,
        *PROTOCOL_RESOURCE,
        ROUTE_INPUT,
        REFUSED_FLOOR,
        validity,
    );
    let hash = charges.submit(c, swap);

    assert!(
        c.run_until(epochs(8), |c| held(c, trader.address(), *PROTOCOL_RESOURCE)
            < SWAPPER_FUNDING - ROUTE_INPUT),
        "the caller's leg must stage the input, or no crossing was ever handed across",
    );
    let staged = held(c, trader.address(), *PROTOCOL_RESOURCE);
    assert!(
        c.run_until(epochs(8), |c| matches!(
            c.chain_fate(FIRST_VENUE_SHARD, hash).1,
            Some((_, TransactionDecision::Reject))
        )),
        "the venue must refuse the swap: a refused member is what leaves the claim unwritten",
    );
    let (refused_at, _) = c
        .chain_fate(FIRST_VENUE_SHARD, hash)
        .1
        .expect("the venue refused");
    let declined: Vec<BlockHeight> = c
        .declined(FIRST_VENUE_SHARD, hash)
        .into_iter()
        .map(|(height, _)| height)
        .collect();
    assert_eq!(
        declined,
        vec![refused_at],
        "the Never lands with the venue's rejecting finalization and rides nothing else",
    );
    assert!(
        c.run_until(epochs(4), |_| cut.fired() > 0),
        "the certificate channel must actually have been exercised and cut",
    );

    // The verdict reaches the producer, and the input comes home off the
    // `Never` once, with the pair conserved across it.
    c.clear_drops();
    assert!(
        c.run_until(epochs(10), |c| held(
            c,
            trader.address(),
            *PROTOCOL_RESOURCE
        ) > staged),
        "the input must come home once the verdict reaches the producer: caller holds {}",
        held(c, trader.address(), *PROTOCOL_RESOURCE),
    );
    protocol_resource.assert_settles_within(c, &charges, epochs(10), "a refused crossing");
    units.assert_settles_within(c, &Charges::default(), epochs(10), "a refused crossing");
}

/// Everything that can hold each side of the pair in a route scenario:
/// the traders and the two venues themselves. The providers stocked and
/// hold nothing a route can reach.
/// The accounts of `keyed` signers.
fn accounts(
    keyed: &[(Ed25519PrivateKey, PrincipalAddr)],
) -> impl Iterator<Item = PrincipalAddr> + '_ {
    keyed.iter().map(|(_, account)| *account)
}

pub fn route_worlds<C: Cluster>(
    c: &C,
    first: &StockedVenue,
    second: &StockedVenue,
    holders: impl IntoIterator<Item = PrincipalAddr>,
) -> (World, World) {
    let holders: Vec<Address> = holders.into_iter().map(PrincipalAddr::address).collect();
    let protocol_resource = World::open(
        c,
        *PROTOCOL_RESOURCE,
        holders.iter().copied(),
        [
            reserve_cell(&first.meta, *PROTOCOL_RESOURCE),
            reserve_cell(&second.meta, *PROTOCOL_RESOURCE),
        ],
    );
    let units = World::open(
        c,
        first.unit,
        holders,
        [
            reserve_cell(&first.meta, first.unit),
            reserve_cell(&second.meta, second.unit),
        ],
    );
    (protocol_resource, units)
}

/// Drive every trader's route through both venues and hold the run to
/// every route accepting, with both sides of the pair conserved.
/// Which way a route's record crosses: into the core from the trader's
/// inbound leg, or out of it to the trader's outbound leg. An edge
/// between two core legs writes no record, since every core shard runs
/// the whole core.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecordRoad {
    IntoTheCore,
    OutOfTheCore,
}

/// The records a route's legs write, each with the road it crosses.
fn records_by_road(legs: &[LegShape]) -> Vec<(SubstateKey, RecordRoad)> {
    legs.iter()
        .flat_map(|consumer| consumer.edges.iter().map(move |edge| (consumer, edge)))
        .filter_map(|(consumer, edge)| {
            let producer = legs.get(edge.source as usize)?;
            let road = match (producer.role, consumer.role) {
                (LegRole::Inbound, LegRole::Core) => RecordRoad::IntoTheCore,
                (LegRole::Core, LegRole::Outbound) => RecordRoad::OutOfTheCore,
                _ => return None,
            };
            let key = CrossingId::of_edge(producer, consumer.target, edge.output)
                .record_key(&ProtocolHasher);
            Some((key, road))
        })
        .collect()
}

fn drive_routes<C: Cluster>(
    c: &mut C,
    first: &StockedVenue,
    second: &StockedVenue,
    traders: &[(Ed25519PrivateKey, PrincipalAddr)],
    budget: Budget,
) -> RouteReport {
    let (protocol_resource, units) = route_worlds(c, first, second, accounts(traders));

    let start = c.now();
    let mut charges = Charges::default();
    let mut submissions: Vec<TxHash> = Vec::with_capacity(traders.len());
    let mut records: Vec<(SubstateKey, RecordRoad)> = Vec::new();
    for (key, account) in traders {
        let tx = build_route_tx(
            key,
            *account,
            (&first.meta, &second.meta),
            *PROTOCOL_RESOURCE,
            ROUTE_INPUT,
            0,
            validity_around(c.now()),
        );
        records.extend(records_by_road(
            &tx.try_derived(c.derivation().as_ref())
                .expect("a scenario route derives")
                .legs,
        ));
        submissions.push(charges.submit(c, tx));
    }

    let all = c.run_until(budget, |c| {
        submissions
            .iter()
            .all(|hash| c.tx_status(*hash).is_some_and(|s| s.is_final()))
    });
    assert!(
        all,
        "the route never settled within budget: {:?}",
        submissions
            .iter()
            .map(|hash| (*hash, c.tx_status(*hash)))
            .collect::<Vec<_>>(),
    );

    for hash in &submissions {
        let status = c.tx_status(*hash);
        assert!(
            matches!(
                status,
                Some(TransactionStatus::Completed(TransactionDecision::Accept))
            ),
            "a route spanning two core shards must settle whole; status = {status:?}",
        );
    }

    // Each trader's records reached their consumers as held readings in
    // the consumers' chains: pushed by the producer's next proposer, or
    // read by the consumer when no push landed. The inbound record is
    // consumed by the core, which every venue shard runs, so both venue
    // chains read it; the outbound record is consumed on the trader's shard,
    // where the deposit that banks the trader's output lands a hop
    // after the second venue's verdict. Waited for, since the verdict
    // is what the status reports and the deposit is what conserves.
    assert!(
        !records.is_empty(),
        "a route through two venues writes records"
    );
    let readers = |road: &RecordRoad| -> &'static [ShardId] {
        match road {
            RecordRoad::IntoTheCore => &[FIRST_VENUE_SHARD, SECOND_VENUE_SHARD],
            RecordRoad::OutOfTheCore => &[TRADER_SHARD],
        }
    };
    let unread = |c: &C| -> Vec<(SubstateKey, RecordRoad)> {
        records
            .iter()
            .filter(|(key, road)| {
                readers(road)
                    .iter()
                    .any(|shard| !c.reads_record(*shard, *key))
            })
            .copied()
            .collect()
    };
    let delivered = c.run_until(budget, |c| unread(c).is_empty());
    assert!(
        delivered,
        "every trader's record must be read by its consumers' chains within budget; unread: {:?}",
        unread(c),
    );

    // Nothing here mints: the protocol resource the traders paid in is what the venues
    // now hold less the prices burned, and the units the first venue
    // paid out are what the second took back.
    protocol_resource.assert_settles_within(c, &charges, budget, "routes through two venues");
    units.assert_settles_within(c, &Charges::default(), budget, "routes through two venues");

    RouteReport {
        submitted: submissions.len(),
        elapsed: c.now().saturating_sub(start),
    }
}

/// A route refused at its second venue gives back what the first venue
/// took.
///
/// The refusal is where a two-shard core costs something a one-shard
/// core never owed: the first venue priced and claimed the trader's
/// escrow, and the refusal comes from a shard that ran after it. What
/// has to hold is that the claim is taken back — the trader keeps what
/// it paid in, both venues keep what they were holding, and neither is
/// left with a crossing the other has already spent.
///
/// The trader's half is read off its vault, because spending alone does
/// not prove it: a trader funded for several routes can pay for the next
/// one out of what it kept, and a route that quietly took the input
/// would read as a pass. So the vault is measured across the refusal,
/// and what it must show is the input back — the price the refusal
/// settles is the only thing the trader is out.
///
/// The venues' halves are read off their reserves, before and after.
/// Spending does not prove them, and proves them in the wrong direction:
/// a venue that wrongly *kept* the input holds a deeper reserve and
/// prices more easily, so a second route through the same two hops is
/// satisfied by the very failure it would be standing in for.
///
/// # Panics
///
/// Panics if either venue misses its budget standing up, if the refused
/// route does not refuse, if the trader or either venue is left holding
/// anything but what it started with less the price, or if the route
/// after it does not accept.
pub fn a_route_refused_at_its_second_venue_gives_back_what_the_first_took<C: Cluster>(
    c: &mut C,
    budget: Budget,
) {
    let mut taken = Vec::new();
    let (first, second) = stand_up_venues(c, &mut taken);
    let cast = traders(&mut taken);
    let (trader_key, trader) = (&cast[0].0, cast[0].1);

    // A floor no pool this size can pay, held by the hop that runs last.
    let refused = build_route_tx(
        trader_key,
        trader,
        (&first.meta, &second.meta),
        *PROTOCOL_RESOURCE,
        ROUTE_INPUT,
        REFUSED_FLOOR,
        validity_around(c.now()),
    );
    let price = declared_price(c, &refused);
    let funded = vault_balance(c, TRADER_SHARD, trader);
    let (first_cell, second_cell) = (
        reserve_cell(&first.meta, *PROTOCOL_RESOURCE),
        reserve_cell(&second.meta, *PROTOCOL_RESOURCE),
    );
    let (first_before, second_before) = (held_at(c, first_cell), held_at(c, second_cell));
    assert!(
        first_before > 0 && second_before > 0,
        "both venues have to be holding something, or the reserve check \
         holds trivially at zero: {first_before} and {second_before}",
    );
    let (protocol_resource, units) = route_worlds(c, &first, &second, accounts(&cast[..1]));
    let mut charges = Charges::default();
    let refused_hash = charges.submit(c, refused);

    // The trader's withdraw is a leg, its own to reach: it takes the
    // input and the price on the trader's own chain before either venue
    // has said anything. A shard replicating the whole shape would only
    // ever be out the price, so this is the divided path's own signature
    // on the balance.
    let paid = c.run_until(budget, |c| {
        funded.saturating_sub(vault_balance(c, TRADER_SHARD, trader)) == ROUTE_INPUT + price
    });
    assert!(
        paid,
        "the trader's leg must take its input and its price before the \
         route reaches a verdict",
    );

    let settled = c.run_until(budget, |c| {
        c.tx_status(refused_hash).is_some_and(|s| s.is_final())
    });
    assert!(settled, "the refused route never reached a verdict");

    // The trader's own leg certifies first, which finalizes the leg and
    // decides nothing; the second venue's refusal is a terminal on the
    // venues' chains, and the reclaim it licenses is a block of the
    // trader shard's own after that. So nothing is read off the first
    // terminal status: what is asserted is the reclaim.
    //
    // The input came back and the price did not: a refusal costs what
    // the success it displaced would have. Asserting the difference
    // rather than an inequality against the input is what makes this
    // separate a reclaim from a price that happens to exceed it.
    let back = c.run_until(budget, |c| {
        funded.saturating_sub(vault_balance(c, TRADER_SHARD, trader)) == price
    });
    let kept = vault_balance(c, TRADER_SHARD, trader);
    assert!(
        back,
        "a refused route must give its trader back what it paid in and \
         charge it the price: {funded} before, {kept} after, on an input \
         of {ROUTE_INPUT} priced at {price}",
    );
    assert_reclaimed_leg(
        c,
        TRADER_SHARD,
        refused_hash,
        budget,
        "a route refused at its second venue",
    );

    assert_venues_gave_back(
        c,
        (first_cell, second_cell),
        (first_before, second_before),
        budget,
    );

    // That the venues can still price is a weaker claim than the reserves
    // above, and it is the one that says the route after this is not
    // running against a wedged pool.
    let again = build_route_tx(
        trader_key,
        trader,
        (&first.meta, &second.meta),
        *PROTOCOL_RESOURCE,
        ROUTE_INPUT,
        0,
        validity_around(c.now()),
    );
    let again_hash = charges.submit(c, again);
    let settled = c.run_until(budget, |c| {
        c.tx_status(again_hash).is_some_and(|s| s.is_final())
    });
    assert!(settled, "the route after the refusal never settled");
    let status = c.tx_status(again_hash);
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "a refused route must leave its trader funded and its venues \
         priceable; status = {status:?}",
    );

    // Across the refusal and the route after it, the pair is conserved:
    // the trader and the venues hold between them what they started
    // with, less the two prices.
    protocol_resource.assert_settles_within(
        c,
        &charges,
        budget,
        "a refused route and the route after it",
    );
    units.assert_settles_within(
        c,
        &Charges::default(),
        budget,
        "a refused route and the route after it",
    );
}

/// A load of routes, each through a venue pair of its own.
#[derive(Debug, Clone, Copy)]
pub struct CoreLoad {
    /// The venue pairs: one venue on [`FIRST_VENUE_SHARD`] and one on
    /// [`SECOND_VENUE_SHARD`] each, so no two pairs share a reserve.
    pub pairs: usize,
    /// The traders on [`TRADER_SHARD`] the routes are dealt among.
    pub traders: usize,
    /// The routes offered each second of the cluster's clock, spread
    /// evenly across it, as far as pairs stand free to take them.
    pub routes_per_second: usize,
    /// How long the load is offered for.
    pub duration: Duration,
    /// Whether the venues' certificates reach each other while it is.
    pub certificates: Certificates,
}

/// What becomes of the venue shards' certificates on their way to each
/// other while a load is offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Certificates {
    /// They arrive. A row stands stated until its sibling's certificate
    /// does, which is as long as the sibling's own member takes to run:
    /// on committees that share no host, most of a finalization delay.
    Flow,
    /// Each venue shard is cut off from the other's until the offering
    /// ends, so every row that states stands stated, and what it learns
    /// of its sibling it learns from a verdict reading. Requires the
    /// venue shards' committees on hosts of their own.
    CutWhileOffered,
}

/// What each trader of a load is funded with: every route it has in
/// flight is out its input, and every route it ever sent its price.
const LOAD_TRADER_FUNDING: u128 = PROVIDER_FUNDING;

/// How long past the last offer a load's routes are given to settle: a
/// route's signed window closes inside it, so one still unsettled at its
/// end is one the chain never decided.
const LOAD_DRAIN: Duration = Duration::from_secs(300);

/// How many seconds of the cluster's clock pass between the readings a
/// load prints of itself as it runs.
const LOAD_REPORT_EVERY: usize = 10;

/// How many blocks under a shard's committed tip a load walks its chain
/// again from: a harness's walkable chain may trail the tip its hosts
/// report by a block or two.
const ARCHIVE_SLACK: u64 = 8;

/// The shards a load's routes touch: the venues', then the traders'.
const LOAD_SHARDS: [(&str, ShardId); 3] = [
    ("first venue shard", FIRST_VENUE_SHARD),
    ("second venue shard", SECOND_VENUE_SHARD),
    ("trader shard", TRADER_SHARD),
];

/// A provider on each venue shard and `traders` traders, each funded for
/// what [`core_routes_under_load`] has it do.
#[must_use]
pub fn core_load_genesis_accounts(traders: usize) -> Vec<(PrincipalAddr, u128)> {
    let mut taken = Vec::new();
    let mut accounts = vec![
        (
            grind_onto(FIRST_VENUE_SHARD, &mut taken).1,
            PROVIDER_FUNDING,
        ),
        (
            grind_onto(SECOND_VENUE_SHARD, &mut taken).1,
            PROVIDER_FUNDING,
        ),
    ];
    accounts.extend(
        load_traders(traders, &mut taken)
            .into_iter()
            .map(|(_, account)| (account, LOAD_TRADER_FUNDING)),
    );
    accounts
}

fn load_traders(count: usize, taken: &mut Vec<u8>) -> Vec<(Ed25519PrivateKey, PrincipalAddr)> {
    (0..count)
        .map(|_| grind_onto(TRADER_SHARD, taken))
        .collect()
}

/// A shard's member rows, by where each stands.
#[derive(Debug, Clone, Copy, Default)]
struct RowCounts {
    pending: usize,
    in_flight: usize,
    stated: usize,
    released: usize,
    accepted: usize,
    /// The rows no abort has let go of: what stands toward the sibling,
    /// every row of a load's venue shard awaiting it.
    standing: usize,
}

impl RowCounts {
    fn read<C: Cluster>(c: &C, shard: ShardId) -> Self {
        let rows = c
            .member_rows(shard)
            .expect("the harness reads a venue shard's member rows");
        let mut counts = Self::default();
        for row in rows.values() {
            match row {
                RowState::Pending => counts.pending += 1,
                RowState::InFlight { .. } => counts.in_flight += 1,
                RowState::Stated { .. } => counts.stated += 1,
                RowState::Released { .. } => counts.released += 1,
                RowState::Accepted => counts.accepted += 1,
            }
            let aborted = matches!(
                row,
                RowState::InFlight {
                    joins: Joins::Aborted,
                    ..
                }
            );
            counts.standing += usize::from(!aborted);
        }
        counts
    }
}

/// One reading of a load in progress.
#[derive(Debug, Clone, Copy)]
struct CoreLoadSample {
    at: Duration,
    /// Routes offered and not yet settled on both venue shards.
    flying: usize,
    /// Each venue shard's height and its rows.
    venues: [(u64, RowCounts); 2],
    /// Verdict asks started and neither answered nor given up.
    asks_open: u64,
}

impl CoreLoadSample {
    fn read<C: FaultableCluster>(c: &C, flying: usize) -> Self {
        let venue = |shard| {
            (
                c.committed_height(shard).map_or(0, BlockHeight::inner),
                RowCounts::read(c, shard),
            )
        };
        let asks = |name| c.metric(name, Some("verdict_proof"));
        Self {
            at: c.now(),
            flying,
            venues: [venue(FIRST_VENUE_SHARD), venue(SECOND_VENUE_SHARD)],
            asks_open: asks("fetch_started")
                .saturating_sub(asks("fetch_completed") + asks("fetch_abandoned")),
        }
    }
}

impl Display for CoreLoadSample {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "at {:?} flying {}", self.at, self.flying)?;
        for (name, (height, rows)) in ["first", "second"].iter().zip(self.venues) {
            write!(
                f,
                "; {name} venue shard height {height} standing {} (pending {}, in flight {}, \
                 stated {}, accepted {}, released {})",
                rows.standing,
                rows.pending,
                rows.in_flight,
                rows.stated,
                rows.accepted,
                rows.released,
            )?;
        }
        write!(f, "; verdict asks open {}", self.asks_open)
    }
}

/// The fetches a load's readings ride: a row's ask of its sibling's
/// verdict cells, a consumer's read of a crossing's cells, and a core
/// member's fallback for its sibling's certificate.
const LOAD_FETCHES: &[Option<&str>] = &[
    Some("verdict_proof"),
    Some("state_proof"),
    Some("exec_cert"),
];

/// Every counter a load's report reads, with the labels it reads each
/// under.
const LOAD_COUNTERS: &[(&str, &[Option<&str>])] = &[
    ("core_members_settled", &[None]),
    ("verdict_cells_named", &[None]),
    ("verdict_cells_carried", &[None]),
    ("verdict_cells_changed", &[None]),
    ("verdict_claims_weight_named", &[None]),
    ("verdict_claims_weight", &[None]),
    ("verdict_claims_weight_changed", &[None]),
    ("fenced_claims_carried", &[Some("record"), Some("removed")]),
    ("fenced_claims_refused", &[Some("record")]),
    ("boundary_claim_bytes", &[None]),
    ("boundary_deletions_carried", &[None]),
    ("boundary_cells_asked", &[None]),
    (
        "crossing_pushes_dropped",
        &[
            None,
            Some("fenced"),
            Some("below_floor"),
            Some("anchor_disagrees"),
            Some("evicted"),
            Some("departed"),
            Some("retired"),
            Some("unhosted"),
            Some("unscheduled_anchor"),
            Some("sender"),
            Some("signature"),
        ],
    ),
    ("record_asks", &[None]),
    ("crossing_fallback_asks", &[Some("producer")]),
    ("rebuilt_record_entries", &[None]),
    ("batches_unavailable", &[None]),
    ("early_votes_refused", &[None]),
    ("block_commit_deferred", &[None]),
    ("hold_contentions", &[None]),
    ("hold_inversions_proven", &[None]),
    ("transactions_aborted", &[None]),
    ("unresolvable_txs", &[None]),
    ("expected_tx_dropped", &[None]),
    ("fetch_started", LOAD_FETCHES),
    ("fetch_completed", LOAD_FETCHES),
    ("fetch_abandoned", LOAD_FETCHES),
    ("fetch_retried", LOAD_FETCHES),
    (
        "fetch_items_sent",
        &[Some("state_proof"), Some("exec_cert")],
    ),
    ("fetch_responses_refused", LOAD_FETCHES),
];

/// The counters a load is read by, each as it stood at one instant.
#[derive(Debug, Clone, Default)]
struct LoadCounters(BTreeMap<(&'static str, Option<&'static str>), u64>);

impl LoadCounters {
    fn read(c: &impl FaultableCluster) -> Self {
        Self(
            LOAD_COUNTERS
                .iter()
                .flat_map(|(name, labels)| labels.iter().map(move |label| (*name, *label)))
                .map(|(name, label)| ((name, label), c.metric(name, label)))
                .collect(),
        )
    }

    /// What `name` under `label` counted since `earlier`.
    fn since(&self, earlier: &Self, name: &'static str, label: Option<&'static str>) -> u64 {
        let at = |counters: &Self| counters.0.get(&(name, label)).copied().unwrap_or(0);
        at(self).saturating_sub(at(earlier))
    }
}

/// The value `per_mille` thousandths of the way up `values`, which it
/// sorts.
fn quantile(values: &mut [usize], per_mille: usize) -> usize {
    values.sort_unstable();
    let last = values.len().saturating_sub(1);
    let rank = (last * per_mille).div_ceil(1000);
    values.get(rank.min(last)).copied().unwrap_or(0)
}

/// `values` as their count, mean, median, 99th percentile and greatest.
fn spread(mut values: Vec<usize>) -> String {
    let total: usize = values.iter().sum();
    format!(
        "mean {}, p50 {}, p99 {}, max {} (of {})",
        mean(wide(total), wide(values.len())),
        quantile(&mut values, 500),
        quantile(&mut values, 990),
        quantile(&mut values, 1000),
        values.len(),
    )
}

fn wide(count: usize) -> u64 {
    u64::try_from(count).unwrap_or(u64::MAX)
}

/// `part` of `whole` as a percentage, to two places.
fn percent(part: u64, whole: u64) -> String {
    let basis = part.saturating_mul(10_000).checked_div(whole).unwrap_or(0);
    format!("{}.{:02}%", basis / 100, basis % 100)
}

/// `total` over `count`, to two places.
fn mean(total: u64, count: u64) -> String {
    let hundredths = total.saturating_mul(100).checked_div(count).unwrap_or(0);
    format!("{}.{:02}", hundredths / 100, hundredths % 100)
}

/// Where one venue shard's chain carried each step of a route's member:
/// its commit, the stating half that stated it, the first claim naming
/// it for a reading of its sibling's verdict, and what settled it.
#[derive(Debug, Clone, Copy, Default)]
struct MemberLife {
    committed: Option<BlockHeight>,
    stated: Option<BlockHeight>,
    heard: Option<BlockHeight>,
    settled: Option<(BlockHeight, TransactionDecision)>,
}

impl MemberLife {
    fn settled_at(&self) -> Option<BlockHeight> {
        self.settled.map(|(height, _)| height)
    }
}

/// The life of `tx`'s member on venue shard `venue`.
fn life_of(
    lives: &mut BTreeMap<TxHash, [MemberLife; 2]>,
    tx: TxHash,
    venue: usize,
) -> &mut MemberLife {
    &mut lives.entry(tx).or_default()[venue]
}

/// The blocks from `from` to `to`, where the chain carried both in that
/// order.
fn blocks_between(from: Option<BlockHeight>, to: Option<BlockHeight>) -> Option<usize> {
    let (from, to) = from.zip(to)?;
    usize::try_from(to.inner().checked_sub(from.inner())?).ok()
}

/// The routes of a load: every one offered, the ones still out, and the
/// pairs free to take another.
struct Flight {
    routes: BTreeMap<TxHash, Arc<Transaction>>,
    /// Each route still out, with the pair it runs through.
    flying: BTreeMap<TxHash, usize>,
    free: VecDeque<usize>,
    /// What the venue shards decided of each route that landed: their
    /// accept, or what the one that did not accept said.
    decided: BTreeMap<TxHash, TransactionDecision>,
    /// Each route's member on each venue shard, the first venue's first.
    lives: BTreeMap<TxHash, [MemberLife; 2]>,
    /// The height each venue shard's chain has been walked to.
    walked: [BlockHeight; 2],
    /// Offers not made for want of a free pair.
    short: usize,
    /// Whether every offer was made at the instant it was spread to.
    spread: bool,
    samples: Vec<CoreLoadSample>,
}

impl Flight {
    fn over(pairs: usize, walked: [BlockHeight; 2]) -> Self {
        Self {
            lives: BTreeMap::new(),
            walked,
            routes: BTreeMap::new(),
            flying: BTreeMap::new(),
            free: (0..pairs).collect(),
            decided: BTreeMap::new(),
            short: 0,
            spread: true,
            samples: Vec::new(),
        }
    }

    /// Take every route both venue shards' chains have settled out of
    /// the air, and give its pair back.
    ///
    /// Read off the venues' chains and not a status: a route's status is
    /// the furthest any host reports, and its trader's shard settles its
    /// leg alone, blocks before either venue lets go of its reserve. A
    /// pair given back on that report would seat its next route behind
    /// the one still holding it.
    fn land<C: Cluster>(&mut self, c: &C) {
        let out: BTreeSet<TxHash> = self.flying.keys().copied().collect();
        for (venue, shard) in [FIRST_VENUE_SHARD, SECOND_VENUE_SHARD]
            .into_iter()
            .enumerate()
        {
            let tip = c.committed_height(shard).unwrap_or(BlockHeight::GENESIS);
            let mentions = walked(c, shard, self.walked[venue], &out);
            self.walked[venue] = tip.saturating_sub(ARCHIVE_SLACK);
            let lives = &mut self.lives;
            for (tx, height) in mentions.committed {
                life_of(lives, tx, venue).committed.get_or_insert(height);
            }
            for (tx, height) in mentions.stated {
                life_of(lives, tx, venue).stated.get_or_insert(height);
            }
            for (tx, height) in mentions.heard {
                life_of(lives, tx, venue).heard.get_or_insert(height);
            }
            for ((tx, height), (_, decision)) in
                mentions.finalized.into_iter().zip(mentions.decisions)
            {
                life_of(lives, tx, venue)
                    .settled
                    .get_or_insert((height, decision));
            }
            for (tx, height) in mentions.fated {
                life_of(lives, tx, venue)
                    .settled
                    .get_or_insert((height, TransactionDecision::Aborted));
            }
        }
        let Self {
            flying,
            free,
            decided,
            lives,
            ..
        } = self;
        flying.retain(|hash, pair| {
            let Some([first, second]) = lives.get(hash) else {
                return true;
            };
            let Some(((_, first), (_, second))) = first.settled.zip(second.settled) else {
                return true;
            };
            let accepted = TransactionDecision::Accept;
            decided.insert(*hash, if first == accepted { second } else { first });
            free.push_back(*pair);
            false
        });
    }

    /// Run the cluster's clock a second on and read the load, printing
    /// every [`LOAD_REPORT_EVERY`]th reading as `phase`'s.
    fn tick<C: FaultableCluster>(&mut self, c: &mut C, phase: &str) {
        let next = c.now() + Duration::from_secs(1);
        let _ = c.run_until(epochs(1), |c| c.now() >= next);
        self.land(c);
        let sample = CoreLoadSample::read(c, self.flying.len());
        if self.samples.len().is_multiple_of(LOAD_REPORT_EVERY) {
            println!("core load, {phase}: {sample}");
        }
        self.samples.push(sample);
    }

    /// How many of the routes the venue shards decided as `wanted`.
    fn decided_as(&self, wanted: TransactionDecision) -> usize {
        self.decided
            .values()
            .filter(|decision| **decision == wanted)
            .count()
    }
}

/// Everything `shard`'s chain carries of `txs` from `from` up.
///
/// # Panics
///
/// Panics on a cluster that walks no chain: a load is read off its
/// shards' chains and nowhere else.
fn walked<C: Cluster>(
    c: &C,
    shard: ShardId,
    from: BlockHeight,
    txs: &BTreeSet<TxHash>,
) -> ChainMentions {
    c.chain_mentions(shard, from, txs)
        .expect("a load runs on a cluster that walks its shards' chains")
}

/// The venue pairs of a load and the traders its routes are dealt among.
struct LoadCast {
    firsts: Vec<StockedVenue>,
    seconds: Vec<StockedVenue>,
    traders: Vec<(Ed25519PrivateKey, PrincipalAddr)>,
}

impl LoadCast {
    fn stand_up<C: Cluster>(c: &mut C, load: CoreLoad) -> Self {
        let mut taken = Vec::new();
        let mut venues = stand_up_venues_on(
            c,
            &[FIRST_VENUE_SHARD, SECOND_VENUE_SHARD],
            load.pairs,
            &mut taken,
        );
        let seconds = venues.pop().expect("the second shard's venues");
        let firsts = venues.pop().expect("the first shard's venues");
        Self {
            firsts,
            seconds,
            traders: load_traders(load.traders, &mut taken),
        }
    }

    /// Everything that can hold `resource` in the load: the traders and
    /// every venue's reserve.
    fn world<C: Cluster>(&self, c: &C, resource: ResourceAddr) -> World {
        World::open(
            c,
            resource,
            accounts(&self.traders).map(PrincipalAddr::address),
            self.firsts
                .iter()
                .chain(&self.seconds)
                .map(|venue| reserve_cell(&venue.meta, resource)),
        )
    }

    /// Offer the coming second's `load.routes_per_second` routes through
    /// pairs standing free, the nth of them that far through the second,
    /// each paying in an amount of its own so no two are one
    /// transaction.
    fn offer<C: Cluster>(&self, c: &mut C, load: CoreLoad, flight: &mut Flight) {
        let window = validity_around(c.now());
        let step = Duration::from_secs(1)
            / u32::try_from(load.routes_per_second.max(1)).unwrap_or(u32::MAX);
        for slot in 0..load.routes_per_second {
            let Some(pair) = flight.free.pop_front() else {
                flight.short += 1;
                continue;
            };
            let nth = flight.routes.len();
            let (key, trader) = &self.traders[nth % self.traders.len()];
            let route = Arc::new(build_route_tx(
                key,
                *trader,
                (&self.firsts[pair].meta, &self.seconds[pair].meta),
                *PROTOCOL_RESOURCE,
                ROUTE_INPUT + u128::try_from(nth).expect("a count of routes"),
                0,
                window,
            ));
            let after = step * u32::try_from(slot).unwrap_or(u32::MAX);
            flight.spread &= c.submit_after(after, Arc::clone(&route));
            flight.flying.insert(route.hash(), pair);
            flight.routes.insert(route.hash(), route);
        }
    }
}

/// What the routes of `flight` a chain has charged burned between them:
/// each one decided other than by an abort, and each one the traders'
/// chain carries the burn or the fate of from `from` up.
fn load_burned<C: Cluster>(c: &C, flight: &Flight, from: BlockHeight) -> u128 {
    let hashes: BTreeSet<TxHash> = flight.routes.keys().copied().collect();
    let mentions = walked(c, TRADER_SHARD, from, &hashes);
    let on_the_payers_chain: BTreeSet<TxHash> = mentions
        .burned
        .into_iter()
        .chain(mentions.fated)
        .map(|(tx, _)| tx)
        .collect();
    flight
        .routes
        .iter()
        .filter(|(hash, _)| {
            flight
                .decided
                .get(*hash)
                .is_some_and(|decision| *decision != TransactionDecision::Aborted)
                || on_the_payers_chain.contains(*hash)
        })
        .map(|(_, route)| declared_price(c, route))
        .sum()
}

/// Drive until both sides of the load's pair settle against what its
/// routes burned, hold them there a few blocks, and read each side:
/// what it held before, what it holds, and what was burned of it.
fn load_conserved<C: Cluster>(
    c: &mut C,
    flight: &Flight,
    from: BlockHeight,
    protocol_resource: &World,
    units: &World,
) -> [(&'static str, u128, u128, u128); 2] {
    let settle_by = c.now() + LOAD_DRAIN;
    let settled =
        |c: &C| protocol_resource.settles(c, load_burned(c, flight, from)) && units.settles(c, 0);
    while !settled(c) && c.now() < settle_by {
        let next = c.now() + Duration::from_secs(5);
        let _ = c.run_until(epochs(1), |c| c.now() >= next);
    }
    let tail = c.now() + Duration::from_secs(5);
    let _ = c.run_until(epochs(1), |c| c.now() >= tail);
    [
        (
            "protocol resource",
            protocol_resource.before(),
            protocol_resource.held(c),
            load_burned(c, flight, from),
        ),
        ("units", units.before(), units.held(c), 0),
    ]
}

/// Many routes at once, each a core member on both venue shards and none
/// sharing a reserve with another.
///
/// A route writes both its venues' reserves and its core member holds
/// them from naming to its legs half, so routes through one pair run one
/// at a time. Here every route has a pair of its own: `load.pairs`
/// venues stand on each venue shard, and a route is offered through a
/// pair only while no route through it is unsettled. Its trader's legs
/// settle alone and hold nothing a second route of the same trader
/// waits on, so a few traders on a third shard serve every pair. Each
/// second of the cluster's clock the traders offer
/// `load.routes_per_second` routes through pairs standing free, spread
/// evenly across the second, for `load.duration`; then the routes still
/// out are given their window to settle.
///
/// What the run reports, read off each shard's committed chain and off
/// the counters from the offering's opening to the settled end, the
/// chain's figures apart for the blocks of the offering and the blocks
/// after it: the core members each block committed and settled, what
/// each block's claims section weighed and what of it read crossings
/// and what verdicts, what a member cost of each, how many blocks a
/// member took from its commit to its stating and from there to its
/// first reading and its settlement on each venue shard, the rows
/// standing toward a sibling, what delayed a crossing reading, and what
/// the asks did.
///
/// Under [`Certificates::CutWhileOffered`] no certificate of one venue
/// shard reaches the other until the offering ends, so each pair takes
/// one route, its rows stand stated on both venue shards, and the
/// readings are what tell each of the other; the cut then lifts and the
/// certificates settle them.
///
/// Requires a grown four-shard cluster over
/// [`core_load_genesis_accounts`] of `load.traders`, one that walks its
/// shards' chains.
///
/// # Panics
///
/// Panics if a venue misses its budget standing up, if a cut asked for
/// never fires, if either side of the pair is not conserved, if a route
/// is still undecided once its window and the drain have passed, or if
/// any route is not accepted.
pub fn core_routes_under_load<C: FaultableCluster>(c: &mut C, load: CoreLoad) {
    let wall = Instant::now();
    let cast = LoadCast::stand_up(c, load);
    let protocol_resource = cast.world(c, *PROTOCOL_RESOURCE);
    let units = cast.world(c, cast.firsts[0].unit);
    println!(
        "core load: {} pairs stood up by {:?} of the cluster's clock, in {:.0}s of wall",
        load.pairs,
        c.now(),
        wall.elapsed().as_secs_f64(),
    );

    let height = |c: &C, shard: ShardId| c.committed_height(shard).unwrap_or(BlockHeight::GENESIS);
    let opened_at = LOAD_SHARDS.map(|(_, shard)| height(c, shard).next());
    let opened = c.now();
    let before = LoadCounters::read(c);
    let offering = Instant::now();
    let cuts = match load.certificates {
        Certificates::Flow => Vec::new(),
        Certificates::CutWhileOffered => vec![
            isolate_ec_intake(c, FIRST_VENUE_SHARD, SECOND_VENUE_SHARD),
            isolate_ec_intake(c, SECOND_VENUE_SHARD, FIRST_VENUE_SHARD),
        ],
    };
    let mut flight = Flight::over(load.pairs, [opened_at[0], opened_at[1]]);
    while c.now() < opened + load.duration {
        cast.offer(c, load, &mut flight);
        flight.tick(c, "offering");
    }
    assert!(
        cuts.iter().all(|cut| cut.fired() > 0),
        "each venue shard must actually have been cut off from the other's certificates",
    );
    c.clear_drops();
    let closed_at = LOAD_SHARDS.map(|(_, shard)| height(c, shard));
    let closed = c.now();
    let offering = offering.elapsed();
    let offered = flight.samples.len();
    while !flight.flying.is_empty() && c.now() < closed + LOAD_DRAIN {
        flight.tick(c, "draining");
    }
    let conserved = load_conserved(c, &flight, opened_at[2], &protocol_resource, &units);
    let after = LoadCounters::read(c);

    CoreLoadRun {
        load,
        flight: &flight,
        offered,
        window: [opened, closed],
        heights: [
            opened_at,
            closed_at,
            LOAD_SHARDS.map(|(_, shard)| height(c, shard)),
        ],
        counters: [&before, &after],
        wall: [wall.elapsed(), offering],
    }
    .report(c);

    for (side, before, held, burned) in conserved {
        assert_eq!(
            held + burned,
            before,
            "the load's {side} must be conserved: held {held} and burned {burned} against \
             {before} before",
        );
    }
    assert!(
        flight.flying.is_empty(),
        "{} of {} routes were still undecided {LOAD_DRAIN:?} past the last offer, the first \
         {:?}",
        flight.flying.len(),
        flight.routes.len(),
        flight
            .flying
            .keys()
            .next()
            .map(|hash| (*hash, c.tx_status(*hash))),
    );
    let accepted = flight.decided_as(TransactionDecision::Accept);
    assert_eq!(
        accepted,
        flight.routes.len(),
        "every route of the load must be accepted; the first that was not: {:?}",
        flight
            .decided
            .iter()
            .find(|(_, decision)| **decision != TransactionDecision::Accept),
    );
}

/// Everything one run of [`core_routes_under_load`] is reported from.
struct CoreLoadRun<'a> {
    load: CoreLoad,
    flight: &'a Flight,
    /// How many of the flight's samples were read while offering.
    offered: usize,
    /// When the offering opened and closed.
    window: [Duration; 2],
    /// Each of [`LOAD_SHARDS`]' first height of the offering, its last,
    /// and its height once the load had settled.
    heights: [[BlockHeight; 3]; 3],
    /// The counters as the offering opened and once the load had
    /// settled.
    counters: [&'a LoadCounters; 2],
    /// The wall time of the whole run, and of the offering.
    wall: [Duration; 2],
}

/// One kind of reading, picked out of a block's claims section.
type ReadingsOf = fn(&ClaimsSection) -> Readings;

/// The kinds a claims section's cells are counted as.
const READING_KINDS: [(&str, ReadingsOf); 4] = [
    ("crossing", |section| section.crossing),
    ("verdict leaf", |section| section.verdict),
    ("verdict support", |section| section.support),
    ("other", |section| section.other),
];

impl CoreLoadRun<'_> {
    /// Print what the run measured.
    fn report<C: FaultableCluster>(&self, c: &C) {
        self.report_routes();
        let routes: BTreeSet<TxHash> = self.flight.routes.keys().copied().collect();
        for (index, (name, shard)) in LOAD_SHARDS.into_iter().enumerate() {
            let [opened, closed, settled] = self.heights.map(|heights| heights[index]);
            let mentions = walked(c, shard, opened, &routes);
            let sections = c.claims_sections(shard, opened).unwrap_or_default();
            for (window, from, to) in [
                ("offering", opened, closed),
                ("after the offering", closed.next(), settled),
            ] {
                let label = format!("{name}, {window}");
                report_members(&label, (from, to), &mentions);
                let within: Vec<ClaimsSection> = sections
                    .iter()
                    .filter(|section| section.height >= from && section.height <= to)
                    .copied()
                    .collect();
                report_claims(&label, &within);
            }
            report_cost_per_member(name, mentions.committed.len(), &sections);
        }
        self.report_lives();
        self.report_verdicts(c);
        self.report_standing();
        self.report_answers(c);
        self.report_counters();
        self.report_simulator(c);
    }

    /// The answers standing on each shard of the load, the boundary
    /// claims its blocks carried to delete them, and how long a
    /// boundary's deletions took to leave the replicas that held them.
    fn report_answers<C: FaultableCluster>(&self, c: &C) {
        for (name, shard) in LOAD_SHARDS {
            let label = shard.inner().to_string();
            let at = |metric, q| {
                c.metric_quantile_above(metric, Some(&label), q, f64::NEG_INFINITY)
                    .unwrap_or(0.0)
            };
            println!(
                "core load [9 {name}, answers standing under its prefix, read by each replica \
                 at each of its commits over the whole run, each quantile the upper edge of \
                 its bucket]: answers p50 {:.0}, p90 {:.0}, max {:.0}; bytes of their leaves, \
                 key and value: p50 {:.0}, p90 {:.0}, max {:.0}",
                at("standing_answers", 0.5),
                at("standing_answers", 0.9),
                at("standing_answers", 1.0),
                at("standing_answer_bytes", 0.5),
                at("standing_answer_bytes", 0.9),
                at("standing_answer_bytes", 1.0),
            );
        }
        let [before, after] = self.counters;
        let delta = |name| after.since(before, name, None);
        let (bytes, deletions) = (
            delta("boundary_claim_bytes"),
            delta("boundary_deletions_carried"),
        );
        let weight = |q| {
            c.metric_quantile_above("boundary_claims_block_weight", None, q, 0.0)
                .unwrap_or(0.0)
        };
        println!(
            "core load [9 boundary claims, counters summed over replicas and shards]: bytes \
             carried {bytes}, answer deletions read {deletions}, bytes a deletion {}; cells \
             asked at boundaries {}; bytes of them a block, over the {} commits carrying any, \
             each replica's counted: p50 {:.0}, p99 {:.0}, max {:.0}",
            mean(bytes, deletions),
            delta("boundary_cells_asked"),
            c.metric_count("boundary_claims_block_weight", None),
            weight(0.5),
            weight(0.99),
            weight(1.0),
        );
        let drained = |q| {
            c.metric_quantile_above("boundary_drain_ms", None, q, f64::NEG_INFINITY)
                .unwrap_or(0.0)
        };
        println!(
            "core load [9 drain after a beacon fold, each replica, committed clock from its \
             ask at a boundary to the commit at which it holds no deletion read there]: {} \
             boundaries drained: p50 {:.0}ms, p90 {:.0}ms, max {:.0}ms",
            c.metric_count("boundary_drain_ms", None),
            drained(0.5),
            drained(0.9),
            drained(1.0),
        );
    }

    fn report_routes(&self) {
        let (load, flight) = (self.load, self.flight);
        println!(
            "core load [0 size]: {} pairs, {} traders, {} routes a second offered for {:?} \
             with the venues' certificates {:?} ({:?} to {:?})",
            load.pairs,
            load.traders,
            load.routes_per_second,
            load.duration,
            load.certificates,
            self.window[0],
            self.window[1],
        );
        println!(
            "core load [0 arrival]: {}",
            if flight.spread {
                "each second's offers spread evenly across it"
            } else {
                "each second's offers made at one instant: this cluster schedules no submission"
            },
        );
        if load.certificates == Certificates::CutWhileOffered {
            println!(
                "core load [0 what the cut does not show]: every reading here is a yes and \
                 changes an entry; the rows state together, so their leaves change together \
                 and the readings ride densely batched; and the rows are settled by the \
                 certificates once the cut lifts, never by a reading",
            );
        }
        println!(
            "core load [1 routes]: offered {}, {} offers short of a free pair; accepted {}, \
             rejected {}, aborted {}, undecided {}",
            flight.routes.len(),
            flight.short,
            flight.decided_as(TransactionDecision::Accept),
            flight.decided_as(TransactionDecision::Reject),
            flight.decided_as(TransactionDecision::Aborted),
            flight.flying.len(),
        );
    }

    /// How many blocks each venue shard's chain took over each step of
    /// a member's life, read off the chain block for block.
    fn report_lives(&self) {
        for (venue, name) in ["first", "second"].into_iter().enumerate() {
            let lives: Vec<MemberLife> =
                self.flight.lives.values().map(|life| life[venue]).collect();
            let over = |step: fn(&MemberLife) -> Option<usize>| -> Vec<usize> {
                lives.iter().filter_map(step).collect()
            };
            println!(
                "core load [4 {name} venue shard, blocks of its own chain, each member]: \
                 commit to stated: {}; stated to its first reading carried: {}; stated to \
                 settled: {}; commit to settled: {}",
                spread(over(|life| blocks_between(life.committed, life.stated))),
                spread(over(|life| blocks_between(life.stated, life.heard))),
                spread(over(|life| blocks_between(life.stated, life.settled_at()))),
                spread(over(|life| blocks_between(
                    life.committed,
                    life.settled_at()
                ))),
            );
            let count =
                |wanted: fn(&MemberLife) -> bool| lives.iter().filter(|life| wanted(life)).count();
            println!(
                "core load [4 {name} venue shard, members]: settled {}, of which stated {}, \
                 named by a reading while they stood {}, settled with no reading carried {}",
                count(|life| life.settled.is_some()),
                count(|life| life.settled.is_some() && life.stated.is_some()),
                count(|life| life.settled.is_some() && life.heard.is_some()),
                count(|life| life.settled.is_some() && life.heard.is_none()),
            );
        }
    }

    fn report_verdicts<C: FaultableCluster>(&self, c: &C) {
        let [before, after] = self.counters;
        let delta = |name| after.since(before, name, None);
        let settled = delta("core_members_settled");
        let cells = [
            delta("verdict_cells_named"),
            delta("verdict_cells_carried"),
            delta("verdict_cells_changed"),
        ];
        let bytes = [
            delta("verdict_claims_weight_named"),
            delta("verdict_claims_weight"),
            delta("verdict_claims_weight_changed"),
        ];
        let heard = c.metric_count("blocks_from_stated_to_heard", None);
        println!(
            "core load [3 verdict readings, counters summed over replicas and shards]: cells in \
             claims naming a member {}, reaching a hearing row {}, changing an entry {}; bytes \
             {}, {} and {}; core members settled {settled}",
            cells[0], cells[1], cells[2], bytes[0], bytes[1], bytes[2],
        );
        println!(
            "core load [3 computed from those]: bytes a changed cell {}, cells named a changed \
             cell {}; of the verdict bytes {} reached a hearing row and {} changed an entry",
            mean(bytes[2], cells[2]),
            mean(cells[0], cells[2]),
            percent(bytes[1], bytes[0]),
            percent(bytes[2], bytes[0]),
        );
        let waited = |q| {
            c.metric_quantile_above("blocks_from_stated_to_heard", None, q, f64::NEG_INFINITY)
                .unwrap_or(0.0)
        };
        println!(
            "core load [4 blocks_from_stated_to_heard, the counter, both venue shards and every \
             replica together, each quantile the upper edge of its bucket]: {heard} rows heard \
             every sibling: p50 {:.0}, p90 {:.0}, p99 {:.0}, max {:.0}; core members settled \
             less rows that heard, both read once the load had settled: {}",
            waited(0.5),
            waited(0.9),
            waited(0.99),
            waited(1.0),
            i128::from(settled) - i128::from(heard),
        );
        report_accepted_measures(c, "core load [4 accepted rows, the whole run]");
    }

    fn report_standing(&self) {
        let offering = &self.flight.samples[..self.offered];
        for (index, name) in ["first", "second"].into_iter().enumerate() {
            let over = |read: fn(&RowCounts) -> usize| -> Vec<usize> {
                offering
                    .iter()
                    .map(|sample| read(&sample.venues[index].1))
                    .collect()
            };
            println!(
                "core load [5 {name} venue shard, read each second of the offering]: rows \
                 standing toward its sibling against {MAX_STANDING_TOWARD_SHARD}: {}; stated: \
                 {}; accepted: {}; pending: {}; in flight: {}",
                spread(over(|rows| rows.standing)),
                spread(over(|rows| rows.stated)),
                spread(over(|rows| rows.accepted)),
                spread(over(|rows| rows.pending)),
                spread(over(|rows| rows.in_flight)),
            );
        }
        println!(
            "core load [5 routes out at once, read each second of the offering]: {}",
            spread(offering.iter().map(|sample| sample.flying).collect()),
        );
        println!(
            "core load [7 verdict asks open, read each second of the offering]: {}",
            spread(
                offering
                    .iter()
                    .map(|sample| usize::try_from(sample.asks_open).unwrap_or(usize::MAX))
                    .collect()
            ),
        );
    }

    fn report_counters(&self) {
        let [before, after] = self.counters;
        let line = |title: &str, names: &[&'static str]| {
            let mut out = format!("core load [{title}, summed over replicas and shards]:");
            for (name, labels) in LOAD_COUNTERS
                .iter()
                .filter(|(name, _)| names.contains(name))
            {
                for label in *labels {
                    let _ = write!(
                        out,
                        " {name}{} {};",
                        label.map_or_else(String::new, |label| format!("{{{label}}}")),
                        after.since(before, name, *label),
                    );
                }
            }
            println!("{out}");
        };
        line(
            "6 crossing readings",
            &[
                "fenced_claims_carried",
                "fenced_claims_refused",
                "boundary_claim_bytes",
                "boundary_deletions_carried",
                "boundary_cells_asked",
                "crossing_pushes_dropped",
                "record_asks",
                "crossing_fallback_asks",
                "rebuilt_record_entries",
            ],
        );
        line(
            "6 blocks and votes",
            &[
                "batches_unavailable",
                "early_votes_refused",
                "block_commit_deferred",
                "hold_contentions",
                "hold_inversions_proven",
                "transactions_aborted",
                "unresolvable_txs",
                "expected_tx_dropped",
            ],
        );
        line(
            "7 fetches",
            &[
                "fetch_started",
                "fetch_completed",
                "fetch_abandoned",
                "fetch_retried",
                "fetch_items_sent",
                "fetch_responses_refused",
            ],
        );
        let routes = wide(self.flight.routes.len());
        println!(
            "core load [7 computed]: a verdict ask is served as a state proof, so its answers \
             are counted in fetch_items_sent{{state_proof}} with the record reads' and under no \
             label of their own; no counter tells a verdict reading that arrived by push from \
             one that was asked for; exec_cert fetches a route {}, retries a route {}",
            mean(
                after.since(before, "fetch_started", Some("exec_cert")),
                routes
            ),
            mean(
                after.since(before, "fetch_retried", Some("exec_cert")),
                routes
            ),
        );
    }

    fn report_simulator<C: Cluster>(&self, c: &C) {
        let [whole, offering] = self.wall;
        let offered_for = self.window[1].saturating_sub(self.window[0]);
        println!(
            "core load [8 simulator]: {:.1}s of wall for the {offered_for:?} offered, {:.2} \
             wall seconds a simulated second; {:.0}s of wall for the whole run to {:?}",
            offering.as_secs_f64(),
            offering.as_secs_f64() / offered_for.as_secs_f64().max(1.0),
            whole.as_secs_f64(),
            c.now(),
        );
    }
}

/// The members of the load each block of `label`'s chain between
/// `heights` committed, and the ones each settled.
fn report_members(label: &str, (from, to): (BlockHeight, BlockHeight), mentions: &ChainMentions) {
    let blocks =
        usize::try_from((to.inner() + 1).saturating_sub(from.inner())).expect("a block count");
    let per_block = |mentions: &[(TxHash, BlockHeight)]| -> Vec<usize> {
        let mut counts = vec![0usize; blocks];
        for (_, height) in mentions
            .iter()
            .filter(|(_, height)| *height >= from && *height <= to)
        {
            let slot = usize::try_from(height.inner() - from.inner()).expect("in the window");
            counts[slot] += 1;
        }
        counts
    };
    println!(
        "core load [1 {label}]: blocks {} to {}; members committed a block: {}; members \
         stated a block: {}; members settled a block: {}; fated in all {}",
        from.inner(),
        to.inner(),
        spread(per_block(&mentions.committed)),
        spread(per_block(&mentions.stated)),
        spread(per_block(&mentions.finalized)),
        mentions.fated.len(),
    );
}

/// What the claims sections of `label`'s blocks weighed, the claims
/// that are not verdict claims against their budget and the verdict
/// claims against the section's, and what of them each kind of reading
/// took.
fn report_claims(label: &str, sections: &[ClaimsSection]) {
    let over =
        |read: fn(&ClaimsSection) -> usize| -> Vec<usize> { sections.iter().map(read).collect() };
    let skipped: u64 = sections
        .windows(2)
        .map(|pair| pair[1].round.saturating_sub(pair[0].round + 1))
        .sum();
    println!(
        "core load [2 {label}]: claims bytes a block against {MAX_STATE_CLAIMS_BYTES}: {}; \
         claims a block against {MAX_STATE_CLAIMS_PER_BLOCK}: {}; transactions a block: {}; \
         rounds skipped {skipped}",
        spread(over(|section| section.bytes)),
        spread(over(|section| section.claims)),
        spread(over(|section| section.transactions)),
    );
    println!(
        "core load [2 {label}]: verdict claims bytes a block, in a section of \
         {MAX_CLAIMS_BYTES}: {}; verdict claims a block, in a section of \
         {MAX_CLAIMS_PER_BLOCK}: {}",
        spread(over(|section| section.verdict_bytes)),
        spread(over(|section| section.verdict_claims)),
    );
    let section_bytes: usize = sections
        .iter()
        .map(|section| section.bytes + section.verdict_bytes)
        .sum();
    for (kind, read) in READING_KINDS {
        let sum = |of: fn(Readings) -> usize| -> usize {
            sections.iter().map(|section| of(read(section))).sum()
        };
        println!(
            "core load [2 {label}]: {kind} readings: {} claims, {} cells, {} bytes, {} of the \
             sections' bytes; bytes a block: {}",
            sum(|readings| readings.claims),
            sum(|readings| readings.cells),
            sum(|readings| readings.bytes),
            percent(wide(sum(|readings| readings.bytes)), wide(section_bytes)),
            spread(sections.iter().map(|section| read(section).bytes).collect()),
        );
    }
}

/// What the claims sections of the `name`'s whole run cost for each of
/// the `members` it committed, by kind, and what a verdict leaf cost.
fn report_cost_per_member(name: &str, members: usize, sections: &[ClaimsSection]) {
    let total = |read: ReadingsOf, of: fn(Readings) -> usize| -> u64 {
        wide(sections.iter().map(|section| of(read(section))).sum())
    };
    let mut out = format!(
        "core load [2 {name}, the whole run, section bytes a member committed, of {members}]:"
    );
    for (kind, read) in READING_KINDS {
        let _ = write!(
            out,
            " {kind} {};",
            mean(total(read, |readings| readings.bytes), wide(members)),
        );
    }
    let [_, (_, leaf), (_, support), _] = READING_KINDS;
    let leaves = total(leaf, |readings| readings.cells);
    let _ = write!(
        out,
        " a verdict leaf carried, with its support: {} bytes and {} of a claim",
        mean(
            total(leaf, |readings| readings.bytes) + total(support, |readings| readings.bytes),
            leaves,
        ),
        mean(total(leaf, |readings| readings.claims), leaves),
    );
    println!("{out}");
}
