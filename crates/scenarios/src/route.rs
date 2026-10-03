//! A route through two venues on two shards, and whether it settles.
//!
//! One venue is a core of one shard. Two of them on separate shards is a
//! core that spans both: neither swap is reservation shaped nor total,
//! so both are core, and the route's atomicity has to cover them
//! together while nothing about their execution is shared. Each venue
//! awaits the other's certificate, which is what makes this the first
//! shape whose settlement waits on a certificate from across a shard
//! boundary — a transfer never does, its recipient claims a bundle.

use std::time::Duration;

use hyperscale_effects_bridge::ProtocolHasher;
use hyperscale_engine::PROTOCOL_RESOURCE;
use hyperscale_storage::{FeeTerms, RowState};
use hyperscale_types::{
    Address, BlockHeight, Deadline, Ed25519PrivateKey, PrincipalAddr, ShardId, ShardTrie,
    SubstateKey, Transaction, TransactionDecision, TransactionStatus, TxHash, WeightedTimestamp,
    Window,
};
use hyperscale_vm_effects::{Answered, CrossingAnswer, CrossingId, Kind, fee_hold_total_key};
use hyperscale_vm_types::{LegRole, LegShape};

use crate::straddler::{isolate_crossing_intake, isolate_ec_intake, isolate_provision_intake};
use crate::support::conservation::{Charges, World};
use crate::support::query::{
    assert_reclaimed_leg, declared_price, held, held_at, stands_at, vault_balance,
};
use crate::support::tx::{
    build_route_tx, build_sponsored_route_tx, build_swap_tx, validity_around,
};
use crate::support::wait::await_blocks;
use crate::support::{Budget, Cluster, FaultHandle, FaultableCluster, epochs};
use crate::venue::{
    PROVIDER_FUNDING, SWAPPER_FUNDING, StockedVenue, grind_onto, reserve_cell, stand_up_venue,
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
fn sponsor(taken: &mut Vec<u8>) -> (Ed25519PrivateKey, PrincipalAddr) {
    grind_onto(FIRST_VENUE_SHARD, taken)
}

fn traders(taken: &mut Vec<u8>) -> Vec<(Ed25519PrivateKey, PrincipalAddr)> {
    (0..ROUTES)
        .map(|_| grind_onto(TRADER_SHARD, taken))
        .collect()
}

/// Both venues, stood up in the order the genesis accounts were dealt.
fn stand_up_venues<C: Cluster>(c: &mut C, taken: &mut Vec<u8>) -> (StockedVenue, StockedVenue) {
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
pub fn a_route_settles_across_two_venues<C: Cluster>(c: &mut C, budget: Budget) -> RouteReport {
    let mut taken = Vec::new();
    let (first, second) = stand_up_venues(c, &mut taken);
    let traders = traders(&mut taken);
    drive_routes(c, &first, &second, &traders, budget)
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

    // Each venue holds the route whose record it heard, and the other
    // route stands committed and unseated beside it.
    let holds = |c: &C, venue: ShardId, held: TxHash, waiting: TxHash| {
        c.member_rows(venue).is_some_and(|rows| {
            matches!(rows.get(&held), Some(RowState::InFlight { .. }))
                && rows.get(&waiting) == Some(&RowState::Pending)
        })
    };
    assert!(
        c.run_until(epochs(8), |c| {
            holds(c, FIRST_VENUE_SHARD, held_first, held_second)
                && holds(c, SECOND_VENUE_SHARD, held_second, held_first)
        }),
        "each venue must seat the route whose record it heard, and hold it",
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
    let later = held_first.max(held_second);
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
    assert!(
        c.metric("hold_inversions_proven", None) > proven,
        "a block must have aborted the victim on a proven cycle",
    );
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
                matches!(rows.get(&routes[prev(at)]), Some(RowState::InFlight { .. }))
                    && rows.get(&routes[at]) == Some(&RowState::Pending)
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

    let deadline = Deadline::of(validity.end_timestamp_exclusive).at();
    let clock = |c: &C| WeightedTimestamp::ZERO.plus(c.now());
    c.run_until(epochs(8), |c| clock(c) >= deadline || !ring_holds(c));
    assert!(
        clock(c) >= deadline && ring_holds(c),
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

/// A decline an abandonment wrote, unseen, is read seen off its record
/// and goes once the record does.
///
/// The route's second venue never engages: every bundle it would need is
/// cut away from it, so the route never enters a block there. The first
/// venue commits the route, holds the trader's escrowed input past its
/// deadline with its sibling silent, and is aborted, declining the
/// input's crossing unseen, since its member never ran on the record. An
/// absence alone must not delete such a decline, which might predate the
/// record's write. Here the record stands: the first venue's asks read it
/// present, which marks the decline seen, the trader's shard reclaims on
/// the decline, and the record's absence then deletes it. The trader's
/// input comes home and both worlds settle with nothing locked.
///
/// Requires disjoint committees, as its neighbours do.
///
/// # Panics
///
/// Panics if either venue misses its budget standing up, if the first
/// venue never commits the route or never declines the crossing unseen,
/// if the second venue engages, if the decline outlives its record, if
/// the input does not come home, or if either world is not conserved.
pub fn an_abandoned_never_is_read_seen_and_goes<C: FaultableCluster>(c: &mut C) {
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
    let route = build_route_tx(
        key,
        *trader,
        (&first.meta, &second.meta),
        *PROTOCOL_RESOURCE,
        ROUTE_INPUT,
        0,
        validity_around(c.now()),
    );
    let price = declared_price(c, &route);
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
        "the first venue must decline the input it held past its deadline",
    );
    assert!(
        c.substate(FIRST_VENUE_SHARD, decline.owner, decline.local.0)
            .as_deref()
            .and_then(CrossingAnswer::from_bytes)
            .is_some_and(|answer| answer.answered == Answered::Never),
        "and the decline is the abandonment's",
    );
    assert!(
        c.run_until(epochs(12), |c| !stands_at(c, decline)),
        "the decline must go once its record, read present and reclaimed, is read absent",
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
        "the trader's input must come home, less the price: holds {} against {}",
        held(c, trader.address(), *PROTOCOL_RESOURCE),
        funded - price,
    );
    let locked = protocol_resource.assert_settles_within(
        c,
        &charges,
        epochs(8),
        "an abandoned decline read seen",
    );
    assert!(locked.is_empty(), "nothing stays locked: {locked:?}");
    units.assert_settles_within(
        c,
        &Charges::default(),
        epochs(8),
        "an abandoned decline read seen",
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

fn route_worlds<C: Cluster>(
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
    // chains read it, one through the push and the other through its
    // own read; the outbound record is consumed on the trader's shard,
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
