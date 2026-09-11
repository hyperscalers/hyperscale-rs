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

use hyperscale_engine::XRD;
use hyperscale_types::{
    Address, Deadline, Ed25519PrivateKey, PrincipalAddr, ShardId, SubstateKey, TransactionDecision,
    TransactionStatus, TxHash, WeightedTimestamp, Window,
};

use crate::straddler::isolate_ec_intake;
use crate::support::conservation::{Charges, World};
use crate::support::query::{assert_reclaimed_leg, declared_price, held, held_at, vault_balance};
use crate::support::tx::{build_route_tx, validity_around};
use crate::support::wait::await_blocks;
use crate::support::{Budget, Cluster, FaultableCluster, epochs};
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

/// How many routes run at once.
pub const ROUTES: usize = 4;

/// A floor the second hop cannot meet: two swaps of [`ROUTE_INPUT`] pay
/// out less than they took in, so anything above the input refuses, and
/// this is well clear of it.
const REFUSED_FLOOR: u128 = ROUTE_INPUT * 100;

/// A provider on each venue's shard and the traders, with the funding
/// each needs. Stocking is local to its venue, so it costs no crossing
/// and is not part of the shape under test.
#[must_use]
pub fn route_genesis_accounts() -> Vec<(PrincipalAddr, u128)> {
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
        traders(&mut taken)
            .into_iter()
            .map(|(_, account)| (account, SWAPPER_FUNDING)),
    );
    accounts
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
    let (xrd, units) = route_worlds(c, &first, &second, &traders);

    let mut charges = Charges::default();
    let validity = validity_around(c.now());
    let route = build_route_tx(
        key,
        *trader,
        (&first.meta, &second.meta),
        *XRD,
        ROUTE_INPUT,
        0,
        validity,
    );
    let hash = charges.submit(c, route);

    // The trader's withdraw is a leg, its own to reach: it pays the input
    // and the price whatever the core does after.
    assert!(
        c.run_until(epochs(8), |c| held(c, trader.address(), *XRD)
            < SWAPPER_FUNDING - ROUTE_INPUT),
        "the trader's leg must pay before the core is asked anything",
    );
    let paid = held(c, trader.address(), *XRD);

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
    assert!(
        clock(c) < Window::Delivery.of(Deadline::of(validity_end)).end,
        "the cut has to lift inside the delivery window, or the core's output has nowhere to land",
    );
    for shard in [FIRST_VENUE_SHARD, SECOND_VENUE_SHARD] {
        assert!(
            c.chain_fate(shard, hash).1.is_none(),
            "the core must still be waiting on its certificates when the cut lifts, \
             or the reclaim below is answered by its verdict rather than by the probe",
        );
    }
    assert_eq!(
        held(c, trader.address(), *XRD),
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
        c.run_until(epochs(8), |c| held(c, trader.address(), *XRD) > paid),
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
    xrd.assert_settles_within(
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

/// Everything that can hold each side of the pair in a route scenario:
/// the traders and the two venues themselves. The providers stocked and
/// hold nothing a route can reach.
fn route_worlds<C: Cluster>(
    c: &C,
    first: &StockedVenue,
    second: &StockedVenue,
    traders: &[(Ed25519PrivateKey, PrincipalAddr)],
) -> (World, World) {
    let holders: Vec<Address> = traders
        .iter()
        .map(|(_, account)| account.address())
        .collect();
    let xrd = World::open(
        c,
        *XRD,
        holders.iter().copied(),
        [
            reserve_cell(&first.meta, *XRD),
            reserve_cell(&second.meta, *XRD),
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
    (xrd, units)
}

/// Drive every trader's route through both venues and hold the run to
/// every route accepting, with both sides of the pair conserved.
fn drive_routes<C: Cluster>(
    c: &mut C,
    first: &StockedVenue,
    second: &StockedVenue,
    traders: &[(Ed25519PrivateKey, PrincipalAddr)],
    budget: Budget,
) -> RouteReport {
    let (xrd, units) = route_worlds(c, first, second, traders);

    let start = c.now();
    let mut charges = Charges::default();
    let mut submissions: Vec<TxHash> = Vec::with_capacity(traders.len());
    for (key, account) in traders {
        let tx = build_route_tx(
            key,
            *account,
            (&first.meta, &second.meta),
            *XRD,
            ROUTE_INPUT,
            0,
            validity_around(c.now()),
        );
        submissions.push(charges.submit(c, tx));
    }

    let all = c.run_until(budget, |c| {
        submissions
            .iter()
            .all(|hash| c.tx_status(*hash).is_some_and(|s| s.is_final()))
    });
    assert!(all, "the route never settled within budget");

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

    // Nothing here mints: the XRD the traders paid in is what the venues
    // now hold less the prices burned, and the units the first venue
    // paid out are what the second took back. Driven rather than read,
    // since the deposit that banks each trader's output lands a hop
    // after the second venue's verdict.
    xrd.assert_settles_within(c, &charges, budget, "routes through two venues");
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
        *XRD,
        ROUTE_INPUT,
        REFUSED_FLOOR,
        validity_around(c.now()),
    );
    let price = declared_price(c, &refused);
    let funded = vault_balance(c, TRADER_SHARD, trader);
    let (first_cell, second_cell) = (
        reserve_cell(&first.meta, *XRD),
        reserve_cell(&second.meta, *XRD),
    );
    let (first_before, second_before) = (held_at(c, first_cell), held_at(c, second_cell));
    assert!(
        first_before > 0 && second_before > 0,
        "both venues have to be holding something, or the reserve check \
         holds trivially at zero: {first_before} and {second_before}",
    );
    let (xrd, units) = route_worlds(c, &first, &second, &cast[..1]);
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

    // The trader's own leg certifies first and reports the route accepted
    // on its chain, which is a claim about the leg and not the verdict;
    // the second venue's refusal follows on its own chain, and the
    // reclaim it licenses is a block of the trader shard's own after
    // that. So nothing is read off the first terminal status: what is
    // asserted is the reclaim.
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
        *XRD,
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
    xrd.assert_settles_within(
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
