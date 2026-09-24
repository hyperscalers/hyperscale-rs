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
use hyperscale_types::{
    Address, BUNDLE_WAIT, BlockHeight, Deadline, Ed25519PrivateKey, PrincipalAddr, ShardId,
    SubstateKey, TransactionDecision, TransactionStatus, TxHash, WeightedTimestamp, Window,
};
use hyperscale_vm_effects::{CrossingId, Kind};
use hyperscale_vm_types::{LegRole, LegShape};

use crate::straddler::isolate_ec_intake;
use crate::support::conservation::{Charges, World};
use crate::support::query::{assert_reclaimed_leg, declared_price, held, held_at, vault_balance};
use crate::support::tx::{build_route_tx, build_swap_tx, validity_around};
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
    let (protocol_resource, units) = route_worlds(c, &first, &second, &traders);

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
    assert!(
        clock(c) < validity_end.plus(BUNDLE_WAIT),
        "the cut has to lift while the delivering member is still waiting on its bundle, \
         or the core's output has nowhere to land",
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
/// report is empty.
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
/// member may still take, if the route does not settle whole once the
/// cut lifts, or if the resource is not conserved.
pub fn a_route_whose_core_never_combines_holds_its_input<C: FaultableCluster>(c: &mut C) {
    let mut taken = Vec::new();
    let (first, second) = stand_up_venues(c, &mut taken);
    let traders = traders(&mut taken);
    let (key, trader) = &traders[0];
    let cut = [
        isolate_ec_intake(c, FIRST_VENUE_SHARD, SECOND_VENUE_SHARD),
        isolate_ec_intake(c, SECOND_VENUE_SHARD, FIRST_VENUE_SHARD),
    ];
    let (protocol_resource, units) = route_worlds(c, &first, &second, &traders);

    let mut charges = Charges::default();
    let validity = validity_around(c.now());
    let funded = held(c, trader.address(), *PROTOCOL_RESOURCE);
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

    assert!(
        c.run_until(epochs(8), |c| held(c, trader.address(), *PROTOCOL_RESOURCE)
            < funded - ROUTE_INPUT),
        "the trader's leg must pay the input and the price before the core is asked anything",
    );
    let paid = held(c, trader.address(), *PROTOCOL_RESOURCE);

    let deadline = Deadline::of(validity.end_timestamp_exclusive);
    hold_past_the_core_window(c, deadline);
    assert!(
        cut.iter().any(|handle| handle.fired() > 0),
        "the certificate channel must actually have been exercised and cut",
    );
    assert_nothing_spoke(c, hash, *trader, paid);
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
    let (protocol_resource, units) = route_worlds(c, &first, &second, &traders);

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
    let (protocol_resource, units) = route_worlds(c, first, second, traders);

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
    let (protocol_resource, units) = route_worlds(c, &first, &second, &cast[..1]);
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
