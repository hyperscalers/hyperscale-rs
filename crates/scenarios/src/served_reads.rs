//! What a shared member reads of the vaults the members around it
//! reserve, and from which block its part is served.
//!
//! A route through a venue on its payer's shard runs a core member there
//! that reads the vault it presents as a badge and reserves the vault it
//! withdraws from. Its part to the other venue, which shares its verdict,
//! is served from the block that makes it head: by then every member
//! placed ahead of it on those vaults has left the queue, and every tick
//! below its place has settled what it took, so both venues read the
//! vaults as one.

use hyperscale_engine::PROTOCOL_RESOURCE;
use hyperscale_storage::RowState;
use hyperscale_types::{
    Ed25519PrivateKey, PrincipalAddr, ResourceAddr, ShardId, TimestampRange, Transaction,
    TransactionDecision, TransactionStatus, TxHash,
};

use crate::route::{FIRST_VENUE_SHARD, ROUTE_INPUT, SECOND_VENUE_SHARD};
use crate::straddler::{isolate_crossing_intake, isolate_provision_intake};
use crate::support::conservation::{Charges, World};
use crate::support::query::{held, held_at};
use crate::support::tx::{
    build_resource_transfer_tx, build_route_presenting_tx, build_sponsored_route_presenting_tx,
    build_swap_tx, validity_around,
};
use crate::support::wait::await_tx_terminal;
use crate::support::{Budget, Cluster, FaultableCluster, epochs};
use crate::venue::{
    PROVIDER_FUNDING, SWAPPER_FUNDING, StockedVenue, accepted, grind_onto, reserve_cell,
    stand_up_venue,
};

/// Where the vaults the members read and reserve sit, beside a venue.
const HOME: ShardId = FIRST_VENUE_SHARD;

/// The venue every core here shares with [`HOME`]'s.
const AWAY: ShardId = SECOND_VENUE_SHARD;

/// A venue on each, in the order they are stood up.
const VENUES: [ShardId; 2] = [HOME, AWAY];

/// What each of the cast swaps into stake units before any route.
const UNITS_BOUGHT: u128 = 4 * ROUTE_INPUT;

/// A provider on every venue's quarter, then the two holders on
/// [`HOME`], each funded for what it does.
#[must_use]
pub fn served_reads_genesis_accounts() -> Vec<(PrincipalAddr, u128)> {
    let mut taken = Vec::new();
    let mut accounts: Vec<(PrincipalAddr, u128)> = VENUES
        .iter()
        .map(|&venue| (grind_onto(venue, &mut taken).1, PROVIDER_FUNDING))
        .collect();
    accounts.extend(
        cast(&mut taken)
            .into_iter()
            .map(|(_, account)| (account, SWAPPER_FUNDING)),
    );
    accounts.push((grind_onto(AWAY, &mut taken).1, SWAPPER_FUNDING));
    accounts
}

/// Two holders of stake units on [`HOME`], ground after the providers.
fn cast(taken: &mut Vec<u8>) -> [(Ed25519PrivateKey, PrincipalAddr); 2] {
    [grind_onto(HOME, taken), grind_onto(HOME, taken)]
}

/// Two stocked venues, the cast holding stake units, and the worlds
/// every route reaches.
struct Stage {
    venues: Vec<StockedVenue>,
    cast: [(Ed25519PrivateKey, PrincipalAddr); 2],
    /// An account on [`AWAY`], which sends the cast what lands on them
    /// from there.
    courier: (Ed25519PrivateKey, PrincipalAddr),
    unit: ResourceAddr,
    protocol_resource: World,
    units: World,
    charges: Charges,
}

impl Stage {
    /// Stand every venue up, swap the cast into stake units on
    /// [`HOME`]'s venue, and open the worlds.
    fn stand_up<C: Cluster>(c: &mut C) -> Self {
        assert!(
            VENUES.iter().all(|&shard| c.serves_shard(shard)),
            "the grown four-shard topology must seat every venue's quarter",
        );
        let mut taken = Vec::new();
        let venues: Vec<StockedVenue> = VENUES
            .iter()
            .map(|&shard| stand_up_venue(c, shard, &mut taken))
            .collect();
        let cast = cast(&mut taken);
        let courier = grind_onto(AWAY, &mut taken);
        let unit = venues[0].unit;
        for (key, account) in &cast {
            accepted(
                c,
                build_swap_tx(
                    key,
                    *account,
                    &venues[0].meta,
                    *PROTOCOL_RESOURCE,
                    UNITS_BOUGHT,
                    0,
                    validity_around(c.now()),
                ),
                "a local swap must hand its caller stake units",
            );
            assert!(
                c.run_until(epochs(4), |c| held(c, account.address(), unit)
                    >= ROUTE_INPUT),
                "the swap's units must land before a route spends them",
            );
        }
        let world = |c: &C, resource| {
            World::open(
                c,
                resource,
                cast.iter()
                    .chain([&courier])
                    .map(|(_, account)| account.address()),
                venues
                    .iter()
                    .map(|venue| reserve_cell(&venue.meta, resource)),
            )
        };
        let protocol_resource = world(c, *PROTOCOL_RESOURCE);
        let units = world(c, unit);
        Self {
            venues,
            cast,
            courier,
            unit,
            protocol_resource,
            units,
            charges: Charges::default(),
        }
    }

    /// Submit `tx`, owing its price.
    fn submit<C: Cluster>(&mut self, c: &mut C, tx: Transaction) -> TxHash {
        self.charges.submit(c, tx)
    }

    /// A route of the first of the cast, through both venues, presenting
    /// its vault of units as a badge and withdrawing `asked` of them: a
    /// `Read` and a `Reserve` on one served key.
    fn presenting_route(&self, asked: u128, validity: TimestampRange) -> Transaction {
        let (key, holder) = &self.cast[0];
        build_route_presenting_tx(
            key,
            *holder,
            (&self.venues[0].meta, &self.venues[1].meta),
            (self.unit, asked),
            validity,
        )
    }

    /// Hold the holder to a route's withdraw of `asked` out of `whole`:
    /// the vault ends below `whole`, short of what the two swaps bring
    /// back of `asked`, and above `whole - asked`, which is every other
    /// balance's leaving it.
    fn assert_route_spent<C: Cluster>(&self, c: &mut C, whole: u128, asked: u128) {
        let holder = self.cast[0].1.address();
        assert!(
            c.run_until(epochs(4), |c| held(c, holder, self.unit) != whole),
            "the route must settle on the holder's vault",
        );
        let ended = held(c, holder, self.unit);
        assert!(
            whole - asked < ended && ended < whole,
            "the holder ends at one balance: {ended} of {whole}, {asked} spent",
        );
    }

    /// What the venues pool of the unit between them.
    fn pooled_units<C: Cluster>(&self, c: &C) -> u128 {
        self.venues
            .iter()
            .map(|venue| held_at(c, reserve_cell(&venue.meta, self.unit)))
            .sum()
    }

    /// Submit [`Self::presenting_route`] with [`AWAY`]'s bundle held off
    /// [`HOME`], and run until it stands head there, named by no line:
    /// the state of its head block is what it reads from then on, and
    /// nothing is due to run it until `held_back` is let go.
    fn stand_a_route_head<C: FaultableCluster>(&mut self, c: &mut C, asked: u128) -> TxHash {
        let _held_back = isolate_provision_intake(c, HOME, AWAY);
        let route = self.presenting_route(asked, validity_around(c.now()));
        let route = self.submit(c, route);
        assert!(
            c.run_until(epochs(4), |c| heads(c, HOME, route)),
            "the route must stand head on its payer's shard",
        );
        route
    }

    /// Hold both worlds to settling, `context` naming what ran.
    fn assert_conserved<C: Cluster>(self, c: &mut C, context: &str) {
        self.protocol_resource
            .assert_settles_within(c, &self.charges, epochs(8), context);
        self.units
            .assert_settles_within(c, &Charges::default(), epochs(8), context);
    }
}

/// Whether `tx` stands placed and head on `shard`, unnamed.
fn heads<C: Cluster>(c: &C, shard: ShardId, tx: TxHash) -> bool {
    c.queued_rows(shard).is_some_and(|rows| {
        rows.get(&tx).is_some_and(|row| {
            row.state == RowState::Pending && row.queued.is_some() && row.head.is_some()
        })
    })
}

/// Whether `tx` stands placed on `shard` and waits there, not head.
fn waits<C: Cluster>(c: &C, shard: ShardId, tx: TxHash) -> bool {
    c.queued_rows(shard).is_some_and(|rows| {
        rows.get(&tx).is_some_and(|row| {
            row.state == RowState::Pending && row.queued.is_some() && row.head.is_none()
        })
    })
}

/// Assert `tx` ends as `decision` within the budget.
fn ends_as<C: Cluster>(c: &mut C, tx: TxHash, decision: TransactionDecision, context: &str) {
    let status = await_tx_terminal(c, tx, epochs(8));
    assert_eq!(
        status,
        Some(TransactionStatus::Completed(decision)),
        "{context}",
    );
}

/// What a run past a refusal takes to bring a boundary above it into the
/// beacon's record, which a reclaim reads it at.
///
/// The refusal first stands out a span of seconds, whatever an epoch is,
/// so that takes two epochs of five minutes and nine of thirty seconds.
/// A wait short of it leaves the reclaim to land past the route's naming
/// window.
const ANSWER_BOUNDARY: Budget = epochs(10);

/// Two members reading what the other reserves both settle, in the
/// order they were placed.
///
/// Each of two holders on [`HOME`] trades its own units through
/// [`HOME`]'s venue and [`AWAY`]'s, sponsored by the other, who presents
/// its vault of units as a badge: the first route reads the second
/// holder's vault and reserves the first's, the second reads the first's
/// and reserves the second's. Both are payer cores on [`HOME`], placed at
/// their commits. The first heads; the second's read meets the first's
/// reservation, so it waits behind it, and heads only once the first has
/// left. Each is served to [`AWAY`] from the block making it head there,
/// over the vaults as everything ahead of it left them, so both venues
/// run each over one reading and both accept.
///
/// # Panics
///
/// Panics if a venue or a swap misses its budget, if the first route
/// does not stand head before the second is submitted, if either route
/// does not accept, if the second is not served after the first, at or
/// after the block settling the first and past its own commit, or if
/// either side is not conserved.
pub fn two_members_reading_what_the_other_reserves_both_settle<C: Cluster>(c: &mut C) {
    let mut stage = Stage::stand_up(c);
    let validity = validity_around(c.now());
    let route = |stage: &Stage, sponsor: usize, trader: usize| {
        let (sponsor_key, _) = &stage.cast[sponsor];
        let (trader_key, trader) = &stage.cast[trader];
        build_sponsored_route_presenting_tx(
            sponsor_key,
            trader_key,
            *trader,
            (&stage.venues[0].meta, &stage.venues[1].meta),
            (stage.unit, ROUTE_INPUT),
            Some(stage.unit),
            validity,
        )
    };
    let first = route(&stage, 1, 0);
    let first = stage.submit(c, first);
    assert!(
        c.run_until(epochs(4), |c| heads(c, HOME, first)),
        "the first route's payer core must stand head on its sponsor's shard",
    );
    let second = route(&stage, 0, 1);
    let second = stage.submit(c, second);
    ends_as(
        c,
        first,
        TransactionDecision::Accept,
        "the first route must accept",
    );
    ends_as(
        c,
        second,
        TransactionDecision::Accept,
        "the second route must accept once the first has left",
    );
    let served = |c: &C, tx| c.served_at(HOME, AWAY, tx);
    assert!(
        c.run_until(epochs(4), |c| served(c, first).is_some()
            && served(c, second).is_some()),
        "the away venue must hold both routes' parts",
    );
    assert!(
        served(c, first) < served(c, second),
        "the second is served from a later head than the first: {:?} against {:?}",
        served(c, first),
        served(c, second),
    );
    let (second_committed, _) = c.chain_fate(HOME, second);
    let second_committed = second_committed.expect("the second route commits on its payer's shard");
    let first_settled = c
        .chain_fate(HOME, first)
        .1
        .map(|(height, _)| height)
        .expect("the first route settles on its payer's shard");
    let second_served = served(c, second).expect("the away venue holds the second's part");
    assert!(
        second_served >= first_settled,
        "the second is served no earlier than the block settling the first: {second_served:?} \
         against {first_settled:?}",
    );
    assert!(
        second_served > second_committed,
        "the second is served from its head, past the block committing it: {second_served:?} \
         against {second_committed:?}",
    );
    c.assert_effects_agreed(first);
    c.assert_effects_agreed(second);
    stage.assert_conserved(c, "two members reading what the other reserves");
}

/// A reclaim landing between a member's head and its naming moves the
/// vault the member reads and reserves, and both shards still read one
/// balance.
///
/// A swap out of the holder's vault of units asks a floor past any
/// pool's reach, and the venue refuses it. A reclaim reads that refusal
/// at a boundary the beacon recorded, a long way off on this chain's
/// epochs, so the reading is held back from [`HOME`] until the first of
/// them comes up. A route presenting that vault and withdrawing from it
/// then stands head there, its part read at a height where the leg's
/// units are gone. The reading is let through, and the reclaim credits
/// the vault with the route still unnamed, so the tick's view holds what
/// the part does not. The route then runs: both shards read the part,
/// and the reclaim composes with its reservation at settlement.
///
/// # Panics
///
/// Panics if the leg does not pay, if the route does not stand head, if
/// the reclaim does not land with the route unnamed, if the route does
/// not accept, if the holder does not end at what the reclaim and the
/// route leave, if the route's own part is not held to the one its
/// counterpart absorbed, or differs from it, or if either side is not
/// conserved.
pub fn a_reclaim_onto_a_served_till_reads_one_balance_on_both_shards<C: FaultableCluster>(
    c: &mut C,
) {
    let mut stage = Stage::stand_up(c);
    let holder = stage.cast[0].1;
    let before = held(c, holder.address(), stage.unit);
    let (issued, asked) = (before / 2, before / 4);
    let answer = isolate_crossing_intake(c, HOME, AWAY);
    let refused = build_swap_tx(
        &stage.cast[0].0,
        holder,
        &stage.venues[1].meta,
        stage.unit,
        issued,
        issued * 1_000_000,
        validity_around(c.now()),
    );
    stage.submit(c, refused);
    assert!(
        c.run_until(epochs(8), |c| held(c, holder.address(), stage.unit)
            == before - issued),
        "the refused swap's leg must pay out of the vault first",
    );
    let _ = c.run_until(ANSWER_BOUNDARY, |_| false);
    assert!(
        answer.fired() > 0,
        "the venue's refusal must have come up for reading",
    );

    let route = stage.stand_a_route_head(c, asked);
    let reclaimed = c.metric("reclaims_folded", None);
    assert_eq!(
        held(c, holder.address(), stage.unit),
        before - issued,
        "the refusal must not have landed yet",
    );
    c.clear_drops();
    let _still_held_back = isolate_provision_intake(c, HOME, AWAY);
    assert!(
        c.run_until(epochs(8), |c| held(c, holder.address(), stage.unit)
            == before),
        "the reclaim must land",
    );
    assert!(
        heads(c, HOME, route),
        "the reclaim must land with the route still unnamed: {:?}",
        c.chain_fate(HOME, route),
    );
    assert!(c.metric("reclaims_folded", None) > reclaimed);

    c.clear_drops();
    ends_as(
        c,
        route,
        TransactionDecision::Accept,
        "the route must accept",
    );
    stage.assert_route_spent(c, before, asked);
    assert!(
        c.run_until(epochs(4), |c| c.served_part_agreed(HOME, route)),
        "the oracle must have compared the route's part",
    );
    c.assert_effects_agreed(route);
    stage.assert_conserved(c, "a reclaim onto a served till");
}

/// An owed credit landing between a member's head and its naming lands
/// on a vault the member debits, and composes with the debit.
///
/// The courier on [`AWAY`] holds units and sends them to the holder on
/// [`HOME`], through no venue, so nothing the route holds on [`AWAY`]
/// stands in its way, and [`HOME`]'s fold credits them. A route presenting
/// the holder's vault and withdrawing from it stands head first, so its part
/// lacks the credit, the view its tick reads the holds on holds it, and
/// the settlement of its withdraw lands on the vault as the credit left
/// it: the fold differential compares a credit the part never saw.
///
/// # Panics
///
/// Panics if the route does not stand head, if the credit does not land
/// with the route unnamed, if the route does not accept, if the holder
/// does not end at what the credit and the route leave, if the route's
/// own part is not held to the one its counterpart absorbed, or differs
/// from it, or if either side is not conserved.
pub fn an_owed_credit_onto_a_served_vault_composes<C: FaultableCluster>(c: &mut C) {
    let mut stage = Stage::stand_up(c);
    let holder = stage.cast[0].1;
    let before = held(c, holder.address(), stage.unit);
    let asked = before / 2;
    let courier = stage.courier.1.address();
    let stocking = build_swap_tx(
        &stage.courier.0,
        stage.courier.1,
        &stage.venues[1].meta,
        *PROTOCOL_RESOURCE,
        ROUTE_INPUT,
        0,
        validity_around(c.now()),
    );
    let stocking = stage.submit(c, stocking);
    ends_as(
        c,
        stocking,
        TransactionDecision::Accept,
        "the courier must stock up",
    );
    assert!(
        c.run_until(epochs(4), |c| held(c, courier, stage.unit) > 0),
        "the courier's units must land",
    );
    let credited = held(c, courier, stage.unit) / 2;
    let pooled = stage.pooled_units(c);
    let route = stage.stand_a_route_head(c, asked);

    let delivery = build_resource_transfer_tx(
        &stage.courier.0,
        stage.courier.1,
        (stage.unit, credited),
        holder,
        validity_around(c.now()),
    );
    let delivery = stage.submit(c, delivery);
    assert!(
        c.run_until(epochs(8), |c| held(c, holder.address(), stage.unit)
            == before + credited),
        "the owed credit must land on the holder's vault",
    );
    assert!(
        heads(c, HOME, route),
        "the credit must land with the route still unnamed",
    );

    c.clear_drops();
    ends_as(
        c,
        delivery,
        TransactionDecision::Accept,
        "the delivery must accept",
    );
    ends_as(
        c,
        route,
        TransactionDecision::Accept,
        "the route must accept",
    );
    stage.assert_route_spent(c, before + credited, asked);
    // The route's net is far smaller than the credit, so the bound above
    // holds with the credit lost: only the units the venues kept say
    // exactly where the vault ends.
    assert!(
        c.run_until(epochs(4), |c| held(c, holder.address(), stage.unit)
            + stage.pooled_units(c)
            == before + credited + pooled),
        "the vault must end at the credit less what the venues kept: {} held, {} pooled",
        held(c, holder.address(), stage.unit),
        stage.pooled_units(c),
    );
    assert!(
        c.run_until(epochs(4), |c| c.served_part_agreed(HOME, route)),
        "the oracle must have compared the route's part",
    );
    c.assert_effects_agreed(route);
    stage.assert_conserved(c, "an owed credit onto a served vault");
}

/// A member named in the block that makes it head, where that block's
/// write trails its commit, reads one part with its counterpart.
///
/// The route's core on [`AWAY`] commits behind [`HOME`]'s bundle, so its
/// head and its naming fall in one block there, or the shard's disk has
/// it wait for that block's write before it reads the part.
///
/// # Panics
///
/// Panics if the route does not accept, if no shard names it in its head
/// block, if that shard's part is not held to the one its counterpart
/// absorbed, or differs from it, or if either side is not conserved.
pub fn a_member_named_in_its_head_block_reads_one_part<C: Cluster>(c: &mut C) {
    let mut stage = Stage::stand_up(c);
    let holder = stage.cast[0].1;
    let before = held(c, holder.address(), stage.unit);
    let route = stage.presenting_route(before / 2, validity_around(c.now()));
    let route = stage.submit(c, route);
    ends_as(
        c,
        route,
        TransactionDecision::Accept,
        "the route must accept",
    );
    let named_at_head = |c: &C, shard: ShardId| {
        c.ran_line(shard, route)
            .is_some_and(|(tick, served)| served == Some(tick))
    };
    assert!(
        c.run_until(epochs(4), |c| named_at_head(c, HOME)
            || named_at_head(c, AWAY)),
        "one shard must name the route in the block making it head: {:?} {:?}",
        c.ran_line(HOME, route),
        c.ran_line(AWAY, route),
    );
    let shard = if named_at_head(c, HOME) { HOME } else { AWAY };
    assert!(
        c.run_until(epochs(4), |c| c.served_part_agreed(shard, route)),
        "the oracle must have compared the route's part on {shard:?}",
    );
    c.assert_effects_agreed(route);
    stage.assert_conserved(c, "a member named in its head block");
}

/// A restart of the committee between a member's head and its tick leaves
/// the tick reading the part its counterpart reads.
///
/// `restart` takes [`HOME`]'s committee down and back with the route head
/// and unnamed. The store keeps the head height, the replay seats the
/// row, and the line that then runs it reads the part from that height.
///
/// # Panics
///
/// Panics if the route does not stand head, if it does not accept, if a
/// member's own part is not the one its counterpart absorbed, or if
/// either side is not conserved.
pub fn a_restart_between_head_and_tick_reads_the_same_part<C: FaultableCluster>(
    c: &mut C,
    restart: impl FnOnce(&mut C, ShardId),
) {
    let mut stage = Stage::stand_up(c);
    let holder = stage.cast[0].1;
    let before = held(c, holder.address(), stage.unit);
    let asked = before / 2;
    let route = stage.stand_a_route_head(c, asked);
    let served_before = c.ran_line(HOME, route);
    assert_eq!(served_before, None, "the route is unnamed at the restart");

    restart(c, HOME);
    assert!(
        c.run_until(epochs(8), |c| heads(c, HOME, route)),
        "the restarted shard must still hold the route head",
    );
    c.clear_drops();
    ends_as(
        c,
        route,
        TransactionDecision::Accept,
        "the route must accept",
    );
    stage.assert_route_spent(c, before, asked);
    assert!(
        c.run_until(epochs(4), |c| c.served_parts_agreed() > 0),
        "the oracle must have read a part",
    );
    c.assert_effects_agreed(route);
    stage.assert_conserved(c, "a restart between head and tick");
}

/// A leg reserving a vault settles before a member that reads the vault
/// heads, and the member reads what the leg left.
///
/// A holder on [`HOME`] swaps four fifths of its units into the protocol
/// resource at [`AWAY`]'s venue: on [`HOME`] that swap is only a leg, its
/// withdraw, which a line names to run, and whose tick the holder's
/// committee certifies only once its execution votes, held back, flow
/// again. A second route of the same holder, through [`HOME`]'s venue
/// and [`AWAY`]'s, submitted while the leg stands in its tick, presents
/// the holder's vault of units and withdraws half of what it held. Its core
/// on [`HOME`] is placed behind the leg's hold and heads only once the
/// leg has left its tick; its part to [`AWAY`] then serves the vault the
/// leg left, short of the half: the withdraw is infeasible, the route
/// is rejected, and both venues end it.
///
/// # Panics
///
/// Panics if a venue or a swap misses its budget, if the leg is not
/// named before the read is submitted, if the leg does not accept, if
/// the read completes anywhere or is served before the leg settles, or
/// if either side is not conserved.
pub fn a_leg_reserving_a_read_vault_settles_before_the_read<C: FaultableCluster>(c: &mut C) {
    let mut stage = Stage::stand_up(c);
    let holder = stage.cast[0].1;
    let before = held(c, holder.address(), stage.unit);
    let (taken, asked) = (before * 4 / 5, before / 2);
    assert!(
        before - taken < asked,
        "the leg leaves less than the read asks"
    );
    let validity = validity_around(c.now());
    let leg = build_swap_tx(
        &stage.cast[0].0,
        holder,
        &stage.venues[1].meta,
        stage.unit,
        taken,
        0,
        validity,
    );
    // The holder's committee keeps its execution votes to itself until
    // the read stands behind the leg, so the leg's tick certifies only
    // once the read is placed.
    let votes = c.drop_type_between_members(HOME, HOME, "execution.vote");
    let leg = stage.submit(c, leg);
    assert!(
        c.run_until(epochs(4), |c| c.member_rows(HOME).is_some_and(|rows| {
            matches!(rows.get(&leg), Some(RowState::InFlight { .. }))
        })),
        "the leg's withdraw must be named on the holder's shard",
    );
    let read = build_route_presenting_tx(
        &stage.cast[0].0,
        holder,
        (&stage.venues[0].meta, &stage.venues[1].meta),
        (stage.unit, asked),
        validity,
    );
    let read = stage.submit(c, read);
    assert!(
        c.run_until(epochs(4), |c| waits(c, HOME, read)),
        "the read must stand placed behind the leg on the holder's shard",
    );
    assert!(votes.fired() > 0, "the holder's votes must have been held");
    c.clear_drops();
    ends_as(c, leg, TransactionDecision::Accept, "the leg must accept");
    ends_as(
        c,
        read,
        TransactionDecision::Reject,
        "the read must fail on what the leg left",
    );
    for venue in [HOME, AWAY] {
        assert!(
            c.run_until(epochs(4), |c| c.chain_fate(venue, read).1.is_some()),
            "{venue:?} must end the read: {:?}",
            c.chain_fate(venue, read),
        );
    }
    assert!(
        c.ran(HOME, read).iter().all(|ran| !ran.succeeded),
        "the read must not complete where the holder's vault sits: {:?}",
        c.ran(HOME, read),
    );
    let settled = c
        .chain_fate(HOME, leg)
        .1
        .map(|(height, _)| height)
        .expect("the leg settled on the holder's shard");
    assert!(
        c.served_at(HOME, AWAY, read)
            .is_some_and(|at| at >= settled),
        "the read is served once the leg has settled: served at {:?}, settled at {settled:?}",
        c.served_at(HOME, AWAY, read),
    );
    stage.assert_conserved(c, "a leg reserving a read vault");
}
