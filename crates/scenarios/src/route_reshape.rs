//! A divided shape meeting a reshape: the shard a leg or a core sits on
//! leaving the trie while the shape is in flight.
//!
//! A shard scheduled to leave divides like any other, to its terminal:
//! classification is the shape's legs against the committing block's
//! trie and nothing else, so a pending reshape changes what a member
//! runs not at all. A record cell follows its prefix to the successor,
//! and a claim or a delivery is a pull on whoever holds the prefix when
//! it is made. What these scenarios pin is that nothing in flight across
//! the cut is stranded by it — a transfer the leaving shard included settles
//! there, one it never included is delivered by its successor or refused
//! at the payer's deadline, and a call into a component on the leaving
//! shard keeps clearing from admission through the cut and from the
//! successor after it.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use hyperscale_effects_bridge::genesis::GenesisPackages;
use hyperscale_effects_bridge::vm_statics::crossing_records;
use hyperscale_engine::PROTOCOL_RESOURCE;
use hyperscale_storage::{FeeTerms, RowState};
use hyperscale_types::{
    Address, BlockHeight, Deadline, Ed25519PrivateKey, Epoch, EpochWindows,
    MAX_UNSETTLED_PER_BLOCK, MAX_UNSETTLED_TXS, PrincipalAddr, ShardId, SubstateKey,
    TimestampRange, Transaction, TransactionDecision, TransactionStatus, TxHash, TxsInFlight,
    WeightedTimestamp, Window,
};
use hyperscale_vm_effects::{Answered, ProtocolHasher, fee_hold_total_key};

use crate::reshape::split_lifecycle;
use crate::route::{FIRST_VENUE_SHARD, ROUTE_INPUT, SECOND_VENUE_SHARD, TRADER_SHARD};
use crate::straddler::{
    STRADDLER_PAYMENT, cast_splitter_vote, cast_threshold_vote, isolate_crossing_intake,
    isolate_crossing_intake_but_from, isolate_ec_intake, merge_executed, straddler_split_bytes,
    vote_splitter_down_to,
};
use crate::support::conservation::{Charges, World};
use crate::support::faultable::report_crossing_measures;
use crate::support::query::{
    ChainMentions, anchor_seeded, answer_standing, beacon_epoch, clock, crossing_cells,
    declared_price, epoch_duration_ms, escrowed_into, held, held_at, merge_keeper_count, owed_at,
    owning_shard, scheduled_terminal_epoch, shard_decisions, split_admitted, stands_at,
    terminal_height,
};
use crate::support::tx::{
    MERGE_STRADDLER_LEFT, MERGE_STRADDLER_RIGHT, MERGE_STRADDLER_SURVIVOR, ParamBallot,
    STRADDLER_SPLITTER, STRADDLER_SURVIVOR, armed_split_bytes, ballast_to, build_param_vote_tx,
    build_route_tx, build_sponsored_swap_tx, build_swap_tx, build_transfer_tx, departing_target,
    merge_survivor_ballast_accounts, merge_train_setup, pool_operator, split_ballast_accounts_for,
    split_train_setup, validity_around, voted_split_bytes,
};
use crate::support::wait::{
    await_anchor_seeded, await_crossings_end, await_merge_keeper_count, await_serves,
    await_split_admitted, await_tx_terminal, measure_blocks_per_epoch,
};
use crate::support::{
    Budget, Cluster, FaultHandle, FaultableCluster, committees_on_separate_hosts, epochs,
};
use crate::venue::{
    PROVIDER_FUNDING, SWAP_INPUT, SWAPPER_FUNDING, StockedVenue, caller_on_the_venues_shard,
    grind_onto, reserve_cell, stand_up_venue, swappers_on, venue_genesis_accounts_on,
};

/// The most transfers the train carries into the splitter, and what the
/// funding covers: enough to reach the admission at a few submissions
/// per epoch with several to spare past it, one payer each.
pub const SPLIT_TRAIN: usize = 48;

/// The most transfers the train carries into the merging shard: enough
/// to reach the pairing from the grow at a few submissions per epoch
/// with several to spare past the gate, one payer each.
pub const MERGE_TRAIN: usize = 32;

/// Submissions per epoch: slow enough that the funded train outlasts a
/// reshape's lead and the admission it leads to, with transfers on both
/// sides of the fold.
const TRAIN_PER_EPOCH: u64 = 2;

/// Transfers the train keeps sending once the reshape's gate has
/// drained: enough to reach the leaving shard's coast, where it includes
/// nothing.
const PAST_THE_GATE: usize = 6;

/// Where the leaving shard stood when a transfer into it was submitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// No reshape pending: the transfer divides and its delivery lands.
    Live,
    /// The reshape admitted and pending — a split admitted, a merge
    /// paired: the shard is departing and still including. The transfer
    /// divides and settles as it would anywhere, unless the shard's
    /// terminal overtakes it first: the shard includes content up to its
    /// cut and its terminal sweep abandons whatever is still in flight
    /// there, so a transfer sent late in this phase can meet the fate a
    /// draining one does.
    Departing,
    /// The gate drained: the reshape no longer pends, the shard still
    /// includes for a while, then coasts on empty blocks to its terminal.
    /// A transfer it settled before the terminal settles; one it never
    /// settled — never included, or included and overtaken by the cut —
    /// is aborted on the payer's chain, or accepted there and delivered
    /// by the shard's successor once the cut has landed the recipient's
    /// prefix there, or, where nothing delivers it, reclaimed on the
    /// successor's proof that nothing did.
    Draining,
}

/// The byte skew for [`a_departing_venue_clears_swaps_and_carries_on`],
/// on a network born running the fixtures beside the protocol's own.
#[must_use]
pub fn departing_venue_ballast() -> Vec<(PrincipalAddr, u128)> {
    split_ballast_accounts_for(&GenesisPackages::with_fixtures())
}

/// The reshape trigger [`a_departing_venue_clears_swaps_and_carries_on`]
/// arms at genesis: above each child of the ballasted root and below the
/// root itself, on the fixture flash's scale.
#[must_use]
pub fn departing_venue_split_bytes() -> u64 {
    armed_split_bytes(&GenesisPackages::with_fixtures())
}

/// Genesis funding for the departing-route scenarios.
///
/// On the four-shard route topology: ballast putting the first venue's
/// quarter alone over the threshold the scenarios vote in, a provider on
/// each venue's shard, and the trader on its own, ground in the order
/// [`departing_route`] stands them up.
///
/// Only that quarter is ballasted: no quarter can draw enough of the
/// flash to reach the armed threshold on its own, and one drawing too
/// little to clear the derived floor has a sibling well over it, so its
/// merge half never pairs.
#[must_use]
pub fn departing_route_genesis_accounts() -> Vec<(PrincipalAddr, u128)> {
    let packages = GenesisPackages::with_fixtures();
    let mut accounts = ballast_to(FIRST_VENUE_SHARD, 4, departing_target(&packages), &packages);
    let mut taken = Vec::new();
    accounts.push((
        grind_onto(FIRST_VENUE_SHARD, &mut taken).1,
        PROVIDER_FUNDING,
    ));
    accounts.push((
        grind_onto(SECOND_VENUE_SHARD, &mut taken).1,
        PROVIDER_FUNDING,
    ));
    accounts.push((grind_onto(TRADER_SHARD, &mut taken).1, SWAPPER_FUNDING));
    accounts
}

/// Genesis funding for [`a_train_into_a_splitter_strands_nothing`].
#[must_use]
pub fn split_train_genesis_accounts() -> Vec<(PrincipalAddr, u128)> {
    split_train_setup(SPLIT_TRAIN).accounts
}

/// Genesis funding for [`a_train_into_a_merging_shard_strands_nothing`].
#[must_use]
pub fn merge_train_genesis_accounts() -> Vec<(PrincipalAddr, u128)> {
    merge_train_setup(MERGE_TRAIN).accounts
}

/// A venue whose shard is leaving keeps clearing swaps, and clears them
/// from its child once it has left.
///
/// The venue sits on the splitter and its callers on the survivor. With
/// the split admitted the venue's shard is departing, and every swap
/// reaching it divides and settles as it would anywhere: the callers pay
/// their input and one price, the venue claims the inputs. Then the cut:
/// the venue's cells land under a child, the reserve reads there at
/// exactly what the swaps left in it, and a swap after the cut divides
/// against the child and settles like any other.
///
/// # Panics
///
/// Panics if the venue misses its budget standing up, if the split is
/// not admitted or executed within budget, if any swap fails to accept,
/// if the reserve does not carry across the cut, or if either side of
/// the pair is not conserved.
pub fn a_departing_venue_clears_swaps_and_carries_on(c: &mut impl Cluster, budget: Budget) {
    let venue_shard = STRADDLER_SPLITTER;
    let caller_shard = STRADDLER_SURVIVOR;
    split_lifecycle(c);
    assert!(
        c.serves_shard(venue_shard) && c.serves_shard(caller_shard),
        "the grow must seat the venue's shard and its callers'",
    );
    let mut taken = Vec::new();
    let venue = stand_up_venue(c, venue_shard, &mut taken);
    let swappers = swappers_on(&[caller_shard], &mut taken);
    let reserve = reserve_cell(&venue.meta, *PROTOCOL_RESOURCE);
    let stocked = held_at(c, reserve);
    assert!(
        stocked > 0,
        "the venue has to be holding something to price against"
    );

    let holders: Vec<_> = swappers
        .iter()
        .map(|(_, account)| account.address())
        .collect();
    let protocol_resource = World::open(c, *PROTOCOL_RESOURCE, holders.iter().copied(), [reserve]);
    let units = World::open(
        c,
        venue.unit,
        holders,
        [reserve_cell(&venue.meta, venue.unit)],
    );
    let mut charges = Charges::default();

    // The venue's shard is leaving from here to the cut.
    vote_splitter_down_to(c, voted_split_bytes(&GenesisPackages::with_fixtures()));

    let (leaving, later) = swappers.split_at(swappers.len() - 1);
    let mut submitted: Vec<TxHash> = Vec::new();
    for (key, caller) in leaving {
        let swap = build_swap_tx(
            key,
            *caller,
            &venue.meta,
            *PROTOCOL_RESOURCE,
            SWAP_INPUT,
            0,
            validity_around(c.now()),
        );
        submitted.push(charges.submit(c, swap));
    }
    for hash in &submitted {
        let status = await_tx_terminal(c, *hash, budget);
        assert!(
            matches!(
                status,
                Some(TransactionStatus::Completed(TransactionDecision::Accept))
            ),
            "a swap reaching a departing venue must still settle; status = {status:?}",
        );
    }
    let claimed = stocked + SWAP_INPUT * u128::try_from(leaving.len()).expect("a few swaps");
    assert!(
        c.run_until(budget, |c| held_at(c, reserve) == claimed),
        "the departing venue must claim every input: reserve {} against {claimed}",
        held_at(c, reserve),
    );

    // The cut. The venue's prefix lands under one of the children, and
    // the reserve reads there at what the swaps left.
    let (left, right) = venue_shard.children();
    assert!(
        await_serves(c, left, epochs(28)) && await_serves(c, right, epochs(28)),
        "both splitter children must be served within budget",
    );
    assert!(
        await_anchor_seeded(c, left, epochs(6)),
        "the beacon must compose the split children's anchor",
    );
    assert!(
        anchor_seeded(c, left),
        "the children's seeded genesis pins the venue's cells under a child",
    );
    assert_eq!(
        held_at(c, reserve),
        claimed,
        "the venue's reserve must carry across the cut untouched",
    );

    swap_against_the_child(c, &venue, &later[0], &mut charges, claimed, budget);

    protocol_resource.assert_settles_within(c, &charges, budget, "swaps across the venue's split");
    units.assert_settles_within(
        c,
        &Charges::default(),
        budget,
        "swaps across the venue's split",
    );
}

/// The ballast [`a_leg_issued_on_a_departing_shard_reaches_its_venue`]
/// arms its trigger over.
///
/// The callers' shard carries the ballast, so the venue's shard stays
/// under the threshold the scenario votes in.
#[must_use]
pub fn departing_caller_ballast() -> Vec<(PrincipalAddr, u128)> {
    split_ballast_accounts_for(&GenesisPackages::with_fixtures())
}

/// A venue that stays, callers on the shard that is leaving, and the
/// worlds a swap between them can reach.
struct DepartingCallers {
    venue: StockedVenue,
    swappers: Vec<(Ed25519PrivateKey, PrincipalAddr)>,
    /// A funded account on the venue's own shard, which pays a
    /// sponsored swap's fee.
    sponsor: (Ed25519PrivateKey, PrincipalAddr),
    reserve: SubstateKey,
    stocked: u128,
    protocol_resource: World,
    units: World,
}

impl DepartingCallers {
    /// Both worlds settle within `budget` with nothing locked.
    ///
    /// # Panics
    ///
    /// Panics if either world misses its budget or locks a record.
    fn settle_with_nothing_locked<C: Cluster>(
        &self,
        c: &mut C,
        charges: &Charges,
        budget: Budget,
        what: &str,
    ) {
        let locked = self
            .protocol_resource
            .assert_settles_within(c, charges, budget, what);
        assert!(
            locked.is_empty(),
            "{what}: nothing stays locked: {locked:?}"
        );
        let locked = self
            .units
            .assert_settles_within(c, &Charges::default(), budget, what);
        assert!(
            locked.is_empty(),
            "{what}: no delivery stays locked: {locked:?}"
        );
    }
}

/// Stand a venue up on `venue_shard` with its callers on `caller_shard`,
/// then vote the splitter down so one of the two is leaving.
///
/// Which one is the caller's choice of shards: the vote picks the
/// splitter by bytes and knows nothing of the roles, so passing
/// [`STRADDLER_SPLITTER`] as the venue's shard leaves the core and
/// passing it as the callers' leaves the issuer.
///
/// # Panics
///
/// Panics if either shard is unserved, if the venue misses its budget
/// standing up or is holding nothing, or if the split is not admitted on
/// the splitter or is admitted on the survivor.
fn departing_callers<C: Cluster>(
    c: &mut C,
    venue_shard: ShardId,
    caller_shard: ShardId,
) -> DepartingCallers {
    split_lifecycle(c);
    let set = stock_callers_against(c, venue_shard, caller_shard);
    // The splitter is leaving from here to the cut; the survivor stays
    // under the threshold with the flash on it.
    vote_splitter_down_to(c, voted_split_bytes(&GenesisPackages::with_fixtures()));
    assert!(
        await_split_admitted(c, STRADDLER_SPLITTER, epochs(20)),
        "the splitter must admit the split",
    );
    assert!(
        !split_admitted(c, STRADDLER_SURVIVOR),
        "the survivor must not split",
    );
    set
}

/// Stand the venue up on a surviving quarter and the callers on the
/// merge-left child, then wait for the light pair to pair its keepers so
/// the callers' shard is the one leaving.
///
/// # Panics
///
/// Panics if a quarter is unserved, if the venue misses its budget
/// standing up or is holding nothing, or if the light pair does not pair
/// a keeper quorum within budget.
fn merging_callers<C: Cluster>(c: &mut C) -> DepartingCallers {
    let (venue_shard, caller_shard) = (MERGE_STRADDLER_SURVIVOR, MERGE_STRADDLER_LEFT);
    assert!(
        (0..4).all(|path| await_serves(c, ShardId::leaf(2, path), epochs(4))),
        "the grown four-shard topology must seat every quarter",
    );
    let set = stock_callers_against(c, venue_shard, caller_shard);
    // The light merging pair asserts its merge from the genesis byte
    // skew, so the callers' shard is leaving from the pairing to the cut.
    let parent = caller_shard.parent().expect("a depth-2 leaf has a parent");
    assert!(
        await_merge_keeper_count(c, parent, 3, epochs(24)),
        "the light merging pair must pair a keeper quorum within budget",
    );
    assert!(
        c.serves_shard(caller_shard),
        "the callers' shard must still be committing when the swaps go",
    );
    set
}

/// Stand a venue up on `venue_shard` with its callers on `caller_shard`,
/// and open the worlds a swap between them can reach.
///
/// # Panics
///
/// Panics if either shard is unserved, or if the venue misses its budget
/// standing up or is holding nothing to price against.
fn stock_callers_against<C: Cluster>(
    c: &mut C,
    venue_shard: ShardId,
    caller_shard: ShardId,
) -> DepartingCallers {
    assert!(
        c.serves_shard(venue_shard) && c.serves_shard(caller_shard),
        "the grow must seat the venue's shard and its callers'",
    );
    let mut taken = Vec::new();
    let venue = stand_up_venue(c, venue_shard, &mut taken);
    let swappers = swappers_on(&[caller_shard], &mut taken);
    let sponsor = caller_on_the_venues_shard(venue_shard, &[caller_shard]);
    let reserve = reserve_cell(&venue.meta, *PROTOCOL_RESOURCE);
    let stocked = held_at(c, reserve);
    assert!(
        stocked > 0,
        "the venue has to be holding something to price against"
    );
    let holders: Vec<_> = swappers
        .iter()
        .chain([&sponsor])
        .map(|(_, account)| account.address())
        .collect();
    let protocol_resource = World::open(c, *PROTOCOL_RESOURCE, holders.iter().copied(), [reserve]);
    let units = World::open(
        c,
        venue.unit,
        holders,
        [reserve_cell(&venue.meta, venue.unit)],
    );
    DepartingCallers {
        venue,
        swappers,
        sponsor,
        reserve,
        stocked,
        protocol_resource,
        units,
    }
}

/// A caller whose own shard is leaving still reaches a venue that stays,
/// and its successor holds what the swap returned.
///
/// The mirror of [`a_departing_venue_clears_swaps_and_carries_on`]: there
/// the core's shard leaves, here the issuer's. With the reshape pending
/// the callers' shard is departing, and a swap issued there divides as it
/// would anywhere — the caller's leg pays, its crossing reaches the
/// venue, and the venue claims the input and returns the units. Then the
/// cut, which `cut` waits for: the callers' cells land on the successor,
/// the units read there at exactly what the swaps returned, and a swap
/// issued from the successor settles like any other.
///
/// # Panics
///
/// Panics if any swap fails to accept, if the venue does not claim every
/// input, if a caller's output does not carry across the cut, or if
/// either side of the pair is not conserved.
fn swaps_across_the_callers_cut<C: Cluster>(
    c: &mut C,
    set: DepartingCallers,
    cut: impl FnOnce(&mut C),
    budget: Budget,
) {
    let DepartingCallers {
        venue,
        swappers,
        sponsor: _,
        reserve,
        stocked,
        protocol_resource,
        units,
    } = set;
    let mut charges = Charges::default();

    let (leaving, later) = swappers.split_at(swappers.len() - 1);
    let mut submitted: Vec<TxHash> = Vec::new();
    for (key, caller) in leaving {
        let swap = build_swap_tx(
            key,
            *caller,
            &venue.meta,
            *PROTOCOL_RESOURCE,
            SWAP_INPUT,
            0,
            validity_around(c.now()),
        );
        submitted.push(charges.submit(c, swap));
    }
    for hash in &submitted {
        let status = await_tx_terminal(c, *hash, budget);
        assert!(
            matches!(
                status,
                Some(TransactionStatus::Completed(TransactionDecision::Accept))
            ),
            "a swap issued on a departing shard must still settle; status = {status:?}",
        );
    }
    let claimed = stocked + SWAP_INPUT * u128::try_from(leaving.len()).expect("a few swaps");
    assert!(
        c.run_until(budget, |c| held_at(c, reserve) == claimed),
        "the staying venue must claim every input a departing caller sent: reserve {} against \
         {claimed}",
        held_at(c, reserve),
    );
    // What the issuing side is owed: the venue's return crosses back into
    // the shard that is leaving, and every caller banks it before the cut.
    let callers: Vec<PrincipalAddr> = leaving.iter().map(|(_, caller)| *caller).collect();
    assert!(
        c.run_until(budget, |c| callers.iter().all(|caller| held(
            c,
            caller.address(),
            venue.unit
        ) > 0)),
        "every caller on the departing shard must bank its output before the cut; holdings = {:?}",
        callers
            .iter()
            .map(|caller| held(c, caller.address(), venue.unit))
            .collect::<Vec<_>>(),
    );
    let banked: Vec<u128> = callers
        .iter()
        .map(|caller| held(c, caller.address(), venue.unit))
        .collect();

    cut(c);
    // The successor answers for the prefix once it has adopted it, which
    // is a moment after it serves — so the read is awaited and the
    // assertion is on the figure, not on when it arrives.
    let carried = |c: &C| {
        callers
            .iter()
            .map(|caller| held(c, caller.address(), venue.unit))
            .collect::<Vec<_>>()
    };
    assert!(
        c.run_until(budget, |c| carried(c) == banked),
        "a departing caller's output must carry across its own shard's cut untouched: {:?} \
         against {banked:?}",
        carried(c),
    );

    swap_against_the_child(c, &venue, &later[0], &mut charges, claimed, budget);

    protocol_resource.assert_settles_within(c, &charges, budget, "swaps across the callers' cut");
    units.assert_settles_within(
        c,
        &Charges::default(),
        budget,
        "swaps across the callers' cut",
    );
}

/// A swap issued on a splitting shard reaches its venue, and the child
/// that takes the caller's prefix holds what came back.
///
/// # Panics
///
/// Panics as [`departing_callers`] and [`swaps_across_the_callers_cut`]
/// do.
pub fn a_leg_issued_on_a_departing_shard_reaches_its_venue(c: &mut impl Cluster, budget: Budget) {
    let set = departing_callers(c, STRADDLER_SURVIVOR, STRADDLER_SPLITTER);
    swaps_across_the_callers_cut(c, set, |c| await_cut(c, STRADDLER_SPLITTER), budget);
}

/// An answer outlives its producer's split and ends at the read
/// frontier the producer's lineage carries across it.
///
/// A caller on the splitting shard swaps against a venue that stays.
/// Once the venue has taken the input, every pushed reading and every
/// proof asked is cut, so the caller never reads the venue's `Taken`
/// and its escrowed record stands across the cut, now under the child
/// that inherits the caller's prefix. The swap's delivery back is owed
/// to that child in turn. When the cut lifts, the child reads the
/// `Taken` and retires the record, the venue reads the record absent at
/// the child, which its frontier holds as the splitter's lineage, and
/// deletes the `Taken`; the delivery ends the same way in the other
/// direction. Reports the fenced claims and claims weight the run
/// carried.
///
/// # Panics
///
/// Panics as [`departing_callers`] does, if the venue does not take the
/// input, if the record or its answer does not stand across the cut, if
/// the cuts never fired, if any record or answer of the swap stands once
/// they lift, or if either resource is not conserved with nothing
/// locked.
pub fn answers_end_at_the_read_frontier_across_a_reshape<C: FaultableCluster>(
    c: &mut C,
    budget: Budget,
) {
    let mut set = departing_callers(c, STRADDLER_SURVIVOR, STRADDLER_SPLITTER);
    let (venue_hosts, caller_hosts) =
        committees_on_separate_hosts(c, STRADDLER_SURVIVOR, STRADDLER_SPLITTER);
    let unheard = [
        c.drop_type_between(&venue_hosts, &caller_hosts, "crossing.readings"),
        c.drop_type_between(&caller_hosts, &venue_hosts, "state_proof.request"),
    ];
    let mut charges = Charges::default();
    let (key, caller) = &set.swappers[0];
    let swap = build_swap_tx(
        key,
        *caller,
        &set.venue.meta,
        *PROTOCOL_RESOURCE,
        SWAP_INPUT,
        0,
        validity_around(c.now()),
    );
    let crossings = crossing_cells(c, &swap);
    let input = *crossings
        .iter()
        .find(|crossing| owning_shard(c, crossing.record.owner) == STRADDLER_SPLITTER)
        .expect("a swap's input crosses from its caller");
    charges.submit(c, swap);
    set.protocol_resource.owing(charges.records(c));
    set.units.owing(charges.records(c));

    assert!(
        c.run_until(budget, |c| stands_at(c, input.taken)),
        "the venue must take the caller's input",
    );
    assert!(
        c.serves_shard(STRADDLER_SPLITTER) && !anchor_seeded(c, STRADDLER_SPLITTER.children().0),
        "the venue takes the input while the caller's shard still runs",
    );
    assert!(
        stands_at(c, input.record),
        "the caller never reads the venue's answer",
    );
    // The children seat on hosts of their own: nothing is heard across
    // the cut until it lands.
    c.drop_type("crossing.readings");
    c.drop_type("state_proof.request");
    await_cut(c, STRADDLER_SPLITTER);
    assert!(
        stands_at(c, input.record) && stands_at(c, input.taken),
        "the record and its answer stand across the producer's cut",
    );
    assert!(
        unheard.iter().all(|cut| cut.fired() > 0),
        "the venue's readings and the caller's asks must actually have been cut",
    );
    c.clear_drops();

    await_crossings_end(
        c,
        &crossings,
        budget,
        "the swap's crossings end across the cut",
    );
    set.settle_with_nothing_locked(c, &charges, budget, "answers across a producer's split");
    report_crossing_measures(c, "answers_end_at_the_read_frontier_across_a_reshape");
}

/// An abandonment's `Never` for a record its producer never writes goes
/// on the producer member's exit, read at one anchor.
///
/// A caller on the splitter swaps against a venue on the survivor, each
/// committee on hosts of its own. The caller's execution votes are cut
/// among its own committee, so its leg commits and never finalizes: the
/// escrowed record it would write is never written, and the splitter
/// aborts the leg before it ends. The venue waits on its input to the deadline
/// and its abandonment writes an unseen `Never`. No record presence can
/// ever mark it seen, and its record's absence alone deletes no unseen
/// answer; what ends it is the exit proof, read at one anchor of the
/// child holding the caller's prefix: the leg's member row absent, and
/// the committed marker present or the anchor past the swap's validity
/// end. The caller is charged the abort and keeps its input, and both
/// worlds are conserved with nothing locked.
///
/// # Panics
///
/// Panics as [`departing_callers`] does, if the two committees share a
/// host, if the splitter does not abort the leg or a child holds its
/// row, if the record is ever
/// written, if the venue does not abandon with a `Never` or the `Never`
/// outlives the budget, if the votes were never cut, if the caller is
/// not charged the abort alone, or if either world is not conserved.
pub fn an_unseen_never_goes_when_its_producer_aborts<C: FaultableCluster>(
    c: &mut C,
    budget: Budget,
) {
    let (venue_shard, caller_shard) = (STRADDLER_SURVIVOR, STRADDLER_SPLITTER);
    let mut set = departing_callers(c, venue_shard, caller_shard);
    let cut = scheduled_cut(c, caller_shard, budget);
    assert!(
        clock(c) < cut,
        "the swap goes while the callers' shard still runs"
    );
    let (leg_hosts, _) = committees_on_separate_hosts(c, caller_shard, venue_shard);
    let mut charges = Charges::default();
    let (key, caller) = &set.swappers[0];
    let swap = build_swap_tx(
        key,
        *caller,
        &set.venue.meta,
        *PROTOCOL_RESOURCE,
        SWAP_INPUT,
        0,
        validity_around(c.now()),
    );
    let input = crossing_cells(c, &swap)
        .into_iter()
        .find(|crossing| owning_shard(c, crossing.record.owner) == caller_shard)
        .expect("a swap's input crosses from its caller");
    let funded = held(c, caller.address(), *PROTOCOL_RESOURCE);
    let price = declared_price(c, &swap);
    let held_leg = c.drop_type_between(&leg_hosts, &leg_hosts, "execution.vote");
    let hash = charges.submit(c, swap);
    set.protocol_resource.owing(charges.records(c));

    let written = Cell::new(false);
    let watch = |c: &C| written.set(written.get() || stands_at(c, input.record));
    assert!(
        c.run_until(budget, |c| {
            watch(c);
            stands_at(c, input.never)
        }),
        "the venue must abandon the swap with a Never",
    );
    assert!(
        c.run_until(budget, |c| {
            watch(c);
            !stands_at(c, input.never)
        }),
        "the Never must go on its producer member's exit",
    );
    let children: [ShardId; 2] = caller_shard.children().into();
    assert_fated_off(c, caller_shard, hash, &children);
    assert!(!written.get(), "the record is never written");
    assert!(
        held_leg.fired() > 0,
        "the leg's votes must actually have been cut"
    );
    c.clear_drops();

    set.settle_with_nothing_locked(c, &charges, budget, "a Never its producer's exit ends");
    assert_eq!(
        held(c, caller.address(), *PROTOCOL_RESOURCE),
        funded - price,
        "the caller keeps its input and pays the abort",
    );
}

/// A swap issued on a merging shard reaches its venue, and the parent the
/// pair collapses into holds what came back.
///
/// [`a_leg_issued_on_a_departing_shard_reaches_its_venue`] across the
/// other reshape: the callers sit on the merge-left child, which the
/// grown topology's byte skew pairs with its sibling from the grow alone,
/// and the venue on a surviving quarter. Requires the
/// [`merging_caller_genesis_accounts`] funding on a config grown to four
/// shards.
///
/// # Panics
///
/// Panics as [`merging_callers`] and [`swaps_across_the_callers_cut`] do,
/// and if the merged parent is not served within budget.
pub fn a_leg_issued_on_a_merging_shard_reaches_its_venue<C: Cluster>(c: &mut C, budget: Budget) {
    let parent = MERGE_STRADDLER_LEFT
        .parent()
        .expect("a depth-2 leaf has a parent");
    let set = merging_callers(c);
    swaps_across_the_callers_cut(
        c,
        set,
        |c| {
            assert!(
                await_serves(c, parent, epochs(28)),
                "the merged parent must be served within budget",
            );
            // The parent's id is the one the grow split, so a host still
            // holding that frozen chain serves it before the merge lands:
            // the merge has run once the parent commits past both terminals.
            let (left, right) = parent.children();
            let merged = |c: &C| {
                terminal_height(c, left)
                    .zip(terminal_height(c, right))
                    .zip(c.committed_height(parent))
                    .is_some_and(|((left, right), tip)| tip > left.max(right))
            };
            assert!(
                c.run_until(epochs(28), merged),
                "the merged parent must commit past both children's terminals; terminals {:?} \
                 and {:?}, tip {:?}",
                terminal_height(c, left),
                terminal_height(c, right),
                c.committed_height(parent),
            );
        },
        budget,
    );
}

/// A departing venue's terminal cuts a stream of swaps in two, and both
/// halves settle: what it took it settles, and the rest its successor
/// runs.
///
/// The core-side cell the leg-local design leaves open. A single-shard
/// core waits on no counterpart certificate — the leg settles alone and
/// the core claims the crossing it delivered — so the only way a
/// departing core leaves a swap unsettled is by never including it. That
/// makes the shard's terminal the whole question: a swap on one side of
/// it is settled by the venue, and a swap on the other is settled by the
/// child that takes the venue's prefix, which runs the core the venue
/// never ran. Nothing falls between the two.
///
/// # Panics
///
/// Panics as [`departing_callers`] does, and if the venue's gate never
/// drains, if the terminal does not fall inside the stream, if any swap
/// fails to accept, if an un-included swap is settled by anything but the
/// child holding the venue's prefix, if a caller does not bank its
/// output, if the reserve does not hold every input, or if either side of
/// the pair is not conserved.
pub fn a_departing_venues_terminal_hands_on_what_it_never_took<C: Cluster>(
    c: &mut C,
    budget: Budget,
) {
    let (venue_shard, caller_shard) = (STRADDLER_SPLITTER, STRADDLER_SURVIVOR);
    let set = departing_callers(c, venue_shard, caller_shard);
    let mut charges = Charges::default();

    // From the drain the venue includes for a while, then coasts on empty
    // blocks until its children take over — so a stream spaced across the
    // coast lands on both sides of its terminal. A swap sent once the
    // children serve is handed on by routing alone, so the stream stops
    // spacing itself out there and the rest go at once.
    assert!(
        c.run_until(budget, |c| !split_admitted(c, venue_shard)),
        "the venue's reshape gate must drain before the stream goes",
    );
    let (left, right) = venue_shard.children();
    let mut stream: Vec<(TxHash, PrincipalAddr)> = Vec::new();
    for (key, caller) in &set.swappers {
        let swap = build_swap_tx(
            key,
            *caller,
            &set.venue.meta,
            *PROTOCOL_RESOURCE,
            SWAP_INPUT,
            0,
            validity_around(c.now()),
        );
        stream.push((charges.submit(c, swap), *caller));
        let _ = c.run_until(epochs(1), |c| c.serves_shard(left) && c.serves_shard(right));
    }
    await_cut(c, venue_shard);

    let mut took = 0;
    let mut handed_on = 0;
    for (hash, caller) in &stream {
        let status = await_tx_terminal(c, *hash, budget);
        assert!(
            matches!(
                status,
                Some(TransactionStatus::Completed(TransactionDecision::Accept))
            ),
            "every swap across the venue's terminal must settle; status = {status:?}",
        );
        let settled_by = |c: &C, shard| {
            c.chain_fate(shard, *hash)
                .1
                .is_some_and(|(_, decision)| decision == TransactionDecision::Accept)
        };
        if c.chain_fate(venue_shard, *hash).0.is_some() {
            assert!(
                settled_by(c, venue_shard),
                "a swap the venue included before its terminal must be settled there",
            );
            took += 1;
        } else {
            // Exactly one child holds the venue's prefix, and it is the
            // one that runs the core the venue never ran.
            assert!(
                settled_by(c, left) != settled_by(c, right),
                "an un-included swap must be settled by the one child holding the venue's \
                 prefix, not by both and not by neither",
            );
            handed_on += 1;
        }
        assert!(
            c.run_until(budget, |c| held(c, caller.address(), set.venue.unit) > 0),
            "every caller must bank the output of a swap that settled",
        );
    }
    assert!(
        took > 0 && handed_on > 0,
        "the venue's terminal has to fall inside the stream, or nothing here crosses it: \
         {took} taken against {handed_on} handed on",
    );

    let claimed = set.stocked + SWAP_INPUT * u128::try_from(stream.len()).expect("a few swaps");
    assert!(
        c.run_until(budget, |c| held_at(c, set.reserve) == claimed),
        "the venue and its successor between them must claim every input: reserve {} against \
         {claimed}",
        held_at(c, set.reserve),
    );
    set.protocol_resource.assert_settles_within(
        c,
        &charges,
        budget,
        "swaps across the venue's terminal",
    );
    set.units.assert_settles_within(
        c,
        &Charges::default(),
        budget,
        "swaps across the venue's terminal",
    );
}

/// A swap the departing venue included but could not run is fated at
/// its terminal, and its caller's input comes home once.
///
/// The venue sits on the splitter and its callers on the survivor. Every
/// crossing reading the survivor pushes is dropped, and so is every
/// proof the venue could ask for in its place, so a swap the venue
/// includes stands as a member waiting on its input. The venue coasts
/// from its drain on blocks that name no line, so nothing ends the
/// member before its terminal, which fates it: an abort committed in the
/// terminal's own manifest, with the member's floor charge burned there.
/// No child reads the member's row as its own. Once the cut lifts, the
/// survivor reads the venue's settled set without the swap, names it in
/// an abandonment record, and the escrowed input comes back to the
/// caller exactly once; both worlds are conserved with nothing locked.
/// A second swap's fee is paid by a sponsor on the venue's shard, so its
/// hold stands under the venue's member: the terminal burns the charge
/// beside the fate and releases the hold, and none reaches a child.
///
/// # Panics
///
/// Panics as [`departing_callers`] does, and if the venue's and the
/// callers' committees share a host, if the venue does not
/// include both swaps before its terminal, if the sponsor's hold does
/// not stand while the venue holds its swap, if the terminal does not
/// fate both, if a child holds a row or the hold, if the readings were
/// never cut, if an input does not come home once or the sponsor is not
/// charged once, or if either world is not conserved.
pub fn a_departing_venues_terminal_fates_what_it_could_not_run<C: FaultableCluster>(
    c: &mut C,
    budget: Budget,
) {
    let (venue_shard, caller_shard) = (STRADDLER_SPLITTER, STRADDLER_SURVIVOR);
    let (set, cut) = callers_against_a_scheduled_cut(c, venue_shard, caller_shard, budget);
    let mut charges = Charges::default();
    let (key, caller) = &set.swappers[0];
    let window = await_fated_window(c, cut, budget);

    committees_on_separate_hosts(c, venue_shard, caller_shard);
    let held_back = [
        c.drop_type("crossing.readings"),
        c.drop_type("state_proof.request"),
        c.drop_type("remote_header.request"),
    ];
    let funded = held(c, caller.address(), *PROTOCOL_RESOURCE);
    let swap = build_swap_tx(
        key,
        *caller,
        &set.venue.meta,
        *PROTOCOL_RESOURCE,
        SWAP_INPUT,
        0,
        window,
    );
    let price = declared_price(c, &swap);
    let hash = charges.submit(c, swap);
    let sponsored = Sponsored::submit(c, &set, 1, &mut charges, window);
    assert!(
        c.run_until(budget, |c| [hash, sponsored.hash]
            .iter()
            .all(|hash| c.chain_fate(venue_shard, *hash).0.is_some())),
        "the venue must include both swaps before its terminal",
    );
    sponsored.assert_held(c);
    await_cut(c, venue_shard);

    let children: [ShardId; 2] = venue_shard.children().into();
    let terminal = terminal_height(c, venue_shard);
    for hash in [hash, sponsored.hash] {
        assert_eq!(
            Some(assert_fated_off(c, venue_shard, hash, &children)),
            terminal,
            "the venue's terminal must fate each swap it held",
        );
    }
    assert!(
        held_back.iter().any(|handle| handle.fired() > 0),
        "the readings must actually have been cut, or the venue ran the swap",
    );
    c.clear_drops();

    let home = funded - price;
    assert!(
        c.run_until(budget, |c| held(c, caller.address(), *PROTOCOL_RESOURCE)
            == home),
        "the caller's input must come home, less the price: holds {} against {home}",
        held(c, caller.address(), *PROTOCOL_RESOURCE),
    );
    let locked = set.protocol_resource.assert_settles_within(
        c,
        &charges,
        budget,
        "a swap fated at the venue's terminal",
    );
    assert!(locked.is_empty(), "nothing stays locked: {locked:?}");
    set.units.assert_settles_within(
        c,
        &Charges::default(),
        budget,
        "a swap fated at the venue's terminal",
    );
    assert_eq!(
        held(c, caller.address(), *PROTOCOL_RESOURCE),
        home,
        "the input comes home once",
    );
    sponsored.assert_released_at_the_terminal(c, set.sponsor.1);
}

/// A crossing whose consumer is fated at its terminal, when producer and
/// consumer merge into one parent, is declined by the parent and taken
/// back.
///
/// The venue sits on the merging right quarter and its callers on the
/// left, so the swap's leg issues an escrowed record on the pair that is
/// leaving and the core that would take it leaves beside it. The leg's
/// readings to the venue are cut, so the venue includes the swap and
/// holds it as a member waiting on its input until its terminal fates
/// it. The two chains end together, so neither ever holds the other's
/// attested settled set: no abandonment record names the swap, and the
/// merged parent holds the record escrowed with both its ends. Past the
/// swap's validity end the parent reads the record at its own parent
/// with the swap's member row absent, its fold writes the `Never`, and
/// the input is taken back on it. The resource is conserved with
/// nothing locked. The second swap's fee is paid by a
/// sponsor on the venue's shard: its hold stands under the venue's
/// member until the terminal burns the charge, and none reaches the
/// merged parent.
///
/// # Panics
///
/// Panics if a quarter is unserved, if the venue misses its budget
/// standing up, if the two committees share a host, if the merge is
/// never scheduled or the venue does not
/// include both swaps before it, if the sponsor's hold does not stand
/// meanwhile, if either swap is not fated, if any record names one, if
/// the input does not come home or the venue is credited it, if the
/// sponsor is not charged once or its hold reaches the parent, or if
/// the resource is not conserved with nothing locked.
pub fn a_merged_pair_returns_a_crossing_its_consumer_never_took<C: FaultableCluster>(
    c: &mut C,
    budget: Budget,
) {
    let (venue_shard, caller_shard) = (MERGE_STRADDLER_RIGHT, MERGE_STRADDLER_LEFT);
    let parent = venue_shard.parent().expect("a depth-2 leaf has a parent");
    assert!(
        (0..4).all(|path| await_serves(c, ShardId::leaf(2, path), epochs(4))),
        "the grown four-shard topology must seat every quarter",
    );
    let mut set = stock_callers_against(c, venue_shard, caller_shard);
    let cut = scheduled_cut(c, parent, budget);
    let window = await_fated_window(c, cut, budget);

    let mut charges = Charges::default();
    let (key, caller) = &set.swappers[0];
    committees_on_separate_hosts(c, venue_shard, caller_shard);
    let held_back = [
        c.drop_type("crossing.readings"),
        c.drop_type("state_proof.request"),
        c.drop_type("remote_header.request"),
    ];
    let funded = held(c, caller.address(), *PROTOCOL_RESOURCE);
    let swap = build_swap_tx(
        key,
        *caller,
        &set.venue.meta,
        *PROTOCOL_RESOURCE,
        SWAP_INPUT,
        0,
        window,
    );
    let price = declared_price(c, &swap);
    let hash = charges.submit(c, swap);
    let sponsored = Sponsored::submit(c, &set, 1, &mut charges, window);
    set.protocol_resource.owing(charges.records(c));
    assert!(
        c.run_until(budget, |c| [hash, sponsored.hash]
            .iter()
            .all(|hash| c.chain_fate(venue_shard, *hash).0.is_some())),
        "the venue must include both swaps before its terminal",
    );
    sponsored.assert_held(c);
    assert!(
        await_serves(c, parent, budget) && await_anchor_seeded(c, parent, budget),
        "the merged parent must serve on its seeded anchor within budget",
    );
    for hash in [hash, sponsored.hash] {
        let fate = c.chain_fate(venue_shard, hash).1;
        assert!(
            matches!(fate, Some((_, TransactionDecision::Aborted))),
            "the venue's terminal must fate each swap it held; fate = {fate:?}",
        );
    }
    assert!(
        held_back.iter().any(|handle| handle.fired() > 0),
        "the readings must actually have been cut, or the venue ran the swap",
    );
    c.clear_drops();

    let home = funded - price;
    assert!(
        c.run_until(budget, |c| charges
            .records(c)
            .iter()
            .all(|record| !stands_at(c, *record))),
        "the merged parent must decline each swap's record and take its input back",
    );
    let locked = set.protocol_resource.assert_settles_within(
        c,
        &charges,
        budget,
        "a crossing its merged consumer never took",
    );
    for shard in [caller_shard, parent] {
        assert!(
            c.named_unsettled(shard, hash).is_empty(),
            "no record may name the swap, the two chains having ended together; \
             {shard:?} names {:?}",
            c.named_unsettled(shard, hash),
        );
    }
    assert_eq!(
        held(c, caller.address(), *PROTOCOL_RESOURCE),
        home,
        "the input comes home once",
    );
    assert_eq!(
        held_at(c, set.reserve),
        set.stocked,
        "the venue never took the input",
    );
    assert!(locked.is_empty(), "nothing stays locked: {locked:?}");
    set.units.assert_settles_within(
        c,
        &Charges::default(),
        budget,
        "a crossing its merged consumer never took",
    );
    sponsored.assert_released_at_the_terminal(c, set.sponsor.1);
}

/// Crossings whose two ends a merge brings together finish on the
/// successor, off readings it takes at its own parent.
///
/// The venue sits on the merging right quarter and its callers on the
/// left, each committee on hosts of its own. Every reading the venue
/// pushes to the callers' hosts, and every proof the callers ask of it,
/// is cut for the whole run. The venue takes one swap's input and
/// refuses another's, so a `Taken` and a `Never` stand that their
/// producer never reads, and the first swap's delivery back is never
/// read either. The pair merges with every record standing. The merged
/// parent holds both ends of each crossing and reads them at its own
/// parent: it retires the taken record, reclaims the refused one to its
/// caller and credits the delivery, and each answer goes once its record
/// reads absent. The cuts stay in place throughout, so nothing but the
/// successor's own readings finishes them. Reports the fenced claims and
/// claims weight the run carried.
///
/// # Panics
///
/// Panics if a quarter is unserved, if the two committees share a host,
/// if the answers do not stand before the merge or a record does not
/// stand with its answer, if the merged parent is not served or leaves a
/// record or answer standing, if the cuts never fired, if the refused
/// swap's input does not come home once, or if either resource is not
/// conserved with nothing locked.
pub fn a_crossing_a_merge_converges_finishes_on_the_successor<C: FaultableCluster>(
    c: &mut C,
    budget: Budget,
) {
    let (venue_shard, caller_shard) = (MERGE_STRADDLER_RIGHT, MERGE_STRADDLER_LEFT);
    let parent = venue_shard.parent().expect("a depth-2 leaf has a parent");
    assert!(
        (0..4).all(|path| await_serves(c, ShardId::leaf(2, path), epochs(4))),
        "the grown four-shard topology must seat every quarter",
    );
    let mut set = stock_callers_against(c, venue_shard, caller_shard);
    let (venue_hosts, caller_hosts) = committees_on_separate_hosts(c, venue_shard, caller_shard);
    let cuts = [
        c.drop_type_between(&venue_hosts, &caller_hosts, "crossing.readings"),
        c.drop_type_between(&caller_hosts, &venue_hosts, "state_proof.request"),
    ];

    let mut charges = Charges::default();
    let window = validity_around(c.now());
    let (taking_key, taking) = &set.swappers[0];
    let (refused_key, refused) = &set.swappers[1];
    let taken_swap = build_swap_tx(
        taking_key,
        *taking,
        &set.venue.meta,
        *PROTOCOL_RESOURCE,
        SWAP_INPUT,
        0,
        window,
    );
    let refused_swap = build_swap_tx(
        refused_key,
        *refused,
        &set.venue.meta,
        *PROTOCOL_RESOURCE,
        SWAP_INPUT,
        SWAP_INPUT * 100,
        window,
    );
    let input = |c: &C, swap: &Transaction| {
        crossing_cells(c, swap)
            .into_iter()
            .find(|crossing| owning_shard(c, crossing.record.owner) == caller_shard)
            .expect("a swap's input crosses from its caller")
    };
    let (taken, refusal) = (input(c, &taken_swap), input(c, &refused_swap));
    let funded = held(c, refused.address(), *PROTOCOL_RESOURCE);
    let refused_price = declared_price(c, &refused_swap);
    charges.submit(c, taken_swap);
    charges.submit(c, refused_swap);
    set.protocol_resource.owing(charges.records(c));
    set.units.owing(charges.records(c));
    let crossings = charges.crossings(c);

    assert!(
        c.run_until(budget, |c| stands_at(c, taken.taken)
            && stands_at(c, refusal.never)),
        "the venue must take one input and refuse the other before the merge",
    );
    assert!(
        !merge_executed(c, parent),
        "both answers must stand before the pair merges",
    );
    assert!(
        stands_at(c, taken.record) && stands_at(c, refusal.record),
        "neither producer reads its answer while the venue's readings are cut",
    );
    assert!(
        c.run_until(budget, |c| merge_executed(c, parent)),
        "the pair must merge within budget",
    );
    assert!(
        [taken.record, taken.taken, refusal.record, refusal.never]
            .into_iter()
            .all(|cell| stands_at(c, cell)),
        "every record and answer stands on the pair as it merges",
    );
    assert!(
        await_serves(c, parent, budget) && await_anchor_seeded(c, parent, budget),
        "the merged parent must serve on its seeded anchor within budget",
    );
    await_crossings_end(
        c,
        &crossings,
        budget,
        "the successor finishes every crossing",
    );
    assert!(
        cuts.iter().all(|cut| cut.fired() > 0),
        "the venue's readings and the callers' asks must actually have been cut",
    );
    c.clear_drops();

    set.settle_with_nothing_locked(c, &charges, budget, "crossings a merge converged");
    assert_eq!(
        held(c, refused.address(), *PROTOCOL_RESOURCE),
        funded - refused_price,
        "the refused swap's input comes home once, less its price",
    );
    report_crossing_measures(c, "a_crossing_a_merge_converges_finishes_on_the_successor");
}

/// Assert that `venue`'s chain aborted `hash` and that none of its
/// `successors` reads the transaction's member row as its own, returning
/// the height the abort committed at.
///
/// # Panics
///
/// Panics if the chain holds no abort of `hash`, or a successor holds its
/// row.
fn assert_fated_off<C: Cluster>(
    c: &C,
    venue: ShardId,
    hash: TxHash,
    successors: &[ShardId],
) -> BlockHeight {
    let fate = c.chain_fate(venue, hash).1;
    let Some((at, TransactionDecision::Aborted)) = fate else {
        panic!("{venue:?} must abort the transaction it held; fate = {fate:?}");
    };
    for successor in successors {
        assert!(
            c.member_rows(*successor)
                .is_none_or(|rows| !rows.contains_key(&hash)),
            "{successor:?} reads {venue:?}'s fated row as its own",
        );
    }
    at
}

/// When `shard`'s scheduled reshape cuts it: the end of its terminal
/// epoch's window.
///
/// # Panics
///
/// Panics if the beacon schedules no reshape of `shard` within `budget`.
fn scheduled_cut<C: Cluster>(c: &mut C, shard: ShardId, budget: Budget) -> WeightedTimestamp {
    assert!(
        c.run_until(budget, |c| scheduled_terminal_epoch(c, shard).is_some()),
        "the beacon must schedule {shard:?}'s reshape",
    );
    let terminal = scheduled_terminal_epoch(c, shard).expect("scheduled above");
    let epoch_ms = epoch_duration_ms(c).expect("the beacon carries its epoch length");
    EpochWindows::new(epoch_ms).window_of(terminal).end
}

/// A window closing past `cut`, so no deadline ends a member before the
/// terminal does, waited for until it opens, while the venue still
/// includes.
///
/// # Panics
///
/// Panics if the window does not open within `budget`.
fn await_fated_window<C: Cluster>(
    c: &mut C,
    cut: WeightedTimestamp,
    budget: Budget,
) -> TimestampRange {
    let window = TimestampRange::new(
        cut.minus(FATED_OPENS_BEFORE_THE_CUT),
        cut.plus(FATED_CLOSES_AFTER_THE_CUT),
    );
    assert!(
        c.run_until(budget, |c| clock(c) >= window.start_timestamp_inclusive),
        "the swap's window must open before the cut",
    );
    window
}

/// A swap a sponsor on the venue's own shard pays for, so its fee hold
/// stands under the venue's member of it.
struct Sponsored {
    hash: TxHash,
    hold: SubstateKey,
    total: SubstateKey,
    funded: u128,
    price: u128,
}

impl Sponsored {
    /// Submit a swap by `set`'s caller `index` in `window`, its fee paid
    /// by `set`'s sponsor.
    fn submit<C: Cluster>(
        c: &mut C,
        set: &DepartingCallers,
        index: usize,
        charges: &mut Charges,
        window: TimestampRange,
    ) -> Self {
        let (key, caller) = &set.swappers[index];
        let (sponsor_key, sponsor) = &set.sponsor;
        let swap = build_sponsored_swap_tx(
            sponsor_key,
            key,
            *caller,
            &set.venue.meta,
            SWAP_INPUT,
            0,
            window,
        );
        let price = declared_price(c, &swap);
        let fee = FeeTerms::of(&swap);
        let funded = held(c, sponsor.address(), *PROTOCOL_RESOURCE);
        let hash = charges.submit(c, swap);
        Self {
            hash,
            hold: fee.hold_key(),
            total: fee_hold_total_key(&ProtocolHasher, fee.vault),
            funded,
            price,
        }
    }

    /// Assert the hold stands under the venue while it holds the swap.
    fn assert_held<C: Cluster>(&self, c: &C) {
        assert!(
            stands_at(c, self.hold) && stands_at(c, self.total),
            "the sponsor's hold and its total stand while the venue holds the swap",
        );
    }

    /// Assert the terminal burned the sponsor's charge once and no hold or
    /// total reached the successor.
    fn assert_released_at_the_terminal<C: Cluster>(&self, c: &C, sponsor: PrincipalAddr) {
        assert!(
            !stands_at(c, self.hold) && !stands_at(c, self.total),
            "no fee hold crosses the cut",
        );
        assert_eq!(
            held(c, sponsor.address(), *PROTOCOL_RESOURCE),
            self.funded - self.price,
            "the terminal burns the sponsor's charge once",
        );
    }
}

/// How far before the venue's cut the fated swap's window opens, and how
/// far past it the window closes: together one validity range less a
/// margin, so the venue can include it before it coasts and its deadline
/// falls after the terminal.
const FATED_OPENS_BEFORE_THE_CUT: Duration = Duration::from_secs(110);
const FATED_CLOSES_AFTER_THE_CUT: Duration = Duration::from_secs(10);

/// How far before the venue's cut the post-cut swap's window opens, and
/// how far past it the window closes: together one validity range less
/// a margin, so the swap is admissible on the caller's shard after the
/// cut while its window opened before it.
const OPENS_BEFORE_THE_CUT: Duration = Duration::from_secs(10);
const CLOSES_AFTER_THE_CUT: Duration = Duration::from_secs(110);

/// The latest the post-cut swap may go and still leave the child that
/// holds the venue's prefix room to include it before its window
/// closes.
const LATEST_SUBMISSION_AFTER_THE_CUT: Duration = Duration::from_secs(70);

/// How long past the children's anchor the caller's shard is given to
/// fetch the departed venue's settled set and write a record from it:
/// the set is wanted on the first beacon fold that attests the terminal
/// and a record is offered at the next proposal.
const SETTLED_SET_SLACK: Duration = Duration::from_secs(60);

/// Stand the venue up on the departing shard with its callers on the
/// survivor, and read the cut its reshape is scheduled for.
///
/// The cut is an epoch boundary the beacon fixes ahead of time, which is
/// what lets a transaction be built to straddle it.
///
/// # Panics
///
/// Panics as [`departing_callers`] does, and if the beacon never
/// schedules the cut, or schedules it too near for a window to open
/// before it.
fn callers_against_a_scheduled_cut<C: Cluster>(
    c: &mut C,
    venue_shard: ShardId,
    caller_shard: ShardId,
    budget: Budget,
) -> (DepartingCallers, WeightedTimestamp) {
    let set = departing_callers(c, venue_shard, caller_shard);
    let cut = scheduled_cut(c, venue_shard, budget);
    assert!(
        clock(c) < cut.minus(OPENS_BEFORE_THE_CUT),
        "the cut must still be ahead when the swap's window opens; now {:?}, cut {cut:?}",
        clock(c),
    );
    (set, cut)
}

/// A swap committed after the venue's cut is disposed of exactly once.
///
/// Its window opened before the cut and its commit fell after it, so
/// the child holding the venue's prefix claims the input — and no
/// record of the departed venue may name it, since naming it would
/// hand that same input back.
///
/// The venue sits on the splitter and the caller on the survivor. The
/// cut is an epoch boundary the beacon schedules ahead of time, so the
/// swap is built against it: its window opens before the cut and closes
/// after, and it goes once the cut has landed. The caller's shard
/// commits it against a trie in which the venue's prefix is the child's,
/// the leg pays, the crossing reaches the child, and the child runs the
/// core and claims the input. The departed venue never held the swap,
/// so its settled set cannot name it — and a record reading that
/// absence as the venue leaving the swap unsettled would license the
/// leg to take back a crossing the child holds.
///
/// The record is only ever composed once the beacon attests the
/// venue's terminal, an epoch fold after the cut, by which time a swap
/// the child settled has ordinarily been read back and retired. What
/// the fault holds open is that window: once the child has claimed, the
/// state proofs and remote headers a claim is read through are cut, so
/// the leg entry still stands when the settled set arrives and a record
/// naming it would be honoured.
///
/// # Panics
///
/// Panics as [`departing_callers`] does, and if the beacon never
/// schedules the cut, if the caller's shard does not commit the swap
/// after the cut, if the child does not claim the input, if a record
/// on the caller's shard names the swap, if the input comes back to the
/// caller once the cut lifts, or if either side of the pair is not
/// conserved.
pub fn a_swap_committed_after_the_venues_cut_is_disposed_once<C: FaultableCluster>(c: &mut C) {
    let (venue_shard, caller_shard) = (STRADDLER_SPLITTER, STRADDLER_SURVIVOR);
    let budget = epochs(24);
    let (set, cut) = callers_against_a_scheduled_cut(c, venue_shard, caller_shard, budget);
    let mut charges = Charges::default();
    let (key, caller) = &set.swappers[0];
    let swap = build_swap_tx(
        key,
        *caller,
        &set.venue.meta,
        *PROTOCOL_RESOURCE,
        SWAP_INPUT,
        0,
        TimestampRange::new(
            cut.minus(OPENS_BEFORE_THE_CUT),
            cut.plus(CLOSES_AFTER_THE_CUT),
        ),
    );
    // The cut: both children seated, so the venue's prefix is a child's
    // and the swap can reach it.
    let (left, right) = venue_shard.children();
    assert!(
        c.run_until(budget, |c| c.serves_shard(left) && c.serves_shard(right)),
        "both splitter children must be served within budget",
    );
    assert!(
        clock(c) > cut && clock(c) <= cut.plus(LATEST_SUBMISSION_AFTER_THE_CUT),
        "the children must seat inside the swap's window; now {:?}, cut {cut:?}",
        clock(c),
    );

    let paid_before = held(c, caller.address(), *PROTOCOL_RESOURCE);
    let hash = charges.submit(c, swap);
    assert!(
        c.run_until(epochs(2), |c| c.chain_fate(caller_shard, hash).0.is_some()),
        "the caller's shard must commit the swap inside its window",
    );
    assert!(
        c.chain_fate(venue_shard, hash).0.is_none(),
        "the departed venue must never have seen the swap",
    );
    let claimed = set.stocked + SWAP_INPUT;
    let child_claimed = c.run_until(epochs(4), |c| held_at(c, set.reserve) == claimed);
    assert!(
        child_claimed,
        "the child holding the venue's prefix must claim the input: reserve {} against \
         {claimed}",
        held_at(c, set.reserve),
    );

    // The child holds the crossing. From here the caller's shard may not
    // read that it does: the claim cell sits on the child, and a proof of
    // it travels as a state proof against a header the caller fetches, so
    // cutting both leaves the leg entry standing where a record can still
    // speak for it. Cut by message class rather than between committees,
    // because a split child seats on a host its parent shared and a rule
    // keyed on hosts would cut that host's other shard with it — and
    // neither class carries anything a shard needs from itself.
    let held_back = [
        c.drop_type("state_proof.request"),
        c.drop_type("remote_header.request"),
    ];

    // The settled set lands: the beacon anchors the children on the fold
    // that attests the venue's terminal, and the caller's shard fetches
    // the set on reading it.
    assert!(
        c.run_until(budget, |c| anchor_seeded(c, left)),
        "the beacon must anchor the split children",
    );
    let landed = clock(c).plus(SETTLED_SET_SLACK);
    let _ = c.run_until(budget, |c| {
        clock(c) >= landed || !c.named_unsettled(caller_shard, hash).is_empty()
    });
    assert!(
        c.named_unsettled(caller_shard, hash).is_empty(),
        "no record of the departed venue may name a swap it never held; named by {:?}",
        c.named_unsettled(caller_shard, hash),
    );
    assert!(
        held_back.iter().any(|handle| handle.fired() > 0),
        "the claim must actually have been made unreadable, or the leg was read and \
         retired before any record could speak",
    );
    c.clear_drops();

    // The input is the child's, and stays so once the caller's shard can
    // read the claim: the leg retires, and nothing licenses it to take
    // the crossing back.
    set.protocol_resource.assert_settles_within(
        c,
        &charges,
        budget,
        "a swap committed after the venue's cut",
    );
    assert_eq!(
        held(c, caller.address(), *PROTOCOL_RESOURCE),
        paid_before - SWAP_INPUT - charges.burned(c),
        "the caller's input must not come back: the child claimed it",
    );
    set.units.assert_settles_within(
        c,
        &Charges::default(),
        budget,
        "a swap committed after the venue's cut",
    );
}

/// How many callers on the survivor pay for the load of
/// [`a_survivor_admits_after_a_reshape_under_saturated_cross_shard_load`].
const LOAD_CALLERS: usize = 8;

/// The most swaps the load offers: twice what the drain holds.
const LOAD_SWAPS: usize = 2 * MAX_UNSETTLED_PER_BLOCK;

/// How many swaps the load keeps offered and not yet committed on the
/// survivor: more than a block of them carries, so no block it builds
/// wants for one, and few enough that the backlog is not itself the
/// load on its proposers.
const LOAD_BACKLOG: usize = 1_024;

/// How far before the departing venue's cut the load starts, so the
/// survivor is committing it through its last blocks before the cut.
const LOAD_OPENS_BEFORE_THE_CUT: Duration = Duration::from_secs(30);

/// What the load's first swap pays in; each later one pays one quantum
/// more, so every swap is its own transaction.
const LOAD_INPUT: u128 = 1_000;

/// How often the load scenario reads the survivor's rows.
const LOAD_SAMPLE: Duration = Duration::from_secs(30);

/// The callers the load's swaps are paid by, on the survivor, ground
/// after every account [`venue_genesis_accounts_on`] grinds.
fn load_callers() -> Vec<(Ed25519PrivateKey, PrincipalAddr)> {
    let mut taken = Vec::new();
    let _ = grind_onto(STRADDLER_SPLITTER, &mut taken);
    let _ = swappers_on(&[STRADDLER_SURVIVOR], &mut taken);
    let _ = grind_onto(STRADDLER_SPLITTER, &mut taken);
    (0..LOAD_CALLERS)
        .map(|_| grind_onto(STRADDLER_SURVIVOR, &mut taken))
        .collect()
}

/// Genesis funding for
/// [`a_survivor_admits_after_a_reshape_under_saturated_cross_shard_load`]:
/// the departing venue's ballast and accounts, and the load's callers on
/// the survivor.
#[must_use]
pub fn saturated_reshape_genesis_accounts() -> Vec<(PrincipalAddr, u128)> {
    let mut accounts = departing_venue_ballast();
    accounts.extend(venue_genesis_accounts_on(
        STRADDLER_SPLITTER,
        &[STRADDLER_SURVIVOR],
    ));
    accounts.extend(
        load_callers()
            .into_iter()
            .map(|(_, account)| (account, SWAPPER_FUNDING)),
    );
    accounts
}

/// One reading of the survivor under the load.
#[derive(Clone, Copy)]
struct LoadSample {
    at: WeightedTimestamp,
    height: u64,
    /// The drain its tip's header carries: the member rows standing.
    standing: u64,
    pending: usize,
    in_flight: usize,
    released: usize,
}

impl LoadSample {
    fn read<C: Cluster>(c: &C, shard: ShardId) -> Self {
        let rows = c
            .member_rows(shard)
            .expect("the harness reads the survivor's member rows");
        let count = |wanted: fn(&RowState) -> bool| rows.values().filter(|row| wanted(row)).count();
        Self {
            at: clock(c),
            height: c.committed_height(shard).map_or(0, BlockHeight::inner),
            standing: c
                .committed_txs_in_flight(shard)
                .map_or(0, TxsInFlight::inner),
            pending: count(|row| matches!(row, RowState::Pending)),
            in_flight: count(|row| {
                matches!(row, RowState::InFlight { .. } | RowState::Stated { .. })
            }),
            released: count(|row| matches!(row, RowState::Released { .. })),
        }
    }
}

impl std::fmt::Display for LoadSample {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "at {:?} height {} standing {} (pending {}, in flight {}, released {})",
            self.at, self.height, self.standing, self.pending, self.in_flight, self.released,
        )
    }
}

/// Keep `sample`, printing it as it is read so a run that never ends
/// still leaves its readings.
fn record(samples: &mut Vec<LoadSample>, sample: LoadSample) {
    println!("saturated reshape: {sample}");
    samples.push(sample);
}

/// Drive until `done` or `until`, reading the survivor every
/// [`LOAD_SAMPLE`] into `samples`. Whether `done` held.
fn drive_sampling<C: Cluster>(
    c: &mut C,
    shard: ShardId,
    until: WeightedTimestamp,
    samples: &mut Vec<LoadSample>,
    done: impl Fn(&C) -> bool,
) -> bool {
    loop {
        if done(c) {
            record(samples, LoadSample::read(c, shard));
            return true;
        }
        if clock(c) >= until {
            return false;
        }
        let next = clock(c).plus(LOAD_SAMPLE);
        let _ = c.run_until(epochs(1), |c| {
            done(c) || clock(c) >= next || clock(c) >= until
        });
        record(samples, LoadSample::read(c, shard));
    }
}

/// Stand the venue up on the splitter, vote the splitter down, and
/// drive to the load's start, [`LOAD_OPENS_BEFORE_THE_CUT`] short of the
/// cut its split is scheduled for. The venue, two accounts on the
/// survivor that pay for nothing of the load, and the cut.
fn stand_the_load_up<C: Cluster>(
    c: &mut C,
) -> (
    StockedVenue,
    Vec<(Ed25519PrivateKey, PrincipalAddr)>,
    WeightedTimestamp,
) {
    let (venue_shard, survivor) = (STRADDLER_SPLITTER, STRADDLER_SURVIVOR);
    let budget = epochs(24);
    split_lifecycle(c);
    assert!(
        c.serves_shard(venue_shard) && c.serves_shard(survivor),
        "the grow must seat the venue's shard and its callers'",
    );
    let mut taken = Vec::new();
    let venue = stand_up_venue(c, venue_shard, &mut taken);
    let bystanders = swappers_on(&[survivor], &mut taken);
    vote_splitter_down_to(c, voted_split_bytes(&GenesisPackages::with_fixtures()));
    assert!(
        await_split_admitted(c, venue_shard, epochs(20)),
        "the splitter must admit the split",
    );
    assert!(!split_admitted(c, survivor), "the survivor must not split");
    let cut = scheduled_cut(c, venue_shard, budget);
    let opens = cut.minus(LOAD_OPENS_BEFORE_THE_CUT);
    assert!(
        clock(c) < opens,
        "the cut must still be ahead when the load starts; now {:?}, cut {cut:?}",
        clock(c),
    );
    assert!(
        c.run_until(budget, |c| clock(c) >= opens),
        "the load's start must come",
    );
    (venue, bystanders, cut)
}

/// Offer the load until `cut` or until [`LOAD_SWAPS`] have gone: each
/// time the survivor's height moves, the callers top up what they have
/// offered and it has not yet committed to [`LOAD_BACKLOG`]. A leg's row
/// stands across several readings, so every swap the survivor commits
/// is seen. Every swap offered, and the last window offered in.
fn offer_the_load<C: Cluster>(
    c: &mut C,
    venue: &StockedVenue,
    cut: WeightedTimestamp,
    samples: &mut Vec<LoadSample>,
) -> (BTreeMap<TxHash, Arc<Transaction>>, TimestampRange) {
    let survivor = STRADDLER_SURVIVOR;
    let callers = load_callers();
    let height = |c: &C| c.committed_height(survivor).map_or(0, BlockHeight::inner);
    let mut offered: BTreeMap<TxHash, Arc<Transaction>> = BTreeMap::new();
    let mut committed: BTreeSet<TxHash> = BTreeSet::new();
    let mut last_window = validity_around(c.now());
    while offered.len() < LOAD_SWAPS && clock(c) < cut {
        last_window = validity_around(c.now());
        committed.extend(
            c.member_rows(survivor)
                .expect("the harness reads the survivor's member rows")
                .into_keys(),
        );
        let waiting = offered.len() - committed.len().min(offered.len());
        let wanted = LOAD_BACKLOG.saturating_sub(waiting);
        for _ in 0..wanted.min(LOAD_SWAPS - offered.len()) {
            let (key, caller) = &callers[offered.len() % callers.len()];
            let input = LOAD_INPUT + u128::try_from(offered.len()).expect("a count of swaps");
            let swap = Arc::new(build_swap_tx(
                key,
                *caller,
                &venue.meta,
                *PROTOCOL_RESOURCE,
                input,
                0,
                last_window,
            ));
            c.submit(Arc::clone(&swap));
            offered.insert(swap.hash(), swap);
        }
        let from = height(c);
        let _ = c.run_until(epochs(1), |c| height(c) > from || clock(c) >= cut);
        record(samples, LoadSample::read(c, survivor));
    }
    (offered, last_window)
}

/// A leg of the load the venue's departure left waiting on the survivor.
struct StrandedLeg {
    tx: TxHash,
    payer: Address,
    /// The close of its own leg entry window, where its row is fated.
    lapse: WeightedTimestamp,
    hold: SubstateKey,
    total: SubstateKey,
    price: u128,
}

impl StrandedLeg {
    /// Every row of the survivor's still waiting, as the swap of `load`
    /// it is the leg of.
    ///
    /// # Panics
    ///
    /// Panics if the harness reads no member rows, or if a waiting row
    /// is no swap of the load.
    fn read<C: Cluster>(c: &C, load: &BTreeMap<TxHash, Arc<Transaction>>) -> Vec<Self> {
        c.member_rows(STRADDLER_SURVIVOR)
            .expect("the harness reads the survivor's member rows")
            .into_iter()
            .filter(|(_, row)| matches!(row, RowState::Pending))
            .map(|(tx, _)| {
                let swap = load.get(&tx).expect("a waiting row is a swap of the load");
                let fee = FeeTerms::of(swap);
                Self {
                    tx,
                    payer: swap.fee_payer(),
                    lapse: Window::LegEntry.of(Deadline::of_transaction(swap)).end,
                    hold: fee.hold_key(),
                    total: fee_hold_total_key(&ProtocolHasher, fee.vault),
                    price: declared_price(c, swap),
                }
            })
            .collect()
    }
}

/// How many of `mentions` name `tx`.
fn naming(mentions: &[(TxHash, BlockHeight)], tx: TxHash) -> usize {
    mentions.iter().filter(|(named, _)| *named == tx).count()
}

/// A transfer between two accounts on the survivor, offered to read
/// whether it admits.
struct Probe {
    tx: TxHash,
    offered: WeightedTimestamp,
    /// The first step that read it committed.
    committed: Option<WeightedTimestamp>,
}

/// What every step past the cut reads of the survivor: where each
/// stranded leg's row stands, which probes it has committed, and the
/// drain its tip's header carries.
struct Watch<'a> {
    stranded: &'a [StrandedLeg],
    /// Each leg read anywhere but waiting, or gone short of the close of
    /// its own leg entry window, with the first such reading.
    strays: RefCell<BTreeMap<TxHash, String>>,
    probes: RefCell<Vec<Probe>>,
    /// The highest drain read.
    peak: Cell<u64>,
}

impl<'a> Watch<'a> {
    fn over(stranded: &'a [StrandedLeg], samples: &[LoadSample]) -> Self {
        let peak = samples.iter().map(|sample| sample.standing).max();
        Self {
            stranded,
            strays: RefCell::new(BTreeMap::new()),
            probes: RefCell::new(Vec::new()),
            peak: Cell::new(peak.unwrap_or(0)),
        }
    }

    /// Offer a transfer from the first of `bystanders` to the second,
    /// afresh each time since one lapses with its validity window.
    fn offer<C: Cluster>(
        &self,
        c: &mut C,
        bystanders: &[(Ed25519PrivateKey, PrincipalAddr)],
        charges: &mut Charges,
    ) {
        let (key, from) = &bystanders[0];
        let to = bystanders[1].1;
        let amount = 1 + u128::try_from(self.probes.borrow().len()).expect("a count of transfers");
        let offered = clock(c);
        let transfer = build_transfer_tx(key, *from, to, amount, validity_around(c.now()));
        let tx = charges.submit(c, transfer);
        self.probes.borrow_mut().push(Probe {
            tx,
            offered,
            committed: None,
        });
    }

    /// Read the survivor at this step. How many stranded rows stand.
    fn read<C: Cluster>(&self, c: &C) -> usize {
        let now = clock(c);
        for (index, probe) in self.probes.borrow_mut().iter_mut().enumerate() {
            if probe.committed.is_some() {
                continue;
            }
            let committed = matches!(
                c.tx_status(probe.tx),
                Some(
                    TransactionStatus::Committed(_)
                        | TransactionStatus::LegFinalized
                        | TransactionStatus::Completed(
                            TransactionDecision::Accept | TransactionDecision::Reject
                        )
                )
            );
            if committed {
                println!(
                    "saturated reshape: transfer {index} offered {:?} read committed {now:?}",
                    probe.offered
                );
                probe.committed = Some(now);
            }
        }
        let drain = c
            .committed_txs_in_flight(STRADDLER_SURVIVOR)
            .map_or(0, TxsInFlight::inner);
        self.peak.set(self.peak.get().max(drain));
        let rows = c
            .member_rows(STRADDLER_SURVIVOR)
            .expect("the harness reads the survivor's member rows");
        let mut strays = self.strays.borrow_mut();
        let mut standing = 0;
        for leg in self.stranded {
            let row = rows.get(&leg.tx);
            standing += usize::from(row.is_some());
            let stray = match row {
                Some(RowState::Pending) => false,
                Some(_) => true,
                None => now < leg.lapse,
            };
            if stray {
                strays.entry(leg.tx).or_insert_with(|| {
                    format!("{row:?} at {now:?}, its window closing {:?}", leg.lapse)
                });
            }
        }
        standing
    }

    /// Whether every probe offered has been read committed.
    fn admitted_all(&self) -> bool {
        self.probes
            .borrow()
            .iter()
            .all(|probe| probe.committed.is_some())
    }

    /// Offer a transfer at each reading until no stranded row stands
    /// past `closes`, or for one `epoch` past it, and then once more,
    /// driving until every transfer offered is read committed. How many
    /// stranded rows stood at the last reading of the first stretch.
    fn probe_until_the_stranded_go<C: Cluster>(
        &self,
        c: &mut C,
        bystanders: &[(Ed25519PrivateKey, PrincipalAddr)],
        charges: &mut Charges,
        (closes, epoch): (WeightedTimestamp, Duration),
        samples: &mut Vec<LoadSample>,
    ) -> usize {
        let standing = loop {
            self.offer(c, bystanders, charges);
            let next = clock(c).plus(LOAD_SAMPLE);
            let _ = c.run_until(epochs(1), |c| {
                let _ = self.read(c);
                clock(c) >= next
            });
            record(samples, LoadSample::read(c, STRADDLER_SURVIVOR));
            let standing = self.read(c);
            if (clock(c) >= closes && standing == 0) || clock(c) >= closes.plus(epoch) {
                break standing;
            }
        };
        self.offer(c, bystanders, charges);
        let _ = c.run_until(epochs(1), |c| {
            let _ = self.read(c);
            self.admitted_all()
        });
        record(samples, LoadSample::read(c, STRADDLER_SURVIVOR));
        standing
    }
}

/// Assert the survivor's chain commits each of `stranded` once, runs and
/// reclaims none, names none in a departure's record, and fates each
/// once, ending its fee hold.
///
/// # Panics
///
/// Panics if any of that does not hold.
fn assert_fated_unreclaimed<C: Cluster>(c: &C, stranded: &[StrandedLeg], mentions: &ChainMentions) {
    for leg in stranded {
        assert_eq!(
            (
                naming(&mentions.finalized, leg.tx),
                naming(&mentions.named_unsettled, leg.tx),
            ),
            (0, 0),
            "no member of a stranded leg ran, so no finalization names {:?}, and no departure's \
             record does",
            leg.tx,
        );
        assert_eq!(
            (
                naming(&mentions.committed, leg.tx),
                naming(&mentions.fated, leg.tx),
            ),
            (1, 1),
            "the survivor commits a stranded leg once and fates it once: {:?}",
            leg.tx,
        );
        assert!(
            !stands_at(c, leg.hold) && !stands_at(c, leg.total),
            "the fate of {:?} ends its fee hold, and the last hold on a vault ends its total",
            leg.tx,
        );
    }
}

/// Each of `probes` the survivor's chain does not carry exactly once, or
/// that no step read committed within `epoch` of its being offered.
fn unadmitted(probes: &[Probe], mentions: &ChainMentions, epoch: Duration) -> Vec<String> {
    probes
        .iter()
        .enumerate()
        .filter(|(_, probe)| {
            naming(&mentions.committed, probe.tx) != 1
                || probe
                    .committed
                    .is_none_or(|at| at > probe.offered.plus(epoch))
        })
        .map(|(index, probe)| {
            format!(
                "transfer {index} offered {:?} read committed {:?}",
                probe.offered, probe.committed
            )
        })
        .collect()
}

/// Where the scenario accounts the protocol resource: each caller's
/// vault and the crossing records its swaps have out, the two transfer
/// accounts and the venue's reserve.
///
/// A leg that ran paid its input into a record and ended its row at its
/// own finalization, so a record stands with no row beside it until the
/// venue's side answers for it, and what it holds comes back to its
/// caller's vault or goes on to the reserve whenever that is.
struct Accounts {
    /// Each caller's records standing with the cut served.
    records: BTreeMap<Address, Vec<SubstateKey>>,
    transfers: Vec<Address>,
    reserve: SubstateKey,
}

/// One reading of [`Accounts`].
struct Books {
    /// Each caller's vault, and what its records owe.
    callers: BTreeMap<Address, (u128, u128)>,
    transfers: u128,
    reserve: u128,
}

impl Accounts {
    /// The accounts of `load`, keeping of its records those standing
    /// now: no leg runs past the cut, so none is written after it.
    ///
    /// # Panics
    ///
    /// Panics if a swap of the load does not derive.
    fn of<C: Cluster>(
        c: &C,
        load: &BTreeMap<TxHash, Arc<Transaction>>,
        bystanders: &[(Ed25519PrivateKey, PrincipalAddr)],
        venue: &StockedVenue,
    ) -> Self {
        let derivation = c.derivation();
        let mut records: BTreeMap<Address, Vec<SubstateKey>> = BTreeMap::new();
        for swap in load.values() {
            let derived = swap
                .try_derived(derivation.as_ref())
                .expect("a swap of the load derives");
            records.entry(swap.fee_payer()).or_default().extend(
                crossing_records(&derived.legs)
                    .into_iter()
                    .filter(|record| owed_at(c, *record, *PROTOCOL_RESOURCE) > 0),
            );
        }
        Self {
            records,
            transfers: bystanders
                .iter()
                .map(|(_, account)| account.address())
                .collect(),
            reserve: reserve_cell(&venue.meta, *PROTOCOL_RESOURCE),
        }
    }

    fn read<C: Cluster>(&self, c: &C) -> Books {
        let resource = *PROTOCOL_RESOURCE;
        Books {
            callers: self
                .records
                .iter()
                .map(|(caller, records)| {
                    let owed = records
                        .iter()
                        .map(|record| owed_at(c, *record, resource))
                        .sum();
                    (*caller, (held(c, *caller, resource), owed))
                })
                .collect(),
            transfers: self
                .transfers
                .iter()
                .map(|account| held(c, *account, resource))
                .sum(),
            reserve: held_at(c, self.reserve),
        }
    }
}

impl Books {
    fn total(&self) -> u128 {
        let callers: u128 = self
            .callers
            .values()
            .map(|(vault, owed)| vault + owed)
            .sum();
        callers + self.transfers + self.reserve
    }
}

/// Assert the protocol resource is conserved from `before`, read with
/// the cut served, to `after`: each caller's vault and records are down
/// one price for each of its `stranded` legs and nothing else, and the
/// whole is down those prices and what the transfers of `charges`
/// burned. Each caller's figures are printed first.
///
/// # Panics
///
/// Panics if either does not hold, or if a charged transfer's fee hold
/// stands.
fn assert_conserved_from_the_cut<C: Cluster>(
    c: &C,
    (before, after): (&Books, &Books),
    stranded: &[StrandedLeg],
    charges: &Charges,
) {
    let prices = |caller: Address| -> u128 {
        stranded
            .iter()
            .filter(|leg| leg.payer == caller)
            .map(|leg| leg.price)
            .sum()
    };
    for (caller, (vault, owed)) in &before.callers {
        let (vault_after, owed_after) = after.callers[caller];
        println!(
            "saturated reshape: {caller:?} held {vault} and {owed} in records at the cut, \
             {vault_after} and {owed_after} at the end, against {} in prices",
            prices(*caller),
        );
    }
    println!(
        "saturated reshape: the venue's reserve held {} at the cut and {} at the end, the \
         transfer accounts {} and {}",
        before.reserve, after.reserve, before.transfers, after.transfers,
    );
    for (caller, (vault, owed)) in &before.callers {
        let (vault_after, owed_after) = after.callers[caller];
        assert_eq!(
            vault_after + owed_after + prices(*caller),
            vault + owed,
            "{caller:?} is charged one price for each of its stranded legs and nothing else",
        );
    }
    let fates: u128 = stranded.iter().map(|leg| leg.price).sum();
    let transfers = charges.burned(c);
    assert_eq!(
        after.total() + fates + transfers,
        before.total(),
        "the protocol resource is conserved from the cut, less {fates} the fates burned and \
         {transfers} the transfers did",
    );
    let unreleased = charges.standing_holds(c);
    assert!(
        unreleased.is_empty(),
        "a charged transfer still holds its payer's fee: {unreleased:?}",
    );
}

/// What the venue's departure left of the load on the survivor.
struct Stranding {
    /// Two accounts on the survivor that pay for nothing of the load.
    bystanders: Vec<(Ed25519PrivateKey, PrincipalAddr)>,
    /// The survivor's height as the load began.
    opened_at: BlockHeight,
    epoch: Duration,
    legs: Vec<StrandedLeg>,
    /// The reading the legs were taken at, with the cut served.
    at_the_cut: LoadSample,
    /// The close of the last of the legs' leg entry windows.
    closes: WeightedTimestamp,
    accounts: Accounts,
    /// What the accounts held at that reading.
    books: Books,
}

/// Stand the load up, offer it to the venue's cut, and drive until the
/// cut is served: both children seated and the beacon anchoring them.
/// The legs still waiting on the survivor then are the stranded ones.
///
/// # Panics
///
/// Panics as [`stand_the_load_up`] does, if the cut is not served short
/// of the close of the load's last leg entry window, if no leg is
/// stranded, if any row but a stranded leg's stands on the survivor, if
/// a stranded leg's fee hold does not, or if a swap of the load does not
/// derive.
fn strand_the_load<C: Cluster>(c: &mut C, samples: &mut Vec<LoadSample>) -> Stranding {
    let (venue_shard, survivor) = (STRADDLER_SPLITTER, STRADDLER_SURVIVOR);
    let (venue, bystanders, cut) = stand_the_load_up(c);
    let epoch = Duration::from_millis(epoch_duration_ms(c).expect("the beacon carries its epoch"));
    record(samples, LoadSample::read(c, survivor));
    let opened_at = c
        .committed_height(survivor)
        .expect("the survivor is served");
    let (load, last_window) = offer_the_load(c, &venue, cut, samples);
    // No leg of the load stands past this: its row is fated at the close
    // of its leg entry window.
    let lapse = Window::LegEntry
        .of(Deadline::of(last_window.end_timestamp_exclusive))
        .end;
    println!(
        "saturated reshape: cut {cut:?}, load offered {} to {last_window:?}, leg entry window \
         closes {lapse:?}, epoch {epoch:?}",
        load.len(),
    );

    // The cut, and the legs it stranded: the rows still waiting on the
    // survivor once the venue's prefix is its children's.
    let (left, right) = venue_shard.children();
    assert!(
        drive_sampling(c, survivor, lapse, samples, |c| c.serves_shard(left)
            && c.serves_shard(right)
            && anchor_seeded(c, left)),
        "the splitter must cut and the beacon anchor its children",
    );
    let legs = StrandedLeg::read(c, &load);
    let at_the_cut = *samples.last().expect("a reading at the cut");
    assert!(
        !legs.is_empty(),
        "the load must strand legs whose core left before committing them: {at_the_cut}",
    );
    assert!(
        at_the_cut.in_flight == 0 && at_the_cut.released == 0,
        "the callers are accounted from here, so no row of the load may stand but a stranded \
         leg's, whose exit burns a price: {at_the_cut}",
    );
    assert!(
        legs.iter()
            .all(|leg| stands_at(c, leg.hold) && stands_at(c, leg.total)),
        "a stranded leg's fee hold and its vault's total stand while its row does",
    );
    let closes = legs.iter().map(|leg| leg.lapse).max().unwrap_or(lapse);
    let accounts = Accounts::of(c, &load, &bystanders, &venue);
    let books = accounts.read(c);
    println!(
        "saturated reshape: stranded {} legs, the last of their leg entry windows closing \
         {closes:?}; {} records of legs that ran stand",
        legs.len(),
        accounts.records.values().map(Vec::len).sum::<usize>(),
    );
    Stranding {
        bystanders,
        opened_at,
        epoch,
        legs,
        at_the_cut,
        closes,
        accounts,
        books,
    }
}

/// A survivor under cross-shard load keeps admitting while the legs its
/// counterpart's reshape stranded hold their rows.
///
/// The venue sits on the splitter and the load's callers on the survivor.
/// Through the survivor's last blocks before the venue's cut the callers
/// offer swaps against the venue, keeping more offered than a block
/// carries, up to twice the drain between them. The survivor
/// commits what its drain admits; a swap's leg there waits for the
/// venue's shard to commit the swap too, and the venue's shard leaves
/// before it has committed them all. Those legs never run, issue no
/// record, and so have nothing to return. No tick took one, so no
/// certificate of the survivor's covers it, and the departure's records
/// name only what one covers. So each stranded leg stands pending with
/// its fee hold, holding its place in the drain, until the close of its
/// own leg entry window, where a fate deletes its row, burns the price
/// its block took and ends the hold.
///
/// The measure is whether the survivor admits throughout: from the cut
/// being served until every stranded row has gone, and once more after,
/// a plain transfer between two accounts on the survivor is offered at
/// each reading. Every one is committed within one epoch of being
/// offered, and the drain stays short of [`MAX_UNSETTLED_TXS`] at every
/// step. The readings of the survivor's rows are printed as they are
/// taken, whatever the outcome.
///
/// What the chain carries of the stranded legs and the transfers is read
/// in one walk from the load's first block, and the protocol resource is
/// accounted from the cut being served. A leg that ran paid its input
/// into a crossing record and ended its row, and the record stands until
/// the venue's side answers for it, so a caller's vault is read with the
/// records its swaps have out: the two together are down one price for
/// each of its stranded legs and nothing else, and with the two transfer
/// accounts and the venue's reserve the whole is down those prices and
/// one for each transfer. The swaps of the load that ran are not
/// followed one by one: reading whether one transaction was charged
/// walks the chain for it, and the load offers thousands.
///
/// # Panics
///
/// Panics if a shard is unserved, if the venue misses its budget
/// standing up, if the split is not admitted and scheduled with room for
/// the load before its cut, if the harness reads no member rows or walks
/// no chain, if the load strands no leg, or if anything but the stranded
/// legs stands once the cut is served. Panics if a stranded leg is read
/// in flight or released, goes short of the close of its leg entry
/// window, or stands an epoch past the last of them; if the survivor's
/// chain carries a finalization or an abandonment record naming one, or
/// any number of fates of one but one; if a fee hold outlives its row;
/// if a caller's vault and records move by anything but one price for
/// each of its stranded legs; or if the protocol resource is not
/// conserved. Panics
/// if a transfer is not committed on the survivor, once, within one
/// epoch of being offered, or if the drain is read full.
pub fn a_survivor_admits_after_a_reshape_under_saturated_cross_shard_load<C: Cluster>(c: &mut C) {
    let survivor = STRADDLER_SURVIVOR;
    let mut samples = Vec::new();
    let Stranding {
        bystanders,
        opened_at,
        epoch,
        legs: stranded,
        at_the_cut,
        closes,
        accounts,
        books,
    } = strand_the_load(c, &mut samples);

    // Whether the survivor admits while the stranded rows stand, and
    // once they have gone.
    let watch = Watch::over(&stranded, &samples);
    let mut charges = Charges::default();
    let still_standing = watch.probe_until_the_stranded_go(
        c,
        &bystanders,
        &mut charges,
        (closes, epoch),
        &mut samples,
    );
    let offered = watch.probes.borrow().len();
    let _ = c.run_until(epochs(1), |c| {
        let _ = watch.read(c);
        charges.charged(c) == offered
    });
    let settled = LoadSample::read(c, survivor);
    record(&mut samples, settled);

    let probes = watch.probes.take();
    let followed: BTreeSet<TxHash> = stranded
        .iter()
        .map(|leg| leg.tx)
        .chain(probes.iter().map(|probe| probe.tx))
        .collect();
    let mentions = c
        .chain_mentions(survivor, opened_at, &followed)
        .expect("the harness walks the survivor's chain");
    let of_the_stranded = |mentions: &[(TxHash, BlockHeight)]| -> usize {
        stranded.iter().map(|leg| naming(mentions, leg.tx)).sum()
    };
    let slowest = probes
        .iter()
        .filter_map(|probe| Some(probe.committed?.elapsed_since(probe.offered)))
        .max();
    let unadmitted = unadmitted(&probes, &mentions, epoch);
    let (peak, strays) = (watch.peak.get(), watch.strays.take());
    println!(
        "saturated reshape: stranded {} legs; at the cut: {at_the_cut}; the last leg entry \
         window closes {closes:?}, {still_standing} stranded standing past it; settled: \
         {settled}; of the stranded the chain carries {} inclusions, {} finalizations, {} \
         abandonment record names, {} fates; {} read off their wait or gone early; drain peak \
         {peak} of {MAX_UNSETTLED_TXS}; {} transfers offered, {} not committed once within \
         {epoch:?}, slowest {slowest:?}",
        stranded.len(),
        of_the_stranded(&mentions.committed),
        of_the_stranded(&mentions.finalized),
        of_the_stranded(&mentions.named_unsettled),
        of_the_stranded(&mentions.fated),
        strays.len(),
        probes.len(),
        unadmitted.len(),
    );

    // The stranded legs: waiting to the close of their windows, reclaimed
    // by nothing, and fated there.
    assert!(
        strays.is_empty(),
        "a stranded leg waits, and leaves no sooner than the close of its leg entry window: \
         {} read otherwise, the first {:?}",
        strays.len(),
        strays.first_key_value(),
    );
    assert_eq!(
        still_standing, 0,
        "no stranded leg stands an epoch past the close of the last leg entry window",
    );
    assert_fated_unreclaimed(c, &stranded, &mentions);
    assert_conserved_from_the_cut(c, (&books, &accounts.read(c)), &stranded, &charges);

    // The survivor: admitting throughout, its drain never full.
    assert!(
        unadmitted.is_empty(),
        "every transfer offered must be committed on the survivor, once, within {epoch:?} of \
         being offered: {unadmitted:?}",
    );
    assert!(
        peak < MAX_UNSETTLED_TXS,
        "the survivor's drain must never be read full: peak {peak} of {MAX_UNSETTLED_TXS}",
    );
}

/// The merged-pair genesis: the merge ballast, the venue on the merging
/// right quarter and its callers on the left.
#[must_use]
pub fn merged_pair_genesis_accounts() -> Vec<(PrincipalAddr, u128)> {
    let mut accounts = merge_survivor_ballast_accounts(&GenesisPackages::with_fixtures());
    accounts.extend(venue_genesis_accounts_on(
        MERGE_STRADDLER_RIGHT,
        &[MERGE_STRADDLER_LEFT],
    ));
    accounts
}

/// Genesis funding for [`a_leg_issued_on_a_merging_shard_reaches_its_venue`].
///
/// The merge topology's byte skew, the venue's provider on a surviving
/// quarter, and the callers on the merge-left child — so the pair that
/// merges is the callers', and the venue's shard never reshapes.
#[must_use]
pub fn merging_caller_genesis_accounts() -> Vec<(PrincipalAddr, u128)> {
    let mut accounts = merge_survivor_ballast_accounts(&GenesisPackages::with_fixtures());
    accounts.extend(venue_genesis_accounts_on(
        MERGE_STRADDLER_SURVIVOR,
        &[MERGE_STRADDLER_LEFT],
    ));
    accounts
}

/// Wait for `splitter` to cut: both children served and the beacon
/// carrying their seeded genesis, so the prefixes it held read on the
/// children.
///
/// # Panics
///
/// Panics if a child is unserved within budget or the anchor is never
/// composed.
fn await_cut<C: Cluster>(c: &mut C, splitter: ShardId) {
    let (left, right) = splitter.children();
    assert!(
        await_serves(c, left, epochs(28)) && await_serves(c, right, epochs(28)),
        "both splitter children must be served within budget",
    );
    assert!(
        await_anchor_seeded(c, left, epochs(6)),
        "the beacon must compose the split children's anchor",
    );
    assert!(
        anchor_seeded(c, left),
        "the children's seeded genesis pins the split shard's cells under a child",
    );
}

/// Two stocked venues, one on a shard about to leave, and the trader on
/// a shard of its own, opened over the worlds a route can reach.
struct DepartingRoute {
    leaving: StockedVenue,
    staying: StockedVenue,
    key: Ed25519PrivateKey,
    trader: PrincipalAddr,
    reserves: [SubstateKey; 2],
    stocked: [u128; 2],
    protocol_resource: World,
    units: World,
}

/// Stand the departing route up on the four-shard route topology: the
/// first venue's shard is voted over the threshold and admitted to
/// split, and both venues are stocked before that. The trader sits on a
/// shard of its own: a leg beside a core node on one shard runs as that
/// core member and waits with it, where the leg under test pays and
/// settles alone.
///
/// # Panics
///
/// Panics if a quarter is unserved, if either venue misses its budget
/// standing up, or if the split is not admitted, or admitted elsewhere.
fn departing_route<C: Cluster>(c: &mut C) -> DepartingRoute {
    let departing = FIRST_VENUE_SHARD;
    assert!(
        (0..4).all(|path| c.serves_shard(ShardId::leaf(2, path))),
        "the grown four-shard topology must seat every quarter",
    );
    let mut taken = Vec::new();
    let leaving = stand_up_venue(c, departing, &mut taken);
    let staying = stand_up_venue(c, SECOND_VENUE_SHARD, &mut taken);
    let (key, trader) = grind_onto(TRADER_SHARD, &mut taken);
    let reserves = [
        reserve_cell(&leaving.meta, *PROTOCOL_RESOURCE),
        reserve_cell(&staying.meta, *PROTOCOL_RESOURCE),
    ];
    let stocked = reserves.map(|reserve| held_at(c, reserve));
    assert!(
        stocked.iter().all(|&held| held > 0),
        "both venues have to be holding something to price against"
    );
    let protocol_resource = World::open(c, *PROTOCOL_RESOURCE, [trader.address()], reserves);
    let units = World::open(
        c,
        leaving.unit,
        [trader.address()],
        [
            reserve_cell(&leaving.meta, leaving.unit),
            reserve_cell(&staying.meta, staying.unit),
        ],
    );
    // The departing venue's shard is leaving from here to the cut: its
    // ballast alone crosses the voted threshold. The vote settles before
    // any certificate channel is cut, since it crosses the same shards.
    cast_threshold_vote(c, voted_split_bytes(&GenesisPackages::with_fixtures()));
    assert!(
        await_split_admitted(c, departing, epochs(20)),
        "only the over-threshold venue shard must admit a split",
    );
    assert!(
        (0..4)
            .map(|path| ShardId::leaf(2, path))
            .filter(|&shard| shard != departing)
            .all(|shard| !split_admitted(c, shard)),
        "no other quarter may split",
    );
    DepartingRoute {
        leaving,
        staying,
        key,
        trader,
        reserves,
        stocked,
        protocol_resource,
        units,
    }
}

/// Submit one route through the departing venue and hold it until both
/// shards have committed it while both are live, the survivor's drain
/// has engaged, and the trader's leg has paid. Returns the route's hash,
/// the survivor's drain before the route, and what the trader holds
/// once its leg has paid.
///
/// # Panics
///
/// Panics if both shards do not commit the route while both are live,
/// if it engages no hold on the survivor, or if the trader's leg does
/// not pay.
fn submit_departing_route<C: Cluster>(
    c: &mut C,
    route: &mut DepartingRoute,
    charges: &mut Charges,
) -> (TxHash, TxsInFlight, u128) {
    let (departing, survivor) = (FIRST_VENUE_SHARD, SECOND_VENUE_SHARD);
    let baseline = c
        .committed_txs_in_flight(survivor)
        .expect("the survivor must serve a committed tip before the route");
    let validity = validity_around(c.now());
    let tx = build_route_tx(
        &route.key,
        route.trader,
        (&route.leaving.meta, &route.staying.meta),
        *PROTOCOL_RESOURCE,
        ROUTE_INPUT,
        0,
        validity,
    );
    // The records the route's crossings write are value the world still
    // holds while they stand; the output's is the one a departure can
    // leave owed to the trader.
    route.protocol_resource.owing(crossing_records(
        &tx.try_derived(c.derivation().as_ref())
            .expect("a scenario route derives")
            .legs,
    ));
    let hash = charges.submit(c, tx);
    assert!(
        c.run_until(epochs(12), |c| c.chain_fate(survivor, hash).0.is_some()
            && c.chain_fate(departing, hash).0.is_some()),
        "both shards must commit the route while both are live",
    );
    let engaged = c
        .committed_txs_in_flight(survivor)
        .expect("the survivor must serve a committed tip once it holds the route");
    assert!(
        engaged > baseline,
        "the route must engage a hold against the survivor's drain, or its release below \
         proves nothing; baseline = {baseline:?}, engaged = {engaged:?}",
    );
    assert!(
        c.run_until(epochs(8), |c| held(
            c,
            route.trader.address(),
            *PROTOCOL_RESOURCE
        ) < SWAPPER_FUNDING - ROUTE_INPUT),
        "the trader's leg must pay before the core is asked anything",
    );
    (
        hash,
        baseline,
        held(c, route.trader.address(), *PROTOCOL_RESOURCE),
    )
}

/// Wait for the departing venue's shard to terminate: both children
/// served.
///
/// # Panics
///
/// Panics if a child is not served within budget.
fn await_departed<C: Cluster>(c: &mut C) {
    let (left, right) = FIRST_VENUE_SHARD.children();
    assert!(
        await_serves(c, left, epochs(28)) && await_serves(c, right, epochs(28)),
        "both splitter children must be served within budget",
    );
}

/// The venue whose shard the late vote takes away — one half of the
/// pair the grow's own split leaves behind, which the vote collapses
/// back into their parent.
///
/// The departure is a merge rather than a split because a split draws a
/// fresh cohort from the pool and the parent's split leaves it short of
/// another, while a merge's keepers come from the committees the halves
/// already hold.
const LATE_DEPARTING_VENUE: ShardId = ShardId::leaf(3, 0);

/// The parent the departing pair collapses into.
const LATE_MERGED_PARENT: ShardId = ShardId::leaf(2, 0);

/// The venue that outlives it: heavy enough to stay clear of the derived
/// `merge_bytes` the vote raises.
const LATE_SURVIVOR_VENUE: ShardId = ShardId::leaf(2, 2);

/// Where the trader sits.
const LATE_TRADER_SHARD: ShardId = ShardId::leaf(2, 3);

/// The threshold the late vote installs. Raised rather than lowered: the
/// derived `merge_bytes` is an eighth of it, and the figure puts that
/// eighth above the departing pair and below the surviving venue, so one
/// pair collapses and nothing else moves.
const LATE_SPLIT_BYTES: u64 = 1_200_000;

/// The floor [`LATE_SPLIT_BYTES`] derives: an eighth of it, which every
/// quarter of this scenario is placed on one side of.
const LATE_MERGE_FLOOR: u64 = LATE_SPLIT_BYTES / 8;

/// Headroom either side of [`LATE_MERGE_FLOOR`], so a quarter's exact
/// draw from the genesis flash never decides which side it lands on.
const LATE_FLOOR_MARGIN: u64 = 30_000;

/// What each quarter that must outlive the merge carries: clear of the
/// floor on its own, so it neither asserts a merge with its sibling nor
/// leaves the venue standing on it.
const LATE_SURVIVING_QUARTER_BYTES: u64 = LATE_MERGE_FLOOR + LATE_FLOOR_MARGIN;

/// What the merging parent carries, shared between the two children the
/// vote collapses: enough under twice the floor that each child sits
/// below it however the flash and the ballast divide between them.
const LATE_MERGING_PARENT_BYTES: u64 = (LATE_MERGE_FLOOR - LATE_FLOOR_MARGIN) * 2;

/// The reshape threshold the late-departure topology grows under.
///
/// Between the merging parent's ballast and every other quarter's, so the
/// parent is the one leaf that splits once it is in force, into the pair
/// the late vote collapses.
pub const LATE_GROWN_SPLIT_BYTES: u64 =
    u64::midpoint(LATE_MERGING_PARENT_BYTES, LATE_SURVIVING_QUARTER_BYTES);

/// Genesis funding for
/// [`a_route_committed_before_its_departure_was_voted_still_resolves`].
///
/// Every quarter is placed against the floor the late vote derives: the
/// parent whose children collapse sits under it once halved, and the two
/// that outlive the merge sit over it. Each target counts the genesis
/// flash the quarter already drew, which is a hash's answer rather than
/// a figure any of them controls.
#[must_use]
pub fn late_departing_route_genesis_accounts() -> Vec<(PrincipalAddr, u128)> {
    let packages = GenesisPackages::with_fixtures();
    let mut accounts = ballast_to(LATE_MERGED_PARENT, 4, LATE_MERGING_PARENT_BYTES, &packages);
    for surviving in [LATE_SURVIVOR_VENUE, LATE_TRADER_SHARD] {
        accounts.extend(ballast_to(
            surviving,
            4,
            LATE_SURVIVING_QUARTER_BYTES,
            &packages,
        ));
    }
    let mut taken = Vec::new();
    accounts.push((
        grind_onto(LATE_DEPARTING_VENUE, &mut taken).1,
        PROVIDER_FUNDING,
    ));
    accounts.push((
        grind_onto(LATE_SURVIVOR_VENUE, &mut taken).1,
        PROVIDER_FUNDING,
    ));
    accounts.push((grind_onto(LATE_TRADER_SHARD, &mut taken).1, SWAPPER_FUNDING));
    accounts
}

/// Epochs of lead the late threshold vote carries, so it is cast while
/// the venues can still hear each other and takes effect only once the
/// route it is meant to outlive has long committed.
const LATE_VOTE_LEAD_EPOCHS: u64 = 16;

/// Attempts [`cast_late_threshold_vote`] makes before giving up.
const LATE_VOTE_ATTEMPTS: u32 = 4;

/// Cast the founding pool's vote to retune `split_bytes`, activating
/// `lead` epochs out rather than as soon as the fold allows, and hold
/// until the proposal is on the chain.
///
/// The standard helper waits for the change to *apply*, which is no use
/// where the point is to keep it pending across everything that happens
/// between. Registration is what has to be confirmed here: past this the
/// venues stop hearing each other and no further vote could land.
///
/// # Panics
///
/// Panics if the proposal never reaches `param_votes` within budget.
fn cast_late_threshold_vote<C: Cluster>(c: &mut C, split_bytes: u64, lead: u64) -> Epoch {
    for _ in 0..LATE_VOTE_ATTEMPTS {
        let current = beacon_epoch(c).expect("a grown cluster has a beacon epoch");
        let live = c
            .beacon_state()
            .expect("a grown cluster has beacon state")
            .params;
        let mut ballot = ParamBallot::of(&live);
        ballot.split_bytes = split_bytes;
        let activate_at = Epoch::new(current.inner() + lead);
        let vote = build_param_vote_tx(
            &pool_operator().0,
            ballot,
            activate_at,
            validity_around(c.now()),
        );
        c.submit(Arc::new(vote));
        if c.run_until(epochs(6), |c| {
            c.beacon_state().is_some_and(|state| {
                state.param_votes.values().any(|proposal| {
                    proposal.activate_at == activate_at
                        && proposal.params.reshape_thresholds.split_bytes == split_bytes
                })
            })
        }) {
            return activate_at;
        }
    }
    panic!("the late threshold vote never reached the chain");
}

/// A venue sealed on a freshly formed split child runs.
///
/// The committee seated at a cut has run nothing: every artifact it
/// needs is one it has to acquire, and a seal offered to it names code
/// none of its members has ever compiled. Nothing about the chain says
/// when that code arrives, so the seal waits at each node's door until
/// its own fetch lands, and the tick that runs it waits at the dispatch
/// head until its own build does.
///
/// The inverse of what every other reshape scenario here does. Those
/// seal before the cut so the child inherits the code with the keyspace;
/// this one seals after, which is the case a node with no code and no
/// way to ask for it could not survive.
///
/// # Panics
///
/// Panics if the grown topology does not settle, if the split does not
/// run, if the venue misses its budget standing up on the child, or if a
/// swap through it does not settle.
pub fn a_venue_sealed_on_a_fresh_split_child_runs<C: Cluster>(c: &mut C) {
    // Let the grow's own split run first, so the venue is offered to a
    // committee that came up at the cut rather than one that inherited
    // anything.
    let (left, right) = LATE_MERGED_PARENT.children();
    assert!(
        await_serves(c, left, epochs(28)) && await_serves(c, right, epochs(28)),
        "the grow's own split must have run before the venue is sealed",
    );

    let mut taken = Vec::new();
    let venue = stand_up_venue(c, left, &mut taken);
    let (caller_key, caller) = grind_onto(LATE_TRADER_SHARD, &mut taken);

    let swap = build_swap_tx(
        &caller_key,
        caller,
        &venue.meta,
        *PROTOCOL_RESOURCE,
        ROUTE_INPUT,
        0,
        validity_around(c.now()),
    );
    let hash = swap.hash();
    c.submit(Arc::new(swap));
    let status = await_tx_terminal(c, hash, epochs(24));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "a swap through a venue sealed on a fresh child did not settle; status = {status:?}",
    );
}

/// Both venues were genuinely held apart, and neither settled a route
/// whose verdict the other never read.
///
/// The two halves of one claim: the channel carried something and was
/// cut, so a run where the fault never fired proves nothing; and no
/// venue reached an acceptance alone, which is what a core that never
/// read its counterpart's verdict may never do.
fn assert_neither_venue_settled<C: FaultableCluster>(
    c: &C,
    cut: &[FaultHandle],
    hash: TxHash,
    venues: [ShardId; 2],
) {
    assert!(
        cut.iter().any(|handle| handle.fired() > 0),
        "the channels between the venues must actually have been exercised and cut, or the \
         venues were never held apart",
    );
    for shard in venues {
        let fate = c.chain_fate(shard, hash).1.map(|(_, decision)| decision);
        assert!(
            fate != Some(TransactionDecision::Accept),
            "a venue settled a route whose verdict it never read; {shard} reached {fate:?}",
        );
    }
}

/// A record naming a commit from before its departure was ever voted
/// still resolves the window that priced it.
///
/// Every other reshape scenario takes its departure from the grow, which
/// admits one before any scenario code runs — so the commit always falls
/// inside the floor that admission pins, and the window the record names
/// is always still retained. Here the grow's own split is allowed to run
/// first, the route commits against quarters that survive it, and only
/// then does a vote schedule the departure. The commit is left on the far
/// side of every floor the schedule derives, while its entry lives on:
/// nothing bounds how long a certified entry waits for a silent
/// counterpart.
///
/// # Panics
///
/// Panics if the grown topology does not settle, if the late split is not
/// admitted where it was voted, or if the survivor's hold or the trader's
/// input does not come back.
pub fn a_route_committed_before_its_departure_was_voted_still_resolves<C: FaultableCluster>(
    c: &mut C,
) {
    let (departing, survivor) = (LATE_DEPARTING_VENUE, LATE_SURVIVOR_VENUE);
    // The departing venue is sealed while its shard's parent still holds
    // the keyspace, so the child inherits it at the cut. A venue sealed
    // on a child after the fact would ask its freshly seated committee
    // for code none of them has ever run.
    let mut taken = Vec::new();
    let leaving = stand_up_venue(c, departing, &mut taken);

    // The grown threshold admits the merging parent's split. Let it run:
    // the pair it forms is what the vote later collapses, and the floor
    // its own admission pins expires before the route commits rather than
    // after.
    let (grown_left, grown_right) = LATE_MERGED_PARENT.children();
    assert!(
        await_serves(c, grown_left, epochs(28)) && await_serves(c, grown_right, epochs(28)),
        "the grow's own split must have run before the route commits",
    );

    let staying = stand_up_venue(c, survivor, &mut taken);
    let (key, trader) = grind_onto(LATE_TRADER_SHARD, &mut taken);
    let reserves = [
        reserve_cell(&leaving.meta, *PROTOCOL_RESOURCE),
        reserve_cell(&staying.meta, *PROTOCOL_RESOURCE),
    ];
    let mut protocol_resource = World::open(c, *PROTOCOL_RESOURCE, [trader.address()], reserves);

    // A vote crosses both venue shards, so it has to be cast while they
    // can still hear each other — but it carries an activation far
    // enough out that the departure it schedules lands well after the
    // route has committed. That gap is the whole scenario.
    let activates_at = cast_late_threshold_vote(c, LATE_SPLIT_BYTES, LATE_VOTE_LEAD_EPOCHS);

    let cut = hold_late_venues_apart(c, LATE_TRADER_SHARD);
    let baseline = c
        .committed_txs_in_flight(survivor)
        .expect("the survivor must serve a committed tip before the route");
    let mut charges = Charges::default();
    let tx = build_route_tx(
        &key,
        trader,
        (&leaving.meta, &staying.meta),
        *PROTOCOL_RESOURCE,
        ROUTE_INPUT,
        0,
        validity_around(c.now()),
    );
    // A record the cut leaves standing is value the world still holds,
    // counted rather than reported as a strand.
    protocol_resource.owing(crossing_records(
        &tx.try_derived(c.derivation().as_ref())
            .expect("a scenario route derives")
            .legs,
    ));
    let hash = charges.submit(c, tx);
    assert!(
        c.run_until(epochs(12), |c| c.chain_fate(survivor, hash).0.is_some()
            && c.chain_fate(departing, hash).0.is_some()),
        "both shards must commit the route while both are live",
    );
    let engaged = c
        .committed_txs_in_flight(survivor)
        .expect("the survivor must serve a committed tip once it holds the route");
    assert!(
        engaged > baseline,
        "the route must engage a hold against the survivor's drain; baseline = {baseline:?}, \
         engaged = {engaged:?}",
    );
    assert!(
        c.run_until(epochs(8), |c| held(c, trader.address(), *PROTOCOL_RESOURCE)
            < SWAPPER_FUNDING - ROUTE_INPUT),
        "the trader's leg must pay before the core is asked anything",
    );
    let paid = held(c, trader.address(), *PROTOCOL_RESOURCE);

    await_late_departure(c, activates_at);
    assert_fated_off(c, departing, hash, &[LATE_MERGED_PARENT]);
    assert!(
        c.run_until(epochs(32), |c| c.committed_txs_in_flight(survivor)
            == Some(baseline)),
        "the survivor's hold must return to its baseline once the departed venue's ended names \
         have answered a commit from before the vote; holds {:?} against {baseline:?}",
        c.committed_txs_in_flight(survivor),
    );
    // And the crossing the trader's leg issued comes back to it. Which
    // of the two settles it is the epoch length's to decide and not this
    // scenario's: `CLAIM_WINDOW` is counted in epochs, so on a long one
    // the leg entry is gone before the record the cut licenses lands and
    // the record leaf is all that is left to compose from, while on a
    // short one the entry is still standing and settles it itself. The
    // value comes back either way, which is the whole of what is owed.
    assert!(
        c.run_until(epochs(12), |c| held(
            c,
            trader.address(),
            *PROTOCOL_RESOURCE
        ) == paid + ROUTE_INPUT),
        "the trader must get the route's input back however late the cut lands; holds {} \
         against {}",
        held(c, trader.address(), *PROTOCOL_RESOURCE),
        paid + ROUTE_INPUT,
    );
    assert_neither_venue_settled(c, &cut, hash, [departing, survivor]);
    c.clear_drops();
    // The trader holds its input again and neither venue settled, so no
    // record stands and the reserves are untouched.
    protocol_resource.assert_settled(
        c,
        &charges,
        "a route committed before its departure was voted",
    );
}

/// Cut the late departure's venues off from each other's certificates
/// and readings, with the trader's shard still read by both. The
/// survivor's readings are cut from every host but the trader shard's,
/// since the departing venue's committee gains members before it leaves
/// and a cut keyed on its hosts would let them through.
fn hold_late_venues_apart<C: FaultableCluster>(c: &mut C, trader: ShardId) -> [FaultHandle; 3] {
    let (departing, survivor) = (LATE_DEPARTING_VENUE, LATE_SURVIVOR_VENUE);
    [
        isolate_ec_intake(c, departing, survivor),
        isolate_ec_intake(c, survivor, departing),
        isolate_crossing_intake_but_from(c, survivor, &[trader]),
    ]
}

/// Drive the late vote through to the merged parent serving.
///
/// The activation carries the run past the floor the grow's own split
/// pinned and past the horizon the commit's window would otherwise have
/// been kept under, so the departure it schedules leaves the route's
/// commit on the far side of every floor.
///
/// # Panics
///
/// Panics if the vote never activates, the pair never pairs its keepers,
/// or the merged parent is unserved within budget.
fn await_late_departure<C: Cluster>(c: &mut C, activates_at: Epoch) {
    assert!(
        c.run_until(epochs(28), |c| c.beacon_state().is_some_and(|s| s
            .params
            .reshape_thresholds
            .split_bytes
            == LATE_SPLIT_BYTES)),
        "the late vote must activate at {activates_at:?}",
    );
    assert!(
        await_merge_keeper_count(c, LATE_MERGED_PARENT, 3, epochs(28)),
        "the activated threshold must pair the departing venue's shard with its sibling",
    );
    assert!(
        await_serves(c, LATE_MERGED_PARENT, epochs(28)),
        "the merged parent must be served within budget",
    );
}

/// Where the trader of [`a_merged_chain_declines_at_its_own_parent`]
/// sits: the departing venue's sibling, which the late vote collapses
/// into one parent with it.
const LATE_MERGING_TRADER_SHARD: ShardId = ShardId::leaf(3, 1);

/// Genesis funding for [`a_merged_chain_declines_at_its_own_parent`]:
/// [`late_departing_route_genesis_accounts`] with the trader under the
/// merging parent, on the half the departing venue is not.
#[must_use]
pub fn merging_route_genesis_accounts() -> Vec<(PrincipalAddr, u128)> {
    let packages = GenesisPackages::with_fixtures();
    let mut accounts = ballast_to(LATE_MERGED_PARENT, 4, LATE_MERGING_PARENT_BYTES, &packages);
    for surviving in [LATE_SURVIVOR_VENUE, LATE_TRADER_SHARD] {
        accounts.extend(ballast_to(
            surviving,
            4,
            LATE_SURVIVING_QUARTER_BYTES,
            &packages,
        ));
    }
    let mut taken = Vec::new();
    accounts.push((
        grind_onto(LATE_DEPARTING_VENUE, &mut taken).1,
        PROVIDER_FUNDING,
    ));
    accounts.push((
        grind_onto(LATE_SURVIVOR_VENUE, &mut taken).1,
        PROVIDER_FUNDING,
    ));
    accounts.push((
        grind_onto(LATE_MERGING_TRADER_SHARD, &mut taken).1,
        SWAPPER_FUNDING,
    ));
    accounts
}

/// A chain a merge brought both ends of a crossing onto declines the
/// record at its own parent, takes it back in a later block, and then
/// lets the answer go.
///
/// [`a_route_committed_before_its_departure_was_voted_still_resolves`]
/// with the trader on the departing venue's sibling. The trader's leg
/// stages the route's input as a record under one half of the merging
/// pair, for a venue under the other, and the core never combines. The
/// late vote collapses the pair: both terminals fate what they hold, and
/// the merged parent inherits the record and the venue's prefix
/// together, with no member of the route and no answer.
///
/// No counterpart holds either end to be asked or pushed to, so the
/// merged chain reads the crossing at its own parent: the record with
/// its value and the route's member row absent, on which its fold
/// writes the `Never`; then the `Never` present beside the record, on
/// which the input is taken back; then the record absent, on which the
/// `Never` is deleted.
///
/// # Panics
///
/// Panics if the grown topology does not settle, if the late split is
/// not admitted where it was voted, if the record and the venue's
/// prefix do not come to the merged parent together, if the merged
/// chain does not decline the record, if the decline is a refusal's or
/// names another transaction, if the input does not come home, or if
/// the answer outlives the record.
pub fn a_merged_chain_declines_at_its_own_parent<C: FaultableCluster>(c: &mut C) {
    let (departing, survivor) = (LATE_DEPARTING_VENUE, LATE_SURVIVOR_VENUE);
    let mut taken = Vec::new();
    let leaving = stand_up_venue(c, departing, &mut taken);
    let (grown_left, grown_right) = LATE_MERGED_PARENT.children();
    assert!(
        await_serves(c, grown_left, epochs(28)) && await_serves(c, grown_right, epochs(28)),
        "the grow's own split must have run before the route commits",
    );
    let staying = stand_up_venue(c, survivor, &mut taken);
    let (key, trader) = grind_onto(LATE_MERGING_TRADER_SHARD, &mut taken);
    let reserves = [
        reserve_cell(&leaving.meta, *PROTOCOL_RESOURCE),
        reserve_cell(&staying.meta, *PROTOCOL_RESOURCE),
    ];
    let mut protocol_resource = World::open(c, *PROTOCOL_RESOURCE, [trader.address()], reserves);
    let activates_at = cast_late_threshold_vote(c, LATE_SPLIT_BYTES, LATE_VOTE_LEAD_EPOCHS);

    let cut = hold_late_venues_apart(c, LATE_MERGING_TRADER_SHARD);
    let mut charges = Charges::default();
    let tx = build_route_tx(
        &key,
        trader,
        (&leaving.meta, &staying.meta),
        *PROTOCOL_RESOURCE,
        ROUTE_INPUT,
        0,
        validity_around(c.now()),
    );
    protocol_resource.owing(crossing_records(
        &tx.try_derived(c.derivation().as_ref())
            .expect("a scenario route derives")
            .legs,
    ));
    let hash = charges.submit(c, tx);
    assert!(
        c.run_until(epochs(12), |c| c.chain_fate(survivor, hash).0.is_some()
            && c.chain_fate(departing, hash).0.is_some()),
        "both venue shards must commit the route while both are live",
    );
    assert!(
        c.run_until(epochs(8), |c| held(c, trader.address(), *PROTOCOL_RESOURCE)
            < SWAPPER_FUNDING - ROUTE_INPUT),
        "the trader's leg must pay before the core is asked anything",
    );
    let paid = held(c, trader.address(), *PROTOCOL_RESOURCE);
    let (record, id) = escrowed_into(c, &charges.records(c), departing);
    let decline = id.answer_key(&ProtocolHasher, Answered::Never);
    assert_eq!(
        (
            owning_shard(c, record.owner),
            owning_shard(c, decline.owner)
        ),
        (LATE_MERGING_TRADER_SHARD, departing),
        "the record and its consumer sit on the two halves of the merging pair",
    );

    await_late_departure(c, activates_at);
    assert_fated_off(c, departing, hash, &[LATE_MERGED_PARENT]);
    assert_eq!(
        (
            owning_shard(c, record.owner),
            owning_shard(c, decline.owner)
        ),
        (LATE_MERGED_PARENT, LATE_MERGED_PARENT),
        "the merge must bring both ends of the crossing onto one chain",
    );
    assert!(
        c.run_until(epochs(12), |c| answer_standing(c, decline).is_some()),
        "the merged chain must decline the record at its own parent",
    );
    let answer = answer_standing(c, decline).expect("the decline stands");
    assert_eq!(
        (answer.answered, answer.tx, answer.seen),
        (Answered::Never, hash, true),
        "the fold's decline names the route and is written seen",
    );
    assert!(
        c.declined(departing, hash).is_empty() && c.declined(LATE_MERGED_PARENT, hash).is_empty(),
        "no member of the route refused the input: the decline is the merged chain's fold's",
    );
    assert!(
        c.run_until(epochs(12), |c| held(
            c,
            trader.address(),
            *PROTOCOL_RESOURCE
        ) == paid + ROUTE_INPUT),
        "the trader must get the route's input back on the merged chain's decline; holds {} \
         against {}",
        held(c, trader.address(), *PROTOCOL_RESOURCE),
        paid + ROUTE_INPUT,
    );
    assert!(
        c.run_until(epochs(4), |c| !stands_at(c, record)
            && answer_standing(c, decline).is_none()),
        "the record is gone and its answer after it, read absent at the chain's own parent",
    );
    assert_neither_venue_settled(c, &cut, hash, [departing, survivor]);
    c.clear_drops();
    protocol_resource.assert_settled(c, &charges, "a record a merged chain declined");
}

/// A route the surviving venue accepted before its counterpart's split
/// was projected is not torn: if the survivor settled it, the departing
/// venue's side applied too, on it or on its successor.
///
/// [`a_route_committed_before_its_departure_was_voted_still_resolves`]
/// with the certificate channel cut one way. The survivor still receives
/// the departing venue's certificate and finalizes the route at an
/// anchor where the departure is not yet scheduled; the departing venue
/// never receives the survivor's. Neither certificate decides anything
/// on the other venue: the departing venue reads the survivor's verdict
/// in its state, and accepts before its terminal.
///
/// Two things make the result trustworthy: the cut fired, and the
/// survivor's finalization landed before the departure was admitted —
/// without both the scenario proves nothing. The oracle is the
/// departing venue's reserve, which moves exactly when its side applied,
/// and the conservation of the trader and both reserves.
///
/// # Panics
///
/// Panics as the scenario it follows does, if the positive control does
/// not hold, and if the route is torn: the survivor accepted and the
/// departing venue's side applied nowhere, or the world does not
/// balance.
pub fn a_route_accepted_before_its_venues_split_is_projected_is_not_torn<C: FaultableCluster>(
    c: &mut C,
) {
    let (departing, survivor) = (LATE_DEPARTING_VENUE, LATE_SURVIVOR_VENUE);
    let mut taken = Vec::new();
    let leaving = stand_up_venue(c, departing, &mut taken);
    let (grown_left, grown_right) = LATE_MERGED_PARENT.children();
    assert!(
        await_serves(c, grown_left, epochs(28)) && await_serves(c, grown_right, epochs(28)),
        "the grow's own split must have run before the route commits",
    );
    let staying = stand_up_venue(c, survivor, &mut taken);
    let (key, trader) = grind_onto(LATE_TRADER_SHARD, &mut taken);
    let leaving_reserve = reserve_cell(&leaving.meta, *PROTOCOL_RESOURCE);
    let reserves = [
        leaving_reserve,
        reserve_cell(&staying.meta, *PROTOCOL_RESOURCE),
    ];
    let mut protocol_resource = World::open(c, *PROTOCOL_RESOURCE, [trader.address()], reserves);
    let leaving_held = held_at(c, leaving_reserve);

    let activates_at = cast_late_threshold_vote(c, LATE_SPLIT_BYTES, LATE_VOTE_LEAD_EPOCHS);

    // One way only: the departing venue never holds the survivor's
    // certificate, while the survivor holds the departing venue's and
    // settles the route on it.
    let cut = isolate_ec_intake(c, departing, survivor);
    let mut charges = Charges::default();
    let tx = build_route_tx(
        &key,
        trader,
        (&leaving.meta, &staying.meta),
        *PROTOCOL_RESOURCE,
        ROUTE_INPUT,
        0,
        validity_around(c.now()),
    );
    protocol_resource.owing(crossing_records(
        &tx.try_derived(c.derivation().as_ref())
            .expect("a scenario route derives")
            .legs,
    ));
    let hash = charges.submit(c, tx);
    assert!(
        c.run_until(epochs(12), |c| c.chain_fate(survivor, hash).0.is_some()
            && c.chain_fate(departing, hash).0.is_some()),
        "both shards must commit the route while both are live",
    );
    assert!(
        c.run_until(epochs(12), |c| c.chain_fate(survivor, hash).1.is_some()),
        "the survivor must finalize the route on the departing venue's certificate",
    );
    // The positive control: the finalization landed before the departure
    // was admitted, where the fence's pre-boundary hold could not have
    // deferred it, and the cut is what kept the departing venue from the
    // survivor's certificate.
    assert!(
        merge_keeper_count(c, LATE_MERGED_PARENT).is_none(),
        "the survivor's finalization must land before the departure is admitted; the vote \
         activates at {activates_at:?}",
    );
    assert!(
        cut.fired() > 0,
        "the cut must have dropped something, or the departing venue was never kept from the \
         survivor's certificate",
    );
    let survivor_fate = c.chain_fate(survivor, hash).1.map(|(_, decision)| decision);

    assert!(
        c.run_until(epochs(28), |c| c.beacon_state().is_some_and(|s| s
            .params
            .reshape_thresholds
            .split_bytes
            == LATE_SPLIT_BYTES)),
        "the late vote must activate at {activates_at:?}",
    );
    assert!(
        await_merge_keeper_count(c, LATE_MERGED_PARENT, 3, epochs(28)),
        "the activated threshold must pair the departing venue's shard with its sibling",
    );
    assert!(
        await_serves(c, LATE_MERGED_PARENT, epochs(28)),
        "the merged parent must be served within budget",
    );
    c.clear_drops();

    // The oracle: an accept on the survivor is an accept on both sides,
    // or the route is torn. The departing venue's reserve moves exactly
    // when its leg applied — on the venue itself, or carried into the
    // successor that inherited its keyspace.
    if survivor_fate == Some(TransactionDecision::Accept) {
        assert!(
            c.run_until(epochs(12), |c| held_at(c, leaving_reserve) != leaving_held),
            "the survivor accepted the route and the departing venue's side applied nowhere: \
             the route is torn; the departing venue reached {:?}",
            c.chain_fate(departing, hash).1,
        );
    }
    protocol_resource.assert_settles_within(
        c,
        &charges,
        epochs(12),
        "a route accepted before its venue's split was projected",
    );
}

/// What a route's world reads at one instant: the trader's protocol
/// resource, then each venue's two reserves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RouteBalances {
    trader: u128,
    leaving_protocol: u128,
    leaving_units: u128,
    staying_protocol: u128,
    staying_units: u128,
}

/// The cells [`RouteBalances`] reads, and every change it has seen in
/// them, stamped with the cluster's clock.
struct RouteLedger {
    trader: PrincipalAddr,
    /// The leaving venue's protocol and unit reserves, then the staying
    /// venue's.
    reserves: [SubstateKey; 4],
    seen: RefCell<Vec<(Duration, RouteBalances)>>,
}

impl RouteLedger {
    fn read<C: Cluster + ?Sized>(&self, c: &C) -> RouteBalances {
        let [
            leaving_protocol,
            leaving_units,
            staying_protocol,
            staying_units,
        ] = self.reserves.map(|reserve| held_at(c, reserve));
        RouteBalances {
            trader: held(c, self.trader.address(), *PROTOCOL_RESOURCE),
            leaving_protocol,
            leaving_units,
            staying_protocol,
            staying_units,
        }
    }

    /// Read the world and keep the reading where it differs from the
    /// last one kept.
    fn observe<C: Cluster + ?Sized>(&self, c: &C) -> RouteBalances {
        let now = self.read(c);
        let mut seen = self.seen.borrow_mut();
        if seen.last().is_none_or(|(_, last)| *last != now) {
            seen.push((c.now(), now));
        }
        now
    }
}

/// A route submitted across a late departure with one venue's
/// certificate intake cut, and everything the scenario reads it by.
struct OneWayRoute {
    ledger: RouteLedger,
    protocol_resource: World,
    units: World,
    charges: Charges,
    hash: TxHash,
    /// The survivor's drain before the route.
    baseline: TxsInFlight,
    activates_at: Epoch,
    /// What the world read before the route was submitted.
    opened: RouteBalances,
    /// What the trader held once its leg had paid.
    paid: u128,
    cut: FaultHandle,
    timeline: Vec<String>,
}

impl OneWayRoute {
    /// Stand both venues up, cast the late vote, cut `deaf`'s intake of
    /// `hearing`'s certificate, and submit the route, holding until both
    /// venues have committed it and the trader's leg has paid.
    fn submit<C: FaultableCluster>(c: &mut C, deaf: ShardId, hearing: ShardId) -> Self {
        let (departing, survivor) = (LATE_DEPARTING_VENUE, LATE_SURVIVOR_VENUE);
        let mut taken = Vec::new();
        let leaving = stand_up_venue(c, departing, &mut taken);
        let (grown_left, grown_right) = LATE_MERGED_PARENT.children();
        assert!(
            await_serves(c, grown_left, epochs(28)) && await_serves(c, grown_right, epochs(28)),
            "the grow's own split must have run before the route commits",
        );
        let staying = stand_up_venue(c, survivor, &mut taken);
        let (key, trader) = grind_onto(LATE_TRADER_SHARD, &mut taken);
        let reserves = [
            reserve_cell(&leaving.meta, *PROTOCOL_RESOURCE),
            reserve_cell(&leaving.meta, leaving.unit),
            reserve_cell(&staying.meta, *PROTOCOL_RESOURCE),
            reserve_cell(&staying.meta, staying.unit),
        ];
        let ledger = RouteLedger {
            trader,
            reserves,
            seen: RefCell::new(Vec::new()),
        };
        let mut protocol_resource = World::open(
            c,
            *PROTOCOL_RESOURCE,
            [trader.address()],
            [reserves[0], reserves[2]],
        );
        let mut units = World::open(
            c,
            leaving.unit,
            [trader.address()],
            [reserves[1], reserves[3]],
        );
        let opened = ledger.observe(c);

        let activates_at = cast_late_threshold_vote(c, LATE_SPLIT_BYTES, LATE_VOTE_LEAD_EPOCHS);
        let cut = isolate_ec_intake(c, deaf, hearing);
        let baseline = c
            .committed_txs_in_flight(survivor)
            .expect("the survivor must serve a committed tip before the route");
        let mut charges = Charges::default();
        let tx = build_route_tx(
            &key,
            trader,
            (&leaving.meta, &staying.meta),
            *PROTOCOL_RESOURCE,
            ROUTE_INPUT,
            0,
            validity_around(c.now()),
        );
        let records = crossing_records(
            &tx.try_derived(c.derivation().as_ref())
                .expect("a scenario route derives")
                .legs,
        );
        protocol_resource.owing(records.clone());
        units.owing(records);
        let hash = charges.submit(c, tx);
        let submitted = c.now();
        assert!(
            c.run_until(epochs(12), |c| {
                ledger.observe(c);
                c.chain_fate(survivor, hash).0.is_some()
                    && c.chain_fate(departing, hash).0.is_some()
            }),
            "both shards must commit the route while both are live",
        );
        assert!(
            c.run_until(epochs(8), |c| ledger.observe(c).trader
                < SWAPPER_FUNDING - ROUTE_INPUT),
            "the trader's leg must pay before the core is asked anything",
        );
        let paid = ledger.observe(c).trader;
        let timeline = vec![format!(
            "{:?}: submitted at {submitted:?}, both venues committed, the trader paid and holds \
             {paid}",
            c.now()
        )];
        Self {
            ledger,
            protocol_resource,
            units,
            charges,
            hash,
            baseline,
            activates_at,
            opened,
            paid,
            cut,
            timeline,
        }
    }

    /// Whether the late vote's threshold is the one in force.
    fn threshold_in_force<C: Cluster>(c: &C) -> bool {
        c.beacon_state()
            .is_some_and(|s| s.params.reshape_thresholds.split_bytes == LATE_SPLIT_BYTES)
    }

    /// Add a line to the timeline: the clock, `what` happened, where each
    /// chain stands on the route, and how far the departure has come.
    fn mark<C: Cluster>(&mut self, c: &C, what: &str) {
        let (departing, survivor) = (LATE_DEPARTING_VENUE, LATE_SURVIVOR_VENUE);
        let hash = self.hash;
        let boundary = c
            .beacon_state()
            .and_then(|s| s.boundaries.get(&departing).cloned());
        self.timeline.push(format!(
            "{:?}: {what}; verdicts: survivor {:?}, departing {:?}, successor {:?}; unsettled \
             records: survivor {:?}, trader's shard {:?}, successor {:?}; survivor in flight \
             {:?} against {:?}; epoch {:?}, vote activates at {:?}, threshold in force {}, \
             merge keepers {:?}, admitted at {:?}, terminal epoch {:?}",
            c.now(),
            c.chain_fate(survivor, hash).1,
            c.chain_fate(departing, hash).1,
            c.chain_fate(LATE_MERGED_PARENT, hash).1,
            c.named_unsettled(survivor, hash),
            c.named_unsettled(LATE_TRADER_SHARD, hash),
            c.named_unsettled(LATE_MERGED_PARENT, hash),
            c.committed_txs_in_flight(survivor),
            self.baseline,
            beacon_epoch(c),
            self.activates_at,
            Self::threshold_in_force(c),
            merge_keeper_count(c, LATE_MERGED_PARENT),
            boundary.as_ref().and_then(|b| b.reshape_admitted_epoch),
            boundary.as_ref().and_then(|b| b.terminal_epoch),
        ));
    }

    /// Run until `reached`, reading the ledger at every step.
    fn drive<C: Cluster>(&self, c: &mut C, budget: Budget, reached: impl Fn(&C) -> bool) -> bool {
        c.run_until(budget, |c| {
            self.ledger.observe(c);
            reached(c)
        })
    }

    /// Hold the cut from `hearing`'s verdict through the late vote's
    /// activation, the departure's admission and the departing venue's
    /// terminal, and lift it once the successor serves.
    fn depart_and_lift<C: FaultableCluster>(&mut self, c: &mut C, deaf: ShardId, hearing: ShardId) {
        let hash = self.hash;
        assert!(
            self.drive(c, epochs(12), |c| c.chain_fate(hearing, hash).1.is_some()),
            "{hearing} must reach a verdict",
        );
        self.mark(c, &format!("{hearing} finalized"));
        assert!(
            self.drive(c, epochs(28), Self::threshold_in_force),
            "the late vote must activate at {:?}",
            self.activates_at,
        );
        self.mark(c, "threshold in force");
        assert!(
            self.drive(c, epochs(28), |c| {
                merge_keeper_count(c, LATE_MERGED_PARENT).is_some_and(|keepers| keepers >= 3)
            }),
            "the activated threshold must pair the departing venue's shard with its sibling",
        );
        self.mark(c, "departure admitted");
        assert!(
            self.drive(c, epochs(28), |c| {
                c.chain_fate(LATE_DEPARTING_VENUE, hash).1.is_some()
            }),
            "the departing venue's chain must reach a verdict by its terminal",
        );
        self.mark(c, "the departing venue's chain holds a verdict");
        assert!(
            self.drive(c, epochs(28), |c| c.serves_shard(LATE_MERGED_PARENT)),
            "the merged parent must be served within budget",
        );
        let dropped = self.cut.fired();
        assert!(
            dropped > 0,
            "the cut must have dropped something, or {deaf} was never kept from {hearing}'s \
             certificate",
        );
        self.mark(
            c,
            &format!("successor serves, the cut lifts after dropping {dropped}"),
        );
        c.clear_drops();
    }

    /// Give the open network its budget to answer, then read the
    /// invariant three ways and name every reading that fails.
    fn assert_not_torn<C: Cluster>(mut self, c: &mut C) {
        let (departing, survivor) = (LATE_DEPARTING_VENUE, LATE_SURVIVOR_VENUE);
        // The drive ends early only where both sides of the pair balance
        // and the survivor holds nothing for the route, and a tail
        // follows either way, so a credit landing after the balance is
        // read too.
        let _ = self.drive(c, epochs(12), |c| {
            self.protocol_resource.settles(c, self.charges.burned(c))
                && self.units.settles(c, 0)
                && c.committed_txs_in_flight(survivor) == Some(self.baseline)
        });
        let _ = self.drive(c, epochs(2), |_| false);
        let closed = self.ledger.observe(c);
        self.mark(c, "closing");

        let accepted = |shard| {
            matches!(
                c.chain_fate(shard, self.hash).1,
                Some((_, TransactionDecision::Accept))
            )
        };
        let survivor_accepted = accepted(survivor);
        let departing_accepted = accepted(departing) || accepted(LATE_MERGED_PARENT);
        let output = self
            .opened
            .staying_protocol
            .saturating_sub(closed.staying_protocol);
        let (paid, regained) = (self.paid, closed.trader.saturating_sub(self.paid));
        let burned = self.charges.burned(c);
        let (protocol_before, protocol_held) = (
            self.protocol_resource.before(),
            self.protocol_resource.held(c),
        );
        let (units_before, units_held) = (self.units.before(), self.units.held(c));

        let mut failures = Vec::new();
        if survivor_accepted != departing_accepted {
            failures.push(format!(
                "VERDICT: the venues disagree — the survivor accepted: {survivor_accepted}, the \
                 departing venue or its successor accepted: {departing_accepted}"
            ));
        }
        if regained > ROUTE_INPUT.max(output) {
            failures.push(format!(
                "TRADER: the trader holds its input and the route's output — it paid down to \
                 {paid}, holds {}, and regained {regained} against an input of {ROUTE_INPUT} \
                 and an output of {output}",
                closed.trader
            ));
        }
        if protocol_held + burned != protocol_before {
            failures.push(format!(
                "PROTOCOL RESOURCE: the world held {protocol_before} before and {protocol_held} \
                 after, with {burned} burned"
            ));
        }
        if units_held != units_before {
            failures.push(format!(
                "UNITS: the world held {units_before} before and {units_held} after"
            ));
        }
        assert!(
            failures.is_empty(),
            "a route heard one way across a departure is torn:\n  {}\ntimeline:\n  {}\n\
             balances:\n  {}",
            failures.join("\n  "),
            self.timeline.join("\n  "),
            self.ledger
                .seen
                .borrow()
                .iter()
                .map(|(at, balances)| format!("{at:?}: {balances:?}"))
                .collect::<Vec<_>>()
                .join("\n  "),
        );
        let context = "a route heard one way across a departure";
        self.protocol_resource
            .assert_settled(c, &self.charges, context);
        self.units.assert_settled(c, &Charges::default(), context);
    }
}

/// The shared body of the two scenarios that cut one venue's certificate
/// intake across the other's late departure: `deaf` never obtains its
/// counterpart's certificate until the departed venue's successor serves,
/// while the counterpart obtains `deaf`'s by every road. A certificate
/// decides nothing on another shard, so the cut holds neither venue: each
/// reads the other's verdict in its state, and both settle the route
/// alike.
///
/// The invariant is the one a cross-shard core exists to keep, read
/// three ways once the cut has lifted and the world has had its budget
/// to answer: the two venues reach one verdict, the trader holds its
/// input or the route's output and never both, and each side of the pair
/// sums to what it did before. Every reading that fails is named
/// together, with the timeline that led to it.
///
/// # Panics
///
/// Panics if the grown topology does not settle, if the hearing venue
/// reaches no verdict, if the cut never fired, if the departure misses
/// its budget, or if any of the three readings fails.
fn a_route_heard_one_way_across_a_late_departure<C: FaultableCluster>(c: &mut C, deaf: ShardId) {
    let hearing = if deaf == LATE_DEPARTING_VENUE {
        LATE_SURVIVOR_VENUE
    } else {
        LATE_DEPARTING_VENUE
    };
    let mut route = OneWayRoute::submit(c, deaf, hearing);
    route.depart_and_lift(c, deaf, hearing);
    route.assert_not_torn(c);
}

/// A route whose surviving venue heard its departing counterpart, and
/// was never heard back, settles on both venues or on neither.
///
/// [`a_route_committed_before_its_departure_was_voted_still_resolves`]
/// with the certificate channel cut one way: the survivor obtains the
/// departing venue's certificate by every road, the departing venue
/// obtains the survivor's by none, and the cut lifts once the departed
/// venue's successor serves. Each venue still reads the other's verdict
/// in its state.
///
/// # Panics
///
/// As [`a_route_heard_one_way_across_a_late_departure`].
pub fn a_route_only_the_survivor_heard_settles_on_both_venues_or_neither<C: FaultableCluster>(
    c: &mut C,
) {
    a_route_heard_one_way_across_a_late_departure(c, LATE_DEPARTING_VENUE);
}

/// A route whose departing venue heard its surviving counterpart, and
/// was never heard back, settles on both venues or on neither.
///
/// The mirror of
/// [`a_route_only_the_survivor_heard_settles_on_both_venues_or_neither`]:
/// the departing venue obtains the survivor's certificate by every road
/// and the survivor obtains the departing venue's by none until the
/// successor serves.
///
/// # Panics
///
/// As [`a_route_heard_one_way_across_a_late_departure`].
pub fn a_route_only_the_departing_venue_heard_settles_on_both_venues_or_neither<
    C: FaultableCluster,
>(
    c: &mut C,
) {
    a_route_heard_one_way_across_a_late_departure(c, LATE_SURVIVOR_VENUE);
}

/// A route through a departing venue releases the surviving venue's
/// hold at the terminal and gives the trader its input back.
///
/// A route's two venues are one core, each awaiting the other's
/// verdict, so a route is the shape that still holds work across a
/// shard's terminal: the trader's leg pays and settles alone, and the
/// two venue rows wait. With each venue cut off from the other's state
/// and certificates both ways, neither ever reads the other's yes: each
/// states its own and stands, the departing venue's terminal fates its
/// row, and the survivor's stated row stays engaged against its drain
/// until it reads the departed sibling's ended names, which do not
/// name the route. Then the survivor aborts the core member, the drain
/// returns to its baseline, and the trader's crossing is reclaimed.
/// Neither reserve moves.
///
/// # Panics
///
/// Panics as [`departing_route`] and [`submit_departing_route`] do, and
/// if the hold does not return to its baseline or the input to the
/// trader after the terminal, if the route is not abandoned, if a
/// reserve moves, or if either side of the pair is not conserved.
pub fn a_route_into_a_departing_venue_releases_the_survivors_hold<C: FaultableCluster>(c: &mut C) {
    let (departing, survivor) = (FIRST_VENUE_SHARD, SECOND_VENUE_SHARD);
    let mut route = departing_route(c);
    // Neither venue may read the other's verdict or hold its
    // certificate. Provisions and headers still flow, so each venue
    // commits the route and runs its own core leg, which is the state
    // under test.
    let cut = [
        isolate_ec_intake(c, departing, survivor),
        isolate_ec_intake(c, survivor, departing),
        isolate_crossing_intake(c, departing, survivor),
        isolate_crossing_intake(c, survivor, departing),
    ];
    let mut charges = Charges::default();
    let (hash, baseline, paid) = submit_departing_route(c, &mut route, &mut charges);

    // The cut. The departing venue's cells land under a child, and its
    // settled set reaches the survivor.
    await_departed(c);
    // The departing venue's core never heard its sibling, so its row
    // stood stated at the terminal, which fates it; neither child reads
    // its row as its own.
    let (left, right) = departing.children();
    assert!(
        await_anchor_seeded(c, left, epochs(6)),
        "the beacon must compose the departed venue's children's anchor",
    );
    let terminal = terminal_height(c, departing);
    assert_eq!(
        Some(assert_fated_off(c, departing, hash, &[left, right])),
        terminal,
        "the departing venue's terminal must fate the route's core",
    );
    assert!(
        c.run_until(epochs(12), |c| c.committed_txs_in_flight(survivor)
            == Some(baseline)),
        "the survivor's hold must return to its baseline once the departed venue's ended \
         names have answered; holds {:?} against {baseline:?}",
        c.committed_txs_in_flight(survivor),
    );
    // The trader's reclaim is licensed by whichever lands first: the
    // abandonment record naming the route, or the `Never` the shard
    // holding the departed venue's prefix writes for the record no
    // member there took. Either reads the record cell the trader's leg
    // wrote, whenever it lands, because a record is value and value is
    // not swept on a clock. Neither licence is a probe, so no window
    // bounds it: the input comes back however long the departure took,
    // on either epoch clock.
    assert!(
        c.run_until(epochs(12), |c| held(
            c,
            route.trader.address(),
            *PROTOCOL_RESOURCE
        ) == paid + ROUTE_INPUT),
        "the trader must get the route's input back once the departed venue's side is \
         answered; holds {} against {}",
        held(c, route.trader.address(), *PROTOCOL_RESOURCE),
        paid + ROUTE_INPUT,
    );
    // The trader's own leg accepted and stays accepted; the core it
    // fed is abandoned on both shards, never settled one-sided.
    assert_neither_venue_settled(c, &cut, hash, [departing, survivor]);
    // And nobody is told otherwise. Each venue stated a yes, which is
    // not the route accepted: the core never combined, and the trader's
    // chain reclaimed its input, which every replica of it reads as the
    // abort — one that never held the leg's entry as well as one that
    // did.
    let decisions = shard_decisions(c, hash);
    assert!(
        decisions
            .values()
            .all(|decision| *decision != TransactionDecision::Accept),
        "no shard may report accepted a route its chain reclaimed; reported {decisions:?}",
    );
    assert!(
        decisions
            .get(&TRADER_SHARD)
            .is_none_or(|decision| *decision == TransactionDecision::Aborted),
        "the trader's chain reclaimed the route's input, which is the abort; reported \
         {decisions:?}",
    );
    for (reserve, before) in route.reserves.into_iter().zip(route.stocked) {
        assert_eq!(
            held_at(c, reserve),
            before,
            "neither venue may have applied its side of a route whose verdict it never read",
        );
    }
    c.clear_drops();
    // And conserved outright: nothing of the route is stranded, because
    // nothing it issued was swept out from under its reclaim.
    assert!(
        c.run_until(epochs(8), |c| route
            .protocol_resource
            .settles(c, charges.burned(c))),
        "a route through a departing venue: the world must settle against the burn alone",
    );
    route
        .protocol_resource
        .assert_settled(c, &charges, "a route through a departing venue");
    charges.assert_each_fits_a_full_block(c);
    route.units.assert_settles_within(
        c,
        &Charges::default(),
        epochs(8),
        "a route through a departing venue",
    );
}

/// A record whose consumer's shard departed with the record untaken is
/// declined by the successor holding the consumer's prefix.
///
/// [`a_route_into_a_departing_venue_releases_the_survivors_hold`], read
/// at the crossing: the departing venue committed the route and its
/// terminal fated the core, so no member of the route ever took the
/// trader's input and no refusal of it was ever written. The record
/// stands on the trader's shard and is pushed, past its transaction's
/// validity end, to whichever shard holds the venue's prefix: after the
/// cut, a child that never committed the route and holds no row of it.
/// That child's fold writes the `Never`, seen and naming the route, and
/// the trader's shard takes the input back on it.
///
/// # Panics
///
/// Panics as [`departing_route`] and [`submit_departing_route`] do, and
/// if the departing venue's terminal does not fate the route's core, if
/// no successor declines the record, if the decline is a refusal's or
/// names another transaction, or if the input does not come home.
pub fn a_record_whose_consumers_shard_departed_is_declined_by_its_successor<C: FaultableCluster>(
    c: &mut C,
) {
    let (departing, survivor) = (FIRST_VENUE_SHARD, SECOND_VENUE_SHARD);
    let mut route = departing_route(c);
    let cut = [
        isolate_ec_intake(c, departing, survivor),
        isolate_ec_intake(c, survivor, departing),
        isolate_crossing_intake(c, departing, survivor),
        isolate_crossing_intake(c, survivor, departing),
    ];
    let mut charges = Charges::default();
    let (hash, _, paid) = submit_departing_route(c, &mut route, &mut charges);
    let (record, id) = escrowed_into(c, &charges.records(c), departing);
    let decline = id.answer_key(&ProtocolHasher, Answered::Never);

    await_departed(c);
    let (left, right) = departing.children();
    assert!(
        await_anchor_seeded(c, left, epochs(6)),
        "the beacon must compose the departed venue's children's anchor",
    );
    assert_eq!(
        Some(assert_fated_off(c, departing, hash, &[left, right])),
        terminal_height(c, departing),
        "the departing venue's terminal must fate the route's core",
    );
    assert!(
        c.run_until(epochs(12), |c| answer_standing(c, decline).is_some()),
        "the successor holding the venue's prefix must decline the record",
    );
    let successor = owning_shard(c, decline.owner);
    assert!(
        [left, right].contains(&successor),
        "the decline stands under a child of the departed venue's shard, not {successor:?}",
    );
    let answer = answer_standing(c, decline).expect("the decline stands");
    assert_eq!(
        (answer.answered, answer.tx, answer.seen),
        (Answered::Never, hash, true),
        "the fold's decline names the route and is written seen",
    );
    assert!(
        c.declined(departing, hash).is_empty() && c.declined(successor, hash).is_empty(),
        "no member of the route refused the input: the decline is the successor's fold's",
    );
    assert!(
        c.chain_fate(successor, hash).0.is_none(),
        "the successor never committed the route",
    );
    assert!(
        cut.iter().any(|handle| handle.fired() > 0),
        "the certificate channel must actually have been exercised and cut",
    );
    assert!(
        c.run_until(epochs(12), |c| held(
            c,
            route.trader.address(),
            *PROTOCOL_RESOURCE
        ) == paid + ROUTE_INPUT),
        "the trader must get the route's input back on the successor's decline; holds {} \
         against {}",
        held(c, route.trader.address(), *PROTOCOL_RESOURCE),
        paid + ROUTE_INPUT,
    );
    assert!(!stands_at(c, record), "and the record is gone with it");
    c.clear_drops();
    assert!(
        c.run_until(epochs(8), |c| route
            .protocol_resource
            .settles(c, charges.burned(c))),
        "a record its consumer's successor declined: the world must settle against the burn",
    );
    route.units.assert_settles_within(
        c,
        &Charges::default(),
        epochs(8),
        "a record its consumer's successor declined",
    );
}

/// A route the departing venue settled is settled by the surviving venue
/// too, from the names the departed chain's terminal ended.
///
/// The mirror of
/// [`a_route_into_a_departing_venue_releases_the_survivors_hold`]: the
/// cut takes only the survivor's intake, so the departing venue reads
/// the survivor's yes and accepts, applying its half, while the
/// survivor never reads the departing venue's verdict and stands
/// stated. The departing venue's accepted row stands until its terminal
/// ends it, and that `End` line is the one place the departed chain
/// still says it accepted: once the departing venue leaves the trie,
/// the survivor reads it in the terminal's lines, which name the route,
/// and accepts. The cut lifts once the children seat, so what is
/// measured is the departed sibling's reading and not a partition, and
/// the route banks its output.
///
/// # Panics
///
/// Panics as [`departing_route`] and [`submit_departing_route`] do, and
/// if the departing venue does not settle the route before it leaves,
/// if the survivor never applies what the departed venue settled, if
/// its hold does not return to its baseline, or if either side of the
/// pair is not conserved.
pub fn a_route_the_departing_venue_settled_is_settled_by_the_survivor<C: FaultableCluster>(
    c: &mut C,
) {
    let (departing, survivor) = (FIRST_VENUE_SHARD, SECOND_VENUE_SHARD);
    let mut route = departing_route(c);
    let cut = [
        isolate_ec_intake(c, survivor, departing),
        isolate_crossing_intake(c, survivor, departing),
    ];
    let mut charges = Charges::default();
    let (hash, baseline, paid) = submit_departing_route(c, &mut route, &mut charges);
    assert!(
        c.run_until(epochs(12), |c| matches!(
            c.chain_fate(departing, hash).1,
            Some((_, TransactionDecision::Accept))
        )),
        "the departing venue reads the survivor's yes and settles the route before it leaves",
    );
    assert!(
        c.chain_fate(survivor, hash).1.is_none(),
        "the survivor never read the departing venue's verdict and cannot apply yet",
    );

    await_departed(c);
    assert!(
        cut.iter().all(|handle| handle.fired() > 0),
        "the survivor's intake must actually have been exercised and cut, or it read the \
         departed venue's verdict all along",
    );
    c.clear_drops();
    assert!(
        c.run_until(epochs(12), |c| matches!(
            c.chain_fate(survivor, hash).1,
            Some((_, TransactionDecision::Accept))
        )),
        "the survivor must read the departed venue's accept in its terminal's ended names and \
         apply what it settled",
    );
    assert!(
        c.run_until(epochs(12), |c| c.committed_txs_in_flight(survivor)
            == Some(baseline)),
        "the survivor's hold must return to its baseline once it has settled; holds {:?} \
         against {baseline:?}",
        c.committed_txs_in_flight(survivor),
    );
    // The output is owed to the trader: nothing closes its window and
    // nothing takes it back, and the trader's fold banks it whenever the
    // record's reading lands.
    assert!(
        c.run_until(epochs(8), |c| {
            held(c, route.trader.address(), *PROTOCOL_RESOURCE) > paid
        }),
        "the route must bank its output for the trader; holds {} against {paid}",
        held(c, route.trader.address(), *PROTOCOL_RESOURCE),
    );
    route.protocol_resource.assert_settles_within(
        c,
        &charges,
        epochs(8),
        "a route settled across a departure",
    );
    route.units.assert_settles_within(
        c,
        &Charges::default(),
        epochs(8),
        "a route settled across a departure",
    );
}

/// A train of transfers into a shard across its split's admission strands
/// nothing: each reaches the fate its phase owes it, and the train's
/// accounts are conserved throughout.
///
/// The payers sit on the survivor and the recipients on the splitter.
/// A transfer every few blocks from before the vote until the splitter
/// has coasted, so the train holds every [`Phase`] — transfers the payer
/// committed before the admission fold, ones committed while the split
/// pended, and ones the coasting splitter never included — and, around
/// the fold, the pair whose payer committed on one side of it and whose
/// delivery landed on the other. A transfer the splitter settled credits
/// its recipient once; one its terminal overtook, included or not,
/// credits its recipient exactly when the payer accepted it and a chain
/// holding the recipient delivered it, and never otherwise.
///
/// # Panics
///
/// Panics if the train misses any phase or never reaches the coast, if a
/// transfer's credit disagrees with its verdict, or if the train's
/// accounts are not conserved.
pub fn a_train_into_a_splitter_strands_nothing<C: Cluster>(c: &mut C) {
    let splitter = STRADDLER_SPLITTER;
    let setup = split_train_setup(SPLIT_TRAIN);
    split_lifecycle(c);
    let mut world = train_world(c, &setup.legs);
    let mut charges = Charges::default();

    let sent = drive_train(
        c,
        splitter,
        &setup.legs,
        &mut charges,
        &mut world,
        |c| split_admitted(c, splitter),
        |c| cast_splitter_vote(c, straddler_split_bytes()),
    );

    let children = <[ShardId; 2]>::from(splitter.children());
    assert_train_fates(c, splitter, &children, &sent, &world);
    world.assert_settles_within(c, &charges, epochs(8), "a train across a split's admission");
}

/// A train of transfers into a shard across its merge's pairing strands
/// nothing: each reaches the fate its phase owes it, and the train's
/// accounts are conserved throughout.
///
/// [`a_train_into_a_splitter_strands_nothing`] across the other reshape.
/// The payers sit on the surviving quarter and the recipients on the
/// merge-left child, which the grown topology's byte skew pairs with its
/// sibling from the grow alone. A transfer every few blocks from before
/// the pairing until the merging child has coasted, so the train holds
/// every [`Phase`]: transfers committed before the pairing fold, ones
/// committed while the merge pended, and ones the coasting child never
/// included, which the merged parent delivers once the cut has landed
/// the recipient's prefix there. Requires the [`merge_train_setup`]
/// funding on a config grown to four shards.
///
/// # Panics
///
/// Panics if the grown topology does not seat every quarter, if the
/// train misses any phase or never reaches the coast, if a transfer's
/// credit disagrees with its verdict, or if the train's accounts are not
/// conserved.
pub fn a_train_into_a_merging_shard_strands_nothing<C: Cluster>(c: &mut C) {
    let merging = MERGE_STRADDLER_LEFT;
    let parent = merging.parent().expect("a depth-2 leaf has a parent");
    let setup = merge_train_setup(MERGE_TRAIN);
    assert!(
        (0..4).all(|path| await_serves(c, ShardId::leaf(2, path), epochs(4))),
        "the grown four-shard topology must seat every quarter",
    );
    let mut world = train_world(c, &setup.legs);
    let mut charges = Charges::default();

    let sent = drive_train(
        c,
        merging,
        &setup.legs,
        &mut charges,
        &mut world,
        |c| merge_keeper_count(c, parent).is_some(),
        |_| {},
    );

    assert_train_fates(c, merging, &[parent], &sent, &world);
    world.assert_settles_within(c, &charges, epochs(8), "a train across a merge's pairing");
}

/// Everything a train can reach: each leg's payer and recipient. The
/// ballast holds the byte skew and never spends.
fn train_world<C: Cluster>(
    c: &C,
    legs: &[(Ed25519PrivateKey, PrincipalAddr, PrincipalAddr)],
) -> World {
    World::open(
        c,
        *PROTOCOL_RESOURCE,
        legs.iter()
            .flat_map(|(_, from, to)| [from.address(), to.address()]),
        [],
    )
}

/// Send `legs` into `terminating` every few blocks until its reshape has
/// drained and several more have gone after it, recording the phase each
/// went in — and sooner than that wherever a phase nothing has covered
/// opens, so the coverage the train exists for does not turn on the
/// reshape's timing. `pending` reads whether the reshape is admitted and
/// pending; `arm` runs once the cadence is measured, before the second
/// leg — where a scenario casts the vote that starts its reshape.
///
/// # Panics
///
/// Panics if the train ends without a transfer sent in every [`Phase`].
fn drive_train<C: Cluster>(
    c: &mut C,
    terminating: ShardId,
    legs: &[(Ed25519PrivateKey, PrincipalAddr, PrincipalAddr)],
    charges: &mut Charges,
    world: &mut World,
    pending: impl Fn(&C) -> bool,
    arm: impl FnOnce(&mut C),
) -> Vec<(TxHash, PrincipalAddr, Phase)> {
    // Block cadence is activity-driven, so the spacing is measured off
    // the first leg rather than assumed.
    let mut legs = legs.iter();
    let mut sent: Vec<(TxHash, PrincipalAddr, Phase)> = Vec::new();
    let mut admitted_once = false;
    let height = |c: &C| {
        c.committed_height(terminating)
            .map_or(0, BlockHeight::inner)
    };
    send_leg(
        c,
        legs.next().expect("a funded leg"),
        charges,
        world,
        &mut sent,
        &mut admitted_once,
        &pending,
    );
    let spacing = (measure_blocks_per_epoch(c, terminating) / TRAIN_PER_EPOCH).max(1);

    arm(c);

    let mut draining = 0;
    for leg in legs {
        if send_leg(
            c,
            leg,
            charges,
            world,
            &mut sent,
            &mut admitted_once,
            &pending,
        ) == Phase::Draining
        {
            draining += 1;
            if draining >= PAST_THE_GATE {
                break;
            }
        }
        // The spacing is what the train rides, and phase coverage is
        // what it is for: a phase narrower than the spacing would get no
        // leg at all, and the assertion below would fail on the reshape's
        // timing rather than on anything the train measures. So the wait
        // ends early the moment a phase nothing has been sent in opens.
        let from_height = height(c);
        let covered: Vec<Phase> = sent.iter().map(|(_, _, phase)| *phase).collect();
        let seen_admitted = admitted_once;
        c.run_until(epochs(2), |c| {
            height(c) >= from_height + spacing
                || !covered.contains(&phase_of(pending(c), seen_admitted))
        });
    }
    for phase in [Phase::Live, Phase::Departing, Phase::Draining] {
        assert!(
            sent.iter().any(|(_, _, sent_in)| *sent_in == phase),
            "the train has to hold a transfer sent {phase:?}, or that phase's fate goes unread; \
             sent = {:?}",
            sent.iter().map(|(_, _, phase)| *phase).collect::<Vec<_>>(),
        );
    }
    sent
}

/// Every transfer's fate, once `terminating` has reached its terminal and
/// nothing more can be included: a recipient is credited exactly when its
/// payer's transfer was accepted, by the fold of whichever chain held its
/// prefix when the record's reading landed — the leaving shard or a
/// successor — and no chain holding the recipient ever includes the
/// transfer. Nothing accepted is left standing in its record.
///
/// # Panics
///
/// Panics if a successor is not served within budget, if a chain holding
/// the recipient includes a transfer, if a credit disagrees with a
/// verdict, or if an accepted payment is left standing.
fn assert_train_fates<C: Cluster>(
    c: &mut C,
    terminating: ShardId,
    successors: &[ShardId],
    sent: &[(TxHash, PrincipalAddr, Phase)],
    world: &World,
) {
    for &successor in successors {
        assert!(
            await_serves(c, successor, epochs(28)),
            "successor {successor} must be served within budget",
        );
    }
    for (hash, to, phase) in sent {
        let status = await_tx_terminal(c, *hash, epochs(12));
        let credited = match status {
            Some(TransactionStatus::Completed(TransactionDecision::Accept)) => {
                10 + STRADDLER_PAYMENT
            }
            Some(TransactionStatus::Completed(TransactionDecision::Aborted)) => 10,
            other => panic!("a transfer sent {phase:?} reached {other:?}, tx = {hash}"),
        };
        assert!(
            c.run_until(epochs(8), |c| held(c, to.address(), *PROTOCOL_RESOURCE)
                == credited),
            "a recipient of a transfer sent {phase:?} and {status:?} must hold {credited}; \
             holds {}",
            held(c, to.address(), *PROTOCOL_RESOURCE),
        );
        for shard in std::iter::once(terminating).chain(successors.iter().copied()) {
            assert!(
                c.chain_fate(shard, *hash).0.is_none(),
                "a chain holding the recipient never includes a transfer it only takes \
                 delivery of; {shard} included one sent {phase:?}",
            );
        }
    }
    let standing = world.standing(c);
    assert!(
        standing.is_empty(),
        "every accepted payment is credited, and nothing stands in its record; \
         standing = {standing:?}",
    );
}

/// Submit one of the train's legs, recording the leaving shard's phase
/// when it went. The reshape shows as pending from its admission until
/// the gate drains, so a shard once admitted and no longer pending is
/// draining.
/// Which phase a shard is in, from whether its reshape pends now and
/// whether one ever has.
///
/// Read without sending anything, so the train can wait on a phase
/// opening as well as record the one a leg went in.
const fn phase_of(pending: bool, admitted_once: bool) -> Phase {
    match (pending, admitted_once) {
        (true, _) => Phase::Departing,
        (false, false) => Phase::Live,
        (false, true) => Phase::Draining,
    }
}

fn send_leg<C: Cluster>(
    c: &mut C,
    (key, from, to): &(Ed25519PrivateKey, PrincipalAddr, PrincipalAddr),
    charges: &mut Charges,
    world: &mut World,
    sent: &mut Vec<(TxHash, PrincipalAddr, Phase)>,
    admitted_once: &mut bool,
    pending: impl Fn(&C) -> bool,
) -> Phase {
    let pending = pending(c);
    *admitted_once |= pending;
    let phase = phase_of(pending, *admitted_once);
    let tx = build_transfer_tx(key, *from, *to, STRADDLER_PAYMENT, validity_around(c.now()));
    // A leg the cut costs its delivery leaves its crossing owed,
    // standing in the record until the successor holding the
    // recipient's prefix claims it. That is value the world still
    // holds.
    world.owing(crossing_records(
        &tx.try_derived(c.derivation().as_ref())
            .expect("a scenario transfer derives")
            .legs,
    ));
    sent.push((charges.submit(c, tx), *to, phase));
    phase
}

/// A swap after the cut divides against the venue's child and settles:
/// the caller banks its output and the child claims the input.
fn swap_against_the_child<C: Cluster>(
    c: &mut C,
    venue: &StockedVenue,
    (key, caller): &(Ed25519PrivateKey, PrincipalAddr),
    charges: &mut Charges,
    claimed: u128,
    budget: Budget,
) {
    let swap = build_swap_tx(
        key,
        *caller,
        &venue.meta,
        *PROTOCOL_RESOURCE,
        SWAP_INPUT,
        0,
        validity_around(c.now()),
    );
    let hash = charges.submit(c, swap);
    let status = await_tx_terminal(c, hash, budget);
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "a swap against the venue's child must settle; status = {status:?}",
    );
    assert!(
        c.run_until(budget, |c| held(c, caller.address(), venue.unit) > 0),
        "the post-cut swap's output never reached its caller",
    );
    assert_eq!(
        held_at(c, reserve_cell(&venue.meta, *PROTOCOL_RESOURCE)),
        claimed + SWAP_INPUT,
        "the venue's child claims the post-cut input",
    );
}
