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

use std::time::Duration;

use hyperscale_engine::XRD;
use hyperscale_types::{
    BlockHeight, Deadline, Ed25519PrivateKey, EpochWindows, PrincipalAddr, ShardId, SubstateKey,
    TimestampRange, TransactionDecision, TransactionStatus, TxHash, WeightedTimestamp, Window,
    WorkInFlight,
};

use crate::reshape::split_lifecycle;
use crate::route::{FIRST_VENUE_SHARD, ROUTE_INPUT, SECOND_VENUE_SHARD, TRADER_SHARD};
use crate::straddler::{
    STRADDLER_PAYMENT, cast_splitter_vote, cast_threshold_vote, isolate_ec_intake,
    split_bytes_over, straddler_split_bytes, vote_splitter_down_to,
};
use crate::support::conservation::{Charges, World};
use crate::support::query::{
    anchored_genesis_height, epoch_duration_ms, held, held_at, merge_keeper_count,
    scheduled_terminal_epoch, split_admitted,
};
use crate::support::tx::{
    MERGE_STRADDLER_LEFT, MERGE_STRADDLER_SURVIVOR, STRADDLER_SPLITTER, STRADDLER_SURVIVOR,
    build_route_tx, build_swap_tx, build_transfer_tx, fixture_flash_bytes,
    merge_survivor_ballast_accounts, merge_train_setup, quarter_ballast_over,
    split_ballast_accounts_over, split_train_setup, validity_around,
};
use crate::support::wait::{
    await_anchor_seeded, await_merge_keeper_count, await_serves, await_split_admitted,
    await_tx_terminal,
};
use crate::support::{Budget, Cluster, FaultableCluster, epochs};
use crate::venue::{
    PROVIDER_FUNDING, SWAP_INPUT, SWAPPER_FUNDING, StockedVenue, grind_onto, reserve_cell,
    stand_up_venue, swappers_on, venue_genesis_accounts_on,
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

/// The byte skew for [`a_departing_venue_clears_swaps_and_carries_on`]:
/// the survivor holds the fixture flash, so the splitter's ballast leads
/// that rather than the protocol's alone.
#[must_use]
pub fn departing_venue_ballast() -> Vec<(PrincipalAddr, u128)> {
    split_ballast_accounts_over(fixture_flash_bytes())
}

/// The reshape trigger [`a_departing_venue_clears_swaps_and_carries_on`]
/// arms at genesis: above each child of the ballasted root and below the
/// root itself, on the fixture flash's scale.
#[must_use]
pub fn departing_venue_split_bytes() -> u64 {
    fixture_flash_bytes() + 30_000
}

/// Genesis funding for the departing-route scenarios.
///
/// On the four-shard route topology: ballast putting the first venue's
/// quarter alone over the threshold the scenarios vote in, a provider on
/// each venue's shard, and the trader on its own, ground in the order
/// [`departing_route`] stands them up.
#[must_use]
pub fn departing_route_genesis_accounts() -> Vec<(PrincipalAddr, u128)> {
    let mut accounts = quarter_ballast_over(FIRST_VENUE_SHARD, fixture_flash_bytes());
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
    let reserve = reserve_cell(&venue.meta, *XRD);
    let stocked = held_at(c, reserve);
    assert!(
        stocked > 0,
        "the venue has to be holding something to price against"
    );

    let holders: Vec<_> = swappers
        .iter()
        .map(|(_, account)| account.address())
        .collect();
    let xrd = World::open(c, *XRD, holders.iter().copied(), [reserve]);
    let units = World::open(
        c,
        venue.unit,
        holders,
        [reserve_cell(&venue.meta, venue.unit)],
    );
    let mut charges = Charges::default();

    // The venue's shard is leaving from here to the cut.
    vote_splitter_down_to(c, split_bytes_over(fixture_flash_bytes()));

    let (leaving, later) = swappers.split_at(swappers.len() - 1);
    let mut submitted: Vec<TxHash> = Vec::new();
    for (key, caller) in leaving {
        let swap = build_swap_tx(
            key,
            *caller,
            &venue.meta,
            *XRD,
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
        anchored_genesis_height(c, left).is_some(),
        "the children's seeded genesis pins the venue's cells under a child",
    );
    assert_eq!(
        held_at(c, reserve),
        claimed,
        "the venue's reserve must carry across the cut untouched",
    );

    swap_against_the_child(c, &venue, &later[0], &mut charges, claimed, budget);

    xrd.assert_settles_within(c, &charges, budget, "swaps across the venue's split");
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
/// The callers' shard carries the lead, so the flash-holding venue shard
/// stays under the threshold the scenario votes in.
#[must_use]
pub fn departing_caller_ballast() -> Vec<(PrincipalAddr, u128)> {
    split_ballast_accounts_over(fixture_flash_bytes())
}

/// A venue that stays, callers on the shard that is leaving, and the
/// worlds a swap between them can reach.
struct DepartingCallers {
    venue: StockedVenue,
    swappers: Vec<(Ed25519PrivateKey, PrincipalAddr)>,
    reserve: SubstateKey,
    stocked: u128,
    xrd: World,
    units: World,
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
    vote_splitter_down_to(c, split_bytes_over(fixture_flash_bytes()));
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
    let reserve = reserve_cell(&venue.meta, *XRD);
    let stocked = held_at(c, reserve);
    assert!(
        stocked > 0,
        "the venue has to be holding something to price against"
    );
    let holders: Vec<_> = swappers
        .iter()
        .map(|(_, account)| account.address())
        .collect();
    let xrd = World::open(c, *XRD, holders.iter().copied(), [reserve]);
    let units = World::open(
        c,
        venue.unit,
        holders,
        [reserve_cell(&venue.meta, venue.unit)],
    );
    DepartingCallers {
        venue,
        swappers,
        reserve,
        stocked,
        xrd,
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
        reserve,
        stocked,
        xrd,
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
            *XRD,
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

    xrd.assert_settles_within(c, &charges, budget, "swaps across the callers' cut");
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
pub fn a_leg_issued_on_a_merging_shard_reaches_its_venue(c: &mut impl Cluster, budget: Budget) {
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
    // blocks to its terminal — so a stream spaced across the coast lands
    // on both sides of it.
    assert!(
        c.run_until(budget, |c| !split_admitted(c, venue_shard)),
        "the venue's reshape gate must drain before the stream goes",
    );
    let mut stream: Vec<(TxHash, PrincipalAddr)> = Vec::new();
    for (key, caller) in &set.swappers {
        let swap = build_swap_tx(
            key,
            *caller,
            &set.venue.meta,
            *XRD,
            SWAP_INPUT,
            0,
            validity_around(c.now()),
        );
        stream.push((charges.submit(c, swap), *caller));
        c.run_until(epochs(1), |_| false);
    }
    await_cut(c, venue_shard);

    let (left, right) = venue_shard.children();
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
    set.xrd
        .assert_settles_within(c, &charges, budget, "swaps across the venue's terminal");
    set.units.assert_settles_within(
        c,
        &Charges::default(),
        budget,
        "swaps across the venue's terminal",
    );
}

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

/// The cluster's clock as the weighted timestamp a block anchored now
/// carries.
fn clock<C: Cluster + ?Sized>(c: &C) -> WeightedTimestamp {
    WeightedTimestamp::ZERO.plus(c.now())
}

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
    assert!(
        c.run_until(budget, |c| scheduled_terminal_epoch(c, venue_shard)
            .is_some()),
        "the beacon must schedule the venue's cut",
    );
    let terminal = scheduled_terminal_epoch(c, venue_shard).expect("scheduled above");
    let epoch_ms = epoch_duration_ms(c).expect("the beacon carries its epoch length");
    let cut = EpochWindows::new(epoch_ms).window_of(terminal).end;
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
        *XRD,
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

    let paid_before = held(c, caller.address(), *XRD);
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
        c.run_until(budget, |c| anchored_genesis_height(c, left).is_some()),
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
    set.xrd.assert_settles_within(
        c,
        &charges,
        budget,
        "a swap committed after the venue's cut",
    );
    assert_eq!(
        held(c, caller.address(), *XRD),
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

/// Genesis funding for [`a_leg_issued_on_a_merging_shard_reaches_its_venue`].
///
/// The merge topology's byte skew, the venue's provider on a surviving
/// quarter, and the callers on the merge-left child — so the pair that
/// merges is the callers', and the venue's shard never reshapes.
#[must_use]
pub fn merging_caller_genesis_accounts() -> Vec<(PrincipalAddr, u128)> {
    let mut accounts = merge_survivor_ballast_accounts();
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
        anchored_genesis_height(c, left).is_some(),
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
    xrd: World,
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
        reserve_cell(&leaving.meta, *XRD),
        reserve_cell(&staying.meta, *XRD),
    ];
    let stocked = reserves.map(|reserve| held_at(c, reserve));
    assert!(
        stocked.iter().all(|&held| held > 0),
        "both venues have to be holding something to price against"
    );
    let xrd = World::open(c, *XRD, [trader.address()], reserves);
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
    cast_threshold_vote(c, split_bytes_over(fixture_flash_bytes()));
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
        xrd,
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
    route: &DepartingRoute,
    charges: &mut Charges,
) -> (TxHash, WorkInFlight, u128, WeightedTimestamp) {
    let (departing, survivor) = (FIRST_VENUE_SHARD, SECOND_VENUE_SHARD);
    let baseline = c
        .committed_work_in_flight(survivor)
        .expect("the survivor must serve a committed tip before the route");
    let validity = validity_around(c.now());
    let tx = build_route_tx(
        &route.key,
        route.trader,
        (&route.leaving.meta, &route.staying.meta),
        *XRD,
        ROUTE_INPUT,
        0,
        validity,
    );
    let hash = charges.submit(c, tx);
    assert!(
        c.run_until(epochs(12), |c| c.chain_fate(survivor, hash).0.is_some()
            && c.chain_fate(departing, hash).0.is_some()),
        "both shards must commit the route while both are live",
    );
    let engaged = c
        .committed_work_in_flight(survivor)
        .expect("the survivor must serve a committed tip once it holds the route");
    assert!(
        engaged > baseline,
        "the route must engage a hold against the survivor's drain, or its release below \
         proves nothing; baseline = {baseline:?}, engaged = {engaged:?}",
    );
    assert!(
        c.run_until(epochs(8), |c| held(c, route.trader.address(), *XRD)
            < SWAPPER_FUNDING - ROUTE_INPUT),
        "the trader's leg must pay before the core is asked anything",
    );
    (
        hash,
        baseline,
        held(c, route.trader.address(), *XRD),
        validity.end_timestamp_exclusive,
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

/// A route through a departing venue releases the surviving venue's
/// hold at the terminal and gives the trader its input back.
///
/// A route's two venues are one core, each awaiting the other's
/// certificate, so a route is the shape that still holds work across a
/// shard's terminal: the trader's leg pays and settles alone, and the
/// two venue ticks wait. With the certificate channel cut both ways
/// neither venue ever holds the other's, the departing venue abandons
/// at its deadline and terminates having settled nothing, and the
/// survivor's tick — fenced on the departing shard's settled set from
/// the admission — stays engaged against the survivor's drain until that
/// set arrives. Then the abandonment record speaks: the survivor abandons
/// the core member, the drain returns to its baseline, and the trader's
/// crossing is reclaimed. Neither reserve moves.
///
/// # Panics
///
/// Panics as [`departing_route`] and [`submit_departing_route`] do, and
/// if the hold does not return to its baseline or the input to the
/// trader after the terminal, if the route is not abandoned, if a
/// reserve moves, or if either side of the pair is not conserved.
pub fn a_route_into_a_departing_venue_releases_the_survivors_hold<C: FaultableCluster>(c: &mut C) {
    let (departing, survivor) = (FIRST_VENUE_SHARD, SECOND_VENUE_SHARD);
    let route = departing_route(c);
    // Neither venue may hold the other's certificate. Provisions and
    // headers still flow, so each venue commits the route and runs its
    // own core leg, which is the state under test.
    let cut = [
        isolate_ec_intake(c, departing, survivor),
        isolate_ec_intake(c, survivor, departing),
    ];
    let mut charges = Charges::default();
    let (hash, baseline, paid, ..) = submit_departing_route(c, &route, &mut charges);

    // The cut. The departing venue's cells land under a child, and its
    // settled set reaches the survivor.
    await_departed(c);
    assert!(
        c.run_until(epochs(12), |c| c.committed_work_in_flight(survivor)
            == Some(baseline)),
        "the survivor's hold must return to its baseline once the departed venue's settled \
         set has answered; holds {:?} against {baseline:?}",
        c.committed_work_in_flight(survivor),
    );
    // The abandonment record licenses the trader's reclaim, which reads the
    // record cell the trader's leg wrote — and reads it whenever the
    // record lands, because a record is value and value is not swept on
    // a clock. The licence is the record itself rather than a probe, so
    // no window bounds it either: the input comes back however long the
    // departure took, on either epoch clock.
    assert!(
        c.run_until(epochs(12), |c| held(c, route.trader.address(), *XRD)
            == paid + ROUTE_INPUT),
        "the trader must get the route's input back on the abandonment record; holds {} \
         against {}",
        held(c, route.trader.address(), *XRD),
        paid + ROUTE_INPUT,
    );
    assert!(
        cut.iter().any(|handle| handle.fired() > 0),
        "the certificate channel must actually have been exercised and cut, or the venues \
         were never held apart",
    );
    // The trader's own leg accepted and stays accepted; the core it
    // fed is abandoned on both shards, never settled one-sided.
    for shard in [departing, survivor] {
        let fate = c.chain_fate(shard, hash).1.map(|(_, decision)| decision);
        assert!(
            fate != Some(TransactionDecision::Accept),
            "a venue settled a route its counterpart never certified; {shard} reached {fate:?}",
        );
    }
    for (reserve, before) in route.reserves.into_iter().zip(route.stocked) {
        assert_eq!(
            held_at(c, reserve),
            before,
            "neither venue may have applied its side of a route the other never certified",
        );
    }
    c.clear_drops();
    // And conserved outright: nothing of the route is stranded, because
    // nothing it issued was swept out from under its reclaim.
    assert!(
        c.run_until(epochs(8), |c| route.xrd.settles(c, charges.burned(c))),
        "a route through a departing venue: the world must settle against the burn alone",
    );
    route
        .xrd
        .assert_settled(c, charges.burned(c), "a route through a departing venue");
    charges.assert_each_fits_a_full_block(c);
    route.units.assert_settles_within(
        c,
        &Charges::default(),
        epochs(8),
        "a route through a departing venue",
    );
}

/// A route the departing venue settled is settled by the surviving venue
/// too, from the certificate the departed chain left behind.
///
/// The mirror of
/// [`a_route_into_a_departing_venue_releases_the_survivors_hold`]: the
/// cut takes only the survivor's intake, so the departing venue holds
/// both certificates and settles, applying its half, while the survivor
/// holds only its own and cannot apply until the departed venue's
/// reaches it. What that leaves the survivor is a transaction its
/// counterpart's settled set names as settled — so no record covers it,
/// the fence refuses any abandonment of it, and the only resolution left
/// is the certificate itself, committed on the departed shard's tail
/// chain. The cut lifts once the children seat, so what is measured is
/// a retention limit and not a partition: the survivor asks for the
/// certificate on a whole network, having missed it while the cut was
/// up, and the route banks its output.
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
    let route = departing_route(c);
    let cut = isolate_ec_intake(c, survivor, departing);
    let mut charges = Charges::default();
    let (hash, baseline, paid, validity_end) = submit_departing_route(c, &route, &mut charges);
    assert!(
        c.run_until(epochs(12), |c| matches!(
            c.chain_fate(departing, hash).1,
            Some((_, TransactionDecision::Accept))
        )),
        "the departing venue holds both certificates and settles the route before it leaves",
    );
    assert!(
        c.chain_fate(survivor, hash).1.is_none(),
        "the survivor holds only its own certificate and cannot apply yet",
    );

    await_departed(c);
    assert!(
        cut.fired() > 0,
        "the survivor's certificate intake must actually have been exercised and cut, or it \
         held the departed venue's certificate all along",
    );
    c.clear_drops();
    assert!(
        c.run_until(epochs(12), |c| matches!(
            c.chain_fate(survivor, hash).1,
            Some((_, TransactionDecision::Accept))
        )),
        "the survivor must recover the departed venue's certificate from its tail chain and \
         apply what it settled",
    );
    assert!(
        c.run_until(epochs(12), |c| c.committed_work_in_flight(survivor)
            == Some(baseline)),
        "the survivor's hold must return to its baseline once it has settled; holds {:?} \
         against {baseline:?}",
        c.committed_work_in_flight(survivor),
    );
    // The output is a delivery to the trader, admissible to the delivery
    // window's close. On a clock the window outlasts, the trader banks
    // it. On a clock whose epochs outrun the window the survivor settles
    // after it and the delivery can no longer be admitted — but the
    // claim cell the lapse probe asks about outlives the window it
    // answers for, so the absence is proved against a live cell and the
    // issuer takes the output back. Past the window the trader is out
    // its input; the world is not, on either clock.
    let banked = c.run_until(epochs(8), |c| held(c, route.trader.address(), *XRD) > paid);
    if !banked {
        let clock = WeightedTimestamp::ZERO.plus(c.now());
        assert!(
            clock >= Window::Delivery.of(Deadline::of(validity_end)).end,
            "the route must bank its output for the trader while its delivery window is open; \
             holds {} against {paid}",
            held(c, route.trader.address(), *XRD),
        );
        assert_eq!(
            held(c, route.trader.address(), *XRD),
            paid,
            "past its delivery window the output never reaches the trader",
        );
    }
    route
        .xrd
        .assert_settles_within(c, &charges, epochs(8), "a route settled across a departure");
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
    let world = train_world(c, &setup.legs);
    let mut charges = Charges::default();

    let sent = drive_train(
        c,
        splitter,
        &setup.legs,
        &mut charges,
        |c| split_admitted(c, splitter),
        |c| cast_splitter_vote(c, straddler_split_bytes()),
    );

    let children = <[ShardId; 2]>::from(splitter.children());
    assert_train_fates(c, splitter, &children, &sent);
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
    let world = train_world(c, &setup.legs);
    let mut charges = Charges::default();

    let sent = drive_train(
        c,
        merging,
        &setup.legs,
        &mut charges,
        |c| merge_keeper_count(c, parent).is_some(),
        |_| {},
    );

    assert_train_fates(c, merging, &[parent], &sent);
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
        *XRD,
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
    let before = height(c);
    send_leg(
        c,
        legs.next().expect("a funded leg"),
        charges,
        &mut sent,
        &mut admitted_once,
        &pending,
    );
    c.run_until(epochs(1), |_| false);
    let spacing = (height(c).saturating_sub(before) / TRAIN_PER_EPOCH).max(1);

    arm(c);

    let mut draining = 0;
    for leg in legs {
        if send_leg(c, leg, charges, &mut sent, &mut admitted_once, &pending) == Phase::Draining {
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
/// nothing more can be included: whether it settled the transfer before
/// its terminal is what decides between a settlement there and the
/// successor's delivery or a reclaim, and a recipient is credited exactly
/// when its payer's transfer was accepted and some chain delivered it.
///
/// # Panics
///
/// Panics if a successor is not served within budget, if a transfer sent
/// while the shard was live was not settled by it, if any transfer
/// reaches a fate its phase does not allow, if a credit disagrees with a
/// verdict, or if the train never reached the coast.
fn assert_train_fates<C: Cluster>(
    c: &mut C,
    terminating: ShardId,
    successors: &[ShardId],
    sent: &[(TxHash, PrincipalAddr, Phase)],
) {
    for &successor in successors {
        assert!(
            await_serves(c, successor, epochs(28)),
            "successor {successor} must be served within budget",
        );
    }
    let mut never_included = 0;
    for (hash, to, phase) in sent {
        let (included, settled) = c.chain_fate(terminating, *hash);
        // Settled means settled in the recipient's favour. An abort on
        // the leaving shard leaves the transfer exactly where a transfer
        // it never settled is left — no credit given, the payment to
        // come back — so it owes `CarriedOrReclaimed`, and reading the
        // decision is what tells the two apart.
        let settled = settled.is_some_and(|(_, decision)| decision != TransactionDecision::Aborted);
        assert!(
            settled || *phase != Phase::Live,
            "a transfer sent {phase:?} must be settled by the leaving shard",
        );
        never_included += usize::from(included.is_none());
        let taken = match (included.is_some(), settled) {
            (_, true) => "settled",
            (true, false) => "included but never settled in the recipient's favour",
            (false, false) => "never included",
        };
        let status = await_tx_terminal(c, *hash, epochs(12));
        // The credit is the recipient's chain's to give: the leaving
        // shard's or, for a transfer it never settled, whichever
        // successor took the recipient's prefix. A transfer accepted by
        // its payer and by no chain holding the recipient is one whose
        // delivery lapsed, and the reclaim returns the payment — the
        // world's conservation is what reads that.
        let delivered = std::iter::once(terminating)
            .chain(successors.iter().copied())
            .any(|shard| {
                c.chain_fate(shard, *hash)
                    .1
                    .is_some_and(|(_, decision)| decision == TransactionDecision::Accept)
            });
        let credited = match (fate_owed(*phase, settled), status, delivered) {
            (
                Fate::Settled | Fate::CarriedOrReclaimed,
                Some(TransactionStatus::Completed(TransactionDecision::Accept)),
                true,
            ) => 10 + STRADDLER_PAYMENT,
            (
                Fate::CarriedOrReclaimed,
                Some(TransactionStatus::Completed(
                    TransactionDecision::Accept | TransactionDecision::Aborted,
                )),
                false,
            ) => 10,
            (owed, other, delivered) => panic!(
                "a transfer sent {phase:?} and {taken} by the leaving shard owes {owed:?} and \
                 reached {other:?}, delivered = {delivered}",
            ),
        };
        assert!(
            c.run_until(epochs(8), |c| held(c, to.address(), *XRD) == credited),
            "a recipient of a transfer sent {phase:?} and {taken} by the leaving shard must \
             hold {credited}; holds {}",
            held(c, to.address(), *XRD),
        );
    }
    assert!(
        never_included > 0,
        "the train has to reach the leaving shard's coast, or nothing here crosses the cut",
    );
}

/// What a transfer's phase leaves open once the leaving shard has
/// terminated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fate {
    /// Settled on a chain that credited the recipient: the leaving shard
    /// settled it before its terminal, whatever it was doing at the time.
    Settled,
    /// Aborted on the payer's chain, carried by the successor that took
    /// the recipient's prefix, or, if nothing delivered it, reclaimed on
    /// the successor's proof that nothing did.
    CarriedOrReclaimed,
}

/// The fate a phase owes a transfer the leaving shard did or did not
/// settle.
///
/// One shape takes two fates, and it is the one the reshape opens: a
/// transfer the leaving shard's terminal overtook — never included, or
/// included and abandoned by the terminal sweep — races the delivery
/// window's close. A live shard settles everything it takes, so a run
/// that crossed no cut satisfies no disjunction here.
const fn fate_owed(phase: Phase, settled: bool) -> Fate {
    match (phase, settled) {
        (Phase::Live, _) | (Phase::Departing | Phase::Draining, true) => Fate::Settled,
        (Phase::Departing | Phase::Draining, false) => Fate::CarriedOrReclaimed,
    }
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
    sent: &mut Vec<(TxHash, PrincipalAddr, Phase)>,
    admitted_once: &mut bool,
    pending: impl Fn(&C) -> bool,
) -> Phase {
    let pending = pending(c);
    *admitted_once |= pending;
    let phase = phase_of(pending, *admitted_once);
    let tx = build_transfer_tx(key, *from, *to, STRADDLER_PAYMENT, validity_around(c.now()));
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
        *XRD,
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
        held_at(c, reserve_cell(&venue.meta, *XRD)),
        claimed + SWAP_INPUT,
        "the venue's child claims the post-cut input",
    );
}
