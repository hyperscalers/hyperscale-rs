//! A route through two venues on two shards, and whether it settles.
//!
//! One venue is a core of one shard. Two of them on separate shards is a
//! core that spans both: neither swap is reservation shaped nor total,
//! so both are core, and the route's atomicity has to cover them
//! together while nothing about their execution is shared. Each venue
//! awaits the other's certificate, which is what makes this the first
//! shape whose settlement waits on a certificate from across a shard
//! boundary — a transfer never does, its recipient claims a bundle.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::{self, Display, Formatter, Write};
use std::time::{Duration, Instant};

use hyperscale_effects_bridge::ProtocolHasher;
use hyperscale_engine::PROTOCOL_RESOURCE;
use hyperscale_storage::{FeeTerms, Place, RowState, seat_leaf};
use hyperscale_types::test_utils::Withheld;
use hyperscale_types::{
    Address, BlockHeight, Deadline, Ed25519PrivateKey, Joins, MAX_CLAIMS_BYTES,
    MAX_CLAIMS_PER_BLOCK, MAX_FINALIZATION_DELAY, MAX_STANDING_ANSWERS,
    MAX_STANDING_ANSWERS_FROM_SHARD, MAX_STANDING_TOWARD_SHARD, MAX_STATE_CLAIMS_BYTES,
    MAX_STATE_CLAIMS_PER_BLOCK, MAX_VALIDITY_RANGE, NAMING_WINDOW, PrincipalAddr,
    REATTESTATION_STEP, RETENTION_HORIZON, ResourceAddr, ShardId, ShardTrie, SubstateKey,
    TimestampRange, Transaction, TransactionDecision, TransactionStatus, TxHash, ValidatorId,
    WeightedTimestamp, Window, staged_leaf, verdict_leaf,
};
use hyperscale_vm_effects::{Answered, CrossingAnswer, CrossingId, Kind, fee_hold_total_key};
use hyperscale_vm_types::{LegRole, LegShape};

use crate::faults::{await_halt_recovery, freeze_shard};
use crate::straddler::{
    isolate_crossing_intake, isolate_crossing_intake_among, isolate_ec_intake,
    isolate_provision_intake, isolate_pushed_readings, isolate_state_reads,
};
use crate::support::conservation::{Charges, World};
use crate::support::faultable::{
    Crash, CrashableCluster, RestartableCluster, report_accepted_measures, report_claims_recarried,
    report_crossing_measures,
};
use crate::support::query::{
    ChainMentions, ClaimsSection, Readings, assert_reclaimed_leg, await_leg_fated, declared_price,
    epoch_duration_ms, held, held_at, stands_at, vault_balance,
};
use crate::support::tx::{
    build_route_tx, build_sponsored_route_tx, build_swap_tx, build_transfer_tx, validity_around,
};
use crate::support::wait::{await_blocks, await_tx_terminal};
use crate::support::{
    Budget, Cluster, FaultHandle, FaultableCluster, ProofMeter, ProofTally, epochs,
};
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
pub fn both_venues_read_a_routes_record_inside_the_finalization_delay<C: FaultableCluster>(
    c: &mut C,
    budget: Budget,
) {
    let mut taken = Vec::new();
    let (first, second) = stand_up_venues(c, &mut taken);
    let traders = traders(&mut taken);
    let (route, records) = submit_core_route(c, (&first, &second), &traders[0], ROUTE_INPUT);

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
    let asks = c.metric("record_asks", None);
    assert!(
        asks <= read_bound(1),
        "a healthy route's pushes land before any read is armed: {asks} reads",
    );
}

/// Submit a route of `trader`'s through `venues`, paying in `amount`, and
/// hand back its hash and the records it writes into its core.
fn submit_core_route<C: Cluster>(
    c: &mut C,
    (first, second): (&StockedVenue, &StockedVenue),
    (key, account): &(Ed25519PrivateKey, PrincipalAddr),
    amount: u128,
) -> (TxHash, Vec<SubstateKey>) {
    let tx = build_route_tx(
        key,
        *account,
        (&first.meta, &second.meta),
        *PROTOCOL_RESOURCE,
        amount,
        0,
        validity_around(c.now()),
    );
    let records = core_records(c, &tx);
    (Charges::default().submit(c, tx), records)
}

/// The records `tx` writes into its core.
fn core_records<C: Cluster>(c: &C, tx: &Transaction) -> Vec<SubstateKey> {
    let records: Vec<SubstateKey> = records_by_road(
        &c.with_derivation(|derivation| tx.try_derived(derivation))
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
    records
}

/// Run until `venue`'s chain carries every one of `records` for `route`
/// and hand back the longest it waited.
fn await_record_reads<C: Cluster>(
    c: &mut C,
    venue: ShardId,
    route: TxHash,
    records: &[SubstateKey],
) -> Duration {
    let waits = |c: &C| {
        records
            .iter()
            .map(|record| c.record_wait(venue, route, *record))
            .collect::<Option<Vec<Duration>>>()
    };
    assert!(
        c.run_until(epochs(40), |c| waits(c).is_some()),
        "{venue:?} must carry a reading of every record of {route:?}",
    );
    waits(c)
        .and_then(|waits| waits.into_iter().max())
        .expect("every read is in")
}

/// The longest a route's record may take to reach a venue whose push was
/// lost, at the latency these scenarios run at, while the holder's chain
/// carries a load.
const LOST_RECORD_BOUND: Duration = Duration::from_secs(10);

/// [`LOST_RECORD_BOUND`] on an idle holder: the 5 s cold grace, about
/// 4.2 s of proven anchor lag at three idle block steps, and the read.
const IDLE_LOST_RECORD_BOUND: Duration = Duration::from_secs(12);

/// A record lost to one venue on an idle holder is read inside
/// [`IDLE_LOST_RECORD_BOUND`] of the venue's commit.
///
/// The read arms on the holder's clock, well short of the finalization
/// delay.
///
/// Requires disjoint committees, as the cut is keyed on them.
///
/// # Panics
///
/// Panics if a venue misses its budget standing up, if the cut never
/// fires, or if the record takes longer.
pub fn a_lost_record_is_read_inside_twelve_seconds<C: FaultableCluster>(c: &mut C) {
    let mut taken = Vec::new();
    let (first, second) = stand_up_venues(c, &mut taken);
    let traders = traders(&mut taken);
    let lost = isolate_pushed_readings(c, FIRST_VENUE_SHARD, TRADER_SHARD);
    let (route, records) = submit_core_route(c, (&first, &second), &traders[0], ROUTE_INPUT);
    let wait = await_record_reads(c, FIRST_VENUE_SHARD, route, &records);
    assert!(lost.fired() > 0, "the push must actually have been lost");
    println!("record read: a lost record reached its venue in {wait:?}");
    assert!(
        wait < IDLE_LOST_RECORD_BOUND,
        "a lost record must be read inside {IDLE_LOST_RECORD_BOUND:?}, and took {wait:?}",
    );
}

/// How long [`LocalTransfers`] run before a busy holder's route goes in,
/// so its heights are at the loaded rate from the route's first block.
const BUSY_HOLDER_LEAD: Duration = Duration::from_secs(3);

/// The holder heights a second under which a chain is not loaded: an idle
/// chain steps about every 1.3 s, a loaded one about every 0.3 s.
const LOADED_HEIGHTS_PER_SECOND: f64 = 2.0;

/// A record lost to one venue on a holder carrying transfers throughout
/// is read inside [`LOST_RECORD_BOUND`] of the venue's commit.
///
/// The holder's anchors move at the loaded rate, which takes the idle
/// block steps out of the proven anchor's lag.
///
/// Requires disjoint committees, as the cut is keyed on them.
///
/// # Panics
///
/// Panics if a venue misses its budget standing up, if the cut never
/// fires, if the holder passes fewer than [`LOADED_HEIGHTS_PER_SECOND`]
/// while the record is awaited, or if the record takes longer.
pub fn a_lost_record_on_a_busy_holder_is_read_inside_ten_seconds<C: FaultableCluster>(c: &mut C) {
    let mut taken = Vec::new();
    let (first, second) = stand_up_venues(c, &mut taken);
    let traders = traders(&mut taken);
    let mut transfers = LocalTransfers {
        payer: &traders[1],
        to: traders[2].1,
        sent: 0,
    };
    let underway = c.now() + BUSY_HOLDER_LEAD;
    transfers.run_until(c, BUSY_HOLDER_LEAD, |c| c.now() >= underway);
    let lost = isolate_pushed_readings(c, FIRST_VENUE_SHARD, TRADER_SHARD);
    let holder_height = |c: &C| {
        c.committed_height(TRADER_SHARD)
            .map_or(0, BlockHeight::inner)
    };
    let from_height = holder_height(c);
    let from = c.now();
    let (route, records) = submit_core_route(c, (&first, &second), &traders[0], ROUTE_INPUT);
    let carried = |c: &C| {
        records
            .iter()
            .map(|record| c.record_wait(FIRST_VENUE_SHARD, route, *record))
            .collect::<Option<Vec<Duration>>>()
    };
    assert!(
        transfers.run_until(c, MAX_FINALIZATION_DELAY * 2, |c| carried(c).is_some()),
        "the venue must carry a reading of the record",
    );
    let wait = carried(c)
        .and_then(|waits| waits.into_iter().max())
        .expect("every read is in");
    let passed = holder_height(c).saturating_sub(from_height);
    let rate = f64::from(u32::try_from(passed).expect("a short run"))
        / c.now().saturating_sub(from).as_secs_f64();
    assert!(lost.fired() > 0, "the push must actually have been lost");
    println!(
        "record read: a lost record reached its venue in {wait:?} on a busy holder, at \
         {rate:.2} heights a second",
    );
    assert!(
        rate > LOADED_HEIGHTS_PER_SECOND,
        "the holder must stay loaded while the record is awaited, and passed {rate:.2} heights \
         a second against {LOADED_HEIGHTS_PER_SECOND}",
    );
    assert!(
        wait < LOST_RECORD_BOUND,
        "a lost record on a busy holder must be read inside {LOST_RECORD_BOUND:?}, and took \
         {wait:?}",
    );
}

/// What a reread takes past the ladder's next rung: the answer's round
/// trip, and the block that carries the arrival.
const REREAD_ALLOWANCE: Duration = Duration::from_secs(2);

/// The ladder's gap in holder heights once `passed` heights have gone by
/// since a key's first ask: 2 past the first ask, doubling on each rung.
const fn ladder_gap(passed: u64) -> u64 {
    let mut gap = 2;
    let mut rung = gap;
    while rung <= passed {
        gap *= 2;
        rung += gap;
    }
    gap
}

/// How finely a scenario watches for a state only a moment separates
/// from what follows it, well under a block.
const FINE_POLL: Duration = Duration::from_millis(50);

/// The gap between [`LocalTransfers`], about a loaded block.
const LOCAL_TRANSFER_GAP: Duration = Duration::from_millis(300);

/// Transfers between two accounts of one shard, which pass that shard's
/// heights at the loaded rate and not at an idle block a second.
struct LocalTransfers<'a> {
    payer: &'a (Ed25519PrivateKey, PrincipalAddr),
    to: PrincipalAddr,
    sent: u128,
}

impl LocalTransfers<'_> {
    /// Run `c` with the transfers flowing until `done`, for at most
    /// `within`. Hands back whether `done` held.
    fn run_until<C: Cluster>(
        &mut self,
        c: &mut C,
        within: Duration,
        done: impl Fn(&C) -> bool,
    ) -> bool {
        let deadline = c.now() + within;
        while !done(c) && c.now() < deadline {
            self.sent += 1;
            let (key, from) = self.payer;
            c.submit(build_transfer_tx(
                key,
                *from,
                self.to,
                self.sent,
                validity_around(c.now()),
            ));
            let next = c.now() + LOCAL_TRANSFER_GAP;
            let _ = c.run_polling(epochs(1), FINE_POLL, |c| c.now() >= next || done(c));
        }
        done(c)
    }
}

/// How long a leg's votes are dropped from the first of them, short of
/// their 8 s retry, so the retry goes through and finishes the leg past
/// the venue's first read.
const VOTES_HELD: Duration = Duration::from_millis(7_500);

/// A read that finds no record yet holds nothing and asks again.
///
/// The leg's votes are dropped, so the venue's first read comes back
/// absent, and no block ever carries the absence. What this bounds is the
/// ladder: the record is carried within one ladder gap of its leg
/// finalizing, the gap read off the holder heights since the first ask
/// and timed at the rate the holder passed them, plus
/// [`REREAD_ALLOWANCE`]. The trader's chain carries transfers throughout,
/// so those heights pass at the loaded rate. A leg's lateness sets how
/// far up the ladder it lands, so the wait is not a constant: it grows
/// with the gap, up to the finalization delay.
///
/// Requires disjoint committees, as the cuts are keyed on them.
///
/// # Panics
///
/// Panics if a venue misses its budget standing up, if no read went out
/// while the leg was held, if a block carries an absent reading of the
/// record, or if the reread takes longer than the ladder's gap and
/// [`REREAD_ALLOWANCE`].
pub fn a_read_that_finds_no_record_yet_reads_again<C: FaultableCluster>(c: &mut C) {
    let mut taken = Vec::new();
    let (first, second) = stand_up_venues(c, &mut taken);
    let traders = traders(&mut taken);
    let mut transfers = LocalTransfers {
        payer: &traders[1],
        to: traders[2].1,
        sent: 0,
    };
    let leg_hosts = c.committee_hosts(TRADER_SHARD);
    let _ = isolate_pushed_readings(c, FIRST_VENUE_SHARD, TRADER_SHARD);
    let held_leg = c.drop_type_between(&leg_hosts, &leg_hosts, "execution.vote");
    let (route, records) = submit_core_route(c, (&first, &second), &traders[0], ROUTE_INPUT);
    let within = MAX_FINALIZATION_DELAY;
    assert!(
        transfers.run_until(c, within, |_| held_leg.fired() > 0),
        "the leg's votes must be held",
    );
    let released = c.now() + VOTES_HELD;
    transfers.run_until(c, within, |c| c.now() >= released);
    c.clear_drops();
    let _ = isolate_pushed_readings(c, FIRST_VENUE_SHARD, TRADER_SHARD);

    let written = |c: &C| records.iter().all(|record| stands_at(c, *record));
    let read_or_written = |c: &C| c.metric("record_asks", None) > 0 || written(c);
    assert!(
        transfers.run_until(c, within, read_or_written),
        "the read must go out or the record stand",
    );
    let asked = c.now();
    let holder_height = |c: &C| {
        c.committed_height(TRADER_SHARD)
            .map_or(0, BlockHeight::inner)
    };
    let asked_height = holder_height(c);
    assert!(!written(c), "the read must go out before the record stands");
    assert!(
        transfers.run_until(c, within, written),
        "the leg finalizes past the first read",
    );
    let written_height = holder_height(c);
    let written = c.now();
    assert!(
        c.metric("fetch_completed", Some("record_proof")) > 0,
        "the first read must have come back before the record stood",
    );
    assert!(
        transfers.run_until(c, within, |c| records
            .iter()
            .all(|record| c.record_wait(FIRST_VENUE_SHARD, route, *record).is_some())),
        "the venue must carry a reading of the record",
    );
    let waited = c.now().saturating_sub(written);
    let gap = ladder_gap(written_height.saturating_sub(asked_height));
    let passed = written_height.saturating_sub(asked_height).max(1);
    let per_height = written.saturating_sub(asked) / u32::try_from(passed).expect("a short run");
    let ladder =
        (per_height * u32::try_from(gap).expect("a short run")).min(MAX_FINALIZATION_DELAY);
    let bound = ladder + REREAD_ALLOWANCE;
    println!(
        "record read: record written {:?} past the first read, {passed} holder heights, ladder \
         gap {gap} heights at {per_height:?} each is {ladder:?}; carried {waited:?} past the \
         record, bound {bound:?}",
        written.saturating_sub(asked),
    );
    assert!(
        waited < bound,
        "the ladder's next rung must read the record, and it took {waited:?} against {bound:?}",
    );
    for record in records {
        assert_eq!(
            c.absent_record_readings(FIRST_VENUE_SHARD, record),
            0,
            "an absent reading of a wanted record takes no place in a block",
        );
    }
}

/// A held push the read frontier passes costs its key a read, no more.
///
/// One venue member alone hears a route's push and proposes nothing, so
/// no block carries it, and the reads that would answer the route are
/// cut. A second route's push, a height above, then lands everywhere, and
/// the block carrying it raises the holder's read frontier over what the
/// member holds: that push is refused and the member reads again, as a
/// push landing behind a read would be.
///
/// Both venues hear the two routes in the same order, so each places them
/// alike: heard apart, the venues would hold them in opposite order and
/// the later hash would lose to the cycle, as a route does.
///
/// Requires disjoint committees, as the cut is keyed on them.
///
/// # Panics
///
/// Panics if a venue misses its budget standing up, if a cut never fires,
/// if no held push is refused, if either route is not accepted on both
/// venues, or if either record takes longer than [`LOST_RECORD_BOUND`]
/// past the reads' return.
pub fn one_lost_height_among_delivered_pushes<C: FaultableCluster>(c: &mut C) {
    let mut taken = Vec::new();
    let (first, second) = stand_up_venues(c, &mut taken);
    let traders = traders(&mut taken);
    let member = c
        .beacon_state()
        .and_then(|state| {
            state
                .shard_consensus_members
                .get(&FIRST_VENUE_SHARD)
                .cloned()
        })
        .expect("the venue has a consensus committee")[0];
    let hearing = c.host_of(member).expect("the member is hosted");
    let others: Vec<usize> = c
        .committee_hosts(FIRST_VENUE_SHARD)
        .into_iter()
        .filter(|host| *host != hearing)
        .collect();
    let leg_hosts = c.committee_hosts(TRADER_SHARD);
    let venues = [FIRST_VENUE_SHARD, SECOND_VENUE_SHARD];
    let lost = [
        c.drop_type_between(&leg_hosts, &others, "crossing.readings"),
        isolate_pushed_readings(c, SECOND_VENUE_SHARD, TRADER_SHARD),
    ];
    let _ = venues.map(|venue| isolate_state_reads(c, venue, TRADER_SHARD));
    let _ = c.withhold(&[member], Withheld::Consensus);
    let (held, held_records) = submit_core_route(c, (&first, &second), &traders[0], ROUTE_INPUT);
    assert!(
        c.run_polling(epochs(10), FINE_POLL, |c| held_records
            .iter()
            .all(|record| stands_at(c, *record))
            && lost.iter().all(|cut| cut.fired() > 0)),
        "the leg finalizes, and its push is lost to all but one member",
    );
    c.clear_drops();
    let _ = venues.map(|venue| isolate_state_reads(c, venue, TRADER_SHARD));
    let (above, above_records) = submit_core_route(c, (&first, &second), &traders[1], ROUTE_INPUT);
    let refused = |c: &C| c.metric("fenced_claims_refused", Some("record"));
    assert!(
        c.run_polling(epochs(10), FINE_POLL, |c| refused(c) > 0),
        "the block carrying the push above must refuse the one held below it",
    );
    println!("record read: {} held pushes refused", refused(c));
    let _ = c.withhold(&[member], Withheld::Nothing);
    c.clear_drops();

    let lifted = c.now();
    for (route, records) in [(above, &above_records), (held, &held_records)] {
        for venue in venues {
            let _ = await_record_reads(c, venue, route, records);
            let wait = c.now().saturating_sub(lifted);
            println!("record read: {route:?} on {venue:?} {wait:?} past the reads' return");
            assert!(
                wait < LOST_RECORD_BOUND,
                "{route:?} must be read inside {LOST_RECORD_BOUND:?}, and took {wait:?}",
            );
        }
    }
    for route in [above, held] {
        for venue in venues {
            assert!(
                c.run_until(epochs(40), |c| accepted_on(c, venue, route)),
                "{route:?} must be accepted on {venue:?}",
            );
        }
    }
}

/// The longest a record may take to reach a venue when the block that
/// should have pushed it lost its proposer: a read, and room for the view
/// change.
const KILLED_PROPOSER_BOUND: Duration = Duration::from_secs(12);

/// A crash takes one block's pusher with no type drop in play.
///
/// The trader committee's member at `victim` dies as the first record
/// stands, so when that member's turn is the next the block's push dies
/// with it. Every route still accepts, and the worst a record pays is a
/// read.
///
/// A trader member's turn cannot be read from here, so a run names one
/// member and the suite runs each. Hands back whether this run killed the
/// push: every venue read that record at an anchor past the one a push
/// stands at, so the read and not the push delivered it.
///
/// Requires disjoint committees, so the crash touches only the trader's
/// shard.
///
/// # Panics
///
/// Panics if a venue misses its budget standing up, if a route is not
/// accepted on both venues, or if a record takes longer than
/// [`KILLED_PROPOSER_BOUND`].
pub fn a_killed_proposer_costs_a_route_no_more_than_a_read<C>(c: &mut C, victim: usize) -> bool
where
    C: FaultableCluster + CrashableCluster,
{
    let mut taken = Vec::new();
    let (first, second) = stand_up_venues(c, &mut taken);
    let traders = traders(&mut taken);
    let victim = c.committee_hosts(TRADER_SHARD)[victim];
    let routes: Vec<(TxHash, Vec<SubstateKey>)> = traders
        .iter()
        .map(|trader| submit_core_route(c, (&first, &second), trader, ROUTE_INPUT))
        .collect();
    let written =
        |c: &C, records: &[SubstateKey]| records.iter().all(|record| stands_at(c, *record));
    assert!(
        c.run_polling(epochs(10), FINE_POLL, |c| routes
            .iter()
            .any(|(_, records)| written(c, records))),
        "a leg finalizes",
    );
    let height = c
        .committed_height(TRADER_SHARD)
        .expect("the trader's shard runs");
    let first = routes
        .iter()
        .find(|(_, records)| written(c, records))
        .map(|(_, records)| records.clone())
        .expect("a leg has finalized");
    c.crash(victim, Crash::Process, epochs(2));

    let mut longest = Duration::ZERO;
    for (route, records) in &routes {
        for venue in [FIRST_VENUE_SHARD, SECOND_VENUE_SHARD] {
            longest = longest.max(await_record_reads(c, venue, *route, records));
            assert!(
                c.run_until(epochs(40), |c| accepted_on(c, venue, *route)),
                "{route:?} must be accepted on {venue:?}",
            );
        }
    }
    let read = [FIRST_VENUE_SHARD, SECOND_VENUE_SHARD]
        .into_iter()
        .all(|venue| {
            first.iter().all(|record| {
                c.record_reading_anchor(venue, *record)
                    .is_some_and(|anchor| anchor.height > height)
            })
        });
    println!(
        "record read: the longest record took {longest:?} past a killed proposer; the first \
         record came by a read: {read}",
    );
    assert!(
        longest < KILLED_PROPOSER_BOUND,
        "a killed proposer must cost no more than a read, and a record took {longest:?}",
    );
    read
}

/// Well over the record fetch's 256 places, with room for the pushes that
/// land before the holder dies.
const DEAD_HOLDER_ROUTES: usize = 300;

/// A holder nobody can reach pins no more of the record fetch than its
/// share, so a lost record at a healthy holder is still read in time.
///
/// More keys are wanted of it than the fetch has places, and a validator
/// keeps `asks_per_holder` reads open toward it and no more.
///
/// Requires a grown four-shard cluster over
/// [`contended_load_genesis_accounts`] of `traders`.
///
/// # Panics
///
/// Panics if a venue misses its budget standing up, if the dead holder
/// never reaches more wanted keys than the fetch has places, if the reads
/// open toward it are over `asks_per_holder` a validator or under half
/// that, if the cut never fires, or if the record takes longer than
/// [`IDLE_LOST_RECORD_BOUND`]: the lost record's holder carries this one
/// route, so it pays an idle holder's stages, the cold grace, the proven
/// anchor's lag and the read.
pub fn a_dead_holder_leaves_room_for_a_lost_record<C: FaultableCluster>(
    c: &mut C,
    traders: usize,
    asks_per_holder: usize,
) {
    let cast = LoadCast::stand_up(c, DEAD_HOLDER_ROUTES + 1, &traders_on_both_shards(traders));
    let walked = [BlockHeight::GENESIS, BlockHeight::GENESIS];
    let mut flight = Flight::over(DEAD_HOLDER_ROUTES + 1, walked);
    let window = validity_around(c.now());
    for pair in 0..DEAD_HOLDER_ROUTES {
        cast.send(
            c,
            &mut flight,
            TradersOn::First,
            (pair, Heading::Out),
            window,
            Duration::ZERO,
        );
    }
    let wanted = |c: &C| {
        c.metric_quantile_above("wanted_records", None, 1.0, 0.0)
            .unwrap_or(0.0)
    };
    assert!(
        c.run_until(epochs(4), |c| wanted(c) > 256.0),
        "more keys must be wanted of the holder than the fetch has places: {}",
        wanted(c),
    );
    let dead = c.committee_hosts(TRADER_SHARD);
    let others: Vec<usize> = (0..c.host_count())
        .filter(|host| !dead.contains(host))
        .collect();
    c.partition(&dead, &others);
    // A cut-off holder's clock stands still, so only the finalization
    // delay arms what is wanted of it.
    let asked = c.now() + MAX_FINALIZATION_DELAY + Duration::from_secs(4);
    assert!(
        c.run_until(epochs(2), |c| c.now() >= asked),
        "the cluster's clock must pass the finalization delay",
    );
    let open = record_reads_open(c);
    let cap = wide(asks_per_holder) * venue_validators(c);
    println!("record read: {open} reads stand open toward a dead holder, of {cap} places");
    assert!(
        open <= cap,
        "a dead holder holds {open} reads, past its {cap} places",
    );
    assert!(
        open >= cap / 2,
        "the dead holder must fill its places, and holds {open} of {cap}",
    );

    let lost = isolate_pushed_readings(c, FIRST_VENUE_SHARD, SECOND_TRADER_SHARD);
    let hash = cast.send(
        c,
        &mut flight,
        TradersOn::Second,
        (DEAD_HOLDER_ROUTES, Heading::Out),
        window,
        Duration::ZERO,
    );
    let records = core_records(c, &flight.routes[&hash]);
    let wait = await_record_reads(c, FIRST_VENUE_SHARD, hash, &records);
    assert!(lost.fired() > 0, "the push must actually have been lost");
    println!("record read: {wait:?} for a lost record beside a dead holder");
    assert!(
        wait < IDLE_LOST_RECORD_BOUND,
        "a dead holder must leave room for a lost record, which took {wait:?}",
    );
    c.heal_all();
}

/// How many record reads stand open across the cluster.
fn record_reads_open<C: FaultableCluster>(c: &C) -> u64 {
    let count = |name| c.metric(name, Some("record_proof"));
    count("fetch_started").saturating_sub(count("fetch_completed") + count("fetch_abandoned"))
}

/// How long a holder stalls: past the finalization delay, so everything
/// in flight arms on the clock.
const HOLDER_STALL: Duration = Duration::from_secs(26);

/// A holder stalled past the finalization delay draws one read per key
/// and per validator, however long it stalls, and takes no place from
/// the other asks.
///
/// Requires disjoint committees, as the partition is keyed on them.
///
/// # Panics
///
/// Panics if a venue misses its budget standing up, if more reads stand
/// open than there are wants, if no state proof lands past the stall, or
/// if a route is not accepted once it ends.
pub fn a_stalled_holder_draws_one_ask_per_key<C: FaultableCluster>(c: &mut C) {
    let mut taken = Vec::new();
    let (first, second) = stand_up_venues(c, &mut taken);
    let traders = traders(&mut taken);
    let routes: Vec<(TxHash, Vec<SubstateKey>)> = traders
        .iter()
        .map(|trader| submit_core_route(c, (&first, &second), trader, ROUTE_INPUT))
        .collect();
    let filed = c.now() + Duration::from_secs(2);
    let _ = c.run_until(epochs(1), |c| c.now() >= filed);

    let stalled = c.committee_hosts(TRADER_SHARD);
    let others: Vec<usize> = (0..c.host_count())
        .filter(|host| !stalled.contains(host))
        .collect();
    c.partition(&stalled, &others);
    let keys: usize = routes.iter().map(|(_, records)| records.len()).sum();
    let venue_validators =
        c.committee_hosts(FIRST_VENUE_SHARD).len() + c.committee_hosts(SECOND_VENUE_SHARD).len();
    let wants = u64::try_from(keys * venue_validators).expect("a small count");
    let resume = c.now() + HOLDER_STALL;
    let mut most = 0;
    while c.now() < resume {
        let next = c.now() + Duration::from_secs(1);
        let _ = c.run_until(epochs(1), |c| c.now() >= next);
        most = most.max(record_reads_open(c));
    }
    c.heal_all();
    let proofs = c.metric("fetch_completed", Some("state_proof"));
    for _ in 0..8 {
        let next = c.now() + Duration::from_secs(1);
        let _ = c.run_until(epochs(1), |c| c.now() >= next);
        most = most.max(record_reads_open(c));
    }
    println!("record read: at most {most} reads open of {wants} wants across a stall");
    assert!(
        most <= wants,
        "one read stands for a key, and {most} stood for {wants} wants",
    );
    for (route, _) in routes {
        for venue in [FIRST_VENUE_SHARD, SECOND_VENUE_SHARD] {
            assert!(
                c.run_until(epochs(40), |c| accepted_on(c, venue, route)),
                "{route:?} must be accepted on {venue:?}",
            );
        }
    }
    assert!(
        c.run_until(epochs(10), |c| c
            .metric("fetch_completed", Some("state_proof"))
            > proofs),
        "a state proof must still land past the stall",
    );
}

/// Run `c` for `span`, a second at a time, and hand back the most record
/// reads that stood open at any of them.
fn most_reads_open<C: FaultableCluster>(c: &mut C, span: Duration) -> u64 {
    let end = c.now() + span;
    let mut most = 0;
    while c.now() < end {
        let next = c.now() + Duration::from_secs(1);
        let _ = c.run_until(epochs(1), |c| c.now() >= next);
        most = most.max(record_reads_open(c));
    }
    most
}

/// One record read a venue validator makes of each of `records`.
fn wanted_reads<C: FaultableCluster>(c: &C, records: &[SubstateKey]) -> u64 {
    wide(records.len()) * venue_validators(c)
}

/// How long past a route's submission a restart comes: its venues have
/// filed it, and the finalization delay has passed their filing.
const PAST_THE_CLOCK: Duration = MAX_FINALIZATION_DELAY.saturating_add(Duration::from_secs(6));

/// How long a restarted validator is watched, past the first proven
/// header of the record's holder it needs to ask at.
const RESTART_WATCH: Duration = Duration::from_secs(8);

/// A consumer restarted with wants past the finalization delay asks each
/// of them at first sight, once per key, and its route still accepts.
///
/// The restart comes once the wants are past the delay, so the validator
/// is back at once and holds nothing but what it re-derives. Its own
/// reads are cut from there, which counts that it asked and leaves its
/// ids standing. The other validators read on up their ladders, each
/// read holding nothing as the leg stays held, so what the run bounds is
/// every validator's one read of each key.
///
/// Requires disjoint committees, as the held leg is keyed on them.
///
/// # Panics
///
/// Panics if a venue misses its budget standing up, if the restarted
/// validator asks nothing, if more reads go out or stand open than there
/// are wants, or if a route is not accepted.
pub fn a_restart_with_wants_past_the_clock_asks_each_once<C>(c: &mut C)
where
    C: FaultableCluster + RestartableCluster,
{
    let mut taken = Vec::new();
    let (first, second) = stand_up_venues(c, &mut taken);
    let traders = traders(&mut taken);
    let leg_hosts = c.committee_hosts(TRADER_SHARD);
    let _ = c.drop_type_between(&leg_hosts, &leg_hosts, "execution.vote");
    let (route, records) = submit_core_route(c, (&first, &second), &traders[0], ROUTE_INPUT);
    let past_the_clock = c.now() + PAST_THE_CLOCK;
    let _ = c.run_until(epochs(2), |c| c.now() >= past_the_clock);

    let restarted = c.committee_hosts(FIRST_VENUE_SHARD)[0];
    c.stop_host(restarted, epochs(0));
    assert!(
        c.run_until(epochs(1), |c| c.is_up(restarted)),
        "the validator must come back",
    );
    let own_reads = c.drop_type_between(&[restarted], &leg_hosts, "state_proof.request");
    let asks = c.metric("record_asks", None);
    let most = most_reads_open(c, RESTART_WATCH);
    let asked = c.metric("record_asks", None).saturating_sub(asks);
    let wants = wanted_reads(c, &records);
    println!(
        "record read: {asked} asks past a restart, of its own {}, at most {most} reads open of \
         {wants} wants",
        own_reads.fired(),
    );
    assert!(
        own_reads.fired() > 0,
        "the restarted validator must ask what it re-derived",
    );
    assert!(
        asked <= wants + read_bound(1),
        "one read goes out for a key, and {asked} went out for {wants} wants",
    );
    assert!(
        most > 0 && most <= wants,
        "one read stands for a key, and {most} stood for {wants} wants",
    );
    c.clear_drops();
    for venue in [FIRST_VENUE_SHARD, SECOND_VENUE_SHARD] {
        assert!(
            c.run_until(epochs(40), |c| accepted_on(c, venue, route)),
            "{route:?} must be accepted on {venue:?}",
        );
    }
}

/// A read nobody answers gives its place to the next, as the holder's
/// anchors move under it.
///
/// The venues' reads are cut and the leg stays held with the trader's
/// headers flowing, so each validator climbs its ladder at moving anchors
/// and no id ever comes back: each re-ask has to let go of the one before
/// it. Past the cut the route ends and no read stays open.
///
/// Requires disjoint committees, as the held leg is keyed on them.
///
/// # Panics
///
/// Panics if a venue misses its budget standing up, if no read is cut or
/// replaced, if more reads stand open than there are wants or any stands
/// open once the route has ended, or if the route is not accepted.
pub fn a_read_nobody_answers_stands_alone_for_its_key<C: FaultableCluster>(c: &mut C) {
    let mut taken = Vec::new();
    let (first, second) = stand_up_venues(c, &mut taken);
    let traders = traders(&mut taken);
    let leg_hosts = c.committee_hosts(TRADER_SHARD);
    let _ = c.drop_type_between(&leg_hosts, &leg_hosts, "execution.vote");
    let cut = [FIRST_VENUE_SHARD, SECOND_VENUE_SHARD]
        .map(|venue| c.drop_type_between_members(venue, TRADER_SHARD, "state_proof.request"));
    let (route, records) = submit_core_route(c, (&first, &second), &traders[0], ROUTE_INPUT);
    let most = most_reads_open(c, PAST_THE_CLOCK);
    let wants = wanted_reads(c, &records);
    let replaced = c.metric("fetch_abandoned", Some("record_proof"));
    println!("record read: at most {most} reads open of {wants} wants, {replaced} replaced");
    assert!(
        cut.iter().all(|cut| cut.fired() > 0),
        "the reads must have been cut",
    );
    assert!(replaced > 0, "a re-ask must let go of the read it replaces");
    assert!(
        most <= wants,
        "one read stands for a key, and {most} stood for {wants} wants",
    );
    c.clear_drops();
    for venue in [FIRST_VENUE_SHARD, SECOND_VENUE_SHARD] {
        assert!(
            c.run_until(epochs(40), |c| accepted_on(c, venue, route)),
            "{route:?} must be accepted on {venue:?}",
        );
    }
    assert!(
        c.run_until(epochs(1), |c| record_reads_open(c) == 0),
        "no read outlives its want: {} stand open",
        record_reads_open(c),
    );
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
/// asking for it, and accept on it.
///
/// Each venue is cut off from the other's certificate, which decides
/// nothing, and from the other's pushed readings, so nothing tells it
/// what the other's chain wrote. Each venue's row stands stated, asks
/// the other venue for the route's verdict cell, carries the reading it
/// fetches in a block, and accepts on it: the route settles on both
/// venues with every cut still standing.
///
/// Requires disjoint committees, as the cuts are keyed on the hosts.
///
/// # Panics
///
/// Panics if either venue misses its budget standing up, if either cut
/// never fires, if either venue does not accept the route while the cuts
/// stand, or if either side of the pair is not conserved.
pub fn stated_venues_hear_each_others_yes_by_asking<C: FaultableCluster>(c: &mut C) {
    stated_venues_hear_each_other(c, Road::Asked);
}

/// Two venues that have each said yes to a route hear the other's yes
/// from the push of the block that wrote it, and accept on it.
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

    let accepted = |c: &C, venue: ShardId| {
        matches!(
            c.chain_fate(venue, route).1,
            Some((_, TransactionDecision::Accept))
        )
    };
    assert!(
        c.run_until(epochs(8), |c| {
            accepted(c, FIRST_VENUE_SHARD) && accepted(c, SECOND_VENUE_SHARD)
        }),
        "each venue must accept the route on the other's yes while the cuts stand: first \
         {:?} heard {:?}, second {:?} heard {:?}",
        c.chain_fate(FIRST_VENUE_SHARD, route),
        c.heard(FIRST_VENUE_SHARD, route),
        c.chain_fate(SECOND_VENUE_SHARD, route),
        c.heard(SECOND_VENUE_SHARD, route),
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
    c.run_until(epochs(8), |c| {
        c.tx_status(route).is_some_and(|status| status.is_final())
    });
    assert_eq!(
        c.tx_status(route),
        Some(TransactionStatus::Completed(TransactionDecision::Accept)),
        "the route accepts on what the rows heard",
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

/// Two routes each venue heads in the other's order lose only the later
/// hash, well inside the naming window, and the other accepts on both
/// venues, conserved.
///
/// Each route's trader sits on a shard of its own, and each venue is cut
/// off from one trader's record: the second venue from the first route's,
/// the first venue from the second route's. Every other input flows, so
/// the first venue places the first route and makes it head, the second
/// venue the second, and neither can run: a venue serves the route it
/// heads to the other only from the block that makes it head there,
/// where it is not yet placed. The cuts lift, each venue places the other
/// route behind its head, and each head refuses it and takes a clock.
/// Each venue then asks the other about its head and the route behind
/// it, and reads the cycle off the other's seats: the route waiting
/// there is seated, its head committed and unseated. Both name the later
/// hash, aborting it unnamed where it waits and where it heads, by half
/// a naming window past the later refusal; the earlier hash heads on the
/// venue it waited on, is served and accepts on both.
///
/// Requires disjoint committees, as the cut is keyed on the hosts.
///
/// # Panics
///
/// Panics if either venue misses its budget standing up, if the cut never
/// fires, if the venues do not head the routes in opposite order, if a
/// block proves anything while the cuts stand, if the later route does
/// not leave both venues unnamed within half a naming window of the
/// later refusal or the earlier one does not accept on both in that
/// time, if no block proves the cycle or a head leaves at its window, or
/// if either side of the pair is not conserved.
pub fn routes_seated_in_opposite_order_lose_the_later_to_the_cycle<C: FaultableCluster>(c: &mut C) {
    crossed_routes(c, Seating::AsSubmitted, Lift::Together);
}

/// The same cycle with each venue heading the other's route.
///
/// As [`routes_seated_in_opposite_order_lose_the_later_to_the_cycle`],
/// with the venues heading the routes the other way.
///
/// # Panics
///
/// As [`routes_seated_in_opposite_order_lose_the_later_to_the_cycle`].
pub fn routes_seated_the_other_way_lose_the_later_to_the_cycle<C: FaultableCluster>(c: &mut C) {
    crossed_routes(c, Seating::Swapped, Lift::Together);
}

/// The crossed routes with one venue hearing late: the later route still
/// loses fast on both.
///
/// Only the cut on the venue where the later route waits lifts. That
/// venue places it behind its head, proves the cycle off the other's
/// seats and aborts it, which deletes its row there and with it the
/// cycle reading the other venue would need. The other cut lifts only
/// once the route has left the first venue. The other venue then places
/// the earlier route behind the later, its head, and reads the later's
/// leaving off the first venue: verdict leaf and row gone, committed
/// marker standing. It aborts the later route unnamed, and the earlier
/// heads, is served and accepts on both venues, all within half a naming
/// window of the second lift. Without the leaving the later route would
/// hold its head until its window closed.
///
/// Requires disjoint committees, as the cut is keyed on the hosts.
///
/// # Panics
///
/// As [`routes_seated_in_opposite_order_lose_the_later_to_the_cycle`],
/// the bound running from the second lift.
pub fn a_venue_hearing_late_still_loses_the_later_route_fast<C: FaultableCluster>(c: &mut C) {
    crossed_routes(c, Seating::AsSubmitted, Lift::VictimsWaitingVenueFirst);
}

/// Which route each venue seats in [`crossed_routes`].
#[derive(Clone, Copy, PartialEq, Eq)]
enum Seating {
    /// The first venue the first route, the second venue the second.
    AsSubmitted,
    /// The first venue the second route, the second venue the first.
    Swapped,
}

/// When the cuts of [`crossed_routes`] lift.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Lift {
    /// Both at once.
    Together,
    /// The cut on the venue where the later route waits first, and the
    /// other once that route has left that venue.
    VictimsWaitingVenueFirst,
}

/// Two routes headed in opposite order on the two venues as `seating`
/// says, the cuts lifting as `lift` says, the cycle between them ended by
/// a wound of the later hash.
fn crossed_routes<C: FaultableCluster>(c: &mut C, seating: Seating, lift: Lift) {
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
    let windowed = c.metric("heads_windowed", None);
    let row_on = |c: &C, venue: ShardId, route: TxHash| {
        c.queued_rows(venue)
            .and_then(|rows| rows.get(&route).cloned())
    };
    let heads = [
        (FIRST_VENUE_SHARD, held_first, held_second),
        (SECOND_VENUE_SHARD, held_second, held_first),
    ];
    let [victim, survivor] = if routes[0] > routes[1] {
        routes
    } else {
        [routes[1], routes[0]]
    };
    // The later route waits where the earlier heads.
    let (waits_at, heads_at) = if held_first == survivor {
        (FIRST_VENUE_SHARD, SECOND_VENUE_SHARD)
    } else {
        (SECOND_VENUE_SHARD, FIRST_VENUE_SHARD)
    };
    let venues = [FIRST_VENUE_SHARD, SECOND_VENUE_SHARD];

    // While the cut stands each venue heads the route whose record it
    // heard, and the other route is not placed there.
    assert!(
        c.run_until(epochs(8), |c| {
            cut.iter().all(|handle| handle.fired() > 0)
                && heads.iter().all(|&(venue, own, other)| {
                    row_on(c, venue, own)
                        .is_some_and(|row| row.state == RowState::Pending && row.head.is_some())
                        && row_on(c, venue, other).is_none_or(|row| row.queued.is_none())
                })
        }),
        "each venue must head the route whose record it heard, the other unplaced there",
    );
    assert_eq!(
        c.metric("hold_inversions_proven", None),
        proven,
        "no venue seats the route the other heads while the cuts stand, so nothing is proven",
    );

    let late_cut = if heads_at == SECOND_VENUE_SHARD {
        (SECOND_VENUE_SHARD, first_hears)
    } else {
        (FIRST_VENUE_SHARD, second_hears)
    };
    let (start, proven) = lift_crossed_cuts(c, lift, &heads, (victim, waits_at), late_cut, proven);
    let bound = start.plus(NAMING_WINDOW / 2);
    let gone = the_later_leaves_both_venues_by(c, victim, &venues, bound);
    let accepted = the_earlier_accepts_on_both_venues_by(c, survivor, &venues, bound);
    let since = |at: WeightedTimestamp| at.as_millis().saturating_sub(start.as_millis());
    println!(
        "crossed routes, lifted {}: from {start:?}, the later gone from {:?} at +{:?} ms, the \
         earlier accepted at +{:?} ms, against a window of {} ms",
        match lift {
            Lift::Together => "together",
            Lift::VictimsWaitingVenueFirst => "the waiting venue first",
        },
        venues,
        gone.iter().map(|at| since(*at)).collect::<Vec<_>>(),
        accepted.iter().map(|at| since(*at)).collect::<Vec<_>>(),
        NAMING_WINDOW.as_millis(),
    );

    the_cycle_ends_by_a_wound(c, [victim, survivor], &venues, (proven, windowed));
    the_later_comes_home_by(c, &protocol_resource, &charges, validity);
    units.assert_settles_within(c, &Charges::default(), epochs(8), "crossed holds");
}

/// Assert the later route's input is home on the clock its `validity` sets.
///
/// It comes home off its validity end, however early the cycle ended:
/// past one horizon, inside two epochs. The wait is held to that clock and
/// not to one running from the wound.
fn the_later_comes_home_by<C: FaultableCluster>(
    c: &mut C,
    world: &World,
    charges: &Charges,
    validity: TimestampRange,
) {
    let validity_end = Duration::from_millis(validity.end_timestamp_exclusive.as_millis());
    let epoch =
        Duration::from_millis(epoch_duration_ms(c).expect("the beacon carries its epoch length"));
    let deadline = validity_end + RETENTION_HORIZON + epoch * 2;
    let _ = c.run_until(epochs(40), |c| {
        c.now() >= deadline || world.settles(c, charges.burned(c))
    });
    let home = c.now();
    println!(
        "crossed routes: home at {home:?}, {:?} past the validity end {validity_end:?}",
        home.saturating_sub(validity_end),
    );
    assert!(
        home < deadline,
        "the later route's input must be home by {deadline:?} on the clock, and it is {home:?}",
    );
    world.assert_settles_within(c, charges, epochs(1), "crossed holds");
}

/// Assert `victim` aborts and `survivor` accepts, no tick on `venues`
/// having named it to run, a block having proven its abort on each venue
/// and no head having left at its window: `proven` is the count of
/// `hold_inversions_proven` short of the second venue's proof, and
/// `windowed` is `heads_windowed` before.
fn the_cycle_ends_by_a_wound<C: FaultableCluster>(
    c: &mut C,
    [victim, survivor]: [TxHash; 2],
    venues: &[ShardId],
    (proven, windowed): (u64, u64),
) {
    let resolved = c.run_until(epochs(8), |c| {
        [victim, survivor]
            .iter()
            .all(|hash| c.tx_status(*hash).is_some_and(|status| status.is_final()))
    });
    assert!(
        resolved,
        "both routes must resolve: {:?}",
        [victim, survivor].map(|hash| c.tx_status(hash)),
    );
    assert_eq!(
        c.tx_status(victim),
        Some(TransactionStatus::Completed(TransactionDecision::Aborted)),
        "the later route aborts",
    );
    assert_eq!(
        c.tx_status(survivor),
        Some(TransactionStatus::Completed(TransactionDecision::Accept)),
        "the earlier route accepts",
    );
    for &venue in venues {
        assert_eq!(
            named_to_run(c, venue, victim),
            Vec::new(),
            "no tick on {venue:?} names the later route to run",
        );
    }
    assert!(
        c.metric("hold_inversions_proven", None) > proven,
        "a block on the second venue proves the later route's abort",
    );
    assert_eq!(
        c.metric("heads_windowed", None),
        windowed,
        "no head leaves at its naming window",
    );
}

/// The heights on `venue`'s chain of the lines naming `tx` to run, where
/// the cluster keeps a chain it walks. An aborting line is not among them.
fn named_to_run<C: Cluster>(c: &C, venue: ShardId, tx: TxHash) -> Vec<(TxHash, BlockHeight)> {
    c.chain_mentions(venue, BlockHeight::new(1), &BTreeSet::from([tx]))
        .map_or_else(Vec::new, |mentions| mentions.run)
}

/// Lift the cuts of [`crossed_routes`] as `lift` says, and return the
/// clock the later route's bound runs from, the later of the two heads'
/// refusals where both lift together and the second lift otherwise, with
/// a count of `hold_inversions_proven` that only the second venue's
/// abort of it can pass, `proven` being the count before.
///
/// Each of `heads` is a venue, the route it heads and the route it holds
/// behind. `victim` waits at `waits_at`; `late_cut`, the venue and the
/// producer it is cut off from, stands until the victim has left there.
fn lift_crossed_cuts<C: FaultableCluster>(
    c: &mut C,
    lift: Lift,
    heads: &[(ShardId, TxHash, TxHash); 2],
    (victim, waits_at): (TxHash, ShardId),
    (late_venue, late_producer): (ShardId, ShardId),
    proven: u64,
) -> (WeightedTimestamp, u64) {
    let clock = |c: &C| WeightedTimestamp::ZERO.plus(c.now());
    let row_on = |c: &C, venue: ShardId, route: TxHash| {
        c.queued_rows(venue)
            .and_then(|rows| rows.get(&route).cloned())
    };
    // Once a venue hears both records it places the other route behind
    // its head, which refuses it and takes the clock of that block: a head
    // refusing nobody while the cuts stood. Seen venue by venue, since the
    // wound can take the later route's row from one venue before the
    // other has placed. A poll is a second of cluster clock, and a head
    // can be placed against and wounded inside one; a venue whose head is
    // first seen already gone takes that poll's clock, which is past its
    // refusal.
    let refused: RefCell<BTreeMap<ShardId, WeightedTimestamp>> = RefCell::new(BTreeMap::new());
    let placed = |c: &C, on: &[ShardId]| {
        for &(venue, own, _) in heads {
            let head = row_on(c, venue, own)
                .filter(|row| row.state == RowState::Pending && row.head.is_some());
            let seen = match head {
                Some(row) => row.blocked_at,
                None => Some(clock(c)),
            };
            if on.contains(&venue)
                && let Some(seen) = seen
            {
                refused.borrow_mut().entry(venue).or_insert(seen);
            }
        }
        on.iter().all(|venue| refused.borrow().contains_key(venue))
    };
    c.clear_drops();
    match lift {
        Lift::Together => {
            let venues = heads.map(|(venue, _, _)| venue);
            assert!(
                c.run_until(epochs(8), |c| placed(c, &venues)),
                "each venue must hold the other route behind its head, refusing it: refused \
                 {:?}, rows {:?}",
                refused.borrow(),
                heads.map(|(venue, own, other)| (
                    venue,
                    row_on(c, venue, own).map(|row| (row.state, row.head, row.blocked_at)),
                    row_on(c, venue, other).map(|row| (row.state, row.queued, row.head)),
                )),
            );
            let later = refused.borrow().values().max().copied();
            (later.expect("both venues refused"), proven + 1)
        }
        Lift::VictimsWaitingVenueFirst => {
            let _standing = isolate_crossing_intake(c, late_venue, late_producer);
            assert!(
                c.run_until(epochs(8), |c| placed(c, &[waits_at])),
                "the venue hearing first must hold the later route behind its head",
            );
            // Its row gone, not only aborted: an aborted row standing
            // unseated until its tick settles still reads as the cycle.
            assert!(
                c.run_until(epochs(8), |c| row_on(c, waits_at, victim).is_none()),
                "the later route's row must leave the venue where it waits",
            );
            let first_refused = refused.borrow()[&waits_at];
            assert!(
                clock(c) <= first_refused.plus(NAMING_WINDOW / 2),
                "the venue hearing first must wound the later route off the other's seats: \
                 refused at {first_refused:?}, gone by {:?}",
                clock(c),
            );
            // A dozen heights on, three seat asks apart, so no anchor the
            // venue hearing late asks at still holds the row.
            assert!(
                await_blocks(c, waits_at, 12, epochs(8)),
                "the venue where the later route waited must keep committing",
            );
            assert!(
                row_on(c, late_venue, victim)
                    .is_some_and(|row| row.state == RowState::Pending && row.head.is_some()),
                "the later route must still head the venue hearing late",
            );
            // Read with the row gone from the first venue, which so names
            // no further abort of it, and still standing on the late one.
            let first_venue_proved = c.metric("hold_inversions_proven", None);
            assert!(
                first_venue_proved > proven,
                "a block on the venue hearing first proves the cycle",
            );
            c.clear_drops();
            (clock(c), first_venue_proved)
        }
    }
}

/// Assert `route` accepts on each of `venues` by `bound`, and return when
/// each chain was first seen holding the accept.
fn the_earlier_accepts_on_both_venues_by<C: Cluster>(
    c: &mut C,
    route: TxHash,
    venues: &[ShardId],
    bound: WeightedTimestamp,
) -> Vec<WeightedTimestamp> {
    let clock = |c: &C| WeightedTimestamp::ZERO.plus(c.now());
    let accepted: RefCell<BTreeMap<ShardId, WeightedTimestamp>> = RefCell::new(BTreeMap::new());
    let all_accepted = c.run_until(epochs(8), |c| {
        for &venue in venues {
            if matches!(
                c.chain_fate(venue, route).1,
                Some((_, TransactionDecision::Accept))
            ) {
                accepted
                    .borrow_mut()
                    .entry(venue)
                    .or_insert_with(|| clock(c));
            }
        }
        accepted.borrow().len() == venues.len()
    });
    assert!(
        all_accepted,
        "the earlier route must accept on every venue: {:?}",
        venues
            .iter()
            .map(|venue| c.chain_fate(*venue, route))
            .collect::<Vec<_>>(),
    );
    let accepted = accepted.into_inner();
    for venue in venues {
        let at = accepted[venue];
        assert!(
            at <= bound,
            "the earlier route must accept on {venue:?} by {bound:?}: accepted at {at:?}",
        );
    }
    venues.iter().map(|venue| accepted[venue]).collect()
}

/// Assert `route` leaves each of `venues` by `bound`, and return when it
/// was first seen gone from each.
fn the_later_leaves_both_venues_by<C: Cluster>(
    c: &mut C,
    route: TxHash,
    venues: &[ShardId],
    bound: WeightedTimestamp,
) -> Vec<WeightedTimestamp> {
    let clock = |c: &C| WeightedTimestamp::ZERO.plus(c.now());
    let left: RefCell<BTreeMap<ShardId, WeightedTimestamp>> = RefCell::new(BTreeMap::new());
    let all_left = c.run_until(epochs(8), |c| {
        for &venue in venues {
            let waits = c.queued_rows(venue).is_some_and(|rows| {
                rows.get(&route)
                    .is_some_and(|row| row.state == RowState::Pending)
            });
            if !waits {
                left.borrow_mut().entry(venue).or_insert_with(|| clock(c));
            }
        }
        left.borrow().len() == venues.len()
    });
    assert!(all_left, "the later route must leave every venue");
    let left = left.into_inner();
    for venue in venues {
        let gone = left[venue];
        assert!(
            gone <= bound,
            "the later route must leave {venue:?} by {bound:?}: gone at {gone:?}",
        );
    }
    venues.iter().map(|venue| left[venue]).collect()
}

/// Three routes held in a ring of three venues abort at their naming
/// windows.
///
/// Each route runs from one venue to the next round the ring, its trader
/// on its first venue's shard, so it pays there and is placed there at
/// its commit, and reaches its second venue by that venue's bundle. A
/// venue's successor serves it a route's part only from the block that
/// makes the route head there, which it never is while the successor's
/// own route heads, and each venue is cut off from its successor's
/// bundles besides: every route stands head and unready on its first
/// venue. Each venue commits the route arriving from its predecessor only
/// once the predecessor's bundle lands, which places it behind the
/// venue's own route on the venue's reserve: each venue's own route
/// refuses its predecessor's route there, and takes the clock of the
/// block that first shows it. No two of the routes await a shard in
/// common and none is named, so no venue can read the cycle off one
/// counterpart's seats: each route is aborted unnamed on its first venue
/// once its naming window closes, short of its deadline, and its payer
/// pays its charge.
///
/// Requires disjoint committees, as the cut is keyed on the hosts.
///
/// # Panics
///
/// Panics if a venue misses its budget standing up, if the cut never
/// fires, if the venues do not place the routes round the ring, if any
/// route runs on its first venue, is not aborted there within its naming
/// window of its first refusal, or resolves otherwise than aborted before
/// its deadline, if a block aborts any as a proven victim or counts a
/// contention, or if either side is not conserved.
pub fn routes_held_in_a_ring_abort_at_the_window<C: FaultableCluster>(c: &mut C) {
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
    let contended = c.metric("hold_contentions", None);
    let windowed = c.metric("heads_windowed", None);

    // Each venue holds its own route head, unnamed and refusing, and the
    // route arriving from the venue before it placed behind it.
    let ring_stands = |c: &C| {
        (0..RING.len()).all(|at| {
            c.queued_rows(RING[at]).is_some_and(|rows| {
                let own = rows.get(&routes[at]);
                let arriving = rows.get(&routes[prev(at)]);
                own.is_some_and(|row| {
                    row.state == RowState::Pending && row.head.is_some() && row.blocked_at.is_some()
                }) && arriving.is_some_and(|row| {
                    row.state == RowState::Pending && row.queued.is_some() && row.head.is_none()
                })
            })
        })
    };
    assert!(
        c.run_until(epochs(8), |c| ring_stands(c)),
        "each venue must place its own route head, refusing the route arriving from the venue \
         before it",
    );
    let heads: Vec<(ShardId, TxHash)> = RING.iter().copied().zip(routes.iter().copied()).collect();
    each_leaves_its_head_at_its_window(
        c,
        &heads,
        Deadline::of(validity.end_timestamp_exclusive).at(),
    );

    each_aborts_unnamed(c, &heads);
    assert!(
        cut.iter().all(|handle| handle.fired() > 0),
        "each venue must actually have been cut off from its successor's bundles",
    );
    c.clear_drops();
    assert_eq!(
        c.metric("hold_inversions_proven", None),
        proven,
        "no block can prove a ring off one counterpart's seats",
    );
    // Counted per block built, so a round that fails and is built again
    // counts its window twice.
    assert!(
        c.metric("heads_windowed", None) >= windowed + 3,
        "each route leaves its head at its window",
    );
    assert_eq!(
        c.metric("hold_contentions", None),
        contended,
        "a ring pairs no members awaiting a shard in common",
    );
    protocol_resource.assert_settles_within(c, &charges, epochs(8), "a ring of holds");
    units.assert_settles_within(c, &Charges::default(), epochs(8), "a ring of holds");
}

/// Assert each of `heads`, a route and the venue it headed, aborts with no
/// tick there having named it to run.
fn each_aborts_unnamed<C: Cluster>(c: &mut C, heads: &[(ShardId, TxHash)]) {
    let resolved = c.run_until(epochs(8), |c| {
        heads
            .iter()
            .all(|(_, route)| c.tx_status(*route).is_some_and(|status| status.is_final()))
    });
    assert!(resolved, "the windows must resolve every route");
    for &(venue, route) in heads {
        assert_eq!(
            c.tx_status(route),
            Some(TransactionStatus::Completed(TransactionDecision::Aborted)),
            "a route held in the ring aborts at its window",
        );
        assert_eq!(
            named_to_run(c, venue, route),
            Vec::new(),
            "no tick on {venue:?} names the route it held to run",
        );
    }
}

/// Assert each of `heads`, a route standing head on its venue with a
/// refusal clock, leaves that venue by an abort named at its naming
/// window, short of `deadline`.
fn each_leaves_its_head_at_its_window<C: Cluster>(
    c: &mut C,
    heads: &[(ShardId, TxHash)],
    deadline: WeightedTimestamp,
) {
    let refused: Vec<WeightedTimestamp> = heads
        .iter()
        .map(|&(venue, route)| {
            c.queued_rows(venue)
                .and_then(|rows| rows.get(&route).and_then(|row| row.blocked_at))
                .expect("the head stands refusing")
        })
        .collect();
    // Each route leaves its venue by the window's abort, its row there
    // gone or let go of; the time each is first seen gone is when it
    // left.
    let clock = |c: &C| WeightedTimestamp::ZERO.plus(c.now());
    let left: RefCell<BTreeMap<usize, WeightedTimestamp>> = RefCell::new(BTreeMap::new());
    let all_left = c.run_until(epochs(8), |c| {
        for (at, &(venue, route)) in heads.iter().enumerate() {
            let waits = c.queued_rows(venue).is_some_and(|rows| {
                rows.get(&route)
                    .is_some_and(|row| row.state == RowState::Pending)
            });
            if !waits {
                left.borrow_mut().entry(at).or_insert_with(|| clock(c));
            }
        }
        left.borrow().len() == heads.len()
    });
    assert!(all_left, "every route must leave the venue it heads");
    // A window closes at an anchor; the abort is named in the block
    // anchored there and folds a block or two later.
    let slack = Duration::from_secs(4);
    for (at, gone) in left.into_inner() {
        let (venue, _) = heads[at];
        let closes = refused[at].plus(NAMING_WINDOW);
        assert!(
            gone >= closes && gone <= closes.plus(slack) && gone < deadline,
            "route {at} must leave {venue:?} at its naming window: refused at {:?}, the window \
             closing at {closes:?}, gone at {gone:?}, its deadline {deadline:?}",
            refused[at],
        );
    }
}

/// One route with the venues cut off from each other across the
/// trader's deadline, and the trader's paid leg not reclaimed at it.
///
/// Neither venue can read the other's state or hold its certificate,
/// pushes and pulls alike, so the two-shard core commits the route,
/// each venue states its yes, and neither can accept while the cut
/// stands. The trader's leg meanwhile pays its input and reaches its
/// deadline with the core silent. Its crossing goes back only on the
/// core's `Never`, and a core that stated writes none: a stated row
/// leaves only on what it hears, so the deadline ends neither venue's
/// row. The leg stays paid. The cut lifts inside the delivery window,
/// each venue reads the other's yes, and the route accepts: paid once,
/// delivered once.
///
/// One route rather than the usual four: the core's row for the first
/// holds the venues' reserves until it accepts, so a second route could
/// not compose while the cut stood and would be aborted at the deadline
/// instead, a refusal whose `Never` rightly returns the leg's crossing,
/// and not the boundary this pins.
///
/// Requires disjoint committees — a host serving both venues, or a venue
/// and the trader, would carry readings in-process past the cut or be
/// cut off from its own shard by it.
///
/// # Panics
///
/// Panics if either venue misses its budget standing up, if the trader's
/// leg never pays, if the cut never fires or lifts outside the delivery
/// window, if the trader is refunded while the cut stands past the
/// deadline, if the route does not accept once the cut lifts, or
/// if either side of the pair is not conserved.
pub fn a_route_cut_off_across_its_deadline_is_not_reclaimed<C: FaultableCluster>(c: &mut C) {
    let mut taken = Vec::new();
    let (first, second) = stand_up_venues(c, &mut taken);
    let traders = traders(&mut taken);
    let (key, trader) = &traders[0];
    // Neither venue can read the other's verdict or obtain its
    // certificate by any path, push or pull; the trader's shard is
    // untouched, and its leg awaits nobody.
    let cut = [
        isolate_ec_intake(c, FIRST_VENUE_SHARD, SECOND_VENUE_SHARD),
        isolate_ec_intake(c, SECOND_VENUE_SHARD, FIRST_VENUE_SHARD),
        isolate_crossing_intake(c, FIRST_VENUE_SHARD, SECOND_VENUE_SHARD),
        isolate_crossing_intake(c, SECOND_VENUE_SHARD, FIRST_VENUE_SHARD),
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

    // Past the deadline, and held there until each venue's chain has
    // committed blocks anchored past it with the route's row still
    // stated: the deadline is no exit of a row that said yes, so the
    // core is not aborted and writes no `Never`. Read off the rows
    // rather than off a settling delay, so the scenario fails where the
    // evidence is instead of wherever a timer happened to land.
    let validity_end = validity.end_timestamp_exclusive;
    let deadline = Deadline::of(validity_end).at();
    let clock = |c: &C| WeightedTimestamp::ZERO.plus(c.now());
    assert!(
        c.run_until(epochs(8), |c| clock(c) >= deadline),
        "the cut must stand past the transaction's deadline",
    );
    let reclaimed = c.metric("reclaims_folded", None);
    assert_stated_past_the_deadline(c, hash);
    assert!(
        cut.iter().any(|handle| handle.fired() > 0),
        "the channels between the venues must actually have been exercised and cut",
    );
    for shard in [FIRST_VENUE_SHARD, SECOND_VENUE_SHARD] {
        assert!(
            c.chain_fate(shard, hash).1.is_none(),
            "the core must still be waiting on its sibling's verdict when the cut lifts, \
             or the leg below stays paid on the core's verdict rather than on its silence",
        );
    }
    assert_eq!(
        held(c, trader.address(), *PROTOCOL_RESOURCE),
        paid,
        "a leg whose core committed the transaction must stay paid at its deadline: \
         the core writes no `Never`, so nothing returns the crossing",
    );
    assert_eq!(
        c.metric("reclaims_folded", None),
        reclaimed,
        "no return folds anywhere in the cluster while the core is pending",
    );

    // Whole network from here: the readings flow, the core settles,
    // and the trader banks the route's output.
    c.clear_drops();
    assert!(
        c.run_until(epochs(8), |c| held(c, trader.address(), *PROTOCOL_RESOURCE)
            > paid),
        "the core must settle once its readings flow, and the route bank its output",
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

/// Run each venue's chain on past the transaction's deadline, which the
/// cluster clock has passed, and assert `hash`'s row still stands stated
/// on both.
///
/// # Panics
///
/// Panics if either venue commits no block anchored past the deadline
/// within budget, or either row has left `Stated`.
fn assert_stated_past_the_deadline<C: Cluster>(c: &mut C, hash: TxHash) {
    let venues = [FIRST_VENUE_SHARD, SECOND_VENUE_SHARD];
    let at_the_deadline = venues.map(|venue| c.committed_height(venue));
    let stated = |c: &C, venue: ShardId| {
        c.member_rows(venue)
            .is_some_and(|rows| matches!(rows.get(&hash), Some(RowState::Stated { .. })))
    };
    // A block's anchor is its parent's certificate, so the second block
    // committed past the deadline's instant is anchored past it.
    assert!(
        c.run_until(epochs(8), |c| venues
            .iter()
            .zip(at_the_deadline)
            .all(|(venue, then)| c.committed_height(*venue)
                > then.map(|then| BlockHeight::new(then.inner() + 2)))),
        "each venue must commit blocks anchored past the deadline",
    );
    assert!(
        venues.iter().all(|venue| stated(c, *venue)),
        "each venue's row must stand stated past the deadline: first {:?}, second {:?}",
        c.member_rows(FIRST_VENUE_SHARD)
            .and_then(|rows| rows.get(&hash).copied()),
        c.member_rows(SECOND_VENUE_SHARD)
            .and_then(|rows| rows.get(&hash).copied()),
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
/// A route's core holds the first venue's reserves while neither venue
/// can read the other's verdict, so a swap by a caller on the first
/// venue's shard commits and waits behind the hold. The shard then certifies nothing
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
        c.submit(tx);
        hash
    };

    let healthy = local_transfer(c, 1);
    let status = await_tx_terminal(c, healthy, epochs(8));
    assert_eq!(
        status,
        Some(TransactionStatus::Completed(TransactionDecision::Accept)),
        "a transfer local to {shard:?} must accept while nothing is cut",
    );

    // Neither venue can read the other's verdict by any path, push or
    // pull, so the core states and stands held: a sibling's certificate
    // decides nothing here, and needs no cut.
    let cut = [
        isolate_crossing_intake(c, FIRST_VENUE_SHARD, SECOND_VENUE_SHARD),
        isolate_crossing_intake(c, SECOND_VENUE_SHARD, FIRST_VENUE_SHARD),
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
    c.submit(route);
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
    c.submit(swap);
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
        "the verdict readings must actually have been exercised and cut",
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
        self.stand_from_now(c, until, 0)
    }

    /// Hold the shard from its height now until the cluster clock
    /// reaches `until`, letting it commit at most `drain` blocks off the
    /// rounds in flight, and return the height it stood at.
    fn stand_from_now<C: FaultableCluster>(
        &self,
        c: &mut C,
        until: WeightedTimestamp,
        drain: u64,
    ) -> BlockHeight {
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
        let advanced = c
            .committed_height(self.shard)
            .map_or(0, |height| height.inner() - frozen.inner());
        assert!(
            advanced <= drain,
            "half the committee withholding leaves no quorum, so {:?} must halt: {advanced} \
             blocks committed past {frozen:?}",
            self.shard,
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
/// by a silent sibling has no answer to give: its yes stands in its
/// state, and the sibling may yet accept on it. What the
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

/// Hold one route's core by cutting its siblings' certificates and
/// readings of each other past the close of [`Window::Core`], then lift
/// the cut and settle it, its fee paid by `payer`. The readings are cut
/// among every host outside the trader shard's committee, since the
/// venues' committees may gain members over a span this long.
fn route_held_by_a_silent_sibling<C: FaultableCluster>(c: &mut C, payer: FeePayer) {
    let mut taken = Vec::new();
    let (first, second) = stand_up_venues(c, &mut taken);
    let traders = traders(&mut taken);
    let sponsor = sponsor(&mut taken);
    let (key, trader) = &traders[0];
    let cut = [
        isolate_ec_intake(c, FIRST_VENUE_SHARD, SECOND_VENUE_SHARD),
        isolate_ec_intake(c, SECOND_VENUE_SHARD, FIRST_VENUE_SHARD),
        isolate_crossing_intake_among(c, &[TRADER_SHARD]),
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
        "the channels between the venues must actually have been exercised and cut",
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

/// A route's core stated on both venues through a halt of its first
/// venue's shard is accepted on both past the recovery, and the trader's
/// escrowed input is spent on the route.
///
/// The core is held on both venues, each cut off from the other's state
/// and certificates, and stands stated on both through a halt of the
/// first venue's shard and its committee redraw. The recovery's crossing
/// block keeps the stated row and the yes it staged, so neither venue
/// withdraws its yes. Once the venues read each other, both accept, both
/// rows end, and both resources settle.
///
/// # Panics
///
/// Panics if the core never stands stated on both venues, the halt or
/// its recovery misses a budget, either venue's shard does not accept
/// the core, a row, leaf or staged yes of it stands, or either resource
/// does not settle.
pub fn a_core_stated_at_a_halt_is_accepted_on_both_venues<C: FaultableCluster>(c: &mut C) {
    let (halted, survivor) = (FIRST_VENUE_SHARD, SECOND_VENUE_SHARD);
    let venues = [halted, survivor];
    let mut taken = Vec::new();
    let (first, second) = stand_up_venues(c, &mut taken);
    let traders = traders(&mut taken);
    let sponsor = sponsor(&mut taken);
    let (key, trader) = &traders[0];
    let cut = [
        isolate_ec_intake(c, halted, survivor),
        isolate_ec_intake(c, survivor, halted),
        isolate_crossing_intake(c, halted, survivor),
        isolate_crossing_intake(c, survivor, halted),
    ];
    let (protocol_resource, units) =
        route_worlds(c, &first, &second, accounts(&traders).chain([sponsor.1]));
    let mut charges = Charges::default();
    let route = build_route_tx(
        key,
        *trader,
        (&first.meta, &second.meta),
        *PROTOCOL_RESOURCE,
        ROUTE_INPUT,
        0,
        validity_around(c.now()),
    );
    let hash = charges.submit(c, route);
    let stated_on =
        |c: &C, shard: ShardId| matches!(row_on(c, shard, hash), Some(RowState::Stated { .. }));
    assert!(
        c.run_until(epochs(8), |c| stated_on(c, halted)
            && stated_on(c, survivor)),
        "the route's core must stand stated on both venues: {:?} {:?}",
        row_on(c, halted, hash),
        row_on(c, survivor, hash),
    );
    // The recovery's frontier is the last boundary the beacon attested,
    // so the block stating the core has to stand through one.
    c.run_until(epochs(2), |_| false);

    let halt = freeze_shard(c, halted, survivor, |_| {});
    assert!(
        cut.iter().any(|handle| handle.fired() > 0),
        "the channels between the venues must actually have been exercised and cut",
    );
    await_halt_recovery(c, &halt);
    c.clear_drops();
    assert!(
        c.run_until(epochs(RECOVERED_ROW_EPOCHS), |c| venues.iter().all(
            |venue| accepted_on(c, *venue, hash) && row_on(c, *venue, hash).is_none()
        )),
        "both venues accept the route's core and both rows end: {:?} {:?}",
        venues.map(|venue| c.chain_fate(venue, hash).1),
        venues.map(|venue| row_on(c, venue, hash)),
    );
    for venue in venues {
        assert!(
            !leaf_stands(c, venue, hash) && !staged_stands(c, venue, hash),
            "{venue:?} keeps no leaf or staged yes of the route",
        );
    }
    protocol_resource.assert_settles_within(
        c,
        &charges,
        epochs(8),
        "a core stated on both venues through a halt",
    );
    units.assert_settles_within(
        c,
        &Charges::default(),
        epochs(8),
        "a core stated on both venues through a halt",
    );
}

/// How long past now the near route of
/// [`a_stall_past_the_finalization_delay_states_every_member_of_its_tick`]
/// is valid: time enough for both venues to name it, and short of the
/// others' validity.
const NEAR_VALIDITY: Duration = Duration::from_secs(45);

/// Stall `shard` by withholding half its committee's block votes until
/// the cluster clock reaches `until`, then lift the stall and let the
/// shard commit again.
///
/// # Panics
///
/// Panics if the stall never stands until `until`, if the withheld votes
/// are never refused or the shard keeps committing through them, or if
/// the shard does not commit again once they flow.
fn stall_past<C: FaultableCluster>(c: &mut C, shard: ShardId, until: WeightedTimestamp) {
    let halt = Halt::of(c, shard);
    halt.stand_from_now(c, until, STALL_DRAIN_BLOCKS);
    halt.lift(c);
    assert!(
        await_blocks(c, shard, 4, epochs(2)),
        "{shard:?} must commit again once the stall lifts",
    );
}

/// A route per trader through a pair of venues of its own, one on each
/// shard, so no two routes touch the same reserves and one tick can run
/// them all: the first valid for [`NEAR_VALIDITY`] past `now` and the
/// rest for the full window.
fn near_among_long_routes(
    now: Duration,
    traders: &[(Ed25519PrivateKey, PrincipalAddr)],
    (firsts, seconds): (&[StockedVenue], &[StockedVenue]),
) -> Vec<Transaction> {
    let near = TimestampRange::new(
        WeightedTimestamp::ZERO.plus(now.saturating_sub(Duration::from_secs(5))),
        WeightedTimestamp::ZERO.plus(now + NEAR_VALIDITY),
    );
    traders
        .iter()
        .zip(firsts.iter().zip(seconds))
        .enumerate()
        .map(|(index, ((key, trader), (first, second)))| {
            let validity = if index == 0 {
                near
            } else {
                validity_around(now)
            };
            build_route_tx(
                key,
                *trader,
                (&first.meta, &second.meta),
                *PROTOCOL_RESOURCE,
                ROUTE_INPUT,
                0,
                validity,
            )
        })
        .collect()
}

/// Blocks a stalled shard may still commit off the rounds in flight when
/// its votes are withheld.
const STALL_DRAIN_BLOCKS: u64 = 2;

/// Every member of a tick a view-change stall holds past one member's
/// deadline still states once the stall lifts.
///
/// One route valid for [`NEAR_VALIDITY`] and the rest for the full
/// window, each through venues of its own, are submitted together, and
/// the first venue's committee cannot hear its own execution votes, so
/// no tick there certifies. Once each
/// venue holds every route's member, the first venue's committee
/// withholds half its block votes for longer than
/// [`MAX_FINALIZATION_DELAY`] and past the near route's deadline. The
/// stall lifts, the chain commits past the deadline with the near
/// member still standing in flight, and only then do the execution votes
/// flow: the stating half lands inside the near member's stating window,
/// and every route accepts on both venues.
///
/// Requires disjoint committees, as the vote cut is keyed on the first
/// venue's hosts.
///
/// # Panics
///
/// Panics if either venue misses its budget standing up, if a venue does
/// not hold every route's member before the near deadline, if the near
/// member shares no tick with another route on the first venue, if the
/// stall or the vote cut never fires, if the near member does not stand
/// in flight past its deadline, or if any route does not accept on both
/// venues.
pub fn a_stall_past_the_finalization_delay_states_every_member_of_its_tick<C: FaultableCluster>(
    c: &mut C,
) {
    let (stalled, sibling) = (FIRST_VENUE_SHARD, SECOND_VENUE_SHARD);
    let mut taken = Vec::new();
    let venues = stand_up_venues_on(c, &[stalled, sibling], ROUTES, &mut taken);
    let traders = traders(&mut taken);
    let hosts = c.committee_hosts(stalled);
    let votes_cut = c.drop_type_between(&hosts, &hosts, "execution.vote");

    let routes = near_among_long_routes(c.now(), &traders, (&venues[0], &venues[1]));
    let near = routes[0].hash();
    c.with_derivation(|derivation| routes[0].try_declared(derivation))
        .expect("a scenario route declares its terms");
    let deadline = Deadline::of_transaction(&routes[0]);
    let hashes: Vec<TxHash> = routes.iter().map(Transaction::hash).collect();
    let mut charges = Charges::default();
    for route in routes {
        charges.submit(c, route);
    }

    let tick_of = |c: &C, shard: ShardId, tx: TxHash| match row_on(c, shard, tx) {
        Some(RowState::InFlight { tick, .. } | RowState::Stated { tick, .. }) => Some(tick),
        _ => None,
    };
    let held = |c: &C| {
        hashes.iter().all(|&tx| {
            matches!(row_on(c, stalled, tx), Some(RowState::InFlight { .. }))
                && tick_of(c, sibling, tx).is_some()
        })
    };
    let clock = |c: &C| WeightedTimestamp::ZERO.plus(c.now());
    assert!(
        c.run_until(epochs(8), |c| held(c) || clock(c) >= deadline.at()),
        "the routes must not settle while {stalled:?} cannot certify",
    );
    assert!(
        held(c) && clock(c) < deadline.at(),
        "both venues must hold every route's member before the near deadline {deadline:?} \
         (clock {:?}): {:?}",
        clock(c),
        hashes
            .iter()
            .map(|&tx| (row_on(c, stalled, tx), row_on(c, sibling, tx)))
            .collect::<Vec<_>>(),
    );
    let near_tick = tick_of(c, stalled, near);
    assert!(
        hashes[1..]
            .iter()
            .any(|&tx| tick_of(c, stalled, tx) == near_tick),
        "the near member must share its tick on {stalled:?} with a longer route",
    );

    stall_past(
        c,
        stalled,
        clock(c).plus(MAX_FINALIZATION_DELAY).max(deadline.at()),
    );
    assert!(
        matches!(
            row_on(c, stalled, near),
            Some(RowState::InFlight { joins, .. }) if joins != Joins::Aborted
        ),
        "the near member stands in flight past its deadline, inside its stating window, \
         with no abort named: {:?}",
        row_on(c, stalled, near),
    );
    assert!(
        votes_cut.fired() > 0,
        "{stalled:?}'s execution votes must actually have been cut",
    );

    c.clear_drops();
    let accepted = |c: &C| {
        hashes
            .iter()
            .all(|&tx| accepted_on(c, stalled, tx) && accepted_on(c, sibling, tx))
    };
    assert!(
        c.run_until(epochs(12), accepted),
        "every route must accept on both venues inside the near member's stating window \
         {:?}: {:?}",
        Window::Stating.of(deadline),
        hashes
            .iter()
            .map(|&tx| (
                verdict_on(c, stalled, tx),
                row_on(c, stalled, tx),
                verdict_on(c, sibling, tx),
                row_on(c, sibling, tx),
            ))
            .collect::<Vec<_>>(),
    );
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
        c.with_derivation(|derivation| route.try_declared(derivation))
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

/// An unseen decline goes once its producer's leg is fated, and not
/// before.
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
/// With no record written the decline takes nothing back on the
/// trader's shard, and the leg's row stands. So the decline stands, and
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
/// if the second venue engages, if the trader's vault moves or the
/// decline goes before the fate, if the decline goes before the trader's
/// leg is fated or outlives its fate, if the leg is fated short of its
/// window's close, if the trader is not charged its price once, or if
/// either world is not conserved.
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

    // The trader's leg never ran, so it issued no record: the decline
    // takes nothing back, charges nothing and deletes no row.
    assert_eq!(
        (
            held(c, trader.address(), *PROTOCOL_RESOURCE),
            unseen_never_at(c, decline),
        ),
        (funded, true),
        "the decline must leave the trader's vault as it was and stand: the leg's row \
         stands until its fate",
    );

    // The decline stands until the leg's row is fated at the close of
    // its leg entry window, and goes once the first venue reads the row
    // absent.
    await_leg_fated(
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
    let legs = &c
        .with_derivation(|derivation| route.try_derived(derivation))
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
    // The venue's own committee certifies its refusal, and that
    // certificate is cut from the shard holding the record. It decides
    // nothing there: the producer reclaims off the `Never` it reads from
    // the venue's state.
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
            &c.with_derivation(|derivation| tx.try_derived(derivation))
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
    /// Each venue shard is cut off from the other's certificates until
    /// the offering ends, and what it learns of its sibling it learns
    /// from a verdict reading, as it does with them. Requires the
    /// venue shards' committees on hosts of their own.
    CutWhileOffered,
}

/// Transfer pairs per loaded shard, each paying within its own shard and
/// cycled one per shard per [`LOAD_PERIOD`].
const LOAD_PAIRS: usize = 4;

/// How often the steady load submits a transfer on each shard it covers.
const LOAD_PERIOD: Duration = Duration::from_secs(2);

/// Epochs a route held past a certificate's life gets to settle in once
/// the venue waiting on it can read its sibling again: a verdict question
/// asked again at the widest gap of its backoff, and the blocks that
/// carry its reading, accept and end the row.
const LATE_CERTIFICATE_SETTLE_EPOCHS: u32 = 8;

/// Epochs the terminal records a grow leaves get to leave beacon state.
const RESHAPE_EVIDENCE_EPOCHS: u32 = 16;

/// The route cast, and transfer pairs local to each venue's shard for a
/// steady load on both, ground last so every other account lands where
/// [`route_genesis_accounts`] puts it.
#[must_use]
pub fn late_certificate_genesis_accounts() -> Vec<(PrincipalAddr, u128)> {
    let mut taken = Vec::new();
    let mut accounts = route_accounts(&mut taken);
    accounts.extend(VenueLoad::new(&mut taken).accounts());
    accounts
}

type Pair = (Ed25519PrivateKey, PrincipalAddr, PrincipalAddr);

/// Steady transfers local to each venue's shard, so both chains carry
/// work of their own whatever a route between them is waiting on.
struct VenueLoad {
    pairs: Vec<Vec<Pair>>,
    round: usize,
    /// The last transfer submitted on each shard, in the order of `pairs`.
    last: Vec<Option<TxHash>>,
    /// A shard the load submits nothing on while it is set.
    paused: Option<ShardId>,
}

impl VenueLoad {
    const SHARDS: [ShardId; 2] = [FIRST_VENUE_SHARD, SECOND_VENUE_SHARD];

    fn new(taken: &mut Vec<u8>) -> Self {
        let pairs = Self::SHARDS
            .iter()
            .map(|&shard| {
                (0..LOAD_PAIRS)
                    .map(|_| {
                        let (key, from) = grind_onto(shard, taken);
                        let (_, to) = grind_onto(shard, taken);
                        (key, from, to)
                    })
                    .collect()
            })
            .collect();
        Self {
            pairs,
            round: 0,
            last: vec![None; Self::SHARDS.len()],
            paused: None,
        }
    }

    fn accounts(&self) -> Vec<(PrincipalAddr, u128)> {
        self.pairs
            .iter()
            .flatten()
            .flat_map(|(_, from, to)| [(*from, SWAPPER_FUNDING), (*to, 10)])
            .collect()
    }

    /// Submit one transfer on each shard the load is not paused on.
    fn submit<C: Cluster>(&mut self, c: &mut C) {
        for ((pairs, last), shard) in self.pairs.iter().zip(&mut self.last).zip(Self::SHARDS) {
            if self.paused == Some(shard) {
                continue;
            }
            let (key, from, to) = &pairs[self.round % LOAD_PAIRS];
            let tx = build_transfer_tx(key, *from, *to, 1, validity_around(c.now()));
            *last = Some(tx.hash());
            c.submit(tx);
        }
        self.round += 1;
    }

    /// Stop submitting on `shard`, and run on until the last transfer
    /// submitted there has an outcome, so no transfer of the load is
    /// left to share a block with what is submitted next.
    fn pause<C: Cluster>(&mut self, c: &mut C, shard: ShardId, span: Duration) {
        self.paused = Some(shard);
        let index = Self::SHARDS
            .iter()
            .position(|&loaded| loaded == shard)
            .expect("the load covers the shard");
        if let Some(hash) = self.last[index] {
            let settled = self.run(c, span, |c| {
                c.tx_status(hash).is_some_and(|status| status.is_final())
            });
            assert!(settled, "the load's last transfer on {shard:?} must settle");
        }
    }

    /// Run under load until `cond` holds, for at most `span`. Whether it
    /// came to hold.
    fn run<C: Cluster>(&mut self, c: &mut C, span: Duration, cond: impl Fn(&C) -> bool) -> bool {
        let deadline = c.now() + span;
        loop {
            if cond(c) {
                return true;
            }
            if c.now() >= deadline {
                return false;
            }
            self.submit(c);
            let next = (c.now() + LOAD_PERIOD).min(deadline);
            c.run_until(epochs(1), |c| c.now() >= next);
        }
    }

    /// A transfer on `shard` submitted now, run under load to an outcome.
    fn settles_on<C: Cluster>(
        &mut self,
        c: &mut C,
        shard: ShardId,
        span: Duration,
    ) -> Option<TransactionStatus> {
        let index = Self::SHARDS
            .iter()
            .position(|&loaded| loaded == shard)
            .expect("the load covers the shard");
        self.submit(c);
        let hash = self.last[index].expect("just submitted");
        self.run(c, span, |c| {
            c.tx_status(hash).is_some_and(|status| status.is_final())
        });
        c.tx_status(hash)
    }
}

/// A route's core settles on both venues when each reads the other's
/// verdict only after the anchor its certificate was signed at has
/// lapsed.
///
/// Both venues state the member, and every road each venue's certificate
/// and state have to the other is cut for three epochs and three
/// [`REATTESTATION_STEP`]s, so the anchor each certificate was signed at
/// is below every schedule floor when the cut lifts: the route is
/// submitted only once the terminal records the grow left are gone, so
/// nothing but the clock holds the floor. Both chains carry transfers of
/// their own throughout. Each row stands stated through the cut, and
/// once it lifts each must accept on the other's state, which no
/// certificate's life bounds, end its row, and let its reserves price a
/// swap again.
///
/// Requires disjoint committees, as its neighbours do.
///
/// # Panics
///
/// Panics if either venue misses its budget standing up, if either
/// venue's member is never stated, if the cut never fires, if either
/// venue settles before the cut lifts, if a transfer local to either
/// venue's shard reaches no outcome after it, if the venues reach no
/// verdict or different ones, if a row of the route stands, or if a swap
/// on the first venue's shard does not accept after it.
pub fn a_route_settles_on_a_certificate_delivered_past_its_life<C: FaultableCluster>(c: &mut C) {
    route_held_past_a_certificates_life(c, LateCertificate::CutOff);
}

/// The same route held with nothing cut between the venues, its second
/// venue's certificate forming only past the life of its tick's anchor.
///
/// The second venue's committee cannot hear its own execution votes
/// until one [`REATTESTATION_STEP`] past the naming of its member, so
/// the certificate its tick's anchor was signed for never forms. Its
/// member stands unstated and unaborted through the span, inside its
/// stating window, and the first venue's stated row waits on it; once
/// the votes flow, the second venue re-signs its tick for a later
/// committee, states the member, and both venues accept. The load
/// pauses on the second venue's shard from just before the route to the
/// fault lifting, so the member's tick there holds it alone and owes no
/// determined half, whose re-signing would state the member with it.
///
/// # Panics
///
/// As [`a_route_settles_on_a_certificate_delivered_past_its_life`], with
/// the second venue's member held unstated rather than stated while the
/// fault stands, or aborted by the time it lifts.
pub fn a_route_settles_on_a_certificate_formed_past_its_life<C: FaultableCluster>(c: &mut C) {
    route_held_past_a_certificates_life(c, LateCertificate::FormedLate);
}

/// The same route held with nothing cut between the venues, its second
/// venue's certificate unable to form before the member's stating window
/// closes: the route aborts on both venues.
///
/// The second venue's committee cannot hear its own execution votes.
/// Its member stands unstated, and the first venue's stated row waits on
/// it. Once the member's stating window closes the second venue names
/// its abort, which settles once the votes flow; the first venue reads
/// the row gone without a yes and refuses. The load pauses on the second
/// venue's shard from just before the route to the fault lifting, so
/// the member's tick there holds it alone and owes no determined half,
/// which would hold the member with no clock.
///
/// # Panics
///
/// As [`a_route_settles_on_a_certificate_delivered_past_its_life`], with
/// the second venue's member held unstated rather than stated while the
/// fault stands, its abort not named once the stating window closes, and
/// the venues aborting rather than accepting.
pub fn a_route_unstated_past_its_stating_window_aborts_on_both_venues<C: FaultableCluster>(
    c: &mut C,
) {
    route_held_past_a_certificates_life(c, LateCertificate::Unformed);
}

/// What keeps a venue's verdict from its sibling past a certificate's
/// life.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum LateCertificate {
    /// Both venues certify and state, and every road each one's
    /// certificate and state have to the other is cut.
    CutOff,
    /// Nothing between the venues is cut: the second venue's committee
    /// cannot hear its own execution votes, so no certificate forms and
    /// its member is never stated while the fault stands. The fault
    /// lifts past the life of the tick's first certificate and inside
    /// the member's stating window.
    FormedLate,
    /// As [`Self::FormedLate`], with the fault standing past the
    /// member's stating window.
    Unformed,
}

impl LateCertificate {
    /// The verdict both venues reach once the fault lifts.
    const fn decision(self) -> TransactionDecision {
        match self {
            Self::CutOff | Self::FormedLate => TransactionDecision::Accept,
            Self::Unformed => TransactionDecision::Aborted,
        }
    }

    /// When the fault lifts, for a route held from `held_from`, its
    /// second venue's member named by `named_by`, and its stating window
    /// closing at `closes`.
    ///
    /// # Panics
    ///
    /// Panics where a certificate re-signed once the fault lifts could
    /// not form inside the stating window.
    fn lifts_at(
        self,
        epoch: Duration,
        held_from: Duration,
        named_by: WeightedTimestamp,
        closes: WeightedTimestamp,
    ) -> WeightedTimestamp {
        match self {
            Self::CutOff => {
                WeightedTimestamp::ZERO.plus(held_from + epoch * 3 + REATTESTATION_STEP * 3)
            }
            Self::FormedLate => {
                assert!(
                    named_by.plus(REATTESTATION_STEP * 2 + RESIGN_MARGIN) < closes,
                    "the step a re-signed certificate forms at must open inside the stating \
                     window closing at {closes:?}; the member was named by {named_by:?}",
                );
                named_by.plus(REATTESTATION_STEP + RESIGN_MARGIN)
            }
            Self::Unformed => closes.plus(epoch),
        }
    }

    /// Whether the second venue's member stands aborted when the fault
    /// lifts, where that venue could not certify.
    const fn aborted_at_lift(self) -> Option<bool> {
        match self {
            Self::CutOff => None,
            Self::FormedLate => Some(false),
            Self::Unformed => Some(true),
        }
    }

    /// How long both venues get to reach their verdict once the fault
    /// lifts. A certificate formed late
    /// forms at the next step on its tick's anchor grid, which may sit a
    /// whole step past the fault lifting: the member's own, or that of
    /// the abort a venue that could not certify named.
    fn settle_budget(self, epoch: Duration) -> Duration {
        epoch * LATE_CERTIFICATE_SETTLE_EPOCHS
            + match self {
                Self::CutOff => Duration::ZERO,
                Self::FormedLate | Self::Unformed => REATTESTATION_STEP,
            }
    }
}

/// The route's two venues: the swap that follows it runs on the first.
const LATE_CERTIFICATE_VENUES: (ShardId, ShardId) = (FIRST_VENUE_SHARD, SECOND_VENUE_SHARD);

/// Where `tx`'s row stands on `shard`, if it holds one.
fn row_on<C: Cluster>(c: &C, shard: ShardId, tx: TxHash) -> Option<RowState> {
    c.member_rows(shard).and_then(|rows| rows.get(&tx).copied())
}

/// The verdict `shard`'s chain reached on `tx`, and where.
fn verdict_on<C: Cluster>(
    c: &C,
    shard: ShardId,
    tx: TxHash,
) -> Option<(BlockHeight, TransactionDecision)> {
    c.chain_fate(shard, tx).1
}

/// Whether beacon state holds no departed shard's boundary record.
///
/// A departed shard's record pins the schedule floor at its settled
/// window for as long as it lingers, so no certificate signed since
/// lapses however late it lands.
fn no_reshape_evidence<C: Cluster>(c: &C) -> bool {
    c.beacon_state().is_some_and(|state| {
        state
            .boundaries
            .values()
            .all(|boundary| boundary.terminal_epoch.is_none())
            && state.live_settled_window_floors().is_empty()
    })
}

fn route_held_past_a_certificates_life<C: FaultableCluster>(c: &mut C, late: LateCertificate) {
    let (waiting, sibling) = LATE_CERTIFICATE_VENUES;
    let mut taken = Vec::new();
    let (first, second) = stand_up_venues(c, &mut taken);
    let traders = traders(&mut taken);
    let (caller_key, caller) = sponsor(&mut taken);
    let mut load = VenueLoad::new(&mut taken);
    let (key, trader) = &traders[0];
    let epoch = c
        .beacon_state()
        .expect("beacon committed")
        .chain_config
        .epoch_duration();

    for shard in VenueLoad::SHARDS {
        let status = load.settles_on(c, shard, epoch * 8);
        assert_eq!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept)),
            "a transfer local to {shard:?} must accept while nothing is cut",
        );
    }
    // The grow that seated these shards left two terminal records.
    assert!(
        c.run_until(epochs(RESHAPE_EVIDENCE_EPOCHS), no_reshape_evidence),
        "the grow's terminal records must go before a certificate can lapse",
    );

    let route = build_route_tx(
        key,
        *trader,
        (&first.meta, &second.meta),
        *PROTOCOL_RESOURCE,
        ROUTE_INPUT,
        0,
        validity_around(c.now()),
    );
    let hash = route.hash();
    let hold = hold_past_a_certificates_life(c, &mut load, route, late, epoch);

    c.clear_drops();
    let budget = late.settle_budget(epoch);
    let settled = load.run(c, budget, |c| {
        verdict_on(c, waiting, hash).is_some() && verdict_on(c, sibling, hash).is_some()
    });
    for shard in VenueLoad::SHARDS {
        let status = load.settles_on(c, shard, epoch * 4);
        assert!(
            matches!(status, Some(TransactionStatus::Completed(_))),
            "a transfer local to {shard:?} must reach an outcome once the fault lifts; \
             status = {status:?}",
        );
    }
    assert!(
        settled,
        "the route must reach a verdict on both venues within {budget:?} of the fault \
         lifting ({late:?}, held {hold:?}): {waiting:?} verdict {:?} and row {:?}, \
         {sibling:?} verdict {:?} and row {:?}, status {:?}",
        verdict_on(c, waiting, hash),
        row_on(c, waiting, hash),
        verdict_on(c, sibling, hash),
        row_on(c, sibling, hash),
        c.tx_status(hash),
    );
    for venue in [waiting, sibling] {
        assert_eq!(
            verdict_on(c, venue, hash).map(|(_, decision)| decision),
            Some(late.decision()),
            "{venue:?} must reach the route's one verdict ({late:?})",
        );
    }
    let ended = |c: &C| row_on(c, waiting, hash).is_none() && row_on(c, sibling, hash).is_none();
    assert!(
        load.run(c, epoch * 4, ended),
        "a decided member ends its row on both venues: {:?} {:?}",
        row_on(c, waiting, hash),
        row_on(c, sibling, hash),
    );

    // The reserves the held member claimed price a swap again.
    let swap = build_swap_tx(
        &caller_key,
        caller,
        &first.meta,
        *PROTOCOL_RESOURCE,
        SWAP_INPUT,
        0,
        validity_around(c.now()),
    );
    let swap_hash = swap.hash();
    c.submit(swap);
    load.run(c, epoch * 8, |c| {
        c.tx_status(swap_hash)
            .is_some_and(|status| status.is_final())
    });
    assert_eq!(
        c.tx_status(swap_hash),
        Some(TransactionStatus::Completed(TransactionDecision::Accept)),
        "a swap on {waiting:?} must accept once the route let its reserves go; its row \
         stands {:?}",
        row_on(c, waiting, swap_hash),
    );
}

/// Raise the fault `late` names, submit `route`, and hold it under load:
/// for three epochs and three [`REATTESTATION_STEP`]s where its venues
/// are cut off; where its second venue cannot certify, for one step and
/// [`RESIGN_MARGIN`] past the naming of its member there, or for one
/// epoch past its stating window. The span held, with the fault still
/// standing.
///
/// A cut is raised among every host outside the committees it must
/// leave open, both ways: each venue's committee gains members over a
/// span this long, and a cut keyed on one committee's hosts would let a
/// joiner through. [`LateCertificate::CutOff`] cuts the venues'
/// certificates both ways and readings among every host outside the
/// trader shard's committee. [`LateCertificate::FormedLate`] and
/// [`LateCertificate::Unformed`] cut execution votes among every host outside the trader shard's and the
/// first venue's committees, so the second venue's committee, joiners
/// included, cannot certify, and pauses the load on the second venue's
/// shard until the span ends.
///
/// # Panics
///
/// Panics if a venue's member is not held as `late` has it, if the fault
/// never fires, if a reshape lands inside the span, if either venue
/// reaches a verdict while the fault stands, if a second venue that
/// cannot certify has named its member's abort by a lift inside the
/// stating window or has not named it by one past it, or if a re-signed
/// certificate could not land inside the stating window.
fn hold_past_a_certificates_life<C: FaultableCluster>(
    c: &mut C,
    load: &mut VenueLoad,
    route: Transaction,
    late: LateCertificate,
    epoch: Duration,
) -> Duration {
    let (waiting, sibling) = LATE_CERTIFICATE_VENUES;
    let fault = match late {
        LateCertificate::CutOff => vec![
            isolate_ec_intake(c, waiting, sibling),
            isolate_ec_intake(c, sibling, waiting),
            isolate_crossing_intake_among(c, &[TRADER_SHARD]),
        ],
        LateCertificate::FormedLate | LateCertificate::Unformed => {
            load.pause(c, sibling, epoch * 2);
            vec![isolate_execution_votes_among(c, &[TRADER_SHARD, waiting])]
        }
    };
    let held_from = c.now();
    let hash = route.hash();
    c.with_derivation(|derivation| route.try_declared(derivation))
        .expect("a scenario route declares its terms");
    let closes = Window::Stating.of(Deadline::of_transaction(&route)).end;
    c.submit(route);

    let stated =
        |c: &C, venue: ShardId| matches!(row_on(c, venue, hash), Some(RowState::Stated { .. }));
    let unstated =
        |c: &C, venue: ShardId| matches!(row_on(c, venue, hash), Some(RowState::InFlight { .. }));
    let standing = |c: &C| {
        stated(c, waiting)
            && match late {
                LateCertificate::CutOff => stated(c, sibling),
                LateCertificate::FormedLate | LateCertificate::Unformed => unstated(c, sibling),
            }
    };
    assert!(
        load.run(c, epoch * 8, standing),
        "the route's core must stand held on both venues ({late:?}); its rows stand {:?} \
         and {:?}",
        row_on(c, waiting, hash),
        row_on(c, sibling, hash),
    );

    // The sibling's tick is anchored at or before the moment its row is
    // first seen standing.
    let named_by = WeightedTimestamp::ZERO.plus(c.now());
    let hold = late
        .lifts_at(epoch, held_from, named_by, closes)
        .elapsed_since(WeightedTimestamp::ZERO)
        .saturating_sub(held_from);
    let remaining = (held_from + hold).saturating_sub(c.now());
    let decided =
        |c: &C| verdict_on(c, waiting, hash).is_some() || verdict_on(c, sibling, hash).is_some();
    load.run(c, remaining, decided);
    assert!(
        fault.iter().all(|handle| handle.fired() > 0),
        "the fault must actually have dropped what it cuts ({late:?})",
    );
    assert!(
        no_reshape_evidence(c),
        "a reshape during the hold pins the schedule floor under the certificate",
    );
    assert!(
        !decided(c),
        "neither venue may settle while it cannot read the other ({late:?}): {:?} {:?}",
        verdict_on(c, waiting, hash),
        verdict_on(c, sibling, hash),
    );
    if let Some(aborted) = late.aborted_at_lift() {
        assert!(
            matches!(
                row_on(c, sibling, hash),
                Some(RowState::InFlight { joins, .. }) if (joins == Joins::Aborted) == aborted
            ),
            "{sibling:?} must hold its unstated member in flight while its votes are cut, \
             its abort named exactly where its stating window has closed ({late:?}); its row \
             stands {:?}",
            row_on(c, sibling, hash),
        );
        load.paused = None;
    }
    hold
}

/// How far past the life of its tick's first certificate a second venue
/// that cannot certify is held before its votes flow.
const RESIGN_MARGIN: Duration = Duration::from_secs(15);

/// Cut execution votes among every host outside the committees of
/// `open`, both ways: a committee drawn from those hosts, joiners
/// included, certifies nothing while the cut stands.
fn isolate_execution_votes_among<C: FaultableCluster>(c: &mut C, open: &[ShardId]) -> FaultHandle {
    let kept: BTreeSet<usize> = open
        .iter()
        .flat_map(|&shard| c.committee_hosts(shard))
        .collect();
    let cut: Vec<usize> = (0..c.host_count())
        .filter(|host| !kept.contains(host))
        .collect();
    c.drop_type_between(&cut, &cut, "execution.vote")
}

/// Epochs a recovered venue gets to accept and end the stated row its
/// recovery kept, and its sibling the accepted row it holds beside it,
/// once every channel is open again.
const RECOVERED_ROW_EPOCHS: u32 = 6;

/// Whether `shard`'s chain accepted `tx`.
fn accepted_on<C: Cluster>(c: &C, shard: ShardId, tx: TxHash) -> bool {
    matches!(
        c.chain_fate(shard, tx).1,
        Some((_, TransactionDecision::Accept))
    )
}

/// Whether a verdict leaf of `tx` stands on `shard`.
fn leaf_stands<C: Cluster>(c: &C, shard: ShardId, tx: TxHash) -> bool {
    let leaf = verdict_leaf(shard, tx);
    c.substate(shard, leaf.owner, leaf.local.0).is_some()
}

/// Whether a staged yes of `tx` stands on `shard`.
fn staged_stands<C: Cluster>(c: &C, shard: ShardId, tx: TxHash) -> bool {
    let leaf = staged_leaf(shard, tx);
    c.substate(shard, leaf.owner, leaf.local.0).is_some()
}

/// The height of the last boundary the beacon attests for `shard`.
fn attested_boundary<C: Cluster>(c: &C, shard: ShardId) -> Option<BlockHeight> {
    c.beacon_state()
        .and_then(|state| state.boundaries.get(&shard).map(|boundary| boundary.height))
}

/// A route both venues accepted and ended before one of them halts stays
/// settled on both past the recovery.
///
/// Nothing is cut. Each venue reads the other's yes, accepts and ends
/// its row, and the beacon attests a boundary of the first venue's shard
/// past the block that ended it, so the recovery's frontier keeps it.
/// The shard then halts and a fresh committee resumes it: a recovery
/// discards tick rows, and the route stands in none, so neither venue's
/// verdict moves and no row or leaf of the route comes back.
///
/// # Panics
///
/// Panics if either venue misses its budget standing up, if the route
/// does not accept and end on both venues before the halt, if the halt
/// or its recovery misses a budget, if either venue's verdict is
/// anything but an accept after it, if a row or leaf of the route
/// stands, or if either resource does not settle.
pub fn a_route_a_halting_venue_could_read_is_settled_before_the_halt<C: FaultableCluster>(
    c: &mut C,
) {
    let (halted, survivor) = (FIRST_VENUE_SHARD, SECOND_VENUE_SHARD);
    let venues = [halted, survivor];
    let mut taken = Vec::new();
    let (first, second) = stand_up_venues(c, &mut taken);
    let traders = traders(&mut taken);
    let (key, trader) = &traders[0];
    let (protocol_resource, units) = route_worlds(c, &first, &second, accounts(&traders));
    let mut charges = Charges::default();
    let route = build_route_tx(
        key,
        *trader,
        (&first.meta, &second.meta),
        *PROTOCOL_RESOURCE,
        ROUTE_INPUT,
        0,
        validity_around(c.now()),
    );
    let hash = charges.submit(c, route);
    let settled_on =
        |c: &C, venue: ShardId| accepted_on(c, venue, hash) && row_on(c, venue, hash).is_none();
    assert!(
        c.run_until(epochs(8), |c| venues
            .iter()
            .all(|venue| settled_on(c, *venue))),
        "both venues must accept the route and end its rows before the halt: {:?}",
        venues.map(|venue| (c.chain_fate(venue, hash).1, row_on(c, venue, hash))),
    );
    let ended = c.committed_height(halted);
    assert!(
        c.run_until(epochs(4), |c| attested_boundary(c, halted) >= ended),
        "the beacon must attest a boundary of {halted:?} past the route's end at {ended:?}; it \
         attests {:?}",
        attested_boundary(c, halted),
    );

    let halt = freeze_shard(c, halted, survivor, |_| {});
    await_halt_recovery(c, &halt);
    for venue in venues {
        assert!(
            settled_on(c, venue) && !leaf_stands(c, venue, hash),
            "{venue:?} keeps the route accepted past the recovery, with no row or leaf of it: \
             {:?} {:?}",
            c.chain_fate(venue, hash).1,
            row_on(c, venue, hash),
        );
    }
    protocol_resource.assert_settles_within(
        c,
        &charges,
        epochs(8),
        "a route settled before its venue's halt",
    );
    units.assert_settles_within(
        c,
        &Charges::default(),
        epochs(8),
        "a route settled before its venue's halt",
    );
}

/// A route one venue accepted while its sibling could not read it is
/// kept by the sibling's recovery, and settles on both venues.
///
/// The first venue is cut off from the second's certificate and state,
/// so it states its yes and stands, while the second reads that yes and
/// accepts. The first venue's shard then halts and a fresh committee
/// resumes it, its harvest keeping the block that stated the yes: the
/// recovery keeps the stated row and the yes it staged. Once it reads
/// the second venue's accept, the recovered chain accepts in turn,
/// applying that yes, and both rows end. Nothing tears: both venues
/// apply, and nothing of the route stands on either.
///
/// # Panics
///
/// Panics if either venue misses its budget standing up, if the second
/// venue does not accept while the first stands stated, if the cut
/// never fires, if the halt or its recovery misses a budget, if the
/// recovered chain does not accept the route past the halt, if a row,
/// leaf or staged yes of the route stands, or if either resource does
/// not settle.
pub fn a_recovered_venue_keeps_what_its_sibling_accepted<C: FaultableCluster>(c: &mut C) {
    let (halted, survivor) = (FIRST_VENUE_SHARD, SECOND_VENUE_SHARD);
    let venues = [halted, survivor];
    let mut taken = Vec::new();
    let (first, second) = stand_up_venues(c, &mut taken);
    let traders = traders(&mut taken);
    let (key, trader) = &traders[0];
    let (protocol_resource, units) = route_worlds(c, &first, &second, accounts(&traders));
    let cut = [
        isolate_ec_intake(c, halted, survivor),
        isolate_crossing_intake(c, halted, survivor),
    ];
    let mut charges = Charges::default();
    let route = build_route_tx(
        key,
        *trader,
        (&first.meta, &second.meta),
        *PROTOCOL_RESOURCE,
        ROUTE_INPUT,
        0,
        validity_around(c.now()),
    );
    let hash = charges.submit(c, route);
    let stated_on_halted = |c: &C| matches!(row_on(c, halted, hash), Some(RowState::Stated { .. }));
    assert!(
        c.run_until(epochs(8), |c| accepted_on(c, survivor, hash)
            && stated_on_halted(c)),
        "{survivor:?} must accept the route while {halted:?} stands stated: {:?} {:?}",
        c.chain_fate(survivor, hash).1,
        row_on(c, halted, hash),
    );
    assert!(
        cut.iter().all(|handle| handle.fired() > 0),
        "the halting venue must actually have been cut off from its sibling",
    );

    let frozen = c.committed_height(halted);
    let halt = freeze_shard(c, halted, survivor, |_| {});
    await_halt_recovery(c, &halt);
    c.clear_drops();
    assert!(
        c.run_until(epochs(RECOVERED_ROW_EPOCHS), |c| accepted_on(
            c, halted, hash
        ) && venues
            .iter()
            .all(|venue| row_on(c, *venue, hash).is_none())),
        "the recovered venue accepts the route and both rows end: {:?} {:?}, heard {:?}",
        c.chain_fate(halted, hash).1,
        venues.map(|venue| row_on(c, venue, hash)),
        c.heard(halted, hash),
    );
    let accepted_at = verdict_on(c, halted, hash).map(|(height, _)| height);
    assert!(
        accepted_at > frozen,
        "the recovered chain accepts the row it kept, at {accepted_at:?}, past the halt at \
         {frozen:?}",
    );
    for venue in venues {
        assert!(
            accepted_on(c, venue, hash)
                && !leaf_stands(c, venue, hash)
                && !staged_stands(c, venue, hash),
            "{venue:?} accepts the route and keeps no leaf or staged yes of it",
        );
    }
    protocol_resource.assert_settles_within(
        c,
        &charges,
        epochs(8),
        "a route its venue's recovery kept",
    );
    units.assert_settles_within(
        c,
        &Charges::default(),
        epochs(8),
        "a route its venue's recovery kept",
    );
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
    load_genesis_accounts(&[(TRADER_SHARD, traders)])
}

/// A provider on each venue shard and `traders` traders dealt evenly
/// between the two trader shards, each funded for what
/// [`contended_routes_through_one_pair_under_load`] has it do.
#[must_use]
pub fn contended_load_genesis_accounts(traders: usize) -> Vec<(PrincipalAddr, u128)> {
    load_genesis_accounts(&traders_on_both_shards(traders))
}

/// [`core_load_genesis_accounts`] of the traders a hot pool deals its
/// routes among.
#[must_use]
pub fn hot_pool_genesis_accounts() -> Vec<(PrincipalAddr, u128)> {
    core_load_genesis_accounts(HOT_POOL_TRADERS)
}

fn load_genesis_accounts(traders: &[(ShardId, usize)]) -> Vec<(PrincipalAddr, u128)> {
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
            .flatten()
            .map(|(_, account)| (account, LOAD_TRADER_FUNDING)),
    );
    accounts
}

/// `traders` dealt evenly between the two trader shards.
const fn traders_on_both_shards(traders: usize) -> [(ShardId, usize); 2] {
    [
        (TRADER_SHARD, traders / 2),
        (SECOND_TRADER_SHARD, traders - traders / 2),
    ]
}

/// The traders ground onto each shard of `shards`, in its order.
fn load_traders(
    shards: &[(ShardId, usize)],
    taken: &mut Vec<u8>,
) -> Vec<Vec<(Ed25519PrivateKey, PrincipalAddr)>> {
    shards
        .iter()
        .map(|&(shard, count)| (0..count).map(|_| grind_onto(shard, taken)).collect())
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
                RowState::Accepted { .. } => counts.accepted += 1,
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
/// verdict cells, the seat, ledger and boundary asks, and a consumer's
/// read of a crossing's record.
const LOAD_FETCHES: &[Option<&str>] = &[
    Some("verdict_proof"),
    Some("state_proof"),
    Some("record_proof"),
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
            Some("outlasted"),
            Some("crowded"),
            Some("departed"),
            Some("retired"),
            Some("unhosted"),
            Some("unscheduled_anchor"),
            Some("sender"),
            Some("signature"),
        ],
    ),
    ("record_asks", &[None]),
    ("records_repushed", &[Some("owed"), Some("escrowed")]),
    ("repush_due", &[None]),
    ("rebuilt_record_entries", &[None]),
    ("batches_unavailable", &[None]),
    ("early_votes_refused", &[None]),
    ("block_commit_deferred", &[None]),
    ("hold_contentions", &[None]),
    ("hold_inversions_proven", &[None]),
    ("heads_windowed", &[None]),
    ("transactions_aborted", &[None]),
    ("unresolvable_txs", &[None]),
    ("expected_tx_dropped", &[None]),
    ("fetch_started", LOAD_FETCHES),
    ("fetch_completed", LOAD_FETCHES),
    ("fetch_abandoned", LOAD_FETCHES),
    ("fetch_retried", LOAD_FETCHES),
    // Counted by the server under the wire request's name, which a record
    // read shares with every other state proof.
    ("fetch_items_sent", &[Some("state_proof")]),
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
    routes: BTreeMap<TxHash, Transaction>,
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
    /// Routes the pool held past their window, given up on.
    lapsed: usize,
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
            lapsed: 0,
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
            decided,
            lives,
            ..
        } = self;
        let mut landed = BTreeSet::new();
        flying.retain(|hash, pair| {
            let Some([first, second]) = lives.get(hash) else {
                return true;
            };
            let Some(((_, first), (_, second))) = first.settled.zip(second.settled) else {
                return true;
            };
            let accepted = TransactionDecision::Accept;
            decided.insert(*hash, if first == accepted { second } else { first });
            landed.insert(*pair);
            false
        });
        self.give_back(landed);
    }

    /// Free each of `pairs` no route still out runs through.
    fn give_back(&mut self, pairs: BTreeSet<usize>) {
        for pair in pairs {
            if !self.flying.values().any(|out| *out == pair) {
                self.free.push_back(pair);
            }
        }
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

    /// Give back the pair of every route still out that neither venue
    /// chain carries [`LAPSE_SLACK`] past its window: one the pool held
    /// until it lapsed, which no chain commits now.
    fn lapse<C: Cluster>(&mut self, c: &C) {
        let now = WeightedTimestamp::ZERO.plus(c.now());
        let Self {
            routes,
            flying,
            lives,
            lapsed,
            ..
        } = self;
        let mut given_up = BTreeSet::new();
        flying.retain(|hash, pair| {
            let carried = lives
                .get(hash)
                .is_some_and(|[first, second]| first.committed.or(second.committed).is_some());
            let ended = routes.get(hash).is_some_and(|route| {
                route
                    .validity_range()
                    .end_timestamp_exclusive
                    .plus(LAPSE_SLACK)
                    <= now
            });
            if carried || !ended {
                return true;
            }
            *lapsed += 1;
            given_up.insert(*pair);
            false
        });
        self.give_back(given_up);
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
    /// The traders on each shard they were ground onto.
    traders: Vec<Vec<(Ed25519PrivateKey, PrincipalAddr)>>,
}

impl LoadCast {
    fn stand_up<C: Cluster>(c: &mut C, pairs: usize, traders: &[(ShardId, usize)]) -> Self {
        let mut taken = Vec::new();
        let mut venues = stand_up_venues_on(
            c,
            &[FIRST_VENUE_SHARD, SECOND_VENUE_SHARD],
            pairs,
            &mut taken,
        );
        let seconds = venues.pop().expect("the second shard's venues");
        let firsts = venues.pop().expect("the first shard's venues");
        Self {
            firsts,
            seconds,
            traders: load_traders(traders, &mut taken),
        }
    }

    /// Everything that can hold `resource` in the load: the traders and
    /// every venue's reserve.
    fn world<C: Cluster>(&self, c: &C, resource: ResourceAddr) -> World {
        World::open(
            c,
            resource,
            self.traders
                .iter()
                .flat_map(|traders| accounts(traders))
                .map(PrincipalAddr::address),
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
            let after = step * u32::try_from(slot).unwrap_or(u32::MAX);
            self.send(
                c,
                flight,
                TradersOn::First,
                (pair, Heading::Out),
                window,
                after,
            );
        }
    }

    /// Offer the coming second's `load.twins_per_second` twins through
    /// pairs standing free, the nth of them that far through the second:
    /// a route each way through one pair, at one instant, from a trader
    /// on each trader shard.
    fn offer_twins<C: Cluster>(
        &self,
        c: &mut C,
        load: ContendedLoad,
        flight: &mut Flight,
        twins: &mut Vec<Twin>,
    ) {
        let window = validity_around(c.now());
        let step = Duration::from_secs(1)
            / u32::try_from(load.twins_per_second.max(1)).unwrap_or(u32::MAX);
        for slot in 0..load.twins_per_second {
            let Some(pair) = flight.free.pop_front() else {
                flight.short += 1;
                continue;
            };
            let after = step * u32::try_from(slot).unwrap_or(u32::MAX);
            let routes = [
                self.send(
                    c,
                    flight,
                    TradersOn::First,
                    (pair, Heading::Out),
                    window,
                    after,
                ),
                self.send(
                    c,
                    flight,
                    TradersOn::Second,
                    (pair, Heading::Back),
                    window,
                    after,
                ),
            ];
            twins.push(Twin {
                routes,
                offered: c.now() + after,
            });
        }
    }

    /// Top `flight` up towards `pool.routes` routes out through the one
    /// pair, by at most [`HOT_POOL_ARRIVALS`] this second.
    fn offer_hot<C: Cluster>(&self, c: &mut C, pool: HotPool, flight: &mut Flight) {
        let window = validity_around(c.now());
        let missing = pool.routes.saturating_sub(flight.flying.len());
        for _ in 0..missing.min(HOT_POOL_ARRIVALS) {
            self.send(
                c,
                flight,
                TradersOn::First,
                (0, Heading::Out),
                window,
                Duration::ZERO,
            );
        }
    }

    /// Build the next route, send it through `pair` as `heading` says from
    /// the next of `traders` once `after` has passed, and put it in the
    /// air, its amount its own so no two are one transaction.
    fn send<C: Cluster>(
        &self,
        c: &mut C,
        flight: &mut Flight,
        traders: TradersOn,
        (pair, heading): (usize, Heading),
        window: TimestampRange,
        after: Duration,
    ) -> TxHash {
        let nth = flight.routes.len();
        let dealt = &self.traders[traders as usize];
        let (key, trader) = &dealt[nth % dealt.len()];
        let (first, second) = (&self.firsts[pair].meta, &self.seconds[pair].meta);
        let route = build_route_tx(
            key,
            *trader,
            match heading {
                Heading::Out => (first, second),
                Heading::Back => (second, first),
            },
            *PROTOCOL_RESOURCE,
            ROUTE_INPUT + u128::try_from(nth).expect("a count of routes"),
            0,
            window,
        );
        let hash = route.hash();
        flight.spread &= c.submit_after(after, route.clone());
        flight.flying.insert(hash, pair);
        flight.routes.insert(hash, route);
        hash
    }
}

/// Which of a load's trader shards a route's trader is dealt from.
#[derive(Clone, Copy)]
enum TradersOn {
    First,
    Second,
}

/// Which way a route runs through its pair.
#[derive(Clone, Copy)]
enum Heading {
    /// The first shard's venue, then the second's.
    Out,
    /// The second shard's venue, then the first's.
    Back,
}

/// What the routes of `flight` a chain has charged burned between them:
/// each one decided other than by an abort, and each one its trader's
/// chain carries the burn or the fate of. `from` is each trader shard
/// and the height its chain is walked from.
fn load_burned<C: Cluster>(c: &C, flight: &Flight, from: &[(ShardId, BlockHeight)]) -> u128 {
    let hashes: BTreeSet<TxHash> = flight.routes.keys().copied().collect();
    let on_the_payers_chain: BTreeSet<TxHash> = from
        .iter()
        .flat_map(|&(shard, height)| {
            let mentions = walked(c, shard, height, &hashes);
            mentions.burned.into_iter().chain(mentions.fated)
        })
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
/// routes burned, for up to `settle_within`, hold them there a few
/// blocks, and read each side: what it held before, what it holds, and
/// what was burned of it.
fn load_conserved<C: Cluster>(
    c: &mut C,
    flight: &Flight,
    from: &[(ShardId, BlockHeight)],
    settle_within: Duration,
    protocol_resource: &World,
    units: &World,
) -> [(&'static str, u128, u128, u128); 2] {
    let settle_by = c.now() + settle_within;
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

/// Assert each side [`load_conserved`] read holds what it held before,
/// less what was burned of it.
fn assert_load_conserved(conserved: [(&'static str, u128, u128, u128); 2]) {
    for (side, before, held, burned) in conserved {
        assert_eq!(
            held + burned,
            before,
            "the load's {side} must be conserved: held {held} and burned {burned} against \
             {before} before",
        );
    }
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
/// shard reaches the other until the offering ends. A sibling's
/// certificate decides nothing on another shard, so the rows still
/// settle: each venue shard reads the other's verdict from its state.
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
pub fn core_routes_under_load<C: FaultableCluster>(c: &mut C, load: CoreLoad) -> RecordReadCost {
    let wall = Instant::now();
    let cast = LoadCast::stand_up(c, load.pairs, &[(TRADER_SHARD, load.traders)]);
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
    let mut cold = ColdAsks::from(opened);
    while c.now() < opened + load.duration {
        cast.offer(c, load, &mut flight);
        flight.tick(c, "offering");
        cold.read(c);
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
    let payers = [(TRADER_SHARD, opened_at[2])];
    let conserved = load_conserved(c, &flight, &payers, LOAD_DRAIN, &protocol_resource, &units);
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
    let reads = RecordReadCost::read(c, flight.routes.len(), cold, [&before, &after]);
    reads.report();

    assert_load_conserved(conserved);
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
    reads
}

/// How long a load runs before its asks count: it stands up only venue
/// shards, so the trader's shard has pushed nothing and every key of its
/// runs at the grace's floor until the first pushes land.
const COLD_START: Duration = Duration::from_secs(15);

/// `record_asks` as it stood [`COLD_START`] into an offering.
#[derive(Debug, Clone, Copy)]
struct ColdAsks {
    until: Duration,
    read: Option<u64>,
}

impl ColdAsks {
    fn from(opened: Duration) -> Self {
        Self {
            until: opened + COLD_START,
            read: None,
        }
    }

    /// Take the reading if the cold start has passed and none is taken.
    fn read<C: FaultableCluster>(&mut self, c: &C) {
        if c.now() >= self.until {
            self.read
                .get_or_insert_with(|| c.metric("record_asks", None));
        }
    }
}

/// The most record reads a healthy load of `routes` may draw: one late
/// key, two ladder rounds at four validators, plus the same per hundred
/// routes.
#[must_use]
pub const fn read_bound(routes: usize) -> u64 {
    8 * (1 + routes as u64 / 100)
}

/// The largest load offered short of the row held to twice [`read_bound`].
const SINGLE_BOUND_ROUTES: usize = 1_000;

/// The record reads a load's row allows: [`read_bound`], and twice that
/// on the largest load, whose tail outruns the grace at 250 ms.
const fn row_read_bound(routes: usize) -> u64 {
    if routes > SINGLE_BOUND_ROUTES {
        2 * read_bound(routes)
    } else {
        read_bound(routes)
    }
}

/// What a load's record reads came to.
#[derive(Debug, Clone, Copy)]
pub struct RecordReadCost {
    /// The routes offered.
    pub routes: usize,
    /// Reads put in the first [`COLD_START`] of the offering.
    pub cold: u64,
    /// Reads put from then to the end of the run.
    pub delta: u64,
    /// Every read of the run.
    pub asks: u64,
    /// The largest span a kept push took, in milliseconds, an eighth
    /// above the truth at most.
    pub largest_span_ms: f64,
    /// The median span, as closely.
    pub median_span_ms: f64,
    /// The median grace derived over the run, in milliseconds, and the
    /// largest.
    pub grace_ms: [f64; 2],
}

impl RecordReadCost {
    /// What the reads between `before` and `after` came to.
    fn read<C: FaultableCluster>(
        c: &C,
        routes: usize,
        cold: ColdAsks,
        [before, after]: [&LoadCounters; 2],
    ) -> Self {
        let asks = after.since(before, "record_asks", None);
        let cold = cold.read.map_or(asks, |at| {
            at.saturating_sub(before.since(&LoadCounters::default(), "record_asks", None))
        });
        let quantile = |name, q| {
            c.metric_quantile_above(name, None, q, f64::NEG_INFINITY)
                .unwrap_or(0.0)
        };
        Self {
            routes,
            cold,
            delta: asks.saturating_sub(cold),
            asks,
            largest_span_ms: quantile("record_push_span", 1.0),
            median_span_ms: quantile("record_push_span", 0.5),
            grace_ms: [
                quantile("record_push_grace", 0.5),
                quantile("record_push_grace", 1.0),
            ],
        }
    }

    fn report(&self) {
        println!(
            "core load [6 record reads]: {} routes, record_asks {} in the first {COLD_START:?} \
             and {} after, bound {}; push span median {:.0}ms, largest {:.0}ms; grace median \
             {:.0}ms, largest {:.0}ms",
            self.routes,
            self.cold,
            self.delta,
            row_read_bound(self.routes),
            self.median_span_ms,
            self.largest_span_ms,
            self.grace_ms[0],
            self.grace_ms[1],
        );
    }
}

/// Epochs an aborted route's input gets to come home to its trader, as
/// [`crossed_routes`] gives it: [`LOAD_DRAIN`] can be a single epoch, which
/// is too short for it.
const ABORT_REFUND_EPOCHS: u32 = 8;

/// The message a block's crossing readings are pushed in.
const CROSSING_READINGS: &str = "crossing.readings";

/// A load of twins: two routes offered at one instant through one venue
/// pair, each way round.
#[derive(Debug, Clone, Copy)]
pub struct ContendedLoad {
    /// The venue pairs, one twin through each at a time.
    pub pairs: usize,
    /// The traders the routes are dealt among, half on each trader shard.
    pub traders: usize,
    /// The twins offered each second of the cluster's clock, spread evenly
    /// across it, as far as pairs stand free to take them.
    pub twins_per_second: usize,
    /// How long the load is offered for.
    pub duration: Duration,
    /// The share of crossing readings dropped while it is, which skews
    /// each venue's arrivals so the twins invert.
    pub record_loss: f64,
}

/// Two routes offered at one instant through one venue pair.
#[derive(Debug, Clone, Copy)]
struct Twin {
    routes: [TxHash; 2],
    offered: Duration,
}

/// What each route's rows on the venue shards were seen to do.
#[derive(Debug, Default)]
struct PlacesSeen {
    /// Where each route was first seen placed on each venue shard.
    places: BTreeMap<TxHash, [Option<Place>; 2]>,
    /// When each route, on each venue shard, first refused someone.
    refusals: BTreeMap<TxHash, [Option<WeightedTimestamp>; 2]>,
}

impl PlacesSeen {
    /// Note where each venue shard's queue holds each route out.
    fn read<C: Cluster>(&mut self, c: &C, flight: &Flight) {
        let now = WeightedTimestamp::ZERO.plus(c.now());
        for (venue, shard) in [FIRST_VENUE_SHARD, SECOND_VENUE_SHARD]
            .into_iter()
            .enumerate()
        {
            let rows = c
                .queued_rows(shard)
                .expect("the harness reads a venue shard's queue");
            for route in flight.flying.keys() {
                let seen = self.places.entry(*route).or_default();
                let refused = self.refusals.entry(*route).or_default();
                match rows.get(route) {
                    Some(row) => {
                        if let Some(place) = row.queued {
                            seen[venue].get_or_insert(place);
                        }
                        if let Some(at) = row.blocked_at {
                            refused[venue].get_or_insert(at);
                        }
                    }
                    // A poll is a second of cluster clock, and a row can be
                    // placed against and wounded inside one: a placed row
                    // first seen gone takes that poll's clock, which is
                    // past its refusal.
                    None if seen[venue].is_some() => {
                        refused[venue].get_or_insert(now);
                    }
                    None => {}
                }
            }
        }
    }

    /// Whether the venues placed the twin in opposite order; `None` where
    /// either place went unseen.
    fn inverted(&self, [a, b]: [TxHash; 2]) -> Option<bool> {
        let (a, b) = (self.places.get(&a)?, self.places.get(&b)?);
        let first = a[0]?.cmp(&b[0]?);
        let second = a[1]?.cmp(&b[1]?);
        Some(first != second)
    }

    /// The later of the refusals the twin's two heads made, each venue's
    /// head the route it placed first; `None` where one went unseen.
    fn later_refusal(&self, [a, b]: [TxHash; 2]) -> Option<WeightedTimestamp> {
        let (places, refusals) = (
            [self.places.get(&a)?, self.places.get(&b)?],
            [self.refusals.get(&a)?, self.refusals.get(&b)?],
        );
        let refusal = |venue: usize| {
            let head = usize::from(places[1][venue]? < places[0][venue]?);
            refusals[head][venue]
        };
        Some(refusal(0)?.max(refusal(1)?))
    }
}

/// The millisecond of the cluster's clock `route` had settled on both
/// venue chains by; `None` until it has.
fn settled_ms<C: Cluster>(c: &C, flight: &Flight, route: TxHash) -> Option<u64> {
    let [first, second] = flight.lives.get(&route)?;
    let clock = |shard, life: &MemberLife| {
        c.committed_clock(shard, life.settled_at()?)
            .map(WeightedTimestamp::as_millis)
    };
    Some(clock(FIRST_VENUE_SHARD, first)?.max(clock(SECOND_VENUE_SHARD, second)?))
}

/// What became of one twin.
struct TwinOutcome {
    /// Whether the venues placed it in opposite order, where that was
    /// seen.
    inverted: Option<bool>,
    /// The routes that aborted.
    aborted: Vec<TxHash>,
    /// How long each route took from its offer to both venue chains
    /// settling it, by route.
    resolved: [(TxHash, Option<usize>); 2],
    /// How long a twin that lost a route took from the later of its heads'
    /// refusals to both venue chains settling the survivor, in
    /// milliseconds, where those were seen.
    since_refusal: Option<usize>,
}

impl TwinOutcome {
    fn read<C: Cluster>(c: &C, flight: &Flight, places: &PlacesSeen, twin: &Twin) -> Self {
        let resolved = twin.routes.map(|route| {
            let offered = u64::try_from(twin.offered.as_millis()).unwrap_or(u64::MAX);
            let took = settled_ms(c, flight, route)
                .and_then(|at| usize::try_from(at.saturating_sub(offered)).ok());
            (route, took)
        });
        let aborted: Vec<TxHash> = twin
            .routes
            .into_iter()
            .filter(|route| flight.decided.get(route) == Some(&TransactionDecision::Aborted))
            .collect();
        let survivor = twin
            .routes
            .into_iter()
            .find(|route| !aborted.contains(route))
            .filter(|_| !aborted.is_empty());
        let since_refusal = survivor.and_then(|survivor| {
            let refused = places.later_refusal(twin.routes)?.as_millis();
            usize::try_from(settled_ms(c, flight, survivor)?.saturating_sub(refused)).ok()
        });
        Self {
            inverted: places.inverted(twin.routes),
            aborted,
            resolved,
            since_refusal,
        }
    }

    /// How long each route `keep` picks took to resolve.
    fn times(&self, keep: impl Fn(&TxHash) -> bool) -> impl Iterator<Item = usize> + '_ {
        let keep = self
            .resolved
            .map(|(route, took)| took.filter(|_| keep(&route)));
        keep.into_iter().flatten()
    }
}

/// `values`, in milliseconds, as their median and 99th percentile.
fn ms_quantiles(mut values: Vec<usize>) -> String {
    format!(
        "p50 {} ms, p99 {} ms (of {})",
        quantile(&mut values, 500),
        quantile(&mut values, 990),
        values.len(),
    )
}

/// The aborts that came at a route's own deadline: each route the venues
/// aborted whose settling was at or past the end of its signed validity.
fn deadline_aborts<C: Cluster>(c: &C, flight: &Flight) -> usize {
    flight
        .decided
        .iter()
        .filter(|(_, decision)| **decision == TransactionDecision::Aborted)
        .filter(|(route, _)| {
            let deadline = flight.routes[*route]
                .validity_range()
                .end_timestamp_exclusive
                .as_millis();
            settled_ms(c, flight, **route).is_none_or(|at| at >= deadline)
        })
        .count()
}

/// Print `tally`, the seat fetches of a run, for the `blocks` the venue
/// chains committed over it and the `askers` that fetched them.
fn report_seat_fetches(label: &str, tally: ProofTally, blocks: u64, askers: u64) {
    println!(
        "{label} [seat fetches, requests naming a route's seat leaf, answered by every host]: \
         {} fetches of {} cells, {} bytes asked and {} answered; {} fetches a venue block over \
         {blocks} blocks, {} a validator's venue block over {askers} validators",
        tally.answers,
        tally.cells,
        tally.asked_bytes,
        tally.answer_bytes,
        mean(tally.answers, blocks),
        mean(tally.answers, blocks.saturating_mul(askers)),
    );
}

/// The blocks both venue chains committed from `opened` to `settled`, each
/// a height for every one of [`LOAD_SHARDS`].
fn venue_blocks(
    opened: [BlockHeight; LOAD_SHARDS.len()],
    settled: [BlockHeight; LOAD_SHARDS.len()],
) -> u64 {
    (0..2)
        .map(|venue| settled[venue].inner().saturating_sub(opened[venue].inner()) + 1)
        .sum()
}

/// How many venue validators ask seat questions: each venue shard's
/// committee asks the other.
fn venue_validators<C: FaultableCluster>(c: &C) -> u64 {
    [FIRST_VENUE_SHARD, SECOND_VENUE_SHARD]
        .into_iter()
        .map(|shard| wide(c.committee_hosts(shard).len()))
        .sum()
}

/// Watch the seat leaf of every route out, on both venue shards.
fn watch_seats(meter: &ProofMeter, flight: &Flight) {
    meter.watch(flight.flying.keys().flat_map(|route| {
        [
            seat_leaf(FIRST_VENUE_SHARD, *route),
            seat_leaf(SECOND_VENUE_SHARD, *route),
        ]
    }));
}

/// Twins through one venue pair lose only the later hash, and only when
/// the venues place them in opposite order.
///
/// Each second `load.twins_per_second` twins are offered through pairs
/// standing free: one route from a trader on [`TRADER_SHARD`] through the
/// first shard's venue and then the second's, and one from a trader on
/// [`SECOND_TRADER_SHARD`] the other way round. A pair takes another twin
/// only once both routes have settled on both venue chains, so a route
/// contends with its twin alone. Dropping `load.record_loss` of the
/// crossing readings while the load is offered skews what each venue
/// hears first, so some twins place in opposite order; re-pushes and
/// answers to asks recover the drops.
///
/// On top of what [`core_routes_under_load`] reports, the run reports the
/// twins, how many the venues placed in opposite order as read off their
/// queues, the abort fraction, p50 and p99 time to resolve for the twins
/// the venues agreed on, for the survivors of inverted twins and for
/// their victims, the wounds and windows, and the seat fetches a venue
/// block.
///
/// Requires a grown four-shard cluster over
/// [`contended_load_genesis_accounts`] of `load.traders`, on committees
/// that share no host, one that walks its shards' chains.
///
/// # Panics
///
/// Panics if a venue misses its budget standing up, if either side of the
/// pair is not conserved, if a route is still undecided past the drain, if
/// a head leaves at its window or a route aborts at its deadline, if both
/// routes of a twin abort, if an aborted route is not the later of its
/// twin or its twin does not accept, if the aborted outnumber the twins
/// seen inverted, if no twin inverts, or if the p99 survivor resolves half
/// a naming window past the later of its heads' refusals.
pub fn contended_routes_through_one_pair_under_load<C: FaultableCluster>(
    c: &mut C,
    load: ContendedLoad,
) {
    let wall = Instant::now();
    let cast = LoadCast::stand_up(c, load.pairs, &traders_on_both_shards(load.traders));
    let protocol_resource = cast.world(c, *PROTOCOL_RESOURCE);
    let units = cast.world(c, cast.firsts[0].unit);
    let height = |c: &C, shard: ShardId| c.committed_height(shard).unwrap_or(BlockHeight::GENESIS);
    let opened_at = LOAD_SHARDS.map(|(_, shard)| height(c, shard).next());
    let payers = [
        (TRADER_SHARD, opened_at[2]),
        (SECOND_TRADER_SHARD, height(c, SECOND_TRADER_SHARD).next()),
    ];
    let opened = c.now();
    let before = LoadCounters::read(c);
    let offering = Instant::now();
    let meter = ProofMeter::default();
    let metered = c.meter_state_proofs(&meter);
    let lost = c.drop_type_with_probability(CROSSING_READINGS, load.record_loss);
    let mut flight = Flight::over(load.pairs, [opened_at[0], opened_at[1]]);
    let mut twins = Vec::new();
    let mut places = PlacesSeen::default();
    let mut cold = ColdAsks::from(opened);
    while c.now() < opened + load.duration {
        cast.offer_twins(c, load, &mut flight, &mut twins);
        watch_seats(&meter, &flight);
        flight.tick(c, "offering");
        places.read(c, &flight);
        cold.read(c);
    }
    let dropped = lost.fired();
    c.clear_drops();
    c.meter_state_proofs(&meter);
    let closed_at = LOAD_SHARDS.map(|(_, shard)| height(c, shard));
    let closed = c.now();
    let offering = offering.elapsed();
    let offered = flight.samples.len();
    while !flight.flying.is_empty() && c.now() < closed + LOAD_DRAIN {
        flight.tick(c, "draining");
        places.read(c, &flight);
    }
    let epoch =
        Duration::from_millis(epoch_duration_ms(c).expect("the beacon carries its epoch length"));
    let refund_within = epoch * ABORT_REFUND_EPOCHS;
    let conserved = load_conserved(
        c,
        &flight,
        &payers,
        refund_within,
        &protocol_resource,
        &units,
    );
    let after = LoadCounters::read(c);
    let heights = [
        opened_at,
        closed_at,
        LOAD_SHARDS.map(|(_, shard)| height(c, shard)),
    ];

    CoreLoadRun {
        load: CoreLoad {
            pairs: load.pairs,
            traders: load.traders,
            routes_per_second: load.twins_per_second * 2,
            duration: load.duration,
            certificates: Certificates::Flow,
        },
        flight: &flight,
        offered,
        window: [opened, closed],
        heights,
        counters: [&before, &after],
        wall: [wall.elapsed(), offering],
    }
    .report(c);

    RecordReadCost::read(c, flight.routes.len(), cold, [&before, &after]).report();

    let label = "contended load";
    let read = TwinsRead::over(c, &flight, &places, &twins);
    read.report(label, &flight, dropped);
    let delta = |name| after.since(&before, name, None);
    let windowed = delta("heads_windowed");
    let deadlines = deadline_aborts(c, &flight);
    println!(
        "{label} [wounds and windows, summed over replicas]: hold_inversions_proven {}, \
         heads_windowed {windowed}; deadline aborts {deadlines}",
        delta("hold_inversions_proven"),
    );
    if metered {
        let blocks = venue_blocks(opened_at, heights[2]);
        report_seat_fetches(label, meter.total(), blocks, venue_validators(c));
    }

    assert_load_conserved(conserved);
    assert!(
        flight.flying.is_empty(),
        "{} of {} routes were still undecided {LOAD_DRAIN:?} past the last offer",
        flight.flying.len(),
        flight.routes.len(),
    );
    assert_eq!(windowed, 0, "no head leaves at its naming window");
    assert_eq!(deadlines, 0, "no route aborts at its deadline");
    read.assert_the_later_hash_lost(&flight);
    read.assert_survivors_resolved_in_time();
}

/// The twins of a contended load, read once they have settled.
struct TwinsRead<'a> {
    twins: &'a [Twin],
    outcomes: Vec<TwinOutcome>,
    /// The twins the venues placed in opposite order.
    inverted: usize,
    /// The twins with a place unseen on either venue.
    unread: usize,
    /// How long, in milliseconds, each route of a twin the venues placed
    /// alike took to resolve.
    uninverted: Vec<usize>,
    /// How long each route of an inverted twin that did not abort took.
    survivors: Vec<usize>,
    /// How long each aborted route took.
    victims: Vec<usize>,
    /// How long each twin that lost a route took from the later of its
    /// heads' refusals to settling its survivor.
    since_refusal: Vec<usize>,
}

impl<'a> TwinsRead<'a> {
    fn over<C: Cluster>(c: &C, flight: &Flight, places: &PlacesSeen, twins: &'a [Twin]) -> Self {
        let outcomes: Vec<TwinOutcome> = twins
            .iter()
            .map(|twin| TwinOutcome::read(c, flight, places, twin))
            .collect();
        let count = |wanted: Option<bool>| {
            outcomes
                .iter()
                .filter(|twin| twin.inverted == wanted)
                .count()
        };
        let times = |split: &dyn Fn(&TwinOutcome, &TxHash) -> bool| -> Vec<usize> {
            outcomes
                .iter()
                .flat_map(|twin| twin.times(|route| split(twin, route)).collect::<Vec<_>>())
                .collect()
        };
        let uninverted = times(&|twin, _| twin.inverted == Some(false));
        let survivors = times(&|twin, route| {
            (twin.inverted == Some(true) || !twin.aborted.is_empty())
                && !twin.aborted.contains(route)
        });
        let victims = times(&|twin, route| twin.aborted.contains(route));
        let since_refusal = outcomes
            .iter()
            .filter_map(|twin| twin.since_refusal)
            .collect();
        Self {
            twins,
            inverted: count(Some(true)),
            unread: count(None),
            uninverted,
            survivors,
            victims,
            since_refusal,
            outcomes,
        }
    }

    fn report(&self, label: &str, flight: &Flight, dropped: u64) {
        let aborted = flight.decided_as(TransactionDecision::Aborted);
        let decided = flight.decided.len();
        println!(
            "{label} [twins]: {} offered, {} offers short of a free pair; {} placed in opposite \
             order, {} with a place unseen; {dropped} crossing readings dropped",
            self.twins.len(),
            flight.short,
            self.inverted,
            self.unread,
        );
        println!(
            "{label} [aborts]: {aborted} of {decided} decided, {}",
            percent(wide(aborted), wide(decided)),
        );
        println!(
            "{label} [time to resolve, offer to both venue chains settled]: uninverted {}; \
             survivors of inverted twins {}; victims {}",
            ms_quantiles(self.uninverted.clone()),
            ms_quantiles(self.survivors.clone()),
            ms_quantiles(self.victims.clone()),
        );
        println!(
            "{label} [survivors, the later refusal to both venue chains settled]: {}",
            ms_quantiles(self.since_refusal.clone()),
        );
    }

    /// Assert each twin lost at most one route, the later hash, and that
    /// an inversion accounts for every abort and the load inverted one.
    fn assert_the_later_hash_lost(&self, flight: &Flight) {
        for (twin, outcome) in self.twins.iter().zip(&self.outcomes) {
            let [a, b] = twin.routes;
            match outcome.aborted.as_slice() {
                [] => {}
                [victim] => {
                    let survivor = if *victim == a { b } else { a };
                    assert_eq!(
                        *victim,
                        a.max(b),
                        "the route a twin loses is the later hash: {twin:?}",
                    );
                    assert_eq!(
                        flight.decided.get(&survivor),
                        Some(&TransactionDecision::Accept),
                        "the twin of an aborted route accepts: {twin:?}",
                    );
                }
                both => panic!("at most one route of a twin aborts: {twin:?} lost {both:?}"),
            }
        }
        let aborted = flight.decided_as(TransactionDecision::Aborted);
        assert!(
            aborted <= self.inverted + self.unread,
            "every abort comes of an inversion: {aborted} aborted, {} twins seen inverted, {} \
             unseen",
            self.inverted,
            self.unread,
        );
        assert!(
            self.inverted > 0,
            "the load must invert a twin, or it measures nothing: raise record_loss",
        );
    }

    /// Assert the p99 survivor resolved within half a naming window of the
    /// later of its heads' refusals.
    fn assert_survivors_resolved_in_time(&self) {
        let mut since_refusal = self.since_refusal.clone();
        let since_refusal = Duration::from_millis(wide(quantile(&mut since_refusal, 990)));
        assert!(
            since_refusal < NAMING_WINDOW / 2,
            "the p99 survivor resolved {since_refusal:?} past the later refusal, past half a \
             naming window",
        );
    }
}

/// The traders a hot pool's routes are dealt among.
const HOT_POOL_TRADERS: usize = 32;

/// How many routes a hot pool offers a second as it fills.
const HOT_POOL_ARRIVALS: usize = 100;

/// The share of its routes, in percent, a hot pool must have waiting
/// behind a head before its seat fetches are priced.
const HOT_POOL_STANDING_PERCENT: usize = 75;

/// The seat fetch bytes a validator may spend a second on a hot pool of
/// 500 waiting routes before a capped ask backoff has to replace the
/// fixed ask gap.
pub const HOT_POOL_ADOPT_IF: u64 = 200_000;

/// Many routes in one direction through one venue pair, so about
/// `routes` rows wait behind each head on the shared pool.
#[derive(Debug, Clone, Copy)]
pub struct HotPool {
    /// The routes kept out at once.
    pub routes: usize,
    /// How long they are kept out for.
    pub duration: Duration,
}

/// The rows waiting behind a head on `shard`.
fn waiting_rows<C: Cluster>(c: &C, shard: ShardId) -> usize {
    c.queued_rows(shard)
        .expect("the harness reads a venue shard's queue")
        .values()
        .filter(|row| row.state == RowState::Pending && row.queued.is_some() && row.head.is_none())
        .count()
}

/// What seat questions cost on a hot pool, from
/// [`HOT_POOL_STANDING_PERCENT`] of its routes waiting to its end.
///
/// `pool.routes` routes are kept out through one venue pair for
/// `pool.duration`, the pool filling at [`HOT_POOL_ARRIVALS`] a second,
/// and nothing here waits for them to settle: only one runs through a pair
/// at a time, and the shape is the queue, not the throughput.
///
/// The run reports the rows waiting, the seat cells and seat fetch bytes
/// per validator per second, and the answer bytes per second served by
/// the busiest venue validator and the mean one, and returns seat fetch
/// bytes per validator per second.
///
/// Requires a grown four-shard cluster over
/// [`hot_pool_genesis_accounts`], on committees that share no host, one
/// that walks its shards' chains and meters state proofs.
///
/// # Panics
///
/// Panics if a venue misses its budget standing up, if the harness cannot
/// meter a state proof, or if the rows waiting never reach
/// [`HOT_POOL_STANDING_PERCENT`] of `pool.routes`.
pub fn seat_fetches_on_a_hot_pool<C: FaultableCluster>(c: &mut C, pool: HotPool) -> u64 {
    let label = "hot pool";
    let cast = LoadCast::stand_up(c, 1, &[(TRADER_SHARD, HOT_POOL_TRADERS)]);
    let height = |c: &C, shard: ShardId| c.committed_height(shard).unwrap_or(BlockHeight::GENESIS);
    let walked = [FIRST_VENUE_SHARD, SECOND_VENUE_SHARD].map(|shard| height(c, shard).next());
    let meter = ProofMeter::default();
    assert!(
        c.meter_state_proofs(&meter),
        "a hot pool is priced off a metered harness",
    );
    let mut flight = Flight::over(1, walked);
    let opened = c.now();
    let mut waiting = Vec::new();
    let mut standing = None;
    while c.now() < opened + pool.duration {
        cast.offer_hot(c, pool, &mut flight);
        watch_seats(&meter, &flight);
        flight.tick(c, label);
        flight.lapse(c);
        let behind = waiting_rows(c, FIRST_VENUE_SHARD).min(waiting_rows(c, SECOND_VENUE_SHARD));
        waiting.push(behind);
        if standing.is_none() && behind * 100 >= pool.routes * HOT_POOL_STANDING_PERCENT {
            let venue_heights = [FIRST_VENUE_SHARD, SECOND_VENUE_SHARD].map(|s| height(c, s));
            standing = Some((c.now(), meter.served(), venue_heights));
        }
    }
    let (from, earlier, venue_heights) = standing.unwrap_or_else(|| {
        panic!(
            "the rows waiting on the pool never reached {HOT_POOL_STANDING_PERCENT}% of {}: {}",
            pool.routes,
            spread(waiting.clone()),
        )
    });
    let seconds = c.now().saturating_sub(from).as_secs().max(1);
    let served: Vec<ProofTally> = meter
        .served()
        .into_iter()
        .map(|(host, tally)| tally.since(earlier.get(&host).copied().unwrap_or_default()))
        .collect();
    let total = served
        .iter()
        .copied()
        .fold(ProofTally::default(), ProofTally::plus);
    let askers = venue_validators(c).max(1);
    let per_second = |count: u64| count / seconds;
    let fetched = per_second((total.asked_bytes + total.answer_bytes) / askers);
    let most_served = per_second(
        served
            .iter()
            .map(|tally| tally.answer_bytes)
            .max()
            .unwrap_or(0),
    );
    let blocks: u64 = [FIRST_VENUE_SHARD, SECOND_VENUE_SHARD]
        .into_iter()
        .zip(venue_heights)
        .map(|(shard, from)| height(c, shard).inner().saturating_sub(from.inner()))
        .sum();
    println!(
        "{label} [rows waiting behind a head, read each second, the lesser venue]: {}; {} routes \
         offered, {} settled, {} lapsed",
        spread(waiting),
        flight.routes.len(),
        flight.decided.len(),
        flight.lapsed,
    );
    report_seat_fetches(label, total, blocks, askers);
    println!(
        "{label} [seat fetches over the {seconds} s standing]: {} cells and {fetched} bytes a \
         validator a second against {HOT_POOL_ADOPT_IF}; answers served, {} bytes a second the \
         mean venue validator, {most_served} the busiest",
        per_second(total.cells / askers),
        per_second(total.answer_bytes / askers),
    );
    fetched
}

/// How near its cap a sustained load reads a pair as standing at the
/// ceiling: within a sixteenth.
const AT_THE_CEILING: u64 = MAX_STANDING_ANSWERS_FROM_SHARD - MAX_STANDING_ANSWERS_FROM_SHARD / 16;

/// How many epochs a sustained load holds its load once its pairs stand
/// at the ceiling.
const LEVEL_OFF_EPOCHS: u32 = 8;

/// How many epochs past the last offer a sustained load waits for every
/// load shard to stand no answer.
const ANSWER_DRAIN_EPOCHS: u32 = 12;

/// How long past a route's validity a load waits for the venue chains
/// to show it before it reads the route as one the pool held past its
/// window: the chains it walks may trail their tips.
const LAPSE_SLACK: Duration = Duration::from_secs(30);

/// What a load shard stands toward a lineage: a consumer shard and the
/// lineage of the producers it holds answers from.
type StandingPair = (ShardId, ShardId);

/// A consumer's standing answers level off at the cap under a load
/// that would carry them past it.
///
/// [`core_routes_under_load`]'s routes are offered until some lineage of
/// some load shard stands within a sixteenth of
/// [`MAX_STANDING_ANSWERS_FROM_SHARD`], then for `LEVEL_OFF_EPOCHS`
/// epochs more. `load.duration` bounds the wait for the ceiling. A route
/// the cap keeps in its pool past its window lapses there, and its pair
/// takes the next. At every reading, through the offering and the
/// drain, every load shard stands within the cap on every lineage and
/// in total.
///
/// At the held window's end the run prints the retirements a second the
/// pair at the ceiling read over the window, counted on its lineage's
/// chain, and what the claims sections spent on boundary claims and on
/// the rest. It then prints, over the whole run so far, how long answers
/// stood, how long records waited from their re-push due instant to
/// their retirement, the records consumers waited on and the re-pushes.
/// Once the routes still out settle, the run goes on until no load shard
/// stands an answer, within `ANSWER_DRAIN_EPOCHS` epochs of the last
/// offer, and prints how long that took; then both sides of the pair are
/// conserved and every route is decided or lapsed.
///
/// Requires a grown four-shard cluster over
/// [`core_load_genesis_accounts`] of `load.traders`, one that walks its
/// shards' chains.
///
/// # Panics
///
/// Panics if a venue misses its budget standing up, a cap is passed at
/// any reading, no lineage reaches the ceiling within `load.duration`, a
/// load shard still stands an answer `ANSWER_DRAIN_EPOCHS` epochs past
/// the last offer, either side of the pair is not conserved, or a route
/// is still out once its window and the drain have passed.
pub fn standing_answers_level_off_under_sustained_load<C: FaultableCluster>(
    c: &mut C,
    load: CoreLoad,
) {
    let label = "standing answers level off";
    let cast = LoadCast::stand_up(c, load.pairs, &[(TRADER_SHARD, load.traders)]);
    let protocol_resource = cast.world(c, *PROTOCOL_RESOURCE);
    let units = cast.world(c, cast.firsts[0].unit);
    let epoch =
        Duration::from_millis(epoch_duration_ms(c).expect("the beacon carries its epoch length"));
    let height = |c: &C, shard: ShardId| c.committed_height(shard).unwrap_or(BlockHeight::GENESIS);
    let opened_at = LOAD_SHARDS.map(|(_, shard)| height(c, shard).next());
    let opened = c.now();
    let mut flight = Flight::over(load.pairs, [opened_at[0], opened_at[1]]);
    let mut held: Option<HeldWindow> = None;
    loop {
        cast.offer(c, load, &mut flight);
        flight.tick(c, "offering");
        flight.lapse(c);
        let standing = standing_within_the_answer_caps(c);
        match &mut held {
            Some(window) => {
                window.low = window
                    .low
                    .min(standing.get(&window.pair).copied().unwrap_or(0));
                if c.now() >= window.at + epoch * LEVEL_OFF_EPOCHS {
                    break;
                }
            }
            None => match standing.iter().max_by_key(|(_, count)| **count) {
                Some((pair, count)) if *count >= AT_THE_CEILING => {
                    held = Some(HeldWindow::open(c, label, *pair, *count));
                }
                _ => assert!(
                    c.now() < opened + load.duration,
                    "no pair reached the ceiling within {:?}; the highest stands at {}",
                    load.duration,
                    standing.values().max().copied().unwrap_or(0),
                ),
            },
        }
    }
    let window = held.expect("the loop ends only on a held window");
    let (consumer, lineage) = window.pair;
    println!(
        "{label}: standing answers held {LEVEL_OFF_EPOCHS} epochs at the ceiling, \
         {consumer:?} toward lineage {lineage:?} never below {}; {} routes lapsed in the pool",
        window.low, flight.lapsed,
    );
    window.report(c, label);
    report_retirement_figures(c, label);
    let closed = c.now();
    while !flight.flying.is_empty() && c.now() < closed + LOAD_DRAIN {
        flight.tick(c, "draining");
        flight.lapse(c);
        standing_within_the_answer_caps(c);
    }
    drain_standing_answers(c, closed + epoch * ANSWER_DRAIN_EPOCHS, label);
    println!(
        "{label}: no load shard stands an answer {:?} past the last offer",
        c.now().saturating_sub(closed),
    );
    let payers = [(TRADER_SHARD, opened_at[2])];
    let conserved = load_conserved(c, &flight, &payers, LOAD_DRAIN, &protocol_resource, &units);
    standing_within_the_answer_caps(c);
    assert_load_conserved(conserved);
    assert!(
        flight.flying.is_empty(),
        "{} of {} routes were still out {LOAD_DRAIN:?} past the last offer",
        flight.flying.len(),
        flight.routes.len(),
    );
}

/// Run the cluster on until no load shard stands an answer.
///
/// # Panics
///
/// If one still stands one at `by`.
fn drain_standing_answers<C: FaultableCluster>(c: &mut C, by: Duration, label: &str) {
    loop {
        let standing: u64 = standing_within_the_answer_caps(c).values().sum();
        if standing == 0 {
            return;
        }
        assert!(
            c.now() < by,
            "{label}: the load shards still stand {standing} answers {ANSWER_DRAIN_EPOCHS} \
             epochs past the last offer",
        );
        let next = c.now() + Duration::from_secs(5);
        let _ = c.run_until(epochs(1), |c| c.now() >= next);
    }
}

/// The window a sustained load holds at the ceiling, from the instant
/// its pair first stood there.
struct HeldWindow {
    /// When the pair first stood at the ceiling.
    at: Duration,
    /// The pair at the ceiling.
    pair: StandingPair,
    /// The first height of the pair's lineage's chain in the window.
    from: BlockHeight,
    /// The least the pair stood at over the window.
    low: u64,
    /// The claims bytes as the window opened.
    bytes: ClaimBytes,
}

impl HeldWindow {
    /// Open the window now on `pair`, standing `count` answers, and say
    /// so.
    fn open<C: FaultableCluster>(c: &C, label: &str, pair: StandingPair, count: u64) -> Self {
        let (consumer, lineage) = pair;
        println!(
            "{label}: standing answers at the ceiling at {:?}: {count} toward lineage \
             {lineage:?} on {consumer:?}",
            c.now(),
        );
        Self {
            at: c.now(),
            pair,
            from: c
                .committed_height(lineage)
                .unwrap_or(BlockHeight::GENESIS)
                .next(),
            low: u64::MAX,
            bytes: ClaimBytes::read(c),
        }
    }

    /// Print the retirements a second the pair's consumer read on its
    /// lineage's chain over the window, and what the claims sections
    /// spent.
    fn report<C: FaultableCluster>(&self, c: &C, label: &str) {
        let (consumer, lineage) = self.pair;
        let held = c.now().saturating_sub(self.at);
        let held_ms = u64::try_from(held.as_millis()).unwrap_or(u64::MAX);
        let retired = c
            .retirements_by_holder(lineage, self.from)
            .expect("a load runs on a cluster that walks its shards' chains")
            .get(&consumer)
            .copied()
            .unwrap_or(0);
        println!(
            "{label} [retirements over the held {held:?}, read on lineage {lineage:?}'s \
             chain]: toward {consumer:?} {retired}, {} a second",
            mean(retired.saturating_mul(1_000), held_ms),
        );
        ClaimBytes::read(c).report(&self.bytes, label);
    }
}

/// What the state claims of every replica's committed blocks weighed,
/// as it stood at one instant: the boundary claims' bytes, every state
/// claim's bytes that is no verdict claim, and the blocks weighed.
#[derive(Debug, Clone, Copy)]
struct ClaimBytes {
    boundary: u64,
    claims: u64,
    blocks: u64,
}

impl ClaimBytes {
    fn read(c: &impl FaultableCluster) -> Self {
        Self {
            boundary: c.metric("boundary_claim_bytes", None),
            claims: c.metric("state_claims_bytes", None),
            blocks: c.metric_count("state_claims_weight", None),
        }
    }

    /// Print what the claims spent since `earlier`: the boundary claims'
    /// share of the bytes, and the bytes a block of the fresh claims and
    /// parent readings that are the rest.
    fn report(&self, earlier: &Self, label: &str) {
        let boundary = self.boundary.saturating_sub(earlier.boundary);
        let claims = self.claims.saturating_sub(earlier.claims);
        let blocks = self.blocks.saturating_sub(earlier.blocks);
        println!(
            "{label} [claims over the held window, every replica's commits on every shard]: \
             boundary claim bytes {boundary} of {claims}, {}; fresh claim bytes a block {} \
             over {blocks} commits",
            percent(boundary, claims),
            mean(claims.saturating_sub(boundary), blocks),
        );
    }
}

/// Print, over the whole run, the bytes a carried retirement weighed,
/// the records consumers waited on with no arrival, and the re-pushes.
fn report_retirement_figures<C: FaultableCluster>(c: &C, label: &str) {
    let bytes = c.metric("retirement_bytes_spent", None);
    let retirements = c.metric("retirements_spent", None);
    println!(
        "{label} [retirements carried, every proposer's blocks]: {retirements} retirements in \
         {bytes} bytes, {} bytes a retirement",
        mean(bytes, retirements),
    );
    let at = |metric, kind, q| {
        c.metric_quantile_above(metric, kind, q, f64::NEG_INFINITY)
            .unwrap_or(0.0)
    };
    println!(
        "{label} [wanted records, every replica at each commit]: p50 {:.0}, p99 {:.0}, max {:.0}",
        at("wanted_records", None, 0.5),
        at("wanted_records", None, 0.99),
        at("wanted_records", None, 1.0),
    );
    println!(
        "{label} [re-pushes, per proposing replica]: owed {}, escrowed {}; records first found \
         due {}",
        c.metric("records_repushed", Some("owed")),
        c.metric("records_repushed", Some("escrowed")),
        c.metric("repush_due", None),
    );
}

/// What each of [`LOAD_SHARDS`] stands toward each lineage, asserting
/// each shard stands within the cap on every lineage and in total.
fn standing_within_the_answer_caps<C: Cluster>(c: &C) -> BTreeMap<StandingPair, u64> {
    let trie = ShardTrie::uniform_from_count(4);
    let mut standing = BTreeMap::new();
    for (name, shard) in LOAD_SHARDS {
        let answers = c
            .standing_answers(shard)
            .expect("the harness reads a load shard's standing answers");
        assert!(
            answers.total() <= MAX_STANDING_ANSWERS,
            "the {name} stands {}, past the total cap",
            answers.total(),
        );
        for (lineage, count) in answers.per_lineage(&trie) {
            assert!(
                count <= MAX_STANDING_ANSWERS_FROM_SHARD,
                "the {name} stands {count} toward lineage {lineage:?}, past its cap",
            );
            standing.insert((shard, lineage), count);
        }
    }
    standing
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
        report_claims_recarried(c, "core load");
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
                 and the readings ride densely batched",
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
                "records_repushed",
                "repush_due",
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
                "heads_windowed",
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
        println!(
            "core load [7 computed]: no counter tells a verdict reading that arrived by push \
             from one that was asked for"
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
