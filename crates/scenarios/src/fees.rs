//! Fee-controller scenarios.
//!
//! The price level is governed in two halves: a pool vote fixes the
//! interval each row may travel, and the epoch controller picks the
//! point inside it from what the network declared. Genesis pins the two
//! together — floor and ceiling both at the reference table — so the
//! level cannot move until a vote opens a band.
//!
//! That makes the whole controller inert on a fresh cluster, which is
//! deliberate and is also why it needs a scenario: every piece is
//! unit-tested on its own, and what nothing else walks is the path from
//! a cast ballot to a repriced transaction.

use std::sync::Arc;

use hyperscale_types::{
    NetworkParams, PriceBounds, PriceTable, ReshapeThresholds, TransactionDecision,
    TransactionStatus,
};

use crate::support::conservation::{Charges, probe_world};
use crate::support::query::{beacon_epoch, declared_price};
use crate::support::tx::{
    build_transfer_at_priority, build_transfer_tx, pool_operator, recipient, sender,
    validity_around,
};
use crate::support::wait::{await_beacon_epoch, await_tx_terminal};
use crate::support::{Cluster, epochs, vote_params, vote_reshape_threshold};

/// Four fifths and eight times the reference table: wide enough that
/// the controller's own step — an eighth of a row per epoch — has
/// somewhere to go, and a floor an idle network reaches in a handful of
/// folds. A floor far below the level only ever reads as "above the
/// floor", which every level is.
const FLOOR_BP: u32 = 8_000;
const CEILING_BP: u32 = 80_000;

/// Half again over the table price: large enough that the charge cannot
/// be confused with rounding, and inside `MAX_PRIORITY_BP`.
const PRIORITY_BP: u32 = 5_000;

/// A vote opens the band, the controller walks the level inside it, and
/// the chain goes on pricing transactions at wherever it got to.
///
/// An idle cluster is the readable case: its blocks declare almost
/// nothing against their caps, so every row reads far under the
/// half-full point the step stands still at and walks down. What this
/// pins is the rail rather than the arithmetic — that a ballot reaches
/// `price_bounds`, that the fold steps a level that could not move
/// before it, that the level stays inside the interval the vote named,
/// and that a transaction still settles once it has moved.
///
/// # Panics
///
/// Panics if the ballot never activates, if the level never moves, or if
/// a transfer stops settling once it has.
pub fn a_vote_opens_the_band_and_the_level_moves<C: Cluster>(c: &mut C) {
    assert!(
        await_beacon_epoch(c, 1, epochs(6)),
        "the beacon must fold before a ballot can reach it"
    );

    // Genesis pins every row: the interval is a point, so whatever the
    // network declares the level is what the reference table says.
    let (level, bounds) = prices(c);
    assert_eq!(
        level,
        PriceTable::GENESIS,
        "a fresh cluster prices at the reference table"
    );
    assert_eq!(
        bounds,
        PriceBounds::GENESIS,
        "and cannot move, because genesis fixes the interval to a point"
    );

    // And folds go by without moving it, which is the half of the claim
    // a constant cannot make: the level is pinned by the interval and
    // not by nothing having happened yet.
    let before = beacon_epoch(c);
    assert!(
        !c.run_until(epochs(4), |c| prices(c).0 != PriceTable::GENESIS),
        "a pinned interval must hold the level through folds that would \
         otherwise step it; level = {:?}",
        prices(c).0,
    );
    assert!(
        beacon_epoch(c) > before,
        "and the run has to have spanned a fold, or the level held for \
         want of anything happening: {before:?} to {:?}",
        beacon_epoch(c),
    );

    let opened = PriceBounds::band(FLOOR_BP, CEILING_BP);
    vote_params(
        c,
        |ballot| {
            ballot.floor_bp = FLOOR_BP;
            ballot.ceiling_bp = CEILING_BP;
        },
        |params| params.price_bounds == opened,
        "the price band",
    );

    // The level moves at a fold and never at the vote, so the interval
    // is open for an epoch before anything inside it travels.
    assert!(
        c.run_until(epochs(8), |c| prices(c).0.compute
            < PriceTable::GENESIS.compute),
        "an idle network declares far under half its caps, so the compute \
         row must walk down once the band admits it; level = {:?}",
        prices(c).0,
    );

    // And it comes to rest on the floor rather than travelling through
    // it. An idle network drives the row down at every fold, so a level
    // that stops stopped because the interval held it — which is the
    // claim, and one no reading taken while the row is still far above
    // the floor can make.
    assert!(
        c.run_until(epochs(8), |c| prices(c).0.compute == opened.floor.compute),
        "the row must walk down to the floor the ballot named; level = {:?}",
        prices(c).0,
    );
    assert!(
        !c.run_until(epochs(4), |c| prices(c).0.compute != opened.floor.compute),
        "and hold there through folds that would otherwise step it past; \
         level = {:?}",
        prices(c).0,
    );

    let (moved, bounds) = prices(c);
    assert_eq!(bounds, opened, "the band is the one the ballot named");

    // And the chain still prices: a transfer admitted against the moved
    // table settles like any other.
    let (payer, from) = pool_operator();
    let tx = build_transfer_tx(&payer, from, from, 1, validity_around(c.now()));
    let hash = tx.hash();
    c.submit(Arc::new(tx));
    let status = await_tx_terminal(c, hash, epochs(8));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "a transfer must settle at the moved level; status = {status:?}, \
         level = {moved:?}, epoch = {:?}",
        beacon_epoch(c),
    );
}

/// The live level and the interval it is held inside.
fn prices<C: Cluster>(c: &C) -> (PriceTable, PriceBounds) {
    c.beacon_state()
        .map(|state| (state.prices, state.params.price_bounds))
        .expect("a committed beacon state")
}

/// A signed priority is charged, burned, and conserved.
///
/// Half again over the table price, which is what
/// [`PRIORITY_BP`]'s five thousand basis points name. What makes this an
/// end-to-end claim rather than arithmetic is the conservation check:
/// the world settles against the sum of the *declared* prices, so a
/// chain that admitted the priority and then burned the plain figure
/// leaves value unaccounted for and the assertion fires.
///
/// What a priority buys is a place in a block and never a position in
/// one; the ordering half is the pool's, pinned where the selection is.
///
/// # Panics
///
/// Panics if either transfer fails to settle, if the priority is not
/// priced over the plain figure, or if the world does not conserve.
pub fn a_priority_is_charged_over_the_table_price<C: Cluster>(c: &mut C) {
    let (payer, from) = sender(0);
    let to = recipient(0);
    let world = probe_world(c);
    let mut charges = Charges::default();

    let plain = build_transfer_tx(&payer, from, to, 1, validity_around(c.now()));
    let raised =
        build_transfer_at_priority(&payer, from, to, 2, validity_around(c.now()), PRIORITY_BP);

    // The prices the chain will charge, read before either is submitted:
    // a pure function of signed content and the table at the head.
    let plain_price = declared_price(c, &plain);
    let raised_price = declared_price(c, &raised);
    assert!(
        raised_price > plain_price,
        "a priority must cost more than the table price: {raised_price} against {plain_price}"
    );

    let plain_hash = charges.submit(c, plain);
    let raised_hash = charges.submit(c, raised);
    for (hash, what) in [
        (plain_hash, "the plain transfer"),
        (raised_hash, "the raised one"),
    ] {
        let status = await_tx_terminal(c, hash, epochs(8));
        assert!(
            matches!(
                status,
                Some(TransactionStatus::Completed(TransactionDecision::Accept))
            ),
            "{what} must settle; status = {status:?}",
        );
    }

    // The ledger closes against both declared prices together, which is
    // the burn agreeing with what the priority was quoted at.
    world.assert_settles_within(c, &charges, epochs(4), "a plain and a prioritised transfer");
}

/// A vote moves the row it names and no other, in both directions.
///
/// One vote is one whole proposal and the tally buckets by the exact
/// set, so a ballot is only ever a re-proposal of what the chain runs
/// with one row changed. Seeded from anything else — the type's own
/// defaults, say — a vote about the price would carry a reshape
/// threshold nobody cast, and silently retune it on any cluster not
/// already running the default.
///
/// Both directions, because the two rows read back differently and only
/// one of them used to: the thresholds are stored as they are voted,
/// where the band is two figures on the wire and ten rows in storage.
/// A ballot that could not state the live band back had to guess at it,
/// so every vote about anything else shut the price interval.
///
/// # Panics
///
/// Panics if either vote fails to activate, or if either moves a row it
/// did not name.
pub fn a_vote_moves_the_row_it_names_and_no_other<C: Cluster>(c: &mut C) {
    assert!(
        await_beacon_epoch(c, 1, epochs(6)),
        "the beacon must fold before a ballot can reach it"
    );
    let before = live_params(c);
    assert_ne!(
        before.reshape_thresholds,
        ReshapeThresholds::default(),
        "this cluster has to run something other than the defaults for the \
         claim to have teeth"
    );

    let opened = PriceBounds::band(FLOOR_BP, CEILING_BP);
    vote_params(
        c,
        |ballot| {
            ballot.floor_bp = FLOOR_BP;
            ballot.ceiling_bp = CEILING_BP;
        },
        |params| params.price_bounds == opened,
        "the price band",
    );

    let after = live_params(c);
    assert_eq!(after.price_bounds, opened, "the row the ballot named moved");
    assert_eq!(
        after.reshape_thresholds, before.reshape_thresholds,
        "and the reshape thresholds it did not name did not"
    );
    assert_eq!(
        after.impound_epochs, before.impound_epochs,
        "nor the impound window"
    );

    // And back the other way, over the open band rather than the
    // degenerate one: a threshold vote has to restate an interval it
    // never names, which it can only do by reading the live one back.
    let raised = before.reshape_thresholds.split_bytes + 1;
    vote_reshape_threshold(c, raised);

    let last = live_params(c);
    assert_eq!(
        last.reshape_thresholds.split_bytes, raised,
        "the threshold the second ballot named moved"
    );
    assert_eq!(
        last.price_bounds, opened,
        "and the band it did not name survived it"
    );
}

/// The live governed parameters.
fn live_params<C: Cluster>(c: &C) -> NetworkParams {
    c.beacon_state().expect("a committed beacon state").params
}
