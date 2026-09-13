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

use hyperscale_types::{PriceBounds, PriceTable, TransactionDecision, TransactionStatus};

use crate::support::query::beacon_epoch;
use crate::support::tx::{ParamBallot, build_transfer_tx, pool_operator, validity_around};
use crate::support::wait::{await_beacon_epoch, await_tx_terminal};
use crate::support::{Cluster, epochs, vote_params};

/// An eighth and eight times the reference table: wide enough that the
/// controller's own step — an eighth of a row per epoch — has somewhere
/// to go in a handful of folds.
const FLOOR_BP: u32 = 1_250;
const CEILING_BP: u32 = 80_000;

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
    assert!(
        !c.run_until(epochs(4), |c| prices(c).0 != PriceTable::GENESIS),
        "a pinned interval must hold the level through folds that would \
         otherwise step it; level = {:?}",
        prices(c).0,
    );

    let opened = PriceBounds::band(FLOOR_BP, CEILING_BP);
    vote_params(
        c,
        ParamBallot {
            floor_bp: FLOOR_BP,
            ceiling_bp: CEILING_BP,
            ..ParamBallot::default()
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

    let (moved, bounds) = prices(c);
    assert_eq!(bounds, opened, "the band is the one the ballot named");
    assert!(
        moved.compute >= bounds.floor.compute,
        "the controller stays inside the interval: {} under a floor of {}",
        moved.compute,
        bounds.floor.compute,
    );

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
