//! A halt recovery's frontier is a floor on the tick chain.
//!
//! A shard halted past f is recovered by a fresh committee that holds the
//! settled state at the beacon-attested frontier and nothing of the tick
//! chain below it. A retained replica held more: the determined writes
//! of ticks the recovery discards, which every tick it ran above the
//! frontier read. Once it learns the recovery it withdraws all of that,
//! and runs every tick above the frontier over what the fresh committee
//! holds, so the two derive one set of outputs.

mod common;

use common::sim::{ExecutionSim, Schedule, cell_of, counter};
use hyperscale_storage::TickOutput;
use hyperscale_types::test_utils::{test_prefix, test_transaction_with_prefixes};
use hyperscale_types::{BlockHeight, Transaction};

/// The prefix every transaction here writes a counter under.
const LOCAL: u8 = 7;

/// The recovery's attested frontier.
const FRONTIER: BlockHeight = BlockHeight::new(3);

/// A single-shard transaction over one counter: it joins the tick its
/// block commits, and its write stays determined and unsettled until a
/// certificate commits, which none here does.
fn local_tx(seed: u8) -> Transaction {
    test_transaction_with_prefixes(
        &[seed, seed ^ 0x5a, seed ^ 0xa5],
        &[],
        &[test_prefix(LOCAL)],
    )
}

/// The last output each tick above the frontier produced: a withdrawn
/// run's output is superseded by the run that replaced it.
fn above_the_frontier(sim: &ExecutionSim) -> Vec<(BlockHeight, TickOutput)> {
    let mut last = std::collections::BTreeMap::new();
    for (tick, output) in sim.outputs() {
        if *tick > FRONTIER {
            last.insert(*tick, output.clone());
        }
    }
    last.into_iter().collect()
}

/// What a fresh replica seated at the frontier runs for `seeds`.
fn fresh(seeds: std::ops::Range<u8>) -> ExecutionSim {
    let mut fresh = ExecutionSim::seated_at(Schedule::Eager, FRONTIER);
    fresh.recover(FRONTIER);
    for seed in seeds {
        fresh.commit(vec![local_tx(seed)], Vec::new());
    }
    fresh.drain();
    fresh
}

/// A retained replica that ran the ticks at or below the frontier, their
/// determined writes unsettled, runs the ticks above it over what a
/// fresh replica holds once it learns the recovery.
#[test]
fn a_retained_replica_runs_above_the_frontier_what_a_fresh_one_runs() {
    let mut retained = ExecutionSim::new(Schedule::Eager);
    for seed in 0..3 {
        retained.commit(vec![local_tx(seed)], Vec::new());
    }
    retained.recover(FRONTIER);
    for seed in 3..5 {
        retained.commit(vec![local_tx(seed)], Vec::new());
    }
    retained.drain();

    let fresh = fresh(3..5);
    assert_eq!(above_the_frontier(&retained), above_the_frontier(&fresh));
    assert_eq!(
        counter(retained.read(cell_of(test_prefix(LOCAL)))),
        2,
        "no tick above the frontier reads a write at or below it",
    );
}

/// A tick the retained replica ran above the frontier before it learned
/// the recovery read a baseline the recovery withdraws, so it runs again
/// and lands what the fresh replica's run of it lands.
#[test]
fn a_tick_run_before_the_record_is_run_again() {
    let mut retained = ExecutionSim::new(Schedule::Eager);
    for seed in 0..5 {
        retained.commit(vec![local_tx(seed)], Vec::new());
    }
    retained.recover(FRONTIER);
    retained.commit(vec![local_tx(5)], Vec::new());
    retained.drain();

    let fresh = fresh(3..6);
    assert_eq!(above_the_frontier(&retained), above_the_frontier(&fresh));
    assert_eq!(counter(retained.read(cell_of(test_prefix(LOCAL)))), 3);
}

/// A batch in flight when the floor rises lands nothing: its completion
/// records nothing, and the tick runs again over the raised floor.
#[test]
fn a_batch_in_flight_at_the_raise_lands_nothing() {
    let mut retained = ExecutionSim::new(Schedule::Lagged(1));
    for seed in 0..5 {
        retained.commit(vec![local_tx(seed)], Vec::new());
    }
    retained.recover(FRONTIER);
    retained.commit(vec![local_tx(5)], Vec::new());
    retained.drain();

    let fresh = fresh(3..6);
    assert_eq!(above_the_frontier(&retained), above_the_frontier(&fresh));
}
