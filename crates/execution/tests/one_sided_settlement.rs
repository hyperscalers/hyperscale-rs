//! A crossing settles its local half once its tick's halves land.

mod common;

use common::sim::{
    ExecutionSim, LEFT, Schedule, amount, cell_of, charge_of, counter, settle, vault_of,
};
use hyperscale_types::test_utils::{test_prefix, test_transaction_with_prefixes};
use hyperscale_types::{ShardId, Transaction};

/// The local cell the crossing writes.
const LOCAL: u8 = 7;

/// A prefix on the far side of the partition.
const REMOTE: u8 = 200;

fn crossing(seed: u8) -> Transaction {
    test_transaction_with_prefixes(
        &[seed, seed ^ 0x33, seed ^ 0xcc],
        &[],
        &[test_prefix(LOCAL), test_prefix(REMOTE)],
    )
}

/// Settle a crossing, and report what reached state: the cell its
/// effects write, the vault they credit, and any charge.
fn settled_local_effect() -> (u64, u128, u128) {
    let mut sim = ExecutionSim::with_shards(Schedule::Eager, 2, LEFT);

    let leg = crossing(0);
    let hash = leg.hash();
    sim.commit(vec![leg], Vec::new());
    // The payer's leg runs in the tick that attests it, so it waits for
    // the counterpart to commit the transaction and echo that back.
    sim.engage(ShardId::leaf(1, 1), &[hash]);
    sim.drain();

    let tick = sim.tick_of(hash).expect("the crossing joined a tick");
    let receipts = sim.receipts_for(&tick);
    assert!(!receipts.is_empty(), "the local half executed");

    sim.commit(Vec::new(), vec![settle(&tick, &receipts)]);
    sim.drain();
    (
        counter(sim.settled(cell_of(test_prefix(LOCAL)))),
        amount(sim.settled(vault_of(test_prefix(LOCAL)))),
        amount(sim.settled(charge_of(test_prefix(LOCAL)))),
    )
}

/// With every participant accepting, the local half settles and there is
/// nothing to charge.
#[test]
fn an_accepted_crossing_settles_its_local_half() {
    assert_eq!(settled_local_effect(), (1, 1, 0));
}
