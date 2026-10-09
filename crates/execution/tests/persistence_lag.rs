//! A tick reads one baseline however far its replica's persistence has
//! got.
//!
//! A commit reaches execution before its write is acknowledged, and a
//! block's commit puts things in the settled base that no tick's output
//! carries. So the tick after a block waits for that block's write: it
//! runs on every replica over the base as the block left it, whether the
//! write was acknowledged as the block committed or long after.
//!
//! The abandonment is the case driven here because the coordinator alone
//! produces it: the member reaches no engine, so its tick runs nothing,
//! and the charge its verdict settles exists only in the finalization the
//! coordinator builds.

mod common;

use std::time::Duration;

use common::sim::{ExecutionSim, LEFT, Schedule, amount};
use hyperscale_storage::TickOutput;
use hyperscale_types::test_utils::{stub_transaction, test_prefix, test_transaction_with_prefixes};
use hyperscale_types::{
    BlockHeight, PriceTable, PrincipalAddr, TimestampRange, Transaction, WeightedTimestamp,
};

/// What the payer's vault holds at genesis.
const FUNDED: u128 = 1_000;

/// Blocks to commit before giving up on the deadline: the fixture's
/// validity window and the finalization delay past it, with room.
const PAST_THE_DEADLINE: usize = 400;

/// A transaction paid from this shard that also reaches its sibling, so
/// it waits on a counterpart that never engages.
fn crossing() -> Transaction {
    test_transaction_with_prefixes(&[0, 0x33, 0xcc], &[], &[test_prefix(7), test_prefix(200)])
}

/// A transaction this shard runs alone, in the tick of the block that
/// commits it, valid from `now`.
fn local(now: WeightedTimestamp) -> Transaction {
    stub_transaction(
        PrincipalAddr::new([0x44; 31]),
        &[test_prefix(9)],
        1_000,
        TimestampRange::new(now, now.plus(Duration::from_mins(1))),
    )
}

/// What a replica ran, and what the tick after its tip reads at the
/// payer's vault.
struct Ran {
    outputs: Vec<(BlockHeight, TickOutput)>,
    payer_vault: u128,
}

/// Commit a crossing whose counterpart never engages, the finalization of
/// the tick that abandons it past its deadline, and then a block whose
/// tick reads the base that finalization's block left.
///
/// A `prompt` replica acknowledges every write as its block commits. One
/// that is not commits the last two blocks unwritten, and its tick must
/// not run until they are.
fn past_an_abandonment(prompt: bool) -> Ran {
    let mut sim = ExecutionSim::with_shards(Schedule::Eager, 2, LEFT);
    let tx = crossing();
    let vault = tx.fee_vault();
    let floor = tx.price(&PriceTable::GENESIS);
    sim.fund(vault, FUNDED);
    sim.commit(vec![tx], Vec::new());

    let mut abandonment = Vec::new();
    for _ in 0..PAST_THE_DEADLINE {
        sim.commit(Vec::new(), Vec::new());
        abandonment = sim.certify_votable();
        if !abandonment.is_empty() {
            break;
        }
    }
    assert_eq!(abandonment.len(), 1, "the deadline abandons the crossing");
    assert!(
        sim.outputs().is_empty() && sim.retained_ticks() == 0,
        "the abandoning tick ran nothing and appended nothing",
    );

    if !prompt {
        sim.withhold_persistence();
    }
    sim.commit(Vec::new(), abandonment);
    assert_eq!(
        amount(sim.settled(vault)),
        FUNDED - floor,
        "the finalization's block burns the floor from the payer's vault",
    );
    sim.commit(vec![local(sim.now())], Vec::new());
    if !prompt {
        assert!(
            sim.outputs().is_empty(),
            "the tick above the finalization's block waits for that block's write",
        );
        sim.persist();
    }
    assert_eq!(sim.outputs().len(), 1, "written, the tick runs");
    Ran {
        outputs: sim.outputs().to_vec(),
        payer_vault: amount(sim.read(vault)),
    }
}

/// The tick after an abandonment's finalization runs over the floor that
/// finalization burned, on a replica that wrote its block at once and on
/// one that wrote it late.
#[test]
fn the_tick_after_an_abandonment_waits_for_its_charge_to_be_written() {
    let (prompt, late) = (past_an_abandonment(true), past_an_abandonment(false));
    assert_eq!(late.outputs, prompt.outputs, "the tick's output");
    assert_eq!(
        late.payer_vault, prompt.payer_vault,
        "the payer's vault as the next tick reads it",
    );
}
