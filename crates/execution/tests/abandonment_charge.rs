//! An abandonment's charge and a judged debit on the same vault settle
//! without either running past what the vault holds.
//!
//! An abandonment reaches no engine, so its tick appends nothing to the
//! tick chain and its charge reaches the payer's vault only in the block
//! that commits its finalization. A tick between the two reads the vault
//! as it stood before the charge, and a debit it judges against that
//! reading settles after the charge has landed. What keeps the two
//! inside the vault is the abandoned member's fee hold: it stands in the
//! base from the block that committed the member to the block that lands
//! the charge, every debit between them is judged under it, and the
//! charge is at most the ceiling it held.
//!
//! The spend is the harness's stand-in for a completed transfer: a judged
//! debit of everything the tick's baseline shows less what unresolved legs
//! hold and less the fee holds standing on the vault, which is the floor
//! the kernel judges a movement against. The abandonment, its receipt and
//! both finalizations are the coordinator's own, and settlement is
//! `merge_writes_from_receipts` under the commit fold's fee holds.

mod common;

use std::time::Duration;

use common::sim::{ExecutionSim, LEFT, Schedule, amount};
use hyperscale_types::test_utils::{stub_transaction, test_prefix, test_transaction_with_prefixes};
use hyperscale_types::{
    Finalization, PriceTable, PrincipalAddr, SubstateKey, TimestampRange, Transaction,
    WeightedTimestamp,
};

/// What the payer's vault holds at genesis: past the crossing's ceiling,
/// so a spend under its hold still takes something.
const FUNDED: u128 = 3_000;

/// The fee ceiling the crossing signs, which its hold keeps of the vault.
const CEILING: u128 = 1_000;

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

/// A funded payer whose crossing the deadline has just abandoned: the
/// abandoning tick has been seated and certified, and its finalization
/// is in hand and not yet committed.
struct Abandoned {
    sim: ExecutionSim,
    vault: SubstateKey,
    /// What the abandonment burns.
    floor: u128,
    finalization: Vec<Finalization>,
}

fn abandoned() -> Abandoned {
    let mut sim = ExecutionSim::with_shards(Schedule::Eager, 2, LEFT);
    let tx = crossing();
    let vault = tx.fee_vault();
    let floor = tx.price(&PriceTable::GENESIS);
    assert_eq!(tx.terms().max_fee, CEILING);
    assert!(
        0 < floor && floor < CEILING && CEILING < FUNDED,
        "the hold covers the floor and the vault covers the hold",
    );
    sim.fund(vault, FUNDED);
    sim.commit(vec![tx], Vec::new());

    let mut finalization = Vec::new();
    for _ in 0..PAST_THE_DEADLINE {
        sim.commit(Vec::new(), Vec::new());
        finalization = sim.certify_votable();
        if !finalization.is_empty() {
            break;
        }
    }
    assert_eq!(finalization.len(), 1, "the deadline abandons the crossing");
    assert!(
        sim.outputs().is_empty() && sim.retained_ticks() == 0,
        "the abandoning tick ran nothing and appended nothing",
    );
    Abandoned {
        sim,
        vault,
        floor,
        finalization,
    }
}

/// Commit a block carrying a transaction that empties `vault`, returning
/// what its tick took.
fn commit_spend(sim: &mut ExecutionSim, vault: SubstateKey) -> u128 {
    let before = amount(sim.read(vault));
    let spend = local(sim.now());
    sim.spend_all(spend.hash(), vault);
    sim.commit(vec![spend], Vec::new());
    before - amount(sim.read(vault))
}

/// Certify the spend's tick and commit its finalization.
fn settle_spend(sim: &mut ExecutionSim) {
    let finalization = sim.certify_votable();
    assert_eq!(finalization.len(), 1, "the spend's tick certifies");
    sim.commit(Vec::new(), finalization);
}

/// The control: a spend whose tick sits above the finalization's block
/// reads the vault less the floor, takes that, and settles on it.
#[test]
fn a_spend_above_the_charge_takes_what_the_charge_left() {
    let Abandoned {
        mut sim,
        vault,
        floor,
        finalization,
    } = abandoned();
    sim.commit(Vec::new(), finalization);
    assert_eq!(amount(sim.settled(vault)), FUNDED - floor);

    assert_eq!(commit_spend(&mut sim, vault), FUNDED - floor);
    settle_spend(&mut sim);
    assert_eq!(amount(sim.settled(vault)), 0);
}

/// A spend whose tick sits between the abandoning tick and the block
/// that commits its finalization settles after the charge without
/// running past what the charge left: it took everything but the
/// ceiling the abandoned member still held.
#[test]
fn a_spend_below_the_charge_settles_within_what_the_charge_left() {
    let Abandoned {
        mut sim,
        vault,
        floor,
        finalization,
    } = abandoned();
    let taken = commit_spend(&mut sim, vault);
    assert_eq!(taken, FUNDED - CEILING);

    sim.commit(Vec::new(), finalization);
    let left = amount(sim.settled(vault));
    assert_eq!(left, FUNDED - floor, "the charge lands first");
    settle_spend(&mut sim);
    assert_eq!(
        Some(amount(sim.settled(vault))),
        left.checked_sub(taken),
        "the spend settles as the debit its tick judged",
    );
}

/// The tick after the finalization's block reads the payer's vault: the
/// charge in the base under the spend still unsettled above it, which
/// left the ceiling the charge came out of.
#[test]
fn a_tick_above_the_charge_reads_the_vault_under_an_unsettled_spend() {
    let Abandoned {
        mut sim,
        vault,
        floor,
        finalization,
    } = abandoned();
    commit_spend(&mut sim, vault);

    sim.commit(Vec::new(), finalization);
    // The baseline the next tick executes against.
    assert_eq!(amount(sim.read(vault)), CEILING - floor);
}
