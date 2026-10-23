//! What a restart has to rebuild before it can execute again.
//!
//! The committed chain survives a restart and everything execution was
//! tracking does not. Two replicas at one committed frontier still have
//! to compose the same tick and execute it against the same baseline, so
//! whatever the restart lost has to come back out of committed content.

mod common;

use std::time::Duration;

use common::sim::{ExecutionSim, LEFT, Schedule, cell_of, counter, settle};
use hyperscale_storage::TickOutput;
use hyperscale_types::test_utils::{stub_transaction, test_prefix, test_transaction_with_prefixes};
use hyperscale_types::{
    BlockHeight, Deadline, Finalization, PrincipalAddr, ShardId, TickId, TimestampRange,
    Transaction, WeightedTimestamp,
};

/// The cell the fixture writes.
const CELL: u8 = 7;

fn tx(seed: u8, cell: u8) -> Transaction {
    test_transaction_with_prefixes(&[seed, seed ^ 0x5a, seed ^ 0xa5], &[], &[test_prefix(cell)])
}

/// A tick's writes are readable through the tick chain from the moment
/// it executes and reach the base only when its certificate settles
/// them. A restart in between drops the chain, so the baseline the next
/// tick executes against has to be rebuilt by replaying the blocks that
/// produced it.
#[test]
fn a_restart_rebuilds_the_baseline_an_unsettled_tick_left() {
    let mut sim = ExecutionSim::new(Schedule::Eager);
    sim.commit(vec![tx(0, CELL)], Vec::new());
    sim.drain();

    let cell = cell_of(test_prefix(CELL));
    assert_eq!(
        counter(sim.read(cell)),
        1,
        "fixture precondition: the write is readable through the chain",
    );
    assert_eq!(
        counter(sim.settled(cell)),
        0,
        "fixture precondition: nothing has settled it into the base",
    );

    sim.restart();
    assert_eq!(
        counter(sim.read(cell)),
        1,
        "so the restarted replica executes the next tick against the same baseline",
    );

    // And the tick above it reads that baseline rather than the bare
    // base, which is the whole reason the fold has to come back.
    sim.commit(vec![tx(1, CELL)], Vec::new());
    sim.drain();
    assert_eq!(
        counter(sim.read(cell)),
        2,
        "a tick after the restart chains onto what the replayed one wrote",
    );
}

/// A replica restarted over a store that commits nothing more runs its
/// unsettled tick again and signs its vote: the base its replay reads was
/// written before the restart, so the replica waits on no persist, and on
/// a quiet chain none would come.
#[test]
fn a_restarted_replica_on_a_quiet_chain_signs_its_unsettled_ticks() {
    let mut sim = ExecutionSim::new(Schedule::Eager);
    sim.commit(vec![tx(0, CELL)], Vec::new());
    let member = tx(1, CELL);
    sim.commit(vec![member.clone()], Vec::new());
    sim.drain();
    let tick = sim.tick_of(member.hash()).expect("tick assigned");
    assert!(
        tick.block_height() > BlockHeight::new(1),
        "fixture precondition: the tick reads a baseline above genesis",
    );

    sim.restart();

    let certified = sim.certify_votable();
    assert!(
        certified.iter().any(|fw| *fw.tick_id() == tick),
        "the restarted replica signs the vote of the tick it ran again",
    );
}

/// A tick already settled into the base is not folded a second time.
///
/// Replay re-runs every tick in the window, including ones whose
/// certificate has since committed — so the fold and the base both hold
/// their effect, and counting it twice would be as wrong as losing it.
#[test]
fn a_restart_does_not_refold_what_the_base_already_carries() {
    let mut sim = ExecutionSim::new(Schedule::Eager);
    sim.commit(vec![tx(0, CELL)], Vec::new());
    sim.drain();

    let tick = sim.tick_of(tx(0, CELL).hash()).expect("tick assigned");
    let receipts = sim.receipts_for(&tick);
    sim.commit(Vec::new(), vec![settle(&tick, &receipts)]);
    sim.drain();

    let cell = cell_of(test_prefix(CELL));
    assert_eq!(
        counter(sim.settled(cell)),
        1,
        "fixture precondition: the certificate put it in the base",
    );

    sim.restart();
    assert_eq!(
        counter(sim.read(cell)),
        1,
        "a replayed tick the base already carries contributes nothing further",
    );
}

/// What the abandoned member's payer holds at genesis.
const FUNDED: u128 = 3_000;

/// The fee ceiling every fixture transaction signs, which its hold
/// keeps of its payer's vault until its finalization commits.
const CEILING: u128 = 1_000;

/// A transaction paid from this shard that also reaches its sibling.
fn crossing() -> Transaction {
    test_transaction_with_prefixes(
        &[0, 0x33, 0xcc],
        &[],
        &[test_prefix(CELL), test_prefix(200)],
    )
}

/// A transaction this shard runs alone over `cell`, paid by `payer` and
/// valid for `valid_for` from `now`.
fn local(payer: u8, cell: u8, now: WeightedTimestamp, valid_for: Duration) -> Transaction {
    stub_transaction(
        PrincipalAddr::new([payer; 31]),
        &[test_prefix(cell)],
        CEILING,
        TimestampRange::new(now, now.plus(valid_for)),
    )
}

/// Which half of its tick the abandoned member's refusal receipt rides.
#[derive(Clone, Copy, Debug)]
enum Rides {
    /// The determined half: the member reaches no other shard.
    Determined,
    /// The legs half: the member reaches the sibling shard.
    Legs,
}

/// Where the spend of the abandoned member's payer vault commits.
#[derive(Clone, Copy, Debug)]
enum SpendAt {
    /// In a block between the abandoning tick's and the one that commits
    /// its finalizations.
    Between,
    /// In the block that commits the abandoning tick's finalizations.
    WithTheCharge,
}

/// How a replica came to the abandoning tick.
#[derive(Clone, Copy, Debug)]
enum Replica {
    /// It ran the tick.
    Live,
    /// It restarted over a store that anchors no baseline below the
    /// block above the tick, so it holds the tick and seats what the
    /// tick left from its finalizations. `ledger` says whether its
    /// replay reaches the block that committed the abandoned member.
    Holding { ledger: bool },
}

/// What the spend's tick left, and what the spend took of the vault.
#[derive(Debug, PartialEq, Eq)]
struct Spent {
    output: TickOutput,
    taken: u128,
}

/// Commit a tick that runs one member and abandons another, then a
/// spend of the abandoned member's payer vault at `spend_at`, on a
/// replica that came to the abandoning tick as `replica` did.
///
/// A member riding the determined half is a transaction of this shard
/// alone kept out of every tick by a leg's claim on the cell it writes
/// until its own deadline passes. One riding the legs half is a crossing
/// whose counterpart never engages.
fn spend_above_an_abandonment(rides: Rides, spend_at: SpendAt, replica: Replica) -> Spent {
    let mut sim = ExecutionSim::with_shards(Schedule::Eager, 2, LEFT);
    let abandoned = match rides {
        Rides::Determined => local(0x22, CELL, sim.now(), Duration::from_secs(2)),
        Rides::Legs => crossing(),
    };
    let vault = abandoned.fee_vault();
    sim.fund(vault, FUNDED);
    match rides {
        Rides::Determined => {
            let leg = crossing();
            sim.engage(ShardId::leaf(1, 1), &[leg.hash()]);
            sim.commit(vec![leg, abandoned.clone()], Vec::new());
        }
        Rides::Legs => sim.commit(vec![abandoned.clone()], Vec::new()),
    }
    let committed_at = sim.height();

    let deadline = Deadline::of_transaction(&abandoned);
    while !deadline.passed(sim.next_anchor()) {
        sim.commit(Vec::new(), Vec::new());
    }
    let bystander = local(0x44, 9, sim.now(), Duration::from_mins(1));
    let bystander_hash = bystander.hash();
    sim.commit(vec![bystander], Vec::new());
    let abandoning = TickId::new(LEFT, sim.height());
    assert_eq!(
        (sim.tick_of(abandoned.hash()), sim.tick_of(bystander_hash)),
        (Some(abandoning), Some(abandoning)),
        "fixture precondition: one tick abandons the member and runs the bystander",
    );
    let mut finalizations: Vec<Finalization> = sim
        .certify_votable()
        .into_iter()
        .filter(|finalization| *finalization.tick_id() == abandoning)
        .collect();
    finalizations.sort_by_key(|finalization| !finalization.is_determined());
    assert_eq!(
        finalizations.len(),
        match rides {
            Rides::Determined => 1,
            Rides::Legs => 2,
        },
        "fixture precondition: the abandoning tick certifies every half it owes",
    );

    if let Replica::Holding { ledger } = replica {
        let replay_from = if ledger {
            BlockHeight::new(1)
        } else {
            committed_at.next()
        };
        sim.restart_replaying(replay_from, abandoning.block_height().next());
        assert_eq!(
            sim.tick_of(abandoned.hash()),
            Some(abandoning),
            "the holder seats the abandonment off the block's line, whether or not its \
             ledger holds the member (ledger: {ledger})",
        );
    }

    let spend = local(0x55, 11, sim.now(), Duration::from_mins(1));
    let spend_hash = spend.hash();
    sim.spend_all(spend_hash, vault);
    match spend_at {
        SpendAt::Between => {
            sim.commit(vec![spend], Vec::new());
            sim.commit(Vec::new(), finalizations);
        }
        SpendAt::WithTheCharge => sim.commit(vec![spend], finalizations),
    }
    sim.drain();

    let spending = sim
        .tick_of(spend_hash)
        .expect("the spend joined a tick")
        .block_height();
    let output = sim
        .outputs()
        .iter()
        .rev()
        .find(|(tick, _)| *tick == spending)
        .map(|(_, output)| output.clone())
        .expect("the spend's tick ran");
    let taken = output
        .determined
        .iter()
        .find(|(tx_hash, _)| *tx_hash == spend_hash)
        .and_then(|(_, writes)| writes.movements.get(&vault))
        .map_or(0, |movement| movement.debit);
    Spent { output, taken }
}

/// Every placement of the member and the spend at which a held tick's
/// restored entry and a run's can read differently: any tick above the
/// abandoning one up to the block committing its determined half, and
/// the tick of the block committing its legs half.
const PLACEMENTS: [(Rides, SpendAt); 3] = [
    (Rides::Determined, SpendAt::Between),
    (Rides::Determined, SpendAt::WithTheCharge),
    (Rides::Legs, SpendAt::WithTheCharge),
];

/// A replica that held the abandoning tick runs a spend of the payer's
/// vault against the baseline a replica that ran it does.
///
/// An abandoned member reaches no engine, so the replica that ran the
/// tick appended nothing for it and reads its charge only once the base
/// carries the finalization's block. The holder seats what the tick left
/// from the same finalization, and reads the charge no earlier. Until
/// then the member's fee hold stands on the vault for both, so the spend
/// takes everything but the ceiling; a replica reading the charge early
/// would read the hold's end with it and take everything but the charge.
#[test]
fn a_spend_above_a_held_abandonment_takes_what_a_live_replica_takes() {
    for (rides, spend_at) in PLACEMENTS {
        let live = spend_above_an_abandonment(rides, spend_at, Replica::Live);
        assert_eq!(
            live.taken,
            FUNDED - CEILING,
            "fixture precondition: the live replica's spend reads the vault uncharged, under \
             the abandoned member's hold ({rides:?}, {spend_at:?})",
        );
        let held = spend_above_an_abandonment(rides, spend_at, Replica::Holding { ledger: true });
        assert_eq!(held, live, "{rides:?}, {spend_at:?}");
    }
}

/// The same where the holder's replay starts above the block that
/// committed the abandoned member: its ledger holds no entry for it, and
/// it seats the abandonment off the block's line as a replica holding the
/// entry does. What it leaves out of the restored entry is read off the
/// same lines.
#[test]
fn a_holder_without_the_ledger_entry_takes_the_same() {
    for (rides, spend_at) in PLACEMENTS {
        let live = spend_above_an_abandonment(rides, spend_at, Replica::Live);
        let held = spend_above_an_abandonment(rides, spend_at, Replica::Holding { ledger: false });
        assert_eq!(held, live, "{rides:?}, {spend_at:?}");
    }
}
