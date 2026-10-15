//! A member a halt recovery released is ended by an abort of its own.
//!
//! A recovery discards a tick whole, and with it a member a counterpart
//! shares the verdict on: no fresh quorum holds the certificate its legs
//! half would carry, so no half settles it. Past its deadline a block
//! names it `Aborted` off its row, and the tick that seats the
//! line settles it on this shard's certificate alone: its stating half
//! carries no counterpart's certificate, puts no claim to a
//! counterpart's settled set, burns the charge the line states and lands
//! none of the effects the member's run produced. The abort ends the row
//! on this shard, and a counterpart that has not settled reads it off the
//! fresh committee's certificate.

mod common;

use std::collections::BTreeSet;
use std::time::Duration;

use common::sim::{ExecutionSim, LEFT, Schedule, amount, cell_of, counter};
use hyperscale_engine::tick_select::{CommittedSets, member_lines};
use hyperscale_hbor::Capped;
use hyperscale_storage::RowState;
use hyperscale_types::test_utils::{genesis_charge, test_prefix, test_transaction_with_prefixes};
use hyperscale_types::{
    Deadline, Evidence, Joins, PriceTable, Role, Settlement, ShardId, TickHalf, TickLine,
    Transaction, WeightedTimestamp,
};

/// The shard the crossing also reaches.
const SIBLING: ShardId = ShardId::leaf(1, 1);

/// The local cell the crossing writes.
const LOCAL: u8 = 7;

/// What the payer's vault holds at genesis.
const FUNDED: u128 = 3_000;

/// A transaction paid from this shard that also writes on its sibling.
fn crossing() -> Transaction {
    test_transaction_with_prefixes(
        &[0, 0x33, 0xcc],
        &[],
        &[test_prefix(LOCAL), test_prefix(200)],
    )
}

/// The line that aborts `tx` once a recovery has released it: reaching
/// the sibling, awaiting nobody and answering no crossing.
fn aborting(tx: &Transaction) -> TickLine {
    TickLine::Member {
        tx: tx.hash(),
        joins: Joins::Aborted,
        settlement: Settlement::Awaited,
        holds: Capped::empty(),
        reach: Capped::from_array([SIBLING]),
        awaits: Capped::empty(),
        charge: genesis_charge(tx),
        share: tx.price(&PriceTable::GENESIS),
        reserves: Capped::empty(),
        deadline: Deadline::of_transaction(tx),
        nevers: Capped::empty(),
    }
}

/// A replica that committed `tx`, ran it beside its sibling's
/// engagement and formed its certificate, and then folded a recovery
/// discarding the tick before any block carried a half of it.
fn released_after_running(tx: &Transaction) -> ExecutionSim {
    let mut sim = ExecutionSim::with_shards(Schedule::Eager, 2, LEFT);
    let hash = tx.hash();
    sim.fund(tx.fee_vault(), FUNDED);
    sim.commit(vec![tx.clone()], Vec::new());
    sim.engage(SIBLING, &[hash]);
    sim.drain();
    let ran_in = sim.tick_of(hash).expect("the crossing joined a tick");
    assert!(!sim.receipts_for(&ran_in).is_empty(), "the member ran");
    sim.certify_votable();

    sim.recover(sim.height(), sim.next_epoch());
    sim.commit(Vec::new(), Vec::new());
    assert_eq!(sim.tick_of(hash), None, "the recovery discards its tick");
    sim
}

/// The lines a block anchored at `anchor` names over the rows `sim`'s
/// chain leaves, its sibling still answering.
fn lines_at(sim: &ExecutionSim, anchor: WeightedTimestamp) -> Vec<TickLine> {
    let (lines, missing, _) = member_lines(
        &sim.member_rows(),
        anchor,
        &CommittedSets::default(),
        &|_, _| Evidence::Live { terminating: false },
        false,
        &BTreeSet::new(),
    );
    assert!(missing.is_empty());
    lines
}

/// The abort line the rows of a replica that ran `tx` name for it at its
/// deadline, and at no anchor short of it: the row stands released, a
/// counterpart sharing its verdict, having run and under no record.
fn abort_named_at_the_deadline(sim: &ExecutionSim, tx: &Transaction) -> Vec<TickLine> {
    let row = &sim.member_rows().members[&tx.hash()];
    assert_eq!(
        (row.state, row.executed, row.covered),
        (
            RowState::Released {
                settlement: Settlement::Shared,
            },
            true,
            false,
        ),
    );
    let deadline = Deadline::of_transaction(tx);
    assert_eq!(
        lines_at(sim, deadline.at().minus(Duration::from_millis(1))),
        vec![],
        "the row stands short of its deadline",
    );
    let lines = lines_at(sim, deadline.at());
    assert_eq!(lines, vec![aborting(tx)]);
    lines
}

/// A member that ran, whose certificate formed, and whose tick a
/// recovery then discarded is named for an abort by the block anchored
/// at its deadline, and the tick seating that line settles it with no
/// certificate of its sibling's.
#[test]
fn a_released_shared_member_settles_the_abort_its_row_names_with_no_counterpart_certificate() {
    let tx = crossing();
    let hash = tx.hash();
    let vault = tx.fee_vault();
    let charge = genesis_charge(&tx);
    assert!(0 < charge.amount && charge.amount < FUNDED);
    assert_eq!(charge.vault, vault);
    let mut sim = released_after_running(&tx);
    assert_eq!(amount(sim.settled(vault)), FUNDED);

    sim.commit_naming(abort_named_at_the_deadline(&sim, &tx));
    let seated_in = sim.tick_of(hash).expect("the line seats the abort");
    let offered = sim.certify_votable();
    let [half] = &offered[..] else {
        panic!("the abort's tick offers one half: {offered:?}");
    };
    assert_eq!(*half.tick_id(), seated_in);
    assert_eq!(half.half(), TickHalf::Stated);
    let certificates = half.execution_certificates();
    assert_eq!(certificates.len(), 1, "no certificate but this shard's");
    assert_eq!(certificates[0].shard_id(), LEFT);
    let [outcome] = &certificates[0].tx_outcomes()[..] else {
        panic!("the half settles the one member");
    };
    assert_eq!(outcome.tx_hash(), hash);
    assert!(outcome.is_aborted());
    assert_eq!(outcome.role(), Role::Settling);
    assert_eq!(
        outcome.counterparts(),
        &[SIBLING],
        "the outcome names the sibling the member reaches",
    );
    assert_eq!(
        half.claims(LEFT, |_| false),
        vec![],
        "it asks nothing of the sibling's settled set",
    );

    sim.commit(Vec::new(), offered);
    assert!(
        !sim.member_rows().members.contains_key(&hash),
        "the stating half deletes the row",
    );
    assert_eq!(
        amount(sim.settled(vault)),
        FUNDED - charge.amount,
        "the abort burns the charge its line states",
    );
    assert_eq!(
        counter(sim.settled(cell_of(test_prefix(LOCAL)))),
        0,
        "none of the effects its run produced land",
    );
}

/// A replica that ran the member and held its certificate when the
/// recovery discarded its tick, and one that holds nothing of the
/// transaction but the line the first one's rows name, hand off the same
/// stating half for the abort and leave the same vault.
#[test]
fn a_replica_holding_only_the_line_settles_the_abort_its_peers_settle() {
    let tx = crossing();
    let vault = tx.fee_vault();
    let settle = |mut sim: ExecutionSim, lines: Vec<TickLine>| {
        sim.commit_naming(lines);
        let offered = sim.certify_votable();
        let [half] = &offered[..] else {
            panic!("the abort's tick offers one half: {offered:?}");
        };
        // The two stand at different heights, so the tick differs and
        // what it attests is what is held alike.
        let certificate = &half.execution_certificates()[0];
        let attested = (
            half.half(),
            certificate.global_receipt_root(),
            certificate.tx_outcomes().clone(),
        );
        sim.commit(Vec::new(), offered);
        (attested, amount(sim.settled(vault)))
    };

    let retained = released_after_running(&tx);
    let lines = abort_named_at_the_deadline(&retained, &tx);
    let mut fresh = ExecutionSim::with_shards(Schedule::Eager, 2, LEFT);
    fresh.fund(vault, FUNDED);
    fresh.commit(Vec::new(), Vec::new());
    fresh.recover(fresh.height(), fresh.next_epoch());
    fresh.commit(Vec::new(), Vec::new());

    let (retained, fresh) = (settle(retained, lines.clone()), settle(fresh, lines));
    assert_eq!(retained.0, fresh.0, "one root over one outcome");
    assert_eq!(retained.1, fresh.1);
    assert_eq!(fresh.1, FUNDED - genesis_charge(&tx).amount);
}
