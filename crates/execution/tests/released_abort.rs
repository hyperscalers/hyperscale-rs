//! A member a halt recovery released is ended by an abort of its own.
//!
//! A recovery discards a tick whole, and with it a member a counterpart
//! shares the verdict on: its stated yes goes with its row, so no half
//! settles it. The next block names it `Aborted` off its row, and the
//! tick that seats the line settles it on this shard's certificate
//! alone: its stating half carries no counterpart's certificate, burns
//! the charge the line states and lands none of the effects the member's
//! run produced. The abort ends the row on this shard, and a counterpart
//! reads its exit off this shard's state.
//!
//! A shared member still in flight when its stating window closes is
//! aborted the same way, and the discard of its tick releases it alone:
//! the members the tick keeps still state off the tick's certificate.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use common::sim::{ExecutionSim, LEFT, Schedule, amount, cell_of, counter};
use hyperscale_engine::tick_select::{CommittedSets, member_lines};
use hyperscale_hbor::Capped;
use hyperscale_storage::RowState;
use hyperscale_types::test_utils::{
    genesis_charge, stub_transaction_with_reads, test_prefix, test_transaction_with_prefixes,
};
use hyperscale_types::{
    Deadline, DiscardCause, Evidence, Joins, PriceTable, PrincipalAddr, Role, Settlement, ShardId,
    TickHalf, TickLine, TimestampRange, Transaction, TxOutcome, WeightedTimestamp, Window,
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
        crossings: Capped::empty(),
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
        &BTreeMap::new(),
    );
    assert!(missing.is_empty());
    lines
}

/// The abort line the rows of a replica that ran `tx` name for it at
/// once, short of its deadline: the row stands released, a counterpart
/// sharing its verdict, having run and under no record.
fn abort_named_at_once(sim: &ExecutionSim, tx: &Transaction) -> Vec<TickLine> {
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
    let lines = lines_at(sim, deadline.at().minus(Duration::from_millis(1)));
    assert_eq!(lines, vec![aborting(tx)]);
    lines
}

/// A member that ran, whose certificate formed, and whose tick a
/// recovery then discarded is named for an abort by the next block, and
/// the tick seating that line settles it with no certificate of its
/// sibling's.
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

    sim.commit_naming(abort_named_at_once(&sim, &tx));
    let seated_in = sim.tick_of(hash).expect("the line seats the abort");
    let offered = sim.certify_votable();
    let [half] = &offered[..] else {
        panic!("the abort's tick offers one half: {offered:?}");
    };
    assert_eq!(*half.tick_id(), seated_in);
    assert_eq!(half.half(), TickHalf::Stated);
    let certificate = half
        .local_ec()
        .expect("a stating half carries its certificate");
    assert_eq!(certificate.shard_id(), LEFT);
    let [outcome] = &certificate.tx_outcomes()[..] else {
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
        let certificate = half
            .local_ec()
            .expect("a stating half carries its certificate");
        let attested = (
            half.half(),
            certificate.global_receipt_root(),
            certificate.tx_outcomes().clone(),
        );
        sim.commit(Vec::new(), offered);
        (attested, amount(sim.settled(vault)))
    };

    let retained = released_after_running(&tx);
    let lines = abort_named_at_once(&retained, &tx);
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

/// A crossing paid by `payer` from this shard, writing `local` here and
/// `remote` on its sibling, valid until `until`.
fn crossing_until(payer: u8, local: u8, remote: u8, until: WeightedTimestamp) -> Transaction {
    let mut body = [0u8; 31];
    body[1] = payer;
    stub_transaction_with_reads(
        PrincipalAddr::new(body),
        &[],
        &[test_prefix(local), test_prefix(remote)],
        1_000,
        TimestampRange::new(WeightedTimestamp::ZERO, until),
    )
}

/// A tick whose members all share their verdict, one near its deadline
/// among one valid far longer, runs both and forms its certificate, and
/// no block carries its stating half before the near member's stating
/// window closes. The block anchored there aborts the near member and
/// discards it from the tick; the tick keeps the other, and its stating
/// half, built again from the certificate over the member kept, states
/// it. The abort settles in a tick of its own.
#[test]
fn a_released_all_shared_tick_states_its_kept_members_from_its_certificate() {
    let near = crossing_until(0x11, LOCAL, 200, WeightedTimestamp::from_millis(10_000));
    let far = crossing_until(0x22, LOCAL + 1, 201, WeightedTimestamp::from_millis(60_000));
    let mut sim = ExecutionSim::with_shards(Schedule::Eager, 2, LEFT);
    for tx in [&near, &far] {
        sim.fund(tx.fee_vault(), FUNDED);
    }
    sim.commit(vec![near.clone(), far.clone()], Vec::new());
    sim.engage(SIBLING, &[near.hash(), far.hash()]);
    sim.drain();
    let tick = sim
        .tick_of(near.hash())
        .expect("the crossings joined a tick");
    assert_eq!(sim.tick_of(far.hash()), Some(tick), "one tick runs both");
    let [half] = &sim.certify_votable()[..] else {
        panic!("the tick offers one stating half");
    };
    assert_eq!(half.half(), TickHalf::Stated);
    let certified = half
        .local_ec()
        .expect("a stating half carries its certificate")
        .tx_outcomes()
        .len();
    assert_eq!(certified, 2, "the certificate covers both members");

    let closed = Window::Stating.of(Deadline::of_transaction(&near)).end;
    assert!(
        closed < Window::Stating.of(Deadline::of_transaction(&far)).end,
        "the far member is still inside its stating window",
    );
    let lines = lines_at(&sim, closed);
    assert!(
        matches!(
            &lines[..],
            [
                TickLine::Member { tx, joins: Joins::Aborted, .. },
                TickLine::Discard { tick: discarded, cause: DiscardCause::Abandoned(abandoned) },
            ] if *tx == near.hash() && *discarded == tick && *abandoned == near.hash()
        ),
        "the near member is aborted and discarded from its tick: {lines:?}",
    );
    sim.commit_naming(lines);
    assert!(matches!(
        sim.member_rows().members[&far.hash()].state,
        RowState::InFlight { .. }
    ));

    sim.commit(Vec::new(), Vec::new());
    let mut offered = sim.offered();
    offered.extend(sim.certify_votable());
    let kept = offered
        .iter()
        .find(|half| *half.tick_id() == tick)
        .expect("the tick owes its stating half again");
    assert_eq!(kept.half(), TickHalf::Stated);
    let stated: Vec<_> = kept.stated_outcomes().map(TxOutcome::tx_hash).collect();
    assert_eq!(
        stated,
        [far.hash()],
        "the rebuilt half states the kept member and leaves out the aborted one",
    );
    sim.commit(Vec::new(), offered);
    let rows = sim.member_rows();
    assert!(
        matches!(rows.members[&far.hash()].state, RowState::Stated { .. }),
        "the kept member states off the certificate",
    );
    assert!(
        !rows.members.contains_key(&near.hash()),
        "the abort settles in its own tick",
    );
}
