//! One manifest, read by both of its readers.
//!
//! A block's tick manifest is folded into member rows by every replica,
//! and seated into a tick by execution. Admission holds a determined
//! half to the rows: it settles every row its tick holds in flight for
//! that half, and no other. So the half execution builds from its seats
//! has to name exactly the members the fold put in flight alone, for
//! every kind of member a line names, or the chain refuses the only half
//! its replicas offer.

mod common;

use std::sync::Arc;

use common::sim::{ExecutionSim, LEFT, Schedule};
use hyperscale_shard::admission::admit_finalization_over;
use hyperscale_storage::{MemberIndex, MemberInputs, MemberSections, RowState};
use hyperscale_types::test_utils::{stub_transaction, test_prefix, test_transaction_with_prefixes};
use hyperscale_types::{
    CertifiedBlock, Deadline, EpochWindows, Finalization, Joins, PrincipalAddr, Settlement,
    ShardId, TickLine, TimestampRange, Transaction, TxHash, Verifiable, WeightedTimestamp,
};

/// A transaction paid from this shard that also reaches its sibling,
/// writing the local cell of `local`.
fn crossing(seed: u8, local: u8) -> Transaction {
    test_transaction_with_prefixes(
        &[seed, seed ^ 0x33, seed ^ 0xcc],
        &[],
        &[test_prefix(local), test_prefix(200 + seed)],
    )
}

/// A transaction this shard runs alone, writing the cell of `local`.
fn single(seed: u8, local: u8) -> Transaction {
    test_transaction_with_prefixes(
        &[seed, seed ^ 0x33, seed ^ 0xcc],
        &[],
        &[test_prefix(local)],
    )
}

/// A transaction this shard runs alone, valid from `now`.
fn fresh(now: WeightedTimestamp) -> Transaction {
    stub_transaction(
        PrincipalAddr::new([0x44; 31]),
        &[test_prefix(9)],
        1_000,
        TimestampRange::new(now, now.plus(std::time::Duration::from_mins(1))),
    )
}

/// The members a block's lines name, each with how it joins and which
/// half settles it.
fn named(certified: &CertifiedBlock) -> Vec<(TxHash, Joins, Settlement)> {
    certified
        .block()
        .tick_manifest()
        .iter()
        .filter_map(|line| match line {
            TickLine::Member {
                tx,
                joins,
                settlement,
                ..
            } => Some((*tx, *joins, *settlement)),
            _ => None,
        })
        .collect()
}

/// One tick naming a member it runs alone, an abort that reaches no
/// other shard and an abort that reaches one. The determined half
/// execution builds from the tick it seated off those lines is admitted
/// against the rows the same lines fold to, and the block carrying it
/// leaves standing in the tick exactly the member its lines settle
/// elsewhere.
#[test]
fn the_half_execution_builds_settles_the_rows_its_manifest_folds_to() {
    let mut sim = ExecutionSim::with_shards(Schedule::Eager, 2, LEFT);

    // A crossing that engages and stays in flight holding the cell of
    // prefix 7, so a single-shard member writing that cell waits behind
    // it to its deadline. A second crossing never engages.
    let (holder, waiting, unengaged) = (crossing(1, 7), single(2, 7), crossing(3, 8));
    let deadline = Deadline::of_transaction(&waiting);
    assert_eq!(deadline, Deadline::of_transaction(&unengaged));
    let (holder_tx, waiting_tx, unengaged_tx) = (holder.hash(), waiting.hash(), unengaged.hash());
    sim.commit(vec![holder], Vec::new());
    sim.engage(ShardId::leaf(1, 1), &[holder_tx]);
    sim.commit(vec![waiting, unengaged], Vec::new());
    sim.drain();
    assert!(sim.tick_of(holder_tx).is_some(), "the holder runs");
    assert!(
        sim.tick_of(waiting_tx).is_none() && sim.tick_of(unengaged_tx).is_none(),
        "one waits on a held cell and one on its counterpart",
    );

    while !deadline.passed(sim.next_anchor()) {
        sim.commit(Vec::new(), Vec::new());
    }
    let runs = fresh(sim.next_anchor());
    let runs_tx = runs.hash();
    sim.commit(vec![runs], Vec::new());
    sim.drain();
    let tick = sim.height();

    let lines = named(sim.committed().last().expect("a block committed"));
    let line_of = |tx: TxHash| {
        lines
            .iter()
            .find(|(named, ..)| *named == tx)
            .map(|(_, joins, settlement)| (*joins, *settlement))
    };
    assert_eq!(
        [line_of(runs_tx), line_of(waiting_tx), line_of(unengaged_tx)],
        [
            Some((Joins::Executes, Settlement::Alone)),
            Some((Joins::Aborted, Settlement::Alone)),
            Some((Joins::Aborted, Settlement::Awaited)),
        ],
        "the tick names one member of each kind: {lines:?}",
    );

    let rows = sim.member_rows();
    let standing = |rows: &MemberIndex, alone: bool| -> Vec<TxHash> {
        let mut standing: Vec<TxHash> = rows
            .members
            .values()
            .filter(|row| {
                matches!(
                    row.state,
                    RowState::InFlight { tick: held, settlement, .. }
                        if held == tick && settlement.alone() == alone
                )
            })
            .map(|row| row.tx)
            .collect();
        standing.sort_unstable();
        standing
    };
    let mut alone = vec![runs_tx, waiting_tx];
    alone.sort_unstable();
    assert_eq!(standing(&rows, true), alone);
    assert_eq!(standing(&rows, false), vec![unengaged_tx]);

    let half: Finalization = sim
        .certify_votable()
        .into_iter()
        .find(|fw| fw.is_determined() && fw.tick_id().block_height() == tick)
        .expect("execution hands off the tick's determined half");
    let mut settled: Vec<TxHash> = half.tx_hashes().collect();
    settled.sort_unstable();
    assert_eq!(settled, alone, "the half names the rows in flight alone");
    assert_eq!(half.validate_against_certificates(), Ok(()));

    let frontier = tick.prev().expect("a tick above genesis");
    assert_eq!(
        admit_finalization_over(sim.snapshot(), LEFT, &rows, frontier, &half),
        Ok(()),
    );

    let mut after = rows;
    after.advance(&MemberInputs::deriving(
        LEFT,
        tick.next(),
        sim.next_anchor(),
        std::iter::empty(),
        MemberSections {
            certificates: &[Arc::new(Verifiable::from(half))],
            records: &[],
            claims: &[],
        },
        EpochWindows::new(0, 0),
        Vec::new(),
    ));
    assert_eq!(standing(&after, true), Vec::<TxHash>::new());
    assert_eq!(standing(&after, false), vec![unengaged_tx]);
    assert!(
        after
            .ticks
            .get(&tick)
            .is_some_and(|row| !row.determined_unsettled && row.awaiting == 1),
        "the tick owes what its other half settles, and nothing else",
    );
    assert!(after.owed_determined().range(..=tick).next().is_none());
}
