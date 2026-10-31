//! A halt recovery's crossing block lets go of every tick below its
//! bridge.
//!
//! A shard halted past f is recovered by a fresh committee that holds the
//! settled state at the beacon-attested frontier and folds the harvested
//! blocks above it. No replica that has folded the recovery dispatches a
//! run of a tick anchored below its bridge, or signs one. The crossing block, the first
//! anchored at or past the bridge, discards every tick its parent's rows
//! hold, and the tick chain floor rises to its parent, so the first tick
//! past it reads the base alone on a replica that ran the discarded ticks
//! and on one that ran none. A tick the recovered chain keeps is one a
//! kept block settled.

mod common;

use std::sync::Arc;

use common::sim::{ExecutionSim, SHARD, Schedule, cell_of, counter};
use hyperscale_engine::tick_select::terms_of;
use hyperscale_shard::admission::admit_finalization_over;
use hyperscale_storage::{MemberIndex, MemberInputs, MemberSections, RowState, TickOutput};
use hyperscale_types::test_utils::{test_prefix, test_transaction_with_prefixes};
use hyperscale_types::{
    BlockHeight, Deadline, Epoch, EpochWindows, Finalization, Joins, Settlement, StatedTerms,
    TickId, TickLine, Transaction, TxHash, Verifiable,
};

/// The prefix every transaction here writes a counter under.
const LOCAL: u8 = 7;

/// The recovery's attested frontier.
const FRONTIER: BlockHeight = BlockHeight::new(3);

/// The tick above the frontier the chains below halt over.
const ABOVE: BlockHeight = BlockHeight::new(4);

/// A single-shard transaction over one counter: it joins the tick its
/// block commits, and its write stays determined and unsettled until a
/// certificate commits.
fn local_tx(seed: u8) -> Transaction {
    test_transaction_with_prefixes(
        &[seed, seed ^ 0x5a, seed ^ 0xa5],
        &[],
        &[test_prefix(LOCAL)],
    )
}

/// The last output `sim` produced for the tick at `tick`.
fn output_of(sim: &ExecutionSim, tick: BlockHeight) -> Option<TickOutput> {
    sim.outputs()
        .iter()
        .rev()
        .find(|(height, _)| *height == tick)
        .map(|(_, output)| output.clone())
}

/// A fresh replica seated at the frontier, folding the harvested blocks
/// carrying `seeds` below a bridge one block past them, then the crossing
/// block carrying `crossing`.
fn fresh_through_the_crossing(seeds: std::ops::Range<u8>, crossing: u8) -> ExecutionSim {
    let mut fresh = ExecutionSim::seated_at(Schedule::Eager, FRONTIER);
    let bridge = Epoch::new(FRONTIER.inner() + u64::try_from(seeds.len()).unwrap() + 1);
    fresh.recover(FRONTIER, bridge);
    for seed in seeds {
        fresh.commit(vec![local_tx(seed)], Vec::new());
    }
    fresh.commit(vec![local_tx(crossing)], Vec::new());
    fresh.drain();
    fresh
}

/// A replica that has folded a recovery runs no tick anchored below its
/// bridge and signs none, harvested or not: the first it runs is the
/// crossing block's.
#[test]
fn a_replica_that_folded_the_recovery_runs_no_tick_below_its_bridge() {
    let mut retained = ExecutionSim::new(Schedule::Eager);
    for seed in 0..3 {
        retained.commit(vec![local_tx(seed)], Vec::new());
    }
    retained.drain();
    let ran = retained.outputs().len();
    retained.recover(FRONTIER, Epoch::new(7));
    for seed in 3..5 {
        retained.commit(vec![local_tx(seed)], Vec::new());
    }
    retained.commit(Vec::new(), Vec::new());
    retained.drain();
    assert!(
        retained.outputs()[ran..].is_empty(),
        "no tick anchored below the bridge runs",
    );
    assert!(
        retained.certify_votable().is_empty(),
        "no tick anchored below the bridge is signed",
    );

    retained.commit(vec![local_tx(5)], Vec::new());
    retained.drain();
    let past: Vec<BlockHeight> = retained.outputs()[ran..]
        .iter()
        .map(|(tick, _)| *tick)
        .collect();
    assert_eq!(
        past,
        vec![BlockHeight::new(7)],
        "the crossing block's tick runs"
    );
}

/// A tick queued before the replica folded the recovery, waiting on the
/// write of the block below it, does not run once it has: the first
/// commit past the fold takes every tick anchored below the bridge out
/// of the queue.
#[test]
fn a_tick_queued_before_the_fold_does_not_run_after_it() {
    let mut retained = ExecutionSim::new(Schedule::Eager);
    retained.withhold_persistence();
    for seed in 0..3 {
        retained.commit(vec![local_tx(seed)], Vec::new());
    }
    let ran = retained.outputs().len();
    retained.recover(FRONTIER, Epoch::new(7));
    retained.commit(Vec::new(), Vec::new());
    retained.persist();
    retained.drain();
    assert!(
        retained.outputs()[ran..].is_empty(),
        "no queued tick anchored below the bridge runs: {:?}",
        retained.outputs()[ran..]
            .iter()
            .map(|(tick, _)| *tick)
            .collect::<Vec<_>>(),
    );
}

/// The first tick past the crossing reads the base alone on a replica
/// whose chain holds runs of the ticks the recovery discards, made before
/// the halt and over the harvested blocks before it folded the recovery,
/// and runs what a fresh replica that ran none of them runs.
#[test]
fn the_first_tick_past_the_crossing_reads_the_base_alone() {
    let mut retained = ExecutionSim::new(Schedule::Eager);
    for seed in 0..5 {
        retained.commit(vec![local_tx(seed)], Vec::new());
    }
    retained.drain();
    retained.recover(FRONTIER, retained.next_epoch());
    retained.commit(vec![local_tx(5)], Vec::new());
    retained.drain();

    let fresh = fresh_through_the_crossing(3..5, 5);
    let crossing = BlockHeight::new(6);
    assert!(output_of(&retained, crossing).is_some());
    assert_eq!(output_of(&retained, crossing), output_of(&fresh, crossing));
    for sim in [&retained, &fresh] {
        assert_eq!(
            counter(sim.read(cell_of(test_prefix(LOCAL)))),
            1,
            "nothing below the crossing is read past it",
        );
    }
}

/// A batch in flight at the crossing commit is of a tick the recovery
/// discards: its completion records nothing, and the crossing block's
/// tick runs over the base alone.
#[test]
fn a_run_in_flight_at_the_crossing_records_nothing() {
    let mut retained = ExecutionSim::new(Schedule::Lagged(1));
    for seed in 0..5 {
        retained.commit(vec![local_tx(seed)], Vec::new());
    }
    retained.recover(FRONTIER, retained.next_epoch());
    retained.commit(vec![local_tx(5)], Vec::new());
    retained.drain();

    let fresh = fresh_through_the_crossing(3..5, 5);
    let crossing = BlockHeight::new(6);
    assert_eq!(output_of(&retained, crossing), output_of(&fresh, crossing));
    assert_eq!(counter(retained.read(cell_of(test_prefix(LOCAL)))), 1);
    assert_eq!(retained.tick_of(local_tx(4).hash()), None);
}

/// A chain as a halt leaves it: three ticks at or below the frontier
/// and one above it, each run over the ones before and none settled.
fn halted() -> ExecutionSim {
    let mut sim = ExecutionSim::new(Schedule::Eager);
    for seed in 0..4 {
        sim.commit(vec![local_tx(seed)], Vec::new());
    }
    sim.drain();
    sim
}

/// The member rows every block `sim` committed leaves: each block's
/// transactions on the terms its committee derives, its finalizations,
/// and the lines its commit seated.
fn rows_of(sim: &ExecutionSim) -> MemberIndex {
    let mut rows = MemberIndex::empty(SHARD);
    for certified in sim.committed() {
        let block = certified.block();
        let header = block.header();
        let terms = block
            .transactions()
            .iter()
            .map(|tx| StatedTerms {
                tx: tx.hash(),
                terms: terms_of(tx.as_unverified(), sim.snapshot(), SHARD),
            })
            .collect();
        rows.advance(&MemberInputs {
            manifest: Arc::new(block.tick_manifest().clone()),
            ..MemberInputs::deriving(
                SHARD,
                header.height(),
                header.parent_qc().weighted_timestamp(),
                block.transactions().iter().map(Verifiable::as_unverified),
                MemberSections {
                    certificates: block.certificates(),
                    records: block.abandonment_records(),
                    claims: block.state_claims(),
                },
                EpochWindows::new(0, 0),
                terms,
            )
        });
    }
    rows
}

/// The determined half among `halves` of the tick at `tick`.
fn half_of(halves: &[Finalization], tick: BlockHeight) -> Finalization {
    halves
        .iter()
        .find(|fw| fw.is_determined() && fw.tick_id().block_height() == tick)
        .cloned()
        .expect("the tick's committee certifies its determined half")
}

/// `sim` past its recovery's crossing block, the block after its tip.
fn crossed(mut sim: ExecutionSim) -> ExecutionSim {
    sim.recover(FRONTIER, sim.next_epoch());
    sim.commit(Vec::new(), Vec::new());
    sim.drain();
    sim
}

/// A tick below the bridge settles only what a kept block settled. The
/// crossing block discards the tick above the frontier with the ticks
/// below it: no half is offered or admitted for it, and the recovered
/// chain settles nothing of it, whether the ticks below it stood
/// unsettled at the halt or a kept block above it had settled them.
#[test]
fn a_tick_below_the_bridge_settles_only_what_a_kept_block_settled() {
    let cell = cell_of(test_prefix(LOCAL));
    let lost = half_of(&halted().certify_votable(), ABOVE);
    let (kept, lost_over_kept) = halted_past_settling_the_frontier();
    for (sim, lost, settled) in [(halted(), lost, 0), (kept, lost_over_kept, 3)] {
        let mut recovered = crossed(sim);
        let rows = rows_of(&recovered);
        assert!(
            rows.ticks.is_empty(),
            "the crossing discards every tick row"
        );
        assert!(recovered.certify_votable().is_empty());
        assert!(recovered.offered_finalizations().is_empty());
        let refused = admit_finalization_over(
            recovered.snapshot(),
            SHARD,
            &rows,
            BlockHeight::GENESIS,
            &lost,
        );
        assert!(
            refused
                .as_ref()
                .is_err_and(|err| err.contains("does not hold")),
            "the replaced committee's half of the tick above the frontier: {refused:?}",
        );
        assert_eq!(counter(recovered.settled(cell)), settled);
    }
}

/// A replica holding the replaced committee's certificate for every tick
/// it ran, the one above the frontier included, crosses the recovery
/// without running any of them again: nothing it holds is reconciled
/// against a second run, and it holds no tick, vote or finalization for
/// any of them past the crossing.
#[test]
fn a_retained_seat_holding_a_certificate_survives_the_crossing() {
    let mut retained = halted();
    assert_eq!(retained.certify_votable().len(), 4);
    let mut retained = crossed(retained);
    for seed in 0..4 {
        assert_eq!(retained.tick_of(local_tx(seed).hash()), None);
    }
    retained.commit(vec![local_tx(4)], Vec::new());
    retained.drain();
    assert!(retained.offered_finalizations().is_empty());
    assert_eq!(
        retained.certify_votable().len(),
        1,
        "only the tick past the crossing is signed",
    );
}

/// A tick a halt recovery discards settles nothing afterwards, the one
/// above the frontier with the ones at or below it. The half its
/// replaced committee certified is refused over the rows the discard
/// leaves, the coordinator holds no tick, vote or finalization for it,
/// and no later block names a member of it to run: each is aborted from
/// its deadline, and nothing it wrote reaches state.
#[test]
fn a_discarded_tick_settles_nothing_its_replaced_committee_certified() {
    let discarded: Vec<TxHash> = (0..4).map(|seed| local_tx(seed).hash()).collect();
    let deadline = Deadline::of_transaction(&local_tx(0));
    let replaced = halted().certify_votable();

    let mut recovered = crossed(halted());

    let rows = rows_of(&recovered);
    for (tx, tick) in discarded.iter().zip(1u64..) {
        assert_eq!(
            rows.members.get(tx).map(|row| row.state),
            Some(RowState::Released {
                settlement: Settlement::Alone
            }),
        );
        assert_eq!(recovered.tick_of(*tx), None);
        let half = half_of(&replaced, BlockHeight::new(tick));
        let refused = admit_finalization_over(
            recovered.snapshot(),
            SHARD,
            &rows,
            BlockHeight::GENESIS,
            &half,
        );
        assert!(
            refused
                .as_ref()
                .is_err_and(|err| err.contains("does not hold")),
            "the replaced committee's half of tick {tick}: {refused:?}",
        );
    }
    let mut offered: Vec<BlockHeight> = recovered
        .certify_votable()
        .iter()
        .map(|fw| fw.tick_id().block_height())
        .collect();
    offered.extend(
        recovered
            .offered_finalizations()
            .iter()
            .map(TickId::block_height),
    );
    offered.sort_unstable();
    offered.dedup();
    assert!(
        offered.is_empty(),
        "no tick below the bridge is offered: {offered:?}"
    );

    let recovered_at = recovered.committed().len();
    while !deadline.passed(recovered.now()) {
        recovered.commit(Vec::new(), Vec::new());
    }
    recovered.drain();
    let mut aborted = Vec::new();
    for certified in &recovered.committed()[recovered_at..] {
        for line in certified.block().tick_manifest().iter() {
            let TickLine::Member {
                tx,
                joins,
                crossings,
                ..
            } = line
            else {
                continue;
            };
            if discarded.contains(tx) {
                assert_eq!(*joins, Joins::Aborted, "no line runs a released member");
                assert!(crossings.is_empty());
                aborted.push(*tx);
            }
        }
    }
    aborted.sort_unstable();
    let mut expected = discarded;
    expected.sort_unstable();
    assert_eq!(aborted, expected, "each is aborted once, from its deadline");
    assert_eq!(
        counter(recovered.settled(cell_of(test_prefix(LOCAL)))),
        0,
        "nothing a discarded tick wrote reaches state",
    );
}

/// A chain as a halt leaves it once it has settled every tick at or
/// below the frontier in a block above it: the tick above the frontier
/// ran over those three while none had settled, and no tick at or below
/// the frontier is owed anything at the tip.
///
/// Beside it, the half its committee certified for the tick above.
fn halted_past_settling_the_frontier() -> (ExecutionSim, Finalization) {
    let mut sim = halted();
    let mut certified = sim.certify_votable();
    let above = half_of(&certified, ABOVE);
    certified.retain(|fw| fw.tick_id().block_height() <= FRONTIER);
    certified.sort_by_key(|fw| fw.tick_id().block_height());
    assert_eq!(certified.len(), 3, "a determined half for each tick below");
    sim.commit(Vec::new(), certified);
    sim.drain();
    (sim, above)
}

/// The crossing raises the tick chain floor under the committee the
/// shard reads the block with. The crossing block's parent is anchored in
/// a window the beacon froze before it stamped the recovery, and the
/// block is handed to execution under that parent's anchor; execution
/// still names the crossing, so the first tick past it reads the base
/// alone on a replica whose chain holds runs of the discarded ticks.
#[test]
fn the_crossing_raises_the_floor_under_the_parents_anchor() {
    let mut retained = ExecutionSim::new(Schedule::Eager);
    for seed in 0..5 {
        retained.commit(vec![local_tx(seed)], Vec::new());
    }
    retained.drain();
    retained.recover(FRONTIER, retained.next_epoch());
    retained.commit(vec![local_tx(5)], Vec::new());
    retained.drain();
    assert_eq!(
        counter(retained.read(cell_of(test_prefix(LOCAL)))),
        1,
        "nothing below the crossing is read past it",
    );
}
