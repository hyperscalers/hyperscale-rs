//! Portable network-fault scenarios.

use std::collections::BTreeSet;
use std::fmt::Write;
use std::sync::Arc;
use std::time::Duration;

use hyperscale_engine::PROTOCOL_RESOURCE;
use hyperscale_engine::tick_select::{awaited_core, member_of};
use hyperscale_storage::{RowState, committed_tx_cell_key};
use hyperscale_types::test_utils::Withheld;
use hyperscale_types::{
    BlockHeight, Deadline, Ed25519PrivateKey, Epoch, HALT_THRESHOLD_EPOCHS, Joins,
    MAX_STANDING_ANSWERS, MAX_STANDING_ANSWERS_FROM_SHARD, MAX_STANDING_TOWARD_SHARD,
    MAX_TXS_PER_BLOCK, PrincipalAddr, SWEEP_BUCKET_MS, ShardId, ShardTrie, StateRoot,
    TimestampRange, TransactionDecision, TransactionStatus, TxHash, ValidatorId, WeightedTimestamp,
    Window,
};
use hyperscale_vm_types::{COMMITTED_GRACE_MS, MAX_CROSSINGS_PER_TX};

use crate::reshape::split_lifecycle;
use crate::route::{FIRST_VENUE_SHARD, SECOND_VENUE_SHARD, sponsor, stand_up_venues, traders};
use crate::straddler::{STRADDLER_PAYMENT, chain_settled, isolate_crossing_intake};
use crate::support::conservation::{Charges, World, probe_world};
use crate::support::faultable::{FaultableCluster, report_crossing_measures};
use crate::support::query::{
    beacon_epoch, clock, epoch_duration_ms, epoch_windows, into_epoch_ms, retirement_wait,
    vault_balance,
};
use crate::support::tx::{
    HALT_STRADDLER_BATCH, HaltStraddlerSetup, HarvestedTickSetup, PaymentLeg, account_shard,
    build_composed_tx, build_probe_transfer_tx, build_route_tx,
    build_sponsored_bounded_transfer_tx, build_transfer_tx, cross_shard_fault_cast,
    halt_straddler_setup, harvested_tick_setup, payment_request_for, validity_around,
};
use crate::support::wait::{
    await_beacon_epoch, await_crossings_end, await_height, await_tx_terminal,
};
use crate::support::{Cluster, committees_on_separate_hosts, epochs};
use crate::venue::grind_onto;

/// Dropping `transaction.gossip` still delivers a submitted transfer — via the
/// fetch fallback — with the drop rule firing and the fetch engaging.
///
/// The feasibility check for the iroh gate: on the sim the drop is total at
/// delivery; on production the inbound `Ignore` filter suppresses the gossip on
/// every host, so a submitted transaction reaches the committee only by the
/// fetch fallback.
///
/// # Panics
///
/// Panics if the transfer does not accept within budget, the drop rule never
/// fired, or the fetch fallback never engaged.
pub fn gossip_drop_engages_fetch_fallback(c: &mut impl FaultableCluster) {
    let fetch_before = c.metric("fetch_items_sent", Some("transaction"));
    let dropped = c.drop_type("transaction.gossip");
    let world = probe_world(c);
    let mut charges = Charges::default();

    let transfer = build_probe_transfer_tx(validity_around(c.now()));
    let hash = charges.submit(c, transfer);

    let status = await_tx_terminal(c, hash, epochs(8));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "the transfer must still accept via the fetch fallback; status = {status:?}"
    );
    world.assert_settles_within(c, &charges, epochs(4), "a probe under a gossip drop");
    assert!(
        dropped.fired() >= 1,
        "the transaction.gossip drop rule must fire",
    );
    assert!(
        c.metric("fetch_items_sent", Some("transaction")) > fetch_before,
        "the transaction fetch fallback must engage (before={fetch_before})",
    );
}

/// A 2-2 host partition starves quorum (3 of 4), so consensus halts; healing it
/// resumes commits as the lagging half catches up.
///
/// Requires a four-host single-shard cluster. The heal exercises the catch-up
/// sync path: the lagging half resynchronises via block fetch, not gossip
/// re-delivery, so the resume budget covers a few sync rounds.
///
/// # Panics
///
/// Panics if consensus does not commit before the partition, progress fails to
/// halt under it, or commits do not resume after the heal.
pub fn partition_halts_and_heals(c: &mut impl FaultableCluster) {
    assert!(
        await_height(c, ShardId::ROOT, 1, epochs(4)),
        "consensus must commit a block before the partition",
    );
    let before = c
        .committed_height(ShardId::ROOT)
        .expect("a committed height before the partition")
        .inner();

    // Neither half of a 2-2 split has the 3-of-4 quorum, so progress halts.
    c.partition(&[0, 1], &[2, 3]);
    c.run_until(epochs(1), |_| false);
    let during = c
        .committed_height(ShardId::ROOT)
        .expect("a committed height during the partition")
        .inner();
    assert!(
        during <= before + 2,
        "a 2-2 partition has no quorum, so progress must halt: before={before}, during={during}",
    );

    // Healing lets the pacemaker resynchronise the lagging half; commits resume.
    c.heal_all();
    assert!(
        await_height(c, ShardId::ROOT, during + 3, epochs(6)),
        "consensus must resume committing once the partition heals (stalled at {during})",
    );
}

/// A transaction settles while one validator is isolated: the remaining 3-of-4
/// quorum holds, and the vote-retry rotation recovers any tick the isolated node
/// was leading.
///
/// Requires a four-host single-shard cluster. Submission routes to host 0, so a
/// different host is isolated — one that still proposes some rounds, exercising
/// the leader-failure fallback.
///
/// # Panics
///
/// Panics if consensus does not commit before the isolation or the transfer does
/// not complete while a validator is isolated.
pub fn isolated_validator_still_settles(c: &mut impl FaultableCluster) {
    assert!(
        await_height(c, ShardId::ROOT, 1, epochs(4)),
        "consensus must commit a block before isolating a validator",
    );
    c.isolate(3);
    let world = probe_world(c);
    let mut charges = Charges::default();

    let transfer = build_probe_transfer_tx(validity_around(c.now()));
    let hash = charges.submit(c, transfer);

    let status = await_tx_terminal(c, hash, epochs(6));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "the transfer must complete despite an isolated validator; status = {status:?}",
    );
    world.assert_settles_within(
        c,
        &charges,
        epochs(4),
        "a probe beside an isolated validator",
    );
}

/// A shard halts when f+1 of its committee withhold their consensus
/// messages, and the beacon recovers it by re-drawing the whole committee
/// from the pool.
///
/// After the root grows, two members of the left child's four-member
/// committee go silent at the consensus layer only: they stop signing
/// proposals, votes, and timeouts, while every other duty — beacon
/// participation, pool ratification, block serving — carries on. The
/// honest remainder is short of the 2f+1 quorum, so the shard freezes
/// while its sibling and the beacon keep committing. Once
/// the boundary watermark stalls past the halt threshold the beacon flags
/// the shard, seats a fresh committee from the pool spares, and retains
/// the replaced members in the routing view; the incomers sync the halted
/// tip from them, bridge the halt gap, and the shard resumes committing.
/// The first crossing under the fresh committee clears the recovery
/// record.
///
/// The reshape thresholds stay armed throughout — quiet (both children
/// hold in the stable band between the derived merge floor and the split
/// threshold), but forcing every proposal and vote through the reshape
/// predicate's substate walk. Across the recovery that walk crosses the
/// sync-admitted halted tip, whose byte total no fresh member can
/// resolve; the bridge blocks build and verify only because both sides
/// agree the assertion is out of play there, and that agreement is what
/// this scenario exercises.
///
/// Requires [`halt_straddler_setup`] at genesis and two committees'
/// worth of pool surplus — one grow cohort, one recovery committee.
///
/// [`halt_straddler_setup`]: crate::tx::halt_straddler_setup
///
/// # Panics
///
/// Panics if the shard fails to halt, the beacon or the sibling shard
/// stops committing through the halt, the recovery never fires, the shard
/// fails to resume under its fresh committee, the recovery record never
/// clears, or a redrawn committee rather than the first one clears it.
pub fn halted_shard_recovers_by_committee_redraw(c: &mut impl FaultableCluster) {
    let (left, right) = ShardId::ROOT.children();
    split_lifecycle(c);
    let halt = freeze_shard(c, left, right, |_| {});
    await_halt_recovery(c, &halt);
}

/// A recovery chained onto a pending one.
///
/// The first fresh committee is held below a quorum from its draw, so
/// its crossing never folds; after the halt threshold the beacon stamps a
/// second recovery over the pending one, keeping the first's frontier,
/// and the second fresh committee resumes the shard and clears the
/// record.
///
/// Characterising: the shard's history holds both bindings, the first
/// never completed and the second did, at one frontier, and every
/// replica of the recovered shard agrees on one state root. The pair that
/// froze the shard is released once the first draw has replaced it, so a
/// later draw that seats one of them seats an honest member.
///
/// Requires [`halt_straddler_setup`] at genesis and three committees'
/// worth of pool surplus.
///
/// [`halt_straddler_setup`]: crate::tx::halt_straddler_setup
///
/// # Panics
///
/// Panics if the shard fails to halt, the first recovery is never
/// drawn or never superseded, the second fresh committee fails to resume
/// the shard or clear the record, or the recovered shard's replicas never
/// agree on a state root.
pub fn a_fresh_committee_recovered_again_before_its_crossing_folds(c: &mut impl FaultableCluster) {
    let (shard, sibling) = ShardId::ROOT.children();
    split_lifecycle(c);
    let replaced = committee_members(c, shard);
    let halt = freeze_shard(c, shard, sibling, |_| {});
    let first = await_recovery_draw(c, &halt);
    c.withhold(&replaced, Withheld::Nothing);

    let stalled = c
        .beacon_state()
        .and_then(|state| state.next_shard_committees.get(&shard).cloned())
        .expect("the draw seats the first fresh committee")
        .members;
    c.withhold(&stalled[..2], Withheld::Consensus);
    let threshold = u32::try_from(HALT_THRESHOLD_EPOCHS).expect("threshold fits u32");
    let restamped = c.run_until(epochs(threshold + 25), |c| {
        c.beacon_state().is_some_and(|state| {
            state
                .pending_recoveries
                .get(&shard)
                .is_some_and(|recovery| recovery.rotated_at != first)
        })
    });
    assert!(
        restamped,
        "a first fresh committee that never crosses is recovered again",
    );
    let second = c
        .beacon_state()
        .and_then(|state| state.pending_recoveries.get(&shard).map(|r| r.rotated_at))
        .expect("the second recovery is pending");
    c.withhold(&stalled[..2], Withheld::Nothing);

    await_recovery_resume(c, &halt, second);
    let history: Vec<(Epoch, BlockHeight, bool)> = c
        .beacon_state()
        .and_then(|state| state.recoveries.get(&shard).cloned())
        .expect("the shard keeps its recovery history")
        .iter()
        .map(|binding| {
            (
                binding.rotated_at,
                binding.attested_frontier,
                binding.completed,
            )
        })
        .collect();
    let first_binding = history
        .iter()
        .find(|(rotated_at, ..)| *rotated_at == first)
        .copied()
        .expect("the first recovery keeps its binding");
    let second_binding = history
        .iter()
        .find(|(rotated_at, ..)| *rotated_at == second)
        .copied()
        .expect("the second recovery keeps its binding");
    assert!(!first_binding.2, "the first recovery never completed");
    assert!(second_binding.2, "the second recovery completed");
    assert_eq!(
        first_binding.1, second_binding.1,
        "the second recovery keeps the first's frontier",
    );
    let agreed = c.run_until(epochs(10), |c| agreed_state_root(c, shard).is_some());
    assert!(
        agreed,
        "the recovered shard's replicas agree on one state root"
    );
}

/// `shard`'s consensus committee as the beacon state records it.
fn committee_members(c: &impl FaultableCluster, shard: ShardId) -> Vec<ValidatorId> {
    c.beacon_state()
        .and_then(|state| state.shard_consensus_members.get(&shard).cloned())
        .expect("the shard has a consensus committee")
}

/// How long before its validity ends the swept-suffix scenario submits
/// its transfer: room to commit on a quiet shard, inside the longest
/// range a transaction may sign.
const SWEPT_SUFFIX_VALIDITY_LEFT_MS: u64 = 90_000;

/// How far short of the sweep's bucket boundary the swept-suffix scenario
/// reads the halting shard's height, so the height it reads is below the
/// block that sweeps on every replica.
const SWEPT_SUFFIX_BOUNDARY_LEAD_MS: u64 = 2_000;

/// A halted shard's fresh committee commits the blocks above the
/// recovery's frontier as the halted committee built them, a block whose
/// sweep removed a cell included.
///
/// A transfer commits on the halting shard and leaves its committed cell
/// there, expiring a bucket short of a boundary the scenario picks in
/// the middle of an epoch. The first block anchored past that boundary
/// sweeps the cell, and the shard is frozen once it has, before another
/// epoch boundary is crossed: the sweeping block sits above the frontier
/// the beacon last attested, in the suffix every fresh member commits on
/// the halted committee's certificates. By then each of them has folded
/// the recovery, under which a block proposed at that anchor would only
/// coast and sweep nothing; the certified block swept, and a replica
/// that commits it any other way lands on its parent's root and stops.
///
/// Requires [`halt_straddler_setup`] at genesis and two committees' worth
/// of pool surplus, as [`halted_shard_recovers_by_committee_redraw`]
/// does.
///
/// [`halt_straddler_setup`]: crate::tx::halt_straddler_setup
///
/// # Panics
///
/// Panics if the transfer's cell is never written or never swept, the
/// sweeping block is not above the recovery's frontier, no fresh member
/// commits through the sweeping block before the shard resumes, the
/// halt or its recovery misses a lifecycle budget, or the recovered
/// shard's replicas never agree on a state root.
pub fn halted_shard_recovery_replays_a_sweep_its_suffix_walked<C: FaultableCluster>(c: &mut C) {
    let (halted, survivor) = ShardId::ROOT.children();
    let setup = halt_straddler_setup();
    split_lifecycle(c);

    let epoch_ms = epoch_duration_ms(c).expect("the beacon carries its epoch length");
    let windows = epoch_windows(c).expect("the beacon carries its epoch grid");
    let now_ms = |c: &C| clock(c).as_millis();
    let until = |c: &C, at_ms: u64| {
        let away = at_ms.saturating_sub(now_ms(c)) / epoch_ms + 2;
        epochs(u32::try_from(away).expect("a wait of a few epochs"))
    };
    // The first bucket boundary a transfer still valid now can expire a
    // bucket short of, sitting in the middle third of its epoch: the
    // epoch boundary before it is attested well below the sweeping
    // block, and the one after it is not reached before the freeze.
    let earliest = now_ms(c) + SWEPT_SUFFIX_VALIDITY_LEFT_MS + COMMITTED_GRACE_MS + SWEEP_BUCKET_MS;
    let boundary = (earliest / SWEEP_BUCKET_MS + 1..)
        .take(64)
        .map(|bucket| bucket * SWEEP_BUCKET_MS)
        .find(|at| (epoch_ms / 3..2 * epoch_ms / 3).contains(&into_epoch_ms(windows, *at)))
        .expect("a bucket boundary falls mid-epoch within a few buckets");
    let validity_end = boundary - SWEEP_BUCKET_MS / 2 - COMMITTED_GRACE_MS;

    c.run_until(until(c, validity_end), |c| {
        now_ms(c) + SWEPT_SUFFIX_VALIDITY_LEFT_MS >= validity_end
    });
    let (key, from, _, to) = &setup.straddlers[HALT_STRADDLER_BATCH - 1];
    assert_eq!(
        account_shard(*from, 2),
        halted,
        "the transfer must pay from the halting shard, which commits it",
    );
    let validity = TimestampRange::new(
        validity_around(c.now()).start_timestamp_inclusive,
        WeightedTimestamp::from_millis(validity_end),
    );
    let tx = Arc::new(build_transfer_tx(
        key,
        *from,
        *to,
        STRADDLER_PAYMENT,
        validity,
    ));
    let cell = committed_tx_cell_key(halted, tx.hash(), validity.end_timestamp_exclusive);
    c.submit(tx);
    let held = |c: &C| c.substate(halted, cell.owner, cell.local.0).is_some();
    assert!(
        c.run_until(epochs(3), held),
        "the halting shard must commit the transfer and write its committed cell",
    );

    c.run_until(until(c, boundary), |c| {
        now_ms(c) + SWEPT_SUFFIX_BOUNDARY_LEAD_MS >= boundary
    });
    assert!(held(c), "the cell must stand until its bucket has passed");
    let held_through = c
        .committed_height(halted)
        .expect("the halting shard serves");
    assert!(
        c.run_until(epochs(1), |c| !held(c)),
        "the first block anchored past the boundary must sweep the cell",
    );

    let halt = freeze_shard(c, halted, survivor, |_| {});
    let seated_at = await_recovery_draw(c, &halt);
    let frontier = c
        .beacon_state()
        .and_then(|state| {
            state
                .pending_recoveries
                .get(&halted)
                .map(|recovery| recovery.attested_frontier)
        })
        .expect("the pending recovery names its attested frontier");
    assert!(
        frontier <= held_through,
        "the block that swept the cell must sit above the recovery's frontier, \
         in the suffix the fresh committee commits on certificates: frontier \
         {frontier:?}, cell held through {held_through:?}",
    );
    // Nothing has seated the draw yet, so what each host holds of the
    // shard now is what it held before the fresh committee began.
    let before_seating: Vec<Option<BlockHeight>> = (0..c.host_count())
        .map(|host| c.host_committed_height(host, halted))
        .collect();
    assert!(
        await_height(c, halted, halt.frozen_at + 3, epochs(40)),
        "the recovered shard must resume committing under its fresh committee \
         (frozen at {})",
        halt.frozen_at,
    );
    // The shard's first blocks under the fresh committee need a quorum
    // of it at the halted tip, and no boundary above the recovery's
    // frontier is attested for a member to import state at until one of
    // those blocks crosses it. A member that stood at or below the last
    // height the cell was held at, and stands above it now, got there
    // through the sweeping block.
    let through_the_sweep = c
        .committee_hosts(halted)
        .into_iter()
        .filter(|&host| {
            before_seating[host].is_none_or(|height| height <= held_through)
                && c.host_committed_height(host, halted)
                    .is_some_and(|height| height > held_through)
        })
        .count();
    assert!(
        through_the_sweep > 0,
        "a fresh member must have committed the sweeping block on its certificate: \
         before seating {before_seating:?}, cell held through {held_through:?}",
    );
    await_recovery_resume(c, &halt, seated_at);
    assert!(
        c.run_until(epochs(4), |c| agreed_state_root(c, halted).is_some()),
        "the recovered shard's replicas must agree on one state root",
    );
}

/// The opening part of an epoch, as a share of it in eighths, the
/// answered-suffix scenario waits past before it submits: past the
/// epoch's boundary block on the halting shard, so what the transfers
/// write lands above it.
const ANSWERED_SUFFIX_OPENING_EIGHTHS: u64 = 1;

/// The part of an epoch, in eighths, the answered-suffix scenario's
/// answers must land inside, so the shard freezes before the epoch's
/// next boundary is committed.
const ANSWERED_SUFFIX_CLOSING_EIGHTHS: u64 = 6;

/// A halted shard's recovery completes where the suffix its fresh
/// committee commits on the halted committee's certificates carries
/// answers, with the cap on standing answers armed throughout.
///
/// Every transfer [`halt_straddler_setup`] pays from the surviving shard
/// into the halting one is submitted early in an epoch. The halting
/// shard credits each off the survivor's record, writing its answer,
/// and freezes before the epoch's next boundary: the blocks writing the
/// answers sit above the frontier the beacon last attested, in the
/// suffix. A fresh member commits that suffix as certified, never
/// judging the cap on it, and the first block it builds on it stands in
/// the recovery's suffix band, where the cap is out of play; every
/// later block is judged against the count the suffix left. The
/// recovered shard resumes, its replicas agree on one state root, each
/// transfer is credited once, a transfer each way settles after the
/// recovery, the world settles, and every answer ends.
///
/// The closing check on the recovered shard's count is a smoke check
/// only. A handful of answers never nears a cap, and the band's
/// exemption is not what lets this recovery through: a fresh member
/// holds no count until a persist of a block it committed itself
/// re-bases one, so its leaders build blocks that add nothing. Biting
/// on the band needs a fresh leader holding a count over voters that
/// hold none, which no harness seam arranges; the band's rule is the
/// coordinator's `a_block_with_its_parent_in_a_suffix_band_is_not_capped`.
///
/// Requires [`halt_straddler_setup`] at genesis and two committees'
/// worth of pool surplus, as [`halted_shard_recovers_by_committee_redraw`]
/// does.
///
/// [`halt_straddler_setup`]: crate::tx::halt_straddler_setup
///
/// # Panics
///
/// Panics if no answer lands on the halting shard inside the epoch the
/// transfers were submitted in, the blocks writing them are not above
/// the recovery's frontier, the halt or its recovery misses a lifecycle
/// budget, the recovered shard's replicas never agree on a state root,
/// a transfer is not credited exactly once, a post-recovery transfer
/// fails to settle, the world does not settle, an answer outlives its
/// budget, or the standing count of the recovered shard passes a cap.
pub fn a_halt_recovery_with_answers_in_its_suffix_completes<C: FaultableCluster>(c: &mut C) {
    let (halted, survivor) = ShardId::ROOT.children();
    let setup = halt_straddler_setup();
    split_lifecycle(c);
    let world = World::open(
        c,
        *PROTOCOL_RESOURCE,
        setup
            .straddlers
            .iter()
            .chain(&setup.post_recovery)
            .flat_map(|(_, from, _, to)| [from.address(), to.address()]),
        [],
    );
    let mut charges = Charges::default();

    let (probes, unanswered) = answer_early_in_an_epoch(c, &setup, &mut charges);

    let halt = freeze_shard(c, halted, survivor, |_| {});
    let seated_at = await_recovery_draw(c, &halt);
    let frontier = c
        .beacon_state()
        .and_then(|state| {
            state
                .pending_recoveries
                .get(&halted)
                .map(|recovery| recovery.attested_frontier)
        })
        .expect("the pending recovery names its attested frontier");
    assert!(
        frontier <= unanswered,
        "the blocks writing the answers must sit above the recovery's frontier, in the \
         suffix the fresh committee commits on certificates: frontier {frontier:?}, \
         no answer through {unanswered:?}",
    );
    await_recovery_resume(c, &halt, seated_at);
    assert!(
        c.run_until(epochs(4), |c| agreed_state_root(c, halted).is_some()),
        "the recovered shard's replicas must agree on one state root",
    );
    assert!(
        c.run_until(epochs(20), |c| {
            probes
                .iter()
                .all(|p| chain_settled(c, p.payer_shard, p.hash) && credited_once(c, p))
        }),
        "every transfer into the halted shard must settle and credit its recipient once",
    );

    let revived: Vec<Probe> = setup
        .post_recovery
        .iter()
        .map(|leg| submit_probe(c, &mut charges, leg))
        .collect();
    assert!(
        c.run_until(epochs(40), |c| {
            revived
                .iter()
                .all(|p| chain_settled(c, p.payer_shard, p.hash) && credited_once(c, p))
        }),
        "a post-recovery transfer per direction must settle and credit its recipient once; {}",
        revival_report(c, halted, survivor, &revived),
    );
    world.assert_settles_within(c, &charges, epochs(8), "a recovery over answers");
    await_crossings_end(
        c,
        &charges.crossings(c),
        epochs(12),
        "every answer ends after the recovery",
    );
    let standing = c
        .standing_answers(halted)
        .expect("the harness reads the recovered shard's standing answers");
    assert!(
        standing.total() <= MAX_STANDING_ANSWERS
            && standing
                .per_lineage(&ShardTrie::uniform_from_count(2))
                .values()
                .all(|count| *count <= MAX_STANDING_ANSWERS_FROM_SHARD),
        "the recovered shard stands within the caps: {standing:?}",
    );
}

/// Submit every transfer `setup` pays from the surviving shard into the
/// halting one past the next epoch's opening, and run until the first
/// lands, inside that epoch. Returns the transfers, and the halting
/// shard's tip read last before any credit stood: a credit lands in the
/// block that writes its transfer's answer, so every block writing one
/// sits above it.
fn answer_early_in_an_epoch<C: FaultableCluster>(
    c: &mut C,
    setup: &HaltStraddlerSetup,
    charges: &mut Charges,
) -> (Vec<Probe>, BlockHeight) {
    let (halted, survivor) = ShardId::ROOT.children();
    let epoch_ms = epoch_duration_ms(c).expect("the beacon carries its epoch length");
    let windows = epoch_windows(c).expect("the beacon carries its epoch grid");
    let now_ms = |c: &C| clock(c).as_millis();
    let opening = epoch_ms * ANSWERED_SUFFIX_OPENING_EIGHTHS / 8;
    let next_start = windows
        .window_of(windows.epoch_for(clock(c)).next())
        .start
        .as_millis()
        + opening;
    assert!(
        c.run_until(epochs(2), |c| now_ms(c) >= next_start),
        "the cluster's clock must reach the next epoch's opening",
    );
    let epoch_of_submission = windows.epoch_for(clock(c));

    let height = |c: &C| c.committed_height(halted).unwrap_or(BlockHeight::GENESIS);
    let probes: Vec<Probe> = setup
        .straddlers
        .iter()
        .filter(|(_, from, _, _)| account_shard(*from, 2) == survivor)
        .map(|leg| submit_probe(c, charges, leg))
        .collect();
    let credited = |c: &C| probes.iter().any(|p| credited_once(c, p));
    let mut unanswered = height(c);
    while !credited(c) {
        unanswered = height(c);
        assert!(
            c.run_until(epochs(1), |c| height(c) > unanswered),
            "the halting shard must keep committing while the transfers land",
        );
    }
    let closing = epoch_ms * ANSWERED_SUFFIX_CLOSING_EIGHTHS / 8;
    assert!(
        windows.epoch_for(clock(c)) == epoch_of_submission
            && into_epoch_ms(windows, now_ms(c)) < closing,
        "the answers must stand inside the epoch the transfers were submitted in, \
         before its next boundary: submitted in epoch {epoch_of_submission:?}, at {}ms now",
        now_ms(c),
    );
    assert!(
        c.standing_answers(halted)
            .expect("the harness reads the halting shard's standing answers")
            .total()
            > 0,
        "the credited transfers' answers must stand on the halting shard",
    );

    (probes, unanswered)
}

/// Routes the capped-sibling scenario offers toward the halted venue:
/// the cap, and more than a block of them still pooled once it is
/// reached.
const CAPPED_SIBLING_LOAD: usize = MAX_STANDING_TOWARD_SHARD + MAX_TXS_PER_BLOCK + 64;

/// Transfers the capped-sibling scenario settles on the survivor while
/// its sibling's traffic stands at the cap.
const CAPPED_SIBLING_CONTROLS: u128 = 4;

/// A halted sibling pins no more of a shard's drain than the cap on rows
/// standing toward one shard, and the shard's other intake carries on
/// beside it.
///
/// Two venues stand on two shards and the second venue's shard freezes
/// as in [`halted_shard_recovers_by_committee_redraw`]. The traders then
/// offer routes through both: a route's core spans the venues' shards,
/// so its member on the first venue's shard awaits the frozen one and
/// stands, with no sibling to answer it, until its own deadline. The
/// first venue's shard commits them until
/// [`MAX_STANDING_TOWARD_SHARD`] stand and commits no more toward its
/// sibling while they do, however many are pooled. Transfers local to
/// it, submitted while the count sits at the cap behind a pool still
/// holding more than a block of refused routes, settle.
///
/// Requires the route scenarios' grown four-shard cluster and genesis
/// accounts.
///
/// # Panics
///
/// Panics if either venue misses its budget standing up, a route's
/// member on the survivor awaits anything but the halted shard, the rows
/// standing toward it never reach the cap or ever pass it, fewer than a
/// block of routes are still pooled at the cap, or a local transfer
/// fails to settle beside them.
pub fn a_halted_siblings_traffic_stops_at_the_cap_while_other_intake_continues<
    C: FaultableCluster,
>(
    c: &mut C,
) {
    let (survivor, halted) = (FIRST_VENUE_SHARD, SECOND_VENUE_SHARD);
    let mut taken = Vec::new();
    let (first, second) = stand_up_venues(c, &mut taken);
    let traders = traders(&mut taken);
    let (_, control_to) = sponsor(&mut taken);
    let (control_key, control_from) = grind_onto(survivor, &mut Vec::new());
    let halt = freeze_shard(c, halted, survivor, |_| {});

    let window = validity_around(c.now());
    let trie = ShardTrie::uniform_from_count(4);
    let mut offered: BTreeSet<TxHash> = BTreeSet::new();
    for nth in 0..CAPPED_SIBLING_LOAD {
        let (key, trader) = &traders[nth % traders.len()];
        let route = build_route_tx(
            key,
            *trader,
            (&first.meta, &second.meta),
            *PROTOCOL_RESOURCE,
            1 + u128::try_from(nth).expect("a count of routes"),
            0,
            window,
        );
        if nth == 0 {
            c.with_derivation(|derivation| route.try_derived(derivation))
                .expect("a scenario route derives");
            assert_eq!(
                awaited_core(&member_of(&route, &trie, survivor))[..],
                [halted],
                "a route's member on the survivor must await the halted shard",
            );
        }
        offered.insert(route.hash());
        c.submit(Arc::new(route));
    }

    let height = |c: &C| c.committed_height(survivor).map_or(0, BlockHeight::inner);
    let mut peak = 0;
    let mut blocks_at_cap = 0;
    let mut committed: BTreeSet<TxHash> = BTreeSet::new();
    while blocks_at_cap < 3 {
        let from = height(c);
        assert!(
            c.run_until(epochs(1), |c| height(c) > from),
            "the survivor must keep committing beside its halted sibling",
        );
        let standing = standing_of(c, survivor, &offered);
        assert!(
            standing.len() <= MAX_STANDING_TOWARD_SHARD,
            "{} rows stand toward {halted:?}, past the cap",
            standing.len(),
        );
        peak = peak.max(standing.len());
        if standing.len() == MAX_STANDING_TOWARD_SHARD {
            blocks_at_cap += 1;
        }
        committed.extend(standing);
        assert!(
            window.contains(WeightedTimestamp::ZERO.plus(c.now())),
            "the routes' window closed with {peak} standing toward {halted:?}",
        );
    }
    let pooled = offered.len() - committed.len();
    assert!(
        pooled > MAX_TXS_PER_BLOCK,
        "more than a block of routes must still be pooled at the cap; {pooled} are",
    );

    for nth in 0..CAPPED_SIBLING_CONTROLS {
        let control = build_transfer_tx(
            &control_key,
            control_from,
            control_to,
            100 + nth,
            validity_around(c.now()),
        );
        let hash = control.hash();
        c.submit(Arc::new(control));
        let status = await_tx_terminal(c, hash, epochs(2));
        assert!(
            matches!(
                status,
                Some(TransactionStatus::Completed(TransactionDecision::Accept))
            ),
            "local transfer {nth} must settle beside the capped sibling; status = {status:?}",
        );
        let standing = standing_of(c, survivor, &offered).len();
        assert!(
            standing <= MAX_STANDING_TOWARD_SHARD,
            "{standing} rows stand toward {halted:?}, past the cap",
        );
    }
    assert_eq!(peak, MAX_STANDING_TOWARD_SHARD);
    let frozen = c.committed_height(halted).map_or(0, BlockHeight::inner);
    assert!(
        frozen <= halt.frozen_at + 2,
        "the sibling must stay halted through the run: {frozen} past {}",
        halt.frozen_at,
    );
}

/// The crossings a silent sibling's rows may owe toward it on one
/// consumer before one more row is refused: a quarter of everything the
/// consumer may stand holding. The row admitted last may carry them up
/// to one transaction's crossings past it.
const SILENT_SIBLING_SHARE: u64 = MAX_STANDING_ANSWERS / 4;

/// A silent sibling holds at most a quarter of what its consumer may
/// stand holding, and its consumer's intake toward it lifts once it is
/// recovered.
///
/// As in [`a_halted_siblings_traffic_stops_at_the_cap_while_other_intake_continues`],
/// the second venue's shard freezes and the traders offer more routes
/// through both venues than may stand toward it. At every block the
/// survivor commits, the rows standing toward the frozen shard and the
/// crossings they owe stay within [`MAX_STANDING_TOWARD_SHARD`] and a
/// quarter of [`MAX_STANDING_ANSWERS`] plus one transaction's
/// crossings, and what the survivor stands holding, answers and owed
/// crossings, stays within the cap on each lineage and in total.
///
/// The row cap is what closes intake here: a route row owes far fewer
/// than the 22 crossings a row would need for the quarter to bind
/// before [`MAX_STANDING_TOWARD_SHARD`] rows do, and no builder makes a
/// transaction owing that many. The quarter is asserted at every block
/// and is not what closes intake; the dimension itself is covered by
/// the intake unit tests.
///
/// Once intake toward the sibling has stood closed for three blocks
/// with more than a block of routes still pooled, local transfers on
/// the survivor settle beside it. The frozen shard is then recovered,
/// and a fresh route through both venues commits on the survivor and
/// settles.
///
/// Requires the route scenarios' grown four-shard cluster and genesis
/// accounts, with a committee's worth of pool surplus beyond the grow
/// cohort for the recovery.
///
/// # Panics
///
/// Panics if either venue misses its budget standing up, a bound above
/// is passed at any block, intake toward the sibling never closes,
/// fewer than a block of routes are still pooled once it has, a local
/// transfer fails to settle beside it, the halt or its recovery misses a
/// lifecycle budget, or the route offered after the recovery does not
/// settle as an accept.
pub fn a_silent_sibling_holds_no_more_than_a_quarter<C: FaultableCluster>(c: &mut C) {
    let (survivor, halted) = (FIRST_VENUE_SHARD, SECOND_VENUE_SHARD);
    let mut taken = Vec::new();
    let (first, second) = stand_up_venues(c, &mut taken);
    let traders = traders(&mut taken);
    let (_, control_to) = sponsor(&mut taken);
    let (control_key, control_from) = grind_onto(survivor, &mut Vec::new());
    let halt = freeze_shard(c, halted, survivor, |_| {});

    let window = validity_around(c.now());
    let mut offered: BTreeSet<TxHash> = BTreeSet::new();
    for nth in 0..CAPPED_SIBLING_LOAD {
        let (key, trader) = &traders[nth % traders.len()];
        let route = build_route_tx(
            key,
            *trader,
            (&first.meta, &second.meta),
            *PROTOCOL_RESOURCE,
            1 + u128::try_from(nth).expect("a count of routes"),
            0,
            window,
        );
        offered.insert(route.hash());
        c.submit(Arc::new(route));
    }

    let height = |c: &C| c.committed_height(survivor).map_or(0, BlockHeight::inner);
    let mut blocks_closed = 0;
    let mut committed: BTreeSet<TxHash> = BTreeSet::new();
    while blocks_closed < 3 {
        let from = height(c);
        assert!(
            c.run_until(epochs(1), |c| height(c) > from),
            "the survivor must keep committing beside its silent sibling",
        );
        if silent_sibling_within_its_share(c, survivor, halted) {
            blocks_closed += 1;
        }
        committed.extend(standing_of(c, survivor, &offered));
        assert!(
            window.contains(WeightedTimestamp::ZERO.plus(c.now())),
            "the routes' window closed before intake toward {halted:?} closed",
        );
    }
    let pooled = offered.len() - committed.len();
    assert!(
        pooled > MAX_TXS_PER_BLOCK,
        "more than a block of routes must still be pooled once intake closes; {pooled} are",
    );

    for nth in 0..CAPPED_SIBLING_CONTROLS {
        let control = build_transfer_tx(
            &control_key,
            control_from,
            control_to,
            100 + nth,
            validity_around(c.now()),
        );
        let hash = control.hash();
        c.submit(Arc::new(control));
        let status = await_tx_terminal(c, hash, epochs(2));
        assert!(
            matches!(
                status,
                Some(TransactionStatus::Completed(TransactionDecision::Accept))
            ),
            "local transfer {nth} must settle beside the silent sibling; status = {status:?}",
        );
        silent_sibling_within_its_share(c, survivor, halted);
    }

    await_halt_recovery(c, &halt);
    silent_sibling_within_its_share(c, survivor, halted);
    let (key, trader) = &traders[0];
    let fresh = build_route_tx(
        key,
        *trader,
        (&first.meta, &second.meta),
        *PROTOCOL_RESOURCE,
        u128::try_from(CAPPED_SIBLING_LOAD + 1).expect("a count of routes"),
        0,
        validity_around(c.now()),
    );
    let hash = fresh.hash();
    c.submit(Arc::new(fresh));
    let status = await_tx_terminal(c, hash, epochs(8));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "a route toward the recovered sibling must settle once its intake lifts; \
         status = {status:?}",
    );
}

/// Assert that the rows `survivor` holds toward `silent` stand within
/// their caps, that their owed crossings stand under a quarter of
/// [`MAX_STANDING_ANSWERS`] plus one transaction's crossings, and that `survivor` stands within the cap
/// on its answers and owed crossings, on every lineage and in total.
/// Returns whether intake toward `silent` stands closed: the rows at
/// their cap, or the owed crossings within one transaction's of their
/// share.
fn silent_sibling_within_its_share<C: Cluster>(c: &C, survivor: ShardId, silent: ShardId) -> bool {
    let toward = c
        .standing_toward(survivor)
        .expect("the harness reads the survivor's rows");
    let (rows, owed) = (toward.toward(silent), toward.owed_toward(silent));
    assert!(
        rows <= MAX_STANDING_TOWARD_SHARD,
        "{rows} rows stand toward {silent:?}, past the cap",
    );
    let crossings = u64::try_from(MAX_CROSSINGS_PER_TX).expect("a crossing count");
    assert!(
        owed < SILENT_SIBLING_SHARE + crossings,
        "rows toward {silent:?} owe {owed} crossings, past a quarter of the total and a \
         transaction's crossings",
    );
    let standing = c
        .standing_answers(survivor)
        .expect("the harness reads the survivor's standing answers");
    assert!(
        standing.total() <= MAX_STANDING_ANSWERS,
        "the survivor stands {}, past the total cap",
        standing.total(),
    );
    for (lineage, count) in standing.per_lineage(&ShardTrie::uniform_from_count(4)) {
        assert!(
            count <= MAX_STANDING_ANSWERS_FROM_SHARD,
            "the survivor stands {count} toward lineage {lineage:?}, past its cap",
        );
    }
    rows == MAX_STANDING_TOWARD_SHARD || owed + crossings > SILENT_SIBLING_SHARE
}

/// The transactions of `offered` whose row `shard` holds and no abort
/// has let go of: the ones still standing toward whatever they await.
fn standing_of<C: Cluster>(c: &C, shard: ShardId, offered: &BTreeSet<TxHash>) -> BTreeSet<TxHash> {
    c.member_rows(shard)
        .expect("the harness reads the shard's member rows")
        .into_iter()
        .filter(|(tx, state)| {
            offered.contains(tx)
                && !matches!(
                    state,
                    RowState::InFlight {
                        joins: Joins::Aborted,
                        ..
                    }
                )
        })
        .map(|(tx, _)| tx)
        .collect()
}

/// Cross-shard ticks stay atomic across a shard halt and its
/// committee-redraw recovery.
///
/// The grown left child freezes exactly as in
/// [`halted_shard_recovers_by_committee_redraw`], but with cross-child
/// transfers in flight at every phase of the cut: a settling batch
/// settled and credited before any fault installs, a racing batch
/// submitted at the freeze edge — the last instant with any chance to
/// commit on the halting shard — and a doomed batch submitted against the
/// frozen shard. A transfer settles on its payer's chain alone and is
/// credited by the recipient's commit fold off the record's reading, so
/// the surviving sibling accepts every transfer it pays for during the
/// halt, never waiting on the dead counterparty; a probe whose payer is
/// the dead shard commits nowhere. What the survivor accepted into the
/// frozen shard is owed, and after the recovery the survivor's pushes of
/// the standing records reach the fresh committee, which credits each
/// once. Once the recovery record clears, a fresh transfer per direction
/// must settle and credit — the recovered shard's cross-shard rail serves
/// again. Every record and answer the run wrote then ends, the recovered
/// shard's `Taken`s on reading their records absent at the survivor.
/// Reports the fenced claims and claims weight the run carried.
///
/// Requires [`halt_straddler_setup`] at genesis and two committees' worth
/// of pool surplus.
///
/// [`halt_straddler_setup`]: crate::tx::halt_straddler_setup
///
/// # Panics
///
/// Panics if the halt or recovery misses a lifecycle budget, a redrawn
/// committee rather than the first one completes the recovery, an
/// in-flight tick hangs, a recipient is credited other than once for an
/// accepted transfer, a crossing the survivor accepted is not credited
/// after the recovery, the post-recovery transfers fail to settle, or a
/// record or answer outlives the settled world.
pub fn halted_shard_straddler_atomic(c: &mut impl FaultableCluster) {
    let (halted, survivor) = ShardId::ROOT.children();
    let setup = halt_straddler_setup();
    split_lifecycle(c);

    // Every account a probe pays from or delivers to, in every batch and
    // after the recovery. The ballast holds the band and never spends.
    let world = World::open(
        c,
        *PROTOCOL_RESOURCE,
        setup
            .straddlers
            .iter()
            .chain(&setup.post_recovery)
            .flat_map(|(_, from, _, to)| [from.address(), to.address()]),
        [],
    );
    let mut charges = Charges::default();
    let mut probes: Vec<Probe> = Vec::new();

    // Settling batch: settled on its payer's chain and credited to its
    // recipient before any fault installs.
    for leg in &setup.straddlers[..HALT_STRADDLER_BATCH] {
        probes.push(submit_probe(c, &mut charges, leg));
    }
    assert!(
        c.run_until(epochs(12), |c| {
            probes
                .iter()
                .all(|p| chain_settled(c, p.payer_shard, p.hash) && credited_once(c, p))
        }),
        "the settling batch must settle and credit before the halt",
    );

    // Racing batch: submitted at the freeze edge, inside the staged cut —
    // the shard commits at most a couple more heights, so each probe
    // either squeezes through or is left in flight when it freezes. No
    // per-batch assertion; each lands in whichever bucket it raced into.
    let halt = freeze_shard(c, halted, survivor, |c| {
        for leg in &setup.straddlers[HALT_STRADDLER_BATCH..2 * HALT_STRADDLER_BATCH] {
            probes.push(submit_probe(c, &mut charges, leg));
        }
    });

    // Doomed batch: submitted against the frozen shard. A survivor-paid
    // probe still settles on the survivor — its payer's chain answers
    // alone — but its credit waits for the frozen shard to read the
    // record; a halted-paid probe never commits anywhere.
    for leg in &setup.straddlers[2 * HALT_STRADDLER_BATCH..] {
        probes.push(submit_probe(c, &mut charges, leg));
    }

    // The survivor's verdict waits on no one: a probe it pays for accepts
    // during the halt, well inside the detection window, and its credit
    // on the frozen shard does not land. A probe the *halted* shard pays
    // for is the opposite case and costs the survivor nothing: a frozen
    // shard commits nothing, so there is no record to read. There is
    // nothing to wait on, which is why these are not waited on — doing so
    // would spend the halt's own detection window on probes that were
    // never going to answer.
    let mut engaged = 0u32;
    for probe in &probes[HALT_STRADDLER_BATCH..] {
        if probe.payer_shard != survivor {
            assert!(
                c.chain_fate(survivor, probe.hash).0.is_none(),
                "the survivor engaged a probe whose payer shard is frozen",
            );
            continue;
        }
        engaged += 1;
        let status = await_tx_terminal(c, probe.hash, epochs(6));
        assert!(
            matches!(
                status,
                Some(TransactionStatus::Completed(TransactionDecision::Accept))
            ),
            "a survivor-paid probe must accept on its payer's chain during the halt; \
             status = {status:?}",
        );
    }
    assert!(
        engaged > 0,
        "no in-flight probe was paid for by the survivor — the probe batches \
         no longer exercise its verdict clock",
    );
    for probe in &probes[2 * HALT_STRADDLER_BATCH..] {
        if probe.payer_shard == survivor {
            assert!(
                !credited_once(c, probe),
                "a credit landed on the frozen shard",
            );
        }
    }

    // The frozen chain's record is canonical for pre-halt heights: the
    // recovery bridges over the QC-attested tip, so nothing recorded here
    // is orphaned, while a fresh member's synced view may not reach below
    // its snap anchor.
    let at_freeze: Vec<_> = probes
        .iter()
        .map(|p| c.chain_fate(halted, p.hash))
        .collect();

    await_halt_recovery(c, &halt);

    assert_credits_agree(c, halted, survivor, &probes, &at_freeze);

    // The recovered shard's cross-shard rail serves again: a fresh
    // transfer per direction settles on its payer's chain and credits its
    // recipient once. The budget is generous — a ceiling, not the
    // expected latency: the fresh committee is establishing cross-shard
    // connectivity from a cold start right after the recovery record
    // cleared, which on a real-network harness takes longer than a
    // steady-state cross-shard settlement round.
    let revived: Vec<Probe> = setup
        .post_recovery
        .iter()
        .map(|leg| submit_probe(c, &mut charges, leg))
        .collect();
    assert!(
        c.run_until(epochs(40), |c| {
            revived
                .iter()
                .all(|p| chain_settled(c, p.payer_shard, p.hash) && credited_once(c, p))
        }),
        "a post-recovery transfer per direction must settle and credit its recipient once; {}",
        revival_report(c, halted, survivor, &revived),
    );

    world.assert_settles_within(c, &charges, epochs(8), "a halt and its recovery");

    // Every answer ends at the read frontier across the recovery: what
    // the survivor accepted into the frozen shard is credited by the
    // fresh committee, retired on the survivor off that `Taken`, and the
    // `Taken` deleted once the recovered shard reads the record absent.
    await_crossings_end(
        c,
        &charges.crossings(c),
        epochs(12),
        "every answer ends after the recovery",
    );
    report_crossing_measures(c, "halted_shard_straddler_atomic");
}

/// What each transaction of [`a_harvested_tick_over_a_discarded_tick_settles_nothing`]
/// moves.
const HARVESTED_PAYMENT: u128 = 100;

/// A tick the recovered shard harvests, run over a tick its recovery
/// discards, settles nothing there.
///
/// The halting shard's execution votes are cut among its own hosts, so
/// no tick of it certifies. Under the cut it commits `j`, a payment its
/// payer makes on the shard, and the beacon records a boundary above
/// `j`: the recovery's frontier will stand at or above it. It then
/// commits `K`, a transfer escrowed on the survivor into a deposit on
/// the halting shard whose fee the same payer pays, and names it in a
/// tick above `j`'s, so `K` runs over the vault `j` spent. The cut lifts
/// until both ticks certify, while the survivor is kept from reading the
/// halting shard's crossings, and every host serving the shard is capped
/// to serve no block above `K`'s tick, so the fresh committee harvests a
/// tip holding `K` in flight and the tail holding both finalizations is
/// lost unread. The shard then halts and recovers.
///
/// Past the crossing block no tick row stands on the recovered shard,
/// and every row the crossing released ends by its clock: `j` by its
/// abort, and `K`, a row its own shard settles alone, by its fate once
/// its leg entry window closes, which settles as an abort. The budget
/// for both is the epochs to that close and four more. The survivor's
/// escrow is never both delivered to the recipient and credited back to
/// its source, and the world settles.
///
/// Requires [`harvested_tick_setup`] at genesis and two committees'
/// worth of pool surplus.
///
/// [`harvested_tick_setup`]: crate::tx::harvested_tick_setup
///
/// # Panics
///
/// Panics if either transaction misses a budget to commit, the beacon
/// records no boundary above `j`, `K` is never named in a tick or no
/// longer stands in flight in it when the cut lifts, the ticks never
/// certify, the cap never refuses a block or the survivor never asks for
/// the tail, the recovery's frontier does not separate `j` from `K`'s
/// tick, the halt or its recovery misses a lifecycle budget, a tick row
/// stands past the crossing or a released row outlives its budget, `j`
/// or `K` settles other than as an abort, the escrow is both delivered
/// and credited back, or the world does not settle.
pub fn a_harvested_tick_over_a_discarded_tick_settles_nothing<C: FaultableCluster>(c: &mut C) {
    let (halted, survivor) = ShardId::ROOT.children();
    let setup = harvested_tick_setup();
    split_lifecycle(c);
    let (_, payer) = &setup.payer;
    let (_, source) = &setup.source;
    let world = World::open(
        c,
        *PROTOCOL_RESOURCE,
        [*payer, setup.beneficiary, *source, setup.recipient].map(PrincipalAddr::address),
        [],
    );
    let mut charges = Charges::default();

    let hosts = c.committee_hosts(halted);
    let UncertifiedTicks {
        j,
        j_at,
        k,
        k_at,
        k_lapse,
    } = commit_over_uncertified_ticks(c, halted, &setup, &mut charges, &hosts);

    // Nothing certifies under the cut, so `K` stands in flight in every
    // block from its tick up: the tip the cap leaves the harvest holds it.
    assert!(
        tick_of(c, halted, k) == Some(k_at),
        "the transfer must stand in flight in its tick at {k_at:?} as the cut lifts: {:?}",
        c.member_rows(halted).and_then(|rows| rows.get(&k).copied()),
    );

    // Both ticks certify once the votes flow, and their finalizations
    // land above `K`'s tick, in the tail the cap keeps from the harvest.
    // The survivor reads none of that tail: a counterpart that read it
    // before the recovery discarded it is torn, which is the recovery's
    // stated residual and not what this asserts.
    c.clear_drops();
    let tail_unread = isolate_crossing_intake(c, survivor, halted);
    let in_flight = |c: &C, tx: TxHash| tick_of(c, halted, tx).is_some();
    assert!(
        c.run_until(epochs(2), |c| !in_flight(c, j) && !in_flight(c, k)),
        "both ticks must certify once the votes flow",
    );
    let cap = c.cap_block_serving(halted, k_at);
    let halt = freeze_shard(c, halted, survivor, |_| {});
    await_halt_recovery(c, &halt);
    assert!(
        cap.fired() > 0,
        "the harvest must have been refused a block above {k_at:?}",
    );
    assert!(
        tail_unread.fired() > 0,
        "the survivor must actually have been kept from reading the tail",
    );
    c.clear_drops();

    let frontier = c
        .beacon_state()
        .and_then(|state| state.latest_completed_recovery(halted))
        .expect("a cleared recovery leaves its completed record")
        .attested_frontier;
    assert!(
        j_at <= frontier && frontier < k_at,
        "the recovery's frontier {frontier:?} must stand at or above the payer's payment \
         at {j_at:?} and below the transfer's tick at {k_at:?}",
    );

    assert_discarded_ticks_end(c, halted, k_at, k_lapse, j, k);

    let delivered_and_returned = |c: &C| {
        vault_balance(c, halted, setup.recipient) == 10 + HARVESTED_PAYMENT
            && vault_balance(c, survivor, *source) == 10_000
    };
    assert!(
        !delivered_and_returned(c),
        "the escrow is both delivered and credited back",
    );
    world.assert_settles_within(
        c,
        &charges,
        epochs(8),
        "a harvested tick over a discarded tick",
    );
    assert!(
        !delivered_and_returned(c),
        "the escrow is both delivered and credited back",
    );
}

/// A survivor that read a tail its counterpart's recovery discards keeps
/// the escrow it holds there, and gets it back once the recovered chain
/// refuses the transfer.
///
/// [`a_harvested_tick_over_a_discarded_tick_settles_nothing`] without the
/// survivor's crossing intake cut: the tail holding `K`'s finalization
/// commits before the halt, and the survivor reads `K`'s `Taken` there
/// fresh, off a chain above the halting shard's last recorded boundary.
/// It retires nothing on that reading, so its escrow record stands. The
/// recovered shard settles `K` as an abort and declines the record, and
/// the survivor reads the `Never` at a boundary of the recovered shard
/// and credits the escrow back to its source.
///
/// # Panics
///
/// As that scenario, but for the survivor's cut, and if the source is
/// not credited back.
pub fn a_survivor_that_read_a_discarded_tail_gets_its_escrow_back<C: FaultableCluster>(c: &mut C) {
    let (halted, survivor) = ShardId::ROOT.children();
    let setup = harvested_tick_setup();
    split_lifecycle(c);
    let (_, payer) = &setup.payer;
    let (_, source) = &setup.source;
    let world = World::open(
        c,
        *PROTOCOL_RESOURCE,
        [*payer, setup.beneficiary, *source, setup.recipient].map(PrincipalAddr::address),
        [],
    );
    let mut charges = Charges::default();

    let hosts = c.committee_hosts(halted);
    let UncertifiedTicks {
        j,
        j_at,
        k,
        k_at,
        k_lapse,
    } = commit_over_uncertified_ticks(c, halted, &setup, &mut charges, &hosts);

    // Both ticks certify once the votes flow, and their finalizations
    // land above `K`'s tick, in the tail the cap keeps from the harvest.
    // The survivor reads that tail before the halt.
    c.clear_drops();
    let in_flight = |c: &C, tx: TxHash| tick_of(c, halted, tx).is_some();
    assert!(
        c.run_until(epochs(2), |c| !in_flight(c, j) && !in_flight(c, k)),
        "both ticks must certify once the votes flow",
    );
    let cap = c.cap_block_serving(halted, k_at);
    let halt = freeze_shard(c, halted, survivor, |_| {});
    await_halt_recovery(c, &halt);
    assert!(
        cap.fired() > 0,
        "the harvest must have been refused a block above {k_at:?}",
    );
    c.clear_drops();

    let frontier = c
        .beacon_state()
        .and_then(|state| state.latest_completed_recovery(halted))
        .expect("a cleared recovery leaves its completed record")
        .attested_frontier;
    assert!(
        j_at <= frontier && frontier < k_at,
        "the recovery's frontier {frontier:?} must stand at or above the payer's payment \
         at {j_at:?} and below the transfer's tick at {k_at:?}",
    );

    assert_discarded_ticks_end(c, halted, k_at, k_lapse, j, k);

    let delivered_and_returned = |c: &C| {
        vault_balance(c, halted, setup.recipient) == 10 + HARVESTED_PAYMENT
            && vault_balance(c, survivor, *source) == 10_000
    };
    assert!(
        !delivered_and_returned(c),
        "the escrow is both delivered and credited back",
    );
    assert!(
        c.run_until(epochs(8) + retirement_wait(c), |c| vault_balance(
            c, survivor, *source
        ) == 10_000),
        "the survivor's escrow for a transfer its counterpart's recovered chain aborted is \
         credited back to its source: source holds {}, recipient holds {}",
        vault_balance(c, survivor, *source),
        vault_balance(c, halted, setup.recipient),
    );
    world.assert_settles_within(
        c,
        &charges,
        epochs(8),
        "a survivor that read a discarded tail",
    );
    assert!(
        !delivered_and_returned(c),
        "the escrow is both delivered and credited back",
    );
}

/// A producer that read its consumer's `Taken` of a credit the
/// consumer's recovery discards delivers the credit again.
///
/// The survivor pays a transfer into the halting shard, an owed
/// crossing, just past a boundary the beacon recorded for the halting
/// shard. The halting shard's fold credits the recipient and writes the
/// `Taken`, and the survivor reads the `Taken`'s push, fresh, off a
/// chain above that boundary. Every host serving the halting shard is
/// capped to serve no block from the transfer's submission up, so the
/// fresh committee harvests a tip without the credit. The shard freezes
/// and recovers on that tip.
///
/// The survivor retired nothing on the fresh `Taken`, so its record
/// stands and is pushed again. The recovered shard's fold credits the
/// recipient once, on the record it reads with no `Taken` of the
/// transfer standing, and the survivor retires the record on the new
/// `Taken` read at a boundary of the recovered shard. The world settles.
///
/// Requires [`halt_straddler_setup`] at genesis and two committees'
/// worth of pool surplus.
///
/// # Panics
///
/// Panics if the transfer does not commit or credit before the halt, if
/// the cap never refuses a block, if the recovery's frontier is not
/// below the credit, if the recipient is not credited exactly once or
/// the record is not retired after the recovery, or if the world does
/// not settle.
pub fn a_producer_that_read_a_discarded_credit_delivers_it_again<C: FaultableCluster>(c: &mut C) {
    let (halted, survivor) = ShardId::ROOT.children();
    let HaltStraddlerSetup { straddlers, .. } = halt_straddler_setup();
    split_lifecycle(c);
    let Some((payer_key, payer, _, recipient)) = straddlers.into_iter().next() else {
        panic!("the setup grinds straddlers");
    };
    assert!(
        account_shard(payer.address(), 2) == survivor
            && account_shard(recipient.address(), 2) == halted,
        "the first straddler pays from the survivor into the halting shard",
    );
    let world = World::open(
        c,
        *PROTOCOL_RESOURCE,
        [payer, recipient].map(PrincipalAddr::address),
        [],
    );
    let mut charges = Charges::default();
    let recorded = |c: &C| {
        c.beacon_state().and_then(|state| {
            state
                .boundaries
                .get(&halted)
                .map(|boundary| boundary.height)
        })
    };

    // Just past a newly recorded boundary, so the credit lands above it
    // and the shard halts before the next.
    let before = recorded(c);
    assert!(
        c.run_until(epochs(2), |c| recorded(c) != before),
        "the beacon records a boundary of the halting shard",
    );
    let uncredited = c.committed_height(halted).expect("the halting shard runs");
    let tx = charges.submit(
        c,
        build_transfer_tx(
            &payer_key,
            payer,
            recipient,
            STRADDLER_PAYMENT,
            validity_around(c.now()),
        ),
    );
    let [record] = charges.records(c)[..] else {
        panic!("a transfer crosses once");
    };
    let credited = |c: &C| vault_balance(c, halted, recipient) == 10 + STRADDLER_PAYMENT;
    assert!(
        c.run_until(epochs(2), credited),
        "the halting shard's fold credits the recipient: {:?}",
        c.tx_status(tx),
    );
    let stands = |c: &C| c.substate(survivor, record.owner, record.local.0).is_some();
    let read_by = c.now() + Duration::from_secs(5);
    let _ = c.run_until(epochs(1), |c| c.now() >= read_by);

    let cap = c.cap_block_serving(halted, uncredited);
    let halt = freeze_shard(c, halted, survivor, |_| {});
    await_halt_recovery(c, &halt);
    assert!(
        cap.fired() > 0,
        "the harvest must have been refused a block above {uncredited:?}",
    );
    c.clear_drops();
    let frontier = c
        .beacon_state()
        .and_then(|state| state.latest_completed_recovery(halted))
        .expect("a cleared recovery leaves its completed record")
        .attested_frontier;
    assert!(
        frontier <= uncredited,
        "the recovery's frontier {frontier:?} must stand below the credit, above {uncredited:?}",
    );

    assert!(
        c.run_until(epochs(8) + retirement_wait(c), |c| credited(c)
            && !stands(c)),
        "the recovered shard credits the recipient again and the survivor retires the \
         record: recipient holds {}, record stands {}",
        vault_balance(c, halted, recipient),
        stands(c),
    );
    world.assert_settles_within(
        c,
        &charges,
        epochs(8),
        "a producer that read a discarded credit",
    );
    assert!(
        credited(c),
        "the recipient is credited exactly once: holds {}",
        vault_balance(c, halted, recipient),
    );
}

/// What [`commit_over_uncertified_ticks`] leaves on the halting shard.
struct UncertifiedTicks {
    /// The payer's own payment, and the height that committed it.
    j: TxHash,
    j_at: BlockHeight,
    /// The transfer, the height of the tick it stands in flight in, and
    /// the close of its leg entry window, at which its row is fated once
    /// a recovery releases it.
    k: TxHash,
    k_at: BlockHeight,
    k_lapse: WeightedTimestamp,
}

/// The tick `tx` stands in flight in on `shard`, if it does.
fn tick_of<C: Cluster>(c: &C, shard: ShardId, tx: TxHash) -> Option<BlockHeight> {
    match c.member_rows(shard)?.get(&tx)? {
        RowState::InFlight { tick, .. } => Some(*tick),
        _ => None,
    }
}

/// Commit [`a_harvested_tick_over_a_discarded_tick_settles_nothing`]'s
/// `j` and `K` on `halted`, with its execution votes cut among `hosts` so
/// neither certifies, with a boundary the beacon recorded between them,
/// and with `K` named in a tick.
fn commit_over_uncertified_ticks<C: FaultableCluster>(
    c: &mut C,
    halted: ShardId,
    setup: &HarvestedTickSetup,
    charges: &mut Charges,
    hosts: &[usize],
) -> UncertifiedTicks {
    let (payer_key, payer) = &setup.payer;
    let (source_key, source) = &setup.source;
    let votes = c.drop_type_between(hosts, hosts, "execution.vote");

    let j = charges.submit(
        c,
        build_transfer_tx(
            payer_key,
            *payer,
            setup.beneficiary,
            HARVESTED_PAYMENT,
            validity_around(c.now()),
        ),
    );
    assert!(
        c.run_until(epochs(4), |c| c.chain_fate(halted, j).0.is_some()),
        "the payer's own payment must commit on its shard",
    );
    let j_at = c.chain_fate(halted, j).0.expect("committed above");
    let recorded = |c: &C| {
        c.beacon_state().and_then(|state| {
            state
                .boundaries
                .get(&halted)
                .map(|boundary| boundary.height)
        })
    };
    assert!(
        c.run_until(epochs(4), |c| recorded(c)
            .is_some_and(|height| height >= j_at)),
        "the beacon must record a boundary of the halting shard at or above {j_at:?}",
    );

    let k_validity = validity_around(c.now());
    let k = charges.submit(
        c,
        build_sponsored_bounded_transfer_tx(
            payer_key,
            source_key,
            *source,
            setup.recipient,
            HARVESTED_PAYMENT,
            k_validity,
        ),
    );
    assert!(
        c.run_until(epochs(4), |c| c.chain_fate(halted, k).0.is_some()),
        "the transfer must commit on the halting shard",
    );
    assert!(
        c.run_until(epochs(2), |c| tick_of(c, halted, k).is_some()),
        "the transfer must be named in a tick: {:?}",
        c.member_rows(halted).and_then(|rows| rows.get(&k).copied()),
    );
    let k_at = tick_of(c, halted, k).expect("named above");
    assert!(
        votes.fired() > 0,
        "the halting shard's execution votes must actually have been cut",
    );

    UncertifiedTicks {
        j,
        j_at,
        k,
        k_at,
        k_lapse: Window::LegEntry
            .of(Deadline::of(k_validity.end_timestamp_exclusive))
            .end,
    }
}

/// Assert that no tick row at or below `k_at`, the harvested tip, stands
/// on the recovered `halted`, that every row its crossing released ends
/// by `k_lapse`, the close of `k`'s leg entry window, and four epochs on,
/// and that `j` and `k` both settle there as an abort.
fn assert_discarded_ticks_end<C: Cluster>(
    c: &mut C,
    halted: ShardId,
    k_at: BlockHeight,
    k_lapse: WeightedTimestamp,
    j: TxHash,
    k: TxHash,
) {
    let rows = c
        .member_rows(halted)
        .expect("the harness reads the recovered shard's member rows");
    let standing: Vec<_> = rows
        .iter()
        .filter(|(_, row)| {
            matches!(row, RowState::InFlight { tick, .. } | RowState::Stated { tick, .. }
                if *tick <= k_at)
        })
        .collect();
    assert!(
        standing.is_empty(),
        "no tick row at or below the harvested tip stands past the crossing: {standing:?}",
    );
    let released = |c: &C| {
        c.member_rows(halted).is_some_and(|rows| {
            rows.values()
                .any(|row| matches!(row, RowState::Released { .. }))
        })
    };
    let epoch_ms = epoch_duration_ms(c).expect("the beacon carries its epoch length");
    let to_lapse = k_lapse.as_millis().saturating_sub(clock(c).as_millis());
    let budget = epochs(
        u32::try_from(to_lapse.div_ceil(epoch_ms) + 4).expect("a leg entry window of epochs"),
    );
    assert!(
        c.run_until(budget, |c| !released(c)),
        "every row the crossing released must end by its clock, the transfer's leg entry \
         window closing at {k_lapse:?}: {:?}",
        c.member_rows(halted),
    );

    let ended = |c: &C, tx: TxHash| {
        c.member_rows(halted)
            .is_some_and(|rows| !rows.contains_key(&tx))
    };
    assert!(
        ended(c, j)
            && matches!(
                c.chain_fate(halted, j).1,
                Some((_, TransactionDecision::Aborted))
            ),
        "the payer's own payment ends by its abort: {:?}, row {:?}",
        c.chain_fate(halted, j),
        c.member_rows(halted).and_then(|rows| rows.get(&j).copied()),
    );
    assert!(
        ended(c, k)
            && matches!(
                c.chain_fate(halted, k).1,
                Some((_, TransactionDecision::Aborted))
            ),
        "the transfer ends on the recovered shard by its fate, settled as an abort: {:?}, \
         row {:?}",
        c.chain_fate(halted, k),
        c.member_rows(halted).and_then(|rows| rows.get(&k).copied()),
    );
}

/// A halted shard's recovery lands on retained and fresh hosts alike, and
/// every replica agrees on what the recovered shard runs.
///
/// The fresh committee seats partly on a host that kept running the shard
/// across the halt and partly on a host that seats it afresh. The draw is
/// host-blind, so the shape is built rather than hoped for: once the beacon
/// has drawn the fresh committee and before any host seats it, `rehome`
/// moves a drawn member onto a host that kept the shard, and another onto
/// one that did not, wherever the draw left neither. The member on a kept
/// host seats into the shard loop that host never stopped, whose tick
/// chain still carries what it ran up to the freeze. Transfers go in
/// flight at the freeze edge, so that chain holds runs of ticks below the
/// recovery's bridge, which the fresh committee never runs. The crossing
/// block discards every such tick and raises the chain's floor to its
/// parent, so past it the retained replica has to produce the receipts a
/// freshly seated one does, or its vote diverges from the committee's
/// certificate and its host panics. The in-flight and post-recovery
/// transfers then settle, and the committee's replicas converge on one
/// state root.
///
/// `rehome(c, validator, host)` runs `validator` on `host` from then on if
/// it holds no seat, and says whether it did. Requires [`halt_straddler_setup`] at genesis, two
/// committees' worth of pool surplus, and a host that runs no member of the
/// halting shard's committee.
///
/// [`halt_straddler_setup`]: crate::tx::halt_straddler_setup
///
/// # Panics
///
/// Panics if the halt or recovery misses a lifecycle budget, every host
/// runs a member of the halting committee, the fresh committee does not
/// land on both kinds of host, a retained replica diverges, a transfer
/// fails to settle, or the replicas never agree on a state root.
pub fn halted_shard_recovery_agrees_across_retained_and_fresh<C: FaultableCluster>(
    c: &mut C,
    mut rehome: impl FnMut(&mut C, ValidatorId, usize) -> bool,
) {
    let (halted, survivor) = ShardId::ROOT.children();
    let setup = halt_straddler_setup();
    split_lifecycle(c);

    let world = World::open(
        c,
        *PROTOCOL_RESOURCE,
        setup
            .straddlers
            .iter()
            .chain(&setup.post_recovery)
            .flat_map(|(_, from, _, to)| [from.address(), to.address()]),
        [],
    );
    let mut charges = Charges::default();
    let kept: BTreeSet<usize> = c.committee_hosts(halted).into_iter().collect();
    let afresh = (0..c.host_count())
        .find(|host| !kept.contains(host))
        .unwrap_or_else(|| {
            panic!("a host must run no member of the halting committee; kept {kept:?}")
        });

    let halt = freeze_shard(c, halted, survivor, |c| {
        for leg in &setup.straddlers[..HALT_STRADDLER_BATCH] {
            submit_probe(c, &mut charges, leg);
        }
    });
    let seated_at = await_recovery_draw(c, &halt);
    let fresh: Vec<ValidatorId> = c
        .beacon_state()
        .and_then(|state| {
            state
                .next_shard_committees
                .get(&halted)
                .map(|committee| committee.members.clone())
        })
        .expect("the recovery drew a fresh committee");
    let on_kept = |c: &C, validator: &ValidatorId| {
        c.host_of(*validator)
            .is_some_and(|host| kept.contains(&host))
    };
    let mut moved: Vec<ValidatorId> = Vec::new();
    if !fresh.iter().any(|validator| on_kept(c, validator)) {
        let host = *kept.first().expect("the halting committee runs somewhere");
        let validator = fresh
            .iter()
            .copied()
            .find(|validator| rehome(c, *validator, host))
            .unwrap_or_else(|| panic!("no member of {fresh:?} could move onto kept host {host}"));
        moved.push(validator);
    }
    if fresh.iter().all(|validator| on_kept(c, validator)) {
        let validator = fresh
            .iter()
            .copied()
            .filter(|validator| !moved.contains(validator))
            .find(|validator| rehome(c, *validator, afresh))
            .unwrap_or_else(|| panic!("no member of {fresh:?} could move onto host {afresh}"));
        moved.push(validator);
    }
    await_recovery_resume(c, &halt, seated_at);

    let recovered: BTreeSet<usize> = c.committee_hosts(halted).into_iter().collect();
    assert!(
        recovered.intersection(&kept).next().is_some(),
        "the fresh committee must seat a member on a host that kept the shard \
         across the halt; kept {kept:?}, recovered {recovered:?}",
    );
    assert!(
        recovered.difference(&kept).next().is_some(),
        "the fresh committee must seat a member on a host that seats the shard \
         afresh; kept {kept:?}, recovered {recovered:?}",
    );

    let revived: Vec<Probe> = setup
        .post_recovery
        .iter()
        .map(|leg| submit_probe(c, &mut charges, leg))
        .collect();
    assert!(
        c.run_until(epochs(40), |c| {
            revived
                .iter()
                .all(|p| chain_settled(c, p.payer_shard, p.hash) && credited_once(c, p))
        }),
        "a post-recovery transfer per direction must settle and credit its recipient once; {}",
        revival_report(c, halted, survivor, &revived),
    );
    world.assert_settles_within(
        c,
        &charges,
        epochs(8),
        "a recovery across retained and fresh replicas",
    );
    assert!(
        c.run_until(epochs(4), |c| agreed_state_root(c, halted).is_some()),
        "the recovered shard's replicas, retained and fresh, must agree on one state root",
    );
}

/// Assert one crossing's halves under the severance: the payer settles
/// it alone if its chain carried it at all, and no delivery lands.
///
/// Whether the payer committed it is the race the cut lands in the
/// middle of, so that is read first rather than assumed — a transaction
/// the partition beat into the block is nobody's to decide.
fn assert_severed_crossing<C: FaultableCluster>(
    c: &mut C,
    (left, right): (ShardId, ShardId),
    crossing: &Crossing,
    label: &str,
) {
    let payer_shard = payer_of(crossing, left, right);
    if c.chain_fate(payer_shard, crossing.hash).0.is_some() {
        let decided = c.run_until(epochs(4), |c| {
            matches!(
                c.chain_fate(payer_shard, crossing.hash).1,
                Some((_, TransactionDecision::Accept))
            )
        });
        let payer_fate = c.chain_fate(payer_shard, crossing.hash).1.map(|(_, d)| d);
        assert!(
            decided,
            "a payer that committed the {label} transfer settles it alone under the \
             severance — it awaits nobody: {payer_fate:?}",
        );
    } else {
        assert!(
            c.chain_fate(payer_shard, crossing.hash).1.is_none(),
            "the {label} transfer's payer reached a verdict on a transaction its \
             chain never carried",
        );
    }
    assert!(
        c.chain_fate(crossing.recipient_shard, crossing.hash)
            .0
            .is_none(),
        "the {label} delivery landed across the severance",
    );
}

/// A transaction's fate on one chain: the height that committed it and
/// the height and decision that finalized it.
type ChainFate = (
    Option<BlockHeight>,
    Option<(BlockHeight, TransactionDecision)>,
);

/// One straddler probe: where it pays and where it is credited.
struct Probe {
    hash: TxHash,
    payer_shard: ShardId,
    recipient_shard: ShardId,
    recipient: PrincipalAddr,
}

/// Submit one straddler leg as a transfer, recording what the assertions
/// read back.
fn submit_probe<C: Cluster>(
    c: &mut C,
    charges: &mut Charges,
    (key, from, _, to): &PaymentLeg,
) -> Probe {
    let tx = build_transfer_tx(key, *from, *to, STRADDLER_PAYMENT, validity_around(c.now()));
    Probe {
        hash: charges.submit(c, tx),
        payer_shard: account_shard(*from, 2),
        recipient_shard: account_shard(*to, 2),
        recipient: *to,
    }
}

/// Where each post-recovery probe stands, for the stall report: its
/// direction, what each chain recorded for it, the status the cluster
/// reports, and its recipient's balance, beside both shards' heights.
fn revival_report<C: Cluster>(
    c: &C,
    halted: ShardId,
    survivor: ShardId,
    revived: &[Probe],
) -> String {
    let mut report = format!(
        "at {}s, halted {halted:?} at {:?}, survivor {survivor:?} at {:?}, epoch {:?}",
        c.now().as_secs(),
        c.committed_height(halted),
        c.committed_height(survivor),
        beacon_epoch(c),
    );
    for probe in revived {
        let _ = write!(
            report,
            "; probe {:?} {:?} -> {:?}: halted {:?}, survivor {:?}, status {:?}, recipient holds {}",
            probe.hash,
            probe.payer_shard,
            probe.recipient_shard,
            c.chain_fate(halted, probe.hash),
            c.chain_fate(survivor, probe.hash),
            c.tx_status(probe.hash),
            vault_balance(c, probe.recipient_shard, probe.recipient),
        );
    }
    report
}

/// Whether `probe`'s recipient holds exactly its genesis dust plus one
/// payment — credited once, never twice.
fn credited_once<C: Cluster>(c: &C, probe: &Probe) -> bool {
    vault_balance(c, probe.recipient_shard, probe.recipient) == 10 + STRADDLER_PAYMENT
}

/// Assert the probes' credits once the halted shard has recovered: a
/// recipient is credited at most once, and only for a transfer its payer
/// accepted; every settling probe was credited; every doomed probe the
/// frozen shard paid for committed nowhere; and every transfer the
/// survivor accepted into the frozen shard is credited once the recovered
/// shard reads the record the survivor keeps pushing.
///
/// `at_freeze` is the halted chain's own view taken before the recovery:
/// a commit or an accept in either that snapshot or the post-recovery
/// walk counts, since the snapshot covers heights a fresh member never
/// synced and the walk covers anything finalized after resume.
fn assert_credits_agree<C: Cluster>(
    c: &mut C,
    halted: ShardId,
    survivor: ShardId,
    probes: &[Probe],
    at_freeze: &[ChainFate],
) {
    let accepted = |c: &C, idx: usize, probe: &Probe| {
        matches!(
            fate_including_freeze(c, halted, at_freeze, probe.payer_shard, idx, probe.hash).1,
            Some((_, TransactionDecision::Accept))
        )
    };
    let credited = c.run_until(epochs(20), |c| {
        probes
            .iter()
            .enumerate()
            .all(|(idx, probe)| !accepted(c, idx, probe) || credited_once(c, probe))
    });
    let mut report = String::new();
    let mut doomed_nowhere = 0u32;
    let batch = HALT_STRADDLER_BATCH;
    for (idx, probe) in probes.iter().enumerate() {
        let payer = fate_including_freeze(c, halted, at_freeze, probe.payer_shard, idx, probe.hash);
        let held = vault_balance(c, probe.recipient_shard, probe.recipient);
        let _ = write!(
            report,
            "\n  #{idx}: payer={:?} {payer:?}; recipient={:?}; holds {held}",
            probe.payer_shard, probe.recipient_shard,
        );
        let was_accepted = accepted(c, idx, probe);
        assert_eq!(
            held,
            if was_accepted {
                10 + STRADDLER_PAYMENT
            } else {
                10
            },
            "a recipient is credited exactly when its payer accepted, and once:{report}",
        );
        if idx < batch {
            assert!(was_accepted, "every settling probe must accept:{report}");
        } else if idx >= 2 * batch && probe.payer_shard == halted {
            assert!(
                payer.0.is_none(),
                "a probe the frozen shard paid for committed somewhere:{report}",
            );
            doomed_nowhere += 1;
        }
    }
    assert!(
        credited,
        "every transfer a payer accepted must be credited once the recovered shard reads \
         its record:{report}",
    );
    assert!(
        doomed_nowhere > 0,
        "no doomed probe was paid for by the frozen shard — the batches no \
         longer exercise it",
    );
    assert!(
        probes
            .iter()
            .any(|probe| probe.payer_shard == survivor && probe.recipient_shard == halted),
        "no probe crossed into the frozen shard — nothing was owed across the halt",
    );
}

/// A probe's fate on `shard`, taking the halted shard's reading from
/// before the freeze where its chain has since said nothing.
///
/// A recovered shard's chain answers for what it committed before the
/// freeze, but a scenario that read it only after the recovery would
/// miss a probe the shard settled and then stopped answering for.
fn fate_including_freeze<C: Cluster>(
    c: &C,
    halted: ShardId,
    at_freeze: &[ChainFate],
    shard: ShardId,
    idx: usize,
    hash: TxHash,
) -> ChainFate {
    let now = c.chain_fate(shard, hash);
    if shard == halted {
        let frozen = at_freeze[idx];
        (now.0.or(frozen.0), now.1.or(frozen.1))
    } else {
        now
    }
}

/// A staged shard freeze: the fault rules are installed and the shard has
/// verifiably stopped committing. Carries the observations
/// [`await_halt_recovery`] asserts against.
pub struct StagedHalt {
    /// The frozen shard.
    shard: ShardId,
    /// Its live sibling, asserted to keep committing through the halt.
    sibling: ShardId,
    /// The frozen shard's settled height once in-flight rounds drained.
    frozen_at: u64,
    /// The beacon epoch when the freeze settled.
    epoch_at_halt: u64,
    /// The sibling's committed height when the freeze settled.
    sibling_at_halt: u64,
}

/// Freeze `shard` by having two of its four committee members withhold
/// their consensus.
///
/// f+1 of the committee withhold, as validators: they stop signing their
/// shard consensus on whichever hosts run them, while every other vnode on
/// those hosts, and their own beacon, execution and serving, carry on. The
/// honest remainder is 2f, short of quorum, so the shard halts; nothing else
/// stops.
///
/// The withholding is staged. A pair member due to aggregate the next
/// rounds' votes can hold a QC no one else ever sees and commit one height
/// past the beacon-attested frontier — a suffix the recovery orphans, and
/// the linkage break kills its host. So the pair first withholds its votes,
/// which stops every quorum from forming while a QC a pair member already
/// holds still leaves in its next proposal and becomes common knowledge;
/// an epoch later it withholds its proposals and timeouts too.
///
/// `at_freeze_edge` runs just before the votes stop — the last instant new
/// work enters the shard's pipeline with any chance to commit.
pub fn freeze_shard<C: FaultableCluster>(
    c: &mut C,
    shard: ShardId,
    sibling: ShardId,
    at_freeze_edge: impl FnOnce(&mut C),
) -> StagedHalt {
    let members: Vec<ValidatorId> = c
        .beacon_state()
        .and_then(|state| state.shard_consensus_members.get(&shard).cloned())
        .expect("the halting shard has a consensus committee");
    assert_eq!(
        members.len(),
        4,
        "the halting shard must be served by a four-member committee",
    );
    let withholding = &members[..2];

    at_freeze_edge(c);
    let votes_withheld = c.withhold(withholding, Withheld::Votes);
    c.run_until(epochs(1), |_| false);
    c.withhold(withholding, Withheld::Consensus);

    // In-flight rounds drain, then the shard freezes.
    c.run_until(epochs(1), |_| false);
    let frozen = c
        .committed_height(shard)
        .expect("the halting shard committed during the grow")
        .inner();
    let epoch_at_halt = beacon_epoch(c).expect("a committed beacon epoch").inner();
    let sibling_at_halt = c
        .committed_height(sibling)
        .expect("the sibling shard serves")
        .inner();
    c.run_until(epochs(2), |_| false);
    let during = c
        .committed_height(shard)
        .expect("a committed height during the halt")
        .inner();
    assert!(
        during <= frozen + 2,
        "two of four withholding leaves no quorum, so the shard must halt: \
         frozen={frozen}, during={during}",
    );
    assert!(
        votes_withheld.fired() >= 1,
        "the withheld votes must actually be refused",
    );
    StagedHalt {
        shard,
        sibling,
        frozen_at: during,
        epoch_at_halt,
        sibling_at_halt,
    }
}

/// Drive a staged freeze through detection, committee redraw, resume, and
/// record clear, asserting the beacon and the sibling shard stay live
/// throughout.
pub fn await_halt_recovery(c: &mut impl FaultableCluster, halt: &StagedHalt) {
    let seated_at = await_recovery_draw(c, halt);
    await_recovery_resume(c, halt, seated_at);
}

/// Drive a staged freeze through detection until the beacon draws the
/// fresh committee, returning the epoch it was seated at. Nothing has
/// seated it yet: the hosts place a committed draw on their next scan.
fn await_recovery_draw(c: &mut impl FaultableCluster, halt: &StagedHalt) -> Epoch {
    let shard = halt.shard;

    // The boundary watermark stalls past the threshold; the beacon flags
    // the shard and re-draws its committee from the pool spares. The
    // withholding is permanent, so detection is guaranteed — the budget is a generous
    // ceiling, not the expected latency: cross-shard traffic in flight at
    // the freeze lets the shard commit a few more blocks before it stalls,
    // and on a real-network harness the per-fold cadence varies, so the
    // `threshold` miss folds accrue later than on the quiet quick sim.
    let threshold = u32::try_from(HALT_THRESHOLD_EPOCHS).expect("threshold fits u32");
    let recovered = c.run_until(epochs(threshold + 25), |c| {
        c.beacon_state()
            .is_some_and(|state| state.pending_recoveries.contains_key(&shard))
    });
    assert!(
        recovered,
        "the beacon must flag the halted shard and seat a fresh committee",
    );
    let seated_at = c
        .beacon_state()
        .and_then(|state| state.pending_recoveries.get(&shard).map(|r| r.rotated_at))
        .expect("the pending recovery names its seating epoch");
    // Only the shard halted: the beacon and the sibling kept committing.
    let epoch_now = beacon_epoch(c).expect("a committed beacon epoch").inner();
    assert!(
        epoch_now > halt.epoch_at_halt,
        "the beacon must keep producing epochs through the halt \
         ({} -> {epoch_now})",
        halt.epoch_at_halt,
    );
    assert!(
        c.committed_height(halt.sibling)
            .expect("the sibling shard serves")
            .inner()
            > halt.sibling_at_halt,
        "the sibling shard must keep committing through the halt",
    );
    seated_at
}

/// Drive a drawn recovery through resume and record clear: the fresh
/// committee seated at `seated_at` resumes the halted shard and its first
/// crossing clears the record.
pub fn await_recovery_resume(c: &mut impl FaultableCluster, halt: &StagedHalt, seated_at: Epoch) {
    let shard = halt.shard;
    // The fresh committee syncs the halted tip from the retained members,
    // bridges the halt gap, and resumes committing past the frozen height.
    // The pool the recovery draws from holds exactly `shard_size` spares,
    // so the fresh committee is whatever the tenure shuffle rotated into
    // the pool — possibly a withholding validator, cycled off the halted
    // shard before the flag and redrawn (the recovery is only as clean as
    // a fresh draw at the pool's corrupt fraction). The fresh committee
    // keeps its honest majority and recovers, but a lone withholding
    // member silencing a quarter of the views stretches the resume, so the budget
    // is generous — a ceiling on the wait, not the expected latency.
    assert!(
        await_height(c, shard, halt.frozen_at + 3, epochs(40)),
        "the recovered shard must resume committing under its fresh committee \
         (frozen at {})",
        halt.frozen_at,
    );
    // The first crossing under the fresh committee completes the recovery.
    let cleared = c.run_until(epochs(20), |c| {
        c.beacon_state()
            .is_some_and(|state| !state.pending_recoveries.contains_key(&shard))
    });
    assert!(
        cleared,
        "the shard's next boundary crossing must clear the recovery record",
    );
    // The committee the flag seated is the one that recovered the shard.
    // A recovery that stalls re-flags and redraws after another full
    // threshold, and can still clear inside the budgets above; the
    // completed record's seating epoch tells the two apart.
    let completed_at = c
        .beacon_state()
        .and_then(|state| state.latest_completed_recovery(shard).map(|r| r.rotated_at))
        .expect("a cleared recovery leaves its completed record");
    assert_eq!(
        completed_at, seated_at,
        "the first fresh committee must complete the recovery; a later seating \
         epoch means it stalled and the beacon redrew",
    );
}

/// The committed state root that every host serving `shard` agrees on, or `None`
/// if any two disagree or one has not yet reported. The stall-not-fork check:
/// after a heal, this becoming `Some` means the shard's whole committee — the
/// rejoined dark hosts included — converged on one chain. A host still catching
/// up reports a different (or no) root, so it holds this at `None` until every
/// committee member is back in step. Scoped to the shard's committee so it works
/// in a multi-shard cluster, where only some hosts serve any given shard.
fn agreed_state_root(c: &impl FaultableCluster, shard: ShardId) -> Option<StateRoot> {
    let hosts = c.committee_hosts(shard);
    let first = c.host_committed_state_root(*hosts.first()?, shard)?;
    for &host in &hosts[1..] {
        if c.host_committed_state_root(host, shard)? != first {
            return None;
        }
    }
    Some(first)
}

/// A connected minority fragment partitions off, stays dark across an epoch
/// boundary, then rejoins as a group.
///
/// The regression shape behind the rejoin-wedge class, where fragment members
/// share stale state with each other while partitioned.
///
/// Requires a seven-host single-shard committee: quorum is five (strict >2/3),
/// so cutting the two-host fragment `{0, 1}` off the majority `{2..6}` leaves
/// both the shard and the beacon majority live — the majority keeps committing
/// and crossing epoch boundaries while the fragment is frozen. A full
/// bipartition, so both harnesses agree on the cut.
///
/// # Panics
///
/// Panics if consensus does not commit before the partition, the majority fails
/// to progress while the fragment is dark, the fragment keeps up with the
/// majority while partitioned, or the rejoined fragment fails to catch up and
/// agree on the committed root after the heal.
pub fn minority_fragment_rejoins_after_partition(c: &mut impl FaultableCluster) {
    assert_eq!(
        c.host_count(),
        7,
        "this scenario needs a seven-host committee so a two-host fragment leaves quorum live",
    );

    // Every host — the future fragment included — must be seated and committing
    // before the cut, so the fragment goes dark from a real synced state (not a
    // never-seated genesis host) and rejoins by catching up a bounded gap.
    let seated = c.run_until(epochs(6), |c| {
        (0..7).all(|host| {
            c.host_committed_height(host, ShardId::ROOT)
                .is_some_and(|h| h.inner() >= 1)
        })
    });
    assert!(
        seated,
        "every host must commit a block before the partition"
    );
    let start_epoch = beacon_epoch(c).expect("a committed beacon epoch").inner();

    c.partition(&[0, 1], &[2, 3, 4, 5, 6]);
    let before = c
        .committed_height(ShardId::ROOT)
        .expect("a committed height before the partition")
        .inner();

    // Keep the fragment dark across exactly one epoch boundary — the majority
    // (five of seven) keeps both shard and beacon consensus live, and bounding
    // the dark window to a single epoch keeps the fragment's catch-up gap inside
    // the block-retention window.
    assert!(
        await_beacon_epoch(c, start_epoch + 1, epochs(6)),
        "the five-host majority must cross an epoch boundary while the fragment is dark",
    );
    // Partition onset can transiently stall the majority: a replica missing a
    // pending ancestor body breaks the zero-slack five-of-five quorum until
    // the spin detector's sync recovers it, and rotating fetches past the two
    // dark peers costs a timeout each. Progress is the requirement, not
    // instantaneous progress — so give the sample a recovery budget.
    assert!(
        c.run_until(epochs(3), |c| c
            .committed_height(ShardId::ROOT)
            .is_some_and(|h| h.inner() > before + 2)),
        "the five-host majority must keep committing while the fragment is dark: \
         before={before}",
    );
    let during = c
        .committed_height(ShardId::ROOT)
        .expect("a committed height during the partition")
        .inner();

    // The dark fragment has no quorum of its own, so it falls behind the
    // majority. It may still commit what it was handed before the cut, as
    // much as its queues held, which a loaded host may not have worked
    // through when the cut came; it cannot follow the majority past that.
    for host in [0, 1] {
        let now = c
            .host_committed_height(host, ShardId::ROOT)
            .map_or(0, BlockHeight::inner);
        assert!(
            now < during,
            "fragment host {host} kept up with the majority while partitioned \
             (cut at {before}, fragment at {now}, majority at {during})",
        );
    }

    // Heal: the fragment resynchronises via block fetch, catches up to a tip past
    // the dark window, and every host — fragment included — agrees on the root.
    c.heal_all();
    let target = during + 2;
    let caught_up = c.run_until(epochs(10), |c| {
        [0, 1].iter().all(|&host| {
            c.host_committed_height(host, ShardId::ROOT)
                .is_some_and(|h| h.inner() >= target)
        }) && agreed_state_root(c, ShardId::ROOT).is_some()
    });
    assert!(
        caught_up,
        "the rejoined fragment must catch up past the dark window ({target}) and \
         every host must agree on the committed state root",
    );
}

/// Liveness needs a quorum, not the whole committee.
///
/// After a partition drops the cluster below quorum, restoring exactly a quorum
/// — with the remaining member still dark — must resume progress; the final
/// member then catches up.
///
/// Requires a four-host single-shard committee (quorum three). Hosts 0 and 1 are
/// isolated rather than split `{0,1} | {2,3}`, so host 0 is genuinely edgeless:
/// a plain partition would leave the 0–1 edge open, and production gossip would
/// relay across it once the staged heal reconnects host 1. `{2, 3}` alone is two
/// of four, below quorum, so consensus halts; reconnecting host 1 to hosts 2 and
/// 3 forms an exact three-of-four quorum that resumes progress before host 0 is
/// healed back in.
///
/// # Panics
///
/// Panics if consensus does not commit before the partition, progress fails to
/// halt under it, the exact-quorum heal fails to resume progress, or host 0 fails
/// to catch up and agree on the committed root after the final heal.
pub fn partition_heals_at_exact_quorum(c: &mut impl FaultableCluster) {
    assert_eq!(
        c.host_count(),
        4,
        "this scenario needs a four-host committee so three connected hosts are exactly quorum",
    );
    // Every host — host 0 included — must be seated and committing before the
    // isolation, so the host that stays dark rejoins from a real synced state.
    let seated = c.run_until(epochs(6), |c| {
        (0..4).all(|host| {
            c.host_committed_height(host, ShardId::ROOT)
                .is_some_and(|h| h.inner() >= 1)
        })
    });
    assert!(
        seated,
        "every host must commit a block before the partition"
    );

    // Isolate both 0 and 1 so the 0–1 edge is cut too; `{2, 3}` is below quorum.
    c.isolate(0);
    c.isolate(1);
    let before = c
        .committed_height(ShardId::ROOT)
        .expect("a committed height before the partition")
        .inner();
    c.run_until(epochs(1), |_| false);
    let during = c
        .committed_height(ShardId::ROOT)
        .expect("a committed height during the partition")
        .inner();
    assert!(
        during <= before + 2,
        "with only two of four connected there is no quorum, so progress must halt: \
         before={before}, during={during}",
    );

    // Reconnect host 1 to hosts 2 and 3 — an exact three-of-four quorum, host 0
    // still dark. Progress must resume before the final heal.
    c.heal_between(1, 2);
    c.heal_between(1, 3);
    let resumed = during + 3;
    assert!(
        await_height(c, ShardId::ROOT, resumed, epochs(6)),
        "an exact three-of-four quorum (host 0 still dark) must resume progress",
    );
    let host0 = c
        .host_committed_height(0, ShardId::ROOT)
        .map_or(0, BlockHeight::inner);
    assert!(
        host0 < resumed,
        "the still-dark host 0 must not have kept pace (host0={host0}, tip={resumed})",
    );

    // Heal host 0 back in; it catches up and every host agrees on the root.
    c.heal_all();
    let target = resumed + 2;
    let caught_up = c.run_until(epochs(8), |c| {
        c.host_committed_height(0, ShardId::ROOT)
            .is_some_and(|h| h.inner() >= target)
            && agreed_state_root(c, ShardId::ROOT).is_some()
    });
    assert!(
        caught_up,
        "host 0 must catch up to the tip ({target}) and every host must agree on \
         the committed state root after the final heal",
    );
}

/// Severing every edge between two shards strands their in-flight cross-shard
/// ticks without ever splitting one, and healing resolves them.
///
/// A two-shard cluster (`split_lifecycle`) whose committees sit on disjoint host
/// sets, so `partition(committee_hosts(left), committee_hosts(right))` cuts every
/// inter-shard edge in both directions while leaving intra-shard edges intact —
/// unlike the drop scenarios, which always leave a fetch route the tick recovers
/// through.
///
/// No tick aborts while the cut holds, and that is the shape of the cut rather
/// than a slow deadline. The same partition splits the beacon quorum, so epoch
/// production halts, and both shards coast their `L = 1` lookahead runway and
/// then hold at the schedule head with their attested clocks frozen. Every
/// deadline in the system is read from that clock, so none of them can arrive:
/// the cut that strands a tick is the cut that stops the clock its abort would
/// be timed against. What must hold under it is the safety half — no stranded
/// tick settles Accept on either side, and the two shards never disagree — and
/// then, on the heal, that both reach a terminal verdict rather than wedging.
///
/// The deadline itself has its own scenario, which cuts the two message types a
/// payer's bundle travels and leaves both committees and the beacon healthy, so
/// the clock keeps running while the evidence does not arrive.
///
/// The two probes end up in different cases, deliberately. The one in flight as
/// the cut lands was already committed on its payer's shard, so it owes a
/// verdict and gets one on the heal. The one submitted into the frozen half was
/// never included at all, and its signed window closes before that half
/// resumes — so it expires in the pool with no chain owing it anything, which
/// is what a validity window is for.
///
/// Cross-shard transfers run in each direction over the funded pair; the
/// single-shard controls run on disjoint accounts, so they settle intra-shard
/// without colliding with the severed ticks' declared writes.
///
/// # Panics
///
/// Panics if a shard wedges under the severance, a single-shard control fails to
/// settle, a severed cross-shard transfer settles or the two shards disagree on
/// its fate, an in-flight transfer never resolves after the heal, or a fresh
/// cross-shard transfer fails to settle.
pub fn inter_shard_partition_strands_ticks_until_it_heals(c: &mut impl FaultableCluster) {
    let (left, right) = ShardId::ROOT.children();
    split_lifecycle(c);

    let left_hosts = c.committee_hosts(left);
    let right_hosts = c.committee_hosts(right);
    assert!(
        !left_hosts.is_empty() && !right_hosts.is_empty(),
        "both split children must be served before the severance",
    );
    assert!(
        left_hosts.iter().all(|h| !right_hosts.contains(h)),
        "the two committees must sit on disjoint host sets: left={left_hosts:?}, right={right_hosts:?}",
    );

    let cast = cross_shard_fault_cast();
    let world = fault_family_world(c);
    let mut charges = Charges::default();

    let left_before = c
        .committed_height(left)
        .expect("left serves before the severance")
        .inner();
    let right_before = c
        .committed_height(right)
        .expect("right serves before the severance")
        .inner();

    // A cross-shard transfer in flight as the cut lands.
    let before = submit_crossing(c, &mut charges);

    // Sever every inter-shard edge (both directions), intra-shard edges intact.
    c.partition(&left_hosts, &right_hosts);

    // A second cross-shard transfer submitted under the severance, sourced on
    // the far side so each shard pays for one stranded delivery.
    let during = submit_crossing_between(c, &mut charges, &cast.right, left, &cast.left);

    // A single-shard control per child, on accounts disjoint from the crossing
    // pair — these must settle purely intra-shard while the cross-shard
    // deliveries are stranded.
    for (index, (key, from, to)) in cast.controls.iter().enumerate() {
        let control = build_transfer_tx(key, *from, *to, 100, validity_around(c.now()));
        let hash = charges.submit(c, control);
        let status = await_tx_terminal(c, hash, epochs(2));
        assert!(
            matches!(
                status,
                Some(TransactionStatus::Completed(TransactionDecision::Accept))
            ),
            "single-shard control {index} must settle under the severance; \
             status = {status:?}",
        );
    }

    // Both shards kept committing locally throughout — the severance froze the
    // cross-shard deliveries, not either side's consensus.
    let left_during = c
        .committed_height(left)
        .expect("left serves during the severance")
        .inner();
    let right_during = c
        .committed_height(right)
        .expect("right serves during the severance")
        .inner();
    assert!(
        left_during > left_before,
        "the left shard wedged under the severance (before={left_before}, during={left_during})",
    );
    assert!(
        right_during > right_before,
        "the right shard wedged under the severance (before={right_before}, during={right_during})",
    );

    // No delivery lands across the cut, and a payer that carried the
    // transaction reaches its verdict anyway. A divided transfer's payer
    // settles it alone, so the severance stalls the delivery and nothing
    // else — the case worth failing is a payer that committed the
    // transaction and then waits on a counterpart it does not await.
    // Whether it committed at all is the race the cut lands in the middle
    // of, so that is read first rather than assumed: a transaction the
    // partition beat into the block is nobody's to decide, and the
    // `resolved > 0` check below is what keeps the pair from being
    // vacuous. The delivery's absence is read off the chain rather than
    // waited for: with the beacon starved by the same partition, one that
    // has not landed is not going to.
    for (crossing, label) in [(&before, "left→right"), (&during, "right→left")] {
        assert_severed_crossing(c, (left, right), crossing, label);
    }

    // Heal every edge. Epoch production resumes and both clocks restart, so a
    // transfer a payer had committed accepts if it has not already, and its
    // delivery — stranded, not lost — lands on the recipient's chain.
    //
    // A transfer submitted *into* the frozen half is the other case: its shard
    // held at the schedule head without ever including it, and by the heal its
    // signed window has closed, so it can never be included and no chain owes
    // it a verdict. It expires, which is the pool's job and not consensus's.
    c.heal_all();
    let resolved = [(&before, "left→right"), (&during, "right→left")]
        .into_iter()
        .filter(|(crossing, label)| assert_delivered_after_heal(c, left, right, crossing, label))
        .count();
    assert!(
        resolved > 0,
        "no transfer was in flight across the cut — the severance landed before \
         either shard could commit one, so nothing was stranded",
    );

    // A fresh cross-shard transfer settles normally on the healed network.
    let fresh = submit_crossing(c, &mut charges);
    let fresh_status = await_tx_terminal(c, fresh.hash, epochs(10));
    assert!(
        matches!(
            fresh_status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "a fresh cross-shard transfer must settle once the severance heals; \
         status = {fresh_status:?}",
    );
    await_crossed(c, &fresh, "post-heal");

    // Stranded, not lost: every delivery the cut held back landed on the
    // heal, and the one transfer no shard ever included cost nobody
    // anything.
    world.assert_settles_within(c, &charges, epochs(8), "a severance and its heal");
}

/// The child that pays for `crossing`: the one it does not deliver to.
fn payer_of(crossing: &Crossing, left: ShardId, right: ShardId) -> ShardId {
    if crossing.recipient_shard == right {
        left
    } else {
        right
    }
}

/// Assert `crossing` resolved once the severance healed, and report whether
/// it was ever committed at all.
///
/// A crossing its payer had committed owes an accept there and on the
/// recipient's chain, since it runs whole. One no shard ever included owes nothing: its
/// signed window closed while its half held at the schedule head, so it
/// expires in the pool.
fn assert_delivered_after_heal<C: FaultableCluster>(
    c: &mut C,
    left: ShardId,
    right: ShardId,
    crossing: &Crossing,
    label: &str,
) -> bool {
    let payer_shard = payer_of(crossing, left, right);
    if c.chain_fate(payer_shard, crossing.hash).0.is_none() {
        assert!(
            c.tx_status(crossing.hash).is_none(),
            "a transfer no shard ever committed reached a verdict anyway ({label})",
        );
        return false;
    }
    let verdict = await_tx_terminal(c, crossing.hash, epochs(10));
    assert!(
        matches!(
            verdict,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "the {label} transfer must accept on its payer's chain once the severance \
         heals; status = {verdict:?}",
    );
    assert!(
        c.run_until(epochs(10), |c| matches!(
            c.chain_fate(crossing.recipient_shard, crossing.hash).1,
            Some((_, TransactionDecision::Accept))
        )),
        "the {label} crossing must land on the recipient's chain once the \
         severance heals; recipient = {:?}",
        c.chain_fate(crossing.recipient_shard, crossing.hash),
    );
    true
}

/// A ratification pool partitioned below quorum halts epoch production, and the
/// shards defer at the schedule head rather than fork.
///
/// A disjoint two-shard cluster (eight hosts, one validator each).
/// `partition(committee_hosts(left), committee_hosts(right))` splits the beacon
/// pool 4|4 — neither side reaches quorum, so no beacon block commits and epoch
/// production halts — while each shard keeps its own four hosts together, so
/// shard consensus stays live. The partition then holds *past* the `L = 1`
/// lookahead runway. The shards coast on the committees the last committed beacon
/// epoch resolved, so their heights climb for the runway and then plateau once
/// the weighted timestamp crosses past the last resolved committee window —
/// stall, not fork. Healing restores the pool quorum, epoch production resumes,
/// and both shards commit on past their frozen heights.
///
/// # Panics
///
/// Panics if the partitioned pool advances the epoch, a shard fails to coast then
/// freeze, either shard keeps committing past its runway (a fork or a wedge
/// rather than a clean defer), or the heal fails to resume epochs, shard
/// progress, or cross-host root agreement.
pub fn beacon_pool_partition_stalls_epoch_production(c: &mut impl FaultableCluster) {
    let (left, right) = ShardId::ROOT.children();
    split_lifecycle(c);

    let left_hosts = c.committee_hosts(left);
    let right_hosts = c.committee_hosts(right);
    assert!(
        !left_hosts.is_empty() && !right_hosts.is_empty(),
        "both split children must be served before the partition",
    );
    assert!(
        left_hosts.iter().all(|h| !right_hosts.contains(h)),
        "the two committees must sit on disjoint host sets: left={left_hosts:?}, right={right_hosts:?}",
    );

    let start_epoch = beacon_epoch(c)
        .expect("a committed beacon epoch before the partition")
        .inner();
    let left_before = c.committed_height(left).expect("left serves").inner();
    let right_before = c.committed_height(right).expect("right serves").inner();

    // Split the beacon pool below quorum. Each shard keeps its own hosts, so
    // shard consensus survives; the pool spanning both shards does not.
    c.partition(&left_hosts, &right_hosts);

    // Coast past the L = 1 runway, then the shards defer at the schedule head.
    c.run_until(epochs(3), |_| false);
    let left_frozen = c.committed_height(left).expect("left serves").inner();
    let right_frozen = c.committed_height(right).expect("right serves").inner();
    assert_eq!(
        beacon_epoch(c).map(Epoch::inner),
        Some(start_epoch),
        "the pool partitioned below quorum must halt epoch production",
    );
    assert!(
        left_frozen > left_before && right_frozen > right_before,
        "both shards must coast the lookahead runway before deferring \
         (left {left_before}->{left_frozen}, right {right_before}->{right_frozen})",
    );

    // Hold longer: the deferred shards make no further progress — a stall, not a
    // fork, and not an unbounded run past the runway.
    c.run_until(epochs(2), |_| false);
    assert_eq!(
        c.committed_height(left).map(BlockHeight::inner),
        Some(left_frozen),
        "the left shard must defer at the schedule head, not commit past its runway",
    );
    assert_eq!(
        c.committed_height(right).map(BlockHeight::inner),
        Some(right_frozen),
        "the right shard must defer at the schedule head, not commit past its runway",
    );
    assert_eq!(
        beacon_epoch(c).map(Epoch::inner),
        Some(start_epoch),
        "epoch production must stay halted while the pool is partitioned",
    );

    // Heal: the pool reaches quorum again, epochs resume, and both shards commit
    // past their frozen heights on the one chain every serving host agrees on.
    c.heal_all();
    assert!(
        await_beacon_epoch(c, start_epoch + 1, epochs(8)),
        "epoch production must resume once the pool heals (stalled at epoch {start_epoch})",
    );
    assert!(
        await_height(c, left, left_frozen + 1, epochs(8))
            && await_height(c, right, right_frozen + 1, epochs(8)),
        "both shards must resume committing past their frozen heights after the heal \
         (left {left_frozen}, right {right_frozen})",
    );
    let agreed = c.run_until(epochs(8), |c| {
        agreed_state_root(c, left).is_some() && agreed_state_root(c, right).is_some()
    });
    assert!(
        agreed,
        "every serving host must agree on each shard's committed root after the heal",
    );
}

/// The payment every cross-shard fault probe carries.
const CROSSING_PAYMENT: u128 = 500;

/// Submit a transfer from the left child's funded account into the right
/// child's, and return its hash.
///
/// The signed validity window discriminates repeat submissions: two probes
/// built at the same clock over the same pair would be one transaction under
/// hash dedup, which is the replay protection working rather than a builder
/// limitation.
/// A cross-shard transfer in flight, with what its recipient held when it
/// was submitted.
///
/// The credit is asserted as a delta off that reading: the vault is
/// cluster-wide state, and what it holds is whatever earlier crossings
/// left there.
struct Crossing {
    hash: TxHash,
    recipient_shard: ShardId,
    recipient: PrincipalAddr,
    held_before: u128,
}

/// Wait for `crossing` to land on both chains and credit its recipient's
/// vault.
///
/// The crossing runs whole, so both shards commit it and the recipient's
/// credits the vault as it does. Read the moment the payer's status
/// flips, the recipient shows nothing yet — and a scenario in this family
/// that never read the recipient at all would pass on a payment that
/// never left one shard: the DA fetch engages for any dropped gossip, and
/// the remote-header channel runs as ordinary machinery in a grown
/// cluster, so neither counter alone distinguishes a crossing from a
/// local payment.
fn await_crossed<C: Cluster>(c: &mut C, crossing: &Crossing, context: &str) {
    let (left, right) = ShardId::ROOT.children();
    let credited = crossing.held_before + CROSSING_PAYMENT;
    let landed = c.run_until(epochs(8), |c| {
        c.chain_fate(left, crossing.hash).0.is_some()
            && c.chain_fate(right, crossing.hash).0.is_some()
            && vault_balance(c, crossing.recipient_shard, crossing.recipient) == credited
    });
    assert!(
        landed,
        "the {context} crossing never landed on both chains: left={:?}, right={:?}, \
         recipient holds {} against {credited} expected",
        c.chain_fate(left, crossing.hash).0,
        c.chain_fate(right, crossing.hash).0,
        vault_balance(c, crossing.recipient_shard, crossing.recipient),
    );
}

/// Everything the cross-shard fault family's transfers can reach: the
/// crossing pair and the controls' accounts, on both children.
fn fault_family_world<C: Cluster>(c: &C) -> World {
    let cast = cross_shard_fault_cast();
    let mut holders = vec![cast.left.1.address(), cast.right.1.address()];
    for (_, payer, recipient) in &cast.controls {
        holders.push(payer.address());
        holders.push(recipient.address());
    }
    World::open(c, *PROTOCOL_RESOURCE, holders, [])
}

/// Submit the family's crossing: the left child's funded account pays the
/// right child's.
fn submit_crossing<C: Cluster>(c: &mut C, charges: &mut Charges) -> Crossing {
    let cast = cross_shard_fault_cast();
    let (_, right) = ShardId::ROOT.children();
    submit_crossing_between(c, charges, &cast.left, right, &cast.right)
}

/// Submit a crossing from `payer` into `recipient`'s account on
/// `recipient_shard`.
///
/// The recipient signs the deposit as a request the payer composes, so
/// the recipient's account is one the transaction acts as. Its shard is
/// then no mere taker of delivery, and the shape runs whole: both shards
/// commit it, the payer's bundle crosses to the recipient's shard, and
/// the recipient's engagement crosses back — the traffic this family
/// faults. A plain transfer would cross only as a record read, which no
/// bundle carries.
fn submit_crossing_between<C: Cluster>(
    c: &mut C,
    charges: &mut Charges,
    payer: &(Ed25519PrivateKey, PrincipalAddr),
    recipient_shard: ShardId,
    recipient: &(Ed25519PrivateKey, PrincipalAddr),
) -> Crossing {
    let (recipient_key, recipient) = (&recipient.0, recipient.1);
    let held_before = vault_balance(c, recipient_shard, recipient);
    let validity = validity_around(c.now());
    let tx = build_composed_tx(
        &payer.0,
        payer.1,
        recipient_key,
        &payment_request_for(recipient, CROSSING_PAYMENT, validity),
        CROSSING_PAYMENT,
        validity,
    );
    let hash = charges.submit(c, tx);
    Crossing {
        hash,
        recipient_shard,
        recipient,
        held_before,
    }
}

/// Grow to two shards, drop the `broadcast` message type, then run a cross-shard
/// transfer that must recover via the `fetch_kind` fetch fallback.
///
/// Works for any broadcast the cross-shard flow relies on — the unicast
/// bundle delivery (`provisions.broadcast`) suppressed at the sender's gate,
/// or a gossip broadcast (`transaction.gossip`, `block.committed`) suppressed
/// by the receiver's inbound filter. The transfer runs from the left child's
/// funded account into the right child's, both seeded at genesis. Faults
/// install after the split settles, so the grow rides its own broadcasts
/// cleanly. Asserts the transfer accepts and lands, the drop fired, the fetch
/// engaged, and nothing aborted.
///
/// The provisions leg is the sharpest of these on the engine: a payer's
/// bundle is the evidence its counterpart engages against, so suppressing the
/// broadcast withholds engagement itself until the fetch bridges it.
fn cross_shard_broadcast_drop(
    c: &mut impl FaultableCluster,
    broadcast: &'static str,
    fetch_kind: &'static str,
) {
    split_lifecycle(c);
    // Snapshot the fetch counter before the drop: the counter is cluster-wide
    // and monotonic, so measuring the increase isolates the fetches this outage
    // forces from any the split itself emitted (remote-header sync in particular
    // runs as normal machinery in a grown cluster, not only as a fallback).
    let fetch_before = c.metric("fetch_items_sent", Some(fetch_kind));
    let dropped = c.drop_type(broadcast);
    let world = fault_family_world(c);
    let mut charges = Charges::default();

    let crossing = submit_crossing(c, &mut charges);

    let status = await_tx_terminal(c, crossing.hash, epochs(10));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "the cross-shard transfer must settle despite the dropped {broadcast}; status = {status:?}",
    );
    await_crossed(c, &crossing, broadcast);
    world.assert_settles_within(c, &charges, epochs(8), broadcast);
    assert!(dropped.fired() >= 1, "the {broadcast} drop must fire");
    assert!(
        c.metric("fetch_items_sent", Some(fetch_kind)) > fetch_before,
        "the {fetch_kind} fetch fallback must engage (before={fetch_before})",
    );
    assert_eq!(
        c.metric("transactions_aborted", None),
        0,
        "the cross-shard transfer must not abort",
    );
}

/// Dropping `provisions.broadcast` still settles a cross-shard transfer — the
/// destination shard fetches the provisions rather than receiving them.
///
/// # Panics
///
/// Panics if the transfer does not settle, the drop never fires, the provision
/// fetch never engages, or anything aborts.
pub fn cross_shard_provisions_drop_fetch_fallback(c: &mut impl FaultableCluster) {
    cross_shard_broadcast_drop(c, "provisions.broadcast", "provision");
}

/// Dropping `execution.cert.batch` changes nothing for a divided transfer.
///
/// Nothing waits on a certificate from across the split, so the transfer
/// lands and credits as it would with the channel open. The payer's chain settles the transfer on its own verdict, and the
/// recipient commits the delivery off the payer's committed bundle, never
/// off a certificate. A certificate is waited for only where a route sends
/// one shard's verdict to another — a leg with its core elsewhere — and a
/// transfer has no such edge.
///
/// # Panics
///
/// Panics if the transfer does not settle and land, or anything aborts.
pub fn cross_shard_exec_cert_drop_is_inert(c: &mut impl FaultableCluster) {
    split_lifecycle(c);
    let _dropped = c.drop_type("execution.cert.batch");
    let world = fault_family_world(c);
    let mut charges = Charges::default();

    let crossing = submit_crossing(c, &mut charges);

    let status = await_tx_terminal(c, crossing.hash, epochs(10));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "the transfer must settle with execution.cert.batch dropped; status = {status:?}",
    );
    await_crossed(c, &crossing, "execution.cert.batch");
    world.assert_settles_within(c, &charges, epochs(8), "execution.cert.batch");
    assert_eq!(
        c.metric("transactions_aborted", None),
        0,
        "the cross-shard transfer must not abort",
    );
}

/// Dropping BOTH `provisions.broadcast` and `execution.cert.batch` at once
/// still settles a cross-shard transfer.
///
/// The provision fetch bridges the bundle, and the certificate channel has
/// nothing a divided transfer waits on.
///
/// # Panics
///
/// Panics if the transfer does not settle and land, the bundle drop never
/// fires, the provision fetch never engages, or anything aborts.
pub fn cross_shard_compound_drop_fetch_fallback(c: &mut impl FaultableCluster) {
    split_lifecycle(c);
    let provision_before = c.metric("fetch_items_sent", Some("provision"));
    let provisions_dropped = c.drop_type("provisions.broadcast");
    let _exec_cert_dropped = c.drop_type("execution.cert.batch");
    let world = fault_family_world(c);
    let mut charges = Charges::default();

    let crossing = submit_crossing(c, &mut charges);

    let status = await_tx_terminal(c, crossing.hash, epochs(12));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "the transfer must settle despite both channels dropped; status = {status:?}",
    );
    await_crossed(c, &crossing, "compound-drop");
    world.assert_settles_within(c, &charges, epochs(8), "compound-drop");
    assert!(
        provisions_dropped.fired() >= 1,
        "the provisions.broadcast drop must fire",
    );
    assert!(
        c.metric("fetch_items_sent", Some("provision")) > provision_before,
        "the provision fetch fallback must engage (before={provision_before})",
    );
    assert_eq!(
        c.metric("transactions_aborted", None),
        0,
        "the compound cross-shard transfer must not abort",
    );
}

/// Dropping `transaction.gossip` in a grown cluster still settles a cross-shard
/// transfer — the source committee fetches the transaction body (the DA
/// fallback) rather than receiving it by gossip.
///
/// # Panics
///
/// Panics if the transfer does not settle, the drop never fires, the transaction
/// fetch never engages, or anything aborts.
pub fn cross_shard_transaction_da_fetch_fallback(c: &mut impl FaultableCluster) {
    cross_shard_broadcast_drop(c, "transaction.gossip", "transaction");
}

/// Dropping `block.committed` still settles a cross-shard transfer — the shard
/// tracking its counterpart's committed headers fetches them via the
/// remote-header sync rather than receiving them by gossip.
///
/// # Panics
///
/// Panics if the transfer does not settle, the drop never fires, the
/// remote-header fetch never engages, or anything aborts.
pub fn cross_shard_header_fetch_fallback(c: &mut impl FaultableCluster) {
    cross_shard_broadcast_drop(c, "block.committed", "remote_header");
}

/// A cross-shard transfer settles under unreliable request RPC.
///
/// Provisions never broadcast — forcing the provision fetch fallback — AND half
/// of every `provision.request` leg is dropped, so each fetch attempt is a
/// coin-flip that must be retried until one gets through. Proves the
/// request-manager retry path recovers a fetch under probabilistic request
/// loss without aborting.
///
/// The 50% loss is exercised per attempt on both harnesses: the sim draws from
/// the engine's own seeded RNG at the request-drain site, and production
/// consults the same gate in the iroh request streams per send, surfacing a
/// dropped leg as the timeout the retry loop rolls again.
///
/// Returns the cluster-wide `provision.request` drop count. Engagement is
/// deterministic on the sim — the wiring asserts it per seed — but not on
/// production, where the async retry path can settle the fetch on an undropped
/// first leg, so a caller there asserts only the liveness invariants this body
/// checks. All other invariants (settle, broadcast dropped, fetch engaged, zero
/// aborts) hold on both.
///
/// # Panics
///
/// Panics if the split children's committees share a host, the transfer fails
/// to settle, the broadcast drop never fires, the provision fetch never
/// engages, or anything aborts.
pub fn cross_shard_provisions_fetch_with_request_loss(c: &mut impl FaultableCluster) -> u64 {
    split_lifecycle(c);
    let (payer_shard, recipient_shard) = ShardId::ROOT.children();
    committees_on_separate_hosts(c, payer_shard, recipient_shard);
    let fetch_before = c.metric("fetch_items_sent", Some("provision"));
    let broadcast_dropped = c.drop_type("provisions.broadcast");
    let request_dropped = c.drop_type_with_probability("provision.request", 0.5);
    let world = fault_family_world(c);
    let mut charges = Charges::default();

    let crossing = submit_crossing(c, &mut charges);

    let status = await_tx_terminal(c, crossing.hash, epochs(12));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "the transfer must settle despite 50% provision.request loss; status = {status:?}",
    );
    await_crossed(c, &crossing, "request-loss");
    world.assert_settles_within(c, &charges, epochs(8), "request-loss");
    assert!(
        broadcast_dropped.fired() >= 1,
        "the provisions.broadcast drop must fire",
    );
    assert!(
        c.metric("fetch_items_sent", Some("provision")) > fetch_before,
        "the provision fetch fallback must engage (before={fetch_before})",
    );
    assert_eq!(
        c.metric("transactions_aborted", None),
        0,
        "the transfer must not abort under request loss",
    );

    request_dropped.fired()
}

/// A transient `provisions.broadcast` outage recovers even when the fault lifts
/// mid-flight.
///
/// Drop the broadcast, submit a cross-shard transfer, and hold the outage
/// until it has bitten the bundle that matters: the payer's chain sends one
/// bundle when it commits the transfer and another, carrying the crossing
/// the recipient's delivery rides, when it commits the finalization. Only
/// the second withholds the delivery, so the fault holds until the payer's
/// chain has finalized. Then lift it and confirm the delivery still lands
/// via the provision fetch fallback with nothing aborting. A dropped
/// bundle is not re-emitted on lift, so the recipient recovers by fetch
/// either way; the point is that removing a live drop rule mid-recovery is
/// safe — the fetch bridge completes and no tick wedges.
///
/// One transfer, not two: both accounts of the crossing pair are declared
/// writes of every transfer between them, so a second overlapping cross-shard
/// transfer would race the first's conflict window rather than test recovery.
///
/// # Panics
///
/// Panics if the payer's chain fails to finalize the transfer, the outage
/// never fired, the transfer fails to land, the provision fetch never
/// engaged, or anything aborts.
pub fn cross_shard_provisions_recovers_after_transient_outage(c: &mut impl FaultableCluster) {
    split_lifecycle(c);
    let (payer_shard, _) = ShardId::ROOT.children();
    let fetch_before = c.metric("fetch_items_sent", Some("provision"));
    let dropped = c.drop_type("provisions.broadcast");
    let world = fault_family_world(c);
    let mut charges = Charges::default();

    let crossing = submit_crossing(c, &mut charges);

    // Let the outage bite the crossing bundle: the payer's chain finalizes
    // the transfer and the bundle its finalizing block sends is dropped
    // before we lift the fault, so the recovery genuinely spans a removal.
    let finalized = c.run_until(epochs(8), |c| {
        c.chain_fate(payer_shard, crossing.hash).1.is_some()
    });
    assert!(
        finalized,
        "the payer's chain must finalize the transfer before the outage lifts",
    );
    assert!(
        dropped.fired() >= 1,
        "the provisions.broadcast drop must fire before the outage lifts",
    );
    c.clear_drops();

    let status = await_tx_terminal(c, crossing.hash, epochs(10));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "the transfer must settle via the provision fetch despite the transient \
         outage; status = {status:?}",
    );
    await_crossed(c, &crossing, "transient-outage");
    world.assert_settles_within(c, &charges, epochs(8), "transient-outage");
    assert!(
        c.metric("fetch_items_sent", Some("provision")) > fetch_before,
        "the provision fetch fallback must bridge the outage (before={fetch_before})",
    );
    assert_eq!(
        c.metric("transactions_aborted", None),
        0,
        "the transfer must not abort",
    );
}

/// Every channel a beacon commit needs, the proposal fetch included. With all
/// eight dropped the committee never reaches its vote threshold, so each
/// epoch commits as a skip block: the topology schedule keeps advancing —
/// shards stay live and keep crossing epoch cuts — while no shard
/// contribution seats.
pub const BEACON_COMMIT_CHANNELS: [&str; 8] = [
    "beacon.proposal",
    "beacon.proposal.request",
    "beacon.spc.new_view",
    "beacon.spc.new_commit",
    "beacon.spc.empty_view",
    "beacon.pc.vote1",
    "beacon.pc.vote2",
    "beacon.pc.vote3",
];

/// Epochs the beacon spends committing skips.
const SUPPRESSED_EPOCHS: u32 = 3;

/// The anchor epoch of the reveal chain the fold last seeded from `shard`.
///
/// `record_boundaries` stamps `ShardBoundary::weighted_timestamp` from the
/// crossing header's parent QC on exactly the folds that seed, so the anchor
/// epoch a fold closed reads straight off the boundary record. The identity
/// holds while no crossing is fenced — a fenced crossing records without
/// seeding — which is the case whenever no halt recovery is pending.
fn folded_anchor_epoch<C: Cluster>(c: &C, shard: ShardId) -> Option<Epoch> {
    let state = c.beacon_state()?;
    let boundary = state.boundaries.get(&shard)?;
    Some(
        state
            .chain_config
            .epoch_windows()
            .epoch_for(boundary.weighted_timestamp),
    )
}

/// A beacon that lags across several epochs folds one crossing on resumption
/// and drops the reveal chains of every epoch it skipped.
///
/// The fold seeds `state.randomness` from one chain value per crossing, and a
/// chain is per-epoch: nothing carries an unfolded epoch's reveals forward, so
/// entropy the shard produced while the beacon was blind is gone rather than
/// deferred. This prices that loss. Suppressing the commit channels leaves
/// epoch production running on skip blocks, so the shard keeps producing and
/// crossing cuts throughout; on resumption the sourcing rule anchors the
/// newest crossing and the epochs between the last fold and that crossing
/// never contribute.
///
/// The loss is one reveal chain per beacon epoch committed between the two
/// folds: the fold cannot skip an epoch it was awake for, and the first
/// commit to seat a contribution folds the newest crossing. Those epochs are
/// the skip blocks the outage forces, and with them a slot whose proposals
/// went out while the channels were shut: its members feed whatever partial
/// vectors their fetches recover once the channels reopen, and vectors that
/// disagree commit empty. So the loss counts the beacon epochs that seated
/// nothing up to the resuming fold, not the skips standing when the channels
/// reopen. A healthy-beacon control runs first, pinning the awake fold at one
/// anchor epoch closed per step, so the gap the outage opens cannot be
/// mistaken for one the fold leaves anyway.
///
/// # Panics
///
/// Panics if no crossing folds before the outage, the awake fold leaves a gap
/// of its own, the beacon stops committing (freezing the shard rather than
/// lagging it), the suppression fails to stall the fold, the fold never
/// resumes, or the skipped span differs from the beacon epochs that seated
/// nothing between the two folds.
pub fn beacon_lag_drops_skipped_epochs_reveal_chains(c: &mut impl FaultableCluster) {
    let shard = ShardId::ROOT;

    // A seeded genesis record reads as anchor epoch 0, and so does the first
    // crossing (the one into epoch 1, anchored below the cut it crosses), so
    // only an anchor epoch past 0 proves a real crossing folded.
    assert!(
        c.run_until(epochs(8), |c| folded_anchor_epoch(c, shard)
            .is_some_and(|e| e.inner() >= 1)),
        "the fold must seed from a crossing before the outage",
    );
    let warmed = folded_anchor_epoch(c, shard)
        .expect("a folded crossing")
        .inner();

    // Control: an awake beacon closes every anchor epoch, so the next fold
    // steps by exactly one. Without this the outage measurement below could
    // be reading a gap the fold leaves anyway.
    assert!(
        c.run_until(epochs(3), |c| folded_anchor_epoch(c, shard)
            .is_some_and(|e| e.inner() > warmed)),
        "the fold must close an anchor epoch while the beacon is awake",
    );
    let before = folded_anchor_epoch(c, shard)
        .expect("a folded crossing")
        .inner();
    assert_eq!(
        before - warmed,
        1,
        "an awake beacon must leave no gap: folded {warmed} then {before}",
    );
    let epoch_before = beacon_epoch(c).expect("a committed beacon epoch").inner();

    for channel in BEACON_COMMIT_CHANNELS {
        c.drop_type(channel);
    }
    c.run_until(epochs(SUPPRESSED_EPOCHS), |_| false);
    let during = folded_anchor_epoch(c, shard)
        .expect("the boundary record survives the outage")
        .inner();
    let skip_blocks = beacon_epoch(c).expect("a committed beacon epoch").inner() - epoch_before;
    assert!(
        skip_blocks > 0,
        "the beacon must keep committing skip blocks through the outage, \
         or the shard freezes at the schedule head instead of lagging",
    );
    assert_eq!(
        during, before,
        "a beacon committing only skips must seat no contribution",
    );
    c.clear_drops();

    assert!(
        c.run_until(epochs(10), |c| folded_anchor_epoch(c, shard)
            .is_some_and(|e| e.inner() > before)),
        "the fold must resume once the commit channels reopen",
    );
    let after = folded_anchor_epoch(c, shard)
        .expect("a folded crossing")
        .inner();
    let epoch_after = beacon_epoch(c).expect("a committed beacon epoch").inner();

    // Anchor epochs strictly between the two folds contributed nothing, one
    // for each beacon epoch committed between them.
    let unseated = epoch_after - epoch_before - 1;
    let skipped = after - before - 1;
    assert_eq!(
        skipped, unseated,
        "{unseated} beacon epochs seating nothing must cost exactly that \
         many epochs' reveal chains, but skipped {skipped} (folded {before} \
         then {after})",
    );
}
