//! HotStuff-2 implicit view-change invariants pinned by the shard
//! sim.

mod common;

use std::time::Duration;

use common::{HoldFilter, ShardCoordinatorSim};
use hyperscale_types::{
    BlockHeight, MAX_PROGRESS_WAIT, Round, VIEW_CHANGE_TIMEOUT, VIEW_CHANGE_TIMEOUT_INCREMENT,
    ValidatorId,
};

const MAX_STEPS: usize = 5_000;

/// A silent round-1 leader stalls the chain: while its headers are
/// withheld no replica commits, and past `MAX_PROGRESS_WAIT` every
/// replica self-times-out and advances its round.
///
/// Rounds increase per block, so `proposer_for(shard=0, r=1) =
/// committee[1] = idx 1`. Holding idx 1's outbound headers at every
/// other replica models a leader that builds locally but is never heard.
#[test]
fn silent_leader_triggers_view_change() {
    let mut sim = ShardCoordinatorSim::new(4, 0x57_E1);
    let silent_leader = ValidatorId::new(1);

    for idx in 0..sim.n() {
        let replica = ValidatorId::new(idx as u64);
        if replica == silent_leader {
            continue;
        }
        sim.hold_matching(replica, HoldFilter::BlockHeaderFromProposer(silent_leader));
    }

    sim.kick_off();
    // Drain whatever the silent leader emitted; its headers land
    // in the held buffers and any votes go nowhere useful.
    sim.run_for_at_most(100);

    for idx in 0..sim.n() {
        assert_eq!(
            sim.commits[idx].len(),
            0,
            "replica {idx} committed despite silent leader",
        );
    }

    // Past `MAX_PROGRESS_WAIT`, the `has_pending_at_tip`
    // suppression in `should_advance_round` lifts and the timer
    // fires even though the silent leader's own pending block is
    // sitting on its local tip.
    sim.advance_clock(MAX_PROGRESS_WAIT + Duration::from_millis(100));
    sim.fire_view_change_timer_all();

    // Every replica advances past the silent round-1 slot (round 2's
    // leader is a different proposer, idx 2) and counts the self-timeout.
    for idx in 0..sim.n() {
        assert!(
            sim.coordinators[idx].view().inner() >= 2,
            "replica {idx} view didn't advance past round 1: {}",
            sim.coordinators[idx].view().inner(),
        );
        assert!(
            sim.coordinators[idx].stats().view_changes >= 1,
            "replica {idx} view_changes counter didn't increment: {}",
            sim.coordinators[idx].stats().view_changes,
        );
    }
}

/// Local view changes vs. view syncs:
///
/// - `view_changes` ticks when the replica self-times-out.
/// - `view_syncs` ticks when the replica catches up to a
///   higher-round QC / header / vote it observed.
///
/// Silence idx 1 (round-1 leader). Fire the timer on idx 1, 2, 3
/// only — they bump `view_changes`. Idx 0 stays untouched until
/// the round-2 leader's header arrives; `sync_view_to_header_round`
/// then bumps idx 0's `view_syncs` (not `view_changes`).
#[test]
fn view_sync_via_higher_round_header_does_not_increment_view_changes() {
    let mut sim = ShardCoordinatorSim::new(4, 0x5C_60);
    let silent_leader = ValidatorId::new(1);

    // Hold the silent round-1 leader's headers at every receiver, so
    // round 1 never forms a QC. The round-2 leader is a different
    // proposer, so its header flows through and drives the view sync
    // on idx 0.
    for idx in 0..sim.n() {
        let replica = ValidatorId::new(idx as u64);
        if replica == silent_leader {
            continue;
        }
        sim.hold_matching(replica, HoldFilter::BlockHeaderFromProposer(silent_leader));
    }
    sim.kick_off();
    sim.run_for_at_most(100);
    sim.advance_clock(MAX_PROGRESS_WAIT + Duration::from_millis(100));

    // Idx 0 stays at its fresh view and must catch up via observed
    // header round.
    sim.fire_view_change_timer(ValidatorId::new(1));
    sim.fire_view_change_timer(ValidatorId::new(2));
    sim.fire_view_change_timer(ValidatorId::new(3));

    assert_eq!(
        sim.coordinators[0].view(),
        Round::new(1),
        "idx 0 must remain at its fresh view (round 1) before observing a higher-round header",
    );
    assert_eq!(
        sim.coordinators[0].stats().view_changes,
        0,
        "idx 0 must not have self-timed-out yet",
    );

    // Release the holds. The filter only matches the silent
    // leader's headers, so this just empties the held buffers.
    for idx in 0..sim.n() {
        let replica = ValidatorId::new(idx as u64);
        if replica != silent_leader {
            sim.release_held(replica);
        }
    }

    sim.run_for_at_most(MAX_STEPS);

    assert!(
        sim.coordinators[0].view().inner() >= 1,
        "idx 0's view didn't catch up; still {:?}",
        sim.coordinators[0].view(),
    );
    assert!(
        sim.coordinators[0].stats().view_syncs >= 1,
        "idx 0's view_syncs counter didn't increment: {}",
        sim.coordinators[0].stats().view_syncs,
    );
    assert_eq!(
        sim.coordinators[0].stats().view_changes,
        0,
        "idx 0 reported a local view-change despite never firing its own timer",
    );
}

/// Linear backoff: after `K` consecutive view changes at the
/// same height, `current_view_change_timeout` is
/// `VIEW_CHANGE_TIMEOUT + K * VIEW_CHANGE_TIMEOUT_INCREMENT`.
///
/// Skip `kick_off` entirely so no leader activity ever resets the
/// timer, then drive each iteration with `advance_clock` past the
/// per-round timeout + `fire_view_change_timer_all`.
#[test]
fn linear_backoff_grows_timeout_per_consecutive_view_change() {
    let mut sim = ShardCoordinatorSim::new(4, 0xBA_C0);
    // `initialize_genesis` records last_leader_activity at now=0;
    // r=0, no commits.
    assert_eq!(
        sim.coordinators[0].current_view_change_timeout(),
        VIEW_CHANGE_TIMEOUT
    );

    for k in 1u32..=3 {
        let prev_timeout = sim.coordinators[0].current_view_change_timeout();
        sim.advance_clock(prev_timeout + Duration::from_millis(100));
        sim.fire_view_change_timer_all();
        // With no leader activity in between, every replica
        // advances every iteration.
        for idx in 0..sim.n() {
            assert_eq!(
                sim.coordinators[idx].stats().view_changes,
                u64::from(k),
                "replica {idx} view_changes count after iteration {k}",
            );
        }
        let expected = VIEW_CHANGE_TIMEOUT + VIEW_CHANGE_TIMEOUT_INCREMENT * k;
        let actual = sim.coordinators[0].current_view_change_timeout();
        assert_eq!(
            actual, expected,
            "after {k} view changes timeout should be {expected:?}, got {actual:?}",
        );
    }
}

/// HotStuff-2's round-fail unlock rule: a view change at `H` with
/// no QC at `H` clears the local `voted_heights` lock — quorum
/// intersection guarantees no conflicting QC can form
/// retroactively.
///
/// Idx 1 is the h=1 r=1 leader; deafening idx 2 and idx 3 leaves only
/// idx 0 and the leader active, two votes short of the 3-vote quorum,
/// so no QC forms and idx 0's lock survives long enough to assert
/// against.
#[test]
fn view_change_unlocks_voted_height_when_no_qc_formed() {
    let mut sim = ShardCoordinatorSim::new(4, 0x10_C8);
    sim.drop_for(ValidatorId::new(2), 10_000);
    sim.drop_for(ValidatorId::new(3), 10_000);
    sim.kick_off();
    // Idx 0 receives idx 1's header, verifies, votes. Only idx 0 and
    // the leader stay active — two votes can't reach quorum, so no QC
    // forms.
    sim.run_for_at_most(500);

    assert!(
        sim.coordinators[0]
            .voted_heights()
            .contains_key(&BlockHeight::new(1)),
        "idx 0 should hold a vote lock at h=1 before view change",
    );
    assert!(
        sim.coordinators[0].latest_qc().is_none(),
        "no QC must have formed at h=1 — that's the precondition for the unlock rule",
    );

    // Past `MAX_PROGRESS_WAIT` the pending-block-at-tip
    // suppression in `should_advance_round` lifts.
    sim.advance_clock(MAX_PROGRESS_WAIT + Duration::from_millis(100));
    sim.fire_view_change_timer(ValidatorId::new(0));

    assert!(
        sim.coordinators[0].stats().view_changes >= 1,
        "idx 0 view_changes must have ticked",
    );
    assert!(
        !sim.coordinators[0]
            .voted_heights()
            .contains_key(&BlockHeight::new(1)),
        "idx 0 vote lock at h=1 must clear after view change with no QC formed",
    );
}
