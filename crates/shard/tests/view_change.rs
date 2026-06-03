//! HotStuff-2 implicit view-change invariants pinned by the shard
//! sim.

mod common;

use std::time::Duration;

use common::{HoldFilter, ShardCoordinatorSim};
use hyperscale_types::{
    BlockHeight, MAX_PROGRESS_WAIT, VIEW_CHANGE_TIMEOUT, VIEW_CHANGE_TIMEOUT_INCREMENT, ValidatorId,
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
    // sitting on its local tip. Each replica broadcasts a timeout
    // instead of advancing locally; delivering them forms the 2f+1
    // quorum that advances every replica together.
    sim.advance_clock(MAX_PROGRESS_WAIT + Duration::from_millis(100));
    sim.fire_view_change_timer_all();
    sim.run_for_at_most(MAX_STEPS);

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
/// - `view_changes` ticks when the replica joins a timeout quorum
///   (it broadcast its own timeout, directly or via Bracha).
/// - `view_syncs` ticks when the replica catches up to a
///   higher-round QC / header / vote it observed.
///
/// Silence idx 1 (round-1 leader) so round 1 can't certify. The other
/// three time out and form a 2f+1 quorum that advances them to round 2,
/// where the non-silent leader (idx 2) proposes. The laggard idx 0 holds
/// every timeout, so it can't join the quorum and converges only when idx
/// 2's higher-round header arrives — bumping `view_syncs`, never
/// `view_changes`.
#[test]
fn view_sync_via_higher_round_header_does_not_increment_view_changes() {
    let mut sim = ShardCoordinatorSim::new(4, 0x5C_60);
    let silent_leader = ValidatorId::new(1);
    let lagging = ValidatorId::new(0);

    // Hold the silent round-1 leader's headers at every receiver, so
    // round 1 never forms a QC and the cluster has to time out.
    for idx in 0..sim.n() {
        let replica = ValidatorId::new(idx as u64);
        if replica != silent_leader {
            sim.hold_matching(replica, HoldFilter::BlockHeaderFromProposer(silent_leader));
        }
    }
    // Keep the laggard out of the timeout quorum: holding every timeout
    // means it can neither self-time-out nor Bracha-amplify, so its only
    // path past round 1 is the round-2 leader's header.
    sim.hold_matching(lagging, HoldFilter::AnyTimeout);

    sim.kick_off();
    sim.run_for_at_most(100);
    sim.advance_clock(MAX_PROGRESS_WAIT + Duration::from_millis(100));

    // idx 1, 2, 3 time out, form a 2f+1 quorum at round 1, and advance to
    // round 2; idx 2 then proposes and its header reaches idx 0.
    sim.fire_view_change_timer(ValidatorId::new(1));
    sim.fire_view_change_timer(ValidatorId::new(2));
    sim.fire_view_change_timer(ValidatorId::new(3));
    sim.run_for_at_most(MAX_STEPS);

    assert!(
        sim.coordinators[0].view().inner() >= 2,
        "idx 0 should have caught up to the round-2 leader's header; view {:?}",
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
        "idx 0 reported a local view-change despite holding every timeout",
    );
}

/// Linear backoff: after `K` consecutive view changes at the
/// same height, `current_view_change_timeout` is
/// `VIEW_CHANGE_TIMEOUT + K * VIEW_CHANGE_TIMEOUT_INCREMENT`.
///
/// Hold every proposer's header so no block ever certifies — the chain
/// stays at height 0 and consecutive timeout quorums accrue at one
/// height, which is what grows the backoff. Each iteration advances the
/// clock past both the progress-wait suppression and the current timeout,
/// fires every timer, and delivers the timeouts so the 2f+1 quorum forms.
#[test]
fn linear_backoff_grows_timeout_per_consecutive_view_change() {
    let mut sim = ShardCoordinatorSim::new(4, 0xBA_C0);
    for idx in 0..sim.n() {
        sim.hold_matching(ValidatorId::new(idx as u64), HoldFilter::AnyHeader);
    }
    // `initialize_genesis` records last_leader_activity at now=0;
    // r=1 (genesis QC round 0 + 1), no commits.
    assert_eq!(
        sim.coordinators[0].current_view_change_timeout(),
        VIEW_CHANGE_TIMEOUT
    );

    for k in 1u32..=3 {
        let prev_timeout = sim.coordinators[0].current_view_change_timeout();
        sim.advance_clock(MAX_PROGRESS_WAIT + prev_timeout + Duration::from_millis(100));
        sim.fire_view_change_timer_all();
        sim.run_for_at_most(MAX_STEPS);
        // No block certifies (headers held), so every replica advances on
        // each timeout quorum and the height-start round never rebases.
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

    // Past `MAX_PROGRESS_WAIT` the pending-block-at-tip suppression in
    // `should_advance_round` lifts. The deafened idx 2 / idx 3 still
    // broadcast their own timeouts (only their inbound is dropped), so
    // idx 0 collects a 2f+1 timeout quorum and advances + unlocks.
    sim.advance_clock(MAX_PROGRESS_WAIT + Duration::from_millis(100));
    sim.fire_view_change_timer_all();
    sim.run_for_at_most(MAX_STEPS);

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

/// Bracha amplification: only f+1 = 2 replicas self-time-out, yet every
/// replica advances. The two replicas that never fired their own timer see
/// f+1 timeouts, broadcast their own, and that amplification carries the
/// round to a full 2f+1 quorum. Without amplification two timeouts could
/// never reach the 3-power quorum.
#[test]
fn bracha_amplification_completes_quorum_from_f_plus_one() {
    let mut sim = ShardCoordinatorSim::new(4, 0xB2_AC);
    // Hold every header so the only round motion is timeout-driven.
    for idx in 0..sim.n() {
        sim.hold_matching(ValidatorId::new(idx as u64), HoldFilter::AnyHeader);
    }

    sim.advance_clock(MAX_PROGRESS_WAIT + VIEW_CHANGE_TIMEOUT + Duration::from_millis(100));
    // Only f+1 = 2 replicas fire their own timer.
    sim.fire_view_change_timer(ValidatorId::new(0));
    sim.fire_view_change_timer(ValidatorId::new(1));
    sim.run_for_at_most(MAX_STEPS);

    for idx in 0..sim.n() {
        assert!(
            sim.coordinators[idx].view().inner() >= 2,
            "replica {idx} should have advanced via the amplified quorum; view {}",
            sim.coordinators[idx].view().inner(),
        );
        assert!(
            sim.coordinators[idx].stats().view_changes >= 1,
            "replica {idx} view_changes didn't tick: {}",
            sim.coordinators[idx].stats().view_changes,
        );
    }
}

/// A lone timeout is below the f+1 amplification threshold and the 2f+1
/// advance threshold, so no replica advances.
#[test]
fn lone_timeout_does_not_advance() {
    let mut sim = ShardCoordinatorSim::new(4, 0x10_E5);
    for idx in 0..sim.n() {
        sim.hold_matching(ValidatorId::new(idx as u64), HoldFilter::AnyHeader);
    }

    sim.advance_clock(MAX_PROGRESS_WAIT + VIEW_CHANGE_TIMEOUT + Duration::from_millis(100));
    sim.fire_view_change_timer(ValidatorId::new(0));
    sim.run_for_at_most(MAX_STEPS);

    for idx in 0..sim.n() {
        assert_eq!(
            sim.coordinators[idx].view().inner(),
            1,
            "replica {idx} advanced on a single timeout (no quorum)",
        );
        assert_eq!(
            sim.coordinators[idx].stats().view_changes,
            0,
            "replica {idx} counted a view change without a 2f+1 quorum",
        );
    }
}
