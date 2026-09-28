//! End-to-end vnode movement across a shard committee rotation.
//!
//! Boots a 2-shard network, runs past the shuffle-interval boundary,
//! and — unlike [`topology_rotation`], which only checks that
//! cross-shard *verification* survives the rotation — actually moves
//! the vnodes the rotation names. A rotation is make before break, so it
//! moves two: the entrant seats first and the victim retires once the
//! entrant is ready, and this test follows both halves.
//!
//! The entrant's lookahead placement delta surfaces through
//! `StepOutput`, the harness snap-syncs its shard against the
//! beacon-attested anchor (the same sans-io `ShardBootstrap` sequencer
//! production pumps), seats the vnode, and the protocol does the rest —
//! tail sync, the self-signed `ReadySignal`, the fold flipping `ready:
//! true`, and consensus participation. That readiness is what retires
//! the victim: its seat drains, the shard keeps committing without it,
//! and a rejoin with the retained storage takes the fast path with no
//! snap-sync.

use std::fmt::Write as _;
use std::time::Duration;

use hyperscale_core::ParticipationChange;
use hyperscale_network_memory::NodeIndex;
use hyperscale_simulation::{EPOCH_MS, JoinKind, SimulationRunner};
use hyperscale_storage::ShardChainReader;
use hyperscale_storage_memory::SimShardStorage;
use hyperscale_types::{
    BeaconChainConfig, BlockHeight, ShardId, ValidatorId, ValidatorStatus, shard_prefix_path,
};
use tracing_test::traced_test;

mod support;

use support::{PER_SHARD, SimCluster, committee_member_host, discard, rotation_config};

/// Seed for the grown placement the rotation runs against.
const SEED: u64 = 7;

/// Epochs past the shuffle boundary the placement delta gets to
/// surface through `StepOutput`.
const SHUFFLE_SLACK_EPOCHS: u64 = 4;

/// Epochs the joiner gets to tail-sync and flip `ready: true`. The
/// budget is liveness slack only; the flip being signal-driven rather
/// than the `ready_timeout_epochs` backstop is asserted separately
/// against the flip epoch.
const READY_BUDGET_EPOCHS: u64 = 6;

/// Epochs the seated mover gets to land a committed proposal in the
/// destination shard.
const PROPOSAL_BUDGET_EPOCHS: u64 = 12;

/// Epochs the drained origin shard gets to demonstrate liveness
/// without the mover.
const DRAIN_BUDGET_EPOCHS: u64 = 4;

/// Run in one-second slices until `predicate` holds or `deadline`
/// passes, draining placement deltas into `moves` along the way.
fn run_until_or(
    runner: &mut SimulationRunner,
    deadline: Duration,
    moves: &mut Vec<(NodeIndex, ParticipationChange)>,
    mut predicate: impl FnMut(&SimulationRunner) -> bool,
) -> bool {
    while runner.now() < deadline {
        let next = runner.now() + Duration::from_secs(1);
        runner.run_until(next);
        moves.extend(runner.take_participation_changes());
        if predicate(runner) {
            return true;
        }
    }
    false
}

/// The shard's consensus committee must be at full strength on every
/// slice of every wait below — that is what make-before-break buys.
/// A rotation may carry a fifth member, but the set that votes holds at
/// `shard_size`, so `quorum_threshold` never tightens and neither end of
/// the sync window costs a view change.
fn assert_at_strength(runner: &SimulationRunner, shard: ShardId) {
    let topology = runner.host_topology(0).expect("host 0 holds a topology");
    let consensus = topology.consensus_committee_for_shard(shard);
    assert_eq!(
        consensus.len(),
        PER_SHARD as usize,
        "consensus committee for {shard:?} dipped to {consensus:?}",
    );
}

/// Run in one-second slices until `found` picks a delta out of the
/// deltas collected so far, or `deadline` passes, running `on_slice`
/// over the runner each time round.
fn run_until_delta(
    runner: &mut SimulationRunner,
    deadline: Duration,
    moves: &mut Vec<(NodeIndex, ParticipationChange)>,
    found: impl Fn(&ParticipationChange) -> bool,
    on_slice: impl Fn(&SimulationRunner),
) -> Option<(NodeIndex, ValidatorId, ShardId)> {
    let picked = |moves: &[(NodeIndex, ParticipationChange)]| {
        moves.iter().find(|(_, c)| found(c)).map(|(node, c)| {
            let shard = c.join.or(c.leave).expect("a picked delta names a shard");
            (*node, c.validator, shard)
        })
    };
    while runner.now() < deadline {
        if let Some(delta) = picked(moves) {
            return Some(delta);
        }
        let next = runner.now() + Duration::from_secs(1);
        runner.run_until(next);
        moves.extend(runner.take_participation_changes());
        on_slice(runner);
    }
    picked(moves)
}

/// The mover's status in the latest committed beacon state, read from
/// its own host's fold.
fn mover_status(
    runner: &SimulationRunner,
    node: NodeIndex,
    validator: ValidatorId,
) -> Option<ValidatorStatus> {
    let (_, state) = runner.beacon_storage(node)?.latest_committed()?;
    state.validators.get(&validator).map(|r| r.status)
}

#[traced_test]
#[test]
#[allow(clippy::too_many_lines)] // one relocation lifecycle asserted end to end
fn vnode_moves_through_a_committee_rotation() {
    let mut cluster = SimCluster::with_dedicated_pool_hosts(&rotation_config(), SEED);
    let runner = cluster.runner_mut();
    // Grow the single-shard genesis into the two shards the shuffle rotates,
    // then discard the grow's placement deltas so only the shuffle's move is
    // collected below.
    runner.grow_to(2);
    let _ = runner.take_participation_changes();

    // ── Make: the first shuffle seats an entrant ────────────────────
    let (_, chain_state) = runner
        .beacon_storage(0)
        .expect("host 0 exists")
        .latest_committed()
        .expect("beacon committed");
    let shuffle_interval = chain_state.chain_config.shuffle_interval_epochs();
    let shuffle = Duration::from_millis(EPOCH_MS * (shuffle_interval + SHUFFLE_SLACK_EPOCHS));
    let mut moves: Vec<(NodeIndex, ParticipationChange)> = Vec::new();
    let (node, validator, to) = run_until_delta(
        &mut *runner,
        shuffle,
        &mut moves,
        |c| c.join.is_some(),
        |_| {},
    )
    .unwrap_or_else(|| discard(&format!("the shuffle seated no entrant; got {moves:?}")));

    // ── Join: snap-sync bootstrap against the attested anchor ───────
    // The harness runs the same `ShardBootstrap` sequencing production
    // does; the sequencer itself verifies the imported root against the
    // anchor, so a successful SnapSync return IS the root == anchor
    // assertion.
    let kind = runner.join_shard(
        node,
        validator,
        to,
        SimShardStorage::new(shard_prefix_path(to)),
    );
    let JoinKind::SnapSync { anchor_height } = kind else {
        panic!("fresh store must take the snap-sync path, got {kind:?}");
    };
    assert!(
        anchor_height > BlockHeight::GENESIS,
        "the anchor must be a real epoch boundary, not genesis"
    );

    // ── Ready: tail sync completes and the fold flips the flag ──────
    // The joiner's self-signed ReadySignal must flip `ready: true`
    // within a few epochs.
    let ready_deadline = runner.now() + Duration::from_millis(EPOCH_MS * READY_BUDGET_EPOCHS);
    let became_ready = run_until_or(&mut *runner, ready_deadline, &mut moves, |r| {
        assert_at_strength(r, to);
        matches!(
            mover_status(r, node, validator),
            Some(ValidatorStatus::OnShard { shard, ready: true, .. }) if shard == to
        )
    });
    assert!(
        became_ready,
        "joiner must flip ready:true via its ReadySignal within \
         {READY_BUDGET_EPOCHS} epochs"
    );
    // The flip must beat the auto-ready backstop: the committed state
    // that first shows `ready: true` sits before `placed_at_epoch +
    // ready_timeout_epochs`, so the fold consumed the mover's
    // ReadySignal witness — the timeout fallback could not have fired
    // yet.
    let ready_timeout = BeaconChainConfig::default().ready_timeout_epochs;
    let (_, flip_state) = runner
        .beacon_storage(node)
        .expect("mover host has beacon storage")
        .latest_committed()
        .expect("beacon chain is committed");
    let Some(ValidatorStatus::OnShard {
        placed_at_epoch, ..
    }) = flip_state.validators.get(&validator).map(|r| r.status)
    else {
        panic!("mover must be OnShard in the flip-epoch state");
    };
    assert!(
        flip_state.current_epoch.inner() < placed_at_epoch.inner() + ready_timeout,
        "ready flip at epoch {} is not signal-driven: the auto-ready \
         timeout (placed {} + {ready_timeout}) had already matured",
        flip_state.current_epoch.inner(),
        placed_at_epoch.inner(),
    );

    // ── Participation: the mover follows, votes, and proposes in B ──
    let watch_from = runner
        .vnode_state_in(node, to)
        .expect("joined shard is hosted")
        .shard_coordinator()
        .committed_height();
    let proposed_deadline = runner.now() + Duration::from_millis(EPOCH_MS * PROPOSAL_BUDGET_EPOCHS);
    let proposed = run_until_or(&mut *runner, proposed_deadline, &mut moves, |r| {
        assert_at_strength(r, to);
        // Resolve the observer afresh each poll: a shuffle can rotate
        // the member chosen at watch start out of the committee, and an
        // ex-member's vnode freezes below the heights where the mover's
        // proposals commit.
        let (peer, _) = committee_member_host(r, to, Some(node));
        let tip = r
            .vnode_state_in(peer, to)
            .expect("member host carries the shard")
            .shard_coordinator()
            .committed_height();
        let storage = r
            .hosts_shard(peer, to)
            .expect("member host serves the shard");
        (watch_from.inner()..=tip.inner()).any(|h| {
            storage
                .get_block(BlockHeight::new(h))
                .is_some_and(|block| block.block().header().proposer() == validator)
        })
    });
    if !proposed {
        let (peer, _) = committee_member_host(&*runner, to, Some(node));
        let peer_tip = runner
            .vnode_state_in(peer, to)
            .map(|s| s.shard_coordinator().committed_height());
        let mover_tip = runner
            .vnode_state_in(node, to)
            .map(|s| s.shard_coordinator().committed_height());
        let mut per_member = String::new();
        if let Some((_, state)) = runner
            .beacon_storage(node)
            .and_then(|b| b.latest_committed())
        {
            for m in state.shard_consensus_members.get(&to).into_iter().flatten() {
                let h = runner.network().validator_to_node(*m);
                let tip = runner
                    .vnode_state_in(h, to)
                    .map(|s| s.shard_coordinator().committed_height());
                let _ = write!(per_member, "\n  v{m:?} host{h} tip={tip:?}");
            }
        }
        panic!(
            "no committed proposal from the mover in {to:?}; watch_from={watch_from:?} \
             peer={peer} peer_tip={peer_tip:?} mover_tip={mover_tip:?} \
             validator={validator:?} consensus members:{per_member}"
        );
    }
    let mover_tip = runner
        .vnode_state_in(node, to)
        .expect("joined shard is hosted")
        .shard_coordinator()
        .committed_height();
    assert!(
        mover_tip > anchor_height,
        "the joiner must follow the new shard's chain past its snap-sync anchor"
    );

    // ── Windowed witness commitment: the cycle ran under a moved base ─
    // The ready flip above IS a folded Ready leaf, so the destination
    // shard's witness window base has advanced past zero by now — the
    // mover's proposals and votes above verified windowed roots with a
    // nonzero base, and its snap-sync witness fetch assembled a window,
    // not the full history (a full-history transfer cannot verify
    // against a windowed root).
    let (_, beacon_state) = runner
        .beacon_storage(node)
        .expect("mover host has beacon storage")
        .latest_committed()
        .expect("beacon chain is committed");
    assert!(
        beacon_state
            .window
            .witness_bases
            .get(&to)
            .is_some_and(|base| base.inner() > 0),
        "the destination shard's witness window base must have advanced \
         past zero once the mover's Ready leaf folded"
    );

    // ── Break: the entrant's readiness retires the victim ───────────
    // The seat the entrant synced into is the one the rotation has been
    // holding open, so the victim leaves the very shard it joined.
    let retire_deadline = runner.now() + Duration::from_millis(EPOCH_MS * DRAIN_BUDGET_EPOCHS);
    let (victim_node, victim, from) = run_until_delta(
        &mut *runner,
        retire_deadline,
        &mut moves,
        move |c| c.leave == Some(to),
        move |r| assert_at_strength(r, to),
    )
    .unwrap_or_else(|| panic!("a ready entrant must retire its rotation's victim; got {moves:?}"));
    assert_ne!(
        victim, validator,
        "a rotation retires the member it replaces"
    );

    // ── Drain: the retired seat tears down and the shard stays live ──
    assert!(
        !matches!(
            mover_status(&*runner, victim_node, victim),
            Some(ValidatorStatus::OnShard { shard, .. }) if shard == from
        ),
        "the victim's window on the shard has closed"
    );
    let retained = runner.leave_shard(victim_node, from);
    let (origin_peer, _) = committee_member_host(&*runner, from, Some(victim_node));
    let origin_before = runner
        .vnode_state_in(origin_peer, from)
        .expect("origin member host")
        .shard_coordinator()
        .committed_height();
    let drain_deadline = runner.now() + Duration::from_millis(EPOCH_MS * DRAIN_BUDGET_EPOCHS);
    let origin_alive = run_until_or(&mut *runner, drain_deadline, &mut moves, |r| {
        assert_at_strength(r, from);
        r.vnode_state_in(origin_peer, from)
            .expect("origin member host")
            .shard_coordinator()
            .committed_height()
            > origin_before
    });
    assert!(
        origin_alive,
        "the shard must keep committing after the victim drains"
    );

    // ── Fast path: rejoining with retained storage skips snap-sync ──
    let kind = runner.join_shard(victim_node, victim, from, retained);
    let JoinKind::Retained { committed_height } = kind else {
        panic!("retained store must take the fast path, got {kind:?}");
    };
    assert!(committed_height > BlockHeight::GENESIS);
    // The rejoined vnode resumes exactly at the retained tip — the
    // chain survived the leave/rejoin cycle without replay. (It is no
    // longer a committee member, so it observes rather than
    // participates; member-grade catch-up is the beacon-driven join
    // path asserted above.)
    let resumed = runner
        .vnode_state_in(victim_node, from)
        .expect("rejoined shard is hosted")
        .shard_coordinator()
        .committed_height();
    assert_eq!(
        resumed, committed_height,
        "the retained chain must resume at its tip, not replay"
    );
}
