//! End-to-end vnode relocation across a shard committee rotation.
//!
//! Boots a 2-shard network, runs past the `SHUFFLE_INTERVAL_EPOCHS`
//! boundary, and — unlike [`topology_rotation`], which only checks that
//! cross-shard *verification* survives the rotation — actually moves
//! the shuffled vnode: the lookahead placement delta surfaces through
//! `StepOutput`, the harness snap-syncs the destination shard against
//! its beacon-attested anchor (the same sans-io `ShardBootstrap`
//! sequencer production pumps), seats the vnode, and the protocol does
//! the rest — tail sync, the self-signed `ReadySignal`, the fold
//! flipping `ready: true`, and consensus participation in the new
//! shard. The origin shard then drains, and a rejoin with the retained
//! storage takes the fast path with no snap-sync.

use std::fmt::Write as _;
use std::time::Duration;

use hyperscale_core::ParticipationChange;
use hyperscale_network_memory::NodeIndex;
use hyperscale_simulation::{EPOCH_MS, JoinKind, SimulationRunner};
use hyperscale_storage::ShardChainReader;
use hyperscale_storage_memory::SimShardStorage;
use hyperscale_types::{
    BlockHeight, READY_TIMEOUT_EPOCHS, SHUFFLE_INTERVAL_EPOCHS, ShardId, ValidatorId,
    ValidatorStatus, shard_prefix_path,
};
use tracing_test::traced_test;

mod common;
mod support;

use common::rotation_config;
use support::sim_cluster::SimCluster;

/// Seed chosen so the epoch-16 shuffle produces a *direct* cross-shard
/// move: one shard's rotation victim is drawn straight into the other
/// shard's freed slot, yielding a single `ParticipationChange` with
/// both `join` and `leave` set on a hosted vnode. `RELOC_SEED` overrides
/// it to search for a direct move under a different grown placement.
const SEED: u64 = 7;

/// Epochs past the shuffle boundary the placement delta gets to
/// surface through `StepOutput`.
const SHUFFLE_SLACK_EPOCHS: u64 = 4;

/// Epochs the joiner gets to tail-sync and flip `ready: true` — far
/// inside `READY_TIMEOUT_EPOCHS`, so the flip is signal-driven, not
/// the timeout fallback.
const READY_BUDGET_EPOCHS: u64 = 8;

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
        moves.extend(runner.take_reconfigurations());
        if predicate(runner) {
            return true;
        }
    }
    false
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

/// A host (other than `except`) of a *current* consensus member of `shard`,
/// for reading the shard's chain from a member that tracks the live tip. A
/// shuffle rotates members out, but an ex-member's host keeps running the
/// shard as a stalled non-member, so membership must be read from the
/// committee, not from "hosts a `shard` vnode".
fn member_host(runner: &SimulationRunner, shard: ShardId, except: NodeIndex) -> NodeIndex {
    let (_, state) = runner
        .beacon_storage(except)
        .expect("host exists")
        .latest_committed()
        .expect("beacon committed");
    let members = state
        .shard_consensus_members
        .get(&shard)
        .expect("shard has a consensus committee");
    members
        .iter()
        .map(|m| runner.network().validator_to_node(*m))
        .find(|&h| h != except && runner.vnode_state_in(h, shard).is_some())
        .expect("a current consensus member host other than `except`")
}

#[traced_test]
#[test]
#[allow(clippy::too_many_lines)] // one relocation lifecycle asserted end to end
fn vnode_relocates_across_shards_at_the_shuffle() {
    let seed = std::env::var("RELOC_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(SEED);
    let mut cluster = SimCluster::with_dedicated_pool_hosts(&rotation_config(), seed, &[]);
    let runner = cluster.runner_mut();
    // Grow the single-shard genesis into the two shards the shuffle rotates,
    // then discard the grow's placement deltas so only the shuffle's move is
    // collected below.
    runner.grow_to(2);
    let _ = runner.take_reconfigurations();

    // ── Detection: the epoch-16 shuffle surfaces a direct move ──────
    let shuffle =
        Duration::from_millis(EPOCH_MS * (SHUFFLE_INTERVAL_EPOCHS + SHUFFLE_SLACK_EPOCHS));
    let mut moves: Vec<(NodeIndex, ParticipationChange)> = Vec::new();
    run_until_or(&mut *runner, shuffle, &mut moves, |_| false);
    let (node, change) = moves
        .iter()
        .find(|(_, c)| c.join.is_some() && c.leave.is_some())
        .cloned()
        .unwrap_or_else(|| {
            panic!("seed {seed} must yield a direct cross-shard move; got {moves:?}")
        });
    let validator = change.validator;
    let from = change.leave.expect("direct move carries a leave");
    let to = change.join.expect("direct move carries a join");

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
    // within a few epochs — far inside READY_TIMEOUT_EPOCHS, so the
    // flip is signal-driven, not the timeout fallback.
    let ready_deadline = runner.now() + Duration::from_millis(EPOCH_MS * READY_BUDGET_EPOCHS);
    let became_ready = run_until_or(&mut *runner, ready_deadline, &mut moves, |r| {
        matches!(
            mover_status(r, node, validator),
            Some(ValidatorStatus::OnShard { shard, ready: true, .. }) if shard == to
        )
    });
    assert!(
        became_ready,
        "joiner must flip ready:true via its ReadySignal within \
         {READY_BUDGET_EPOCHS} epochs (READY_TIMEOUT is {READY_TIMEOUT_EPOCHS})"
    );

    // ── Participation: the mover follows, votes, and proposes in B ──
    let watch_from = runner
        .vnode_state_in(node, to)
        .expect("joined shard is hosted")
        .shard_coordinator()
        .committed_height();
    let peer = member_host(&*runner, to, node);
    let proposed_deadline = runner.now() + Duration::from_millis(EPOCH_MS * PROPOSAL_BUDGET_EPOCHS);
    let proposed = run_until_or(&mut *runner, proposed_deadline, &mut moves, |r| {
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
            .witness_window_bases
            .get(&to)
            .is_some_and(|base| base.inner() > 0),
        "the destination shard's witness window base must have advanced \
         past zero once the mover's Ready leaf folded"
    );

    // ── Drain: the origin shard tears down and stays live without us ─
    assert!(
        !matches!(
            mover_status(&*runner, node, validator),
            Some(ValidatorStatus::OnShard { shard, .. }) if shard == from
        ),
        "the mover's window on the origin shard has closed"
    );
    let retained = runner.leave_shard(node, from);
    let origin_peer = member_host(&*runner, from, node);
    let origin_before = runner
        .vnode_state_in(origin_peer, from)
        .expect("origin member host")
        .shard_coordinator()
        .committed_height();
    let drain_deadline = runner.now() + Duration::from_millis(EPOCH_MS * DRAIN_BUDGET_EPOCHS);
    let origin_alive = run_until_or(&mut *runner, drain_deadline, &mut moves, |r| {
        r.vnode_state_in(origin_peer, from)
            .expect("origin member host")
            .shard_coordinator()
            .committed_height()
            > origin_before
    });
    assert!(
        origin_alive,
        "the origin shard must keep committing after the drain"
    );

    // ── Fast path: rejoining with retained storage skips snap-sync ──
    let kind = runner.join_shard(node, validator, from, retained);
    let JoinKind::Retained { committed_height } = kind else {
        panic!("retained store must take the fast path, got {kind:?}");
    };
    assert!(committed_height > BlockHeight::GENESIS);
    // The rejoined vnode resumes exactly at the retained tip — the
    // chain survived the leave/rejoin cycle without replay. (It is no
    // longer an origin-committee member, so it observes rather than
    // participates; member-grade catch-up is the beacon-driven join
    // path asserted above.)
    let resumed = runner
        .vnode_state_in(node, from)
        .expect("rejoined shard is hosted")
        .shard_coordinator()
        .committed_height();
    assert_eq!(
        resumed, committed_height,
        "the retained chain must resume at its tip, not replay"
    );
}
