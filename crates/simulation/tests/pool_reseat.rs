//! A shard-less validator follows the beacon in the pool and re-seats from it.
//!
//! Exercises the follower model end to end on the deterministic sim — the same
//! `PoolLoop` / `seat_follower` path the production supervisor drives: a host
//! keeps a beacon follower warm after losing a shard (`leave_shard` builds one,
//! mirroring the supervisor's `on_torn_down`), and retires it when the
//! validator is seated again (`join_shard` drops it, mirroring
//! `unfollow_in_pool`).

use std::time::Duration;

use hyperscale_network_memory::NodeIndex;
use hyperscale_simulation::{EPOCH_MS, JoinKind, SimulationRunner};
use hyperscale_types::{ShardId, ValidatorId};
use tracing_test::traced_test;

mod common;
use common::rotation_config;

/// Any seed works — the cycle is harness-driven over the deterministic grow,
/// not dependent on a particular shuffle outcome.
const SEED: u64 = 7;

#[traced_test]
#[test]
fn drained_validator_follows_the_beacon_in_the_pool_and_reseats() {
    let mut runner = SimulationRunner::new(&rotation_config(), SEED);
    runner.initialize_genesis();
    // Grow to two shards; the grow draws one cohort from the pool and leaves
    // one surplus extra `Pooled` — a real shard-less beacon follower.
    runner.grow_to(2);
    let _ = runner.take_reconfigurations();

    // ── A surplus pool follower keeps its host's beacon storage warm ──
    let pool_host = (0..runner.num_hosts())
        .find(|&n| runner.pooled_len(n) > 0)
        .expect("the grow's surplus pool extra follows the beacon on its host");
    let before = committed_beacon_epoch(&runner, pool_host);
    runner.run_until(runner.now() + Duration::from_millis(EPOCH_MS * 4));
    let after = committed_beacon_epoch(&runner, pool_host);
    assert!(
        after > before,
        "the pool follower must fold committed beacon blocks and keep its \
         host's beacon storage warm ({before} -> {after})"
    );

    // ── Drain a committee member to the pool, then re-seat it ──
    // A grown host retains its terminated parent alongside its active child,
    // so the validator drains off its last shard only once every shard the
    // host runs is gone; the follower appears on that final leave.
    let leaf = ShardId::leaf(1, 0);
    let (node, validator) = committee_member_host(&runner, leaf);
    assert_eq!(
        runner.pooled_len(node),
        0,
        "a seated member's host runs no pool"
    );

    let mut leaf_storage = None;
    for shard in runner.hosted_shards_of(node) {
        let storage = runner.leave_shard(node, shard);
        if shard == leaf {
            leaf_storage = Some(storage);
        }
    }
    assert_eq!(
        runner.pooled_len(node),
        1,
        "draining the validator off its last shard makes it a beacon follower"
    );
    assert!(
        runner.vnode_state_in(node, leaf).is_none(),
        "the drained shards are gone from the host"
    );

    // ── The drained follower keeps folding the beacon while pooled ──
    // The host started with a shard, so the only thing that can advance its
    // beacon storage now is the pool follower folding gossiped blocks — no
    // shard loop is left on the host. A rising committed tip proves the
    // runtime-built pool is actually fed (the routing gap this guards against
    // left such a follower dark, never raising its own re-seat trigger).
    let before = committed_beacon_epoch(&runner, node);
    runner.run_until(runner.now() + Duration::from_millis(EPOCH_MS * 4));
    let after = committed_beacon_epoch(&runner, node);
    assert!(
        after > before,
        "the drained pool follower must keep folding committed beacon blocks \
         ({before} -> {after})"
    );
    let _ = runner.take_reconfigurations();

    let kind = runner.join_shard(
        node,
        validator,
        leaf,
        leaf_storage.expect("the leaf was among the host's shards"),
    );
    assert!(
        matches!(kind, JoinKind::Retained { .. }),
        "the retained store re-seats without snap-sync, got {kind:?}"
    );
    assert_eq!(
        runner.pooled_len(node),
        0,
        "seating the validator retires its pool follower"
    );
    assert!(
        runner.vnode_state_in(node, leaf).is_some(),
        "the validator is seated on the shard again"
    );
}

/// The host's committed beacon-chain tip epoch.
fn committed_beacon_epoch(runner: &SimulationRunner, node: NodeIndex) -> u64 {
    runner
        .beacon_storage(node)
        .expect("host has beacon storage")
        .latest_committed_epoch()
        .expect("beacon committed")
        .inner()
}

/// A host running a current consensus member of `shard`, and that member's
/// validator id — read from the committee so a post-grow placement is found
/// without assuming the host layout.
fn committee_member_host(runner: &SimulationRunner, shard: ShardId) -> (NodeIndex, ValidatorId) {
    let (_, state) = runner
        .beacon_storage(0)
        .expect("host 0 exists")
        .latest_committed()
        .expect("beacon committed");
    let members = state
        .shard_consensus_members
        .get(&shard)
        .expect("shard has a consensus committee");
    members
        .iter()
        .map(|m| (runner.network().validator_to_node(*m), *m))
        .find(|(node, _)| runner.vnode_state_in(*node, shard).is_some())
        .expect("a current member of the shard is hosted")
}
