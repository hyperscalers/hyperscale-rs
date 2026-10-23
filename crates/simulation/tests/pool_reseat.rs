//! A shard-less validator follows the beacon in the pool and re-seats from it.
//!
//! Exercises the participant model end to end on the deterministic sim: a
//! host runs a beacon participant for every identity it holds from startup
//! on, so a validator that loses its last shard keeps following and taking
//! part in the beacon through it, and is seated again with the same
//! participant. Seating and draining never touch it.

use std::time::Duration;

use hyperscale_network_memory::NodeIndex;
use hyperscale_simulation::{EPOCH_MS, JoinKind, SimulationRunner};
use hyperscale_storage_memory::SimShardStorage;
use hyperscale_types::{
    BeaconBlockHash, Hash, RatifyPhase, RatifyPolka, ShardId, ValidatorId, ValidatorStatus,
    shard_prefix_path,
};
use tracing_test::traced_test;

mod support;

use support::{SimCluster, committee_member_host, rotation_config};

/// Any seed works — the cycle is harness-driven over the deterministic grow,
/// not dependent on a particular shuffle outcome.
const SEED: u64 = 7;

#[traced_test]
#[test]
fn drained_validator_follows_the_beacon_in_the_pool_and_reseats() {
    let mut cluster = SimCluster::with_dedicated_pool_hosts(&rotation_config(), SEED);
    let runner = cluster.runner_mut();
    // Grow to two shards; the grow draws one cohort from the pool and leaves
    // one surplus extra `Pooled`, seated nowhere.
    runner.grow_to(2);
    let _ = runner.take_participation_changes();

    // ── A surplus pooled participant keeps its host's beacon storage warm ──
    let pool_host = (0..runner.num_hosts())
        .find(|&n| runner.pooled_len(n) > 0)
        .expect("the grow's surplus pool extra runs a participant on its host");
    let before = committed_beacon_epoch(&*runner, pool_host);
    runner.run_until(runner.now() + Duration::from_millis(EPOCH_MS * 4));
    let after = committed_beacon_epoch(&*runner, pool_host);
    assert!(
        after > before,
        "the host of a pooled participant must fold committed beacon blocks \
         and keep its beacon storage warm ({before} -> {after})"
    );

    // ── Drain a committee member to the pool, then re-seat it ──
    // A grown host retains its terminated parent alongside its active child,
    // so the validator drains off its last shard only once every shard the
    // host runs is gone. Its participant runs throughout.
    let leaf = ShardId::leaf(1, 0);
    let (node, validator) = committee_member_host(&*runner, leaf, None);
    assert_eq!(runner.pooled_len(node), 0, "the member is seated");
    assert_eq!(
        runner.participants(node),
        vec![validator],
        "a seated member's host runs its participant"
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
        "the validator drained off its last shard"
    );
    assert_eq!(
        runner.participants(node),
        vec![validator],
        "the drain keeps the participant"
    );
    assert!(
        runner.replica_in(node, leaf).is_none(),
        "the drained shards are gone from the host"
    );

    // ── The drained host keeps folding the beacon ──
    // No shard loop is left on the host, so the only thing that can advance
    // its beacon storage now is its beacon loop folding gossiped blocks. A
    // rising committed tip proves the loop is still fed (a host left unfed
    // goes dark, and its participant never raises its own re-seat trigger).
    let before = committed_beacon_epoch(&*runner, node);
    runner.run_until(runner.now() + Duration::from_millis(EPOCH_MS * 4));
    let after = committed_beacon_epoch(&*runner, node);
    assert!(
        after > before,
        "the drained host must keep folding committed beacon blocks \
         ({before} -> {after})"
    );
    let _ = runner.take_participation_changes();

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
    assert_eq!(runner.pooled_len(node), 0, "the validator is seated again");
    assert_eq!(
        runner.participants(node),
        vec![validator],
        "seating keeps the one participant it ran all along"
    );
    assert!(
        runner.replica_in(node, leaf).is_some(),
        "the validator is seated on the shard again"
    );
}

/// A shard-less host partitioned past the gossip horizon catches up via
/// beacon sync.
///
/// While partitioned the host's tip freezes and the network advances
/// several epochs. Those gap epochs are no longer gossiped once the
/// partition heals — only the live tip is — so any advance past the frozen
/// tip proves the host's beacon loop fetched the gap via
/// `GetBeaconBlockRequest`, since the fold commits serially and cannot
/// skip the missing epochs.
#[traced_test]
#[test]
fn partitioned_follower_catches_up_via_beacon_sync() {
    let mut cluster = SimCluster::with_dedicated_pool_hosts(&rotation_config(), SEED);
    let runner = cluster.runner_mut();
    runner.grow_to(2);
    let _ = runner.take_participation_changes();

    let pool_host = (0..runner.num_hosts())
        .find(|&n| runner.pooled_len(n) > 0)
        .expect("the grow's surplus pool extra runs a participant on its host");
    let others: Vec<NodeIndex> = (0..runner.num_hosts())
        .filter(|&n| n != pool_host)
        .collect();

    // Let the shard-less host get current before isolating it.
    runner.run_until(runner.now() + Duration::from_millis(EPOCH_MS * 2));
    let frozen_tip = committed_beacon_epoch(&*runner, pool_host);

    // Isolate the host: no beacon gossip in or out.
    runner.network_mut().partition_groups(&[pool_host], &others);
    runner.run_until(runner.now() + Duration::from_millis(EPOCH_MS * 6));
    assert_eq!(
        committed_beacon_epoch(&*runner, pool_host),
        frozen_tip,
        "the isolated host receives no gossip, so its tip is frozen"
    );
    let network_tip = committed_beacon_epoch(&*runner, others[0]);
    assert!(
        network_tip > frozen_tip + 1,
        "the network must advance past the host by more than one epoch \
         ({frozen_tip} -> {network_tip})"
    );

    // Heal: the live gossip tip is now several epochs ahead of the host,
    // so its coordinator opens a catch-up sync to fill the gap.
    runner.network_mut().heal_all();
    runner.run_until(runner.now() + Duration::from_millis(EPOCH_MS * 6));
    let caught_up = committed_beacon_epoch(&*runner, pool_host);
    assert!(
        caught_up > frozen_tip,
        "the host must fetch the gap epochs over beacon sync — gossip no \
         longer carries them ({frozen_tip} -> {caught_up})"
    );
    assert!(
        caught_up >= network_tip,
        "the host catches up to where the network was during the outage \
         ({caught_up} >= {network_tip})"
    );
}

/// A fresh store joining a genesis-born shard that has not yet crossed a
/// boundary has no anchor to snap-sync from, and none is coming until the
/// shard crosses. It seats at the network genesis instead: the block and
/// state every member committed at birth, which block sync extends.
#[traced_test]
#[test]
fn a_join_before_the_first_crossing_seats_at_genesis() {
    let mut cluster = SimCluster::with_dedicated_pool_hosts(&rotation_config(), SEED);
    let runner = cluster.runner_mut();
    let (member_host, _) = committee_member_host(&*runner, ShardId::ROOT, None);
    let (pool_host, validator) = pooled_validator(&*runner);
    let topology = runner.host_topology(pool_host).expect("host topology");
    assert!(
        topology.boundary(ShardId::ROOT).is_none() && topology.genesis_unanchored(ShardId::ROOT),
        "ROOT has not crossed, so it has no anchor and replays from genesis"
    );

    let kind = runner.join_shard(
        pool_host,
        validator,
        ShardId::ROOT,
        SimShardStorage::new(shard_prefix_path(ShardId::ROOT)),
    );
    assert_eq!(kind, JoinKind::Genesis);
    assert_eq!(runner.pooled_len(pool_host), 0);

    // Let the scheduled genesis commit land, before the members extend it.
    runner.run_until(runner.now() + Duration::from_millis(1));
    let genesis = |host| {
        let coordinator = runner
            .replica_in(host, ShardId::ROOT)
            .expect("the host runs ROOT")
            .shard_coordinator();
        (coordinator.committed_hash(), coordinator.jmt_root())
    };
    assert_eq!(
        genesis(pool_host),
        genesis(member_host),
        "the joiner commits the block and state every member began from",
    );
}

/// A validator moved between hosts while it holds no seat carries the
/// beacon records it signed where it ran. Its participant on the new host
/// abstains at every slot it already signed: a vote for another value at
/// a slot the old host's record holds is refused there.
#[traced_test]
#[test]
fn a_rehomed_identity_abstains_at_beacon_slots_it_signed_on_its_old_host() {
    let mut cluster = SimCluster::with_dedicated_pool_hosts(&rotation_config(), SEED);
    let runner = cluster.runner_mut();
    runner.run_until(runner.now() + Duration::from_millis(EPOCH_MS * 4));
    // A seated member votes in every epoch's ratification; drained off
    // every shard its host runs, it holds no seat and may move.
    let (from, validator) = committee_member_host(&*runner, ShardId::ROOT, None);
    let signed = runner
        .beacon_storage(from)
        .expect("the old host exists")
        .ratify_record(validator)
        .expect("a pool member signs its ratify votes");
    let signed_votes = runner
        .beacon_storage(from)
        .expect("the old host exists")
        .beacon_vote_record(validator)
        .expect("a committee member signs its SPC votes");
    for shard in runner.hosted_shards_of(from) {
        let _ = runner.leave_shard(from, shard);
    }
    let to = (0..runner.num_hosts())
        .find(|&host| host != from)
        .expect("another host");

    assert!(runner.rehome_validator(validator, to));
    assert!(!runner.participants(from).contains(&validator));
    assert!(runner.participants(to).contains(&validator));

    let destination = runner.beacon_storage(to).expect("the new host exists");
    assert_eq!(
        destination.ratify_record(validator).as_ref(),
        Some(&signed),
        "the record moved with the identity",
    );
    assert_eq!(
        destination.beacon_vote_record(validator).as_ref(),
        Some(&signed_votes),
        "the SPC vote record moved with the identity",
    );
    let (&round, &prevoted) = signed
        .prevoted
        .iter()
        .next()
        .expect("the record holds a prevote");
    let other = BeaconBlockHash::from_raw(Hash::from_bytes(b"another value"));
    assert_ne!(prevoted, other);
    assert!(
        !destination.admit_ratify_vote(
            validator,
            signed.epoch,
            round,
            RatifyPhase::Prevote,
            other,
            RatifyPolka::empty(),
        ),
        "the new host refuses a second value at a slot the old host signed",
    );
}

/// A host carrying a `Pooled` validator, and that validator.
fn pooled_validator(runner: &SimulationRunner) -> (NodeIndex, ValidatorId) {
    let (_, state) = runner
        .beacon_storage(0)
        .expect("host 0 exists")
        .latest_committed()
        .expect("beacon committed");
    state
        .validators
        .iter()
        .filter(|(_, record)| matches!(record.status, ValidatorStatus::Pooled))
        .map(|(&id, _)| (runner.network().validator_to_node(id), id))
        .find(|&(host, _)| runner.pooled_len(host) > 0)
        .expect("a pooled validator runs a participant on its host")
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
