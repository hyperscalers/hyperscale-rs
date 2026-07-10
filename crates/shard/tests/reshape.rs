//! Reshape-trigger behavior pinned by the shard sim: a shard whose
//! committed substate byte total satisfies the load predicate asserts the
//! trigger on its manifest, every replica re-derives and verifies the
//! assertion as part of the beacon-witness root, the committed
//! accumulator gains the trigger leaf, and re-assertion is suppressed
//! for the rest of the witness window.

mod common;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use common::ShardCoordinatorSim;
use hyperscale_shard::ready_signal_pool::MIN_READY_SIGNAL_DWELL;
use hyperscale_types::{
    NetworkDefinition, NetworkParams, ReshapeThresholds, ShardId, ShardWitnessPayload,
    TopologySchedule, TopologySnapshot, ValidatorId, ValidatorInfo, ValidatorSet,
    WeightedTimestamp,
};

const MAX_STEPS: usize = 5_000;

/// With a zero split threshold every block's load predicate fires, so
/// the first committed block must carry exactly one `ScheduleSplit`
/// leaf — and the window dedup must keep every later block in the same
/// witness window from re-asserting. All replicas commit the same
/// chain, which means each one re-derived the assertion and accepted
/// it (a predicate mismatch rejects the block before voting).
#[test]
fn split_trigger_asserts_once_per_window_and_verifies() {
    let mut sim = ShardCoordinatorSim::new(4, 0x7E5A);
    let snapshot = sim
        .topology_schedule
        .head()
        .as_ref()
        .clone()
        .with_params(NetworkParams {
            reshape_thresholds: ReshapeThresholds { split_bytes: 0 },
        });
    sim.topology_schedule = TopologySchedule::single(Arc::new(snapshot));
    sim.kick_off();

    let mut steps = 0;
    while steps < MAX_STEPS && sim.commits.iter().any(|c| c.len() < 3) {
        if !sim.step() {
            break;
        }
        steps += 1;
    }

    for (replica, commits) in sim.commits.iter().enumerate() {
        assert!(
            commits.len() >= 3,
            "replica {replica} expected >= 3 commits within step budget; got {}",
            commits.len(),
        );

        let asserting: Vec<u64> = commits
            .iter()
            .filter(|c| {
                c.witness_leaves
                    .iter()
                    .any(|l| matches!(l, ShardWitnessPayload::ScheduleSplit { .. }))
            })
            .map(|c| c.height.inner())
            .collect();
        assert_eq!(
            asserting,
            vec![1],
            "replica {replica}: exactly the first committed block asserts the \
             split; later blocks in the same witness window dedup",
        );
    }

    // Byte-identical chains across replicas — the assertion was
    // verified, not trusted.
    for replica in 1..4 {
        for i in 0..3 {
            assert_eq!(
                sim.commits[0][i].block_hash, sim.commits[replica][i].block_hash,
                "replica {replica} diverged at commit {i}",
            );
        }
    }
}

/// An observer's ready signal commits as a `ReshapeReady` witness leaf
/// — never a `Ready` leaf — on every replica. The observer rides the
/// committee for transport (signal admission, gossip) while the
/// consensus subset excludes it, and each replica re-derives the leaf
/// classification from its own schedule entry as part of beacon-witness
/// root verification, so the byte-identical committed chains prove the
/// classification is replica-deterministic, not proposer-trusted.
#[test]
fn observer_ready_signal_commits_as_reshape_ready_leaf() {
    let mut sim = ShardCoordinatorSim::new(4, 0x7E5C);

    // Reseat the schedule: full membership keeps all four, the
    // consensus subset drops the last member, who instead holds an
    // observer seat for the pending left child.
    let validator_set = ValidatorSet::new(
        sim.members
            .iter()
            .map(|(id, pk)| ValidatorInfo {
                validator_id: *id,
                public_key: *pk,
            })
            .collect(),
    );
    let all: Vec<ValidatorId> = sim.members.iter().map(|(id, _)| *id).collect();
    let consensus = all[..3].to_vec();
    let observer = all[3];
    let (left, _) = ShardId::ROOT.children();
    let snapshot = TopologySnapshot::from_explicit_committees(
        NetworkDefinition::simulator(),
        &validator_set,
        HashMap::from([(ShardId::ROOT, all)]),
        HashMap::from([(ShardId::ROOT, consensus)]),
        HashMap::new(),
        HashMap::new(),
        BTreeMap::from([(ShardId::ROOT, BTreeMap::from([(observer, left)]))]),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeSet::from([ShardId::ROOT]),
    );
    sim.topology_schedule = TopologySchedule::single(Arc::new(snapshot));

    sim.emit_ready_signal_for_shard(
        3,
        left,
        WeightedTimestamp::from_millis(0),
        WeightedTimestamp::from_millis(u64::MAX),
    );
    sim.advance_clock(MIN_READY_SIGNAL_DWELL + Duration::from_millis(10));
    sim.kick_off();
    sim.run_until_committed(2, MAX_STEPS);

    for (replica, commits) in sim.commits.iter().enumerate() {
        assert!(
            commits.len() >= 2,
            "replica {replica} expected >= 2 commits within step budget; got {}",
            commits.len(),
        );
        let leaves: Vec<&ShardWitnessPayload> =
            commits.iter().flat_map(|c| &c.witness_leaves).collect();
        assert!(
            leaves.iter().any(|l| matches!(
                l,
                ShardWitnessPayload::ReshapeReady { validator, child }
                    if *validator == observer && *child == left
            )),
            "replica {replica}: observer signal never committed as ReshapeReady for its child",
        );
        assert!(
            !leaves
                .iter()
                .any(|l| matches!(l, ShardWitnessPayload::Ready { .. })),
            "replica {replica}: an observer signal must never classify as Ready",
        );
    }
    for replica in 1..4 {
        assert_eq!(
            sim.commits[0][0].block_hash, sim.commits[replica][0].block_hash,
            "replica {replica} diverged at the signal-carrying commit",
        );
    }
}

/// With reshaping disabled (the default schedule), no block ever
/// asserts a trigger and no `ScheduleSplit`/`ScheduleMerge` leaf
/// reaches the accumulator.
#[test]
fn disabled_thresholds_never_assert() {
    let mut sim = ShardCoordinatorSim::new(4, 0x7E5B);
    sim.kick_off();

    let mut steps = 0;
    while steps < MAX_STEPS && sim.commits[0].len() < 3 {
        if !sim.step() {
            break;
        }
        steps += 1;
    }
    assert!(sim.commits[0].len() >= 3);

    for commit in &sim.commits[0] {
        assert!(
            !commit.witness_leaves.iter().any(|l| matches!(
                l,
                ShardWitnessPayload::ScheduleSplit { .. }
                    | ShardWitnessPayload::ScheduleMerge { .. }
            )),
            "no reshape leaf may appear while thresholds are disabled",
        );
    }
}
