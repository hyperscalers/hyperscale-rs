//! A validator drawn onto a shard its host already runs is seated there.
//!
//! The beacon draws committees without regard to hosts, so on a layout
//! where pool extras ride the committee hosts a shuffle can land a
//! validator on a host already serving the shard it is drawn to. The
//! host seats it into the running loop rather than leaving the committee
//! a voter short, and a member the shuffle rotates out leaves the loop
//! while another seat keeps it running.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use hyperscale_network_memory::NodeIndex;
use hyperscale_simulation::{EPOCH_MS, SimulationRunner};
use hyperscale_storage::ShardChainReader;
use hyperscale_types::{BlockHeight, ShardId, ValidatorId};

mod support;

use hyperscale_scenarios::assume;
use support::{SimCluster, rotation_config};

/// Seed for the grown placement the shuffle runs against.
const SEED: u64 = 7;

/// Epochs the shuffle gets to move a validator into and out of a running
/// loop.
const BUDGET_EPOCHS: u64 = 60;

/// Epochs the shards keep running once both moves are seen.
const SETTLE_EPOCHS: u64 = 4;

/// What each host carries on each shard, by validator.
type Seating = BTreeMap<(NodeIndex, ShardId), BTreeSet<ValidatorId>>;

fn seating(runner: &SimulationRunner) -> Seating {
    let topology = runner.host_topology(0).expect("host 0 holds a topology");
    let mut seating = Seating::new();
    for host in 0..runner.num_hosts() {
        for shard in topology.shard_trie().leaves() {
            let seated: BTreeSet<ValidatorId> = runner
                .shard_vnodes_in(host, shard)
                .iter()
                .map(|v| v.validator_id())
                .collect();
            if !seated.is_empty() {
                seating.insert((host, shard), seated);
            }
        }
    }
    seating
}

/// Every member of each shard's consensus committee is seated on that
/// shard by some host.
fn assert_fully_seated(runner: &SimulationRunner, seating: &Seating) {
    let topology = runner.host_topology(0).expect("host 0 holds a topology");
    for shard in topology.shard_trie().leaves() {
        for member in topology.consensus_committee_for_shard(shard) {
            assert!(
                seating
                    .iter()
                    .any(|(&(_, seated_on), seated)| seated_on == shard && seated.contains(member)),
                "{member:?} sits in {shard:?}'s committee but no host seats it; \
                 seating {seating:?}",
            );
        }
    }
}

fn committed_heights(runner: &SimulationRunner) -> BTreeMap<ShardId, BlockHeight> {
    let topology = runner.host_topology(0).expect("host 0 holds a topology");
    topology
        .shard_trie()
        .leaves()
        .map(|shard| {
            let height = (0..runner.num_hosts())
                .filter_map(|host| runner.hosts_shard(host, shard))
                .map(ShardChainReader::committed_height)
                .max()
                .unwrap_or(BlockHeight::GENESIS);
            (shard, height)
        })
        .collect()
}

#[test]
fn a_shuffle_onto_a_host_already_serving_the_shard_keeps_the_committee_seated() {
    let mut cluster = SimCluster::new(&rotation_config(), SEED);
    let runner = cluster.runner_mut();
    runner.grow_to(2);

    let deadline = runner.now() + Duration::from_millis(EPOCH_MS * BUDGET_EPOCHS);
    let mut previous = seating(runner);
    let (mut joined, mut left) = (false, false);
    let mut settle_until: Option<Duration> = None;
    let mut heights = committed_heights(runner);
    while runner.now() < settle_until.unwrap_or(deadline) {
        runner.topology_step();
        let next = runner.now() + Duration::from_secs(1);
        runner.run_until(next);

        let current = seating(runner);
        assert_fully_seated(runner, &current);
        for (key, before) in &previous {
            let Some(after) = current.get(key) else {
                continue;
            };
            joined |= after.difference(before).next().is_some();
            left |= before.difference(after).next().is_some();
        }
        previous = current;
        if joined && left && settle_until.is_none() {
            settle_until = Some(runner.now() + Duration::from_millis(EPOCH_MS * SETTLE_EPOCHS));
            heights = committed_heights(runner);
        }
    }

    // The shape under test is the seed's to produce, not the protocol's.
    assume(
        joined,
        "no validator joined a loop its host was already running",
    );
    assume(left, "no validator left a loop that kept running");
    for (shard, height) in committed_heights(runner) {
        assert!(
            height > heights[&shard],
            "{shard:?} stopped committing after the moves: still at {height:?}",
        );
    }
}
