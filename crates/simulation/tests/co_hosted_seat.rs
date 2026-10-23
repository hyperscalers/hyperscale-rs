//! A validator drawn onto a shard its host already runs signs through the
//! replica already there.
//!
//! The beacon draws committees without regard to hosts, so on a layout
//! where pool extras ride the committee hosts a shuffle can land a
//! validator on a host already serving the shard it is drawn to. The
//! host attaches it to the running replica rather than leaving the
//! committee a voter short, and a member the shuffle rotates out detaches
//! from it while the replica keeps running.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use hyperscale_network_memory::NodeIndex;
use hyperscale_simulation::{EPOCH_MS, SimulationRunner};
use hyperscale_storage::ShardChainReader;
use hyperscale_types::{BlockHeight, ShardId, ValidatorId};

mod support;

use hyperscale_scenarios::{ScenarioConfig, assume};
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
            let seated: BTreeSet<ValidatorId> =
                runner.signers_in(host, shard).into_iter().collect();
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

/// One shard whose committee is the whole validator set, one validator
/// per host, with resharding disarmed.
const fn one_shard_config() -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 4,
        vnodes_per_host: 1,
        pool_surplus: 0,
        num_shards: 1,
        split_bytes: u64::MAX,
        latency: Duration::from_millis(150),
    }
}

/// A replica whose last signer detaches keeps following its chain: it
/// commits what the rest of its committee certifies, and no certificate
/// formed after the detach carries the detached validator's signature.
#[test]
fn the_last_signer_detached_leaves_the_replica_following() {
    const HOST: NodeIndex = 0;
    let mut cluster = SimCluster::new(&one_shard_config(), SEED);
    let runner = cluster.runner_mut();
    runner.topology_step();
    let start = runner.now();
    runner.run_until(start + Duration::from_millis(EPOCH_MS / 2));

    let [validator] = runner.signers_in(HOST, ShardId::ROOT)[..] else {
        panic!("one validator per host");
    };
    assert!(runner.detach_signer(HOST, ShardId::ROOT, validator));
    assert!(runner.signers_in(HOST, ShardId::ROOT).is_empty());
    let committed = |runner: &SimulationRunner| {
        runner
            .hosts_shard(HOST, ShardId::ROOT)
            .expect("the host keeps the shard")
            .committed_height()
    };
    let detached_at = committed(runner);

    // Within the epoch: the placement scan, which would attach it again,
    // runs only at the next committed epoch.
    let now = runner.now();
    runner.run_until(now + Duration::from_millis(EPOCH_MS / 3));
    let followed = committed(runner);
    assert!(
        followed.inner() > detached_at.inner() + 3,
        "the replica stopped following at {followed:?}, detached at {detached_at:?}",
    );

    let topology = runner
        .host_topology(HOST)
        .expect("the host holds a topology");
    let index = topology
        .consensus_committee_for_shard(ShardId::ROOT)
        .iter()
        .position(|member| *member == validator)
        .expect("the validator sits in the committee");
    let storage = runner.hosts_shard(HOST, ShardId::ROOT).expect("hosted");
    // A vote signed before the detach can certify the next block or two.
    for height in detached_at.inner() + 3..=followed.inner() {
        let certified = storage
            .get_certified_header(BlockHeight::new(height))
            .expect("the replica holds every block it committed");
        assert!(
            !certified.qc().signers().is_set(index),
            "the detached validator signed the certificate at height {height}",
        );
    }
}
