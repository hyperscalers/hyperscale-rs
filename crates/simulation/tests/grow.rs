//! The single-shard-to-target grow primitive, exercised as test setup.
//!
//! Boots a single-shard network with the split trigger armed from genesis,
//! grows it to a power-of-two target through the real split lifecycle, and
//! asserts the reached topology: every leaf the splits reshaped into stands at
//! full committee strength and commits past its child genesis on a seated host.

mod support;

use std::time::Duration;

use hyperscale_scenarios::{ScenarioConfig, grow_to};
use hyperscale_simulation::SimulationRunner;
use hyperscale_storage::ShardChainReader;
use hyperscale_types::{BlockHeight, ShardId};
use support::sim_cluster::SimCluster;
use tracing_test::traced_test;

const PER_SHARD: u32 = 4;

/// A single-shard, paced-epoch network with the split trigger armed from
/// genesis and one cohort of pooled extras per split.
const fn grow_config(target_shards: u32) -> ScenarioConfig {
    ScenarioConfig {
        validators_per_shard: PER_SHARD,
        vnodes_per_host: 1,
        pool_surplus: (target_shards - 1) * PER_SHARD,
        num_shards: 1,
        split_bytes: 0,
        latency: Duration::from_millis(150),
        dedicated_hosts: false,
    }
}

/// Assert the runner reached exactly `target_shards` leaves, each at full
/// committee strength on every host and committing past its child genesis.
fn assert_grown(runner: &SimulationRunner, target_shards: u32) {
    let depth = target_shards.trailing_zeros();
    let expected: Vec<ShardId> = (0..u64::from(target_shards))
        .map(|path| ShardId::leaf(depth, path))
        .collect();

    for node in 0..runner.num_hosts() {
        let snapshot = runner.host_topology(node).expect("host carries a topology");
        assert_eq!(
            snapshot.num_shards(),
            u64::from(target_shards),
            "host {node} must see {target_shards} shards after the grow",
        );
        let leaves: Vec<ShardId> = snapshot.shard_trie().leaves().collect();
        assert_eq!(leaves, expected, "the leaves are the target partition");
        for &leaf in &expected {
            assert_eq!(
                snapshot.committee_for_shard(leaf).len(),
                PER_SHARD as usize,
                "leaf {leaf:?} must stand at full committee strength",
            );
        }
    }

    for &leaf in &expected {
        let advanced = (0..runner.num_hosts()).any(|node| {
            runner
                .hosts_shard(node, leaf)
                .is_some_and(|storage| storage.committed_height() > BlockHeight::GENESIS)
        });
        assert!(advanced, "leaf {leaf:?} must commit past its genesis");
    }
}

#[traced_test]
#[test]
fn grow_to_two_shards_reaches_topology() {
    let target = 2;
    let mut cluster = SimCluster::new(&grow_config(target), 11);
    grow_to(&mut cluster, target);
    assert_grown(cluster.runner(), target);
}

#[traced_test]
#[test]
fn grow_to_four_shards_reaches_topology() {
    let target = 4;
    let mut cluster = SimCluster::new(&grow_config(target), 11);
    grow_to(&mut cluster, target);
    assert_grown(cluster.runner(), target);
}
