//! Split grow phase, composed over the portable `split_lifecycle` scenario.
//!
//! `split_lifecycle` drives the organic split on both harnesses and asserts its
//! outcome core (admitted → both children served → committed root == the
//! beacon-composed anchor → parent frozen). This bespoke sim test layers the
//! sim-only **post-lifecycle** facts on top: every validator is seated on a
//! child at full committee strength, each child keeps committing real blocks
//! past the grow, and each child's chain is structurally continuous with the
//! parent it forked from (a committed block carries a structural genesis QC).
//!
//! The split's **mid-lifecycle** properties — an observer's child-rooted store
//! holds exactly the imported subtree, co-observers of a half agree byte for
//! byte, and the two imported roots recompose to the parent's terminal root —
//! are not re-asserted here: they are unit-tested directly on the sans-io
//! sequencer in `hyperscale_node::bootstrap::observer`
//! (`observer_bootstraps_adopt_the_child_subtrees`,
//! `child_spans_partition_the_parent_population`), which both harnesses drive.

mod support;

use hyperscale_scenarios::{Cluster, ScenarioConfig, epochs, split_lifecycle};
use hyperscale_storage::ShardChainReader;
use hyperscale_types::{BlockHeight, ShardId, ValidatorId, ValidatorStatus};
use support::sim_cluster::SimCluster;

/// Committee validators per shard — also the cohort the admission draws, so the
/// pool surplus matches it exactly.
const PER_SHARD: u32 = 4;

/// Single-shard genesis with the split trigger armed (`split_bytes = 0`) and one
/// cohort of pooled extras — the shape that drives an organic root split.
const fn grow_config() -> ScenarioConfig {
    ScenarioConfig {
        validators_per_shard: PER_SHARD,
        vnodes_per_host: 1,
        pool_surplus: PER_SHARD,
        num_shards: 1,
        split_bytes: 0,
        latency: std::time::Duration::from_millis(150),
        dedicated_hosts: false,
    }
}

#[test]
fn grown_split_seats_children_with_chains_continuous_from_the_parent() {
    let mut cluster = SimCluster::new(&grow_config(), 11);
    let (left, right) = ShardId::ROOT.children();

    split_lifecycle(&mut cluster);

    // Placement: every original member and every drawn observer is seated on one
    // of the two children, splitting evenly into two full committees.
    let state = cluster
        .beacon_state()
        .expect("the grow committed a beacon state");
    let mut on_left = 0u32;
    let mut on_right = 0u32;
    for v in 0..PER_SHARD * 2 {
        let id = ValidatorId::new(u64::from(v));
        match state.validators[&id].status {
            ValidatorStatus::OnShard { shard, .. } if shard == left => on_left += 1,
            ValidatorStatus::OnShard { shard, .. } if shard == right => on_right += 1,
            other => panic!("validator {v} was not seated on a split child: {other:?}"),
        }
    }
    assert_eq!(
        on_left, PER_SHARD,
        "the left child must seat a full committee"
    );
    assert_eq!(
        on_right, PER_SHARD,
        "the right child must seat a full committee"
    );

    // Forward progress: the scenario only requires the children reach the anchor
    // at genesis (a single block), so prove they keep committing past it.
    let left_base = cluster.committed_height(left).expect("left child commits");
    let right_base = cluster
        .committed_height(right)
        .expect("right child commits");
    assert!(
        cluster.run_until(epochs(6), |c| {
            c.committed_height(left).is_some_and(|h| h > left_base)
                && c.committed_height(right).is_some_and(|h| h > right_base)
        }),
        "both children must keep committing blocks past the grow",
    );

    // Chain continuity: each child's committed chain is consensus-rooted in a
    // structural genesis — some committed block carries a genesis QC, the fork
    // point where the parent chain's terminal root was adopted as the child's
    // base (the scenario proves the genesis state root matches the anchor; this
    // proves the chain itself descends from it).
    let runner = cluster.runner();
    for child in [left, right] {
        for node in 0..runner.num_hosts() {
            let Some(storage) = runner.hosts_shard(node, child) else {
                continue;
            };
            let tip = storage.committed_height();
            let mut height = BlockHeight::new(1);
            let mut rooted = false;
            while height <= tip {
                if storage
                    .get_block(height)
                    .is_some_and(|block| block.block().header().parent_qc().is_genesis())
                {
                    rooted = true;
                    break;
                }
                height = height.next();
            }
            assert!(
                rooted,
                "child {child:?} on node {node} has no structural-genesis block — \
                 its committed chain is not rooted in the parent fork",
            );
        }
    }
}
