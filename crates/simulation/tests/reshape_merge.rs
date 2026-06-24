//! Merge lifecycle, composed over the portable `merge_lifecycle` scenario.
//!
//! `merge_lifecycle` grows the root into two shards, votes the reshape threshold
//! up so the cold children fall under the merge threshold, and asserts the
//! outcome core (keepers paired → the reformed parent served → committed root ==
//! the beacon-composed anchor). This bespoke sim test layers the sim-only
//! **post-lifecycle** facts on top: the keepers seat a full committee on the
//! parent, it keeps committing past its merged genesis, and its chain is
//! structurally continuous with the children it formed from (a committed block
//! carries a structural genesis QC).
//!
//! The merge's **mid-lifecycle** properties are not re-asserted here: the
//! compose keystone — the parent anchor is `hash_internal` of the two child
//! terminal roots — is unit-tested on the sans-io sequencer in
//! `hyperscale_node::bootstrap::merge_flip` (`derivation_reconstructs_the_beacon_anchor`),
//! and the gate safety — a merge that pairs but whose keepers never ready must
//! not collapse the trie — in `hyperscale_beacon`
//! (`merge_executes_only_when_keepers_reach_quorum`).

mod support;

use hyperscale_scenarios::{Cluster, ScenarioConfig, epochs, merge_lifecycle};
use hyperscale_storage::ShardChainReader;
use hyperscale_types::{BlockHeight, ShardId, ValidatorId, ValidatorStatus};
use support::sim_cluster::SimCluster;

/// Committee validators per shard — the merge draws half of each child's
/// committee, so the reformed parent seats a full committee of keepers.
const PER_SHARD: u32 = 4;

/// Single-shard genesis with the split trigger armed (`split_bytes = 0`) and one
/// cohort of pooled extras — `merge_lifecycle` grows it to two shards and votes
/// them back together.
const fn merge_config() -> ScenarioConfig {
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
fn merged_parent_seats_keepers_with_a_chain_continuous_from_the_children() {
    let mut cluster = SimCluster::new(&merge_config(), 11);
    let root = ShardId::ROOT;

    merge_lifecycle(&mut cluster);

    // Placement: the merged committee is the keeper set — half of each child's
    // committee — all seated on the reformed parent; the non-keeper half
    // returned to the pool.
    let state = cluster
        .beacon_state()
        .expect("the merge committed a beacon state");
    let on_parent = (0..PER_SHARD * 2)
        .filter(|&v| {
            matches!(
                state.validators[&ValidatorId::new(u64::from(v))].status,
                ValidatorStatus::OnShard { shard, .. } if shard == root
            )
        })
        .count();
    assert_eq!(
        on_parent, PER_SHARD as usize,
        "the reformed parent must seat a full keeper committee",
    );

    // Forward progress: the scenario only requires the parent reach the anchor
    // at its merged genesis (a single block), so prove it keeps committing.
    let base = cluster
        .committed_height(root)
        .expect("the reformed parent commits");
    assert!(
        cluster.run_until(epochs(6), |c| {
            c.committed_height(root).is_some_and(|h| h > base)
        }),
        "the reformed parent must keep committing past the merge",
    );

    // Chain continuity: the merged chain is consensus-rooted in a structural
    // genesis — the fork point where the children's terminal roots were composed
    // into the parent's base.
    let runner = cluster.runner();
    for node in 0..runner.num_hosts() {
        let Some(storage) = runner.hosts_shard(node, root) else {
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
            "the merged chain on node {node} has no structural-genesis block — \
             it is not rooted in the children's fork",
        );
    }
}
