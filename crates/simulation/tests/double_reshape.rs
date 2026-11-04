//! Cut spacing on one lineage against the validity range.

mod support;

use std::time::Duration;

use hyperscale_scenarios::tx::{
    build_probe_transfer_tx, probe_train_genesis_accounts, validity_around,
};
use hyperscale_scenarios::wait::await_split_admitted;
use hyperscale_scenarios::{Cluster, ScenarioConfig, epochs};
use hyperscale_types::{MAX_VALIDITY_RANGE, ShardId, WeightedTimestamp};
use support::{SimCluster, sim_seed};

/// The split trigger armed, and pool surplus for three splits: the root,
/// then both children, so the left child's split cannot starve the
/// right's of a cohort.
const fn double_split_config() -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 4,
        vnodes_per_host: 1,
        pool_surplus: 12,
        num_shards: 1,
        split_bytes: 0,
        latency: Duration::from_millis(150),
    }
}

fn live(c: &impl Cluster, shard: ShardId) -> bool {
    c.serves_shard(shard) && c.committed_height(shard).is_some_and(|h| h.inner() >= 1)
}

fn origin(c: &impl Cluster, shard: ShardId) -> WeightedTimestamp {
    c.chain_origin(shard)
        .expect("a live shard reports its origin")
        .anchor_wt
}

/// Split `parent` and return the earlier of its children's origins: the
/// first instant any block of either is anchored at.
fn split(c: &mut SimCluster, parent: ShardId) -> WeightedTimestamp {
    let (left, right) = parent.children();
    assert!(
        await_split_admitted(c, parent, epochs(12)),
        "the beacon did not admit {parent}'s split within budget",
    );
    // Activity carries the parent to the crossing that seeds its children.
    c.submit(build_probe_transfer_tx(validity_around(c.now())));
    assert!(
        c.run_until(epochs(28), |c| live(c, left) && live(c, right)),
        "{parent}'s children were not live within budget",
    );
    origin(c, left).min(origin(c, right))
}

/// The cut that formed `shard`: the opening of the window its record
/// names as its formation.
fn formation_cut(c: &impl Cluster, shard: ShardId) -> WeightedTimestamp {
    let state = c.beacon_state().expect("the beacon has committed");
    let formed = state.boundaries[&shard].formed;
    state.chain_config.epoch_windows().window_of(formed).start
}

/// A transaction predates at most one cut on its lineage.
///
/// A successor reads only its immediate predecessors' committed markers,
/// so the rule holds only while every block of a grandchild is anchored
/// at least a validity range after the cut that formed its parent. A
/// transaction the grandparent committed was anchored at or before that
/// cut, and its range ends at most [`MAX_VALIDITY_RANGE`] past its anchor,
/// so no block anchored there or later can carry it. The beacon holds a
/// young chain's cut until this is so; here it is watched on a live
/// cluster splitting the root and then its right child.
#[test]
fn a_grandchild_anchors_a_validity_range_past_its_parents_formation() {
    let seed = sim_seed(42);
    let root = ShardId::ROOT;
    let (_, right) = root.children();

    let mut c = SimCluster::with_accounts(
        &double_split_config(),
        seed,
        &probe_train_genesis_accounts(4),
    );
    assert!(
        c.run_until(epochs(8), |c| c.beacon_state().is_some()),
        "the beacon must commit an epoch",
    );
    let first_anchor = split(&mut c, root);
    let formed_at = formation_cut(&c, right);
    let grandchild_anchor = split(&mut c, right);
    let gap = Duration::from_millis(grandchild_anchor.as_millis() - formed_at.as_millis());
    eprintln!(
        "seed {seed}: {right} formed at {} ms, first anchored at {} ms; its children first \
         anchored at {} ms, {gap:?} past its formation",
        formed_at.as_millis(),
        first_anchor.as_millis(),
        grandchild_anchor.as_millis(),
    );
    assert!(
        grandchild_anchor >= formed_at.plus(MAX_VALIDITY_RANGE),
        "{right}'s children first anchored {gap:?} past the cut that formed it, within one \
         validity range ({MAX_VALIDITY_RANGE:?}): a transaction can predate both cuts",
    );
}
