//! Cut spacing on one lineage against the validity range.

mod support;

use std::time::Duration;

use hyperscale_scenarios::tx::{
    build_probe_transfer_tx, probe_train_genesis_accounts, validity_around,
};
use hyperscale_scenarios::wait::await_split_admitted;
use hyperscale_scenarios::{Cluster, ScenarioConfig, epochs};
use hyperscale_types::{MAX_VALIDITY_RANGE, ShardId};
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

fn origin_ms(c: &impl Cluster, shard: ShardId) -> u64 {
    c.chain_origin(shard)
        .expect("a live shard reports its origin")
        .anchor_wt
        .as_millis()
}

/// Split `parent` and return the later of its children's origins.
fn split(c: &mut SimCluster, parent: ShardId) -> u64 {
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
    origin_ms(c, left).max(origin_ms(c, right))
}

/// A transaction predates at most one cut on its lineage.
///
/// A successor reads only its immediate predecessors' committed markers,
/// so the rule holds only while the next cut on a lineage falls more than
/// a validity range after the last. A transaction the grandparent
/// committed was anchored before the first cut, and its range ends at
/// most [`MAX_VALIDITY_RANGE`] past its start, so no block a grandchild
/// anchors at or past the second cut can carry it.
#[test]
fn two_cuts_on_one_lineage_lie_further_apart_than_a_validity_range() {
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
    let first_cut = split(&mut c, root);
    let second_cut = split(&mut c, right);
    let gap = Duration::from_millis(second_cut - first_cut);
    eprintln!("seed {seed}: cuts at {first_cut} ms and {second_cut} ms, gap {gap:?}");
    assert!(
        gap > MAX_VALIDITY_RANGE,
        "the cuts at {first_cut} ms and {second_cut} ms lie {gap:?} apart, within one \
         validity range ({MAX_VALIDITY_RANGE:?}): a transaction can predate both",
    );
}
