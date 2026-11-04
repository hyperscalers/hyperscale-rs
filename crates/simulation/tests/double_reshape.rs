//! Cut spacing on one lineage against the validity range.

mod support;

use std::cell::Cell;
use std::time::Duration;

use hyperscale_scenarios::tx::{
    build_probe_transfer_tx, probe_train_genesis_accounts, validity_around,
};
use hyperscale_scenarios::wait::await_split_admitted;
use hyperscale_scenarios::{Cluster, ScenarioConfig, epochs};
use hyperscale_types::{
    BeaconState, Epoch, MAX_VALIDITY_RANGE, PendingReshape, ShardId, WeightedTimestamp,
};
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

/// Split `parent`, showing `observe` the cluster at every poll until its
/// children are live, and return the earlier of their origins: the first
/// instant any block of either is anchored at.
fn split(c: &mut SimCluster, parent: ShardId, observe: impl Fn(&SimCluster)) -> WeightedTimestamp {
    let (left, right) = parent.children();
    assert!(
        await_split_admitted(c, parent, epochs(12)),
        "the beacon did not admit {parent}'s split within budget",
    );
    // Activity carries the parent to the crossing that seeds its children.
    c.submit(build_probe_transfer_tx(validity_around(c.now())));
    assert!(
        c.run_until(epochs(28), |c| {
            observe(c);
            live(c, left) && live(c, right)
        }),
        "{parent}'s children were not live within budget",
    );
    origin(c, left).min(origin(c, right))
}

/// The cut that formed `shard`: the opening of the window its record
/// names as its formation.
fn formation_cut(state: &BeaconState, shard: ShardId) -> WeightedTimestamp {
    let formed = state.boundaries[&shard].formed;
    state.chain_config.epoch_windows().window_of(formed).start
}

/// Whether a cut at the close of `terminal` ends `shard` a validity range
/// or more after the cut that formed it.
fn outlives_its_predecessors(state: &BeaconState, shard: ShardId, terminal: Epoch) -> bool {
    let end = state.chain_config.epoch_windows().window_of(terminal).end;
    end >= formation_cut(state, shard).plus(MAX_VALIDITY_RANGE)
}

/// A transaction predates at most one cut on its lineage.
///
/// A successor reads only its immediate predecessors' committed markers,
/// so the rule holds only while every block of a grandchild is anchored
/// at least a validity range after the cut that formed its parent. The
/// beacon holds a young chain's cut until the window it ends on closes
/// that far past the cut. Here the root splits and then its right child
/// does, and the right child's scheduled terminal is checked against the
/// bound, with the grandchildren's first anchor as the end-to-end witness.
///
/// The hold itself is not exercised here, and the test says so rather
/// than requiring it. The split waits on the child's own admission, its
/// cohort's sync and a quiet assertion folded under a window showing the
/// latch, so on 30-second windows the first quiet fold comes several
/// windows after formation, past the earliest terminal the bound allows.
/// The hold is pinned by the beacon's own fold tests instead. On
/// five-minute windows (`production-epochs`) no legal terminal ends
/// inside the range at all, so the bound holds for any cut.
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
    let first_anchor = split(&mut c, root, |_| {});
    let state = c.beacon_state().expect("the beacon has committed");
    let formed = state.boundaries[&right].formed;
    let formed_at = formation_cut(&state, right);

    let quiet_at = Cell::new(None::<Epoch>);
    let terminal = Cell::new(None::<Epoch>);
    let grandchild_anchor = split(&mut c, right, |c| {
        let Some(state) = c.beacon_state() else {
            return;
        };
        if let Some(PendingReshape::Split {
            quiet, scheduled, ..
        }) = state.pending_reshapes.get(&right)
        {
            if *quiet && quiet_at.get().is_none() {
                quiet_at.set(Some(state.current_epoch));
            }
            if let Some(scheduled) = scheduled {
                terminal.set(Some(scheduled.terminal));
            }
        }
    });
    let terminal = terminal
        .get()
        .expect("the right child's split was seen scheduled");
    let gap = Duration::from_millis(grandchild_anchor.as_millis() - formed_at.as_millis());
    eprintln!(
        "seed {seed}: {right} formed at {formed:?} ({} ms), first anchored at {} ms; quiet at \
         {:?}, terminal {terminal:?}; its children first anchored at {} ms, {gap:?} past its \
         formation",
        formed_at.as_millis(),
        first_anchor.as_millis(),
        quiet_at.get(),
        grandchild_anchor.as_millis(),
    );
    assert!(
        outlives_its_predecessors(&state, right, terminal),
        "{right}'s split was scheduled to end it at {terminal:?}, within one validity range \
         ({MAX_VALIDITY_RANGE:?}) of the cut that formed it",
    );
    assert!(
        grandchild_anchor >= formed_at.plus(MAX_VALIDITY_RANGE),
        "{right}'s children first anchored {gap:?} past the cut that formed it, within one \
         validity range ({MAX_VALIDITY_RANGE:?}): a transaction can predate both cuts",
    );
}
