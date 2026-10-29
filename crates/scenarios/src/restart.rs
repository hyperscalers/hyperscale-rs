//! A host stopped and started again on the disk it left, across a split's
//! handoff: the stores it held resume, and its child store catches up
//! with the chain.

use hyperscale_types::{BlockHeight, NetworkDefinition, ShardId, TopologySnapshot, ValidatorId};

use crate::support::{Budget, Cluster, FaultableCluster, RestartableCluster, epochs, grow_to};

/// How far past its height at the restart a restarted host's child store
/// has to commit before it counts as caught up with the chain.
const CATCH_UP_BLOCKS: u64 = 3;

/// The topology the cluster's latest committed beacon state projects.
fn live_topology(c: &impl Cluster) -> TopologySnapshot {
    c.beacon_state()
        .expect("a beacon state is committed")
        .derive_topology_snapshot(NetworkDefinition::simulator())
}

/// A former member of a split parent restarted with the parent's store
/// still on disk comes back up.
///
/// The departed store serves its history for as long as routing names
/// this host among the parent's members, and the host's child store
/// resumes and catches up with the chain. Start `c` at genesis on one shard with the split trigger armed and a
/// cohort of pool surplus.
///
/// # Panics
///
/// Panics if the split never hands off, the restarted host stops serving
/// a departed store it served before, or its child store does not catch
/// up.
pub fn a_restart_beside_a_departed_parent_store_resumes<C: RestartableCluster>(c: &mut C) {
    let parent_committee = live_topology(c).committee_for_shard(ShardId::ROOT).to_vec();
    grow_to(c, 2);

    let child = ShardId::leaf(1, 0);
    let settled = |c: &C| {
        c.beacon_state().is_some_and(|state| {
            let topology = state.derive_topology_snapshot(NetworkDefinition::simulator());
            !topology.reshape_handoff_pending(ShardId::ROOT)
                && topology.reshape_parent_half_cohorts().is_empty()
                && topology.boundary(child).is_some()
        })
    };
    assert!(
        c.run_until(Budget(20), settled),
        "the split hands off to its children"
    );
    let member = live_topology(c)
        .committee_for_shard(child)
        .iter()
        .copied()
        .find(|member| parent_committee.contains(member))
        .expect("a parent member carries on into the child");
    let host = c.host_of(member).expect("a host runs the member");
    let before = c
        .committed_height(child)
        .expect("the child commits after the grow");
    let served = c.committee_hosts(ShardId::ROOT).contains(&host);

    restart(c, host);
    assert!(
        !served
            || c.run_until(epochs(1), |c| c
                .committee_hosts(ShardId::ROOT)
                .contains(&host)),
        "a departed store host {host} served before the restart is served after it"
    );

    await_caught_up(c, host, child, before);
}

/// A split child's parent-half member restarted before the handoff
/// completes, with every store it held kept, resumes both.
///
/// The departed parent's loop serves its terminal, the child's loop
/// resumes from its own store, and the child catches up with the chain.
/// Start `c` as [`a_restart_beside_a_departed_parent_store_resumes`]
/// says.
///
/// # Panics
///
/// Panics if the handoff is over once both children commit, or the
/// restarted host's child store does not catch up.
pub fn a_restart_mid_handoff_keeping_its_stores_catches_the_child_up<C: RestartableCluster>(
    c: &mut C,
) {
    grow_to(c, 2);

    let (child, member) = parent_half_member(c);
    let host = c.host_of(member).expect("a host runs the member");
    let before = c
        .committed_height(child)
        .expect("the child commits after the grow");

    restart(c, host);

    await_caught_up(c, host, child, before);
}

/// A split child and one of its parent-half members, while the split's
/// handoff is in flight.
fn parent_half_member(c: &impl Cluster) -> (ShardId, ValidatorId) {
    live_topology(c)
        .reshape_parent_half_cohorts()
        .iter()
        .find_map(|(&child, cohort)| cohort.keys().next().map(|&member| (child, member)))
        .expect("the handoff is still in flight once both children commit")
}

/// Stop host `host` and wait until it is up again.
fn restart(c: &mut impl RestartableCluster, host: usize) {
    c.stop_host(host, Budget(0));
    assert!(
        c.run_until(epochs(1), |c| c.is_up(host)),
        "host {host} must come back"
    );
}

/// Wait until host `host`'s store for `child` has committed
/// [`CATCH_UP_BLOCKS`] past `before`.
fn await_caught_up(
    c: &mut impl FaultableCluster,
    host: usize,
    child: ShardId,
    before: BlockHeight,
) {
    let target = BlockHeight::new(before.inner() + CATCH_UP_BLOCKS);
    assert!(
        c.run_until(Budget(20), |c| c
            .host_committed_height(host, child)
            .is_some_and(|height| height >= target)),
        "the restarted host's child store catches up with the chain",
    );
}
