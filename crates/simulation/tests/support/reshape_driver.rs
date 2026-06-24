//! `ReshapeDriver`: the simulation's reactive reshape orchestrator.
//!
//! The deterministic counterpart of the production `ShardSupervisor`'s reshape
//! duties. `SimCluster::run_until` pumps it once per slice; every action is
//! idempotent — guarded by what committed beacon state shows versus what the
//! driver has already done — so pumping every slice is safe. It reuses the
//! runner's existing reshape methods (`observe_child`, `broadcast_observer_ready`,
//! `flip_all_for`); only *when* they fire is decided here.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use hyperscale_simulation::SimulationRunner;
use hyperscale_storage_memory::SimShardStorage;
use hyperscale_types::{
    BeaconState, BlockHash, PendingReshape, ShardAnchor, ShardId, StateRoot, ValidatorId,
};

/// One splitting parent's observer duty: its pre-split committee and each
/// cohort member's synced child store.
struct SplitDuty {
    members: Vec<ValidatorId>,
    synced: Vec<(
        ValidatorId,
        ShardId,
        SimShardStorage,
        ShardAnchor,
        StateRoot,
    )>,
}

/// Drives split reshape on the simulation by reacting to committed beacon state.
#[derive(Default)]
pub struct ReshapeDriver {
    splits: HashMap<ShardId, SplitDuty>,
    flipped: HashSet<ShardId>,
}

impl ReshapeDriver {
    /// Advance every in-flight reshape one step from committed beacon state:
    /// sync an admitted cohort once, re-assert its ready signal, and flip a
    /// drained-and-seeded parent's members onto their children.
    pub fn pump(&mut self, runner: &mut SimulationRunner) {
        let Some(state) = committed_beacon_state(runner) else {
            return;
        };

        // Observer duty: sync each admitted full cohort once, then re-assert
        // ready every slice until the gate drains the parent.
        for (parent, reshape) in &state.pending_reshapes {
            let PendingReshape::Split { cohort, .. } = reshape else {
                continue;
            };
            // Observe once, the first time the cohort reaches full strength.
            if !self.splits.contains_key(parent) {
                let members = committee_for(runner, *parent);
                if members.is_empty() || cohort.len() != members.len() {
                    continue;
                }
                let synced = cohort
                    .iter()
                    .map(|(validator, seat)| {
                        let (store, root, anchor) =
                            runner.observe_child(*validator, *parent, seat.child);
                        (*validator, seat.child, store, anchor, root)
                    })
                    .collect();
                self.splits.insert(*parent, SplitDuty { members, synced });
            }
            // Re-assert ready for the current cohort every slice — whatever its
            // size — re-signed against the freshest anchor. A cohort that lapses
            // and re-staffs must keep being re-asserted or the gate never fires.
            for validator in cohort.keys() {
                runner.broadcast_observer_ready(*validator, *parent);
            }
        }

        // Flip: a parent drained from `pending_reshapes` with both children
        // seeded and not yet flipped → follow each store to the terminal and
        // seat every member onto its child.
        let ready: Vec<ShardId> = self
            .splits
            .keys()
            .copied()
            .filter(|parent| {
                !self.flipped.contains(parent)
                    && !state.pending_reshapes.contains_key(parent)
                    && children_seeded(&state, *parent)
            })
            .collect();
        for parent in ready {
            let duty = self.splits.remove(&parent).expect("ready duty present");
            runner.flip_all_for(parent, &duty.members, duty.synced, &state);
            self.flipped.insert(parent);
        }
    }
}

/// Host 0's latest committed beacon state.
fn committed_beacon_state(runner: &SimulationRunner) -> Option<Arc<BeaconState>> {
    let (_, state) = runner.beacon_storage(0)?.latest_committed()?;
    Some(state)
}

/// The committee `shard` currently runs, from host 0's topology snapshot.
fn committee_for(runner: &SimulationRunner, shard: ShardId) -> Vec<ValidatorId> {
    runner
        .host_topology(0)
        .map(|topology| topology.committee_for_shard(shard).to_vec())
        .unwrap_or_default()
}

/// Whether both of `parent`'s children carry a seeded beacon anchor.
fn children_seeded(state: &BeaconState, parent: ShardId) -> bool {
    let (left, right) = parent.children();
    let seeded = |child: ShardId| {
        state
            .boundaries
            .get(&child)
            .is_some_and(|boundary| boundary.block_hash != BlockHash::ZERO)
    };
    seeded(left) && seeded(right)
}
