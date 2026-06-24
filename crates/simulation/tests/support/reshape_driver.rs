//! `ReshapeDriver`: the simulation's reactive reshape orchestrator.
//!
//! The deterministic counterpart of the production `ShardSupervisor`'s reshape
//! duties. `SimCluster::run_until` pumps it once per slice; every action is
//! idempotent — guarded by what committed beacon state shows versus what the
//! driver has already done — so pumping every slice is safe. It reuses the
//! runner's existing reshape methods (`observe_child`, `broadcast_observer_ready`,
//! `flip_all_for`); only *when* they fire is decided here.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use hyperscale_network_memory::NodeIndex;
use hyperscale_node::reshape::view::ReshapeView;
use hyperscale_simulation::SimulationRunner;
use hyperscale_storage_memory::SimShardStorage;
use hyperscale_types::{BeaconState, PendingReshape, ShardAnchor, ShardId, StateRoot, ValidatorId};

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

/// One merging parent's keeper duty: the keeper set drawn for the merge.
struct MergeDuty {
    keepers: Vec<ValidatorId>,
}

/// Drives reshape on the simulation by reacting to committed beacon state.
#[derive(Default)]
pub struct ReshapeDriver {
    splits: HashMap<ShardId, SplitDuty>,
    flipped: HashSet<ShardId>,
    merges: HashMap<ShardId, MergeDuty>,
    merge_flipped: HashSet<ShardId>,
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

        // Keeper duty: sync each paired full keeper set's sibling half once, then
        // re-assert ready every slice until the gate collapses the children into
        // the parent.
        for (parent, reshape) in &state.pending_reshapes {
            let PendingReshape::Merge {
                keepers,
                admitted_at: Some(_),
                ..
            } = reshape
            else {
                continue;
            };
            if !self.merges.contains_key(parent) {
                if keepers.len() != state.chain_config.shard_size as usize {
                    continue;
                }
                for (validator, seat) in keepers {
                    let sibling = seat.child.sibling().expect("a merging child has a sibling");
                    runner.merge_keeper(*validator, seat.child, sibling);
                }
                self.merges.insert(
                    *parent,
                    MergeDuty {
                        keepers: keepers.keys().copied().collect(),
                    },
                );
            }
            for (validator, seat) in keepers {
                runner.broadcast_keeper_ready(*validator, seat.child);
            }
        }

        // Flip gate, read through the shared `ReshapeView` over host 0's
        // topology projection — the same seeding predicate the production
        // supervisor flips on. The projection drops zeroed placeholders, so
        // `children_seeded`/`parent_composed` match the raw-boundary checks
        // this driver used to hand-roll.
        let Some(topology) = runner.host_topology(0) else {
            return;
        };
        let view = ReshapeView::new(&topology);

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
                    && view.children_seeded(*parent)
            })
            .collect();
        for parent in ready {
            let duty = self.splits.remove(&parent).expect("ready duty present");
            runner.flip_all_for(parent, &duty.members, duty.synced, &state);
            self.flipped.insert(parent);
        }

        // Merge flip: a parent drained from `pending_reshapes` whose composed
        // anchor is seeded and not yet flipped → seat each host's keepers onto
        // the reformed parent against the composed merged store.
        let merge_ready: Vec<ShardId> = self
            .merges
            .keys()
            .copied()
            .filter(|parent| {
                !self.merge_flipped.contains(parent)
                    && !state.pending_reshapes.contains_key(parent)
                    && view.parent_composed(*parent)
            })
            .collect();
        for parent in merge_ready {
            let duty = self
                .merges
                .remove(&parent)
                .expect("ready merge duty present");
            flip_merge_by_host(runner, parent, &duty.keepers);
            self.merge_flipped.insert(parent);
        }
    }
}

/// Group `keepers` by host and seat each host's set onto the reformed `parent` —
/// a merge converges every keeper onto the one parent shard, so co-hosted
/// keepers seat against the single shared merged store together.
fn flip_merge_by_host(runner: &mut SimulationRunner, parent: ShardId, keepers: &[ValidatorId]) {
    let mut by_node: BTreeMap<NodeIndex, Vec<ValidatorId>> = BTreeMap::new();
    for &validator in keepers {
        let node = runner.network().validator_to_node(validator);
        by_node.entry(node).or_default().push(validator);
    }
    for (node, validators) in &by_node {
        runner.flip_merge_parent(*node, validators, parent);
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
