//! Grow a single-shard genesis to a target topology by driving real splits.
//!
//! The simulation counterpart of a network that launches single-shard and
//! fans out under load: starting from one root shard, this walks each split
//! through its full lifecycle — the armed trigger folds and the beacon draws
//! the cohort from the pooled extras, every cohort member runs its observer
//! duty ([`SimulationRunner::observe_child`]) and re-asserts its ready signal
//! until the readiness gate reshapes the children into the lookahead, the
//! parent coasts to its crossing and seeds both child anchors, every store
//! follows the parent to its terminal root, and each member flips onto its
//! assigned child. Every leaf of one generation splits together — an admitted
//! split that no one drives stalls the beacon fold the others depend on —
//! so the runner is left positioned exactly where a multi-shard genesis used
//! to leave it: every child at full committee strength, committing past its
//! genesis.

use std::sync::Arc;
use std::time::Duration;

use hyperscale_network_memory::NodeIndex;
use hyperscale_storage::ShardChainReader;
use hyperscale_storage_memory::SimShardStorage;
use hyperscale_types::{
    BeaconState, BlockHash, BlockHeight, PendingReshape, ShardAnchor, ShardId, StateRoot,
    TopologySnapshot, ValidatorId, ValidatorStatus,
};

use super::SimulationRunner;

/// Epochs the standing trigger gets to fold and the admission to draw a cohort.
const ADMISSION_BUDGET_EPOCHS: u64 = 8;

/// Epochs the folded ready signals get to fire the readiness gate.
const GATE_BUDGET_EPOCHS: u64 = 10;

/// Epochs the parent gets to coast to its crossing and seed both child anchors.
const SEED_BUDGET_EPOCHS: u64 = 12;

/// Epochs the flipped children get to commit past their genesis.
const CHILD_RUN_BUDGET_EPOCHS: u64 = 6;

/// One frontier leaf's split, carried through the generation's phases.
struct PendingSplit {
    /// The splitting leaf.
    parent: ShardId,
    /// Its two children, `parent.children()`.
    left: ShardId,
    right: ShardId,
    /// The parent's pre-split committee — the members that partition across the
    /// children when the gate fires.
    members: Vec<ValidatorId>,
    /// Each cohort member's synced child store, its imported root, and the
    /// anchor the sync verified against.
    synced: Vec<(
        ValidatorId,
        ShardId,
        SimShardStorage,
        ShardAnchor,
        StateRoot,
    )>,
}

impl SimulationRunner {
    /// Grow the current single-shard topology until it holds `target_shards`
    /// leaves, splitting every frontier leaf together once per generation.
    ///
    /// The caller must have run genesis first
    /// (`initialize_genesis` / `initialize_genesis_with_balances`) and armed
    /// the split trigger (`ReshapeThresholds { split_bytes: 0 }`) with one
    /// cohort of pooled extras per split — `(target_shards - 1) * shard_size`
    /// in total. Returns once every leaf at depth `log2(target_shards)` stands
    /// at full committee strength and commits past its child genesis.
    ///
    /// # Panics
    ///
    /// Panics if `target_shards` is not a power of two, or if any split fails
    /// to admit, gate, seed, or run within its epoch budget.
    pub fn grow_to(&mut self, target_shards: u32) {
        assert!(
            target_shards.is_power_of_two(),
            "grow_to target must be a power of two; got {target_shards}",
        );
        loop {
            let frontier = self.current_leaf_shards();
            if frontier.len() as u64 >= u64::from(target_shards) {
                break;
            }
            self.split_frontier(&frontier);
        }
    }

    /// Drive every leaf in `parents` through one split generation together,
    /// leaving each child seated at full strength and committing past genesis.
    fn split_frontier(&mut self, parents: &[ShardId]) {
        let mut splits = self.prepare_splits(parents);
        self.await_admission(&splits);
        self.observe_all(&mut splits);
        self.await_gate(&splits);
        self.await_seed(&splits);

        let state = self
            .committed_beacon_state()
            .expect("post-gate beacon state");
        let children_genesis: Vec<(ShardId, BlockHeight)> = splits
            .iter()
            .flat_map(|split| [split.left, split.right])
            .map(|child| (child, state.boundaries[&child].height))
            .collect();

        self.flip_all(splits, &state);
        self.await_children(&children_genesis);
    }

    /// Capture each frontier leaf's children and pre-split committee.
    fn prepare_splits(&self, parents: &[ShardId]) -> Vec<PendingSplit> {
        parents
            .iter()
            .map(|&parent| {
                let (left, right) = parent.children();
                let members = self.snapshot().committee_for_shard(parent).to_vec();
                PendingSplit {
                    parent,
                    left,
                    right,
                    members,
                    synced: Vec::new(),
                }
            })
            .collect()
    }

    /// Wait until the armed trigger folds and the beacon draws a full cohort
    /// for every frontier split.
    fn await_admission(&mut self, splits: &[PendingSplit]) {
        let deadline = self.now + self.epochs(ADMISSION_BUDGET_EPOCHS);
        let admitted = self.run_until_predicate(deadline, |r| {
            splits.iter().all(|split| {
                r.pending_split_cohort(split.parent)
                    .is_some_and(|cohort| cohort.len() == split.members.len())
            })
        });
        assert!(
            admitted,
            "every frontier split must draw a full cohort within \
             {ADMISSION_BUDGET_EPOCHS} epochs",
        );
    }

    /// Run each cohort member's observer duty: sync its assigned child span and
    /// signal ready.
    fn observe_all(&mut self, splits: &mut [PendingSplit]) {
        for split in splits.iter_mut() {
            let parent = split.parent;
            let cohort = self
                .pending_split_cohort(parent)
                .expect("cohort just admitted");
            for (validator, child) in cohort {
                let (store, root, anchor) = self.observe_child(validator, parent, child);
                split.synced.push((validator, child, store, anchor, root));
            }
        }
    }

    /// Re-assert every cohort's ready signal until all frontier splits reshape
    /// their children into the lookahead.
    fn await_gate(&mut self, splits: &[PendingSplit]) {
        let deadline = self.now + self.epochs(GATE_BUDGET_EPOCHS);
        let mut reshaped = false;
        while self.now < deadline {
            for split in splits {
                if let Some(cohort) = self.pending_split_cohort(split.parent) {
                    for (validator, _) in cohort {
                        self.broadcast_observer_ready(validator, split.parent);
                    }
                }
            }
            let next = self.now + Duration::from_secs(1);
            self.run_until(next);
            if self.all_reshaped(splits) {
                reshaped = true;
                break;
            }
        }
        assert!(
            reshaped,
            "every frontier split's ready signals must fire the gate within \
             {GATE_BUDGET_EPOCHS} epochs",
        );
    }

    /// Whether every split's parent has drained from `pending_reshapes` and its
    /// children stand in the lookahead.
    fn all_reshaped(&self, splits: &[PendingSplit]) -> bool {
        self.committed_beacon_state().is_some_and(|state| {
            splits.iter().all(|split| {
                !state.pending_reshapes.contains_key(&split.parent)
                    && state.next_shard_committees.contains_key(&split.left)
            })
        })
    }

    /// Wait until every parent coasts to its crossing and seeds both child
    /// anchors from its terminal contribution.
    fn await_seed(&mut self, splits: &[PendingSplit]) {
        let deadline = self.now + self.epochs(SEED_BUDGET_EPOCHS);
        let seeded = self.run_until_predicate(deadline, |r| {
            r.committed_beacon_state().is_some_and(|state| {
                splits.iter().all(|split| {
                    [split.left, split.right].iter().all(|child| {
                        state
                            .boundaries
                            .get(child)
                            .is_some_and(|boundary| boundary.block_hash != BlockHash::ZERO)
                    })
                })
            })
        });
        assert!(
            seeded,
            "every frontier split must seed both child anchors within \
             {SEED_BUDGET_EPOCHS} epochs",
        );
    }

    /// Follow each synced store to the parent's terminal root, then flip every
    /// member onto its assigned child.
    fn flip_all(&mut self, splits: Vec<PendingSplit>, state: &BeaconState) {
        for split in splits {
            let parent_halves: Vec<(ValidatorId, ShardId)> = split
                .members
                .iter()
                .map(|member| {
                    let status = state.validators[member].status;
                    let ValidatorStatus::OnShard { shard, .. } = status else {
                        panic!(
                            "parent member {member:?} must land on a child of {:?}; got {status:?}",
                            split.parent,
                        )
                    };
                    (*member, shard)
                })
                .collect();
            for (_, child, store, anchor, imported_root) in &split.synced {
                self.follow_child(store, split.parent, *child, *anchor, *imported_root);
            }
            self.flip_split_members(split.parent, &parent_halves, split.synced);
        }
    }

    /// Flip every member onto its assigned child: parent halves clone-and-adopt
    /// on their own hosts; each observer reopens its synced store on a host of
    /// its own.
    ///
    /// With [`NetworkConfig::dedicated_pool_hosts`] every observer seats on its
    /// own dedicated host — kept current by the beacon follower that ran there
    /// since construction — and that follower is dropped once the shard vnode
    /// is seated, so the validator runs a single coordinator and every
    /// committee member ends on a single shard (the layout the shuffle's
    /// cross-shard relocation needs). Otherwise an observer co-hosts on a host
    /// whose own vnode flipped to the sibling child.
    ///
    /// [`NetworkConfig::dedicated_pool_hosts`]: hyperscale_network_memory::NetworkConfig::dedicated_pool_hosts
    fn flip_split_members(
        &mut self,
        parent: ShardId,
        parent_halves: &[(ValidatorId, ShardId)],
        synced: Vec<(
            ValidatorId,
            ShardId,
            SimShardStorage,
            ShardAnchor,
            StateRoot,
        )>,
    ) {
        for (member, child) in parent_halves {
            let node = self.network.validator_to_node(*member);
            self.flip_split_child(node, *member, parent, *child, None);
        }
        let dedicated = self.config.dedicated_pool_hosts;
        let mut sibling_hosts: Vec<NodeIndex> = Vec::new();
        for (validator, child, store, _, _) in synced {
            let node = if dedicated {
                self.network.validator_to_node(validator)
            } else {
                let node = parent_halves
                    .iter()
                    .map(|(member, member_child)| {
                        (self.network.validator_to_node(*member), *member_child)
                    })
                    .find(|(node, member_child)| {
                        *member_child != child && !sibling_hosts.contains(node)
                    })
                    .map(|(node, _)| node)
                    .expect("a free host whose own vnode flipped to the sibling");
                sibling_hosts.push(node);
                node
            };
            self.flip_split_child(node, validator, parent, child, Some(store));
            if dedicated {
                // The seat rebuilt the validator's coordinator from the host's
                // warm beacon storage; retire the now-redundant follower.
                self.hosts[node as usize].drop_pooled_vnode(validator);
            }
        }
    }

    /// Wait until every grown child commits past its genesis on a seated host.
    fn await_children(&mut self, children_genesis: &[(ShardId, BlockHeight)]) {
        let deadline = self.now + self.epochs(CHILD_RUN_BUDGET_EPOCHS);
        let progressed = self.run_until_predicate(deadline, |r| {
            children_genesis.iter().all(|(child, genesis_height)| {
                (0..r.num_hosts()).any(|node| {
                    r.hosts_shard(node, *child)
                        .is_some_and(|storage| storage.committed_height() > *genesis_height)
                })
            })
        });
        assert!(
            progressed,
            "every grown child must commit past genesis within \
             {CHILD_RUN_BUDGET_EPOCHS} epochs",
        );
    }

    /// The current live leaf shards, read from host 0's topology snapshot.
    fn current_leaf_shards(&self) -> Vec<ShardId> {
        self.snapshot().shard_trie().leaves().collect()
    }

    /// Host 0's latest topology snapshot.
    fn snapshot(&self) -> Arc<TopologySnapshot> {
        self.host_topology(0).expect("host 0 carries a topology")
    }

    /// Host 0's latest committed beacon state.
    fn committed_beacon_state(&self) -> Option<Arc<BeaconState>> {
        let (_, state) = self.beacon_storage(0)?.latest_committed()?;
        Some(state)
    }

    /// The pending split's cohort for `parent` as `(observer, child)` pairs,
    /// once admitted.
    fn pending_split_cohort(&self, parent: ShardId) -> Option<Vec<(ValidatorId, ShardId)>> {
        let state = self.committed_beacon_state()?;
        let PendingReshape::Split { cohort, .. } = state.pending_reshapes.get(&parent)? else {
            return None;
        };
        Some(
            cohort
                .iter()
                .map(|(validator, seat)| (*validator, seat.child))
                .collect(),
        )
    }

    /// Run in one-second slices until `predicate` holds or `deadline` passes.
    fn run_until_predicate(
        &mut self,
        deadline: Duration,
        mut predicate: impl FnMut(&Self) -> bool,
    ) -> bool {
        while self.now < deadline {
            let next = self.now + Duration::from_secs(1);
            self.run_until(next);
            if predicate(self) {
                return true;
            }
        }
        false
    }

    /// `n` beacon epochs as a duration, from the configured epoch length.
    const fn epochs(&self, n: u64) -> Duration {
        Duration::from_millis(self.epoch_duration_ms.saturating_mul(n))
    }
}
