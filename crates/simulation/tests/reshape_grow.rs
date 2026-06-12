//! End-to-end split grow phase with real observers.
//!
//! Boots a single-shard network whose chain config arms the split
//! trigger from genesis, lets the shard's own quorum assert it and the
//! beacon fold admit it (drawing the four pooled extras as the observer
//! cohort), then runs each observer's real duty through the harness:
//! the sans-io child-span bootstrap served by the splitting shard's
//! committee, and the self-signed ready signal delivered over the
//! network — BLS-verified, pooled, drained into a block, classified as
//! a `ReshapeReady` witness leaf, and folded into the readiness gate.
//! The gate fires and the trie reshapes into the lookahead: the parent
//! membership partitions across the two children, every observer lands
//! on its assigned child, and each child stands at full committee
//! strength a full epoch before its window opens.

use std::fmt::Write;
use std::sync::Arc;
use std::time::Duration;

use hyperscale_network_memory::NetworkConfig;
use hyperscale_node::shard_loop::{ProcessScopedInput, ShardEvent};
use hyperscale_simulation::SimulationRunner;
use hyperscale_storage::{ShardChainReader, SubstateStore};
use hyperscale_storage_memory::SimShardStorage;
use hyperscale_types::test_utils::test_transaction;
use hyperscale_types::{
    BeaconChainConfig, BeaconState, BlockHash, PendingReshape, ReshapeThresholds, ShardId,
    SplitChildRoots, StateRoot, ValidatorId, ValidatorStatus,
};
use tracing_test::traced_test;

/// 2-second epochs: short enough to run the whole grow inside the
/// test budget, long enough that the beacon paces (one epoch per
/// `epoch_duration_ms`) rather than stalling against its
/// production-sized SPC/skip timeouts.
const TEST_EPOCH_MS: u64 = 2000;

/// Committee validators on the one shard — also the cohort size the
/// admission draws, so `pool_extra_validators` matches it exactly.
const PER_SHARD: u32 = 4;

/// Epochs the standing trigger gets to fold and the admission to draw.
const ADMISSION_BUDGET_EPOCHS: u64 = 8;

/// Epochs the folded `ReshapeReady` signals get to fire the gate —
/// well inside `RESHAPE_READY_TTL_EPOCHS`, so the reshape executes
/// rather than abandons.
const GATE_BUDGET_EPOCHS: u64 = 8;

/// Epochs allowed for the parent's final window, its coast to the
/// crossing, and the fold that consumes the terminal contribution.
const SEED_BUDGET_EPOCHS: u64 = 6;

/// Epochs allowed for the flipped children to commit past genesis.
const CHILD_RUN_BUDGET_EPOCHS: u64 = 4;

/// The single-shard, paced-epoch network with the split trigger armed
/// from genesis (`split_substates: 0` — every committed count
/// satisfies the predicate) and exactly one cohort's worth of pooled
/// extras.
fn grow_config() -> NetworkConfig {
    NetworkConfig {
        num_shards: 1,
        validators_per_shard: PER_SHARD,
        intra_shard_latency: Duration::from_millis(50),
        cross_shard_latency: Duration::from_millis(50),
        jitter_fraction: 0.1,
        beacon_chain_config: Some(BeaconChainConfig {
            epoch_duration_ms: TEST_EPOCH_MS,
            num_shards: 1,
            shard_size: PER_SHARD,
            reshape_thresholds: ReshapeThresholds { split_substates: 0 },
            ..BeaconChainConfig::default()
        }),
        pool_extra_validators: PER_SHARD,
        ..Default::default()
    }
}

/// Host 0's latest committed beacon state.
fn beacon_state(runner: &SimulationRunner) -> Option<Arc<BeaconState>> {
    let (_, state) = runner.beacon_storage(0)?.latest_committed()?;
    Some(state)
}

/// The pending split's cohort as `(observer, assigned child)` pairs,
/// once admitted.
fn pending_cohort(runner: &SimulationRunner) -> Option<Vec<(ValidatorId, ShardId)>> {
    let state = beacon_state(runner)?;
    let Some(PendingReshape::Split { cohort, .. }) = state.pending_reshapes.get(&ShardId::ROOT)
    else {
        return None;
    };
    Some(
        cohort
            .iter()
            .map(|(validator, seat)| (*validator, seat.child))
            .collect(),
    )
}

/// Run in one-second slices until `predicate` holds or `deadline`
/// passes.
fn run_until(
    runner: &mut SimulationRunner,
    deadline: Duration,
    mut predicate: impl FnMut(&SimulationRunner) -> bool,
) -> bool {
    while runner.now() < deadline {
        let next = runner.now() + Duration::from_secs(1);
        runner.run_until(next);
        if predicate(runner) {
            return true;
        }
    }
    false
}

const fn epochs(n: u64) -> Duration {
    Duration::from_millis(TEST_EPOCH_MS * n)
}

#[traced_test]
#[test]
#[allow(clippy::too_many_lines)] // one grow-split lifecycle asserted end to end
fn observers_grow_a_split_through_its_readiness_gate() {
    let mut runner = SimulationRunner::new(&grow_config(), 11);
    runner.initialize_genesis();
    // A handful of committed substates so the child spans the
    // observers sync carry real state, not just empty trees.
    for i in 0..6u8 {
        runner.schedule_initial_event(
            0,
            Duration::from_millis(50 + u64::from(i)),
            ShardEvent::process(ProcessScopedInput::SubmitTransaction {
                tx: Arc::new(test_transaction(i)),
            }),
        );
    }

    // ── Admission: the standing trigger folds and draws the cohort ──
    let admitted = run_until(&mut runner, epochs(ADMISSION_BUDGET_EPOCHS), |r| {
        pending_cohort(r).is_some_and(|c| c.len() == PER_SHARD as usize)
    });
    assert!(
        admitted,
        "the armed trigger must fold and draw a full cohort within \
         {ADMISSION_BUDGET_EPOCHS} epochs",
    );
    let cohort = pending_cohort(&runner).expect("cohort just observed");
    let (left, right) = ShardId::ROOT.children();
    for child in [left, right] {
        assert_eq!(
            cohort.iter().filter(|(_, c)| *c == child).count(),
            2,
            "the cohort halves must split evenly; got {cohort:?}",
        );
    }

    // ── Observer duty: sync each child span, signal ready ──
    let mut synced: Vec<(ValidatorId, ShardId, StateRoot)> = Vec::new();
    let mut synced_stores: Vec<(ValidatorId, SimShardStorage)> = Vec::new();
    for (validator, child) in &cohort {
        let (store, root) = runner.observe_child(*validator, ShardId::ROOT, *child);
        assert_eq!(
            store.state_root(),
            root,
            "the child-rooted store must hold exactly the imported subtree",
        );
        synced.push((*validator, *child, root));
        synced_stores.push((*validator, store));
    }
    // Same child, same anchor: the two observers of each half must have
    // assembled byte-identical subtrees.
    for child in [left, right] {
        let roots: Vec<StateRoot> = synced
            .iter()
            .filter(|(_, c, _)| *c == child)
            .map(|(_, _, root)| *root)
            .collect();
        assert_eq!(roots.len(), 2);
        assert_eq!(
            roots[0], roots[1],
            "co-observers of {child:?} synced against one anchor must agree",
        );
    }

    // ── The gate fires: the trie reshapes into the lookahead ──
    let gate_deadline = runner.now() + epochs(GATE_BUDGET_EPOCHS);
    let reshaped = run_until(&mut runner, gate_deadline, |r| {
        beacon_state(r).is_some_and(|s| {
            s.pending_reshapes.is_empty() && s.next_shard_committees.contains_key(&left)
        })
    });
    assert!(
        reshaped,
        "the folded ReshapeReady signals must fire the gate within \
         {GATE_BUDGET_EPOCHS} epochs",
    );

    let state = beacon_state(&runner).expect("post-gate state");
    assert!(
        !state.next_shard_committees.contains_key(&ShardId::ROOT),
        "the lookahead must carry the children, not the parent",
    );
    for child in [left, right] {
        assert_eq!(
            state.next_shard_committees[&child].members.len(),
            PER_SHARD as usize,
            "each child must start at full committee strength",
        );
    }
    // Every observer landed on its assigned child — placed by the
    // execution, ready via its folded signal or the normal path after.
    for (validator, child, _) in &synced {
        let status = state.validators[validator].status;
        assert!(
            matches!(status, ValidatorStatus::OnShard { shard, .. } if shard == *child),
            "observer {validator:?} must land on {child:?}; got {status:?}",
        );
    }
    // The parent membership partitioned across the children: every
    // original member sits on exactly one child.
    let mut parent_halves: Vec<(ValidatorId, ShardId)> = Vec::new();
    for member in 0..u64::from(PER_SHARD) {
        let id = ValidatorId::new(member);
        let status = state.validators[&id].status;
        match status {
            ValidatorStatus::OnShard { shard, .. } if shard.parent() == Some(ShardId::ROOT) => {
                parent_halves.push((id, shard));
            }
            other => panic!("parent member {member} must land on a child; got {other:?}"),
        }
    }
    let parent_terminal_root = runner
        .node_storage(0)
        .expect("host 0 carries the parent")
        .state_root();

    // ── Through the boundary: the parent coasts to its crossing and
    // the fold seeds both children from its terminal contribution ──
    let seed_deadline = runner.now() + epochs(SEED_BUDGET_EPOCHS);
    let seeded = run_until(&mut runner, seed_deadline, |r| {
        beacon_state(r).is_some_and(|s| {
            [left, right].iter().all(|c| {
                s.boundaries
                    .get(c)
                    .is_some_and(|b| b.block_hash != BlockHash::ZERO)
            })
        })
    });
    if !seeded {
        let s = beacon_state(&runner).expect("state");
        let storage = runner.node_storage(0).expect("host 0 carries the parent");
        let committed = storage.committed_height();
        let mut tail = String::new();
        let mut height = committed;
        for _ in 0..6 {
            if let Some(block) = storage.get_block(height) {
                let header = block.block().header();
                let _ = write!(
                    tail,
                    "\n  h={height:?} child_roots={:?} parent_qc_wt={:?} root={:?}",
                    header.split_child_roots(),
                    header.parent_qc().weighted_timestamp(),
                    header.state_root(),
                );
            }
            let Some(prev) = height.prev() else { break };
            height = prev;
        }
        panic!(
            "seeding timed out; boundaries: {:?}; parent committed: {committed:?}; \
             parent root: {:?}; epoch {:?}; parent tail:{tail}",
            s.boundaries,
            storage.state_root(),
            s.current_epoch,
        );
    }
    let state = beacon_state(&runner).expect("post-seed state");
    assert!(
        !state.boundaries.contains_key(&ShardId::ROOT),
        "the parent's terminal record must drop once consumed and drained",
    );
    // Subtree-root continuity, the keystone: the seeded anchors are
    // exactly the parent terminal root's two children.
    let pair = SplitChildRoots {
        left: state.boundaries[&left].state_root,
        right: state.boundaries[&right].state_root,
    };
    assert!(
        pair.composes_to(parent_terminal_root),
        "the children's anchors must compose to the parent's terminal root",
    );

    // ── The flip: parent halves clone-and-adopt on their own hosts;
    // each observer's synced store reopens on a host whose own vnode
    // flipped to the sibling (a pool extra runs no host in sim, so the
    // harness seats it cross-shard — production observers run their
    // own hosts through the supervisor) ──
    for (validator, child) in &parent_halves {
        let node = u32::try_from(validator.inner()).expect("host per parent member");
        runner.flip_split_child(node, *validator, ShardId::ROOT, *child, None);
    }
    let mut sibling_hosts: Vec<u32> = Vec::new();
    for (validator, child, _) in &synced {
        let (node, _) = parent_halves
            .iter()
            .map(|(v, c)| (u32::try_from(v.inner()).expect("host index"), *c))
            .find(|(node, host_child)| host_child != child && !sibling_hosts.contains(node))
            .expect("a free host whose own vnode flipped to the sibling");
        sibling_hosts.push(node);
        let store = synced_stores
            .iter()
            .position(|(v, _)| v == validator)
            .map(|i| synced_stores.swap_remove(i).1)
            .expect("every observer synced a store");
        runner.flip_split_child(node, *validator, ShardId::ROOT, *child, Some(store));
    }

    // ── Both children run: blocks commit past their genesis on every
    // seated member, from state continuous with the parent's subtree ──
    let genesis_height = state.boundaries[&left].height;
    let run_deadline = runner.now() + epochs(CHILD_RUN_BUDGET_EPOCHS);
    let progressed = run_until(&mut runner, run_deadline, |r| {
        [left, right].iter().all(|child| {
            (0..r.num_hosts()).any(|node| {
                r.hosts_shard(node, *child)
                    .is_some_and(|storage| storage.committed_height() > genesis_height)
            })
        })
    });
    if !progressed {
        let s = beacon_state(&runner).expect("state");
        let mut detail = String::new();
        for child in [left, right] {
            for node in 0..runner.num_hosts() {
                if let Some(storage) = runner.hosts_shard(node, child) {
                    let _ = write!(
                        detail,
                        "\n  node {node} {child:?}: committed {:?} root {:?}",
                        storage.committed_height(),
                        storage.state_root(),
                    );
                }
            }
        }
        panic!(
            "both children must commit blocks past their genesis (h{}) within \
             {CHILD_RUN_BUDGET_EPOCHS} epochs; epoch {:?}; stores:{detail}",
            genesis_height.inner(),
            s.current_epoch,
        );
    }

    // Every committed child chain extends the deterministic genesis the
    // beacon anchored: the first committed block names the genesis as
    // its parent and certifies it with a structural genesis QC carrying
    // the parent chain's terminal clock.
    for child in [left, right] {
        let anchor = state.boundaries[&child];
        for node in 0..runner.num_hosts() {
            let Some(storage) = runner.hosts_shard(node, child) else {
                continue;
            };
            if storage.committed_height() <= genesis_height {
                continue;
            }
            let first = storage
                .get_block(genesis_height.next())
                .expect("committed chains are contiguous from genesis");
            let header = first.block().header();
            assert_eq!(header.parent_block_hash(), anchor.block_hash);
            assert!(header.parent_qc().is_genesis());
            assert_eq!(header.parent_qc().height(), genesis_height);
        }
    }
}
