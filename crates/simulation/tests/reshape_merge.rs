//! End-to-end merge of two cold sibling shards back into their parent.
//!
//! Boots a two-shard network whose chain config makes both shards
//! merge-eligible from genesis (their genesis substate counts sit below
//! `MERGE_THRESHOLD = split_substates / 8`), lets each child's quorum
//! assert the merge and the beacon pair it — drawing half of each
//! child's committee as the keeper set — then runs each keeper's real
//! duty: the sibling-half sync served by the sibling's committee, and
//! the self-signed ready signal delivered over its own child's network,
//! BLS-verified, pooled, drained into a block, classified as a
//! `ReshapeReady` leaf, and folded into the merge gate. The gate fires,
//! the trie collapses both children into their parent in the lookahead,
//! the children coast to their crossing and the beacon composes the
//! parent anchor from their terminal roots, and the keepers flip onto
//! the parent — its committed root the `hash_internal` of the two child
//! terminal roots, its chain continuing past the merged genesis.

use std::sync::Arc;
use std::time::Duration;

use hyperscale_network_memory::NetworkConfig;
use hyperscale_simulation::SimulationRunner;
use hyperscale_storage::{ShardChainReader, SubstateStore};
use hyperscale_types::{
    BeaconChainConfig, BeaconState, BlockHash, KeeperSeat, PendingReshape, ReshapeThresholds,
    ShardId, SplitChildRoots, StateRoot, ValidatorId, ValidatorStatus,
};
use tracing_test::traced_test;

/// 2-second epochs — short enough to run the whole merge inside the test
/// budget, long enough that the beacon paces by wall clock rather than
/// stalling against production-sized SPC/skip timeouts.
const TEST_EPOCH_MS: u64 = 2000;

/// Committee size on each child shard.
const PER_SHARD: u32 = 4;

/// `split_substates / 8` is the merge threshold; at 4000 it is 500,
/// comfortably above the ~293 substates genesis lays into each child, so
/// both children assert the merge from genesis and neither splits.
const SPLIT_SUBSTATES: u64 = 4000;

const ADMISSION_BUDGET_EPOCHS: u64 = 8;
const GATE_BUDGET_EPOCHS: u64 = 8;
const COMPOSE_BUDGET_EPOCHS: u64 = 14;
const PARENT_RUN_BUDGET_EPOCHS: u64 = 6;

/// Two sibling shards (`leaf(1,0)`, `leaf(1,1)`) merging into `ROOT`,
/// paced epochs, merge armed from genesis.
fn merge_config() -> NetworkConfig {
    NetworkConfig {
        num_shards: 2,
        validators_per_shard: PER_SHARD,
        intra_shard_latency: Duration::from_millis(50),
        cross_shard_latency: Duration::from_millis(50),
        jitter_fraction: 0.1,
        beacon_chain_config: Some(BeaconChainConfig {
            epoch_duration_ms: TEST_EPOCH_MS,
            num_shards: 2,
            shard_size: PER_SHARD,
            reshape_thresholds: ReshapeThresholds {
                split_substates: SPLIT_SUBSTATES,
            },
            ..BeaconChainConfig::default()
        }),
        pool_extra_validators: 0,
        ..Default::default()
    }
}

fn beacon_state(runner: &SimulationRunner) -> Option<Arc<BeaconState>> {
    let (_, state) = runner.beacon_storage(0)?.latest_committed()?;
    Some(state)
}

/// The pending merge's keepers as `(validator, the child it runs)`
/// pairs, once paired.
fn pending_keepers(runner: &SimulationRunner) -> Option<Vec<(ValidatorId, ShardId)>> {
    let state = beacon_state(runner)?;
    let Some(PendingReshape::Merge {
        keepers,
        admitted_at: Some(_),
        ..
    }) = state.pending_reshapes.get(&ShardId::ROOT)
    else {
        return None;
    };
    Some(
        keepers
            .iter()
            .map(|(validator, seat): (&ValidatorId, &KeeperSeat)| (*validator, seat.child))
            .collect(),
    )
}

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
#[allow(clippy::too_many_lines)] // one merge lifecycle asserted end to end
fn keepers_merge_two_cold_siblings_into_their_parent() {
    let (left, right) = ShardId::ROOT.children();
    let mut runner = SimulationRunner::new(&merge_config(), 8);
    runner.initialize_genesis();

    // ── Admission: each child asserts the merge; the beacon pairs and
    // draws the keeper committee ──
    let paired = run_until(&mut runner, epochs(ADMISSION_BUDGET_EPOCHS), |r| {
        pending_keepers(r).is_some_and(|k| k.len() == PER_SHARD as usize)
    });
    assert!(
        paired,
        "both children must assert the merge and pair a full keeper set within \
         {ADMISSION_BUDGET_EPOCHS} epochs",
    );
    let keepers = pending_keepers(&runner).expect("keepers just observed");
    for child in [left, right] {
        assert_eq!(
            keepers.iter().filter(|(_, c)| *c == child).count(),
            (PER_SHARD / 2) as usize,
            "each child contributes half the keeper committee; got {keepers:?}",
        );
    }

    // ── Keeper duty: sync the sibling half, signal ready ──
    for (validator, own_child) in &keepers {
        let sibling = if *own_child == left { right } else { left };
        runner.merge_keeper(*validator, *own_child, sibling);
    }

    // ── The gate fires: the trie collapses both children into the
    // parent in the lookahead ──
    let gate_deadline = runner.now() + epochs(GATE_BUDGET_EPOCHS);
    let reshaped = run_until(&mut runner, gate_deadline, |r| {
        beacon_state(r).is_some_and(|s| {
            s.pending_reshapes.is_empty() && s.next_shard_committees.contains_key(&ShardId::ROOT)
        })
    });
    assert!(
        reshaped,
        "the folded ReshapeReady signals must fire the merge gate within \
         {GATE_BUDGET_EPOCHS} epochs",
    );
    let state = beacon_state(&runner).expect("post-gate state");
    assert!(
        !state.next_shard_committees.contains_key(&left)
            && !state.next_shard_committees.contains_key(&right),
        "the lookahead must carry the parent, not the children",
    );
    assert_eq!(
        state.next_shard_committees[&ShardId::ROOT].members.len(),
        PER_SHARD as usize,
        "the merged committee starts at full strength (the keepers)",
    );
    // Every keeper landed on the parent; the non-keeper half returned to
    // the pool.
    for (validator, _) in &keepers {
        let status = state.validators[validator].status;
        assert!(
            matches!(status, ValidatorStatus::OnShard { shard, .. } if shard == ShardId::ROOT),
            "keeper {validator:?} must land on the parent; got {status:?}",
        );
    }

    // ── Through the boundary: the children coast to their crossing and
    // the beacon composes the parent anchor from their terminal roots ──
    let compose_deadline = runner.now() + epochs(COMPOSE_BUDGET_EPOCHS);
    let composed = run_until(&mut runner, compose_deadline, |r| {
        beacon_state(r).is_some_and(|s| {
            s.boundaries
                .get(&ShardId::ROOT)
                .is_some_and(|b| b.block_hash != BlockHash::ZERO)
        })
    });
    if !composed {
        let s = beacon_state(&runner).expect("state");
        let mut detail = String::new();
        for child in [left, right] {
            for node in 0..runner.num_hosts() {
                if let Some(storage) = runner.hosts_shard(node, child) {
                    use std::fmt::Write;
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
            "compose timed out; epoch {:?}; boundaries {:?}; pending {:?}; committee {:?}; stores:{detail}",
            s.current_epoch,
            s.boundaries,
            s.pending_reshapes.keys().collect::<Vec<_>>(),
            s.committee.len(),
        );
    }

    // Subtree-root continuity, the keystone: the composed parent anchor
    // is `hash_internal` of the two children's terminal roots.
    let state = beacon_state(&runner).expect("post-compose state");
    let left_terminal_root = child_terminal_root(&runner, left);
    let right_terminal_root = child_terminal_root(&runner, right);
    let pair = SplitChildRoots {
        left: left_terminal_root,
        right: right_terminal_root,
    };
    assert_eq!(
        pair.composed_root(),
        state.boundaries[&ShardId::ROOT].state_root,
        "the parent anchor must be hash_internal of the two child terminal roots",
    );

    // ── The flip: each keeper builds the merged store from both halves
    // and seats onto the parent ──
    let parent_anchor = state.boundaries[&ShardId::ROOT];
    for (validator, _) in &keepers {
        let node = u32::try_from(validator.inner()).expect("host per keeper");
        let adopted = runner.flip_merge_parent(node, *validator, ShardId::ROOT);
        assert_eq!(
            adopted, parent_anchor.state_root,
            "every keeper adopts the same beacon-composed merged root",
        );
    }

    // ── The merged chain runs: blocks commit past the merged genesis,
    // from state continuous with both children's subtrees ──
    let genesis_height = parent_anchor.height;
    let run_deadline = runner.now() + epochs(PARENT_RUN_BUDGET_EPOCHS);
    let progressed = run_until(&mut runner, run_deadline, |r| {
        (0..r.num_hosts()).any(|node| {
            r.hosts_shard(node, ShardId::ROOT)
                .is_some_and(|storage| storage.committed_height() > genesis_height)
        })
    });
    assert!(
        progressed,
        "the merged shard must commit past its genesis (h{}) within \
         {PARENT_RUN_BUDGET_EPOCHS} epochs",
        genesis_height.inner(),
    );

    // Every merged store holds the deterministic genesis as its committed
    // base, and every committed chain extends it.
    for node in 0..runner.num_hosts() {
        let Some(storage) = runner.hosts_shard(node, ShardId::ROOT) else {
            continue;
        };
        let genesis = storage
            .get_block(genesis_height)
            .expect("the adoption recorded the merged genesis as the committed tip");
        assert_eq!(genesis.block().hash(), parent_anchor.block_hash);
        assert_eq!(
            genesis.block().header().state_root(),
            parent_anchor.state_root
        );
    }
}

/// The terminal subtree root of a terminated child, read from a host
/// still carrying it.
fn child_terminal_root(runner: &SimulationRunner, child: ShardId) -> StateRoot {
    for node in 0..runner.num_hosts() {
        if let Some(storage) = runner.hosts_shard(node, child) {
            return storage.state_root();
        }
    }
    panic!("no host carries the terminated child {child:?}");
}
