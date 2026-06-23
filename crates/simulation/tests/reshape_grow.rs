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

use hyperscale_node::shard::{HostEvent, ProcessScopedInput};
use hyperscale_simulation::{EPOCH_MS, SimConfig, SimulationRunner};
use hyperscale_storage::{ShardChainReader, SubstateStore};
use hyperscale_storage_memory::SimShardStorage;
use hyperscale_types::{
    BeaconChainConfig, BeaconState, BlockHash, PendingReshape, ReshapeThresholds, ShardAnchor,
    ShardId, SplitChildRoots, StateRoot, TimestampRange, ValidatorId, ValidatorStatus,
    WeightedTimestamp, ed25519_keypair_from_seed, routable_from_notarized_v1, sign_and_notarize,
};
use radix_common::constants::XRD;
use radix_common::math::Decimal;
use radix_common::network::NetworkDefinition;
use radix_common::types::ComponentAddress;
use radix_transactions::builder::ManifestBuilder;
use tracing_test::traced_test;

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
/// from genesis (`split_bytes: 0` — every committed count
/// satisfies the predicate) and exactly one cohort's worth of pooled
/// extras.
fn grow_config() -> SimConfig {
    SimConfig {
        num_shards: 1,
        validators_per_shard: PER_SHARD,
        jitter_fraction: 0.1,
        beacon_chain_config: Some(BeaconChainConfig {
            epoch_duration_ms: EPOCH_MS,
            num_shards: 1,
            shard_size: PER_SHARD,
            reshape_thresholds: ReshapeThresholds { split_bytes: 0 },
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
    Duration::from_millis(EPOCH_MS * n)
}

#[traced_test]
#[test]
#[allow(clippy::too_many_lines)] // one grow-split lifecycle asserted end to end
fn observers_grow_a_split_through_its_readiness_gate() {
    let mut runner = SimulationRunner::new(&grow_config(), 11);
    // Two pre-funded accounts give the grow a real transfer to commit
    // mid-flight (the engine genesis itself populates both child spans
    // with substates).
    let payer_key = ed25519_keypair_from_seed(&[31; 32]);
    let payer = ComponentAddress::preallocated_account_from_public_key(&payer_key.public_key());
    let recipient = ComponentAddress::preallocated_account_from_public_key(
        &ed25519_keypair_from_seed(&[32; 32]).public_key(),
    );
    runner.initialize_genesis_with_balances(&[
        (payer, Decimal::from(10_000)),
        (recipient, Decimal::from(10_000)),
    ]);

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
    let mut synced_stores: Vec<(
        ValidatorId,
        ShardId,
        SimShardStorage,
        ShardAnchor,
        StateRoot,
    )> = Vec::new();
    for (validator, child) in &cohort {
        let (store, root, anchor) = runner.observe_child(*validator, ShardId::ROOT, *child);
        assert_eq!(
            store.state_root(),
            root,
            "the child-rooted store must hold exactly the imported subtree",
        );
        synced.push((*validator, *child, root));
        synced_stores.push((*validator, *child, store, anchor, root));
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

    // ── The gate fires: the trie reshapes into the lookahead. Each
    // observer re-asserts its ready signal until then — the cohort promotes
    // into the active reshape-observer window only a window after admission
    // (the freeze discipline), and the parent's blocks anchor in that
    // window only as their `parent_qc.wt` catches up, so a one-shot signal
    // can land while it still classifies as a plain `Ready`. ──
    let gate_deadline = runner.now() + epochs(GATE_BUDGET_EPOCHS);
    let mut reshaped = false;
    while runner.now() < gate_deadline {
        if let Some(current) = pending_cohort(&runner) {
            for (validator, _child) in &current {
                runner.broadcast_observer_ready(*validator, ShardId::ROOT);
            }
        }
        let next = runner.now() + Duration::from_secs(1);
        runner.run_until(next);
        if beacon_state(&runner).is_some_and(|s| {
            s.pending_reshapes.is_empty() && s.next_shard_committees.contains_key(&left)
        }) {
            reshaped = true;
            break;
        }
    }
    assert!(
        reshaped,
        "the re-asserted ReshapeReady signals must fire the gate within \
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
    // ── Staleness pressure: a real transfer commits in the parent's
    // final window, so the observers' anchor-time stores fall behind
    // the terminal root their child genesis will adopt ──
    let manifest = ManifestBuilder::new()
        .lock_fee(payer, Decimal::from(10))
        .withdraw_from_account(payer, XRD, Decimal::from(500))
        .try_deposit_entire_worktop_or_abort(recipient, None)
        .build();
    let notarized = sign_and_notarize(manifest, &NetworkDefinition::simulator(), 1, &payer_key)
        .expect("transfer signs");
    // The grow has consumed many epochs of weighted time, so a genesis-anchored
    // validity range has long expired. Bracket the current weighted time.
    let now = runner.now();
    let validity = TimestampRange::new(
        WeightedTimestamp::ZERO.plus(now.saturating_sub(Duration::from_secs(5))),
        WeightedTimestamp::ZERO.plus(now + Duration::from_secs(150)),
    );
    let transfer = routable_from_notarized_v1(notarized, validity).expect("transfer is routable");
    runner.schedule_initial_event(
        0,
        Duration::from_millis(50),
        HostEvent::process(ProcessScopedInput::SubmitTransaction {
            tx: Arc::new(transfer),
        }),
    );

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
    // The parent's terminal record lingers past the drain to project its
    // beacon-attested settled-waves root to surviving counterparts; the
    // retention GC drops it later.
    let root_record = state
        .boundaries
        .get(&ShardId::ROOT)
        .expect("the parent's terminal record lingers for the retention window");
    assert!(
        root_record.terminal_epoch.is_some(),
        "the lingering record is the parent's terminal record",
    );
    assert!(
        root_record.settled_waves_root.is_some(),
        "the terminal record carries the parent's settled-waves root",
    );
    // Subtree-root continuity, the keystone: the seeded anchors are
    // exactly the parent terminal root's two children.
    let parent_terminal_root = runner
        .node_storage(0)
        .expect("host 0 carries the parent")
        .state_root();
    let pair = SplitChildRoots {
        left: state.boundaries[&left].state_root,
        right: state.boundaries[&right].state_root,
    };
    assert!(
        pair.composes_to(parent_terminal_root),
        "the children's anchors must compose to the parent's terminal root",
    );

    // ── Stay-current duty: the staleness txs moved the parent's tree
    // past the observers' anchor, so the anchor-time stores no longer
    // compose to the terminal root — each must follow the parent chain
    // to its crossing before its child genesis can adopt it ──
    let stale_pair = SplitChildRoots {
        left: synced
            .iter()
            .find(|(_, c, _)| *c == left)
            .expect("left observer")
            .2,
        right: synced
            .iter()
            .find(|(_, c, _)| *c == right)
            .expect("right observer")
            .2,
    };
    assert!(
        !stale_pair.composes_to(parent_terminal_root),
        "the staleness txs must have moved the tree past the observers' anchor",
    );
    for (_, child, store, anchor, imported_root) in &synced_stores {
        let followed = runner.follow_child(store, ShardId::ROOT, *child, *anchor, *imported_root);
        assert_eq!(
            followed, state.boundaries[child].state_root,
            "a followed store must arrive at the beacon-seeded child anchor",
        );
    }

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
            .position(|(v, ..)| v == validator)
            .map(|i| synced_stores.swap_remove(i).2)
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

    // Every child store holds the deterministic genesis the beacon
    // anchored as its committed base, and every committed chain extends
    // it: the first block names the genesis as its parent and certifies
    // it with a structural genesis QC carrying the parent chain's
    // terminal clock.
    for child in [left, right] {
        let anchor = state.boundaries[&child];
        for node in 0..runner.num_hosts() {
            let Some(storage) = runner.hosts_shard(node, child) else {
                continue;
            };
            let genesis = storage
                .get_block(genesis_height)
                .expect("the adoption recorded the genesis as the committed tip");
            assert_eq!(genesis.block().hash(), anchor.block_hash);
            assert_eq!(genesis.block().header().state_root(), anchor.state_root);
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
