//! Transfers around a split boundary: settlement and atomicity.
//!
//! Runs the full grow-split lifecycle (as in `reshape_grow`) with
//! transfers timed against the parent's final window. Each transfer
//! moves XRD between a payer routed to the left child's half and a
//! recipient routed to the right child's half — single-shard while the
//! parent governs, cross-shard `p0 <-> p1` once the children take
//! over.
//!
//! Asserted:
//! - a transfer submitted with enough runway settles on the parent
//!   before its terminal block;
//! - a transfer submitted after the boundary settles cross-child —
//!   committed on both children, provisions and certificates routed
//!   between them, finalized on both chains (post-split child-side
//!   execution end to end, exercising every committee member's store:
//!   hard-linked parent halves and bootstrap-replicated observers);
//! - a transfer that commits on the parent too late to finalize there
//!   never settles on exactly one child — the boundary cannot
//!   half-apply a cross-child transfer.

use std::fmt::Write;
use std::sync::Arc;
use std::time::Duration;

use hyperscale_network_memory::NetworkConfig;
use hyperscale_node::shard_loop::{ProcessScopedInput, ShardEvent};
use hyperscale_simulation::SimulationRunner;
use hyperscale_storage::ShardChainReader;
use hyperscale_storage_memory::SimShardStorage;
use hyperscale_types::state_key::node_routing_hash;
use hyperscale_types::test_utils::test_validity_range;
use hyperscale_types::{
    BeaconChainConfig, BeaconState, BlockHash, BlockHeight, Ed25519PrivateKey, NodeId,
    PendingReshape, ReshapeThresholds, RoutableTransaction, ShardAnchor, ShardId, StateRoot,
    TransactionDecision, TransactionStatus, TxHash, ValidatorId, ValidatorStatus,
    ed25519_keypair_from_seed, routable_from_notarized_v1, sign_and_notarize,
};
use radix_common::constants::XRD;
use radix_common::math::Decimal;
use radix_common::network::NetworkDefinition;
use radix_common::types::ComponentAddress;
use radix_transactions::builder::ManifestBuilder;
use tracing_test::traced_test;

const TEST_EPOCH_MS: u64 = 2000;
const PER_SHARD: u32 = 4;
const ADMISSION_BUDGET_EPOCHS: u64 = 8;
const GATE_BUDGET_EPOCHS: u64 = 8;
const SEED_BUDGET_EPOCHS: u64 = 6;
const CHILD_RUN_BUDGET_EPOCHS: u64 = 4;
const CONTROL_BUDGET_EPOCHS: u64 = 8;

/// Submission offsets before the parent's terminal cut, in
/// milliseconds. The early offsets leave room for the full
/// commit-execute-certify-finalize pipeline on the parent; the late
/// ones commit but straddle.
const PROBE_OFFSETS_MS: [u64; 5] = [1200, 600, 450, 300, 150];

fn straddle_config() -> NetworkConfig {
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
            reshape_thresholds: ReshapeThresholds { split_bytes: 0 },
            ..BeaconChainConfig::default()
        }),
        pool_extra_validators: PER_SHARD,
        ..Default::default()
    }
}

fn beacon_state(runner: &SimulationRunner) -> Option<Arc<BeaconState>> {
    let (_, state) = runner.beacon_storage(0)?.latest_committed()?;
    Some(state)
}

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

/// Find a fresh keypair whose preallocated account routes to `child` —
/// the first bit of the account node's routing hash picks the half.
fn account_in(child: ShardId, taken: &mut Vec<u8>) -> (Ed25519PrivateKey, ComponentAddress) {
    let (left, right) = ShardId::ROOT.children();
    for seed in 1u8..=u8::MAX {
        if taken.contains(&seed) {
            continue;
        }
        let key = ed25519_keypair_from_seed(&[seed; 32]);
        let address = ComponentAddress::preallocated_account_from_public_key(&key.public_key());
        let node = NodeId(
            address.into_node_id().0[..30]
                .try_into()
                .expect("account address carries a 30-byte node id"),
        );
        let side = if node_routing_hash(&node)[0] >> 7 == 0 {
            left
        } else {
            right
        };
        if side == child {
            taken.push(seed);
            return (key, address);
        }
    }
    panic!("no account seed routes to {child:?}");
}

/// A payer-to-recipient XRD transfer, signed and routable.
fn transfer(
    payer_key: &Ed25519PrivateKey,
    payer: ComponentAddress,
    recipient: ComponentAddress,
) -> Arc<RoutableTransaction> {
    let manifest = ManifestBuilder::new()
        .lock_fee(payer, Decimal::from(10))
        .withdraw_from_account(payer, XRD, Decimal::from(500))
        .try_deposit_entire_worktop_or_abort(recipient, None)
        .build();
    let notarized = sign_and_notarize(manifest, &NetworkDefinition::simulator(), 1, payer_key)
        .expect("transfer signs");
    Arc::new(routable_from_notarized_v1(notarized, test_validity_range()).expect("routable"))
}

/// Walk a committed chain from `from` to its tip: the heights at which
/// `hash` was committed (rides `transactions`) and finalized (rides a
/// `FinalizedWave` certificate).
fn scan_chain(
    storage: &SimShardStorage,
    from: BlockHeight,
    hash: TxHash,
) -> (Option<BlockHeight>, Option<BlockHeight>) {
    let mut committed = None;
    let mut finalized = None;
    let tip = storage.committed_height();
    let mut height = from;
    while height <= tip {
        if let Some(certified) = storage.get_block(height) {
            let block = certified.block();
            if block.transactions().iter().any(|tx| tx.hash() == hash) {
                committed = Some(height);
            }
            if block
                .certificates()
                .iter()
                .any(|fw| fw.tx_hashes().any(|t| t == hash))
            {
                finalized = Some(height);
            }
        }
        height = height.next();
    }
    (committed, finalized)
}

/// First host carrying `shard`, if any.
fn store_for(runner: &SimulationRunner, shard: ShardId) -> Option<&SimShardStorage> {
    (0..runner.num_hosts()).find_map(|node| runner.hosts_shard(node, shard))
}

#[traced_test]
#[test]
#[allow(clippy::too_many_lines)] // one straddle lifecycle asserted end to end
fn transfers_around_the_split_boundary_settle_atomically() {
    let mut runner = SimulationRunner::new(&straddle_config(), 11);
    let (left, right) = ShardId::ROOT.children();

    // One payer/recipient pair per probe offset plus one control pair,
    // payers in the left half and recipients in the right, so every
    // transfer is cross-child under the post-split trie.
    let mut taken = Vec::new();
    let pairs: Vec<(Ed25519PrivateKey, ComponentAddress, ComponentAddress)> = (0
        ..=PROBE_OFFSETS_MS.len())
        .map(|_| {
            let (payer_key, payer) = account_in(left, &mut taken);
            let (_, recipient) = account_in(right, &mut taken);
            (payer_key, payer, recipient)
        })
        .collect();
    let balances: Vec<(ComponentAddress, Decimal)> = pairs
        .iter()
        .flat_map(|(_, payer, recipient)| {
            [
                (*payer, Decimal::from(10_000)),
                (*recipient, Decimal::from(10_000)),
            ]
        })
        .collect();
    runner.initialize_genesis_with_balances(&balances);

    // ── Admission ──
    let admitted = run_until(&mut runner, epochs(ADMISSION_BUDGET_EPOCHS), |r| {
        pending_cohort(r).is_some_and(|c| c.len() == PER_SHARD as usize)
    });
    assert!(admitted, "trigger must fold and draw a full cohort");
    let cohort = pending_cohort(&runner).expect("cohort just observed");

    // ── Observer duty ──
    let mut synced_stores: Vec<(
        ValidatorId,
        ShardId,
        SimShardStorage,
        ShardAnchor,
        StateRoot,
    )> = Vec::new();
    for (validator, child) in &cohort {
        let (store, root, anchor) = runner.observe_child(*validator, ShardId::ROOT, *child);
        synced_stores.push((*validator, *child, store, anchor, root));
    }

    // ── The gate fires; pin the parent's final window. Each observer
    // re-asserts its ready signal until then — the cohort promotes into the
    // active reshape-observer window a window after admission (the freeze
    // discipline), and the busy parent's blocks anchor in that window only
    // as their `parent_qc.wt` catches up, so a one-shot signal can land
    // while it still classifies as a plain `Ready`. ──
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
        "the re-asserted ReshapeReady signals must fire the gate"
    );
    let state = beacon_state(&runner).expect("post-gate state");
    assert!(
        state.shard_committees.contains_key(&ShardId::ROOT),
        "gate observed after the final window already closed; cut timing unusable",
    );
    let final_epoch = state.current_epoch;
    let cut = Duration::from_millis((final_epoch.inner() + 1) * TEST_EPOCH_MS);
    let parent_halves: Vec<(ValidatorId, ShardId)> = (0..u64::from(PER_SHARD))
        .map(|member| {
            let id = ValidatorId::new(member);
            match state.validators[&id].status {
                ValidatorStatus::OnShard { shard, .. } if shard.parent() == Some(ShardId::ROOT) => {
                    (id, shard)
                }
                other => panic!("parent member {member} must land on a child; got {other:?}"),
            }
        })
        .collect();

    // ── Probe transfers staggered against the cut ──
    let mut probes: Vec<(u64, TxHash)> = Vec::new();
    for (offset_ms, (payer_key, payer, recipient)) in PROBE_OFFSETS_MS.iter().zip(&pairs) {
        let tx = transfer(payer_key, *payer, *recipient);
        let hash = tx.hash();
        let target = cut.saturating_sub(Duration::from_millis(*offset_ms));
        let delay = target
            .saturating_sub(runner.now())
            .max(Duration::from_millis(10));
        runner.schedule_initial_event(
            0,
            delay,
            ShardEvent::process(ProcessScopedInput::SubmitTransaction { tx }),
        );
        probes.push((*offset_ms, hash));
    }

    // ── Through the boundary: coast, crossing, child seeding ──
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
    assert!(seeded, "the fold must seed both children from the terminal");
    let state = beacon_state(&runner).expect("post-seed state");
    let genesis_height = state.boundaries[&left].height;
    let terminal_height = genesis_height.prev().expect("terminal below genesis");

    // ── Observers follow the parent to its crossing, then everyone flips ──
    for (_, child, store, anchor, imported_root) in &synced_stores {
        let followed = runner.follow_child(store, ShardId::ROOT, *child, *anchor, *imported_root);
        assert_eq!(
            followed, state.boundaries[child].state_root,
            "a followed store must arrive at the beacon-seeded child anchor",
        );
    }
    for (validator, child) in &parent_halves {
        let node = u32::try_from(validator.inner()).expect("host per parent member");
        runner.flip_split_child(node, *validator, ShardId::ROOT, *child, None);
    }
    let observer_seats: Vec<(ValidatorId, ShardId)> =
        synced_stores.iter().map(|(v, c, ..)| (*v, *c)).collect();
    let mut sibling_hosts: Vec<u32> = Vec::new();
    for (validator, child) in &observer_seats {
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

    // ── Both children run past genesis ──
    let run_deadline = runner.now() + epochs(CHILD_RUN_BUDGET_EPOCHS);
    let progressed = run_until(&mut runner, run_deadline, |r| {
        [left, right].iter().all(|child| {
            (0..r.num_hosts()).any(|node| {
                r.hosts_shard(node, *child)
                    .is_some_and(|storage| storage.committed_height() > genesis_height)
            })
        })
    });
    assert!(progressed, "both children must commit past their genesis");

    // ── Control: a fresh cross-child transfer after the boundary —
    // committed on both children, provisions and certificates routed
    // between them, finalized on both chains ──
    let (control_key, control_payer, control_recipient) = &pairs[PROBE_OFFSETS_MS.len()];
    let control_tx = transfer(control_key, *control_payer, *control_recipient);
    let control_hash = control_tx.hash();
    runner.schedule_initial_event(
        0,
        Duration::from_millis(10),
        ShardEvent::process(ProcessScopedInput::SubmitTransaction { tx: control_tx }),
    );
    let control_deadline = runner.now() + epochs(CONTROL_BUDGET_EPOCHS);
    let control_settled = run_until(&mut runner, control_deadline, |r| {
        [left, right].iter().all(|child| {
            store_for(r, *child).is_some_and(|s| {
                scan_chain(s, genesis_height.next(), control_hash)
                    .1
                    .is_some()
            })
        })
    });

    // ── Report ──
    let parent_store = runner
        .hosts_shard(0, ShardId::ROOT)
        .expect("host 0 keeps the parent store");
    let mut report = String::new();
    let _ = write!(
        report,
        "terminal B = h{}; child genesis = h{}",
        terminal_height.inner(),
        genesis_height.inner(),
    );
    let mut settled_on_parent = 0u32;
    let mut straddlers = 0u32;
    let mut half_applied = 0u32;
    let mut unswept_straddlers = 0u32;
    for (offset_ms, hash) in &probes {
        let (p_committed, p_finalized) = scan_chain(parent_store, BlockHeight::new(1), *hash);
        let child_fates: Vec<(ShardId, Option<BlockHeight>, Option<BlockHeight>)> = [left, right]
            .iter()
            .map(|child| {
                let (c, f) = store_for(&runner, *child).map_or((None, None), |s| {
                    scan_chain(s, genesis_height.next(), *hash)
                });
                (*child, c, f)
            })
            .collect();
        let status = runner.tx_status(0, hash);
        let _ = write!(
            report,
            "\n  cut-{offset_ms}ms: parent committed={:?} finalized={:?}; children={child_fates:?}; host0 status={status:?}",
            p_committed.map(BlockHeight::inner),
            p_finalized.map(BlockHeight::inner),
        );
        if p_finalized.is_some() {
            settled_on_parent += 1;
        }
        if p_committed.is_some() && p_finalized.is_none() {
            straddlers += 1;
            let settled_children = child_fates.iter().filter(|(_, _, f)| f.is_some()).count();
            if settled_children == 1 {
                half_applied += 1;
            }
            // The parent's terminal sweep must have driven the
            // undecidable tx to its terminal abort on the parent host.
            if !matches!(
                status,
                Some(TransactionStatus::Completed(TransactionDecision::Aborted))
            ) {
                unswept_straddlers += 1;
            }
        }
    }
    let control_fates: Vec<(ShardId, Option<BlockHeight>, Option<BlockHeight>)> = [left, right]
        .iter()
        .map(|child| {
            let (c, f) = store_for(&runner, *child).map_or((None, None), |s| {
                scan_chain(s, genesis_height.next(), control_hash)
            });
            (*child, c, f)
        })
        .collect();
    let _ = write!(
        report,
        "\n  control: settled={control_settled} children={control_fates:?} \
         status={:?} hash={control_hash:?}",
        runner.tx_status(0, &control_hash),
    );

    assert!(
        control_settled,
        "a post-split cross-child transfer must settle on both children;\n{report}",
    );
    assert!(
        settled_on_parent > 0,
        "the earliest transfer must settle on the parent before its terminal \
         block — offsets need retuning;\n{report}",
    );
    assert!(
        straddlers > 0,
        "no transfer straddled (all finalized on the parent or never \
         committed) — offsets need retuning;\n{report}",
    );
    assert!(
        half_applied == 0,
        "{half_applied} straddling transfer(s) finalized on exactly one child \
         — the boundary half-applied a cross-child transfer;\n{report}",
    );
    assert!(
        unswept_straddlers == 0,
        "{unswept_straddlers} straddling transfer(s) never reached \
         completed(aborted) on the parent host — the terminal sweep must \
         abort what no later block can decide;\n{report}",
    );
}
