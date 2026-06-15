//! A surviving sibling reconstructs a split shard's settled set.
//!
//! Two genesis shards, `leaf(1,1)` and `leaf(1,0)`. `leaf(1,0)` is funded
//! past the split threshold and splits into `leaf(2,0)`/`leaf(2,1)` while
//! `leaf(1,1)` stays under it and keeps running — the surviving-sibling
//! shape the split-boundary fence needs and that `reshape_straddle`
//! (a single ROOT split, both children fresh) cannot produce.
//!
//! This file builds the lifecycle first: the trigger fires for `leaf(1,0)`
//! alone, its observers grow the split through the readiness gate, the
//! children seed from its terminal contribution with subtree-root
//! continuity, and `leaf(1,1)` commits throughout. The straddler and the
//! fence assertions build on top.

use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Duration;

use hyperscale_network_memory::NetworkConfig;
use hyperscale_node::shard_loop::{ProcessScopedInput, ShardEvent};
use hyperscale_simulation::SimulationRunner;
use hyperscale_storage::{ShardChainReader, SubstateStore};
use hyperscale_storage_memory::SimShardStorage;
use hyperscale_types::test_utils::test_validity_range;
use hyperscale_types::{
    BeaconChainConfig, BeaconState, BlockHash, BlockHeight, Ed25519PrivateKey, NodeId,
    PendingReshape, ReshapeThresholds, RoutableTransaction, ShardAnchor, ShardId, SplitChildRoots,
    StateRoot, TransactionDecision, TransactionStatus, TxHash, ValidatorId, ValidatorStatus,
    WeightedTimestamp, ed25519_keypair_from_seed, routable_from_notarized_v1, sign_and_notarize,
    uniform_shard_for_node,
};
use radix_common::constants::XRD;
use radix_common::math::Decimal;
use radix_common::network::NetworkDefinition;
use radix_common::types::ComponentAddress;
use radix_transactions::builder::ManifestBuilder;
use tracing_test::traced_test;

const TEST_EPOCH_MS: u64 = 2000;
const PER_SHARD: u32 = 4;

/// `leaf(1,0)`'s genesis byte total (~627k — the heavier engine-bootstrap
/// half plus 20 bulk accounts) sits above this; `leaf(1,1)`'s (~377k) sits
/// below — so the trigger fires for `leaf(1,0)` alone. A cross-shard
/// transfer moves no substates, so `leaf(1,1)` stays under the threshold
/// throughout.
const SPLIT_BYTES: u64 = 500_000;

/// Bulk accounts funded into `leaf(1,0)` to widen its margin over the
/// threshold.
const RIGHT_BULK: usize = 20;

/// Fixed delays from admission for the straddlers meant to *settle* on
/// `leaf(1,0)`. Submitted during the grow phase, they have the full
/// runway to commit-execute-certify-finalize on `leaf(1,0)` well before
/// its terminal block (the survivor finalizes them once it reconstructs
/// `S_{leaf(1,0)}`). The gate-to-cut window alone is far too short for
/// that pipeline, so these cannot ride the cut-anchored offsets below.
const SETTLE_DELAYS_MS: [u64; 2] = [1500, 3000];

/// Submission offsets *before* `leaf(1,0)`'s terminal cut for the
/// straddlers meant to *straddle*. Anchored to the now-known cut so they
/// track the boundary however long the heavier shard's grow phase runs;
/// landing after the gate, they leave the grow phase — and thus the cut
/// — undisturbed. They commit on `leaf(1,0)` but cross its terminal
/// before settling, so neither side finalizes them.
const STRADDLE_OFFSETS_MS: [u64; 3] = [700, 400, 200];

const ADMISSION_BUDGET_EPOCHS: u64 = 8;
const GATE_BUDGET_EPOCHS: u64 = 8;
const SEED_BUDGET_EPOCHS: u64 = 6;
const CHILD_RUN_BUDGET_EPOCHS: u64 = 6;
const SETTLE_BUDGET_EPOCHS: u64 = 6;

fn sibling_config() -> NetworkConfig {
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
                split_bytes: SPLIT_BYTES,
            },
            ..BeaconChainConfig::default()
        }),
        // One cohort's worth of pooled extras to staff leaf(1,0)'s split.
        pool_extra_validators: PER_SHARD,
        ..Default::default()
    }
}

fn beacon_state(runner: &SimulationRunner) -> Option<Arc<BeaconState>> {
    let (_, state) = runner.beacon_storage(0)?.latest_committed()?;
    Some(state)
}

/// The pending split's cohort for `parent` as `(observer, assigned child)`.
fn pending_cohort_for(
    runner: &SimulationRunner,
    parent: ShardId,
) -> Option<Vec<(ValidatorId, ShardId)>> {
    let state = beacon_state(runner)?;
    let Some(PendingReshape::Split { cohort, .. }) = state.pending_reshapes.get(&parent) else {
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

/// A fresh keypair whose preallocated account routes to `shard` under a
/// `num_shards`-wide uniform trie — the same routing genesis uses.
fn account_in(
    shard: ShardId,
    num_shards: u64,
    taken: &mut Vec<u8>,
) -> (Ed25519PrivateKey, ComponentAddress) {
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
        if uniform_shard_for_node(&node, num_shards) == shard {
            taken.push(seed);
            return (key, address);
        }
    }
    panic!("no account seed routes to {shard:?}");
}

fn store_for(runner: &SimulationRunner, shard: ShardId) -> Option<&SimShardStorage> {
    (0..runner.num_hosts()).find_map(|node| runner.hosts_shard(node, shard))
}

/// A validator currently seated on `shard`, per the committed beacon
/// state — used to address the surviving sibling's coordinator (which
/// validator index that is depends on the committee draw, not a fixed
/// seat).
fn member_of(runner: &SimulationRunner, shard: ShardId) -> ValidatorId {
    beacon_state(runner)
        .expect("beacon state")
        .validators
        .iter()
        .find_map(|(id, record)| match record.status {
            ValidatorStatus::OnShard { shard: seated, .. } if seated == shard => Some(*id),
            _ => None,
        })
        .expect("shard has a seated member")
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
/// `FinalizedWave` certificate), and the finalizing block's weighted
/// timestamp.
fn scan_chain(
    storage: &SimShardStorage,
    from: BlockHeight,
    hash: TxHash,
) -> (
    Option<BlockHeight>,
    Option<BlockHeight>,
    Option<WeightedTimestamp>,
) {
    let mut committed = None;
    let mut finalized = None;
    let mut finalized_wt = None;
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
                finalized_wt = Some(block.header().parent_qc().weighted_timestamp());
            }
        }
        height = height.next();
    }
    (committed, finalized, finalized_wt)
}

#[traced_test]
#[test]
#[allow(clippy::too_many_lines)] // one surviving-sibling straddler lifecycle
fn surviving_sibling_reconstructs_a_split_shards_settled_set() {
    let mut runner = SimulationRunner::new(&sibling_config(), 11);
    let survivor = ShardId::leaf(1, 1);
    let splitter = ShardId::leaf(1, 0);
    let (left_child, right_child) = splitter.children();

    // Bulk-fund leaf(1,0) past the threshold.
    let mut taken = Vec::new();
    let mut balances = Vec::new();
    for _ in 0..RIGHT_BULK {
        let (_, a) = account_in(splitter, 2, &mut taken);
        balances.push((a, Decimal::from(10_000)));
    }
    // Straddler pairs: payer in the surviving leaf(1,1), recipient in the
    // splitting leaf(1,0) — a genuine cross-shard transfer between the two,
    // so leaf(1,1)'s wave names the terminating leaf(1,0).
    let straddlers: Vec<(Ed25519PrivateKey, ComponentAddress, ComponentAddress)> = (0
        ..SETTLE_DELAYS_MS.len() + STRADDLE_OFFSETS_MS.len())
        .map(|_| {
            let (payer_key, payer) = account_in(survivor, 2, &mut taken);
            let (_, recipient) = account_in(splitter, 2, &mut taken);
            (payer_key, payer, recipient)
        })
        .collect();
    for (_, payer, recipient) in &straddlers {
        balances.push((*payer, Decimal::from(10_000)));
        balances.push((*recipient, Decimal::from(10_000)));
    }
    // A surviving-shard recipient for the post-abort lock-release probe.
    let (_, lock_probe_recipient) = account_in(survivor, 2, &mut taken);
    balances.push((lock_probe_recipient, Decimal::from(10_000)));
    runner.initialize_genesis_with_balances(&balances);

    // ── Admission: leaf(1,0) folds its trigger and draws a cohort; the
    // under-threshold leaf(1,1) folds none ──
    let admitted = run_until(&mut runner, epochs(ADMISSION_BUDGET_EPOCHS), |r| {
        pending_cohort_for(r, splitter).is_some_and(|c| c.len() == PER_SHARD as usize)
    });
    assert!(
        admitted,
        "leaf(1,0)'s trigger must fold and draw a full cohort"
    );
    assert!(
        pending_cohort_for(&runner, survivor).is_none(),
        "the under-threshold survivor must not split",
    );
    let cohort = pending_cohort_for(&runner, splitter).expect("cohort just observed");
    for child in [left_child, right_child] {
        assert_eq!(
            cohort.iter().filter(|(_, c)| *c == child).count(),
            2,
            "the cohort halves must split evenly; got {cohort:?}",
        );
    }

    // ── Settle straddlers: submitted now, during the grow phase, so the
    // full cross-shard 2PC finalizes on leaf(1,0) before its terminal.
    // The straddle straddlers ride the cut-anchored offsets, below ──
    let mut probes: Vec<(u64, TxHash)> = Vec::new();
    for (delay_ms, pair) in SETTLE_DELAYS_MS.iter().zip(&straddlers) {
        let (payer_key, payer, recipient) = pair;
        let tx = transfer(payer_key, *payer, *recipient);
        let hash = tx.hash();
        runner.schedule_initial_event(
            0,
            Duration::from_millis(*delay_ms).max(Duration::from_millis(10)),
            ShardEvent::process(ProcessScopedInput::SubmitTransaction { tx }),
        );
        probes.push((*delay_ms, hash));
    }

    // ── Observer duty: each cohort member syncs its child span ──
    let mut synced_stores: Vec<(
        ValidatorId,
        ShardId,
        SimShardStorage,
        ShardAnchor,
        StateRoot,
    )> = Vec::new();
    for (validator, child) in &cohort {
        let (store, root, anchor) = runner.observe_child(*validator, splitter, *child);
        synced_stores.push((*validator, *child, store, anchor, root));
    }

    // ── The gate fires: leaf(1,0) reshapes into the lookahead; leaf(1,1)
    // keeps its committee. Each observer re-asserts its ready signal until
    // then — the cohort promotes into the active reshape-observer window a
    // window after admission (the freeze discipline), and the busy
    // splitter's blocks anchor in that window only as their `parent_qc.wt`
    // catches up, so a one-shot signal can land while it still classifies
    // as a plain `Ready`. ──
    let gate_deadline = runner.now() + epochs(GATE_BUDGET_EPOCHS);
    let mut reshaped = false;
    while runner.now() < gate_deadline {
        if let Some(current) = pending_cohort_for(&runner, splitter) {
            for (validator, _child) in &current {
                runner.broadcast_observer_ready(*validator, splitter);
            }
        }
        let next = runner.now() + Duration::from_secs(1);
        runner.run_until(next);
        if beacon_state(&runner).is_some_and(|s| {
            s.pending_reshapes.is_empty() && s.next_shard_committees.contains_key(&left_child)
        }) {
            reshaped = true;
            break;
        }
    }
    assert!(
        reshaped,
        "leaf(1,0)'s re-asserted ReshapeReady signals must fire the gate"
    );
    let state = beacon_state(&runner).expect("post-gate state");
    assert!(
        state.next_shard_committees.contains_key(&survivor)
            || state.shard_committees.contains_key(&survivor),
        "the survivor must keep its committee across leaf(1,0)'s split",
    );
    assert!(
        !state.next_shard_committees.contains_key(&splitter),
        "the lookahead must carry leaf(1,0)'s children, not leaf(1,0)",
    );
    let final_epoch = state.current_epoch;
    let cut = Duration::from_millis((final_epoch.inner() + 1) * TEST_EPOCH_MS);

    // ── Submit the straddle straddlers against the now-known cut: each
    // lands `offset` ms before leaf(1,0)'s terminal boundary ──
    for (offset_ms, (payer_key, payer, recipient)) in STRADDLE_OFFSETS_MS
        .iter()
        .zip(&straddlers[SETTLE_DELAYS_MS.len()..])
    {
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

    // The parent halves are leaf(1,0)'s original members landing on a
    // child — excluding the synced cohort (the pooled extras), which the
    // observer flips handle separately.
    let cohort_validators: Vec<ValidatorId> = cohort.iter().map(|(v, _)| *v).collect();
    let parent_halves: Vec<(ValidatorId, ShardId)> = state
        .validators
        .iter()
        .filter_map(|(id, record)| match record.status {
            ValidatorStatus::OnShard { shard, .. }
                if shard.parent() == Some(splitter) && !cohort_validators.contains(id) =>
            {
                Some((*id, shard))
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        parent_halves.len(),
        PER_SHARD as usize,
        "leaf(1,0)'s original members must each land on a child; got {parent_halves:?}",
    );

    // ── Through the boundary: leaf(1,0) coasts to its crossing and the
    // fold seeds both children from its terminal contribution ──
    let seed_deadline = runner.now() + epochs(SEED_BUDGET_EPOCHS);
    let seeded = run_until(&mut runner, seed_deadline, |r| {
        beacon_state(r).is_some_and(|s| {
            [left_child, right_child].iter().all(|c| {
                s.boundaries
                    .get(c)
                    .is_some_and(|b| b.block_hash != BlockHash::ZERO)
            })
        })
    });
    assert!(seeded, "the fold must seed both children from the terminal");
    let state = beacon_state(&runner).expect("post-seed state");
    let genesis_height = state.boundaries[&left_child].height;

    // Subtree-root continuity: the children's anchors compose to the
    // parent's terminal root.
    let parent_terminal_root = store_for(&runner, splitter)
        .expect("a host still carries leaf(1,0)")
        .state_root();
    let pair = SplitChildRoots {
        left: state.boundaries[&left_child].state_root,
        right: state.boundaries[&right_child].state_root,
    };
    assert!(
        pair.composes_to(parent_terminal_root),
        "the children's anchors must compose to leaf(1,0)'s terminal root",
    );

    // ── Follow + flip: observers reach the crossing, parent halves adopt,
    // observers reopen on a sibling-flipped host ──
    for (_, child, store, anchor, imported_root) in &synced_stores {
        let followed = runner.follow_child(store, splitter, *child, *anchor, *imported_root);
        assert_eq!(
            followed, state.boundaries[child].state_root,
            "a followed store must arrive at the beacon-seeded child anchor",
        );
    }
    for (validator, child) in &parent_halves {
        let node = u32::try_from(validator.inner()).expect("host per parent member");
        runner.flip_split_child(node, *validator, splitter, *child, None);
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
        runner.flip_split_child(node, *validator, splitter, *child, Some(store));
    }

    // ── Both children run past genesis, and the survivor keeps committing ──
    let survivor_base = store_for(&runner, survivor)
        .expect("survivor store")
        .committed_height();
    let run_deadline = runner.now() + epochs(CHILD_RUN_BUDGET_EPOCHS);
    let progressed = run_until(&mut runner, run_deadline, |r| {
        let children_live = [left_child, right_child].iter().all(|child| {
            (0..r.num_hosts()).any(|node| {
                r.hosts_shard(node, *child)
                    .is_some_and(|s| s.committed_height() > genesis_height)
            })
        });
        let survivor_live =
            store_for(r, survivor).is_some_and(|s| s.committed_height() > survivor_base);
        children_live && survivor_live
    });
    if !progressed {
        let mut detail = String::new();
        for shard in [survivor, left_child, right_child] {
            for node in 0..runner.num_hosts() {
                if let Some(s) = runner.hosts_shard(node, shard) {
                    let _ = write!(
                        detail,
                        "\n  node {node} {shard:?}: committed {:?}",
                        s.committed_height(),
                    );
                }
            }
        }
        panic!(
            "children must commit past genesis (h{}) and the survivor past h{} \
             within {CHILD_RUN_BUDGET_EPOCHS} epochs:{detail}",
            genesis_height.inner(),
            survivor_base.inner(),
        );
    }

    // ── Settlement window: the survivor reconstructs S_{leaf(1,0)} from
    // the coast headers it sees, finalizes the straddlers it settled, and
    // counterpart-aborts the ones it never did (releasing their locks).
    // Run until the first abort lands so the status cache is settled ──
    let survivor_validator = member_of(&runner, survivor);
    let survivor_host = runner.network().validator_to_node(survivor_validator);
    let settle_deadline = runner.now() + epochs(SETTLE_BUDGET_EPOCHS);
    let swept = run_until(&mut runner, settle_deadline, |r| {
        probes.iter().any(|(_, hash)| {
            matches!(
                r.tx_status(survivor_host, hash),
                Some(TransactionStatus::Completed(TransactionDecision::Aborted))
            )
        })
    });

    // ── Scan each straddler's fate on both chains + its survivor status ──
    let cut_wt = WeightedTimestamp::from_millis(u64::try_from(cut.as_millis()).expect("cut fits"));
    let terminal_b = genesis_height
        .prev()
        .expect("leaf(1,0)'s terminal sits below the child genesis");
    let survivor_store = store_for(&runner, survivor).expect("survivor store");
    let splitter_store = store_for(&runner, splitter).expect("leaf(1,0) still served");

    let mut report = format!(
        "cut={}ms terminal_B=h{} child_genesis=h{}",
        cut.as_millis(),
        terminal_b.inner(),
        genesis_height.inner(),
    );
    let mut settled = 0u32; // settled on leaf(1,0) and finalized on the survivor
    let mut one_sided = 0u32; // finalized on the survivor but not settled on leaf(1,0)
    let mut straddled = 0u32; // committed on leaf(1,0) but never settled there
    let mut doomed = 0u32; // committed on the survivor but unsettled on leaf(1,0)
    let mut doomed_aborted = 0u32; // ... and driven to Completed(Aborted) on the survivor
    let mut wrongly_aborted = 0u32; // settled on leaf(1,0) yet aborted on the survivor
    let mut lock_probe_idx: Option<usize> = None;
    for (idx, (delay, hash)) in probes.iter().enumerate() {
        let (s_committed, s_finalized, _) = scan_chain(splitter_store, BlockHeight::new(1), *hash);
        let (v_committed, v_finalized, v_wt) =
            scan_chain(survivor_store, BlockHeight::new(1), *hash);
        let settled_on_splitter = s_finalized.is_some_and(|h| h <= terminal_b);
        let finalized_on_survivor = v_finalized.is_some();
        let post_cut = v_wt.is_some_and(|wt| wt > cut_wt);
        let survivor_status = runner.tx_status(survivor_host, hash);
        let aborted_on_survivor = matches!(
            survivor_status,
            Some(TransactionStatus::Completed(TransactionDecision::Aborted))
        );
        let _ = write!(
            report,
            "\n  +{delay}ms: leaf(1,0) committed={:?} finalized={:?} settled={settled_on_splitter}; \
             leaf(1,1) committed={:?} finalized={:?} wt={:?} post_cut={post_cut} status={survivor_status:?}",
            s_committed.map(BlockHeight::inner),
            s_finalized.map(BlockHeight::inner),
            v_committed.map(BlockHeight::inner),
            v_finalized.map(BlockHeight::inner),
            v_wt.map(WeightedTimestamp::as_millis),
        );
        if finalized_on_survivor && !settled_on_splitter {
            one_sided += 1;
        }
        if settled_on_splitter && finalized_on_survivor {
            settled += 1;
        }
        if s_committed.is_some() && !settled_on_splitter {
            straddled += 1;
        }
        if settled_on_splitter && aborted_on_survivor {
            wrongly_aborted += 1;
        }
        if v_committed.is_some() && !settled_on_splitter {
            doomed += 1;
            if aborted_on_survivor {
                doomed_aborted += 1;
                if lock_probe_idx.is_none() {
                    lock_probe_idx = Some(idx);
                }
            }
        }
    }

    // The driver demonstrably ran: a surviving leaf(1,1) member
    // reconstructed leaf(1,0)'s settled-wave set from its coast tail. The
    // committed mechanism only unit-tested this; here it runs over the real
    // network against the draining committee.
    let reconstructed = runner.vnode_state(survivor_validator).and_then(|node| {
        node.shard_coordinator()
            .settled_set(splitter)
            .map(|set| set.waves.len())
    });
    assert!(
        reconstructed.is_some_and(|n| n > 0),
        "the survivor must reconstruct a non-empty settled set for the terminated leaf(1,0) \
         (got {reconstructed:?}) — the io_loop driver never delivered S_P:\n{report}",
    );

    // Atomicity: the survivor finalizes a cross-shard wave with leaf(1,0)
    // only when leaf(1,0) settled it by its terminal block — never
    // one-sided, and never aborts one leaf(1,0) did settle.
    assert_eq!(
        one_sided, 0,
        "the survivor finalized a straddler leaf(1,0) never settled — one-sided cross-shard \
         application:\n{report}",
    );
    assert_eq!(
        wrongly_aborted, 0,
        "the survivor aborted a straddler leaf(1,0) settled by its terminal block — a settled \
         half was discarded:\n{report}",
    );
    assert!(
        settled > 0,
        "no straddler settled cross-shard between the survivor and the splitting shard — \
         the offsets need retuning:\n{report}",
    );
    assert!(
        straddled > 0,
        "no straddler reached leaf(1,0)'s boundary unsettled — the offsets need retuning so \
         the test actually stresses the cut:\n{report}",
    );

    // Counterpart abort sweep: every straddler the survivor committed but
    // leaf(1,0) never settled must reach Completed(Aborted) — it can never
    // gain leaf(1,0)'s coverage, so its in-flight slot and node locks free.
    assert!(
        swept,
        "the survivor must abort at least one unsettled straddler once it reconstructs \
         S_{{leaf(1,0)}}:\n{report}",
    );
    assert!(
        doomed > 0,
        "no straddler committed on the survivor went unsettled — offsets need retuning so the \
         counterpart sweep has something to abort:\n{report}",
    );
    assert_eq!(
        doomed_aborted, doomed,
        "the survivor must drive every doomed straddler to Completed(Aborted); \
         {doomed_aborted}/{doomed} aborted:\n{report}",
    );

    // ── Lock-release probe: the counterpart abort released the straddler's
    // declared-node locks, so a fresh single-shard transfer from the same
    // payer (touching a node the straddler had locked) now completes ──
    let probe_idx = lock_probe_idx.expect("a doomed straddler was aborted above");
    let (probe_payer_key, probe_payer, _) = &straddlers[probe_idx];
    let lock_probe = transfer(probe_payer_key, *probe_payer, lock_probe_recipient);
    let probe_hash = lock_probe.hash();
    runner.schedule_initial_event(
        survivor_host,
        Duration::from_millis(10),
        ShardEvent::process(ProcessScopedInput::SubmitTransaction { tx: lock_probe }),
    );
    let probe_deadline = runner.now() + epochs(SETTLE_BUDGET_EPOCHS);
    let probe_completed = run_until(&mut runner, probe_deadline, |r| {
        matches!(
            r.tx_status(survivor_host, &probe_hash),
            Some(TransactionStatus::Completed(_))
        )
    });
    assert!(
        probe_completed,
        "a fresh transfer from an aborted straddler's payer must complete once the counterpart \
         abort released its locks; got status {:?}\n{report}",
        runner.tx_status(survivor_host, &probe_hash),
    );
}
