//! A surviving shard reconstructs a *merged* shard's settled set.
//!
//! The split-side analogue ([`reshape_sibling`]) proves a surviving sibling
//! reconstructs a split parent's `S_P` and resolves cross-shard straddlers
//! against it. The same fence must hold when the terminated shard leaves at
//! a **merge** rather than a split — the case the carry predicate missed
//! while it keyed on `split_at_next_boundary` alone, so a merge child's
//! terminal header never carried a `settled_waves_root` and a survivor
//! could never acquire `S_P`.
//!
//! Four genesis leaves: `leaf(2,2)`/`leaf(2,3)` (both under the merge
//! threshold) merge back into `leaf(1,1)`, while `leaf(2,0)` (above it)
//! keeps `leaf(1,0)`'s subtree alive as the surviving counterpart. A
//! cross-shard transfer runs from the survivor `leaf(2,0)` into the merging
//! `leaf(2,2)`, so the survivor's wave names a shard that terminates at the
//! merge. After the merge the survivor must read `leaf(2,2)`'s
//! beacon-attested `settled_waves_root`, fetch and verify `S_{leaf(2,2)}`,
//! and finalize the straddler only because `leaf(2,2)` settled it — never
//! one-sided.

use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Duration;

use hyperscale_network_memory::NetworkConfig;
use hyperscale_node::shard_loop::{ProcessScopedInput, ShardEvent};
use hyperscale_simulation::{EPOCH_MS, SimulationRunner};
use hyperscale_storage::{ShardChainReader, SubstateStore};
use hyperscale_storage_memory::SimShardStorage;
use hyperscale_types::test_utils::test_validity_range;
use hyperscale_types::{
    BeaconChainConfig, BeaconState, BlockHash, BlockHeight, Ed25519PrivateKey, KeeperSeat, NodeId,
    PendingReshape, ReshapeThresholds, RoutableTransaction, ShardId, SplitChildRoots,
    TransactionDecision, TransactionStatus, TxHash, ValidatorId, ValidatorStatus,
    ed25519_keypair_from_seed, routable_from_notarized_v1, sign_and_notarize,
    uniform_shard_for_node,
};
use radix_common::constants::XRD;
use radix_common::math::Decimal;
use radix_common::network::NetworkDefinition;
use radix_common::types::ComponentAddress;
use radix_transactions::builder::ManifestBuilder;
use tracing_test::traced_test;

const PER_SHARD: u32 = 4;

/// `merge_threshold = split_bytes / 8 = 420_000`. The cold genesis byte
/// totals are `leaf(2,0)≈522k`, `leaf(2,1)≈89k`, `leaf(2,2)≈317k`,
/// `leaf(2,3)≈56k`: only the `leaf(1,1)` pair sits below the threshold, so
/// it alone merges, while `leaf(2,0)` keeps `leaf(1,0)` above it as the
/// surviving counterpart.
const SPLIT_BYTES: u64 = 3_360_000;

/// Delays from genesis for the cross-shard straddlers. Submitted early, so
/// the full 2PC settles on both the survivor and the merging child well
/// before the child's terminal block.
const SETTLE_DELAYS_MS: [u64; 3] = [1500, 2500, 3500];

const ADMISSION_BUDGET_EPOCHS: u64 = 8;
const GATE_BUDGET_EPOCHS: u64 = 8;
const COMPOSE_BUDGET_EPOCHS: u64 = 14;
const RUN_BUDGET_EPOCHS: u64 = 6;
const SETTLE_BUDGET_EPOCHS: u64 = 8;

fn merge_config() -> NetworkConfig {
    NetworkConfig {
        num_shards: 4,
        validators_per_shard: PER_SHARD,
        jitter_fraction: 0.1,
        beacon_chain_config: Some(BeaconChainConfig {
            epoch_duration_ms: EPOCH_MS,
            num_shards: 4,
            shard_size: PER_SHARD,
            reshape_thresholds: ReshapeThresholds {
                split_bytes: SPLIT_BYTES,
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

/// The pending merge's keepers as `(validator, the child it runs)` pairs,
/// once paired, for the merge under `parent`.
fn pending_keepers(
    runner: &SimulationRunner,
    parent: ShardId,
) -> Option<Vec<(ValidatorId, ShardId)>> {
    let state = beacon_state(runner)?;
    let Some(PendingReshape::Merge {
        keepers,
        admitted_at: Some(_),
        ..
    }) = state.pending_reshapes.get(&parent)
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
    Duration::from_millis(EPOCH_MS * n)
}

/// A fresh keypair whose preallocated account routes to `shard` under a
/// `num_shards`-wide uniform trie.
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

/// A validator currently seated on `shard`, per the committed beacon state.
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
/// `hash` committed and finalized, and the finalizing block's weighted
/// timestamp.
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

#[traced_test]
#[test]
#[allow(clippy::too_many_lines)] // one merge-straddler lifecycle asserted end to end
fn survivor_reconstructs_a_merged_shards_settled_set() {
    let survivor = ShardId::leaf(2, 0);
    let merge_parent = ShardId::leaf(1, 1);
    let (merge_left, merge_right) = merge_parent.children(); // leaf(2,2), leaf(2,3)
    let merging = merge_left; // the straddler's far half terminates here

    let mut runner = SimulationRunner::new(&merge_config(), 7);

    // Straddler pairs: payer in the surviving leaf(2,0), recipient in the
    // merging leaf(2,2) — a genuine cross-shard transfer, so the survivor's
    // wave names the terminating shard.
    let mut taken = Vec::new();
    let mut balances = Vec::new();
    let straddlers: Vec<(Ed25519PrivateKey, ComponentAddress, ComponentAddress)> = SETTLE_DELAYS_MS
        .iter()
        .map(|_| {
            let (payer_key, payer) = account_in(survivor, 4, &mut taken);
            let (_, recipient) = account_in(merging, 4, &mut taken);
            (payer_key, payer, recipient)
        })
        .collect();
    for (_, payer, recipient) in &straddlers {
        balances.push((*payer, Decimal::from(10_000)));
        balances.push((*recipient, Decimal::from(10_000)));
    }
    runner.initialize_genesis_with_balances(&balances);

    // ── Admission: the under-threshold leaf(1,1) pair asserts the merge and
    // the beacon pairs a full keeper set; the heavy leaf(1,0) pair does not ──
    let paired = run_until(&mut runner, epochs(ADMISSION_BUDGET_EPOCHS), |r| {
        pending_keepers(r, merge_parent).is_some_and(|k| k.len() == PER_SHARD as usize)
    });
    assert!(
        paired,
        "the leaf(1,1) pair must assert the merge and pair a full keeper set",
    );
    // leaf(2,1) (under threshold) asserts a merge, which *admits* an
    // unpaired `PendingReshape::Merge` for leaf(1,0); it can never *pair*
    // because its sibling leaf(2,0) stays above the threshold. The survivor
    // subtree therefore never executes a merge.
    assert!(
        pending_keepers(&runner, ShardId::leaf(1, 0)).is_none(),
        "the heavy leaf(1,0) pair must not pair a merge (leaf(2,0) stays above threshold)",
    );
    let mut keepers = pending_keepers(&runner, merge_parent).expect("keepers just observed");

    // ── Submit settling straddlers now, during the grow phase, so the full
    // cross-shard 2PC finalizes on both halves before the child's terminal ──
    let mut probes: Vec<(u64, TxHash)> = Vec::new();
    for (delay_ms, pair) in SETTLE_DELAYS_MS.iter().zip(&straddlers) {
        let (payer_key, payer, recipient) = pair;
        let tx = transfer(payer_key, *payer, *recipient);
        let hash = tx.hash();
        runner.schedule_initial_event(
            0,
            Duration::from_millis(*delay_ms),
            ShardEvent::process(ProcessScopedInput::SubmitTransaction { tx }),
        );
        probes.push((*delay_ms, hash));
    }

    // ── Keeper duty: prove each keeper's sibling-half sync once. ──
    for (validator, own_child) in &keepers {
        let sibling = if *own_child == merge_left {
            merge_right
        } else {
            merge_left
        };
        runner.merge_keeper(*validator, *own_child, sibling);
    }

    // ── The gate fires: each keeper re-asserts its ready signal until the
    // merge collapses both children into the parent in the lookahead. The
    // keepers promote into the active reshape-keeper window only a window
    // after pairing (the freeze discipline), so a one-shot signal can land
    // while it still classifies as a plain `Ready`. A production keeper
    // re-asserts until it is placed; the harness does the same, re-reading
    // the live keeper set so a re-pair is followed and stopping once the
    // merge executes. ──
    let gate_deadline = runner.now() + epochs(GATE_BUDGET_EPOCHS);
    let mut reshaped = false;
    while runner.now() < gate_deadline {
        if let Some(current) = pending_keepers(&runner, merge_parent) {
            keepers = current;
            for (validator, own_child) in &keepers {
                runner.broadcast_keeper_ready(*validator, *own_child);
            }
        }
        let next = runner.now() + Duration::from_secs(1);
        runner.run_until(next);
        if beacon_state(&runner).is_some_and(|s| {
            !s.pending_reshapes.contains_key(&merge_parent)
                && s.next_shard_committees.contains_key(&merge_parent)
        }) {
            reshaped = true;
            break;
        }
    }
    assert!(
        reshaped,
        "the re-asserted keepers' ReshapeReady signals must fire the merge gate"
    );
    let state = beacon_state(&runner).expect("post-gate state");
    assert!(
        !state.next_shard_committees.contains_key(&merge_left)
            && !state.next_shard_committees.contains_key(&merge_right),
        "the lookahead must carry the merged parent, not the children",
    );
    assert!(
        state.shard_committees.contains_key(&survivor)
            || state.next_shard_committees.contains_key(&survivor),
        "the survivor must keep its committee across the merge",
    );

    // ── Through the boundary: the children coast and the beacon composes
    // the parent anchor from their terminal roots ──
    let compose_deadline = runner.now() + epochs(COMPOSE_BUDGET_EPOCHS);
    let composed = run_until(&mut runner, compose_deadline, |r| {
        beacon_state(r).is_some_and(|s| {
            s.boundaries
                .get(&merge_parent)
                .is_some_and(|b| b.block_hash != BlockHash::ZERO)
        })
    });
    assert!(
        composed,
        "the fold must compose leaf(1,1) from its children's terminals"
    );
    let state = beacon_state(&runner).expect("post-compose state");
    let parent_anchor = state.boundaries[&merge_parent];

    // Subtree-root continuity: the composed anchor is hash_internal of the
    // two children's terminal roots.
    let pair = SplitChildRoots {
        left: store_for(&runner, merge_left)
            .expect("leaf(2,2) served")
            .state_root(),
        right: store_for(&runner, merge_right)
            .expect("leaf(2,3) served")
            .state_root(),
    };
    assert_eq!(
        pair.composed_root(),
        parent_anchor.state_root,
        "the merged anchor must be hash_internal of the child terminal roots",
    );

    // ── The flip: each keeper builds the merged store and seats on leaf(1,1) ──
    for (validator, _) in &keepers {
        let node = u32::try_from(validator.inner()).expect("host per keeper");
        let adopted = runner.flip_merge_parent(node, *validator, merge_parent);
        assert_eq!(
            adopted, parent_anchor.state_root,
            "every keeper adopts the beacon-composed merged root",
        );
    }

    // ── The merged shard runs past genesis and the survivor keeps committing ──
    let genesis_height = parent_anchor.height;
    let survivor_base = store_for(&runner, survivor)
        .expect("survivor store")
        .committed_height();
    let run_deadline = runner.now() + epochs(RUN_BUDGET_EPOCHS);
    let progressed = run_until(&mut runner, run_deadline, |r| {
        let merged_live = (0..r.num_hosts()).any(|node| {
            r.hosts_shard(node, merge_parent)
                .is_some_and(|s| s.committed_height() > genesis_height)
        });
        let survivor_live =
            store_for(r, survivor).is_some_and(|s| s.committed_height() > survivor_base);
        merged_live && survivor_live
    });
    assert!(
        progressed,
        "the merged shard must commit past its genesis (h{}) and the survivor past h{}",
        genesis_height.inner(),
        survivor_base.inner(),
    );

    // ── Settlement window: the survivor reads leaf(2,2)'s attested
    // settled-waves root, acquires S_{leaf(2,2)}, and finalizes the
    // straddlers it settled ──
    let survivor_validator = member_of(&runner, survivor);
    let survivor_host = runner.network().validator_to_node(survivor_validator);
    let settle_deadline = runner.now() + epochs(SETTLE_BUDGET_EPOCHS);
    let _ = run_until(&mut runner, settle_deadline, |r| {
        r.vnode_state(survivor_validator)
            .and_then(|n| {
                n.shard_coordinator()
                    .settled_set(merging)
                    .map(|s| s.waves.len())
            })
            .is_some_and(|n| n > 0)
            && probes.iter().all(|(_, hash)| {
                matches!(
                    r.tx_status(survivor_host, hash),
                    Some(TransactionStatus::Completed(_))
                )
            })
    });

    // ── The crux: the survivor reconstructed a non-empty settled set for the
    // *merged-away* leaf(2,2). Before the carry-predicate fix this was
    // None forever — a merge child never carried a settled_waves_root, so
    // the survivor's acquisition scan skipped it. ──
    let reconstructed = runner.vnode_state(survivor_validator).and_then(|node| {
        node.shard_coordinator()
            .settled_set(merging)
            .map(|set| set.waves.len())
    });
    assert!(
        reconstructed.is_some_and(|n| n > 0),
        "the survivor must reconstruct a non-empty settled set for the merged-away \
         {merging:?} (got {reconstructed:?}) — the merge terminal must attest a \
         settled_waves_root and the survivor must acquire it",
    );

    // ── Atomicity: scan each straddler's fate on both chains. The survivor
    // finalizes a cross-shard wave naming leaf(2,2) only because leaf(2,2)
    // settled it — never one-sided, and at least one settles end to end ──
    let merging_store = store_for(&runner, merging).expect("leaf(2,2) still served");
    let survivor_store = store_for(&runner, survivor).expect("survivor store");
    let terminal_b = genesis_height
        .prev()
        .expect("leaf(2,2)'s terminal sits below the merged genesis");
    let mut report = format!(
        "merged_genesis=h{} leaf(2,2)_terminal_B=h{}",
        genesis_height.inner(),
        terminal_b.inner(),
    );
    let mut settled = 0u32;
    let mut one_sided = 0u32;
    for (delay, hash) in &probes {
        let (m_committed, m_finalized) = scan_chain(merging_store, BlockHeight::new(1), *hash);
        let (v_committed, v_finalized) = scan_chain(survivor_store, BlockHeight::new(1), *hash);
        let settled_on_merging = m_finalized.is_some_and(|h| h <= terminal_b);
        let finalized_on_survivor = v_finalized.is_some();
        let _ = write!(
            report,
            "\n  +{delay}ms: leaf(2,2) committed={:?} finalized={:?} settled={settled_on_merging}; \
             survivor committed={:?} finalized={:?} status={:?}",
            m_committed.map(BlockHeight::inner),
            m_finalized.map(BlockHeight::inner),
            v_committed.map(BlockHeight::inner),
            v_finalized.map(BlockHeight::inner),
            runner.tx_status(survivor_host, hash),
        );
        if finalized_on_survivor && !settled_on_merging {
            one_sided += 1;
        }
        if settled_on_merging && finalized_on_survivor {
            settled += 1;
        }
    }

    assert_eq!(
        one_sided, 0,
        "the survivor finalized a straddler leaf(2,2) never settled — one-sided \
         cross-shard application:\n{report}",
    );
    assert!(
        settled > 0,
        "no straddler settled cross-shard between the survivor and the merging shard — \
         the delays need retuning:\n{report}",
    );

    // Belt and suspenders: no straddler is stuck — every one reaches a
    // terminal status, so none deferred forever at the fence.
    for (delay, hash) in &probes {
        assert!(
            matches!(
                runner.tx_status(survivor_host, hash),
                Some(TransactionStatus::Completed(_))
            ),
            "straddler +{delay}ms never reached a terminal status on the survivor — \
             a wave naming the merged-away shard deferred forever at the fence:\n{report}",
        );
    }
    // The decision recorded matches settlement: a settled straddler commits,
    // not aborts, on the survivor.
    for (delay, hash) in &probes {
        if let (_, Some(_)) = scan_chain(merging_store, BlockHeight::new(1), *hash) {
            assert!(
                !matches!(
                    runner.tx_status(survivor_host, hash),
                    Some(TransactionStatus::Completed(TransactionDecision::Aborted))
                ),
                "straddler +{delay}ms settled on leaf(2,2) yet aborted on the survivor:\n{report}",
            );
        }
    }
}
