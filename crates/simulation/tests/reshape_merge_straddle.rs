//! Cross-shard atomicity across a merge — rebuilt from the property up.
//!
//! The subject under test is one invariant: when a shard merges away, a
//! cross-shard wave naming it resolves atomically on its surviving
//! counterpart — finalized iff the merging shard settled it by its terminal
//! block, aborted otherwise, never one-sided, never wedged.
//!
//! Everything else (admission, the readiness gate, the beacon's parent
//! composition, the keeper flip) is *machinery* that gets the merging shard
//! to its terminal. This test drives that machinery as plainly as it can and
//! asserts nothing about it beyond "the merging shard reached its terminal";
//! the keeper flip — leaf(1,1) coming alive — is a separate concern and is
//! deliberately not exercised here, since the survivor's resolution depends
//! only on the terminated child's attested `settled_waves_root`.
//!
//! Topology, reached the way mainnet would: a single-shard genesis grows into
//! the four shards through two real split generations, then a stake-pool
//! parameter vote raises `split_bytes` so only the lighter `leaf(1,1)` pair
//! falls under the merge threshold. `leaf(2,2)`/`leaf(2,3)` merge into
//! `leaf(1,1)`; `leaf(2,0)` keeps `leaf(1,0)` alive as the surviving
//! counterpart. Cross-shard transfers run from the survivor `leaf(2,0)` into
//! the merging `leaf(2,2)`, so each wave names a shard that terminates at the
//! merge. The flow records a timestamped timeline; every assertion prints it,
//! so a failure shows the chronology.

use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Duration;

use hyperscale_node::shard::{HostEvent, ProcessScopedInput};
use hyperscale_simulation::{EPOCH_MS, SimConfig, SimulationRunner};
use hyperscale_storage::ShardChainReader;
use hyperscale_storage_memory::SimShardStorage;
use hyperscale_types::{
    BeaconChainConfig, BeaconState, BlockHeight, Ed25519PrivateKey, Epoch, KeeperSeat, NodeId,
    PendingReshape, ReshapeThresholds, RoutableTransaction, ShardId, TimestampRange,
    TransactionDecision, TransactionStatus, TxHash, ValidatorId, ValidatorStatus,
    WeightedTimestamp, ed25519_keypair_from_seed, routable_from_notarized_v1, sign_and_notarize,
    uniform_shard_for_node,
};
use radix_common::constants::XRD;
use radix_common::math::Decimal;
use radix_common::network::NetworkDefinition;
use radix_common::types::ComponentAddress;
use radix_transactions::builder::ManifestBuilder;

const PER_SHARD: u32 = 4;

/// The threshold the parameter vote installs after the grow:
/// `merge_threshold = split_bytes / 8 = 360_000`. The grow's two split
/// generations skew the four shards toward the low prefixes
/// (`leaf(2,0)`~525k, `leaf(2,2)`~320k, `leaf(2,3)`~56k, and `leaf(2,1)`
/// bulk-funded to ~402k); 360k sits between `leaf(2,2)` (merges) and both
/// surviving children `leaf(2,0)`/`leaf(2,1)` (stay above it), so only the
/// `leaf(1,1)` pair merges and `leaf(2,0)` keeps `leaf(1,0)` alive as the
/// surviving counterpart — with no live child stuck wanting an unpairable
/// merge.
const MERGE_VOTE_SPLIT_BYTES: u64 = 2_880_000;

/// Epochs after the post-grow epoch at which the threshold vote activates —
/// enough lead for the vote transaction to commit and fold into
/// `param_votes` before the tally reads it.
const ACTIVATE_LEAD: u64 = 4;

/// Number of settling waves: cross-shard transfers submitted while
/// `leaf(2,2)` is still live (before the keeper-ready broadcast arms the
/// gate), so their 2PC finalizes on `leaf(2,2)` at or below its terminal
/// block and lands in the attested `settled_waves_root`.
const NUM_SETTLE_WAVES: usize = 2;

/// Offsets before the cut for the straddling waves: close enough to the
/// terminal that the cross-shard 2PC commits on `leaf(2,2)` but finalizes
/// only on a post-terminal coast block (so the wave never settles and the
/// survivor must counterpart-abort it), yet not so close that the provision
/// arrives after `leaf(2,2)` stops voting on waves that name it. The commit
/// to finalize gap is ~3s of BFT rounds, so the window is the few seconds
/// before the cut, in absolute time and epoch-independent; the spread keeps
/// several inside it across the per-seed terminal-height drift.
const STRADDLE_OFFSETS_MS: [u64; 5] = [2_500, 2_000, 1_500, 1_000, 500];

const ADMISSION_BUDGET_EPOCHS: u64 = 28;
const SETTLE_BUDGET_EPOCHS: u64 = 8;
const GATE_BUDGET_EPOCHS: u64 = 10;
const TERMINAL_BUDGET_EPOCHS: u64 = 16;
const RESOLVE_BUDGET_EPOCHS: u64 = 12;

/// Single-shard genesis with the split trigger armed from genesis
/// (`split_bytes: 0` — every committed count exceeds it) and three cohorts
/// of pooled extras, so `grow_to(4)` drives the two split generations
/// (ROOT → `leaf(1,*)` → `leaf(2,*)`) through the real lifecycle. The merge
/// arrives once the vote raises `split_bytes`.
fn merge_config() -> SimConfig {
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
        pool_extra_validators: 3 * PER_SHARD,
        ..Default::default()
    }
}

fn beacon_state(runner: &SimulationRunner) -> Option<Arc<BeaconState>> {
    let (_, state) = runner.beacon_storage(0)?.latest_committed()?;
    Some(state)
}

/// The pending merge's keepers as `(validator, the child it runs)` pairs.
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

/// A fresh keypair whose preallocated account routes to `shard`.
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

/// Push `count` funded accounts routing to `shard` under a `num_shards`-wide
/// trie onto `balances`. The `u8`-seeded [`account_in`] tops out at 255 keys
/// (~`255 / num_shards` per shard); this uses a wide `u64` seed space to fund
/// a shard's prefix far past the merge threshold — needed to lift a grown
/// shard's light child above `merge_bytes` so it doesn't perpetually emit an
/// unpairable merge (the skew-induced churn that freezes the terminal fold).
fn bulk_fund_into(
    shard: ShardId,
    num_shards: u64,
    count: usize,
    balances: &mut Vec<(ComponentAddress, Decimal)>,
) {
    let mut found = 0;
    let mut seed: u64 = 1;
    while found < count {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&seed.to_le_bytes());
        let key = ed25519_keypair_from_seed(&bytes);
        let address = ComponentAddress::preallocated_account_from_public_key(&key.public_key());
        let node = NodeId(
            address.into_node_id().0[..30]
                .try_into()
                .expect("account address carries a 30-byte node id"),
        );
        if uniform_shard_for_node(&node, num_shards) == shard {
            balances.push((address, Decimal::from(10_000)));
            found += 1;
        }
        seed += 1;
    }
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

/// A payer-to-recipient XRD transfer, with a validity window bracketing
/// `anchor` — the approximate weighted time it commits at.
fn transfer(
    payer_key: &Ed25519PrivateKey,
    payer: ComponentAddress,
    recipient: ComponentAddress,
    anchor: Duration,
) -> Arc<RoutableTransaction> {
    let manifest = ManifestBuilder::new()
        .lock_fee(payer, Decimal::from(10))
        .withdraw_from_account(payer, XRD, Decimal::from(500))
        .try_deposit_entire_worktop_or_abort(recipient, None)
        .build();
    let notarized =
        sign_and_notarize(manifest, &NetworkDefinition::simulator(), 1, payer_key).expect("signs");
    let validity = TimestampRange::new(
        WeightedTimestamp::ZERO.plus(anchor.saturating_sub(Duration::from_secs(5))),
        WeightedTimestamp::ZERO.plus(anchor + Duration::from_secs(150)),
    );
    Arc::new(routable_from_notarized_v1(notarized, validity).expect("routable"))
}

/// Walk a committed chain from height 1 to its tip: the heights at which
/// `hash` committed (rides `transactions`) and finalized (rides a
/// `FinalizedWave` certificate).
fn scan_chain(
    storage: &SimShardStorage,
    hash: TxHash,
) -> (Option<BlockHeight>, Option<BlockHeight>) {
    let mut committed = None;
    let mut finalized = None;
    let tip = storage.committed_height();
    let mut height = BlockHeight::new(1);
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

const fn epochs(n: u64) -> Duration {
    Duration::from_millis(EPOCH_MS * n)
}

/// Run in one-second slices until `predicate` holds or `deadline` passes.
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

/// A timestamped phase log; printed by every assertion so a failure shows the
/// real chronology.
#[derive(Default)]
struct Timeline(String);

impl Timeline {
    fn mark(&mut self, now: Duration, event: &str) {
        let _ = writeln!(self.0, "  t={:>5}s  {event}", now.as_secs());
    }
}

// The four-shard grow and the merge-admission handshake are liveness-fragile
// under the seeded schedule, so the seed is pinned to one where the setup
// (grow, keeper pairing, merge execution) completes and the test reaches its
// subject — the cross-shard atomicity of a wave naming the merging shard.
// `MERGE_SEED` overrides it to sweep that fragility.
#[test]
#[allow(clippy::too_many_lines)] // one lifecycle asserted end to end
fn cross_shard_waves_resolve_atomically_across_a_merge() {
    let survivor = ShardId::leaf(2, 0);
    let merge_parent = ShardId::leaf(1, 1);
    let (merging, sibling) = merge_parent.children(); // leaf(2,2), leaf(2,3)

    let seed = std::env::var("MERGE_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4);
    let mut runner = SimulationRunner::new(&merge_config(), seed);
    let mut tl = Timeline::default();

    // The threshold vote is a fee-paying system transaction; fund the payer
    // at genesis so its `lock_fee` succeeds.
    let vote_payer = Ed25519PrivateKey::from_u64(9_999).expect("vote payer key");
    let vote_account =
        ComponentAddress::preallocated_account_from_public_key(&vote_payer.public_key());

    // Wave accounts: payer in the survivor, recipient in the merging shard,
    // so each transfer names the shard that terminates at the merge. The
    // accounts route to their depth-2 leaves by prefix, so the grow's splits
    // partition them onto `leaf(2,0)`/`leaf(2,2)`. The transactions are built
    // and submitted later, once the lifecycle reaches each wave's phase.
    let mut taken = Vec::new();
    let mut balances = vec![(vote_account, Decimal::from(100_000))];
    let waves: Vec<(Ed25519PrivateKey, ComponentAddress, ComponentAddress)> = (0..NUM_SETTLE_WAVES
        + STRADDLE_OFFSETS_MS.len())
        .map(|_| {
            let (payer_key, payer) = account_in(survivor, 4, &mut taken);
            let (_, recipient) = account_in(merging, 4, &mut taken);
            (payer_key, payer, recipient)
        })
        .collect();
    for (_, payer, recipient) in &waves {
        balances.push((*payer, Decimal::from(10_000)));
        balances.push((*recipient, Decimal::from(10_000)));
    }
    // Lift the surviving pair's light child `leaf(2,1)` (~89k of engine
    // bootstrap, the prefix the split barely populates) above `merge_bytes`
    // so it doesn't perpetually emit an unpairable merge against its heavy
    // sibling `leaf(2,0)` — that skew-induced churn rewrites the schedule
    // every epoch and freezes `leaf(2,2)`'s terminal fold.
    bulk_fund_into(ShardId::leaf(2, 1), 4, 500, &mut balances);
    runner.initialize_genesis_with_balances(&balances);
    tl.mark(runner.now(), "genesis");

    // ── Grow the single-shard genesis into the four shards through two real
    // split generations, then vote `split_bytes` up so only the lighter
    // `leaf(1,1)` pair falls under the merge threshold ──
    runner.grow_to(4);
    tl.mark(runner.now(), "grown to four shards");
    let post_grow_epoch = beacon_state(&runner)
        .expect("post-grow beacon state")
        .current_epoch;
    let activate_at = Epoch::new(post_grow_epoch.inner() + ACTIVATE_LEAD);
    runner.vote_reshape_thresholds(&vote_payer, 1, MERGE_VOTE_SPLIT_BYTES, activate_at);

    // ── Machinery: admission ──
    let paired = run_until(&mut runner, epochs(ADMISSION_BUDGET_EPOCHS), |r| {
        pending_keepers(r, merge_parent).is_some_and(|k| k.len() == PER_SHARD as usize)
    });
    assert!(
        paired,
        "the leaf(1,1) pair must pair a full keeper set\n{}",
        tl.0
    );
    let mut keepers = pending_keepers(&runner, merge_parent).expect("keepers paired");
    tl.mark(runner.now(), "keepers paired");

    // ── Settling waves: submitted while leaf(2,2) is still live and before
    // the keeper-ready broadcast arms the readiness gate, so the cross-shard
    // 2PC finalizes on leaf(2,2) at a height at or below its terminal block
    // and lands in that block's settled-waves window. We wait for them to
    // finalize before arming the gate, so settlement can't lose the race to
    // the sub-epoch window between the gate and the cut. They are not
    // cut-anchored — a settler only needs to finalize before the terminal. ──
    let mut probes: Vec<(String, TxHash)> = Vec::new();
    for (i, pair) in waves.iter().take(NUM_SETTLE_WAVES).enumerate() {
        let (payer_key, payer, recipient) = pair;
        let anchor = runner.now();
        let tx = transfer(payer_key, *payer, *recipient, anchor);
        probes.push((format!("settle#{i}"), tx.hash()));
        runner.schedule_initial_event(
            0,
            Duration::from_millis(10),
            HostEvent::process(ProcessScopedInput::SubmitTransaction { tx }),
        );
    }
    let settle_hashes: Vec<TxHash> = probes.iter().map(|(_, hash)| *hash).collect();
    let settle_deadline = runner.now() + epochs(SETTLE_BUDGET_EPOCHS);
    let settled_early = run_until(&mut runner, settle_deadline, |r| {
        store_for(r, merging)
            .is_some_and(|s| settle_hashes.iter().all(|h| scan_chain(s, *h).1.is_some()))
    });
    assert!(
        settled_early,
        "settling waves must finalize on leaf(2,2) before it terminates\n{}",
        tl.0
    );
    tl.mark(runner.now(), "settling waves finalized on leaf(2,2)");

    // ── Machinery: keeper sibling-sync (which also broadcasts keeper-ready,
    // arming the readiness gate), then drive it to fire the merge ──
    for (validator, own_child) in &keepers {
        let other = if *own_child == merging {
            sibling
        } else {
            merging
        };
        runner.merge_keeper(*validator, *own_child, other);
    }
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
    assert!(reshaped, "the readiness gate must fire the merge\n{}", tl.0);
    let final_epoch = beacon_state(&runner).expect("state").current_epoch;
    let cut = Duration::from_millis((final_epoch.inner() + 1) * EPOCH_MS);
    tl.mark(
        runner.now(),
        &format!("merge executed; cut at t={}s", cut.as_secs()),
    );

    // ── Straddling waves: cut-anchored a few seconds before the terminal so
    // the cross-shard provision routes and commits on leaf(2,2) but its 2PC
    // can't finalize before the terminal block — the survivor must
    // counterpart-abort them. ──
    for (offset_ms, pair) in STRADDLE_OFFSETS_MS.iter().zip(&waves[NUM_SETTLE_WAVES..]) {
        let (payer_key, payer, recipient) = pair;
        let target = cut.saturating_sub(Duration::from_millis(*offset_ms));
        let tx = transfer(payer_key, *payer, *recipient, target);
        let delay = target
            .saturating_sub(runner.now())
            .max(Duration::from_millis(10));
        probes.push((format!("straddle cut-{offset_ms}ms"), tx.hash()));
        runner.schedule_initial_event(
            0,
            delay,
            HostEvent::process(ProcessScopedInput::SubmitTransaction { tx }),
        );
    }
    tl.mark(runner.now(), &format!("{} waves total", probes.len()));

    // ── Machinery: leaf(2,2) terminates and its terminal folds (the beacon
    // attests its settled_waves_root) ──
    let terminal_deadline = runner.now() + epochs(TERMINAL_BUDGET_EPOCHS);
    let folded = run_until(&mut runner, terminal_deadline, |r| {
        beacon_state(r)
            .and_then(|s| {
                s.boundaries
                    .get(&merging)
                    .map(|b| b.settled_waves_root.is_some())
            })
            .unwrap_or(false)
    });
    if let Some(b) = beacon_state(&runner).and_then(|s| s.boundaries.get(&merging).copied()) {
        tl.mark(
            runner.now(),
            &format!(
                "leaf(2,2) boundary: terminal_epoch={:?} settled_waves_root={} height={:?}",
                b.terminal_epoch,
                b.settled_waves_root.is_some(),
                b.height,
            ),
        );
    }
    assert!(
        folded,
        "leaf(2,2)'s terminal must fold and attest a settled_waves_root\n{}",
        tl.0,
    );

    // ── The subject: the survivor reconstructs S_{leaf(2,2)} and resolves
    // every wave to a terminal decision ──
    let survivor_validator = member_of(&runner, survivor);
    let survivor_host = runner.network().validator_to_node(survivor_validator);
    let reconstructed_waves = |r: &SimulationRunner| {
        r.vnode_state(survivor_validator).and_then(|n| {
            n.shard_coordinator()
                .settled_set(merging)
                .map(|s| s.waves.len())
        })
    };
    let resolve_deadline = runner.now() + epochs(RESOLVE_BUDGET_EPOCHS);
    let resolved = run_until(&mut runner, resolve_deadline, |r| {
        reconstructed_waves(r).is_some_and(|n| n > 0)
            && probes.iter().all(|(_, hash)| {
                matches!(
                    r.tx_status(survivor_host, hash),
                    Some(TransactionStatus::Completed(_))
                )
            })
    });
    tl.mark(
        runner.now(),
        &format!(
            "survivor settled_set(leaf(2,2)) = {:?} waves",
            reconstructed_waves(&runner)
        ),
    );

    // ── Property: scan each wave's fate on both chains ──
    let merging_store = store_for(&runner, merging).expect("leaf(2,2) still served");
    let survivor_store = store_for(&runner, survivor).expect("survivor served");
    let terminal_height = beacon_state(&runner)
        .and_then(|s| s.boundaries.get(&merging).map(|b| b.height))
        .expect("leaf(2,2) terminal height");

    let mut settled = 0u32;
    let mut straddled = 0u32;
    let mut one_sided = 0u32;
    for (label, hash) in &probes {
        let (m_committed, m_finalized) = scan_chain(merging_store, *hash);
        let (v_committed, v_finalized) = scan_chain(survivor_store, *hash);
        let settled_on_merging = m_finalized.is_some_and(|h| h <= terminal_height);
        let status = runner.tx_status(survivor_host, hash);
        let accepted = matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        );
        tl.mark(
            runner.now(),
            &format!(
                "wave {label}: leaf(2,2) committed={:?} finalized={:?} settled={settled_on_merging}; \
                 survivor committed={:?} finalized={:?} status={status:?}",
                m_committed.map(BlockHeight::inner),
                m_finalized.map(BlockHeight::inner),
                v_committed.map(BlockHeight::inner),
                v_finalized.map(BlockHeight::inner),
            ),
        );
        if settled_on_merging && accepted {
            settled += 1;
        }
        if m_committed.is_some() && !settled_on_merging {
            straddled += 1;
        }
        if accepted && !settled_on_merging {
            one_sided += 1;
        }
    }

    assert!(
        resolved,
        "every wave must resolve to a terminal decision\n{}",
        tl.0
    );
    assert_eq!(
        one_sided, 0,
        "the survivor accepted a wave leaf(2,2) never settled — one-sided application\n{}",
        tl.0,
    );
    assert!(
        settled > 0,
        "no wave settled cross-shard before the terminal\n{}",
        tl.0
    );
    assert!(
        straddled > 0,
        "no wave straddled the terminal unsettled\n{}",
        tl.0
    );
    for (label, hash) in &probes {
        let settled_on_merging = scan_chain(merging_store, *hash)
            .1
            .is_some_and(|h| h <= terminal_height);
        if settled_on_merging {
            assert!(
                !matches!(
                    runner.tx_status(survivor_host, hash),
                    Some(TransactionStatus::Completed(TransactionDecision::Aborted))
                ),
                "wave {label} settled on leaf(2,2) yet aborted on the survivor\n{}",
                tl.0,
            );
        }
    }
}
