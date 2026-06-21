//! End-to-end merge of two cold sibling shards back into their parent,
//! reached the way mainnet would: grow a single-shard genesis into two
//! shards through the real split lifecycle, then govern the reshape
//! threshold up so the cold grown children fall below the merge threshold.
//!
//! A grown topology cannot merge under a frozen threshold — the threshold
//! that splits a parent always leaves children too large to fall back under
//! `merge_bytes = split_bytes / 8`. Raising `split_bytes` with a stake-pool
//! parameter vote is the honest trigger: once it activates, both children
//! sit below the new merge threshold and assert the merge. From there each
//! child's quorum pairs the merge and the beacon draws the keeper set —
//! half of each child's committee — then runs each keeper's real duty: the
//! sibling-half sync served by the sibling's committee, and the self-signed
//! ready signal delivered over its own child's network, BLS-verified,
//! pooled, drained into a block, classified as a `ReshapeReady` leaf, and
//! folded into the merge gate. The gate fires, the trie collapses both
//! children into their parent in the lookahead, the children coast to their
//! crossing and the beacon composes the parent anchor from their terminal
//! roots, and the keepers flip onto the parent — its committed root the
//! `hash_internal` of the two child terminal roots, its chain continuing
//! past the merged genesis.

use std::sync::Arc;
use std::time::Duration;

use hyperscale_simulation::{EPOCH_MS, SimConfig, SimulationRunner};
use hyperscale_storage::{ShardChainReader, SubstateStore};
use hyperscale_types::{
    BeaconChainConfig, BeaconState, BlockHash, Ed25519PrivateKey, Epoch, KeeperSeat,
    PendingReshape, RESHAPE_READY_TTL_EPOCHS, ReshapeThresholds, ShardId, SplitChildRoots,
    StateRoot, ValidatorId, ValidatorStatus,
};
use radix_common::math::Decimal;
use radix_common::types::ComponentAddress;
use tracing_test::traced_test;

/// Committee size on each shard — also the cohort `grow_to(2)` draws for the
/// one split, so `pool_extra_validators` matches it exactly.
const PER_SHARD: u32 = 4;

/// Reshape threshold armed for the grow: ROOT's ~988k genesis byte total
/// sits above it so ROOT splits once, while each child's half (the heavier
/// `leaf(1,0)` ~611k, the lighter ~377k) sits below it so neither child
/// re-splits and `merge_bytes = 100k` is far below both so neither merges —
/// the children rest stable until the vote lands.
const GROW_SPLIT_BYTES: u64 = 800_000;

/// Reshape threshold the parameter vote installs after the grow:
/// `merge_bytes = 1_000_000`, comfortably above each cold child's byte
/// total, so both assert the merge once the change activates.
const MERGE_VOTE_SPLIT_BYTES: u64 = 8_000_000;

/// Epochs after the post-grow epoch at which the threshold vote activates —
/// enough lead for the vote transaction to commit and fold into
/// `param_votes` before the tally reads it.
const ACTIVATE_LEAD: u64 = 4;

const ADMISSION_BUDGET_EPOCHS: u64 = 12;
const GATE_BUDGET_EPOCHS: u64 = 8;
const COMPOSE_BUDGET_EPOCHS: u64 = 14;
const PARENT_RUN_BUDGET_EPOCHS: u64 = 6;

/// Single-shard genesis with the split trigger armed for one generation and
/// one cohort of pooled extras — `grow_to(2)` drives it to the two sibling
/// shards (`leaf(1,0)`, `leaf(1,1)`) through the real split lifecycle.
fn merge_config() -> SimConfig {
    SimConfig {
        num_shards: 1,
        validators_per_shard: PER_SHARD,
        jitter_fraction: 0.1,
        beacon_chain_config: Some(BeaconChainConfig {
            epoch_duration_ms: EPOCH_MS,
            num_shards: 1,
            shard_size: PER_SHARD,
            reshape_thresholds: ReshapeThresholds {
                split_bytes: GROW_SPLIT_BYTES,
            },
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

/// Boot single-shard, grow to the two sibling shards through the real split
/// lifecycle, then vote the reshape threshold up so the cold grown children
/// fall under the merge threshold. Returns the runner with the vote
/// submitted and activating `ACTIVATE_LEAD` epochs out — the
/// grow-then-merge step that is impossible under a frozen threshold.
fn grown_and_voted_to_merge(seed: u64) -> SimulationRunner {
    // The threshold vote is a fee-paying system transaction; fund the payer
    // at genesis so its `lock_fee` succeeds.
    let payer = Ed25519PrivateKey::from_u64(42).expect("payer key");
    let account = ComponentAddress::preallocated_account_from_public_key(&payer.public_key());
    let mut runner = SimulationRunner::new(&merge_config(), seed);
    runner.initialize_genesis_with_balances(&[(account, Decimal::from(100_000))]);
    runner.grow_to(2);

    let epoch = beacon_state(&runner)
        .expect("post-grow beacon state")
        .current_epoch;
    let activate_at = Epoch::new(epoch.inner() + ACTIVATE_LEAD);
    runner.vote_reshape_thresholds(&payer, 1, MERGE_VOTE_SPLIT_BYTES, activate_at);
    runner
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
    Duration::from_millis(EPOCH_MS * n)
}

#[traced_test]
#[test]
#[allow(clippy::too_many_lines)] // one merge lifecycle asserted end to end
fn keepers_merge_two_cold_siblings_into_their_parent() {
    let (left, right) = ShardId::ROOT.children();
    let mut runner = grown_and_voted_to_merge(8);

    // ── Admission: the vote activates, each child asserts the merge against
    // the raised threshold, and the beacon pairs and draws the keeper
    // committee ──
    let admission_deadline = runner.now() + epochs(ADMISSION_BUDGET_EPOCHS);
    let paired = run_until(&mut runner, admission_deadline, |r| {
        pending_keepers(r).is_some_and(|k| k.len() == PER_SHARD as usize)
    });
    assert!(
        paired,
        "the threshold vote must activate and both children pair a full keeper \
         set within {ADMISSION_BUDGET_EPOCHS} epochs",
    );
    let mut keepers = pending_keepers(&runner).expect("keepers just observed");
    for child in [left, right] {
        assert_eq!(
            keepers.iter().filter(|(_, c)| *c == child).count(),
            (PER_SHARD / 2) as usize,
            "each child contributes half the keeper committee; got {keepers:?}",
        );
    }

    // ── Keeper duty: prove each keeper's sibling-half sync once. ──
    for (validator, own_child) in &keepers {
        let sibling = if *own_child == left { right } else { left };
        runner.merge_keeper(*validator, *own_child, sibling);
    }

    // ── The gate fires: each keeper re-asserts its ready signal until the
    // merge collapses both children into the parent in the lookahead. The
    // keepers promote into the active reshape-keeper window only a window
    // after pairing (the freeze discipline), and a child chain's blocks
    // anchor in that window only as their `parent_qc.wt` catches up, so a
    // one-shot signal can land while it still classifies as a plain
    // `Ready`. A production keeper re-asserts until it is placed; the
    // harness does the same, re-reading the live keeper set so a re-pair
    // is followed and stopping once the merge executes. ──
    let gate_deadline = runner.now() + epochs(GATE_BUDGET_EPOCHS);
    let mut reshaped = false;
    while runner.now() < gate_deadline {
        if let Some(current) = pending_keepers(&runner) {
            keepers = current;
            for (validator, own_child) in &keepers {
                runner.broadcast_keeper_ready(*validator, *own_child);
            }
        }
        let next = runner.now() + Duration::from_secs(1);
        runner.run_until(next);
        if beacon_state(&runner).is_some_and(|s| {
            s.pending_reshapes.is_empty() && s.next_shard_committees.contains_key(&ShardId::ROOT)
        }) {
            reshaped = true;
            break;
        }
    }
    assert!(
        reshaped,
        "the re-asserted ReshapeReady signals must fire the merge gate within \
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
        use std::fmt::Write;
        let s = beacon_state(&runner).expect("state");
        let mut detail = String::new();
        // What does each host's head trie carry — has the merge dropped the
        // children for ROOT, or do they linger as live leaves?
        for node in 0..runner.num_hosts() {
            if let Some(topo) = runner.host_topology(node) {
                let leaves: Vec<ShardId> = topo.shard_trie().leaves().collect();
                let _ = write!(detail, "\n  node {node} head trie leaves: {leaves:?}");
            }
        }
        // Per child: tip height and the tip block's weighted timestamp →
        // epoch, to compare the children's clock against the beacon's.
        for child in [left, right] {
            for node in 0..runner.num_hosts() {
                if let Some(storage) = runner.hosts_shard(node, child) {
                    let tip = storage.committed_height();
                    let tip_wt_ms = storage
                        .get_block(tip)
                        .map_or(0, |b| b.block().header().timestamp().as_millis());
                    let _ = write!(
                        detail,
                        "\n  node {node} {child:?}: committed {tip:?} tip_wt={tip_wt_ms}ms \
                         (epoch {}) root {:?}",
                        tip_wt_ms / EPOCH_MS,
                        storage.state_root(),
                    );
                }
            }
        }
        panic!(
            "compose timed out; beacon epoch {:?}; committee {}; pending {:?}; boundaries {:?}; \
             detail:{detail}",
            s.current_epoch,
            s.committee.len(),
            s.pending_reshapes.keys().collect::<Vec<_>>(),
            s.boundaries,
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
    // Each child's terminal substate population, captured before the
    // children are torn down — for the account-continuity keystone below.
    let left_count = child_terminal_count(&runner, left);
    let right_count = child_terminal_count(&runner, right);

    // ── The flip: each host's keepers build the merged store from both
    // halves and seat onto the parent. Keepers drawn from both children can
    // share a host, and a merge converges them all onto the one parent
    // shard, so group by host and seat each host's keepers together. ──
    let parent_anchor = state.boundaries[&ShardId::ROOT];
    let mut keepers_by_node: std::collections::BTreeMap<_, Vec<ValidatorId>> =
        std::collections::BTreeMap::new();
    for (validator, _) in &keepers {
        keepers_by_node
            .entry(runner.network().validator_to_node(*validator))
            .or_default()
            .push(*validator);
    }
    for (node, validators) in &keepers_by_node {
        let adopted = runner.flip_merge_parent(*node, validators, ShardId::ROOT);
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

    // Every keeper's merged store holds the deterministic genesis as its
    // committed base, and every committed chain extends it. Only the keeper
    // hosts carry the reformed parent; non-keeper hosts still hold the dead
    // pre-grow genesis chain under the same id.
    let mut merged_count = None;
    for &node in keepers_by_node.keys() {
        let storage = runner
            .hosts_shard(node, ShardId::ROOT)
            .expect("a keeper host carries the merged shard");
        let genesis = storage
            .get_block(genesis_height)
            .expect("the adoption recorded the merged genesis as the committed tip");
        assert_eq!(genesis.block().hash(), parent_anchor.block_hash);
        assert_eq!(
            genesis.block().header().state_root(),
            parent_anchor.state_root
        );
        merged_count = Some(
            storage
                .substate_bytes_at_version(genesis_height.inner())
                .expect("the merged genesis recorded its substate byte total"),
        );
    }

    // State continuity, the account-level keystone: the merged keyset is
    // the disjoint union of the two children's — no account lost or
    // duplicated. The counts add up exactly (a key shared across the
    // halves would dedup on import and shrink the merged count below the
    // sum), and the composed-root check already pinned the structure.
    assert_eq!(
        merged_count.expect("a host carries the merged shard"),
        left_count + right_count,
        "the merged substate population must be the sum of the two children's",
    );
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

/// A terminated child's committed substate byte total, read from a host still
/// carrying it.
fn child_terminal_count(runner: &SimulationRunner, child: ShardId) -> u64 {
    for node in 0..runner.num_hosts() {
        if let Some(storage) = runner.hosts_shard(node, child) {
            return storage
                .substate_bytes_at_version(storage.committed_height().inner())
                .unwrap_or(0);
        }
    }
    panic!("no host carries the terminated child {child:?}");
}

/// The readiness gate is load-bearing: a merge that pairs but whose
/// keepers never sync the sibling half — never signal `ReshapeReady` —
/// must never collapse the trie. The readiness TTL abandons each pairing
/// and the standing trigger re-pairs, but without `2f+1` ready keepers
/// the parent never takes the children's place.
#[traced_test]
#[test]
fn the_merge_gate_requires_keeper_readiness() {
    let (left, right) = ShardId::ROOT.children();
    let mut runner = grown_and_voted_to_merge(8);

    let admission_deadline = runner.now() + epochs(ADMISSION_BUDGET_EPOCHS);
    let paired = run_until(&mut runner, admission_deadline, |r| {
        pending_keepers(r).is_some()
    });
    assert!(
        paired,
        "the merge must pair within {ADMISSION_BUDGET_EPOCHS} epochs",
    );

    // No keeper signals ready across more than the readiness TTL.
    let watch_deadline = runner.now() + epochs(2 * RESHAPE_READY_TTL_EPOCHS);
    let executed = run_until(&mut runner, watch_deadline, |r| {
        beacon_state(r).is_some_and(|s| s.next_shard_committees.contains_key(&ShardId::ROOT))
    });
    assert!(
        !executed,
        "the merge must not execute without keeper readiness",
    );

    // The children remain separate active leaves; the parent never formed.
    let state = beacon_state(&runner).expect("post-watch state");
    assert!(
        state.next_shard_committees.contains_key(&left)
            && state.next_shard_committees.contains_key(&right),
        "both children must still be active leaves",
    );
    assert!(!state.next_shard_committees.contains_key(&ShardId::ROOT));
}
