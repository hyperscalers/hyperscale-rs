//! Shared scaffolding for the simulation tests.
//!
//! Two families live here. The rotation knobs (`rotation_config`, `PER_SHARD`,
//! `POOL_EXTRAS`) drive `topology_rotation` / `vnode_relocation`, which need a
//! paced-epoch, refillable-pool network and shuffle reachability. The
//! grow-convert helpers (`cross_shard_grow_config` and friends) boot a
//! single-shard network and drive `grow_to(2)`, the shape every cross-shard
//! test now uses instead of a multi-shard genesis.

// This module is compiled into every test binary that declares `mod common;`,
// but each uses only the helpers it needs, so unused-in-this-binary items are
// expected.
#![allow(dead_code)]

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use hyperscale_metrics::{MetricsRecorder, with_scoped_recorder};
use hyperscale_metrics_memory::MemoryRecorder;
use hyperscale_node::NodeStateMachine;
use hyperscale_node::shard_loop::{HostEvent, ProcessScopedInput};
use hyperscale_simulation::{EPOCH_MS, SimConfig, SimulationRunner};
use hyperscale_types::{
    BeaconChainConfig, Ed25519PrivateKey, NodeId, ReshapeThresholds, RoutableTransaction, ShardId,
    TimestampRange, TxHash, ValidatorId, WeightedTimestamp, ed25519_keypair_from_seed,
    routable_from_notarized_v1, sign_and_notarize, uniform_shard_for_node,
};
use radix_common::constants::XRD;
use radix_common::math::Decimal;
use radix_common::network::NetworkDefinition;
use radix_common::types::ComponentAddress;
use radix_transactions::builder::ManifestBuilder;

/// Committee validators per shard. The shuffle retires one member at the
/// boundary and refills it; the refill seats on its own dedicated host but the
/// test drives only the direct move, so the other refills run no shard vnode.
/// Seven keeps both committees above quorum (five) through the rotation even
/// with an unseated replacement.
pub const PER_SHARD: u32 = 7;

/// `Pooled` validators left over once `grow_to(2)` has seated its cohort.
/// Exactly one: the shuffle processes the two shards in order, so shard 0
/// refills from this lone surplus, leaving only shard 0's just-rotated victim
/// in the pool for shard 1 to re-draw — a *direct* cross-shard move every seed
/// (`pool_draw` re-draws an earlier shard's victim, and the beacon resample
/// runs after the shuffle, so it can't drain the pool first). An empty pool
/// would skip the rotation entirely.
pub const POOL_EXTRAS: u32 = 1;

/// Single-shard, paced-epoch network both rotation tests grow to two shards
/// (`grow_to(2)`) before exercising the committee shuffle. The split trigger is
/// armed from genesis; the pool carries one cohort (`PER_SHARD`) for the grow
/// plus `POOL_EXTRAS` surplus for the shuffle to refill from, each on its own
/// dedicated beacon-follower host so every committee member ends on a single
/// shard.
#[must_use]
pub fn rotation_config() -> SimConfig {
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
        pool_extra_validators: PER_SHARD + POOL_EXTRAS,
        dedicated_pool_hosts: true,
        ..Default::default()
    }
}

/// Run `f` against a fresh per-test `MemoryRecorder` installed as the
/// thread-local metrics recorder. Cargo runs each test on its own thread, so
/// concurrent tests get fully isolated counters.
pub fn with_test_recorder<R>(f: impl FnOnce(&MemoryRecorder) -> R) -> R {
    let recorder = MemoryRecorder::new();
    let arc: Arc<dyn MetricsRecorder> = Arc::new(recorder.clone());
    with_scoped_recorder(arc, || f(&recorder))
}

/// Committee size for the grow-convert config — also the cohort size each
/// split draws, so `pool_extra_validators` matches it exactly per split.
pub const GROW_PER_SHARD: u32 = 4;

/// Single-shard genesis with the split trigger armed, short paced epochs, and
/// one cohort of pooled extras — `grow_to(2)` drives it to two shards through
/// the real split lifecycle, mirroring a network that launches single-shard
/// and fans out under load.
#[must_use]
pub fn cross_shard_grow_config() -> SimConfig {
    SimConfig {
        num_shards: 1,
        validators_per_shard: GROW_PER_SHARD,
        jitter_fraction: 0.1,
        beacon_chain_config: Some(BeaconChainConfig {
            epoch_duration_ms: EPOCH_MS,
            num_shards: 1,
            shard_size: GROW_PER_SHARD,
            reshape_thresholds: ReshapeThresholds { split_bytes: 0 },
            ..BeaconChainConfig::default()
        }),
        pool_extra_validators: GROW_PER_SHARD,
        ..Default::default()
    }
}

/// The two leaf shards a `grow_to(2)` produces.
#[must_use]
pub const fn grown_leaves() -> [ShardId; 2] {
    [ShardId::leaf(1, 0), ShardId::leaf(1, 1)]
}

fn account_from_keypair(kp: &Ed25519PrivateKey) -> ComponentAddress {
    ComponentAddress::preallocated_account_from_public_key(&kp.public_key())
}

/// Find one funded keypair whose account routes to each of the two leaf shards
/// under `num_shards`. Account routing equals the prefix the grow assigns, so
/// these stay on their shards across the split.
///
/// # Panics
///
/// Panics if no account is found for either shard within the seed range.
#[must_use]
pub fn find_accounts_on_each_shard(
    num_shards: u64,
) -> (
    (Ed25519PrivateKey, ComponentAddress),
    (Ed25519PrivateKey, ComponentAddress),
) {
    let mut shard0 = None;
    let mut shard1 = None;
    for seed in 10u8..=255 {
        let kp = ed25519_keypair_from_seed(&[seed; 32]);
        let acc = account_from_keypair(&kp);
        let radix_node_id = acc.into_node_id();
        let hs_node_id = NodeId(radix_node_id.0[..30].try_into().unwrap());
        let shard = uniform_shard_for_node(&hs_node_id, num_shards);
        if shard == ShardId::leaf(1, 0) {
            shard0.get_or_insert((kp, acc));
        } else if shard == ShardId::leaf(1, 1) {
            shard1.get_or_insert((kp, acc));
        }
        if shard0.is_some() && shard1.is_some() {
            break;
        }
    }
    match (shard0, shard1) {
        (Some(a), Some(b)) => (a, b),
        _ => panic!("could not find accounts on both shards within seed range"),
    }
}

/// A validity range bracketing `now` (the current weighted time after a grow).
/// The genesis-anchored `test_validity_range()` (`[0, 1min]`) has long expired
/// by the time `grow_to` finishes, so a post-grow tx must carry its own — 150s
/// forward, well under the 5-minute `MAX_VALIDITY_RANGE`.
#[must_use]
pub fn grow_validity_range(now: Duration) -> TimestampRange {
    TimestampRange::new(
        WeightedTimestamp::ZERO.plus(now.saturating_sub(Duration::from_secs(5))),
        WeightedTimestamp::ZERO.plus(now + Duration::from_secs(150)),
    )
}

/// Build a withdraw-from-`acc_a`, deposit-to-`acc_b` cross-shard transfer whose
/// validity range brackets `now`.
///
/// # Panics
///
/// Panics if signing or routability conversion fails.
#[must_use]
pub fn build_cross_shard_transfer(
    kp_a: &Ed25519PrivateKey,
    acc_a: ComponentAddress,
    acc_b: ComponentAddress,
    now: Duration,
) -> RoutableTransaction {
    let manifest = ManifestBuilder::new()
        .lock_fee(acc_a, Decimal::from(10))
        .withdraw_from_account(acc_a, XRD, Decimal::from(500))
        .try_deposit_entire_worktop_or_abort(acc_b, None)
        .build();
    let notarized = sign_and_notarize(manifest, &NetworkDefinition::simulator(), 200, kp_a)
        .expect("transfer signs");
    routable_from_notarized_v1(notarized, grow_validity_range(now)).expect("transfer is routable")
}

/// Submit `tx` to whichever host now carries `source_shard`. The grow shuffles
/// validator placement, so the source host can't be assumed to be node 0; and
/// `schedule_initial_event`'s second arg is a delay, so it must be
/// `Duration::ZERO` to submit immediately rather than `runner.now()` into the
/// future.
///
/// # Panics
///
/// Panics if no host carries `source_shard`.
pub fn submit_to_shard(
    runner: &mut SimulationRunner,
    source_shard: ShardId,
    tx: RoutableTransaction,
) {
    let submit_host = (0..runner.num_hosts())
        .find(|&node| runner.hosts_shard(node, source_shard).is_some())
        .expect("a host carries the source shard");
    runner.schedule_initial_event(
        submit_host,
        Duration::ZERO,
        HostEvent::process(ProcessScopedInput::SubmitTransaction { tx: Arc::new(tx) }),
    );
}

/// Whether a vnode has reached a terminal outcome for `tx_hash` — finalized
/// (an execution certificate landed) or tombstoned (committed-and-removed, or
/// aborted).
#[must_use]
pub fn vnode_reached_terminal_state(vnode: &NodeStateMachine, tx_hash: TxHash) -> bool {
    vnode.execution_coordinator().is_finalized(tx_hash)
        || vnode.mempool_coordinator().is_tombstoned(&tx_hash)
}

/// Poll the sim in one-second slices until every live committee member across
/// `live_leaves` reaches a terminal outcome for `tx_hash`, or `deadline`
/// passes. A successful tx finalizes and is then cleaned up (status returns to
/// `None`), so latch the first terminal observation per validator rather than
/// reading the post-cleanup state. Returns the validators ever observed
/// terminal.
///
/// Walks `SimulationRunner::shard_vnodes` per leaf, not host-indexed `node(i)`:
/// a flip leaves terminated parent vnodes on hosts and seats observers
/// cross-shard, so host-indexing misses live committee members.
pub fn await_all_terminal(
    runner: &mut SimulationRunner,
    live_leaves: &[ShardId],
    tx_hash: TxHash,
    deadline: Duration,
) -> HashSet<ValidatorId> {
    let mut latched: HashSet<ValidatorId> = HashSet::new();
    while runner.now() < deadline {
        let next = runner.now() + Duration::from_secs(1);
        runner.run_until(next);
        let all_terminal = live_leaves.iter().all(|&leaf| {
            runner.shard_vnodes(leaf).iter().all(|&vnode| {
                if vnode_reached_terminal_state(vnode, tx_hash) {
                    latched.insert(vnode.validator_id());
                    true
                } else {
                    latched.contains(&vnode.validator_id())
                }
            })
        });
        if all_terminal {
            break;
        }
    }
    latched
}
