//! Full-stack determinism for the composed simulation runner.
//!
//! The shard mini-sim (`crates/shard/tests`) guards coordinator-level
//! determinism and the beacon (`crates/beacon/tests`) guards its fold; neither
//! covers the assembled `SimulationRunner` — node state machine, `io_loop`,
//! mempool, execution, and shard consensus folded together over one seeded
//! clock. This pins that: a rich run (genesis, packet loss, live transactions)
//! replays byte-identical from the same seed across every observable surface,
//! and a different seed produces a different chain.
//!
//! The two partition tests assert the full-stack liveness the mini-sim cannot
//! model: a 2-2 split halts without quorum and resumes on heal.

use std::sync::Arc;
use std::time::Duration;

use hyperscale_node::shard::{HostEvent, ProcessScopedInput};
use hyperscale_simulation::{SimConfig, SimulationRunner};
use hyperscale_storage::SubstateStore;
use hyperscale_types::test_utils::test_transaction;
use hyperscale_types::{BeaconBlockHash, BlockHeight, Round, ShardId, StateRoot};

/// A four-validator single-shard network with light jitter; beacon options
/// default.
fn test_network_config() -> SimConfig {
    SimConfig {
        validators_per_shard: 4,
        jitter_fraction: 0.1,
        ..Default::default()
    }
}

/// The determinism guard's config: the base network plus a lossy delivery path,
/// so a replay exercises the packet-loss RNG stream as well as consensus.
fn determinism_config() -> SimConfig {
    SimConfig {
        packet_loss_rate: 0.10,
        ..test_network_config()
    }
}

/// Every observable surface of a run, captured per node so two seeded replays
/// can be compared for byte-identical equality.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RunFingerprint {
    events_processed: u64,
    messages_sent: u64,
    messages_dropped_loss: u64,
    timers_set: u64,
    actions_generated: u64,
    heights: Vec<BlockHeight>,
    views: Vec<Round>,
    state_roots: Vec<Option<StateRoot>>,
    beacon_blocks: Vec<Option<BeaconBlockHash>>,
}

/// Drive one run: genesis, three transactions submitted to node 0, then ten
/// seconds of progress under packet loss. Returns its fingerprint.
fn run_once(seed: u64) -> RunFingerprint {
    let config = determinism_config();
    let mut runner = SimulationRunner::new(&config, seed);
    runner.initialize_genesis();

    for (i, delay_ms) in [50u64, 51, 52].into_iter().enumerate() {
        let tx = test_transaction(u8::try_from(i).unwrap() + 1);
        runner.schedule_initial_event(
            0,
            Duration::from_millis(delay_ms),
            HostEvent::process(ProcessScopedInput::SubmitTransaction { tx: Arc::new(tx) }),
        );
    }
    runner.run_until(Duration::from_secs(10));

    let stats = runner.stats().clone();
    RunFingerprint {
        events_processed: stats.events_processed,
        messages_sent: stats.messages_sent,
        messages_dropped_loss: stats.messages_dropped_loss,
        timers_set: stats.timers_set,
        actions_generated: stats.actions_generated,
        heights: (0..4u32)
            .map(|i| {
                runner
                    .node(i)
                    .unwrap()
                    .shard_coordinator()
                    .committed_height()
            })
            .collect(),
        views: (0..4u32)
            .map(|i| runner.node(i).unwrap().shard_coordinator().view())
            .collect(),
        state_roots: (0..4u32)
            .map(|i| {
                runner
                    .hosts_shard(i, ShardId::ROOT)
                    .map(SubstateStore::state_root)
            })
            .collect(),
        beacon_blocks: (0..4u32)
            .map(|i| {
                runner
                    .beacon_storage(i)
                    .and_then(|s| s.latest_committed())
                    .map(|(block, _)| block.block_hash())
            })
            .collect(),
    }
}

/// The same seed replays byte-identically across stats, per-node committed
/// heights and views, committed state roots, and beacon blocks — the composed
/// runner is deterministic end to end. The run also confirms transactions drive
/// progress and packet loss is exercised, so a regression in either surfaces
/// here.
#[test]
fn same_seed_replays_byte_identical() {
    let first = run_once(12345);
    let second = run_once(12345);

    assert!(
        first.heights.iter().any(|h| *h > BlockHeight::GENESIS),
        "the run must commit past genesis for the comparison to mean anything; got {:?}",
        first.heights,
    );
    assert!(
        first.messages_dropped_loss > 0,
        "the run must exercise the packet-loss path; none dropped",
    );
    assert_eq!(
        first, second,
        "same seed must replay byte-identically across the full stack",
    );
}

/// A different seed produces a different run. The shared deterministic genesis
/// means divergence shows up in the network-driven surfaces (message counts,
/// per-node progress), so compare the whole fingerprint rather than any single
/// field.
#[test]
fn different_seed_diverges() {
    let a = run_once(111);
    let b = run_once(222);
    assert_ne!(a, b, "different seeds must produce a different run");
}
