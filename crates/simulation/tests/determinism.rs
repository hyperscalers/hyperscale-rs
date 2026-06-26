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
use tracing_test::traced_test;

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

/// Test partition recovery with 2-2 split using HotStuff-2 style round advancement.
///
/// With HotStuff-2 style view changes, round advancement happens implicitly via
/// the proposal timer when no QC forms within the timeout. This test verifies
/// that the system can recover from a partition.
///
/// **What happens:**
/// 1. Consensus runs normally, committing blocks
/// 2. A 2-2 partition is created (need 3/4 for quorum, neither side has it)
/// 3. During partition, progress halts (can't form QC with only 2 nodes)
/// 4. When partition heals, nodes reconnect
/// 5. With HotStuff-2, nodes advance rounds locally via proposal timer timeout
/// 6. Once connectivity is restored, nodes may sync via block headers with higher QCs
///
/// **Note:** This test primarily verifies that the system doesn't crash or deadlock
/// during partition recovery. Full recovery may require additional sync mechanisms.
#[traced_test]
#[test]
#[allow(clippy::too_many_lines)] // assertion-heavy partition-recovery scenario
fn test_partition_recovery_hotstuff2() {
    let config = test_network_config();
    let mut runner = SimulationRunner::new(&config, 42);

    runner.initialize_genesis();

    // Run normally for 1 second
    runner.run_until(Duration::from_secs(1));
    let height_before = runner
        .node(0)
        .unwrap()
        .shard_coordinator()
        .committed_height();
    println!("Height before partition: {height_before}");

    // Create a partition: nodes 0,1 can't talk to nodes 2,3
    runner.network_mut().partition_groups(&[0, 1], &[2, 3]);
    println!("Network partitioned: {{0,1}} <-> {{2,3}}");

    // Run during partition (1 second) - progress should halt (can't form QC with 2/4)
    runner.run_until(Duration::from_secs(2));
    let height_during = runner
        .node(0)
        .unwrap()
        .shard_coordinator()
        .committed_height();
    println!("Height during partition: {height_during}");

    // Debug: check shard consensus state (HotStuff-2 style - round tracked via view())
    let shard = runner.node(0).unwrap().shard_coordinator();
    println!(
        "shard consensus state: committed_height={}, view/round={}",
        shard.committed_height(),
        shard.view()
    );

    // Heal the partition
    runner.network_mut().heal_all();
    println!("Partition healed at sim time {:?}", runner.now());

    // Check heights on all nodes before continuing
    println!("Node heights before continuing:");
    for i in 0..4u32 {
        let h = runner
            .node(i)
            .unwrap()
            .shard_coordinator()
            .committed_height();
        let v = runner.node(i).unwrap().shard_coordinator().view();
        println!("  Node {i}: height={h}, view={v}");
    }

    // Run long enough for recovery to clear the post-heal suppression window.
    // After the partition, every node holds a stale pending block at its tip,
    // so `should_advance_round` suppresses the first timeout for up to
    // `MAX_PROGRESS_WAIT` (9s); only then does the pacemaker re-synchronise the
    // rounds and the chain resume committing.
    runner.run_until(Duration::from_secs(16));
    let height_after = runner
        .node(0)
        .unwrap()
        .shard_coordinator()
        .committed_height();
    println!(
        "Height after heal: {} (sim time {:?})",
        height_after,
        runner.now()
    );

    // Check heights on all nodes after
    println!("Node heights/shard consensus state after:");
    for i in 0..4u32 {
        let node = runner.node(i).unwrap();
        let h = node.shard_coordinator().committed_height();
        let v = node.shard_coordinator().view();
        println!("  Node {i}: shard(height={h}, view/round={v})");
    }

    let stats = runner.stats();
    println!("\nSimulation stats:");
    println!("  Events processed: {}", stats.events_processed);
    println!("  Timers set: {}", stats.timers_set);
    println!("  Messages sent: {}", stats.messages_sent);
    println!(
        "  Dropped (partition): {}",
        stats.messages_dropped_partition
    );
    println!(
        "  Events by priority (Internal, Timer, Network, Client): {:?}",
        stats.events_by_priority
    );

    // Collect heights after partition heals
    let post_heal_heights: Vec<BlockHeight> = (0..4u32)
        .map(|i| {
            runner
                .node(i)
                .unwrap()
                .shard_coordinator()
                .committed_height()
        })
        .collect();

    // Verify partition state
    let max_height = *post_heal_heights.iter().max().unwrap();
    let min_height = *post_heal_heights.iter().min().unwrap();

    println!("\nPartition effect:");
    println!("  Max height: {max_height}");
    println!("  Min height: {min_height}");
    println!("  Divergence: {}", max_height - min_height);

    // With HotStuff-2 style, nodes advance rounds locally without explicit vote exchange.
    // Recovery from partition requires receiving proposals/votes from other nodes.
    // This test verifies that:
    // 1. The system doesn't crash or deadlock
    // 2. All nodes have valid shard consensus state
    // 3. Round advancement is happening (view > 0 indicates timeout handling)

    // All nodes should have advanced rounds during the timeout period
    let all_views: Vec<Round> = (0..4u32)
        .map(|i| runner.node(i).unwrap().shard_coordinator().view())
        .collect();
    println!("Final views: {all_views:?}");

    // At minimum, nodes should not be deadlocked and should have valid state
    assert!(
        stats.events_processed > 0,
        "System should have processed events"
    );

    // After partition heals, nodes should resume making progress
    // The key assertion: max_height should be higher than height_during
    let height_diff = max_height.inner().saturating_sub(min_height.inner());
    println!("Height difference: {height_diff}");

    // Once the suppression window clears, the timeout pacemaker re-synchronises
    // the lagging half on a 2f+1 quorum and the chain resumes in earnest —
    // committing several more blocks, not crawling one at a time.
    assert!(
        max_height > height_during + 3,
        "Nodes should resume committing blocks after partition heals. \
         height_during={}, max_height={} (expected > {})",
        height_during,
        max_height,
        (height_during + 3).inner()
    );

    // Small divergence is expected due to in-flight messages and sync timing
    assert!(
        height_diff <= 5,
        "Height divergence should be small after recovery. Got diff={height_diff}, heights={post_heal_heights:?}"
    );
}

/// Test behavior during network partition.
///
/// With a 2-2 partition (nodes 0,1 vs 2,3), neither side can reach quorum
/// (need 3/4 = 75% for shard consensus). This test verifies:
/// 1. Progress halts during partition (expected behavior)
/// 2. Messages are being dropped as expected
#[traced_test]
#[test]
fn test_consensus_during_partition() {
    let config = test_network_config();
    let mut runner = SimulationRunner::new(&config, 42);

    runner.initialize_genesis();

    // Run normally for 1 second
    runner.run_until(Duration::from_secs(1));
    let height_before = runner
        .node(0)
        .unwrap()
        .shard_coordinator()
        .committed_height();
    println!("Height before partition: {height_before}");

    // Create a partition: nodes 0,1 can't talk to nodes 2,3
    runner.network_mut().partition_groups(&[0, 1], &[2, 3]);
    println!("Network partitioned: {{0,1}} <-> {{2,3}}");

    // Run during partition - neither side should make progress (need 3/4 for quorum)
    runner.run_until(Duration::from_secs(2));
    let height_during_partition = runner
        .node(0)
        .unwrap()
        .shard_coordinator()
        .committed_height();
    println!(
        "Height during partition: {height_during_partition} (expected ~{height_before} due to no quorum)"
    );

    // Progress should be minimal during partition
    // (may advance by 1-2 blocks if votes were in-flight when partition started)
    assert!(
        height_during_partition <= height_before + 2,
        "Progress should halt during partition (no quorum possible)"
    );

    let stats = runner.stats();
    println!("\nMessage stats:");
    println!("  Sent: {}", stats.messages_sent);
    println!(
        "  Dropped (partition): {}",
        stats.messages_dropped_partition
    );

    // Verify messages are being dropped
    assert!(
        stats.messages_dropped_partition > 0,
        "Messages should be dropped during partition"
    );
}
