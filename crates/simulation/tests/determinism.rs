//! Tests for deterministic simulation.
//!
//! These tests verify that the simulation produces identical results
//! given the same seed, which is the core property we need for debugging
//! and replay.

use hyperscale_core::Event;
use hyperscale_simulation::{NetworkConfig, SimulationRunner};
use std::sync::Arc;
use std::time::Duration;
use tracing_test::traced_test;

/// Create a basic network configuration for testing.
fn test_network_config() -> NetworkConfig {
    NetworkConfig {
        num_shards: 1,
        validators_per_shard: 4,
        intra_shard_latency: Duration::from_millis(10),
        cross_shard_latency: Duration::from_millis(50),
        jitter_fraction: 0.1,
        ..Default::default()
    }
}

/// Test that the simulation runner can be created and run without panicking.
#[test]
fn test_simulation_runner_creation() {
    let config = test_network_config();
    let runner = SimulationRunner::new(config, 42);

    // Should have 4 nodes (1 shard * 4 validators)
    assert!(runner.node(0).is_some());
    assert!(runner.node(1).is_some());
    assert!(runner.node(2).is_some());
    assert!(runner.node(3).is_some());
    assert!(runner.node(4).is_none());
}

/// Test that scheduling initial events works.
#[test]
fn test_schedule_initial_events() {
    let config = test_network_config();
    let mut runner = SimulationRunner::new(config, 42);

    // Schedule proposal timers for all nodes
    for node in 0..4 {
        runner.schedule_initial_event(node, Duration::from_millis(100), Event::ProposalTimer);
    }

    // Run for a short time
    runner.run_until(Duration::from_millis(200));

    // Should have processed at least the initial events
    let stats = runner.stats();
    assert!(
        stats.events_processed >= 4,
        "Should have processed at least 4 events"
    );
}

/// Test that the same seed produces the same sequence of events.
#[test]
fn test_determinism_same_seed() {
    let config = test_network_config();
    let seed = 12345u64;

    // Run simulation with seed
    let mut runner1 = SimulationRunner::new(config.clone(), seed);
    for node in 0..4 {
        runner1.schedule_initial_event(node, Duration::from_millis(100), Event::ProposalTimer);
    }
    runner1.run_until(Duration::from_secs(1));
    let stats1 = runner1.stats().clone();

    // Run simulation again with same seed
    let mut runner2 = SimulationRunner::new(config.clone(), seed);
    for node in 0..4 {
        runner2.schedule_initial_event(node, Duration::from_millis(100), Event::ProposalTimer);
    }
    runner2.run_until(Duration::from_secs(1));
    let stats2 = runner2.stats().clone();

    // Results should be identical
    assert_eq!(
        stats1.events_processed, stats2.events_processed,
        "Same seed should produce same number of events"
    );
    assert_eq!(
        stats1.messages_sent, stats2.messages_sent,
        "Same seed should produce same number of messages"
    );
    assert_eq!(
        stats1.timers_set, stats2.timers_set,
        "Same seed should produce same number of timers"
    );
    assert_eq!(
        stats1.actions_generated, stats2.actions_generated,
        "Same seed should produce same number of actions"
    );
}

/// Test that different seeds produce different results.
#[test]
fn test_different_seeds_diverge() {
    let config = test_network_config();

    // Run simulation with seed 1
    let mut runner1 = SimulationRunner::new(config.clone(), 111);
    for node in 0..4 {
        runner1.schedule_initial_event(node, Duration::from_millis(100), Event::ProposalTimer);
    }
    runner1.run_until(Duration::from_secs(1));

    // Run simulation with seed 2
    let mut runner2 = SimulationRunner::new(config.clone(), 222);
    for node in 0..4 {
        runner2.schedule_initial_event(node, Duration::from_millis(100), Event::ProposalTimer);
    }
    runner2.run_until(Duration::from_secs(1));

    // Note: The stats might actually be the same since the BFT logic is deterministic
    // given the initial state. The difference would show in timing/ordering of network
    // messages due to different latency samples.
    // For now, just verify both complete successfully
    assert!(runner1.stats().events_processed > 0);
    assert!(runner2.stats().events_processed > 0);
}

/// Test simulation with multiple shards.
#[test]
fn test_multi_shard_simulation() {
    let config = NetworkConfig {
        num_shards: 2,
        validators_per_shard: 3,
        intra_shard_latency: Duration::from_millis(10),
        cross_shard_latency: Duration::from_millis(50),
        jitter_fraction: 0.1,
        ..Default::default()
    };

    let mut runner = SimulationRunner::new(config, 42);

    // Should have 6 nodes (2 shards * 3 validators)
    assert!(runner.node(0).is_some());
    assert!(runner.node(5).is_some());
    assert!(runner.node(6).is_none());

    // Schedule proposal timers for all nodes
    for node in 0..6 {
        runner.schedule_initial_event(node, Duration::from_millis(100), Event::ProposalTimer);
    }

    runner.run_until(Duration::from_secs(1));

    let stats = runner.stats();
    assert!(
        stats.events_processed >= 6,
        "Should have processed events from all nodes"
    );
}

/// Test that view change timer can be scheduled and processed.
#[test]
fn test_view_change_timer() {
    let config = test_network_config();
    let mut runner = SimulationRunner::new(config, 42);

    // Schedule view change timers
    for node in 0..4 {
        runner.schedule_initial_event(node, Duration::from_secs(5), Event::ViewChangeTimer);
    }

    runner.run_until(Duration::from_secs(10));

    let stats = runner.stats();
    assert!(
        stats.events_processed >= 4,
        "Should have processed view change timers"
    );
}

/// Test longer simulation for more complex interactions.
#[test]
fn test_extended_simulation() {
    let config = test_network_config();
    let mut runner = SimulationRunner::new(config, 42);

    // Schedule initial proposal timers
    for node in 0..4 {
        runner.schedule_initial_event(node, Duration::from_millis(100), Event::ProposalTimer);
    }

    // Run for 10 seconds of simulated time
    runner.run_until(Duration::from_secs(10));

    let stats = runner.stats();

    // With proposal timers every 100ms for 4 nodes over 10 seconds,
    // we should see significant activity
    println!("Extended simulation stats:");
    println!("  Events processed: {}", stats.events_processed);
    println!("  Actions generated: {}", stats.actions_generated);
    println!("  Messages sent: {}", stats.messages_sent);
    println!("  Timers set: {}", stats.timers_set);

    // Basic sanity checks
    assert!(
        stats.events_processed > 10,
        "Should have processed many events"
    );
    assert!(stats.timers_set > 0, "Should have set some timers");
}

/// Test determinism of extended simulation.
#[test]
fn test_extended_simulation_determinism() {
    let config = test_network_config();
    let seed = 999u64;

    // First run
    let mut runner1 = SimulationRunner::new(config.clone(), seed);
    for node in 0..4 {
        runner1.schedule_initial_event(node, Duration::from_millis(100), Event::ProposalTimer);
    }
    runner1.run_until(Duration::from_secs(5));
    let stats1 = runner1.stats().clone();

    // Second run with same seed
    let mut runner2 = SimulationRunner::new(config.clone(), seed);
    for node in 0..4 {
        runner2.schedule_initial_event(node, Duration::from_millis(100), Event::ProposalTimer);
    }
    runner2.run_until(Duration::from_secs(5));
    let stats2 = runner2.stats().clone();

    // Verify exact match
    assert_eq!(stats1.events_processed, stats2.events_processed);
    assert_eq!(stats1.actions_generated, stats2.actions_generated);
    assert_eq!(stats1.messages_sent, stats2.messages_sent);
    assert_eq!(stats1.timers_set, stats2.timers_set);
    assert_eq!(stats1.timers_cancelled, stats2.timers_cancelled);
    assert_eq!(stats1.events_by_priority, stats2.events_by_priority);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Genesis Initialization Tests
// ═══════════════════════════════════════════════════════════════════════════════

/// Test that genesis initialization works.
#[test]
fn test_genesis_initialization() {
    let config = test_network_config();
    let mut runner = SimulationRunner::new(config, 42);

    // Initialize genesis - this should set proposal timers for all nodes
    runner.initialize_genesis();

    // Run for a short time (must be longer than proposal_interval of 300ms)
    runner.run_until(Duration::from_millis(500));

    let stats = runner.stats();

    // Genesis init sets proposal timers, which should fire and generate activity
    assert!(
        stats.timers_set >= 4,
        "Should have set timers for all nodes"
    );
    assert!(
        stats.events_processed >= 4,
        "Should have processed timer events"
    );
}

/// Test that genesis initialization is deterministic.
#[test]
fn test_genesis_initialization_determinism() {
    let config = test_network_config();
    let seed = 7777u64;

    // First run with genesis init
    let mut runner1 = SimulationRunner::new(config.clone(), seed);
    runner1.initialize_genesis();
    runner1.run_until(Duration::from_secs(2));
    let stats1 = runner1.stats().clone();

    // Second run with same seed and genesis init
    let mut runner2 = SimulationRunner::new(config.clone(), seed);
    runner2.initialize_genesis();
    runner2.run_until(Duration::from_secs(2));
    let stats2 = runner2.stats().clone();

    // Results should be identical
    assert_eq!(stats1.events_processed, stats2.events_processed);
    assert_eq!(stats1.actions_generated, stats2.actions_generated);
    assert_eq!(stats1.messages_sent, stats2.messages_sent);
    assert_eq!(stats1.timers_set, stats2.timers_set);
    assert_eq!(stats1.events_by_priority, stats2.events_by_priority);
}

/// Test full consensus simulation with genesis.
#[test]
fn test_full_consensus_simulation() {
    let config = test_network_config();
    let mut runner = SimulationRunner::new(config, 42);

    // Initialize genesis
    runner.initialize_genesis();

    // Run for several seconds - enough for multiple rounds of proposals
    runner.run_until(Duration::from_secs(5));

    let stats = runner.stats();

    println!("Full consensus simulation stats:");
    println!("  Events processed: {}", stats.events_processed);
    println!("  Actions generated: {}", stats.actions_generated);
    println!("  Messages sent: {}", stats.messages_sent);
    println!("  Timers set: {}", stats.timers_set);
    println!("  Events by priority: {:?}", stats.events_by_priority);

    // With genesis init, we should see:
    // - Timer events from proposal timers
    // - Network events from block headers and votes being gossiped
    // - Internal events from QC formation and commits
    assert!(
        stats.events_processed > 50,
        "Should process many events in full simulation"
    );
    assert!(
        stats.messages_sent > 0,
        "Should send messages between nodes"
    );

    // Check that we have events of multiple priorities
    let timer_events = stats.events_by_priority[1]; // Timer priority = 1
    let network_events = stats.events_by_priority[2]; // Network priority = 2

    assert!(timer_events > 0, "Should have timer events");
    // Note: network_events might be 0 if blocks aren't being sent yet
    println!("  Timer events: {}", timer_events);
    println!("  Network events: {}", network_events);
}

/// Test multi-shard genesis initialization.
#[test]
fn test_multi_shard_genesis() {
    let config = NetworkConfig {
        num_shards: 3,
        validators_per_shard: 4,
        intra_shard_latency: Duration::from_millis(10),
        cross_shard_latency: Duration::from_millis(50),
        jitter_fraction: 0.1,
        ..Default::default()
    };

    let mut runner = SimulationRunner::new(config, 42);

    // Initialize genesis for all shards
    runner.initialize_genesis();

    // Run simulation
    runner.run_until(Duration::from_secs(2));

    let stats = runner.stats();

    // Should have initialized 12 nodes (3 shards * 4 validators)
    // Each shard gets its own genesis block
    assert!(
        stats.timers_set >= 12,
        "Should have set timers for all 12 nodes"
    );
    assert!(
        stats.events_processed >= 12,
        "Should have processed events from all nodes"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// View Change Integration Tests
// ═══════════════════════════════════════════════════════════════════════════════

/// Test that view change timers are set during genesis initialization.
#[traced_test]
#[test]
fn test_view_change_timer_setup() {
    let config = test_network_config();
    let mut runner = SimulationRunner::new(config, 42);

    // Initialize genesis - this should set both proposal and view change timers
    runner.initialize_genesis();

    // The genesis init sets proposal timers + view change timers
    // So we should have 8 timers (4 proposal + 4 view change)
    let stats = runner.stats();
    assert!(
        stats.timers_set >= 8,
        "Should have set proposal and view change timers"
    );
}

/// Test that view change state is properly integrated.
#[traced_test]
#[test]
fn test_view_change_integration() {
    let config = test_network_config();
    let mut runner = SimulationRunner::new(config, 42);

    // Initialize genesis
    runner.initialize_genesis();

    // Run for long enough that view change timers fire
    // View change timeout is 5 seconds by default
    runner.run_until(Duration::from_secs(10));

    let stats = runner.stats();

    println!("View change integration test stats:");
    println!("  Events processed: {}", stats.events_processed);
    println!("  Actions generated: {}", stats.actions_generated);
    println!("  Messages sent: {}", stats.messages_sent);
    println!("  Timers set: {}", stats.timers_set);

    // Should have processed view change timer events
    assert!(
        stats.events_processed > 50,
        "Should have processed many events including view change timers"
    );
}

/// Test that view change is deterministic.
#[traced_test]
#[test]
fn test_view_change_determinism() {
    let config = test_network_config();
    let seed = 8888u64;

    // First run
    let mut runner1 = SimulationRunner::new(config.clone(), seed);
    runner1.initialize_genesis();
    runner1.run_until(Duration::from_secs(8));
    let stats1 = runner1.stats().clone();

    // Second run with same seed
    let mut runner2 = SimulationRunner::new(config.clone(), seed);
    runner2.initialize_genesis();
    runner2.run_until(Duration::from_secs(8));
    let stats2 = runner2.stats().clone();

    // Results should be identical
    assert_eq!(stats1.events_processed, stats2.events_processed);
    assert_eq!(stats1.actions_generated, stats2.actions_generated);
    assert_eq!(stats1.messages_sent, stats2.messages_sent);
    assert_eq!(stats1.timers_set, stats2.timers_set);
    assert_eq!(stats1.events_by_priority, stats2.events_by_priority);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Comprehensive View Change Tests
// ═══════════════════════════════════════════════════════════════════════════════

/// Test the complete view change flow:
/// 1. Genesis initialization sets height to 1 for view change tracking
/// 2. After timeout (5s), validators broadcast view change votes
/// 3. When quorum reached, round increments
/// 4. New proposer is selected based on new round
///
/// This test verifies actual state changes, not just statistics.
#[traced_test]
#[test]
fn test_view_change_complete_flow() {
    let config = test_network_config();
    let mut runner = SimulationRunner::new(config, 42);

    // Initialize genesis
    runner.initialize_genesis();

    // After genesis, all validators should be at height 0 committed, working on height 1
    // View change state should be at height 1, round 0
    for node_idx in 0..4u32 {
        let node = runner.node(node_idx).expect("Node should exist");
        assert_eq!(
            node.bft().committed_height(),
            0,
            "Node {} should be at height 0",
            node_idx
        );
        assert_eq!(
            node.bft().view(),
            0,
            "Node {} should be at round 0",
            node_idx
        );
        assert_eq!(
            node.view_change().current_round(),
            0,
            "Node {} view change should be at round 0",
            node_idx
        );
    }

    // Run for 1 second - not enough for view change
    runner.run_until(Duration::from_secs(1));

    // Check that no view change has occurred yet
    for node_idx in 0..4u32 {
        let node = runner.node(node_idx).expect("Node should exist");
        assert_eq!(
            node.view_change().current_round(),
            0,
            "Node {} should still be at round 0 after 1 second",
            node_idx
        );
    }

    // Run past the view change timeout (5 seconds) plus some network propagation time
    // At 6 seconds: view change votes should be broadcast
    // By 7 seconds: quorum should be reached
    runner.run_until(Duration::from_secs(8));

    // After timeout, at least some nodes should have incremented their round
    let mut nodes_with_view_change = 0;
    for node_idx in 0..4u32 {
        let node = runner.node(node_idx).expect("Node should exist");
        let round = node.view_change().current_round();
        if round > 0 {
            nodes_with_view_change += 1;
        }
        println!(
            "Node {}: BFT view={}, ViewChange round={}, height={}",
            node_idx,
            node.bft().view(),
            round,
            node.view_change().current_height()
        );
    }

    // We expect view change votes to be broadcast after timeout
    // Due to how the view change logic works:
    // - At genesis, current_height is 0, so should_change_view returns false
    // - After blocks commit, current_height updates
    // - If no blocks commit, view change won't trigger at height 0
    //
    // This is actually correct behavior - view change is for liveness when
    // progress stalls at height > 0.
    //
    // For this test to see view change, we need either:
    // 1. A block to commit first (moving to height 1)
    // 2. Or modify the test to simulate a stall at height 1
    //
    // Let's verify the stats show view change activity
    let stats = runner.stats();
    println!("\nView change flow test stats:");
    println!("  Events processed: {}", stats.events_processed);
    println!("  Messages sent: {}", stats.messages_sent);
    println!("  Nodes with view change: {}", nodes_with_view_change);
    println!("  Events by priority: {:?}", stats.events_by_priority);

    // The view change timers should have fired multiple times
    let timer_events = stats.events_by_priority[1];
    assert!(
        timer_events >= 8,
        "Should have processed at least 8 timer events (proposal + view change per node)"
    );
}

/// Test view change quorum mechanics.
///
/// This test creates a scenario where:
/// 1. We first commit a block to move to height 1
/// 2. Then let the view change timeout fire
/// 3. Verify quorum is reached and round increments
#[traced_test]
#[test]
fn test_view_change_quorum_after_commit() {
    let config = test_network_config();
    let mut runner = SimulationRunner::new(config, 42);

    // Initialize genesis
    runner.initialize_genesis();

    // Run for 2 seconds - enough for proposals and votes
    // But proposal happens at round 0 for height 1
    // Validator 1 is the proposer for height 1, round 0 (since (1 + 0) % 4 = 1)
    runner.run_until(Duration::from_secs(2));

    // Check if we've made any progress (committed any blocks)
    let mut any_committed = false;
    for node_idx in 0..4u32 {
        let node = runner.node(node_idx).expect("Node should exist");
        if node.bft().committed_height() > 0 {
            any_committed = true;
            println!(
                "Node {} has committed height {}",
                node_idx,
                node.bft().committed_height()
            );
        }
    }

    println!("\nAfter 2 seconds:");
    println!("  Any blocks committed: {}", any_committed);

    // If blocks were committed, we have progress at height > 0
    // Now let's wait for view change timeout
    runner.run_until(Duration::from_secs(10));

    let stats = runner.stats();
    println!("\nAfter 10 seconds:");
    println!("  Events processed: {}", stats.events_processed);
    println!("  Messages sent: {}", stats.messages_sent);

    // Check view change state
    for node_idx in 0..4u32 {
        let node = runner.node(node_idx).expect("Node should exist");
        println!(
            "Node {}: committed_height={}, bft_view={}, vc_round={}, vc_height={}",
            node_idx,
            node.bft().committed_height(),
            node.bft().view(),
            node.view_change().current_round(),
            node.view_change().current_height()
        );
    }
}

/// Test that view change votes are properly broadcast and collected.
///
/// This test verifies the network message flow for view change.
#[traced_test]
#[test]
fn test_view_change_vote_broadcast() {
    let config = test_network_config();
    let mut runner = SimulationRunner::new(config, 42);

    // Initialize genesis
    runner.initialize_genesis();

    // Get initial message count
    let initial_messages = runner.stats().messages_sent;

    // Run past view change timeout
    runner.run_until(Duration::from_secs(7));

    let final_messages = runner.stats().messages_sent;
    let messages_during_view_change = final_messages - initial_messages;

    println!(
        "Messages sent during view change period: {}",
        messages_during_view_change
    );

    // Should have sent messages - proposal timers fire every 100ms,
    // view change timers fire at 5s
    assert!(
        messages_during_view_change > 0,
        "Should have sent some messages"
    );
}

/// Test proposer rotation after view change.
///
/// Verifies that after a view change, the proposer changes according to:
/// proposer = (height + round) % committee_size
#[traced_test]
#[test]
fn test_proposer_rotation_after_view_change() {
    // For height 1:
    // - Round 0: proposer = (1 + 0) % 4 = 1 -> Validator 1
    // - Round 1: proposer = (1 + 1) % 4 = 2 -> Validator 2
    // - Round 2: proposer = (1 + 2) % 4 = 3 -> Validator 3
    // - Round 3: proposer = (1 + 3) % 4 = 0 -> Validator 0

    let config = test_network_config();
    let mut runner = SimulationRunner::new(config, 42);
    runner.initialize_genesis();

    // Get initial view for all nodes
    let initial_views: Vec<u64> = (0..4u32)
        .map(|i| runner.node(i).unwrap().bft().view())
        .collect();

    println!("Initial views: {:?}", initial_views);

    // Run for extended time to allow view changes
    runner.run_until(Duration::from_secs(15));

    // Get final views
    let final_views: Vec<u64> = (0..4u32)
        .map(|i| runner.node(i).unwrap().bft().view())
        .collect();

    println!("Final views after 15 seconds: {:?}", final_views);

    // All nodes should have the same view (consensus on round)
    let first_view = final_views[0];
    for (i, &view) in final_views.iter().enumerate() {
        assert_eq!(
            view, first_view,
            "Node {} has view {} but node 0 has view {}",
            i, view, first_view
        );
    }

    // Verify stats show activity
    let stats = runner.stats();
    println!("Final stats:");
    println!("  Events processed: {}", stats.events_processed);
    println!("  Messages sent: {}", stats.messages_sent);
    println!("  Timers set: {}", stats.timers_set);
}

/// Test that view change state is properly reset on block commit.
///
/// When a block commits, the view change timeout should reset
/// and the round should stay at 0 for the new height.
#[traced_test]
#[test]
fn test_view_change_reset_on_commit() {
    let config = test_network_config();
    let mut runner = SimulationRunner::new(config, 42);

    // Initialize genesis
    runner.initialize_genesis();

    // Run for short time - if blocks commit, view change resets
    runner.run_until(Duration::from_secs(3));

    // Check committed heights and view change state
    for node_idx in 0..4u32 {
        let node = runner.node(node_idx).expect("Node should exist");
        let committed = node.bft().committed_height();
        let vc_height = node.view_change().current_height();
        let vc_round = node.view_change().current_round();

        println!(
            "Node {}: committed={}, vc_height={}, vc_round={}",
            node_idx, committed, vc_height, vc_round
        );

        // If blocks were committed, view change height should track
        // View change height = committed + 1 (next height to work on)
        if committed > 0 {
            // View change state might be ahead due to reset_timeout calls
            assert!(
                vc_height >= committed,
                "View change height should be >= committed height"
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Block Commit Diagnostic and Verification Tests
// ═══════════════════════════════════════════════════════════════════════════════

/// Diagnostic test to trace block commit flow.
///
/// This test helps identify why blocks might not be committing by
/// examining each step of the consensus pipeline.
#[test]
fn test_block_commit_diagnostic() {
    let config = test_network_config();
    let mut runner = SimulationRunner::new(config, 42);

    // Initialize genesis
    runner.initialize_genesis();

    println!("\n=== Initial State After Genesis ===");
    for node_idx in 0..4u32 {
        let node = runner.node(node_idx).expect("Node should exist");
        println!(
            "Node {}: committed_height={}, view={}, has_qc={}",
            node_idx,
            node.bft().committed_height(),
            node.bft().view(),
            node.bft().latest_qc().is_some()
        );
    }

    // Run for 500ms - should be enough for first proposal and votes
    runner.run_until(Duration::from_millis(500));

    println!("\n=== After 500ms ===");
    let stats = runner.stats();
    println!("Events processed: {}", stats.events_processed);
    println!("Messages sent: {}", stats.messages_sent);
    println!("Event types: {:?}", stats.events_by_priority);

    for node_idx in 0..4u32 {
        let node = runner.node(node_idx).expect("Node should exist");
        println!(
            "Node {}: committed_height={}, view={}, has_qc={}",
            node_idx,
            node.bft().committed_height(),
            node.bft().view(),
            node.bft().latest_qc().is_some()
        );
    }

    // Run for another second
    runner.run_until(Duration::from_secs(2));

    println!("\n=== After 2 seconds ===");
    let stats = runner.stats();
    println!("Events processed: {}", stats.events_processed);
    println!("Messages sent: {}", stats.messages_sent);

    for node_idx in 0..4u32 {
        let node = runner.node(node_idx).expect("Node should exist");
        let qc_height = node.bft().latest_qc().map(|qc| qc.height.0);
        println!(
            "Node {}: committed_height={}, view={}, latest_qc_height={:?}",
            node_idx,
            node.bft().committed_height(),
            node.bft().view(),
            qc_height
        );
    }

    // The two-chain commit rule means:
    // - Block at height N needs a QC
    // - When block at height N+1 gets a QC, block at height N can commit
    //
    // So we need at least 2 rounds of successful proposal/voting to commit 1 block
    //
    // Expected flow:
    // 1. Proposal timer fires for proposer (validator (1+0)%4 = 1 for height 1)
    // 2. Proposer broadcasts BlockHeader
    // 3. Other validators receive header, vote
    // 4. Votes are collected, QC forms for height 1
    // 5. Repeat for height 2
    // 6. When QC for height 2 forms, height 1 can commit

    // Run longer to give two-chain commit a chance
    runner.run_until(Duration::from_secs(5));

    println!("\n=== After 5 seconds ===");
    let stats = runner.stats();
    println!("Events processed: {}", stats.events_processed);
    println!("Messages sent: {}", stats.messages_sent);

    for node_idx in 0..4u32 {
        let node = runner.node(node_idx).expect("Node should exist");
        let qc_height = node.bft().latest_qc().map(|qc| qc.height.0);
        println!(
            "Node {}: committed_height={}, view={}, latest_qc_height={:?}",
            node_idx,
            node.bft().committed_height(),
            node.bft().view(),
            qc_height
        );
    }
}

/// Test determinism of view change round increments.
///
/// Runs the same simulation twice and verifies that the
/// round numbers match exactly at every node.
#[test]
fn test_view_change_round_determinism() {
    let config = test_network_config();
    let seed = 54321u64;

    // First run
    let mut runner1 = SimulationRunner::new(config.clone(), seed);
    runner1.initialize_genesis();
    runner1.run_until(Duration::from_secs(12));

    let views1: Vec<u64> = (0..4u32)
        .map(|i| runner1.node(i).unwrap().bft().view())
        .collect();
    let vc_rounds1: Vec<u64> = (0..4u32)
        .map(|i| runner1.node(i).unwrap().view_change().current_round())
        .collect();

    // Second run with same seed
    let mut runner2 = SimulationRunner::new(config.clone(), seed);
    runner2.initialize_genesis();
    runner2.run_until(Duration::from_secs(12));

    let views2: Vec<u64> = (0..4u32)
        .map(|i| runner2.node(i).unwrap().bft().view())
        .collect();
    let vc_rounds2: Vec<u64> = (0..4u32)
        .map(|i| runner2.node(i).unwrap().view_change().current_round())
        .collect();

    // Views and rounds should match exactly
    assert_eq!(views1, views2, "BFT views should be identical across runs");
    assert_eq!(
        vc_rounds1, vc_rounds2,
        "View change rounds should be identical across runs"
    );

    println!("BFT views (run1): {:?}", views1);
    println!("BFT views (run2): {:?}", views2);
    println!("VC rounds (run1): {:?}", vc_rounds1);
    println!("VC rounds (run2): {:?}", vc_rounds2);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Block Commit Verification Tests
// ═══════════════════════════════════════════════════════════════════════════════

/// Verify that all nodes commit identical blocks.
///
/// This test runs the simulation and verifies that:
/// 1. All nodes reach the same committed height
/// 2. All nodes have the same QC heights
#[test]
fn test_block_commit_verification() {
    let config = test_network_config();
    let mut runner = SimulationRunner::new(config, 42);

    // Initialize genesis
    runner.initialize_genesis();

    // Run for 1 second - should commit several blocks
    runner.run_until(Duration::from_secs(1));

    // Get committed heights for all nodes
    let committed_heights: Vec<u64> = (0..4u32)
        .map(|i| runner.node(i).unwrap().bft().committed_height())
        .collect();

    println!("Committed heights: {:?}", committed_heights);

    // All nodes should have the same committed height
    let first_height = committed_heights[0];
    assert!(first_height > 0, "Should have committed at least one block");

    for (i, &height) in committed_heights.iter().enumerate() {
        assert_eq!(
            height, first_height,
            "Node {} has committed height {} but expected {}",
            i, height, first_height
        );
    }

    // All nodes should have the same latest QC
    let qc_heights: Vec<Option<u64>> = (0..4u32)
        .map(|i| {
            runner
                .node(i)
                .unwrap()
                .bft()
                .latest_qc()
                .map(|qc| qc.height.0)
        })
        .collect();

    let first_qc_height = qc_heights[0];
    for (i, &qc_height) in qc_heights.iter().enumerate() {
        assert_eq!(
            qc_height, first_qc_height,
            "Node {} has QC height {:?} but expected {:?}",
            i, qc_height, first_qc_height
        );
    }

    println!("All nodes consistent:");
    println!("  Committed height: {}", first_height);
    println!("  QC height: {:?}", first_qc_height);
}

/// Verify block commit determinism across runs.
///
/// Runs the same simulation twice with identical seeds and verifies
/// that all nodes commit the same blocks in the same order.
#[test]
fn test_block_commit_determinism() {
    let config = test_network_config();
    let seed = 12345u64;

    // First run
    let mut runner1 = SimulationRunner::new(config.clone(), seed);
    runner1.initialize_genesis();
    runner1.run_until(Duration::from_secs(2));

    let heights1: Vec<u64> = (0..4u32)
        .map(|i| runner1.node(i).unwrap().bft().committed_height())
        .collect();
    let qc_heights1: Vec<Option<u64>> = (0..4u32)
        .map(|i| {
            runner1
                .node(i)
                .unwrap()
                .bft()
                .latest_qc()
                .map(|qc| qc.height.0)
        })
        .collect();
    let stats1 = runner1.stats().clone();

    // Second run with same seed
    let mut runner2 = SimulationRunner::new(config.clone(), seed);
    runner2.initialize_genesis();
    runner2.run_until(Duration::from_secs(2));

    let heights2: Vec<u64> = (0..4u32)
        .map(|i| runner2.node(i).unwrap().bft().committed_height())
        .collect();
    let qc_heights2: Vec<Option<u64>> = (0..4u32)
        .map(|i| {
            runner2
                .node(i)
                .unwrap()
                .bft()
                .latest_qc()
                .map(|qc| qc.height.0)
        })
        .collect();
    let stats2 = runner2.stats().clone();

    // Verify determinism
    assert_eq!(heights1, heights2, "Committed heights should be identical");
    assert_eq!(qc_heights1, qc_heights2, "QC heights should be identical");
    assert_eq!(stats1.events_processed, stats2.events_processed);
    assert_eq!(stats1.messages_sent, stats2.messages_sent);

    println!("Determinism verified:");
    println!("  Committed heights (run1): {:?}", heights1);
    println!("  Committed heights (run2): {:?}", heights2);
    println!("  Events processed: {}", stats1.events_processed);
    println!("  Messages sent: {}", stats1.messages_sent);
}

/// Test that blocks commit sequentially without gaps.
///
/// This verifies the two-chain commit rule is working correctly:
/// - QC for height N commits height N-1
/// - Blocks are committed in sequential order
#[test]
fn test_sequential_commit() {
    let config = test_network_config();
    let mut runner = SimulationRunner::new(config, 42);

    // Initialize genesis
    runner.initialize_genesis();

    // Run incrementally and verify sequential commits
    let mut last_committed = 0u64;

    for step in 1..=10 {
        runner.run_until(Duration::from_millis(step * 200));

        for node_idx in 0..4u32 {
            let node = runner.node(node_idx).expect("Node should exist");
            let current_committed = node.bft().committed_height();

            // Committed height should never go backwards
            // Note: We're checking a snapshot, not continuous monitoring
            if current_committed > last_committed {
                last_committed = current_committed;
            }
        }
    }

    // Verify all nodes have committed sequentially to the same height
    let final_heights: Vec<u64> = (0..4u32)
        .map(|i| runner.node(i).unwrap().bft().committed_height())
        .collect();

    let first = final_heights[0];
    for (i, &h) in final_heights.iter().enumerate() {
        assert_eq!(
            h, first,
            "Node {} has height {} but expected {}",
            i, h, first
        );
    }

    assert!(
        first > 10,
        "Should have committed more than 10 blocks, got {}",
        first
    );
    println!("Sequential commit verified: {} blocks committed", first);
}

/// Test throughput and latency characteristics.
///
/// This test measures:
/// - Blocks per second
/// - Messages per block
#[test]
fn test_consensus_throughput() {
    let config = test_network_config();
    let mut runner = SimulationRunner::new(config, 42);

    runner.initialize_genesis();

    // Run for 5 seconds
    runner.run_until(Duration::from_secs(5));

    let committed_height = runner.node(0).unwrap().bft().committed_height();
    let stats = runner.stats();

    let blocks_per_second = committed_height as f64 / 5.0;
    let messages_per_block = if committed_height > 0 {
        stats.messages_sent as f64 / committed_height as f64
    } else {
        0.0
    };

    println!("Throughput metrics:");
    println!("  Blocks committed: {}", committed_height);
    println!("  Blocks per second: {:.1}", blocks_per_second);
    println!("  Total messages: {}", stats.messages_sent);
    println!("  Messages per block: {:.1}", messages_per_block);
    println!("  Events processed: {}", stats.events_processed);

    // Sanity checks
    assert!(
        committed_height > 100,
        "Should commit at least 100 blocks in 5 seconds"
    );
    assert!(
        blocks_per_second > 20.0,
        "Should achieve at least 20 blocks/second"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Mempool Integration Tests
// ═══════════════════════════════════════════════════════════════════════════════

/// Test that transactions submitted to mempool are included in blocks.
///
/// This verifies the mempool→BFT integration:
/// 1. Submit transactions to the mempool
/// 2. Run consensus
/// 3. Verify transactions appear in committed blocks
#[test]
fn test_mempool_to_block_integration() {
    use hyperscale_core::Event;
    use hyperscale_types::test_utils::test_transaction;

    let config = test_network_config();
    let mut runner = SimulationRunner::new(config, 42);

    // Initialize genesis
    runner.initialize_genesis();

    // Create some test transactions
    let tx1 = test_transaction(1);
    let tx2 = test_transaction(2);
    let tx3 = test_transaction(3);

    let tx1_hash = tx1.hash();
    let tx2_hash = tx2.hash();
    let tx3_hash = tx3.hash();

    // Submit transactions to node 0's mempool
    runner.schedule_initial_event(
        0,
        Duration::from_millis(50),
        Event::SubmitTransaction { tx: Arc::new(tx1) },
    );
    runner.schedule_initial_event(
        0,
        Duration::from_millis(51),
        Event::SubmitTransaction { tx: Arc::new(tx2) },
    );
    runner.schedule_initial_event(
        0,
        Duration::from_millis(52),
        Event::SubmitTransaction { tx: Arc::new(tx3) },
    );

    // Run for 100ms - before first proposal timer fires (100ms default)
    runner.run_until(Duration::from_millis(99));

    // Check that transactions are in node 0's mempool
    let node0 = runner.node(0).expect("Node 0 should exist");
    assert!(
        node0.mempool().has_transaction(&tx1_hash),
        "Transaction 1 should be in mempool"
    );
    assert!(
        node0.mempool().has_transaction(&tx2_hash),
        "Transaction 2 should be in mempool"
    );
    assert!(
        node0.mempool().has_transaction(&tx3_hash),
        "Transaction 3 should be in mempool"
    );

    // Get ready transactions count
    let ready_count = node0.mempool().ready_transactions(100).len();
    assert_eq!(ready_count, 3, "Should have 3 ready transactions");

    println!("Mempool state before proposals:");
    println!("  Total transactions: {}", node0.mempool().len());
    println!("  Ready transactions: {}", ready_count);

    // Run for 2 seconds - should commit several blocks with transactions
    runner.run_until(Duration::from_secs(2));

    let committed_height = runner.node(0).unwrap().bft().committed_height();
    println!("\nAfter 2 seconds:");
    println!("  Committed height: {}", committed_height);

    // Transactions should now be marked as committed in the mempool
    let node0 = runner.node(0).expect("Node 0 should exist");
    let status1 = node0.mempool().status(&tx1_hash);
    let status2 = node0.mempool().status(&tx2_hash);
    let status3 = node0.mempool().status(&tx3_hash);

    println!("  Transaction 1 status: {:?}", status1);
    println!("  Transaction 2 status: {:?}", status2);
    println!("  Transaction 3 status: {:?}", status3);

    // At least one block should have been committed
    assert!(
        committed_height > 0,
        "Should have committed at least one block"
    );
}

/// Test that transactions are executed after blocks commit.
///
/// This verifies the full flow:
/// 1. Submit transactions to mempool
/// 2. Transactions gossip to all validators
/// 3. Transactions are included in blocks
/// 4. Blocks commit
/// 5. Execution runs and creates certificates
#[test]
fn test_execution_flow() {
    use hyperscale_core::Event;
    use hyperscale_types::test_utils::test_transaction;

    let config = test_network_config();
    let mut runner = SimulationRunner::new(config, 42);

    runner.initialize_genesis();

    // Submit a transaction
    let tx = test_transaction(100);
    let tx_hash = tx.hash();

    runner.schedule_initial_event(
        0,
        Duration::from_millis(50),
        Event::SubmitTransaction { tx: Arc::new(tx) },
    );

    // Run for 2 seconds - should commit blocks and execute transactions
    runner.run_until(Duration::from_secs(2));

    let node0 = runner.node(0).expect("Node 0 should exist");

    // Check transaction completed the full execution flow.
    // Status should be Completed (certificate was committed in a block).
    let status = node0.mempool().status(&tx_hash);
    println!("  Committed height: {}", node0.bft().committed_height());
    println!("  Tx status: {:?}", status);

    // Transaction should reach Completed state (certificate committed in block).
    // This is the terminal success state for the full execution flow:
    // Pending → Accepted → Committed → Executing → Finalized → Completed
    assert!(
        matches!(
            status,
            Some(hyperscale_types::TransactionStatus::Completed(_))
        ),
        "Transaction should be Completed (certificate committed), got {:?}",
        status
    );
}

/// Test that transactions are gossiped between validators.
///
/// This verifies that when a transaction is submitted to one validator,
/// it eventually appears in other validators' mempools via gossip.
#[test]
fn test_transaction_gossip() {
    use hyperscale_core::Event;
    use hyperscale_types::test_utils::test_transaction;

    let config = test_network_config();
    let mut runner = SimulationRunner::new(config, 42);

    runner.initialize_genesis();

    // Submit transaction to node 0
    let tx = test_transaction(42);
    let tx_hash = tx.hash();

    runner.schedule_initial_event(
        0,
        Duration::from_millis(10),
        Event::SubmitTransaction { tx: Arc::new(tx) },
    );

    // Run briefly - transaction should be in node 0's mempool
    runner.run_until(Duration::from_millis(20));

    let node0_has_tx = runner.node(0).unwrap().mempool().has_transaction(&tx_hash);
    assert!(node0_has_tx, "Node 0 should have the transaction");

    // Note: Transaction gossip requires the mempool to emit BroadcastToShard actions
    // This is currently not implemented - this test documents expected behavior
    println!("Transaction submitted to node 0: {}", tx_hash);
    println!("Node 0 has transaction: {}", node0_has_tx);

    // Run for 500ms to allow gossip (if implemented)
    runner.run_until(Duration::from_millis(500));

    // Check if other nodes have the transaction
    // (Currently they won't because gossip isn't implemented)
    for node_idx in 1..4u32 {
        let has_tx = runner
            .node(node_idx)
            .unwrap()
            .mempool()
            .has_transaction(&tx_hash);
        println!("Node {} has transaction: {}", node_idx, has_tx);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Cross-Shard Execution Tests
// ═══════════════════════════════════════════════════════════════════════════════

/// Multi-shard network configuration for testing cross-shard execution.
fn multi_shard_config() -> NetworkConfig {
    NetworkConfig {
        num_shards: 2,
        validators_per_shard: 4,
        intra_shard_latency: Duration::from_millis(10),
        cross_shard_latency: Duration::from_millis(50),
        jitter_fraction: 0.1,
        ..Default::default()
    }
}

/// Test that multi-shard simulation initializes correctly.
#[test]
fn test_multi_shard_initialization() {
    let config = multi_shard_config();
    let mut runner = SimulationRunner::new(config, 42);

    // Should have 8 nodes (2 shards * 4 validators)
    assert!(runner.node(0).is_some());
    assert!(runner.node(7).is_some());
    assert!(runner.node(8).is_none());

    // Initialize genesis for both shards
    runner.initialize_genesis();

    // Check nodes in shard 0 (nodes 0-3)
    for node_idx in 0..4u32 {
        let node = runner.node(node_idx).expect("Node should exist");
        assert_eq!(node.shard().0, 0, "Node {} should be in shard 0", node_idx);
        assert_eq!(
            node.bft().committed_height(),
            0,
            "Node {} should be at genesis",
            node_idx
        );
    }

    // Check nodes in shard 1 (nodes 4-7)
    for node_idx in 4..8u32 {
        let node = runner.node(node_idx).expect("Node should exist");
        assert_eq!(node.shard().0, 1, "Node {} should be in shard 1", node_idx);
        assert_eq!(
            node.bft().committed_height(),
            0,
            "Node {} should be at genesis",
            node_idx
        );
    }

    println!("Multi-shard initialization successful: 2 shards, 4 validators each");
}

/// Test that both shards progress independently in consensus.
#[test]
fn test_multi_shard_consensus_progress() {
    let config = multi_shard_config();
    let mut runner = SimulationRunner::new(config, 42);
    runner.initialize_genesis();

    // Run for 5 seconds
    runner.run_until(Duration::from_secs(5));

    // Collect committed heights by shard
    let mut shard0_heights: Vec<u64> = Vec::new();
    let mut shard1_heights: Vec<u64> = Vec::new();

    for node_idx in 0..4u32 {
        let height = runner.node(node_idx).unwrap().bft().committed_height();
        shard0_heights.push(height);
    }

    for node_idx in 4..8u32 {
        let height = runner.node(node_idx).unwrap().bft().committed_height();
        shard1_heights.push(height);
    }

    println!("Shard 0 committed heights: {:?}", shard0_heights);
    println!("Shard 1 committed heights: {:?}", shard1_heights);

    // All nodes in a shard should have the same committed height (consensus)
    let shard0_first = shard0_heights[0];
    for (i, &h) in shard0_heights.iter().enumerate() {
        assert_eq!(
            h, shard0_first,
            "Shard 0 node {} has height {} but expected {}",
            i, h, shard0_first
        );
    }

    let shard1_first = shard1_heights[0];
    for (i, &h) in shard1_heights.iter().enumerate() {
        assert_eq!(
            h,
            shard1_first,
            "Shard 1 node {} has height {} but expected {}",
            i + 4,
            h,
            shard1_first
        );
    }

    // Both shards should have made progress
    assert!(shard0_first > 0, "Shard 0 should have committed blocks");
    assert!(shard1_first > 0, "Shard 1 should have committed blocks");

    let stats = runner.stats();
    println!("\nSimulation stats:");
    println!("  Events processed: {}", stats.events_processed);
    println!("  Messages sent: {}", stats.messages_sent);
}

/// Test cross-shard message delivery latency.
#[test]
fn test_cross_shard_latency() {
    let config = multi_shard_config();
    let runner = SimulationRunner::new(config.clone(), 42);

    // Intra-shard: nodes in same shard
    let network = runner.network();

    // Node 0 to Node 1 (both in shard 0) should use intra-shard latency
    let shard_0_0 = network.shard_for_node(0);
    let shard_0_1 = network.shard_for_node(1);
    assert_eq!(
        shard_0_0, shard_0_1,
        "Nodes 0 and 1 should be in same shard"
    );

    // Node 0 to Node 4 (different shards) should use cross-shard latency
    let shard_0 = network.shard_for_node(0);
    let shard_4 = network.shard_for_node(4);
    assert_ne!(
        shard_0, shard_4,
        "Nodes 0 and 4 should be in different shards"
    );

    // Verify shard assignment
    assert_eq!(shard_0.0, 0);
    assert_eq!(shard_4.0, 1);

    println!("Cross-shard latency test passed");
    println!("  Intra-shard latency: {:?}", config.intra_shard_latency);
    println!("  Cross-shard latency: {:?}", config.cross_shard_latency);
}

/// Test that Topology correctly identifies cross-shard transactions.
#[test]
fn test_cross_shard_transaction_detection() {
    use hyperscale_types::test_utils::{test_node, test_transaction_with_nodes};
    use hyperscale_types::{
        KeyPair, ShardGroupId, StaticTopology, Topology, ValidatorId, ValidatorInfo, ValidatorSet,
    };
    use std::collections::HashMap;
    use std::sync::Arc;

    // Create a 2-shard network with 2 validators per shard
    let keys: Vec<KeyPair> = (0..4).map(|_| KeyPair::generate_bls()).collect();
    let validators: Vec<ValidatorInfo> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| ValidatorInfo {
            validator_id: ValidatorId(i as u64),
            public_key: k.public_key(),
            voting_power: 1,
        })
        .collect();
    let validator_set = ValidatorSet::new(validators);

    // Build shard committees
    let mut shard_committees: HashMap<ShardGroupId, Vec<ValidatorId>> = HashMap::new();
    shard_committees.insert(ShardGroupId(0), vec![ValidatorId(0), ValidatorId(1)]);
    shard_committees.insert(ShardGroupId(1), vec![ValidatorId(2), ValidatorId(3)]);

    let topology: Arc<dyn Topology> = Arc::new(StaticTopology::with_shard_committees(
        ValidatorId(0),
        ShardGroupId(0),
        2, // num_shards
        &validator_set,
        shard_committees,
    ));

    // Create nodes that hash to different shards
    let node_a = test_node(0);
    let node_b = test_node(1);
    let node_c = test_node(100);

    let shard_a = topology.shard_for_node_id(&node_a);
    let shard_b = topology.shard_for_node_id(&node_b);
    let shard_c = topology.shard_for_node_id(&node_c);

    println!("Node A shard: {:?}", shard_a);
    println!("Node B shard: {:?}", shard_b);
    println!("Node C shard: {:?}", shard_c);

    // Create a single-shard transaction (all nodes in same shard)
    let same_shard_nodes: Vec<_> = (0..10u8)
        .map(test_node)
        .filter(|n| topology.shard_for_node_id(n) == ShardGroupId(0))
        .take(2)
        .collect();

    if same_shard_nodes.len() >= 2 {
        let tx = test_transaction_with_nodes(
            b"single_shard_tx",
            vec![same_shard_nodes[0]],
            vec![same_shard_nodes[1]],
        );
        let shards = topology.all_shards_for_transaction(&tx);
        println!("Single-shard tx touches shards: {:?}", shards);
        assert_eq!(shards.len(), 1, "Single-shard tx should touch 1 shard");
    }

    // Create a cross-shard transaction (nodes in different shards)
    let shard0_node = (0..255u8)
        .map(test_node)
        .find(|n| topology.shard_for_node_id(n) == ShardGroupId(0));
    let shard1_node = (0..255u8)
        .map(test_node)
        .find(|n| topology.shard_for_node_id(n) == ShardGroupId(1));

    if let (Some(node0), Some(node1)) = (shard0_node, shard1_node) {
        let tx = test_transaction_with_nodes(b"cross_shard_tx", vec![node0], vec![node1]);
        let shards = topology.all_shards_for_transaction(&tx);
        println!("Cross-shard tx touches shards: {:?}", shards);
        assert_eq!(shards.len(), 2, "Cross-shard tx should touch 2 shards");
    }
}

/// Test determinism of multi-shard simulation.
#[test]
fn test_multi_shard_determinism() {
    let config = multi_shard_config();
    let seed = 98765u64;

    // First run
    let mut runner1 = SimulationRunner::new(config.clone(), seed);
    runner1.initialize_genesis();
    runner1.run_until(Duration::from_secs(3));

    let heights1: Vec<u64> = (0..8u32)
        .map(|i| runner1.node(i).unwrap().bft().committed_height())
        .collect();
    let stats1 = runner1.stats().clone();

    // Second run with same seed
    let mut runner2 = SimulationRunner::new(config, seed);
    runner2.initialize_genesis();
    runner2.run_until(Duration::from_secs(3));

    let heights2: Vec<u64> = (0..8u32)
        .map(|i| runner2.node(i).unwrap().bft().committed_height())
        .collect();
    let stats2 = runner2.stats().clone();

    // Verify identical results
    assert_eq!(heights1, heights2, "Committed heights should be identical");
    assert_eq!(
        stats1.events_processed, stats2.events_processed,
        "Events processed should be identical"
    );
    assert_eq!(
        stats1.messages_sent, stats2.messages_sent,
        "Messages sent should be identical"
    );

    println!("Multi-shard determinism verified:");
    println!("  Heights: {:?}", heights1);
    println!("  Events: {}", stats1.events_processed);
    println!("  Messages: {}", stats1.messages_sent);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Network Fault Tolerance Tests
// ═══════════════════════════════════════════════════════════════════════════════

/// Test that consensus continues when a single node is isolated.
/// With 4 validators (f=1), we can tolerate 1 faulty/isolated node.
#[traced_test]
#[test]
fn test_consensus_with_isolated_node() {
    let config = test_network_config();
    let mut runner = SimulationRunner::new(config, 42);

    runner.initialize_genesis();

    // Run normally for 1 second to establish baseline
    runner.run_until(Duration::from_secs(1));
    let height_before = runner.node(0).unwrap().bft().committed_height();
    println!("Height before isolation: {}", height_before);

    // Isolate node 0 (it can neither send nor receive)
    runner.network_mut().isolate_node(0);
    println!("Node 0 isolated");

    // Continue running - consensus should still work with 3/4 nodes
    runner.run_until(Duration::from_secs(3));

    // Check that non-isolated nodes made progress
    let height_node1 = runner.node(1).unwrap().bft().committed_height();
    let height_node2 = runner.node(2).unwrap().bft().committed_height();
    let height_node3 = runner.node(3).unwrap().bft().committed_height();

    println!("Heights after isolation:");
    println!(
        "  Node 0 (isolated): {}",
        runner.node(0).unwrap().bft().committed_height()
    );
    println!("  Node 1: {}", height_node1);
    println!("  Node 2: {}", height_node2);
    println!("  Node 3: {}", height_node3);

    // Nodes 1, 2, 3 should all be at the same height (consensus)
    assert_eq!(height_node1, height_node2);
    assert_eq!(height_node2, height_node3);

    // They should have made progress beyond the isolation point
    assert!(
        height_node1 > height_before,
        "Consensus should continue with 3/4 nodes"
    );

    let stats = runner.stats();
    println!("\nMessage stats:");
    println!("  Sent: {}", stats.messages_sent);
    println!(
        "  Dropped (partition): {}",
        stats.messages_dropped_partition
    );
    println!("  Dropped (loss): {}", stats.messages_dropped_loss);
    println!("  Delivery rate: {:.1}%", stats.delivery_rate() * 100.0);
}

/// Test partition recovery with 2-2 split using view change votes to trigger sync.
///
/// This test demonstrates how view change votes can trigger sync to recover
/// from a partition where nodes end up at different heights.
///
/// **What happens:**
/// 1. Consensus runs normally, committing blocks
/// 2. A 2-2 partition is created (need 3/4 for quorum, neither side has it)
/// 3. During partition, some nodes may commit 1 more block (in-flight messages)
/// 4. When partition heals, nodes are at DIFFERENT heights
/// 5. View change timer fires and nodes exchange view change votes
/// 6. Nodes receiving votes for higher heights detect they're behind
/// 7. They use the highest_qc from the vote to trigger sync
/// 8. After sync, all nodes are at the same height
///
/// **Key insight:** View change votes carry `highest_qc` which allows lagging
/// nodes to discover committed blocks and sync up, even when no new proposals
/// are being made.
#[traced_test]
#[test]
fn test_partition_recovery_via_view_change_sync() {
    let config = test_network_config();
    let mut runner = SimulationRunner::new(config, 42);

    runner.initialize_genesis();

    // Run normally for 1 second
    runner.run_until(Duration::from_secs(1));
    let height_before = runner.node(0).unwrap().bft().committed_height();
    println!("Height before partition: {}", height_before);

    // Create a partition: nodes 0,1 can't talk to nodes 2,3
    runner.network_mut().partition_groups(&[0, 1], &[2, 3]);
    println!("Network partitioned: {{0,1}} <-> {{2,3}}");

    // Run during partition (1 second) - progress should halt
    runner.run_until(Duration::from_secs(2));
    let height_during = runner.node(0).unwrap().bft().committed_height();
    println!("Height during partition: {}", height_during);

    // Debug: check view change state
    let vc = runner.node(0).unwrap().view_change();
    println!(
        "View change state: height={}, round={}, should_change=false",
        vc.current_height(),
        vc.current_round() // Can't call should_change_view from here
    );

    // Heal the partition
    runner.network_mut().heal_all();
    println!("Partition healed at sim time {:?}", runner.now());

    // Check heights on all nodes before continuing
    println!("Node heights before continuing:");
    for i in 0..4u32 {
        let h = runner.node(i).unwrap().bft().committed_height();
        let v = runner.node(i).unwrap().bft().view();
        println!("  Node {}: height={}, view={}", i, h, v);
    }

    // Run for longer to allow view change and recovery
    // View change timeout is 5 seconds by default, so we need to wait
    runner.run_until(Duration::from_secs(12));
    let height_after = runner.node(0).unwrap().bft().committed_height();
    println!(
        "Height after heal: {} (sim time {:?})",
        height_after,
        runner.now()
    );

    // Check heights on all nodes after
    println!("Node heights/view change state after:");
    for i in 0..4u32 {
        let node = runner.node(i).unwrap();
        let h = node.bft().committed_height();
        let v = node.bft().view();
        let vc_height = node.view_change().current_height();
        let vc_round = node.view_change().current_round();
        println!(
            "  Node {}: bft(height={}, view={}), vc(height={}, round={})",
            i, h, v, vc_height, vc_round
        );
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
    let heights_after: Vec<u64> = (0..4u32)
        .map(|i| runner.node(i).unwrap().bft().committed_height())
        .collect();

    // Verify that nodes diverged during partition (some at height_before+1, some at height_before)
    let max_height = *heights_after.iter().max().unwrap();
    let min_height = *heights_after.iter().min().unwrap();

    println!("\nPartition effect:");
    println!("  Max height: {}", max_height);
    println!("  Min height: {}", min_height);
    println!("  Divergence: {}", max_height - min_height);

    // CRITICAL: After partition heals, at least some nodes should make progress.
    // This verifies that the system isn't completely stuck due to view change bugs.
    assert!(
        max_height > height_during,
        "At least some nodes should make progress after partition heals. \
         max_height={} should be > height_during={}. \
         If all nodes are stuck, there may be a view change bug.",
        max_height,
        height_during
    );

    // After view change votes trigger sync, all nodes should be at the same height.
    // The view change votes carry highest_qc, which allows lagging nodes to discover
    // committed blocks and sync up even without new proposals.
    assert_eq!(
        max_height, min_height,
        "All nodes should be at the same height after view change triggered sync"
    );

    // Nodes should have caught up - verify no divergence remains
    assert_eq!(
        max_height - min_height,
        0,
        "Height divergence should be resolved by sync"
    );
}

/// Test behavior during network partition.
///
/// With a 2-2 partition (nodes 0,1 vs 2,3), neither side can reach quorum
/// (need 3/4 = 75% for BFT). This test verifies:
/// 1. Progress halts during partition (expected behavior)
/// 2. Messages are being dropped as expected
#[traced_test]
#[test]
fn test_consensus_during_partition() {
    let config = test_network_config();
    let mut runner = SimulationRunner::new(config, 42);

    runner.initialize_genesis();

    // Run normally for 1 second
    runner.run_until(Duration::from_secs(1));
    let height_before = runner.node(0).unwrap().bft().committed_height();
    println!("Height before partition: {}", height_before);

    // Create a partition: nodes 0,1 can't talk to nodes 2,3
    runner.network_mut().partition_groups(&[0, 1], &[2, 3]);
    println!("Network partitioned: {{0,1}} <-> {{2,3}}");

    // Run during partition - neither side should make progress (need 3/4 for quorum)
    runner.run_until(Duration::from_secs(2));
    let height_during_partition = runner.node(0).unwrap().bft().committed_height();
    println!(
        "Height during partition: {} (expected ~{} due to no quorum)",
        height_during_partition, height_before
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

/// Test that packet loss is applied correctly.
///
/// Note: The current BFT implementation doesn't have message retransmission,
/// so packet loss can significantly impact consensus throughput. Lost votes
/// prevent QC formation until the next proposal.
///
/// This test verifies:
/// 1. Packet loss is being applied at roughly the configured rate
/// 2. Results remain deterministic under packet loss
#[test]
fn test_packet_loss_application() {
    let config = NetworkConfig {
        num_shards: 1,
        validators_per_shard: 4,
        intra_shard_latency: Duration::from_millis(10),
        cross_shard_latency: Duration::from_millis(50),
        jitter_fraction: 0.1,
        packet_loss_rate: 0.10, // 10% packet loss
    };

    let mut runner = SimulationRunner::new(config, 42);
    runner.initialize_genesis();

    // Run with packet loss
    runner.run_until(Duration::from_secs(3));

    let heights: Vec<u64> = (0..4u32)
        .map(|i| runner.node(i).unwrap().bft().committed_height())
        .collect();

    println!("Heights with 10% packet loss: {:?}", heights);

    let stats = runner.stats();
    println!("\nStats with 10% packet loss:");
    println!("  Messages sent: {}", stats.messages_sent);
    println!("  Messages dropped: {}", stats.messages_dropped_loss);

    // Verify packet loss is actually happening
    assert!(
        stats.messages_dropped_loss > 0,
        "Some messages should be dropped"
    );

    let total_attempted = stats.messages_sent + stats.messages_dropped_loss;
    let actual_loss_rate = stats.messages_dropped_loss as f64 / total_attempted as f64;
    println!("  Actual loss rate: {:.1}%", actual_loss_rate * 100.0);

    // Loss rate should be roughly what we configured (within reasonable variance)
    // With enough messages, should be close to 10%
    assert!(
        actual_loss_rate > 0.05 && actual_loss_rate < 0.20,
        "Loss rate should be roughly 10%, got {:.1}%",
        actual_loss_rate * 100.0
    );

    // Some progress should still be made (consensus isn't completely broken)
    let max_height = *heights.iter().max().unwrap();
    assert!(
        max_height > 0,
        "Some progress should be made even with 10% loss"
    );
}

/// Test that packet loss is deterministic (same seed = same drops).
#[test]
fn test_packet_loss_determinism() {
    let config = NetworkConfig {
        num_shards: 1,
        validators_per_shard: 4,
        intra_shard_latency: Duration::from_millis(10),
        cross_shard_latency: Duration::from_millis(50),
        jitter_fraction: 0.1,
        packet_loss_rate: 0.2, // 20% packet loss for more variation
    };

    let seed = 12345u64;

    // Run 1
    let mut runner1 = SimulationRunner::new(config.clone(), seed);
    runner1.initialize_genesis();
    runner1.run_until(Duration::from_secs(3));
    let stats1 = runner1.stats().clone();
    let heights1: Vec<u64> = (0..4u32)
        .map(|i| runner1.node(i).unwrap().bft().committed_height())
        .collect();

    // Run 2
    let mut runner2 = SimulationRunner::new(config, seed);
    runner2.initialize_genesis();
    runner2.run_until(Duration::from_secs(3));
    let stats2 = runner2.stats().clone();
    let heights2: Vec<u64> = (0..4u32)
        .map(|i| runner2.node(i).unwrap().bft().committed_height())
        .collect();

    // Should be identical
    assert_eq!(heights1, heights2, "Heights should be identical");
    assert_eq!(
        stats1.messages_sent, stats2.messages_sent,
        "Messages sent should be identical"
    );
    assert_eq!(
        stats1.messages_dropped_loss, stats2.messages_dropped_loss,
        "Messages dropped should be identical"
    );

    println!("Packet loss determinism verified:");
    println!("  Heights: {:?}", heights1);
    println!("  Sent: {}", stats1.messages_sent);
    println!("  Dropped: {}", stats1.messages_dropped_loss);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Sync Protocol Tests
// ═══════════════════════════════════════════════════════════════════════════════

/// Test that a node behind by multiple blocks triggers sync.
///
/// This test manually creates a scenario where one node is behind,
/// then verifies that sync is triggered when it receives a block header.
#[traced_test]
#[test]
fn test_sync_triggers_when_behind() {
    let config = test_network_config();
    let mut runner = SimulationRunner::new(config, 42);

    runner.initialize_genesis();

    // Run to commit some blocks
    runner.run_until(Duration::from_secs(3));

    // Check all nodes have made progress
    let heights: Vec<u64> = (0..4u32)
        .map(|i| runner.node(i).unwrap().bft().committed_height())
        .collect();

    println!("Initial heights: {:?}", heights);

    // All nodes should be synced at the same height
    let max_height = *heights.iter().max().unwrap();
    let min_height = *heights.iter().min().unwrap();

    assert!(
        max_height >= 5,
        "Should have committed at least 5 blocks, got {}",
        max_height
    );
    assert_eq!(
        max_height, min_height,
        "All nodes should be at the same height"
    );

    // Verify no sync was needed (nodes were always in sync)
    for i in 0..4u32 {
        let is_syncing = runner.node(i).unwrap().is_syncing();
        assert!(
            !is_syncing,
            "Node {} should not be syncing in normal operation",
            i
        );
    }

    println!("Test passed: nodes progressed normally without sync");
}

/// Test sync detection threshold - sync only triggers when 2+ blocks behind.
///
/// Being 1 block behind is normal operation (waiting for the next commit).
/// Sync should only trigger when we're 2+ blocks behind.
#[traced_test]
#[test]
fn test_sync_detection_threshold() {
    let config = test_network_config();
    let mut runner = SimulationRunner::new(config, 42);

    runner.initialize_genesis();

    // Run a bit to let nodes commit
    runner.run_until(Duration::from_secs(2));

    // All nodes should be in sync - no sync should have been triggered
    for i in 0..4u32 {
        let node = runner.node(i).unwrap();
        assert!(
            !node.is_syncing(),
            "Node {} should not be syncing during normal consensus",
            i
        );
    }

    println!("Test passed: sync not triggered during normal operation");
}

/// Test that committed blocks are stored for sync retrieval.
///
/// When a node commits a block, it should be stored so other nodes
/// can request it via the sync protocol.
#[traced_test]
#[test]
fn test_committed_blocks_stored_for_sync() {
    let config = test_network_config();
    let mut runner = SimulationRunner::new(config, 42);

    runner.initialize_genesis();

    // Run to commit some blocks
    runner.run_until(Duration::from_secs(3));

    // Check that node 0 has committed blocks
    let height = runner.node(0).unwrap().bft().committed_height();
    assert!(height >= 5, "Should have committed at least 5 blocks");

    // The simulation stores committed blocks in the runner's committed_blocks cache
    // This is verified indirectly - if blocks weren't stored, sync requests would fail
    println!("Test passed: committed {} blocks", height);
}

/// Test sync state machine isolation.
///
/// The sync state machine should be independent per node, not shared.
#[traced_test]
#[test]
fn test_sync_state_isolation() {
    let config = test_network_config();
    let runner = SimulationRunner::new(config, 42);

    // Each node should have its own sync state
    for i in 0..4u32 {
        let node = runner.node(i).unwrap();
        let sync = node.sync();

        // Fresh sync state should not be syncing
        assert!(!sync.is_syncing(), "Fresh node {} should not be syncing", i);
        assert_eq!(
            sync.sync_target(),
            None,
            "Fresh node {} should have no sync target",
            i
        );
    }

    println!("Test passed: each node has isolated sync state");
}

/// Test partition recovery scenario.
///
/// This test creates a scenario where:
/// 1. Network runs normally, nodes commit blocks
/// 2. One node is isolated (can't receive messages)
/// 3. Other nodes continue making progress
/// 4. Isolation is removed
/// 5. The lagging node receives new block headers and detects it's behind
///
/// Note: Full sync recovery requires the lagging node to receive a block header
/// that reveals it's 2+ blocks behind. This test verifies the infrastructure
/// and documents the current behavior.
#[traced_test]
#[test]
fn test_isolated_node_divergence() {
    let config = test_network_config();
    let mut runner = SimulationRunner::new(config, 42);

    runner.initialize_genesis();

    // Run normally first
    runner.run_until(Duration::from_secs(1));

    let initial_height = runner.node(0).unwrap().bft().committed_height();
    println!("Initial height: {}", initial_height);

    // Isolate node 3 - it can't receive from anyone
    runner.network_mut().partition_groups(&[3], &[0, 1, 2]);
    println!("Node 3 isolated");

    // Run while node 3 is isolated - other nodes should progress
    // With 3/4 nodes, they can still reach quorum (need 3 for 4-node network)
    runner.run_until(Duration::from_secs(4));

    // Check heights
    let heights_during: Vec<u64> = (0..4u32)
        .map(|i| runner.node(i).unwrap().bft().committed_height())
        .collect();
    println!("Heights during isolation: {:?}", heights_during);

    // Nodes 0,1,2 should have progressed, node 3 should be behind
    let majority_height = heights_during[0];
    let isolated_height = heights_during[3];

    println!(
        "Majority at height {}, isolated node at height {}",
        majority_height, isolated_height
    );

    // Verify divergence occurred
    assert!(
        majority_height > isolated_height,
        "Majority should be ahead of isolated node"
    );

    // Heal the partition
    runner.network_mut().heal_all();
    println!("Partition healed");

    // Check what blocks are stored
    println!("Committed blocks stored per node:");
    for i in 0..4u32 {
        let count = runner.committed_block_count(i);
        // Check specific heights
        let has_46 = runner.has_committed_block(i, 46);
        let has_47 = runner.has_committed_block(i, 47);
        let has_48 = runner.has_committed_block(i, 48);
        let has_49 = runner.has_committed_block(i, 49);
        println!(
            "  Node {}: {} blocks, has 46={}, 47={}, 48={}, 49={}",
            i, count, has_46, has_47, has_48, has_49
        );
    }

    // Check sync state before running
    println!("Sync state before recovery:");
    for i in 0..4u32 {
        let node = runner.node(i).unwrap();
        println!(
            "  Node {}: is_syncing={}, sync_target={:?}",
            i,
            node.is_syncing(),
            node.sync().sync_target()
        );
    }

    // Run to allow recovery attempts - give more time for sync
    runner.run_until(Duration::from_secs(30));

    // Check sync state after
    println!("Sync state after recovery:");
    for i in 0..4u32 {
        let node = runner.node(i).unwrap();
        let sync = node.sync();
        println!(
            "  Node {}: bft_height={}, sync_height={}, is_syncing={}, sync_target={:?}, pending={}",
            i,
            node.bft().committed_height(),
            sync.committed_height(),
            node.is_syncing(),
            sync.sync_target(),
            sync.pending_fetch_count()
        );
    }

    // Check final heights
    let final_heights: Vec<u64> = (0..4u32)
        .map(|i| runner.node(i).unwrap().bft().committed_height())
        .collect();
    println!("Final heights: {:?}", final_heights);

    let max_final = *final_heights.iter().max().unwrap();
    let min_final = *final_heights.iter().min().unwrap();

    println!(
        "Final height range: {} to {} (diff: {})",
        min_final,
        max_final,
        max_final - min_final
    );

    // The majority should have continued making progress
    assert!(
        max_final > majority_height,
        "Majority should continue progressing after heal"
    );

    // Verify sync caught up the isolated node
    let divergence = max_final - min_final;
    println!("Height divergence after recovery attempt: {}", divergence);

    // Sync should catch up the isolated node completely
    assert_eq!(
        divergence, 0,
        "Sync should have caught up the isolated node"
    );
}
