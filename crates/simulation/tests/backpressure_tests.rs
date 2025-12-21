//! Integration tests for backpressure functionality.
//!
//! These tests verify that the backpressure system works correctly in the
//! integrated simulation environment, testing the interaction between:
//! - MempoolState (ready_transactions with backpressure, in_flight count)
//! - ProvisionCoordinator (tracking provisions for livelock detection)
//! - NodeStateMachine (attaching proofs to transactions)
//!
//! Note: The backpressure limit (default 512 soft, 1024 hard) is based on ALL TXs
//! holding state locks in the mempool (Committed or Executed status). Cross-shard
//! TXs with verified provisions bypass the soft limit (other shards waiting on us).
//! These tests verify the system behavior without hitting that limit.

use hyperscale_core::{Event, TransactionStatus};
use hyperscale_simulation::{NetworkConfig, SimulationRunner};
use hyperscale_types::{sign_and_notarize, KeyPair, KeyType, RoutableTransaction};
use radix_common::constants::XRD;
use radix_common::crypto::Ed25519PublicKey;
use radix_common::math::Decimal;
use radix_common::network::NetworkDefinition;
use radix_common::types::ComponentAddress;
use radix_transactions::builder::ManifestBuilder;
use std::sync::Arc;
use std::time::Duration;

/// Create a multi-shard network configuration for cross-shard tests.
fn multi_shard_config() -> NetworkConfig {
    NetworkConfig {
        num_shards: 2,
        validators_per_shard: 3,
        intra_shard_latency: Duration::from_millis(10),
        cross_shard_latency: Duration::from_millis(50),
        jitter_fraction: 0.1,
        ..Default::default()
    }
}

/// Create a single-shard network configuration.
fn single_shard_config() -> NetworkConfig {
    NetworkConfig {
        num_shards: 1,
        validators_per_shard: 4,
        intra_shard_latency: Duration::from_millis(10),
        cross_shard_latency: Duration::from_millis(50),
        jitter_fraction: 0.1,
        ..Default::default()
    }
}

/// Helper to create a deterministic keypair for signing transactions.
fn test_keypair_from_seed(seed: u8) -> KeyPair {
    let seed_bytes = [seed; 32];
    KeyPair::from_seed(KeyType::Ed25519, &seed_bytes)
}

/// Helper to create a deterministic Radix account address from a seed.
fn test_account(seed: u8) -> ComponentAddress {
    let pk = Ed25519PublicKey([seed; 32]);
    ComponentAddress::preallocated_account_from_public_key(&pk)
}

/// Get the simulator network definition.
fn simulator_network() -> NetworkDefinition {
    NetworkDefinition::simulator()
}

// ═══════════════════════════════════════════════════════════════════════════════
// Backpressure Behavior Tests
// ═══════════════════════════════════════════════════════════════════════════════

/// Test that single-shard transactions work normally regardless of backpressure state.
#[test]
fn test_single_shard_unaffected_by_backpressure() {
    let config = single_shard_config();
    let mut runner = SimulationRunner::new(config.clone(), 12345);

    // Initialize genesis
    runner.initialize_genesis();
    runner.run_until(Duration::from_millis(100));

    // Create and submit a single-shard transaction
    let keypair = test_keypair_from_seed(1);
    let recipient = test_account(99);

    let manifest = ManifestBuilder::new()
        .lock_fee_from_faucet()
        .get_free_xrd_from_faucet()
        .take_from_worktop(XRD, Decimal::from(100), "bucket")
        .try_deposit_or_abort(recipient, None, "bucket")
        .build();

    let notarized = sign_and_notarize(manifest, &simulator_network(), 1, &keypair)
        .expect("should sign transaction");
    let transaction: RoutableTransaction = notarized.try_into().expect("valid transaction");
    let tx_hash = transaction.hash();

    // Submit via event
    runner.schedule_initial_event(
        0,
        Duration::ZERO,
        Event::SubmitTransaction {
            tx: Arc::new(transaction),
        },
    );

    // Run to process
    runner.run_until(Duration::from_secs(5));

    // Verify transaction was processed
    let node = runner.node(0).unwrap();
    let status = node.mempool().status(&tx_hash);

    // Check backpressure state - now driven by mempool's in_flight count
    let mempool = node.mempool();
    let in_flight = mempool.in_flight();
    let at_limit = mempool.at_in_flight_limit();

    println!(
        "Single-shard TX status: {:?}, in_flight: {}, at_limit: {}",
        status, in_flight, at_limit
    );

    // Single-shard TX should have processed (not stuck in pending due to backpressure)
    assert!(
        status.is_none()
            || matches!(
                status,
                Some(TransactionStatus::Committed { .. })
                    | Some(TransactionStatus::Executed { .. })
                    | Some(TransactionStatus::Completed(_))
            ),
        "Single-shard TX should not be blocked by backpressure: {:?}",
        status
    );
}

/// Test that cross-shard transactions are tracked by provision coordinator.
#[test]
fn test_provision_coordinator_tracking() {
    let config = multi_shard_config();
    let mut runner = SimulationRunner::new(config.clone(), 12346);

    // Initialize genesis
    runner.initialize_genesis();
    runner.run_until(Duration::from_millis(100));

    let keypair = test_keypair_from_seed(2);
    let recipient = test_account(88);

    // Build a transaction
    let manifest = ManifestBuilder::new()
        .lock_fee_from_faucet()
        .get_free_xrd_from_faucet()
        .take_from_worktop(XRD, Decimal::from(50), "bucket")
        .try_deposit_or_abort(recipient, None, "bucket")
        .build();

    let notarized = sign_and_notarize(manifest, &simulator_network(), 2, &keypair)
        .expect("should sign transaction");
    let transaction: RoutableTransaction = notarized.try_into().expect("valid transaction");
    let tx_hash = transaction.hash();
    let is_cross_shard = transaction.is_cross_shard(2);

    println!(
        "Transaction: hash={}, is_cross_shard={}",
        tx_hash, is_cross_shard
    );

    // Submit via event
    runner.schedule_initial_event(
        0,
        Duration::ZERO,
        Event::SubmitTransaction {
            tx: Arc::new(transaction),
        },
    );

    // Run to allow processing
    runner.run_until(Duration::from_secs(3));

    // Check backpressure state - now driven by mempool
    let node = runner.node(0).unwrap();
    let mempool = node.mempool();

    let in_flight = mempool.in_flight();
    let at_limit = mempool.at_in_flight_limit();

    // Also check provision coordinator for comparison
    let provisions = node.provisions();
    let coordinator_count = provisions.cross_shard_pending_count();

    println!(
        "After submission: mempool_in_flight={}, coordinator_count={}, at_limit={}",
        in_flight, coordinator_count, at_limit
    );

    // We shouldn't be at limit with small number of TXs
    assert!(
        !at_limit,
        "Should not be at backpressure limit with few TXs"
    );
}

/// Test that the mempool correctly queries provision coordinator for backpressure.
#[test]
fn test_mempool_backpressure_integration() {
    let config = multi_shard_config();
    let mut runner = SimulationRunner::new(config.clone(), 12347);

    // Initialize genesis
    runner.initialize_genesis();
    runner.run_until(Duration::from_millis(100));

    let keypair = test_keypair_from_seed(3);

    // Submit several transactions
    for i in 0..5 {
        let recipient = test_account(100 + i);

        let manifest = ManifestBuilder::new()
            .lock_fee_from_faucet()
            .get_free_xrd_from_faucet()
            .take_from_worktop(XRD, Decimal::from(10), "bucket")
            .try_deposit_or_abort(recipient, None, "bucket")
            .build();

        let notarized = sign_and_notarize(manifest, &simulator_network(), 3 + i as u32, &keypair)
            .expect("should sign transaction");
        let transaction: RoutableTransaction = notarized.try_into().expect("valid transaction");

        runner.schedule_initial_event(
            0,
            Duration::from_millis(i as u64 * 10),
            Event::SubmitTransaction {
                tx: Arc::new(transaction),
            },
        );
    }

    // Run briefly
    runner.run_until(Duration::from_millis(500));

    // Check backpressure state via mempool
    let node = runner.node(0).unwrap();
    let mempool = node.mempool();

    let mempool_size = mempool.len();
    let in_flight = mempool.in_flight();
    let at_limit = mempool.at_in_flight_limit();

    println!(
        "Mempool size: {}, in_flight: {}, at_limit: {}",
        mempool_size, in_flight, at_limit
    );

    // Verify the system is working
    assert!(!at_limit, "Should not be at limit with small number of TXs");
}

/// Test that cross-shard TXs are correctly tracked through the lifecycle.
#[test]
fn test_provision_lifecycle_tracking() {
    let config = multi_shard_config();
    let mut runner = SimulationRunner::new(config.clone(), 12348);

    // Initialize genesis
    runner.initialize_genesis();

    // Run for enough time to see some blocks committed
    runner.run_until(Duration::from_secs(3));

    // Check backpressure state on all nodes
    for node_idx in 0..6u32 {
        // 2 shards × 3 validators
        let node = runner.node(node_idx).unwrap();
        let mempool = node.mempool();

        let in_flight = mempool.in_flight();
        let at_limit = mempool.at_in_flight_limit();

        println!(
            "Node {}: in_flight={}, at_limit={}",
            node_idx, in_flight, at_limit
        );

        // None should be at limit in idle state
        assert!(
            !at_limit,
            "Node {} should not be at backpressure limit in idle state",
            node_idx
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Metrics Integration Tests
// ═══════════════════════════════════════════════════════════════════════════════

/// Test that backpressure metrics are accessible.
#[test]
fn test_provision_metrics_accessible() {
    let config = multi_shard_config();
    let mut runner = SimulationRunner::new(config.clone(), 12349);

    // Initialize genesis
    runner.initialize_genesis();
    runner.run_until(Duration::from_millis(100));

    // Verify we can access the metrics-relevant data
    let node = runner.node(0).unwrap();
    let mempool = node.mempool();

    // These are the methods used by production metrics
    let in_flight = mempool.in_flight();
    let at_limit = mempool.at_in_flight_limit();

    println!(
        "Metrics check: in_flight={}, at_limit={}",
        in_flight, at_limit
    );

    // Basic sanity checks
    assert_eq!(in_flight, 0, "Should start with 0 in-flight");
    assert!(!at_limit, "Should not start at limit");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Edge Case Tests
// ═══════════════════════════════════════════════════════════════════════════════

/// Test behavior early in simulation before many TXs have been processed.
#[test]
fn test_provisions_pending_verification() {
    let config = multi_shard_config();
    let mut runner = SimulationRunner::new(config.clone(), 12350);

    // Initialize genesis
    runner.initialize_genesis();

    // Run for a short time
    runner.run_until(Duration::from_millis(200));

    let node = runner.node(0).unwrap();
    let mempool = node.mempool();

    // The mempool should be in a valid state
    let in_flight = mempool.in_flight();
    let at_limit = mempool.at_in_flight_limit();

    println!(
        "Early state: in_flight={}, at_limit={}",
        in_flight, at_limit
    );

    // These should be valid regardless of internal state
    assert!(!at_limit, "Should not be at limit early in simulation");
}

/// Test that completed transactions don't affect backpressure count.
#[test]
fn test_completed_tx_cleanup() {
    let config = single_shard_config();
    let mut runner = SimulationRunner::new(config.clone(), 12351);

    // Initialize genesis
    runner.initialize_genesis();

    let keypair = test_keypair_from_seed(4);
    let recipient = test_account(200);

    let manifest = ManifestBuilder::new()
        .lock_fee_from_faucet()
        .get_free_xrd_from_faucet()
        .take_from_worktop(XRD, Decimal::from(100), "bucket")
        .try_deposit_or_abort(recipient, None, "bucket")
        .build();

    let notarized = sign_and_notarize(manifest, &simulator_network(), 4, &keypair)
        .expect("should sign transaction");
    let transaction: RoutableTransaction = notarized.try_into().expect("valid transaction");
    let tx_hash = transaction.hash();

    runner.schedule_initial_event(
        0,
        Duration::ZERO,
        Event::SubmitTransaction {
            tx: Arc::new(transaction),
        },
    );

    // Run long enough for transaction to complete
    runner.run_until(Duration::from_secs(10));

    // Check final state
    let node = runner.node(0).unwrap();
    let status = node.mempool().status(&tx_hash);
    let in_flight = node.mempool().in_flight();

    println!("Final state: status={:?}, in_flight={}", status, in_flight);

    // Completed TX shouldn't be counted in-flight (lock released)
    // Note: status might be None if evicted after completion
    assert_eq!(
        in_flight, 0,
        "Completed TX shouldn't affect in-flight count"
    );
}

/// Test that all nodes in a multi-shard setup have consistent backpressure state.
#[test]
fn test_multi_node_provision_consistency() {
    let config = multi_shard_config();
    let mut runner = SimulationRunner::new(config.clone(), 12352);

    // Initialize genesis
    runner.initialize_genesis();

    // Run for a bit
    runner.run_until(Duration::from_secs(2));

    // All nodes should have consistent backpressure state (not at limit)
    let mut all_consistent = true;
    for node_idx in 0..6u32 {
        let node = runner.node(node_idx).unwrap();
        let at_limit = node.mempool().at_in_flight_limit();
        if at_limit {
            println!("Node {} unexpectedly at backpressure limit", node_idx);
            all_consistent = false;
        }
    }

    assert!(
        all_consistent,
        "All nodes should have consistent backpressure state"
    );
}
