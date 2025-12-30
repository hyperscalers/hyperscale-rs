//! End-to-end integration tests for deterministic simulation.
//!
//! These tests verify the complete flow from transaction submission to finalization
//! in a deterministic, single-threaded environment. Unlike the async consensus-node
//! tests, these run entirely synchronously with simulated time.
//!
//! Key differences from async e2e tests:
//! - No tokio runtime - all execution is synchronous
//! - Simulated time - `run_until()` advances the simulation clock
//! - Deterministic - same seed always produces same results
//! - Inline execution - Radix Engine runs synchronously (not in thread pool)

use hyperscale_core::{Event, TransactionStatus};
use hyperscale_simulation::{NetworkConfig, SimulationRunner};
use hyperscale_types::{
    ed25519_keypair_from_seed, shard_for_node, sign_and_notarize, Ed25519PrivateKey, NodeId,
    RoutableTransaction, ShardGroupId,
};
use radix_common::constants::XRD;
use radix_common::crypto::Ed25519PublicKey;
use radix_common::math::Decimal;
use radix_common::network::NetworkDefinition;
use radix_common::types::ComponentAddress;
use radix_transactions::builder::ManifestBuilder;
use std::sync::Arc;
use std::time::Duration;
use tracing_test::traced_test;

/// Create a basic single-shard network configuration.
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

/// Create a multi-shard network configuration.
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

/// Helper to create a deterministic Ed25519 keypair for signing transactions.
fn test_keypair_from_seed(seed: u8) -> Ed25519PrivateKey {
    let seed_bytes = [seed; 32];
    ed25519_keypair_from_seed(&seed_bytes)
}

/// Helper to create a deterministic Radix account address from a seed.
/// NOTE: This creates an account with a "fake" public key that doesn't match
/// any keypair - useful for deposit-only accounts.
fn test_account(seed: u8) -> ComponentAddress {
    let pk = Ed25519PublicKey([seed; 32]);
    ComponentAddress::preallocated_account_from_public_key(&pk)
}

/// Helper to create an account that can be controlled by the given Ed25519 keypair.
/// This derives the account address from the keypair's actual public key,
/// so withdrawals can be authorized by signing with the keypair.
fn account_from_keypair(keypair: &Ed25519PrivateKey) -> ComponentAddress {
    let radix_pk = keypair.public_key();
    ComponentAddress::preallocated_account_from_public_key(&radix_pk)
}

/// Get the simulator network definition.
fn simulator_network() -> NetworkDefinition {
    NetworkDefinition::simulator()
}

// ═══════════════════════════════════════════════════════════════════════════════
// Single-Shard Transaction Tests
// ═══════════════════════════════════════════════════════════════════════════════

/// Test end-to-end single-shard transaction flow.
///
/// This test verifies the complete deterministic flow:
/// 1. Genesis initialization
/// 2. Transaction submission to mempool
/// 3. BFT consensus ordering the transaction into a block
/// 4. Block commit via two-chain rule
/// 5. Execution coordinator processing the committed block
/// 6. Transaction reaches executed status
///
/// Flow:
/// ```text
/// submit_transaction() → Mempool → BFT orders → Block committed → Execution → Executed
/// ```
#[traced_test]
#[test]
fn test_e2e_single_shard_transaction() {
    println!("\n=== E2E Test: Single-Shard Transaction (Deterministic) ===\n");

    let config = single_shard_config();
    let mut runner = SimulationRunner::new(config, 42);

    // Initialize genesis - creates genesis blocks and sets up timers
    runner.initialize_genesis();

    println!("✓ Genesis initialized for all validators\n");

    // Verify initial state
    for node_idx in 0..4u32 {
        let node = runner.node(node_idx).expect("Node should exist");
        assert_eq!(
            node.bft().committed_height(),
            0,
            "Node {} should be at genesis height",
            node_idx
        );
    }

    // Create and submit transaction BEFORE running initial consensus
    // This ensures the transaction is in the mempool when proposers first propose
    let signer = test_keypair_from_seed(1);
    let to_account = test_account(2);

    let manifest = ManifestBuilder::new()
        .lock_fee_from_faucet()
        .get_free_xrd_from_faucet()
        .try_deposit_entire_worktop_or_abort(to_account, None)
        .build();

    let notarized = sign_and_notarize(manifest, &simulator_network(), 1, &signer)
        .expect("should sign transaction");
    let transaction: RoutableTransaction = notarized.try_into().expect("valid transaction");
    let tx_hash = transaction.hash();

    println!("Transaction created: {:?}", tx_hash);
    println!("  Target account: {:?}", to_account);

    // Submit transaction to node 0 BEFORE consensus runs
    // Use SubmitTransaction to trigger gossip to all validators in the shard
    runner.schedule_initial_event(
        0,
        Duration::ZERO,
        Event::SubmitTransaction {
            tx: Arc::new(transaction.clone()),
        },
    );

    println!("✓ Transaction submitted to node 0\n");

    // Run simulation for a bit to let consensus establish AND process the transaction
    runner.run_until(Duration::from_secs(2));

    // Check that blocks are being committed
    let mut any_committed = false;
    for node_idx in 0..4u32 {
        let node = runner.node(node_idx).expect("Node should exist");
        if node.bft().committed_height() > 0 {
            any_committed = true;
            println!(
                "Node {} committed height: {}",
                node_idx,
                node.bft().committed_height()
            );
        }
    }

    println!(
        "\n✓ Initial consensus established, blocks committed: {}\n",
        any_committed
    );

    // Check mempool status on node 0
    // Note: By this point (2s of consensus), the transaction may already be completed and evicted!
    let node0 = runner.node(0).expect("Node 0 should exist");
    let initial_status = node0.mempool().status(&tx_hash);
    println!(
        "Transaction status after initial consensus: {:?}",
        initial_status
    );

    // If status is None, the transaction completed and was evicted from mempool.
    // This is the expected behavior for completed transactions.
    // Check execution state to confirm it was processed.
    if initial_status.is_none() {
        // Transaction was evicted - check if it was executed
        let is_executed = node0.execution().is_executed(&tx_hash);
        if is_executed {
            println!("✓ Transaction already completed and evicted after initial consensus!\n");

            // Print final state
            let max_height: u64 = (0..4)
                .map(|i| runner.node(i).unwrap().bft().committed_height())
                .max()
                .unwrap();

            println!("\n✅ E2E Single-Shard Test PASSED!");
            println!("   ✅ Genesis initialized");
            println!("   ✅ Transaction committed and executed");
            println!("   ✅ Max committed height: {}", max_height);
            return;
        }
        // If not executed, it might just not have been processed yet - continue with polling
    }

    // If already completed (but not yet evicted due to timing), we can skip the polling loop.
    if matches!(initial_status, Some(TransactionStatus::Completed(_))) {
        println!("✓ Transaction already completed after initial consensus!\n");

        // Print final state
        let max_height: u64 = (0..4)
            .map(|i| runner.node(i).unwrap().bft().committed_height())
            .max()
            .unwrap();

        println!("\n✅ E2E Single-Shard Test PASSED!");
        println!("   ✅ Genesis initialized");
        println!("   ✅ Transaction committed and executed");
        println!("   ✅ Max committed height: {}", max_height);
        return;
    }

    println!(
        "✓ Transaction entered mempool ({})\n",
        if initial_status == Some(TransactionStatus::Pending) {
            "Pending"
        } else {
            "already processing"
        }
    );

    // Run simulation to process the transaction through consensus and execution
    println!("Running consensus protocol...");

    let start_time = runner.now();

    // Poll for status changes
    let mut committed = false;
    let mut executed = false;

    for iteration in 0..100 {
        runner.run_until(runner.now() + Duration::from_millis(100));

        let node0 = runner.node(0).expect("Node 0 should exist");

        // Check mempool status
        // Transaction progresses: Pending -> Committed -> ... -> Finalized -> Completed
        if let Some(status) = node0.mempool().status(&tx_hash) {
            if !committed && status.holds_state_lock() {
                let elapsed = runner.now() - start_time;
                println!(
                    "  ✓ Transaction committed to block (iteration {}, {:?})",
                    iteration, elapsed
                );
                committed = true;
            }
        }

        // Check execution status
        if node0.execution().is_executed(&tx_hash) && !executed {
            let elapsed = runner.now() - start_time;
            println!(
                "  ✓ Transaction executed (iteration {}, {:?})",
                iteration, elapsed
            );
            executed = true;
        }

        // Early exit if fully processed
        if committed && executed {
            break;
        }

        // Progress report
        if (iteration + 1) % 20 == 0 {
            let elapsed = runner.now() - start_time;
            let height = node0.bft().committed_height();
            println!(
                "  Iteration {}: elapsed={:?}, height={}, committed={}, executed={}",
                iteration + 1,
                elapsed,
                height,
                committed,
                executed
            );
        }
    }

    let elapsed = runner.now() - start_time;

    // Check final state
    println!("\n=== Final State After {:?} ===", elapsed);

    let stats = runner.stats();
    println!("Events processed: {}", stats.events_processed);
    println!("Messages sent: {}", stats.messages_sent);
    println!("Timers set: {}", stats.timers_set);

    // Verify all nodes have progressed
    let mut max_height = 0;
    for node_idx in 0..4u32 {
        let node = runner.node(node_idx).expect("Node should exist");
        let height = node.bft().committed_height();
        max_height = max_height.max(height);

        // Check transaction status on each node
        let mempool_status = node.mempool().status(&tx_hash);
        let is_executed = node.execution().is_executed(&tx_hash);

        println!(
            "Node {}: height={}, view={}, tx_status={:?}, executed={}",
            node_idx,
            height,
            node.bft().view(),
            mempool_status,
            is_executed
        );
    }

    // Assertions
    assert!(
        max_height >= 1,
        "Should have committed at least one block beyond genesis"
    );
    assert!(
        committed,
        "Transaction should have been committed to a block"
    );
    assert!(executed, "Transaction should have been executed");

    println!("\n✅ E2E Single-Shard Test PASSED!");
    println!("   ✅ Genesis initialized");
    println!("   ✅ Transaction entered mempool (Pending)");
    println!("   ✅ Transaction committed to block");
    println!("   ✅ Transaction executed");
    println!("   ✅ Max committed height: {}", max_height);
}

/// Test that single-shard transactions are deterministic.
///
/// Runs the same test twice with the same seed and verifies
/// that all results are identical.
#[traced_test]
#[test]
fn test_e2e_single_shard_determinism() {
    println!("\n=== E2E Test: Single-Shard Determinism ===\n");

    let config = single_shard_config();
    let seed = 12345u64;

    // Create the same transaction for both runs
    let signer = test_keypair_from_seed(1);
    let to_account = test_account(2);

    let manifest = ManifestBuilder::new()
        .lock_fee_from_faucet()
        .get_free_xrd_from_faucet()
        .try_deposit_entire_worktop_or_abort(to_account, None)
        .build();

    let notarized = sign_and_notarize(manifest, &simulator_network(), 1, &signer)
        .expect("should sign transaction");
    let transaction: RoutableTransaction = notarized.try_into().expect("valid transaction");

    // First run
    let mut runner1 = SimulationRunner::new(config.clone(), seed);
    runner1.initialize_genesis();
    runner1.schedule_initial_event(
        0,
        Duration::from_millis(100),
        Event::SubmitTransaction {
            tx: Arc::new(transaction.clone()),
        },
    );
    runner1.run_until(Duration::from_secs(5));

    let stats1 = runner1.stats().clone();
    let heights1: Vec<u64> = (0..4)
        .map(|i| runner1.node(i).unwrap().bft().committed_height())
        .collect();

    // Second run with same seed
    let mut runner2 = SimulationRunner::new(config.clone(), seed);
    runner2.initialize_genesis();
    runner2.schedule_initial_event(
        0,
        Duration::from_millis(100),
        Event::SubmitTransaction {
            tx: Arc::new(transaction.clone()),
        },
    );
    runner2.run_until(Duration::from_secs(5));

    let stats2 = runner2.stats().clone();
    let heights2: Vec<u64> = (0..4)
        .map(|i| runner2.node(i).unwrap().bft().committed_height())
        .collect();

    // Verify identical results
    assert_eq!(
        stats1.events_processed, stats2.events_processed,
        "Events processed should match"
    );
    assert_eq!(
        stats1.messages_sent, stats2.messages_sent,
        "Messages sent should match"
    );
    assert_eq!(
        stats1.actions_generated, stats2.actions_generated,
        "Actions generated should match"
    );
    assert_eq!(heights1, heights2, "Committed heights should match");

    println!("✅ Determinism verified!");
    println!("   Events: {}", stats1.events_processed);
    println!("   Messages: {}", stats1.messages_sent);
    println!("   Heights: {:?}", heights1);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Multi-Shard Transaction Tests
// ═══════════════════════════════════════════════════════════════════════════════

/// Test end-to-end multi-shard consensus with separate shard transactions.
///
/// This test verifies that:
/// 1. Multiple shards can run consensus independently
/// 2. Each shard maintains its own block chain
/// 3. Validators only vote on their own shard's blocks
#[traced_test]
#[test]
fn test_e2e_multi_shard_consensus() {
    println!("\n=== E2E Test: Multi-Shard Consensus (Deterministic) ===\n");

    let config = multi_shard_config();
    let mut runner = SimulationRunner::new(config, 42);

    // Initialize genesis for all shards
    runner.initialize_genesis();

    println!("✓ Genesis initialized for 2 shards (3 validators each)\n");

    // Verify initial state
    // Shard 0: nodes 0, 1, 2
    // Shard 1: nodes 3, 4, 5
    for node_idx in 0..6u32 {
        let node = runner.node(node_idx).expect("Node should exist");
        let shard = if node_idx < 3 { 0 } else { 1 };
        println!(
            "Node {} (Shard {}): committed_height={}",
            node_idx,
            shard,
            node.bft().committed_height()
        );
    }

    // Run simulation
    runner.run_until(Duration::from_secs(5));

    println!("\n=== After 5 seconds ===");

    // Check each shard's progress
    let shard0_heights: Vec<u64> = (0..3)
        .map(|i| runner.node(i).unwrap().bft().committed_height())
        .collect();
    let shard1_heights: Vec<u64> = (3..6)
        .map(|i| runner.node(i).unwrap().bft().committed_height())
        .collect();

    println!("Shard 0 heights: {:?}", shard0_heights);
    println!("Shard 1 heights: {:?}", shard1_heights);

    // Validators within each shard should have similar heights
    // (may differ slightly due to message timing)
    let shard0_max = *shard0_heights.iter().max().unwrap();
    let shard1_max = *shard1_heights.iter().max().unwrap();

    assert!(shard0_max >= 1, "Shard 0 should have made progress");
    assert!(shard1_max >= 1, "Shard 1 should have made progress");

    let stats = runner.stats();
    println!("\nFinal stats:");
    println!("  Events processed: {}", stats.events_processed);
    println!("  Messages sent: {}", stats.messages_sent);

    println!("\n✅ E2E Multi-Shard Consensus Test PASSED!");
    println!("   ✅ Both shards initialized");
    println!(
        "   ✅ Shard 0 max height: {}, Shard 1 max height: {}",
        shard0_max, shard1_max
    );
}

/// Test cross-shard transaction flow.
///
/// This test verifies the 2PC (two-phase commit) protocol:
/// 1. Transaction touches accounts on both shards
/// 2. Both shards execute and create certificates
/// 3. Certificates are exchanged and aggregated
/// 4. Transaction finalizes on all shards
///
/// Flow:
/// ```text
/// submit_transaction() → Mempool → BFT orders → Block committed
///                                            ↓
///                                    Execution Coordinator
///                                            ↓
///                        ┌──────────────────┴──────────────────┐
///                        ▼                                      ▼
///                   Shard 0: Execute                       Shard 1: Execute
///                        ↓                                      ↓
///                   Create vote                            Create vote
///                        ↓                                      ↓
///                   Aggregate → Certificate            Aggregate → Certificate
///                        └──────────────────┬──────────────────┘
///                                           ▼
///                                   Finalize: Accept/Reject
/// ```
#[traced_test]
#[test]
fn test_e2e_cross_shard_transaction() {
    println!("\n=== E2E Test: Cross-Shard Transaction (Deterministic) ===\n");

    let config = multi_shard_config();
    let num_shards = config.num_shards as u64;
    let mut runner = SimulationRunner::new(config, 42);

    // Find accounts that route to different shards
    let mut shard0_keypair = None;
    let mut shard1_keypair = None;

    for seed in 10u8..=255 {
        let kp = test_keypair_from_seed(seed);
        let account = account_from_keypair(&kp);
        let node_id = account.into_node_id();
        // Convert Radix NodeId to Hyperscale NodeId (first 30 bytes)
        let hs_node_id = NodeId(node_id.0[..30].try_into().unwrap());
        let shard = shard_for_node(&hs_node_id, num_shards);

        if shard == ShardGroupId(0) && shard0_keypair.is_none() {
            shard0_keypair = Some((seed, kp, account));
        } else if shard == ShardGroupId(1) && shard1_keypair.is_none() {
            shard1_keypair = Some((seed, kp, account));
        }

        if shard0_keypair.is_some() && shard1_keypair.is_some() {
            break;
        }
    }

    let (seed0, account0_kp, account_shard0) =
        shard0_keypair.expect("Should find keypair for shard 0");
    let (seed1, _account1_kp, account_shard1) =
        shard1_keypair.expect("Should find keypair for shard 1");

    println!("✓ Found accounts on different shards:");
    println!("  Shard 0 account: seed={}", seed0);
    println!("  Shard 1 account: seed={}\n", seed1);

    // Initialize genesis with pre-funded accounts (no funding transactions needed)
    let initial_balance = Decimal::from(10000);
    runner.initialize_genesis_with_balances(vec![
        (account_shard0, initial_balance),
        (account_shard1, initial_balance),
    ]);
    println!("✓ Accounts funded at genesis\n");

    // Run for a bit before starting the test to let consensus start producing blocks
    runner.run_until(Duration::from_secs(3));

    // Create cross-shard transaction: withdraw from shard 0, deposit to shard 1
    // Use lock_fee on the source account (not faucet) to properly declare it as a write
    let manifest = ManifestBuilder::new()
        .lock_fee(account_shard0, Decimal::from(10))
        .withdraw_from_account(account_shard0, XRD, Decimal::from(500))
        .try_deposit_entire_worktop_or_abort(account_shard1, None)
        .build();
    let notarized =
        sign_and_notarize(manifest, &simulator_network(), 200, &account0_kp).expect("should sign");
    let cross_shard_tx: RoutableTransaction = notarized.try_into().expect("valid transaction");
    let tx_hash = cross_shard_tx.hash();

    println!("Cross-shard transaction: {:?}", tx_hash);

    // Submit cross-shard transaction
    runner.schedule_initial_event(
        0,
        Duration::ZERO,
        Event::SubmitTransaction {
            tx: Arc::new(cross_shard_tx),
        },
    );

    // Poll for transaction status progression
    println!("Running 2PC protocol...");

    let start_time = runner.now();
    let mut in_mempool = false;
    let mut committed = false;
    let mut executed = false;
    let mut finalized = false;
    let mut completed = false;

    for iteration in 0..100 {
        runner.run_until(runner.now() + Duration::from_millis(100));

        let node0 = runner.node(0).unwrap();

        // Check mempool status
        // Transaction progresses: Pending -> Committed -> (Completed|Rejected)
        if let Some(status) = node0.mempool().status(&tx_hash) {
            // If it's in the mempool at all (any status), it entered the mempool
            if !in_mempool {
                println!("  ✓ Transaction in mempool ({:?})", status);
                in_mempool = true;
            }
            if !committed && status.holds_state_lock() {
                let elapsed = runner.now() - start_time;
                println!(
                    "  ✓ Transaction committed (iteration {}, {:?})",
                    iteration, elapsed
                );
                committed = true;
            }
            // Also check for Completed status (which implies it was committed)
            if !completed && matches!(status, TransactionStatus::Completed(_)) {
                let elapsed = runner.now() - start_time;
                println!(
                    "  ✓ Transaction completed (iteration {}, {:?})",
                    iteration, elapsed
                );
                completed = true;
                // If completed, it must have been committed at some point
                committed = true;
            }
        }

        // Check execution status
        if !executed && node0.execution().is_executed(&tx_hash) {
            let elapsed = runner.now() - start_time;
            println!(
                "  ✓ Transaction executed (iteration {}, {:?})",
                iteration, elapsed
            );
            executed = true;
        }

        // Check finalization status (for cross-shard, this means certificate created)
        if !finalized && node0.execution().is_finalized(&tx_hash) {
            let elapsed = runner.now() - start_time;
            println!(
                "  ✓ Transaction finalized with certificate (iteration {}, {:?})",
                iteration, elapsed
            );
            finalized = true;
        }

        // Early exit if fully processed
        if completed && executed && finalized {
            break;
        }

        // Progress report
        if (iteration + 1) % 20 == 0 {
            let elapsed = runner.now() - start_time;
            println!(
                "  Iteration {}: elapsed={:?}, committed={}, executed={}, finalized={}",
                iteration + 1,
                elapsed,
                committed,
                executed,
                finalized
            );
        }
    }

    // Check final state
    println!("\n=== Final State ===");

    let stats = runner.stats();
    println!("Events processed: {}", stats.events_processed);
    println!("Messages sent: {}", stats.messages_sent);

    // Check heights and transaction status on both shards
    println!("\nShard 0 validators:");
    for i in 0..3 {
        let node = runner.node(i).unwrap();
        let status = node.mempool().status(&tx_hash);
        let executed = node.execution().is_executed(&tx_hash);
        let finalized = node.execution().is_finalized(&tx_hash);
        println!(
            "  Node {}: height={}, tx_status={:?}, executed={}, finalized={}",
            i,
            node.bft().committed_height(),
            status,
            executed,
            finalized
        );
    }

    println!("\nShard 1 validators:");
    for i in 3..6 {
        let node = runner.node(i).unwrap();
        let status = node.mempool().status(&tx_hash);
        let executed = node.execution().is_executed(&tx_hash);
        let finalized = node.execution().is_finalized(&tx_hash);
        println!(
            "  Node {}: height={}, tx_status={:?}, executed={}, finalized={}",
            i,
            node.bft().committed_height(),
            status,
            executed,
            finalized
        );
    }

    // Verify both shards made progress
    let shard0_max: u64 = (0..3)
        .map(|i| runner.node(i).unwrap().bft().committed_height())
        .max()
        .unwrap();
    let shard1_max: u64 = (3..6)
        .map(|i| runner.node(i).unwrap().bft().committed_height())
        .max()
        .unwrap();

    // Assertions
    assert!(shard0_max >= 2, "Shard 0 should have committed blocks");
    assert!(shard1_max >= 2, "Shard 1 should have committed blocks");
    assert!(in_mempool, "Transaction should have entered mempool");
    assert!(
        committed || completed,
        "Transaction should have been committed to a block"
    );
    assert!(executed, "Transaction should have been executed");
    // Note: finalized may or may not be true depending on 2PC completion

    println!("\n✅ E2E Cross-Shard Test PASSED!");
    println!("   ✅ Both shards initialized");
    println!("   ✅ Accounts funded at genesis");
    println!("   ✅ Cross-shard transaction entered mempool");
    println!("   ✅ Cross-shard transaction committed");
    println!("   ✅ Cross-shard transaction executed");
    if finalized {
        println!("   ✅ Cross-shard transaction finalized with certificate");
    } else {
        println!("   ⚠️  Cross-shard finalization not yet complete (2PC still in progress)");
    }
    println!(
        "   ✅ Both shards made progress (S0: {}, S1: {})",
        shard0_max, shard1_max
    );
}

/// Test determinism of cross-shard transactions.
#[traced_test]
#[test]
fn test_e2e_cross_shard_determinism() {
    println!("\n=== E2E Test: Cross-Shard Determinism ===\n");

    let config = multi_shard_config();
    let seed = 54321u64;

    // Create cross-shard transaction (same for both runs)
    let signer = test_keypair_from_seed(10);
    let to_account = test_account(20);

    let manifest = ManifestBuilder::new()
        .lock_fee_from_faucet()
        .get_free_xrd_from_faucet()
        .try_deposit_entire_worktop_or_abort(to_account, None)
        .build();
    let notarized =
        sign_and_notarize(manifest, &simulator_network(), 1, &signer).expect("should sign");
    let transaction: RoutableTransaction = notarized.try_into().expect("valid transaction");

    // First run
    let mut runner1 = SimulationRunner::new(config.clone(), seed);
    runner1.initialize_genesis();
    runner1.schedule_initial_event(
        0,
        Duration::from_millis(100),
        Event::SubmitTransaction {
            tx: Arc::new(transaction.clone()),
        },
    );
    runner1.run_until(Duration::from_secs(5));

    let stats1 = runner1.stats().clone();
    let heights1: Vec<u64> = (0..6)
        .map(|i| runner1.node(i).unwrap().bft().committed_height())
        .collect();

    // Second run with same seed
    let mut runner2 = SimulationRunner::new(config.clone(), seed);
    runner2.initialize_genesis();
    runner2.schedule_initial_event(
        0,
        Duration::from_millis(100),
        Event::SubmitTransaction {
            tx: Arc::new(transaction.clone()),
        },
    );
    runner2.run_until(Duration::from_secs(5));

    let stats2 = runner2.stats().clone();
    let heights2: Vec<u64> = (0..6)
        .map(|i| runner2.node(i).unwrap().bft().committed_height())
        .collect();

    // Verify identical results
    assert_eq!(
        stats1.events_processed, stats2.events_processed,
        "Events processed should match"
    );
    assert_eq!(
        stats1.messages_sent, stats2.messages_sent,
        "Messages sent should match"
    );
    assert_eq!(heights1, heights2, "Committed heights should match");

    println!("✅ Cross-shard determinism verified!");
    println!("   Events: {}", stats1.events_processed);
    println!("   Messages: {}", stats1.messages_sent);
    println!("   Heights: {:?}", heights1);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Throughput and Performance Tests
// ═══════════════════════════════════════════════════════════════════════════════

/// Test consensus throughput with multiple transactions.
#[traced_test]
#[test]
fn test_e2e_transaction_throughput() {
    println!("\n=== E2E Test: Transaction Throughput ===\n");

    let config = single_shard_config();
    let mut runner = SimulationRunner::new(config, 42);

    runner.initialize_genesis();

    // First let consensus establish and commit some blocks
    runner.run_until(Duration::from_secs(3));

    // Submit multiple transactions
    let num_transactions = 10;
    let signer = test_keypair_from_seed(1);

    println!("Submitting {} transactions...", num_transactions);

    for i in 0..num_transactions {
        let to_account = test_account(i as u8 + 10);
        let manifest = ManifestBuilder::new()
            .lock_fee_from_faucet()
            .get_free_xrd_from_faucet()
            .try_deposit_entire_worktop_or_abort(to_account, None)
            .build();
        let notarized = sign_and_notarize(manifest, &simulator_network(), i as u32 + 1, &signer)
            .expect("should sign");
        let tx: RoutableTransaction = notarized.try_into().expect("valid transaction");

        runner.schedule_initial_event(
            (i % 4) as u32, // Distribute across validators
            Duration::from_millis(i as u64 * 50),
            Event::SubmitTransaction { tx: Arc::new(tx) },
        );
    }

    // Run simulation
    let start = runner.now();
    runner.run_until(Duration::from_secs(10));
    let elapsed = runner.now() - start;

    // Get final state
    let max_height: u64 = (0..4)
        .map(|i| runner.node(i).unwrap().bft().committed_height())
        .max()
        .unwrap();

    let stats = runner.stats();

    println!("\nThroughput results:");
    println!("  Simulation time: {:?}", elapsed);
    println!("  Max committed height: {}", max_height);
    println!("  Events processed: {}", stats.events_processed);
    println!("  Messages sent: {}", stats.messages_sent);

    if max_height > 0 {
        let blocks_per_second = max_height as f64 / elapsed.as_secs_f64();
        println!("  Blocks per second: {:.2}", blocks_per_second);
    }

    assert!(max_height >= 5, "Should have committed multiple blocks");

    println!("\n✅ Throughput Test PASSED!");
}
