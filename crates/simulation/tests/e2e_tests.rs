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

use std::sync::Arc;
use std::time::Duration;

use hyperscale_node::shard::{HostEvent, ProcessScopedInput};
use hyperscale_simulation::{SimConfig, SimulationRunner};
use hyperscale_types::test_utils::test_validity_range;
use hyperscale_types::{
    BlockHeight, Ed25519PrivateKey, RoutableTransaction, ed25519_keypair_from_seed,
    routable_from_notarized_v1, sign_and_notarize,
};
use radix_common::crypto::Ed25519PublicKey;
use radix_common::math::Decimal;
use radix_common::network::NetworkDefinition;
use radix_common::types::ComponentAddress;
use radix_transactions::builder::ManifestBuilder;
use tracing_test::traced_test;

mod common;
use common::{
    build_cross_shard_transfer, cross_shard_grow_config, find_accounts_on_each_shard, grown_leaves,
    submit_to_shard,
};

/// Create a basic single-shard network configuration.
fn single_shard_config() -> SimConfig {
    SimConfig {
        validators_per_shard: 4,
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

/// Get the simulator network definition.
const fn simulator_network() -> NetworkDefinition {
    NetworkDefinition::simulator()
}

// ═══════════════════════════════════════════════════════════════════════════════
// Single-Shard Transaction Tests
// ═══════════════════════════════════════════════════════════════════════════════

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
    let transaction: RoutableTransaction =
        routable_from_notarized_v1(notarized, test_validity_range()).expect("valid transaction");

    // First run
    let mut runner1 = SimulationRunner::new(&config, seed);
    runner1.initialize_genesis();
    runner1.schedule_initial_event(
        0,
        Duration::from_millis(100),
        HostEvent::process(ProcessScopedInput::SubmitTransaction {
            tx: Arc::new(transaction.clone()),
        }),
    );
    runner1.run_until(Duration::from_secs(5));

    let stats1 = runner1.stats().clone();
    let heights1: Vec<BlockHeight> = (0..4)
        .map(|i| {
            runner1
                .node(i)
                .unwrap()
                .shard_coordinator()
                .committed_height()
        })
        .collect();

    // Second run with same seed
    let mut runner2 = SimulationRunner::new(&config, seed);
    runner2.initialize_genesis();
    runner2.schedule_initial_event(
        0,
        Duration::from_millis(100),
        HostEvent::process(ProcessScopedInput::SubmitTransaction {
            tx: Arc::new(transaction),
        }),
    );
    runner2.run_until(Duration::from_secs(5));

    let stats2 = runner2.stats().clone();
    let heights2: Vec<BlockHeight> = (0..4)
        .map(|i| {
            runner2
                .node(i)
                .unwrap()
                .shard_coordinator()
                .committed_height()
        })
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
    println!("   Heights: {heights1:?}");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Cross-Shard Transaction Tests
// ═══════════════════════════════════════════════════════════════════════════════

/// Two same-seed runs of genesis → `grow_to(2)` → cross-shard transfer must
/// produce identical committed heights and event/message counts: the split
/// lifecycle and the cross-shard execution are deterministic.
#[traced_test]
#[test]
fn test_e2e_cross_shard_determinism() {
    let run = |seed: u64| -> (Vec<BlockHeight>, u64, u64) {
        let mut runner = SimulationRunner::new(&cross_shard_grow_config(), seed);
        let ((kp_a, acc_a), (_kp_b, acc_b)) = find_accounts_on_each_shard(2);
        runner.initialize_genesis_with_balances(&[
            (acc_a, Decimal::from(10_000)),
            (acc_b, Decimal::from(10_000)),
        ]);
        runner.grow_to(2);

        let leaves = grown_leaves();
        let tx = build_cross_shard_transfer(&kp_a, acc_a, acc_b, runner.now());
        submit_to_shard(&mut runner, leaves[0], tx);
        let until = runner.now() + Duration::from_secs(60);
        runner.run_until(until);

        let heights: Vec<BlockHeight> = leaves
            .iter()
            .flat_map(|&leaf| {
                runner
                    .shard_vnodes(leaf)
                    .into_iter()
                    .map(|v| v.shard_coordinator().committed_height())
                    .collect::<Vec<_>>()
            })
            .collect();
        let stats = runner.stats();
        (heights, stats.events_processed, stats.messages_sent)
    };
    assert_eq!(
        run(54321),
        run(54321),
        "same-seed grow + cross-shard runs must be identical",
    );
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
    let mut runner = SimulationRunner::new(&config, 42);

    runner.initialize_genesis();

    // First let consensus establish and commit some blocks
    runner.run_until(Duration::from_secs(3));

    // Submit multiple transactions
    let num_transactions = 10;
    let signer = test_keypair_from_seed(1);

    println!("Submitting {num_transactions} transactions...");

    for i in 0..num_transactions {
        let to_account = test_account(u8::try_from(i).unwrap_or(u8::MAX) + 10);
        let manifest = ManifestBuilder::new()
            .lock_fee_from_faucet()
            .get_free_xrd_from_faucet()
            .try_deposit_entire_worktop_or_abort(to_account, None)
            .build();
        let notarized = sign_and_notarize(
            manifest,
            &simulator_network(),
            u32::try_from(i).unwrap_or(u32::MAX) + 1,
            &signer,
        )
        .expect("should sign");
        let tx: RoutableTransaction = routable_from_notarized_v1(notarized, test_validity_range())
            .expect("valid transaction");

        runner.schedule_initial_event(
            u32::try_from(i % 4).unwrap_or(0), // Distribute across validators
            Duration::from_millis(u64::try_from(i).unwrap_or(u64::MAX) * 50),
            HostEvent::process(ProcessScopedInput::SubmitTransaction { tx: Arc::new(tx) }),
        );
    }

    // Run simulation. After the 3s warmup we only need a few more blocks past
    // the BlockHeight::new(5) assertion floor; ~1 block/sec means 5s is sufficient.
    let start = runner.now();
    runner.run_until(Duration::from_secs(5));
    let elapsed = runner.now().checked_sub(start).unwrap();

    // Get final state
    let max_height: BlockHeight = (0..4)
        .map(|i| {
            runner
                .node(i)
                .unwrap()
                .shard_coordinator()
                .committed_height()
        })
        .max()
        .unwrap();

    let stats = runner.stats();

    println!("\nThroughput results:");
    println!("  Simulation time: {elapsed:?}");
    println!("  Max committed height: {max_height}");
    println!("  Events processed: {}", stats.events_processed);
    println!("  Messages sent: {}", stats.messages_sent);

    if max_height > BlockHeight::GENESIS {
        #[allow(clippy::cast_precision_loss)] // headline throughput stat for human-readable output
        let blocks_per_second = max_height.inner() as f64 / elapsed.as_secs_f64();
        println!("  Blocks per second: {blocks_per_second:.2}");
    }

    assert!(
        max_height >= BlockHeight::new(5),
        "Should have committed multiple blocks"
    );

    println!("\n✅ Throughput Test PASSED!");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Wave Leader Failure Recovery
// ═══════════════════════════════════════════════════════════════════════════════

/// Test that transactions complete when one validator is isolated.
///
/// With 4 validators and quorum=3, isolating one validator still allows shard consensus
/// progress. If the isolated node is the wave leader for a wave, the vote
/// retry rotation mechanism should recover: non-leaders timeout, re-send
/// to a rotated leader, and the EC is formed by the fallback leader.
///
/// We isolate each node in turn (4 runs) to ensure at least one run hits
/// the case where the isolated node is the wave leader.
#[traced_test]
#[test]
fn test_wave_leader_failure_recovers_via_rotation() {
    for isolated_node in 0..4u32 {
        println!("\n=== Wave Leader Failure Test: isolating node {isolated_node} ===\n");

        let config = single_shard_config();
        let mut runner = SimulationRunner::new(&config, 42 + u64::from(isolated_node));
        runner.initialize_genesis();

        // Let consensus establish first.
        runner.run_until(Duration::from_secs(1));

        // Isolate one node — it can neither send nor receive.
        runner.network_mut().isolate_node(isolated_node);
        println!("Node {isolated_node} isolated");

        // Submit a transaction to a non-isolated node.
        let submit_node = u32::from(isolated_node == 0);
        let signer = test_keypair_from_seed(50 + u8::try_from(isolated_node).unwrap_or(u8::MAX));
        let to_account = test_account(100 + u8::try_from(isolated_node).unwrap_or(u8::MAX));

        let manifest = ManifestBuilder::new()
            .lock_fee_from_faucet()
            .get_free_xrd_from_faucet()
            .try_deposit_entire_worktop_or_abort(to_account, None)
            .build();
        let notarized =
            sign_and_notarize(manifest, &simulator_network(), 300 + isolated_node, &signer)
                .expect("should sign");
        let transaction: RoutableTransaction =
            routable_from_notarized_v1(notarized, test_validity_range())
                .expect("valid transaction");
        let tx_hash = transaction.hash();

        runner.schedule_initial_event(
            submit_node,
            Duration::ZERO,
            HostEvent::process(ProcessScopedInput::SubmitTransaction {
                tx: Arc::new(transaction),
            }),
        );

        // Run long enough for:
        // - Transaction to be committed in a block
        // - Vote retry timeout (`VOTE_RETRY_TIMEOUT = 8s`)
        // - Fallback leader to aggregate and broadcast EC
        // - Wave certificate to be finalized
        let mut reached_terminal = false;
        for _ in 0..600 {
            runner.run_until(runner.now() + Duration::from_millis(100));
            let status = runner
                .node(submit_node)
                .unwrap()
                .mempool_coordinator()
                .status(&tx_hash);
            match &status {
                Some(s) if s.is_final() => {
                    println!("Transaction reached terminal state: {s:?}");
                    reached_terminal = true;
                    break;
                }
                None => {
                    // Evicted = terminal (completed and cleaned up).
                    println!("Transaction evicted (terminal)");
                    reached_terminal = true;
                    break;
                }
                _ => {}
            }
        }

        let max_height: BlockHeight = (0..4)
            .map(|i| {
                runner
                    .node(i)
                    .unwrap()
                    .shard_coordinator()
                    .committed_height()
            })
            .max()
            .unwrap();
        println!(
            "Max committed height: {}, isolated node {} height: {}",
            max_height,
            isolated_node,
            runner
                .node(isolated_node)
                .unwrap()
                .shard_coordinator()
                .committed_height()
        );

        assert!(
            reached_terminal,
            "Transaction should reach terminal state even with node {isolated_node} isolated (max_height={max_height})"
        );

        println!("✅ Node {isolated_node} isolated — transaction completed via fallback\n");
    }
}
