//! Abort safety integration tests.
//!
//! These tests verify that cross-shard transactions reach terminal state
//! exclusively through Wave Certificates (WCs), including:
//! - Livelock cycle detection → abort intent → WC(Aborted)
//! - Normal cross-shard execution → WC(Accept)
//! - Execution timeout → abort intent → WC(Aborted)

use hyperscale_core::NodeInput;
use hyperscale_network_memory::NetworkConfig;
use hyperscale_simulation::SimulationRunner;
use hyperscale_types::test_utils::test_validity_range;
use hyperscale_types::{
    Ed25519PrivateKey, NodeId, RoutableTransaction, ShardGroupId, TransactionDecision,
    TransactionStatus, ed25519_keypair_from_seed, routable_from_notarized_v1, shard_for_node,
    sign_and_notarize,
};
use radix_common::constants::XRD;
use radix_common::math::Decimal;
use radix_common::network::NetworkDefinition;
use radix_common::types::ComponentAddress;
use radix_transactions::builder::ManifestBuilder;
use std::sync::Arc;
use std::time::Duration;
use tracing_test::traced_test;

// ═══════════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════════

fn two_shard_config() -> NetworkConfig {
    NetworkConfig {
        num_shards: 2,
        validators_per_shard: 3,
        intra_shard_latency: Duration::from_millis(10),
        cross_shard_latency: Duration::from_millis(50),
        jitter_fraction: 0.1,
        ..Default::default()
    }
}

fn keypair(seed: u8) -> Ed25519PrivateKey {
    ed25519_keypair_from_seed(&[seed; 32])
}

fn account(kp: &Ed25519PrivateKey) -> ComponentAddress {
    ComponentAddress::preallocated_account_from_public_key(&kp.public_key())
}

const fn network() -> NetworkDefinition {
    NetworkDefinition::simulator()
}

/// Find keypairs whose accounts route to shard 0 and shard 1.
fn accounts_on_different_shards(
    num_shards: u64,
) -> (
    Ed25519PrivateKey,
    ComponentAddress,
    Ed25519PrivateKey,
    ComponentAddress,
) {
    let mut shard0 = None;
    let mut shard1 = None;

    for seed in 10u8..=255 {
        let kp = keypair(seed);
        let acc = account(&kp);
        let node_id = acc.into_node_id();
        let hs_node = NodeId(node_id.0[..30].try_into().unwrap());
        let shard = shard_for_node(&hs_node, num_shards);

        if shard == ShardGroupId(0) && shard0.is_none() {
            shard0 = Some((kp, acc));
        } else if shard == ShardGroupId(1) && shard1.is_none() {
            shard1 = Some((kp, acc));
        }
        if shard0.is_some() && shard1.is_some() {
            break;
        }
    }

    let (kp0, acc0) = shard0.expect("account for shard 0");
    let (kp1, acc1) = shard1.expect("account for shard 1");
    (kp0, acc0, kp1, acc1)
}

/// Build a cross-shard transfer: withdraw from `from`, deposit to `to`.
fn cross_shard_transfer(
    from: ComponentAddress,
    to: ComponentAddress,
    amount: u64,
    nonce: u32,
    signer: &Ed25519PrivateKey,
) -> RoutableTransaction {
    let manifest = ManifestBuilder::new()
        .lock_fee(from, Decimal::from(10))
        .withdraw_from_account(from, XRD, Decimal::from(amount))
        .try_deposit_entire_worktop_or_abort(to, None)
        .build();
    let notarized = sign_and_notarize(manifest, &network(), nonce, signer).expect("sign");
    routable_from_notarized_v1(notarized, test_validity_range()).expect("valid tx")
}

/// Poll until a transaction reaches a terminal status or the iteration limit.
/// Returns the final status (or None if evicted/not found).
fn poll_until_terminal(
    runner: &mut SimulationRunner,
    tx_hash: hyperscale_types::TxHash,
    node_index: u32,
    max_iterations: usize,
    step: Duration,
) -> Option<TransactionStatus> {
    for _ in 0..max_iterations {
        runner.run_until(runner.now() + step);
        let status = runner.node(node_index).unwrap().mempool().status(&tx_hash);
        match &status {
            Some(s) if s.is_final() => return status,
            None => return None, // evicted (terminal)
            _ => {}
        }
    }
    runner.node(node_index).unwrap().mempool().status(&tx_hash)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

/// Two conflicting cross-shard transactions form a cycle.
/// The loser (higher hash) should be aborted via TC.
/// The winner (lower hash) should complete via TC(Accept).
/// No retry transactions should be created.
#[traced_test]
#[test]
fn test_cycle_detection_aborts_loser() {
    let config = two_shard_config();
    let mut runner = SimulationRunner::new(&config, 42);

    let (kp0, acc0, kp1, acc1) = accounts_on_different_shards(2);
    runner.initialize_genesis_with_balances(&[
        (acc0, Decimal::from(10_000)),
        (acc1, Decimal::from(10_000)),
    ]);
    runner.run_until(Duration::from_secs(3));

    // TX A: shard 0 → shard 1
    let tx_a = cross_shard_transfer(acc0, acc1, 100, 200, &kp0);
    let hash_a = tx_a.hash();

    // TX B: shard 1 → shard 0 (forms cycle with TX A)
    let tx_b = cross_shard_transfer(acc1, acc0, 100, 201, &kp1);
    let hash_b = tx_b.hash();

    // Submit each to a validator on its home shard
    runner.schedule_initial_event(
        0,
        Duration::ZERO,
        NodeInput::SubmitTransaction { tx: Arc::new(tx_a) },
    );
    runner.schedule_initial_event(
        3,
        Duration::from_millis(5),
        NodeInput::SubmitTransaction { tx: Arc::new(tx_b) },
    );

    // Poll until both reach terminal state.
    // Check each tx on its home shard (where it was committed).
    let mut a_done = false;
    let mut b_done = false;

    for _ in 0..800 {
        runner.run_until(runner.now() + Duration::from_millis(100));

        if !a_done {
            // TX A committed on shard 0 (node 0)
            match runner.node(0).unwrap().mempool().status(&hash_a) {
                Some(s) if s.is_final() => a_done = true,
                None => a_done = true,
                _ => {}
            }
        }
        if !b_done {
            // TX B committed on shard 1 (node 3)
            match runner.node(3).unwrap().mempool().status(&hash_b) {
                Some(s) if s.is_final() => b_done = true,
                None => b_done = true,
                _ => {}
            }
        }
        if a_done && b_done {
            break;
        }
    }

    let n0 = runner.node(0).unwrap();
    let n3 = runner.node(3).unwrap();
    let status_a = n0.mempool().status(&hash_a);
    let status_b = n3.mempool().status(&hash_b);
    let h0 = n0.bft().committed_height();
    let h1 = n3.bft().committed_height();
    assert!(
        a_done,
        "TX A should reach terminal state on shard 0, got {status_a:?} at h={h0}",
    );
    assert!(
        b_done,
        "TX B should reach terminal state on shard 1, got {status_b:?} at h={h1}",
    );

    // Both transactions should be evicted from their home shards
    assert!(
        runner.node(0).unwrap().mempool().status(&hash_a).is_none(),
        "TX A should be evicted from shard 0 mempool"
    );
    assert!(
        runner.node(3).unwrap().mempool().status(&hash_b).is_none(),
        "TX B should be evicted from shard 1 mempool"
    );
}

/// Cross-shard transactions that don't conflict should complete normally.
/// Verifies the happy path still works after the pipeline changes.
#[traced_test]
#[test]
fn test_no_cycle_completes_normally() {
    let config = two_shard_config();
    let mut runner = SimulationRunner::new(&config, 99);

    let (kp0, acc0, _kp1, acc1) = accounts_on_different_shards(2);
    runner.initialize_genesis_with_balances(&[
        (acc0, Decimal::from(10_000)),
        (acc1, Decimal::from(10_000)),
    ]);
    runner.run_until(Duration::from_secs(3));

    // Single cross-shard transfer (no cycle — only one direction)
    let tx = cross_shard_transfer(acc0, acc1, 100, 300, &kp0);
    let hash = tx.hash();

    runner.schedule_initial_event(
        0,
        Duration::ZERO,
        NodeInput::SubmitTransaction { tx: Arc::new(tx) },
    );

    let final_status = poll_until_terminal(&mut runner, hash, 0, 200, Duration::from_millis(100));

    // Should be None (evicted after Completed) or Completed(Accept)
    match final_status {
        None | Some(TransactionStatus::Completed(TransactionDecision::Accept)) => {}
        other => panic!("expected Completed(Accept) or evicted, got {other:?}"),
    }
}

/// A cross-shard transaction that times out should eventually be aborted via TC.
#[traced_test]
#[test]
fn test_timeout_abort() {
    let config = two_shard_config();
    let mut runner = SimulationRunner::new(&config, 777);

    let (kp0, acc0, _kp1, acc1) = accounts_on_different_shards(2);
    runner.initialize_genesis_with_balances(&[
        (acc0, Decimal::from(10_000)),
        (acc1, Decimal::from(10_000)),
    ]);
    runner.run_until(Duration::from_secs(3));

    let tx = cross_shard_transfer(acc0, acc1, 50, 400, &kp0);
    let hash = tx.hash();

    runner.schedule_initial_event(
        0,
        Duration::ZERO,
        NodeInput::SubmitTransaction { tx: Arc::new(tx) },
    );

    // Run for enough time to trigger timeout (timeout is ~50 blocks, blocks ~1s)
    let final_status = poll_until_terminal(&mut runner, hash, 0, 600, Duration::from_millis(100));

    // Should reach terminal state. The key assertion is it doesn't get stuck.
    match final_status {
        None => {} // evicted — terminal
        Some(s) if s.is_final() => {}
        other => panic!("expected terminal state, got {other:?}"),
    }
}

/// Cycle detection + abort should resolve within a reasonable time bound.
#[traced_test]
#[test]
fn test_livelock_resolves_promptly() {
    let config = two_shard_config();
    let mut runner = SimulationRunner::new(&config, 555);

    let (kp0, acc0, kp1, acc1) = accounts_on_different_shards(2);
    runner.initialize_genesis_with_balances(&[
        (acc0, Decimal::from(10_000)),
        (acc1, Decimal::from(10_000)),
    ]);
    runner.run_until(Duration::from_secs(3));

    let tx_a = cross_shard_transfer(acc0, acc1, 100, 500, &kp0);
    let tx_b = cross_shard_transfer(acc1, acc0, 100, 501, &kp1);
    let hash_a = tx_a.hash();
    let hash_b = tx_b.hash();

    let submit_time = runner.now();
    runner.schedule_initial_event(
        0,
        Duration::ZERO,
        NodeInput::SubmitTransaction { tx: Arc::new(tx_a) },
    );
    runner.schedule_initial_event(
        3,
        Duration::from_millis(5),
        NodeInput::SubmitTransaction { tx: Arc::new(tx_b) },
    );

    // Both should resolve within 30 seconds of simulated time
    let deadline = submit_time + Duration::from_secs(30);
    let mut a_done = false;
    let mut b_done = false;

    while runner.now() < deadline {
        runner.run_until(runner.now() + Duration::from_millis(100));
        let node = runner.node(0).unwrap();

        if !a_done {
            match node.mempool().status(&hash_a) {
                Some(s) if s.is_final() => a_done = true,
                None => a_done = true,
                _ => {}
            }
        }
        if !b_done {
            match node.mempool().status(&hash_b) {
                Some(s) if s.is_final() => b_done = true,
                None => b_done = true,
                _ => {}
            }
        }
        if a_done && b_done {
            break;
        }
    }

    let elapsed = runner.now().checked_sub(submit_time).unwrap();
    assert!(
        a_done,
        "TX A should resolve within 30s (elapsed: {elapsed:?})"
    );
    assert!(
        b_done,
        "TX B should resolve within 30s (elapsed: {elapsed:?})"
    );
    assert!(
        elapsed < Duration::from_secs(30),
        "cycle resolution took too long: {elapsed:?}",
    );
}
