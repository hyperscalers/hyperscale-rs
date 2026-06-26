//! End-to-end integration tests on the simulation harness.
//!
//! Each test builds a [`SimCluster`] and drives it through the portable
//! [`Cluster`] surface — submit, `run_until`, and the synchronous observations —
//! reaching for `runner()` / `runner_mut()` only for the white-box reads and
//! mutations (raw stores, host-targeted submission, network faults) the trait
//! deliberately doesn't model. `run_until` predicates are condition-based, so
//! each returns at the slice its condition holds rather than burning a full
//! epoch budget.

mod support;

use std::sync::Arc;
use std::time::Duration;

use hyperscale_node::shard::{HostEvent, ProcessScopedInput};
use hyperscale_scenarios::tx::{
    account_from_seed, build_transfer_tx, signer_from_seed, validity_around,
};
use hyperscale_scenarios::{Cluster, ScenarioConfig, epochs, grow_to};
use hyperscale_types::test_utils::test_validity_range;
use hyperscale_types::{
    BlockHeight, Ed25519PrivateKey, NodeId, ShardId, TransactionStatus, routable_from_notarized_v1,
    sign_and_notarize, uniform_shard_for_node,
};
use radix_common::crypto::Ed25519PublicKey;
use radix_common::math::Decimal;
use radix_common::network::NetworkDefinition;
use radix_common::types::ComponentAddress;
use radix_transactions::builder::ManifestBuilder;
use support::sim_cluster::SimCluster;
use tracing_test::traced_test;

/// A four-validator single-shard network with reshaping disabled — the shape the
/// single-shard tests run on, so pumping the reshape orchestrator each slice is a
/// no-op.
const fn single_shard_config() -> ScenarioConfig {
    ScenarioConfig {
        validators_per_shard: 4,
        vnodes_per_host: 1,
        pool_surplus: 0,
        num_shards: 1,
        split_bytes: u64::MAX,
        latency: Duration::from_millis(150),
        dedicated_hosts: false,
    }
}

/// A deterministic deposit-only account address from a seed — a "fake" public
/// key with no matching signing key, fine as a transfer recipient.
fn test_account(seed: u8) -> ComponentAddress {
    let pk = Ed25519PublicKey([seed; 32]);
    ComponentAddress::preallocated_account_from_public_key(&pk)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Cross-Shard Transaction Tests
// ═══════════════════════════════════════════════════════════════════════════════

/// Single-shard genesis with the split trigger armed and one cohort of pool
/// surplus, the shape [`grow_to`] drives to two shards.
const fn cross_shard_config() -> ScenarioConfig {
    ScenarioConfig {
        validators_per_shard: 4,
        vnodes_per_host: 1,
        pool_surplus: 4,
        num_shards: 1,
        split_bytes: 0,
        latency: Duration::from_millis(150),
        dedicated_hosts: false,
    }
}

/// The first seed whose preallocated account routes to `leaf` under a two-shard
/// trie, with its signing key.
fn account_on_leaf(leaf: ShardId) -> (Ed25519PrivateKey, ComponentAddress) {
    for seed in 1u8..=u8::MAX {
        let account = account_from_seed(seed);
        let radix_node = account.into_node_id();
        let node = NodeId(
            radix_node.0[..30]
                .try_into()
                .expect("account address carries a 30-byte node id"),
        );
        if uniform_shard_for_node(&node, 2) == leaf {
            return (signer_from_seed(seed), account);
        }
    }
    panic!("no account routes to {leaf:?}");
}

/// Two same-seed runs of genesis → grow to two shards → cross-shard transfer must
/// produce identical committed heights and event/message counts: the split
/// lifecycle and the cross-shard execution are deterministic.
#[traced_test]
#[test]
fn test_e2e_cross_shard_determinism() {
    let run = |seed: u64| -> (Vec<BlockHeight>, u64, u64) {
        let (kp_a, acc_a) = account_on_leaf(ShardId::leaf(1, 0));
        let (_kp_b, acc_b) = account_on_leaf(ShardId::leaf(1, 1));
        let balances = [
            (acc_a, Decimal::from(10_000)),
            (acc_b, Decimal::from(10_000)),
        ];
        let mut cluster = SimCluster::with_balances(&cross_shard_config(), seed, &balances);
        grow_to(&mut cluster, 2);

        let tx = build_transfer_tx(
            &kp_a,
            acc_a,
            acc_b,
            Decimal::from(500),
            &NetworkDefinition::simulator(),
            1,
            validity_around(cluster.now()),
        );
        let tx_hash = tx.hash();
        cluster.submit(Arc::new(tx));
        // Advance to the same deterministic point in both runs — settlement, or
        // the budget cap if it never settles; either is identical per seed.
        cluster.run_until(epochs(4), |c| {
            matches!(c.tx_status(tx_hash), Some(TransactionStatus::Completed(_)))
        });

        let runner = cluster.runner();
        let heights: Vec<BlockHeight> = [ShardId::leaf(1, 0), ShardId::leaf(1, 1)]
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

/// Consensus commits a run of blocks while ten transactions are submitted across
/// the committee — a basic throughput-under-load liveness check.
#[traced_test]
#[test]
fn test_e2e_transaction_throughput() {
    let mut cluster = SimCluster::new(&single_shard_config(), 42);

    let signer = signer_from_seed(1);
    for i in 0..10u32 {
        let to_account = test_account(u8::try_from(i).unwrap_or(u8::MAX) + 10);
        let manifest = ManifestBuilder::new()
            .lock_fee_from_faucet()
            .get_free_xrd_from_faucet()
            .try_deposit_entire_worktop_or_abort(to_account, None)
            .build();
        let notarized =
            sign_and_notarize(manifest, &NetworkDefinition::simulator(), i + 1, &signer)
                .expect("should sign");
        let tx = routable_from_notarized_v1(notarized, test_validity_range()).expect("valid");

        cluster.runner_mut().schedule_initial_event(
            i % 4, // distribute across validators
            Duration::from_millis(u64::from(i) * 50),
            HostEvent::process(ProcessScopedInput::SubmitTransaction { tx: Arc::new(tx) }),
        );
    }

    let committed_enough = cluster.run_until(epochs(2), |c| {
        c.committed_height(ShardId::ROOT)
            .is_some_and(|h| h >= BlockHeight::new(5))
    });
    assert!(
        committed_enough,
        "consensus should commit multiple blocks under transaction load",
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Wave Leader Failure Recovery
// ═══════════════════════════════════════════════════════════════════════════════

/// A transaction completes when one validator is isolated.
///
/// With four validators and quorum three, isolating one still allows shard
/// consensus to progress. If the isolated node is the wave leader for a wave, the
/// vote-retry rotation recovers: non-leaders time out, re-send to a rotated
/// leader, and the certificate is formed by the fallback. Each node is isolated in
/// turn (four runs) so at least one run isolates the wave leader.
#[traced_test]
#[test]
fn test_wave_leader_failure_recovers_via_rotation() {
    for isolated_node in 0..4u32 {
        let mut cluster = SimCluster::new(&single_shard_config(), 42 + u64::from(isolated_node));

        // Let consensus commit at least one block before isolating a node.
        cluster.run_until(epochs(1), |c| {
            c.committed_height(ShardId::ROOT)
                .is_some_and(|h| h >= BlockHeight::new(1))
        });
        cluster
            .runner_mut()
            .network_mut()
            .isolate_node(isolated_node);

        // Submit to a non-isolated node.
        let submit_node = u32::from(isolated_node == 0);
        let signer = signer_from_seed(50 + u8::try_from(isolated_node).unwrap_or(u8::MAX));
        let to_account = test_account(100 + u8::try_from(isolated_node).unwrap_or(u8::MAX));
        let manifest = ManifestBuilder::new()
            .lock_fee_from_faucet()
            .get_free_xrd_from_faucet()
            .try_deposit_entire_worktop_or_abort(to_account, None)
            .build();
        let notarized = sign_and_notarize(
            manifest,
            &NetworkDefinition::simulator(),
            300 + isolated_node,
            &signer,
        )
        .expect("should sign");
        let tx = routable_from_notarized_v1(notarized, test_validity_range()).expect("valid");
        let tx_hash = tx.hash();
        cluster.runner_mut().schedule_initial_event(
            submit_node,
            Duration::ZERO,
            HostEvent::process(ProcessScopedInput::SubmitTransaction { tx: Arc::new(tx) }),
        );

        // The fallback rotation (vote-retry timeout ~8s) completes the wave on the
        // non-isolated quorum, so the cluster-wide status reaches Completed.
        let completed = cluster.run_until(epochs(3), |c| {
            matches!(c.tx_status(tx_hash), Some(TransactionStatus::Completed(_)))
        });
        assert!(
            completed,
            "transaction should complete even with node {isolated_node} isolated",
        );
    }
}
