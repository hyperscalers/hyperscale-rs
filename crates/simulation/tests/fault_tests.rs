//! Fetch-fallback simulation tests.
//!
//! Each test installs a [`FaultRule`] suppressing a primary delivery
//! channel, then asserts three layers of recovery:
//! 1. The fault rule actually fired (rule misconfiguration guard).
//! 2. The fallback fetch path engaged (`fetch_started` counter).
//! 3. End-to-end liveness: submitted transactions reach a terminal
//!    state on every node.

use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use hyperscale_core::NodeInput;
use hyperscale_metrics_memory::MemoryRecorder;
use hyperscale_network_memory::NetworkConfig;
use hyperscale_simulation::SimulationRunner;
use hyperscale_types::test_utils::test_validity_range;
use hyperscale_types::{
    BlockHeight, Ed25519PrivateKey, NodeId, RoutableTransaction, ShardGroupId,
    ed25519_keypair_from_seed, routable_from_notarized_v1, shard_for_node, sign_and_notarize,
};
use radix_common::constants::XRD;
use radix_common::crypto::Ed25519PublicKey;
use radix_common::math::Decimal;
use radix_common::network::NetworkDefinition;
use radix_common::types::ComponentAddress;
use radix_transactions::builder::ManifestBuilder;
use tracing_test::traced_test;

/// Serialize tests in this binary: the global metrics recorder is a
/// process-wide `OnceLock`, and counters from one test would otherwise
/// leak into another running in parallel.
fn test_setup() -> (MutexGuard<'static, ()>, MemoryRecorder) {
    static LOCK: Mutex<()> = Mutex::new(());
    static RECORDER: OnceLock<MemoryRecorder> = OnceLock::new();
    let guard = LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let recorder = RECORDER
        .get_or_init(|| {
            let r = MemoryRecorder::new();
            hyperscale_metrics::set_global_recorder(Box::new(r.clone()));
            r
        })
        .clone();
    recorder.reset();
    (guard, recorder)
}

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

fn account_from_keypair(kp: &Ed25519PrivateKey) -> ComponentAddress {
    ComponentAddress::preallocated_account_from_public_key(&kp.public_key())
}

/// Find one funded keypair for each of two shards (0 and 1).
fn find_accounts_on_each_shard(
    num_shards: u64,
) -> (
    (Ed25519PrivateKey, ComponentAddress),
    (Ed25519PrivateKey, ComponentAddress),
) {
    let mut shard0 = None;
    let mut shard1 = None;
    for seed in 10u8..=255 {
        let kp = keypair_from_seed(seed);
        let acc = account_from_keypair(&kp);
        let radix_node_id = acc.into_node_id();
        let hs_node_id = NodeId(radix_node_id.0[..30].try_into().unwrap());
        let shard = shard_for_node(&hs_node_id, num_shards);
        if shard == ShardGroupId(0) && shard0.is_none() {
            shard0 = Some((kp, acc));
        } else if shard == ShardGroupId(1) && shard1.is_none() {
            shard1 = Some((kp, acc));
        }
        if shard0.is_some() && shard1.is_some() {
            // Both populated; safe to take.
            return (
                shard0.take().expect("shard0 just confirmed populated"),
                shard1.take().expect("shard1 just confirmed populated"),
            );
        }
    }
    panic!("could not find accounts on both shards within seed range");
}

fn keypair_from_seed(seed: u8) -> Ed25519PrivateKey {
    ed25519_keypair_from_seed(&[seed; 32])
}

fn account_from_seed(seed: u8) -> ComponentAddress {
    ComponentAddress::preallocated_account_from_public_key(&Ed25519PublicKey([seed; 32]))
}

fn build_transfer_tx(signer_seed: u8, recipient_seed: u8) -> RoutableTransaction {
    let signer = keypair_from_seed(signer_seed);
    let to = account_from_seed(recipient_seed);
    let manifest = ManifestBuilder::new()
        .lock_fee_from_faucet()
        .get_free_xrd_from_faucet()
        .try_deposit_entire_worktop_or_abort(to, None)
        .build();
    let notarized = sign_and_notarize(
        manifest,
        &NetworkDefinition::simulator(),
        u32::from(signer_seed),
        &signer,
    )
    .expect("sign tx");
    routable_from_notarized_v1(notarized, test_validity_range()).expect("valid tx")
}

/// Returns `true` if the node has reached a terminal state for `tx_hash`
/// (executed or tombstoned post-eviction). Does not distinguish between
/// success and abort — pair with `transactions_aborted` counter when the
/// distinction matters.
fn tx_reached_terminal_state(
    runner: &SimulationRunner,
    node_idx: u32,
    tx_hash: &hyperscale_types::TxHash,
) -> bool {
    let node = runner.node(node_idx).expect("node exists");
    node.execution().is_finalized(tx_hash) || node.mempool().is_tombstoned(tx_hash)
}

#[traced_test]
#[test]
fn transaction_fetch_fallback_when_gossip_dropped() {
    let (_guard, recorder) = test_setup();

    let mut runner = SimulationRunner::new(&single_shard_config(), 42);
    runner.initialize_genesis();

    // Suppress all transaction.gossip across the network. The submitting
    // node (0) still admits the tx locally, includes it in any block it
    // proposes, and serves it to followers via GetTransactionsRequest.
    let rule = runner
        .network_mut()
        .fault()
        .drop_type("transaction.gossip")
        .install();

    let tx = build_transfer_tx(1, 2);
    let tx_hash = tx.hash();
    runner.schedule_initial_event(
        0,
        Duration::ZERO,
        NodeInput::SubmitTransaction { tx: Arc::new(tx) },
    );

    runner.run_until(Duration::from_secs(10));

    // Layer 1: fault rule actually intercepted gossip.
    assert!(
        rule.fired() >= 1,
        "expected drop_type(\"transaction.gossip\") rule to fire at least once, got {}",
        rule.fired()
    );

    // Layer 2: the fetch fallback path engaged. `fetch_items_sent` is
    // recorded by the serve handler when it answers a fetch request, so a
    // non-zero value proves at least one fetch round-trip completed
    // successfully. (`fetch_started`/`fetch_completed` are not yet wired
    // client-side; see `crates/node/src/protocol/fetch.rs`.)
    let fetch_items_sent = recorder.counter("fetch_items_sent", Some("transaction"));
    assert!(
        fetch_items_sent >= 1,
        "expected fetch_items_sent{{kind=\"transaction\"}} >= 1, got {fetch_items_sent}"
    );

    // Layer 3: end-to-end — every node finalized the tx and the chain
    // advanced past genesis.
    for node_idx in 0..4u32 {
        assert!(
            tx_reached_terminal_state(&runner, node_idx, &tx_hash),
            "node {node_idx} did not reach terminal state for tx {tx_hash:?}; \
             gossip drops fired {} times, fetch_items_sent={fetch_items_sent}",
            rule.fired()
        );
    }

    let max_height = (0..4)
        .map(|i| runner.node(i).unwrap().bft().committed_height())
        .max()
        .unwrap();
    assert!(
        max_height > BlockHeight(0),
        "expected chain to advance past genesis, got max height {max_height}"
    );
}

/// Cross-shard provisions fetch fallback. The source-shard proposer
/// normally broadcasts `provisions.broadcast` to target shards alongside
/// its block proposal; suppressing it forces the target shard to fetch
/// provisions via `GetProvisionsRequest` against the source-shard
/// committee.
///
/// Liveness criterion: the cross-shard transaction reaches terminal state
/// on every validator in both shards AND was *successfully executed* (not
/// aborted) — verified via `transactions_aborted == 0`.
#[test]
fn cross_shard_provisions_fetch_fallback_when_broadcast_dropped() {
    let (_guard, recorder) = test_setup();

    let config = multi_shard_config();
    let num_shards = u64::from(config.num_shards);
    let mut runner = SimulationRunner::new(&config, 42);

    let ((kp_a, acc_a), (_kp_b, acc_b)) = find_accounts_on_each_shard(num_shards);
    let initial_balance = Decimal::from(10_000);
    runner.initialize_genesis_with_balances(&[(acc_a, initial_balance), (acc_b, initial_balance)]);

    // Let consensus warm up before installing the fault — gives genesis
    // header propagation a chance to land cleanly.
    runner.run_until(Duration::from_secs(1));

    // Drop the cross-shard provisions notification globally. The source
    // shard still produces provisions; the target shard must fetch.
    let rule = runner
        .network_mut()
        .fault()
        .drop_type("provisions.broadcast")
        .install();

    // Cross-shard tx: withdraw on shard 0, deposit on shard 1.
    let manifest = ManifestBuilder::new()
        .lock_fee(acc_a, Decimal::from(10))
        .withdraw_from_account(acc_a, XRD, Decimal::from(500))
        .try_deposit_entire_worktop_or_abort(acc_b, None)
        .build();
    let notarized =
        sign_and_notarize(manifest, &NetworkDefinition::simulator(), 200, &kp_a).expect("sign tx");
    let tx: RoutableTransaction =
        routable_from_notarized_v1(notarized, test_validity_range()).expect("valid tx");
    let tx_hash = tx.hash();

    // Confirm the manifest actually produced a cross-shard tx: declared
    // reads/writes must span both shards.
    let touched_shards: std::collections::BTreeSet<ShardGroupId> = tx
        .declared_reads
        .iter()
        .chain(tx.declared_writes.iter())
        .map(|nid| shard_for_node(nid, num_shards))
        .collect();
    println!(
        "diag: tx declared_reads={} declared_writes={} shards_touched={:?}",
        tx.declared_reads.len(),
        tx.declared_writes.len(),
        touched_shards,
    );
    assert!(
        touched_shards.len() >= 2,
        "tx is not cross-shard: only touches {touched_shards:?}"
    );

    runner.schedule_initial_event(
        0,
        runner.now(),
        NodeInput::SubmitTransaction { tx: Arc::new(tx) },
    );

    // Cross-shard provision fetch only fires after the source shard has
    // committed the block referencing the missing provisions (5s timeout
    // per PROVISION_FALLBACK_TIMEOUT). 30s is enough at these latencies.
    runner.run_until(runner.now() + Duration::from_secs(30));

    // Layer 1: fault rule actually intercepted the cross-shard broadcast.
    assert!(
        rule.fired() >= 1,
        "expected drop_type(\"provisions.broadcast\") rule to fire, got {}",
        rule.fired()
    );

    // Layer 2: the provision-fetch fallback engaged. Recorded by the
    // request handler (all serving paths) and by the client `Fetch`
    // state machine.
    let fetch_items_sent = recorder.counter("fetch_items_sent", Some("provision"));
    let fetch_started = recorder.counter("fetch_started", Some("provision"));
    let fetch_completed = recorder.counter("fetch_completed", Some("provision"));
    assert!(
        fetch_started >= 1,
        "expected fetch_started{{kind=\"provision\"}} >= 1, got {fetch_started} \
         (rule fired {} times)",
        rule.fired()
    );
    assert!(
        fetch_completed >= 1,
        "expected fetch_completed{{kind=\"provision\"}} >= 1, got {fetch_completed} \
         (started={fetch_started})"
    );
    assert!(
        fetch_items_sent >= 1,
        "expected fetch_items_sent{{kind=\"provision\"}} >= 1, got {fetch_items_sent}"
    );

    // Layer 3: every validator in both shards reaches terminal state for
    // the tx, AND the tx was successfully executed (not aborted). Aborts
    // bump `transactions_aborted` per node — it must stay zero.
    let total_nodes = config.num_shards * config.validators_per_shard;
    for node_idx in 0..total_nodes {
        assert!(
            tx_reached_terminal_state(&runner, node_idx, &tx_hash),
            "node {node_idx} did not reach terminal state for tx {tx_hash:?}",
        );
    }
    let aborts = recorder.counter("transactions_aborted", None);
    assert_eq!(
        aborts, 0,
        "expected zero abort events, got {aborts} (fetch fallback \
         delivered provisions but tx still aborted somewhere)"
    );

    for shard in 0..config.num_shards {
        let start = shard * config.validators_per_shard;
        let end = start + config.validators_per_shard;
        let shard_max = (start..end)
            .map(|i| runner.node(i).unwrap().bft().committed_height())
            .max()
            .unwrap();
        assert!(
            shard_max > BlockHeight(0),
            "shard {shard} did not advance past genesis (max height {shard_max})"
        );
    }
}
