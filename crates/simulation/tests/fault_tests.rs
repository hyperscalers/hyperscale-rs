//! Fetch-fallback simulation tests.
//!
//! Each test installs a [`FaultRule`] suppressing a primary delivery
//! channel, then asserts three layers of recovery:
//! 1. The fault rule actually fired (rule misconfiguration guard).
//! 2. The fallback fetch path engaged (`fetch_started` counter).
//! 3. End-to-end liveness: submitted transactions reach a terminal
//!    state on every node.

use std::sync::Arc;
use std::time::Duration;

use hyperscale_metrics::{MetricsRecorder, with_scoped_recorder};
use hyperscale_metrics_memory::MemoryRecorder;
use hyperscale_network_memory::{NetworkConfig, RuleHandle};
use hyperscale_node::io_loop::{ProcessScopedInput, ShardEvent};
use hyperscale_simulation::SimulationRunner;
use hyperscale_types::test_utils::test_validity_range;
use hyperscale_types::{
    BlockHeight, Ed25519PrivateKey, NodeId, RoutableTransaction, ShardGroupId, TxHash,
    ed25519_keypair_from_seed, routable_from_notarized_v1, shard_for_node, sign_and_notarize,
};
use radix_common::constants::XRD;
use radix_common::crypto::Ed25519PublicKey;
use radix_common::math::Decimal;
use radix_common::network::NetworkDefinition;
use radix_common::types::ComponentAddress;
use radix_transactions::builder::ManifestBuilder;
use tracing_test::traced_test;

/// Run `f` against a fresh per-test `MemoryRecorder` installed as the
/// thread-local metrics recorder. Cargo runs each test on its own thread,
/// so concurrent tests get fully isolated counters and the binary can run
/// with the default parallelism.
fn with_test_recorder<R>(f: impl FnOnce(&MemoryRecorder) -> R) -> R {
    let recorder = MemoryRecorder::new();
    let arc: Arc<dyn MetricsRecorder> = Arc::new(recorder.clone());
    with_scoped_recorder(arc, || f(&recorder))
}

fn single_shard_config() -> NetworkConfig {
    NetworkConfig {
        num_shards: 1,
        validators_per_shard: 4,
        intra_shard_latency: Duration::from_millis(100),
        cross_shard_latency: Duration::from_millis(100),
        jitter_fraction: 0.1,
        ..Default::default()
    }
}

fn multi_shard_config() -> NetworkConfig {
    NetworkConfig {
        num_shards: 2,
        validators_per_shard: 3,
        intra_shard_latency: Duration::from_millis(100),
        cross_shard_latency: Duration::from_millis(100),
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
        if shard == ShardGroupId::new(0) && shard0.is_none() {
            shard0 = Some((kp, acc));
        } else if shard == ShardGroupId::new(1) && shard1.is_none() {
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
fn tx_reached_terminal_state(runner: &SimulationRunner, node_idx: u32, tx_hash: TxHash) -> bool {
    let node = runner.node(node_idx).expect("node exists");
    node.execution().is_finalized(tx_hash) || node.mempool().is_tombstoned(&tx_hash)
}

#[traced_test]
#[test]
fn transaction_fetch_fallback_when_gossip_dropped() {
    with_test_recorder(|recorder| {
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
            ShardEvent::process(ProcessScopedInput::SubmitTransaction { tx: Arc::new(tx) }),
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
        // client-side; see `crates/node/src/io_loop/fetch/`.)
        let fetch_items_sent = recorder.counter("fetch_items_sent", Some("transaction"));
        assert!(
            fetch_items_sent >= 1,
            "expected fetch_items_sent{{kind=\"transaction\"}} >= 1, got {fetch_items_sent}"
        );

        // Layer 3: end-to-end — every node finalized the tx and the chain
        // advanced past genesis.
        for node_idx in 0..4u32 {
            assert!(
                tx_reached_terminal_state(&runner, node_idx, tx_hash),
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
            max_height > BlockHeight::new(0),
            "expected chain to advance past genesis, got max height {max_height}"
        );
    });
}

/// Run a multi-shard fault scenario end-to-end and assert universal
/// recovery.
///
/// Common shape across cross-shard fault tests: 2 shards × 3 validators,
/// genesis-funded accounts on each shard, 1s warm-up, install faults,
/// submit a withdraw-deposit cross-shard tx, run 30s, then assert:
///   - L1: every installed rule fired ≥ 1
///   - L2: for each `fetch_kind`, `fetch_started` / `fetch_completed` /
///     `fetch_items_sent` ≥ 1
///   - L3: every validator reached terminal state for the tx, and
///     `transactions_aborted == 0` across the system
///
/// `install_faults` runs after warm-up so genesis can settle cleanly.
fn run_cross_shard_fault_scenario<F>(install_faults: F, fetch_kinds: &[&'static str])
where
    F: FnOnce(&mut SimulationRunner) -> Vec<RuleHandle>,
{
    run_cross_shard_fault_scenario_with_seed(install_faults, fetch_kinds, 42);
}

fn run_cross_shard_fault_scenario_with_seed<F>(
    install_faults: F,
    fetch_kinds: &[&'static str],
    seed: u64,
) where
    F: FnOnce(&mut SimulationRunner) -> Vec<RuleHandle>,
{
    with_test_recorder(|recorder| {
        let config = multi_shard_config();
        let num_shards = u64::from(config.num_shards);
        let mut runner = SimulationRunner::new(&config, seed);

        let ((kp_a, acc_a), (_kp_b, acc_b)) = find_accounts_on_each_shard(num_shards);
        let initial_balance = Decimal::from(10_000);
        runner.initialize_genesis_with_balances(&[
            (acc_a, initial_balance),
            (acc_b, initial_balance),
        ]);

        runner.run_until(Duration::from_secs(1));
        let rules = install_faults(&mut runner);
        assert!(
            !rules.is_empty(),
            "install_faults must return at least one rule handle"
        );

        let manifest = ManifestBuilder::new()
            .lock_fee(acc_a, Decimal::from(10))
            .withdraw_from_account(acc_a, XRD, Decimal::from(500))
            .try_deposit_entire_worktop_or_abort(acc_b, None)
            .build();
        let notarized = sign_and_notarize(manifest, &NetworkDefinition::simulator(), 200, &kp_a)
            .expect("sign tx");
        let tx: RoutableTransaction =
            routable_from_notarized_v1(notarized, test_validity_range()).expect("valid tx");
        let tx_hash = tx.hash();

        let touched_shards: std::collections::BTreeSet<ShardGroupId> = tx
            .declared_reads()
            .iter()
            .chain(tx.declared_writes().iter())
            .map(|nid| shard_for_node(nid, num_shards))
            .collect();
        assert!(
            touched_shards.len() >= 2,
            "tx is not cross-shard: only touches {touched_shards:?}"
        );

        runner.schedule_initial_event(
            0,
            runner.now(),
            ShardEvent::process(ProcessScopedInput::SubmitTransaction { tx: Arc::new(tx) }),
        );

        runner.run_until(runner.now() + Duration::from_secs(30));

        // Layer 1: every installed rule actually intercepted at least one
        // message. Catches misconfigured matchers that silently match nothing.
        for (i, rule) in rules.iter().enumerate() {
            assert!(
                rule.fired() >= 1,
                "fault rule {i} did not fire — test premise broken (rule matched no messages)"
            );
        }

        // Layer 2: each fetch protocol engaged client-side and server-side.
        // `block` and `remote_header` are sync FSMs (range round-trips); the
        // rest are per-id Fetch bindings. Pick the right counter family per
        // kind — both record `items_sent` on the serve side under the same
        // `fetch_items_sent` label, since the responder doesn't distinguish.
        for kind in fetch_kinds {
            let (started, completed) = if matches!(*kind, "block" | "remote_header") {
                (
                    recorder.counter("sync_round_started", Some(kind)),
                    recorder.counter("sync_round_completed", Some(kind)),
                )
            } else {
                (
                    recorder.counter("fetch_started", Some(kind)),
                    recorder.counter("fetch_completed", Some(kind)),
                )
            };
            let items_sent = recorder.counter("fetch_items_sent", Some(kind));
            assert!(
                started >= 1 && completed >= 1 && items_sent >= 1,
                "{kind} fetch fallback didn't engage: started={started} \
             completed={completed} items_sent={items_sent}"
            );
        }

        // Layer 3: every validator reaches terminal state for the tx, and
        // the tx was successfully executed (not aborted).
        let total_nodes = config.num_shards * config.validators_per_shard;
        for node_idx in 0..total_nodes {
            assert!(
                tx_reached_terminal_state(&runner, node_idx, tx_hash),
                "node {node_idx} did not reach terminal state for tx {tx_hash:?}",
            );
        }
        let aborts = recorder.counter("transactions_aborted", None);
        assert_eq!(
            aborts, 0,
            "expected zero abort events, got {aborts} (fetch fallback \
         delivered data but tx still aborted somewhere)"
        );
    });
}

/// Cross-shard provisions fetch fallback. The source-shard proposer
/// normally broadcasts `provisions.broadcast` to target shards alongside
/// its block proposal; suppressing it forces the target shard to fetch
/// provisions via `GetProvisionsRequest` against the source-shard
/// committee.
#[test]
fn cross_shard_provisions_fetch_fallback_when_broadcast_dropped() {
    run_cross_shard_fault_scenario(
        |runner| {
            vec![
                runner
                    .network_mut()
                    .fault()
                    .drop_type("provisions.broadcast")
                    .install(),
            ]
        },
        &["provision"],
    );
}

/// Cross-shard execution-certificate fetch fallback. Wave leaders
/// normally broadcast `execution.cert.batch` notifications to remote
/// participating shards once 2f+1 votes aggregate; suppressing those
/// notifications forces each shard to fetch the remote shard's EC via
/// `GetExecutionCertsRequest` so its local wave can complete.
///
/// Mirrors the provisions test for the *output* side of the cross-shard
/// pipeline (provisions are the input, ECs are the output).
#[test]
fn cross_shard_exec_cert_fetch_fallback_when_broadcast_dropped() {
    run_cross_shard_fault_scenario(
        |runner| {
            vec![
                runner
                    .network_mut()
                    .fault()
                    .drop_type("execution.cert.batch")
                    .install(),
            ]
        },
        &["exec_cert"],
    );
}

/// Compound fault: drop *both* `provisions.broadcast` and
/// `execution.cert.batch` simultaneously. Both fetch protocols must
/// engage independently — they're gated on different timeouts and
/// different fetch instances; this proves they compose without
/// deadlock when both primary cross-shard channels fail at once.
#[test]
fn cross_shard_compound_provisions_and_exec_cert_fetch_fallback() {
    run_cross_shard_fault_scenario(
        |runner| {
            let provisions_rule = runner
                .network_mut()
                .fault()
                .drop_type("provisions.broadcast")
                .install();
            let exec_cert_rule = runner
                .network_mut()
                .fault()
                .drop_type("execution.cert.batch")
                .install();
            vec![provisions_rule, exec_cert_rule]
        },
        &["provision", "exec_cert"],
    );
}

/// Cross-shard transaction-data-availability fallback. A cross-shard tx is
/// submitted to shard 0; provisions flow normally to shard 1, but
/// `transaction.gossip` is dropped network-wide so shard 1 never sees the
/// tx body via gossip. Shard 1's mempool records the tx as expected from
/// the verified provisions bundle, waits out `EXPECTED_TX_GRACE`, then
/// fetches from shard 0's committee via `GetTransactionsRequest`. The
/// shared scenario asserts liveness (every node terminal) and zero aborts;
/// horizon-bounded eviction is covered by mempool unit tests.
#[test]
fn cross_shard_transaction_da_fallback_when_gossip_dropped() {
    run_cross_shard_fault_scenario(
        |runner| {
            vec![
                runner
                    .network_mut()
                    .fault()
                    .drop_type("transaction.gossip")
                    .install(),
            ]
        },
        &["transaction"],
    );
}

/// Time-bounded fault: `provisions.broadcast` drops during a 5s window
/// shortly after the cross-shard tx is submitted, then the fault lifts.
/// The cross-shard tx falls inside the fault window and must recover via
/// the fetch fallback. Once the fault lifts, subsequent provision
/// broadcasts flow normally.
///
/// Exercises the `during(range)` matcher on `FaultInjector` and confirms
/// the system gracefully resumes normal flow after a transient gossip
/// outage.
#[test]
fn cross_shard_provisions_recovers_after_transient_broadcast_outage() {
    run_cross_shard_fault_scenario(
        |runner| {
            let now = runner.now();
            vec![
                runner
                    .network_mut()
                    .fault()
                    .drop_type("provisions.broadcast")
                    .during(now..now + Duration::from_secs(5))
                    .install(),
            ]
        },
        &["provision"],
    );
}

/// Cross-shard provisions fetch under unreliable RPC: `provisions.broadcast`
/// is dropped 100% (forcing fetch as the only recovery path) AND
/// `provision.request` is dropped 50% (so each fetch attempt has a
/// coin-flip chance of timing out and being retried).
///
/// Generate one `#[test]` per seed so cargo runs them in parallel.
///
/// Use for probabilistic / multi-seed scenarios where each seed must
/// independently pass. Each entry is `name => seed`; the macro emits a
/// `#[test] fn <name>()` that invokes `$body($seed)`. Because the test
/// names are spelled out per entry, no proc-macro identifier concatenation
/// (e.g. `paste`) is required.
macro_rules! seeded_tests {
    (fn $body_arg:ident: u64 = $body:block, $($name:ident => $seed:literal),+ $(,)?) => {
        $(
            #[test]
            fn $name() {
                let $body_arg: u64 = $seed;
                $body
            }
        )+
    };
}

// Exercises `Fetch::handle_failed` and the retry path that wasn't covered
// by the all-or-nothing tests above. Every seed must independently reach
// successful execution within the 30s budget.
seeded_tests! {
    fn seed: u64 = {
        run_cross_shard_fault_scenario_with_seed(
            |runner| {
                let broadcast_rule = runner
                    .network_mut()
                    .fault()
                    .drop_type("provisions.broadcast")
                    .install();
                let request_rule = runner
                    .network_mut()
                    .fault()
                    .drop_type_with_probability("provision.request", 0.5)
                    .install();
                vec![broadcast_rule, request_rule]
            },
            &["provision"],
            seed,
        );
    },
    cross_shard_provisions_fetch_with_50pct_request_loss_seed_42 => 42,
    cross_shard_provisions_fetch_with_50pct_request_loss_seed_1337 => 1337,
    cross_shard_provisions_fetch_with_50pct_request_loss_seed_2026 => 2026,
}

/// Cross-shard remote-header sync. Source-shard validators normally
/// broadcast `block.committed` gossip on every commit, which the target
/// shard's `RemoteHeaderCoordinator` consumes to gate downstream
/// provision/EC expectations. Suppressing that gossip forces the target
/// shard's `RemoteHeaderSync` (sliding-window range catch-up) to
/// pull headers directly from source-shard committee members.
///
/// This is the *first link* in the cross-shard recovery chain — without
/// the remote header, neither the provision-fetch nor the EC-fetch
/// trigger has anything to register against.
#[test]
fn cross_shard_header_fetch_fallback_when_committed_gossip_dropped() {
    run_cross_shard_fault_scenario(
        |runner| {
            vec![
                runner
                    .network_mut()
                    .fault()
                    .drop_type("block.committed")
                    .install(),
            ]
        },
        &["remote_header"],
    );
}
