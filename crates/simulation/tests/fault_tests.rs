//! Fault-injection simulation tests.
//!
//! Each test builds a [`SimCluster`] and installs a [`FaultRule`] — a dropped
//! delivery channel or a network partition — via `runner_mut()`, then asserts
//! recovery: the fault fired, any fallback fetch path engaged, and end-to-end
//! liveness — submitted transactions reach a terminal state on every live
//! member, and a partitioned cluster resumes committing once healed.

mod support;

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use hyperscale_metrics::{MetricsRecorder, with_scoped_recorder};
use hyperscale_metrics_memory::MemoryRecorder;
use hyperscale_network_memory::RuleHandle;
use hyperscale_node::NodeStateMachine;
use hyperscale_node::shard::{HostEvent, ProcessScopedInput};
use hyperscale_scenarios::{Cluster, ScenarioConfig, epochs};
use hyperscale_simulation::SimulationRunner;
use hyperscale_types::test_utils::test_validity_range;
use hyperscale_types::{
    BlockHeight, Ed25519PrivateKey, NodeId, RoutableTransaction, ShardId, TimestampRange, TxHash,
    ValidatorId, WeightedTimestamp, ed25519_keypair_from_seed, routable_from_notarized_v1,
    sign_and_notarize, uniform_shard_for_node,
};
use radix_common::constants::XRD;
use radix_common::crypto::Ed25519PublicKey;
use radix_common::math::Decimal;
use radix_common::network::NetworkDefinition;
use radix_common::types::ComponentAddress;
use radix_transactions::builder::ManifestBuilder;
use support::sim_cluster::SimCluster;
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

/// Single-shard genesis with the split trigger armed and one cohort of pooled
/// extras — [`grow_to`] drives it to two shards through the real split
/// lifecycle, mirroring a network that launches single-shard and fans out under
/// load.
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
        let shard = uniform_shard_for_node(&hs_node_id, num_shards);
        if shard == ShardId::leaf(1, 0) && shard0.is_none() {
            shard0 = Some((kp, acc));
        } else if shard == ShardId::leaf(1, 1) && shard1.is_none() {
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
    node.execution_coordinator().is_finalized(tx_hash)
        || node.mempool_coordinator().is_tombstoned(&tx_hash)
}

/// As [`tx_reached_terminal_state`], but against one vnode's state machine
/// directly — used to walk a grown shard's live committee via
/// [`SimulationRunner::shard_vnodes`] rather than host-indexed nodes.
fn vnode_reached_terminal_state(vnode: &NodeStateMachine, tx_hash: TxHash) -> bool {
    vnode.execution_coordinator().is_finalized(tx_hash)
        || vnode.mempool_coordinator().is_tombstoned(&tx_hash)
}

/// Poll the sim in one-second slices until every live committee member across
/// `live_leaves` reaches a terminal outcome for `tx_hash`, or `deadline`
/// passes. A successful tx finalizes and is then cleaned up (status returns to
/// `None`), so latch the first terminal observation per validator rather than
/// reading the post-cleanup state. Returns the validators ever observed
/// terminal.
fn await_all_terminal(
    runner: &mut SimulationRunner,
    live_leaves: &[ShardId],
    tx_hash: TxHash,
    deadline: Duration,
) -> HashSet<ValidatorId> {
    let mut latched: HashSet<ValidatorId> = HashSet::new();
    while runner.now() < deadline {
        let next = runner.now() + Duration::from_secs(1);
        runner.run_until(next);
        let all_terminal = live_leaves.iter().all(|&leaf| {
            runner.shard_vnodes(leaf).iter().all(|&vnode| {
                if vnode_reached_terminal_state(vnode, tx_hash) {
                    latched.insert(vnode.validator_id());
                    true
                } else {
                    latched.contains(&vnode.validator_id())
                }
            })
        });
        if all_terminal {
            break;
        }
    }
    latched
}

#[traced_test]
#[test]
fn transaction_fetch_fallback_when_gossip_dropped() {
    with_test_recorder(|recorder| {
        let mut cluster = SimCluster::new(&single_shard_config(), 42);

        // Suppress all transaction.gossip across the network. The submitting
        // node (0) still admits the tx locally, includes it in any block it
        // proposes, and serves it to followers via GetTransactionsRequest.
        let rule = cluster
            .runner_mut()
            .network_mut()
            .fault()
            .drop_type("transaction.gossip")
            .install();

        let tx = build_transfer_tx(1, 2);
        let tx_hash = tx.hash();
        cluster.runner_mut().schedule_initial_event(
            0,
            Duration::ZERO,
            HostEvent::process(ProcessScopedInput::SubmitTransaction { tx: Arc::new(tx) }),
        );

        cluster.run_until(epochs(1), |c| {
            (0..4u32).all(|i| tx_reached_terminal_state(c.runner(), i, tx_hash))
        });

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
                tx_reached_terminal_state(cluster.runner(), node_idx, tx_hash),
                "node {node_idx} did not reach terminal state for tx {tx_hash:?}; \
             gossip drops fired {} times, fetch_items_sent={fetch_items_sent}",
                rule.fired()
            );
        }

        let max_height = (0..4)
            .map(|i| {
                cluster
                    .runner()
                    .node(i)
                    .unwrap()
                    .shard_coordinator()
                    .committed_height()
            })
            .max()
            .unwrap();
        assert!(
            max_height > BlockHeight::new(0),
            "expected chain to advance past genesis, got max height {max_height}"
        );
    });
}

/// A 2-2 partition (nodes 0,1 vs 2,3) starves quorum, so consensus halts; once
/// healed, the timeout pacemaker re-synchronises the lagging half and the chain
/// resumes committing.
#[traced_test]
#[test]
fn consensus_halts_under_partition_and_recovers_on_heal() {
    let mut cluster = SimCluster::new(&single_shard_config(), 42);

    // Establish consensus before partitioning.
    cluster.run_until(epochs(1), |c| {
        c.committed_height(ShardId::ROOT)
            .is_some_and(|h| h >= BlockHeight::new(1))
    });
    let before = cluster
        .committed_height(ShardId::ROOT)
        .expect("consensus committed a block before the partition");

    cluster
        .runner_mut()
        .network_mut()
        .partition_groups(&[0, 1], &[2, 3]);
    // Advance until the partition is visibly starving consensus, then confirm
    // progress has halted: a 2-2 split has no quorum (needs 3 of 4).
    cluster.run_until(epochs(1), |c| {
        c.runner().stats().messages_dropped_partition >= 10
    });
    let during = cluster
        .committed_height(ShardId::ROOT)
        .expect("the chain still reports a height during the partition");
    assert!(
        during <= before + 2,
        "a 2-2 partition has no quorum, so progress must halt: before={before}, during={during}",
    );
    assert!(
        cluster.runner().stats().messages_dropped_partition > 0,
        "the partition must drop cross-group messages",
    );

    cluster.runner_mut().network_mut().heal_all();
    let recovered = cluster.run_until(epochs(2), |c| {
        c.committed_height(ShardId::ROOT)
            .is_some_and(|h| h > during + 3)
    });
    assert!(
        recovered,
        "consensus must resume committing once the partition heals (stalled at {during})",
    );
}

/// Grow target every cross-shard fault scenario reaches before installing
/// faults: genesis at one shard, split to two, then exercise cross-shard
/// recovery between the children.
const GROW_TARGET: u32 = 2;

/// Run a cross-shard fault scenario end-to-end and assert universal recovery.
///
/// Genesis at one shard funds two accounts on ROOT, `grow_to(2)` splits them
/// onto the two children by prefix, then faults install and a withdraw-deposit
/// tx crosses between the children. Asserts:
///   - L1: every installed rule fired ≥ 1
///   - L2: for each `fetch_kind`, `fetch_started` / `fetch_completed` /
///     `fetch_items_sent` ≥ 1
///   - L3: every live committee member reached terminal state for the tx, and
///     `transactions_aborted == 0` across the system
///
/// `install_faults` runs after the grow so the split lifecycle settles cleanly
/// on its own broadcasts before any are suppressed.
/// Seeds the all-or-nothing cross-shard fallback scenarios run across.
///
/// Liveness — every live committee member reaches a terminal outcome with zero
/// aborts — must hold on every seed; that's the real invariant. But which
/// fallback path a node takes to satisfy a cross-shard dependency depends on
/// the post-grow committee layout, so a given fetch only needs to engage on at
/// least one seed. Pinning a single seed conflates the two and makes coverage
/// fragile: an unrelated shift in the RNG stream can route around a path
/// without anything real breaking.
const FAULT_SCENARIO_SEEDS: [u64; 6] = [1, 3, 13, 20, 42, 1337];

/// Run one cross-shard fault scenario at `seed`, asserting liveness — Layer 1
/// (every installed rule fired) and Layer 3 (every live member reached a
/// terminal outcome, zero aborts) — and returning, per named fetch kind,
/// whether its fallback engaged client- and server-side (Layer 2).
fn run_cross_shard_scenario_core<F>(
    install_faults: &F,
    fetch_kinds: &[&'static str],
    seed: u64,
) -> Vec<(&'static str, bool)>
where
    F: Fn(&mut SimulationRunner) -> Vec<RuleHandle>,
{
    with_test_recorder(|recorder| {
        // Accounts route by prefix, which equals their post-grow shard; fund
        // them on ROOT at genesis and the split partitions them across the
        // children exactly as a multi-shard genesis once placed them.
        let num_shards = u64::from(GROW_TARGET);
        let ((kp_a, acc_a), (_kp_b, acc_b)) = find_accounts_on_each_shard(num_shards);
        let initial_balance = Decimal::from(10_000);
        let mut cluster = SimCluster::with_balances(
            &cross_shard_config(),
            seed,
            &[(acc_a, initial_balance), (acc_b, initial_balance)],
        );

        // White-box grow via `runner_mut`: the cross-shard fault flow needs the
        // full committee seated on both children before faults install, which the
        // runner's `grow_to` settles. The portable `grow_to` exits once a leaf
        // commits past genesis (satisfiable by an observer ahead of committee
        // seating), and `await_all_terminal` doesn't pump to settle the rest.
        let runner = cluster.runner_mut();
        runner.grow_to(GROW_TARGET);

        let rules = install_faults(&mut *runner);
        assert!(
            !rules.is_empty(),
            "install_faults must return at least one rule handle"
        );

        // A tx built after the grow must bracket the current weighted time:
        // the genesis-anchored `test_validity_range()` (`[0, 1min]`) has long
        // expired by the time the split lifecycle finishes.
        let now = runner.now();
        let validity = TimestampRange::new(
            WeightedTimestamp::ZERO.plus(now.saturating_sub(Duration::from_secs(5))),
            WeightedTimestamp::ZERO.plus(now + Duration::from_secs(150)),
        );
        let manifest = ManifestBuilder::new()
            .lock_fee(acc_a, Decimal::from(10))
            .withdraw_from_account(acc_a, XRD, Decimal::from(500))
            .try_deposit_entire_worktop_or_abort(acc_b, None)
            .build();
        let notarized = sign_and_notarize(manifest, &NetworkDefinition::simulator(), 200, &kp_a)
            .expect("sign tx");
        let tx: RoutableTransaction =
            routable_from_notarized_v1(notarized, validity).expect("valid tx");
        let tx_hash = tx.hash();

        let touched_shards: std::collections::BTreeSet<ShardId> = tx
            .declared_reads()
            .iter()
            .chain(tx.declared_writes().iter())
            .map(|nid| uniform_shard_for_node(nid, num_shards))
            .collect();
        assert!(
            touched_shards.len() >= 2,
            "tx is not cross-shard: only touches {touched_shards:?}"
        );

        // The grow shuffles validator placement, so submit on whichever host
        // now carries the source account's shard rather than assuming node 0.
        let depth = GROW_TARGET.trailing_zeros();
        let live_leaves: Vec<ShardId> = (0..num_shards).map(|p| ShardId::leaf(depth, p)).collect();
        let source_shard = ShardId::leaf(depth, 0);
        let submit_host = (0..runner.num_hosts())
            .find(|&node| runner.hosts_shard(node, source_shard).is_some())
            .expect("a host carries the source shard");
        runner.schedule_initial_event(
            submit_host,
            Duration::ZERO,
            HostEvent::process(ProcessScopedInput::SubmitTransaction { tx: Arc::new(tx) }),
        );

        // Cross-shard recovery in the grown sim runs a few cleanup-timer
        // fallback-fetch cycles, so poll until every live committee member
        // reaches a terminal outcome rather than racing a fixed window.
        let deadline = runner.now() + Duration::from_secs(150);
        let latched = await_all_terminal(&mut *runner, &live_leaves, tx_hash, deadline);

        // Layer 1: every installed rule actually intercepted at least one
        // message. Catches misconfigured matchers that silently match nothing.
        for (i, rule) in rules.iter().enumerate() {
            assert!(
                rule.fired() >= 1,
                "fault rule {i} did not fire — test premise broken (rule matched no messages)"
            );
        }

        // Layer 2: record whether each fetch protocol engaged client-side and
        // server-side. `block` and `remote_header` are sync FSMs (range
        // round-trips); the rest are per-id Fetch bindings. Pick the right
        // counter family per kind — both record `items_sent` on the serve side
        // under the same `fetch_items_sent` label, since the responder doesn't
        // distinguish. The caller decides whether engagement is required at
        // this seed or aggregated across seeds.
        let engagement: Vec<(&'static str, bool)> = fetch_kinds
            .iter()
            .map(|&kind| {
                let (started, completed) = if matches!(kind, "block" | "remote_header") {
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
                (kind, started >= 1 && completed >= 1 && items_sent >= 1)
            })
            .collect();

        // Layer 3: every live committee member reached a terminal outcome for
        // the tx, and the tx was successfully executed (not aborted). Walk each
        // leaf's live vnodes — the grow leaves terminated parent vnodes on
        // hosts and seats observers cross-shard, so host-indexing misses some.
        for &leaf in &live_leaves {
            for vnode in runner.shard_vnodes(leaf) {
                assert!(
                    latched.contains(&vnode.validator_id()),
                    "{:?} on {leaf:?} never reached a terminal outcome for tx {tx_hash:?}",
                    vnode.validator_id(),
                );
            }
        }
        let aborts = recorder.counter("transactions_aborted", None);
        assert_eq!(
            aborts, 0,
            "expected zero abort events, got {aborts} (fetch fallback \
         delivered data but tx still aborted somewhere)"
        );

        engagement
    })
}

/// Run a scenario across [`FAULT_SCENARIO_SEEDS`]: liveness is asserted on
/// every seed by the core, and each named fetch kind must engage on at least
/// one of them — so an RNG-stream shift that reroutes one seed's trajectory
/// can't silently drop coverage as long as the path still fires somewhere.
fn run_cross_shard_fault_scenario<F>(install_faults: F, fetch_kinds: &[&'static str])
where
    F: Fn(&mut SimulationRunner) -> Vec<RuleHandle>,
{
    let mut ever_engaged: Vec<(&'static str, bool)> =
        fetch_kinds.iter().map(|&k| (k, false)).collect();
    for &seed in &FAULT_SCENARIO_SEEDS {
        for (kind, engaged) in run_cross_shard_scenario_core(&install_faults, fetch_kinds, seed) {
            if engaged && let Some(slot) = ever_engaged.iter_mut().find(|(k, _)| *k == kind) {
                slot.1 = true;
            }
        }
    }
    for (kind, engaged) in ever_engaged {
        assert!(
            engaged,
            "{kind} fetch fallback never engaged across seeds {FAULT_SCENARIO_SEEDS:?}"
        );
    }
}

/// Run a scenario at a single seed and require every named fetch kind to engage
/// at that seed. For probabilistic scenarios where the fault makes the fetch
/// the only recovery path, so it must fire on every run.
fn run_cross_shard_fault_scenario_with_seed<F>(
    install_faults: F,
    fetch_kinds: &[&'static str],
    seed: u64,
) where
    F: Fn(&mut SimulationRunner) -> Vec<RuleHandle>,
{
    for (kind, engaged) in run_cross_shard_scenario_core(&install_faults, fetch_kinds, seed) {
        assert!(
            engaged,
            "{kind} fetch fallback didn't engage at seed {seed}"
        );
    }
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
/// different fetch instances — and the combined recovery (remote-header
/// sync, then the provision and exec-cert fetches) must complete within
/// `WAVE_TIMEOUT` so the wave finalizes rather than aborting. Proves the
/// two channels compose without deadlock when both primary cross-shard
/// channels fail at once.
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

/// Time-bounded fault: `provisions.broadcast` drops during a 30s window
/// from submission, then the fault lifts. The window must outlast the
/// grown shard's commit-then-broadcast latency so the tx's provision
/// broadcast actually falls inside it and recovers via the fetch fallback;
/// once the fault lifts, subsequent provision broadcasts flow normally.
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
                    .during(now..now + Duration::from_secs(30))
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
