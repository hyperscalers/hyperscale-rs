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
//! A companion test extends the guarantee across a reshape: a genesis → grow to
//! two shards → cross-shard transfer run replays identically from the same seed,
//! so the split lifecycle and the cross-shard settlement are deterministic too.

mod support;

use std::env;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use hex::encode;
use hyperscale_node::shard::{HostEvent, ProcessScopedInput};
use hyperscale_scenarios::tx::{
    build_transfer_tx, cross_shard_cast, cross_shard_genesis_accounts, genesis_accounts, recipient,
    sender, validity_around,
};
use hyperscale_scenarios::{Cluster, ScenarioConfig, epochs, grow_to};
use hyperscale_simulation::{SimConfig, SimulationRunner};
use hyperscale_storage::SubstateStore;
use hyperscale_types::{
    BeaconBlockHash, BlockHeight, Round, ShardId, StateRoot, TransactionStatus,
};
use support::SimCluster;

/// A four-validator single-shard network with light jitter; beacon options
/// default.
fn base_config() -> SimConfig {
    SimConfig {
        shard_size: 4,
        jitter_fraction: 0.1,
        accounts: genesis_accounts(DETERMINISM_TXS, DETERMINISM_TXS),
        ..Default::default()
    }
}

/// Transactions the determinism run submits, one payer and payee apiece so
/// nothing contends and the run's divergence is the network's.
const DETERMINISM_TXS: u8 = 3;

/// The determinism guard's config: the base network plus a lossy delivery path,
/// so a replay exercises the packet-loss RNG stream as well as consensus.
fn determinism_config() -> SimConfig {
    SimConfig {
        packet_loss_rate: 0.10,
        ..base_config()
    }
}

/// Every observable surface of a run, captured per node so two seeded replays
/// can be compared for byte-identical equality.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RunFingerprint {
    events_processed: u64,
    messages_sent: u64,
    messages_dropped_loss: u64,
    messages_retransmitted: u64,
    messages_dropped_fault: u64,
    timers_set: u64,
    actions_generated: u64,
    heights: Vec<BlockHeight>,
    views: Vec<Round>,
    state_roots: Vec<Option<StateRoot>>,
    beacon_blocks: Vec<Option<BeaconBlockHash>>,
    trace: [u8; 32],
}

/// Drive one run: genesis, `install_faults` (fault rules, if any), three
/// transactions submitted to node 0, then ten seconds of progress under packet
/// loss. Returns its fingerprint.
fn run_once(seed: u64, install_faults: impl FnOnce(&mut SimulationRunner)) -> RunFingerprint {
    let config = determinism_config();
    let mut runner = SimulationRunner::new(&config, seed);
    runner.initialize_genesis();
    install_faults(&mut runner);

    for (i, delay_ms) in [50u64, 51, 52].into_iter().enumerate() {
        let index = u8::try_from(i).expect("three transactions fit a byte");
        let (payer, from) = sender(index);
        let tx = build_transfer_tx(
            &payer,
            from,
            recipient(index),
            100,
            validity_around(runner.now()),
        );
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
        messages_retransmitted: stats.messages_retransmitted,
        messages_dropped_fault: stats.messages_dropped_fault,
        timers_set: stats.timers_set,
        actions_generated: stats.actions_generated,
        heights: (0..4u32)
            .map(|i| {
                runner
                    .first_vnode_state(i)
                    .unwrap()
                    .shard_coordinator()
                    .committed_height()
            })
            .collect(),
        views: (0..4u32)
            .map(|i| {
                runner
                    .first_vnode_state(i)
                    .unwrap()
                    .shard_coordinator()
                    .view()
            })
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
        trace: runner.trace_digest(),
    }
}

/// The same seed replays byte-identically across stats, per-node committed
/// heights and views, committed state roots, and beacon blocks — the composed
/// runner is deterministic end to end. The run also confirms transactions drive
/// progress and packet loss is exercised, so a regression in either surfaces
/// here.
#[test]
fn same_seed_replays_byte_identical() {
    let first = run_once(12345, |_| {});
    let second = run_once(12345, |_| {});

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

/// Two fault rules — a deterministic `block.committed` drop and a probabilistic
/// `transaction.gossip` drop — replay byte-identically at one seed. The plain
/// determinism test installs no faults, so the engine's `decide` path and its
/// own probability RNG stream (seeded `seed ^ FAULT_SALT`, disjoint from the
/// master clock) go unchecked; this is their guard. The probabilistic rule
/// forces a coin-flip per matching gossip; a byte-identical replay proves the
/// fault stream is a deterministic function of the seed. The stream is seeded
/// disjoint from the master RNG, so the coin-flips consume no master entropy —
/// faults change the run only through the messages they drop, never by
/// desynchronising the master draws.
#[test]
fn same_seed_with_faults_replays_byte_identical() {
    let install = |runner: &mut SimulationRunner| {
        // The handles are unused — the fault stream is observed through the
        // aggregated `messages_dropped_fault` stat, not per-rule counters.
        let _ = runner
            .network_mut()
            .fault()
            .drop_type("block.committed")
            .install();
        let _ = runner
            .network_mut()
            .fault()
            .drop_type_with_probability("transaction.gossip", 0.5)
            .install();
    };
    let first = run_once(12345, install);
    let second = run_once(12345, install);

    assert!(
        first.messages_dropped_fault > 0,
        "the run must exercise the fault-decision path; none dropped by a fault rule",
    );
    assert_eq!(
        first, second,
        "same seed must replay byte-identically with fault rules installed",
    );
}

/// A different seed produces a different run. The shared deterministic genesis
/// means divergence shows up in the network-driven surfaces (message counts,
/// per-node progress), so compare the whole fingerprint rather than any single
/// field.
#[test]
fn different_seed_diverges() {
    let a = run_once(111, |_| {});
    let b = run_once(222, |_| {});
    assert_ne!(a, b, "different seeds must produce a different run");
}

/// Single-shard genesis with the split trigger armed and one cohort of pool
/// surplus — the shape [`grow_to`] drives to two shards.
const fn cross_shard_config() -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 4,
        vnodes_per_host: 1,
        pool_surplus: 4,
        num_shards: 1,
        split_bytes: 0,
        latency: Duration::from_millis(150),
    }
}

/// Two same-seed runs of genesis → grow to two shards → cross-shard transfer
/// produce identical committed heights and event/message counts: the split
/// lifecycle and the cross-shard execution are deterministic, like the
/// single-shard run above but across a reshape.
#[test]
fn cross_shard_grow_replays_byte_identical() {
    assert_eq!(
        grow_and_transfer(54321),
        grow_and_transfer(54321),
        "same-seed grow + cross-shard runs must be identical",
    );
}

/// Genesis, grow to two shards, one cross-shard transfer driven to
/// settlement or its budget: the run's committed heights, event and message
/// counts, and trace digest.
fn grow_and_transfer(seed: u64) -> (Vec<BlockHeight>, u64, u64, [u8; 32]) {
    let (payer, from, to) = cross_shard_cast();
    let mut cluster =
        SimCluster::with_accounts(&cross_shard_config(), seed, &cross_shard_genesis_accounts());
    grow_to(&mut cluster, 2);

    let tx = build_transfer_tx(&payer, from, to, 500, validity_around(cluster.now()));
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
    (
        heights,
        stats.events_processed,
        stats.messages_sent,
        runner.trace_digest(),
    )
}

/// Environment variable naming the run [`trace_digest_child`] performs.
const CHILD_RUN: &str = "HYPERSCALE_DETERMINISM_CHILD";

/// Prints the trace digest of the run [`CHILD_RUN`] names. Ignored so only
/// [`replays_identically_across_processes`] runs it, each time in a
/// process of its own.
#[test]
#[ignore = "run in a child process by replays_identically_across_processes"]
fn trace_digest_child() {
    let digest = match env::var(CHILD_RUN).as_deref() {
        Ok("lossy") => run_once(12345, |_| {}).trace,
        Ok("grow") => grow_and_transfer(54321).3,
        other => panic!("{CHILD_RUN} names no run: {other:?}"),
    };
    println!("TRACE_DIGEST={}", encode(digest));
}

/// The trace digest [`trace_digest_child`] prints for `run`, from a fresh
/// process of this test binary.
fn digest_in_child(run: &str) -> String {
    let output = Command::new(env::current_exe().expect("test binary path"))
        .args(["--ignored", "--exact", "trace_digest_child", "--nocapture"])
        .env(CHILD_RUN, run)
        .output()
        .expect("child test process runs");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "child run {run} failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr),
    );
    stdout
        .lines()
        .find_map(|line| line.strip_prefix("TRACE_DIGEST="))
        .unwrap_or_else(|| panic!("child run {run} printed no digest:\n{stdout}"))
        .to_owned()
}

/// A seed replays the same events in the same order in two separate
/// processes. A same-process replay cannot see anything a process
/// randomizes at startup — std's hash seeds, a cache's hasher — so this
/// is the check that no such state reaches the run.
#[test]
fn replays_identically_across_processes() {
    for run in ["lossy", "grow"] {
        assert_eq!(
            digest_in_child(run),
            digest_in_child(run),
            "{run}: the same seed must replay identically across processes",
        );
    }
}
