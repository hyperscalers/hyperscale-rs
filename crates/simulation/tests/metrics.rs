//! Smoke test that the in-memory metrics recorder collects values from a
//! running simulation. Asserts that consensus-level counters are non-zero
//! after a few seconds of single-shard progress.

mod support;

use std::sync::Arc;
use std::time::Duration;

use hyperscale_metrics::with_scoped_recorder;
use hyperscale_metrics_memory::MemoryRecorder;
use hyperscale_simulation::{ProcessingTimes, SimConfig, SimulationRunner};
use hyperscale_storage::ShardChainReader;
use hyperscale_types::ShardId;
use support::sim_seed;

#[test]
fn metrics_recorder_collects_values_from_running_sim() {
    let recorder = MemoryRecorder::new();
    let config = SimConfig {
        shard_size: 4,
        jitter_fraction: 0.1,
        ..Default::default()
    };
    with_scoped_recorder(Arc::new(recorder.clone()), || {
        let mut runner = SimulationRunner::new(&config, sim_seed(42));
        runner.initialize_genesis();
        runner.run_until(Duration::from_secs(2));
    });

    // Per-shard metrics are labeled by the shard's scalar id. The single shard
    // is the trie root, whose scalar id is 1.
    let blocks_committed = recorder.counter("blocks_committed", Some("1"));
    let block_height = recorder.gauge("block_height", Some("1"));
    let commit_observations: u64 = ["aggregator", "header", "sync"]
        .iter()
        .map(|src| recorder.histogram_count("block_commit_latency", Some(src)))
        .sum();

    println!("blocks_committed={blocks_committed}");
    println!("block_height={block_height}");
    println!("block_commit_latency observations={commit_observations}");

    assert!(
        blocks_committed > 0,
        "expected at least one block committed across the shard, got 0"
    );
    assert!(
        block_height >= 1.0,
        "expected block_height gauge to advance past genesis, got {block_height}"
    );
    assert_eq!(
        commit_observations, blocks_committed,
        "histogram observation count should match blocks_committed counter"
    );
}

/// A shard whose disk writes fall behind its commits holds each
/// `BlockCommitted` past the lag bound until the write lands, and keeps
/// committing and persisting through it.
///
/// Writes slower than blocks leave the persisted height trailing the tip;
/// with work that completes at once it never trails, and nothing is held
/// back. The writes run deferred, so every store reaching past the lag is
/// also each host running its queued writes when their time comes.
#[test]
fn a_shard_whose_writes_lag_holds_block_committed_back() {
    let recorder = MemoryRecorder::new();
    let config = SimConfig {
        shard_size: 4,
        processing: ProcessingTimes {
            io: Duration::from_secs(2),
            ..ProcessingTimes::INSTANT
        },
        ..Default::default()
    };
    let runner = with_scoped_recorder(Arc::new(recorder.clone()), || {
        let mut runner = SimulationRunner::new(&config, sim_seed(42));
        runner.initialize_genesis();
        runner.run_until(Duration::from_secs(30));
        runner
    });

    let deferred = recorder.counter("block_commit_deferred", None);
    let committed = recorder.counter("blocks_committed", Some("1"));
    let persisted: Vec<u64> = (0..runner.num_hosts())
        .map(|host| {
            runner
                .hosts_shard(host, ShardId::ROOT)
                .map_or(0, |store| store.committed_height().inner())
        })
        .collect();
    assert!(
        deferred > 0,
        "persistence never lagged far enough to hold a BlockCommitted back \
         ({committed} committed, stores at {persisted:?})",
    );
    assert!(
        persisted.iter().all(|&height| height > 10),
        "every store kept persisting through the lag: stores at {persisted:?}, \
         {committed} committed, {deferred} held back",
    );
}

/// A host resolves a fetch against routing from the moment it is built,
/// not from its first topology fold.
///
/// The fold runs on a beacon commit, up to an epoch after a restart.
/// Inside that window a fetch to a shard the head does not name resolves
/// no committee and fails at the transport before it reaches a peer,
/// where the caller re-dispatches it — so the gap is a spin, not a
/// delay. The sim resolves peers by hosting registry and cannot show
/// that; what it can show is the seed being there.
#[test]
fn a_host_boots_with_its_schedules_routing() {
    let config = SimConfig {
        shard_size: 4,
        ..Default::default()
    };
    // Built, not run: no beacon block has committed, so nothing has
    // folded a topology into the network.
    let runner = SimulationRunner::new(&config, sim_seed(42));

    let routing = runner
        .host_routing_committees(0)
        .expect("the sim seats host 0");
    assert!(
        routing.contains_key(&ShardId::ROOT),
        "the boot schedule's routing reached the network, {routing:?}"
    );
}
