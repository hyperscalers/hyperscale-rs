//! Smoke test that the in-memory metrics recorder collects values from a
//! running simulation. Asserts that consensus-level counters are non-zero
//! after a few seconds of single-shard progress.

use std::time::Duration;

use hyperscale_metrics_memory::MemoryRecorder;
use hyperscale_network_memory::NetworkConfig;
use hyperscale_simulation::SimulationRunner;

#[test]
fn metrics_recorder_collects_values_from_running_sim() {
    let recorder = MemoryRecorder::new();
    hyperscale_metrics::set_global_recorder(Box::new(recorder.clone()));

    let config = NetworkConfig {
        num_shards: 1,
        validators_per_shard: 4,
        intra_shard_latency: Duration::from_millis(10),
        cross_shard_latency: Duration::from_millis(50),
        jitter_fraction: 0.1,
        ..Default::default()
    };
    let mut runner = SimulationRunner::new(&config, 42);
    runner.initialize_genesis();
    runner.run_until(Duration::from_secs(2));

    let blocks_committed = recorder.counter("blocks_committed", None);
    let block_height = recorder.gauge("block_height", None);
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
