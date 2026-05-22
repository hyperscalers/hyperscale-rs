//! Multi-vnode-per-host hosting smoke tests.
//!
//! Exercises the path where a single `IoLoop` hosts more than one
//! `Vnode` in the same shard, signing votes independently with
//! per-vnode keys. Validates that the per-vnode action dispatch,
//! inbound state-machine event fan-out, and same-shard sharing of
//! `ShardIo` all hold together end-to-end.

use std::time::Duration;

use hyperscale_network_memory::{HostingMode, NetworkConfig};
use hyperscale_simulation::SimulationRunner;
use hyperscale_types::{BlockHeight, ValidatorId};
use tracing_test::traced_test;

/// Two hosts × two same-shard vnodes each, one shard. Run a short
/// consensus burst and check every validator's state machine reached
/// a non-genesis committed height and that all four agree on it.
#[traced_test]
#[test]
fn test_v2_same_shard_hosting_makes_progress() {
    let config = NetworkConfig {
        num_shards: 1,
        validators_per_shard: 4,
        vnodes_per_host: 2,
        hosting_mode: HostingMode::SameShardBundled,
        intra_shard_latency: Duration::from_millis(50),
        cross_shard_latency: Duration::from_millis(50),
        jitter_fraction: 0.1,
        packet_loss_rate: 0.0,
    };

    let mut runner = SimulationRunner::new(&config, 7);
    runner.initialize_genesis();
    runner.run_until(Duration::from_secs(3));

    let heights: Vec<BlockHeight> = (0..4)
        .map(|i| {
            runner
                .vnode_state(ValidatorId::new(i))
                .expect("validator should be hosted")
                .shard_coordinator()
                .committed_height()
        })
        .collect();

    let min = *heights.iter().min().expect("4 validators");
    let max = *heights.iter().max().expect("4 validators");
    assert!(
        min > BlockHeight::GENESIS,
        "all validators should commit beyond genesis; heights = {heights:?}"
    );
    // Two vnodes on the same host process the same inbound events
    // and so commit in lockstep; cross-host drift is bounded by one
    // block at the moment of snapshot.
    assert!(
        max.inner() - min.inner() <= 1,
        "heights should be within one block across hosts; got {heights:?}"
    );
    assert_eq!(
        heights[0], heights[1],
        "same-host vnodes (host 0) must agree exactly; got {heights:?}"
    );
    assert_eq!(
        heights[2], heights[3],
        "same-host vnodes (host 1) must agree exactly; got {heights:?}"
    );
}
