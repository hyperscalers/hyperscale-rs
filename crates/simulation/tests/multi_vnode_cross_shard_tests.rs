//! Multi-vnode cross-shard hosting smoke tests.
//!
//! Exercises the path where a single `IoLoop` hosts vnodes in *different*
//! shards — the Phase 2c proving test. Mirrors the same-shard variant in
//! `multi_vnode_tests.rs`, but uses [`HostingMode::CrossShard`] so each
//! host carries one validator from every shard.
//!
//! Validates that the full Phase 2c threading work composes end-to-end:
//! `local_shard` plumbing through every `NodeInput` variant, gossip
//! handler shard routing, sync/fetch callbacks tagged correctly,
//! per-shard timer keying, and shared per-shard stores all working
//! together under multi-shard hosting.

use std::time::Duration;

use hyperscale_network_memory::{HostingMode, NetworkConfig};
use hyperscale_simulation::SimulationRunner;
use hyperscale_types::{BlockHeight, ValidatorId};
use tracing_test::traced_test;

/// Two hosts × two vnodes each (one per shard), 2 shards. Each host
/// carries one validator from shard 0 and one from shard 1. Validators
/// `V0`,`V1` are in shard 0; `V2`,`V3` are in shard 1; host 0 hosts
/// `{V0, V2}`, host 1 hosts `{V1, V3}`. Runs a short consensus burst
/// and asserts every validator's BFT committed beyond genesis.
#[traced_test]
#[test]
fn test_v2_cross_shard_hosting_makes_progress() {
    let config = NetworkConfig {
        num_shards: 2,
        validators_per_shard: 2,
        vnodes_per_host: 1, // ignored under CrossShard mode
        hosting_mode: HostingMode::CrossShard,
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
                .bft()
                .committed_height()
        })
        .collect();

    let min = *heights.iter().min().expect("4 validators");
    assert!(
        min > BlockHeight::GENESIS,
        "all validators should commit beyond genesis under cross-shard hosting; heights = {heights:?}"
    );

    // V0 and V1 are both in shard 0 but on *different hosts* (host 0
    // and host 1) — cross-host drift bounded by one block at the
    // moment of snapshot. Same shape for V2/V3 in shard 1. Cross-shard
    // heights (e.g. V0 vs V2) are fully independent and can diverge
    // freely.
    let shard0_drift = heights[0].inner().abs_diff(heights[1].inner());
    let shard1_drift = heights[2].inner().abs_diff(heights[3].inner());
    assert!(
        shard0_drift <= 1,
        "shard 0 validators should drift by at most 1 block; got {heights:?}"
    );
    assert!(
        shard1_drift <= 1,
        "shard 1 validators should drift by at most 1 block; got {heights:?}"
    );
}
