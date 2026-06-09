//! Beacon wall-clock pacing across an outage and recovery.
//!
//! The beacon's synthetic epoch clock (`epoch × epoch_duration_ms`) must
//! never outrun wall-clock: an epoch's SPC starts only once `now` reaches
//! its boundary, so the latest committed epoch is bounded by the wall
//! epoch at every instant. Catch-up after an outage may run arbitrarily
//! fast — it converges *toward* the boundary, never past it.
//!
//! The outage/heal shape matters: catch-up re-arms the skip trigger with a
//! zero-saturated boundary delta on every adoption, and a stale fire from
//! that phase broadcasts a skip request that looks fresh (it anchors at the
//! tip and names the then-current next epoch). A quorum of such fires skips
//! epochs whose windows haven't opened, and each early skip re-arms more —
//! the beacon races ahead of wall-clock and stays there. This test pins the
//! pacing bound through exactly that phase.

use std::time::Duration;

use hyperscale_network_memory::{NetworkConfig, NodeIndex};
use hyperscale_simulation::SimulationRunner;
use hyperscale_types::{BeaconChainConfig, Epoch};
use tracing_test::traced_test;

const TEST_EPOCH_MS: u64 = 5000;
const VALIDATORS: u32 = 4;
const LAGGER: NodeIndex = 3;

/// Epochs the healthy majority must commit during the outage — enough that
/// the heal is followed by a multi-epoch catch-up burst.
const OUTAGE_EPOCHS: u64 = 6;

fn pacing_config() -> NetworkConfig {
    NetworkConfig {
        num_shards: 1,
        validators_per_shard: VALIDATORS,
        intra_shard_latency: Duration::from_millis(50),
        cross_shard_latency: Duration::from_millis(50),
        jitter_fraction: 0.1,
        beacon_chain_config: Some(BeaconChainConfig {
            epoch_duration_ms: TEST_EPOCH_MS,
            num_shards: 1,
            shard_size: VALIDATORS,
            ..BeaconChainConfig::default()
        }),
        ..Default::default()
    }
}

fn latest_beacon_epoch(runner: &SimulationRunner, node: NodeIndex) -> u64 {
    runner
        .beacon_storage(node)
        .expect("node exists")
        .latest_committed_epoch()
        .map_or(0, Epoch::inner)
}

#[traced_test]
#[test]
fn beacon_never_commits_an_epoch_ahead_of_wall_clock() {
    let mut runner = SimulationRunner::new(&pacing_config(), 11);
    runner.initialize_genesis();

    let mut now_secs: u64 = 10;
    runner.run_until(Duration::from_secs(now_secs));

    // Outage: the healthy majority falls behind wall-clock (the isolated
    // member's SPC views time out), banking a catch-up burst for the heal.
    runner.network_mut().isolate_node(LAGGER);
    let frontier_epoch = latest_beacon_epoch(&runner, LAGGER);
    while latest_beacon_epoch(&runner, 0) < frontier_epoch + OUTAGE_EPOCHS {
        now_secs += 5;
        assert!(
            now_secs <= 130,
            "healthy majority failed to advance {OUTAGE_EPOCHS} epochs during the outage"
        );
        runner.run_until(Duration::from_secs(now_secs));
    }
    runner.network_mut().heal_all();

    // Through catch-up and well past it: an epoch's SPC starts no earlier
    // than its wall-clock boundary, so the latest committed epoch can never
    // exceed the wall epoch at the sample instant.
    while now_secs < 140 {
        now_secs += 2;
        runner.run_until(Duration::from_secs(now_secs));
        let wall_epoch = now_secs * 1000 / TEST_EPOCH_MS;
        for node in 0..VALIDATORS {
            let committed = latest_beacon_epoch(&runner, node);
            assert!(
                committed <= wall_epoch,
                "node {node} committed epoch {committed} at t={now_secs}s \
                 (wall epoch {wall_epoch}) — the beacon outran wall-clock",
            );
        }
    }

    // The run must actually have exercised steady-state pacing, not ended
    // mid-catch-up.
    let final_epoch = latest_beacon_epoch(&runner, 0);
    let wall_epoch = now_secs * 1000 / TEST_EPOCH_MS;
    assert!(
        final_epoch + 3 >= wall_epoch,
        "beacon never caught back up to wall-clock (at {final_epoch} of {wall_epoch})",
    );
}
