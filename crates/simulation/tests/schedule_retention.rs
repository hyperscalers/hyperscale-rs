//! Schedule retention across an outage longer than the steady-state window.
//!
//! Isolates one validator while the rest of the network commits beacon
//! epochs well past any fixed few-epoch retention window. On heal, the node
//! replays beacon epochs to the live head — adopting each one evicts
//! schedule entries below the retention floor — while its shard chain still
//! sits at the pre-outage tip. Every artifact that chain can present for
//! verification (synced blocks, live proposals extending the tip) keys its
//! committee lookup at or after the tip's anchor epoch, so the schedule must
//! keep resolving that epoch until shard sync passes it. The floor follows
//! the local chain's committee anchor, which is what this test pins: after
//! full beacon replay, the lagger's schedule still answers at its frontier.
//!
//! Shard height catch-up is deliberately not asserted: at test-sized epochs
//! the shard paces roughly one block per beacon epoch (a fresh block's
//! weighted timestamp sits at wall clock, and the next proposal stalls on
//! the committee lookahead until the beacon commits that window), and it
//! parks entirely while a healed peer rejoins — sim pacing dynamics
//! unrelated to schedule retention.

use std::time::Duration;

use hyperscale_network_memory::{NetworkConfig, NodeIndex};
use hyperscale_simulation::{EPOCH_MS, SimulationRunner};
use hyperscale_types::{BeaconChainConfig, Epoch, WeightedTimestamp};
use tracing_test::traced_test;

/// Four validators: one beacon committee of four (PC quorum 3), so beacon
/// consensus keeps committing with one node isolated.
const VALIDATORS: u32 = 4;

/// The isolated validator.
const LAGGER: NodeIndex = 3;

/// Epochs the healthy majority must commit during the outage — comfortably
/// past any fixed few-epoch retention window.
const OUTAGE_EPOCHS: u64 = 6;

fn retention_config() -> NetworkConfig {
    NetworkConfig {
        num_shards: 1,
        validators_per_shard: VALIDATORS,
        jitter_fraction: 0.1,
        beacon_chain_config: Some(BeaconChainConfig {
            epoch_duration_ms: EPOCH_MS,
            num_shards: 1,
            shard_size: VALIDATORS,
            ..BeaconChainConfig::default()
        }),
        ..Default::default()
    }
}

fn committed_height(runner: &SimulationRunner, node: NodeIndex) -> u64 {
    runner
        .node(node)
        .expect("node exists")
        .shard_coordinator()
        .committed_height()
        .inner()
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
fn schedule_resolves_the_chain_frontier_after_an_outage() {
    let mut runner = SimulationRunner::new(&retention_config(), 11);
    runner.initialize_genesis();

    // Healthy start: everyone commits shard blocks and a beacon epoch or two.
    let mut now_secs = 10;
    runner.run_until(Duration::from_secs(now_secs));
    assert!(
        committed_height(&runner, LAGGER) > 0,
        "lagger must commit blocks before the outage"
    );

    // Outage: the healthy majority keeps committing beacon epochs until the
    // lagger's frontier has aged well past any fixed few-epoch window.
    // Beacon pacing varies with committee latency, so advance adaptively
    // under a hard cap.
    runner.network_mut().isolate_node(LAGGER);
    let frontier_epoch = latest_beacon_epoch(&runner, LAGGER);
    while latest_beacon_epoch(&runner, 0) < frontier_epoch + OUTAGE_EPOCHS {
        now_secs += 5;
        assert!(
            now_secs <= 130,
            "healthy majority failed to advance {OUTAGE_EPOCHS} epochs during the outage \
             (at epoch {})",
            latest_beacon_epoch(&runner, 0),
        );
        runner.run_until(Duration::from_secs(now_secs));
    }

    // Heal, then run until the lagger has replayed beacon epochs to the
    // live head.
    runner.network_mut().heal_all();
    let recovery_deadline = now_secs + 90;
    while latest_beacon_epoch(&runner, LAGGER) + 1 < latest_beacon_epoch(&runner, 0) {
        now_secs += 2;
        assert!(
            now_secs <= recovery_deadline,
            "lagger's beacon failed to reach the live head (at {} of {})",
            latest_beacon_epoch(&runner, LAGGER),
            latest_beacon_epoch(&runner, 0),
        );
        runner.run_until(Duration::from_secs(now_secs));
    }

    // The lagger replayed many epochs past its shard frontier...
    let head_epoch = latest_beacon_epoch(&runner, LAGGER);
    assert!(
        head_epoch >= frontier_epoch + OUTAGE_EPOCHS,
        "replay must end far past the frontier (head {head_epoch}, frontier {frontier_epoch})",
    );

    // ...and its schedule still resolves the committee at that frontier:
    // the eviction floor held the frontier's epoch retained through every
    // adoption, keeping the stalled shard chain verifiable. A frontier-blind
    // window would have evicted it during replay, wedging shard sync on a
    // committee lookup that can never resolve.
    let frontier_wt = WeightedTimestamp::from_millis(frontier_epoch * EPOCH_MS);
    assert!(
        runner
            .node(LAGGER)
            .expect("lagger exists")
            .beacon_coordinator()
            .topology_schedule()
            .at(frontier_wt)
            .is_some(),
        "lagger's schedule must still resolve its chain frontier (epoch {frontier_epoch}) \
         after replaying to epoch {head_epoch}",
    );
}
