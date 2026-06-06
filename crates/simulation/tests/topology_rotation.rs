//! End-to-end cross-shard verification across a shard committee rotation.
//!
//! Boots a 2-shard network and runs past the `SHUFFLE_INTERVAL_EPOCHS` boundary
//! where each shard's committee rotates. With the beacon paced to wall-clock,
//! the shards' weighted-time advances in lockstep with the beacon's epochs, so
//! they reach the rotation and each shard verifies the other's remote headers
//! under the committee seated at the header's weighted timestamp — including
//! headers signed by the *rotated* (post-shuffle) committee.
//!
//! A short epoch (2s) is used so the rotation lands within the run window. The
//! schedule's retention is only a few epochs, so a shard may stall shortly
//! after the rotation (a shard whose tip falls outside the retained window
//! can't resolve its own committee) — but by then each shard has already
//! verified the other's headers under post-shuffle committees, which is the
//! property under test. In production (5-minute epochs) the retention window is
//! tens of minutes of wall-clock and no such stall occurs.

use std::ops::Range;
use std::time::Duration;

use hyperscale_network_memory::NetworkConfig;
use hyperscale_simulation::SimulationRunner;
use hyperscale_types::{BeaconChainConfig, BlockHeight, Epoch, SHUFFLE_INTERVAL_EPOCHS, ShardId};
use tracing_test::traced_test;

/// 2-second epochs: short enough to reach the shuffle within the run window,
/// long enough that the beacon paces (one epoch per `epoch_duration_ms`) rather
/// than stalling against its production-sized SPC/skip timeouts.
const TEST_EPOCH_MS: u64 = 2000;

/// Committee validators per shard. The shuffle retires one member at the
/// boundary; seven keeps the post-rotation committee above quorum.
const PER_SHARD: u32 = 7;

fn rotation_config() -> NetworkConfig {
    NetworkConfig {
        num_shards: 2,
        validators_per_shard: PER_SHARD,
        intra_shard_latency: Duration::from_millis(50),
        cross_shard_latency: Duration::from_millis(50),
        jitter_fraction: 0.1,
        beacon_chain_config: Some(BeaconChainConfig {
            epoch_duration_ms: TEST_EPOCH_MS,
            num_shards: 2,
            shard_size: PER_SHARD,
            ..BeaconChainConfig::default()
        }),
        ..Default::default()
    }
}

/// Host index range for `shard`. Under `SameShardBundled` with one vnode per
/// host, shard `s`'s committee validators occupy hosts
/// `[s·PER_SHARD, (s+1)·PER_SHARD)`.
const fn shard_hosts(shard: u32) -> Range<u32> {
    (shard * PER_SHARD)..((shard + 1) * PER_SHARD)
}

/// Across `verifier_hosts`, the highest committee-anchor epoch among verified
/// remote headers for `source_shard` — the newest epoch whose committee some
/// verifier resolved and checked a QC against.
fn highest_verified_committee_epoch(
    runner: &SimulationRunner,
    verifier_hosts: Range<u32>,
    source_shard: ShardId,
    max_height: u64,
) -> Option<u64> {
    let mut best: Option<u64> = None;
    for host in verifier_hosts {
        let Some(node) = runner.node(host) else {
            continue;
        };
        let coordinator = node.remote_headers_coordinator();
        for height in (1..=max_height).rev() {
            if let Some(verified) = coordinator.get_verified(source_shard, BlockHeight::new(height))
            {
                // A remote header's signing committee is the one seated at its
                // parent QC's weighted timestamp, so that epoch is what the
                // verifier had to resolve to admit it.
                let anchor = verified.header().parent_qc().weighted_timestamp();
                best = Some(best.map_or(anchor.as_millis() / TEST_EPOCH_MS, |b| {
                    b.max(anchor.as_millis() / TEST_EPOCH_MS)
                }));
                break;
            }
        }
    }
    best
}

/// Highest committed shard height across `hosts`.
fn max_committed_height(runner: &SimulationRunner, hosts: Range<u32>) -> u64 {
    hosts
        .filter_map(|h| runner.node(h))
        .map(|n| n.shard_coordinator().committed_height().inner())
        .max()
        .unwrap_or(0)
}

#[traced_test]
#[test]
fn cross_shard_verification_survives_a_committee_rotation() {
    let mut runner = SimulationRunner::new(&rotation_config(), 7);
    runner.initialize_genesis();
    runner.run_until(Duration::from_secs(50));

    let boundary = SHUFFLE_INTERVAL_EPOCHS;
    let storage = runner.beacon_storage(0).expect("host 0 exists");
    let latest = storage
        .latest_committed_epoch()
        .expect("at least one epoch committed past genesis");
    assert!(
        latest > Epoch::new(boundary),
        "beacon must commit past the shuffle boundary (epoch {boundary}), got {latest:?}",
    );

    // The shuffle fires in `apply_epoch(boundary)`, so the active committee at
    // `boundary + 1` differs from the one at `boundary`.
    let active_before = storage
        .get_state_by_epoch(Epoch::new(boundary))
        .expect("boundary epoch state");
    let active_after = storage
        .get_state_by_epoch(Epoch::new(boundary + 1))
        .expect("post-boundary epoch state");
    assert_ne!(
        active_before.shard_committees, active_after.shard_committees,
        "shard committees must rotate across the shuffle at epoch {boundary}",
    );

    // Every host derives the same rotated committee — the schedule is a pure
    // function of beacon state, so verification resolves identically everywhere.
    for host in 1..2 * PER_SHARD {
        let other = runner
            .beacon_storage(host)
            .unwrap_or_else(|| panic!("host {host} exists"))
            .get_state_by_epoch(Epoch::new(boundary + 1))
            .unwrap_or_else(|| panic!("host {host} missing post-boundary state"));
        assert_eq!(
            other.shard_committees,
            active_after.shard_committees,
            "host {host} disagrees on the rotated committee at epoch {}",
            boundary + 1,
        );
    }

    // Each shard verified the other's remote headers under the committee seated
    // at the header's weighted timestamp, reaching headers anchored *past* the
    // shuffle. Those were signed by the rotated committee, so admitting them
    // proves every verifier resolved the rotated set from the header's WT (the
    // pre-shuffle set's signer bitfield would misalign) across a real rotation.
    for (verifier, source) in [(1u32, 0u32), (0u32, 1u32)] {
        let source_shard = ShardId::leaf(1, u64::from(source));
        let source_tip = max_committed_height(&runner, shard_hosts(source));
        let epoch = highest_verified_committee_epoch(
            &runner,
            shard_hosts(verifier),
            source_shard,
            source_tip,
        )
        .unwrap_or_else(|| {
            panic!("shard {verifier} verified no remote header from shard {source}")
        });
        assert!(
            epoch > boundary,
            "shard {verifier} must verify a shard-{source} header signed by the rotated \
             committee (anchor epoch > {boundary}); highest verified anchor epoch was {epoch}",
        );
    }
}
