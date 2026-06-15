//! Liveness baseline for the production reshape harness.
//!
//! Proves a multi-host production cluster can fold real beacon epochs and
//! advance a shard committee's committed height in a real-time test. The
//! `e2e_tests.rs` suite deliberately stops at construction + bind
//! ("consensus exercised separately by the simulator"), so this is the
//! first coverage that drives the `ProductionRunner` to commit a
//! non-genesis block. No reshape here — the reshape scenarios in
//! `reshape_e2e.rs` build on this baseline.

mod cluster;
mod fixtures;

use std::time::Duration;

use cluster::{Cluster, ClusterSpec, HostSpec};
use fixtures::TestFixtures;
use hyperscale_production::VnodeConfig;
use hyperscale_types::{BeaconChainConfig, ReshapeThresholds, ShardId, ValidatorId};
use serial_test::serial;
use tracing_subscriber::fmt;

/// Real-time epoch length. Small enough to fold several epochs inside the
/// liveness timeout, large enough for beacon PC/SPC to commit each block
/// over localhost QUIC.
const EPOCH_MS: u64 = 2000;

/// Generous real-time budget for the cluster to peer, bind, and drive
/// consensus to the liveness targets.
const LIVENESS_TIMEOUT: Duration = Duration::from_secs(60);

fn vnode(fixtures: &TestFixtures, idx: u32, shard: ShardId) -> VnodeConfig {
    VnodeConfig {
        validator_id: ValidatorId::new(u64::from(idx)),
        local_shard: shard,
        signing_key: fixtures.signing_key(idx),
    }
}

/// Four validators in one shard, two per host across two hosts (so real
/// libp2p routing between committee members is exercised). The committee
/// is the full validator set — a clean baseline with no pool surplus and
/// reshaping disabled. Assert the beacon folds several epochs and the
/// shard's committed height advances past genesis, both under timeout.
#[tokio::test]
#[serial]
async fn cluster_folds_epochs_and_commits_blocks() {
    let _ = fmt().with_test_writer().try_init();

    let fixtures = TestFixtures::new(7, 4);
    let shard = ShardId::ROOT;

    let chain_config = BeaconChainConfig {
        epoch_duration_ms: EPOCH_MS,
        num_shards: 1,
        reshape_thresholds: ReshapeThresholds::DISABLED,
        ..BeaconChainConfig::default()
    };

    let cluster = Cluster::start(ClusterSpec {
        topology: fixtures.topology(),
        hosts: vec![
            HostSpec::new(vec![vnode(&fixtures, 0, shard), vnode(&fixtures, 1, shard)]),
            HostSpec::new(vec![vnode(&fixtures, 2, shard), vnode(&fixtures, 3, shard)]),
        ],
        beacon_chain_config: chain_config,
        genesis_config: None,
    })
    .await;

    // The shard committee commits past genesis: the production runner
    // drives consensus, not just construction + bind.
    let height = cluster
        .await_committed_height(shard, 3, LIVENESS_TIMEOUT)
        .await;
    assert!(height >= 3, "shard committed height advanced past genesis");

    // The beacon folds epochs at wall-clock cadence.
    let epoch = cluster.await_beacon_epoch(3, LIVENESS_TIMEOUT).await;
    assert!(epoch >= 3, "beacon folded several epochs");

    cluster.shutdown().await;
}
