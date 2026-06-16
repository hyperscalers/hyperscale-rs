//! Production resharding end-to-end scenarios.
//!
//! Drives real beacon folds over a real libp2p cluster on real
//! `RocksDbShardStorage` to cover the production-only reshape wiring the
//! simulation suite never touches: the beacon fold → `ParticipationChange`
//! → `ShardSupervisor` duty chain and the `RocksDbShardStorage` flips.
//! Like the rest of the production e2e tests these are `#[serial]`,
//! real-time, and bounded by `timeout` — never fixed sleeps for the
//! wait-for-condition assertions.

mod cluster;
mod fixtures;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use cluster::{Cluster, ClusterSpec, HostSpec};
use fixtures::TestFixtures;
use hyperscale_network_libp2p::Libp2pConfig;
use hyperscale_production::{ProductionRunner, VnodeConfig};
use hyperscale_shard::ShardConsensusConfig;
use hyperscale_storage::{BeaconChainReader, BeaconStorage};
use hyperscale_storage_rocksdb::{RocksDbBeaconStorage, RocksDbShardStorage};
use hyperscale_types::{
    BeaconChainConfig, ReshapeThresholds, ShardId, ValidatorId, shard_prefix_path,
};
use serial_test::serial;
use tempfile::TempDir;
use tracing_subscriber::fmt;

/// Real-time epoch length: short enough to fold the many epochs a split
/// takes inside the test budget, long enough for beacon PC/SPC to commit
/// each block over localhost QUIC well under its production-sized SPC
/// timeout.
const EPOCH_MS: u64 = 2000;

fn vnode(fixtures: &TestFixtures, idx: u32, shard: ShardId) -> VnodeConfig {
    VnodeConfig {
        validator_id: ValidatorId::new(u64::from(idx)),
        local_shard: shard,
        signing_key: fixtures.signing_key(idx),
    }
}

/// A custom `beacon_chain_config` threads through the builder into the
/// committed beacon genesis state. This is the single production hook the
/// rest of the suite depends on: the default path (every other production
/// e2e test) leaves the setter unused and is unaffected, so a custom
/// `epoch_duration_ms` + reshape `split_bytes` reach the genesis state
/// only when set explicitly.
#[tokio::test(flavor = "multi_thread", worker_threads = 16)]
#[serial]
async fn beacon_chain_config_reaches_genesis() {
    let _ = fmt().with_test_writer().try_init();

    let fixtures = TestFixtures::new(42, 1);

    let temp_dir = TempDir::new().unwrap();
    let storage = Arc::new(
        RocksDbShardStorage::open(
            temp_dir.path().join("test_db"),
            shard_prefix_path(ShardId::ROOT),
        )
        .unwrap(),
    );
    let network_config = Libp2pConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        bootstrap_peers: vec![],
        ..Default::default()
    };
    let beacon_storage =
        Arc::new(RocksDbBeaconStorage::open(temp_dir.path().join("beacon_db")).unwrap());

    let chain_config = BeaconChainConfig {
        epoch_duration_ms: 400,
        reshape_thresholds: ReshapeThresholds {
            split_bytes: 50_000,
        },
        ..BeaconChainConfig::default()
    };

    let beacon_reader: Arc<dyn BeaconStorage> = beacon_storage.clone();
    let runner = ProductionRunner::builder(
        vec![VnodeConfig {
            validator_id: ValidatorId::new(0),
            local_shard: ShardId::ROOT,
            signing_key: fixtures.signing_key(0),
        }],
        fixtures.topology(),
        ShardConsensusConfig::default(),
        HashMap::from([(ShardId::ROOT, storage)]),
        beacon_reader,
        network_config,
        cluster::temp_storage_factory(&temp_dir),
        cluster::temp_storage_dir(&temp_dir),
    )
    .beacon_chain_config(chain_config)
    .build();
    assert!(
        runner.is_ok(),
        "runner builds with a custom beacon chain config"
    );

    // Build commits the genesis (block, state) pair into the beacon store.
    let (_block, state) = beacon_storage
        .latest_committed()
        .expect("genesis pair committed at build time");
    assert_eq!(
        state.chain_config.epoch_duration_ms, 400,
        "custom epoch duration reaches the beacon genesis state"
    );
    assert_eq!(
        state.chain_config.reshape_thresholds.split_bytes, 50_000,
        "custom split threshold reaches the beacon genesis state"
    );
}

/// A real production split: one ROOT shard, its committee plus a pool
/// surplus, splits into two children. The four committee validators run
/// ROOT consensus; the four pool-surplus validators follow ROOT passively
/// until the beacon draws them as the observer cohort. The beacon admits
/// the split, the observers snap-sync the children and signal ready, the
/// readiness gate fires, the parent coasts to its terminal crossing, and
/// the children seat from the beacon-composed anchors and commit past
/// their genesis — all through the production `ShardSupervisor` duty chain
/// and `RocksDbShardStorage` flips.
///
/// Real-time and `#[serial]`: the split spans several wall-clock epochs
/// (trigger fold, admission, observer sync, gate, terminal coast, child
/// seating), so the simulated network latency paces ROOT to keep the
/// consensus clock on wall-clock. Runs in tens of seconds on a
/// multi-threaded runtime, matching the deployed host (a single-threaded
/// test runtime serializing the eight hosts lags the fold).
#[tokio::test(flavor = "multi_thread", worker_threads = 16)]
#[serial]
async fn split_seats_both_children_from_composed_anchors() {
    let _ = fmt().with_test_writer().try_init();

    // 4 committee validators on ROOT + 4 pool-surplus (the split cohort).
    let fixtures = TestFixtures::with_shards_and_surplus(11, 4, 1, 4);
    let parent = ShardId::ROOT;
    let (child_left, child_right) = parent.children();

    let chain_config = BeaconChainConfig {
        epoch_duration_ms: EPOCH_MS,
        num_shards: 1,
        // Arm the trigger from genesis: every committed byte count clears
        // zero, so ROOT's own quorum asserts the split immediately.
        reshape_thresholds: ReshapeThresholds { split_bytes: 0 },
        ..BeaconChainConfig::default()
    };

    // Seat the full validator set one validator per host, across eight
    // hosts — so every drawn cohort member is live on some host and every
    // seat owns its own libp2p peer and storage directory. The latter
    // matters at the flip: a child's parent-half adoption checkpoints into
    // its own dir while a colocated observer would still hold that dir's
    // store open, so packing both seats of one child onto a host would
    // collide on the per-directory store lock. One vnode per host keeps
    // each adoption and observer flip on its own store. All eight start on
    // ROOT; the surplus are passive followers there until drawn as
    // observers.
    let cluster = Cluster::start(ClusterSpec {
        topology: fixtures.topology(),
        hosts: (0..8)
            .map(|v| HostSpec::new(vec![vnode(&fixtures, v, parent)]))
            .collect(),
        beacon_chain_config: chain_config,
        genesis_config: None,
        // Pace each outbound send to a realistic inter-host RTT. Without it
        // the loadless committee forms quorum certificates dozens of times a
        // second, floods this single-process harness, and lags the consensus
        // clock behind wall-clock — so the gate and child seating miss the
        // real-time budget. At ~60 ms ROOT commits a few blocks a second and
        // the clock tracks wall-clock.
        simulated_outbound_latency: Duration::from_millis(60),
    })
    .await;

    // The beacon admits the split: a pending Split for ROOT with a drawn
    // observer cohort.
    cluster
        .await_split_admitted(parent, Duration::from_secs(90))
        .await;

    // Both children flip in: observers sync, ReshapeReady fires the gate,
    // the parent coasts to its crossing, and the children seat from the
    // composed anchors.
    cluster
        .await_any_host_serves(child_left, Duration::from_secs(120))
        .await;
    cluster
        .await_any_host_serves(child_right, Duration::from_secs(120))
        .await;

    // Each child commits past its genesis — the seated store, derived
    // genesis, and committee are coherent.
    cluster
        .await_height_advances(child_left, Duration::from_secs(60))
        .await;
    cluster
        .await_height_advances(child_right, Duration::from_secs(60))
        .await;

    // Root fidelity: each child's committed root reproduces the
    // beacon-composed anchor (the parent's subtree node at the child
    // prefix).
    cluster
        .await_root_matches_anchor(child_left, Duration::from_secs(30))
        .await;
    cluster
        .await_root_matches_anchor(child_right, Duration::from_secs(30))
        .await;

    // The parent stops: its chain is terminal, so its committed height no
    // longer advances.
    cluster
        .assert_height_frozen(parent, Duration::from_secs(3 * EPOCH_MS / 1000))
        .await;

    cluster.shutdown().await;
}

/// A real production merge: two sibling shards, each below the merge
/// threshold from genesis, collapse back into their parent. Each child's
/// committee asserts the merge; the beacon pairs it and draws half of each
/// committee as the keeper set. Each keeper runs the production keep duty —
/// syncing the sibling half off its committee, signalling `ReshapeReady` on
/// its own child, then building the merged parent store — and once the
/// ready keepers clear the gate the children coast to their crossing, the
/// beacon composes the parent anchor from their terminal roots, and the
/// keepers flip onto the parent. Exercises the production `ShardSupervisor`
/// keep path and the `RocksDbShardStorage` merge adoption.
///
/// Real-time and `#[serial]` like its split sibling. Runs on a
/// multi-threaded runtime: the merge keeps two child shards live through
/// the grow (versus the split's single parent), so the beacon fold, both
/// children's consensus, and the keeper duties all run at once. A
/// production host has a multi-threaded runtime to itself; a
/// single-threaded test runtime serializing the cluster stalls the fold,
/// where giving it real worker threads matches the deployed shape.
#[tokio::test(flavor = "multi_thread", worker_threads = 16)]
#[serial]
async fn keepers_merge_two_siblings_into_their_parent() {
    let _ = fmt().with_test_writer().try_init();

    // Two sibling shards with a committee of four each; the merge draws
    // half of each committee, so the merged parent starts at full strength
    // with four keepers.
    let fixtures = TestFixtures::with_shards(13, 4, 2);
    let parent = ShardId::ROOT;
    let (left, right) = parent.children();

    let chain_config = BeaconChainConfig {
        epoch_duration_ms: EPOCH_MS,
        num_shards: 2,
        // merge_bytes is split_bytes / 8 = 650_000, above each child's
        // genesis byte total (the heavier half is ~611k, the lighter
        // ~373k), so both children assert the merge from genesis and
        // neither ever splits.
        reshape_thresholds: ReshapeThresholds {
            split_bytes: 5_200_000,
        },
        ..BeaconChainConfig::default()
    };

    // Four hosts, each running one left- and one right-child vnode: host h
    // holds left committee member h and right member h+4. Packing both
    // children onto every host halves the cluster (four libp2p endpoints
    // instead of eight), which is the load relief the merge's two live
    // child chains need to fold their ready signals before the readiness
    // TTL churns the pairing. The keeper duty coalesces a host's two seats
    // onto one shared parent store at the boundary, so they don't collide
    // on the directory lock; and because each host runs both children, the
    // boundary handoff reads both terminated halves from local stores with
    // no cross-committee sync.
    let cluster = Cluster::start(ClusterSpec {
        topology: fixtures.topology(),
        hosts: (0..4)
            .map(|h| {
                HostSpec::new(vec![
                    vnode(&fixtures, h, left),
                    vnode(&fixtures, h + 4, right),
                ])
            })
            .collect(),
        beacon_chain_config: chain_config,
        genesis_config: None,
        // Pace each shard's consensus to a realistic RTT so the loadless
        // committees don't race the single-process harness's clock — see
        // the split scenario above.
        simulated_outbound_latency: Duration::from_millis(60),
    })
    .await;

    // The beacon pairs the merge: a pending Merge for ROOT with half of
    // each child committee (four validators) drawn as keepers.
    cluster
        .await_merge_paired(parent, 4, Duration::from_secs(90))
        .await;

    // The merged parent seats: the keepers sync their sibling halves and
    // signal ready, the gate fires, the children coast to their crossing,
    // and the keepers flip onto ROOT from the composed anchor.
    cluster
        .await_any_host_serves(parent, Duration::from_secs(120))
        .await;

    // The merged parent commits past its genesis — the union-imported
    // store, derived genesis, and keeper committee are coherent.
    cluster
        .await_height_advances(parent, Duration::from_secs(60))
        .await;

    // Root fidelity: the merged committed root reproduces the
    // beacon-composed anchor (the `hash_internal` of the two child terminal
    // roots).
    cluster
        .await_root_matches_anchor(parent, Duration::from_secs(30))
        .await;

    // The children stop: their chains are terminal once they cross.
    cluster
        .assert_height_frozen(left, Duration::from_secs(3 * EPOCH_MS / 1000))
        .await;
    cluster
        .assert_height_frozen(right, Duration::from_secs(3 * EPOCH_MS / 1000))
        .await;

    cluster.shutdown().await;
}
