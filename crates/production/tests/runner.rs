//! Production runner lifecycle tests: construction with real networking,
//! graceful shutdown, and runtime shard join/leave through the supervisor.
//!
//! Real localhost QUIC and `RocksDB`. `#[serial]` to avoid port conflicts and
//! state leakage; runs on a multi-threaded runtime to match the production
//! host's runtime shape.

mod support;

use std::sync::Arc;
use std::time::Duration;

use hyperscale_network_libp2p::Libp2pConfig;
use hyperscale_production::{LocalValidator, ProductionRunner, ShardCommand, VnodeConfig};
use hyperscale_shard::ShardConsensusConfig;
use hyperscale_storage::{BeaconChainReader, BeaconStorage};
use hyperscale_storage_rocksdb::RocksDbBeaconStorage;
use hyperscale_test_helpers::fixtures::TestFixtures;
use hyperscale_types::{BeaconChainConfig, ReshapeThresholds, ShardId, ValidatorId};
use serial_test::serial;
use support::{CONNECTION_TIMEOUT, temp_storage_dir, temp_storage_factory};
use tempfile::TempDir;
use tokio::task::spawn;
use tokio::time::{sleep, timeout};
use tracing::info;
use tracing_subscriber::fmt;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_production_runner_with_network() {
    let _ = fmt().with_test_writer().try_init();

    let fixtures = TestFixtures::new(42, 1);

    let temp_dir = TempDir::new().unwrap();

    let network_config = Libp2pConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        bootstrap_peers: vec![],
        ..Default::default()
    };

    let beacon_storage: Arc<dyn BeaconStorage> =
        Arc::new(RocksDbBeaconStorage::open(temp_dir.path().join("beacon_db")).unwrap());
    let runner = ProductionRunner::builder(
        vec![LocalValidator {
            validator_id: ValidatorId::new(0),
            signing_key: fixtures.signing_key(0),
        }],
        fixtures.genesis_validators(),
        ShardConsensusConfig::default(),
        beacon_storage,
        network_config,
        temp_storage_factory(&temp_dir),
        temp_storage_dir(&temp_dir),
    )
    .build();

    assert!(runner.is_ok(), "Runner creation should succeed");
    let mut runner = runner.unwrap();

    // Verify network is configured
    let network = runner.network();
    info!(peer_id = %network.local_peer_id(), "Runner has network");

    // Get listen addresses
    sleep(Duration::from_millis(100)).await;
    let addrs = network.listen_addresses().await;
    info!(addresses = ?addrs, "Runner listening on");

    // Get shutdown handle before running
    let shutdown = runner
        .shutdown_handle()
        .expect("Should have shutdown handle");
    let handle = spawn(runner.run());

    sleep(Duration::from_millis(500)).await;
    drop(shutdown);

    let result = timeout(Duration::from_secs(5), handle).await;
    assert!(result.is_ok(), "Runner should exit cleanly");

    info!("Production runner with network test completed");
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_graceful_shutdown() {
    let _ = fmt().with_test_writer().try_init();

    let fixtures = TestFixtures::new(42, 1);

    let temp_dir = TempDir::new().unwrap();

    let network_config = Libp2pConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        bootstrap_peers: vec![],
        ..Default::default()
    };

    let beacon_storage: Arc<dyn BeaconStorage> =
        Arc::new(RocksDbBeaconStorage::open(temp_dir.path().join("beacon_db")).unwrap());
    let mut runner = ProductionRunner::builder(
        vec![LocalValidator {
            validator_id: ValidatorId::new(0),
            signing_key: fixtures.signing_key(0),
        }],
        fixtures.genesis_validators(),
        ShardConsensusConfig::default(),
        beacon_storage,
        network_config,
        temp_storage_factory(&temp_dir),
        temp_storage_dir(&temp_dir),
    )
    .build()
    .unwrap();

    let shutdown = runner
        .shutdown_handle()
        .expect("Should have shutdown handle");
    let handle = spawn(runner.run());

    // Let it run briefly
    sleep(Duration::from_millis(200)).await;

    // Shutdown via handle
    drop(shutdown);

    // Should exit within 5 seconds (graceful shutdown max)
    let result = timeout(Duration::from_secs(5), handle).await;
    assert!(
        result.is_ok(),
        "Runner should exit within graceful shutdown timeout"
    );

    let run_result = result.unwrap();
    assert!(run_result.is_ok(), "Runner should return Ok on shutdown");

    info!("Graceful shutdown test completed");
}

/// Runtime shard teardown through the supervisor: a runner seated on the root
/// shard leaves it mid-run — the departing vnode's pinned thread is joined and
/// its network subscriptions torn down — then shuts down cleanly hosting no
/// shard. The startup/join half is covered by
/// [`pooled_validator_boots_as_follower_only_host`].
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_runtime_shard_leave_tears_down() {
    let _ = fmt().with_test_writer().try_init();

    let fixtures = TestFixtures::new(43, 1);

    let temp_dir = TempDir::new().unwrap();
    let network_config = Libp2pConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        bootstrap_peers: vec![],
        ..Default::default()
    };
    let beacon_storage: Arc<dyn BeaconStorage> =
        Arc::new(RocksDbBeaconStorage::open(temp_dir.path().join("beacon_db")).unwrap());

    let mut runner = ProductionRunner::builder(
        vec![LocalValidator {
            validator_id: ValidatorId::new(0),
            signing_key: fixtures.signing_key(0),
        }],
        fixtures.genesis_validators(),
        ShardConsensusConfig::default(),
        beacon_storage,
        network_config,
        temp_storage_factory(&temp_dir),
        temp_storage_dir(&temp_dir),
    )
    .build()
    .unwrap();

    let adapter = Arc::clone(runner.network());
    let reconfigure = runner.reconfigure_handle();
    let shutdown = runner
        .shutdown_handle()
        .expect("Should have shutdown handle");
    let handle = spawn(runner.run());
    sleep(Duration::from_millis(200)).await;
    assert!(adapter.local_shards().contains(&ShardId::ROOT));

    // Leave the root shard: the single vnode departing tears the shard down.
    reconfigure
        .send(ShardCommand::Leave {
            shard: ShardId::ROOT,
        })
        .await
        .expect("supervisor accepts commands");
    timeout(CONNECTION_TIMEOUT, async {
        while adapter.local_shards().contains(&ShardId::ROOT) {
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("left shard is removed from the adapter");
    assert!(
        adapter.local_shards().is_empty(),
        "the host hosts no shard after leaving the root"
    );

    drop(shutdown);
    let result = timeout(Duration::from_secs(5), handle).await;
    assert!(result.is_ok(), "Runner should exit after the leave");
    assert!(result.unwrap().is_ok(), "Runner should return Ok");

    info!("Runtime shard leave/teardown test completed");
}

/// A validator the beacon genesis leaves `Pooled` — registered in the global
/// set but in no shard committee — boots as a follower-only host. The runner
/// reads the committed beacon state, derives no seat, and brings the host up
/// hosting no shard with its beacon-follower pool thread running. A later
/// `ShardCommand::Join` seats it onto a shard, draining it from the pool —
/// the startup half of the drain/pool/reseat cycle the sim covers end to end.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn pooled_validator_boots_as_follower_only_host() {
    let _ = fmt().with_test_writer().try_init();

    // One seated validator (id 0 on ROOT) plus one pool surplus (id 1) that
    // the genesis committee never seats.
    let fixtures = TestFixtures::with_surplus(44, 1, 1);
    let surplus = ValidatorId::new(1);

    let temp_dir = TempDir::new().unwrap();
    let network_config = Libp2pConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        bootstrap_peers: vec![],
        ..Default::default()
    };
    let beacon_storage: Arc<dyn BeaconStorage> =
        Arc::new(RocksDbBeaconStorage::open(temp_dir.path().join("beacon_db")).unwrap());

    let mut runner = ProductionRunner::builder(
        vec![LocalValidator {
            validator_id: surplus,
            signing_key: fixtures.signing_key(1),
        }],
        fixtures.genesis_validators(),
        ShardConsensusConfig::default(),
        beacon_storage,
        network_config,
        temp_storage_factory(&temp_dir),
        temp_storage_dir(&temp_dir),
    )
    .build()
    .unwrap();

    // Derivation seated nothing: the host carries no shard before it runs.
    assert!(
        runner.network().local_shards().is_empty(),
        "a pooled validator seats no shard at startup"
    );

    let adapter = Arc::clone(runner.network());
    let reconfigure = runner.reconfigure_handle();
    let shutdown = runner
        .shutdown_handle()
        .expect("Should have shutdown handle");
    let handle = spawn(runner.run());
    sleep(Duration::from_millis(200)).await;

    // Still hosts no shard while the follower pool thread runs.
    assert!(
        adapter.local_shards().is_empty(),
        "follower-only host hosts no shard"
    );

    // Seat the pooled validator onto ROOT: the supervisor opens the store,
    // brings the shard up, and retires the validator's pool follower.
    reconfigure
        .send(ShardCommand::Join {
            shard: ShardId::ROOT,
            vnodes: vec![VnodeConfig {
                validator_id: surplus,
                local_shard: ShardId::ROOT,
                signing_key: fixtures.signing_key(1),
            }],
        })
        .await
        .expect("supervisor accepts commands");
    timeout(CONNECTION_TIMEOUT, async {
        while !adapter.local_shards().contains(&ShardId::ROOT) {
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("seated shard becomes hosted on the adapter");

    drop(shutdown);
    let result = timeout(Duration::from_secs(5), handle).await;
    assert!(result.is_ok(), "Runner should exit after seating");
    assert!(result.unwrap().is_ok(), "Runner should return Ok");

    info!("Pooled follower-boot test completed");
}

/// The `beacon_chain_config` builder setter threads a custom config through into
/// the committed beacon genesis state. Every other production test leaves the
/// setter unused and is unaffected: a custom `epoch_duration_ms` and reshape
/// `split_bytes` reach the genesis state only when set explicitly.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn beacon_chain_config_reaches_genesis() {
    let _ = fmt().with_test_writer().try_init();

    let fixtures = TestFixtures::new(42, 1);

    let temp_dir = TempDir::new().unwrap();
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
        vec![LocalValidator {
            validator_id: ValidatorId::new(0),
            signing_key: fixtures.signing_key(0),
        }],
        fixtures.genesis_validators(),
        ShardConsensusConfig::default(),
        beacon_reader,
        network_config,
        temp_storage_factory(&temp_dir),
        temp_storage_dir(&temp_dir),
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
        state.params.reshape_thresholds.split_bytes, 50_000,
        "custom split threshold seeds the live network params at genesis"
    );
}
