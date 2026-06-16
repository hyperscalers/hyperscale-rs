//! Multi-vnode hosting tests: one host carrying several vnodes, both
//! same-shard and cross-shard.
//!
//! Validates that the multi-validator bind plumbing lands every hosted
//! validator id on the remote adapter's `validator_peers` map. Consensus
//! progress is timing-sensitive over real networking and is exercised
//! separately by the simulator; these scope themselves to the
//! production-runner construction path and the multi-validator handshake.
//! `#[serial]`; runs on a multi-threaded runtime to match the production
//! host's runtime shape.

mod fixtures;
mod support;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use fixtures::TestFixtures;
use hyperscale_network_libp2p::Libp2pConfig;
use hyperscale_production::{ProductionRunner, VnodeConfig};
use hyperscale_shard::ShardConsensusConfig;
use hyperscale_storage::BeaconStorage;
use hyperscale_storage_rocksdb::{RocksDbBeaconStorage, RocksDbShardStorage};
use hyperscale_types::{ShardId, ValidatorId, shard_prefix_path};
use serial_test::serial;
use support::{temp_storage_dir, temp_storage_factory};
use tempfile::TempDir;
use tokio::task::spawn;
use tokio::time::{sleep, timeout};
use tracing::info;
use tracing_subscriber::fmt;

/// Spin up two hosts that each carry two same-shard vnodes, let them peer,
/// and check that the multi-validator bind plumbing lands every hosted
/// validator id on the remote adapter's `validator_peers` map. Real libp2p,
/// real `RocksDB`; consensus progress is exercised separately by the
/// simulator's V=2 test and is timing-sensitive over real network — this
/// test scopes itself to validating the production-runner construction
/// path and the multi-validator handshake.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_v2_same_shard_production_runner_binds_all_vnodes() {
    let _ = fmt().with_test_writer().try_init();

    // Four validators, all in shard 0; two per host.
    let fixtures = TestFixtures::new(7, 4);

    let temp_dir0 = TempDir::new().unwrap();
    let temp_dir1 = TempDir::new().unwrap();
    let storage0 = Arc::new(
        RocksDbShardStorage::open(
            temp_dir0.path().join("db0"),
            shard_prefix_path(ShardId::ROOT),
        )
        .unwrap(),
    );
    let storage1 = Arc::new(
        RocksDbShardStorage::open(
            temp_dir1.path().join("db1"),
            shard_prefix_path(ShardId::ROOT),
        )
        .unwrap(),
    );

    let network_config0 = Libp2pConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        bootstrap_peers: vec![],
        ..Default::default()
    };

    let host0_vnodes = vec![
        VnodeConfig {
            validator_id: ValidatorId::new(0),
            local_shard: ShardId::ROOT,
            signing_key: fixtures.signing_key(0),
        },
        VnodeConfig {
            validator_id: ValidatorId::new(1),
            local_shard: ShardId::ROOT,
            signing_key: fixtures.signing_key(1),
        },
    ];
    let beacon_storage0: Arc<dyn BeaconStorage> =
        Arc::new(RocksDbBeaconStorage::open(temp_dir0.path().join("beacon_db")).unwrap());
    let mut runner0 = ProductionRunner::builder(
        host0_vnodes,
        fixtures.topology(),
        ShardConsensusConfig::default(),
        HashMap::from([(ShardId::ROOT, storage0)]),
        beacon_storage0,
        network_config0,
        temp_storage_factory(&temp_dir0),
        temp_storage_dir(&temp_dir0),
    )
    .build()
    .expect("host 0 builder");

    let adapter0 = Arc::clone(runner0.network());
    assert_eq!(
        adapter0.local_validator_ids(),
        &[ValidatorId::new(0), ValidatorId::new(1)],
        "host 0 should expose both hosted validator ids"
    );

    // Bind host 1 to host 0's listen address.
    sleep(Duration::from_millis(200)).await;
    let host0_addrs = adapter0.listen_addresses().await;
    assert!(!host0_addrs.is_empty(), "host 0 must be listening");
    let host0_addr = host0_addrs[0].clone();

    let network_config1 = Libp2pConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        bootstrap_peers: vec![host0_addr],
        ..Default::default()
    };
    let host1_vnodes = vec![
        VnodeConfig {
            validator_id: ValidatorId::new(2),
            local_shard: ShardId::ROOT,
            signing_key: fixtures.signing_key(2),
        },
        VnodeConfig {
            validator_id: ValidatorId::new(3),
            local_shard: ShardId::ROOT,
            signing_key: fixtures.signing_key(3),
        },
    ];
    let beacon_storage1: Arc<dyn BeaconStorage> =
        Arc::new(RocksDbBeaconStorage::open(temp_dir1.path().join("beacon_db")).unwrap());
    let mut runner1 = ProductionRunner::builder(
        host1_vnodes,
        fixtures.topology(),
        ShardConsensusConfig::default(),
        HashMap::from([(ShardId::ROOT, storage1)]),
        beacon_storage1,
        network_config1,
        temp_storage_factory(&temp_dir1),
        temp_storage_dir(&temp_dir1),
    )
    .build()
    .expect("host 1 builder");

    let adapter1 = Arc::clone(runner1.network());
    assert_eq!(
        adapter1.local_validator_ids(),
        &[ValidatorId::new(2), ValidatorId::new(3)],
        "host 1 should expose both hosted validator ids"
    );

    let shutdown0 = runner0.shutdown_handle().expect("shutdown0");
    let shutdown1 = runner1.shutdown_handle().expect("shutdown1");
    let h0 = spawn(runner0.run());
    let h1 = spawn(runner1.run());

    // Each handshake (Noise → identify → validator-bind) takes a few
    // hundred ms; wait until both sides resolve every remote vid or the
    // bind timeout elapses.
    let bound = timeout(Duration::from_secs(10), async {
        loop {
            let host0_sees = [
                adapter0.peer_for_validator(ValidatorId::new(2)),
                adapter0.peer_for_validator(ValidatorId::new(3)),
            ];
            let host1_sees = [
                adapter1.peer_for_validator(ValidatorId::new(0)),
                adapter1.peer_for_validator(ValidatorId::new(1)),
            ];
            if host0_sees.iter().all(Option::is_some) && host1_sees.iter().all(Option::is_some) {
                return (host0_sees, host1_sees);
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("multi-vnode bind should complete within timeout");

    let (host0_sees, host1_sees) = bound;
    let host1_peer = adapter1.local_peer_id();
    let host0_peer = adapter0.local_peer_id();
    // Every remote validator id on host 0 resolves to host 1's single peer,
    // and vice versa — this is the load-bearing multi-vnode bind property.
    for resolved in host0_sees {
        assert_eq!(resolved, Some(host1_peer));
    }
    for resolved in host1_sees {
        assert_eq!(resolved, Some(host0_peer));
    }

    drop(shutdown0);
    drop(shutdown1);
    let _ = timeout(Duration::from_secs(5), h0).await;
    let _ = timeout(Duration::from_secs(5), h1).await;

    info!("V=2 same-shard production-runner bind test completed");
}

/// Spin up two hosts that each carry two cross-shard vnodes (one in
/// shard 0, one in shard 1) and check that the multi-validator bind
/// plumbing lands every hosted validator id on the remote adapter's
/// `validator_peers` map. Smoke test for the production runner's
/// cross-shard hosting construction path — consensus progress is
/// timing-sensitive over real networking and is exercised separately
/// by the simulator.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_v2_different_shard_production_runner_binds_all_vnodes() {
    let _ = fmt().with_test_writer().try_init();

    // Four validators across two shards: 0/1 in shard 0, 2/3 in shard 1.
    // Each host carries one vnode from each shard.
    let fixtures = TestFixtures::with_shards(7, 2, 2);

    let temp_dir0 = TempDir::new().unwrap();
    let temp_dir1 = TempDir::new().unwrap();

    // Two RocksDB stores per host — one per hosted shard.
    let host0_s0 = Arc::new(
        RocksDbShardStorage::open(
            temp_dir0.path().join("db0_s0"),
            shard_prefix_path(ShardId::leaf(1, 0)),
        )
        .unwrap(),
    );
    let host0_s1 = Arc::new(
        RocksDbShardStorage::open(
            temp_dir0.path().join("db0_s1"),
            shard_prefix_path(ShardId::leaf(1, 1)),
        )
        .unwrap(),
    );
    let host1_s0 = Arc::new(
        RocksDbShardStorage::open(
            temp_dir1.path().join("db1_s0"),
            shard_prefix_path(ShardId::leaf(1, 0)),
        )
        .unwrap(),
    );
    let host1_s1 = Arc::new(
        RocksDbShardStorage::open(
            temp_dir1.path().join("db1_s1"),
            shard_prefix_path(ShardId::leaf(1, 1)),
        )
        .unwrap(),
    );

    let network_config0 = Libp2pConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        bootstrap_peers: vec![],
        ..Default::default()
    };

    // Host 0: validator 0 (shard 0) + validator 2 (shard 1).
    let host0_vnodes = vec![
        VnodeConfig {
            validator_id: ValidatorId::new(0),
            local_shard: ShardId::leaf(1, 0),
            signing_key: fixtures.signing_key(0),
        },
        VnodeConfig {
            validator_id: ValidatorId::new(2),
            local_shard: ShardId::leaf(1, 1),
            signing_key: fixtures.signing_key(2),
        },
    ];
    let beacon_storage0: Arc<dyn BeaconStorage> =
        Arc::new(RocksDbBeaconStorage::open(temp_dir0.path().join("beacon_db")).unwrap());
    let mut runner0 = ProductionRunner::builder(
        host0_vnodes,
        fixtures.topology(),
        ShardConsensusConfig::default(),
        HashMap::from([
            (ShardId::leaf(1, 0), host0_s0),
            (ShardId::leaf(1, 1), host0_s1),
        ]),
        beacon_storage0,
        network_config0,
        temp_storage_factory(&temp_dir0),
        temp_storage_dir(&temp_dir0),
    )
    .build()
    .expect("host 0 builder");

    let adapter0 = Arc::clone(runner0.network());
    assert_eq!(
        adapter0.local_validator_ids(),
        &[ValidatorId::new(0), ValidatorId::new(2)],
        "host 0 should expose its cross-shard validator ids"
    );

    sleep(Duration::from_millis(200)).await;
    let host0_addrs = adapter0.listen_addresses().await;
    assert!(!host0_addrs.is_empty(), "host 0 must be listening");
    let host0_addr = host0_addrs[0].clone();

    let network_config1 = Libp2pConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        bootstrap_peers: vec![host0_addr],
        ..Default::default()
    };
    // Host 1: validator 1 (shard 0) + validator 3 (shard 1).
    let host1_vnodes = vec![
        VnodeConfig {
            validator_id: ValidatorId::new(1),
            local_shard: ShardId::leaf(1, 0),
            signing_key: fixtures.signing_key(1),
        },
        VnodeConfig {
            validator_id: ValidatorId::new(3),
            local_shard: ShardId::leaf(1, 1),
            signing_key: fixtures.signing_key(3),
        },
    ];
    let beacon_storage1: Arc<dyn BeaconStorage> =
        Arc::new(RocksDbBeaconStorage::open(temp_dir1.path().join("beacon_db")).unwrap());
    let mut runner1 = ProductionRunner::builder(
        host1_vnodes,
        fixtures.topology(),
        ShardConsensusConfig::default(),
        HashMap::from([
            (ShardId::leaf(1, 0), host1_s0),
            (ShardId::leaf(1, 1), host1_s1),
        ]),
        beacon_storage1,
        network_config1,
        temp_storage_factory(&temp_dir1),
        temp_storage_dir(&temp_dir1),
    )
    .build()
    .expect("host 1 builder");

    let adapter1 = Arc::clone(runner1.network());
    assert_eq!(
        adapter1.local_validator_ids(),
        &[ValidatorId::new(1), ValidatorId::new(3)],
        "host 1 should expose its cross-shard validator ids"
    );

    let shutdown0 = runner0.shutdown_handle().expect("shutdown0");
    let shutdown1 = runner1.shutdown_handle().expect("shutdown1");
    let h0 = spawn(runner0.run());
    let h1 = spawn(runner1.run());

    // Wait for both hosts to bind every remote validator id (handshake
    // covers all hosted validators on each peer).
    let bound = timeout(Duration::from_secs(10), async {
        loop {
            let host0_sees = [
                adapter0.peer_for_validator(ValidatorId::new(1)),
                adapter0.peer_for_validator(ValidatorId::new(3)),
            ];
            let host1_sees = [
                adapter1.peer_for_validator(ValidatorId::new(0)),
                adapter1.peer_for_validator(ValidatorId::new(2)),
            ];
            if host0_sees.iter().all(Option::is_some) && host1_sees.iter().all(Option::is_some) {
                return (host0_sees, host1_sees);
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("cross-shard multi-vnode bind should complete within timeout");

    let (host0_sees, host1_sees) = bound;
    let host1_peer = adapter1.local_peer_id();
    let host0_peer = adapter0.local_peer_id();
    // Every remote validator id resolves to the remote host's single
    // peer, even across shard boundaries. This is the load-bearing
    // cross-shard bind property.
    for resolved in host0_sees {
        assert_eq!(resolved, Some(host1_peer));
    }
    for resolved in host1_sees {
        assert_eq!(resolved, Some(host0_peer));
    }

    drop(shutdown0);
    drop(shutdown1);
    let _ = timeout(Duration::from_secs(5), h0).await;
    let _ = timeout(Duration::from_secs(5), h1).await;

    info!("V=2 cross-shard production-runner bind test completed");
}
