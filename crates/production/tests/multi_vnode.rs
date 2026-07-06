//! Multi-vnode hosting test: one host carrying several same-shard vnodes.
//!
//! Validates that the multi-validator bind plumbing lands every hosted
//! validator id on the remote adapter's `validator_peers` map. The bind is
//! shard-agnostic (the adapter exposes a flat `local_validator_ids` and resolves
//! peers by validator id), so same-shard hosting exercises the whole bind path.
//! Consensus progress is timing-sensitive over real networking and is exercised
//! separately by the simulator; this scopes itself to the production-runner
//! construction path and the multi-validator handshake. `#[serial]`; runs on a
//! multi-threaded runtime to match the production host's runtime shape.

mod support;

use std::sync::Arc;
use std::time::Duration;

use hyperscale_network_libp2p::Libp2pConfig;
use hyperscale_network_libp2p::test_utils::TestFixtures;
use hyperscale_production::{LocalValidator, ProductionRunner};
use hyperscale_shard::ShardConsensusConfig;
use hyperscale_storage::BeaconStorage;
use hyperscale_storage_rocksdb::RocksDbBeaconStorage;
use hyperscale_types::ValidatorId;
use serial_test::serial;
use support::{temp_storage_dir, temp_storage_factory};
use tempfile::TempDir;
use tokio::task::spawn;
use tokio::time::{sleep, timeout};
use tracing::info;
use tracing_subscriber::fmt;

/// One validator this host runs; the runner derives its shard from the
/// fixture's beacon genesis.
fn validator(fixtures: &TestFixtures, idx: u32) -> LocalValidator {
    LocalValidator {
        validator_id: ValidatorId::new(u64::from(idx)),
        signing_key: fixtures.signing_key(idx),
    }
}

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

    let network_config0 = Libp2pConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        bootstrap_peers: vec![],
        ..Default::default()
    };

    let host0_vnodes = vec![validator(&fixtures, 0), validator(&fixtures, 1)];
    let beacon_storage0: Arc<dyn BeaconStorage> =
        Arc::new(RocksDbBeaconStorage::open(temp_dir0.path().join("beacon_db")).unwrap());
    let mut runner0 = ProductionRunner::builder(
        host0_vnodes,
        fixtures.genesis_validators(),
        ShardConsensusConfig::default(),
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
    let host1_vnodes = vec![validator(&fixtures, 2), validator(&fixtures, 3)];
    let beacon_storage1: Arc<dyn BeaconStorage> =
        Arc::new(RocksDbBeaconStorage::open(temp_dir1.path().join("beacon_db")).unwrap());
    let mut runner1 = ProductionRunner::builder(
        host1_vnodes,
        fixtures.genesis_validators(),
        ShardConsensusConfig::default(),
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
