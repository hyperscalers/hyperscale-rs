//! End-to-end tests for the production runner.
//!
//! These tests validate the production runner with real localhost QUIC networking
//! and `RocksDB` storage. All tests use `#[serial]` to avoid port conflicts and
//! state leakage.
//!
//! Note: The `ProductionRunner` requires both storage and network to be configured.
//! For simpler tests without full infrastructure, use the simulation crate.

mod fixtures;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use fixtures::TestFixtures;
use hyperscale_network::{HandlerRegistry, ValidatorKeyMap};
use hyperscale_network_libp2p::{Libp2pAdapter, Libp2pConfig};
use hyperscale_production::{ProductionRunner, VnodeConfig};
use hyperscale_shard::ShardConsensusConfig;
use hyperscale_storage_rocksdb::RocksDbStorage;
use hyperscale_types::{
    Bls12381G1PrivateKey, NetworkDefinition, ShardGroupId, ValidatorId, generate_bls_keypair,
};
use libp2p::identity::Keypair;
use serial_test::serial;
use tempfile::TempDir;
use tokio::task::spawn;
use tokio::time::{sleep, timeout};
use tracing::info;
use tracing_subscriber::fmt;

/// Test timeout values (from design spec).
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);
#[allow(dead_code)]
const SINGLE_BLOCK_TIMEOUT: Duration = Duration::from_secs(10);
#[allow(dead_code)]
const SYNC_CATCH_UP_TIMEOUT: Duration = Duration::from_secs(30);
#[allow(dead_code)]
const OVERALL_TEST_TIMEOUT: Duration = Duration::from_mins(1);

// ============================================================================
// Network Tests (localhost QUIC)
// ============================================================================

/// Create a dummy bind signing key + validator key map for tests that create
/// adapters directly. Returns the BLS signing key (consumed by the validator-bind
/// service to produce per-session signatures) plus the keymap that will verify
/// signatures from this validator.
fn test_bind_args(validator_id: ValidatorId) -> (Arc<Bls12381G1PrivateKey>, Arc<ValidatorKeyMap>) {
    let bls_key = generate_bls_keypair();
    let pubkey = bls_key.public_key();
    let mut keys = ValidatorKeyMap::new();
    keys.insert(validator_id, pubkey);
    (Arc::new(bls_key), Arc::new(keys))
}

#[tokio::test]
#[serial]
async fn test_network_adapter_starts() {
    let _ = fmt().with_test_writer().try_init();

    let keypair = Keypair::generate_ed25519();
    let validator_id = ValidatorId::new(0);
    let shard = ShardGroupId::new(0);

    // Use port 0 for OS-assigned port
    let config = Libp2pConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        bootstrap_peers: vec![],
        ..Default::default()
    };

    let (bind_sig, topo) = test_bind_args(validator_id);
    let adapter = Libp2pAdapter::new(
        config,
        NetworkDefinition::simulator(),
        keypair,
        vec![(validator_id, bind_sig)],
        HashSet::from([shard]),
        Arc::new(HandlerRegistry::default()),
        topo,
    )
    .unwrap();

    // Verify adapter state
    assert_eq!(adapter.local_validator_ids(), &[validator_id]);

    // Get listen addresses (should have at least one after initialization)
    sleep(Duration::from_millis(100)).await;
    let addrs = adapter.listen_addresses().await;
    info!(addresses = ?addrs, "Adapter listening on");

    info!("Network adapter started successfully");
}

#[tokio::test]
#[serial]
async fn test_two_node_connection() {
    let _ = fmt().with_test_writer().try_init();

    // Node 1
    let keypair1 = Keypair::generate_ed25519();
    let (bind_sig1, topo1) = test_bind_args(ValidatorId::new(0));
    let config1 = Libp2pConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        bootstrap_peers: vec![],
        ..Default::default()
    };
    let adapter1 = Libp2pAdapter::new(
        config1,
        NetworkDefinition::simulator(),
        keypair1,
        vec![(ValidatorId::new(0), bind_sig1)],
        HashSet::from([ShardGroupId::new(0)]),
        Arc::new(HandlerRegistry::default()),
        topo1,
    )
    .unwrap();

    // Wait for node 1 to be ready and get its address
    sleep(Duration::from_millis(200)).await;
    let addrs1 = adapter1.listen_addresses().await;
    assert!(!addrs1.is_empty(), "Node 1 should have listen addresses");
    let node1_addr = addrs1[0].clone();
    info!(addr = %node1_addr, "Node 1 listening");

    // Node 2 - bootstrap to node 1
    let keypair2 = Keypair::generate_ed25519();
    let (bind_sig2, topo2) = test_bind_args(ValidatorId::new(1));
    let config2 = Libp2pConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        bootstrap_peers: vec![node1_addr.clone()],
        ..Default::default()
    };
    let adapter2 = Libp2pAdapter::new(
        config2,
        NetworkDefinition::simulator(),
        keypair2,
        vec![(ValidatorId::new(1), bind_sig2)],
        HashSet::from([ShardGroupId::new(0)]),
        Arc::new(HandlerRegistry::default()),
        topo2,
    )
    .unwrap();

    // Wait for connection to establish
    let connected = timeout(CONNECTION_TIMEOUT, async {
        loop {
            let peers1 = adapter1.connected_peers().await;
            let peers2 = adapter2.connected_peers().await;

            if !peers1.is_empty() && !peers2.is_empty() {
                return (peers1, peers2);
            }

            sleep(Duration::from_millis(100)).await;
        }
    })
    .await;

    assert!(connected.is_ok(), "Nodes should connect within timeout");
    let (peers1, peers2) = connected.unwrap();

    info!(
        node1_peers = peers1.len(),
        node2_peers = peers2.len(),
        "Nodes connected"
    );

    assert!(!peers1.is_empty(), "Node 1 should have peers");
    assert!(!peers2.is_empty(), "Node 2 should have peers");
}

#[tokio::test]
#[serial]
async fn test_topic_subscription() {
    let _ = fmt().with_test_writer().try_init();

    let keypair = Keypair::generate_ed25519();
    let (bind_sig, topo) = test_bind_args(ValidatorId::new(0));
    let config = Libp2pConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        bootstrap_peers: vec![],
        ..Default::default()
    };
    let adapter = Libp2pAdapter::new(
        config,
        NetworkDefinition::simulator(),
        keypair,
        vec![(ValidatorId::new(0), bind_sig)],
        HashSet::from([ShardGroupId::new(0)]),
        Arc::new(HandlerRegistry::default()),
        topo,
    )
    .unwrap();

    // Subscribe to a topic via subscribe_topic (individual subscription)
    let result = adapter.subscribe_topic("hyperscale/block.header/shard-0/1.0.0".to_string());
    assert!(result.is_ok(), "Should subscribe to topic");

    info!("Topic subscription successful");
}

// ============================================================================
// Validator-Bind Protocol Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn test_validator_bind_success() {
    let _ = fmt().with_test_writer().try_init();

    // Shared topology — both validators known to both nodes.
    let fixtures = TestFixtures::new(42, 2);

    // Node 0
    let keypair0 = fixtures.ed25519_keypair(0);
    let bind_sig0 = fixtures.bind_signing_key(0);
    let config0 = Libp2pConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        bootstrap_peers: vec![],
        ..Default::default()
    };
    let adapter0 = Libp2pAdapter::new(
        config0,
        NetworkDefinition::simulator(),
        keypair0,
        vec![(ValidatorId::new(0), bind_sig0)],
        HashSet::from([ShardGroupId::new(0)]),
        Arc::new(HandlerRegistry::default()),
        fixtures.validator_key_map(0),
    )
    .unwrap();

    sleep(Duration::from_millis(200)).await;
    let addrs0 = adapter0.listen_addresses().await;
    assert!(!addrs0.is_empty(), "Node 0 should have listen addresses");
    let node0_addr = addrs0[0].clone();

    // Node 1 — bootstrap to node 0
    let keypair1 = fixtures.ed25519_keypair(1);
    let bind_sig1 = fixtures.bind_signing_key(1);
    let config1 = Libp2pConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        bootstrap_peers: vec![node0_addr],
        ..Default::default()
    };
    let adapter1 = Libp2pAdapter::new(
        config1,
        NetworkDefinition::simulator(),
        keypair1,
        vec![(ValidatorId::new(1), bind_sig1)],
        HashSet::from([ShardGroupId::new(0)]),
        Arc::new(HandlerRegistry::default()),
        fixtures.validator_key_map(1),
    )
    .unwrap();

    // Wait for validator-bind to complete on both sides.
    let bound = timeout(CONNECTION_TIMEOUT, async {
        loop {
            if let (Some(p1), Some(p0)) = (
                adapter0.peer_for_validator(ValidatorId::new(1)),
                adapter1.peer_for_validator(ValidatorId::new(0)),
            ) {
                return (p1, p0);
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await;

    assert!(
        bound.is_ok(),
        "Validator-bind should complete within timeout"
    );
    let (resolved_peer1, resolved_peer0) = bound.unwrap();

    // Resolved PeerIds must match the actual adapter PeerIds.
    assert_eq!(resolved_peer1, adapter1.local_peer_id());
    assert_eq!(resolved_peer0, adapter0.local_peer_id());

    info!("Validator-bind success test completed");
}

#[tokio::test]
#[serial]
async fn test_validator_bind_rejects_wrong_key() {
    let _ = fmt().with_test_writer().try_init();

    let fixtures = TestFixtures::new(42, 2);

    // Node 0 — legitimate
    let keypair0 = fixtures.ed25519_keypair(0);
    let bind_sig0 = fixtures.bind_signing_key(0);
    let config0 = Libp2pConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        bootstrap_peers: vec![],
        ..Default::default()
    };
    let adapter0 = Libp2pAdapter::new(
        config0,
        NetworkDefinition::simulator(),
        keypair0,
        vec![(ValidatorId::new(0), bind_sig0)],
        HashSet::from([ShardGroupId::new(0)]),
        Arc::new(HandlerRegistry::default()),
        fixtures.validator_key_map(0),
    )
    .unwrap();

    sleep(Duration::from_millis(200)).await;
    let addrs0 = adapter0.listen_addresses().await;
    assert!(!addrs0.is_empty(), "Node 0 should have listen addresses");
    let node0_addr = addrs0[0].clone();

    // Node 1 — impersonator: signs with a BLS key that doesn't match the topology.
    // The bind service will produce per-session sigs under this wrong key, and
    // every verification in the peer's topology lookup will fail.
    let keypair1 = fixtures.ed25519_keypair(1);
    let wrong_signing_key = Arc::new(generate_bls_keypair());
    let config1 = Libp2pConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        bootstrap_peers: vec![node0_addr],
        ..Default::default()
    };
    let adapter1 = Libp2pAdapter::new(
        config1,
        NetworkDefinition::simulator(),
        keypair1,
        vec![(ValidatorId::new(1), wrong_signing_key)],
        HashSet::from([ShardGroupId::new(0)]),
        Arc::new(HandlerRegistry::default()),
        fixtures.validator_key_map(1),
    )
    .unwrap();

    // Wait for transport connection to establish.
    let connected = timeout(CONNECTION_TIMEOUT, async {
        loop {
            if !adapter0.connected_peers().await.is_empty() {
                return;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(connected.is_ok(), "Transport connection should establish");

    // Give the bind protocol time to attempt and fail.
    sleep(Duration::from_secs(1)).await;

    // Node 0 must NOT trust the impersonator.
    assert!(
        adapter0.peer_for_validator(ValidatorId::new(1)).is_none(),
        "Node 0 should NOT resolve validator 1 (wrong BLS key)"
    );

    // Suppress unused-variable warning — we need adapter1 alive for the connection.
    drop(adapter1);

    info!("Validator-bind rejection test completed");
}

#[tokio::test]
#[serial]
async fn test_validator_bind_evicted_on_disconnect() {
    let _ = fmt().with_test_writer().try_init();

    let fixtures = TestFixtures::new(42, 2);

    // Node 0
    let keypair0 = fixtures.ed25519_keypair(0);
    let bind_sig0 = fixtures.bind_signing_key(0);
    let config0 = Libp2pConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        bootstrap_peers: vec![],
        ..Default::default()
    };
    let adapter0 = Libp2pAdapter::new(
        config0,
        NetworkDefinition::simulator(),
        keypair0,
        vec![(ValidatorId::new(0), bind_sig0)],
        HashSet::from([ShardGroupId::new(0)]),
        Arc::new(HandlerRegistry::default()),
        fixtures.validator_key_map(0),
    )
    .unwrap();

    sleep(Duration::from_millis(200)).await;
    let addrs0 = adapter0.listen_addresses().await;
    assert!(!addrs0.is_empty(), "Node 0 should have listen addresses");
    let node0_addr = addrs0[0].clone();

    // Node 1
    let keypair1 = fixtures.ed25519_keypair(1);
    let bind_sig1 = fixtures.bind_signing_key(1);
    let config1 = Libp2pConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        bootstrap_peers: vec![node0_addr],
        ..Default::default()
    };
    let adapter1 = Libp2pAdapter::new(
        config1,
        NetworkDefinition::simulator(),
        keypair1,
        vec![(ValidatorId::new(1), bind_sig1)],
        HashSet::from([ShardGroupId::new(0)]),
        Arc::new(HandlerRegistry::default()),
        fixtures.validator_key_map(1),
    )
    .unwrap();

    // Wait for bind to complete.
    let bound = timeout(CONNECTION_TIMEOUT, async {
        loop {
            if adapter0.peer_for_validator(ValidatorId::new(1)).is_some() {
                return;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        bound.is_ok(),
        "Validator-bind should complete within timeout"
    );

    // Drop node 1 — triggers shutdown and connection close.
    drop(adapter1);

    // Node 0 should evict the mapping once the disconnect is detected.
    let evicted = timeout(CONNECTION_TIMEOUT, async {
        loop {
            if adapter0.peer_for_validator(ValidatorId::new(1)).is_none() {
                return;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        evicted.is_ok(),
        "Validator mapping should be evicted after disconnect"
    );

    info!("Validator-bind eviction test completed");
}

// ============================================================================
// Production Runner with Network Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn test_production_runner_with_network() {
    let _ = fmt().with_test_writer().try_init();

    let fixtures = TestFixtures::new(42, 1);

    // Create temp storage
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test_db");
    let storage = RocksDbStorage::open(&db_path).unwrap();
    let storage = Arc::new(storage);

    let network_config = Libp2pConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        bootstrap_peers: vec![],
        ..Default::default()
    };

    let runner = ProductionRunner::builder(
        vec![VnodeConfig {
            topology: fixtures.topology(0),
            signing_key: fixtures.signing_key(0),
        }],
        ShardConsensusConfig::default(),
        HashMap::from([(ShardGroupId::new(0), storage)]),
        network_config,
    )
    .build();

    assert!(runner.is_ok(), "Runner creation should succeed");
    let mut runner = runner.unwrap();
    let _ = CONNECTION_TIMEOUT;

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

// ============================================================================
// Graceful Shutdown Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn test_graceful_shutdown() {
    let _ = fmt().with_test_writer().try_init();

    let fixtures = TestFixtures::new(42, 1);

    // Create temp storage
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test_db");
    let storage = RocksDbStorage::open(&db_path).unwrap();
    let storage = Arc::new(storage);

    let network_config = Libp2pConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        bootstrap_peers: vec![],
        ..Default::default()
    };

    let mut runner = ProductionRunner::builder(
        vec![VnodeConfig {
            topology: fixtures.topology(0),
            signing_key: fixtures.signing_key(0),
        }],
        ShardConsensusConfig::default(),
        HashMap::from([(ShardGroupId::new(0), storage)]),
        network_config,
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

// ============================================================================
// Multi-vnode hosting (same shard)
// ============================================================================

/// Spin up two hosts that each carry two same-shard vnodes, let them peer,
/// and check that the multi-validator bind plumbing lands every hosted
/// validator id on the remote adapter's `validator_peers` map. Real libp2p,
/// real `RocksDB`; consensus progress is exercised separately by the
/// simulator's V=2 test and is timing-sensitive over real network — this
/// test scopes itself to validating the production-runner construction
/// path and the multi-validator handshake.
#[tokio::test]
#[serial]
async fn test_v2_same_shard_production_runner_binds_all_vnodes() {
    let _ = fmt().with_test_writer().try_init();

    // Four validators, all in shard 0; two per host.
    let fixtures = TestFixtures::new(7, 4);

    let temp_dir0 = TempDir::new().unwrap();
    let temp_dir1 = TempDir::new().unwrap();
    let storage0 = Arc::new(RocksDbStorage::open(temp_dir0.path().join("db0")).unwrap());
    let storage1 = Arc::new(RocksDbStorage::open(temp_dir1.path().join("db1")).unwrap());

    let network_config0 = Libp2pConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        bootstrap_peers: vec![],
        ..Default::default()
    };

    let host0_vnodes = vec![
        VnodeConfig {
            topology: fixtures.topology(0),
            signing_key: fixtures.signing_key(0),
        },
        VnodeConfig {
            topology: fixtures.topology(1),
            signing_key: fixtures.signing_key(1),
        },
    ];
    let mut runner0 = ProductionRunner::builder(
        host0_vnodes,
        ShardConsensusConfig::default(),
        HashMap::from([(ShardGroupId::new(0), storage0)]),
        network_config0,
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
            topology: fixtures.topology(2),
            signing_key: fixtures.signing_key(2),
        },
        VnodeConfig {
            topology: fixtures.topology(3),
            signing_key: fixtures.signing_key(3),
        },
    ];
    let mut runner1 = ProductionRunner::builder(
        host1_vnodes,
        ShardConsensusConfig::default(),
        HashMap::from([(ShardGroupId::new(0), storage1)]),
        network_config1,
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

// ============================================================================
// Multi-vnode hosting (different shards)
// ============================================================================

/// Spin up two hosts that each carry two cross-shard vnodes (one in
/// shard 0, one in shard 1) and check that the multi-validator bind
/// plumbing lands every hosted validator id on the remote adapter's
/// `validator_peers` map. Smoke test for the production runner's
/// cross-shard hosting construction path — consensus progress is
/// timing-sensitive over real networking and is exercised separately
/// by the simulator.
#[tokio::test]
#[serial]
async fn test_v2_different_shard_production_runner_binds_all_vnodes() {
    let _ = fmt().with_test_writer().try_init();

    // Four validators across two shards: 0/1 in shard 0, 2/3 in shard 1.
    // Each host carries one vnode from each shard.
    let fixtures = TestFixtures::with_shards(7, 2, 2);

    let temp_dir0 = TempDir::new().unwrap();
    let temp_dir1 = TempDir::new().unwrap();

    // Two RocksDB stores per host — one per hosted shard.
    let host0_s0 = Arc::new(RocksDbStorage::open(temp_dir0.path().join("db0_s0")).unwrap());
    let host0_s1 = Arc::new(RocksDbStorage::open(temp_dir0.path().join("db0_s1")).unwrap());
    let host1_s0 = Arc::new(RocksDbStorage::open(temp_dir1.path().join("db1_s0")).unwrap());
    let host1_s1 = Arc::new(RocksDbStorage::open(temp_dir1.path().join("db1_s1")).unwrap());

    let network_config0 = Libp2pConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        bootstrap_peers: vec![],
        ..Default::default()
    };

    // Host 0: validator 0 (shard 0) + validator 2 (shard 1).
    let host0_vnodes = vec![
        VnodeConfig {
            topology: fixtures.topology(0),
            signing_key: fixtures.signing_key(0),
        },
        VnodeConfig {
            topology: fixtures.topology(2),
            signing_key: fixtures.signing_key(2),
        },
    ];
    let mut runner0 = ProductionRunner::builder(
        host0_vnodes,
        ShardConsensusConfig::default(),
        HashMap::from([
            (ShardGroupId::new(0), host0_s0),
            (ShardGroupId::new(1), host0_s1),
        ]),
        network_config0,
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
            topology: fixtures.topology(1),
            signing_key: fixtures.signing_key(1),
        },
        VnodeConfig {
            topology: fixtures.topology(3),
            signing_key: fixtures.signing_key(3),
        },
    ];
    let mut runner1 = ProductionRunner::builder(
        host1_vnodes,
        ShardConsensusConfig::default(),
        HashMap::from([
            (ShardGroupId::new(0), host1_s0),
            (ShardGroupId::new(1), host1_s1),
        ]),
        network_config1,
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
