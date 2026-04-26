//! End-to-end tests for the production runner.
//!
//! These tests validate the production runner with real localhost QUIC networking
//! and RocksDB storage. All tests use `#[serial]` to avoid port conflicts and
//! state leakage.
//!
//! Note: The ProductionRunner requires both storage and network to be configured.
//! For simpler tests without full infrastructure, use the simulation crate.

mod fixtures;

use fixtures::TestFixtures;
use hyperscale_bft::BftConfig;
use hyperscale_production::{ProductionRunner, RocksDbStorage};
use hyperscale_types::{generate_bls_keypair, validator_bind_message, ShardGroupId, ValidatorId};
use serial_test::serial;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::time::timeout;
use tracing::info;

/// Test timeout values (from design spec).
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);
#[allow(dead_code)]
const SINGLE_BLOCK_TIMEOUT: Duration = Duration::from_secs(10);
#[allow(dead_code)]
const SYNC_CATCH_UP_TIMEOUT: Duration = Duration::from_secs(30);
#[allow(dead_code)]
const OVERALL_TEST_TIMEOUT: Duration = Duration::from_secs(60);

// ============================================================================
// Network Tests (localhost QUIC)
// ============================================================================

/// Create a dummy bind signature + validator key map for tests that create adapters directly.
fn test_bind_args(
    keypair: &libp2p::identity::Keypair,
    validator_id: ValidatorId,
) -> (
    hyperscale_types::Bls12381G2Signature,
    Arc<hyperscale_network::ValidatorKeyMap>,
) {
    let bls_key = generate_bls_keypair();
    let pubkey = bls_key.public_key();
    let peer_id = libp2p::PeerId::from(keypair.public());
    let sig = bls_key.sign_v1(&validator_bind_message(&peer_id.to_bytes()));
    let mut keys = hyperscale_network::ValidatorKeyMap::new();
    keys.insert(validator_id, pubkey);
    (sig, Arc::new(keys))
}

#[tokio::test]
#[serial]
async fn test_network_adapter_starts() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    use hyperscale_network_libp2p::{Libp2pAdapter, Libp2pConfig};
    use libp2p::identity;

    let keypair = identity::Keypair::generate_ed25519();
    let validator_id = ValidatorId(0);
    let shard = ShardGroupId(0);

    // Use port 0 for OS-assigned port
    let config = Libp2pConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        bootstrap_peers: vec![],
        ..Default::default()
    };

    let (bind_sig, topo) = test_bind_args(&keypair, validator_id);
    let adapter = Libp2pAdapter::new(
        config,
        keypair,
        validator_id,
        shard,
        Arc::new(hyperscale_network::HandlerRegistry::new()),
        bind_sig,
        topo,
    )
    .unwrap();

    // Verify adapter state
    assert_eq!(adapter.local_validator_id(), validator_id);

    // Get listen addresses (should have at least one after initialization)
    tokio::time::sleep(Duration::from_millis(100)).await;
    let addrs = adapter.listen_addresses().await;
    info!(addresses = ?addrs, "Adapter listening on");

    info!("Network adapter started successfully");
}

#[tokio::test]
#[serial]
async fn test_two_node_connection() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    use hyperscale_network_libp2p::{Libp2pAdapter, Libp2pConfig};
    use libp2p::identity;

    // Node 1
    let keypair1 = identity::Keypair::generate_ed25519();
    let (bind_sig1, topo1) = test_bind_args(&keypair1, ValidatorId(0));
    let config1 = Libp2pConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        bootstrap_peers: vec![],
        ..Default::default()
    };
    let adapter1 = Libp2pAdapter::new(
        config1,
        keypair1,
        ValidatorId(0),
        ShardGroupId(0),
        Arc::new(hyperscale_network::HandlerRegistry::new()),
        bind_sig1,
        topo1,
    )
    .unwrap();

    // Wait for node 1 to be ready and get its address
    tokio::time::sleep(Duration::from_millis(200)).await;
    let addrs1 = adapter1.listen_addresses().await;
    assert!(!addrs1.is_empty(), "Node 1 should have listen addresses");
    let node1_addr = addrs1[0].clone();
    info!(addr = %node1_addr, "Node 1 listening");

    // Node 2 - bootstrap to node 1
    let keypair2 = identity::Keypair::generate_ed25519();
    let (bind_sig2, topo2) = test_bind_args(&keypair2, ValidatorId(1));
    let config2 = Libp2pConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        bootstrap_peers: vec![node1_addr.clone()],
        ..Default::default()
    };
    let adapter2 = Libp2pAdapter::new(
        config2,
        keypair2,
        ValidatorId(1),
        ShardGroupId(0),
        Arc::new(hyperscale_network::HandlerRegistry::new()),
        bind_sig2,
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

            tokio::time::sleep(Duration::from_millis(100)).await;
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
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    use hyperscale_network_libp2p::{Libp2pAdapter, Libp2pConfig};
    use libp2p::identity;

    let keypair = identity::Keypair::generate_ed25519();
    let (bind_sig, topo) = test_bind_args(&keypair, ValidatorId(0));
    let config = Libp2pConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        bootstrap_peers: vec![],
        ..Default::default()
    };
    let adapter = Libp2pAdapter::new(
        config,
        keypair,
        ValidatorId(0),
        ShardGroupId(0),
        Arc::new(hyperscale_network::HandlerRegistry::new()),
        bind_sig,
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
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    use hyperscale_network_libp2p::{Libp2pAdapter, Libp2pConfig};

    // Shared topology — both validators known to both nodes.
    let fixtures = TestFixtures::new(42, 2);

    // Node 0
    let keypair0 = fixtures.ed25519_keypair(0);
    let bind_sig0 = fixtures.bind_signature(0, &keypair0);
    let config0 = Libp2pConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        bootstrap_peers: vec![],
        ..Default::default()
    };
    let adapter0 = Libp2pAdapter::new(
        config0,
        keypair0,
        ValidatorId(0),
        ShardGroupId(0),
        Arc::new(hyperscale_network::HandlerRegistry::new()),
        bind_sig0,
        fixtures.validator_key_map(0),
    )
    .unwrap();

    tokio::time::sleep(Duration::from_millis(200)).await;
    let addrs0 = adapter0.listen_addresses().await;
    assert!(!addrs0.is_empty(), "Node 0 should have listen addresses");
    let node0_addr = addrs0[0].clone();

    // Node 1 — bootstrap to node 0
    let keypair1 = fixtures.ed25519_keypair(1);
    let bind_sig1 = fixtures.bind_signature(1, &keypair1);
    let config1 = Libp2pConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        bootstrap_peers: vec![node0_addr],
        ..Default::default()
    };
    let adapter1 = Libp2pAdapter::new(
        config1,
        keypair1,
        ValidatorId(1),
        ShardGroupId(0),
        Arc::new(hyperscale_network::HandlerRegistry::new()),
        bind_sig1,
        fixtures.validator_key_map(1),
    )
    .unwrap();

    // Wait for validator-bind to complete on both sides.
    let bound = timeout(CONNECTION_TIMEOUT, async {
        loop {
            if let (Some(p1), Some(p0)) = (
                adapter0.peer_for_validator(ValidatorId(1)),
                adapter1.peer_for_validator(ValidatorId(0)),
            ) {
                return (p1, p0);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
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
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    use hyperscale_network_libp2p::{Libp2pAdapter, Libp2pConfig};

    let fixtures = TestFixtures::new(42, 2);

    // Node 0 — legitimate
    let keypair0 = fixtures.ed25519_keypair(0);
    let bind_sig0 = fixtures.bind_signature(0, &keypair0);
    let config0 = Libp2pConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        bootstrap_peers: vec![],
        ..Default::default()
    };
    let adapter0 = Libp2pAdapter::new(
        config0,
        keypair0,
        ValidatorId(0),
        ShardGroupId(0),
        Arc::new(hyperscale_network::HandlerRegistry::new()),
        bind_sig0,
        fixtures.validator_key_map(0),
    )
    .unwrap();

    tokio::time::sleep(Duration::from_millis(200)).await;
    let addrs0 = adapter0.listen_addresses().await;
    assert!(!addrs0.is_empty(), "Node 0 should have listen addresses");
    let node0_addr = addrs0[0].clone();

    // Node 1 — impersonator: signs with a BLS key that doesn't match the topology.
    let keypair1 = fixtures.ed25519_keypair(1);
    let wrong_bls_key = generate_bls_keypair();
    let peer1_id = libp2p::PeerId::from(keypair1.public());
    let wrong_sig = wrong_bls_key.sign_v1(&validator_bind_message(&peer1_id.to_bytes()));
    let config1 = Libp2pConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        bootstrap_peers: vec![node0_addr],
        ..Default::default()
    };
    let adapter1 = Libp2pAdapter::new(
        config1,
        keypair1,
        ValidatorId(1),
        ShardGroupId(0),
        Arc::new(hyperscale_network::HandlerRegistry::new()),
        wrong_sig,
        fixtures.validator_key_map(1),
    )
    .unwrap();

    // Wait for transport connection to establish.
    let connected = timeout(CONNECTION_TIMEOUT, async {
        loop {
            if !adapter0.connected_peers().await.is_empty() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(connected.is_ok(), "Transport connection should establish");

    // Give the bind protocol time to attempt and fail.
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Node 0 must NOT trust the impersonator.
    assert!(
        adapter0.peer_for_validator(ValidatorId(1)).is_none(),
        "Node 0 should NOT resolve validator 1 (wrong BLS key)"
    );

    // Suppress unused-variable warning — we need adapter1 alive for the connection.
    drop(adapter1);

    info!("Validator-bind rejection test completed");
}

#[tokio::test]
#[serial]
async fn test_validator_bind_evicted_on_disconnect() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    use hyperscale_network_libp2p::{Libp2pAdapter, Libp2pConfig};

    let fixtures = TestFixtures::new(42, 2);

    // Node 0
    let keypair0 = fixtures.ed25519_keypair(0);
    let bind_sig0 = fixtures.bind_signature(0, &keypair0);
    let config0 = Libp2pConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        bootstrap_peers: vec![],
        ..Default::default()
    };
    let adapter0 = Libp2pAdapter::new(
        config0,
        keypair0,
        ValidatorId(0),
        ShardGroupId(0),
        Arc::new(hyperscale_network::HandlerRegistry::new()),
        bind_sig0,
        fixtures.validator_key_map(0),
    )
    .unwrap();

    tokio::time::sleep(Duration::from_millis(200)).await;
    let addrs0 = adapter0.listen_addresses().await;
    assert!(!addrs0.is_empty(), "Node 0 should have listen addresses");
    let node0_addr = addrs0[0].clone();

    // Node 1
    let keypair1 = fixtures.ed25519_keypair(1);
    let bind_sig1 = fixtures.bind_signature(1, &keypair1);
    let config1 = Libp2pConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        bootstrap_peers: vec![node0_addr],
        ..Default::default()
    };
    let adapter1 = Libp2pAdapter::new(
        config1,
        keypair1,
        ValidatorId(1),
        ShardGroupId(0),
        Arc::new(hyperscale_network::HandlerRegistry::new()),
        bind_sig1,
        fixtures.validator_key_map(1),
    )
    .unwrap();

    // Wait for bind to complete.
    let bound = timeout(CONNECTION_TIMEOUT, async {
        loop {
            if adapter0.peer_for_validator(ValidatorId(1)).is_some() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
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
            if adapter0.peer_for_validator(ValidatorId(1)).is_none() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
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
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    use hyperscale_network_libp2p::Libp2pConfig;

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

    let runner = timeout(
        CONNECTION_TIMEOUT,
        ProductionRunner::builder()
            .topology(fixtures.topology(0))
            .signing_key(fixtures.signing_key(0))
            .bft_config(BftConfig::default())
            .storage(storage)
            .network(network_config)
            .build(),
    )
    .await;

    assert!(runner.is_ok(), "Runner creation should not timeout");
    let mut runner = runner.unwrap().unwrap();

    // Verify network is configured
    let network = runner.network();
    info!(peer_id = %network.local_peer_id(), "Runner has network");

    // Get listen addresses
    tokio::time::sleep(Duration::from_millis(100)).await;
    let addrs = network.listen_addresses().await;
    info!(addresses = ?addrs, "Runner listening on");

    // Get shutdown handle before running
    let shutdown = runner
        .shutdown_handle()
        .expect("Should have shutdown handle");
    let handle = tokio::spawn(runner.run());

    tokio::time::sleep(Duration::from_millis(500)).await;
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
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    use hyperscale_network_libp2p::Libp2pConfig;

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

    let mut runner = ProductionRunner::builder()
        .topology(fixtures.topology(0))
        .signing_key(fixtures.signing_key(0))
        .bft_config(BftConfig::default())
        .storage(storage)
        .network(network_config)
        .build()
        .await
        .unwrap();

    let shutdown = runner
        .shutdown_handle()
        .expect("Should have shutdown handle");
    let handle = tokio::spawn(runner.run());

    // Let it run briefly
    tokio::time::sleep(Duration::from_millis(200)).await;

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
