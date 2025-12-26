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
use hyperscale_engine::TransactionValidation;
use hyperscale_production::{
    ProductionRunner, RocksDbStorage, ThreadPoolConfig, ThreadPoolManager,
};
use hyperscale_types::{
    Block, BlockHeader, BlockHeight, Hash, QuorumCertificate, ShardGroupId, ValidatorId,
};
use radix_common::network::NetworkDefinition;
use serial_test::serial;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tracing::info;

/// Create a test transaction validator.
fn test_tx_validator() -> Arc<TransactionValidation> {
    Arc::new(TransactionValidation::new(NetworkDefinition::simulator()))
}

/// Create a minimal test thread pool manager.
fn test_thread_pools() -> Arc<ThreadPoolManager> {
    Arc::new(ThreadPoolManager::new(ThreadPoolConfig::minimal()).unwrap())
}

/// Create a test transaction validation handle.
/// The output channel is returned so tests can receive validated transactions.
fn test_tx_validation_handle() -> (
    hyperscale_production::ValidationBatcherHandle,
    mpsc::UnboundedReceiver<hyperscale_core::Event>,
) {
    let (output_tx, output_rx) = mpsc::unbounded_channel();
    let handle = hyperscale_production::spawn_tx_validation_batcher(
        hyperscale_production::ValidationBatcherConfig::default(),
        test_tx_validator(),
        test_thread_pools(),
        output_tx,
    );
    (handle, output_rx)
}

/// Create a test codec pool handle for network adapter tests.
fn test_codec_pool_handle() -> hyperscale_production::network::CodecPoolHandle {
    hyperscale_production::network::CodecPoolHandle::new(test_thread_pools())
}

/// Test timeout values (from design spec).
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);
#[allow(dead_code)]
const SINGLE_BLOCK_TIMEOUT: Duration = Duration::from_secs(10);
#[allow(dead_code)]
const SYNC_CATCH_UP_TIMEOUT: Duration = Duration::from_secs(30);
#[allow(dead_code)]
const OVERALL_TEST_TIMEOUT: Duration = Duration::from_secs(60);

// ============================================================================
// Storage Tests (no runner needed)
// ============================================================================

#[tokio::test]
#[serial]
async fn test_storage_operations() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test_db");

    let storage = RocksDbStorage::open(&db_path).unwrap();

    // Test block storage
    let header = BlockHeader {
        height: BlockHeight(1),
        parent_hash: Hash::from_bytes(&[0u8; 32]),
        parent_qc: QuorumCertificate::genesis(),
        proposer: ValidatorId(0),
        timestamp: 1000,
        round: 1,
        is_fallback: false,
    };

    let block = Block {
        header: header.clone(),
        retry_transactions: vec![],
        priority_transactions: vec![],
        transactions: vec![],
        committed_certificates: vec![],
        deferred: vec![],
        aborted: vec![],
        commitment_proofs: std::collections::HashMap::new(),
    };

    let qc = QuorumCertificate::genesis();

    storage.put_block(BlockHeight(1), &block, &qc);

    // Retrieve the block
    let retrieved = storage.get_block(BlockHeight(1));
    assert!(retrieved.is_some());
    let (retrieved_block, _retrieved_qc) = retrieved.unwrap();
    assert_eq!(retrieved_block.header.height, BlockHeight(1));

    // Test chain metadata
    storage.set_chain_metadata(
        BlockHeight(1),
        Some(Hash::from_bytes(&[1u8; 32])),
        Some(&qc),
    );
    let (height, hash, _) = storage.get_chain_metadata();
    assert_eq!(height, BlockHeight(1));
    assert!(hash.is_some());

    info!("Storage operations verified");
}

// ============================================================================
// Network Tests (localhost QUIC)
// ============================================================================

#[tokio::test]
#[serial]
async fn test_network_adapter_starts() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    use hyperscale_production::network::{Libp2pAdapter, Libp2pConfig};
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

    let (consensus_tx, _consensus_rx) = mpsc::channel(100);
    let (tx_validation_handle, _tx_rx) = test_tx_validation_handle();

    let codec_pool = test_codec_pool_handle();
    let result = timeout(
        CONNECTION_TIMEOUT,
        Libp2pAdapter::new(
            config,
            keypair,
            validator_id,
            shard,
            consensus_tx,
            tx_validation_handle,
            codec_pool,
        ),
    )
    .await;

    assert!(result.is_ok(), "Adapter creation should not timeout");
    let (adapter, _sync_rx, _tx_rx, _cert_rx) = result.unwrap().unwrap();

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

    use hyperscale_production::network::{Libp2pAdapter, Libp2pConfig};
    use libp2p::identity;

    // Node 1
    let keypair1 = identity::Keypair::generate_ed25519();
    let config1 = Libp2pConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        bootstrap_peers: vec![],
        ..Default::default()
    };
    let (consensus_tx1, _consensus_rx1) = mpsc::channel(100);
    let (tx_validation_handle1, _tx_rx1) = test_tx_validation_handle();
    let codec_pool1 = test_codec_pool_handle();

    let (adapter1, _sync_rx1, _tx_req_rx1, _cert_rx1) = Libp2pAdapter::new(
        config1,
        keypair1,
        ValidatorId(0),
        ShardGroupId(0),
        consensus_tx1,
        tx_validation_handle1,
        codec_pool1,
    )
    .await
    .unwrap();

    // Wait for node 1 to be ready and get its address
    tokio::time::sleep(Duration::from_millis(200)).await;
    let addrs1 = adapter1.listen_addresses().await;
    assert!(!addrs1.is_empty(), "Node 1 should have listen addresses");
    let node1_addr = addrs1[0].clone();
    info!(addr = %node1_addr, "Node 1 listening");

    // Node 2 - bootstrap to node 1
    let keypair2 = identity::Keypair::generate_ed25519();
    let config2 = Libp2pConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        bootstrap_peers: vec![node1_addr.clone()],
        ..Default::default()
    };
    let (consensus_tx2, _consensus_rx2) = mpsc::channel(100);
    let (tx_validation_handle2, _tx_rx2) = test_tx_validation_handle();
    let codec_pool2 = test_codec_pool_handle();

    let (adapter2, _sync_rx2, _tx_req_rx2, _cert_rx2) = Libp2pAdapter::new(
        config2,
        keypair2,
        ValidatorId(1),
        ShardGroupId(0),
        consensus_tx2,
        tx_validation_handle2,
        codec_pool2,
    )
    .await
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

    use hyperscale_production::network::{Libp2pAdapter, Libp2pConfig};
    use libp2p::identity;

    let keypair = identity::Keypair::generate_ed25519();
    let config = Libp2pConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        bootstrap_peers: vec![],
        ..Default::default()
    };
    let (consensus_tx, _consensus_rx) = mpsc::channel(100);
    let (tx_validation_handle, _tx_rx) = test_tx_validation_handle();
    let codec_pool = test_codec_pool_handle();

    let (adapter, _sync_rx, _tx_req_rx, _cert_rx) = Libp2pAdapter::new(
        config,
        keypair,
        ValidatorId(0),
        ShardGroupId(0),
        consensus_tx,
        tx_validation_handle,
        codec_pool,
    )
    .await
    .unwrap();

    // Subscribe to shard topics
    let result = adapter.subscribe_shard(ShardGroupId(0)).await;
    assert!(result.is_ok(), "Should subscribe to shard topics");

    info!("Topic subscription successful");
}

// ============================================================================
// Production Runner with Network Tests
// ============================================================================

#[tokio::test]
#[serial]
async fn test_production_runner_with_network() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    use hyperscale_production::network::Libp2pConfig;
    use libp2p::identity;

    let fixtures = TestFixtures::new(42, 1);

    // Create temp storage
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test_db");
    let storage = RocksDbStorage::open(&db_path).unwrap();
    let storage = Arc::new(storage);

    let ed25519_keypair = identity::Keypair::generate_ed25519();
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
            .network(network_config, ed25519_keypair)
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

    use hyperscale_production::network::Libp2pConfig;
    use libp2p::identity;

    let fixtures = TestFixtures::new(42, 1);

    // Create temp storage
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test_db");
    let storage = RocksDbStorage::open(&db_path).unwrap();
    let storage = Arc::new(storage);

    let ed25519_keypair = identity::Keypair::generate_ed25519();
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
        .network(network_config, ed25519_keypair)
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
