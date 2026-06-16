//! Network adapter tests for the production runner (localhost QUIC).
//!
//! Exercises the raw `Libp2pAdapter` construction, peering, and topic
//! subscription paths. `#[serial]` to avoid port conflicts; runs on a
//! multi-threaded runtime to match the production host's runtime shape.

mod support;

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use hyperscale_network::HandlerRegistry;
use hyperscale_network_libp2p::{Libp2pAdapter, Libp2pConfig};
use hyperscale_types::{NetworkDefinition, ShardId, ValidatorId};
use libp2p::identity::Keypair;
use serial_test::serial;
use support::{CONNECTION_TIMEOUT, test_bind_args};
use tokio::time::{sleep, timeout};
use tracing::info;
use tracing_subscriber::fmt;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_network_adapter_starts() {
    let _ = fmt().with_test_writer().try_init();

    let keypair = Keypair::generate_ed25519();
    let validator_id = ValidatorId::new(0);
    let shard = ShardId::ROOT;

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

#[tokio::test(flavor = "multi_thread")]
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
        HashSet::from([ShardId::ROOT]),
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
        HashSet::from([ShardId::ROOT]),
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

#[tokio::test(flavor = "multi_thread")]
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
        HashSet::from([ShardId::ROOT]),
        Arc::new(HandlerRegistry::default()),
        topo,
    )
    .unwrap();

    // Subscribe to a topic via subscribe_topic (individual subscription)
    let result = adapter.subscribe_topic("hyperscale/block.header/shard-0/1.0.0".to_string());
    assert!(result.is_ok(), "Should subscribe to topic");

    info!("Topic subscription successful");
}
