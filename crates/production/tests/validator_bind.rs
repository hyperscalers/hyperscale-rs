//! Validator-bind protocol tests for the production runner.
//!
//! Covers the bind handshake's success, wrong-key rejection, and
//! disconnect-eviction paths over real localhost QUIC. `#[serial]` to avoid
//! port conflicts; runs on a multi-threaded runtime to match the production
//! host's runtime shape.

mod fixtures;
mod support;

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use fixtures::TestFixtures;
use hyperscale_network::HandlerRegistry;
use hyperscale_network_libp2p::{Libp2pAdapter, Libp2pConfig};
use hyperscale_types::{NetworkDefinition, ShardId, ValidatorId, generate_bls_keypair};
use serial_test::serial;
use support::CONNECTION_TIMEOUT;
use tokio::time::{sleep, timeout};
use tracing::info;
use tracing_subscriber::fmt;

#[tokio::test(flavor = "multi_thread")]
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
        HashSet::from([ShardId::ROOT]),
        Arc::new(HandlerRegistry::default()),
        fixtures.validator_key_map(),
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
        HashSet::from([ShardId::ROOT]),
        Arc::new(HandlerRegistry::default()),
        fixtures.validator_key_map(),
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

#[tokio::test(flavor = "multi_thread")]
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
        HashSet::from([ShardId::ROOT]),
        Arc::new(HandlerRegistry::default()),
        fixtures.validator_key_map(),
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
        HashSet::from([ShardId::ROOT]),
        Arc::new(HandlerRegistry::default()),
        fixtures.validator_key_map(),
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

#[tokio::test(flavor = "multi_thread")]
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
        HashSet::from([ShardId::ROOT]),
        Arc::new(HandlerRegistry::default()),
        fixtures.validator_key_map(),
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
        HashSet::from([ShardId::ROOT]),
        Arc::new(HandlerRegistry::default()),
        fixtures.validator_key_map(),
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
