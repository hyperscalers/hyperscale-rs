//! Multi-vnode hosting: one host carrying several same-shard vnodes.
//!
//! Validates that the multi-validator bind plumbing lands every hosted
//! validator id on the remote adapter's `validator_peers` map. The bind is
//! shard-agnostic (the adapter exposes a flat `local_validator_ids` and resolves
//! peers by validator id), so same-shard hosting exercises the whole bind path.
//! Consensus progress is timing-sensitive over real networking and is exercised
//! separately by the simulator; this scopes itself to a host's start and the
//! multi-validator handshake. `#[serial]`.

mod support;

use std::time::Duration;

use hyperscale_network_iroh::test_utils::TestFixtures;
use hyperscale_types::{BeaconChainConfig, ValidatorId};
use serial_test::serial;
use support::start_host;
use tokio::time::{sleep, timeout};
use tracing_subscriber::fmt;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn two_hosts_resolve_every_hosted_validator_id() {
    let _ = fmt().with_test_writer().try_init();

    // Four validators, all in shard 0; two per host.
    let fixtures = TestFixtures::new(7, 4);

    let (node0, _dir0) = start_host(&fixtures, &[0, 1], vec![], BeaconChainConfig::default());
    let host0 = node0.handle();
    let (ids0, host0_addr, host0_id) = host0
        .probe(|p| {
            let network = p.network();
            (
                network.local_validator_ids(),
                network.endpoint_addr(),
                network.local_endpoint_id(),
            )
        })
        .expect("host 0 runs");
    assert_eq!(
        ids0,
        &[ValidatorId::new(0), ValidatorId::new(1)],
        "host 0 should expose both hosted validator ids"
    );

    // Bind host 1 to host 0's address.
    let (node1, _dir1) = start_host(
        &fixtures,
        &[2, 3],
        vec![host0_addr],
        BeaconChainConfig::default(),
    );
    let host1 = node1.handle();
    let (ids1, host1_id) = host1
        .probe(|p| {
            (
                p.network().local_validator_ids(),
                p.network().local_endpoint_id(),
            )
        })
        .expect("host 1 runs");
    assert_eq!(
        ids1,
        &[ValidatorId::new(2), ValidatorId::new(3)],
        "host 1 should expose both hosted validator ids"
    );

    // Each handshake takes a few hundred ms at most; wait until both sides resolve every remote vid or the
    // bind timeout elapses.
    let (host0_sees, host1_sees) = timeout(Duration::from_secs(10), async {
        loop {
            let host0_sees = host0
                .probe(|p| {
                    [
                        p.network().peer_for_validator(ValidatorId::new(2)),
                        p.network().peer_for_validator(ValidatorId::new(3)),
                    ]
                })
                .expect("host 0 runs");
            let host1_sees = host1
                .probe(|p| {
                    [
                        p.network().peer_for_validator(ValidatorId::new(0)),
                        p.network().peer_for_validator(ValidatorId::new(1)),
                    ]
                })
                .expect("host 1 runs");
            if host0_sees.iter().all(Option::is_some) && host1_sees.iter().all(Option::is_some) {
                return (host0_sees, host1_sees);
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("multi-vnode bind should complete within timeout");

    // Every remote validator id on host 0 resolves to host 1's single peer,
    // and vice versa — this is the load-bearing multi-vnode bind property.
    for resolved in host0_sees {
        assert_eq!(resolved, Some(host1_id));
    }
    for resolved in host1_sees {
        assert_eq!(resolved, Some(host0_id));
    }

    let _ = timeout(Duration::from_secs(5), node0.stop()).await;
    let _ = timeout(Duration::from_secs(5), node1.stop()).await;
}
