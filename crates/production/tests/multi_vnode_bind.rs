//! Multi-vnode hosting: one host carrying several same-shard vnodes.
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

use hyperscale_network_libp2p::test_utils::TestFixtures;
use hyperscale_types::ValidatorId;
use serial_test::serial;
use support::build_runner;
use tokio::task::spawn;
use tokio::time::{sleep, timeout};
use tracing_subscriber::fmt;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn two_hosts_resolve_every_hosted_validator_id() {
    let _ = fmt().with_test_writer().try_init();

    // Four validators, all in shard 0; two per host.
    let fixtures = TestFixtures::new(7, 4);

    let (mut runner0, _dir0, _) = build_runner(&fixtures, &[0, 1], vec![], None);
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

    let (mut runner1, _dir1, _) =
        build_runner(&fixtures, &[2, 3], vec![host0_addrs[0].clone()], None);
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
    let (host0_sees, host1_sees) = timeout(Duration::from_secs(10), async {
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

    // Every remote validator id on host 0 resolves to host 1's single peer,
    // and vice versa — this is the load-bearing multi-vnode bind property.
    for resolved in host0_sees {
        assert_eq!(resolved, Some(adapter1.local_peer_id()));
    }
    for resolved in host1_sees {
        assert_eq!(resolved, Some(adapter0.local_peer_id()));
    }

    drop(shutdown0);
    drop(shutdown1);
    let _ = timeout(Duration::from_secs(5), h0).await;
    let _ = timeout(Duration::from_secs(5), h1).await;
}
