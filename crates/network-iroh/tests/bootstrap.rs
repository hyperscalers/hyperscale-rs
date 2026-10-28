//! Bootstrap peers found through DNS.

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use hyperscale_crypto_bls::BlsVerifier;
use hyperscale_network::HandlerRegistry;
use hyperscale_network_iroh::test_utils::TestFixtures;
use hyperscale_network_iroh::testing::LocalDns;
use hyperscale_network_iroh::{IrohAdapter, IrohAdapterArgs, IrohConfig, format_endpoint_addr};
use hyperscale_types::{NetworkDefinition, ShardId, ValidatorId};
use iroh::dns::DnsResolver;
use tokio::time::{sleep, timeout};

/// Longest a host takes to find and bind a peer it learns of from DNS.
const BIND_DEADLINE: Duration = Duration::from_secs(20);

/// A host on loopback carrying validator `index`, configured by `adjust`.
async fn host(
    fixtures: &TestFixtures,
    index: u32,
    adjust: impl FnOnce(&mut IrohConfig),
) -> Arc<IrohAdapter> {
    let bind_addr: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let mut config = IrohConfig::for_testing(fixtures.network_key(index), bind_addr);
    adjust(&mut config);
    let shards = [ShardId::ROOT];
    IrohAdapter::bind(IrohAdapterArgs {
        config,
        network: NetworkDefinition::simulator(),
        vnodes: vec![(ValidatorId::new(u64::from(index)), fixtures.signer(index))],
        local_shards: shards.iter().copied().collect::<HashSet<_>>(),
        registry: Arc::new(HandlerRegistry::new(shards.iter().copied().collect())),
        validator_keys: fixtures.validator_key_map(),
        verifier: Arc::new(BlsVerifier),
    })
    .await
    .expect("the host binds")
}

/// A host told only a domain dials the peer its TXT record names, and binds
/// it.
#[tokio::test(flavor = "multi_thread")]
async fn a_host_bootstraps_to_the_peer_its_domain_names() {
    let fixtures = TestFixtures::new(41, 2);
    let named = host(&fixtures, 0, |_| {}).await;
    let dns = LocalDns::serve(vec![(
        "_hyperscale.boot.test".to_owned(),
        vec![format_endpoint_addr(&named.endpoint_addr())],
    )])
    .await
    .expect("the DNS server binds");

    let joining = host(&fixtures, 1, |config| {
        config.bootstrap_domains = vec!["boot.test".to_owned()];
        config.dns_resolver = Some(DnsResolver::with_nameserver(dns.addr()));
    })
    .await;

    timeout(BIND_DEADLINE, async {
        while joining.peer_for_validator(ValidatorId::new(0)).is_none() {
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the host binds the peer its domain names");
}

/// A domain that names nothing leaves the host unbound but running.
#[tokio::test(flavor = "multi_thread")]
async fn a_domain_with_no_records_binds_nothing() {
    let fixtures = TestFixtures::new(42, 2);
    let _unnamed = host(&fixtures, 0, |_| {}).await;
    let dns = LocalDns::serve(Vec::new())
        .await
        .expect("the DNS server binds");

    let joining = host(&fixtures, 1, |config| {
        config.bootstrap_domains = vec!["empty.test".to_owned()];
        config.dns_resolver = Some(DnsResolver::with_nameserver(dns.addr()));
    })
    .await;

    sleep(Duration::from_secs(2)).await;
    assert!(joining.peer_for_validator(ValidatorId::new(0)).is_none());
}
