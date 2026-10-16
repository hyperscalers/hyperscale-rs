//! Validator-bind over real loopback QUIC: two hosts, several validators
//! each, bound by endpoint identity.

use std::collections::{BTreeSet, HashSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use hyperscale_crypto_bls::{BlsSigner, BlsVerifier};
use hyperscale_network::{HandlerRegistry, ValidatorKeyMap};
use hyperscale_network_iroh::test_utils::TestFixtures;
use hyperscale_network_iroh::{ALPN, IrohAdapter, IrohAdapterArgs, IrohConfig, LocalVnodeIdentity};
use hyperscale_types::{NetworkDefinition, ShardId, Signer, ValidatorId};
use iroh::endpoint::{Builder, presets};
use iroh::{EndpointAddr, RelayMode};
use tokio::time::{sleep, timeout};

/// Budget for a connection and its validator-bind handshake over loopback.
const BIND_BUDGET: Duration = Duration::from_secs(10);

/// How long a binding that must not form is watched for.
const REFUSAL_WATCH: Duration = Duration::from_secs(2);

fn loopback() -> SocketAddr {
    (Ipv4Addr::LOCALHOST, 0).into()
}

fn vid(index: u32) -> ValidatorId {
    ValidatorId::new(u64::from(index))
}

/// What a test host is stood up with, beyond its fixtures.
struct HostSpec<'a> {
    fixtures: &'a TestFixtures,
    /// Fixture indices of the validators the host carries; its network key
    /// is the first one's.
    validators: &'a [u32],
    bootstrap: Vec<EndpointAddr>,
    /// Signers the host attests with instead of its fixtures' own.
    signers: Option<Vec<Arc<dyn Signer>>>,
    /// Key map the host verifies against instead of its fixtures' own.
    keys: Option<Arc<ValidatorKeyMap>>,
}

impl<'a> HostSpec<'a> {
    fn new(fixtures: &'a TestFixtures, validators: &'a [u32]) -> Self {
        Self {
            fixtures,
            validators,
            bootstrap: Vec::new(),
            signers: None,
            keys: None,
        }
    }

    async fn bind(self) -> Arc<IrohAdapter> {
        let mut config =
            IrohConfig::for_testing(self.fixtures.network_key(self.validators[0]), loopback());
        config.bootstrap_peers = self.bootstrap;
        let signers = self.signers.unwrap_or_else(|| {
            self.validators
                .iter()
                .map(|&i| self.fixtures.signer(i))
                .collect()
        });
        let vnodes: Vec<LocalVnodeIdentity> = self
            .validators
            .iter()
            .map(|&i| vid(i))
            .zip(signers)
            .collect();
        IrohAdapter::bind(IrohAdapterArgs {
            config,
            network: NetworkDefinition::simulator(),
            vnodes,
            local_shards: HashSet::from([ShardId::ROOT]),
            registry: Arc::new(HandlerRegistry::default()),
            validator_keys: self
                .keys
                .unwrap_or_else(|| self.fixtures.validator_key_map()),
            verifier: Arc::new(BlsVerifier),
        })
        .await
        .expect("the host binds")
    }
}

/// Whether `host` resolves every one of `validators` to `peer`.
fn resolves(host: &IrohAdapter, validators: &[u32], peer: &IrohAdapter) -> bool {
    validators
        .iter()
        .all(|&i| host.peer_for_validator(vid(i)) == Some(peer.local_endpoint_id()))
}

async fn wait_for(budget: Duration, mut check: impl FnMut() -> bool) -> bool {
    timeout(budget, async {
        while !check() {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .is_ok()
}

#[tokio::test(flavor = "multi_thread")]
async fn two_hosts_bind_every_hosted_validator() {
    let fixtures = TestFixtures::new(7, 4);
    let host0 = HostSpec::new(&fixtures, &[0, 1]).bind().await;
    assert_eq!(host0.local_validator_ids(), &[vid(0), vid(1)]);
    assert_eq!(host0.local_endpoint_id(), fixtures.endpoint_id(0));

    let mut spec = HostSpec::new(&fixtures, &[2, 3]);
    spec.bootstrap = vec![host0.endpoint_addr()];
    let host1 = spec.bind().await;

    assert!(
        wait_for(BIND_BUDGET, || resolves(&host0, &[2, 3], &host1)
            && resolves(&host1, &[0, 1], &host0))
        .await,
        "every hosted validator resolves to its host on both sides"
    );
    assert_eq!(host0.connected_peers(), vec![host1.local_endpoint_id()]);
    assert_eq!(host1.cached_peer_count(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_host_that_signs_with_the_wrong_consensus_key_is_refused() {
    let fixtures = TestFixtures::new(7, 2);
    let host0 = HostSpec::new(&fixtures, &[0]).bind().await;

    let mut spec = HostSpec::new(&fixtures, &[1]);
    spec.bootstrap = vec![host0.endpoint_addr()];
    spec.signers = Some(vec![Arc::new(BlsSigner::generate())]);
    let impostor = spec.bind().await;

    sleep(REFUSAL_WATCH).await;
    assert_eq!(host0.peer_for_validator(vid(1)), None);
    assert_eq!(host0.cached_peer_count(), 0);
    assert_eq!(impostor.cached_peer_count(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn bindings_are_evicted_when_the_peer_goes_away() {
    let fixtures = TestFixtures::new(7, 2);
    let host0 = HostSpec::new(&fixtures, &[0]).bind().await;
    let mut spec = HostSpec::new(&fixtures, &[1]);
    spec.bootstrap = vec![host0.endpoint_addr()];
    let host1 = spec.bind().await;
    assert!(wait_for(BIND_BUDGET, || resolves(&host0, &[1], &host1)).await);

    host1.shutdown();

    assert!(
        wait_for(BIND_BUDGET, || host0.peer_for_validator(vid(1)).is_none()).await,
        "a closed connection takes its bindings with it"
    );
    assert_eq!(host0.cached_peer_count(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wanted_validator_is_dialed_from_its_signed_record() {
    let fixtures = TestFixtures::new(7, 4);
    let host0 = HostSpec::new(&fixtures, &[0, 1]).bind().await;
    let host1 = HostSpec::new(&fixtures, &[2, 3]).bind().await;

    let records = host1.address_records();
    assert_eq!(records.len(), 2, "one record per hosted validator");
    for record in &records {
        let _ = host0.ingest_validator_address(record);
    }
    assert_eq!(host0.address_book().len(), 2);
    assert_eq!(
        host0.cached_peer_count(),
        0,
        "a record alone connects nothing"
    );

    host0.update_wanted_validators(BTreeSet::from([vid(2), vid(3)]));

    assert!(
        wait_for(BIND_BUDGET, || resolves(&host0, &[2, 3], &host1)
            && resolves(&host1, &[0, 1], &host0))
        .await,
        "a wanted validator with a record is dialed and bound"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_host_signs_its_records_again_only_when_its_addresses_change() {
    let fixtures = TestFixtures::new(7, 2);
    let host = HostSpec::new(&fixtures, &[0, 1]).bind().await;

    let first = host.address_records();
    assert_eq!(first.len(), 2);
    assert_eq!(
        host.address_records(),
        first,
        "the same addresses give the same records, so every copy dedups"
    );

    host.add_external_addr("203.0.113.7:9000".parse().unwrap())
        .await;
    assert!(
        wait_for(BIND_BUDGET, || host.address_records() != first).await,
        "new addresses are signed afresh"
    );
    let moved = host.address_records();
    assert!(
        moved
            .iter()
            .all(|record| record.sequence > first[0].sequence)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn hosts_that_dial_each_other_at_once_keep_one_connection() {
    let fixtures = TestFixtures::new(7, 2);
    let host0 = HostSpec::new(&fixtures, &[0]).bind().await;
    let mut spec = HostSpec::new(&fixtures, &[1]);
    spec.bootstrap = vec![host0.endpoint_addr()];
    let host1 = spec.bind().await;

    // Host 1 dials its bootstrap peer on its first sweep; host 0 dials back
    // from the record as soon as it has one.
    for record in host1.address_records() {
        let _ = host0.ingest_validator_address(&record);
    }
    host0.update_wanted_validators(BTreeSet::from([vid(1)]));

    assert!(
        wait_for(BIND_BUDGET, || resolves(&host0, &[1], &host1)
            && resolves(&host1, &[0], &host0))
        .await
    );
    // Whichever connection lost has been closed by now; the pair stays
    // bound through it.
    sleep(REFUSAL_WATCH).await;
    assert!(resolves(&host0, &[1], &host1) && resolves(&host1, &[0], &host0));
    assert_eq!(host0.cached_peer_count(), 1);
    assert_eq!(host1.cached_peer_count(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_validator_unknown_to_the_topology_binds_once_its_key_arrives() {
    let fixtures = TestFixtures::new(7, 2);
    let all_keys = fixtures.validator_key_map();
    let only_own: ValidatorKeyMap = all_keys
        .iter()
        .filter(|(validator, _)| **validator == vid(0))
        .map(|(validator, key)| (*validator, *key))
        .collect();

    let mut spec = HostSpec::new(&fixtures, &[0]);
    spec.keys = Some(Arc::new(only_own));
    let host0 = spec.bind().await;
    let mut spec = HostSpec::new(&fixtures, &[1]);
    spec.bootstrap = vec![host0.endpoint_addr()];
    let host1 = spec.bind().await;

    sleep(REFUSAL_WATCH).await;
    assert_eq!(
        host0.cached_peer_count(),
        0,
        "a validator with no key in the topology cannot bind"
    );

    host0.update_validator_keys(all_keys);

    assert!(
        wait_for(Duration::from_secs(30), || resolves(&host0, &[1], &host1)
            && resolves(&host1, &[0], &host0))
        .await,
        "the bootstrap sweep binds the peer once its key is known"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_connection_that_never_binds_is_closed() {
    let fixtures = TestFixtures::new(7, 1);
    let host = HostSpec::new(&fixtures, &[0]).bind().await;

    let stranger = Builder::empty()
        .preset(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .clear_ip_transports()
        .bind_addr(loopback())
        .expect("a loopback socket")
        .bind()
        .await
        .expect("the stranger binds");
    let connection = stranger
        .connect(host.endpoint_addr(), ALPN)
        .await
        .expect("the transport handshake needs no validator");

    let closed = timeout(BIND_BUDGET, connection.closed()).await;
    assert!(closed.is_ok(), "an unbound connection is closed");
    assert_eq!(host.cached_peer_count(), 0);
    stranger.close().await;
}
