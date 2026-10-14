//! What a connection carries once UDP between its two hosts is blocked and
//! it has fallen back to the relay.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use hyperscale_crypto_bls::BlsVerifier;
use hyperscale_hbor::Hbor;
use hyperscale_network::{GossipVerdict, HandlerRegistry, Network, RequestError, ResponseVerdict};
use hyperscale_network_iroh::test_utils::TestFixtures;
use hyperscale_network_iroh::testing::{LocalRelay, UdpBridge};
use hyperscale_network_iroh::{
    EndpointAddr, IrohAdapter, IrohAdapterArgs, IrohConfig, IrohNetwork, PathKind, RequestManager,
    RequestManagerConfig, RequestPool, RequestStreams,
};
use hyperscale_types::{
    GossipMessage, MessageClass, NetworkDefinition, NetworkMessage, Request, RoutingCommittees,
    ShardId, TopicScope, TopologySnapshot, ValidatorId,
};
use tokio::runtime::Handle;
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};

/// Budget for a bind, a path change, or a delivery.
const BUDGET: Duration = Duration::from_secs(20);

/// How long something that must not arrive is watched for.
const SILENCE_WATCH: Duration = Duration::from_millis(500);

/// Path timers short enough that a blocked direct path is abandoned, and
/// the connection falls back, within a second.
const PATH_IDLE_TIMEOUT: Duration = Duration::from_secs(1);
const PATH_KEEP_ALIVE: Duration = Duration::from_millis(300);

#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
struct Vote(u64);

impl NetworkMessage for Vote {
    fn message_type_id() -> &'static str {
        "test.vote"
    }

    fn class() -> MessageClass {
        MessageClass::Consensus
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
struct Backfill(u64);

impl NetworkMessage for Backfill {
    fn message_type_id() -> &'static str {
        "test.backfill"
    }

    fn class() -> MessageClass {
        MessageClass::Bulk
    }
}

impl GossipMessage for Backfill {
    const SCOPE: TopicScope = TopicScope::Shard;
}

#[derive(Debug, Clone, Hbor)]
struct GetProposal(u64);

#[derive(Debug, Clone, Hbor)]
struct Proposal(u64);

impl NetworkMessage for GetProposal {
    fn message_type_id() -> &'static str {
        "test.get_proposal"
    }

    fn class() -> MessageClass {
        MessageClass::Consensus
    }
}

impl NetworkMessage for Proposal {
    fn message_type_id() -> &'static str {
        "test.proposal"
    }

    fn class() -> MessageClass {
        MessageClass::Consensus
    }
}

impl Request for GetProposal {
    type Response = Proposal;
}

#[derive(Debug, Clone, Hbor)]
struct GetRange(u64);

#[derive(Debug, Clone, Hbor)]
struct Range(u64);

impl NetworkMessage for GetRange {
    fn message_type_id() -> &'static str {
        "test.get_range"
    }

    fn class() -> MessageClass {
        MessageClass::Recovery
    }
}

impl NetworkMessage for Range {
    fn message_type_id() -> &'static str {
        "test.range"
    }

    fn class() -> MessageClass {
        MessageClass::Recovery
    }
}

impl Request for GetRange {
    type Response = Range;
}

fn vid(index: u32) -> ValidatorId {
    ValidatorId::new(u64::from(index))
}

struct Host {
    adapter: Arc<IrohAdapter>,
    network: Arc<IrohNetwork>,
}

/// Stand up the host carrying validator `index` on loopback address `ip`,
/// homed on `relay`.
async fn host(
    fixtures: &TestFixtures,
    index: u32,
    ip: IpAddr,
    relay: &LocalRelay,
    shards: &[ShardId],
    bootstrap: Vec<EndpointAddr>,
) -> Host {
    let mut config = IrohConfig::for_testing(fixtures.network_key(index), SocketAddr::new(ip, 0));
    config.relays = vec![relay.url()];
    config.relay_address_discovery = false;
    config.bootstrap_peers = bootstrap;
    config.path_idle_timeout = PATH_IDLE_TIMEOUT;
    config.path_keep_alive = PATH_KEEP_ALIVE;

    let registry = Arc::new(HandlerRegistry::new(shards.iter().copied().collect()));
    let adapter = IrohAdapter::bind(IrohAdapterArgs {
        config,
        network: NetworkDefinition::simulator(),
        vnodes: vec![(vid(index), fixtures.signer(index))],
        local_shards: shards.iter().copied().collect::<HashSet<_>>(),
        registry: Arc::clone(&registry),
        validator_keys: fixtures.validator_key_map(),
        verifier: Arc::new(BlsVerifier),
    })
    .await
    .expect("the host binds");

    let genesis = fixtures.genesis_validators();
    let committee = genesis.committee.clone();
    let topology = Arc::new(ArcSwap::from_pointee(TopologySnapshot::new(
        genesis.network,
        1,
        genesis.validators,
    )));
    let pool: Arc<dyn RequestPool> =
        Arc::new(RequestStreams::new(Arc::clone(&adapter), Duration::ZERO));
    let network = Arc::new(IrohNetwork::new(
        Arc::clone(&adapter),
        Arc::new(RequestManager::new(pool, RequestManagerConfig::default())),
        Handle::current(),
        registry,
        topology,
        Duration::ZERO,
    ));
    network.update_routing_committees(Arc::new(RoutingCommittees::from([(
        ShardId::ROOT,
        committee,
    )])));
    Host { adapter, network }
}

async fn wait_for(what: &str, mut check: impl FnMut() -> bool) {
    timeout(BUDGET, async {
        while !check() {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{what}"));
}

/// Ask the root shard for `request` from `network` and await the outcome.
async fn ask<R: Request + Clone + 'static>(
    network: &IrohNetwork,
    request: R,
) -> Result<R::Response, RequestError> {
    let (tx, mut rx) = mpsc::unbounded_channel();
    network.request(
        ShardId::ROOT,
        None,
        request,
        None,
        Box::new(move |outcome| {
            let _ = tx.send(outcome);
            ResponseVerdict::Accept
        }),
    );
    timeout(BUDGET, rx.recv())
        .await
        .expect("the request resolves")
        .expect("the callback runs")
}

/// Two hosts homed on one relay, on different address families, so the
/// bridge is the only direct path between them and closing it blocks their
/// UDP. The asker serves no shard, so its requests go to the wire; the
/// server serves the root shard.
struct Pair {
    asker: Host,
    server: Host,
    bridge: UdpBridge,
    relay: LocalRelay,
}

impl Pair {
    async fn meet(fixtures: &TestFixtures) -> Self {
        let relay = LocalRelay::spawn().await.expect("the relay starts");
        let asker = host(
            fixtures,
            0,
            Ipv4Addr::LOCALHOST.into(),
            &relay,
            &[],
            Vec::new(),
        )
        .await;
        let asker_addr = asker.adapter.endpoint_addr();
        let by_relay = EndpointAddr::new(asker_addr.id).with_relay_url(relay.url());
        let server = host(
            fixtures,
            1,
            Ipv6Addr::LOCALHOST.into(),
            &relay,
            &[ShardId::ROOT],
            vec![by_relay],
        )
        .await;

        let socket = |host: &Host| {
            *host
                .adapter
                .endpoint_addr()
                .ip_addrs()
                .next()
                .expect("a bound socket")
        };
        let bridge = UdpBridge::spawn(socket(&asker), socket(&server))
            .await
            .expect("the bridge opens");
        asker
            .adapter
            .add_external_addr(bridge.seen_by_right())
            .await;
        server
            .adapter
            .add_external_addr(bridge.seen_by_left())
            .await;
        Self {
            asker,
            server,
            bridge,
            relay,
        }
    }

    /// The kind of path each side reports for the other.
    fn kinds(&self) -> (Option<PathKind>, Option<PathKind>) {
        let kind = |from: &Host, to: &Host| {
            from.adapter
                .path_status(to.adapter.local_endpoint_id())
                .and_then(|status| status.kind)
        };
        (
            kind(&self.asker, &self.server),
            kind(&self.server, &self.asker),
        )
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_relayed_peer_gets_consensus_traffic_and_no_bulk() {
    let fixtures = TestFixtures::new(31, 2);
    let pair = Pair::meet(&fixtures).await;
    let (asker, server) = (&pair.asker, &pair.server);

    let (vote_tx, mut votes) = mpsc::unbounded_channel();
    server
        .network
        .register_notification_handler(move |vote: Vote| {
            let _ = vote_tx.send(vote);
        });
    let (backfill_tx, mut backfills) = mpsc::unbounded_channel();
    server
        .network
        .register_gossip_handler(move |item: Backfill, _: ShardId| {
            let _ = backfill_tx.send(item);
            GossipVerdict::Accept
        });
    server
        .network
        .register_request_handler(ShardId::ROOT, |GetProposal(n): GetProposal| Proposal(n));
    server
        .network
        .register_request_handler(ShardId::ROOT, |GetRange(n): GetRange| Range(n));

    // The pair meets through the relay and moves to the direct path, on
    // which everything goes.
    wait_for("the pair reaches a direct path", || {
        pair.kinds() == (Some(PathKind::Direct), Some(PathKind::Direct))
    })
    .await;
    asker
        .network
        .broadcast_to_shard(ShardId::ROOT, &Backfill(1));
    let delivered = timeout(BUDGET, backfills.recv()).await.expect("delivered");
    assert_eq!(delivered, Some(Backfill(1)));
    assert!(ask(&asker.network, GetRange(1)).await.is_ok());

    // UDP between the two hosts is blocked; both fall back to the relay.
    pair.bridge.set_open(false);
    wait_for("both sides report the peer relayed", || {
        pair.kinds() == (Some(PathKind::Relayed), Some(PathKind::Relayed))
    })
    .await;

    // Consensus traffic still flows, both ways of a request included.
    asker.network.notify(&[vid(1)], &Vote(7));
    let vote = timeout(BUDGET, votes.recv()).await.expect("delivered");
    assert_eq!(vote, Some(Vote(7)));
    let Proposal(answer) = ask(&asker.network, GetProposal(9))
        .await
        .expect("a consensus request is answered over the relay");
    assert_eq!(answer, 9);

    // Bulk gossip is not sent, and a recovery request finds no usable peer.
    asker
        .network
        .broadcast_to_shard(ShardId::ROOT, &Backfill(2));
    assert!(
        timeout(SILENCE_WATCH, backfills.recv()).await.is_err(),
        "bulk gossip does not cross a relayed path"
    );
    assert!(
        matches!(
            ask(&asker.network, GetRange(2)).await,
            Err(RequestError::BackingOff { .. })
        ),
        "a recovery request is held back from a relayed peer"
    );

    let status = asker
        .adapter
        .path_status(server.adapter.local_endpoint_id())
        .expect("the peer is bound");
    assert_eq!(status.kind, Some(PathKind::Relayed));
    assert_eq!(status.fallbacks, 1);
    assert!(status.relayed_consensus_bytes > 0);
    assert!(status.refused >= 1, "the refused bulk frame is counted");

    // The server reaches its only committee peer by relay alone.
    let readiness = server.network.readiness();
    assert_eq!((readiness.direct, readiness.relayed), (0, 1));
    assert!(readiness.degraded());

    pair.relay.shutdown().await.expect("the relay stops");
}
