//! What a connection carries once UDP between its two hosts is blocked and
//! it has fallen back to the relay.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use hyperscale_crypto_bls::BlsVerifier;
use hyperscale_hbor::Hbor;
use hyperscale_network::{HandlerRegistry, Network, RequestError, ResponseVerdict, Verdict};
use hyperscale_network_iroh::test_utils::TestFixtures;
use hyperscale_network_iroh::testing::{LocalRelay, Star, UdpBridge};
use hyperscale_network_iroh::{
    EndpointAddr, IrohAdapter, IrohAdapterArgs, IrohConfig, IrohNetwork, PathKind, PathStatus,
    RedialBudget, RequestManager, RequestManagerConfig, RequestPool, RequestStreams,
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

/// How soon after UDP is restored a relayed pair must be direct again: one
/// re-dial interval and a hole punch, far inside the library's own minute.
const RETURN_BOUND: Duration = Duration::from_secs(12);

/// How long UDP stays blocked after a pair falls back: long enough that
/// the hole punch rounds the library starts by itself in the first seconds
/// of a connection have stopped probing, so that only a later round can
/// bring the pair back.
const OUTAGE_AFTER_FALLBACK: Duration = Duration::from_secs(20);

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
    redial_attempts: u32,
) -> Host {
    let mut config = IrohConfig::for_testing(fixtures.network_key(index), SocketAddr::new(ip, 0));
    config.relays = vec![relay.url()];
    config.relay_address_discovery = false;
    config.bootstrap_peers = bootstrap;
    config.path_idle_timeout = PATH_IDLE_TIMEOUT;
    config.path_keep_alive = PATH_KEEP_ALIVE;
    config.redial.attempts = redial_attempts;

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
    /// `redial_attempts` sets how often each side re-dials while relayed.
    async fn meet(fixtures: &TestFixtures, redial_attempts: u32) -> Self {
        let relay = LocalRelay::spawn().await.expect("the relay starts");
        let asker = host(
            fixtures,
            0,
            Ipv4Addr::LOCALHOST.into(),
            &relay,
            &[],
            Vec::new(),
            redial_attempts,
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
            redial_attempts,
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

    /// The path each side reports for the other, `None` while unbound.
    fn statuses(&self) -> (Option<PathStatus>, Option<PathStatus>) {
        let status =
            |from: &Host, to: &Host| from.adapter.path_status(to.adapter.local_endpoint_id());
        (
            status(&self.asker, &self.server),
            status(&self.server, &self.asker),
        )
    }

    /// The kind of path each side reports for the other.
    fn kinds(&self) -> (Option<PathKind>, Option<PathKind>) {
        let (asker, server) = self.statuses();
        (
            asker.and_then(|status| status.kind),
            server.and_then(|status| status.kind),
        )
    }

    /// Wait until both sides report a path of `kind` for the other; on
    /// timeout, panic with `what` and what each side reported last.
    async fn settle(&self, what: &str, kind: PathKind) {
        let both = (Some(kind), Some(kind));
        if timeout(BUDGET, async {
            while self.kinds() != both {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .is_err()
        {
            let (asker, server) = self.statuses();
            panic!("{what}: the asker reports {asker:?}, the server {server:?}");
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_relayed_peer_gets_consensus_traffic_and_no_bulk() {
    let fixtures = TestFixtures::new(31, 2);
    let pair = Pair::meet(&fixtures, 0).await;
    let (asker, server) = (&pair.asker, &pair.server);

    let (vote_tx, mut votes) = mpsc::unbounded_channel();
    server
        .network
        .register_notification_handler(move |vote: Vote| {
            let _ = vote_tx.send(vote);
            Verdict::Accept
        });
    let (backfill_tx, mut backfills) = mpsc::unbounded_channel();
    server
        .network
        .register_gossip_handler(move |item: Backfill, _: ShardId| {
            let _ = backfill_tx.send(item);
            Verdict::Accept
        });
    server
        .network
        .register_request_handler(ShardId::ROOT, |GetProposal(n): GetProposal| Proposal(n));
    server
        .network
        .register_request_handler(ShardId::ROOT, |GetRange(n): GetRange| Range(n));

    // The pair meets through the relay and moves to the direct path, on
    // which everything goes.
    pair.settle("the pair reaches a direct path", PathKind::Direct)
        .await;
    asker
        .network
        .broadcast_to_shard(ShardId::ROOT, &Backfill(1));
    let delivered = timeout(BUDGET, backfills.recv()).await.expect("delivered");
    assert_eq!(delivered, Some(Backfill(1)));
    assert!(ask(&asker.network, GetRange(1)).await.is_ok());

    // UDP between the two hosts is blocked; both fall back to the relay.
    pair.bridge.set_open(false);
    pair.settle("both sides report the peer relayed", PathKind::Relayed)
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

/// Block UDP between `pair` until both sides are relayed and then for
/// [`OUTAGE_AFTER_FALLBACK`]; then restore it. Returns when it was
/// restored.
async fn fall_back_and_restore(pair: &Pair) -> Instant {
    pair.settle("the pair reaches a direct path", PathKind::Direct)
        .await;
    pair.bridge.set_open(false);
    pair.settle("both sides report the peer relayed", PathKind::Relayed)
        .await;
    sleep(OUTAGE_AFTER_FALLBACK).await;
    pair.bridge.set_open(true);
    Instant::now()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_relayed_pair_is_direct_again_soon_after_udp_returns() {
    let fixtures = TestFixtures::new(32, 2);
    let pair = Pair::meet(&fixtures, 12).await;
    let restored = fall_back_and_restore(&pair).await;

    timeout(RETURN_BOUND, async {
        while pair.kinds() != (Some(PathKind::Direct), Some(PathKind::Direct)) {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the pair returns to a direct path within one re-dial");
    let returned = restored.elapsed();
    let redials = pair.asker.adapter.redials() + pair.server.adapter.redials();
    assert!(
        redials >= 1,
        "returned after {returned:?} without a re-dial"
    );

    // Direct again, nobody re-dials.
    sleep(Duration::from_secs(6)).await;
    assert_eq!(
        pair.asker.adapter.redials() + pair.server.adapter.redials(),
        redials,
        "a direct pair is not re-dialed"
    );

    pair.relay.shutdown().await.expect("the relay stops");
}

#[tokio::test(flavor = "multi_thread")]
async fn without_re_dials_a_relayed_pair_waits_for_the_library() {
    let fixtures = TestFixtures::new(33, 2);
    let pair = Pair::meet(&fixtures, 0).await;
    fall_back_and_restore(&pair).await;

    sleep(RETURN_BOUND).await;
    assert_eq!(
        pair.kinds(),
        (Some(PathKind::Relayed), Some(PathKind::Relayed)),
        "the library alone does not punch again within the bound"
    );
    assert_eq!(
        pair.asker.adapter.redials() + pair.server.adapter.redials(),
        0
    );

    pair.relay.shutdown().await.expect("the relay stops");
}

/// Peers of the hub in the mass fallback test: half dialed by the hub, half
/// dialing it.
const STAR_PEERS: u32 = 12;

/// The hub's budget in the mass fallback test, small enough that its
/// peers' schedules ask for several times more.
const HUB_BUDGET: RedialBudget = RedialBudget {
    burst: 2,
    refill: Duration::from_secs(2),
};

/// How long the mass fallback is watched once every peer is relayed.
const FALLBACK_WATCH: Duration = Duration::from_secs(16);

#[tokio::test(flavor = "multi_thread")]
async fn a_host_whose_every_connection_falls_back_keeps_to_its_re_dial_budget() {
    let hub_key = TestFixtures::new(34, STAR_PEERS + 1)
        .network_key(0)
        .public();
    let star = Star::bind(34, STAR_PEERS, STAR_PEERS / 2, Duration::ZERO, |config| {
        config.path_idle_timeout = PATH_IDLE_TIMEOUT;
        config.path_keep_alive = PATH_KEEP_ALIVE;
        if config.secret_key.public() == hub_key {
            config.redial_budget = HUB_BUDGET;
        }
    })
    .await;
    let peers = STAR_PEERS as usize;
    wait_for("every peer reaches a direct path", || {
        star.on(PathKind::Direct) == peers
    })
    .await;

    // The hub's UDP fails; every connection falls back at once.
    star.set_open(false);
    wait_for("every peer is relayed", || {
        star.on(PathKind::Relayed) == peers
    })
    .await;

    // The hub re-dials the peers it dialed and is re-dialed by the others;
    // both come out of its budget.
    let spent = |star: &Star| {
        let asked: u64 = star.peers.iter().map(|peer| peer.redials()).sum();
        star.hub.redials() + asked - star.hub.redials_refused()
    };
    let (spent_before, refused_before) = (spent(&star), star.hub.redials_refused());
    let start = Instant::now();
    sleep(FALLBACK_WATCH).await;
    let elapsed = start.elapsed();
    let spent = spent(&star) - spent_before;
    let refused = star.hub.redials_refused() - refused_before;

    let earned = elapsed.as_millis() / HUB_BUDGET.refill.as_millis() + 1;
    let allowed = u64::from(HUB_BUDGET.burst) + u64::try_from(earned).unwrap();
    assert!(
        spent <= allowed,
        "the hub spent {spent} re-dials in {elapsed:?}, more than its budget's {allowed}"
    );
    assert!(spent >= 1, "the budget still lets re-dials through");
    assert!(
        refused >= 1,
        "the peers asked for more than the budget, and the excess was refused"
    );

    star.shutdown().await.expect("the relay stops");
}
