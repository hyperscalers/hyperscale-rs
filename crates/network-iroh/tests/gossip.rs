//! Gossip fan-out between hosts over real loopback QUIC.

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use hyperscale_crypto_bls::BlsVerifier;
use hyperscale_hbor::Hbor;
use hyperscale_network::fault::HostId;
use hyperscale_network::{GossipVerdict, HandlerRegistry, Network};
use hyperscale_network_iroh::test_utils::TestFixtures;
use hyperscale_network_iroh::testing::CountingVerifier;
use hyperscale_network_iroh::{
    IrohAdapter, IrohAdapterArgs, IrohConfig, IrohNetwork, RequestManager, RequestManagerConfig,
    RequestPool, RequestStreams,
};
use hyperscale_types::network::gossip::ValidatorAddressGossip;
use hyperscale_types::{
    GossipMessage, MessageClass, NetworkDefinition, NetworkMessage, RoutingCommittees, ShardId,
    TopicScope, TopologySnapshot, ValidatorAddressMessage, ValidatorId, Verifier, signed_bytes,
};
use iroh::EndpointAddr;
use tokio::runtime::Handle;
use tokio::sync::mpsc;
use tokio::time::{interval, sleep, timeout};

/// Budget for hosts to find and bind each other and for an item to arrive.
const BUDGET: Duration = Duration::from_secs(20);

/// How long something that must not arrive is watched for.
const SILENCE_WATCH: Duration = Duration::from_millis(500);

/// Validators seated in the root committee, one per host.
const SEATED: u32 = 3;

/// A committed beacon block, as far as the transport is concerned: a
/// global item that names no source shard.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
struct BeaconBlock(u64);

impl NetworkMessage for BeaconBlock {
    fn message_type_id() -> &'static str {
        "beacon.block"
    }

    fn class() -> MessageClass {
        MessageClass::CrossShardProgress
    }
}

impl GossipMessage for BeaconBlock {
    const SCOPE: TopicScope = TopicScope::Global;
}

/// A committed block header, as far as the transport is concerned: a
/// global item of a few KiB.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
struct CommittedHeader {
    seq: u64,
    body: Vec<u8>,
}

impl NetworkMessage for CommittedHeader {
    fn message_type_id() -> &'static str {
        "block.committed"
    }

    fn class() -> MessageClass {
        MessageClass::CrossShardProgress
    }
}

impl GossipMessage for CommittedHeader {
    const SCOPE: TopicScope = TopicScope::Global;
}

/// Forged address records whose checks fit in a peer's allowance of
/// refused work, and the one that takes it past.
const FORGERIES_IN_ALLOWANCE: u64 = 26;

/// Items of one peer a host judges at once.
const JUDGED_AT_ONCE: u64 = 4;

/// Size of a committed header stand-in.
const HEADER_BYTES: usize = 2048;

/// Headers a second an honest, busy peer sends a host that refuses them
/// all: more than one peer hands any host in a cluster of this size.
const HONEST_RATE: u32 = 300;

/// How long the honest peer keeps sending.
const HONEST_WATCH_SECS: u32 = 15;

/// A batch of transactions, as far as the transport is concerned: an item
/// for one shard.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
struct Transactions(u64);

impl NetworkMessage for Transactions {
    fn message_type_id() -> &'static str {
        "transaction.gossip"
    }

    fn class() -> MessageClass {
        MessageClass::Bulk
    }
}

impl GossipMessage for Transactions {
    const SCOPE: TopicScope = TopicScope::Shard;
}

fn vid(index: u32) -> ValidatorId {
    ValidatorId::new(u64::from(index))
}

struct Host {
    adapter: Arc<IrohAdapter>,
    network: Arc<IrohNetwork>,
}

/// Stand up the host carrying validator `index`, serving `shards`.
async fn host(
    fixtures: &TestFixtures,
    index: u32,
    shards: &[ShardId],
    bootstrap: Vec<EndpointAddr>,
) -> Host {
    host_checking_with(fixtures, index, shards, bootstrap, Arc::new(BlsVerifier)).await
}

/// [`host`], checking signatures with `verifier`.
async fn host_checking_with(
    fixtures: &TestFixtures,
    index: u32,
    shards: &[ShardId],
    bootstrap: Vec<EndpointAddr>,
    verifier: Arc<dyn Verifier>,
) -> Host {
    let bind_addr: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let mut config = IrohConfig::for_testing(fixtures.network_key(index), bind_addr);
    config.bootstrap_peers = bootstrap;
    let registry = Arc::new(HandlerRegistry::new(shards.iter().copied().collect()));
    let adapter = IrohAdapter::bind(IrohAdapterArgs {
        config,
        network: NetworkDefinition::simulator(),
        vnodes: vec![(vid(index), fixtures.signer(index))],
        local_shards: shards.iter().copied().collect::<HashSet<_>>(),
        registry: Arc::clone(&registry),
        validator_keys: fixtures.validator_key_map(),
        verifier,
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

/// Three hosts seated in the root committee and one that serves no shard.
/// Every host but the first knows only the first.
async fn cluster(fixtures: &TestFixtures) -> Vec<Host> {
    let first = host(fixtures, 0, &[ShardId::ROOT], Vec::new()).await;
    let bootstrap = vec![first.adapter.endpoint_addr()];
    let mut hosts = vec![first];
    for index in 1..SEATED {
        hosts.push(host(fixtures, index, &[ShardId::ROOT], bootstrap.clone()).await);
    }
    hosts.push(host(fixtures, SEATED, &[], bootstrap).await);
    hosts
}

async fn wait_for(what: &str, mut check: impl FnMut() -> bool) {
    timeout(BUDGET, async {
        while !check() {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{what}"));
}

/// Wait until every seated host is bound to every other seated host.
async fn seated_mesh(hosts: &[Host]) {
    wait_for("the committee binds to itself from signed records", || {
        hosts[..SEATED as usize]
            .iter()
            .enumerate()
            .all(|(i, host)| {
                (0..SEATED)
                    .filter(|j| *j as usize != i)
                    .all(|j| host.adapter.peer_for_validator(vid(j)).is_some())
            })
    })
    .await;
}

/// A receiver whose signature checks are counted, serving `shards`, and a
/// sender bound to it whose own address record the receiver already holds.
async fn counted_pair(
    fixtures: &TestFixtures,
    shards: &[ShardId],
) -> (Host, Arc<CountingVerifier>, Host) {
    let counted = Arc::new(CountingVerifier::default());
    let receiver = host_checking_with(
        fixtures,
        0,
        shards,
        Vec::new(),
        Arc::clone(&counted) as Arc<dyn Verifier>,
    )
    .await;
    let sender = host(
        fixtures,
        1,
        &[ShardId::ROOT],
        vec![receiver.adapter.endpoint_addr()],
    )
    .await;
    wait_for(
        "the pair binds and the receiver holds the sender's record",
        || {
            receiver.adapter.peer_for_validator(vid(1)).is_some()
                && sender.adapter.peer_for_validator(vid(0)).is_some()
                && !receiver.adapter.address_book().is_empty()
        },
    )
    .await;
    (receiver, counted, sender)
}

/// `host`'s own address record at `sequence`: signed when `forged` is
/// false, carrying a signature over other bytes when it is true.
fn address_record(
    fixtures: &TestFixtures,
    index: u32,
    host: &Host,
    sequence: u64,
    forged: bool,
) -> ValidatorAddressGossip {
    let own = host.adapter.address_records().remove(0);
    let message = if forged {
        b"not this record".to_vec()
    } else {
        signed_bytes(
            &ValidatorAddressMessage::new(&own.peer_id, &own.addresses, sequence),
            &NetworkDefinition::simulator(),
        )
    };
    ValidatorAddressGossip {
        sequence,
        signature: fixtures.signer(index).sign(&message).expect("signs"),
        ..own
    }
}

/// Wait until `counted` has seen no new signature check for a while.
async fn checks_settle(counted: &CountingVerifier) -> u64 {
    loop {
        let before = counted.checked();
        sleep(SILENCE_WATCH).await;
        if counted.checked() == before {
            return before;
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_forged_address_record_is_checked_once() {
    let fixtures = TestFixtures::new(21, 2);
    let (_receiver, counted, sender) = counted_pair(&fixtures, &[ShardId::ROOT]).await;
    let settled = checks_settle(&counted).await;
    let refused = counted.refused();

    for sequence in 0..4 {
        sender.network.broadcast_global(&address_record(
            &fixtures,
            1,
            &sender,
            1_000 + sequence,
            true,
        ));
    }
    wait_for("the forged records are checked", || {
        counted.refused() >= refused + 4
    })
    .await;
    assert_eq!(
        checks_settle(&counted).await - settled,
        4,
        "a host serving a shard checks each record once"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_host_that_serves_no_shard_refuses_forged_address_records() {
    let fixtures = TestFixtures::new(21, 2);
    let (_receiver, counted, sender) = counted_pair(&fixtures, &[]).await;
    checks_settle(&counted).await;
    let refused = counted.refused();

    // A refusal is a verdict against the sender, so a flood of forged
    // records cools it down before the receiver has checked them all.
    let sent = 400;
    for sequence in 0..sent {
        sender.network.broadcast_global(&address_record(
            &fixtures,
            1,
            &sender,
            1_000 + sequence,
            true,
        ));
        sleep(Duration::from_millis(5)).await;
    }
    checks_settle(&counted).await;
    let checked = counted.refused() - refused;
    assert!(checked > 0, "the forged records reach the receiver");
    assert!(
        checked < sent / 2,
        "the sender is cooled down: {checked} of {sent} checked"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_host_that_serves_no_shard_receives_a_beacon_block() {
    let fixtures = TestFixtures::with_surplus(21, SEATED, 1);
    let hosts = cluster(&fixtures).await;
    seated_mesh(&hosts).await;
    let follower = &hosts[SEATED as usize];

    let (tx, mut rx) = mpsc::unbounded_channel();
    follower
        .network
        .register_host_gossip_handler(move |block: BeaconBlock| {
            let _ = tx.send(block);
        });
    // The shard-less host has no per-shard handler to accept the item, so
    // one that accepts keeps the type known to its registry.
    follower
        .network
        .register_gossip_handler(|_: BeaconBlock, _: ShardId| GossipVerdict::Accept);
    for seated in &hosts[..SEATED as usize] {
        seated
            .network
            .register_gossip_handler(|_: BeaconBlock, _: ShardId| GossipVerdict::Accept);
    }

    // The follower learned the committee from the host it bootstrapped to.
    wait_for("the follower's book fills from its bootstrap peer", || {
        follower.adapter.address_book().len() >= SEATED as usize
    })
    .await;

    // A seated host the follower never dialed publishes.
    hosts[1].network.broadcast_global(&BeaconBlock(42));

    let block = timeout(BUDGET, rx.recv())
        .await
        .expect("the follower receives the block");
    assert_eq!(block, Some(BeaconBlock(42)));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_shard_item_reaches_its_committee_and_nobody_else() {
    let fixtures = TestFixtures::with_surplus(21, SEATED, 1);
    let hosts = cluster(&fixtures).await;
    seated_mesh(&hosts).await;

    let mut receivers = Vec::new();
    for host in &hosts {
        let (tx, rx) = mpsc::unbounded_channel();
        host.network
            .register_gossip_handler(move |item: Transactions, shard: ShardId| {
                let _ = tx.send((item, shard));
                GossipVerdict::Accept
            });
        receivers.push(rx);
    }

    hosts[0]
        .network
        .broadcast_to_shard(ShardId::ROOT, &Transactions(9));

    for (index, rx) in receivers.iter_mut().enumerate().take(SEATED as usize) {
        let delivered = timeout(BUDGET, rx.recv())
            .await
            .unwrap_or_else(|_| panic!("host {index} receives the shard item"));
        assert_eq!(delivered, Some((Transactions(9), ShardId::ROOT)));
    }
    assert!(
        timeout(SILENCE_WATCH, receivers[SEATED as usize].recv())
            .await
            .is_err(),
        "a host outside the committee is sent nothing"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_global_item_is_handled_once_however_many_copies_arrive() {
    let fixtures = TestFixtures::with_surplus(21, SEATED, 1);
    let hosts = cluster(&fixtures).await;
    seated_mesh(&hosts).await;

    let mut handled = Vec::new();
    for host in &hosts[..SEATED as usize] {
        let count = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&count);
        host.network
            .register_gossip_handler(move |_: BeaconBlock, _: ShardId| {
                counted.fetch_add(1, Ordering::SeqCst);
                GossipVerdict::Accept
            });
        handled.push(count);
    }

    // Every seated host gets the item from its publisher and again from
    // each host that forwards it.
    hosts[1].network.broadcast_global(&BeaconBlock(5));

    wait_for("the other seated hosts handle the item", || {
        handled[0].load(Ordering::SeqCst) == 1 && handled[2].load(Ordering::SeqCst) == 1
    })
    .await;
    sleep(SILENCE_WATCH).await;
    let counts: Vec<usize> = handled.iter().map(|c| c.load(Ordering::SeqCst)).collect();
    assert_eq!(
        counts,
        vec![1, 1, 1],
        "each host handles the item once, the publisher through its own registry"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_peer_slipping_signed_records_between_forged_ones_is_cooled_down() {
    let fixtures = TestFixtures::new(21, 2);
    let (_receiver, counted, sender) = counted_pair(&fixtures, &[ShardId::ROOT]).await;
    checks_settle(&counted).await;
    let refused = counted.refused();

    // Seven forged records, then one the sender signed, which the receiver
    // accepts: accepting it buys none of the forged ones back.
    let start = Instant::now();
    let mut forged = 0;
    for sequence in 1..=800 {
        let is_forged = sequence % 8 != 0;
        forged += u64::from(is_forged);
        sender.network.broadcast_global(&address_record(
            &fixtures,
            1,
            &sender,
            1_000 + sequence,
            is_forged,
        ));
        sleep(Duration::from_millis(2)).await;
    }
    checks_settle(&counted).await;
    let checked = counted.refused() - refused;
    // What the receiver's budget admits over the time the flood ran: its
    // first allowance, the items judged when the cooldown began, then five
    // checks a second paid down by time and the items judged at each lapse.
    let secs = start.elapsed().as_secs() + 1;
    let admitted = FORGERIES_IN_ALLOWANCE + JUDGED_AT_ONCE + secs * (5 + JUDGED_AT_ONCE);
    assert!(
        checked <= admitted,
        "the sender is cooled down: {checked} of {forged} forged records checked in {secs} s"
    );

    // The cooldown lapses and the sender is heard again.
    let mut sequence = 10_000;
    let heard = counted.checked();
    wait_for("the sender is heard again after its cooldown", || {
        sequence += 1;
        sender
            .network
            .broadcast_global(&address_record(&fixtures, 1, &sender, sequence, false));
        counted.checked() > heard
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_host_that_is_behind_still_hears_a_peer_whose_items_it_refuses() {
    let fixtures = TestFixtures::new(21, 2);
    let (receiver, _counted, sender) = counted_pair(&fixtures, &[ShardId::ROOT]).await;

    // The receiver cannot place any header yet and refuses each one, as a
    // host behind the chain refuses headers signed under a committee it
    // has not learned. The sender is honest and busy.
    let handled = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&handled);
    receiver
        .network
        .register_gossip_handler(move |_: CommittedHeader, _: ShardId| {
            counted.fetch_add(1, Ordering::SeqCst);
            GossipVerdict::Reject
        });

    let sent = HONEST_RATE * HONEST_WATCH_SECS;
    let mut tick = interval(Duration::from_secs(1) / HONEST_RATE);
    for seq in 0..sent {
        tick.tick().await;
        sender.network.broadcast_global(&CommittedHeader {
            seq: u64::from(seq),
            body: vec![7; HEADER_BYTES],
        });
    }
    wait_for("every refused header is still read", || {
        handled.load(Ordering::SeqCst) == sent as usize
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn gossip_does_not_cross_a_partition() {
    let fixtures = TestFixtures::new(21, 2);
    let first = host(&fixtures, 0, &[ShardId::ROOT], Vec::new()).await;
    let second = host(
        &fixtures,
        1,
        &[ShardId::ROOT],
        vec![first.adapter.endpoint_addr()],
    )
    .await;
    wait_for("the pair binds", || {
        first.adapter.peer_for_validator(vid(1)).is_some()
            && second.adapter.peer_for_validator(vid(0)).is_some()
    })
    .await;

    let (tx, mut rx) = mpsc::unbounded_channel();
    second
        .network
        .register_gossip_handler(move |block: BeaconBlock, _: ShardId| {
            let _ = tx.send(block);
            GossipVerdict::Accept
        });

    // The gate sits at the receiver: it refuses what the far side sends.
    second
        .adapter
        .fault_configure(HostId(1), [(first.adapter.local_endpoint_id(), HostId(0))]);
    second.adapter.fault_gate().block_host(HostId(0));
    first.network.broadcast_global(&BeaconBlock(1));
    assert!(timeout(SILENCE_WATCH, rx.recv()).await.is_err());

    second.adapter.fault_gate().heal();
    first.network.broadcast_global(&BeaconBlock(2));
    let delivered = timeout(BUDGET, rx.recv()).await.expect("delivered");
    assert_eq!(delivered, Some(BeaconBlock(2)));
}
