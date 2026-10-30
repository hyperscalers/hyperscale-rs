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
use hyperscale_network::{HandlerRegistry, Network, ValidatorKeyMap, Verdict, VerdictKey};
use hyperscale_network_iroh::test_utils::TestFixtures;
use hyperscale_network_iroh::testing::CountingVerifier;
use hyperscale_network_iroh::{
    AddVnodeError, IrohAdapter, IrohAdapterArgs, IrohConfig, IrohNetwork, RequestManager,
    RequestManagerConfig, RequestPool, RequestStreams,
};
use hyperscale_types::network::gossip::ValidatorAddressGossip;
use hyperscale_types::{
    GossipMessage, GossipScope, MessageClass, NetworkDefinition, NetworkMessage, RoutingCommittees,
    ShardId, TopologySnapshot, ValidatorAddressMessage, ValidatorId, Verifier, signed_bytes,
};
use iroh::{EndpointAddr, SecretKey};
use tokio::runtime::Handle;
use tokio::spawn;
use tokio::sync::mpsc;
use tokio::time::{interval, sleep, timeout};

/// Budget for hosts to find and bind each other and for an item to arrive.
const BUDGET: Duration = Duration::from_secs(20);

/// How long something that must not arrive is watched for.
const SILENCE_WATCH: Duration = Duration::from_millis(500);

/// Validators seated in the root committee, one per host.
const SEATED: u32 = 3;

/// Validators the topology knows in the address record tests: two hosts,
/// and the rest named by forged records, each a validator whose turn at
/// having a record checked has not been taken.
const KNOWN: u32 = 64;

/// Least time between two checks of one validator's records.
const RECORD_INTERVAL: Duration = Duration::from_secs(5);

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
    const SCOPE: GossipScope = GossipScope::Global;
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
    const SCOPE: GossipScope = GossipScope::Global;
}

/// One copy of some content several senders publish, as committee members
/// each publish a committed header under their own signature: the content
/// key covers `seq` alone.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
struct Copy {
    seq: u64,
    sender: u32,
    forged: bool,
}

impl NetworkMessage for Copy {
    fn message_type_id() -> &'static str {
        "test.copy"
    }

    fn class() -> MessageClass {
        MessageClass::CrossShardProgress
    }
}

impl GossipMessage for Copy {
    const SCOPE: GossipScope = GossipScope::Global;

    fn dedup_key(&self) -> Option<u64> {
        Some(self.seq)
    }
}

/// A vote, as far as the transport is concerned: a small notification.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
struct Vote(u64);

impl NetworkMessage for Vote {
    fn message_type_id() -> &'static str {
        "block.vote"
    }

    fn class() -> MessageClass {
        MessageClass::Consensus
    }
}

/// Votes a cooled down peer sends while it is watched.
const VOTES_WHILE_COOLING: u64 = 10;

/// How long a cooled down peer's votes are watched for.
const VOTE_WATCH: Duration = Duration::from_millis(200);

/// Cooldowns a watch may try, should one lapse before its watch ends.
const COOLDOWNS_WATCHED: usize = 5;

/// Items that are their sender's fault, such as forged address records,
/// whose charges fit in a peer's allowance of refused work, and the one
/// that takes it past.
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

/// Size of a header a host with no room refuses: at [`HONEST_RATE`], the
/// work of reading such headers outruns what time pays down.
const BUSY_HEADER_BYTES: usize = 128 * 1024;

/// How long the peer keeps sending a host with no room.
const BUSY_WATCH_SECS: u32 = 6;

/// Items a validator sends from each endpoint it binds as.
const ROTATION_FLOOD: u64 = 200;

/// How long a validator signs records without pause.
const FLOOD_WATCH: Duration = Duration::from_secs(6);

/// How long a peer whose headers are its own fault keeps sending.
const REJECTED_WATCH_SECS: u32 = 5;

/// How long a deferred check takes, as long as the shard loop's batch
/// window holds a committed header.
const CHECK_DELAY: Duration = Duration::from_millis(15);

/// Items of one peer a host waits on deferred verdicts for at once.
const DEFERRED_AT_ONCE: u64 = 64;

/// Time a follower takes to subscribe to the hosts it is bound to.
const SUBSCRIBE_WAIT: Duration = Duration::from_secs(6);

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
    const SCOPE: GossipScope = GossipScope::Shard;
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
    host_keyed(
        fixtures,
        index,
        fixtures.network_key(index),
        shards,
        bootstrap,
        verifier,
    )
    .await
}

/// [`host_checking_with`], binding as the endpoint `key` names.
async fn host_keyed(
    fixtures: &TestFixtures,
    index: u32,
    key: SecretKey,
    shards: &[ShardId],
    bootstrap: Vec<EndpointAddr>,
    verifier: Arc<dyn Verifier>,
) -> Host {
    let bind_addr: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let mut config = IrohConfig::for_testing(key, bind_addr);
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

/// `host`'s own address record, `sequence` past the one it signed itself:
/// signed when `forged` is false, carrying a signature over other bytes
/// when it is true.
fn address_record(
    fixtures: &TestFixtures,
    index: u32,
    host: &Host,
    sequence: u64,
    forged: bool,
) -> ValidatorAddressGossip {
    address_record_naming(fixtures, index, host, vid(index), sequence, forged)
}

/// [`address_record`], naming `validator` as the record's own.
fn address_record_naming(
    fixtures: &TestFixtures,
    index: u32,
    host: &Host,
    validator: ValidatorId,
    sequence: u64,
    forged: bool,
) -> ValidatorAddressGossip {
    let own = host.adapter.address_records().remove(0);
    let sequence = own.sequence + sequence;
    let message = if forged {
        b"not this record".to_vec()
    } else {
        signed_bytes(
            &ValidatorAddressMessage::new(&own.endpoint_id, &own.addresses, sequence),
            &NetworkDefinition::simulator(),
        )
    };
    ValidatorAddressGossip {
        validator,
        sequence,
        signature: fixtures.signer(index).sign(&message).expect("signs"),
        ..own
    }
}

/// The validator a forged record in a flood names: one of those no host
/// carries, in turn.
fn forged_validator(sequence: u64) -> ValidatorId {
    ValidatorId::new(2 + sequence % u64::from(KNOWN - 2))
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
    let fixtures = TestFixtures::new(21, KNOWN);
    let (_receiver, counted, sender) = counted_pair(&fixtures, &[ShardId::ROOT]).await;
    let settled = checks_settle(&counted).await;
    let refused = counted.refused();

    for sequence in 0..4 {
        sender.network.broadcast_global(&address_record_naming(
            &fixtures,
            1,
            &sender,
            forged_validator(sequence),
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
    let fixtures = TestFixtures::new(21, KNOWN);
    let (_receiver, counted, sender) = counted_pair(&fixtures, &[]).await;
    checks_settle(&counted).await;
    let refused = counted.refused();

    // A refusal is a verdict against the sender, so a flood of forged
    // records cools it down before the receiver has checked them all.
    let sent = 400;
    for sequence in 0..sent {
        sender.network.broadcast_global(&address_record_naming(
            &fixtures,
            1,
            &sender,
            forged_validator(sequence),
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
        .register_gossip_handler(|_: BeaconBlock, _: ShardId| Verdict::Accept);
    for seated in &hosts[..SEATED as usize] {
        seated
            .network
            .register_gossip_handler(|_: BeaconBlock, _: ShardId| Verdict::Accept);
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
                Verdict::Accept
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
                Verdict::Accept
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
    let fixtures = TestFixtures::new(21, KNOWN);
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
        let validator = if is_forged {
            forged_validator(sequence)
        } else {
            vid(1)
        };
        sender.network.broadcast_global(&address_record_naming(
            &fixtures,
            1,
            &sender,
            validator,
            1_000 + sequence,
            is_forged,
        ));
        sleep(Duration::from_millis(2)).await;
    }
    // Records held for their validators' turns are checked when those come.
    sleep(RECORD_INTERVAL).await;
    checks_settle(&counted).await;
    let checked = counted.refused() - refused;
    // What the receiver's budget admits over the time the flood ran: its
    // first allowance, the items judged when the cooldown began, then five
    // checks a second paid down by time and the items judged at each lapse,
    // and at most one held record of each validator named.
    let secs = start.elapsed().as_secs() + 1;
    let admitted = FORGERIES_IN_ALLOWANCE
        + JUDGED_AT_ONCE
        + secs * (5 + JUDGED_AT_ONCE)
        + u64::from(KNOWN - 2);
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
async fn a_validator_signing_records_without_pause_is_checked_once_an_interval() {
    let fixtures = TestFixtures::with_surplus(21, 2, 1);
    let (receiver, counted, sender) = counted_pair(&fixtures, &[ShardId::ROOT]).await;
    // A third host, bound to the receiver, counts what reaches it.
    let onward_counted = Arc::new(CountingVerifier::default());
    let onward = host_checking_with(
        &fixtures,
        2,
        &[ShardId::ROOT],
        vec![receiver.adapter.endpoint_addr()],
        Arc::clone(&onward_counted) as Arc<dyn Verifier>,
    )
    .await;
    wait_for("the third host binds", || {
        onward.adapter.peer_for_validator(vid(0)).is_some()
    })
    .await;
    let settled = checks_settle(&counted).await;
    let onward_settled = checks_settle(&onward_counted).await;

    // The sender's own validator signs a newer record every 5 ms.
    let start = Instant::now();
    let mut sent = 0;
    let mut latest = 0;
    while start.elapsed() < FLOOD_WATCH {
        sent += 1;
        let record = address_record(&fixtures, 1, &sender, sent, false);
        latest = record.sequence;
        sender.network.broadcast_global(&record);
        sleep(Duration::from_millis(5)).await;
    }
    // The last record held is checked when its turn comes.
    wait_for("the newest record is taken within an interval", || {
        receiver
            .adapter
            .address_book()
            .sequence(vid(1))
            .is_some_and(|held| held == latest)
    })
    .await;
    let secs = start.elapsed().as_secs() + 1;
    let turns = 1 + secs / RECORD_INTERVAL.as_secs() + 1;
    let checked = checks_settle(&counted).await - settled;
    let onward_checked = checks_settle(&onward_counted).await - onward_settled;
    assert!(
        checked <= turns,
        "the receiver checked {checked} of {sent} records in {secs} s"
    );
    assert!(
        onward_checked <= turns,
        "the next host checked {onward_checked} of {sent} records in {secs} s"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_host_that_is_behind_still_hears_a_peer_whose_items_it_refuses() {
    let fixtures = TestFixtures::new(21, 2);
    let (receiver, _counted, sender) = counted_pair(&fixtures, &[ShardId::ROOT]).await;

    // The receiver cannot place any header yet and ignores each one, as a
    // host behind the chain ignores headers signed under a committee it
    // has not learned. The sender is honest and busy.
    let handled = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&handled);
    receiver
        .network
        .register_gossip_handler(move |_: CommittedHeader, _: ShardId| {
            counted.fetch_add(1, Ordering::SeqCst);
            Verdict::Ignore
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
async fn a_host_with_no_room_does_not_cool_down_a_peer_whose_items_it_refuses() {
    let fixtures = TestFixtures::new(21, 2);
    let (receiver, _counted, sender) = counted_pair(&fixtures, &[ShardId::ROOT]).await;

    // The receiver's queues are full and it refuses every header for want
    // of room. The headers are large enough that reading each one, were
    // it charged, would cost the sender more than time pays down.
    let handled = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&handled);
    receiver
        .network
        .register_gossip_handler(move |_: CommittedHeader, _: ShardId| {
            counted.fetch_add(1, Ordering::SeqCst);
            Verdict::Busy
        });

    let sent = HONEST_RATE * BUSY_WATCH_SECS;
    let mut tick = interval(Duration::from_secs(1) / HONEST_RATE);
    for seq in 0..sent {
        tick.tick().await;
        sender.network.broadcast_global(&CommittedHeader {
            seq: u64::from(seq),
            body: vec![7; BUSY_HEADER_BYTES],
        });
    }
    wait_for("every refused header is still read", || {
        handled.load(Ordering::SeqCst) == sent as usize
    })
    .await;
    assert!(
        !receiver.adapter.cooling_down(vid(1)),
        "refusing for want of room costs the sender nothing"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_peer_whose_items_are_rejected_is_cooled_down() {
    let fixtures = TestFixtures::new(21, 2);
    let (receiver, _counted, sender) = counted_pair(&fixtures, &[ShardId::ROOT]).await;

    // The same flood as an honest peer's to a host that is behind, but every
    // header is the sender's fault: each costs it a signature check's worth.
    let handled = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&handled);
    receiver
        .network
        .register_gossip_handler(move |_: CommittedHeader, _: ShardId| {
            counted.fetch_add(1, Ordering::SeqCst);
            Verdict::Reject
        });

    let start = Instant::now();
    let sent = HONEST_RATE * REJECTED_WATCH_SECS;
    let mut tick = interval(Duration::from_secs(1) / HONEST_RATE);
    for seq in 0..sent {
        tick.tick().await;
        sender.network.broadcast_global(&CommittedHeader {
            seq: u64::from(seq),
            body: vec![7; HEADER_BYTES],
        });
    }
    sleep(SILENCE_WATCH).await;
    let judged = handled.load(Ordering::SeqCst) as u64;
    let secs = start.elapsed().as_secs() + 1;
    let admitted = FORGERIES_IN_ALLOWANCE + JUDGED_AT_ONCE + secs * (5 + JUDGED_AT_ONCE);
    assert!(judged > 0, "the headers reach the receiver");
    assert!(
        judged <= admitted,
        "the sender is cooled down: {judged} of {sent} headers judged in {secs} s"
    );
}

/// A host that relays a sender's global items onward to a follower that
/// hears nothing else: the follower refuses whatever the sender sends it.
async fn relay_line(fixtures: &TestFixtures) -> (Host, Host, Host) {
    let relay = host(fixtures, 0, &[ShardId::ROOT], Vec::new()).await;
    let sender = host(
        fixtures,
        1,
        &[ShardId::ROOT],
        vec![relay.adapter.endpoint_addr()],
    )
    .await;
    let follower = host(fixtures, 2, &[], vec![relay.adapter.endpoint_addr()]).await;
    wait_for("the line binds", || {
        relay.adapter.peer_for_validator(vid(1)).is_some()
            && relay.adapter.peer_for_validator(vid(2)).is_some()
    })
    .await;
    follower.adapter.fault_configure(
        HostId(2),
        [
            (relay.adapter.local_endpoint_id(), HostId(0)),
            (sender.adapter.local_endpoint_id(), HostId(1)),
        ],
    );
    follower.adapter.fault_gate().block_host(HostId(1));
    // The follower subscribes to the hosts it is bound to.
    sleep(SUBSCRIBE_WAIT).await;
    (relay, sender, follower)
}

#[tokio::test(flavor = "multi_thread")]
async fn an_item_travels_on_only_once_its_deferred_check_holds_up() {
    let fixtures = TestFixtures::with_surplus(21, 1, 2);
    let (relay, sender, follower) = relay_line(&fixtures).await;

    let (keys_tx, mut keys) = mpsc::unbounded_channel();
    relay
        .network
        .register_gossip_handler(move |block: BeaconBlock, _: ShardId| {
            let key = VerdictKey::of(&block);
            let _ = keys_tx.send(key);
            Verdict::defer(key)
        });
    let (tx, mut rx) = mpsc::unbounded_channel();
    follower
        .network
        .register_host_gossip_handler(move |block: BeaconBlock| {
            let _ = tx.send(block);
        });
    follower
        .network
        .register_gossip_handler(|_: BeaconBlock, _: ShardId| Verdict::Accept);

    sender.network.broadcast_global(&BeaconBlock(7));
    let key = timeout(BUDGET, keys.recv())
        .await
        .expect("the relay judges the item")
        .expect("a key");
    assert!(
        timeout(SILENCE_WATCH, rx.recv()).await.is_err(),
        "nothing travels on while the check runs"
    );
    relay.network.settle(key, Verdict::Accept);
    let delivered = timeout(BUDGET, rx.recv()).await.expect("delivered");
    assert_eq!(delivered, Some(BeaconBlock(7)));

    // One whose check fails stops at the relay.
    sender.network.broadcast_global(&BeaconBlock(8));
    let key = timeout(BUDGET, keys.recv())
        .await
        .expect("the relay judges the item")
        .expect("a key");
    relay.network.settle(key, Verdict::Reject);
    assert!(timeout(SILENCE_WATCH, rx.recv()).await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_peer_whose_items_fail_their_deferred_check_is_cooled_down() {
    let fixtures = TestFixtures::new(21, 2);
    let (receiver, _counted, sender) = counted_pair(&fixtures, &[ShardId::ROOT]).await;

    // Every header is checked off the handler, as the shard loop checks a
    // committed header's sender signature, and every check fails.
    let checked = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&checked);
    let network = Arc::clone(&receiver.network);
    let handle = Handle::current();
    receiver
        .network
        .register_gossip_handler(move |header: CommittedHeader, _: ShardId| {
            let key = VerdictKey::of(&header);
            let (counted, network) = (Arc::clone(&counted), Arc::clone(&network));
            handle.spawn(async move {
                sleep(CHECK_DELAY).await;
                counted.fetch_add(1, Ordering::SeqCst);
                network.settle(key, Verdict::Reject);
            });
            Verdict::defer(key)
        });

    let start = Instant::now();
    let sent = HONEST_RATE * REJECTED_WATCH_SECS;
    let mut tick = interval(Duration::from_secs(1) / HONEST_RATE);
    for seq in 0..sent {
        tick.tick().await;
        sender.network.broadcast_global(&CommittedHeader {
            seq: u64::from(seq),
            body: vec![7; HEADER_BYTES],
        });
    }
    sleep(SILENCE_WATCH).await;
    let judged = checked.load(Ordering::SeqCst) as u64;
    let secs = start.elapsed().as_secs() + 1;
    // As for rejections at once, plus what was already waiting on its check
    // when the cooldown began.
    let admitted = FORGERIES_IN_ALLOWANCE + DEFERRED_AT_ONCE + secs * (5 + DEFERRED_AT_ONCE);
    assert!(judged > 0, "the headers reach the receiver");
    assert!(
        judged <= admitted,
        "the sender is cooled down: {judged} of {sent} headers checked in {secs} s"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_validator_binding_again_under_a_new_endpoint_is_still_cooled_down() {
    let fixtures = TestFixtures::new(21, 2);
    let (receiver, _counted, sender) = counted_pair(&fixtures, &[ShardId::ROOT]).await;
    let handled = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&handled);
    receiver
        .network
        .register_gossip_handler(move |_: CommittedHeader, _: ShardId| {
            counted.fetch_add(1, Ordering::SeqCst);
            Verdict::Reject
        });
    let flood = |host: &Host, from: u64| {
        for seq in from..from + ROTATION_FLOOD {
            host.network.broadcast_global(&CommittedHeader {
                seq,
                body: vec![7; HEADER_BYTES],
            });
        }
    };

    // The sender runs past its allowance and is cooled down: the receiver
    // stops judging its items long before the last.
    let start = Instant::now();
    flood(&sender, 0);
    let before = loop {
        let judged = handled.load(Ordering::SeqCst);
        sleep(SILENCE_WATCH).await;
        if judged > 0 && handled.load(Ordering::SeqCst) == judged {
            break judged as u64;
        }
    };
    assert!(
        before < ROTATION_FLOOD,
        "the sender is cooled down: {before} of {ROTATION_FLOOD} judged"
    );

    // The same validator binds again under an endpoint it just made.
    let again = host_keyed(
        &fixtures,
        1,
        SecretKey::generate(),
        &[ShardId::ROOT],
        vec![receiver.adapter.endpoint_addr()],
        Arc::new(BlsVerifier),
    )
    .await;
    wait_for("the new endpoint binds", || {
        receiver.adapter.peer_for_validator(vid(1)) == Some(again.adapter.local_endpoint_id())
    })
    .await;
    flood(&again, ROTATION_FLOOD);
    sleep(SILENCE_WATCH).await;
    let judged = handled.load(Ordering::SeqCst) as u64 - before;
    // The new endpoint's items wait out the cooldown and are judged against
    // what time has paid back of the validator's debt since, not against
    // an allowance of their own.
    let secs = start.elapsed().as_secs() + 1;
    let admitted = JUDGED_AT_ONCE + secs * 5;
    assert!(
        judged <= admitted && admitted < FORGERIES_IN_ALLOWANCE,
        "the validator's debt follows it: {judged} of {ROTATION_FLOOD} judged from the new endpoint"
    );
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
            Verdict::Accept
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

#[tokio::test(flavor = "multi_thread")]
async fn a_peer_cooled_down_for_its_gossip_is_refused_its_notifications_too() {
    let fixtures = TestFixtures::new(21, 2);
    let (receiver, _counted, sender) = counted_pair(&fixtures, &[ShardId::ROOT]).await;
    receiver
        .network
        .register_gossip_handler(|_: CommittedHeader, _: ShardId| Verdict::Reject);
    let heard = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&heard);
    receiver
        .network
        .register_notification_handler(move |_: Vote| {
            counted.fetch_add(1, Ordering::SeqCst);
            Verdict::Accept
        });
    let heard = || heard.load(Ordering::SeqCst);

    // Before anything is held against the sender, its votes are heard.
    sender.network.notify(&[vid(0)], &Vote(0));
    wait_for("a vote is heard", || heard() == 1).await;

    // The sender's gossip is all its own fault; its votes are fine, but they
    // come from a peer whose traffic is being refused.
    let flood = Arc::clone(&sender.network);
    let flooding = spawn(async move {
        let mut tick = interval(Duration::from_secs(1) / HONEST_RATE);
        let mut seq = 0;
        loop {
            tick.tick().await;
            flood.broadcast_global(&CommittedHeader {
                seq,
                body: vec![7; HEADER_BYTES],
            });
            seq += 1;
        }
    });
    let mut watched = false;
    for _ in 0..COOLDOWNS_WATCHED {
        wait_for("the sender is cooled down", || {
            receiver.adapter.cooling_down(vid(1))
        })
        .await;
        let before = heard();
        for seq in 1..=VOTES_WHILE_COOLING {
            sender.network.notify(&[vid(0)], &Vote(seq));
        }
        sleep(VOTE_WATCH).await;
        let during = heard() - before;
        // Only a watch the cooldown outlasted shows anything.
        if receiver.adapter.cooling_down(vid(1)) {
            assert_eq!(during, 0, "a cooled down peer's votes are not taken up");
            watched = true;
            break;
        }
    }
    flooding.abort();
    assert!(watched, "a cooldown outlasts a watch");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_forged_copy_does_not_keep_an_honest_one_from_its_handler() {
    let fixtures = TestFixtures::new(21, 3);
    let receiver = host(&fixtures, 0, &[ShardId::ROOT], Vec::new()).await;
    let bootstrap = vec![receiver.adapter.endpoint_addr()];
    let forger = host(&fixtures, 1, &[ShardId::ROOT], bootstrap.clone()).await;
    let honest = host(&fixtures, 2, &[ShardId::ROOT], bootstrap).await;
    wait_for("both senders bind to the receiver", || {
        receiver.adapter.peer_for_validator(vid(1)).is_some()
            && receiver.adapter.peer_for_validator(vid(2)).is_some()
    })
    .await;

    // The receiver finds a forged copy false, as a committed header whose
    // sender signature fails, and takes an honest one.
    let handled: Arc<std::sync::Mutex<Vec<Copy>>> = Arc::default();
    let seen = Arc::clone(&handled);
    receiver
        .network
        .register_gossip_handler(move |copy: Copy, _: ShardId| {
            let false_on_its_face = copy.forged;
            seen.lock().unwrap().push(copy);
            if false_on_its_face {
                Verdict::Reject
            } else {
                Verdict::Accept
            }
        });
    let handled_count = || handled.lock().unwrap().len();

    forger.network.broadcast_global(&Copy {
        seq: 1,
        sender: 1,
        forged: true,
    });
    wait_for("the forged copy is judged first", || handled_count() == 1).await;
    honest.network.broadcast_global(&Copy {
        seq: 1,
        sender: 2,
        forged: false,
    });
    wait_for("the honest copy reaches its handler", || {
        handled_count() == 2
    })
    .await;

    // An accepted copy stands for its content: a later copy is not handed
    // to the handler again.
    forger.network.broadcast_global(&Copy {
        seq: 1,
        sender: 1,
        forged: false,
    });
    sleep(SILENCE_WATCH).await;
    assert_eq!(handled_count(), 2, "content already taken is handled once");
}

/// The key of the second check an item rests on, as a committed header
/// rests on its quorum certificate after its sender signature.
fn certificate_of(block: &BeaconBlock) -> VerdictKey {
    VerdictKey::of(&(block.0, 1u8))
}

#[tokio::test(flavor = "multi_thread")]
async fn an_item_travels_on_only_once_every_check_it_rests_on_holds() {
    let fixtures = TestFixtures::with_surplus(21, 1, 2);
    let (relay, sender, follower) = relay_line(&fixtures).await;

    let (keys_tx, mut keys) = mpsc::unbounded_channel();
    relay
        .network
        .register_gossip_handler(move |block: BeaconBlock, _: ShardId| {
            let checks = [VerdictKey::of(&block), certificate_of(&block)];
            let _ = keys_tx.send(checks);
            Verdict::defer_all(checks)
        });
    let (tx, mut rx) = mpsc::unbounded_channel();
    follower
        .network
        .register_host_gossip_handler(move |block: BeaconBlock| {
            let _ = tx.send(block);
        });
    follower
        .network
        .register_gossip_handler(|_: BeaconBlock, _: ShardId| Verdict::Accept);

    sender.network.broadcast_global(&BeaconBlock(7));
    let [signature, certificate] = timeout(BUDGET, keys.recv())
        .await
        .expect("the relay judges the item")
        .expect("its checks");
    relay.network.settle(signature, Verdict::Accept);
    assert!(
        timeout(SILENCE_WATCH, rx.recv()).await.is_err(),
        "nothing travels on while one of its checks runs"
    );
    relay.network.settle(certificate, Verdict::Accept);
    let delivered = timeout(BUDGET, rx.recv()).await.expect("delivered");
    assert_eq!(delivered, Some(BeaconBlock(7)));

    // One whose second check fails stops at the relay, though its first
    // held.
    sender.network.broadcast_global(&BeaconBlock(8));
    let [signature, certificate] = timeout(BUDGET, keys.recv())
        .await
        .expect("the relay judges the item")
        .expect("its checks");
    relay.network.settle(signature, Verdict::Accept);
    relay.network.settle(certificate, Verdict::Reject);
    assert!(timeout(SILENCE_WATCH, rx.recv()).await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_part_checked_before_its_item_arrives_is_settled_for_it() {
    let fixtures = TestFixtures::with_surplus(21, 1, 2);
    let (relay, sender, follower) = relay_line(&fixtures).await;

    let (keys_tx, mut keys) = mpsc::unbounded_channel();
    relay
        .network
        .register_gossip_handler(move |block: BeaconBlock, _: ShardId| {
            let own = VerdictKey::of(&block);
            let _ = keys_tx.send(own);
            Verdict::defer_all([own, certificate_of(&block)])
        });
    let (tx, mut rx) = mpsc::unbounded_channel();
    follower
        .network
        .register_host_gossip_handler(move |block: BeaconBlock| {
            let _ = tx.send(block);
        });
    follower
        .network
        .register_gossip_handler(|_: BeaconBlock, _: ShardId| Verdict::Accept);

    // As a ratify vote a proof carries was checked when it arrived alone:
    // the item that carries it waits only on its own check.
    relay
        .network
        .settle(certificate_of(&BeaconBlock(7)), Verdict::Accept);
    sender.network.broadcast_global(&BeaconBlock(7));
    let own = timeout(BUDGET, keys.recv())
        .await
        .expect("the relay judges the item")
        .expect("its own check");
    relay.network.settle(own, Verdict::Accept);
    let delivered = timeout(BUDGET, rx.recv()).await.expect("delivered");
    assert_eq!(delivered, Some(BeaconBlock(7)));

    // A part found false before stops every item that carries it.
    relay
        .network
        .settle(certificate_of(&BeaconBlock(8)), Verdict::Reject);
    sender.network.broadcast_global(&BeaconBlock(8));
    let own = timeout(BUDGET, keys.recv())
        .await
        .expect("the relay judges the item")
        .expect("its own check");
    relay.network.settle(own, Verdict::Accept);
    assert!(timeout(SILENCE_WATCH, rx.recv()).await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_peer_whose_items_fail_a_later_check_is_cooled_down() {
    let fixtures = TestFixtures::new(21, 2);
    let (receiver, _counted, sender) = counted_pair(&fixtures, &[ShardId::ROOT]).await;

    // Every header's sender signature holds and its certificate does not,
    // checked one after the other as the shard loop and the remote header
    // coordinator check them.
    let checked = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&checked);
    let network = Arc::clone(&receiver.network);
    let handle = Handle::current();
    receiver
        .network
        .register_gossip_handler(move |header: CommittedHeader, _: ShardId| {
            let signature = VerdictKey::of(&header);
            let certificate = VerdictKey::of(&(header.seq, 1u8));
            let (counted, network) = (Arc::clone(&counted), Arc::clone(&network));
            handle.spawn(async move {
                sleep(CHECK_DELAY).await;
                network.settle(signature, Verdict::Accept);
                sleep(CHECK_DELAY).await;
                counted.fetch_add(1, Ordering::SeqCst);
                network.settle(certificate, Verdict::Reject);
            });
            Verdict::defer_all([signature, certificate])
        });

    let start = Instant::now();
    let sent = HONEST_RATE * REJECTED_WATCH_SECS;
    let mut tick = interval(Duration::from_secs(1) / HONEST_RATE);
    for seq in 0..sent {
        tick.tick().await;
        sender.network.broadcast_global(&CommittedHeader {
            seq: u64::from(seq),
            body: vec![7; HEADER_BYTES],
        });
    }
    sleep(SILENCE_WATCH).await;
    let judged = checked.load(Ordering::SeqCst) as u64;
    let secs = start.elapsed().as_secs() + 1;
    // As for a single deferred check: what was already waiting on its
    // checks when the cooldown began, on top of the allowance.
    let admitted = FORGERIES_IN_ALLOWANCE + DEFERRED_AT_ONCE + secs * (5 + DEFERRED_AT_ONCE);
    assert!(judged > 0, "the headers reach the receiver");
    assert!(
        judged <= admitted,
        "the sender is cooled down: {judged} of {sent} certificates checked in {secs} s"
    );
}

/// A validator added to a running host is bound by the hosts it is linked
/// to over the links they already have: each takes the record the host hands
/// it and pulls the proof.
#[tokio::test(flavor = "multi_thread")]
async fn a_validator_added_to_a_linked_host_is_pulled_through_its_record() {
    let fixtures = TestFixtures::new(7, 3);
    let first = host(&fixtures, 0, &[ShardId::ROOT], Vec::new()).await;
    let second = host(
        &fixtures,
        1,
        &[ShardId::ROOT],
        vec![first.adapter.endpoint_addr()],
    )
    .await;
    wait_for("the hosts bind", || {
        first.adapter.peer_for_validator(vid(1)) == Some(second.adapter.local_endpoint_id())
    })
    .await;

    second
        .network
        .add_vnode((vid(2), fixtures.signer(2)))
        .expect("a third validator fits");
    wait_for("the added validator binds over the existing link", || {
        first.adapter.peer_for_validator(vid(2)) == Some(second.adapter.local_endpoint_id())
    })
    .await;
    assert_eq!(
        first.adapter.connected_peers(),
        vec![second.adapter.local_endpoint_id()]
    );
    assert_eq!(second.adapter.local_validator_ids(), vec![vid(1), vid(2)]);
}

/// A validator added before a linked host's topology holds its key is
/// claimed from the record it is handed and pulled the moment the topology
/// does.
#[tokio::test(flavor = "multi_thread")]
async fn a_validator_added_before_its_peer_knows_it_is_pulled_when_it_does() {
    let fixtures = TestFixtures::new(7, 3);
    let first = host(&fixtures, 0, &[ShardId::ROOT], Vec::new()).await;
    let all_keys = fixtures.validator_key_map();
    let without_two: ValidatorKeyMap = all_keys
        .iter()
        .filter(|(validator, _)| **validator != vid(2))
        .map(|(validator, key)| (*validator, *key))
        .collect();
    first.adapter.update_validator_keys(Arc::new(without_two));
    let second = host(
        &fixtures,
        1,
        &[ShardId::ROOT],
        vec![first.adapter.endpoint_addr()],
    )
    .await;
    wait_for("the hosts bind", || {
        first.adapter.peer_for_validator(vid(1)) == Some(second.adapter.local_endpoint_id())
    })
    .await;

    second
        .network
        .add_vnode((vid(2), fixtures.signer(2)))
        .expect("a third validator fits");
    sleep(Duration::from_secs(1)).await;
    assert_eq!(
        first.adapter.peer_for_validator(vid(2)),
        None,
        "a validator the topology holds no key for binds nowhere"
    );

    first.adapter.update_validator_keys(all_keys);
    timeout(Duration::from_secs(2), async {
        while first.adapter.peer_for_validator(vid(2)) != Some(second.adapter.local_endpoint_id()) {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the claim is pulled as soon as the key arrives, ahead of any sweep");
}

/// A host refuses to add a validator it already runs.
#[tokio::test(flavor = "multi_thread")]
async fn a_host_refuses_to_add_a_validator_it_runs() {
    let fixtures = TestFixtures::new(7, 2);
    let only = host(&fixtures, 0, &[ShardId::ROOT], Vec::new()).await;
    assert_eq!(
        only.network.add_vnode((vid(0), fixtures.signer(0))),
        Err(AddVnodeError::Hosted(vid(0)))
    );
}
