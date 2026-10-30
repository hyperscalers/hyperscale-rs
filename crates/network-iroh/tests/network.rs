//! Notifications and requests between hosts over real loopback QUIC.

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use hyperscale_crypto_bls::BlsVerifier;
use hyperscale_hbor::Hbor;
use hyperscale_network::fault::HostId;
use hyperscale_network::{
    HandlerRegistry, Network, RequestError, ResponseVerdict, Verdict, VerdictKey,
};
use hyperscale_network_iroh::test_utils::TestFixtures;
use hyperscale_network_iroh::testing::burn_processor_time;
use hyperscale_network_iroh::{
    IrohAdapter, IrohAdapterArgs, IrohConfig, IrohNetwork, NetworkError, RequestManager,
    RequestManagerConfig, RequestPool, RequestStreams,
};
use hyperscale_types::{
    MessageClass, NetworkDefinition, NetworkMessage, Request, ShardId, TopologySnapshot,
    ValidatorId,
};
use iroh::EndpointAddr;
use tokio::runtime::Handle;
use tokio::spawn;
use tokio::sync::mpsc;
use tokio::time::{interval, sleep, timeout};

/// Budget for a bind, a notification, or a request over loopback.
const BUDGET: Duration = Duration::from_secs(10);

/// How long something that must not arrive is watched for.
const SILENCE_WATCH: Duration = Duration::from_secs(1);

/// Size of one bulk response: near the largest frame the protocol carries.
const BULK_BYTES: usize = 8 * 1024 * 1024;

/// Bulk responses queued towards the requester at once.
const BULK_REQUESTS: usize = 4;

/// Numbers asked for of a shard one of whose responders answers garbage.
const GARBAGE_ROUNDS: u64 = 300;

/// Size of a block header stand-in.
const HEADER_BYTES: usize = 2048;

/// Headers a second an honest, busy peer sends a host that refuses them
/// all: more than one peer sends any host in a cluster of this size.
const HONEST_RATE: u32 = 300;

/// How long the honest peer keeps sending.
const HONEST_WATCH_SECS: u32 = 15;

/// How long a peer whose headers are its own fault keeps sending.
const REJECTED_WATCH_SECS: u32 = 5;

/// Notifications that are their sender's fault whose charges fit in a
/// peer's allowance of refused work, and the one that takes it past.
const FORGERIES_IN_ALLOWANCE: u64 = 26;

/// Notifications of one peer a host judges at once.
const JUDGED_AT_ONCE: u64 = 4;

/// Notifications of one peer a host waits on deferred verdicts for at once.
const DEFERRED_AT_ONCE: u64 = 64;

/// How long a deferred check takes.
const CHECK_DELAY: Duration = Duration::from_millis(15);

#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
struct Ping(u64);

impl NetworkMessage for Ping {
    fn message_type_id() -> &'static str {
        "test.ping"
    }

    fn class() -> MessageClass {
        MessageClass::Consensus
    }
}

/// A block header, as far as the transport is concerned: a notification
/// of some size whose signature its handler checks.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
struct Header {
    seq: u64,
    body: Vec<u8>,
}

impl NetworkMessage for Header {
    fn message_type_id() -> &'static str {
        "test.header"
    }

    fn class() -> MessageClass {
        MessageClass::Consensus
    }
}

#[derive(Debug, Clone, Hbor)]
struct Echo(u64);

#[derive(Debug, Clone, Hbor)]
struct Echoed(u64);

impl NetworkMessage for Echo {
    fn message_type_id() -> &'static str {
        "test.echo"
    }

    fn class() -> MessageClass {
        MessageClass::Consensus
    }
}

impl NetworkMessage for Echoed {
    fn message_type_id() -> &'static str {
        "test.echoed"
    }

    fn class() -> MessageClass {
        MessageClass::Consensus
    }
}

impl Request for Echo {
    type Response = Echoed;
}

/// A request whose answer takes its handler processor time, as a state
/// range with its proof does.
#[derive(Debug, Clone, Hbor)]
struct Costly(u64);

#[derive(Debug, Clone, Hbor)]
struct CostlyAnswer(u64);

impl NetworkMessage for Costly {
    fn message_type_id() -> &'static str {
        "test.costly"
    }

    fn class() -> MessageClass {
        MessageClass::Consensus
    }
}

impl NetworkMessage for CostlyAnswer {
    fn message_type_id() -> &'static str {
        "test.costly_answer"
    }

    fn class() -> MessageClass {
        MessageClass::Consensus
    }
}

impl Request for Costly {
    type Response = CostlyAnswer;
}

/// Processor time a costly answer takes its handler.
const COSTLY: Duration = Duration::from_millis(20);

/// Costly requests a greedy peer keeps in flight.
const GREEDY_IN_FLIGHT: u32 = 8;

/// How long a peer keeps asking for costly answers.
const ASKING_WATCH: Duration = Duration::from_secs(5);

/// Handler time a peer may run up at once beyond what time pays down.
const SERVE_ALLOWANCE: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Hbor)]
struct GetBulk(u64);

#[derive(Debug, Clone, Hbor)]
struct Bulk(Vec<u8>);

impl NetworkMessage for GetBulk {
    fn message_type_id() -> &'static str {
        "test.get_bulk"
    }

    fn class() -> MessageClass {
        MessageClass::Bulk
    }
}

impl NetworkMessage for Bulk {
    fn message_type_id() -> &'static str {
        "test.bulk"
    }

    fn class() -> MessageClass {
        MessageClass::Bulk
    }
}

impl Request for GetBulk {
    type Response = Bulk;
}

fn vid(index: u32) -> ValidatorId {
    ValidatorId::new(u64::from(index))
}

/// Bytes that do not compress, so a response stays its size on the wire.
fn incompressible(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[0]
        })
        .collect()
}

struct Host {
    adapter: Arc<IrohAdapter>,
    streams: Arc<RequestStreams>,
    network: Arc<IrohNetwork>,
}

/// Stand a host up carrying `validators`, serving `shards`.
async fn host(
    fixtures: &TestFixtures,
    validators: &[u32],
    shards: &[ShardId],
    bootstrap: Vec<EndpointAddr>,
) -> Host {
    let bind_addr: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let mut config = IrohConfig::for_testing(fixtures.network_key(validators[0]), bind_addr);
    config.bootstrap_peers = bootstrap;
    let registry = Arc::new(HandlerRegistry::new(shards.iter().copied().collect()));
    let adapter = IrohAdapter::bind(IrohAdapterArgs {
        config,
        network: NetworkDefinition::simulator(),
        vnodes: validators
            .iter()
            .map(|&i| (vid(i), fixtures.signer(i)))
            .collect(),
        local_shards: shards.iter().copied().collect::<HashSet<_>>(),
        registry: Arc::clone(&registry),
        validator_keys: fixtures.validator_key_map(),
        verifier: Arc::new(BlsVerifier),
    })
    .await
    .expect("the host binds");

    let genesis = fixtures.genesis_validators();
    let topology = Arc::new(ArcSwap::from_pointee(TopologySnapshot::new(
        genesis.network,
        1,
        genesis.validators,
    )));
    let streams = Arc::new(RequestStreams::new(Arc::clone(&adapter), Duration::ZERO));
    let pool: Arc<dyn RequestPool> = Arc::clone(&streams) as _;
    let manager = Arc::new(RequestManager::new(pool, RequestManagerConfig::default()));
    let network = Arc::new(IrohNetwork::new(
        Arc::clone(&adapter),
        manager,
        Handle::current(),
        registry,
        topology,
        Duration::ZERO,
    ));
    Host {
        adapter,
        streams,
        network,
    }
}

/// Two hosts, one validator each, bound to each other. Host 0 serves no
/// shard, so its requests go to the wire; host 1 serves the root shard.
async fn bound_pair(fixtures: &TestFixtures) -> (Host, Host) {
    let host0 = host(fixtures, &[0], &[], Vec::new()).await;
    let host1 = host(
        fixtures,
        &[1],
        &[ShardId::ROOT],
        vec![host0.adapter.endpoint_addr()],
    )
    .await;
    timeout(BUDGET, async {
        while host0.adapter.peer_for_validator(vid(1)).is_none()
            || host1.adapter.peer_for_validator(vid(0)).is_none()
        {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the pair binds");
    (host0, host1)
}

/// Send `request` to the root shard from `network` and await its outcome.
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

#[tokio::test(flavor = "multi_thread")]
async fn a_notification_reaches_the_validator_it_names() {
    let fixtures = TestFixtures::new(11, 2);
    let (host0, host1) = bound_pair(&fixtures).await;

    let (remote_tx, mut remote_rx) = mpsc::unbounded_channel();
    host1
        .network
        .register_notification_handler(move |ping: Ping| {
            let _ = remote_tx.send(ping);
            Verdict::Accept
        });
    let (local_tx, mut local_rx) = mpsc::unbounded_channel();
    host0
        .network
        .register_notification_handler(move |ping: Ping| {
            let _ = local_tx.send(ping);
            Verdict::Accept
        });

    // One recipient is behind the peer, the other is this host's own.
    host0.network.notify(&[vid(1), vid(0)], &Ping(7));

    let remote = timeout(BUDGET, remote_rx.recv()).await.expect("delivered");
    assert_eq!(remote, Some(Ping(7)));
    let local = timeout(BUDGET, local_rx.recv()).await.expect("delivered");
    assert_eq!(local, Some(Ping(7)));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_is_answered_by_a_member_that_serves_the_shard() {
    let fixtures = TestFixtures::new(11, 2);
    let (host0, host1) = bound_pair(&fixtures).await;
    host1
        .network
        .register_request_handler(ShardId::ROOT, |Echo(value): Echo| Echoed(value + 1));

    for value in [1, 41] {
        let Echoed(answer) = ask(&host0.network, Echo(value))
            .await
            .expect("the peer answers");
        assert_eq!(answer, value + 1);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_peer_that_does_not_serve_the_shard_says_so_and_is_backed_off() {
    let fixtures = TestFixtures::new(11, 2);
    let (host0, host1) = bound_pair(&fixtures).await;
    let peer = host1.adapter.local_endpoint_id();
    let unserved = ShardId::leaf(1, 1);

    let outcome = host0
        .streams
        .send(
            peer,
            unserved,
            "test.echo",
            vec![1, 2, 3],
            MessageClass::Consensus,
            BUDGET,
        )
        .await;
    assert!(
        matches!(outcome, Err(NetworkError::ShardUnsupported(_))),
        "an unserved shard is a definitive answer, got {outcome:?}"
    );
    assert!(
        host0
            .streams
            .backed_off_for(peer, unserved, MessageClass::Consensus)
            .is_some(),
        "the peer is held back for that shard"
    );
    assert!(
        host0
            .streams
            .backed_off_for(peer, ShardId::ROOT, MessageClass::Consensus)
            .is_none(),
        "and stays usable for a shard it does serve"
    );

    // Once the peer serves the shard, the same request type is answered.
    host1.network.subscribe_shard(unserved);
    host1
        .network
        .register_request_handler(unserved, |Echo(value): Echo| Echoed(value));
    assert!(host1.adapter.local_shards().contains(&unserved));
    host1.network.unsubscribe_shard(unserved);
    assert!(!host1.adapter.local_shards().contains(&unserved));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_consensus_notification_overtakes_queued_bulk_responses() {
    let fixtures = TestFixtures::new(11, 2);
    let (host0, host1) = bound_pair(&fixtures).await;

    // Host 1 answers every bulk request with a frame near the wire cap.
    let served = Arc::new(AtomicUsize::new(0));
    let handled = Arc::clone(&served);
    host1
        .network
        .register_request_handler(ShardId::ROOT, move |GetBulk(seed): GetBulk| {
            let body = incompressible(BULK_BYTES, seed);
            handled.fetch_add(1, Ordering::SeqCst);
            Bulk(body)
        });

    let notified_at: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));
    let seen = Arc::clone(&notified_at);
    host0.network.register_notification_handler(move |_: Ping| {
        seen.lock().unwrap().get_or_insert_with(Instant::now);
        Verdict::Accept
    });

    // Host 0 asks for several at once; each response is queued on its own
    // stream towards host 0.
    let (done_tx, mut done_rx) = mpsc::unbounded_channel();
    for seed in 0..BULK_REQUESTS {
        let done = done_tx.clone();
        host0.network.request(
            ShardId::ROOT,
            None,
            GetBulk(seed as u64 + 1),
            None,
            Box::new(move |outcome: Result<Bulk, RequestError>| {
                let _ = done.send((Instant::now(), outcome.map(|Bulk(body)| body.len())));
                ResponseVerdict::Accept
            }),
        );
    }

    // With every response handed to the transport, host 1 notifies host 0.
    timeout(BUDGET, async {
        while served.load(Ordering::SeqCst) < BULK_REQUESTS {
            sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("every bulk request is served");
    host1.network.notify(&[vid(0)], &Ping(1));

    let mut last_response_at = None;
    for _ in 0..BULK_REQUESTS {
        let (at, outcome) = timeout(Duration::from_secs(60), done_rx.recv())
            .await
            .expect("every bulk response arrives")
            .expect("the callback runs");
        assert_eq!(outcome.expect("the peer answers"), BULK_BYTES);
        last_response_at = last_response_at.max(Some(at));
    }
    let notified_at = notified_at
        .lock()
        .unwrap()
        .expect("the notification arrived while the responses were in flight");
    assert!(
        notified_at < last_response_at.unwrap(),
        "a consensus frame is not held behind bulk data to the same peer"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_peer_is_sent_only_a_few_sheddable_requests_at_a_time() {
    // The backend's bound on sheddable requests in flight to one peer.
    const TURNS: usize = 4;
    const ASKED: u64 = 12;
    let fixtures = TestFixtures::new(11, 2);
    let (host0, host1) = bound_pair(&fixtures).await;

    // Host 1 holds each request a while, counting how many it holds at once.
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let (held, most) = (Arc::clone(&active), Arc::clone(&peak));
    host1
        .network
        .register_request_handler(ShardId::ROOT, move |GetBulk(seed): GetBulk| {
            most.fetch_max(held.fetch_add(1, Ordering::SeqCst) + 1, Ordering::SeqCst);
            thread::sleep(Duration::from_millis(200));
            held.fetch_sub(1, Ordering::SeqCst);
            Bulk(seed.to_le_bytes().to_vec())
        });

    let (done_tx, mut done_rx) = mpsc::unbounded_channel();
    for seed in 0..ASKED {
        let done = done_tx.clone();
        host0.network.request(
            ShardId::ROOT,
            None,
            GetBulk(seed),
            None,
            Box::new(move |outcome: Result<Bulk, RequestError>| {
                let _ = done.send(outcome.is_ok());
                ResponseVerdict::Accept
            }),
        );
    }
    for _ in 0..ASKED {
        let answered = timeout(BUDGET, done_rx.recv())
            .await
            .expect("every request resolves")
            .expect("the callback runs");
        assert!(answered, "a request waiting its turn is still answered");
    }
    assert_eq!(
        peak.load(Ordering::SeqCst),
        TURNS,
        "sheddable requests to one peer run in parallel, but only so many"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_partitioned_peer_gets_neither_notification_nor_request() {
    let fixtures = TestFixtures::new(11, 2);
    let (host0, host1) = bound_pair(&fixtures).await;
    host1
        .network
        .register_request_handler(ShardId::ROOT, |Echo(value): Echo| Echoed(value));
    let (tx, mut rx) = mpsc::unbounded_channel();
    host1
        .network
        .register_notification_handler(move |ping: Ping| {
            let _ = tx.send(ping);
            Verdict::Accept
        });

    host0
        .adapter
        .fault_configure(HostId(0), [(host1.adapter.local_endpoint_id(), HostId(1))]);
    host0.adapter.fault_gate().block_host(HostId(1));

    host0.network.notify(&[vid(1)], &Ping(1));
    assert!(
        timeout(SILENCE_WATCH, rx.recv()).await.is_err(),
        "a notification does not cross the partition"
    );
    assert!(
        matches!(
            ask(&host0.network, Echo(1)).await,
            Err(RequestError::PeerUnreachable(_))
        ),
        "a request finds no member on this side of the partition"
    );

    host0.adapter.fault_gate().heal();
    host0.network.notify(&[vid(1)], &Ping(2));
    let delivered = timeout(BUDGET, rx.recv()).await.expect("delivered");
    assert_eq!(delivered, Some(Ping(2)));
    assert!(ask(&host0.network, Echo(1)).await.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_responder_that_answers_with_garbage_is_seldom_asked() {
    a_garbage_responder_is_seldom_asked(21, false).await;
}

/// An answer whose verdict waits on a check counts against its responder
/// once the check finds it false, as one rejected at once does.
#[tokio::test(flavor = "multi_thread")]
async fn a_responder_whose_deferred_answers_are_found_false_is_seldom_asked() {
    a_garbage_responder_is_seldom_asked(23, true).await;
}

/// One of three responders answers every request falsely; the asker
/// refuses each such answer, at once or, with `deferred`, through a check
/// that settles after the callback returns.
async fn a_garbage_responder_is_seldom_asked(seed: u64, deferred: bool) {
    let fixtures = TestFixtures::new(seed, 4);
    let asker = host(&fixtures, &[0], &[], Vec::new()).await;
    // Each responder, and how many requests it served.
    let mut responders = Vec::new();
    for index in 1..4 {
        let responder = host(
            &fixtures,
            &[index],
            &[ShardId::ROOT],
            vec![asker.adapter.endpoint_addr()],
        )
        .await;
        let count = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&count);
        // The first responder answers every request with someone else's
        // number; the others answer honestly.
        let garbage = index == 1;
        responder
            .network
            .register_request_handler(ShardId::ROOT, move |Echo(n)| {
                counted.fetch_add(1, Ordering::SeqCst);
                Echoed(if garbage { n + 1 } else { n })
            });
        responders.push((responder, count));
    }
    timeout(BUDGET, async {
        while (1..4).any(|i| asker.adapter.peer_for_validator(vid(i)).is_none()) {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the asker binds every responder");

    // Each number is asked for until an honest answer lands, as a fetch
    // retries an answer it rejects.
    for n in 0..GARBAGE_ROUNDS {
        loop {
            let (tx, mut rx) = mpsc::unbounded_channel();
            asker.network.request(
                ShardId::ROOT,
                None,
                Echo(n),
                None,
                Box::new(move |outcome: Result<Echoed, RequestError>| {
                    let answer = match outcome {
                        Ok(Echoed(m)) => Some(m),
                        Err(_) => None,
                    };
                    let _ = tx.send(answer);
                    match answer {
                        Some(m) if deferred => ResponseVerdict::defer(VerdictKey::of(&(n, m))),
                        Some(m) if m == n => ResponseVerdict::Accept,
                        _ => ResponseVerdict::Reject,
                    }
                }),
            );
            let answer = timeout(BUDGET, rx.recv())
                .await
                .expect("the request resolves")
                .expect("the callback runs");
            if deferred && let Some(m) = answer {
                let verdict = if m == n {
                    Verdict::Accept
                } else {
                    Verdict::Reject
                };
                asker.network.settle(VerdictKey::of(&(n, m)), verdict);
            }
            if answer == Some(n) {
                break;
            }
        }
    }

    let counts: Vec<usize> = responders
        .iter()
        .map(|(_, served)| served.load(Ordering::SeqCst))
        .collect();
    let total: usize = counts.iter().sum();
    assert!(
        counts[0] * 20 < total,
        "the garbage responder was asked {} of {total} times",
        counts[0]
    );
    assert!(
        counts[1..].iter().all(|honest| honest * 4 > total),
        "the honest responders share the load: {counts:?}"
    );
}

/// Notify `header`s from `sender` to validator 1 at [`HONEST_RATE`] for
/// `secs` seconds; returns how many were sent.
async fn notify_headers(sender: &Host, secs: u32) -> u32 {
    let sent = HONEST_RATE * secs;
    let mut tick = interval(Duration::from_secs(1) / HONEST_RATE);
    for seq in 0..sent {
        tick.tick().await;
        sender.network.notify(
            &[vid(1)],
            &Header {
                seq: u64::from(seq),
                body: vec![7; HEADER_BYTES],
            },
        );
    }
    sent
}

#[tokio::test(flavor = "multi_thread")]
async fn a_peer_whose_notifications_are_rejected_is_cooled_down() {
    let fixtures = TestFixtures::new(11, 2);
    let (sender, receiver) = bound_pair(&fixtures).await;

    // Every header is the sender's fault, as one whose proposer signature
    // fails is: each costs it a signature check's worth.
    let handled = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&handled);
    receiver
        .network
        .register_notification_handler(move |_: Header| {
            counted.fetch_add(1, Ordering::SeqCst);
            Verdict::Reject
        });

    let start = Instant::now();
    let sent = notify_headers(&sender, REJECTED_WATCH_SECS).await;
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

#[tokio::test(flavor = "multi_thread")]
async fn a_host_that_is_behind_still_hears_a_peer_whose_notifications_it_ignores() {
    let fixtures = TestFixtures::new(11, 2);
    let (sender, receiver) = bound_pair(&fixtures).await;

    // The receiver cannot place any header yet and ignores each one, as a
    // host whose topology is behind ignores a proposer it has no key for.
    // The sender is honest and busy.
    let handled = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&handled);
    receiver
        .network
        .register_notification_handler(move |_: Header| {
            counted.fetch_add(1, Ordering::SeqCst);
            Verdict::Ignore
        });

    let sent = notify_headers(&sender, HONEST_WATCH_SECS).await;
    timeout(BUDGET, async {
        while handled.load(Ordering::SeqCst) < sent as usize {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("every ignored header is still read");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_peer_whose_notifications_fail_their_deferred_check_is_cooled_down() {
    let fixtures = TestFixtures::new(11, 2);
    let (sender, receiver) = bound_pair(&fixtures).await;

    // Every header is checked off the handler, and every check fails.
    let checked = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&checked);
    let network = Arc::clone(&receiver.network);
    let handle = Handle::current();
    receiver
        .network
        .register_notification_handler(move |header: Header| {
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
    let sent = notify_headers(&sender, REJECTED_WATCH_SECS).await;
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

/// Host 1 answers [`Costly`] requests, each taking its handler [`COSTLY`];
/// returns the handler time it spent.
fn serve_costly(host: &Host) -> Arc<Mutex<Duration>> {
    let spent: Arc<Mutex<Duration>> = Arc::default();
    let counted = Arc::clone(&spent);
    host.network
        .register_request_handler(ShardId::ROOT, move |request: Costly| {
            burn_processor_time(COSTLY);
            *counted.lock().unwrap() += COSTLY;
            CostlyAnswer(request.0)
        });
    spent
}

#[tokio::test(flavor = "multi_thread")]
async fn a_peer_asking_for_costly_answers_is_held_to_one_core() {
    let fixtures = TestFixtures::new(11, 2);
    let (asker, server) = bound_pair(&fixtures).await;
    let spent = serve_costly(&server);

    // The asker keeps several requests in flight for as long as it watches,
    // asking again the moment one resolves, answered or not.
    let network = Arc::clone(&asker.network);
    let askers: Vec<_> = (0..GREEDY_IN_FLIGHT)
        .map(|_| {
            let network = Arc::clone(&network);
            spawn(async move {
                let started = Instant::now();
                let mut answered = 0u64;
                while started.elapsed() < ASKING_WATCH {
                    if ask(&network, Costly(answered)).await.is_ok() {
                        answered += 1;
                    }
                }
                answered
            })
        })
        .collect();
    for asker in askers {
        asker.await.expect("an asker finishes");
    }
    let spent = *spent.lock().unwrap();
    // Time pays the debt down as fast as it passes; what was in flight when
    // the allowance ran out was already admitted.
    let bound = ASKING_WATCH + SERVE_ALLOWANCE + COSTLY * GREEDY_IN_FLIGHT * 2;
    assert!(
        spent <= bound,
        "the server spent {spent:?} of handler time on one peer in {ASKING_WATCH:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_peer_asking_one_at_a_time_is_always_answered() {
    let fixtures = TestFixtures::new(11, 2);
    let (asker, server) = bound_pair(&fixtures).await;
    let _spent = serve_costly(&server);

    let started = Instant::now();
    let mut seq = 0u64;
    while started.elapsed() < ASKING_WATCH {
        let answer = ask(&asker.network, Costly(seq)).await;
        assert!(
            answer.is_ok(),
            "request {seq} of a peer asking one at a time: {answer:?}"
        );
        seq += 1;
    }
}
