//! Loopback comparison of the iroh and libp2p backends.
//!
//! Each measurement stands up a cluster of hosts in this process on one
//! backend, drives the same traffic through the [`Network`] trait, and
//! prints one JSON object. Loopback has no latency, loss or NAT: the
//! numbers compare what the two stacks cost on the same machine, not how
//! either behaves between home connections.
//!
//! ```text
//! bench notify    --backend iroh|libp2p --peers 1|127
//! bench range     --backend iroh|libp2p
//! bench committee --backend iroh|libp2p --size 32
//! bench idle      --backend iroh|libp2p --connections 150
//! bench delayed-idle --rtt-ms 40 --connections 500
//! bench reject-flood --rate 1000 --forged-per-signed 7 [--follower]
//! bench refused-flood --rate 1000 --verdict reject|ignore
//! bench forged-flood --rate 1000 --verdict accept|defer
//! bench bind-flood --validators 4 --dialers 16
//! bench garbage-responder --backend iroh|libp2p --requests 2000
//! ```
//!
//! `idle` and `delayed-idle` take `--path-idle-ms` and `--path-keep-alive-ms`
//! to measure what an iroh path timer setting costs an idle connection, and
//! `--redial-attempts` to set how often a relayed peer is re-dialed.
//! `delayed-idle --blocked` measures the connections after every one has
//! fallen back to the relay; `--hub-dials N` has the hub dial N of its
//! peers, so that it re-dials them itself, and `--redial-burst` and
//! `--redial-refill-ms` set the host-wide re-dial budget.

use std::any::Any;
use std::collections::HashSet;
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use clap::{Args, Parser, Subcommand, ValueEnum};
use hyperscale_crypto_bls::BlsVerifier;
use hyperscale_hbor::Hbor;
use hyperscale_network::fault::HostId;
use hyperscale_network::{
    HandlerRegistry, Network, RequestError, ResponseVerdict, Verdict, VerdictKey,
};
use hyperscale_network_iroh::test_utils::TestFixtures as IrohFixtures;
use hyperscale_network_iroh::testing::{
    CountingSigner, CountingVerifier, Star, UdpBridge, bind_hello,
};
use hyperscale_network_iroh::{
    EndpointAddr, IrohAdapter, IrohAdapterArgs, IrohConfig, IrohNetwork, PathKind,
    RequestManager as IrohRequestManager, RequestManagerConfig as IrohRequestManagerConfig,
    RequestPool, RequestStreams,
};
use hyperscale_network_libp2p::test_utils::TestFixtures as Libp2pFixtures;
use hyperscale_network_libp2p::{
    Libp2pAdapter, Libp2pAdapterArgs, Libp2pConfig, Libp2pNetwork,
    RequestManager as Libp2pRequestManager, RequestManagerConfig as Libp2pRequestManagerConfig,
    RequestStreamPool,
};
use hyperscale_types::network::gossip::ValidatorAddressGossip;
use hyperscale_types::{
    ConsensusSignature, GenesisValidators, GossipMessage, MessageClass, NetworkDefinition,
    NetworkMessage, Request, RoutingCommittees, ShardId, Signer, TopicScope, TopologySnapshot,
    ValidatorAddressMessage, ValidatorId, Verifier, signed_bytes,
};
use iroh::RelayMode;
use iroh::endpoint::{Builder, presets};
use libc::{RUSAGE_SELF, getrusage, rusage, timeval};
use serde_json::{Value, json};
use tokio::runtime::Handle;
use tokio::spawn;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{interval, sleep, timeout};

/// Seed of every cluster's keys.
const SEED: u64 = 0xbe9c;

/// Budget for a cluster to bind the links a measurement needs.
const MESH_BUDGET: Duration = Duration::from_secs(180);

/// Size of a block header stand-in.
const HEADER_BYTES: usize = 2048;

/// Spacing of the round trips whose latency is measured.
const PROBE_INTERVAL: Duration = Duration::from_millis(20);

/// Spacing of the header each background peer is sent.
const LOAD_INTERVAL: Duration = Duration::from_millis(100);

/// How long round trips are measured for, after a warm-up.
const NOTIFY_WINDOW: Duration = Duration::from_secs(30);

/// Round trips discarded before measurement starts.
const WARM_UP: Duration = Duration::from_secs(2);

/// Size of one state range chunk stand-in.
const CHUNK_BYTES: usize = 256 * 1024;

/// Sub-ranges fetched in parallel.
const RANGE_WORKERS: u64 = 16;

/// Chunks fetched in all.
const RANGE_CHUNKS: u64 = 2048;

/// Hosts that serve the range.
const RANGE_SERVERS: u32 = 4;

/// Spacing of the blocks a committee produces.
const BLOCK_INTERVAL: Duration = Duration::from_millis(250);

/// How long committee traffic is measured for.
const COMMITTEE_WINDOW: Duration = Duration::from_secs(30);

/// How long idle connections are watched for.
const IDLE_WINDOW: Duration = Duration::from_secs(60);

#[derive(Parser)]
#[command(about = "Loopback comparison of the iroh and libp2p backends")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, ValueEnum)]
enum Backend {
    Iroh,
    Libp2p,
}

impl Backend {
    const fn name(self) -> &'static str {
        match self {
            Self::Iroh => "iroh",
            Self::Libp2p => "libp2p",
        }
    }
}

/// Path timers of the iroh endpoints. Unset fields keep the backend's
/// defaults; the libp2p backend has no such timers.
#[derive(Args, Clone, Copy, Default)]
struct PathTimers {
    /// Idle time after which a path is abandoned, in milliseconds.
    #[arg(long)]
    path_idle_ms: Option<u64>,
    /// Interval of the keep alive that holds each path open, in milliseconds.
    #[arg(long)]
    path_keep_alive_ms: Option<u64>,
    /// Re-dials of a peer while its connection stays relayed; zero turns
    /// re-dialing off.
    #[arg(long)]
    redial_attempts: Option<u32>,
    /// Re-dials a host makes or admits at once.
    #[arg(long)]
    redial_burst: Option<u32>,
    /// Time in which a host earns one more re-dial, in milliseconds.
    #[arg(long)]
    redial_refill_ms: Option<u64>,
}

impl PathTimers {
    const fn apply(self, config: &mut IrohConfig) {
        if let Some(ms) = self.path_idle_ms {
            config.path_idle_timeout = Duration::from_millis(ms);
        }
        if let Some(ms) = self.path_keep_alive_ms {
            config.path_keep_alive = Duration::from_millis(ms);
        }
        if let Some(attempts) = self.redial_attempts {
            config.redial.attempts = attempts;
        }
        if let Some(burst) = self.redial_burst {
            config.redial_budget.burst = burst;
        }
        if let Some(ms) = self.redial_refill_ms {
            config.redial_budget.refill = Duration::from_millis(ms);
        }
    }

    fn report(self) -> Value {
        json!({
            "path_idle_ms": self.path_idle_ms,
            "path_keep_alive_ms": self.path_keep_alive_ms,
            "redial_attempts": self.redial_attempts,
            "redial_burst": self.redial_burst,
            "redial_refill_ms": self.redial_refill_ms,
        })
    }
}

#[derive(Subcommand)]
enum Command {
    /// Round trip of a header out and a vote back, with other peers active.
    Notify {
        #[arg(long)]
        backend: Backend,
        /// Peers exchanging headers and votes with the measuring host.
        #[arg(long, default_value_t = 1)]
        peers: u32,
    },
    /// Throughput of a state range fetched in parallel sub-ranges.
    Range {
        #[arg(long)]
        backend: Backend,
    },
    /// Process CPU of a committee exchanging headers and votes.
    Committee {
        #[arg(long)]
        backend: Backend,
        #[arg(long, default_value_t = 32)]
        size: u32,
    },
    /// Process CPU, and bytes where the backend counts them, of one host
    /// holding idle connections.
    Idle {
        #[arg(long)]
        backend: Backend,
        #[arg(long, default_value_t = 150)]
        connections: u32,
        #[command(flatten)]
        timers: PathTimers,
    },
    /// Bytes idle iroh connections exchange when their round trip time is
    /// above the library's threshold for repeating NAT traversal.
    DelayedIdle {
        /// Peers holding an idle connection to the measuring hub.
        #[arg(long, default_value_t = 1)]
        connections: u32,
        #[arg(long, default_value_t = 40)]
        rtt_ms: u64,
        #[arg(long, default_value_t = 180)]
        secs: u64,
        /// Block every bridge once the connections are direct, and measure
        /// them after they have fallen back to the relay.
        #[arg(long)]
        blocked: bool,
        /// Peers the hub dials; the rest dial the hub. Only the side that
        /// dialed a connection re-dials it.
        #[arg(long, default_value_t = 0)]
        hub_dials: u32,
        #[command(flatten)]
        timers: PathTimers,
    },
    /// Signature checks one peer makes a receiver do by sending forged
    /// address records, each run of them followed by a record it signed.
    RejectFlood {
        /// Items the peer sends a second.
        #[arg(long, default_value_t = 1000)]
        rate: u32,
        /// Forged records the peer sends before each signed one.
        #[arg(long, default_value_t = 7)]
        forged_per_signed: u32,
        #[arg(long, default_value_t = 30)]
        secs: u64,
        /// The receiver serves no shard.
        #[arg(long)]
        follower: bool,
    },
    /// One of a shard's responders answers every request with garbage.
    GarbageResponder {
        #[arg(long, value_enum)]
        backend: Backend,
        /// Requests the asker needs answered.
        #[arg(long, default_value_t = 2000)]
        requests: u64,
    },
    /// Strangers open bind exchanges at a host as fast as they can and
    /// leave once it has signed.
    BindFlood {
        /// Validators the host carries, each of which signs every exchange
        /// it answers.
        #[arg(long, default_value_t = 4)]
        validators: u32,
        /// Exchanges in flight at once.
        #[arg(long, default_value_t = 16)]
        dialers: u32,
        #[arg(long, default_value_t = 30)]
        secs: u64,
    },
    /// A peer floods global items that fail a check its receiver runs off
    /// the handler, while a follower hears only what the receiver forwards.
    ForgedFlood {
        /// Items the peer sends a second.
        #[arg(long, default_value_t = 1000)]
        rate: u32,
        /// What the receiver's handler answers before the check: `accept`
        /// forwards at once and leaves the check unattributed, `defer`
        /// waits on it.
        #[arg(long, value_enum)]
        verdict: Checked,
        #[arg(long, default_value_t = 30)]
        secs: u64,
    },
    /// A peer floods notifications whose signature its receiver checks
    /// and finds false.
    NotifyFlood {
        /// Notifications the peer sends a second.
        #[arg(long, default_value_t = 1000)]
        rate: u32,
        /// What the receiver's handler answers after its check: `accept`
        /// holds nothing against the sender, as a handler that returns no
        /// verdict does; `reject` is the check's own verdict.
        #[arg(long, value_enum)]
        verdict: Judged,
        #[arg(long, default_value_t = 30)]
        secs: u64,
    },
    /// A peer sends a false copy of each committed header just ahead of an
    /// honest peer's copy of the same header.
    ShadowFlood {
        /// Headers a second.
        #[arg(long, default_value_t = 4)]
        rate: u32,
        #[arg(long, default_value_t = 30)]
        secs: u64,
    },
    /// A peer floods global items its receiver refuses with one verdict.
    RefusedFlood {
        /// Items the peer sends a second.
        #[arg(long, default_value_t = 1000)]
        rate: u32,
        /// What the receiver's handler answers every item with.
        #[arg(long, value_enum)]
        verdict: Refusal,
        #[arg(long, default_value_t = 30)]
        secs: u64,
    },
}

/// What a forged flood's receiver answers before its check.
#[derive(Clone, Copy, ValueEnum)]
enum Checked {
    /// Accept at once; the check that fails later is no one's to answer.
    Accept,
    /// Defer to the check, which settles it.
    Defer,
}

/// What a notify flood's receiver answers after its check fails.
#[derive(Clone, Copy, ValueEnum)]
enum Judged {
    /// Nothing held against the sender.
    Accept,
    /// The sender's fault.
    Reject,
}

/// The verdict a refused flood's receiver gives every item.
#[derive(Clone, Copy, ValueEnum)]
enum Refusal {
    /// The item is the sender's fault.
    Reject,
    /// The receiver cannot judge the item.
    Ignore,
}

/// A committed block header, as far as the transport is concerned: a global
/// item of a few KiB.
#[derive(Debug, Clone, Hbor)]
struct Committed {
    seq: u64,
    body: Vec<u8>,
}

impl NetworkMessage for Committed {
    fn message_type_id() -> &'static str {
        "block.committed"
    }

    fn class() -> MessageClass {
        MessageClass::CrossShardProgress
    }
}

impl GossipMessage for Committed {
    const SCOPE: TopicScope = TopicScope::Global;
}

/// One committee member's copy of a committed header: the content key
/// covers `seq`, and the copy carries its sender's signature, which a
/// forger's copy fails.
#[derive(Debug, Clone, Hbor)]
struct HeaderCopy {
    seq: u64,
    sender: u32,
    forged: bool,
    body: Vec<u8>,
}

impl NetworkMessage for HeaderCopy {
    fn message_type_id() -> &'static str {
        "block.committed"
    }

    fn class() -> MessageClass {
        MessageClass::CrossShardProgress
    }
}

impl GossipMessage for HeaderCopy {
    const SCOPE: TopicScope = TopicScope::Global;

    fn dedup_key(&self) -> Option<u64> {
        Some(self.seq)
    }
}

/// How far an honest copy trails the false one ahead of it: past the time
/// the receiver takes to judge the false one.
const HONEST_COPY_LAG: Duration = Duration::from_millis(20);

/// A block header notification, as far as the transport is concerned: a
/// few KiB under its proposer's signature.
#[derive(Debug, Clone, Hbor)]
struct SignedHeader {
    seq: u64,
    body: Vec<u8>,
    signature: ConsensusSignature,
}

impl NetworkMessage for SignedHeader {
    fn message_type_id() -> &'static str {
        "block.header"
    }

    fn class() -> MessageClass {
        MessageClass::Consensus
    }
}

#[derive(Debug, Clone, Hbor)]
struct Header {
    seq: u64,
    proposer: u64,
    /// Size of the committee the header is proposed to.
    committee: u32,
    body: Vec<u8>,
}

impl NetworkMessage for Header {
    fn message_type_id() -> &'static str {
        "bench.header"
    }

    fn class() -> MessageClass {
        MessageClass::Consensus
    }
}

#[derive(Debug, Clone, Hbor)]
struct Vote {
    seq: u64,
    voter: u64,
    signature: Vec<u8>,
}

impl NetworkMessage for Vote {
    fn message_type_id() -> &'static str {
        "bench.vote"
    }

    fn class() -> MessageClass {
        MessageClass::Consensus
    }
}

#[derive(Debug, Clone, Hbor)]
struct GetChunk(u64);

#[derive(Debug, Clone, Hbor)]
struct Chunk(Vec<u8>);

impl NetworkMessage for GetChunk {
    fn message_type_id() -> &'static str {
        "bench.get_chunk"
    }

    fn class() -> MessageClass {
        MessageClass::Recovery
    }
}

impl NetworkMessage for Chunk {
    fn message_type_id() -> &'static str {
        "bench.chunk"
    }

    fn class() -> MessageClass {
        MessageClass::Recovery
    }
}

impl Request for GetChunk {
    type Response = Chunk;
}

fn vid(index: u32) -> ValidatorId {
    ValidatorId::new(u64::from(index))
}

/// Bytes that do not compress.
fn incompressible(len: usize) -> Vec<u8> {
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[0]
        })
        .collect()
}

/// Bytes a backend has sent and received on the wire, where it counts them.
#[derive(Clone, Copy)]
struct Wire {
    sent: u64,
    received: u64,
}

/// One host of a cluster, behind what both backends offer.
struct Host<N> {
    network: Arc<N>,
    /// Whether this host is bound to the host carrying a validator.
    bound: Box<dyn Fn(ValidatorId) -> bool + Send + Sync>,
    /// Bytes on the wire so far, for a backend that counts them.
    wire: Box<dyn Fn() -> Option<Wire> + Send + Sync>,
    _adapter: Box<dyn Any + Send + Sync>,
}

/// What a cluster is built with. Host `i` carries validator `i`.
struct ClusterSpec {
    hosts: u32,
    /// Validators seated in the root committee: `0..seated`.
    seated: u32,
    /// Whether host `i` serves the root shard.
    serves: fn(u32) -> bool,
    /// Whether every host is told the root committee, and so dials all of
    /// it. Otherwise each host knows only the first.
    meshed: bool,
    timers: PathTimers,
}

fn topology(genesis: GenesisValidators) -> Arc<ArcSwap<TopologySnapshot>> {
    Arc::new(ArcSwap::from_pointee(TopologySnapshot::new(
        genesis.network,
        1,
        genesis.validators,
    )))
}

/// The servers of a shard, meshed, and one host asking them.
fn range_cluster() -> ClusterSpec {
    ClusterSpec {
        hosts: RANGE_SERVERS + 1,
        seated: RANGE_SERVERS,
        serves: |index| index < RANGE_SERVERS,
        meshed: true,
        timers: PathTimers::default(),
    }
}

fn root_committee(spec: &ClusterSpec) -> Arc<RoutingCommittees> {
    Arc::new(RoutingCommittees::from([(
        ShardId::ROOT,
        (0..spec.seated).map(vid).collect(),
    )]))
}

fn shards_of(spec: &ClusterSpec, index: u32) -> Vec<ShardId> {
    if (spec.serves)(index) {
        vec![ShardId::ROOT]
    } else {
        Vec::new()
    }
}

async fn iroh_cluster(spec: &ClusterSpec) -> Vec<Host<IrohNetwork>> {
    let fixtures = IrohFixtures::with_surplus(SEED, spec.seated, spec.hosts - spec.seated);
    let mut hosts: Vec<Host<IrohNetwork>> = Vec::new();
    let mut first: Option<EndpointAddr> = None;
    for index in 0..spec.hosts {
        let (adapter, network) = iroh_host(
            &fixtures,
            index,
            &shards_of(spec, index),
            first.clone(),
            spec.timers,
            Arc::new(BlsVerifier),
        )
        .await;
        first.get_or_insert_with(|| adapter.endpoint_addr());
        if spec.meshed {
            network.update_routing_committees(root_committee(spec));
        }
        let (bound, wire) = (Arc::clone(&adapter), Arc::clone(&adapter));
        hosts.push(Host {
            network,
            bound: Box::new(move |validator| bound.peer_for_validator(validator).is_some()),
            wire: Box::new(move || {
                let traffic = wire.traffic();
                Some(Wire {
                    sent: traffic.sent,
                    received: traffic.received,
                })
            }),
            _adapter: Box::new(adapter),
        });
    }
    hosts
}

async fn libp2p_cluster(spec: &ClusterSpec) -> Vec<Host<Libp2pNetwork>> {
    let fixtures = Libp2pFixtures::with_surplus(SEED, spec.seated, spec.hosts - spec.seated);
    let mut hosts: Vec<Host<Libp2pNetwork>> = Vec::new();
    let mut first = None;
    for index in 0..spec.hosts {
        let shards = shards_of(spec, index);
        let config = Libp2pConfig {
            listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
            bootstrap_peers: first.iter().cloned().collect(),
            ..Default::default()
        };
        let registry = Arc::new(HandlerRegistry::new(shards.iter().copied().collect()));
        let adapter = Libp2pAdapter::new(Libp2pAdapterArgs {
            config,
            network: NetworkDefinition::simulator(),
            keypair: fixtures.ed25519_keypair(index),
            vnodes: vec![(vid(index), fixtures.signer(index))],
            local_shards: shards.iter().copied().collect::<HashSet<_>>(),
            registry: Arc::clone(&registry),
            validator_keys: fixtures.validator_key_map(),
            verifier: Arc::new(BlsVerifier),
        })
        .expect("the host binds");
        if first.is_none() {
            first = timeout(Duration::from_secs(10), async {
                loop {
                    if let Some(addr) = adapter.listen_addresses().await.into_iter().next() {
                        return addr;
                    }
                    sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .ok();
        }

        let pool = Arc::new(RequestStreamPool::new(
            Arc::clone(&adapter),
            Handle::current(),
            Duration::ZERO,
        ));
        let network = Arc::new(Libp2pNetwork::new(
            Arc::clone(&adapter),
            Arc::new(Libp2pRequestManager::new(
                pool,
                Libp2pRequestManagerConfig::default(),
            )),
            Handle::current(),
            registry,
            topology(fixtures.genesis_validators()),
            Duration::ZERO,
        ));
        if spec.meshed {
            network.update_routing_committees(root_committee(spec));
        }
        let bound = Arc::clone(&adapter);
        hosts.push(Host {
            network,
            bound: Box::new(move |validator| bound.peer_for_validator(validator).is_some()),
            wire: Box::new(|| None),
            _adapter: Box::new(adapter),
        });
    }
    hosts
}

/// Wait until every `(from, to)` pair of hosts is bound. Returns how long
/// it took and how many pairs were still unbound when the budget ran out.
async fn await_links<N: Network>(hosts: &[Host<N>], pairs: &[(u32, u32)]) -> (Duration, usize) {
    let start = Instant::now();
    loop {
        let unbound = pairs
            .iter()
            .filter(|(from, to)| !(hosts[*from as usize].bound)(vid(*to)))
            .count();
        if unbound == 0 || start.elapsed() >= MESH_BUDGET {
            return (start.elapsed(), unbound);
        }
        sleep(Duration::from_millis(50)).await;
    }
}

/// Every ordered pair among the first `count` hosts.
fn mesh_pairs(count: u32) -> Vec<(u32, u32)> {
    (0..count)
        .flat_map(|from| {
            (0..count)
                .filter(move |to| *to != from)
                .map(move |to| (from, to))
        })
        .collect()
}

/// Both directions between the first host and each of the others.
fn star_pairs(count: u32) -> Vec<(u32, u32)> {
    (1..count).flat_map(|peer| [(0, peer), (peer, 0)]).collect()
}

/// CPU time this process has used, user and system together.
fn cpu_time() -> Duration {
    let mut usage = MaybeUninit::<rusage>::uninit();
    // SAFETY: `getrusage` fills the struct it is given when it returns 0,
    // and `RUSAGE_SELF` with a valid pointer cannot fail.
    let usage = unsafe {
        getrusage(RUSAGE_SELF, usage.as_mut_ptr());
        usage.assume_init()
    };
    let part = |time: timeval| {
        Duration::from_secs(u64::try_from(time.tv_sec).unwrap_or(0))
            + Duration::from_micros(u64::try_from(time.tv_usec).unwrap_or(0))
    };
    part(usage.ru_utime) + part(usage.ru_stime)
}

fn percentile(sorted: &[u64], per_mille: usize) -> u64 {
    sorted
        .get((sorted.len() * per_mille / 1000).min(sorted.len().saturating_sub(1)))
        .copied()
        .unwrap_or(0)
}

/// Have every host but the first answer a header with a vote to the
/// validators `recipients` names for it.
fn vote_on_headers<N: Network>(
    hosts: &[Host<N>],
    recipients: fn(&Header, u32) -> Vec<ValidatorId>,
) {
    for (index, host) in hosts.iter().enumerate() {
        let network = Arc::clone(&host.network);
        let index = u32::try_from(index).expect("a cluster fits in u32");
        host.network
            .register_notification_handler(move |header: Header| {
                let vote = Vote {
                    seq: header.seq,
                    voter: u64::from(index),
                    signature: vec![7; 96],
                };
                network.notify(&recipients(&header, index), &vote);
                Verdict::Accept
            });
    }
}

async fn notify<N: Network>(backend: Backend, hosts: Vec<Host<N>>, peers: u32) {
    let (link_time, unbound) = await_links(&hosts, &star_pairs(peers + 1)).await;
    vote_on_headers(&hosts, |_, _| vec![vid(0)]);

    // The first host measures its round trip with host 1; the rest load it.
    let sent: Arc<Mutex<Vec<Option<Instant>>>> = Arc::new(Mutex::new(Vec::new()));
    let (arrivals_tx, mut arrivals) = mpsc::unbounded_channel::<(Instant, Duration)>();
    let outstanding = Arc::clone(&sent);
    hosts[0]
        .network
        .register_notification_handler(move |vote: Vote| {
            if vote.voter != 1 {
                return Verdict::Accept;
            }
            let now = Instant::now();
            let slot = usize::try_from(vote.seq).ok();
            let started = slot.and_then(|slot| outstanding.lock().unwrap().get_mut(slot)?.take());
            if let Some(started) = started {
                let _ = arrivals_tx.send((now, now - started));
            }
            Verdict::Accept
        });

    let hub = Arc::clone(&hosts[0].network);
    let load: Vec<ValidatorId> = (2..=peers).map(vid).collect();
    let body = incompressible(HEADER_BYTES);
    let load_body = body.clone();
    let load_task = spawn(async move {
        let mut tick = interval(LOAD_INTERVAL);
        loop {
            tick.tick().await;
            if !load.is_empty() {
                hub.notify(
                    &load,
                    &Header {
                        seq: u64::MAX,
                        proposer: 0,
                        committee: peers + 1,
                        body: load_body.clone(),
                    },
                );
            }
        }
    });

    let start = Instant::now();
    let mut tick = interval(PROBE_INTERVAL);
    let mut seq = 0u64;
    while start.elapsed() < WARM_UP + NOTIFY_WINDOW {
        tick.tick().await;
        sent.lock().unwrap().push(Some(Instant::now()));
        hosts[0].network.notify(
            &[vid(1)],
            &Header {
                seq,
                proposer: 0,
                committee: peers + 1,
                body: body.clone(),
            },
        );
        seq += 1;
    }
    sleep(Duration::from_secs(1)).await;
    load_task.abort();

    let mut round_trips = Vec::new();
    let mut gaps_over_100ms = 0u64;
    let mut last_arrival: Option<Instant> = None;
    while let Ok((at, round_trip)) = arrivals.try_recv() {
        if at.duration_since(start) < WARM_UP {
            continue;
        }
        if last_arrival.is_some_and(|last| at.duration_since(last) > Duration::from_millis(100)) {
            gaps_over_100ms += 1;
        }
        last_arrival = Some(at);
        round_trips.push(u64::try_from(round_trip.as_micros()).unwrap_or(u64::MAX));
    }
    round_trips.sort_unstable();
    println!(
        "{}",
        json!({
            "measurement": "notify round trip",
            "backend": backend.name(),
            "active_peers": peers,
            "links_unbound": unbound,
            "link_secs": link_time.as_secs_f64(),
            "sent": seq,
            "answered_after_warm_up": round_trips.len(),
            "p50_us": percentile(&round_trips, 500),
            "p90_us": percentile(&round_trips, 900),
            "p99_us": percentile(&round_trips, 990),
            "max_us": round_trips.last().copied().unwrap_or(0),
            "gaps_over_100ms": gaps_over_100ms,
        })
    );
}

async fn range<N: Network>(backend: Backend, hosts: Vec<Host<N>>) {
    let asker = RANGE_SERVERS;
    let pairs: Vec<(u32, u32)> = (0..RANGE_SERVERS).map(|server| (asker, server)).collect();
    let (link_time, unbound) = await_links(&hosts, &pairs).await;

    let chunk = Arc::new(incompressible(CHUNK_BYTES));
    for server in &hosts[..RANGE_SERVERS as usize] {
        let chunk = Arc::clone(&chunk);
        server
            .network
            .register_request_handler(ShardId::ROOT, move |_: GetChunk| Chunk((*chunk).clone()));
    }

    let next = Arc::new(AtomicU64::new(0));
    let failed = Arc::new(AtomicU64::new(0));
    let network = Arc::clone(&hosts[asker as usize].network);
    let start = Instant::now();
    let workers: Vec<_> = (0..RANGE_WORKERS)
        .map(|_| {
            let (network, next, failed) =
                (Arc::clone(&network), Arc::clone(&next), Arc::clone(&failed));
            spawn(async move {
                let mut bytes = 0u64;
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    if index >= RANGE_CHUNKS {
                        return bytes;
                    }
                    // A failed fetch is retried until it lands, as a sync
                    // would; each failure is counted.
                    loop {
                        let (tx, rx) = oneshot::channel();
                        network.request(
                            ShardId::ROOT,
                            None,
                            GetChunk(index),
                            None,
                            Box::new(move |outcome: Result<Chunk, RequestError>| {
                                let _ = tx.send(outcome.map(|Chunk(body)| body.len()));
                                ResponseVerdict::Accept
                            }),
                        );
                        if let Ok(Ok(len)) = rx.await {
                            bytes += len as u64;
                            break;
                        }
                        failed.fetch_add(1, Ordering::Relaxed);
                        sleep(Duration::from_millis(50)).await;
                    }
                }
            })
        })
        .collect();
    let mut bytes = 0u64;
    for worker in workers {
        bytes += worker.await.expect("a worker finishes");
    }
    let elapsed = start.elapsed();
    #[allow(clippy::cast_precision_loss)] // a rate for a report
    let rate = bytes as f64 / elapsed.as_secs_f64();
    println!(
        "{}",
        json!({
            "measurement": "state range transfer",
            "backend": backend.name(),
            "links_unbound": unbound,
            "link_secs": link_time.as_secs_f64(),
            "chunk_bytes": CHUNK_BYTES,
            "parallel_sub_ranges": RANGE_WORKERS,
            "servers": RANGE_SERVERS,
            "bytes": bytes,
            "secs": elapsed.as_secs_f64(),
            "bytes_per_sec": rate,
            "failed_attempts": failed.load(Ordering::Relaxed),
        })
    );
}

/// The asker of a range cluster needs `requests` small chunks, each asked
/// until a good answer lands, while the first server answers every request
/// with a chunk the asker rejects. Counts what each server was asked.
async fn garbage_responder<N: Network>(backend: Backend, hosts: Vec<Host<N>>, requests: u64) {
    const GOOD: usize = 64;
    let asker = RANGE_SERVERS;
    let pairs: Vec<(u32, u32)> = (0..RANGE_SERVERS).map(|server| (asker, server)).collect();
    let (link_time, unbound) = await_links(&hosts, &pairs).await;

    let served: Vec<Arc<AtomicU64>> = (0..RANGE_SERVERS)
        .map(|_| Arc::new(AtomicU64::new(0)))
        .collect();
    for (index, server) in hosts[..RANGE_SERVERS as usize].iter().enumerate() {
        let count = Arc::clone(&served[index]);
        let len = if index == 0 { 1 } else { GOOD };
        server
            .network
            .register_request_handler(ShardId::ROOT, move |_: GetChunk| {
                count.fetch_add(1, Ordering::Relaxed);
                Chunk(vec![1; len])
            });
    }

    let next = Arc::new(AtomicU64::new(0));
    let network = Arc::clone(&hosts[asker as usize].network);
    let start = Instant::now();
    let workers: Vec<_> = (0..RANGE_WORKERS)
        .map(|_| {
            let (network, next) = (Arc::clone(&network), Arc::clone(&next));
            spawn(async move {
                while next.fetch_add(1, Ordering::Relaxed) < requests {
                    loop {
                        let (tx, rx) = oneshot::channel();
                        network.request(
                            ShardId::ROOT,
                            None,
                            GetChunk(0),
                            None,
                            Box::new(move |outcome: Result<Chunk, RequestError>| {
                                let good =
                                    matches!(&outcome, Ok(Chunk(body)) if body.len() == GOOD);
                                let _ = tx.send(good);
                                if good {
                                    ResponseVerdict::Accept
                                } else {
                                    ResponseVerdict::Reject
                                }
                            }),
                        );
                        if rx.await == Ok(true) {
                            break;
                        }
                    }
                }
            })
        })
        .collect();
    for worker in workers {
        worker.await.expect("a worker finishes");
    }
    let elapsed = start.elapsed();
    let counts: Vec<u64> = served.iter().map(|c| c.load(Ordering::Relaxed)).collect();
    let total: u64 = counts.iter().sum();
    #[allow(clippy::cast_precision_loss)] // a share for a report
    let share = counts[0] as f64 / total as f64;
    println!(
        "{}",
        json!({
            "measurement": "garbage responder",
            "backend": backend.name(),
            "links_unbound": unbound,
            "link_secs": link_time.as_secs_f64(),
            "requests": requests,
            "secs": elapsed.as_secs_f64(),
            "served_per_server": counts,
            "garbage_share": share,
            "wasted_attempts": counts[0],
        })
    );
}

async fn committee<N: Network>(backend: Backend, hosts: Vec<Host<N>>, size: u32) {
    let (link_time, unbound) = await_links(&hosts, &mesh_pairs(size)).await;
    // A vote goes to the round's proposer and the next two, as consensus
    // sends it.
    vote_on_headers(&hosts, |header, _| {
        let proposer = u32::try_from(header.proposer).unwrap_or(0);
        (0..3)
            .map(|step| vid((proposer + step) % header.committee.max(1)))
            .collect()
    });
    let votes = Arc::new(AtomicU64::new(0));
    for host in &hosts {
        let votes = Arc::clone(&votes);
        host.network.register_notification_handler(move |_: Vote| {
            votes.fetch_add(1, Ordering::Relaxed);
            Verdict::Accept
        });
    }

    let idle_start = (Instant::now(), cpu_time());
    sleep(Duration::from_secs(10)).await;
    let idle_cpu = cpu_time().saturating_sub(idle_start.1);
    let idle_wall = idle_start.0.elapsed();

    let body = incompressible(HEADER_BYTES);
    let everyone: Vec<ValidatorId> = (0..size).map(vid).collect();
    let active_start = (Instant::now(), cpu_time());
    let mut tick = interval(BLOCK_INTERVAL);
    let mut height = 0u32;
    while active_start.0.elapsed() < COMMITTEE_WINDOW {
        tick.tick().await;
        let proposer = height % size;
        hosts[proposer as usize].network.notify(
            &everyone,
            &Header {
                seq: u64::from(height),
                proposer: u64::from(proposer),
                committee: size,
                body: body.clone(),
            },
        );
        height += 1;
    }
    let active_cpu = cpu_time().saturating_sub(active_start.1);
    let active_wall = active_start.0.elapsed();
    println!(
        "{}",
        json!({
            "measurement": "committee traffic",
            "backend": backend.name(),
            "committee": size,
            "links_unbound": unbound,
            "link_secs": link_time.as_secs_f64(),
            "header_bytes": body.len(),
            "blocks": height,
            "votes_delivered": votes.load(Ordering::Relaxed),
            "idle_cpu_cores": idle_cpu.as_secs_f64() / idle_wall.as_secs_f64(),
            "active_cpu_cores": active_cpu.as_secs_f64() / active_wall.as_secs_f64(),
        })
    );
}

async fn idle<N: Network>(
    backend: Backend,
    hosts: Vec<Host<N>>,
    connections: u32,
    timers: PathTimers,
) {
    let (link_time, unbound) = await_links(&hosts, &star_pairs(connections + 1)).await;
    // Let handshakes and address exchange settle before watching.
    sleep(Duration::from_secs(10)).await;

    let wire_before = (hosts[0].wire)();
    let start = (Instant::now(), cpu_time());
    sleep(IDLE_WINDOW).await;
    let cpu = cpu_time().saturating_sub(start.1);
    let wall = start.0.elapsed();
    let wire_after = (hosts[0].wire)();

    #[allow(clippy::cast_precision_loss)] // rates for a report
    let hub_bytes_per_sec = wire_before.zip(wire_after).map(|(before, after)| {
        ((after.sent - before.sent) + (after.received - before.received)) as f64
            / wall.as_secs_f64()
    });
    println!(
        "{}",
        json!({
            "measurement": "idle connections",
            "backend": backend.name(),
            "timers": timers.report(),
            "connections": connections,
            "links_unbound": unbound,
            "link_secs": link_time.as_secs_f64(),
            "secs": wall.as_secs_f64(),
            "process_cpu_cores": cpu.as_secs_f64() / wall.as_secs_f64(),
            "hub_bytes_per_sec": hub_bytes_per_sec,
            "hub_bytes_per_sec_per_connection":
                hub_bytes_per_sec.map(|rate| rate / f64::from(connections)),
        })
    );
}

/// Idle iroh connections from a hub to `connections` peers over a
/// [`Star`]. Bytes are the hub's; CPU is the whole process, every peer,
/// bridge and the relay included.
async fn delayed_idle(
    connections: u32,
    hub_dials: u32,
    rtt: Duration,
    watch: Duration,
    blocked: bool,
    timers: PathTimers,
) {
    let star = Star::bind(SEED, connections, hub_dials, rtt, |config| {
        timers.apply(config);
    })
    .await;
    let (hub, peers, bridges) = (&star.hub, &star.peers, &star.bridges);
    let on = |kind: PathKind| star.on(kind);
    let direct = || on(PathKind::Direct);
    let link_start = Instant::now();
    let _ = timeout(MESH_BUDGET, async {
        while direct() < peers.len() {
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    let link_secs = link_start.elapsed().as_secs_f64();
    let linked_direct = direct();
    if blocked {
        star.set_open(false);
        let _ = timeout(MESH_BUDGET, async {
            while on(PathKind::Relayed) < peers.len() {
                sleep(Duration::from_millis(100)).await;
            }
        })
        .await;
    }
    sleep(Duration::from_secs(10)).await;

    let punches = |peers: &[Arc<IrohAdapter>]| {
        peers
            .iter()
            .map(|peer| peer.path_traffic().hole_punch_rounds)
            .sum::<u64>()
    };
    let redials = |peers: &[Arc<IrohAdapter>]| peers.iter().map(|peer| peer.redials()).sum::<u64>();
    let all = || peers.iter().chain([hub]).cloned().collect::<Vec<_>>();
    let refused = || hub.redials_refused();
    let (traffic_before, paths_before) = (hub.traffic(), hub.path_traffic());
    let (punches_before, redials_before) = (punches(&all()), redials(&all()));
    let (hub_redials_before, refused_before) = (hub.redials(), refused());
    let start = (Instant::now(), cpu_time());
    sleep(watch).await;
    let cpu = cpu_time().saturating_sub(start.1);
    let secs = start.0.elapsed().as_secs_f64();
    let (traffic_after, paths_after) = (hub.traffic(), hub.path_traffic());

    let fallbacks: u64 = peers
        .iter()
        .filter_map(|peer| hub.path_status(peer.local_endpoint_id()))
        .map(|status| status.fallbacks)
        .sum();
    #[allow(clippy::cast_precision_loss)] // rates for a report
    let rate = |bytes: u64| bytes as f64 / secs;
    let connection_bytes = (traffic_after.sent - traffic_before.sent)
        + (traffic_after.received - traffic_before.received);
    let direct_bytes = (paths_after.direct_sent - paths_before.direct_sent)
        + (paths_after.direct_received - paths_before.direct_received);
    let relay_bytes = (paths_after.relay_sent - paths_before.relay_sent)
        + (paths_after.relay_received - paths_before.relay_received);
    let per_connection = |bytes: u64| rate(bytes) / f64::from(connections);
    println!(
        "{}",
        json!({
            "measurement": "idle connections with delay",
            "backend": "iroh",
            "timers": timers.report(),
            "connections": connections,
            "linked_direct": linked_direct,
            "link_secs": link_secs,
            "bridge_rtt_ms": rtt.as_millis(),
            "secs": secs,
            "process_cpu_cores": cpu.as_secs_f64() / secs,
            "hub_bytes_per_sec": rate(connection_bytes),
            "hub_bytes_per_sec_per_connection": per_connection(connection_bytes),
            "hub_direct_bytes_per_sec_per_connection": per_connection(direct_bytes),
            "hub_relay_bytes_per_sec_per_connection": per_connection(relay_bytes),
            "blocked": blocked,
            "relayed_at_end": on(PathKind::Relayed),
            "hub_dials": hub_dials.min(connections),
            "hole_punch_rounds": punches(&all()) - punches_before,
            "redials": redials(&all()) - redials_before,
            "redials_by_hub": hub.redials() - hub_redials_before,
            "redials_refused_by_hub": refused() - refused_before,
            "fallbacks": fallbacks,
            "bridge_datagrams_dropped": bridges.iter().map(UdpBridge::dropped).sum::<u64>(),
        })
    );
    star.shutdown().await.expect("the relay stops");
}

/// One iroh host carrying validator `index` of `fixtures`, checking
/// signatures with `verifier`.
async fn iroh_host(
    fixtures: &IrohFixtures,
    index: u32,
    shards: &[ShardId],
    bootstrap: Option<EndpointAddr>,
    timers: PathTimers,
    verifier: Arc<dyn Verifier>,
) -> (Arc<IrohAdapter>, Arc<IrohNetwork>) {
    let bind_addr: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let mut config = IrohConfig::for_testing(fixtures.network_key(index), bind_addr);
    config.bootstrap_peers = bootstrap.into_iter().collect();
    timers.apply(&mut config);
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
    let pool: Arc<dyn RequestPool> =
        Arc::new(RequestStreams::new(Arc::clone(&adapter), Duration::ZERO));
    let network = Arc::new(IrohNetwork::new(
        Arc::clone(&adapter),
        Arc::new(IrohRequestManager::new(
            pool,
            IrohRequestManagerConfig::default(),
        )),
        Handle::current(),
        registry,
        topology(fixtures.genesis_validators()),
        Duration::ZERO,
    ));
    (adapter, network)
}

/// `record` at `sequence`, signed by `signer` when `forged` is false and
/// carrying a signature over other bytes when it is true.
fn address_record(
    record: &ValidatorAddressGossip,
    sequence: u64,
    signer: &dyn Signer,
    forged: bool,
) -> ValidatorAddressGossip {
    let message = if forged {
        b"not this record".to_vec()
    } else {
        signed_bytes(
            &ValidatorAddressMessage::new(&record.peer_id, &record.addresses, sequence),
            &NetworkDefinition::simulator(),
        )
    };
    ValidatorAddressGossip {
        sequence,
        signature: signer.sign(&message).expect("the fixture key signs"),
        ..record.clone()
    }
}

/// A peer sends a receiver forged address records at `rate`, a record it
/// signed after every `forged_per_signed` of them, for `watch`. Signature
/// checks are the receiver's alone; CPU is the whole process, the sender's
/// signing included.
async fn reject_flood(rate: u32, forged_per_signed: u32, watch: Duration, follower: bool) {
    let fixtures = IrohFixtures::new(SEED, 2);
    let counted = Arc::new(CountingVerifier::default());
    let receiver_shards = if follower {
        Vec::new()
    } else {
        vec![ShardId::ROOT]
    };
    let (receiver, _receiver_network) = iroh_host(
        &fixtures,
        0,
        &receiver_shards,
        None,
        PathTimers::default(),
        Arc::clone(&counted) as Arc<dyn Verifier>,
    )
    .await;
    let (sender, sender_network) = iroh_host(
        &fixtures,
        1,
        &[ShardId::ROOT],
        Some(receiver.endpoint_addr()),
        PathTimers::default(),
        Arc::new(BlsVerifier),
    )
    .await;
    let bound = timeout(MESH_BUDGET, async {
        while receiver.peer_for_validator(vid(1)).is_none()
            || sender.peer_for_validator(vid(0)).is_none()
            || sender.address_records().is_empty()
        {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(bound.is_ok(), "the pair binds");
    // Let the pair's own records and handshakes settle before watching.
    sleep(Duration::from_secs(3)).await;

    let own = sender.address_records().remove(0);
    let signer = fixtures.signer(1);
    let mut tick = interval(Duration::from_secs(1) / rate);
    let before = (counted.checked(), counted.refused(), counted.time());
    let start = (Instant::now(), cpu_time());
    let mut sent = 0u64;
    while start.0.elapsed() < watch {
        tick.tick().await;
        sent += 1;
        let forged = !sent.is_multiple_of(u64::from(forged_per_signed + 1));
        let record = address_record(&own, own.sequence + sent, signer.as_ref(), forged);
        sender_network.broadcast_global(&record);
    }
    let cpu = cpu_time().saturating_sub(start.1);
    let wall = start.0.elapsed().as_secs_f64();
    let checked = counted.checked() - before.0;
    let refused = counted.refused() - before.1;
    let verify_time = counted.time().saturating_sub(before.2);

    #[allow(clippy::cast_precision_loss)] // rates for a report
    let per_sec = |count: u64| count as f64 / wall;
    println!(
        "{}",
        json!({
            "measurement": "reject flood",
            "backend": "iroh",
            "receiver_serves_a_shard": !follower,
            "forged_per_signed": forged_per_signed,
            "secs": wall,
            "sent_per_sec": per_sec(sent),
            "receiver_checks_per_sec": per_sec(checked),
            "receiver_refused_checks_per_sec": per_sec(refused),
            "receiver_check_cores": verify_time.as_secs_f64() / wall,
            "receiver_mean_check_us": verify_time.as_secs_f64() * 1e6 / per_sec(checked) / wall,
            "process_cpu_cores": cpu.as_secs_f64() / wall,
        })
    );
}

/// A peer sends a receiver 2 KiB global items at `rate` for `watch`, and the
/// receiver's handler answers each with `refusal`. Counts the items the
/// receiver judged: what the sender made it spend.
async fn refused_flood(rate: u32, refusal: Refusal, watch: Duration) {
    let fixtures = IrohFixtures::new(SEED, 2);
    let (receiver, receiver_network) = iroh_host(
        &fixtures,
        0,
        &[ShardId::ROOT],
        None,
        PathTimers::default(),
        Arc::new(BlsVerifier),
    )
    .await;
    let (sender, sender_network) = iroh_host(
        &fixtures,
        1,
        &[ShardId::ROOT],
        Some(receiver.endpoint_addr()),
        PathTimers::default(),
        Arc::new(BlsVerifier),
    )
    .await;
    let bound = timeout(MESH_BUDGET, async {
        while receiver.peer_for_validator(vid(1)).is_none()
            || sender.peer_for_validator(vid(0)).is_none()
        {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(bound.is_ok(), "the pair binds");
    sleep(Duration::from_secs(3)).await;

    let judged = Arc::new(AtomicU64::new(0));
    let counted = Arc::clone(&judged);
    receiver_network.register_gossip_handler(move |_: Committed, _: ShardId| {
        counted.fetch_add(1, Ordering::Relaxed);
        match refusal {
            Refusal::Reject => Verdict::Reject,
            Refusal::Ignore => Verdict::Ignore,
        }
    });

    let mut tick = interval(Duration::from_secs(1) / rate);
    let start = (Instant::now(), cpu_time());
    let mut sent = 0u64;
    while start.0.elapsed() < watch {
        tick.tick().await;
        sent += 1;
        sender_network.broadcast_global(&Committed {
            seq: sent,
            body: vec![7; HEADER_BYTES],
        });
    }
    let cpu = cpu_time().saturating_sub(start.1);
    let wall = start.0.elapsed().as_secs_f64();

    #[allow(clippy::cast_precision_loss)] // rates for a report
    let per_sec = |count: u64| count as f64 / wall;
    println!(
        "{}",
        json!({
            "measurement": "refused flood",
            "backend": "iroh",
            "verdict": match refusal {
                Refusal::Reject => "reject",
                Refusal::Ignore => "ignore",
            },
            "secs": wall,
            "sent_per_sec": per_sec(sent),
            "receiver_judged_per_sec": per_sec(judged.load(Ordering::Relaxed)),
            "receiver_judged": judged.load(Ordering::Relaxed),
            "process_cpu_cores": cpu.as_secs_f64() / wall,
        })
    );
}

/// A peer notifies a receiver 2 KiB headers at `rate` for `watch`, each under
/// a signature over other bytes. The receiver checks every one it is handed
/// and answers `judged`. Signature checks are the receiver's alone.
async fn notify_flood(rate: u32, judged: Judged, watch: Duration) {
    let fixtures = IrohFixtures::new(SEED, 2);
    let counted = Arc::new(CountingVerifier::default());
    let (receiver, receiver_network) = iroh_host(
        &fixtures,
        0,
        &[ShardId::ROOT],
        None,
        PathTimers::default(),
        Arc::new(BlsVerifier),
    )
    .await;
    let (sender, sender_network) = iroh_host(
        &fixtures,
        1,
        &[ShardId::ROOT],
        Some(receiver.endpoint_addr()),
        PathTimers::default(),
        Arc::new(BlsVerifier),
    )
    .await;
    let bound = timeout(MESH_BUDGET, async {
        while receiver.peer_for_validator(vid(1)).is_none()
            || sender.peer_for_validator(vid(0)).is_none()
        {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(bound.is_ok(), "the pair binds");
    sleep(Duration::from_secs(3)).await;

    let proposer = fixtures.validator_key_map()[&vid(1)];
    let check = Arc::clone(&counted);
    receiver_network.register_notification_handler(move |header: SignedHeader| {
        if check.verify(&proposer, &header.body, &header.signature) {
            return Verdict::Accept;
        }
        match judged {
            Judged::Accept => Verdict::Accept,
            Judged::Reject => Verdict::Reject,
        }
    });

    let forged = fixtures
        .signer(1)
        .sign(b"not this header")
        .expect("the fixture key signs");
    let mut tick = interval(Duration::from_secs(1) / rate);
    let before = (counted.checked(), counted.time());
    let start = (Instant::now(), cpu_time());
    let mut sent = 0u64;
    while start.0.elapsed() < watch {
        tick.tick().await;
        sent += 1;
        sender_network.notify(
            &[vid(0)],
            &SignedHeader {
                seq: sent,
                body: vec![7; HEADER_BYTES],
                signature: forged,
            },
        );
    }
    let cpu = cpu_time().saturating_sub(start.1);
    let wall = start.0.elapsed().as_secs_f64();
    let checked = counted.checked() - before.0;
    let verify_time = counted.time().saturating_sub(before.1);

    #[allow(clippy::cast_precision_loss)] // rates for a report
    let per_sec = |count: u64| count as f64 / wall;
    println!(
        "{}",
        json!({
            "measurement": "notify flood",
            "backend": "iroh",
            "verdict": match judged {
                Judged::Accept => "accept",
                Judged::Reject => "reject",
            },
            "secs": wall,
            "sent_per_sec": per_sec(sent),
            "receiver_checks_per_sec": per_sec(checked),
            "receiver_checks": checked,
            "receiver_check_cores": verify_time.as_secs_f64() / wall,
            "process_cpu_cores": cpu.as_secs_f64() / wall,
        })
    );
}

/// For `watch`, `rate` times a second, a forger publishes a false copy of a
/// committed header and an honest peer publishes its own copy of the same
/// header [`HONEST_COPY_LAG`] later. Counts the honest copies that reach
/// the receiver's handler: the forger shuts out the rest.
async fn shadow_flood(rate: u32, watch: Duration) {
    let fixtures = IrohFixtures::new(SEED, 3);
    let host = |index, bootstrap| {
        iroh_host(
            &fixtures,
            index,
            &[ShardId::ROOT],
            bootstrap,
            PathTimers::default(),
            Arc::new(BlsVerifier),
        )
    };
    let (receiver, receiver_network) = host(0, None).await;
    let (forger, forger_network) = host(1, Some(receiver.endpoint_addr())).await;
    let (honest, honest_network) = host(2, Some(receiver.endpoint_addr())).await;
    let bound = timeout(MESH_BUDGET, async {
        while receiver.peer_for_validator(vid(1)).is_none()
            || receiver.peer_for_validator(vid(2)).is_none()
            || forger.peer_for_validator(vid(0)).is_none()
            || honest.peer_for_validator(vid(0)).is_none()
        {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(bound.is_ok(), "the senders bind");
    sleep(Duration::from_secs(3)).await;

    let false_copies = Arc::new(AtomicU64::new(0));
    let honest_copies = Arc::new(AtomicU64::new(0));
    let (judged_false, judged_honest) = (Arc::clone(&false_copies), Arc::clone(&honest_copies));
    receiver_network.register_gossip_handler(move |copy: HeaderCopy, _: ShardId| {
        if copy.forged {
            judged_false.fetch_add(1, Ordering::Relaxed);
            Verdict::Reject
        } else {
            judged_honest.fetch_add(1, Ordering::Relaxed);
            Verdict::Accept
        }
    });

    let mut tick = interval(Duration::from_secs(1) / rate);
    let start = (Instant::now(), cpu_time());
    let mut sent = 0u64;
    while start.0.elapsed() < watch {
        tick.tick().await;
        sent += 1;
        let copy = |sender, forged| HeaderCopy {
            seq: sent,
            sender,
            forged,
            body: vec![7; HEADER_BYTES],
        };
        forger_network.broadcast_global(&copy(1, true));
        sleep(HONEST_COPY_LAG).await;
        honest_network.broadcast_global(&copy(2, false));
    }
    sleep(Duration::from_secs(1)).await;
    let cpu = cpu_time().saturating_sub(start.1);
    let wall = start.0.elapsed().as_secs_f64();
    let reached = honest_copies.load(Ordering::Relaxed);
    println!(
        "{}",
        json!({
            "measurement": "shadow flood",
            "backend": "iroh",
            "secs": wall,
            "headers": sent,
            "false_copies_judged": false_copies.load(Ordering::Relaxed),
            "honest_copies_handled": reached,
            "honest_copies_shut_out": sent.saturating_sub(reached),
            "process_cpu_cores": cpu.as_secs_f64() / wall,
        })
    );
}

/// `dialers` strangers open bind exchanges at a host carrying `validators`
/// validators for `watch`, each leaving once the host has signed, and the
/// host's signatures are counted.
async fn bind_flood(validators: u32, dialers: u32, watch: Duration) {
    let fixtures = IrohFixtures::new(SEED, validators);
    let signers: Vec<Arc<CountingSigner>> = (0..validators)
        .map(|index| Arc::new(CountingSigner::new(fixtures.signer(index))))
        .collect();
    let bind_addr: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let host = IrohAdapter::bind(IrohAdapterArgs {
        config: IrohConfig::for_testing(fixtures.network_key(0), bind_addr),
        network: NetworkDefinition::simulator(),
        vnodes: signers
            .iter()
            .enumerate()
            .map(|(index, signer)| {
                (
                    vid(u32::try_from(index).expect("few validators")),
                    Arc::clone(signer) as Arc<dyn Signer>,
                )
            })
            .collect(),
        local_shards: HashSet::from([ShardId::ROOT]),
        registry: Arc::new(HandlerRegistry::default()),
        validator_keys: fixtures.validator_key_map(),
        verifier: Arc::new(BlsVerifier),
    })
    .await
    .expect("the host binds");
    let target = host.endpoint_addr();

    let signed = || signers.iter().map(|signer| signer.signed()).sum::<u64>();
    let before = signed();
    let start = (Instant::now(), cpu_time());
    let answered = Arc::new(AtomicU64::new(0));
    let refused = Arc::new(AtomicU64::new(0));
    let floods: Vec<_> = (0..dialers)
        .map(|_| {
            let (target, answered, refused) =
                (target.clone(), Arc::clone(&answered), Arc::clone(&refused));
            spawn(async move {
                let stranger = Builder::empty()
                    .preset(presets::Minimal)
                    .relay_mode(RelayMode::Disabled)
                    .clear_ip_transports()
                    .bind_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                    .expect("a loopback socket")
                    .bind()
                    .await
                    .expect("the stranger binds");
                let deadline = Instant::now() + watch;
                while Instant::now() < deadline {
                    if bind_hello(&stranger, target.clone()).await.is_ok() {
                        answered.fetch_add(1, Ordering::Relaxed);
                    } else {
                        refused.fetch_add(1, Ordering::Relaxed);
                    }
                }
                stranger.close().await;
            })
        })
        .collect();
    for flood in floods {
        flood.await.expect("a dialer finishes");
    }
    let cpu = cpu_time().saturating_sub(start.1);
    let wall = start.0.elapsed().as_secs_f64();

    #[allow(clippy::cast_precision_loss)] // rates for a report
    let per_sec = |count: u64| count as f64 / wall;
    println!(
        "{}",
        json!({
            "measurement": "bind flood",
            "backend": "iroh",
            "validators": validators,
            "dialers": dialers,
            "secs": wall,
            "answered_per_sec": per_sec(answered.load(Ordering::Relaxed)),
            "refused_per_sec": per_sec(refused.load(Ordering::Relaxed)),
            "host_signatures_per_sec": per_sec(signed() - before),
            "process_cpu_cores": cpu.as_secs_f64() / wall,
        })
    );
}

/// A receiver, a sender bound to it, and a follower bound to it that
/// refuses what the sender sends it, so it hears only what the receiver
/// forwards.
async fn relay_line(
    fixtures: &IrohFixtures,
) -> (Arc<IrohNetwork>, Arc<IrohNetwork>, Arc<IrohNetwork>) {
    let (receiver, receiver_network) = iroh_host(
        fixtures,
        0,
        &[ShardId::ROOT],
        None,
        PathTimers::default(),
        Arc::new(BlsVerifier),
    )
    .await;
    let (sender, sender_network) = iroh_host(
        fixtures,
        1,
        &[ShardId::ROOT],
        Some(receiver.endpoint_addr()),
        PathTimers::default(),
        Arc::new(BlsVerifier),
    )
    .await;
    let (follower, follower_network) = iroh_host(
        fixtures,
        2,
        &[],
        Some(receiver.endpoint_addr()),
        PathTimers::default(),
        Arc::new(BlsVerifier),
    )
    .await;
    for network in [&receiver_network, &sender_network, &follower_network] {
        network.update_routing_committees(Arc::new(RoutingCommittees::from([(
            ShardId::ROOT,
            vec![vid(0)],
        )])));
    }
    let bound = timeout(MESH_BUDGET, async {
        while receiver.peer_for_validator(vid(1)).is_none()
            || receiver.peer_for_validator(vid(2)).is_none()
            || sender.peer_for_validator(vid(0)).is_none()
            || follower.peer_for_validator(vid(0)).is_none()
        {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(bound.is_ok(), "the line binds");
    // The follower refuses what the sender sends it, so it hears only what
    // the receiver forwards.
    follower.fault_configure(
        HostId(2),
        [
            (receiver.local_endpoint_id(), HostId(0)),
            (sender.local_endpoint_id(), HostId(1)),
        ],
    );
    follower.fault_gate().block_host(HostId(1));
    // The follower subscribes to the hosts it is bound to.
    sleep(Duration::from_secs(6)).await;

    (receiver_network, sender_network, follower_network)
}

/// A sender floods a receiver with 2 KiB global items at `rate` for
/// `watch`. The receiver hands each to a check that takes as long as the
/// shard loop's batch window and finds it false, answering `checked` first;
/// a follower bound to the receiver alone counts what reaches it.
async fn forged_flood(rate: u32, checked: Checked, watch: Duration) {
    /// How long the check takes.
    const CHECK: Duration = Duration::from_millis(15);
    let fixtures = IrohFixtures::with_surplus(SEED, 1, 2);
    let (receiver_network, sender_network, follower_network) = relay_line(&fixtures).await;

    let checks = Arc::new(AtomicU64::new(0));
    let counted = Arc::clone(&checks);
    let network = Arc::clone(&receiver_network);
    let handle = Handle::current();
    receiver_network.register_gossip_handler(move |item: Committed, _: ShardId| {
        let key = VerdictKey::of(&item);
        let (counted, network) = (Arc::clone(&counted), Arc::clone(&network));
        handle.spawn(async move {
            sleep(CHECK).await;
            counted.fetch_add(1, Ordering::Relaxed);
            network.settle(key, Verdict::Reject);
        });
        match checked {
            Checked::Accept => Verdict::Accept,
            Checked::Defer => Verdict::Defer(key),
        }
    });
    let reached = Arc::new(AtomicU64::new(0));
    let counted = Arc::clone(&reached);
    follower_network.register_host_gossip_handler(move |_: Committed| {
        counted.fetch_add(1, Ordering::Relaxed);
    });
    follower_network.register_gossip_handler(|_: Committed, _: ShardId| Verdict::Accept);

    let mut tick = interval(Duration::from_secs(1) / rate);
    let start = (Instant::now(), cpu_time());
    let mut sent = 0u64;
    while start.0.elapsed() < watch {
        tick.tick().await;
        sent += 1;
        sender_network.broadcast_global(&Committed {
            seq: sent,
            body: vec![7; HEADER_BYTES],
        });
    }
    let cpu = cpu_time().saturating_sub(start.1);
    let wall = start.0.elapsed().as_secs_f64();

    #[allow(clippy::cast_precision_loss)] // rates for a report
    let per_sec = |count: u64| count as f64 / wall;
    println!(
        "{}",
        json!({
            "measurement": "forged flood",
            "backend": "iroh",
            "verdict": match checked {
                Checked::Accept => "accept",
                Checked::Defer => "defer",
            },
            "secs": wall,
            "sent_per_sec": per_sec(sent),
            "receiver_checks_per_sec": per_sec(checks.load(Ordering::Relaxed)),
            "follower_reached_per_sec": per_sec(reached.load(Ordering::Relaxed)),
            "process_cpu_cores": cpu.as_secs_f64() / wall,
        })
    );
}

/// Run `measure` over a cluster on `backend`.
macro_rules! on_backend {
    ($backend:expr, $spec:expr, |$hosts:ident| $measure:expr) => {
        match $backend {
            Backend::Iroh => {
                let $hosts = iroh_cluster(&$spec).await;
                $measure
            }
            Backend::Libp2p => {
                let $hosts = libp2p_cluster(&$spec).await;
                $measure
            }
        }
    };
}

#[tokio::main]
#[allow(clippy::too_many_lines)] // one arm per subcommand
async fn main() {
    match Cli::parse().command {
        Command::Notify { backend, peers } => {
            let spec = ClusterSpec {
                hosts: peers + 1,
                seated: peers + 1,
                serves: |_| true,
                meshed: false,
                timers: PathTimers::default(),
            };
            on_backend!(backend, spec, |hosts| notify(backend, hosts, peers).await);
        }
        Command::Range { backend } => {
            let spec = range_cluster();
            on_backend!(backend, spec, |hosts| range(backend, hosts).await);
        }
        Command::Committee { backend, size } => {
            let spec = ClusterSpec {
                hosts: size,
                seated: size,
                serves: |_| true,
                meshed: true,
                timers: PathTimers::default(),
            };
            on_backend!(backend, spec, |hosts| committee(backend, hosts, size).await);
        }
        Command::Idle {
            backend,
            connections,
            timers,
        } => {
            let spec = ClusterSpec {
                hosts: connections + 1,
                seated: connections + 1,
                serves: |_| true,
                meshed: false,
                timers,
            };
            on_backend!(backend, spec, |hosts| idle(
                backend,
                hosts,
                connections,
                timers
            )
            .await);
        }
        Command::DelayedIdle {
            connections,
            rtt_ms,
            secs,
            blocked,
            hub_dials,
            timers,
        } => {
            delayed_idle(
                connections,
                hub_dials,
                Duration::from_millis(rtt_ms),
                Duration::from_secs(secs),
                blocked,
                timers,
            )
            .await;
        }
        Command::RejectFlood {
            rate,
            forged_per_signed,
            secs,
            follower,
        } => {
            reject_flood(rate, forged_per_signed, Duration::from_secs(secs), follower).await;
        }
        Command::GarbageResponder { backend, requests } => {
            let spec = range_cluster();
            on_backend!(backend, spec, |hosts| garbage_responder(
                backend, hosts, requests
            )
            .await);
        }
        Command::BindFlood {
            validators,
            dialers,
            secs,
        } => {
            bind_flood(validators, dialers, Duration::from_secs(secs)).await;
        }
        Command::ForgedFlood {
            rate,
            verdict,
            secs,
        } => {
            forged_flood(rate, verdict, Duration::from_secs(secs)).await;
        }
        Command::RefusedFlood {
            rate,
            verdict,
            secs,
        } => {
            refused_flood(rate, verdict, Duration::from_secs(secs)).await;
        }
        Command::NotifyFlood {
            rate,
            verdict,
            secs,
        } => {
            notify_flood(rate, verdict, Duration::from_secs(secs)).await;
        }
        Command::ShadowFlood { rate, secs } => {
            shadow_flood(rate, Duration::from_secs(secs)).await;
        }
    }
}
