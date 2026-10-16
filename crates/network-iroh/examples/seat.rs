//! One host of a freshly seated committee, for the seating testbed.
//!
//! Every host of the committee runs this, each in its own network
//! namespace behind whatever router its NAT type needs (see
//! `scripts/iroh-seating.sh`). A host binds its endpoint, comes online
//! through the relay, and writes its signed address record to a directory
//! all hosts share. When the coordinator writes the `go` file, every host
//! reads every record, so the address book is warm, and is seated: it is
//! told the committee, as a committee change tells it, and dials every
//! member. From then on it reads each member's path every 100 ms and,
//! after `--secs`, writes when each member was first bound and first
//! direct, and what its path was at the end.
//!
//! ```text
//! seat --index 7 --hosts 128 --relay https://relay.testbed/ --relay-ca relay.crt \
//!     --bind 10.7.0.2:7000 --dir /work/seating --label symmetric
//! ```

use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use clap::Parser;
use hyperscale_crypto_bls::BlsVerifier;
use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};
use hyperscale_network::{HandlerRegistry, Network};
use hyperscale_network_iroh::test_utils::TestFixtures;
use hyperscale_network_iroh::{
    IrohAdapter, IrohAdapterArgs, IrohConfig, IrohNetwork, PathKind, RelayUrl, RequestManager,
    RequestManagerConfig, RequestPool, RequestStreams,
};
use hyperscale_types::network::gossip::ValidatorAddressGossip;
use hyperscale_types::{
    NetworkDefinition, RoutingCommittees, ShardId, TopologySnapshot, ValidatorId,
};
use iroh::tls::CaTlsConfig;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use serde::Serialize;
use serde_json::to_string as to_json;
use tokio::runtime::Handle;
use tokio::time::{interval, sleep, timeout};

/// Seed of every host's keys; every host of a run must use the same one.
const SEED: u64 = 0x5ea7;

/// How long a host waits to reach its relay before it gives up.
const ONLINE_BUDGET: Duration = Duration::from_secs(60);

/// How long a host keeps learning its own addresses after it is online,
/// before it signs its record.
const ADDRESS_SETTLE: Duration = Duration::from_secs(5);

/// Interval at which each member's path is read once seated.
const SAMPLE_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Parser)]
#[command(about = "One host of a freshly seated committee")]
struct Cli {
    /// This host's validator, `0..hosts`.
    #[arg(long)]
    index: u32,
    /// Members of the committee, one per host.
    #[arg(long)]
    hosts: u32,
    /// The relay every host homes on.
    #[arg(long)]
    relay: RelayUrl,
    /// PEM file of the relay's certificate, trusted in place of the
    /// platform's roots.
    #[arg(long)]
    relay_ca: PathBuf,
    /// Socket to bind. Unset binds every interface, in both families.
    #[arg(long)]
    bind: Option<SocketAddr>,
    /// Directory every host shares: `records/`, `go`, and `out/`.
    #[arg(long)]
    dir: PathBuf,
    /// How long the seated host is watched.
    #[arg(long, default_value_t = 150)]
    secs: u64,
    /// The host's NAT type, carried into its report.
    #[arg(long, default_value = "")]
    label: String,
}

/// What one host saw of one member after it was seated.
#[derive(Serialize, Default)]
struct Member {
    validator: u32,
    /// When the member was first bound, in milliseconds after seating.
    bound_ms: Option<u64>,
    /// When the member's connection first selected a direct path.
    direct_ms: Option<u64>,
    /// Time spent relayed after the first direct path.
    relayed_after_direct_ms: u64,
    /// Path selected at the end: "direct", "relay", or none.
    end: Option<&'static str>,
    fallbacks: u64,
}

#[derive(Serialize)]
struct Report {
    index: u32,
    label: String,
    /// Wall clock at seating, in milliseconds since the epoch.
    seated_at_unix_ms: u128,
    /// The addresses this host's record named.
    addresses: Vec<String>,
    secs: f64,
    redials: u64,
    redials_refused: u64,
    members: Vec<Member>,
}

fn vid(index: u32) -> ValidatorId {
    ValidatorId::new(u64::from(index))
}

fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// Write `bytes` to `path` whole, so a reader never sees part of it.
fn write_whole(path: &Path, bytes: &[u8]) {
    let partial = path.with_extension("partial");
    fs::write(&partial, bytes).expect("the shared directory is writable");
    fs::rename(&partial, path).expect("the shared directory is writable");
}

/// Bind this host's endpoint and its network, unseated.
async fn bind(cli: &Cli, fixtures: &TestFixtures) -> (Arc<IrohAdapter>, IrohNetwork) {
    let roots = CertificateDer::pem_file_iter(&cli.relay_ca)
        .expect("the relay certificate is readable")
        .collect::<Result<Vec<_>, _>>()
        .expect("the relay certificate parses");
    let mut config = IrohConfig::new(fixtures.network_key(cli.index));
    config.bind_addr = cli.bind;
    config.port_mapping = false;
    config.relays = vec![cli.relay.clone()];
    config.relay_roots = Some(CaTlsConfig::custom_roots(roots));
    let registry = Arc::new(HandlerRegistry::new(BTreeSet::from([ShardId::ROOT])));
    let adapter = IrohAdapter::bind(IrohAdapterArgs {
        config,
        network: NetworkDefinition::simulator(),
        vnodes: vec![(vid(cli.index), fixtures.signer(cli.index))],
        local_shards: HashSet::from([ShardId::ROOT]),
        registry: Arc::clone(&registry),
        validator_keys: fixtures.validator_key_map(),
        verifier: Arc::new(BlsVerifier),
    })
    .await
    .expect("the host binds");
    let genesis = fixtures.genesis_validators();
    let pool: Arc<dyn RequestPool> =
        Arc::new(RequestStreams::new(Arc::clone(&adapter), Duration::ZERO));
    let network = IrohNetwork::new(
        Arc::clone(&adapter),
        Arc::new(RequestManager::new(pool, RequestManagerConfig::default())),
        Handle::current(),
        registry,
        Arc::new(ArcSwap::from_pointee(TopologySnapshot::new(
            genesis.network,
            1,
            genesis.validators,
        ))),
        Duration::ZERO,
    );
    (adapter, network)
}

/// Write this host's signed address records where every host reads them.
fn publish_records(adapter: &IrohAdapter, record_dir: &Path, index: u32) {
    fs::create_dir_all(record_dir).expect("the shared directory is writable");
    write_whole(
        &record_dir.join(format!("{index}.hbor")),
        &hbor_to_vec(&adapter.address_records()).expect("records encode"),
    );
}

/// Ingest every host's records, warming the address book.
fn read_book(adapter: &IrohAdapter, record_dir: &Path) {
    for entry in fs::read_dir(record_dir).expect("the records are readable") {
        let path = entry.expect("the records are readable").path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("hbor") {
            continue;
        }
        let bytes = fs::read(&path).expect("a record is readable");
        let records: Vec<ValidatorAddressGossip> =
            hbor_from_slice(&bytes).expect("a record decodes");
        for record in &records {
            let _ = adapter.ingest_validator_address(record);
        }
    }
}

/// Read every member's path until `watch` has passed since `seated`.
async fn watch_members(
    adapter: &IrohAdapter,
    cli: &Cli,
    seated: Instant,
    watch: Duration,
) -> Vec<Member> {
    let mut members: Vec<Member> = (0..cli.hosts)
        .filter(|validator| *validator != cli.index)
        .map(|validator| Member {
            validator,
            ..Member::default()
        })
        .collect();
    let mut tick = interval(SAMPLE_INTERVAL);
    while seated.elapsed() < watch {
        tick.tick().await;
        let now = millis(seated.elapsed());
        for member in &mut members {
            let Some(status) = adapter
                .peer_for_validator(vid(member.validator))
                .and_then(|peer| adapter.path_status(peer))
            else {
                member.end = None;
                continue;
            };
            member.bound_ms.get_or_insert(now);
            member.fallbacks = status.fallbacks;
            member.end = match status.kind {
                Some(PathKind::Direct) => {
                    member.direct_ms.get_or_insert(now);
                    Some("direct")
                }
                Some(PathKind::Relayed) => {
                    if member.direct_ms.is_some() {
                        member.relayed_after_direct_ms += millis(SAMPLE_INTERVAL);
                    }
                    Some("relay")
                }
                None => None,
            };
        }
    }
    members
}

#[tokio::main(worker_threads = 2)]
async fn main() {
    let cli = Cli::parse();
    let fixtures = TestFixtures::new(SEED, cli.hosts);
    let (adapter, network) = bind(&cli, &fixtures).await;

    timeout(ONLINE_BUDGET, adapter.online())
        .await
        .expect("the host reaches its relay");
    sleep(ADDRESS_SETTLE).await;
    let addresses = adapter
        .endpoint_addr()
        .addrs
        .iter()
        .map(|addr| format!("{addr:?}"))
        .collect();
    let record_dir = cli.dir.join("records");
    publish_records(&adapter, &record_dir, cli.index);

    while !cli.dir.join("go").exists() {
        sleep(Duration::from_millis(20)).await;
    }
    read_book(&adapter, &record_dir);

    // Seated: the host learns the committee and dials every member.
    let seated = Instant::now();
    let seated_at_unix_ms = unix_ms();
    network.update_routing_committees(Arc::new(RoutingCommittees::from([(
        ShardId::ROOT,
        (0..cli.hosts).map(vid).collect(),
    )])));
    let members = watch_members(&adapter, &cli, seated, Duration::from_secs(cli.secs)).await;

    let report = Report {
        index: cli.index,
        label: cli.label.clone(),
        seated_at_unix_ms,
        addresses,
        secs: seated.elapsed().as_secs_f64(),
        redials: adapter.redials(),
        redials_refused: adapter.redials_refused(),
        members,
    };
    let out_dir = cli.dir.join("out");
    fs::create_dir_all(&out_dir).expect("the shared directory is writable");
    write_whole(
        &out_dir.join(format!("{}.json", cli.index)),
        to_json(&report).expect("a report encodes").as_bytes(),
    );
    adapter.shutdown();
}
