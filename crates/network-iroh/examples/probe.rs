//! Path probe for the iroh transport.
//!
//! Answers, before any backend is built on it, the questions the transport's
//! relay policy rests on: whether a fall back from a direct path to the
//! relay is visible through the path events, how long it takes to be seen,
//! whether a direct connection outlives its relay, and how fast a host is
//! reachable again after its home relay dies.
//!
//! One machine, everything in process:
//!
//! ```text
//! cargo run --release -p hyperscale-network-iroh --features test-utils \
//!     --example probe -- loopback
//! ```
//!
//! How long a cut of a given length stalls a connection and keeps it on the
//! relay, under one setting of the path timers:
//!
//! ```text
//! probe blip --cut-ms 2000 --cut-ms 20000 --path-idle-ms 5000 --path-keep-alive-ms 1500 --redial
//! ```
//!
//! Two machines on different networks, with an `iroh-relay` both can reach
//! at `https://relay.example`:
//!
//! ```text
//! probe listen --relay https://relay.example --seed 1 --port-mapping
//! probe dial   --relay https://relay.example --seed 2 --peer <id listen printed> --secs 600 --port-mapping
//! ```
//!
//! Every path event is printed as one JSON line as it happens; the run ends
//! with a JSON report. `loopback` exits non-zero when a kill condition
//! holds.

use std::error::Error;
use std::io::stderr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use clap::{Args, Parser, Subcommand};
use futures::StreamExt;
use hyperscale_network_iroh::IrohConfig;
use hyperscale_network_iroh::path::{PathKind, RedialSchedule, Redialer, selected};
use hyperscale_network_iroh::testing::{LocalRelay, UdpBridge};
use iroh::endpoint::{
    Builder, Connection, PathEvent, PortmapperConfig, QuicTransportConfig, presets,
};
use iroh::tls::CaTlsConfig;
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayConfig, RelayMap, RelayMode, RelayUrl, SecretKey,
    TransportAddr,
};
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use serde::Serialize;
use serde_json::{json, to_string as to_json, to_string_pretty as to_json_pretty};
use tokio::runtime::Handle;
use tokio::spawn;
use tokio::time::{sleep, timeout};
use tracing_subscriber::{EnvFilter, fmt};

/// Protocol identifier of the probe's connections.
const ALPN: &[u8] = b"hyperscale/probe/1";

/// Spacing of the echo pings a dialer sends.
const PING_INTERVAL: Duration = Duration::from_millis(20);

/// Granularity at which a waited-for condition is polled.
const POLL_INTERVAL: Duration = Duration::from_millis(5);

/// How long a connection has to move onto a direct path.
const DIRECT_BUDGET: Duration = Duration::from_secs(30);

/// How long a fall back to the relay has to show after the direct path is
/// cut. Twice the longest path idle timeout the library allows.
const FALLBACK_BUDGET: Duration = Duration::from_secs(30);

/// How long a connection has to return to a direct path once one exists
/// again. Above the library's periodic upgrade attempt.
const RETURN_BUDGET: Duration = Duration::from_secs(90);

/// How long the pings queued behind a dead path are given to arrive.
const BACKLOG_DRAIN: Duration = Duration::from_secs(2);

/// How long a dial through a stopped relay has to give up.
const DEAD_RELAY_DIAL_BUDGET: Duration = Duration::from_secs(45);

/// How long a connection is watched after its relay stops.
const RELAY_OUTAGE_WATCH: Duration = Duration::from_secs(20);

/// How long a host has to become reachable through its second relay.
const FAILOVER_BUDGET: Duration = Duration::from_secs(120);

type Outcome<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Parser)]
#[command(about = "Path probe for the iroh transport")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run every loopback measurement in one process.
    Loopback {
        /// How long a settled direct connection is observed before it is
        /// disturbed.
        #[arg(long, default_value_t = 10)]
        hold_secs: u64,
        #[command(flatten)]
        tuning: Tuning,
    },
    /// Cut the direct path of one loopback connection for set times, and
    /// time how long its traffic stalls and how long it then stays relayed.
    Blip {
        /// Length of a cut, in milliseconds; repeat to try several.
        #[arg(long, required = true)]
        cut_ms: Vec<u64>,
        /// Cuts of each length.
        #[arg(long, default_value_t = 2)]
        repeats: u32,
        /// While the connection is relayed, re-dial the peer as the backend
        /// does, on its default schedule unless `--redial-interval-ms` is
        /// given. A new connection makes the endpoint try a hole punch at
        /// once instead of at its next upgrade check.
        #[arg(long)]
        redial: bool,
        /// Wait before the first re-dial, in milliseconds.
        #[arg(long, requires = "redial")]
        redial_interval_ms: Option<u64>,
        #[command(flatten)]
        tuning: Tuning,
    },
    /// Accept connections, echo their pings, and print their path events.
    Listen {
        #[command(flatten)]
        host: HostArgs,
    },
    /// Dial a listener, ping it, and report how its path behaved.
    Dial {
        #[command(flatten)]
        host: HostArgs,
        /// Endpoint id the listener printed.
        #[arg(long)]
        peer: EndpointId,
        /// A direct address of the listener, when one is known.
        #[arg(long)]
        addr: Vec<SocketAddr>,
        /// How long to hold the connection.
        #[arg(long, default_value_t = 600)]
        secs: u64,
    },
}

/// Path timers under test. Unset fields keep the library's defaults.
#[derive(Args, Clone, Copy, Serialize)]
struct Tuning {
    /// Idle time after which a path is abandoned, in milliseconds.
    #[arg(long)]
    path_idle_ms: Option<u64>,
    /// Interval of the keep alive that holds each path open, in milliseconds.
    #[arg(long)]
    path_keep_alive_ms: Option<u64>,
}

#[derive(Args)]
struct HostArgs {
    /// Relay this host homes on; repeat to name a second.
    #[arg(long, required = true)]
    relay: Vec<RelayUrl>,
    /// Byte the fixed secret key is filled with.
    #[arg(long)]
    seed: u8,
    /// Socket to bind instead of every interface; repeat to bind one in
    /// each address family.
    #[arg(long)]
    bind: Vec<SocketAddr>,
    /// PEM file of the only certificates trusted for the relays' TLS. A
    /// relay with a self-signed certificate serves QUIC address discovery,
    /// through which a host behind NAT learns its outside address, only to
    /// hosts that trust it.
    #[arg(long)]
    relay_ca: Option<PathBuf>,
    /// Ask the local router for a port mapping, as a host on a home
    /// connection should. Off unless given, because the mapper reaches the
    /// router even from a host bound to loopback.
    #[arg(long)]
    port_mapping: bool,
    #[command(flatten)]
    tuning: Tuning,
}

/// A path kind as the reports spell it.
const fn kind_name(kind: PathKind) -> &'static str {
    match kind {
        PathKind::Direct => "direct",
        PathKind::Relayed => "relay",
    }
}

/// One path event as a side saw it.
#[derive(Clone, Serialize)]
struct Observation {
    at_ms: u64,
    side: &'static str,
    event: &'static str,
    kind: Option<&'static str>,
    addr: String,
}

/// Collects path events from every watched connection on one clock.
#[derive(Clone)]
struct Recorder {
    origin: Instant,
    events: Arc<Mutex<Vec<Observation>>>,
}

impl Recorder {
    fn new() -> Self {
        Self {
            origin: Instant::now(),
            events: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn now_ms(&self) -> u64 {
        millis(self.origin.elapsed())
    }

    fn record(&self, side: &'static str, event: &'static str, addr: Option<&TransportAddr>) {
        let observation = Observation {
            at_ms: self.now_ms(),
            side,
            event,
            kind: addr.map(|addr| kind_name(PathKind::of(addr))),
            addr: addr.map_or_default(ToString::to_string),
        };
        println!("{}", to_json(&observation).expect("an observation encodes"));
        self.events.lock().expect("recorder lock").push(observation);
    }

    /// Record the paths `connection` already holds, then follow its path
    /// events until it closes. Events from before the subscription are not
    /// replayed, so the snapshot is what shows the path a connection began
    /// on.
    fn watch(&self, side: &'static str, connection: &Connection) {
        let mut events = connection.path_events();
        for path in &connection.paths() {
            let event = if path.is_selected() {
                "held-selected"
            } else {
                "held"
            };
            self.record(side, event, Some(path.remote_addr()));
        }
        let recorder = self.clone();
        spawn(async move {
            while let Some(event) = events.next().await {
                let (name, addr) = match &event {
                    PathEvent::Opened { remote_addr, .. } => ("opened", Some(remote_addr)),
                    PathEvent::Closed { remote_addr, .. } => ("closed", Some(remote_addr)),
                    PathEvent::Selected { remote_addr, .. } => ("selected", Some(remote_addr)),
                    PathEvent::Lagged { .. } => ("lagged", None),
                    _ => ("unknown", None),
                };
                recorder.record(side, name, addr);
            }
        });
    }

    /// When `side` first saw a path of `kind` selected at or after `since_ms`.
    fn selected_at(&self, side: &'static str, kind: PathKind, since_ms: u64) -> Option<u64> {
        self.events
            .lock()
            .expect("recorder lock")
            .iter()
            .find(|o| {
                o.side == side
                    && o.event == "selected"
                    && o.kind == Some(kind_name(kind))
                    && o.at_ms >= since_ms
            })
            .map(|o| o.at_ms)
    }
}

/// One echoed ping.
#[derive(Clone, Copy)]
struct Sample {
    at_ms: u64,
    rtt_us: u64,
    kind: Option<PathKind>,
}

/// Echo latency over a stretch of a connection's life.
#[derive(Serialize)]
struct Window {
    pings: usize,
    on_direct: usize,
    on_relay: usize,
    rtt_p50_us: u64,
    rtt_p99_us: u64,
    /// Longest stretch with no echo arriving, edges included.
    longest_silence_ms: u64,
}

/// Pings a peer on one stream and keeps every echo's latency.
#[derive(Clone)]
struct Pinger {
    recorder: Recorder,
    samples: Arc<Mutex<Vec<Sample>>>,
}

impl Pinger {
    /// Open a stream on `connection` and ping across it until it closes.
    async fn start(connection: &Connection, recorder: &Recorder) -> Outcome<Self> {
        let (mut send, mut recv) = connection.open_bi().await?;
        let pinger = Self {
            recorder: recorder.clone(),
            samples: Arc::new(Mutex::new(Vec::new())),
        };

        let origin = recorder.origin;
        spawn(async move {
            loop {
                let stamp = micros(origin.elapsed()).to_le_bytes();
                if send.write_all(&stamp).await.is_err() {
                    return;
                }
                sleep(PING_INTERVAL).await;
            }
        });

        let samples = Arc::clone(&pinger.samples);
        let connection = connection.clone();
        spawn(async move {
            let mut echoed = [0u8; 8];
            while recv.read_exact(&mut echoed).await.is_ok() {
                let now = origin.elapsed();
                let sample = Sample {
                    at_ms: millis(now),
                    rtt_us: micros(now).saturating_sub(u64::from_le_bytes(echoed)),
                    kind: selected(&connection),
                };
                samples.lock().expect("sample lock").push(sample);
            }
        });

        Ok(pinger)
    }

    /// Echo latency between `from_ms` and now.
    fn since(&self, from_ms: u64) -> Window {
        let until_ms = self.recorder.now_ms();
        let samples: Vec<Sample> = self
            .samples
            .lock()
            .expect("sample lock")
            .iter()
            .filter(|s| s.at_ms >= from_ms)
            .copied()
            .collect();

        let mut longest_silence_ms = 0;
        let mut last = from_ms;
        for sample in &samples {
            longest_silence_ms = longest_silence_ms.max(sample.at_ms - last);
            last = sample.at_ms;
        }
        longest_silence_ms = longest_silence_ms.max(until_ms.saturating_sub(last));

        let mut rtts: Vec<u64> = samples.iter().map(|s| s.rtt_us).collect();
        rtts.sort_unstable();
        let percentile = |per_mille: usize| {
            rtts.get((rtts.len() * per_mille / 1000).min(rtts.len().saturating_sub(1)))
                .copied()
                .unwrap_or(0)
        };
        let on = |kind| samples.iter().filter(|s| s.kind == Some(kind)).count();

        Window {
            pings: samples.len(),
            on_direct: on(PathKind::Direct),
            on_relay: on(PathKind::Relayed),
            rtt_p50_us: percentile(500),
            rtt_p99_us: percentile(990),
            longest_silence_ms,
        }
    }
}

fn millis(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
}

fn micros(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX)
}

/// Whether `connection` holds an open relayed path it is not sending on.
fn holds_idle_relay_path(connection: &Connection) -> bool {
    connection
        .paths()
        .iter()
        .any(|path| path.is_relay() && !path.is_selected())
}

/// Poll `check` until it holds, for at most `limit`.
async fn wait_until(limit: Duration, mut check: impl FnMut() -> bool) -> Option<Duration> {
    let start = Instant::now();
    loop {
        if check() {
            return Some(start.elapsed());
        }
        if start.elapsed() >= limit {
            return None;
        }
        sleep(POLL_INTERVAL).await;
    }
}

/// Echo every stream the peer opens on `connection`.
fn echo(connection: Connection) {
    spawn(async move {
        while let Ok((mut send, mut recv)) = connection.accept_bi().await {
            spawn(async move {
                while let Ok(Some(chunk)) = recv.read_chunk(usize::MAX).await {
                    if send.write_chunk(chunk).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
}

/// Accept connections on `endpoint` forever, echoing each and recording its
/// path events as `side`.
fn serve(endpoint: &Endpoint, side: &'static str, recorder: &Recorder) {
    let endpoint = endpoint.clone();
    let recorder = recorder.clone();
    spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let Ok(connection) = incoming.await else {
                continue;
            };
            recorder.watch(side, &connection);
            echo(connection);
        }
    });
}

/// What an endpoint is bound with.
struct Binding {
    seed: u8,
    bind: Vec<SocketAddr>,
    relays: RelayMode,
    port_mapping: PortmapperConfig,
    relay_ca: Option<CaTlsConfig>,
    tuning: Tuning,
}

async fn bind(binding: Binding) -> Outcome<Endpoint> {
    let mut transport = QuicTransportConfig::builder();
    if let Some(ms) = binding.tuning.path_idle_ms {
        transport = transport.default_path_max_idle_timeout(Duration::from_millis(ms));
    }
    if let Some(ms) = binding.tuning.path_keep_alive_ms {
        transport = transport.default_path_keep_alive_interval(Duration::from_millis(ms));
    }
    let mut builder = Builder::empty()
        .preset(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&[binding.seed; 32]))
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(binding.relays)
        .portmapper_config(binding.port_mapping)
        .transport_config(transport.build());
    if !binding.bind.is_empty() {
        builder = builder.clear_ip_transports();
    }
    for addr in binding.bind {
        builder = builder.bind_addr(addr)?;
    }
    if let Some(ca) = binding.relay_ca {
        builder = builder.ca_tls_config(ca);
    }
    Ok(builder.bind().await?)
}

/// Relay mode naming loopback relays, which serve no address discovery.
fn loopback_relays(relays: &[&LocalRelay]) -> RelayMode {
    RelayMode::Custom(RelayMap::from_iter(
        relays
            .iter()
            .map(|relay| RelayConfig::new(relay.url(), None)),
    ))
}

async fn bind_on_loopback(
    seed: u8,
    ip: impl Into<IpAddr>,
    relays: &[&LocalRelay],
    tuning: Tuning,
) -> Outcome<Endpoint> {
    bind(Binding {
        seed,
        bind: vec![SocketAddr::new(ip.into(), 0)],
        relays: loopback_relays(relays),
        port_mapping: PortmapperConfig::Disabled,
        relay_ca: None,
        tuning,
    })
    .await
}

/// The socket `endpoint` bound.
fn socket_of(endpoint: &Endpoint) -> Outcome<SocketAddr> {
    endpoint
        .bound_sockets()
        .into_iter()
        .next()
        .ok_or_else(|| "the endpoint bound no socket".into())
}

async fn online(endpoint: &Endpoint) -> Outcome<()> {
    timeout(Duration::from_secs(20), endpoint.online())
        .await
        .map_err(|_| "the endpoint reached no relay".into())
}

/// The relay `endpoint` currently homes on.
fn home_relay(endpoint: &Endpoint) -> Option<RelayUrl> {
    endpoint.addr().relay_urls().next().cloned()
}

/// A direct path was cut and later restored under a live connection.
#[derive(Serialize)]
struct Fallback {
    /// Whether both sides reported the relayed path selected.
    observed: bool,
    /// From the cut to the dialer's `Selected` event for the relayed path.
    dialer_event_after_ms: Option<u64>,
    /// From the cut to the listener's `Selected` event for the relayed path.
    listener_event_after_ms: Option<u64>,
    /// From the cut to the dialer's path list showing the relayed path
    /// selected, polled.
    dialer_path_list_after_ms: Option<u64>,
    /// Echo latency from the cut until the relayed path carried traffic.
    while_falling_back: Window,
    /// Echo latency on the relayed path.
    while_relayed: Window,
    /// From the path's restoration to the dialer's `Selected` event for a
    /// direct path.
    returned_to_direct_after_ms: Option<u64>,
}

/// The only relay stopped under a connection on a direct path.
#[derive(Serialize)]
struct RelayOutage {
    connection_survived: bool,
    stayed_direct: bool,
    during: Window,
    /// A third host dialing the listener by direct address alone.
    direct_dial_ms: Option<u64>,
    /// A third host dialing the listener by relay alone, which cannot work:
    /// how long the attempt takes to fail.
    relay_only_dial_failed_after_ms: Option<u64>,
}

/// A host's home relay stopped while its second relay stayed up.
#[derive(Serialize)]
struct Failover {
    home_before: Option<String>,
    home_after: Option<String>,
    /// From the stop to the host naming the second relay as its home.
    rehomed_after_ms: Option<u64>,
    /// From the stop to a relay only peer, dialing every second with both
    /// relays named, getting an echo back.
    reachable_after_ms: Option<u64>,
    dial_attempts: u32,
}

#[derive(Serialize)]
struct LoopbackReport {
    iroh: &'static str,
    tuning: Tuning,
    /// From dialing by relay alone to a direct path being selected.
    relay_to_direct_ms: Option<u64>,
    /// Whether the relayed path stayed open, unselected, while the direct
    /// path carried the connection.
    relay_path_kept_open: bool,
    settled: Window,
    fallback: Fallback,
    relay_outage: RelayOutage,
    failover: Failover,
    /// A fall back to the relay did not show through the path events.
    kill_fallback_not_visible: bool,
    /// A connection on a direct path died when its relay did.
    kill_direct_died_with_relay: bool,
    events: Vec<Observation>,
}

#[allow(clippy::too_many_lines)] // one scripted run; each step reads the state the last one left
async fn loopback(hold: Duration, tuning: Tuning) -> Outcome<LoopbackReport> {
    let recorder = Recorder::new();
    let relay = LocalRelay::spawn().await?;

    // The listener lives on IPv4 loopback and the dialer on IPv6 loopback,
    // so the bridge is the only direct path between them.
    let listener = bind_on_loopback(1, Ipv4Addr::LOCALHOST, &[&relay], tuning).await?;
    let dialer = bind_on_loopback(2, Ipv6Addr::LOCALHOST, &[&relay], tuning).await?;
    let bridge = UdpBridge::spawn(socket_of(&listener)?, socket_of(&dialer)?).await?;
    listener.add_external_addr(bridge.seen_by_right()).await;
    dialer.add_external_addr(bridge.seen_by_left()).await;
    online(&listener).await?;
    online(&dialer).await?;
    serve(&listener, "listener", &recorder);

    let dialed_ms = recorder.now_ms();
    let connection = dialer
        .connect(
            EndpointAddr::new(listener.id()).with_relay_url(relay.url()),
            ALPN,
        )
        .await?;
    recorder.watch("dialer", &connection);
    let pinger = Pinger::start(&connection, &recorder).await?;

    let relay_to_direct_ms = wait_until(DIRECT_BUDGET, || {
        selected(&connection) == Some(PathKind::Direct)
    })
    .await
    .map(|_| recorder.now_ms() - dialed_ms);

    // Settled on the direct path: is the relayed path still held?
    let settled_ms = recorder.now_ms();
    let mut relay_path_kept_open = true;
    let hold_start = Instant::now();
    while hold_start.elapsed() < hold {
        relay_path_kept_open &= holds_idle_relay_path(&connection);
        sleep(Duration::from_millis(100)).await;
    }
    let settled = pinger.since(settled_ms);

    // Cut the direct path under the connection.
    let cut_ms = recorder.now_ms();
    bridge.set_open(false);
    let dialer_path_list_after_ms = wait_until(FALLBACK_BUDGET, || {
        selected(&connection) == Some(PathKind::Relayed)
    })
    .await
    .map(|_| recorder.now_ms() - cut_ms);
    // The listener's own event trails the dialer's by at most a path timeout.
    wait_until(FALLBACK_BUDGET, || {
        recorder
            .selected_at("listener", PathKind::Relayed, cut_ms)
            .is_some()
    })
    .await;
    let after_cut = |side| {
        recorder
            .selected_at(side, PathKind::Relayed, cut_ms)
            .map(|at| at - cut_ms)
    };
    let dialer_event_after_ms = after_cut("dialer");
    let listener_event_after_ms = after_cut("listener");
    let while_falling_back = pinger.since(cut_ms);
    // Pings queued during the blackout arrive in a burst once the relayed
    // path carries the stream; let them drain before timing the relay.
    sleep(BACKLOG_DRAIN).await;
    let relayed_ms = recorder.now_ms();
    sleep(Duration::from_secs(3)).await;
    let while_relayed = pinger.since(relayed_ms);

    // Restore it.
    let restored_ms = recorder.now_ms();
    bridge.set_open(true);
    wait_until(RETURN_BUDGET, || {
        selected(&connection) == Some(PathKind::Direct)
    })
    .await;
    let returned_to_direct_after_ms = recorder
        .selected_at("dialer", PathKind::Direct, restored_ms)
        .map(|at| at - restored_ms);

    let fallback = Fallback {
        observed: dialer_event_after_ms.is_some() && listener_event_after_ms.is_some(),
        dialer_event_after_ms,
        listener_event_after_ms,
        dialer_path_list_after_ms,
        while_falling_back,
        while_relayed,
        returned_to_direct_after_ms,
    };

    // Stop the only relay under the direct connection.
    let outage_ms = recorder.now_ms();
    let relay_url = relay.url();
    relay.shutdown().await?;
    sleep(RELAY_OUTAGE_WATCH).await;
    let during = pinger.since(outage_ms);
    let connection_survived =
        connection.close_reason().is_none() && during.longest_silence_ms < 1_000;
    let stayed_direct = selected(&connection) == Some(PathKind::Direct) && during.on_relay == 0;

    // With the relay still down, a host that knows the listener's address
    // reaches it; one that knows only its relay does not.
    let stranger = bind(Binding {
        seed: 3,
        bind: vec![(Ipv4Addr::LOCALHOST, 0).into()],
        relays: RelayMode::Custom(RelayMap::from_iter([RelayConfig::new(
            relay_url.clone(),
            None,
        )])),
        port_mapping: PortmapperConfig::Disabled,
        relay_ca: None,
        tuning,
    })
    .await?;
    let by_address = EndpointAddr::new(listener.id()).with_ip_addr(socket_of(&listener)?);
    let dial_start = Instant::now();
    let direct_dial_ms = match timeout(DIRECT_BUDGET, stranger.connect(by_address, ALPN)).await {
        Ok(Ok(direct)) => {
            Pinger::start(&direct, &recorder).await?;
            Some(millis(dial_start.elapsed()))
        }
        _ => None,
    };
    let by_relay = EndpointAddr::new(dialer.id()).with_relay_url(relay_url);
    let dial_start = Instant::now();
    let relay_only_dial_failed_after_ms =
        match timeout(DEAD_RELAY_DIAL_BUDGET, stranger.connect(by_relay, ALPN)).await {
            Ok(Ok(_)) | Err(_) => None,
            Ok(Err(_)) => Some(millis(dial_start.elapsed())),
        };

    let relay_outage = RelayOutage {
        connection_survived,
        stayed_direct,
        during,
        direct_dial_ms,
        relay_only_dial_failed_after_ms,
    };

    for endpoint in [&listener, &dialer, &stranger] {
        endpoint.close().await;
    }
    let failover = failover(tuning).await?;

    let events = recorder.events.lock().expect("recorder lock").clone();
    Ok(LoopbackReport {
        iroh: "1.3.0",
        tuning,
        relay_to_direct_ms,
        relay_path_kept_open,
        settled,
        kill_fallback_not_visible: !fallback.observed,
        kill_direct_died_with_relay: !relay_outage.connection_survived,
        fallback,
        relay_outage,
        failover,
        events,
    })
}

/// Stop a host's home relay and time how long a peer that can only reach it
/// by relay takes to get through on the second.
async fn failover(tuning: Tuning) -> Outcome<Failover> {
    let first = LocalRelay::spawn().await?;
    let second = LocalRelay::spawn().await?;
    let urls = [first.url(), second.url()];

    // Different address families and no bridge: the pair has no direct path.
    let host = bind_on_loopback(4, Ipv4Addr::LOCALHOST, &[&first, &second], tuning).await?;
    let peer = bind_on_loopback(5, Ipv6Addr::LOCALHOST, &[&first, &second], tuning).await?;
    online(&host).await?;
    online(&peer).await?;
    let recorder = Recorder::new();
    serve(&host, "failover-host", &recorder);

    let home_before = home_relay(&host);
    let (home, spare) = if home_before.as_ref() == Some(&urls[0]) {
        (first, second)
    } else {
        (second, first)
    };
    let stopped = Instant::now();
    home.shutdown().await?;

    let rehome = {
        let host = host.clone();
        let spare_url = spare.url();
        spawn(async move {
            wait_until(FAILOVER_BUDGET, || {
                home_relay(&host).as_ref() == Some(&spare_url)
            })
            .await
            .map(|_| millis(stopped.elapsed()))
        })
    };

    // A signed address record names both relays, so the peer dials with both.
    let record = EndpointAddr::new(host.id())
        .with_relay_url(urls[0].clone())
        .with_relay_url(urls[1].clone());
    let mut dial_attempts = 0;
    let mut reachable_after_ms = None;
    while stopped.elapsed() < FAILOVER_BUDGET {
        dial_attempts += 1;
        let attempt = async {
            let connection = peer.connect(record.clone(), ALPN).await.ok()?;
            let (mut send, mut recv) = connection.open_bi().await.ok()?;
            send.write_all(&[7u8; 8]).await.ok()?;
            let mut echoed = [0u8; 8];
            recv.read_exact(&mut echoed).await.ok()
        };
        if matches!(timeout(Duration::from_secs(5), attempt).await, Ok(Some(()))) {
            reachable_after_ms = Some(millis(stopped.elapsed()));
            break;
        }
        sleep(Duration::from_secs(1)).await;
    }

    let rehomed_after_ms = rehome.await?;
    let home_after = home_relay(&host).map(|url| url.to_string());
    host.close().await;
    peer.close().await;
    spare.shutdown().await?;
    Ok(Failover {
        home_before: home_before.map(|url| url.to_string()),
        home_after,
        rehomed_after_ms,
        reachable_after_ms,
        dial_attempts,
    })
}

/// One timed cut of a direct path.
#[derive(Serialize)]
struct Blip {
    cut_ms: u64,
    /// Whether the connection selected the relayed path after the cut.
    fell_back: bool,
    /// From the cut to the relayed path being selected.
    fell_back_after_ms: Option<u64>,
    /// From the restore to a direct path being selected again, when the
    /// connection had fallen back.
    returned_after_restore_ms: Option<u64>,
    /// How long the relayed path stayed selected.
    relayed_ms: u64,
    /// Echo latency from the cut until traffic was direct again.
    window: Window,
}

#[derive(Serialize)]
struct BlipReport {
    iroh: &'static str,
    tuning: Tuning,
    redial: Option<RedialReport>,
    blips: Vec<Blip>,
}

/// The re-dial schedule a blip run used, and the re-dials it made.
#[derive(Serialize)]
struct RedialReport {
    interval_ms: u64,
    max_interval_ms: u64,
    attempts: u32,
    redials: u64,
}

async fn blip(
    cuts: &[u64],
    repeats: u32,
    redial: Option<RedialSchedule>,
    tuning: Tuning,
) -> Outcome<BlipReport> {
    let recorder = Recorder::new();
    let relay = LocalRelay::spawn().await?;
    let listener = bind_on_loopback(1, Ipv4Addr::LOCALHOST, &[&relay], tuning).await?;
    let dialer = bind_on_loopback(2, Ipv6Addr::LOCALHOST, &[&relay], tuning).await?;
    let bridge = UdpBridge::spawn(socket_of(&listener)?, socket_of(&dialer)?).await?;
    listener.add_external_addr(bridge.seen_by_right()).await;
    dialer.add_external_addr(bridge.seen_by_left()).await;
    online(&listener).await?;
    online(&dialer).await?;
    serve(&listener, "listener", &recorder);

    let target = EndpointAddr::new(listener.id()).with_relay_url(relay.url());
    let connection = dialer.connect(target, ALPN).await?;
    recorder.watch("dialer", &connection);
    let pinger = Pinger::start(&connection, &recorder).await?;
    let redialer = redial.map(|schedule| {
        let redialer = Redialer::new(dialer.clone(), ALPN, schedule);
        redialer.follow(&connection, &Handle::current());
        redialer
    });

    let mut blips = Vec::new();
    let schedule = (0..repeats).flat_map(|_| cuts.iter().copied());
    for (index, cut_ms) in schedule.enumerate() {
        wait_until(RETURN_BUDGET, || {
            selected(&connection) == Some(PathKind::Direct)
        })
        .await;
        // Cuts land at spread offsets from the library's periodic upgrade
        // check, which decides how long a fallen back connection stays
        // relayed.
        let stagger = 3 + (u64::try_from(index).unwrap_or(0) * 11) % 40;
        sleep(Duration::from_secs(stagger)).await;

        let cut_at = recorder.now_ms();
        bridge.set_open(false);
        sleep(Duration::from_millis(cut_ms)).await;
        let restored_at = recorder.now_ms();
        bridge.set_open(true);
        wait_until(RETURN_BUDGET, || {
            selected(&connection) == Some(PathKind::Direct)
        })
        .await;
        sleep(BACKLOG_DRAIN).await;

        let relayed_at = recorder.selected_at("dialer", PathKind::Relayed, cut_at);
        let direct_at =
            relayed_at.and_then(|at| recorder.selected_at("dialer", PathKind::Direct, at));
        let blip = Blip {
            cut_ms,
            fell_back: relayed_at.is_some(),
            fell_back_after_ms: relayed_at.map(|at| at - cut_at),
            returned_after_restore_ms: direct_at.map(|at| at.saturating_sub(restored_at)),
            relayed_ms: relayed_at
                .zip(direct_at)
                .map_or(0, |(relayed, direct)| direct - relayed),
            window: pinger.since(cut_at),
        };
        eprintln!("{}", to_json(&blip).expect("a blip encodes"));
        blips.push(blip);
    }

    listener.close().await;
    dialer.close().await;
    relay.shutdown().await?;
    Ok(BlipReport {
        iroh: "1.3.0",
        tuning,
        redial: redial
            .zip(redialer)
            .map(|(schedule, redialer)| RedialReport {
                interval_ms: millis(schedule.interval),
                max_interval_ms: millis(schedule.max_interval),
                attempts: schedule.attempts,
                redials: redialer.redials(),
            }),
        blips,
    })
}

/// Trust only the certificates in the PEM file at `path`.
fn trusted_roots(path: &Path) -> Outcome<CaTlsConfig> {
    let roots = CertificateDer::pem_file_iter(path)?.collect::<Result<Vec<_>, _>>()?;
    if roots.is_empty() {
        return Err(format!("{} holds no certificate", path.display()).into());
    }
    Ok(CaTlsConfig::custom_roots(roots))
}

async fn bind_host(host: HostArgs) -> Outcome<Endpoint> {
    let endpoint = bind(Binding {
        seed: host.seed,
        bind: host.bind,
        relays: RelayMode::custom(host.relay),
        port_mapping: if host.port_mapping {
            PortmapperConfig::default()
        } else {
            PortmapperConfig::Disabled
        },
        relay_ca: host.relay_ca.as_deref().map(trusted_roots).transpose()?,
        tuning: host.tuning,
    })
    .await?;
    online(&endpoint).await?;
    Ok(endpoint)
}

async fn listen(host: HostArgs) -> Outcome<()> {
    let endpoint = bind_host(host).await?;
    let addr = endpoint.addr();
    println!(
        "{}",
        json!({
            "id": endpoint.id().to_string(),
            "relays": addr.relay_urls().map(ToString::to_string).collect::<Vec<_>>(),
            "addresses": addr.ip_addrs().map(ToString::to_string).collect::<Vec<_>>(),
        })
    );
    serve(&endpoint, "listener", &Recorder::new());
    endpoint.closed().await;
    Ok(())
}

/// How a dialed connection's path behaved over its life.
#[derive(Serialize)]
struct DialReport {
    /// From dialing to a direct path being selected, if one ever was.
    time_to_direct_ms: Option<u64>,
    /// Kind of the selected path a minute after dialing.
    selected_after_a_minute: Option<&'static str>,
    /// Times a relayed path was selected after a direct one had been.
    fallbacks: usize,
    overall: Window,
    events: Vec<Observation>,
}

async fn dial(
    host: HostArgs,
    peer: EndpointId,
    addrs: Vec<SocketAddr>,
    hold: Duration,
) -> Outcome<DialReport> {
    let relays = host.relay.clone();
    let endpoint = bind_host(host).await?;
    let recorder = Recorder::new();
    let target = EndpointAddr::new(peer)
        .with_addrs(relays.into_iter().map(TransportAddr::Relay))
        .with_addrs(addrs.into_iter().map(TransportAddr::Ip));
    let connection = endpoint.connect(target, ALPN).await?;
    recorder.watch("dialer", &connection);
    let pinger = Pinger::start(&connection, &recorder).await?;

    let mut selected_after_a_minute = None;
    let start = Instant::now();
    while start.elapsed() < hold && connection.close_reason().is_none() {
        if selected_after_a_minute.is_none() && start.elapsed() >= Duration::from_mins(1) {
            selected_after_a_minute = selected(&connection).map(kind_name);
        }
        sleep(Duration::from_millis(100)).await;
    }

    let events = recorder.events.lock().expect("recorder lock").clone();
    let selections: Vec<&str> = events
        .iter()
        .filter(|o| o.event == "selected")
        .filter_map(|o| o.kind)
        .collect();
    Ok(DialReport {
        time_to_direct_ms: recorder.selected_at("dialer", PathKind::Direct, 0),
        selected_after_a_minute,
        fallbacks: selections
            .windows(2)
            .filter(|pair| pair == &[kind_name(PathKind::Direct), kind_name(PathKind::Relayed)])
            .count(),
        overall: pinger.since(0),
        events,
    })
    .inspect(|_| connection.close(0u32.into(), b"done"))
}

fn print_report(report: &impl Serialize) {
    println!("{}", to_json_pretty(report).expect("a report encodes"));
}

#[tokio::main]
async fn main() -> Outcome<ExitCode> {
    fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(stderr)
        .init();

    match Cli::parse().command {
        Command::Loopback { hold_secs, tuning } => {
            let report = loopback(Duration::from_secs(hold_secs), tuning).await?;
            print_report(&report);
            if report.kill_fallback_not_visible || report.kill_direct_died_with_relay {
                return Ok(ExitCode::FAILURE);
            }
        }
        Command::Blip {
            cut_ms,
            repeats,
            redial,
            redial_interval_ms,
            tuning,
        } => {
            let schedule = redial.then(|| {
                let defaults = IrohConfig::new(SecretKey::from_bytes(&[0; 32])).redial;
                RedialSchedule {
                    interval: redial_interval_ms.map_or(defaults.interval, Duration::from_millis),
                    ..defaults
                }
            });
            print_report(&blip(&cut_ms, repeats, schedule, tuning).await?);
        }
        Command::Listen { host } => listen(host).await?,
        Command::Dial {
            host,
            peer,
            addr,
            secs,
        } => print_report(&dial(host, peer, addr, Duration::from_secs(secs)).await?),
    }
    Ok(ExitCode::SUCCESS)
}
