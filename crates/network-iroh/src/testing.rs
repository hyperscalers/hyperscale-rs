//! Loopback fixtures for exercising relay and direct paths on one machine.
//!
//! Two endpoints on the same host always find a direct path, so a relayed
//! path cannot be studied there without help. Binding one endpoint to IPv4
//! loopback and the other to IPv6 loopback leaves the pair with no route of
//! their own; a [`UdpBridge`] between them is then the only direct path, and
//! closing it is a UDP blackout between the two hosts that leaves each one's
//! relay link untouched. A [`Star`] puts many such bridged peers around one
//! hub.

use std::collections::HashSet;
use std::hint::spin_loop;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket as StdUdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use hyperscale_crypto::{
    AggregateError, AggregateSignature, ConsensusPublicKey, ConsensusSignature, SignError, Signer,
    VerifiedSignature, Verifier, VrfProof,
};
use hyperscale_crypto_bls::BlsVerifier;
use hyperscale_network::HandlerRegistry;
use hyperscale_types::{NetworkDefinition, ShardId, ValidatorId};
use iroh::{Endpoint, EndpointAddr, RelayUrl};
use iroh_relay::server::{RelayConfig, Server, ServerConfig, SpawnError, SupervisorError};
use simple_dns::rdata::{RData, TXT};
use simple_dns::{CLASS, Packet, ResourceRecord};
use tokio::net::UdpSocket;
use tokio::spawn;
use tokio::task::JoinHandle;
use tokio::time::sleep;

use crate::path::PathKind;
use crate::protocol::ALPN;
use crate::serve_budget::thread_clock;
use crate::test_utils::TestFixtures;
use crate::{IrohAdapter, IrohAdapterArgs, IrohConfig, bind};

/// Largest UDP payload the bridge forwards.
const MAX_DATAGRAM_BYTES: usize = 65_535;

/// A DNS server on loopback that answers TXT queries from a fixed table,
/// for resolving bootstrap domains without the network.
pub struct LocalDns {
    addr: SocketAddr,
    task: JoinHandle<()>,
}

impl LocalDns {
    /// Serve `records`: each name with the TXT values it answers, one
    /// record each.
    ///
    /// # Errors
    ///
    /// When no loopback socket can be bound.
    pub async fn serve(records: Vec<(String, Vec<String>)>) -> io::Result<Self> {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let addr = socket.local_addr()?;
        let task = spawn(async move {
            let mut buf = [0u8; 1500];
            while let Ok((len, from)) = socket.recv_from(&mut buf).await {
                if let Some(reply) = dns_answer(&buf[..len], &records) {
                    let _ = socket.send_to(&reply, from).await;
                }
            }
        });
        Ok(Self { addr, task })
    }

    /// The socket the server answers at.
    #[must_use]
    pub const fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for LocalDns {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The reply to `query` from `records`, or `None` for bytes that are no
/// query.
fn dns_answer(query: &[u8], records: &[(String, Vec<String>)]) -> Option<Vec<u8>> {
    let query = Packet::parse(query).ok()?;
    let mut reply = Packet::new_reply(query.id());
    for question in &query.questions {
        reply.questions.push(question.clone());
        let asked = question.qname.to_string();
        let asked = asked.trim_end_matches('.');
        for (_, values) in records
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case(asked))
        {
            for value in values {
                let txt = TXT::new().with_string(value).ok()?;
                reply.answers.push(ResourceRecord::new(
                    question.qname.clone(),
                    CLASS::IN,
                    60,
                    RData::TXT(txt),
                ));
            }
        }
    }
    reply.build_bytes_vec().ok()
}

/// A relay server on loopback, serving plain HTTP on a free port.
///
/// It offers no QUIC address discovery: endpoints that use it learn their
/// own addresses from their sockets and from what the test configures.
pub struct LocalRelay {
    server: Server,
    url: RelayUrl,
}

impl LocalRelay {
    /// Start a relay on a free loopback port.
    ///
    /// # Errors
    ///
    /// Returns the relay's [`SpawnError`] when the listener cannot bind.
    ///
    /// # Panics
    ///
    /// Panics if the server reports no HTTP address or one that does not
    /// form a URL; both are impossible for a configured relay.
    pub async fn spawn() -> Result<Self, SpawnError> {
        let mut config = ServerConfig::default();
        config.relay = Some(RelayConfig::new((Ipv4Addr::LOCALHOST, 0)));
        let server = Server::spawn(config).await?;
        let addr = server.http_addr().expect("the relay was configured");
        let url = format!("http://{addr}")
            .parse()
            .expect("a socket address forms a relay url");
        Ok(Self { server, url })
    }

    /// The URL endpoints name this relay by.
    #[must_use]
    pub fn url(&self) -> RelayUrl {
        self.url.clone()
    }

    /// Stop the relay, dropping every client link it holds.
    ///
    /// # Errors
    ///
    /// Returns the relay's [`SupervisorError`] when a server task failed.
    pub async fn shutdown(self) -> Result<(), SupervisorError> {
        self.server.shutdown().await
    }
}

/// A userspace UDP path between two sockets of different address families.
///
/// The bridge holds one socket in each family. A datagram that `left` sends
/// to [`Self::seen_by_left`] leaves the bridge's other socket addressed to
/// `right`, and the reverse; each side therefore sees its peer at a stable
/// address in its own family, as it would behind a one to one address
/// translation. Datagrams from any other source are dropped.
pub struct UdpBridge {
    seen_by_left: SocketAddr,
    seen_by_right: SocketAddr,
    open: Arc<AtomicBool>,
    /// Delay each datagram is held for before it is sent on, in
    /// microseconds.
    delay_micros: Arc<AtomicU64>,
    forwarded: Arc<AtomicU64>,
    dropped: Arc<AtomicU64>,
    tasks: [JoinHandle<()>; 2],
}

/// What both legs of a bridge share.
#[derive(Clone)]
struct Link {
    open: Arc<AtomicBool>,
    delay_micros: Arc<AtomicU64>,
    forwarded: Arc<AtomicU64>,
    dropped: Arc<AtomicU64>,
}

impl UdpBridge {
    /// Bridge `left` and `right`, which must be loopback sockets of
    /// different address families.
    ///
    /// # Errors
    ///
    /// Returns the bind error when a bridge socket cannot be opened, or
    /// [`io::ErrorKind::InvalidInput`] when both addresses share a family.
    pub async fn spawn(left: SocketAddr, right: SocketAddr) -> io::Result<Self> {
        if left.is_ipv4() == right.is_ipv4() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the bridged sockets must be of different address families",
            ));
        }
        let facing_left = Arc::new(UdpSocket::bind(loopback_in_family_of(left)).await?);
        let facing_right = Arc::new(UdpSocket::bind(loopback_in_family_of(right)).await?);
        let link = Link {
            open: Arc::new(AtomicBool::new(true)),
            delay_micros: Arc::new(AtomicU64::new(0)),
            forwarded: Arc::new(AtomicU64::new(0)),
            dropped: Arc::new(AtomicU64::new(0)),
        };

        let leg = |from: Arc<UdpSocket>, source: SocketAddr, to: Arc<UdpSocket>, dest| {
            spawn(forward(from, source, to, dest, link.clone()))
        };
        let tasks = [
            leg(
                Arc::clone(&facing_left),
                left,
                Arc::clone(&facing_right),
                right,
            ),
            leg(
                Arc::clone(&facing_right),
                right,
                Arc::clone(&facing_left),
                left,
            ),
        ];

        Ok(Self {
            seen_by_left: facing_left.local_addr()?,
            seen_by_right: facing_right.local_addr()?,
            open: link.open,
            delay_micros: link.delay_micros,
            forwarded: link.forwarded,
            dropped: link.dropped,
            tasks,
        })
    }

    /// The address at which `left` reaches `right`: what `right` advertises
    /// as its external address.
    #[must_use]
    pub const fn seen_by_left(&self) -> SocketAddr {
        self.seen_by_left
    }

    /// The address at which `right` reaches `left`: what `left` advertises
    /// as its external address.
    #[must_use]
    pub const fn seen_by_right(&self) -> SocketAddr {
        self.seen_by_right
    }

    /// Open or close the path. While closed, every datagram is dropped.
    pub fn set_open(&self, open: bool) {
        self.open.store(open, Ordering::Relaxed);
    }

    /// Hold every datagram for `delay` before sending it on, so a round
    /// trip across the bridge takes twice that.
    pub fn set_delay(&self, delay: Duration) {
        let micros = u64::try_from(delay.as_micros()).unwrap_or(u64::MAX);
        self.delay_micros.store(micros, Ordering::Relaxed);
    }

    /// Datagrams carried across since the bridge started.
    #[must_use]
    pub fn forwarded(&self) -> u64 {
        self.forwarded.load(Ordering::Relaxed)
    }

    /// Datagrams dropped, while closed or from an unknown source.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

impl Drop for UdpBridge {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// The loopback address, on a free port, in the family of `addr`.
fn loopback_in_family_of(addr: SocketAddr) -> SocketAddr {
    if addr.is_ipv4() {
        (Ipv4Addr::LOCALHOST, 0).into()
    } else {
        (Ipv6Addr::LOCALHOST, 0).into()
    }
}

/// Carry datagrams that `source` sends to `from` out of `to`, addressed to
/// `dest`.
async fn forward(
    from: Arc<UdpSocket>,
    source: SocketAddr,
    to: Arc<UdpSocket>,
    dest: SocketAddr,
    link: Link,
) {
    let mut buf = vec![0u8; MAX_DATAGRAM_BYTES];
    loop {
        let Ok((len, sender)) = from.recv_from(&mut buf).await else {
            return;
        };
        if sender != source || !link.open.load(Ordering::Relaxed) {
            link.dropped.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        let delay = Duration::from_micros(link.delay_micros.load(Ordering::Relaxed));
        if delay.is_zero() {
            deliver(&to, &buf[..len], dest, &link).await;
        } else {
            // Each datagram waits out the same delay on its own, so order
            // is kept and none holds another back.
            let (to, datagram, link) = (Arc::clone(&to), buf[..len].to_vec(), link.clone());
            spawn(async move {
                sleep(delay).await;
                deliver(&to, &datagram, dest, &link).await;
            });
        }
    }
}

async fn deliver(to: &UdpSocket, datagram: &[u8], dest: SocketAddr, link: &Link) {
    if to.send_to(datagram, dest).await.is_ok() {
        link.forwarded.fetch_add(1, Ordering::Relaxed);
    } else {
        link.dropped.fetch_add(1, Ordering::Relaxed);
    }
}

/// A port on loopback address `ip` held for a host whose bridge must exist
/// before it binds. The port stays taken until the reservation is dropped,
/// just before the host binds it, so no socket opened meanwhile gets it.
struct Reserved {
    socket: StdUdpSocket,
    addr: SocketAddr,
}

impl Reserved {
    fn on(ip: IpAddr) -> Self {
        let socket = StdUdpSocket::bind((ip, 0)).expect("a loopback port is free");
        let addr = socket.local_addr().expect("a bound socket has an address");
        Self { socket, addr }
    }

    /// Give the port up for its host to bind.
    fn release(self) -> SocketAddr {
        drop(self.socket);
        self.addr
    }
}

/// A hub holding an iroh connection to each of its peers over a bridge.
///
/// Every peer has a [`UdpBridge`] of its own, and all are homed on one
/// [`LocalRelay`]. The hub sits on
/// IPv4 loopback and every peer on IPv6, so each bridge is that peer's only
/// direct path and closing them all is the hub's UDP failing while its
/// relay link holds. Peers meet the hub at its bridge address and through
/// the relay, as hosts behind NAT do, so every connection also keeps its
/// relayed path open.
pub struct Star {
    /// The host every peer connects to.
    pub hub: Arc<IrohAdapter>,
    /// The hub's peers, validator `1..` of the fixtures in order.
    pub peers: Vec<Arc<IrohAdapter>>,
    /// The direct path of each peer, in the order of `peers`.
    pub bridges: Vec<UdpBridge>,
    relay: LocalRelay,
}

impl Star {
    /// Stand up a hub with `peers` peers on seeded keys, with `rtt` on every
    /// bridge. The hub dials the first `hub_dials` peers; the others dial
    /// the hub. `configure` adjusts every host's configuration.
    ///
    /// # Panics
    ///
    /// Panics if the relay, a bridge or a host cannot start.
    pub async fn bind(
        seed: u64,
        peers: u32,
        hub_dials: u32,
        rtt: Duration,
        configure: impl Fn(&mut IrohConfig),
    ) -> Self {
        let fixtures = TestFixtures::new(seed, peers + 1);
        let relay = LocalRelay::spawn().await.expect("the relay starts");
        let bind = |index: u32, addr: SocketAddr, bootstrap: Vec<EndpointAddr>| {
            let (fixtures, relay, configure) = (&fixtures, &relay, &configure);
            async move {
                let mut config = IrohConfig::for_testing(fixtures.network_key(index), addr);
                config.relays = vec![relay.url()];
                config.relay_address_discovery = false;
                config.bootstrap_peers = bootstrap;
                configure(&mut config);
                IrohAdapter::bind(IrohAdapterArgs {
                    config,
                    network: NetworkDefinition::simulator(),
                    vnodes: vec![(ValidatorId::new(u64::from(index)), fixtures.signer(index))],
                    local_shards: HashSet::from([ShardId::ROOT]),
                    registry: Arc::new(HandlerRegistry::default()),
                    validator_keys: fixtures.validator_key_map(),
                    verifier: Arc::new(BlsVerifier),
                })
                .await
                .expect("the host binds")
            }
        };

        let hub_socket = Reserved::on(Ipv4Addr::LOCALHOST.into());
        let mut sockets = Vec::new();
        let mut bridges = Vec::new();
        for _ in 0..peers {
            let socket = Reserved::on(Ipv6Addr::LOCALHOST.into());
            let bridge = UdpBridge::spawn(hub_socket.addr, socket.addr)
                .await
                .expect("the bridge opens");
            bridge.set_delay(rtt / 2);
            sockets.push(socket);
            bridges.push(bridge);
        }

        let dialed = usize::try_from(hub_dials.min(peers)).unwrap_or(usize::MAX);
        let mut sockets = sockets.into_iter();
        let mut bound = Vec::new();
        let mut hub_bootstrap = Vec::new();
        for (slot, (socket, bridge)) in sockets.by_ref().zip(&bridges).enumerate().take(dialed) {
            let index = u32::try_from(slot).unwrap_or(u32::MAX) + 1;
            let peer = bind(index, socket.release(), Vec::new()).await;
            hub_bootstrap.push(
                EndpointAddr::new(peer.local_endpoint_id())
                    .with_ip_addr(bridge.seen_by_left())
                    .with_relay_url(relay.url()),
            );
            bound.push(peer);
        }
        let hub = bind(0, hub_socket.release(), hub_bootstrap).await;
        for (slot, (socket, bridge)) in sockets.zip(bridges.iter().skip(dialed)).enumerate() {
            let index = u32::try_from(slot + dialed).unwrap_or(u32::MAX) + 1;
            let hub_addr = EndpointAddr::new(hub.local_endpoint_id())
                .with_ip_addr(bridge.seen_by_right())
                .with_relay_url(relay.url());
            bound.push(bind(index, socket.release(), vec![hub_addr]).await);
        }
        for (peer, bridge) in bound.iter().zip(&bridges) {
            peer.add_external_addr(bridge.seen_by_left()).await;
        }
        Self {
            hub,
            peers: bound,
            bridges,
            relay,
        }
    }

    /// Peers whose connection the hub sees selecting a path of `kind`.
    #[must_use]
    pub fn on(&self, kind: PathKind) -> usize {
        self.peers
            .iter()
            .filter(|peer| {
                self.hub
                    .path_status(peer.local_endpoint_id())
                    .and_then(|status| status.kind)
                    == Some(kind)
            })
            .count()
    }

    /// Open or close every bridge at once.
    pub fn set_open(&self, open: bool) {
        for bridge in &self.bridges {
            bridge.set_open(open);
        }
    }

    /// Stop every host and the relay.
    ///
    /// # Errors
    ///
    /// Returns the relay's error when it does not stop cleanly.
    pub async fn shutdown(self) -> Result<(), SupervisorError> {
        self.hub.shutdown().await;
        for peer in &self.peers {
            peer.shutdown().await;
        }
        self.relay.shutdown().await
    }
}

/// A BLS verifier that counts the single signatures it checks and the time
/// they take, so a test can see the signature work a host's peers make it
/// do. Aggregate and VRF checks pass through uncounted.
#[derive(Debug, Default)]
pub struct CountingVerifier {
    inner: BlsVerifier,
    checked: AtomicU64,
    refused: AtomicU64,
    nanos: AtomicU64,
}

impl CountingVerifier {
    /// Single signatures checked so far.
    #[must_use]
    pub fn checked(&self) -> u64 {
        self.checked.load(Ordering::Relaxed)
    }

    /// Single signatures checked so far that did not verify.
    #[must_use]
    pub fn refused(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }

    /// Wall time spent checking single signatures so far.
    #[must_use]
    pub fn time(&self) -> Duration {
        Duration::from_nanos(self.nanos.load(Ordering::Relaxed))
    }
}

impl Verifier for CountingVerifier {
    fn verify(&self, key: &ConsensusPublicKey, message: &[u8], sig: &ConsensusSignature) -> bool {
        let start = Instant::now();
        let valid = self.inner.verify(key, message, sig);
        let nanos = u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX);
        self.nanos.fetch_add(nanos, Ordering::Relaxed);
        self.checked.fetch_add(1, Ordering::Relaxed);
        if !valid {
            self.refused.fetch_add(1, Ordering::Relaxed);
        }
        valid
    }

    fn aggregate(&self, sigs: &[ConsensusSignature]) -> Result<AggregateSignature, AggregateError> {
        self.inner.aggregate(sigs)
    }

    fn aggregate_verified(
        &self,
        sigs: &[VerifiedSignature],
    ) -> Result<AggregateSignature, AggregateError> {
        self.inner.aggregate_verified(sigs)
    }

    fn verify_aggregate_same_message(
        &self,
        message: &[u8],
        agg: &AggregateSignature,
        keys: &[ConsensusPublicKey],
    ) -> bool {
        self.inner.verify_aggregate_same_message(message, agg, keys)
    }

    fn verify_aggregate_different_messages(
        &self,
        messages: &[&[u8]],
        agg: &AggregateSignature,
        keys: &[ConsensusPublicKey],
    ) -> bool {
        self.inner
            .verify_aggregate_different_messages(messages, agg, keys)
    }

    fn verify_each(
        &self,
        messages: &[&[u8]],
        sigs: &[ConsensusSignature],
        keys: &[ConsensusPublicKey],
    ) -> bool {
        self.inner.verify_each(messages, sigs, keys)
    }

    fn verify_vrf(&self, key: &ConsensusPublicKey, message: &[u8], proof: &VrfProof) -> bool {
        self.inner.verify_vrf(key, message, proof)
    }
}

/// A [`Signer`] that counts what it signs.
#[derive(Debug)]
pub struct CountingSigner {
    inner: Arc<dyn Signer>,
    signed: AtomicU64,
}

impl CountingSigner {
    /// Count what `inner` signs.
    #[must_use]
    pub fn new(inner: Arc<dyn Signer>) -> Self {
        Self {
            inner,
            signed: AtomicU64::new(0),
        }
    }

    /// Messages signed so far.
    #[must_use]
    pub fn signed(&self) -> u64 {
        self.signed.load(Ordering::Relaxed)
    }
}

impl Signer for CountingSigner {
    fn public_key(&self) -> ConsensusPublicKey {
        self.inner.public_key()
    }

    fn sign(&self, message: &[u8]) -> Result<ConsensusSignature, SignError> {
        self.signed.fetch_add(1, Ordering::Relaxed);
        self.inner.sign(message)
    }

    fn vrf_sign(&self, message: &[u8]) -> Result<VrfProof, SignError> {
        self.inner.vrf_sign(message)
    }
}

/// Keep the calling thread busy until it has taken `work` of processor
/// time, as a request handler charged for that much does.
pub fn burn_processor_time(work: Duration) {
    let started = thread_clock();
    while thread_clock().saturating_sub(started) < work {
        spin_loop();
    }
}

/// Open a bind handshake at `target` from `endpoint` as a dialer that
/// proves nothing, and return how many validators the listener signed for.
///
/// The dialer states a version and a nonce, reads the listener's
/// signatures, and closes.
///
/// # Errors
///
/// Describes the failure when the dial fails or the listener closes the
/// connection instead of signing.
pub async fn bind_hello(endpoint: &Endpoint, target: EndpointAddr) -> Result<usize, String> {
    let connection = endpoint
        .connect(target, ALPN)
        .await
        .map_err(|e| e.to_string())?;
    let signed = bind::hello_only(&connection)
        .await
        .map_err(|e| e.to_string());
    connection.close(0u32.into(), b"done");
    signed
}

#[cfg(test)]
mod tests {
    use tokio::time::timeout;

    use super::*;

    async fn recv_within(socket: &UdpSocket, wait: Duration) -> Option<(Vec<u8>, SocketAddr)> {
        let mut buf = [0u8; 64];
        let (len, from) = timeout(wait, socket.recv_from(&mut buf)).await.ok()?.ok()?;
        Some((buf[..len].to_vec(), from))
    }

    #[tokio::test]
    async fn carries_datagrams_both_ways_and_drops_them_while_closed() {
        let left = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let right = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).await.unwrap();
        let bridge = UdpBridge::spawn(left.local_addr().unwrap(), right.local_addr().unwrap())
            .await
            .unwrap();

        left.send_to(b"to-right", bridge.seen_by_left())
            .await
            .unwrap();
        let (payload, from) = recv_within(&right, Duration::from_secs(5))
            .await
            .expect("the datagram crosses");
        assert_eq!(payload, b"to-right");
        assert_eq!(from, bridge.seen_by_right());

        right
            .send_to(b"to-left", bridge.seen_by_right())
            .await
            .unwrap();
        let (payload, from) = recv_within(&left, Duration::from_secs(5))
            .await
            .expect("the reply crosses");
        assert_eq!(payload, b"to-left");
        assert_eq!(from, bridge.seen_by_left());
        assert_eq!(bridge.forwarded(), 2);

        bridge.set_open(false);
        left.send_to(b"lost", bridge.seen_by_left()).await.unwrap();
        assert!(
            recv_within(&right, Duration::from_millis(200))
                .await
                .is_none(),
            "a closed bridge carries nothing"
        );
        assert_eq!(bridge.dropped(), 1);
    }

    #[tokio::test]
    async fn holds_each_datagram_for_its_delay() {
        let left = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let right = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).await.unwrap();
        let bridge = UdpBridge::spawn(left.local_addr().unwrap(), right.local_addr().unwrap())
            .await
            .unwrap();
        bridge.set_delay(Duration::from_millis(300));

        left.send_to(b"slow", bridge.seen_by_left()).await.unwrap();
        assert!(
            recv_within(&right, Duration::from_millis(100))
                .await
                .is_none(),
            "the datagram is still held"
        );
        assert!(
            recv_within(&right, Duration::from_secs(5)).await.is_some(),
            "and arrives once its delay has passed"
        );
    }

    #[tokio::test]
    async fn refuses_two_sockets_of_one_family() {
        let a: SocketAddr = (Ipv4Addr::LOCALHOST, 1).into();
        let b: SocketAddr = (Ipv4Addr::LOCALHOST, 2).into();
        assert!(UdpBridge::spawn(a, b).await.is_err());
    }
}
