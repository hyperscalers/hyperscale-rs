//! The host's endpoint: its identity, its connections, and who is behind
//! each of them.
//!
//! [`IrohAdapter`] owns the iroh endpoint and holds one bound connection per
//! peer host. A connection counts only once the validator-bind handshake has
//! proved which validators the peer hosts; until then it carries nothing
//! else, and an inbound connection that has not bound within
//! [`BIND_TIMEOUT`] is closed. Anyone who learns an endpoint id can reach
//! the host through its relay without knowing its address, so unbound
//! inbound connections are capped as well as timed, and the host starts a
//! handshake and signs for a dialer only when the dialer has a turn (see
//! [`crate::bind_gate`]).
//!
//! Before its handshake an inbound connection shows where it comes from,
//! and that decides which unbound slots it may take (see [`crate::unbound`]).

use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use dashmap::{DashMap, DashSet};
use hyperscale_crypto::Verifier;
#[cfg(feature = "test-utils")]
use hyperscale_network::fault::HostId;
use hyperscale_network::stream_backoff::{StreamBackoff, StreamFailure};
use hyperscale_network::{HandlerRegistry, ValidatorKeyMap};
use hyperscale_types::network::gossip::ValidatorAddressGossip;
use hyperscale_types::{NetworkDefinition, ShardId, ValidatorId};
use iroh::address_lookup::memory::MemoryLookup;
use iroh::endpoint::{
    Builder, Connection, Incoming, IncomingAddr, PortmapperConfig, QuicTransportConfig, RecvStream,
    SendStream, presets,
};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayConfig, RelayMap, RelayMode, TransportAddr};
use tokio::runtime::Handle;
use tokio::task::JoinHandle;
use tokio::time::{MissedTickBehavior, interval, timeout};
use tracing::{debug, info, warn};

use crate::address_book::{AddressBook, IngestOutcome, record_sequence, sign_records};
use crate::bind::{
    self, BindContext, Bound, LocalIdentities, LocalVnodeIdentity, MAX_VNODES_PER_BIND,
};
use crate::bind_gate::{BindGate, Origin, Ticket};
use crate::bootstrap::{self, RESOLVE_INTERVAL};
use crate::config::{IrohConfig, MAX_RELAYS};
use crate::cooldown::Cooldown;
use crate::error::NetworkError;
use crate::fanout::Fanout;
use crate::fault_gate::FaultState;
use crate::inbound::InboundRouter;
use crate::path::{PathPolicy, PathStatus, Redialer};
use crate::peer::Peer;
use crate::protocol::{
    ALPN, CLOSE_BIND_FAILED, CLOSE_BIND_REFUSED, CLOSE_REDIAL_REFUSED, CLOSE_SHUTDOWN,
    CLOSE_SUPERSEDED, REDIAL_ALPN,
};
use crate::unbound::{Admission, Slot, UnboundSlots};

/// How long a connection has to complete the validator-bind handshake.
const BIND_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a dial has to establish its connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Interval of the sweep that re-dials bootstrap peers and wanted
/// validators with no bound connection.
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(5);

/// How long an endpoint's dial backoff is remembered after its last
/// attempt. Past this the endpoint is no longer being dialed, and its next
/// dial starts the series afresh.
const DIAL_BACKOFF_MEMORY: Duration = Duration::from_mins(1);

/// Why a validator could not be added to a running host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AddVnodeError {
    /// The host already runs it.
    #[error("validator {} is already hosted", .0.inner())]
    Hosted(ValidatorId),
    /// The host runs as many validators as one bind attests.
    #[error("the host already runs {MAX_VNODES_PER_BIND} validators")]
    Full,
}

/// A bound connection to a peer host.
struct Link {
    connection: Connection,
    /// The side that dialed it, which decides which of two simultaneous
    /// connections between a pair is kept.
    dialed_by: EndpointId,
    /// The validator the peer answers as.
    principal: ValidatorId,
    /// Validators the peer claims to host that this host's topology gave no
    /// key when it claimed them; each is pulled once the topology does.
    claimed: BTreeSet<ValidatorId>,
    /// Whether a pull is under way on this link.
    pulling: bool,
}

/// Bytes a host has exchanged in UDP datagrams over its bound connections,
/// each counted since it was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Traffic {
    /// Bytes sent.
    pub sent: u64,
    /// Bytes received.
    pub received: u64,
}

/// What the endpoint has sent and received on each kind of path, over every
/// connection it ever held, and how often it started a hole punch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PathTraffic {
    /// Datagram bytes sent from the host's own sockets.
    pub direct_sent: u64,
    /// Datagram bytes received on the host's own sockets.
    pub direct_received: u64,
    /// Datagram bytes sent through a relay, not counting the relay link's
    /// own framing.
    pub relay_sent: u64,
    /// Datagram bytes received through a relay.
    pub relay_received: u64,
    /// Hole punch rounds started, on connections this host dialed.
    pub hole_punch_rounds: u64,
}

/// Everything [`IrohAdapter::bind`] needs to stand a host's networking up.
pub struct IrohAdapterArgs {
    /// Endpoint and transport configuration.
    pub config: IrohConfig,
    /// The network identity, bound into every signed bind message.
    pub network: NetworkDefinition,
    /// One `(validator_id, signer)` per hosted vnode. The host attests as
    /// every entry on each handshake. Must be non-empty.
    pub vnodes: Vec<LocalVnodeIdentity>,
    /// Shards hosted by this host.
    pub local_shards: HashSet<ShardId>,
    /// Shared handler registry inbound streams are dispatched through.
    pub registry: Arc<HandlerRegistry>,
    /// Initial validator key map for bind verification.
    pub validator_keys: Arc<ValidatorKeyMap>,
    /// Scheme verifier for signed gossip and bind attestations.
    pub verifier: Arc<dyn Verifier>,
}

/// State the adapter shares with its background tasks.
struct Inner {
    /// The runtime the adapter was bound on. Its tasks are spawned here, so
    /// the adapter can be driven from threads that are not the runtime's.
    runtime: Handle,
    endpoint: Endpoint,
    local_shards: Arc<ArcSwap<HashSet<ShardId>>>,
    bind: BindContext,
    /// Serves the streams bound peers open.
    router: Arc<InboundRouter>,
    /// What each peer's refused traffic has cost this host.
    cooldown: Arc<Cooldown>,
    /// Follows each connection's selected path and decides what a relayed
    /// one carries.
    paths: Arc<PathPolicy>,
    /// Re-dials a relayed peer this host dialed, to bring it back to a
    /// direct path.
    redialer: Arc<Redialer>,
    /// The re-dial connection each bound peer holds open to this host, at
    /// most one a peer.
    redials_held: DashMap<EndpointId, Connection>,
    /// Fault gate consulted at the delivery seams. A zero-sized no-op
    /// unless the `test-utils` feature is enabled.
    fault_gate: Arc<FaultState>,
    /// Bound connections, one per peer host.
    links: DashMap<EndpointId, Link>,
    /// Validators proved to be behind each bound connection.
    validator_peers: DashMap<ValidatorId, EndpointId>,
    address_book: AddressBook,
    /// Addresses of every recorded endpoint, for the endpoint's own dials.
    lookup: MemoryLookup,
    /// Validators this host must hold unicast connectivity to.
    wanted_validators: ArcSwap<BTreeSet<ValidatorId>>,
    bootstrap_peers: Vec<EndpointAddr>,
    bootstrap_domains: Vec<String>,
    /// The peers each bootstrap domain last resolved to, in the order of
    /// `bootstrap_domains`.
    resolved_bootstrap: Mutex<Vec<Vec<EndpointAddr>>>,
    /// Endpoints with a dial in flight.
    dialing: DashSet<EndpointId>,
    /// Backoff of every endpoint dialed and not yet bound, so the sweep
    /// does not hammer an unreachable one.
    dial_backoff: Mutex<HashMap<EndpointId, StreamBackoff<Instant>>>,
    /// Slots for inbound connections that have not bound yet.
    unbound: UnboundSlots,
    /// Which dialers this host signs for before they prove anything.
    bind_gate: BindGate,
    /// This host's address records as last signed.
    signed_records: Mutex<Option<SignedRecords>>,
}

/// This host's address records, the addresses they were signed for, and
/// the sequence they carry, which the next signing moves past.
struct SignedRecords {
    addressed: EndpointAddr,
    /// The identities' generation they were signed for.
    generation: u64,
    sequence: u64,
    records: Vec<ValidatorAddressGossip>,
}

/// iroh-based network adapter: the host's endpoint and its bound
/// connections.
pub struct IrohAdapter {
    inner: Arc<Inner>,
    /// The accept and maintenance loops, until [`Self::shutdown`] awaits
    /// them.
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl IrohAdapter {
    /// Bind the host's endpoint and start accepting and dialing.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkError::Endpoint`] if the configuration names more
    /// than [`MAX_RELAYS`] relays or the endpoint cannot bind.
    ///
    /// # Panics
    ///
    /// Panics if `vnodes` is empty or holds more than a bind exchange can
    /// attest. An empty `local_shards` is valid: a pool-only host hosts no
    /// shard and joins shards at runtime.
    pub async fn bind(args: IrohAdapterArgs) -> Result<Arc<Self>, NetworkError> {
        let IrohAdapterArgs {
            config,
            network,
            vnodes,
            local_shards,
            registry,
            validator_keys,
            verifier,
        } = args;
        assert!(
            !vnodes.is_empty(),
            "IrohAdapter needs at least one hosted vnode"
        );
        assert!(
            vnodes.len() <= MAX_VNODES_PER_BIND,
            "hosted vnode count {} exceeds per-bind cap {MAX_VNODES_PER_BIND}",
            vnodes.len(),
        );
        if config.relays.len() > MAX_RELAYS {
            return Err(NetworkError::Endpoint(format!(
                "{} relays configured, at most {MAX_RELAYS} allowed",
                config.relays.len()
            )));
        }
        let local_validator_ids: Vec<ValidatorId> = vnodes.iter().map(|(vid, _)| *vid).collect();

        let lookup = MemoryLookup::new();
        for peer in &config.bootstrap_peers {
            lookup.add_endpoint_info(peer.clone());
        }
        let endpoint = build_endpoint(&config, lookup.clone()).await?;
        info!(
            endpoint = %endpoint.id().fmt_short(),
            validator_ids = ?local_validator_ids,
            shard_count = local_shards.len(),
            sockets = ?endpoint.bound_sockets(),
            "iroh network adapter bound"
        );

        let local_shards = Arc::new(ArcSwap::from_pointee(local_shards));
        let paths = Arc::new(PathPolicy::default());
        let fault_gate = Arc::new(FaultState::new());
        let cooldown = Arc::new(Cooldown::default());
        let inner = Arc::new(Inner {
            runtime: Handle::current(),
            router: Arc::new(InboundRouter::new(
                registry,
                Arc::clone(&local_shards),
                Arc::clone(&paths),
                Arc::clone(&fault_gate),
                Arc::clone(&cooldown),
            )),
            cooldown,
            redialer: Redialer::new(
                endpoint.clone(),
                REDIAL_ALPN,
                config.redial,
                config.redial_budget,
                Arc::clone(&paths),
            ),
            paths,
            redials_held: DashMap::new(),
            fault_gate,
            bind: BindContext {
                network,
                local: Arc::new(ArcSwap::from_pointee(LocalIdentities {
                    generation: 0,
                    vnodes,
                })),
                local_endpoint: endpoint.id(),
                validator_keys: Arc::new(ArcSwap::from(validator_keys)),
                verifier,
                version_interop_mode: config.version_interop_mode,
            },
            endpoint,
            local_shards,
            links: DashMap::new(),
            validator_peers: DashMap::new(),
            address_book: AddressBook::default(),
            lookup,
            wanted_validators: ArcSwap::from_pointee(BTreeSet::new()),
            bootstrap_peers: config.bootstrap_peers,
            resolved_bootstrap: Mutex::new(vec![Vec::new(); config.bootstrap_domains.len()]),
            bootstrap_domains: config.bootstrap_domains,
            dialing: DashSet::new(),
            dial_backoff: Mutex::new(HashMap::new()),
            unbound: UnboundSlots::default(),
            bind_gate: BindGate::default(),
            signed_records: Mutex::new(None),
        });

        inner.router.install_attest(inner.bind.clone());
        let tasks = vec![
            inner.runtime.spawn(Arc::clone(&inner).accept_loop()),
            inner.runtime.spawn(Arc::clone(&inner).maintenance_loop()),
        ];
        Ok(Arc::new(Self {
            inner,
            tasks: Mutex::new(tasks),
        }))
    }

    /// The endpoint id this host binds as.
    #[must_use]
    pub fn local_endpoint_id(&self) -> EndpointId {
        self.inner.endpoint.id()
    }

    /// Validator ids hosted by this endpoint.
    #[must_use]
    pub fn local_validator_ids(&self) -> Vec<ValidatorId> {
        self.inner.bind.local.load().ids()
    }

    /// Host `vnode` from now on: new binds attest it, pulls answer for it,
    /// and the address records name it. Peers already linked learn it from
    /// the records [`Fanout`] hands them, and pull it once their topology
    /// holds its key.
    ///
    /// # Errors
    ///
    /// [`AddVnodeError::Hosted`] if the validator is already hosted, and
    /// [`AddVnodeError::Full`] past [`MAX_VNODES_PER_BIND`].
    pub fn add_vnode(&self, vnode: LocalVnodeIdentity) -> Result<(), AddVnodeError> {
        let local = &self.inner.bind.local;
        let current = local.load();
        if current.vnodes.iter().any(|(vid, _)| *vid == vnode.0) {
            return Err(AddVnodeError::Hosted(vnode.0));
        }
        if current.vnodes.len() >= MAX_VNODES_PER_BIND {
            return Err(AddVnodeError::Full);
        }
        let mut vnodes = current.vnodes.clone();
        vnodes.push(vnode);
        // The one writer: the host adds its validators one at a time.
        local.store(Arc::new(LocalIdentities {
            generation: current.generation + 1,
            vnodes,
        }));
        Ok(())
    }

    /// Shards hosted by this endpoint (a loaded snapshot).
    #[must_use]
    pub fn local_shards(&self) -> Arc<HashSet<ShardId>> {
        self.inner.local_shards.load_full()
    }

    /// Add `shard` to the hosted set: requests for it are served from the
    /// next one that arrives.
    pub(crate) fn add_local_shard(&self, shard: ShardId) {
        let mut set = (**self.inner.local_shards.load()).clone();
        set.insert(shard);
        self.inner.local_shards.store(Arc::new(set));
    }

    /// Remove `shard` from the hosted set: requests for it are answered as
    /// unsupported from the next one that arrives.
    pub(crate) fn remove_local_shard(&self, shard: ShardId) {
        let mut set = (**self.inner.local_shards.load()).clone();
        set.remove(&shard);
        self.inner.local_shards.store(Arc::new(set));
    }

    /// Every way this host can currently be reached: its relays, the
    /// addresses the endpoint knows for itself, and the sockets it bound to
    /// a specific interface.
    #[must_use]
    pub fn endpoint_addr(&self) -> EndpointAddr {
        self.inner.endpoint_addr()
    }

    /// The endpoint a validator was proved to be behind, if it is bound.
    #[must_use]
    pub fn peer_for_validator(&self, validator: ValidatorId) -> Option<EndpointId> {
        self.inner.validator_peers.get(&validator).map(|r| *r)
    }

    /// Peer hosts with a bound connection.
    #[must_use]
    pub fn connected_peers(&self) -> Vec<EndpointId> {
        self.inner.links.iter().map(|link| *link.key()).collect()
    }

    /// Number of peer hosts with a bound connection.
    #[must_use]
    pub fn cached_peer_count(&self) -> usize {
        self.inner.links.len()
    }

    /// The signed validator address book built from gossiped announcements.
    #[must_use]
    pub fn address_book(&self) -> &AddressBook {
        &self.inner.address_book
    }

    /// Verify one gossiped address announcement against the current
    /// validator keys and store it if it is the newest for its validator.
    #[must_use]
    pub fn ingest_validator_address(&self, gossip: &ValidatorAddressGossip) -> IngestOutcome {
        let inner = &self.inner;
        let (outcome, recorded) = inner.address_book.ingest(
            inner.bind.verifier.as_ref(),
            &inner.bind.network,
            &inner.bind.validator_keys.load(),
            gossip,
        );
        if let Some(endpoint) = recorded {
            inner.lookup.set_endpoint_info(endpoint.clone());
            if !inner.validator_peers.contains_key(&gossip.validator) {
                if inner.is_linked(endpoint.id) {
                    // A host already linked that names a validator it has
                    // not proved is asked to prove it.
                    inner.claim(endpoint.id, gossip.validator);
                } else if inner.wanted_validators.load().contains(&gossip.validator) {
                    // A wanted validator whose record has just arrived is
                    // dialed now rather than at the next sweep.
                    inner.dial(endpoint);
                }
            }
        }
        outcome
    }

    /// Whether the topology gives `validator` a key, so that its records
    /// can be checked.
    pub(crate) fn knows_validator(&self, validator: ValidatorId) -> bool {
        self.inner
            .bind
            .validator_keys
            .load()
            .contains_key(&validator)
    }

    /// One signed address record per hosted vnode, naming where this host
    /// can currently be reached. Empty while the endpoint knows no address
    /// for itself.
    ///
    /// The records are signed again only when the addresses change. Every
    /// newly bound peer is handed them, and peers forward what they accept,
    /// so records signed afresh for each link would each travel the whole
    /// network and be verified by every host: on a freshly seated committee
    /// of n hosts, n squared distinct records verified n times over.
    #[must_use]
    pub fn address_records(&self) -> Vec<ValidatorAddressGossip> {
        let endpoint = self.inner.endpoint_addr();
        let mut signed = self
            .inner
            .signed_records
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let local = self.inner.bind.local.load();
        if let Some(last) = signed.as_ref()
            && last.addressed == endpoint
            && last.generation == local.generation
        {
            return last.records.clone();
        }
        let now_ms = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
        )
        .unwrap_or(u64::MAX);
        let sequence = record_sequence(now_ms, signed.as_ref().map(|last| last.sequence));
        let records = sign_records(&endpoint, sequence, &self.inner.bind.network, &local.vnodes);
        *signed = Some(SignedRecords {
            addressed: endpoint,
            generation: local.generation,
            sequence,
            records: records.clone(),
        });
        records
    }

    /// The newest signed address announcement of every recorded validator.
    pub(crate) fn book_records(&self) -> Vec<ValidatorAddressGossip> {
        self.inner.address_book.announcements()
    }

    /// Dial up to `limit` recorded validators' hosts that are not bound.
    pub(crate) fn dial_recorded(&self, limit: usize) {
        let inner = &self.inner;
        let targets = inner.address_book.endpoints_except(limit, |peer| {
            peer == inner.endpoint.id() || inner.is_linked(peer)
        });
        for target in targets {
            inner.dial(target);
        }
    }

    /// Route gossip that bound peers send to `fanout`, and let it greet
    /// each peer as it binds.
    pub(crate) fn install_fanout(&self, fanout: &Arc<Fanout>) {
        self.inner.router.install_fanout(fanout);
        // Peers that bound before now have not been greeted.
        let bound: Vec<Peer> = self
            .inner
            .links
            .iter()
            .map(|link| Peer {
                endpoint: *link.key(),
                principal: link.principal,
            })
            .collect();
        for peer in bound {
            fanout.on_link(peer);
        }
    }

    /// Update the validator key map for bind and address verification, and
    /// pull every claim it now lets this host check.
    pub fn update_validator_keys(&self, keys: Arc<ValidatorKeyMap>) {
        let inner = &self.inner;
        let checkable: Vec<EndpointId> = inner
            .links
            .iter()
            .filter(|link| link.claimed.iter().any(|v| keys.contains_key(v)))
            .map(|link| *link.key())
            .collect();
        inner.bind.validator_keys.store(keys);
        for peer in checkable {
            inner.pull_claims(peer);
        }
    }

    /// Note that the linked `peer` signed a record naming `validator`,
    /// which the topology cannot check yet, so it is pulled once it can.
    pub(crate) fn claim(&self, peer: EndpointId, validator: ValidatorId) {
        self.inner.claim(peer, validator);
    }

    /// Replace the set of validators this host must hold unicast
    /// connectivity to, and immediately dial the unbound ones whose
    /// addresses the book already knows. The maintenance sweep covers the
    /// ones whose announcements arrive later and any dial that fails.
    pub fn update_wanted_validators(&self, wanted: BTreeSet<ValidatorId>) {
        self.inner.wanted_validators.store(Arc::new(wanted));
        self.inner.dial_wanted();
    }

    /// Open a unidirectional stream on the bound connection to `peer`.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkError::NotConnected`] when no bound connection
    /// exists, after starting a dial from whatever address is known for the
    /// peer, and [`NetworkError::StreamOpenFailed`] when the connection
    /// refuses the stream.
    pub(crate) async fn open_uni(&self, peer: EndpointId) -> Result<SendStream, NetworkError> {
        self.inner
            .connection(peer)?
            .open_uni()
            .await
            .map_err(|e| NetworkError::StreamOpenFailed(e.to_string()))
    }

    /// Open a bidirectional stream on the bound connection to `peer`.
    ///
    /// # Errors
    ///
    /// As [`Self::open_uni`].
    pub(crate) async fn open_bi(
        &self,
        peer: EndpointId,
    ) -> Result<(SendStream, RecvStream), NetworkError> {
        self.inner
            .connection(peer)?
            .open_bi()
            .await
            .map_err(|e| NetworkError::StreamOpenFailed(e.to_string()))
    }

    /// Bytes exchanged over every connection bound right now, payload and
    /// transport overhead together. A connection takes its count with it
    /// when it closes.
    #[must_use]
    pub fn traffic(&self) -> Traffic {
        let mut traffic = Traffic::default();
        for link in &self.inner.links {
            let stats = link.connection.stats();
            traffic.sent += stats.udp_tx.bytes;
            traffic.received += stats.udp_rx.bytes;
        }
        traffic
    }

    /// What the endpoint has carried on direct and relayed paths since it
    /// was bound.
    #[must_use]
    pub fn path_traffic(&self) -> PathTraffic {
        let socket = &self.inner.endpoint.metrics().socket;
        PathTraffic {
            direct_sent: socket.send_ipv4.get() + socket.send_ipv6.get(),
            direct_received: socket.recv_data_ipv4.get() + socket.recv_data_ipv6.get(),
            relay_sent: socket.send_relay.get(),
            relay_received: socket.recv_data_relay.get(),
            hole_punch_rounds: socket.holepunch_attempts.get(),
        }
    }

    /// The policy deciding what each connection's current path carries.
    pub(crate) fn paths(&self) -> &PathPolicy {
        &self.inner.paths
    }

    /// The path of `peer`'s connection and what it has carried while
    /// relayed, or `None` when the peer is not bound.
    #[must_use]
    pub fn path_status(&self, peer: EndpointId) -> Option<PathStatus> {
        self.inner.paths.status(peer)
    }

    /// Re-dials this host has made to bring relayed peers back to a direct
    /// path.
    #[must_use]
    pub fn redials(&self) -> u64 {
        self.inner.redialer.redials()
    }

    /// Re-dials from peers this host refused because its re-dial budget
    /// had no turn for them.
    #[must_use]
    pub fn redials_refused(&self) -> u64 {
        self.inner.redialer.refused()
    }

    /// Resolves once the endpoint is connected to its home relay, and so
    /// reachable by peers that know only its id and relay.
    pub async fn online(&self) {
        self.inner.endpoint.online().await;
    }

    /// Advertise `addr` as one at which this host is reachable from
    /// outside, beside what the endpoint discovers for itself.
    pub async fn add_external_addr(&self, addr: SocketAddr) {
        self.inner.endpoint.add_external_addr(addr).await;
    }

    /// The fault gate consulted at this adapter's delivery seams. A
    /// zero-sized no-op unless `test-utils` is enabled; under it, test
    /// clusters install drop rules and partitions through the gate.
    #[must_use]
    pub fn fault_gate(&self) -> &FaultState {
        &self.inner.fault_gate
    }

    /// What each peer's refused traffic has cost this host: one budget per
    /// principal, shared by everything that refuses a peer's traffic.
    pub(crate) fn cooldown(&self) -> &Arc<Cooldown> {
        &self.inner.cooldown
    }

    /// Whether this host is refusing `validator`'s traffic for now.
    #[cfg(feature = "test-utils")]
    #[must_use]
    pub fn cooling_down(&self, validator: ValidatorId) -> bool {
        self.inner.cooldown.cooling_down(validator)
    }

    /// Configure the fault gate: this host's id and the full
    /// `EndpointId → HostId` map. The harness calls this once before
    /// installing faults.
    #[cfg(feature = "test-utils")]
    pub fn fault_configure(
        &self,
        self_host: HostId,
        peers: impl IntoIterator<Item = (EndpointId, HostId)>,
    ) {
        self.inner.fault_gate.configure(self_host, peers);
    }

    /// Closes every connection and the endpoint and waits until they are
    /// closed, so the peers see this host leave and its socket is free by
    /// the time this returns. The adapter answers nothing afterwards.
    pub async fn shutdown(&self) {
        let tasks = std::mem::take(&mut *self.tasks.lock().unwrap_or_else(PoisonError::into_inner));
        for task in &tasks {
            task.abort();
        }
        for task in tasks {
            let _ = task.await;
        }
        for link in &self.inner.links {
            link.connection.close(CLOSE_SHUTDOWN, b"shutdown");
        }
        for held in &self.inner.redials_held {
            held.close(CLOSE_SHUTDOWN, b"shutdown");
        }
        self.inner.endpoint.close().await;
    }
}

impl Drop for IrohAdapter {
    fn drop(&mut self) {
        let tasks = self.tasks.get_mut().unwrap_or_else(PoisonError::into_inner);
        for task in tasks.iter() {
            task.abort();
        }
    }
}

/// Whether `incoming` asks for the re-dial protocol, read from its first
/// packet before any handshake work. A re-dial's hello fits that packet;
/// one that cannot be read is treated as an ordinary connection, which
/// binds or is closed.
fn is_redial(incoming: &Incoming) -> bool {
    incoming
        .decrypt()
        .and_then(|initial| initial.alpns())
        .is_some_and(|mut alpns| {
            alpns.any(|alpn| alpn.is_ok_and(|alpn| alpn.as_ref() == REDIAL_ALPN))
        })
}

async fn build_endpoint(
    config: &IrohConfig,
    lookup: MemoryLookup,
) -> Result<Endpoint, NetworkError> {
    let transport = QuicTransportConfig::builder()
        .default_path_max_idle_timeout(config.path_idle_timeout)
        .default_path_keep_alive_interval(config.path_keep_alive);
    let relay_mode = if config.relays.is_empty() {
        RelayMode::Disabled
    } else if config.relay_address_discovery {
        RelayMode::custom(config.relays.iter().cloned())
    } else {
        RelayMode::Custom(RelayMap::from_iter(
            config
                .relays
                .iter()
                .map(|url| RelayConfig::new(url.clone(), None)),
        ))
    };
    let port_mapping = if config.port_mapping {
        PortmapperConfig::default()
    } else {
        PortmapperConfig::Disabled
    };

    let mut builder = Builder::empty()
        .preset(presets::Minimal)
        .secret_key(config.secret_key.clone())
        .alpns(vec![ALPN.to_vec(), REDIAL_ALPN.to_vec()])
        .relay_mode(relay_mode)
        .address_lookup(lookup)
        .portmapper_config(port_mapping)
        .transport_config(transport.build());
    if let Some(resolver) = &config.dns_resolver {
        builder = builder.dns_resolver(resolver.clone());
    }
    for addr in &config.external_addrs {
        builder = builder.external_addr(*addr);
    }
    if let Some(roots) = &config.relay_roots {
        builder = builder.ca_tls_config(roots.clone());
    }
    if let Some(addr) = config.bind_addr {
        builder = builder
            .clear_ip_transports()
            .bind_addr(addr)
            .map_err(|e| NetworkError::Endpoint(e.to_string()))?;
    }
    builder
        .bind()
        .await
        .map_err(|e| NetworkError::Endpoint(e.to_string()))
}

impl Inner {
    fn endpoint_addr(&self) -> EndpointAddr {
        let bound = self
            .endpoint
            .bound_sockets()
            .into_iter()
            .filter(|socket: &SocketAddr| !socket.ip().is_unspecified())
            .map(TransportAddr::Ip);
        self.endpoint.addr().with_addrs(bound)
    }

    fn is_linked(&self, peer: EndpointId) -> bool {
        self.links.contains_key(&peer)
    }

    /// The bound connection to `peer`. When there is none, a dial starts
    /// from whatever address a record or the bootstrap list gave for it.
    fn connection(self: &Arc<Self>, peer: EndpointId) -> Result<Connection, NetworkError> {
        if let Some(link) = self.links.get(&peer) {
            return Ok(link.connection.clone());
        }
        self.dial(EndpointAddr::new(peer));
        Err(NetworkError::NotConnected)
    }

    /// Accept inbound connections until the endpoint closes.
    async fn accept_loop(self: Arc<Self>) {
        while let Some(incoming) = self.endpoint.accept().await {
            if is_redial(&incoming) {
                if !self.admit_redial(&incoming) {
                    incoming.refuse();
                    continue;
                }
                let Some(slot) = self.unbound.redial() else {
                    incoming.refuse();
                    continue;
                };
                // A re-dial never binds, so it has no use for a ticket.
                let ticket = Ticket::Vouched { paid: None };
                self.spawn_accept(incoming, ticket, slot);
                continue;
            }
            self.admit(incoming);
        }
    }

    /// Let `incoming` on to its handshake if its origin has a slot and a
    /// turn, send it a retry if it must first show its address is its own,
    /// or refuse it. Each is decided from its first packet.
    fn admit(self: &Arc<Self>, incoming: Incoming) {
        let origin = match incoming.remote_addr() {
            IncomingAddr::Relay { endpoint_id, .. } => Origin::Relayed(endpoint_id),
            IncomingAddr::Ip(addr) => Origin::Direct(addr),
            _ => {
                incoming.refuse();
                return;
            }
        };
        let named = match origin {
            Origin::Relayed(peer) => self.address_book.names(peer),
            Origin::Direct(addr) => self.address_book.names_address(addr),
        };
        let slot = match self
            .unbound
            .admit(origin, named, incoming.remote_addr_validated())
        {
            Admission::Admit(slot) => slot,
            Admission::Retry => {
                if let Err(error) = incoming.retry() {
                    error.into_incoming().refuse();
                }
                return;
            }
            Admission::Refuse(reason) => {
                debug!(?origin, named, reason, "Refusing inbound connection");
                incoming.refuse();
                return;
            }
        };
        let Some(ticket) = self.bind_gate.admit_incoming(origin, named) else {
            debug!(
                ?origin,
                "Refusing inbound connection: no turn for this dialer"
            );
            incoming.refuse();
            return;
        };
        self.spawn_accept(incoming, ticket, slot);
    }

    fn spawn_accept(self: &Arc<Self>, incoming: Incoming, ticket: Ticket, slot: Slot) {
        let inner = Arc::clone(self);
        self.runtime.spawn(async move {
            let _slot = slot;
            inner.accept(incoming, ticket).await;
        });
    }

    /// Take one inbound connection through the bind handshake, closing it
    /// if the handshake fails or outlasts [`BIND_TIMEOUT`].
    async fn accept(self: &Arc<Self>, incoming: Incoming, ticket: Ticket) {
        let deadline = Instant::now() + BIND_TIMEOUT;
        let Ok(Ok(connection)) = timeout(BIND_TIMEOUT, incoming).await else {
            debug!("Inbound connection did not complete its handshake");
            return;
        };
        let peer = connection.remote_id();
        if connection.alpn() == REDIAL_ALPN {
            self.hold_redial(connection);
            return;
        }
        // The listener signs before the dialer proves anything, so it signs
        // only for a dialer with a turn.
        if !self
            .bind_gate
            .admit_bind(peer, self.address_book.names(peer), ticket)
        {
            debug!(peer = %peer.fmt_short(), "Refusing to bind: no turn for this dialer");
            connection.close(CLOSE_BIND_REFUSED, b"no turn");
            return;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        match timeout(remaining, bind::respond(&connection, &self.bind)).await {
            Ok(Ok(bound)) => self.register(connection, peer, bound),
            Ok(Err(error)) => {
                warn!(peer = %peer.fmt_short(), %error, "Inbound validator-bind failed");
                connection.close(CLOSE_BIND_FAILED, b"bind failed");
            }
            Err(_) => {
                warn!(peer = %peer.fmt_short(), "Inbound connection did not bind in time");
                connection.close(CLOSE_BIND_FAILED, b"bind timed out");
            }
        }
    }

    /// Whether a re-dial may go on to its handshake: it must come from a
    /// bound peer, when the relay it arrived through names one, and find a
    /// turn in the host's re-dial budget. A refusal costs the relay one
    /// packet each way where a re-dial costs about twenty kilobytes.
    fn admit_redial(&self, incoming: &Incoming) -> bool {
        let peer = match incoming.remote_addr() {
            IncomingAddr::Relay { endpoint_id, .. } => Some(endpoint_id),
            _ => None,
        };
        if peer.is_some_and(|peer| !self.is_linked(peer)) {
            return false;
        }
        self.redialer.admit(peer)
    }

    /// Hold a bound peer's re-dial connection until the peer closes it.
    /// Its handshake alone made the peer's endpoint try a hole punch; it is
    /// kept open while the punch runs. A newer one from the same peer
    /// replaces it, and one from a peer that is not bound is refused.
    fn hold_redial(self: &Arc<Self>, connection: Connection) {
        let peer = connection.remote_id();
        if !self.is_linked(peer) {
            connection.close(CLOSE_REDIAL_REFUSED, b"not bound");
            return;
        }
        let id = connection.stable_id();
        if let Some(older) = self.redials_held.insert(peer, connection.clone()) {
            older.close(CLOSE_REDIAL_REFUSED, b"replaced");
        }
        let inner = Arc::clone(self);
        self.runtime.spawn(async move {
            connection.closed().await;
            inner
                .redials_held
                .remove_if(&peer, |_, held| held.stable_id() == id);
        });
    }

    /// Dial `target` unless it is linked, already being dialed, or backing
    /// off after an earlier attempt.
    fn dial(self: &Arc<Self>, target: EndpointAddr) {
        let peer = target.id;
        if peer == self.endpoint.id() || self.is_linked(peer) {
            return;
        }
        {
            let mut backoff = self.dial_backoff.lock().expect("dial backoff lock");
            let now = Instant::now();
            backoff.retain(|_, state| {
                now.saturating_duration_since(state.next_attempt()) < DIAL_BACKOFF_MEMORY
            });
            let previous = backoff.get(&peer);
            if previous.is_some_and(|state| state.held_for(now).is_some())
                || !self.dialing.insert(peer)
            {
                return;
            }
            // Every attempt extends the series; binding clears it.
            let next = StreamBackoff::after(previous, StreamFailure::Transient, now);
            backoff.insert(peer, next);
        }

        let inner = Arc::clone(self);
        self.runtime.spawn(async move {
            let outcome = timeout(CONNECT_TIMEOUT + BIND_TIMEOUT, async {
                let connection = inner
                    .endpoint
                    .connect(target, ALPN)
                    .await
                    .map_err(|e| e.to_string())?;
                match bind::initiate(&connection, &inner.bind).await {
                    Ok(bound) => Ok((connection, bound)),
                    Err(e) => {
                        connection.close(CLOSE_BIND_FAILED, b"bind failed");
                        Err(e.to_string())
                    }
                }
            })
            .await;
            match outcome {
                Ok(Ok((connection, bound))) => {
                    let dialed_by = inner.endpoint.id();
                    inner.register(connection, dialed_by, bound);
                }
                Ok(Err(error)) => debug!(peer = %peer.fmt_short(), %error, "Dial failed"),
                Err(_) => debug!(peer = %peer.fmt_short(), "Dial timed out"),
            }
            inner.dialing.remove(&peer);
        });
    }

    /// Record a bound connection and the validators behind it.
    ///
    /// Two hosts that dial each other at once end up with two connections.
    /// Both sides keep the one dialed by the smaller endpoint id, so they
    /// agree without talking; a second connection from the same dialer
    /// replaces the first, which that dialer has given up on.
    fn register(self: &Arc<Self>, connection: Connection, dialed_by: EndpointId, bound: Bound) {
        let Bound {
            validators,
            claimed,
        } = bound;
        let peer = connection.remote_id();
        // A bind proves at least one validator; the lowest is the one the
        // peer answers as.
        let Some(&principal) = validators.iter().min() else {
            connection.close(CLOSE_BIND_FAILED, b"no validator");
            return;
        };
        if let Some(existing) = self.links.get(&peer)
            && existing.connection.close_reason().is_none()
            && existing.dialed_by < dialed_by
        {
            drop(existing);
            connection.close(CLOSE_SUPERSEDED, b"superseded");
            return;
        }

        let id = connection.stable_id();
        let superseded = self.links.insert(
            peer,
            Link {
                connection: connection.clone(),
                dialed_by,
                principal,
                claimed: claimed.into_iter().collect(),
                pulling: false,
            },
        );
        if let Some(superseded) = superseded {
            superseded.connection.close(CLOSE_SUPERSEDED, b"superseded");
        }
        for validator in &validators {
            self.validator_peers.insert(*validator, peer);
        }
        self.dial_backoff
            .lock()
            .expect("dial backoff lock")
            .remove(&peer);
        info!(peer = %peer.fmt_short(), ?validators, "Peer bound");
        self.paths.track(&connection, &self.runtime);
        self.redialer.follow(&connection, &self.runtime);
        self.router.serve(&connection, principal);

        // Evict the link and its bindings when this connection closes,
        // unless a later connection to the same peer has replaced it.
        let inner = Arc::clone(self);
        self.runtime.spawn(async move {
            let reason = connection.closed().await;
            let removed = inner
                .links
                .remove_if(&peer, |_, link| link.connection.stable_id() == id);
            if removed.is_some() {
                inner.validator_peers.retain(|_, bound| *bound != peer);
                if let Some((_, held)) = inner.redials_held.remove(&peer) {
                    held.close(CLOSE_REDIAL_REFUSED, b"not bound");
                }
                info!(peer = %peer.fmt_short(), %reason, "Peer connection closed");
            }
        });
    }

    /// Dial every wanted validator that is unbound and has a record, and
    /// pull it from a host it names that is already linked.
    fn dial_wanted(self: &Arc<Self>) {
        let candidates = self
            .address_book
            .dial_candidates(&self.wanted_validators.load(), &self.validator_peers);
        for (target, validators) in candidates {
            if self.is_linked(target.id) {
                for validator in validators {
                    self.claim(target.id, validator);
                }
            } else {
                self.dial(target);
            }
        }
    }

    /// Note that `peer` claims to host `validator`, and pull it if the
    /// topology can check it. A link holds at most
    /// [`MAX_VNODES_PER_BIND`] claims.
    fn claim(self: &Arc<Self>, peer: EndpointId, validator: ValidatorId) {
        if self.validator_peers.contains_key(&validator) {
            return;
        }
        if let Some(mut link) = self.links.get_mut(&peer)
            && link.claimed.len() < MAX_VNODES_PER_BIND
        {
            link.claimed.insert(validator);
        }
        self.pull_claims(peer);
    }

    /// Pull, over the link to `peer`, every validator it claims that the
    /// topology now gives a key, unless a pull is already under way there.
    fn pull_claims(self: &Arc<Self>, peer: EndpointId) {
        let keys = self.bind.validator_keys.load();
        let (connection, wanted) = {
            let Some(mut link) = self.links.get_mut(&peer) else {
                return;
            };
            if link.pulling {
                return;
            }
            let wanted: Vec<ValidatorId> = link
                .claimed
                .iter()
                .copied()
                .filter(|validator| keys.contains_key(validator))
                .collect();
            if wanted.is_empty() {
                return;
            }
            link.pulling = true;
            (link.connection.clone(), wanted)
        };
        let id = connection.stable_id();
        let inner = Arc::clone(self);
        self.runtime.spawn(async move {
            let outcome = timeout(BIND_TIMEOUT, bind::pull(&connection, &inner.bind, &wanted)).await;
            // Inserted while the link is held, so a close that evicts it
            // either comes after and takes these with it, or came before
            // and leaves nothing to insert into.
            let Some(mut link) = inner
                .links
                .get_mut(&peer)
                .filter(|link| link.connection.stable_id() == id)
            else {
                return;
            };
            link.pulling = false;
            match outcome {
                Ok(Ok(bound)) => {
                    for validator in &bound.validators {
                        link.claimed.remove(validator);
                        inner.validator_peers.insert(*validator, peer);
                    }
                    if !bound.validators.is_empty() {
                        info!(peer = %peer.fmt_short(), validators = ?bound.validators, "Peer bound more validators");
                    }
                }
                Ok(Err(error)) => debug!(peer = %peer.fmt_short(), %error, "Pull failed"),
                Err(_) => debug!(peer = %peer.fmt_short(), "Pull timed out"),
            }
        });
    }

    /// Keep bootstrap peers and wanted validators connected.
    async fn maintenance_loop(self: Arc<Self>) {
        let mut tick = interval(MAINTENANCE_INTERVAL);
        tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut next_resolve = Instant::now();
        loop {
            tick.tick().await;
            if !self.bootstrap_domains.is_empty() && Instant::now() >= next_resolve {
                self.resolve_bootstrap_domains().await;
                next_resolve = Instant::now() + RESOLVE_INTERVAL;
            }
            let resolved: Vec<EndpointAddr> = self
                .resolved_bootstrap
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .iter()
                .flatten()
                .cloned()
                .collect();
            for target in self.bootstrap_peers.iter().cloned().chain(resolved) {
                self.dial(target);
            }
            self.dial_wanted();
        }
    }

    /// Look the bootstrap domains up, keeping a domain's last peers when its
    /// lookup fails.
    async fn resolve_bootstrap_domains(&self) {
        let resolver = match self.endpoint.dns_resolver() {
            Ok(resolver) => resolver.clone(),
            Err(err) => {
                warn!(%err, "No DNS resolver for the bootstrap domains");
                return;
            }
        };
        let found =
            bootstrap::resolve(&resolver, &self.bootstrap_domains, self.endpoint.id()).await;
        let mut held = self
            .resolved_bootstrap
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        for (slot, peers) in held.iter_mut().zip(found) {
            if let Some(peers) = peers {
                for peer in &peers {
                    self.lookup.add_endpoint_info(peer.clone());
                }
                *slot = peers;
            }
        }
    }
}
