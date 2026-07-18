//! Core `Libp2pAdapter`: construction, public API, and shutdown.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use arc_swap::ArcSwap;
use dashmap::DashMap;
use futures::FutureExt;
use hyperscale_metrics::{record_libp2p_bandwidth, record_network_message_sent};
#[cfg(feature = "test-utils")]
use hyperscale_network::fault::HostId;
use hyperscale_network::{HandlerRegistry, Topic, ValidatorKeyMap};
use hyperscale_types::network::gossip::ValidatorAddressGossip;
use hyperscale_types::{MessageClass, NetworkDefinition, ShardId, ValidatorId};
use libp2p::connection_limits::{Behaviour as ConnectionLimitsBehaviour, ConnectionLimits};
use libp2p::gossipsub::{
    Behaviour as GossipsubBehaviour, ConfigBuilder as GossipsubConfigBuilder, MessageAuthenticity,
    MessageId, ValidationMode,
};
use libp2p::identify::{Behaviour as IdentifyBehaviour, Config as IdentifyConfig};
use libp2p::identity::Keypair;
use libp2p::kad::store::MemoryStore as KadMemoryStore;
use libp2p::kad::{Behaviour as KadBehaviour, Mode as KadMode};
use libp2p::{Multiaddr, PeerId as Libp2pPeerId, Stream};
use libp2p_stream::{Behaviour as StreamBehaviour, Control as StreamControl, OpenStreamError};
use tokio::spawn;
use tokio::sync::{mpsc, oneshot};
use tracing::{info, trace};

use super::behaviour::{Behaviour, NOTIFY_PROTOCOL, request_protocol};
use super::command::{ClassCommandChannels, SwarmCommand};
use super::error::NetworkError;
use crate::address_book::{AddressBook, IngestOutcome};
use crate::config::Libp2pConfig;
use crate::fault_gate::FaultState;
use crate::validator_bind::{LocalVnodeIdentity, spawn_validator_bind_service};

/// libp2p-based network adapter for production use.
///
/// Uses gossipsub for efficient broadcast and Kademlia DHT for peer discovery.
/// Commands are processed in priority order via [`ClassCommandChannels`].
///
/// Request/response uses raw streams via `libp2p_stream`. The adapter is a "dumb pipe" -
/// all timeout logic is owned by `RequestManager`.
pub struct Libp2pAdapter {
    /// Local peer ID.
    local_peer_id: Libp2pPeerId,

    /// Validator ids hosted by this peer. One under V=1; multiple when
    /// the host runs several same-shard vnodes off one libp2p identity.
    local_validator_ids: Vec<ValidatorId>,

    /// Shards hosted by this peer. Drives per-shard request stream
    /// protocol registration, per-shard gossipsub topic subscription,
    /// and the event loop's inbound shard-local filter — which loads it
    /// per message, so runtime add/drop takes effect immediately.
    local_shards: Arc<ArcSwap<HashSet<ShardId>>>,

    /// Priority-based command channels to swarm task.
    /// Commands are routed to the appropriate channel based on message priority.
    priority_channels: ClassCommandChannels,

    /// Known validators (`ValidatorId` -> `PeerId`).
    /// Used by request-response to resolve peer addresses.
    validator_peers: Arc<DashMap<ValidatorId, Libp2pPeerId>>,

    /// Shutdown signal sender.
    shutdown_tx: Option<mpsc::Sender<()>>,

    /// Cached connected peer count (updated by background task).
    /// This avoids blocking the consensus loop to query peer count.
    cached_peer_count: Arc<AtomicUsize>,

    /// Stream control handle for opening outbound streams.
    /// Cloneable and thread-safe.
    stream_control: StreamControl,

    /// Validator BLS public keys for identity verification.
    /// Shared with the validator-bind service; updated on topology changes.
    validator_keys: Arc<ArcSwap<ValidatorKeyMap>>,

    /// Chain network identity, bound into every locally signed and verified
    /// address announcement.
    network: NetworkDefinition,

    /// Signed `ValidatorId → (PeerId, addresses)` book built from gossiped
    /// announcements — the dial source for validators this host has never
    /// connected to.
    address_book: Arc<AddressBook>,

    /// Validators this host must hold unicast connectivity to — the union
    /// of the routing committees, pushed on every topology change. The
    /// event loop's maintenance sweep keeps dialing the unbound ones.
    wanted_validators: Arc<ArcSwap<HashSet<ValidatorId>>>,

    /// Fault gate consulted at the delivery seams, shared with the swarm event
    /// loop for the inbound gossip filter. A zero-sized no-op unless the
    /// `test-utils` feature is enabled.
    fault_gate: Arc<FaultState>,
}

impl Libp2pAdapter {
    /// Create a new libp2p network adapter.
    ///
    /// # Arguments
    ///
    /// * `config` - Network configuration
    /// * `keypair` - Ed25519 keypair for libp2p transport encryption
    /// * `vnodes` - One `(validator_id, signing_key)` per hosted vnode.
    ///   The bind service attests as every entry on each handshake.
    /// * `local_shards` - Shards hosted by this peer. The adapter
    ///   registers one inbound request accept loop per shard and
    ///   subscribes to per-shard gossipsub topics for the union.
    /// * `registry` - Shared handler registry for per-type message dispatch
    /// * `validator_keys` - Initial validator key map for bind verification
    ///
    /// # Returns
    ///
    /// The adapter wrapped in an Arc for shared ownership.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkError`] if swarm construction or transport setup fails.
    ///
    /// # Panics
    ///
    /// Panics if `vnodes` is empty. An empty `local_shards` is valid: a
    /// shard-less beacon-follower (pool-only) host hosts no shard and joins
    /// shards at runtime via [`Self::add_local_shard`].
    // Single setup path mirroring the libp2p builder structure.
    // `config` is taken by value: every caller constructs a fresh config and hands
    // it over, and the body picks fields out, so converting to `&Libp2pConfig`
    // would just force the body to copy each scalar field.
    #[allow(clippy::too_many_lines, clippy::needless_pass_by_value)]
    pub fn new(
        config: Libp2pConfig,
        network: NetworkDefinition,
        keypair: Keypair,
        vnodes: Vec<LocalVnodeIdentity>,
        local_shards: HashSet<ShardId>,
        registry: Arc<HandlerRegistry>,
        validator_keys: Arc<ValidatorKeyMap>,
    ) -> Result<Arc<Self>, NetworkError> {
        assert!(
            !vnodes.is_empty(),
            "Libp2pAdapter needs at least one hosted vnode"
        );
        let local_peer_id = Libp2pPeerId::from(keypair.public());
        // Shared between the bind service (attests as every vnode) and the
        // event loop (signs the periodic address announcements).
        let vnodes: Arc<[LocalVnodeIdentity]> = Arc::from(vnodes);
        let local_validator_ids: Vec<ValidatorId> = vnodes.iter().map(|(vid, _)| *vid).collect();

        info!(
            local_peer_id = %local_peer_id,
            validator_ids = ?local_validator_ids,
            shard_count = local_shards.len(),
            "Creating libp2p network adapter"
        );

        // Configure gossipsub
        let gossipsub_config = GossipsubConfigBuilder::default()
            .heartbeat_interval(config.gossipsub_heartbeat)
            .history_length(config.gossipsub_history_length)
            .validation_mode(ValidationMode::None)
            .validate_messages()
            .message_id_fn(|msg| {
                // Use message data + topic as ID for deduplication.
                // Including the topic allows the same message (e.g., cross-shard transaction)
                // to be published to multiple shard topics without being rejected as duplicate.
                use std::hash::{Hash, Hasher};
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                msg.data.hash(&mut hasher);
                msg.topic.hash(&mut hasher);
                // more efficient than previous .to_string()
                MessageId::from(hasher.finish().to_le_bytes().to_vec())
            })
            .max_transmit_size(config.max_message_size)
            .build()
            .map_err(|e| NetworkError::NetworkError(e.to_string()))?;

        let gossipsub = GossipsubBehaviour::new(MessageAuthenticity::Anonymous, gossipsub_config)
            .map_err(|e| NetworkError::NetworkError(e.to_string()))?;

        // Set up Kademlia DHT for peer discovery
        let store = KadMemoryStore::new(local_peer_id);
        let mut kademlia = KadBehaviour::new(local_peer_id, store);
        // Set to server mode so we can serve routing information to peers
        kademlia.set_mode(Some(KadMode::Server));

        // Set up raw stream behaviour for request/response.
        // This replaces request_response - RequestManager owns all timeout logic.
        let stream_behaviour = StreamBehaviour::new();
        let stream_control = stream_behaviour.new_control();

        // Connection limits
        let limits = ConnectionLimitsBehaviour::new(
            ConnectionLimits::default()
                .with_max_pending_incoming(Some(10))
                .with_max_pending_outgoing(Some(10))
                .with_max_established_incoming(Some(100))
                .with_max_established_outgoing(Some(100))
                .with_max_established_per_peer(Some(2)),
        );

        // Configure Identify protocol.
        // Agent version format: "hyperscale/<version>"
        // Used for version compatibility checks; ValidatorId binding is
        // handled separately by the validator-bind protocol.
        let version = option_env!("HYPERSCALE_VERSION").unwrap_or("localdev");
        let identify_config =
            IdentifyConfig::new("/hyperscale/1.0.0".to_string(), keypair.public())
                .with_agent_version(format!("hyperscale/{version}"));
        let identify = IdentifyBehaviour::new(identify_config);

        let behaviour = Behaviour {
            gossipsub,
            kademlia,
            stream: stream_behaviour,
            identify,
            limits,
        };

        let mut swarm = super::swarm_builder::build_swarm(&config, keypair, behaviour)?;

        for addr in &config.listen_addresses {
            swarm.listen_on(addr.clone()).map_err(|e| {
                NetworkError::NetworkError(format!(
                    "Failed to bind QUIC transport on {addr}: {e:?}"
                ))
            })?;
            info!("Listening on: {}", addr);
        }

        // Connect to bootstrap peers
        for addr in &config.bootstrap_peers {
            swarm
                .dial(addr.clone())
                .map_err(|e| NetworkError::ConnectionFailed(e.to_string()))?;
            info!("Dialing bootstrap peer: {}", addr);
        }

        let validator_peers = Arc::new(DashMap::new());
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

        // Channel for gossipsub validation results.
        // The gossipsub handler sends Accept/Reject reports; the event loop
        // drains them and calls report_message_validation_result on the swarm.
        let (validation_tx, validation_rx) =
            mpsc::unbounded_channel::<super::gossipsub::ValidationReport>();

        // Class-tiered command channels — commands are routed by message class.
        // Consensus (shard round-blocking) is drained before Recovery (sync) and Bulk.
        let (
            priority_channels,
            (consensus_rx, block_completion_rx, cross_shard_progress_rx, recovery_rx, bulk_rx),
        ) = ClassCommandChannels::new();

        let cached_peer_count = Arc::new(AtomicUsize::new(0));

        // Wrap validator keys in ArcSwap for lock-free updates on topology changes.
        let shared_keys = Arc::new(ArcSwap::from(validator_keys));

        // Spawn the validator-bind service. This handles cryptographic
        // ValidatorId ↔ PeerId binding via BLS signatures.
        let bind_handle = spawn_validator_bind_service(
            stream_control.clone(),
            network.clone(),
            validator_peers.clone(),
            Arc::clone(&vnodes),
            local_peer_id,
            Arc::clone(&shared_keys),
        );

        let adapter = Arc::new(Self {
            local_peer_id,
            local_validator_ids,
            local_shards: Arc::new(ArcSwap::from_pointee(local_shards)),
            priority_channels,
            validator_peers: validator_peers.clone(),
            shutdown_tx: Some(shutdown_tx),
            cached_peer_count: cached_peer_count.clone(),
            stream_control,
            validator_keys: shared_keys,
            network: network.clone(),
            address_book: Arc::new(AddressBook::default()),
            wanted_validators: Arc::new(ArcSwap::from_pointee(HashSet::new())),
            fault_gate: Arc::new(FaultState::new()),
        });

        // Spawn with panic catching - network loop panics are critical but shouldn't
        // crash the entire node. The process supervisor (systemd/k8s) should restart.
        let event_loop_validator_peers = validator_peers;
        let event_loop_local_shards = Arc::clone(&adapter.local_shards);
        let event_loop_fault_gate = Arc::clone(&adapter.fault_gate);
        let bind_trigger_tx = bind_handle.bind_tx.clone();
        let bootstrap_peers = config.bootstrap_peers.clone();
        let announce_network = network;
        let announce_vnodes = vnodes;
        let event_loop_wanted = Arc::clone(&adapter.wanted_validators);
        let event_loop_address_book = Arc::clone(&adapter.address_book);
        spawn(async move {
            // Keep bind_handle alive for the lifetime of the event loop.
            let _bind_handle = bind_handle;

            let result = std::panic::AssertUnwindSafe(super::event_loop::run(
                swarm,
                consensus_rx,
                block_completion_rx,
                cross_shard_progress_rx,
                recovery_rx,
                bulk_rx,
                shutdown_rx,
                cached_peer_count,
                event_loop_local_shards,
                config.version_interop_mode,
                registry,
                event_loop_validator_peers,
                validation_tx,
                validation_rx,
                bind_trigger_tx,
                bootstrap_peers,
                event_loop_fault_gate,
                announce_network,
                announce_vnodes,
                event_loop_wanted,
                event_loop_address_book,
            ))
            .catch_unwind()
            .await;

            match result {
                Ok(()) => {
                    info!("Network event loop exited normally");
                }
                Err(panic_info) => {
                    let panic_msg = panic_info
                        .downcast_ref::<&str>()
                        .map(ToString::to_string)
                        .or_else(|| panic_info.downcast_ref::<String>().cloned())
                        .unwrap_or_else(|| "Unknown panic".to_string());

                    // Log critical error - this should trigger alerts
                    tracing::error!(
                        panic = %panic_msg,
                        "CRITICAL: Network event loop panicked! Networking is down. Node restart required."
                    );
                }
            }
        });

        Ok(adapter)
    }

    /// Update the validator key map for bind verification.
    ///
    /// Called by `Libp2pNetwork::update_validator_keys` on topology changes.
    pub fn update_validator_keys(&self, keys: Arc<ValidatorKeyMap>) {
        self.validator_keys.store(keys);
    }

    /// Subscribe to a gossipsub topic.
    ///
    /// Called by `Libp2pNetwork::register_gossip_handler` to auto-subscribe
    /// when a handler is registered.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkError::NetworkShutdown`] if the swarm task has stopped.
    pub fn subscribe_topic(&self, topic: String) -> Result<(), NetworkError> {
        self.priority_channels
            .send(SwarmCommand::Subscribe { topic })
            .map_err(|_| NetworkError::NetworkShutdown)
    }

    /// Publish pre-encoded data to a topic with a given class.
    ///
    /// Messages are routed to the appropriate class channel based on the
    /// provided [`MessageClass`]. Consensus messages (shard round-blocking) are
    /// processed before Recovery messages (sync) and Bulk (tx gossip).
    ///
    /// Callers are responsible for SBOR-encoding and compressing the message
    /// before calling this method (use `sbor::basic_encode` + `compression::compress`).
    ///
    /// # Errors
    ///
    /// Returns [`NetworkError::NetworkShutdown`] if the swarm task has stopped.
    pub fn publish(
        &self,
        topic: &Topic,
        data: Vec<u8>,
        class: MessageClass,
    ) -> Result<(), NetworkError> {
        let data_len = data.len();

        self.priority_channels
            .send(SwarmCommand::Broadcast {
                topic: topic.to_string(),
                data,
                class,
            })
            .map_err(|_| NetworkError::NetworkShutdown)?;

        record_network_message_sent();
        record_libp2p_bandwidth(0, data_len as u64);

        trace!(
            topic = %topic,
            class = ?class,
            data_len,
            "Published message"
        );

        Ok(())
    }

    /// Dial a peer address.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkError::NetworkShutdown`] if the swarm task has stopped.
    pub fn dial(&self, address: Multiaddr) -> Result<(), NetworkError> {
        self.priority_channels
            .send(SwarmCommand::Dial { address })
            .map_err(|_| NetworkError::NetworkShutdown)
    }

    /// Get the local peer ID.
    #[must_use]
    pub const fn local_peer_id(&self) -> Libp2pPeerId {
        self.local_peer_id
    }

    /// Validator ids hosted by this libp2p peer. Length is 1 under
    /// single-vnode hosting and larger when the host runs several
    /// same-shard vnodes off one peer identity.
    #[must_use]
    pub fn local_validator_ids(&self) -> &[ValidatorId] {
        &self.local_validator_ids
    }

    /// Shards hosted by this libp2p peer (a loaded snapshot). Drives
    /// per-shard request stream protocol registration and per-shard
    /// gossipsub subscriptions.
    #[must_use]
    pub fn local_shards(&self) -> Arc<HashSet<ShardId>> {
        self.local_shards.load_full()
    }

    /// Add `shard` to the hosted set — the event loop's inbound
    /// shard-local filter admits its topics from the next message.
    pub fn add_local_shard(&self, shard: ShardId) {
        let mut set = (**self.local_shards.load()).clone();
        set.insert(shard);
        self.local_shards.store(Arc::new(set));
    }

    /// Remove `shard` from the hosted set — the inbound filter rejects
    /// its shard-local topics from the next message.
    pub fn remove_local_shard(&self, shard: ShardId) {
        let mut set = (**self.local_shards.load()).clone();
        set.remove(&shard);
        self.local_shards.store(Arc::new(set));
    }

    /// Unsubscribe from a gossipsub topic.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkError::NetworkShutdown`] if the swarm task has stopped.
    pub fn unsubscribe_topic(&self, topic: String) -> Result<(), NetworkError> {
        self.priority_channels
            .send(SwarmCommand::Unsubscribe { topic })
            .map_err(|_| NetworkError::NetworkShutdown)
    }

    /// Get the cached connected peer count (non-blocking).
    ///
    /// This returns instantly from an atomic counter that's updated by the
    /// network event loop whenever connections are established or closed.
    /// Use this in hot paths like the consensus event loop.
    #[must_use]
    pub fn cached_peer_count(&self) -> usize {
        self.cached_peer_count.load(Ordering::Relaxed)
    }

    /// Get connected peers by sending a command to the swarm task and
    /// awaiting its response.
    ///
    /// For hot paths like metrics collection in the consensus loop, prefer
    /// [`Self::cached_peer_count`] which returns instantly.
    pub async fn connected_peers(&self) -> Vec<Libp2pPeerId> {
        let (tx, rx) = oneshot::channel();
        let cmd = SwarmCommand::GetConnectedPeers { response_tx: tx };

        if self.priority_channels.send(cmd).is_err() {
            return vec![];
        }

        rx.await.unwrap_or_default()
    }

    /// Get listen addresses.
    pub async fn listen_addresses(&self) -> Vec<Multiaddr> {
        let (tx, rx) = oneshot::channel();
        let cmd = SwarmCommand::GetListenAddresses { response_tx: tx };

        if self.priority_channels.send(cmd).is_err() {
            return vec![];
        }

        rx.await.unwrap_or_default()
    }

    /// Open a bidirectional stream to a peer.
    ///
    /// This is the low-level stream API. The caller is responsible for:
    /// - All timeout logic (via `tokio::time::timeout` wrapping read/write)
    /// - Framing (length-prefixed messages)
    /// - Closing the stream when done
    ///
    /// `RequestManager` should be used for request/response patterns - it wraps
    /// this method with proper timeout, retry, and peer selection logic.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkError::ProtocolUnsupported`] when the peer does not
    /// serve `shard`'s request protocol, and
    /// [`NetworkError::StreamOpenFailed`] for any other rejected open (peer
    /// unknown, handshake I/O failure, etc.).
    pub async fn open_request_stream(
        &self,
        peer: Libp2pPeerId,
        shard: ShardId,
    ) -> Result<Stream, NetworkError> {
        self.stream_control
            .clone()
            .open_stream(peer, request_protocol(shard))
            .await
            .map_err(|e| match e {
                OpenStreamError::UnsupportedProtocol(proto) => {
                    NetworkError::ProtocolUnsupported(proto.to_string())
                }
                other => NetworkError::StreamOpenFailed(format!("{other:?}")),
            })
    }

    /// Open a fire-and-forget notification stream to a peer.
    ///
    /// Uses `NOTIFY_PROTOCOL` — the receiver reads the typed frame and closes
    /// the stream (no response is sent back).
    ///
    /// # Errors
    ///
    /// Returns [`NetworkError::StreamOpenFailed`] if the underlying libp2p
    /// stream control rejects the open.
    pub async fn open_notify_stream(&self, peer: Libp2pPeerId) -> Result<Stream, NetworkError> {
        self.stream_control
            .clone()
            .open_stream(peer, NOTIFY_PROTOCOL)
            .await
            .map_err(|e| NetworkError::StreamOpenFailed(format!("{e:?}")))
    }

    /// Get the peer ID for a validator (if known).
    #[must_use]
    pub fn peer_for_validator(&self, validator_id: ValidatorId) -> Option<Libp2pPeerId> {
        self.validator_peers.get(&validator_id).map(|r| *r)
    }

    /// The signed validator address book built from gossiped announcements.
    #[must_use]
    pub const fn address_book(&self) -> &Arc<AddressBook> {
        &self.address_book
    }

    /// Verify one gossiped address announcement against the current
    /// validator keys and store it in the book if it is the newest for its
    /// validator.
    #[must_use]
    pub fn ingest_validator_address(&self, gossip: &ValidatorAddressGossip) -> IngestOutcome {
        self.address_book
            .ingest(&self.network, &self.validator_keys.load(), gossip)
    }

    /// Replace the set of validators this host must hold unicast
    /// connectivity to, and immediately dial the unbound ones whose
    /// addresses the book already knows. A freshly seated committee's
    /// members were announcing as pool followers, so this seat-time pass
    /// usually connects them at once; the event loop's maintenance sweep
    /// covers the ones whose announcements arrive later and any dial that
    /// fails.
    pub fn update_wanted_validators(&self, wanted: HashSet<ValidatorId>) {
        let candidates = self
            .address_book
            .dial_candidates(&wanted, &self.validator_peers);
        self.wanted_validators.store(Arc::new(wanted));
        for record in candidates {
            let _ = self.priority_channels.send(SwarmCommand::DialPeer {
                peer_id: record.peer_id,
                addresses: record.addresses,
            });
        }
    }

    /// The fault gate consulted at this adapter's delivery seams. A zero-sized
    /// no-op unless `test-utils` is enabled; under it, test clusters install
    /// drop rules and partitions through the gate.
    #[must_use]
    pub fn fault_gate(&self) -> &FaultState {
        &self.fault_gate
    }

    /// Configure the fault gate: this host's id and the full `PeerId → HostId`
    /// map. The harness calls this once before installing faults.
    #[cfg(feature = "test-utils")]
    pub fn fault_configure(
        &self,
        self_host: HostId,
        peers: impl IntoIterator<Item = (Libp2pPeerId, HostId)>,
    ) {
        self.fault_gate.configure(self_host, peers);
    }

    /// Get a clone of the stream control handle.
    ///
    /// This allows external components (like `InboundRouter`) to accept incoming streams.
    #[must_use]
    pub fn stream_control(&self) -> StreamControl {
        self.stream_control.clone()
    }
}

impl Drop for Libp2pAdapter {
    fn drop(&mut self) {
        // Signal shutdown to event loop
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.try_send(());
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::config::Libp2pConfig;

    #[test]
    fn test_config_defaults() {
        let config = Libp2pConfig::default();
        assert!(!config.listen_addresses.is_empty());
        assert_eq!(config.max_message_size, 1024 * 1024 * 10); // 10MB
    }
}
