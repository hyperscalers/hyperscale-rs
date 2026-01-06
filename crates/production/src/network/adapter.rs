//! libp2p network adapter for production use.
//!
//! This module provides the core networking implementation using libp2p with:
//! - Gossipsub for efficient broadcast messaging
//! - Kademlia DHT for peer discovery
//! - Request-Response for sync block fetching
//! - QUIC transport for reliable, encrypted connections

use super::codec::CodecError;
use super::codec_pool::CodecPoolHandle;
use super::config::Libp2pConfig;
use super::inbound_router::InboundRequest;
use super::rate_limiter::{RateLimitConfig, SyncRateLimiter};
use super::topic::Topic;
use crate::metrics;
use crate::network::config::VersionInteroperabilityMode;
use crate::validation_batcher::ValidationBatcherHandle;
use bytes::Bytes;
use dashmap::DashMap;
use futures::future::Either;
use futures::{FutureExt, StreamExt};
use hyperscale_core::{Event, OutboundMessage};
use hyperscale_types::{Bls12381G1PublicKey, MessagePriority, ShardGroupId, ValidatorId};
use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::transport::{OrTransport, Transport};
use libp2p::core::upgrade::Version;
use libp2p::{
    gossipsub, identify, identity, kad,
    request_response::{self, ProtocolSupport, ResponseChannel},
    swarm::{NetworkBehaviour, SwarmEvent},
    Multiaddr, PeerId as Libp2pPeerId, StreamProtocol, Swarm, SwarmBuilder,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
#[cfg(feature = "trace-propagation")]
use tracing::Instrument;
use tracing::{debug, info, trace, warn};
#[cfg(feature = "trace-propagation")]
use tracing_opentelemetry::OpenTelemetrySpanExt;

/// Domain separator for deriving libp2p identity from validator public key.
const LIBP2P_IDENTITY_DOMAIN: &[u8] = b"hyperscale-libp2p-identity-v1:";

/// Derive a libp2p Ed25519 keypair deterministically from a validator's public key.
///
/// This ensures that each validator's PeerId is deterministic and can be computed
/// by other validators from the known public key. This enables peer validation
/// at the network layer.
///
/// The derivation:
/// 1. Hash the public key bytes with a domain separator
/// 2. Use the hash as a seed to derive an Ed25519 keypair
///
/// IMPORTANT: The derivation is based on the PUBLIC key, not the secret key.
/// This allows other validators to compute any validator's PeerId from their
/// known public key.
pub fn derive_libp2p_keypair(public_key: &Bls12381G1PublicKey) -> identity::Keypair {
    use sha2::{Digest, Sha256};

    let public_bytes = public_key.to_vec();

    // Domain-separated hash to derive a seed
    let mut hasher = Sha256::new();
    hasher.update(LIBP2P_IDENTITY_DOMAIN);
    hasher.update(public_bytes);
    let derived_seed: [u8; 32] = hasher.finalize().into();

    // Create an Ed25519 keypair from the derived seed using libp2p's SecretKey type
    let secret_key = identity::ed25519::SecretKey::try_from_bytes(derived_seed)
        .expect("valid ed25519 secret key from derived seed");

    identity::Keypair::from(identity::ed25519::Keypair::from(secret_key))
}

/// Compute the libp2p PeerId for a validator from their signing public key.
///
/// This is a convenience wrapper around `derive_libp2p_keypair` that returns
/// just the PeerId.
pub fn compute_peer_id_for_validator(public_key: &Bls12381G1PublicKey) -> Libp2pPeerId {
    derive_libp2p_keypair(public_key).public().to_peer_id()
}

/// High-priority response commands sent to the swarm task.
///
/// These commands are processed before normal commands because they unblock
/// other validators waiting for data. Using a separate channel ensures
/// response commands don't get queued behind broadcasts/requests.
#[derive(Debug)]
pub enum ResponseCommand {
    /// Send a response (by channel ID).
    /// Used by InboundRouter to send responses for all request types.
    SendResponse { channel_id: u64, response: Vec<u8> },
}

/// Commands sent to the swarm task.
///
/// Commands are processed in priority order when using priority channels.
/// Non-broadcast commands (Subscribe, Dial, etc.) are always processed
/// with high priority since they're control operations.
#[derive(Debug)]
pub enum SwarmCommand {
    /// Subscribe to a gossipsub topic.
    Subscribe { topic: String },

    /// Broadcast a message to a topic with priority.
    ///
    /// Priority determines processing order in the event loop.
    /// Higher priority messages are processed before lower priority ones.
    Broadcast {
        topic: String,
        data: Vec<u8>,
        priority: MessagePriority,
    },

    /// Dial a peer.
    Dial { address: Multiaddr },

    /// Query listen addresses.
    GetListenAddresses {
        response_tx: tokio::sync::oneshot::Sender<Vec<Multiaddr>>,
    },

    /// Query connected peers.
    GetConnectedPeers {
        response_tx: tokio::sync::oneshot::Sender<Vec<Libp2pPeerId>>,
    },

    /// Send a request to a peer and wait for response (generic).
    ///
    /// The caller is responsible for encoding the request data.
    /// Priority determines queue ordering.
    Request {
        peer: Libp2pPeerId,
        data: Bytes,
        priority: MessagePriority,
        response_tx: tokio::sync::oneshot::Sender<Result<Vec<u8>, NetworkError>>,
    },
}

/// A pending response channel with its creation time for timeout cleanup.
struct PendingResponseChannel {
    channel: ResponseChannel<Vec<u8>>,
    created_at: std::time::Instant,
}

/// A pending outbound request awaiting response.
struct PendingRequest {
    /// The response channel for the request.
    response_tx: tokio::sync::oneshot::Sender<Result<Vec<u8>, NetworkError>>,
    /// When the request was created (for timeout cleanup).
    created_at: std::time::Instant,
}

/// Interval for periodic maintenance tasks in the event loop.
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(5);

/// Timeout for pending response channels (after which they are cleaned up).
/// This should be slightly longer than the request_timeout (5s) to allow for processing.
const RESPONSE_CHANNEL_TIMEOUT: Duration = Duration::from_secs(7);

/// Timeout for pending outbound requests (after which they are cleaned up).
/// This is a safety net for when libp2p's OutboundFailure::Timeout doesn't fire.
/// Set to 30s as an emergency backstop - RequestManager handles RTT-based timeouts
/// much faster (500ms-5s), so this should rarely fire in practice.
const PENDING_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum number of pending outbound requests before applying backpressure.
/// When exceeded, new requests are rejected with `NetworkError::Backpressure`.
/// This prevents runaway request accumulation when the network is saturated
/// (e.g., when libp2p hits max sub-streams and requests fail fast, triggering
/// rapid retries that accumulate in pending_requests).
/// Set to ~1000 to allow healthy concurrency while preventing pathological cases
/// where 5000+ requests accumulate.
const MAX_PENDING_REQUESTS: usize = 1000;

/// Delay before attempting to reconnect to a disconnected validator.
const RECONNECT_DELAY: Duration = Duration::from_secs(2);

/// Interval for periodic Kademlia refresh to discover new peers.
const KADEMLIA_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

/// Maximum number of commands to drain per event loop iteration.
/// Prevents tight loops from monopolizing the event loop when channels are flooded.
/// High-priority response commands and normal commands each have this limit.
const MAX_COMMANDS_PER_DRAIN: usize = 100;

/// Priority-based command channels for the swarm task.
///
/// Commands are sent to the appropriate channel based on message priority.
/// The event loop processes channels in priority order (Critical first, Background last).
#[derive(Clone, Debug)]
pub struct PriorityCommandChannels {
    /// Critical priority - BFT consensus messages, pending block requests.
    /// Never dropped, processed immediately.
    critical: mpsc::UnboundedSender<SwarmCommand>,

    /// Coordination priority - Cross-shard 2PC messages.
    /// High priority, may be batched.
    coordination: mpsc::UnboundedSender<SwarmCommand>,

    /// Finalization priority - Transaction certificate gossip.
    /// Important but not liveness-critical.
    finalization: mpsc::UnboundedSender<SwarmCommand>,

    /// Propagation priority - Transaction gossip (mempool).
    /// Best-effort, can be shed under load.
    propagation: mpsc::UnboundedSender<SwarmCommand>,

    /// Background priority - Sync operations.
    /// Lowest priority, fully deferrable.
    background: mpsc::UnboundedSender<SwarmCommand>,
}

/// Receiver type for priority command channels.
type PriorityReceivers = (
    mpsc::UnboundedReceiver<SwarmCommand>,
    mpsc::UnboundedReceiver<SwarmCommand>,
    mpsc::UnboundedReceiver<SwarmCommand>,
    mpsc::UnboundedReceiver<SwarmCommand>,
    mpsc::UnboundedReceiver<SwarmCommand>,
);

impl PriorityCommandChannels {
    /// Create new priority channels, returning (senders, receivers).
    fn new() -> (Self, PriorityReceivers) {
        let (critical_tx, critical_rx) = mpsc::unbounded_channel();
        let (coordination_tx, coordination_rx) = mpsc::unbounded_channel();
        let (finalization_tx, finalization_rx) = mpsc::unbounded_channel();
        let (propagation_tx, propagation_rx) = mpsc::unbounded_channel();
        let (background_tx, background_rx) = mpsc::unbounded_channel();

        (
            Self {
                critical: critical_tx,
                coordination: coordination_tx,
                finalization: finalization_tx,
                propagation: propagation_tx,
                background: background_tx,
            },
            (
                critical_rx,
                coordination_rx,
                finalization_rx,
                propagation_rx,
                background_rx,
            ),
        )
    }

    /// Send a command to the appropriate priority channel.
    ///
    /// For Broadcast commands, uses the embedded priority.
    /// For control commands (Subscribe, Dial, etc.), uses Critical priority.
    #[allow(clippy::result_large_err)]
    pub fn send(&self, cmd: SwarmCommand) -> Result<(), mpsc::error::SendError<SwarmCommand>> {
        let priority = match &cmd {
            SwarmCommand::Broadcast { priority, .. } => *priority,
            // Control commands always get critical priority
            SwarmCommand::Subscribe { .. }
            | SwarmCommand::Dial { .. }
            | SwarmCommand::GetListenAddresses { .. }
            | SwarmCommand::GetConnectedPeers { .. } => MessagePriority::Critical,
            // Requests use their inherent priority from the caller
            SwarmCommand::Request { priority, .. } => *priority,
        };

        match priority {
            MessagePriority::Critical => self.critical.send(cmd),
            MessagePriority::Coordination => self.coordination.send(cmd),
            MessagePriority::Finalization => self.finalization.send(cmd),
            MessagePriority::Propagation => self.propagation.send(cmd),
            MessagePriority::Background => self.background.send(cmd),
        }
    }
}

/// Network errors.
#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Network shutdown")]
    NetworkShutdown,

    #[error("Request timeout")]
    Timeout,

    #[error("Codec error: {0}")]
    CodecError(#[from] CodecError),

    #[error("Invalid peer ID")]
    InvalidPeerId,

    #[error("Network backpressure - too many pending requests")]
    Backpressure,
}

/// Codec for request-response protocol with length-prefixed messages.
#[derive(Debug, Clone, Default)]
struct HyperscaleCodec;

#[async_trait::async_trait]
impl request_response::Codec for HyperscaleCodec {
    type Protocol = StreamProtocol;
    type Request = Bytes;
    type Response = Vec<u8>;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Request>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        use futures::AsyncReadExt;

        // Read 4-byte length prefix
        let mut len_bytes = [0u8; 4];
        io.read_exact(&mut len_bytes).await?;
        let len = u32::from_be_bytes(len_bytes) as usize;

        // Read message body
        let mut buf = vec![0u8; len];
        io.read_exact(&mut buf).await?;
        Ok(Bytes::from(buf))
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Response>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        use futures::AsyncReadExt;

        let mut len_bytes = [0u8; 4];
        io.read_exact(&mut len_bytes).await?;
        let len = u32::from_be_bytes(len_bytes) as usize;

        let mut buf = vec![0u8; len];
        io.read_exact(&mut buf).await?;
        Ok(buf)
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> std::io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        use futures::AsyncWriteExt;

        let len = req.len() as u32;
        io.write_all(&len.to_be_bytes()).await?;
        io.write_all(&req).await?;
        io.close().await?;
        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> std::io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        use futures::AsyncWriteExt;

        let len = res.len() as u32;
        io.write_all(&len.to_be_bytes()).await?;
        io.write_all(&res).await?;
        io.close().await?;
        Ok(())
    }
}

/// libp2p network behaviour combining gossipsub, Kademlia, and request-response.
#[derive(NetworkBehaviour)]
struct Behaviour {
    /// Gossipsub for efficient broadcast.
    gossipsub: gossipsub::Behaviour,

    /// Kademlia DHT for peer discovery.
    kademlia: kad::Behaviour<kad::store::MemoryStore>,

    /// Request-response for sync block fetching.
    request_response: request_response::Behaviour<HyperscaleCodec>,

    /// Identify protocol for peer versioning.
    identify: identify::Behaviour,

    /// Connection limits to prevent storms.
    limits: libp2p::connection_limits::Behaviour,
}

/// libp2p-based network adapter for production use.
///
/// Uses gossipsub for efficient broadcast and Kademlia DHT for peer discovery.
/// Commands are processed in priority order via [`PriorityCommandChannels`].
pub struct Libp2pAdapter {
    /// Local peer ID.
    local_peer_id: Libp2pPeerId,

    /// Local validator ID (from topology).
    local_validator_id: ValidatorId,

    /// Local shard assignment (passed to event loop for shard validation).
    #[allow(dead_code)]
    local_shard: ShardGroupId,

    /// Priority-based command channels to swarm task.
    /// Commands are routed to the appropriate channel based on message priority.
    priority_channels: PriorityCommandChannels,

    /// High-priority response command channel.
    /// Responses are processed first to unblock waiting validators.
    response_tx: mpsc::UnboundedSender<ResponseCommand>,

    /// Consensus event channel for high-priority BFT messages (sent to runner).
    #[allow(dead_code)]
    consensus_tx: mpsc::Sender<Event>,

    /// Known validators (ValidatorId -> PeerId).
    /// Built from Topology at startup.
    validator_peers: Arc<DashMap<ValidatorId, Libp2pPeerId>>,

    /// Reverse mapping (PeerId -> ValidatorId) for inbound message validation.
    peer_validators: Arc<DashMap<Libp2pPeerId, ValidatorId>>,

    /// Shutdown signal sender.
    shutdown_tx: Option<mpsc::Sender<()>>,

    /// Channel for inbound requests (sent to InboundRouter for processing).
    /// Unbounded to avoid blocking the network event loop.
    /// The InboundRouter discriminates request types and handles them appropriately.
    #[allow(dead_code)]
    inbound_request_tx: mpsc::UnboundedSender<InboundRequest>,

    /// Cached connected peer count (updated by background task).
    /// This avoids blocking the consensus loop to query peer count.
    cached_peer_count: Arc<AtomicUsize>,

    /// Codec pool handle for async encoding (encoding happens on caller thread for broadcast).
    codec_pool: CodecPoolHandle,

    /// Request timeout (from config) - used as safety timeout for requests.
    request_timeout: Duration,
}

impl Libp2pAdapter {
    /// Create a new libp2p network adapter.
    ///
    /// # Arguments
    ///
    /// * `config` - Network configuration
    /// * `keypair` - Ed25519 keypair for libp2p identity (derived from validator key)
    /// * `validator_id` - Local validator ID
    /// * `shard` - Local shard assignment
    /// * `consensus_tx` - Channel for high-priority consensus events (BFT messages)
    /// * `tx_validation_handle` - Handle for submitting transactions to the shared batcher
    /// * `codec_pool` - Handle for async message encoding/decoding
    ///
    /// # Returns
    ///
    /// A tuple of (adapter, inbound_request_rx) where:
    /// - inbound_request_rx receives all inbound requests for the InboundRouter
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        config: Libp2pConfig,
        keypair: identity::Keypair,
        validator_id: ValidatorId,
        shard: ShardGroupId,
        consensus_tx: mpsc::Sender<Event>,
        tx_validation_handle: ValidationBatcherHandle,
        codec_pool: CodecPoolHandle,
    ) -> Result<(Arc<Self>, mpsc::UnboundedReceiver<InboundRequest>), NetworkError> {
        let local_peer_id = Libp2pPeerId::from(keypair.public());

        info!(
            local_peer_id = %local_peer_id,
            validator_id = validator_id.0,
            shard = shard.0,
            "Creating libp2p network adapter"
        );

        // Configure gossipsub
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(config.gossipsub_heartbeat)
            .validation_mode(gossipsub::ValidationMode::Strict)
            .message_id_fn(|msg| {
                // Use message data + topic as ID for deduplication.
                // Including the topic allows the same message (e.g., cross-shard transaction)
                // to be published to multiple shard topics without being rejected as duplicate.
                use std::hash::{Hash, Hasher};
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                msg.data.hash(&mut hasher);
                msg.topic.hash(&mut hasher);
                // more efficient than previous .to_string()
                gossipsub::MessageId::from(hasher.finish().to_le_bytes().to_vec())
            })
            .max_transmit_size(config.max_message_size)
            .build()
            .map_err(|e| NetworkError::NetworkError(e.to_string()))?;

        let gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(keypair.clone()),
            gossipsub_config,
        )
        .map_err(|e| NetworkError::NetworkError(e.to_string()))?;

        // Set up Kademlia DHT for peer discovery
        let store = kad::store::MemoryStore::new(local_peer_id);
        let mut kademlia = kad::Behaviour::new(local_peer_id, store);
        // Set to server mode so we can serve routing information to peers
        kademlia.set_mode(Some(kad::Mode::Server));

        // Set up request-response protocol with configured timeout.
        // This timeout is the ultimate backstop for request-response operations.
        // Higher-level timeouts (sync, fetch) should be shorter to enable retries.
        let req_resp_config =
            request_response::Config::default().with_request_timeout(config.request_timeout);
        let protocols = std::iter::once((
            StreamProtocol::new("/hyperscale/sync/1.0.0"),
            ProtocolSupport::Full,
        ));
        let request_response =
            request_response::Behaviour::with_codec(HyperscaleCodec, protocols, req_resp_config);

        // Connection limits
        let limits = libp2p::connection_limits::Behaviour::new(
            libp2p::connection_limits::ConnectionLimits::default()
                .with_max_pending_incoming(Some(10))
                .with_max_pending_outgoing(Some(10))
                .with_max_established_incoming(Some(100))
                .with_max_established_outgoing(Some(100))
                .with_max_established_per_peer(Some(2)),
        );

        // Configure Identify protocol
        let identify_config =
            identify::Config::new("/hyperscale/1.0.0".to_string(), keypair.public())
                .with_agent_version(
                    option_env!("HYPERSCALE_VERSION")
                        .unwrap_or("localdev")
                        .to_string(),
                );
        let identify = identify::Behaviour::new(identify_config);

        // Create behaviour
        let behaviour = Behaviour {
            gossipsub,
            kademlia,
            request_response,
            identify,
            limits,
        };

        // Build swarm with QUIC transport, optionally with TCP fallback
        let mut swarm = if config.tcp_fallback_enabled {
            info!("Building swarm with QUIC (primary) + TCP (fallback)");

            // QUIC configuration
            let mut quic_config = libp2p::quic::Config::new(&keypair);
            quic_config.max_concurrent_stream_limit = 4096;
            // QUIC keep-alive: sends PING frames at this interval to keep connections alive
            quic_config.keep_alive_interval = config.keep_alive_interval;
            // QUIC idle timeout: connections are closed after this duration of inactivity
            // Must be longer than keep_alive_interval to allow keep-alives to work
            quic_config.max_idle_timeout = config.idle_connection_timeout.as_millis() as u32;

            let quic_transport = libp2p::quic::tokio::Transport::new(quic_config)
                .map(|(p, c), _| (p, StreamMuxerBox::new(c)));

            // TCP configuration with Noise + Yamux
            let tcp_transport =
                libp2p::tcp::tokio::Transport::new(libp2p::tcp::Config::default().nodelay(true))
                    .upgrade(Version::V1)
                    .authenticate(
                        libp2p::noise::Config::new(&keypair)
                            .map_err(|e| NetworkError::NetworkError(e.to_string()))?,
                    )
                    .multiplex({
                        let mut config = libp2p::yamux::Config::default();
                        config.set_max_num_streams(4096);
                        // allowing deprecated because replacement (connection-level limits) is not available libp2p 0.56
                        #[allow(deprecated)]
                        {
                            config.set_max_buffer_size(16 * 1024 * 1024);
                            config.set_receive_window_size(16 * 1024 * 1024);
                        }
                        config
                    })
                    .map(|(p, c), _| (p, StreamMuxerBox::new(c)));

            // Prioritize QUIC by putting it first (Left side of OrTransport)
            let transport =
                OrTransport::new(quic_transport, tcp_transport).map(|either, _| match either {
                    Either::Left((peer_id, muxer)) => (peer_id, muxer),
                    Either::Right((peer_id, muxer)) => (peer_id, muxer),
                });

            SwarmBuilder::with_existing_identity(keypair)
                .with_tokio()
                .with_other_transport(|_| transport)
                .unwrap() // Unwrap Infallible error from transport add
                .with_behaviour(|_| behaviour)
                .map_err(|e| {
                    NetworkError::NetworkError(format!(
                        "Failed to configure swarm behaviour: {:?}",
                        e
                    ))
                })?
                .with_swarm_config(|c| {
                    c.with_idle_connection_timeout(config.idle_connection_timeout)
                        .with_max_negotiating_inbound_streams(100)
                })
                .build()
        } else {
            info!("Building swarm with QUIC only (TCP fallback disabled)");
            SwarmBuilder::with_existing_identity(keypair)
                .with_tokio()
                .with_quic_config(|mut quic_config| {
                    // Increase QUIC stream limit to match TCP yamux config (4096).
                    // Default is 256 which causes "max sub-streams reached" errors
                    // during burst sync traffic when catching up.
                    quic_config.max_concurrent_stream_limit = 4096;
                    // QUIC keep-alive: sends PING frames at this interval to keep connections alive
                    quic_config.keep_alive_interval = config.keep_alive_interval;
                    // QUIC idle timeout: connections are closed after this duration of inactivity
                    // Must be longer than keep_alive_interval to allow keep-alives to work
                    quic_config.max_idle_timeout =
                        config.idle_connection_timeout.as_millis() as u32;
                    quic_config
                })
                .with_behaviour(|_| behaviour)
                .map_err(|e| {
                    NetworkError::NetworkError(format!(
                        "Failed to configure swarm behaviour: {:?}",
                        e
                    ))
                })?
                .with_swarm_config(|c| {
                    c.with_idle_connection_timeout(config.idle_connection_timeout)
                        .with_max_negotiating_inbound_streams(100)
                })
                .build()
        };

        // Listen on configured addresses (QUIC)
        for addr in &config.listen_addresses {
            swarm.listen_on(addr.clone()).map_err(|e| {
                NetworkError::NetworkError(format!(
                    "Failed to bind QUIC transport on {}: {:?}",
                    addr, e
                ))
            })?;
            info!("Listening on: {}", addr);
        }

        // Listen on TCP fallback if enabled
        if config.tcp_fallback_enabled {
            if let Some(tcp_port) = config.tcp_fallback_port {
                let tcp_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", tcp_port)
                    .parse()
                    .map_err(|e| {
                        NetworkError::NetworkError(format!("Invalid TCP address: {}", e))
                    })?;
                swarm.listen_on(tcp_addr.clone()).map_err(|e| {
                    NetworkError::NetworkError(format!(
                        "Failed to bind TCP transport on {}: {:?}",
                        tcp_addr, e
                    ))
                })?;
                info!("Listening on TCP fallback: {}", tcp_addr);
            }
        }

        // Connect to bootstrap peers
        for addr in &config.bootstrap_peers {
            swarm
                .dial(addr.clone())
                .map_err(|e| NetworkError::ConnectionFailed(e.to_string()))?;
            info!("Dialing bootstrap peer: {}", addr);
        }

        let validator_peers = Arc::new(DashMap::new());
        let peer_validators = Arc::new(DashMap::new());
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

        // Priority-based command channels - commands are routed by message priority.
        // Critical messages (BFT consensus) are processed before Background (sync).
        let (
            priority_channels,
            (critical_rx, coordination_rx, finalization_rx, propagation_rx, background_rx),
        ) = PriorityCommandChannels::new();

        // High-priority channel for response commands - processed before normal commands
        // to minimize latency for validators waiting for sync data.
        let (response_tx, response_rx) = mpsc::unbounded_channel();
        // Unified inbound request channel - unbounded to avoid blocking the network event loop.
        // The InboundRouter discriminates request types and handles them appropriately.
        // Protection against unbounded growth:
        // 1. Rate limiter limits requests per peer (validators get higher limit)
        // 2. Response channel timeout cleanup prevents leaked channels
        // 3. Peer reputation tracking penalizes misbehaving peers
        // If memory growth is observed, consider bounded channels with try_send + drop.
        let (inbound_request_tx, inbound_request_rx) = mpsc::unbounded_channel();
        let cached_peer_count = Arc::new(AtomicUsize::new(0));

        let adapter = Arc::new(Self {
            local_peer_id,
            local_validator_id: validator_id,
            local_shard: shard,
            priority_channels,
            response_tx,
            consensus_tx: consensus_tx.clone(),
            validator_peers: validator_peers.clone(),
            peer_validators: peer_validators.clone(),
            shutdown_tx: Some(shutdown_tx),
            inbound_request_tx: inbound_request_tx.clone(),
            cached_peer_count: cached_peer_count.clone(),
            codec_pool: codec_pool.clone(),
            request_timeout: config.request_timeout,
        });

        // Spawn event loop (takes ownership of swarm)
        // Use default rate limit config for now
        let rate_limit_config = RateLimitConfig::default();

        // Spawn with panic catching - network loop panics are critical but shouldn't
        // crash the entire node. The process supervisor (systemd/k8s) should restart.
        tokio::spawn(async move {
            let result = std::panic::AssertUnwindSafe(Self::event_loop(
                swarm,
                critical_rx,
                coordination_rx,
                finalization_rx,
                propagation_rx,
                background_rx,
                response_rx,
                consensus_tx,
                peer_validators,
                shutdown_rx,
                inbound_request_tx,
                rate_limit_config,
                cached_peer_count,
                shard,
                tx_validation_handle,
                config.version_interop_mode,
                codec_pool,
            ))
            .catch_unwind()
            .await;

            match result {
                Ok(()) => {
                    info!("Network event loop exited normally");
                }
                Err(panic_info) => {
                    // Extract panic message if possible
                    let panic_msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                        s.to_string()
                    } else if let Some(s) = panic_info.downcast_ref::<String>() {
                        s.clone()
                    } else {
                        "Unknown panic".to_string()
                    };

                    // Log critical error - this should trigger alerts
                    tracing::error!(
                        panic = %panic_msg,
                        "CRITICAL: Network event loop panicked! Networking is down. Node restart required."
                    );

                    // Record metric for alerting
                    metrics::record_network_event_loop_panic();
                }
            }
        });

        Ok((adapter, inbound_request_rx))
    }

    /// Register a validator's peer ID mapping.
    ///
    /// Called during initialization to build the validator allowlist.
    pub async fn register_validator(&self, validator_id: ValidatorId, peer_id: Libp2pPeerId) {
        self.validator_peers.insert(validator_id, peer_id);
        self.peer_validators.insert(peer_id, validator_id);

        debug!(
            validator_id = validator_id.0,
            peer_id = %peer_id,
            "Registered validator peer"
        );
    }

    /// Subscribe to all message types for a shard.
    ///
    /// Called once at startup to subscribe to the local shard's topics.
    pub async fn subscribe_shard(&self, shard: ShardGroupId) -> Result<(), NetworkError> {
        let topics = [
            Topic::block_header(shard),
            Topic::block_vote(shard),
            // Note: view_change topics removed - using HotStuff-2 implicit rounds
            Topic::transaction_gossip(shard),
            Topic::transaction_certificate(shard),
            Topic::state_provision_batch(shard),
            Topic::state_vote_batch(shard),
            Topic::state_certificate_batch(shard),
        ];

        for topic in &topics {
            self.priority_channels
                .send(SwarmCommand::Subscribe {
                    topic: topic.to_string(),
                })
                .map_err(|_| NetworkError::NetworkShutdown)?;

            info!(topic = %topic, "Subscribed to topic");
        }

        Ok(())
    }

    /// Broadcast a message to a shard.
    ///
    /// Messages are routed to the appropriate priority channel based on their
    /// [`MessagePriority`]. Critical messages (BFT consensus) are processed before
    /// Background messages (sync).
    pub async fn broadcast_shard(
        &self,
        shard: ShardGroupId,
        message: &OutboundMessage,
    ) -> Result<(), NetworkError> {
        // Use gossipsub for all consensus broadcasts - it's optimized for this use case.
        // GossipSub has pre-established mesh connections with minimal latency for small committees.
        // DirectBroadcast via request-response adds per-message substream overhead.

        let topic = super::codec::topic_for_message(message, shard);
        let priority = message.priority();
        // Use synchronous encoding here since we're already on an async task
        // and encoding is fast for most messages. The codec pool is primarily
        // beneficial for decoding in the event loop.
        let data = self.codec_pool.encode_sync(message)?;
        let data_len = data.len();

        self.priority_channels
            .send(SwarmCommand::Broadcast {
                topic: topic.to_string(),
                data,
                priority,
            })
            .map_err(|_| NetworkError::NetworkShutdown)?;

        // Record metrics
        metrics::record_network_message_sent();
        metrics::record_libp2p_bandwidth(0, data_len as u64);

        trace!(
            topic = %topic,
            msg_type = message.type_name(),
            priority = ?priority,
            "Broadcast to shard"
        );

        Ok(())
    }

    /// Broadcast a message globally (to all shards).
    pub async fn broadcast_global(&self, message: &OutboundMessage) -> Result<(), NetworkError> {
        // For now, global messages are sent to all shards.
        // In the future, we might have dedicated global topics.
        // Currently, no messages use global broadcast.
        warn!("broadcast_global called but no global topics defined yet");
        let _ = message; // suppress unused warning
        Ok(())
    }

    /// Dial a peer address.
    pub async fn dial(&self, address: Multiaddr) -> Result<(), NetworkError> {
        self.priority_channels
            .send(SwarmCommand::Dial { address })
            .map_err(|_| NetworkError::NetworkShutdown)
    }

    /// Get the local peer ID.
    pub fn local_peer_id(&self) -> Libp2pPeerId {
        self.local_peer_id
    }

    /// Get the local validator ID.
    pub fn local_validator_id(&self) -> ValidatorId {
        self.local_validator_id
    }

    /// Get the cached connected peer count (non-blocking).
    ///
    /// This returns instantly from an atomic counter that's updated by the
    /// network event loop whenever connections are established or closed.
    /// Use this in hot paths like the consensus event loop.
    pub fn cached_peer_count(&self) -> usize {
        self.cached_peer_count.load(Ordering::Relaxed)
    }

    /// Get connected peers (blocking - sends command to swarm task).
    ///
    /// NOTE: This method blocks on a channel response from the swarm task.
    /// For hot paths like metrics collection in the consensus loop, prefer
    /// `cached_peer_count()` which returns instantly.
    pub async fn connected_peers(&self) -> Vec<Libp2pPeerId> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = SwarmCommand::GetConnectedPeers { response_tx: tx };

        if self.priority_channels.send(cmd).is_err() {
            return vec![];
        }

        rx.await.unwrap_or_default()
    }

    /// Get listen addresses.
    pub async fn listen_addresses(&self) -> Vec<Multiaddr> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = SwarmCommand::GetListenAddresses { response_tx: tx };

        if self.priority_channels.send(cmd).is_err() {
            return vec![];
        }

        rx.await.unwrap_or_default()
    }

    /// Send a request to a peer and wait for response.
    ///
    /// This is the generic request method. The caller is responsible for:
    /// - Encoding the request data
    /// - Specifying the priority
    /// - Decoding the response
    ///
    /// Timeout is handled by libp2p's request_timeout (configured in Libp2pConfig).
    /// Higher-level retry logic should be handled by RequestManager.
    pub async fn request(
        &self,
        peer: Libp2pPeerId,
        data: Bytes,
        priority: MessagePriority,
    ) -> Result<Vec<u8>, NetworkError> {
        let (tx, rx) = tokio::sync::oneshot::channel();

        self.priority_channels
            .send(SwarmCommand::Request {
                peer,
                data,
                priority,
                response_tx: tx,
            })
            .map_err(|_| NetworkError::NetworkShutdown)?;

        // Safety timeout: if libp2p's request_timeout doesn't fire for some reason,
        // we still need to return. This is a backstop for edge cases where the
        // request gets "lost" in the swarm without triggering OutboundFailure.
        match tokio::time::timeout(self.request_timeout, rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(NetworkError::NetworkShutdown),
            Err(_elapsed) => {
                warn!(
                    ?peer,
                    "Request safety timeout - libp2p timeout may not have fired"
                );
                Err(NetworkError::Timeout)
            }
        }
    }

    /// Get the peer ID for a validator (if known).
    pub fn peer_for_validator(&self, validator_id: ValidatorId) -> Option<Libp2pPeerId> {
        self.validator_peers.get(&validator_id).map(|r| *r)
    }

    /// Send a generic response for an inbound request.
    ///
    /// This is the unified response method used by `InboundRouter`.
    /// The `channel_id` comes from the `InboundRequest` received via the request channel.
    /// Uses the high-priority response channel to minimize latency.
    pub fn respond(&self, channel_id: u64, response: Vec<u8>) -> Result<(), NetworkError> {
        self.response_tx
            .send(ResponseCommand::SendResponse {
                channel_id,
                response,
            })
            .map_err(|_| NetworkError::NetworkShutdown)
    }

    /// Background event loop that processes swarm events and routes messages.
    ///
    /// Commands are processed in priority order:
    /// 1. Response commands (highest - unblock waiting validators)
    /// 2. Critical priority (BFT consensus)
    /// 3. Coordination priority (cross-shard 2PC)
    /// 4. Finalization priority (certificate gossip)
    /// 5. Propagation priority (transaction gossip)
    /// 6. Background priority (sync operations)
    #[allow(clippy::too_many_arguments)]
    async fn event_loop(
        mut swarm: Swarm<Behaviour>,
        mut critical_rx: mpsc::UnboundedReceiver<SwarmCommand>,
        mut coordination_rx: mpsc::UnboundedReceiver<SwarmCommand>,
        mut finalization_rx: mpsc::UnboundedReceiver<SwarmCommand>,
        mut propagation_rx: mpsc::UnboundedReceiver<SwarmCommand>,
        mut background_rx: mpsc::UnboundedReceiver<SwarmCommand>,
        mut response_rx: mpsc::UnboundedReceiver<ResponseCommand>,
        consensus_tx: mpsc::Sender<Event>,
        peer_validators: Arc<DashMap<Libp2pPeerId, ValidatorId>>,
        mut shutdown_rx: mpsc::Receiver<()>,
        inbound_request_tx: mpsc::UnboundedSender<InboundRequest>,
        rate_limit_config: RateLimitConfig,
        cached_peer_count: Arc<AtomicUsize>,
        local_shard: ShardGroupId,
        tx_validation_handle: ValidationBatcherHandle,
        version_interop_mode: VersionInteroperabilityMode,
        codec_pool: CodecPoolHandle,
    ) {
        // Track pending sync requests (outbound) with creation time for TTL cleanup
        let mut pending_requests: HashMap<request_response::OutboundRequestId, PendingRequest> =
            HashMap::new();

        // Track pending response channels (inbound) - keyed by channel_id
        // Uses PendingResponseChannel to track creation time for timeout cleanup
        let mut pending_response_channels: HashMap<u64, PendingResponseChannel> = HashMap::new();
        let mut next_channel_id: u64 = 0;

        // Rate limiter for inbound sync requests
        let mut rate_limiter = SyncRateLimiter::new(rate_limit_config);

        // Track whether we've bootstrapped Kademlia (do it once after first connection)
        let mut kademlia_bootstrapped = false;

        // Maintenance timer for periodic tasks (cleanup, reconnection, Kademlia refresh)
        let mut maintenance_interval = tokio::time::interval(MAINTENANCE_INTERVAL);
        maintenance_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Track last Kademlia refresh time
        let mut last_kademlia_refresh = std::time::Instant::now();

        // Track validators that need reconnection (peer_id -> scheduled_reconnect_time)
        let mut pending_reconnects: HashMap<Libp2pPeerId, std::time::Instant> = HashMap::new();

        // Track known validator addresses for reconnection
        // (peer_id -> last known address)
        let mut validator_addresses: HashMap<Libp2pPeerId, Multiaddr> = HashMap::new();

        loop {
            tokio::select! {
                // Handle shutdown signal
                _ = shutdown_rx.recv() => {
                    info!("Shutting down libp2p network event loop");
                    break;
                }

                // Periodic maintenance tasks
                _ = maintenance_interval.tick() => {
                    let now = std::time::Instant::now();

                    // 1. Clean up timed-out pending response channels
                    let before_count = pending_response_channels.len();
                    pending_response_channels.retain(|channel_id, pending| {
                        let expired = now.duration_since(pending.created_at) > RESPONSE_CHANNEL_TIMEOUT;
                        if expired {
                            warn!(
                                channel_id,
                                age_secs = now.duration_since(pending.created_at).as_secs(),
                                "Cleaning up timed-out response channel"
                            );
                        }
                        !expired
                    });
                    let cleaned = before_count - pending_response_channels.len();
                    if cleaned > 0 {
                        info!(cleaned, remaining = pending_response_channels.len(), "Cleaned up timed-out response channels");
                    }

                    // 2. Clean up timed-out pending requests (safety net for libp2p failures).
                    // Normally libp2p's OutboundFailure::Timeout handles this, but if that
                    // doesn't fire for some reason, we clean up here to prevent memory leaks.
                    let expired_requests: Vec<_> = pending_requests
                        .iter()
                        .filter(|(_, pending)| {
                            now.duration_since(pending.created_at) > PENDING_REQUEST_TIMEOUT
                        })
                        .map(|(req_id, _)| *req_id)
                        .collect();

                    for req_id in &expired_requests {
                        if let Some(pending) = pending_requests.remove(req_id) {
                            warn!(
                                ?req_id,
                                age_secs = now.duration_since(pending.created_at).as_secs(),
                                "Cleaning up timed-out pending request (libp2p timeout may not have fired)"
                            );
                            // Send timeout error to the caller so they're not left waiting forever
                            let _ = pending.response_tx.send(Err(NetworkError::Timeout));
                        }
                    }
                    if !expired_requests.is_empty() {
                        info!(
                            cleaned_requests = expired_requests.len(),
                            remaining = pending_requests.len(),
                            "Cleaned up timed-out pending requests"
                        );
                    }

                    // 4. Record metrics for pending response channels
                    metrics::record_pending_response_channels(pending_response_channels.len());

                    // 5. Process pending reconnections
                    let reconnects_due: Vec<_> = pending_reconnects
                        .iter()
                        .filter(|(_, scheduled)| now >= **scheduled)
                        .map(|(peer, _)| *peer)
                        .collect();

                    for peer in reconnects_due {
                        pending_reconnects.remove(&peer);

                        // Only reconnect if this is a known validator and we're not already connected
                        if peer_validators.contains_key(&peer) && !swarm.is_connected(&peer) {
                            if let Some(addr) = validator_addresses.get(&peer) {
                                info!(
                                    peer = %peer,
                                    addr = %addr,
                                    "Attempting to reconnect to validator"
                                );
                                if let Err(e) = swarm.dial(addr.clone()) {
                                    warn!(
                                        peer = %peer,
                                        error = ?e,
                                        "Failed to dial validator for reconnection"
                                    );
                                    // Schedule another reconnect attempt
                                    pending_reconnects.insert(peer, now + RECONNECT_DELAY * 2);
                                }
                            } else {
                                // No known address, try to find via Kademlia
                                debug!(peer = %peer, "No known address for validator, relying on Kademlia discovery");
                            }
                        }
                    }

                    // 4. Periodic Kademlia refresh for peer discovery
                    if kademlia_bootstrapped && now.duration_since(last_kademlia_refresh) > KADEMLIA_REFRESH_INTERVAL {
                        // Trigger a random walk to discover new peers
                        let random_peer = Libp2pPeerId::random();
                        swarm.behaviour_mut().kademlia.get_closest_peers(random_peer);
                        last_kademlia_refresh = now;
                        debug!("Triggered Kademlia refresh for peer discovery");
                    }

                    // 5. Check connection health - ensure we're connected to validators
                    let connected_count = swarm.connected_peers().count();
                    let validator_count = peer_validators.len();
                    if connected_count < validator_count / 2 {
                        warn!(
                            connected = connected_count,
                            total_validators = validator_count,
                            "Low peer connectivity - connected to less than half of validators"
                        );
                        // Trigger Kademlia bootstrap to find more peers
                        if kademlia_bootstrapped {
                            let _ = swarm.behaviour_mut().kademlia.bootstrap();
                        }
                    }
                }

                // Handle high-priority response commands first.
                // These unblock other validators waiting for sync data.
                Some(cmd) = response_rx.recv() => {
                    Self::handle_response_command(&mut swarm, cmd, &mut pending_response_channels);

                    // Drain pending response commands (bounded to prevent tight loops)
                    for _ in 0..MAX_COMMANDS_PER_DRAIN {
                        match response_rx.try_recv() {
                            Ok(cmd) => Self::handle_response_command(&mut swarm, cmd, &mut pending_response_channels),
                            Err(_) => break,
                        }
                    }
                }

                // Priority-ordered command processing.
                // Each priority level is checked in order, with higher priorities processed first.
                // Within each branch, we also drain higher-priority channels to maintain ordering.

                // Critical priority - BFT consensus messages (highest command priority)
                Some(cmd) = critical_rx.recv() => {
                    // Drain response commands first (even higher priority)
                    for _ in 0..MAX_COMMANDS_PER_DRAIN {
                        match response_rx.try_recv() {
                            Ok(resp_cmd) => Self::handle_response_command(&mut swarm, resp_cmd, &mut pending_response_channels),
                            Err(_) => break,
                        }
                    }

                    Self::handle_command(&mut swarm, cmd, &mut pending_requests).await;

                    // Drain critical commands
                    for _ in 0..MAX_COMMANDS_PER_DRAIN {
                        match critical_rx.try_recv() {
                            Ok(cmd) => Self::handle_command(&mut swarm, cmd, &mut pending_requests).await,
                            Err(_) => break,
                        }
                    }
                }

                // Coordination priority - Cross-shard 2PC messages
                Some(cmd) = coordination_rx.recv() => {
                    // Drain higher priority channels first
                    Self::drain_higher_priority_commands(
                        &mut swarm,
                        &mut response_rx,
                        &mut critical_rx,
                        &mut pending_response_channels,
                        &mut pending_requests,
                    ).await;

                    Self::handle_command(&mut swarm, cmd, &mut pending_requests).await;

                    // Drain coordination commands
                    for _ in 0..MAX_COMMANDS_PER_DRAIN {
                        match coordination_rx.try_recv() {
                            Ok(cmd) => Self::handle_command(&mut swarm, cmd, &mut pending_requests).await,
                            Err(_) => break,
                        }
                    }
                }

                // Finalization priority - Certificate gossip
                Some(cmd) = finalization_rx.recv() => {
                    // Drain higher priority channels first
                    Self::drain_higher_priority_commands(
                        &mut swarm,
                        &mut response_rx,
                        &mut critical_rx,
                        &mut pending_response_channels,
                        &mut pending_requests,
                    ).await;

                    // Also drain coordination
                    for _ in 0..MAX_COMMANDS_PER_DRAIN {
                        match coordination_rx.try_recv() {
                            Ok(cmd) => Self::handle_command(&mut swarm, cmd, &mut pending_requests).await,
                            Err(_) => break,
                        }
                    }

                    Self::handle_command(&mut swarm, cmd, &mut pending_requests).await;

                    // Drain finalization commands
                    for _ in 0..MAX_COMMANDS_PER_DRAIN {
                        match finalization_rx.try_recv() {
                            Ok(cmd) => Self::handle_command(&mut swarm, cmd, &mut pending_requests).await,
                            Err(_) => break,
                        }
                    }
                }

                // Propagation priority - Transaction gossip (mempool)
                Some(cmd) = propagation_rx.recv() => {
                    // Drain all higher priority channels first
                    Self::drain_all_higher_priority_commands(
                        &mut swarm,
                        &mut response_rx,
                        &mut critical_rx,
                        &mut coordination_rx,
                        &mut finalization_rx,
                        &mut pending_response_channels,
                        &mut pending_requests,
                    ).await;

                    Self::handle_command(&mut swarm, cmd, &mut pending_requests).await;

                    // Drain propagation commands
                    for _ in 0..MAX_COMMANDS_PER_DRAIN {
                        match propagation_rx.try_recv() {
                            Ok(cmd) => Self::handle_command(&mut swarm, cmd, &mut pending_requests).await,
                            Err(_) => break,
                        }
                    }
                }

                // Background priority - Sync operations (lowest priority)
                Some(cmd) = background_rx.recv() => {
                    // Drain all higher priority channels first
                    Self::drain_all_higher_priority_commands(
                        &mut swarm,
                        &mut response_rx,
                        &mut critical_rx,
                        &mut coordination_rx,
                        &mut finalization_rx,
                        &mut pending_response_channels,
                        &mut pending_requests,
                    ).await;

                    // Also drain propagation
                    for _ in 0..MAX_COMMANDS_PER_DRAIN {
                        match propagation_rx.try_recv() {
                            Ok(cmd) => Self::handle_command(&mut swarm, cmd, &mut pending_requests).await,
                            Err(_) => break,
                        }
                    }

                    Self::handle_command(&mut swarm, cmd, &mut pending_requests).await;

                    // Drain background commands
                    for _ in 0..MAX_COMMANDS_PER_DRAIN {
                        match background_rx.try_recv() {
                            Ok(cmd) => Self::handle_command(&mut swarm, cmd, &mut pending_requests).await,
                            Err(_) => break,
                        }
                    }
                }

                // Handle swarm events
                event = swarm.select_next_some() => {
                    // Check version compatibility for Identify events
                    if let SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) = &event {
                        let local_version = option_env!("HYPERSCALE_VERSION").unwrap_or("localdev");
                        if !version_interop_mode.check(local_version, &info.agent_version) {
                            warn!(
                                peer = %peer_id,
                                local_version = %local_version,
                                remote_version = %info.agent_version,
                                mode = ?version_interop_mode,
                                "Peer version incompatible, disconnecting"
                            );
                            if swarm.disconnect_peer_id(*peer_id).is_err() {
                                debug!(peer = %peer_id, "Failed to disconnect incompatible peer");
                            }
                        }
                    }

                    // Check if this is a connection event that changes peer count
                    let is_connection_event = matches!(
                        &event,
                        SwarmEvent::ConnectionEstablished { .. } | SwarmEvent::ConnectionClosed { .. }
                    );

                    // Handle connection established - add peer to Kademlia for discovery
                    if let SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } = &event {
                        let addr = endpoint.get_remote_address().clone();
                        // Add peer to Kademlia routing table for peer discovery
                        swarm.behaviour_mut().kademlia.add_address(peer_id, addr.clone());
                        debug!(
                            peer = %peer_id,
                            addr = %addr,
                            "Added peer to Kademlia routing table"
                        );

                        // Track validator addresses for reconnection
                        if peer_validators.contains_key(peer_id) {
                            validator_addresses.insert(*peer_id, addr);
                            // Clear any pending reconnect since we're now connected
                            pending_reconnects.remove(peer_id);
                        }

                        // Bootstrap Kademlia after first connection to start peer discovery
                        if !kademlia_bootstrapped {
                            if let Err(e) = swarm.behaviour_mut().kademlia.bootstrap() {
                                warn!("Failed to bootstrap Kademlia: {:?}", e);
                            } else {
                                info!("Kademlia bootstrap initiated for peer discovery");
                                kademlia_bootstrapped = true;
                            }
                        }
                    }

                    // Handle connection closed - schedule reconnection for validators
                    if let SwarmEvent::ConnectionClosed { peer_id, num_established, .. } = &event {
                        // Only schedule reconnect if this was the last connection to this peer
                        // and the peer is a known validator
                        if *num_established == 0 && peer_validators.contains_key(peer_id) {
                            let reconnect_time = std::time::Instant::now() + RECONNECT_DELAY;
                            info!(
                                peer = %peer_id,
                                reconnect_in_secs = RECONNECT_DELAY.as_secs(),
                                "Validator disconnected, scheduling reconnection"
                            );
                            pending_reconnects.insert(*peer_id, reconnect_time);
                        }
                    }

                    // Handle Kademlia events for peer discovery
                    if let SwarmEvent::Behaviour(BehaviourEvent::Kademlia(kad_event)) = &event {
                        match kad_event {
                            kad::Event::RoutingUpdated { peer, addresses, .. } => {
                                debug!(
                                    peer = %peer,
                                    num_addresses = addresses.len(),
                                    "Kademlia routing table updated"
                                );
                                // Dial newly discovered peers
                                for addr in addresses.iter() {
                                    if swarm.dial(addr.clone()).is_ok() {
                                        debug!(addr = %addr, "Dialing peer discovered via Kademlia");
                                    }
                                }
                            }
                            kad::Event::OutboundQueryProgressed { result, .. } => {
                                if let kad::QueryResult::Bootstrap(Ok(kad::BootstrapOk { num_remaining, .. })) = result {
                                    debug!(num_remaining = num_remaining, "Kademlia bootstrap progress");
                                }
                            }
                            _ => {
                                trace!("Kademlia event: {:?}", kad_event);
                            }
                        }
                    }

                    Self::handle_swarm_event(
                        event,
                        &consensus_tx,
                        &peer_validators,
                        &mut pending_requests,
                        &mut pending_response_channels,
                        &mut next_channel_id,
                        &inbound_request_tx,
                        &mut rate_limiter,
                        local_shard,
                        &tx_validation_handle,
                        &codec_pool,
                    ).await;

                    // Update cached peer count after connection changes
                    if is_connection_event {
                        let count = swarm.connected_peers().count();
                        cached_peer_count.store(count, Ordering::Relaxed);
                    }
                }
            }
        }
    }

    /// Handle a normal-priority command from the adapter.
    async fn handle_command(
        swarm: &mut Swarm<Behaviour>,
        cmd: SwarmCommand,
        pending_requests: &mut HashMap<request_response::OutboundRequestId, PendingRequest>,
    ) {
        match cmd {
            SwarmCommand::Subscribe { topic } => {
                let topic = gossipsub::IdentTopic::new(topic);
                if let Err(e) = swarm.behaviour_mut().gossipsub.subscribe(&topic) {
                    warn!("Failed to subscribe to topic: {}", e);
                } else {
                    info!("Subscribed to gossipsub topic: {}", topic);
                }
            }
            SwarmCommand::Broadcast { topic, data, .. } => {
                let topic_ident = gossipsub::IdentTopic::new(topic);
                let data_len = data.len();

                if let Err(e) = swarm
                    .behaviour_mut()
                    .gossipsub
                    .publish(topic_ident.clone(), data)
                {
                    // Duplicate errors are expected - multiple validators create the same
                    // certificate and try to gossip it. Gossipsub correctly deduplicates.
                    if matches!(e, gossipsub::PublishError::Duplicate) {
                        trace!(topic = %topic_ident, "Gossipsub duplicate (expected, already delivered)");
                    } else {
                        // Other errors are significant - messages may be lost
                        warn!(
                            topic = %topic_ident,
                            data_len,
                            error = ?e,
                            peers = swarm.connected_peers().count(),
                            "Failed to publish message to gossipsub topic - message may be lost"
                        );
                        crate::metrics::record_gossipsub_publish_failure(&topic_ident.to_string());
                    }
                } else {
                    trace!(topic = %topic_ident, data_len, "Published message to gossipsub topic");
                }
            }
            SwarmCommand::Dial { address } => {
                if let Err(e) = swarm.dial(address) {
                    warn!("Failed to dial peer: {}", e);
                }
            }
            SwarmCommand::GetListenAddresses { response_tx } => {
                let addrs: Vec<Multiaddr> = swarm.listeners().cloned().collect();
                let _ = response_tx.send(addrs);
            }
            SwarmCommand::GetConnectedPeers { response_tx } => {
                let peers: Vec<Libp2pPeerId> = swarm.connected_peers().cloned().collect();
                let _ = response_tx.send(peers);
            }
            SwarmCommand::Request {
                peer,
                data,
                priority: _,
                response_tx,
            } => {
                // Apply backpressure if too many pending requests
                if pending_requests.len() >= MAX_PENDING_REQUESTS {
                    debug!(
                        pending = pending_requests.len(),
                        "Backpressure: rejecting request"
                    );
                    let _ = response_tx.send(Err(NetworkError::Backpressure));
                } else {
                    let req_id = swarm
                        .behaviour_mut()
                        .request_response
                        .send_request(&peer, data);
                    pending_requests.insert(
                        req_id,
                        PendingRequest {
                            response_tx,
                            created_at: std::time::Instant::now(),
                        },
                    );
                    trace!(?peer, "Sent request");
                }
            }
        }
    }

    /// Handle a high-priority response command.
    /// These are processed before normal commands to minimize latency for waiting validators.
    fn handle_response_command(
        swarm: &mut Swarm<Behaviour>,
        cmd: ResponseCommand,
        pending_response_channels: &mut HashMap<u64, PendingResponseChannel>,
    ) {
        let ResponseCommand::SendResponse {
            channel_id,
            response,
        } = cmd;

        if let Some(pending) = pending_response_channels.remove(&channel_id) {
            if let Err(e) = swarm
                .behaviour_mut()
                .request_response
                .send_response(pending.channel, response)
            {
                warn!("Failed to send response: {:?}", e);
            }
        } else {
            warn!(channel_id, "Unknown channel ID for response");
        }
    }

    /// Drain response and critical priority commands.
    /// Used before processing coordination-level commands.
    async fn drain_higher_priority_commands(
        swarm: &mut Swarm<Behaviour>,
        response_rx: &mut mpsc::UnboundedReceiver<ResponseCommand>,
        critical_rx: &mut mpsc::UnboundedReceiver<SwarmCommand>,
        pending_response_channels: &mut HashMap<u64, PendingResponseChannel>,
        pending_requests: &mut HashMap<request_response::OutboundRequestId, PendingRequest>,
    ) {
        // Drain response commands
        for _ in 0..MAX_COMMANDS_PER_DRAIN {
            match response_rx.try_recv() {
                Ok(cmd) => Self::handle_response_command(swarm, cmd, pending_response_channels),
                Err(_) => break,
            }
        }

        // Drain critical commands
        for _ in 0..MAX_COMMANDS_PER_DRAIN {
            match critical_rx.try_recv() {
                Ok(cmd) => Self::handle_command(swarm, cmd, pending_requests).await,
                Err(_) => break,
            }
        }
    }

    /// Drain all higher priority commands (response, critical, coordination, finalization).
    /// Used before processing propagation and background level commands.
    #[allow(clippy::too_many_arguments)]
    async fn drain_all_higher_priority_commands(
        swarm: &mut Swarm<Behaviour>,
        response_rx: &mut mpsc::UnboundedReceiver<ResponseCommand>,
        critical_rx: &mut mpsc::UnboundedReceiver<SwarmCommand>,
        coordination_rx: &mut mpsc::UnboundedReceiver<SwarmCommand>,
        finalization_rx: &mut mpsc::UnboundedReceiver<SwarmCommand>,
        pending_response_channels: &mut HashMap<u64, PendingResponseChannel>,
        pending_requests: &mut HashMap<request_response::OutboundRequestId, PendingRequest>,
    ) {
        // Drain response commands
        for _ in 0..MAX_COMMANDS_PER_DRAIN {
            match response_rx.try_recv() {
                Ok(cmd) => Self::handle_response_command(swarm, cmd, pending_response_channels),
                Err(_) => break,
            }
        }

        // Drain critical commands
        for _ in 0..MAX_COMMANDS_PER_DRAIN {
            match critical_rx.try_recv() {
                Ok(cmd) => Self::handle_command(swarm, cmd, pending_requests).await,
                Err(_) => break,
            }
        }

        // Drain coordination commands
        for _ in 0..MAX_COMMANDS_PER_DRAIN {
            match coordination_rx.try_recv() {
                Ok(cmd) => Self::handle_command(swarm, cmd, pending_requests).await,
                Err(_) => break,
            }
        }

        // Drain finalization commands
        for _ in 0..MAX_COMMANDS_PER_DRAIN {
            match finalization_rx.try_recv() {
                Ok(cmd) => Self::handle_command(swarm, cmd, pending_requests).await,
                Err(_) => break,
            }
        }
    }
}

impl Libp2pAdapter {
    /// Handle a single swarm event.
    #[allow(clippy::too_many_arguments)]
    async fn handle_swarm_event(
        event: SwarmEvent<BehaviourEvent>,
        consensus_tx: &mpsc::Sender<Event>,
        peer_validators: &Arc<DashMap<Libp2pPeerId, ValidatorId>>,
        pending_requests: &mut HashMap<request_response::OutboundRequestId, PendingRequest>,
        pending_response_channels: &mut HashMap<u64, PendingResponseChannel>,
        next_channel_id: &mut u64,
        inbound_request_tx: &mpsc::UnboundedSender<InboundRequest>,
        rate_limiter: &mut SyncRateLimiter,
        local_shard: ShardGroupId,
        tx_validation_handle: &ValidationBatcherHandle,
        codec_pool: &CodecPoolHandle,
    ) {
        match event {
            // Handle gossipsub messages
            SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message {
                propagation_source,
                message,
                ..
            })) => {
                // Parse topic immediately to determine message type and shard
                // Using .as_str() avoids allocation
                let topic_str = message.topic.as_str();
                let parsed_topic = match crate::network::Topic::parse(topic_str) {
                    Some(t) => t,
                    None => {
                        warn!(
                            topic = %topic_str,
                            peer = %propagation_source,
                            "Received message with invalid topic format"
                        );
                        metrics::record_invalid_message();
                        return;
                    }
                };

                let data_len = message.data.len();

                // Record inbound bandwidth
                metrics::record_libp2p_bandwidth(data_len as u64, 0);

                // Validate that the message comes from a known validator
                // This is defense-in-depth - messages are also verified by signature.
                // The peer_validators map is populated at startup using
                // compute_peer_id_for_validator() for all validators in the local committee.
                if !peer_validators.contains_key(&propagation_source) {
                    debug!(
                        peer = %propagation_source,
                        topic = %topic_str,
                        "Ignoring message from unknown peer (not in validator set)"
                    );
                    metrics::record_invalid_message();
                    return;
                }
                //
                // Cross-shard messages (allowed from any shard):
                // - state.provision: Sent cross-shard to request state for transactions
                // - state.certificate: Needed for cross-shard transaction execution
                // - transaction.gossip: Can be routed to appropriate shard

                let msg_type = parsed_topic.message_type();
                let is_shard_local_message =
                    matches!(msg_type, "block.header" | "block.vote" | "state.vote");

                if is_shard_local_message {
                    if let Some(topic_shard) = parsed_topic.shard_id() {
                        if topic_shard != local_shard {
                            warn!(
                                topic = %topic_str,
                                topic_shard = topic_shard.0,
                                local_shard = local_shard.0,
                                msg_type = msg_type,
                                "Dropping shard-local message from wrong shard (cross-shard contamination attempt)"
                            );
                            metrics::record_invalid_message();
                            return;
                        }
                    }
                }

                // Dispatch decoding to the codec pool (non-blocking).
                // The codec pool handles SBOR decoding on a separate thread pool,
                // then sends decoded events directly to the consensus channel.
                // This prevents large messages (state batches) from blocking the event loop.
                codec_pool.decode_async(
                    parsed_topic,
                    message.data,
                    propagation_source,
                    consensus_tx.clone(),
                    tx_validation_handle.clone(),
                );
            }

            // Handle subscription events
            SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Subscribed {
                peer_id,
                topic,
            })) => {
                debug!("Peer {:?} subscribed to topic: {}", peer_id, topic);
            }

            // Handle request-response messages
            SwarmEvent::Behaviour(BehaviourEvent::RequestResponse(
                request_response::Event::Message {
                    peer: _,
                    message:
                        request_response::Message::Response {
                            request_id,
                            response,
                        },
                    ..
                },
            )) => {
                // Route response to waiting requester
                if let Some(pending) = pending_requests.remove(&request_id) {
                    let _ = pending.response_tx.send(Ok(response));
                }
            }

            // Handle request failures
            SwarmEvent::Behaviour(BehaviourEvent::RequestResponse(
                request_response::Event::OutboundFailure {
                    request_id,
                    error,
                    peer,
                    ..
                },
            )) => {
                // Log detailed failure info to understand connection timeouts
                warn!(
                    peer = %peer,
                    request_id = ?request_id,
                    error = ?error,
                    "Request-response outbound failure"
                );
                if let Some(pending) = pending_requests.remove(&request_id) {
                    // Map libp2p error to appropriate NetworkError
                    // Timeout is special - RequestManager uses it for retry-same-peer logic
                    let network_error = match error {
                        request_response::OutboundFailure::Timeout => NetworkError::Timeout,
                        other => NetworkError::NetworkError(format!("Request failed: {:?}", other)),
                    };
                    let _ = pending.response_tx.send(Err(network_error));
                }
            }

            // Handle inbound requests (sync blocks or transaction fetch)
            SwarmEvent::Behaviour(BehaviourEvent::RequestResponse(
                request_response::Event::Message {
                    peer,
                    message:
                        request_response::Message::Request {
                            request, channel, ..
                        },
                    ..
                },
            )) => {
                // Check if sender is a known validator
                let is_validator = peer_validators.contains_key(&peer);

                // Apply rate limiting
                if !rate_limiter.check_request(&peer, is_validator) {
                    warn!(
                        peer = %peer,
                        is_validator = is_validator,
                        "Rate limited request from peer"
                    );
                    metrics::record_request_rate_limited(is_validator);
                    // Drop the request by not processing it
                    // The channel will be dropped, which signals failure to the requester
                    return;
                }

                // Send to InboundRouter for handling.
                // The router will discriminate between block sync, transaction fetch,
                // and certificate fetch requests based on the payload structure.
                {
                    let channel_id = *next_channel_id;
                    *next_channel_id = next_channel_id.wrapping_add(1);
                    pending_response_channels.insert(
                        channel_id,
                        PendingResponseChannel {
                            channel,
                            created_at: std::time::Instant::now(),
                        },
                    );

                    trace!(
                        peer = %peer,
                        len = request.len(),
                        channel_id = channel_id,
                        is_validator = is_validator,
                        "Received inbound request, forwarding to router"
                    );

                    let inbound_request = InboundRequest {
                        peer,
                        payload: request,
                        channel_id,
                    };

                    if inbound_request_tx.send(inbound_request).is_err() {
                        warn!(
                            channel_id,
                            "Failed to send request to InboundRouter (channel closed)"
                        );
                        pending_response_channels.remove(&channel_id);
                    }
                }
            }

            // Handle Identify events
            SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received {
                peer_id,
                info,
                ..
            })) => {
                info!(
                    peer = %peer_id,
                    agent_version = %info.agent_version,
                    protocol_version = %info.protocol_version,
                    protocols = ?info.protocols,
                    "Identified peer"
                );
            }

            // Connection events
            SwarmEvent::ConnectionEstablished {
                peer_id,
                endpoint,
                num_established,
                ..
            } => {
                let addr = endpoint.get_remote_address().clone();
                info!(
                    peer = %peer_id,
                    addr = %addr,
                    total_connections = num_established.get(),
                    "Connection established"
                );
                // Note: num_established is connections to this peer, not total peers
                // We would need swarm.connected_peers().count() for total, but we don't have access here
                // The metrics tick in runner.rs can poll connected_peers() periodically instead
            }

            SwarmEvent::ConnectionClosed {
                peer_id,
                cause,
                num_established,
                connection_id,
                ..
            } => {
                // Detailed logging to debug connection timeouts
                let cause_str = match &cause {
                    Some(e) => format!("{:?}", e),
                    None => "None (graceful)".to_string(),
                };
                warn!(
                    peer = %peer_id,
                    connection_id = ?connection_id,
                    cause = %cause_str,
                    remaining_connections = num_established,
                    "Connection closed - investigating timeout cause"
                );
            }

            SwarmEvent::NewListenAddr { address, .. } => {
                info!("Listening on new address: {}", address);
            }

            _ => {
                // Ignore other events
            }
        }
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
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = Libp2pConfig::default();
        assert_eq!(config.request_timeout, Duration::from_secs(5));
        assert!(!config.listen_addresses.is_empty());
    }
}
