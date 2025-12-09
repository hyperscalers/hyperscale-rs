//! libp2p network adapter for production use.
//!
//! This module provides the core networking implementation using libp2p with:
//! - Gossipsub for efficient broadcast messaging
//! - Kademlia DHT for peer discovery
//! - Request-Response for sync block fetching
//! - QUIC transport for reliable, encrypted connections

use super::codec::{decode_message, encode_message, CodecError};
use super::config::Libp2pConfig;
use super::rate_limiter::{RateLimitConfig, SyncRateLimiter};
use super::topic::Topic;
use crate::metrics;
use futures::StreamExt;
use hyperscale_core::{Event, OutboundMessage};
use hyperscale_types::{ShardGroupId, ValidatorId};
use libp2p::{
    gossipsub, identity, kad,
    request_response::{self, ProtocolSupport, ResponseChannel},
    swarm::{NetworkBehaviour, SwarmEvent},
    Multiaddr, PeerId as Libp2pPeerId, StreamProtocol, Swarm, SwarmBuilder,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};
#[cfg(feature = "trace-propagation")]
use tracing::Instrument;
use tracing::{debug, info, trace, warn};
#[cfg(feature = "trace-propagation")]
use tracing_opentelemetry::OpenTelemetrySpanExt;

/// An inbound sync request from a peer.
///
/// The runner receives these, looks up the block from storage,
/// and sends the response via `Libp2pAdapter::send_block_response()`.
#[derive(Debug)]
pub struct InboundSyncRequest {
    /// The requesting peer.
    pub peer: Libp2pPeerId,
    /// The requested block height.
    pub height: u64,
    /// Opaque response channel ID (used to send the response).
    pub channel_id: u64,
}

/// Commands sent to the swarm task.
enum SwarmCommand {
    /// Subscribe to a gossipsub topic.
    Subscribe { topic: String },

    /// Broadcast a message to a topic.
    Broadcast { topic: String, data: Vec<u8> },

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

    /// Request a block from a peer (for sync).
    RequestBlock {
        peer: Libp2pPeerId,
        height: u64,
        response_tx: tokio::sync::oneshot::Sender<Result<Vec<u8>, NetworkError>>,
    },

    /// Send a response to a block request (by channel ID).
    SendBlockResponse { channel_id: u64, response: Vec<u8> },
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
}

/// Codec for request-response protocol with length-prefixed messages.
#[derive(Debug, Clone, Default)]
struct HyperscaleCodec;

#[async_trait::async_trait]
impl request_response::Codec for HyperscaleCodec {
    type Protocol = StreamProtocol;
    type Request = Vec<u8>;
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
        Ok(buf)
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
}

/// libp2p-based network adapter for production use.
///
/// Uses gossipsub for efficient broadcast and Kademlia DHT for peer discovery.
pub struct Libp2pAdapter {
    /// Local peer ID.
    local_peer_id: Libp2pPeerId,

    /// Local validator ID (from topology).
    local_validator_id: ValidatorId,

    /// Local shard assignment.
    #[allow(dead_code)]
    local_shard: ShardGroupId,

    /// Command channel to swarm task.
    command_tx: mpsc::UnboundedSender<SwarmCommand>,

    /// Event channel for incoming messages (sent to runner).
    #[allow(dead_code)]
    event_tx: mpsc::Sender<Event>,

    /// Known validators (ValidatorId -> PeerId).
    /// Built from Topology at startup.
    validator_peers: Arc<RwLock<HashMap<ValidatorId, Libp2pPeerId>>>,

    /// Reverse mapping (PeerId -> ValidatorId) for inbound message validation.
    peer_validators: Arc<RwLock<HashMap<Libp2pPeerId, ValidatorId>>>,

    /// Request timeout.
    request_timeout: Duration,

    /// Shutdown signal sender.
    shutdown_tx: Option<mpsc::Sender<()>>,

    /// Channel for inbound sync requests (sent to runner for processing).
    #[allow(dead_code)]
    sync_request_tx: mpsc::Sender<InboundSyncRequest>,
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
    /// * `event_tx` - Channel to send incoming events to the runner
    ///
    /// # Returns
    ///
    /// A tuple of (adapter, sync_request_rx) where sync_request_rx receives
    /// inbound sync block requests that need to be handled by the runner.
    pub async fn new(
        config: Libp2pConfig,
        keypair: identity::Keypair,
        validator_id: ValidatorId,
        shard: ShardGroupId,
        event_tx: mpsc::Sender<Event>,
    ) -> Result<(Arc<Self>, mpsc::Receiver<InboundSyncRequest>), NetworkError> {
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
                // Use message hash as ID for deduplication
                use std::hash::{Hash, Hasher};
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                msg.data.hash(&mut hasher);
                gossipsub::MessageId::from(hasher.finish().to_string())
            })
            .max_transmit_size(config.max_message_size)
            .build()
            .map_err(|e| NetworkError::NetworkError(e.to_string()))?;

        let gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(keypair.clone()),
            gossipsub_config,
        )
        .map_err(|e| NetworkError::NetworkError(e.to_string()))?;

        // Set up Kademlia DHT
        let store = kad::store::MemoryStore::new(local_peer_id);
        let kademlia = kad::Behaviour::new(local_peer_id, store);

        // Set up request-response protocol
        let req_resp_config = request_response::Config::default();
        let protocols = std::iter::once((
            StreamProtocol::new("/hyperscale/sync/1.0.0"),
            ProtocolSupport::Full,
        ));
        let request_response =
            request_response::Behaviour::with_codec(HyperscaleCodec, protocols, req_resp_config);

        // Create behaviour
        let behaviour = Behaviour {
            gossipsub,
            kademlia,
            request_response,
        };

        // Build swarm
        let mut swarm = SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_quic()
            .with_behaviour(|_| behaviour)
            .map_err(|e| NetworkError::NetworkError(e.to_string()))?
            .with_swarm_config(|c| c.with_idle_connection_timeout(config.idle_connection_timeout))
            .build();

        // Listen on configured addresses
        for addr in &config.listen_addresses {
            swarm
                .listen_on(addr.clone())
                .map_err(|e| NetworkError::NetworkError(e.to_string()))?;
            info!("Listening on: {}", addr);
        }

        // Connect to bootstrap peers
        for addr in &config.bootstrap_peers {
            swarm
                .dial(addr.clone())
                .map_err(|e| NetworkError::ConnectionFailed(e.to_string()))?;
            info!("Dialing bootstrap peer: {}", addr);
        }

        let validator_peers = Arc::new(RwLock::new(HashMap::new()));
        let peer_validators = Arc::new(RwLock::new(HashMap::new()));
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let (sync_request_tx, sync_request_rx) = mpsc::channel(100); // Buffer for inbound sync requests

        let adapter = Arc::new(Self {
            local_peer_id,
            local_validator_id: validator_id,
            local_shard: shard,
            command_tx,
            event_tx: event_tx.clone(),
            validator_peers: validator_peers.clone(),
            peer_validators: peer_validators.clone(),
            request_timeout: config.request_timeout,
            shutdown_tx: Some(shutdown_tx),
            sync_request_tx: sync_request_tx.clone(),
        });

        // Spawn event loop (takes ownership of swarm)
        // Use default rate limit config for now
        let rate_limit_config = RateLimitConfig::default();
        tokio::spawn(Self::event_loop(
            swarm,
            command_rx,
            event_tx,
            peer_validators,
            shutdown_rx,
            sync_request_tx,
            rate_limit_config,
        ));

        Ok((adapter, sync_request_rx))
    }

    /// Register a validator's peer ID mapping.
    ///
    /// Called during initialization to build the validator allowlist.
    pub async fn register_validator(&self, validator_id: ValidatorId, peer_id: Libp2pPeerId) {
        let mut vp = self.validator_peers.write().await;
        vp.insert(validator_id, peer_id);
        drop(vp);

        let mut pv = self.peer_validators.write().await;
        pv.insert(peer_id, validator_id);

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
            Topic::view_change_vote(shard),
            Topic::view_change_certificate(shard),
            Topic::transaction_gossip(shard),
            Topic::state_provision(shard),
            Topic::state_vote(shard),
            Topic::state_certificate(shard),
        ];

        for topic in &topics {
            self.command_tx
                .send(SwarmCommand::Subscribe {
                    topic: topic.to_string(),
                })
                .map_err(|_| NetworkError::NetworkShutdown)?;

            info!(topic = %topic, "Subscribed to topic");
        }

        Ok(())
    }

    /// Broadcast a message to a shard.
    pub async fn broadcast_shard(
        &self,
        shard: ShardGroupId,
        message: &OutboundMessage,
    ) -> Result<(), NetworkError> {
        let topic = super::codec::topic_for_message(message, shard);
        let data = encode_message(message)?;
        let data_len = data.len();

        self.command_tx
            .send(SwarmCommand::Broadcast {
                topic: topic.to_string(),
                data,
            })
            .map_err(|_| NetworkError::NetworkShutdown)?;

        // Record metrics
        metrics::record_network_message_sent();
        metrics::record_libp2p_bandwidth(0, data_len as u64);

        trace!(
            topic = %topic,
            msg_type = message.type_name(),
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
        self.command_tx
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

    /// Get connected peers.
    pub async fn connected_peers(&self) -> Vec<Libp2pPeerId> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = SwarmCommand::GetConnectedPeers { response_tx: tx };

        if self.command_tx.send(cmd).is_err() {
            return vec![];
        }

        rx.await.unwrap_or_default()
    }

    /// Get listen addresses.
    pub async fn listen_addresses(&self) -> Vec<Multiaddr> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = SwarmCommand::GetListenAddresses { response_tx: tx };

        if self.command_tx.send(cmd).is_err() {
            return vec![];
        }

        rx.await.unwrap_or_default()
    }

    /// Request a block from a peer for sync.
    ///
    /// Returns the raw response bytes. The caller is responsible for decoding.
    pub async fn request_block(
        &self,
        peer: Libp2pPeerId,
        height: hyperscale_types::BlockHeight,
    ) -> Result<Vec<u8>, NetworkError> {
        let (tx, rx) = tokio::sync::oneshot::channel();

        self.command_tx
            .send(SwarmCommand::RequestBlock {
                peer,
                height: height.0,
                response_tx: tx,
            })
            .map_err(|_| NetworkError::NetworkShutdown)?;

        // Wait for response with timeout
        match tokio::time::timeout(self.request_timeout, rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(NetworkError::NetworkShutdown),
            Err(_) => Err(NetworkError::Timeout),
        }
    }

    /// Get the peer ID for a validator (if known).
    pub async fn peer_for_validator(&self, validator_id: ValidatorId) -> Option<Libp2pPeerId> {
        let vp = self.validator_peers.read().await;
        vp.get(&validator_id).cloned()
    }

    /// Send a block response for an inbound sync request.
    ///
    /// The `channel_id` comes from the `InboundSyncRequest` received via the sync request channel.
    pub fn send_block_response(
        &self,
        channel_id: u64,
        response: Vec<u8>,
    ) -> Result<(), NetworkError> {
        self.command_tx
            .send(SwarmCommand::SendBlockResponse {
                channel_id,
                response,
            })
            .map_err(|_| NetworkError::NetworkShutdown)
    }

    /// Background event loop that processes swarm events and routes messages.
    async fn event_loop(
        mut swarm: Swarm<Behaviour>,
        mut command_rx: mpsc::UnboundedReceiver<SwarmCommand>,
        event_tx: mpsc::Sender<Event>,
        peer_validators: Arc<RwLock<HashMap<Libp2pPeerId, ValidatorId>>>,
        mut shutdown_rx: mpsc::Receiver<()>,
        sync_request_tx: mpsc::Sender<InboundSyncRequest>,
        rate_limit_config: RateLimitConfig,
    ) {
        // Track pending sync requests (outbound)
        let mut pending_requests: HashMap<
            request_response::OutboundRequestId,
            tokio::sync::oneshot::Sender<Result<Vec<u8>, NetworkError>>,
        > = HashMap::new();

        // Track pending response channels (inbound) - keyed by channel_id
        let mut pending_response_channels: HashMap<u64, ResponseChannel<Vec<u8>>> = HashMap::new();
        let mut next_channel_id: u64 = 0;

        // Rate limiter for inbound sync requests
        let mut rate_limiter = SyncRateLimiter::new(rate_limit_config);

        loop {
            tokio::select! {
                // Handle shutdown signal
                _ = shutdown_rx.recv() => {
                    info!("Shutting down libp2p network event loop");
                    break;
                }

                // Handle commands from adapter methods
                Some(cmd) = command_rx.recv() => {
                    Self::handle_command(&mut swarm, cmd, &mut pending_requests, &mut pending_response_channels).await;
                }

                // Handle swarm events
                event = swarm.select_next_some() => {
                    Self::handle_swarm_event(
                        event,
                        &event_tx,
                        &peer_validators,
                        &mut pending_requests,
                        &mut pending_response_channels,
                        &mut next_channel_id,
                        &sync_request_tx,
                        &mut rate_limiter,
                    ).await;
                }
            }
        }
    }

    /// Handle a command from the adapter.
    async fn handle_command(
        swarm: &mut Swarm<Behaviour>,
        cmd: SwarmCommand,
        pending_requests: &mut HashMap<
            request_response::OutboundRequestId,
            tokio::sync::oneshot::Sender<Result<Vec<u8>, NetworkError>>,
        >,
        pending_response_channels: &mut HashMap<u64, ResponseChannel<Vec<u8>>>,
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
            SwarmCommand::Broadcast { topic, data } => {
                let topic = gossipsub::IdentTopic::new(topic.clone());

                if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), data) {
                    warn!("Failed to publish message to topic {}: {:?}", topic, e);
                } else {
                    trace!("Published message to topic: {}", topic);
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
            SwarmCommand::RequestBlock {
                peer,
                height,
                response_tx,
            } => {
                // Encode block request as simple height bytes
                let data = height.to_le_bytes().to_vec();
                let req_id = swarm
                    .behaviour_mut()
                    .request_response
                    .send_request(&peer, data);
                pending_requests.insert(req_id, response_tx);
                debug!("Sent block request to {:?} for height {}", peer, height);
            }
            SwarmCommand::SendBlockResponse {
                channel_id,
                response,
            } => {
                if let Some(channel) = pending_response_channels.remove(&channel_id) {
                    if let Err(e) = swarm
                        .behaviour_mut()
                        .request_response
                        .send_response(channel, response)
                    {
                        warn!("Failed to send block response: {:?}", e);
                    }
                } else {
                    warn!(channel_id, "Unknown channel ID for block response");
                }
            }
        }
    }

    /// Handle a single swarm event.
    #[allow(clippy::too_many_arguments)]
    async fn handle_swarm_event(
        event: SwarmEvent<BehaviourEvent>,
        event_tx: &mpsc::Sender<Event>,
        peer_validators: &Arc<RwLock<HashMap<Libp2pPeerId, ValidatorId>>>,
        pending_requests: &mut HashMap<
            request_response::OutboundRequestId,
            tokio::sync::oneshot::Sender<Result<Vec<u8>, NetworkError>>,
        >,
        pending_response_channels: &mut HashMap<u64, ResponseChannel<Vec<u8>>>,
        next_channel_id: &mut u64,
        sync_request_tx: &mpsc::Sender<InboundSyncRequest>,
        rate_limiter: &mut SyncRateLimiter,
    ) {
        match event {
            // Handle gossipsub messages
            SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message {
                propagation_source,
                message,
                ..
            })) => {
                let topic = message.topic.to_string();
                let data_len = message.data.len();

                // Record inbound bandwidth
                metrics::record_libp2p_bandwidth(data_len as u64, 0);

                // TODO: Re-enable peer validation once peer-to-validator mapping is implemented
                // For now, accept messages from all connected peers (trusted local network assumption)
                // let peer_map = peer_validators.read().await;
                // if !peer_map.contains_key(&propagation_source) {
                //     debug!(
                //         peer = %propagation_source,
                //         topic = %topic,
                //         "Ignoring message from unknown peer"
                //     );
                //     metrics::record_invalid_message();
                //     return;
                // }
                // drop(peer_map);
                let _ = &peer_validators; // Suppress unused warning

                // Decode message based on topic
                match decode_message(&topic, &message.data) {
                    Ok(decoded) => {
                        metrics::record_network_message_received();

                        // Extract trace context for distributed tracing (when feature enabled)
                        // We attach the OpenTelemetry context, create a tracing span to capture it,
                        // then use Future::instrument to attach the span to the send future.
                        // This ensures the context is active during the async operation.
                        let send_future = async {
                            if event_tx.send(decoded.event).await.is_err() {
                                warn!("Event channel closed");
                            }
                        };
                        #[cfg(feature = "trace-propagation")]
                        let send_future = {
                            let span = tracing::trace_span!("cross_shard_message");
                            if let Some(ref trace_ctx) = decoded.trace_context {
                                let _ = span.set_parent(trace_ctx.extract());
                                tracing::trace!("Extracted trace context from cross-shard message");
                            }
                            send_future.instrument(span)
                        };

                        send_future.await;
                    }
                    Err(e) => {
                        warn!(
                            error = %e,
                            topic = %topic,
                            peer = %propagation_source,
                            "Failed to decode message"
                        );
                        metrics::record_invalid_message();
                    }
                }
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
                if let Some(tx) = pending_requests.remove(&request_id) {
                    let _ = tx.send(Ok(response));
                }
            }

            // Handle request failures
            SwarmEvent::Behaviour(BehaviourEvent::RequestResponse(
                request_response::Event::OutboundFailure {
                    request_id, error, ..
                },
            )) => {
                warn!("Request {:?} failed: {:?}", request_id, error);
                if let Some(tx) = pending_requests.remove(&request_id) {
                    let _ = tx.send(Err(NetworkError::NetworkError(format!(
                        "Request failed: {:?}",
                        error
                    ))));
                }
            }

            // Handle inbound sync requests
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
                let peer_map = peer_validators.read().await;
                let is_validator = peer_map.contains_key(&peer);
                drop(peer_map);

                // Apply rate limiting
                if !rate_limiter.check_request(&peer, is_validator) {
                    warn!(
                        peer = %peer,
                        is_validator = is_validator,
                        "Rate limited sync request from peer"
                    );
                    // Drop the request by not processing it
                    // The channel will be dropped, which signals failure to the requester
                    return;
                }

                // Parse the request (height as little-endian u64)
                if request.len() >= 8 {
                    let height = u64::from_le_bytes(request[..8].try_into().unwrap());

                    // Allocate a channel ID and store the response channel
                    let channel_id = *next_channel_id;
                    *next_channel_id = next_channel_id.wrapping_add(1);
                    pending_response_channels.insert(channel_id, channel);

                    debug!(
                        peer = %peer,
                        height = height,
                        channel_id = channel_id,
                        is_validator = is_validator,
                        "Received sync block request"
                    );

                    // Send to runner for processing
                    let sync_request = InboundSyncRequest {
                        peer,
                        height,
                        channel_id,
                    };

                    if sync_request_tx.send(sync_request).await.is_err() {
                        warn!(
                            height,
                            "Failed to send sync request to runner (channel full or closed)"
                        );
                        // Remove the channel since we can't process this request
                        pending_response_channels.remove(&channel_id);
                    }
                } else {
                    warn!(peer = %peer, len = request.len(), "Invalid sync request (too short)");
                }
            }

            // Connection events
            SwarmEvent::ConnectionEstablished {
                peer_id,
                endpoint,
                num_established,
                ..
            } => {
                info!(
                    peer = %peer_id,
                    addr = %endpoint.get_remote_address(),
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
                ..
            } => {
                info!(
                    peer = %peer_id,
                    cause = ?cause,
                    remaining_connections = num_established,
                    "Connection closed"
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
        assert_eq!(config.request_timeout, Duration::from_secs(30));
        assert!(!config.listen_addresses.is_empty());
    }
}
