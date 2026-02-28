//! Core Libp2pAdapter: construction, public API, and shutdown.

use super::behaviour::{Behaviour, STREAM_PROTOCOL};
use super::command::{PriorityCommandChannels, SwarmCommand};
use super::error::NetworkError;
use crate::codec_pool::CodecPoolHandle;
use crate::config::Libp2pConfig;
use dashmap::DashMap;
use futures::FutureExt;
use hyperscale_metrics as metrics;
use hyperscale_network::Topic;
use hyperscale_types::{MessagePriority, ShardGroupId, ValidatorId};
use libp2p::{gossipsub, identify, identity, kad, Multiaddr, PeerId as Libp2pPeerId, Stream};
use libp2p_stream as stream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info, trace};

/// libp2p-based network adapter for production use.
///
/// Uses gossipsub for efficient broadcast and Kademlia DHT for peer discovery.
/// Commands are processed in priority order via [`PriorityCommandChannels`].
///
/// Request/response uses raw streams via libp2p_stream. The adapter is a "dumb pipe" -
/// all timeout logic is owned by RequestManager.
pub struct Libp2pAdapter {
    /// Local peer ID.
    local_peer_id: Libp2pPeerId,

    /// Local validator ID (from topology).
    local_validator_id: ValidatorId,

    /// Priority-based command channels to swarm task.
    /// Commands are routed to the appropriate channel based on message priority.
    priority_channels: PriorityCommandChannels,

    /// Known validators (ValidatorId -> PeerId).
    /// Built from Topology at startup.
    validator_peers: Arc<DashMap<ValidatorId, Libp2pPeerId>>,

    /// Reverse mapping (PeerId -> ValidatorId) for inbound message validation.
    peer_validators: Arc<DashMap<Libp2pPeerId, ValidatorId>>,

    /// Shutdown signal sender.
    shutdown_tx: Option<mpsc::Sender<()>>,

    /// Cached connected peer count (updated by background task).
    /// This avoids blocking the consensus loop to query peer count.
    cached_peer_count: Arc<AtomicUsize>,

    #[allow(dead_code)]
    codec_pool: CodecPoolHandle,

    /// Stream control handle for opening outbound streams.
    /// Cloneable and thread-safe.
    stream_control: stream::Control,
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
    /// * `codec_pool` - Handle for async message encoding/decoding
    ///
    /// # Returns
    ///
    /// The adapter wrapped in an Arc for shared ownership.
    pub async fn new(
        config: Libp2pConfig,
        keypair: identity::Keypair,
        validator_id: ValidatorId,
        shard: ShardGroupId,
        codec_pool: CodecPoolHandle,
    ) -> Result<Arc<Self>, NetworkError> {
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

        // Set up raw stream behaviour for request/response.
        // This replaces request_response - RequestManager owns all timeout logic.
        let stream_behaviour = stream::Behaviour::new();
        let stream_control = stream_behaviour.new_control();

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
            stream: stream_behaviour,
            identify,
            limits,
        };

        // Build swarm with QUIC transport, optionally with TCP fallback
        let mut swarm = super::swarm_builder::build_swarm(&config, keypair, behaviour)?;

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

        let cached_peer_count = Arc::new(AtomicUsize::new(0));

        let adapter = Arc::new(Self {
            local_peer_id,
            local_validator_id: validator_id,
            priority_channels,
            validator_peers: validator_peers.clone(),
            peer_validators: peer_validators.clone(),
            shutdown_tx: Some(shutdown_tx),
            cached_peer_count: cached_peer_count.clone(),
            codec_pool: codec_pool.clone(),
            stream_control,
        });

        // Spawn with panic catching - network loop panics are critical but shouldn't
        // crash the entire node. The process supervisor (systemd/k8s) should restart.
        tokio::spawn(async move {
            let result = std::panic::AssertUnwindSafe(super::event_loop::run(
                swarm,
                critical_rx,
                coordination_rx,
                finalization_rx,
                propagation_rx,
                background_rx,
                peer_validators,
                shutdown_rx,
                cached_peer_count,
                shard,
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

        Ok(adapter)
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

    /// Publish pre-encoded data to a topic with a given priority.
    ///
    /// Messages are routed to the appropriate priority channel based on the
    /// provided [`MessagePriority`]. Critical messages (BFT consensus) are
    /// processed before Background messages (sync).
    ///
    /// Callers are responsible for SBOR-encoding and compressing the message
    /// before calling this method (use `hyperscale_network::encode_to_wire`).
    pub fn publish(
        &self,
        topic: &hyperscale_network::Topic,
        data: Vec<u8>,
        priority: MessagePriority,
    ) -> Result<(), NetworkError> {
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
            priority = ?priority,
            data_len,
            "Published message"
        );

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

    /// Open a bidirectional stream to a peer.
    ///
    /// This is the low-level stream API. The caller is responsible for:
    /// - All timeout logic (via tokio::time::timeout wrapping read/write)
    /// - Framing (length-prefixed messages)
    /// - Closing the stream when done
    ///
    /// RequestManager should be used for request/response patterns - it wraps
    /// this method with proper timeout, retry, and peer selection logic.
    pub async fn open_stream(&self, peer: Libp2pPeerId) -> Result<Stream, NetworkError> {
        self.stream_control
            .clone()
            .open_stream(peer, STREAM_PROTOCOL)
            .await
            .map_err(|e| NetworkError::StreamOpenFailed(format!("{:?}", e)))
    }

    /// Get the peer ID for a validator (if known).
    pub fn peer_for_validator(&self, validator_id: ValidatorId) -> Option<Libp2pPeerId> {
        self.validator_peers.get(&validator_id).map(|r| *r)
    }

    /// Get a clone of the stream control handle.
    ///
    /// This allows external components (like InboundRouter) to accept incoming streams.
    pub fn stream_control(&self) -> stream::Control {
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
