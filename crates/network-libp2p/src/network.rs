//! Production network adapter implementing the Network trait.
//!
//! [`ProdNetwork`] wraps [`Libp2pAdapter`] and [`RequestManager`] to provide
//! the [`Network`] interface used by `IoLoop` in the production runner.

use crate::adapter::Libp2pAdapter;
use crate::inbound_router::{spawn_inbound_router, InboundRouterHandle};
use crate::request_manager::{RequestManager, RequestPriority};
use hyperscale_network::{
    compression, GossipHandler, HandlerRegistry, Network, RequestError, RequestHandler, Topic,
    TopicScope,
};
use hyperscale_types::{NetworkMessage, Request, ShardGroupId, ShardMessage, ValidatorId};
use libp2p::PeerId;
use std::sync::Arc;
use tracing::{debug, info, warn};

// ═══════════════════════════════════════════════════════════════════════
// ProdNetwork
// ═══════════════════════════════════════════════════════════════════════

/// Production network adapter implementing the Network trait.
///
/// Wraps `Arc<Libp2pAdapter>` and SBOR-encodes + LZ4-compresses messages before
/// publishing via the adapter's priority channels. The `publish()` call
/// is sync-safe (non-blocking channel send), so this works from the
/// pinned state machine thread without a tokio runtime context.
///
/// Also owns a `RequestManager` for request-response operations.
/// The generic `request<R>()` method SBOR-encodes the request, dispatches
/// to the RequestManager, and SBOR-decodes the response.
pub struct ProdNetwork {
    adapter: Arc<Libp2pAdapter>,
    request_manager: Arc<RequestManager>,
    tokio_handle: tokio::runtime::Handle,
    /// Shared handler registry for per-type gossip and request dispatch.
    registry: Arc<HandlerRegistry>,
    /// Local shard for deriving topic subscriptions.
    local_shard: ShardGroupId,
    /// Inbound router handle — spawned eagerly at construction.
    /// Kept alive to prevent the background task from being aborted.
    _inbound_router: InboundRouterHandle,
}

impl ProdNetwork {
    pub fn new(
        adapter: Arc<Libp2pAdapter>,
        request_manager: Arc<RequestManager>,
        tokio_handle: tokio::runtime::Handle,
        registry: Arc<HandlerRegistry>,
        local_shard: ShardGroupId,
    ) -> Self {
        // Eagerly spawn the inbound router. It will dispatch incoming
        // requests to handlers as they are registered in the registry.
        let _guard = tokio_handle.enter();
        let inbound_router = spawn_inbound_router(adapter.clone(), registry.clone());

        Self {
            adapter,
            request_manager,
            tokio_handle,
            registry,
            local_shard,
            _inbound_router: inbound_router,
        }
    }

    fn validator_peer_id(&self, validator: ValidatorId) -> Option<PeerId> {
        self.adapter.peer_for_validator(validator)
    }
}

impl Network for ProdNetwork {
    fn broadcast_to_shard<M: ShardMessage>(&self, shard: ShardGroupId, message: &M) {
        let topic = Topic::shard(M::message_type_id(), shard);
        let data = compression::compress(&sbor::basic_encode(message).expect("SBOR encode failed"));
        if let Err(e) = self.adapter.publish(&topic, data, M::priority()) {
            debug!(error = ?e, "ProdNetwork: broadcast_to_shard failed");
        }
    }

    fn broadcast_global<M: NetworkMessage>(&self, message: &M) {
        let topic = Topic::global(M::message_type_id());
        let data = compression::compress(&sbor::basic_encode(message).expect("SBOR encode failed"));
        if let Err(e) = self.adapter.publish(&topic, data, M::priority()) {
            debug!(error = ?e, "ProdNetwork: broadcast_global failed");
        }
    }

    fn register_gossip_handler<M: NetworkMessage>(
        &self,
        scope: TopicScope,
        handler: impl GossipHandler<M>,
    ) {
        // Registry owns SBOR decode — just forward.
        self.registry.register_gossip(handler);

        // Auto-subscribe to the corresponding gossipsub topic.
        let topic = match scope {
            TopicScope::Shard => Topic::shard(M::message_type_id(), self.local_shard),
            TopicScope::Global => Topic::global(M::message_type_id()),
        };
        if let Err(e) = self.adapter.subscribe_topic(topic.to_string()) {
            warn!(
                message_type = M::message_type_id(),
                error = ?e,
                "Failed to subscribe to topic"
            );
        } else {
            info!(topic = %topic, "Subscribed to topic");
        }
    }

    fn register_request_handler<R: Request>(&self, handler: impl RequestHandler<R>) {
        // Registry owns SBOR decode/encode — just forward.
        self.registry.register_request(handler);
    }

    fn request<R: Request + 'static>(
        &self,
        peers: &[ValidatorId],
        preferred_peer: Option<ValidatorId>,
        request: R,
        on_response: Box<dyn FnOnce(Result<R::Response, RequestError>) + Send>,
    ) {
        // Resolve ValidatorIds → PeerIds via the adapter's global registry
        let resolved_peers: Vec<PeerId> = peers
            .iter()
            .filter_map(|&v| self.adapter.peer_for_validator(v))
            .collect();

        if resolved_peers.is_empty() {
            on_response(Err(RequestError::PeerUnreachable(
                preferred_peer.unwrap_or(ValidatorId(0)),
            )));
            return;
        }

        let preferred_libp2p = preferred_peer.and_then(|v| self.validator_peer_id(v));
        let priority = if R::priority() == hyperscale_types::MessagePriority::Background {
            RequestPriority::Background
        } else {
            RequestPriority::Critical
        };

        // SBOR-encode the request
        let request_bytes = match sbor::basic_encode(&request) {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!(error = ?e, "ProdNetwork: failed to encode request");
                on_response(Err(RequestError::PeerError(format!("encode error: {e:?}"))));
                return;
            }
        };

        // Pass type_id + SBOR bytes separately — the transport writes the typed frame.
        let type_id = R::message_type_id();
        let description = format!("{}({}B)", type_id, request_bytes.len());
        let rm = self.request_manager.clone();

        self.tokio_handle.spawn(async move {
            match rm
                .request(
                    &resolved_peers,
                    preferred_libp2p,
                    description,
                    type_id,
                    request_bytes,
                    priority,
                )
                .await
            {
                Ok((_peer, bytes)) => {
                    // RequestManager returns decompressed SBOR response bytes
                    match sbor::basic_decode::<R::Response>(&bytes) {
                        Ok(response) => on_response(Ok(response)),
                        Err(e) => {
                            warn!(error = ?e, "Failed to decode response");
                            on_response(Err(RequestError::PeerError(format!(
                                "decode error: {e:?}"
                            ))));
                        }
                    }
                }
                Err(e) => {
                    on_response(Err(RequestError::PeerError(format!("{e}"))));
                }
            }
        });
    }
}
