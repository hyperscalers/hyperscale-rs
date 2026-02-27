//! Production network adapter implementing the Network trait.
//!
//! [`ProdNetwork`] wraps [`Libp2pAdapter`] and [`RequestManager`] to provide
//! the [`Network`] interface used by `NodeLoop` in the production runner.

use crate::adapter::{compute_peer_id_for_validator, Libp2pAdapter};
use crate::inbound_router::{spawn_inbound_router, InboundRouterHandle};
use crate::request_manager::{RequestManager, RequestPriority};
use hyperscale_network::{
    encode_to_wire, frame_request, InboundRequestHandler, Network, RequestError, Topic,
};
use hyperscale_types::{
    NetworkMessage, Request, ShardGroupId, ShardMessage, Topology, ValidatorId,
};
use libp2p::PeerId;
use std::sync::{Arc, OnceLock};
use tracing::{debug, warn};

// ═══════════════════════════════════════════════════════════════════════
// ProdNetwork
// ═══════════════════════════════════════════════════════════════════════

/// Production network adapter implementing the Network trait.
///
/// Wraps `Arc<Libp2pAdapter>` and encodes messages to wire format before
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
    topology: Arc<dyn Topology>,
    tokio_handle: tokio::runtime::Handle,
    /// Inbound router handle — set once via `register_inbound_handler`.
    /// Kept alive to prevent the background task from being aborted.
    inbound_router: OnceLock<InboundRouterHandle>,
}

impl ProdNetwork {
    pub fn new(
        adapter: Arc<Libp2pAdapter>,
        request_manager: Arc<RequestManager>,
        topology: Arc<dyn Topology>,
        tokio_handle: tokio::runtime::Handle,
    ) -> Self {
        Self {
            adapter,
            request_manager,
            topology,
            tokio_handle,
            inbound_router: OnceLock::new(),
        }
    }

    /// Get peer IDs for same-shard committee members (excluding self).
    fn get_committee_peers(&self) -> Vec<PeerId> {
        let local_shard = self.topology.local_shard();
        let local_validator = self.topology.local_validator_id();

        self.topology
            .committee_for_shard(local_shard)
            .iter()
            .filter(|&&v| v != local_validator)
            .filter_map(|&v| {
                let pk = self.topology.public_key(v)?;
                Some(compute_peer_id_for_validator(&pk))
            })
            .collect()
    }

    /// Get the PeerId for a specific validator, if known.
    fn validator_peer_id(&self, validator: ValidatorId) -> Option<PeerId> {
        self.topology
            .public_key(validator)
            .map(|pk| compute_peer_id_for_validator(&pk))
    }
}

impl Network for ProdNetwork {
    fn broadcast_to_shard<M: ShardMessage>(&self, shard: ShardGroupId, message: &M) {
        let topic = Topic::shard(M::message_type_id(), shard);
        match encode_to_wire(message) {
            Ok(data) => {
                if let Err(e) = self.adapter.publish(&topic, data, M::priority()) {
                    debug!(error = ?e, "ProdNetwork: broadcast_to_shard failed");
                }
            }
            Err(e) => {
                debug!(error = ?e, "ProdNetwork: failed to encode message");
            }
        }
    }

    fn broadcast_global<M: NetworkMessage>(&self, message: &M) {
        let topic = Topic::global(M::message_type_id());
        match encode_to_wire(message) {
            Ok(data) => {
                if let Err(e) = self.adapter.publish(&topic, data, M::priority()) {
                    debug!(error = ?e, "ProdNetwork: broadcast_global failed");
                }
            }
            Err(e) => {
                debug!(error = ?e, "ProdNetwork: failed to encode message");
            }
        }
    }

    fn register_inbound_handler(&self, handler: Arc<dyn InboundRequestHandler>) {
        // Enter the tokio runtime context so spawn_inbound_router can use
        // tokio::spawn (this may be called from the main thread before the
        // NodeLoop is moved to its pinned thread).
        let _guard = self.tokio_handle.enter();
        let handle = spawn_inbound_router(self.adapter.clone(), handler);
        let _ = self.inbound_router.set(handle);
    }

    fn request<R: Request + 'static>(
        &self,
        preferred_peer: Option<ValidatorId>,
        request: R,
        on_response: Box<dyn FnOnce(Result<R::Response, RequestError>) + Send>,
    ) {
        let peers = self.get_committee_peers();
        if peers.is_empty() {
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

        // Frame with type_id for dispatch by the receiver's InboundHandler
        let framed = frame_request(R::message_type_id(), &request_bytes);
        let description = format!("{}({}B)", R::message_type_id(), request_bytes.len());
        let rm = self.request_manager.clone();

        self.tokio_handle.spawn(async move {
            match rm
                .request(&peers, preferred_libp2p, description, framed, priority)
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
