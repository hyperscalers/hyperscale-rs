//! Network trait for typed message passing.
//!
//! Defines the `Network` interface implemented by both production (`network-libp2p`)
//! and simulation (`network-memory`) backends.

use std::sync::Arc;

use hyperscale_types::{NetworkMessage, Request, ShardGroupId, ShardMessage, ValidatorId};

/// Error returned when a network request fails.
#[derive(Debug, thiserror::Error)]
pub enum RequestError {
    #[error("Request timed out")]
    Timeout,
    #[error("Peer unreachable: {0}")]
    PeerUnreachable(ValidatorId),
    #[error("Peer returned error: {0}")]
    PeerError(String),
    #[error("Network shutting down")]
    Shutdown,
}

/// Trait for handling inbound request-response payloads.
///
/// Implementations decode request bytes, process them (e.g., look up blocks,
/// transactions, certificates from storage), and return SBOR-encoded response bytes.
///
/// The transport layer (`InboundRouter`) handles stream I/O, framing, and
/// compression. This trait contains only the application-level logic.
pub trait InboundRequestHandler: Send + Sync + 'static {
    /// Process a request payload and return response bytes.
    ///
    /// Both input and output are uncompressed SBOR-encoded bytes.
    /// The transport layer handles compression/decompression.
    fn handle_request(&self, payload: &[u8]) -> Vec<u8>;
}

impl<T: InboundRequestHandler + ?Sized> InboundRequestHandler for std::sync::Arc<T> {
    fn handle_request(&self, payload: &[u8]) -> Vec<u8> {
        (**self).handle_request(payload)
    }
}

/// Handler for incoming gossip messages.
///
/// Receives decompressed SBOR payloads after the network layer has handled
/// transport concerns (decompression, topic parsing, shard validation).
pub trait GossipHandler: Send + Sync + 'static {
    fn on_gossip(&self, message_type: &'static str, payload: Vec<u8>);
}

/// Network interface for sending typed messages and handling inbound requests.
///
/// Generic methods make this NOT object-safe — use `N: Network` bounds.
/// This is consistent with how storage and dispatch are already used:
/// `ActionContext<S: CommitStore + SubstateStore, D: Dispatch>`.
///
/// All sends are fire-and-forget. Responses to requests arrive via callback.
pub trait Network: Send + Sync {
    // ── Pub/sub messaging ──

    /// Broadcast a shard-scoped message to all peers subscribed to that shard's topic.
    fn broadcast_to_shard<M: ShardMessage>(&self, shard: ShardGroupId, message: &M);

    /// Broadcast a message to all connected peers globally.
    fn broadcast_global<M: NetworkMessage>(&self, message: &M);

    // ── Request handling ──

    /// Register a request handler.
    ///
    /// The handler processes incoming request-response payloads (block sync,
    /// transaction/certificate fetches). Called once during node initialization.
    ///
    /// The network layer owns the handler's lifecycle — production spawns an
    /// `InboundRouter` task, simulation stores it for centralized fulfillment.
    fn register_request_handler(&self, handler: Arc<dyn InboundRequestHandler>);

    // ── Gossip handler ──

    /// Register a handler for incoming gossip messages.
    ///
    /// The handler receives decompressed SBOR payloads. Called once during
    /// node initialization, alongside `register_request_handler`.
    fn register_gossip_handler(&self, handler: Arc<dyn GossipHandler>);

    // ── Request-response ──

    /// Send a typed request and receive the response via callback.
    ///
    /// * `peers` — the set of validators eligible to serve this request.
    ///   Typically the local shard committee (excluding self) for intra-shard
    ///   fetches, or a remote shard's committee for cross-shard requests.
    /// * `preferred_peer` — optional hint for which peer to try first (e.g.,
    ///   the block proposer for fetch requests). `None` means any peer from
    ///   the `peers` list.
    /// * Implementation handles peer selection, retry, and failover internally.
    ///
    /// The callback is called on a network thread when the response arrives,
    /// or with an error on timeout/failure. Compatible with sync main loops —
    /// the callback typically pushes into the main loop's event channel.
    fn request<R: Request + 'static>(
        &self,
        peers: &[ValidatorId],
        preferred_peer: Option<ValidatorId>,
        request: R,
        on_response: Box<dyn FnOnce(Result<R::Response, RequestError>) + Send>,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_handler_arc_delegation() {
        struct Echo;
        impl InboundRequestHandler for Echo {
            fn handle_request(&self, payload: &[u8]) -> Vec<u8> {
                payload.to_vec()
            }
        }

        let handler: Arc<Echo> = Arc::new(Echo);
        let input = b"hello";
        let output = handler.handle_request(input);
        assert_eq!(output, input);
    }
}
