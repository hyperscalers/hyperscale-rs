//! Network trait for typed message passing.
//!
//! Defines the `Network` interface implemented by both production (`network-libp2p`)
//! and simulation (`network-memory`) backends.
//!
//! Handlers are registered per message type via `register_gossip_handler` and
//! `register_request_handler`. The network layer dispatches incoming messages
//! to the appropriate handler by `message_type_id` lookup.

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

/// Whether a gossip message type is shard-scoped or global.
///
/// Determines topic subscription in production:
/// - `Shard` → `hyperscale/{type_id}/shard-{local}/1.0.0`
/// - `Global` → `hyperscale/{type_id}/1.0.0`
///
/// Ignored in simulation (delivery is controlled by the harness).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TopicScope {
    /// Shard-local topic. Only peers subscribed to the local shard receive it.
    Shard,
    /// Global topic. All connected peers receive it.
    Global,
}

/// Handler for a single gossip message type.
///
/// Called on the codec pool thread (production) or inline (simulation)
/// after LZ4 decompression. The payload is decompressed SBOR bytes.
///
/// Implementations typically SBOR-decode the payload into a typed message,
/// optionally validate (e.g., BLS signature check), and send a typed
/// event to the IoLoop via a captured channel sender.
pub trait GossipHandler: Send + Sync + 'static {
    fn on_message(&self, payload: Vec<u8>);
}

/// Blanket impl: any `Fn(Vec<u8>)` can serve as a gossip handler.
impl<F: Fn(Vec<u8>) + Send + Sync + 'static> GossipHandler for F {
    fn on_message(&self, payload: Vec<u8>) {
        (self)(payload)
    }
}

/// Handler for a single request message type.
///
/// Called on the inbound router thread (production) or inline (simulation).
/// Receives SBOR-encoded request bytes (no framing — the transport layer
/// strips the type_id prefix before dispatch). Returns SBOR-encoded
/// response bytes.
pub trait RequestHandler: Send + Sync + 'static {
    fn handle_request(&self, payload: &[u8]) -> Vec<u8>;
}

/// Blanket impl: any `Fn(&[u8]) -> Vec<u8>` can serve as a request handler.
impl<F: Fn(&[u8]) -> Vec<u8> + Send + Sync + 'static> RequestHandler for F {
    fn handle_request(&self, payload: &[u8]) -> Vec<u8> {
        (self)(payload)
    }
}

/// Network interface for sending typed messages and handling inbound traffic.
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

    // ── Handler registration ──

    /// Register a handler for a specific gossip message type.
    ///
    /// Each message type gets its own handler. The network layer dispatches
    /// incoming gossip to the handler registered for that type's `message_type_id`.
    ///
    /// In production, this also auto-subscribes to the corresponding gossipsub
    /// topic (shard-scoped or global, per `scope`).
    ///
    /// Called during node initialization — once per message type.
    fn register_gossip_handler(
        &self,
        message_type_id: &'static str,
        scope: TopicScope,
        handler: Arc<dyn GossipHandler>,
    );

    /// Register a handler for a specific request message type.
    ///
    /// Each request type gets its own handler. The network layer parses the
    /// type_id frame from incoming requests and dispatches to the matching handler.
    ///
    /// Called during node initialization — once per request type.
    fn register_request_handler(
        &self,
        message_type_id: &'static str,
        handler: Arc<dyn RequestHandler>,
    );

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
    fn test_closure_gossip_handler() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        let handler: Arc<dyn GossipHandler> = Arc::new(move |_payload: Vec<u8>| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });
        handler.on_message(vec![1, 2, 3]);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_closure_request_handler() {
        let handler: Arc<dyn RequestHandler> =
            Arc::new(|payload: &[u8]| -> Vec<u8> { payload.to_vec() });
        let result = handler.handle_request(b"hello");
        assert_eq!(result, b"hello");
    }
}
