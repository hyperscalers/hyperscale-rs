//! Network trait for typed message passing.
//!
//! Defines the `Network` interface implemented by both production (`network-libp2p`)
//! and simulation (`network-memory`) backends.
//!
//! Handler registration is fully typed: `register_gossip_handler<M>` accepts a
//! `GossipHandler<M>` and `register_request_handler<R>` accepts a `RequestHandler<R>`.
//! The `HandlerRegistry` owns SBOR serialization — `Network` impls just forward.

use hyperscale_types::{
    Bls12381G1PublicKey, NetworkMessage, Request, ShardGroupId, ShardMessage, ValidatorId,
};
use std::collections::HashMap;
use std::sync::Arc;

/// Maps ValidatorId to BLS public key for identity verification (e.g. validator-bind).
///
/// Extracted from the topology snapshot and pushed to the network layer via
/// [`Network::update_validator_keys`] on epoch transitions.
pub type ValidatorKeyMap = HashMap<ValidatorId, Bls12381G1PublicKey>;

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

/// Result of gossip message validation by the application handler.
///
/// Returned by [`GossipHandler::on_message`] to tell the network layer whether
/// the message should be accepted (forwarded to peers) or rejected (dropped
/// with a peer-scoring penalty).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GossipVerdict {
    /// Message is valid — accept and forward to peers.
    Accept,
    /// Message is invalid — reject and penalize sender.
    Reject,
}

/// Typed handler for a single gossip message type.
///
/// Called after the network layer SBOR-decodes the raw payload into `M`.
/// Implementations typically convert the message into a `ProtocolEvent` and
/// send it to the IoLoop via a captured channel sender.
///
/// Returns [`GossipVerdict`] to indicate whether the message should be
/// accepted (forwarded) or rejected (dropped with peer penalty).
pub trait GossipHandler<M: NetworkMessage>: Send + Sync + 'static {
    fn on_message(&self, message: M) -> GossipVerdict;
}

/// Blanket impl: any `Fn(M) -> GossipVerdict` can serve as a typed gossip handler.
impl<M: NetworkMessage, F: Fn(M) -> GossipVerdict + Send + Sync + 'static> GossipHandler<M> for F {
    fn on_message(&self, message: M) -> GossipVerdict {
        (self)(message)
    }
}

/// Typed handler for inbound notification messages (fire-and-forget unicast).
///
/// Called after the network layer SBOR-decodes the raw payload into `M`.
/// No return value — notifications are one-way.
pub trait NotificationHandler<M: NetworkMessage>: Send + Sync + 'static {
    fn on_notification(&self, message: M);
}

/// Blanket impl: any `Fn(M)` can serve as a typed notification handler.
impl<M: NetworkMessage, F: Fn(M) + Send + Sync + 'static> NotificationHandler<M> for F {
    fn on_notification(&self, message: M) {
        (self)(message)
    }
}

/// Typed handler for a single request message type.
///
/// Called after the network layer SBOR-decodes the raw request into `R`.
/// The returned `R::Response` is SBOR-encoded by the network layer before
/// sending back to the requester.
pub trait RequestHandler<R: Request>: Send + Sync + 'static {
    fn handle_request(&self, request: R) -> R::Response;
}

/// Blanket impl: any `Fn(R) -> R::Response` can serve as a typed request handler.
impl<R: Request, F: Fn(R) -> R::Response + Send + Sync + 'static> RequestHandler<R> for F {
    fn handle_request(&self, request: R) -> R::Response {
        (self)(request)
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

    /// Register a typed gossip handler for a message type.
    ///
    /// The implementation SBOR-decodes the raw network payload into `M` before
    /// calling the handler. Decode errors are logged and the message is dropped.
    ///
    /// In production, this also auto-subscribes to the corresponding gossipsub
    /// topic (shard-scoped or global, per `scope`).
    ///
    /// Called during node initialization — once per message type.
    fn register_gossip_handler<M: NetworkMessage>(
        &self,
        scope: TopicScope,
        handler: impl GossipHandler<M>,
    );

    /// Register a typed request handler for a message type.
    ///
    /// The `HandlerRegistry` SBOR-decodes the raw request into `R` and SBOR-encodes
    /// the `R::Response` before sending it back. Decode/encode errors are logged
    /// and an empty response is returned.
    ///
    /// Called during node initialization — once per request type.
    fn register_request_handler<R: Request>(&self, handler: impl RequestHandler<R>);

    // ── Unicast notifications ──

    /// Send a typed notification directly to specific validators (fire-and-forget).
    ///
    /// No response is expected. TCP provides packet-level reliability;
    /// protocol-level timeouts handle the rest.
    fn notify<M: NetworkMessage>(&self, recipients: &[ValidatorId], message: &M);

    /// Register a handler for inbound notification messages (fire-and-forget unicast).
    ///
    /// Called during node initialization — once per notification type.
    fn register_notification_handler<M: NetworkMessage>(
        &self,
        handler: impl NotificationHandler<M>,
    );

    // ── Topology updates ──

    /// Update the validator key map used for identity verification.
    ///
    /// Called by the io_loop when topology changes (epoch transitions).
    /// Production implementations use this to update the validator-bind
    /// handshake's key lookup. Default is a no-op (simulation doesn't need it).
    fn update_validator_keys(&self, _keys: Arc<ValidatorKeyMap>) {}

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

    // Verify that closures satisfy GossipHandler<M> via blanket impl.
    #[test]
    fn test_closure_gossip_handler() {
        use hyperscale_types::NetworkMessage;
        use sbor::{Decode, Encode};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        #[derive(Debug, Encode, Decode)]
        struct TestMsg(u32);
        impl NetworkMessage for TestMsg {
            fn message_type_id() -> &'static str {
                "test.msg"
            }
        }

        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        let handler = move |_msg: TestMsg| -> GossipVerdict {
            counter_clone.fetch_add(1, Ordering::SeqCst);
            GossipVerdict::Accept
        };
        let verdict = handler.on_message(TestMsg(42));
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert_eq!(verdict, GossipVerdict::Accept);
    }
}
