//! Network trait for typed message passing.
//!
//! Defines the `Network` interface implemented by both production (`network-libp2p`)
//! and simulation (`network-memory`) backends.
//!
//! Handler registration is fully typed: `register_gossip_handler<M>` accepts a
//! `GossipHandler<M>` and `register_request_handler<R>` accepts a `RequestHandler<R>`.
//! The `HandlerRegistry` owns SBOR serialization — `Network` impls just forward.

use std::collections::HashMap;
use std::sync::Arc;

use hyperscale_types::{
    Bls12381G1PublicKey, MessageClass, NetworkMessage, Request, ShardGroupId, ShardMessage,
    TopologySnapshot, ValidatorId,
};

/// Maps `ValidatorId` to BLS public key for identity verification (e.g. validator-bind).
///
/// Derived from the topology snapshot inside network impls when
/// [`Network::update_topology`] is called.
pub type ValidatorKeyMap = HashMap<ValidatorId, Bls12381G1PublicKey>;

/// Error returned when a network request fails.
#[derive(Debug, thiserror::Error)]
pub enum RequestError {
    /// No response received within the configured timeout.
    #[error("Request timed out")]
    Timeout,
    /// The transport's request manager retried the request against rotated
    /// peers and exhausted its retry budget. The transport already absorbed
    /// per-peer + per-request backoff before surfacing this — callers
    /// should retry immediately rather than pile additional deferral on
    /// top.
    #[error("Request exhausted after {attempts} attempts")]
    Exhausted {
        /// Number of attempts the transport made.
        attempts: u32,
    },
    /// Network layer could not reach the named peer.
    #[error("Peer unreachable: {0}")]
    PeerUnreachable(ValidatorId),
    /// No peers available in the target pool.
    #[error("No peers available")]
    NoPeers,
    /// Peer answered with an application-level error.
    #[error("Peer returned error: {0}")]
    PeerError(String),
    /// Network is shutting down; the request will not complete.
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

/// Result of request-response evaluation by the application callback.
///
/// Returned by the `on_response` closure passed to [`Network::request`] so
/// the network layer can feed app-level success/failure into the same
/// peer-health tracker that timeouts and connection errors already use.
/// Use `Reject` whenever the response decoded fine at the wire layer but
/// was unusable to the app (peer returned `None`/empty, scope mismatch,
/// partial response, malformed payload). This deprioritizes the peer for
/// future selection without any extra plumbing from the call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseVerdict {
    /// Response was usable — record success.
    Accept,
    /// Response was unusable — penalize the serving peer.
    Reject,
}

/// Typed handler for a single gossip message type.
///
/// Called after the network layer SBOR-decodes the raw payload into `M`.
/// Implementations typically convert the message into a `ProtocolEvent` and
/// send it to the `IoLoop` via a captured channel sender.
///
/// `shard` is the shard the topic encoded for [`TopicScope::Shard`]
/// gossip and `None` for [`TopicScope::Global`] gossip; cross-shard
/// hosting uses it to route the emitted `NodeInput` to the right
/// hosted shard. Global handlers (e.g. `CommittedBlockHeaderGossip`)
/// usually extract the relevant shard from the message body itself.
///
/// Returns [`GossipVerdict`] to indicate whether the message should be
/// accepted (forwarded) or rejected (dropped with peer penalty).
pub trait GossipHandler<M: NetworkMessage>: Send + Sync + 'static {
    /// Process a decoded gossip message; return whether to forward it.
    fn on_message(&self, message: M, shard: Option<ShardGroupId>) -> GossipVerdict;
}

/// Blanket impl: any `Fn(M, Option<ShardGroupId>) -> GossipVerdict` can serve
/// as a typed gossip handler.
impl<M, F> GossipHandler<M> for F
where
    M: NetworkMessage,
    F: Fn(M, Option<ShardGroupId>) -> GossipVerdict + Send + Sync + 'static,
{
    fn on_message(&self, message: M, shard: Option<ShardGroupId>) -> GossipVerdict {
        (self)(message, shard)
    }
}

/// Typed handler for inbound notification messages (fire-and-forget unicast).
///
/// Called after the network layer SBOR-decodes the raw payload into `M`.
/// No return value — notifications are one-way.
pub trait NotificationHandler<M: NetworkMessage>: Send + Sync + 'static {
    /// Process a decoded notification.
    fn on_notification(&self, message: M);
}

/// Blanket impl: any `Fn(M)` can serve as a typed notification handler.
impl<M: NetworkMessage, F: Fn(M) + Send + Sync + 'static> NotificationHandler<M> for F {
    fn on_notification(&self, message: M) {
        (self)(message);
    }
}

/// Typed handler for a single request message type.
///
/// Called after the network layer SBOR-decodes the raw request into `R`.
/// The returned `R::Response` is SBOR-encoded by the network layer before
/// sending back to the requester.
pub trait RequestHandler<R: Request>: Send + Sync + 'static {
    /// Produce a response for a decoded request.
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
/// This is consistent with how storage and the engine are already used:
/// `ActionContext<S: Storage, E: Engine>`.
///
/// All sends are fire-and-forget. Responses to requests arrive via callback.
pub trait Network: Send + Sync + 'static {
    // ── Pub/sub messaging ──

    /// Broadcast a shard-scoped message to all peers subscribed to that shard's topic.
    fn broadcast_to_shard<M: ShardMessage + 'static>(&self, shard: ShardGroupId, message: &M);

    /// Broadcast a message to all connected peers globally.
    fn broadcast_global<M: NetworkMessage + 'static>(&self, message: &M);

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
    fn register_gossip_handler<M: NetworkMessage + Clone + 'static>(
        &self,
        scope: TopicScope,
        handler: impl GossipHandler<M>,
    );

    /// Register a typed request handler for a message type on `shard`.
    ///
    /// The `HandlerRegistry` SBOR-decodes the raw request into `R` and SBOR-encodes
    /// the `R::Response` before sending it back. Decode/encode errors are logged
    /// and an empty response is returned.
    ///
    /// Called during node initialization — once per `(type, hosted shard)` pair.
    /// A multi-shard host registers one handler per hosted shard so each
    /// closure can capture its own `ShardIo`'s storage.
    ///
    /// `R: Send` and `R::Response: Send` are required so the registry can
    /// also install a typed local-dispatch path — same-host requests
    /// bypass libp2p and preserve `Arc`-shared payloads on the response.
    fn register_request_handler<R: Request + Send + 'static>(
        &self,
        shard: ShardGroupId,
        handler: impl RequestHandler<R>,
    ) where
        R::Response: Send + 'static;

    // ── Unicast notifications ──

    /// Send a typed notification directly to specific validators (fire-and-forget).
    ///
    /// No response is expected. TCP provides packet-level reliability;
    /// protocol-level timeouts handle the rest.
    fn notify<M: NetworkMessage + 'static>(&self, recipients: &[ValidatorId], message: &M);

    /// Register a handler for inbound notification messages (fire-and-forget unicast).
    ///
    /// Called during node initialization — once per notification type.
    fn register_notification_handler<M: NetworkMessage + Clone + 'static>(
        &self,
        handler: impl NotificationHandler<M>,
    );

    // ── Topology updates ──

    /// Update the topology snapshot used for peer selection and identity
    /// verification.
    ///
    /// Called by the `io_loop` when topology changes. The network impl reads
    /// shard committees, validator BLS pubkeys, and the local validator set
    /// from the snapshot — callers don't pass any of that explicitly.
    ///
    /// Default is a no-op (simulation impls without committee routing don't
    /// need it).
    fn update_topology(&self, _snapshot: Arc<TopologySnapshot>) {}

    // ── Request-response ──

    /// Send a typed request and receive the response via callback.
    ///
    /// * `shard` — the shard whose committee answers the request. The
    ///   network impl resolves `shard` to its committee using the current
    ///   topology snapshot and picks the actual peer(s) to try (filtering
    ///   out locally-hosted validator ids automatically).
    /// * `preferred_peer` — optional hint for which peer to try first
    ///   (e.g. the block proposer for fetch requests). `None` means the
    ///   network's health-weighted selection picks freely. If the
    ///   `preferred_peer` is not in `shard`'s committee, the hint is
    ///   ignored.
    ///
    /// The callback is called on a network thread when the response arrives,
    /// or with an error on timeout/failure. Compatible with sync main loops —
    /// the callback typically pushes into the main loop's event channel. The
    /// callback returns a [`ResponseVerdict`] so app-level rejections (peer
    /// returned `None`/empty/wrong-scope) feed back into the same peer-health
    /// tracker that timeouts use, deprioritizing the serving peer for future
    /// selection. Verdict is ignored on the `Err` path (the network already
    /// recorded the failure).
    ///
    /// `class_override` lets the caller demote (or, in principle, promote)
    /// the message class on a per-call basis. `None` uses the wire type's
    /// static [`NetworkMessage::class()`]. Bimodal types like
    /// `GetTransactionsRequest` use this to differentiate hot-path
    /// pending-block fetches from sync / DA-backfill fetches.
    fn request<R: Request + 'static>(
        &self,
        shard: ShardGroupId,
        preferred_peer: Option<ValidatorId>,
        request: R,
        class_override: Option<MessageClass>,
        on_response: Box<dyn FnOnce(Result<R::Response, RequestError>) -> ResponseVerdict + Send>,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    // Verify that closures satisfy GossipHandler<M> via blanket impl.
    #[test]
    fn test_closure_gossip_handler() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        use hyperscale_types::NetworkMessage;
        use sbor::{Decode, Encode};

        #[derive(Debug, Encode, Decode)]
        struct TestMsg(u32);
        impl NetworkMessage for TestMsg {
            fn message_type_id() -> &'static str {
                "test.msg"
            }
        }

        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        let handler = move |_msg: TestMsg, _shard: Option<ShardGroupId>| -> GossipVerdict {
            counter_clone.fetch_add(1, Ordering::SeqCst);
            GossipVerdict::Accept
        };
        let verdict = handler.on_message(TestMsg(42), None);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert_eq!(verdict, GossipVerdict::Accept);
    }
}
