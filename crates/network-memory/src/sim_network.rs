//! Network trait implementation for deterministic simulation.
//!
//! [`SimNetworkAdapter`] buffers outgoing messages in an outbox. After each
//! `IoLoop::step()`, the simulation harness drains the outbox and routes
//! entries through [`SimulatedNetwork::accept_gossip`](crate::SimulatedNetwork::accept_gossip),
//! which applies partition/latency/loss, LZ4-decompresses the payload once,
//! and queues deliveries in an internal latency heap.
//!
//! Messages are wire-encoded (SBOR + LZ4) in the outbox, matching the production
//! encoding path. [`SimulatedNetwork::flush_gossip`](crate::SimulatedNetwork::flush_gossip)
//! delivers due messages via each target's registered per-type gossip handler.

use std::sync::{Arc, Mutex};

use hyperscale_network::{
    GossipHandler, HandlerRegistry, Network, NotificationHandler, RequestError, RequestHandler,
    ResponseVerdict, compression,
};
use hyperscale_types::{
    GossipMessage, MessageClass, NetworkMessage, Request, ShardId, ValidatorId,
};
use sbor::{basic_decode, basic_encode};

/// Target for an outbound message.
#[derive(Debug, Clone)]
pub enum BroadcastTarget {
    /// Broadcast to all peers in a specific shard.
    Shard(ShardId),
    /// Broadcast to all connected peers globally.
    Global,
}

/// An outbound message buffered for delivery by the simulation harness.
#[derive(Debug)]
pub struct OutboxEntry {
    /// Where to deliver.
    pub target: BroadcastTarget,
    /// The message type identifier (e.g., "block.header").
    pub message_type: &'static str,
    /// Wire-encoded message bytes (SBOR + LZ4).
    pub data: Vec<u8>,
}

/// A buffered notification (fire-and-forget unicast) awaiting harness delivery.
pub struct PendingNotification {
    /// Validators to deliver to.
    pub recipients: Vec<ValidatorId>,
    /// Message type ID for handler lookup.
    pub type_id: &'static str,
    /// Wire-encoded message bytes (SBOR + LZ4).
    pub data: Vec<u8>,
}

/// A buffered request from `IoLoop`, awaiting harness fulfillment.
///
/// The simulation harness drains these after each step, looks up the
/// per-type request handler on the target peer, passes the SBOR-encoded
/// request bytes directly (no framing needed), and calls `on_response`
/// with the raw SBOR response bytes.
pub struct PendingRequest {
    /// Shard whose committee should serve this request. The harness
    /// resolves it to a peer list from its topology view.
    pub shard: ShardId,
    /// Optional preferred peer (e.g., block proposer for fetch).
    pub preferred_peer: Option<ValidatorId>,
    /// Message type ID for handler lookup (e.g., "block.request").
    pub type_id: &'static str,
    /// SBOR-encoded request bytes.
    pub request_bytes: Vec<u8>,
    /// Callback that receives SBOR-encoded response bytes (or error). Returns
    /// a [`ResponseVerdict`] for parity with the production `Network::request`
    /// signature; the simulation discards the verdict (deterministic harness
    /// owns peer behaviour directly).
    pub on_response: Box<dyn FnOnce(Result<Vec<u8>, RequestError>) -> ResponseVerdict + Send>,
}

/// Network implementation for simulation.
///
/// Buffers outgoing messages in an outbox rather than delivering them immediately.
/// The simulation harness drains the outbox after each `IoLoop::step()` and
/// controls delivery timing, partitions, and packet loss.
///
/// # Usage
///
/// Each simulated node owns a `SimNetworkAdapter`. The harness:
/// 1. Calls `IoLoop::step(event)` which may produce network sends
/// 2. Drains the adapter's outbox via [`drain_outbox()`](Self::drain_outbox)
/// 3. Routes entries through `SimulatedNetwork::accept_gossip()`
/// 4. `SimulatedNetwork::flush_gossip()` delivers due messages via handlers
pub struct SimNetworkAdapter {
    outbox: Mutex<Vec<OutboxEntry>>,
    pending_requests: Mutex<Vec<PendingRequest>>,
    pending_notifications: Mutex<Vec<PendingNotification>>,
    /// Shared handler registry — written by `register_*_handler`,
    /// read by `SimulatedNetwork::accept_requests`, `flush_notifications`, and `flush_gossip`.
    pub(crate) registry: Arc<HandlerRegistry>,
}

impl SimNetworkAdapter {
    /// Create a new adapter with a shared handler registry.
    ///
    /// Use [`SimulatedNetwork::create_adapter`](crate::SimulatedNetwork::create_adapter)
    /// to create adapters with shared registries for request fulfillment and gossip delivery.
    #[must_use]
    pub const fn new(registry: Arc<HandlerRegistry>) -> Self {
        Self {
            outbox: Mutex::new(Vec::new()),
            pending_requests: Mutex::new(Vec::new()),
            pending_notifications: Mutex::new(Vec::new()),
            registry,
        }
    }

    /// Drain all buffered outgoing messages.
    ///
    /// Returns the entries accumulated since the last drain. The harness calls
    /// this after each `IoLoop::step()` to process outbound messages.
    ///
    /// # Panics
    ///
    /// Panics if the internal `Mutex` is poisoned.
    pub fn drain_outbox(&self) -> Vec<OutboxEntry> {
        std::mem::take(&mut self.outbox.lock().unwrap())
    }

    /// Drain all buffered requests.
    ///
    /// The harness calls this after each `IoLoop::step()` to fulfill
    /// requests by looking up data from peer nodes and calling the callbacks.
    ///
    /// # Panics
    ///
    /// Panics if the internal `Mutex` is poisoned.
    pub fn drain_pending_requests(&self) -> Vec<PendingRequest> {
        std::mem::take(&mut self.pending_requests.lock().unwrap())
    }

    /// Drain all buffered notifications.
    ///
    /// The harness calls this after each `IoLoop::step()` to deliver
    /// notifications to their recipients via per-type notification handlers.
    ///
    /// # Panics
    ///
    /// Panics if the internal `Mutex` is poisoned.
    pub fn drain_pending_notifications(&self) -> Vec<PendingNotification> {
        std::mem::take(&mut self.pending_notifications.lock().unwrap())
    }
}

impl Default for SimNetworkAdapter {
    fn default() -> Self {
        Self::new(Arc::new(HandlerRegistry::default()))
    }
}

impl Network for SimNetworkAdapter {
    fn broadcast_to_shard<M: GossipMessage + 'static>(&self, shard: ShardId, message: &M) {
        // Tee to in-process subscribers — the harness's `accept_gossip`
        // skips the publisher's own node (matching gossipsub's no-loop
        // semantics), so colocated vnodes would otherwise miss their
        // own host's broadcasts. The registry computes the per-vnode
        // fan-out from `hosted_shards`.
        let _ = self.registry.local_dispatch_gossip(message, Some(shard));
        let data = compression::compress(
            &basic_encode(message).expect("SimNetworkAdapter: failed to encode message"),
        );
        self.outbox.lock().unwrap().push(OutboxEntry {
            target: BroadcastTarget::Shard(shard),
            message_type: M::message_type_id(),
            data,
        });
    }

    fn broadcast_global<M: GossipMessage + 'static>(&self, message: &M) {
        let _ = self.registry.local_dispatch_gossip(message, None);
        let data = compression::compress(
            &basic_encode(message).expect("SimNetworkAdapter: failed to encode message"),
        );
        self.outbox.lock().unwrap().push(OutboxEntry {
            target: BroadcastTarget::Global,
            message_type: M::message_type_id(),
            data,
        });
    }

    fn register_gossip_handler<M: GossipMessage + 'static>(&self, handler: impl GossipHandler<M>) {
        // Registry owns SBOR decode + per-vnode fan-out. Topic scope
        // is irrelevant in simulation (delivery controlled by harness).
        self.registry.register_gossip(handler);
    }

    fn notify<M: NetworkMessage + 'static>(&self, recipients: &[ValidatorId], message: &M) {
        // Note: compression happens here at send-time, then accept_notifications()
        // decompresses before queueing for delivery. In production (Libp2pNetwork),
        // compression happens inside the stream framing layer (write_typed_frame) instead.
        let data = compression::compress(
            &basic_encode(message).expect("SimNetworkAdapter: failed to encode notification"),
        );
        self.pending_notifications
            .lock()
            .unwrap()
            .push(PendingNotification {
                recipients: recipients.to_vec(),
                type_id: M::message_type_id(),
                data,
            });
    }

    fn register_notification_handler<M: NetworkMessage + Clone + 'static>(
        &self,
        handler: impl NotificationHandler<M>,
    ) {
        self.registry.register_notification(handler);
    }

    fn register_request_handler<R: Request + Send + 'static>(
        &self,
        shard: ShardId,
        handler: impl RequestHandler<R>,
    ) where
        R::Response: Send + 'static,
    {
        // Registry owns SBOR decode/encode — just forward.
        self.registry.register_request(shard, handler);
    }

    fn request<R: Request + Clone + 'static>(
        &self,
        shard: ShardId,
        preferred_peer: Option<ValidatorId>,
        request: R,
        _class_override: Option<MessageClass>,
        on_response: Box<dyn FnOnce(Result<R::Response, RequestError>) -> ResponseVerdict + Send>,
    ) {
        let request_bytes =
            basic_encode(&request).expect("SimNetworkAdapter: failed to encode request");

        // Wrap the typed callback: decode raw response bytes → R::Response
        let typed_callback: Box<
            dyn FnOnce(Result<Vec<u8>, RequestError>) -> ResponseVerdict + Send,
        > = Box::new(move |result| match result {
            Ok(bytes) => match basic_decode::<R::Response>(&bytes) {
                Ok(response) => on_response(Ok(response)),
                Err(e) => on_response(Err(RequestError::PeerError(format!("decode error: {e:?}")))),
            },
            Err(e) => on_response(Err(e)),
        });

        self.pending_requests.lock().unwrap().push(PendingRequest {
            shard,
            preferred_peer,
            type_id: R::message_type_id(),
            request_bytes,
            on_response: typed_callback,
        });
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex as StdMutex;

    use hyperscale_types::network::gossip::TransactionGossip;
    use hyperscale_types::test_utils::{test_node, test_transaction_with_nodes};
    use hyperscale_types::{BlockHeight, ShardId};

    use super::*;

    fn test_gossip() -> TransactionGossip {
        TransactionGossip::new(vec![Arc::new(test_transaction_with_nodes(
            &[1, 2, 3],
            vec![test_node(1)],
            vec![test_node(2)],
        ))])
    }

    #[test]
    fn test_broadcast_to_shard_creates_outbox_entry() {
        let adapter = SimNetworkAdapter::default();
        let gossip = test_gossip();
        let shard = ShardId::leaf(2, 3);

        adapter.broadcast_to_shard(shard, &gossip);

        let entries = adapter.drain_outbox();
        assert_eq!(entries.len(), 1);
        assert!(matches!(entries[0].target, BroadcastTarget::Shard(s) if s == shard));
        assert_eq!(entries[0].message_type, "transaction.gossip");
        assert!(!entries[0].data.is_empty());
    }

    #[test]
    fn test_broadcast_global_creates_outbox_entry() {
        let adapter = SimNetworkAdapter::default();
        let gossip = test_gossip();

        adapter.broadcast_global(&gossip);

        let entries = adapter.drain_outbox();
        assert_eq!(entries.len(), 1);
        assert!(matches!(entries[0].target, BroadcastTarget::Global));
        assert_eq!(entries[0].message_type, "transaction.gossip");
        assert!(!entries[0].data.is_empty());
    }

    #[test]
    fn test_drain_outbox_returns_and_clears() {
        let adapter = SimNetworkAdapter::default();
        let gossip = test_gossip();

        adapter.broadcast_global(&gossip);
        adapter.broadcast_global(&gossip);
        adapter.broadcast_global(&gossip);

        let first_drain = adapter.drain_outbox();
        assert_eq!(first_drain.len(), 3);

        let second_drain = adapter.drain_outbox();
        assert_eq!(second_drain.len(), 0);
    }

    #[test]
    fn test_register_request_handler() {
        use hyperscale_types::network::request::GetBlockRequest;
        use hyperscale_types::network::response::GetBlockResponse;

        let registry = Arc::new(HandlerRegistry::default());
        let adapter = SimNetworkAdapter::new(registry.clone());
        let shard = ShardId::leaf(2, 0);

        assert!(registry.get_request("block.request", shard).is_none());
        adapter.register_request_handler::<GetBlockRequest>(shard, |_req| {
            GetBlockResponse::not_found()
        });
        assert!(registry.get_request("block.request", shard).is_some());
    }

    #[test]
    #[should_panic(expected = "duplicate request handler registration")]
    fn test_register_request_handler_rejects_duplicate() {
        use hyperscale_types::network::request::GetBlockRequest;
        use hyperscale_types::network::response::GetBlockResponse;

        let adapter = SimNetworkAdapter::default();
        let shard = ShardId::leaf(2, 0);

        adapter.register_request_handler::<GetBlockRequest>(shard, |_req| {
            GetBlockResponse::not_found()
        });
        adapter.register_request_handler::<GetBlockRequest>(shard, |_req| {
            GetBlockResponse::not_found()
        });
    }

    #[test]
    fn test_request_creates_pending_request() {
        use hyperscale_types::network::request::GetBlockRequest;

        let adapter = SimNetworkAdapter::default();
        let preferred = Some(ValidatorId::new(7));
        let shard = ShardId::leaf(2, 3);

        adapter.request(
            shard,
            preferred,
            GetBlockRequest::new(BlockHeight::new(42), BlockHeight::new(42)),
            None,
            Box::new(|_| ResponseVerdict::Accept),
        );

        let requests = adapter.drain_pending_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].shard, shard);
        assert_eq!(requests[0].preferred_peer, preferred);
        assert_eq!(requests[0].type_id, "block.request");
        assert!(!requests[0].request_bytes.is_empty());

        // Verify the request bytes decode correctly
        let decoded: GetBlockRequest = basic_decode(&requests[0].request_bytes).unwrap();
        assert_eq!(decoded.height, BlockHeight::new(42));
    }

    #[test]
    fn test_request_callback_decodes_response() {
        use hyperscale_types::network::request::GetBlockRequest;
        use hyperscale_types::network::response::GetBlockResponse;

        let adapter = SimNetworkAdapter::default();
        let result: Arc<StdMutex<Option<Result<GetBlockResponse, RequestError>>>> =
            Arc::new(StdMutex::new(None));
        let result_clone = result.clone();

        adapter.request(
            ShardId::leaf(2, 0),
            None,
            GetBlockRequest::new(BlockHeight::new(1), BlockHeight::new(1)),
            None,
            Box::new(move |r| {
                *result_clone.lock().unwrap() = Some(r);
                ResponseVerdict::Accept
            }),
        );

        let requests = adapter.drain_pending_requests();
        let on_response = requests.into_iter().next().unwrap().on_response;

        // Simulate a successful response with SBOR-encoded bytes
        let response = GetBlockResponse::not_found();
        let response_bytes = basic_encode(&response).unwrap();
        on_response(Ok(response_bytes));

        let captured = result.lock().unwrap().take().unwrap();
        let decoded_response = captured.unwrap();
        assert!(!decoded_response.has_block());
    }

    #[test]
    fn test_request_callback_propagates_error() {
        use hyperscale_types::network::request::GetBlockRequest;
        use hyperscale_types::network::response::GetBlockResponse;

        let adapter = SimNetworkAdapter::default();
        let result: Arc<StdMutex<Option<Result<GetBlockResponse, RequestError>>>> =
            Arc::new(StdMutex::new(None));
        let result_clone = result.clone();

        adapter.request(
            ShardId::leaf(2, 0),
            None,
            GetBlockRequest::new(BlockHeight::new(1), BlockHeight::new(1)),
            None,
            Box::new(move |r| {
                *result_clone.lock().unwrap() = Some(r);
                ResponseVerdict::Accept
            }),
        );

        let requests = adapter.drain_pending_requests();
        let on_response = requests.into_iter().next().unwrap().on_response;
        on_response(Err(RequestError::Timeout));

        let captured = result.lock().unwrap().take().unwrap();
        assert!(matches!(captured, Err(RequestError::Timeout)));
    }
}
