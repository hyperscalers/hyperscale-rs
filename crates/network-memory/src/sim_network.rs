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

use hyperscale_network::{
    GossipHandler, HandlerRegistry, Network, NotificationHandler, RequestError, RequestHandler,
    TopicScope, compression,
};
use hyperscale_types::{NetworkMessage, Request, ShardGroupId, ShardMessage, ValidatorId};
use sbor::basic_encode;
use std::sync::{Arc, Mutex};

/// Target for an outbound message.
#[derive(Debug, Clone)]
pub enum BroadcastTarget {
    /// Broadcast to all peers in a specific shard.
    Shard(ShardGroupId),
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
    /// Validators eligible to serve this request.
    pub peers: Vec<ValidatorId>,
    /// Optional preferred peer (e.g., block proposer for fetch).
    pub preferred_peer: Option<ValidatorId>,
    /// Message type ID for handler lookup (e.g., "block.request").
    pub type_id: &'static str,
    /// SBOR-encoded request bytes.
    pub request_bytes: Vec<u8>,
    /// Callback that receives SBOR-encoded response bytes (or error).
    pub on_response: Box<dyn FnOnce(Result<Vec<u8>, RequestError>) + Send>,
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
    pub fn new(registry: Arc<HandlerRegistry>) -> Self {
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
        Self::new(Arc::new(HandlerRegistry::new()))
    }
}

impl Network for SimNetworkAdapter {
    fn broadcast_to_shard<M: ShardMessage>(&self, shard: ShardGroupId, message: &M) {
        let data = compression::compress(
            &basic_encode(message).expect("SimNetworkAdapter: failed to encode message"),
        );
        self.outbox.lock().unwrap().push(OutboxEntry {
            target: BroadcastTarget::Shard(shard),
            message_type: M::message_type_id(),
            data,
        });
    }

    fn broadcast_global<M: NetworkMessage>(&self, message: &M) {
        let data = compression::compress(
            &basic_encode(message).expect("SimNetworkAdapter: failed to encode message"),
        );
        self.outbox.lock().unwrap().push(OutboxEntry {
            target: BroadcastTarget::Global,
            message_type: M::message_type_id(),
            data,
        });
    }

    fn register_gossip_handler<M: NetworkMessage>(
        &self,
        _scope: TopicScope,
        handler: impl GossipHandler<M>,
    ) {
        // Registry owns SBOR decode — just forward.
        // Scope is irrelevant in simulation (delivery controlled by harness).
        self.registry.register_gossip(handler);
    }

    fn notify<M: NetworkMessage>(&self, recipients: &[ValidatorId], message: &M) {
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

    fn register_notification_handler<M: NetworkMessage>(
        &self,
        handler: impl NotificationHandler<M>,
    ) {
        self.registry.register_notification(handler);
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
        let request_bytes =
            sbor::basic_encode(&request).expect("SimNetworkAdapter: failed to encode request");

        // Wrap the typed callback: decode raw response bytes → R::Response
        let typed_callback: Box<dyn FnOnce(Result<Vec<u8>, RequestError>) + Send> =
            Box::new(move |result| match result {
                Ok(bytes) => match sbor::basic_decode::<R::Response>(&bytes) {
                    Ok(response) => on_response(Ok(response)),
                    Err(e) => {
                        on_response(Err(RequestError::PeerError(format!("decode error: {e:?}"))));
                    }
                },
                Err(e) => on_response(Err(e)),
            });

        self.pending_requests.lock().unwrap().push(PendingRequest {
            peers: peers.to_vec(),
            preferred_peer,
            type_id: R::message_type_id(),
            request_bytes,
            on_response: typed_callback,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_messages::TransactionGossip;
    use hyperscale_types::{
        BlockHeight, ShardGroupId,
        test_utils::{test_node, test_transaction_with_nodes},
    };
    use std::sync::Mutex as StdMutex;

    fn test_gossip() -> TransactionGossip {
        TransactionGossip::new(test_transaction_with_nodes(
            &[1, 2, 3],
            vec![test_node(1)],
            vec![test_node(2)],
        ))
    }

    #[test]
    fn test_broadcast_to_shard_creates_outbox_entry() {
        let adapter = SimNetworkAdapter::default();
        let gossip = test_gossip();
        let shard = ShardGroupId(3);

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
        use hyperscale_messages::request::GetBlockRequest;
        use hyperscale_messages::response::GetBlockResponse;

        let registry = Arc::new(HandlerRegistry::new());
        let adapter = SimNetworkAdapter::new(registry.clone());

        assert!(registry.get_request("block.request").is_none());
        adapter.register_request_handler::<GetBlockRequest>(|_req| GetBlockResponse::not_found());
        assert!(registry.get_request("block.request").is_some());
    }

    #[test]
    fn test_register_request_handler_overwrites() {
        use hyperscale_messages::request::GetBlockRequest;
        use hyperscale_messages::response::GetBlockResponse;

        let adapter = SimNetworkAdapter::default();

        adapter.register_request_handler::<GetBlockRequest>(|_req| GetBlockResponse::not_found());
        adapter.register_request_handler::<GetBlockRequest>(|_req| GetBlockResponse::not_found());

        // Second handler should have won (overwrites).
        // Encode a real request, call the raw handler, verify it works.
        let handler = adapter.registry.get_request("block.request").unwrap();
        let req = GetBlockRequest::new(BlockHeight(1), BlockHeight(1));
        let req_bytes = sbor::basic_encode(&req).unwrap();
        let response_bytes = handler(&req_bytes);
        assert!(!response_bytes.is_empty());
    }

    #[test]
    fn test_request_creates_pending_request() {
        use hyperscale_messages::request::GetBlockRequest;

        let adapter = SimNetworkAdapter::default();
        let preferred = Some(ValidatorId(7));

        let peers = &[ValidatorId(7)];
        adapter.request(
            peers,
            preferred,
            GetBlockRequest::new(BlockHeight(42), BlockHeight(42)),
            Box::new(|_| {}),
        );

        let requests = adapter.drain_pending_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].peers, peers);
        assert_eq!(requests[0].preferred_peer, preferred);
        assert_eq!(requests[0].type_id, "block.request");
        assert!(!requests[0].request_bytes.is_empty());

        // Verify the request bytes decode correctly
        let decoded: GetBlockRequest = sbor::basic_decode(&requests[0].request_bytes).unwrap();
        assert_eq!(decoded.height, BlockHeight(42));
    }

    #[test]
    fn test_request_callback_decodes_response() {
        use hyperscale_messages::request::GetBlockRequest;
        use hyperscale_messages::response::GetBlockResponse;

        let adapter = SimNetworkAdapter::default();
        let result: Arc<StdMutex<Option<Result<GetBlockResponse, RequestError>>>> =
            Arc::new(StdMutex::new(None));
        let result_clone = result.clone();

        adapter.request(
            &[ValidatorId(1)],
            None,
            GetBlockRequest::new(BlockHeight(1), BlockHeight(1)),
            Box::new(move |r| {
                *result_clone.lock().unwrap() = Some(r);
            }),
        );

        let requests = adapter.drain_pending_requests();
        let on_response = requests.into_iter().next().unwrap().on_response;

        // Simulate a successful response with SBOR-encoded bytes
        let response = GetBlockResponse::not_found();
        let response_bytes = sbor::basic_encode(&response).unwrap();
        on_response(Ok(response_bytes));

        let captured = result.lock().unwrap().take().unwrap();
        let decoded_response = captured.unwrap();
        assert!(!decoded_response.has_block());
    }

    #[test]
    fn test_request_callback_propagates_error() {
        use hyperscale_messages::request::GetBlockRequest;
        use hyperscale_messages::response::GetBlockResponse;

        let adapter = SimNetworkAdapter::default();
        let result: Arc<StdMutex<Option<Result<GetBlockResponse, RequestError>>>> =
            Arc::new(StdMutex::new(None));
        let result_clone = result.clone();

        adapter.request(
            &[ValidatorId(1)],
            None,
            GetBlockRequest::new(BlockHeight(1), BlockHeight(1)),
            Box::new(move |r| {
                *result_clone.lock().unwrap() = Some(r);
            }),
        );

        let requests = adapter.drain_pending_requests();
        let on_response = requests.into_iter().next().unwrap().on_response;
        on_response(Err(RequestError::Timeout));

        let captured = result.lock().unwrap().take().unwrap();
        assert!(matches!(captured, Err(RequestError::Timeout)));
    }
}
