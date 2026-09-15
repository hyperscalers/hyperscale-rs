//! Network trait implementation for deterministic simulation.
//!
//! [`SimNetworkAdapter`] buffers outgoing messages in an outbox. After each
//! `IoLoop::step()`, the simulation harness drains the outbox and routes
//! entries through [`SimulatedNetwork::accept_gossip`](crate::SimulatedNetwork::accept_gossip),
//! which applies partition/latency/loss, LZ4-decompresses the payload once,
//! and queues deliveries in an internal latency heap.
//!
//! Messages are wire-encoded (HBOR + LZ4) in the outbox, matching the production
//! encoding path. [`SimulatedNetwork::flush_gossip`](crate::SimulatedNetwork::flush_gossip)
//! delivers due messages via each target's registered per-type gossip handler.

use std::sync::{Arc, Mutex};

use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};
use hyperscale_network::{
    GossipHandler, HandlerRegistry, Network, NotificationHandler, RequestError, RequestHandler,
    ResponseVerdict, compression,
};
use hyperscale_types::{
    GossipMessage, MessageClass, NetworkMessage, Request, RoutingCommittees, ShardId, ValidatorId,
};

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
    pub(crate) target: BroadcastTarget,
    /// The message type identifier (e.g., "block.header").
    pub(crate) message_type: &'static str,
    /// The sending type's [`NetworkMessage::class`]. Carried on the entry
    /// because the class is a property of the Rust type and never reaches
    /// the wire: the harness sees only `message_type` once the message is
    /// encoded, so anything downstream that needs the class needs it here.
    pub(crate) class: MessageClass,
    /// Wire-encoded message bytes (HBOR + LZ4).
    pub(crate) data: Vec<u8>,
}

/// A buffered notification (fire-and-forget unicast) awaiting harness delivery.
pub struct PendingNotification {
    /// Validators to deliver to.
    pub(crate) recipients: Vec<ValidatorId>,
    /// Message type ID for handler lookup.
    pub(crate) type_id: &'static str,
    /// The sending type's [`NetworkMessage::class`]. See
    /// [`OutboxEntry::class`].
    pub(crate) class: MessageClass,
    /// Wire-encoded message bytes (HBOR + LZ4).
    pub(crate) data: Vec<u8>,
}

/// A buffered request from `IoLoop`, awaiting harness fulfillment.
///
/// The simulation harness drains these after each step, looks up the
/// per-type request handler on the target peer, passes the encoded
/// request bytes directly (no framing needed), and calls `on_response`
/// with the raw response wire bytes.
pub struct PendingRequest {
    /// Shard whose committee should serve this request. The harness
    /// resolves it to a peer list from its topology view.
    pub shard: ShardId,
    /// Optional preferred peer (e.g., block proposer for fetch).
    pub(crate) preferred_peer: Option<ValidatorId>,
    /// Message type ID for handler lookup (e.g., "block.request").
    pub(crate) type_id: &'static str,
    /// Class of the request leg — the caller's override where it gave one,
    /// otherwise the request type's own. See [`OutboxEntry::class`].
    pub(crate) class: MessageClass,
    /// Class of the response leg, from the response type. The two legs of a
    /// round trip are separate messages and need not share a class.
    pub(crate) response_class: MessageClass,
    /// encoded request bytes.
    pub(crate) request_bytes: Vec<u8>,
    /// Callback that receives encoded response bytes (or error). Returns
    /// a [`ResponseVerdict`] for parity with the production `Network::request`
    /// signature; the simulation discards the verdict (deterministic harness
    /// owns peer behaviour directly).
    pub(crate) on_response:
        Box<dyn FnOnce(Result<Vec<u8>, RequestError>) -> ResponseVerdict + Send>,
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
    /// Latest terminal-clamped routing view pushed by
    /// [`Network::update_routing_committees`], mirroring the production
    /// adapter — so the sim runner's teardown reads the same routing
    /// projection the production supervisor does.
    routing_committees: Mutex<Arc<RoutingCommittees>>,
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
            routing_committees: Mutex::new(Arc::new(RoutingCommittees::new())),
        }
    }

    /// The routing view most recently pushed through
    /// [`Network::update_routing_committees`].
    ///
    /// # Panics
    ///
    /// Panics if the internal `Mutex` is poisoned.
    #[must_use]
    pub fn routing_committees(&self) -> Arc<RoutingCommittees> {
        Arc::clone(&self.routing_committees.lock().unwrap())
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
    fn update_routing_committees(&self, committees: Arc<RoutingCommittees>) {
        *self.routing_committees.lock().unwrap() = committees;
    }

    fn broadcast_to_shard<M: GossipMessage + 'static>(&self, shard: ShardId, message: &M) {
        // Tee to in-process subscribers — the harness's `accept_gossip`
        // skips the publisher's own node (matching gossipsub's no-loop
        // semantics), so colocated vnodes would otherwise miss their
        // own host's broadcasts. The registry computes the per-vnode
        // fan-out from `hosted_shards`.
        let _ = self.registry.local_dispatch_gossip(message, Some(shard));
        let data = compression::compress(
            &hbor_to_vec(message).expect("SimNetworkAdapter: failed to encode message"),
        );
        self.outbox.lock().unwrap().push(OutboxEntry {
            target: BroadcastTarget::Shard(shard),
            message_type: M::message_type_id(),
            class: M::class(),
            data,
        });
    }

    fn broadcast_global<M: GossipMessage + 'static>(&self, message: &M) {
        let _ = self.registry.local_dispatch_gossip(message, None);
        let data = compression::compress(
            &hbor_to_vec(message).expect("SimNetworkAdapter: failed to encode message"),
        );
        self.outbox.lock().unwrap().push(OutboxEntry {
            target: BroadcastTarget::Global,
            message_type: M::message_type_id(),
            class: M::class(),
            data,
        });
    }

    fn register_gossip_handler<M: GossipMessage + 'static>(&self, handler: impl GossipHandler<M>) {
        // Registry owns wire decode + per-vnode fan-out. Topic scope
        // is irrelevant in simulation (delivery controlled by harness).
        self.registry.register_gossip(handler);
    }

    fn register_host_gossip_handler<M: GossipMessage + 'static>(
        &self,
        handler: impl Fn(M) + Send + Sync + 'static,
    ) {
        // `flush_gossip` invokes this for Global, source-`None` deliveries
        // so a shard-less host folds committed beacon blocks.
        self.registry.register_host_gossip_handler(handler);
    }

    fn notify<M: NetworkMessage + 'static>(&self, recipients: &[ValidatorId], message: &M) {
        // Note: compression happens here at send-time, then accept_notifications()
        // decompresses before queueing for delivery. In production (Libp2pNetwork),
        // compression happens inside the stream framing layer (write_typed_frame) instead.
        let data = compression::compress(
            &hbor_to_vec(message).expect("SimNetworkAdapter: failed to encode notification"),
        );
        self.pending_notifications
            .lock()
            .unwrap()
            .push(PendingNotification {
                recipients: recipients.to_vec(),
                type_id: M::message_type_id(),
                class: M::class(),
                data,
            });
    }

    fn register_notification_handler<M: NetworkMessage + Clone + 'static>(
        &self,
        handler: impl NotificationHandler<M>,
    ) {
        self.registry.register_notification(handler);
    }

    fn subscribe_shard(&self, shard: ShardId) {
        // Delivery is harness-controlled, so participation is purely the
        // registry's hosted set.
        self.registry.add_hosted_shard(shard);
    }

    fn unsubscribe_shard(&self, shard: ShardId) {
        self.registry.remove_hosted_shard(shard);
        self.registry.unregister_requests_for_shard(shard);
    }

    fn register_request_handler<R: Request + Send + 'static>(
        &self,
        shard: ShardId,
        handler: impl RequestHandler<R>,
    ) where
        R::Response: Send + 'static,
    {
        // Registry owns wire decode/encode — just forward.
        self.registry.register_request(shard, handler);
    }

    fn request<R: Request + Clone + 'static>(
        &self,
        shard: ShardId,
        preferred_peer: Option<ValidatorId>,
        request: R,
        class_override: Option<MessageClass>,
        on_response: Box<dyn FnOnce(Result<R::Response, RequestError>) -> ResponseVerdict + Send>,
    ) {
        let request_bytes =
            hbor_to_vec(&request).expect("SimNetworkAdapter: failed to encode request");

        // Wrap the typed callback: decode raw response bytes → R::Response
        let typed_callback: Box<
            dyn FnOnce(Result<Vec<u8>, RequestError>) -> ResponseVerdict + Send,
        > = Box::new(move |result| match result {
            Ok(bytes) => match hbor_from_slice::<R::Response>(&bytes) {
                Ok(response) => on_response(Ok(response)),
                Err(e) => on_response(Err(RequestError::PeerError(format!("decode error: {e:?}")))),
            },
            Err(e) => on_response(Err(e)),
        });

        self.pending_requests.lock().unwrap().push(PendingRequest {
            shard,
            preferred_peer,
            type_id: R::message_type_id(),
            class: class_override.unwrap_or_else(R::class),
            response_class: <R::Response as NetworkMessage>::class(),
            request_bytes,
            on_response: typed_callback,
        });
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex as StdMutex;

    use hyperscale_types::network::gossip::TransactionGossip;
    use hyperscale_types::test_utils::{test_prefix, test_transaction_with_prefixes};
    use hyperscale_types::{BlockHeight, ShardId};

    use super::*;

    fn test_gossip() -> TransactionGossip {
        TransactionGossip::new(vec![Arc::new(test_transaction_with_prefixes(
            &[1, 2, 3],
            &[test_prefix(1)],
            &[test_prefix(2)],
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
        let decoded: GetBlockRequest = hbor_from_slice(&requests[0].request_bytes).unwrap();
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

        // Simulate a successful response with encoded bytes
        let response = GetBlockResponse::not_found();
        let response_bytes = hbor_to_vec(&response).unwrap();
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
