//! Network trait implementation for deterministic simulation.
//!
//! [`SimNetworkAdapter`] buffers outgoing messages in an outbox. After each
//! `NodeLoop::step()`, the simulation harness drains the outbox and routes
//! entries through [`SimulatedNetwork::deliver_gossip`](crate::SimulatedNetwork::deliver_gossip),
//! which applies partition/latency/loss, LZ4-decompresses the payload once,
//! and returns a [`GossipDelivery`](crate::GossipDelivery) per target peer.
//!
//! Messages are wire-encoded (SBOR + LZ4) in the outbox, matching the production
//! encoding path. The harness schedules the resulting `NodeInput::GossipReceived`
//! events directly with the sampled latency.

use hyperscale_network::{encode_to_wire, InboundRequestHandler, Network, RequestError};
use hyperscale_types::{NetworkMessage, Request, ShardGroupId, ShardMessage, ValidatorId};
use std::sync::{Arc, Mutex, OnceLock};

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

/// A buffered request from NodeLoop, awaiting harness fulfillment.
///
/// The simulation harness drains these after each step, dispatches on
/// `type_id` to decode the request, looks up data from peer nodes,
/// SBOR-encodes the response, and calls `on_response` with raw bytes.
/// The generic `request<R>()` wrapper decodes `R::Response` before calling
/// the user's typed callback.
pub struct PendingRequest {
    /// Optional preferred peer (e.g., block proposer for fetch).
    pub preferred_peer: Option<ValidatorId>,
    /// Message type ID for dispatch (e.g., "block.request").
    pub type_id: &'static str,
    /// SBOR-encoded request bytes.
    pub request_bytes: Vec<u8>,
    /// Callback that receives SBOR-encoded response bytes (or error).
    pub on_response: Box<dyn FnOnce(Result<Vec<u8>, RequestError>) + Send>,
}

/// Shared slot for an inbound request handler.
///
/// Created by [`SimulatedNetwork::create_adapter`] and shared between the
/// per-node [`SimNetworkAdapter`] and the central [`SimulatedNetwork`].
/// [`Network::register_inbound_handler`] sets the slot; request fulfillment reads it.
pub type HandlerSlot = Arc<OnceLock<Arc<dyn InboundRequestHandler>>>;

/// Network implementation for simulation.
///
/// Buffers outgoing messages in an outbox rather than delivering them immediately.
/// The simulation harness drains the outbox after each `NodeLoop::step()` and
/// controls delivery timing, partitions, and packet loss.
///
/// # Usage
///
/// Each simulated node owns a `SimNetworkAdapter`. The harness:
/// 1. Calls `NodeLoop::step(event)` which may produce network sends
/// 2. Drains the adapter's outbox via [`drain_outbox()`](Self::drain_outbox)
/// 3. Routes entries through `SimulatedNetwork::deliver_gossip()`
/// 4. Events are scheduled with the sampled latency offset
pub struct SimNetworkAdapter {
    outbox: Mutex<Vec<OutboxEntry>>,
    pending_requests: Mutex<Vec<PendingRequest>>,
    /// Shared handler slot — written by [`Network::register_inbound_handler`],
    /// read by [`SimulatedNetwork::fulfill_requests`].
    handler_slot: HandlerSlot,
}

impl SimNetworkAdapter {
    /// Create a new adapter with a pre-allocated handler slot.
    ///
    /// Use [`SimulatedNetwork::create_adapter`] to create adapters with
    /// shared handler slots for request fulfillment.
    pub fn new(handler_slot: HandlerSlot) -> Self {
        Self {
            outbox: Mutex::new(Vec::new()),
            pending_requests: Mutex::new(Vec::new()),
            handler_slot,
        }
    }

    /// Drain all buffered outgoing messages.
    ///
    /// Returns the entries accumulated since the last drain. The harness calls
    /// this after each `NodeLoop::step()` to process outbound messages.
    pub fn drain_outbox(&self) -> Vec<OutboxEntry> {
        std::mem::take(&mut self.outbox.lock().unwrap())
    }

    /// Drain all buffered requests.
    ///
    /// The harness calls this after each `NodeLoop::step()` to fulfill
    /// requests by looking up data from peer nodes and calling the callbacks.
    pub fn drain_pending_requests(&self) -> Vec<PendingRequest> {
        std::mem::take(&mut self.pending_requests.lock().unwrap())
    }
}

impl Default for SimNetworkAdapter {
    fn default() -> Self {
        Self::new(Arc::new(OnceLock::new()))
    }
}

impl Network for SimNetworkAdapter {
    fn broadcast_to_shard<M: ShardMessage>(&self, shard: ShardGroupId, message: &M) {
        let data = encode_to_wire(message).expect("SimNetworkAdapter: failed to encode message");
        self.outbox.lock().unwrap().push(OutboxEntry {
            target: BroadcastTarget::Shard(shard),
            message_type: M::message_type_id(),
            data,
        });
    }

    fn broadcast_global<M: NetworkMessage>(&self, message: &M) {
        let data = encode_to_wire(message).expect("SimNetworkAdapter: failed to encode message");
        self.outbox.lock().unwrap().push(OutboxEntry {
            target: BroadcastTarget::Global,
            message_type: M::message_type_id(),
            data,
        });
    }

    fn register_inbound_handler(&self, handler: Arc<dyn InboundRequestHandler>) {
        let _ = self.handler_slot.set(handler);
    }

    fn request<R: Request + 'static>(
        &self,
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
                        on_response(Err(RequestError::PeerError(format!("decode error: {e:?}"))))
                    }
                },
                Err(e) => on_response(Err(e)),
            });

        self.pending_requests.lock().unwrap().push(PendingRequest {
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
    use hyperscale_messages::BlockVoteGossip;
    use hyperscale_types::{zero_bls_signature, BlockHeight, BlockVote, Hash};
    use std::sync::Mutex as StdMutex;

    fn test_vote_gossip() -> BlockVoteGossip {
        BlockVoteGossip::new(BlockVote {
            block_hash: Hash::from_bytes(b"test"),
            height: BlockHeight(1),
            round: 0,
            voter: ValidatorId(0),
            signature: zero_bls_signature(),
            timestamp: 1_000_000_000_000,
        })
    }

    #[test]
    fn test_broadcast_to_shard_creates_outbox_entry() {
        let adapter = SimNetworkAdapter::default();
        let gossip = test_vote_gossip();
        let shard = ShardGroupId(3);

        adapter.broadcast_to_shard(shard, &gossip);

        let entries = adapter.drain_outbox();
        assert_eq!(entries.len(), 1);
        assert!(matches!(entries[0].target, BroadcastTarget::Shard(s) if s == shard));
        assert_eq!(entries[0].message_type, "block.vote");
        assert!(!entries[0].data.is_empty());
    }

    #[test]
    fn test_broadcast_global_creates_outbox_entry() {
        let adapter = SimNetworkAdapter::default();
        let gossip = test_vote_gossip();

        adapter.broadcast_global(&gossip);

        let entries = adapter.drain_outbox();
        assert_eq!(entries.len(), 1);
        assert!(matches!(entries[0].target, BroadcastTarget::Global));
        assert_eq!(entries[0].message_type, "block.vote");
        assert!(!entries[0].data.is_empty());
    }

    #[test]
    fn test_drain_outbox_returns_and_clears() {
        let adapter = SimNetworkAdapter::default();
        let gossip = test_vote_gossip();

        adapter.broadcast_global(&gossip);
        adapter.broadcast_global(&gossip);
        adapter.broadcast_global(&gossip);

        let first_drain = adapter.drain_outbox();
        assert_eq!(first_drain.len(), 3);

        let second_drain = adapter.drain_outbox();
        assert_eq!(second_drain.len(), 0);
    }

    #[test]
    fn test_register_inbound_handler_sets_slot() {
        let handler_slot: HandlerSlot = Arc::new(OnceLock::new());
        let adapter = SimNetworkAdapter::new(handler_slot.clone());

        struct EchoHandler;
        impl InboundRequestHandler for EchoHandler {
            fn handle_request(&self, payload: &[u8]) -> Vec<u8> {
                payload.to_vec()
            }
        }

        assert!(handler_slot.get().is_none());
        adapter.register_inbound_handler(Arc::new(EchoHandler));
        assert!(handler_slot.get().is_some());
    }

    #[test]
    fn test_register_inbound_handler_idempotent() {
        let adapter = SimNetworkAdapter::default();

        struct Handler1;
        impl InboundRequestHandler for Handler1 {
            fn handle_request(&self, _: &[u8]) -> Vec<u8> {
                vec![1]
            }
        }

        struct Handler2;
        impl InboundRequestHandler for Handler2 {
            fn handle_request(&self, _: &[u8]) -> Vec<u8> {
                vec![2]
            }
        }

        adapter.register_inbound_handler(Arc::new(Handler1));
        adapter.register_inbound_handler(Arc::new(Handler2)); // should be ignored

        // First handler should have won
        let result = adapter.handler_slot.get().unwrap().handle_request(&[]);
        assert_eq!(result, vec![1]);
    }

    #[test]
    fn test_request_creates_pending_request() {
        use hyperscale_messages::request::GetBlockRequest;

        let adapter = SimNetworkAdapter::default();
        let preferred = Some(ValidatorId(7));

        adapter.request(
            preferred,
            GetBlockRequest::new(BlockHeight(42)),
            Box::new(|_| {}),
        );

        let requests = adapter.drain_pending_requests();
        assert_eq!(requests.len(), 1);
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
            None,
            GetBlockRequest::new(BlockHeight(1)),
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
            None,
            GetBlockRequest::new(BlockHeight(1)),
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
