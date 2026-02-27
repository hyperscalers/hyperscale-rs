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
