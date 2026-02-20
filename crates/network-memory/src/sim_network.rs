//! Network trait implementation for deterministic simulation.
//!
//! [`SimNetworkAdapter`] buffers outgoing messages in an outbox. After each
//! `NodeLoop::step()`, the simulation harness drains the outbox and applies
//! partition/latency/loss from [`SimulatedNetwork`](crate::SimulatedNetwork)
//! before scheduling delivery to target nodes.
//!
//! Messages are wire-encoded (SBOR + LZ4) in the outbox, matching the production
//! path and catching serialization bugs. The harness decodes them back to events
//! using [`hyperscale_node::gossip_dispatch::decode_gossip_to_events`].

use hyperscale_network::{encode_to_wire, Network, RequestError};
use hyperscale_types::{NetworkMessage, Request, ShardGroupId, ShardMessage, ValidatorId};
use std::sync::Mutex;

/// Target for an outbound message.
#[derive(Debug, Clone)]
pub enum BroadcastTarget {
    /// Broadcast to all peers in a specific shard.
    Shard(ShardGroupId),
    /// Broadcast to all connected peers globally.
    Global,
    /// Send to a specific peer.
    Peer(ValidatorId),
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
/// 3. For each entry, determines target peers from shard topology
/// 4. Applies partition/loss/latency from `SimulatedNetwork`
/// 5. Decodes the entry via `decode_gossip_to_events` to get events
/// 6. Schedules those events for delivery to target nodes
pub struct SimNetworkAdapter {
    outbox: Mutex<Vec<OutboxEntry>>,
    pending_requests: Mutex<Vec<PendingRequest>>,
}

impl SimNetworkAdapter {
    pub fn new() -> Self {
        Self {
            outbox: Mutex::new(Vec::new()),
            pending_requests: Mutex::new(Vec::new()),
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
        Self::new()
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

    fn send_to<M: NetworkMessage>(&self, peer: ValidatorId, message: &M) {
        let data = encode_to_wire(message).expect("SimNetworkAdapter: failed to encode message");
        self.outbox.lock().unwrap().push(OutboxEntry {
            target: BroadcastTarget::Peer(peer),
            message_type: M::message_type_id(),
            data,
        });
    }

    fn subscribe_shard(&self, _shard: ShardGroupId) {
        // No-op in simulation. The harness controls delivery based on
        // shard topology, not subscriptions.
    }

    fn on_message<M: NetworkMessage + 'static>(
        &self,
        _handler: Box<dyn Fn(ValidatorId, M) + Send + Sync>,
    ) {
        // No-op in simulation. Events are delivered directly via
        // NodeLoop::step(event), not through handler dispatch.
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
