//! Network trait implementation for deterministic simulation.
//!
//! [`SimNetworkAdapter`] buffers outgoing messages in an outbox. After each
//! `NodeLoop::step()`, the simulation harness drains the outbox and applies
//! partition/latency/loss from [`SimulatedNetwork`](crate::SimulatedNetwork)
//! before scheduling delivery to target nodes.
//!
//! Messages are wire-encoded (SBOR + LZ4) in the outbox, matching the production
//! path and catching serialization bugs. The harness decodes them back to events
//! using [`hyperscale_network::decode_message`].

use hyperscale_network::{
    encode_to_wire, BlockResponseCallback, CertificatesResponseCallback, Network, RequestError,
    TransactionsResponseCallback,
};
use hyperscale_types::{
    BlockHeight, Hash, NetworkMessage, Request, ShardGroupId, ShardMessage, ValidatorId,
};
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

/// A buffered high-level request from NodeLoop, awaiting harness fulfillment.
///
/// The simulation harness drains these after each step, looks up the data from
/// peer nodes, and calls the `on_response` callback to deliver the result.
pub enum PendingRequest {
    /// Fetch a block by height.
    Block {
        height: BlockHeight,
        on_response: BlockResponseCallback,
    },
    /// Fetch transactions by hash.
    Transactions {
        proposer: ValidatorId,
        block_hash: Hash,
        hashes: Vec<Hash>,
        on_response: TransactionsResponseCallback,
    },
    /// Fetch certificates by hash.
    Certificates {
        proposer: ValidatorId,
        block_hash: Hash,
        hashes: Vec<Hash>,
        on_response: CertificatesResponseCallback,
    },
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
/// 5. Decodes the entry via [`hyperscale_network::decode_message`] to get events
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

    /// Drain all buffered high-level requests (block, tx, cert fetches).
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
        _peer: ValidatorId,
        _request: &R,
        _on_response: Box<dyn FnOnce(Result<R::Response, RequestError>) + Send>,
    ) {
        // Low-level request/response is not used in simulation.
        // Use request_block/request_transactions/request_certificates instead.
        unimplemented!("SimNetworkAdapter::request() is not used; use typed request methods")
    }

    fn request_block(&self, height: BlockHeight, on_response: BlockResponseCallback) {
        self.pending_requests
            .lock()
            .unwrap()
            .push(PendingRequest::Block {
                height,
                on_response,
            });
    }

    fn request_transactions(
        &self,
        proposer: ValidatorId,
        block_hash: Hash,
        hashes: Vec<Hash>,
        on_response: TransactionsResponseCallback,
    ) {
        self.pending_requests
            .lock()
            .unwrap()
            .push(PendingRequest::Transactions {
                proposer,
                block_hash,
                hashes,
                on_response,
            });
    }

    fn request_certificates(
        &self,
        proposer: ValidatorId,
        block_hash: Hash,
        hashes: Vec<Hash>,
        on_response: CertificatesResponseCallback,
    ) {
        self.pending_requests
            .lock()
            .unwrap()
            .push(PendingRequest::Certificates {
                proposer,
                block_hash,
                hashes,
                on_response,
            });
    }
}
