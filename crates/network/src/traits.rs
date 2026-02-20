//! Network trait for typed message passing.
//!
//! Defines the `Network` interface implemented by both production (`network-libp2p`)
//! and simulation (`network-memory`) backends.

use hyperscale_types::{
    Block, BlockHeight, Hash, NetworkMessage, QuorumCertificate, Request, RoutableTransaction,
    ShardGroupId, ShardMessage, TransactionCertificate, ValidatorId,
};
use std::sync::Arc;

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

/// Callback for block fetch responses.
pub type BlockResponseCallback =
    Box<dyn FnOnce(Result<Option<(Block, QuorumCertificate)>, RequestError>) + Send>;

/// Callback for transaction fetch responses.
pub type TransactionsResponseCallback =
    Box<dyn FnOnce(Result<Vec<Arc<RoutableTransaction>>, RequestError>) + Send>;

/// Callback for certificate fetch responses.
pub type CertificatesResponseCallback =
    Box<dyn FnOnce(Result<Vec<TransactionCertificate>, RequestError>) + Send>;

/// Network interface for sending typed messages and registering listeners.
///
/// Generic methods make this NOT object-safe — use `N: Network` bounds.
/// This is consistent with how storage and dispatch are already used:
/// `ActionContext<S: CommitStore + SubstateStore, D: Dispatch>`.
///
/// All sends are fire-and-forget. Responses to requests arrive via callback.
/// Listeners are called from the network's decode/delivery thread — handlers
/// should be lightweight (push into a channel, not do heavy processing).
pub trait Network: Send + Sync {
    // ── Pub/sub messaging ──

    /// Broadcast a shard-scoped message to all peers subscribed to that shard's topic.
    fn broadcast_to_shard<M: ShardMessage>(&self, shard: ShardGroupId, message: &M);

    /// Broadcast a message to all connected peers globally.
    fn broadcast_global<M: NetworkMessage>(&self, message: &M);

    /// Send a message to a specific validator (point-to-point, not gossip).
    fn send_to<M: NetworkMessage>(&self, peer: ValidatorId, message: &M);

    /// Subscribe to a shard's message topics.
    ///
    /// After subscribing, messages broadcast to this shard by other peers
    /// will be delivered to registered listeners.
    fn subscribe_shard(&self, shard: ShardGroupId);

    /// Register a typed listener for a message type.
    ///
    /// When a message of type M arrives (from gossip or point-to-point),
    /// the handler is called with the sender's identity and the decoded message.
    ///
    /// Implementations store handlers type-erased (keyed by `M::message_type_id()`).
    /// The handler is called on the network's decode thread — keep it lightweight
    /// (typically: push into a crossbeam channel).
    fn on_message<M: NetworkMessage + 'static>(
        &self,
        handler: Box<dyn Fn(ValidatorId, M) + Send + Sync>,
    );

    // ── Request-response ──

    /// Send a typed request to a specific peer and receive the response via callback.
    ///
    /// The callback is called on a network thread when the response arrives,
    /// or with an error on timeout/failure. Compatible with sync main loops —
    /// the callback typically pushes into the main loop's event channel.
    ///
    /// Retry logic and peer selection live outside this trait (in the
    /// sync/fetch protocol state machines and their runner wrappers).
    fn request<R: Request + 'static>(
        &self,
        peer: ValidatorId,
        request: &R,
        on_response: Box<dyn FnOnce(Result<R::Response, RequestError>) + Send>,
    );

    // ── High-level request methods ──
    //
    // These provide typed, peer-selecting request APIs that NodeLoop calls
    // directly. Implementations handle peer selection and async dispatch.
    // In production, these spawn tokio tasks via a RequestManager.
    // In simulation, these buffer requests for the harness to fulfill.

    /// Fetch a block by height. Implementation handles peer selection and retry.
    fn request_block(&self, height: BlockHeight, on_response: BlockResponseCallback);

    /// Fetch transactions by hash. Implementation prefers proposer, handles retry.
    fn request_transactions(
        &self,
        proposer: ValidatorId,
        block_hash: Hash,
        hashes: Vec<Hash>,
        on_response: TransactionsResponseCallback,
    );

    /// Fetch certificates by hash. Implementation prefers proposer, handles retry.
    fn request_certificates(
        &self,
        proposer: ValidatorId,
        block_hash: Hash,
        hashes: Vec<Hash>,
        on_response: CertificatesResponseCallback,
    );
}
