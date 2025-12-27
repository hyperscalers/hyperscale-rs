//! Network message traits and priority classification.
//!
//! These traits mark types as network messages for serialization and routing.
//!
//! # Priority Levels
//!
//! Messages are classified into five priority tiers, from highest to lowest:
//!
//! 1. **Critical** - BFT consensus messages (BlockHeader, BlockVote) and
//!    requests that unblock pending blocks. Never dropped.
//!
//! 2. **Coordination** - Cross-shard 2PC messages (StateProvision, StateVote,
//!    StateCertificate). High priority, may be batched for efficiency.
//!
//! 3. **Finalization** - Transaction certificate gossip. Important for progress
//!    but not liveness-critical.
//!
//! 4. **Propagation** - Transaction gossip for mempool dissemination.
//!    Best-effort, can be shed under load.
//!
//! 5. **Background** - Sync operations like block fetching. Fully deferrable.

use sbor::prelude::{BasicDecode, BasicEncode, BasicSbor};

/// Network message priority levels.
///
/// Lower numeric values = higher priority.
/// Messages at the same priority level are processed FIFO.
///
/// Priority determines:
/// - Processing order in the network adaptor event loop
/// - Network queue ordering for broadcasts
/// - Backpressure behavior under load
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BasicSbor)]
#[repr(u8)]
pub enum MessagePriority {
    /// Liveness-critical consensus messages.
    ///
    /// Includes:
    /// - `BlockHeaderGossip` - block proposals
    /// - `BlockVoteGossip` - votes on proposals
    /// - `GetTransactionsRequest/Response` - unblock pending blocks
    /// - `GetCertificatesRequest/Response` - unblock pending blocks
    ///
    /// Never dropped, processed immediately.
    Critical = 0,

    /// Cross-shard coordination messages.
    ///
    /// Includes:
    /// - `StateProvisionBatch` - cross-shard state delivery
    /// - `StateVoteBatch` - execution result votes
    /// - `StateCertificateBatch` - 2PC completion certificates
    ///
    /// High priority but may be batched for efficiency.
    Coordination = 1,

    /// Finalization messages.
    ///
    /// Includes:
    /// - `TransactionCertificateGossip` - certificates for committed txs
    ///
    /// Important for progress but not liveness-critical.
    Finalization = 2,

    /// Mempool propagation.
    ///
    /// Includes:
    /// - `TransactionGossip` - new transaction dissemination
    ///
    /// Best-effort, can be shed under load.
    Propagation = 3,

    /// Background/sync operations.
    ///
    /// Includes:
    /// - `GetBlockRequest/Response` - block sync catch-up
    ///
    /// Lowest priority, fully deferrable.
    Background = 4,
}

impl MessagePriority {
    /// Whether this priority level can be dropped under backpressure.
    ///
    /// Only `Propagation` and `Background` messages are droppable.
    /// Higher priority messages must be delivered.
    #[inline]
    pub fn is_droppable(&self) -> bool {
        matches!(
            self,
            MessagePriority::Propagation | MessagePriority::Background
        )
    }
}

/// Marker trait for network messages.
///
/// All messages sent over the network must implement this trait.
/// Each message type declares its priority for network QoS.
pub trait NetworkMessage: Send + Sync + Sized + BasicEncode + BasicDecode {
    /// Unique message type identifier for routing.
    fn message_type_id() -> &'static str
    where
        Self: Sized;

    /// The priority level for this message type.
    ///
    /// Used by the network adaptor for queue ordering and backpressure.
    /// Defaults to `Background` - override for higher priority messages.
    fn priority() -> MessagePriority
    where
        Self: Sized,
    {
        MessagePriority::Background
    }

    /// Get the gossipsub topic for this message type.
    fn topic() -> String
    where
        Self: Sized,
    {
        format!("hyperscale/{}/1.0.0", Self::message_type_id())
    }
}

/// Marker trait for messages that are shard-specific.
pub trait ShardMessage: NetworkMessage {}

/// Marker trait for request messages that expect a response.
pub trait Request: NetworkMessage {
    /// The response type for this request.
    type Response: NetworkMessage;
}
