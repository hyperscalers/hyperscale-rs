//! Network message traits and class classification.
//!
//! These traits mark types as network messages for serialization and routing.
//!
//! # Class Levels
//!
//! Messages are classified by what stalls if delivery is delayed, into five
//! tiers from most to least urgent:
//!
//! 1. **Consensus** — BFT round-blocking messages whose loss can only be
//!    recovered by a view-change timeout (`BlockHeader`, `BlockVote`).
//!
//! 2. **`BlockCompletion`** — DA gap-closure for the *current* proposal. Delay
//!    extends the voting window but the round still completes
//!    (`GetTransactions`, `GetLocalProvisions`, `GetFinalizedWaves` on the
//!    pending-block path).
//!
//! 3. **`CrossShardProgress`** — Execution and finalization across shards.
//!    Delay stalls cross-shard execution but local consensus continues
//!    (`StateProvision`, `ExecutionVotes`, `ExecutionCertificates`,
//!    `CommittedBlockHeader` gossip).
//!
//! 4. **Recovery** — Catch-up traffic. Steady-state volume is zero
//!    (`GetBlock`, `GetSync`, `GetRemoteHeader`).
//!
//! 5. **Bulk** — High-volume best-effort with fetch fallback
//!    (`TransactionGossip`).

use sbor::prelude::{BasicDecode, BasicEncode, BasicSbor};

/// Network message class.
///
/// Lower numeric values = more urgent.
/// Messages within a class are processed FIFO.
///
/// Class determines:
/// - Processing order in the network adaptor event loop
/// - Network queue ordering for broadcasts
/// - Backpressure behavior under load
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BasicSbor)]
#[repr(u8)]
pub enum MessageClass {
    /// BFT round-blocking; loss only recovered by view-change timeout.
    ///
    /// Includes:
    /// - `BlockHeaderNotification` — proposer → committee
    /// - `BlockVoteNotification` — voter → next proposer
    ///
    /// Never dropped, processed immediately, must preempt all other traffic.
    Consensus = 0,

    /// DA gap-closure for the current proposal.
    ///
    /// Includes (on the hot pending-block path):
    /// - `GetTransactionsRequest/Response`
    /// - `GetLocalProvisionsRequest/Response`
    /// - `GetFinalizedWavesRequest/Response`
    ///
    /// Delay extends the voting window but the round still completes.
    BlockCompletion = 1,

    /// Execution and finalization coordination across shards.
    ///
    /// Includes:
    /// - `CommittedBlockHeader` gossip — proposer broadcast on commit
    /// - `StateProvisionNotification` — cross-shard state delivery
    /// - `ExecutionVotesNotification` — execution votes
    /// - `ExecutionCertificatesNotification` — execution certificates
    /// - `GetProvisionsRequest/Response` — cross-shard fallback
    /// - `GetExecutionCertRequest/Response` — EC fallback
    ///
    /// Delay stalls cross-shard progress but not local consensus.
    CrossShardProgress = 2,

    /// Catch-up traffic. Zero volume in steady state.
    ///
    /// Includes:
    /// - `GetBlockRequest/Response` — bulk block sync
    /// - `GetSyncRequest` — sync session bootstrap
    /// - `GetRemoteHeaderRequest/Response` — remote shard catch-up
    ///
    /// Sheddable; must always yield to higher classes.
    Recovery = 3,

    /// High-volume best-effort with fetch fallback.
    ///
    /// Includes:
    /// - `TransactionGossip` — mempool dissemination
    ///
    /// Largest class by volume; sheddable on the wire.
    Bulk = 4,
}

impl MessageClass {
    /// Whether this class can be dropped under backpressure.
    ///
    /// Only `Recovery` and `Bulk` are droppable. Higher classes must be
    /// delivered.
    #[inline]
    #[must_use]
    pub const fn is_droppable(&self) -> bool {
        matches!(self, Self::Recovery | Self::Bulk)
    }

    /// Stable string name used as a metric label.
    #[inline]
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Consensus => "consensus",
            Self::BlockCompletion => "block_completion",
            Self::CrossShardProgress => "cross_shard_progress",
            Self::Recovery => "recovery",
            Self::Bulk => "bulk",
        }
    }
}

/// Marker trait for network messages.
///
/// All messages sent over the network must implement this trait.
/// Each message type declares its class for network `QoS`.
pub trait NetworkMessage: Send + Sync + Sized + BasicEncode + BasicDecode {
    /// Unique message type identifier for routing.
    fn message_type_id() -> &'static str;

    /// The class for this message type.
    ///
    /// Used by the network adaptor for queue ordering and backpressure.
    /// Defaults to `Recovery` — override for higher-urgency messages.
    #[must_use]
    fn class() -> MessageClass {
        MessageClass::Recovery
    }

    /// Get the gossipsub topic for this message type.
    #[must_use]
    fn topic() -> String {
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
