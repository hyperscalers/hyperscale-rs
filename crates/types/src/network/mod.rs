//! Network message traits and concrete wire types.
//!
//! [`MessageClass`], [`NetworkMessage`], [`Request`], and [`ShardMessage`]
//! mark types as network messages for serialization, routing, and `QoS`
//! ordering. Concrete messages live in submodules grouped by transport
//! semantics:
//!
//! - [`gossip`]: best-effort one-to-many fanout via gossipsub.
//! - [`notification`]: targeted one-way pushes that don't expect a reply.
//! - [`request`] / [`response`]: paired request-reply messages used by the
//!   per-payload fetch protocols.
//!
//! All messages are encoded with SBOR (not serde). Per-message wrappers
//! exist mostly to register typed handlers via the network registry; the
//! files in each subdirectory are thin SBOR wire-types — see the
//! containing struct for field semantics.
//!
//! # Class Levels
//!
//! Messages are classified by what stalls if delivery is delayed, into five
//! tiers from most to least urgent:
//!
//! 1. **Consensus** — shard round-blocking messages whose loss can only be
//!    recovered by a view-change timeout (`BlockHeader`, `BlockVote`).
//!
//! 2. **`BlockCompletion`** — DA gap-closure for the *current* proposal. Delay
//!    extends the voting window but the round still completes
//!    (`GetTransactions`, `GetLocalProvisions`, `GetFinalizedWaves` on the
//!    pending-block path).
//!
//! 3. **`CrossShardProgress`** — Execution and finalization across shards.
//!    Delay stalls cross-shard execution but local consensus continues
//!    (`Provisions`, `ExecutionVotes`, `ExecutionCertificates`,
//!    `CommittedBlockHeader` gossip).
//!
//! 4. **Recovery** — Catch-up traffic. Steady-state volume is zero
//!    (`GetBlock`, `GetSync`, `GetRemoteHeader`).
//!
//! 5. **Bulk** — High-volume best-effort with fetch fallback
//!    (`TransactionGossip`).

use sbor::prelude::{BasicDecode, BasicEncode, BasicSbor};

use crate::ShardGroupId;

pub mod gossip;
pub mod notification;
pub mod request;
pub mod response;
mod signed;

pub use signed::{Signed, SignedContext, SignedVerifyError};

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
    /// shard round-blocking; loss only recovered by view-change timeout.
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
    /// - `ProvisionsNotification` — cross-shard state delivery
    /// - `ExecutionVotesNotification` — execution votes
    /// - `ExecutionCertificatesNotification` — execution certificates
    /// - `GetProvisionsRequest/Response` — cross-shard fallback
    /// - `GetExecutionCertsRequest/Response` — EC fallback
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

/// Topic scope for a gossip message type.
///
/// Determines topic subscription in production:
/// - `Shard` → `hyperscale/{type_id}/shard-{shard}/1.0.0` (one per hosted shard)
/// - `Global` → `hyperscale/{type_id}/1.0.0` (single topic)
///
/// Ignored in simulation (delivery is controlled by the harness).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TopicScope {
    /// Shard-local topic. Only peers subscribed to the local shard receive it.
    Shard,
    /// Global topic. All connected peers receive it.
    Global,
}

/// Marker trait for gossip messages — messages broadcast via topics
/// (`broadcast_to_shard` / `broadcast_global`) rather than unicast.
///
/// Encodes the routing semantics on the type so the network layer can
/// fan out to the right per-vnode handlers without each handler closure
/// having to re-implement that logic.
///
/// Two key signals:
///
/// - [`SCOPE`](Self::SCOPE) — `Shard` or `Global`. Drives topic
///   subscription and which broadcast method may carry this type.
/// - [`source_shard`](Self::source_shard) — for global messages tied to a
///   specific shard's history (e.g. a committed-header gossip), the
///   originating shard. Cross-shard hosting filters this shard out when
///   fanning the message into hosted shards' state machines — a vnode in
///   the originating shard sees its own commits directly, not through
///   the gossip path.
///
/// Single-publisher messages (one validator originates each logical
/// message; gossipsub disseminates) need only `SCOPE`. Multi-publisher
/// messages (every committee member emits an equivalent copy with its
/// own sender field) additionally implement
/// [`dedup_key`](Self::dedup_key) so the framework can short-circuit
/// the second-and-later arrivals at the receive boundary.
pub trait GossipMessage: NetworkMessage + Clone {
    /// Whether this message lives on a per-shard topic or a single
    /// global topic. See [`TopicScope`].
    const SCOPE: TopicScope;

    /// For [`TopicScope::Global`] messages, the shard the message
    /// originates from. The framework filters this shard out when
    /// fanning into hosted shards.
    ///
    /// Returns `None` for messages with no inherent source shard, or
    /// for [`TopicScope::Shard`] messages where the topic already pins
    /// the shard.
    #[must_use]
    fn source_shard(&self) -> Option<ShardGroupId> {
        let _ = self;
        None
    }

    /// Content-key for dedup of equivalent copies emitted by multiple
    /// publishers. Two messages with the same logical content (e.g. the
    /// same committed header, different sender signatures) must return
    /// equal keys; the framework's receive-side cache then short-
    /// circuits the second-and-later arrivals.
    ///
    /// `None` (default) disables dedup. Appropriate for single-publisher
    /// types: gossipsub's bytes-id dedup already covers mesh-redundant
    /// re-delivery of one publisher's copy.
    #[must_use]
    fn dedup_key(&self) -> Option<u64> {
        let _ = self;
        None
    }
}

/// Marker trait for request messages that expect a response.
pub trait Request: NetworkMessage {
    /// The response type for this request.
    type Response: NetworkMessage;

    /// Whether `response` indicates the responder had nothing matching
    /// the request — e.g. a fetch hit a store that hasn't admitted the
    /// requested key yet.
    ///
    /// Used by the network's local-serve short-circuit (a host that
    /// carries a vnode in the target shard answers without going to the
    /// wire). Returning `true` tells the caller to fall through to the
    /// remote committee instead of treating the empty local answer as
    /// terminal — without this, a cross-shard packed host that misses
    /// in its co-located shard's store never asks any other peer.
    ///
    /// Default: `false` (every response is meaningful). Fetch-style
    /// requests (`Get*Request`) where the responder may legitimately
    /// not hold the data should override.
    #[must_use]
    fn is_empty_response(_response: &Self::Response) -> bool {
        false
    }
}
