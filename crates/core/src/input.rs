//! Event types for the deterministic state machine.

use crate::ProtocolEvent;
use hyperscale_types::{
    BlockHeight, Bls12381G1PublicKey, Bls12381G2Signature, CertifiedBlock, CommittedBlockHeader,
    ProvisionHash, RoutableTransaction, ShardGroupId, TxHash, ValidatorId, WaveId, WaveIdHash,
};
use std::sync::Arc;

/// Priority levels for event ordering within the same timestamp.
///
/// Events at the same simulation time are processed in priority order.
/// Lower values = higher priority (processed first).
///
/// This ensures causality is preserved: internal events (consequences of
/// processing an event) are handled before new external inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum EventPriority {
    /// Internal events: consequences of prior event processing.
    /// Processed first to maintain causality.
    Internal = 0,

    /// Timer events: scheduled by the node itself.
    Timer = 1,

    /// Network events: external inputs from other nodes.
    Network = 2,

    /// Client events: external inputs from users.
    Client = 3,
}

/// All possible inputs a node can receive.
///
/// `NodeInput` is the top-level input type for [`IoLoop`]. It contains:
/// - `Protocol(ProtocolEvent)`: pass-through events that `IoLoop` extracts and
///   passes to the state machine's `handle()` method directly.
/// - `NodeInput`-specific variants: events that `IoLoop` handles internally
///   (sync, fetch, validation pipeline) before potentially converting them
///   into `ProtocolEvent`s.
#[derive(Debug, Clone, strum::IntoStaticStr)]
pub enum NodeInput {
    /// Pass-through to state machine. `IoLoop` extracts the `ProtocolEvent` and
    /// passes it to `state.handle()` directly. Boxed because `ProtocolEvent`
    /// dwarfs every other variant and would inflate the event queue otherwise.
    Protocol(Box<ProtocolEvent>),

    /// Client submitted a transaction.
    SubmitTransaction {
        /// Transaction submitted by the local client; will be validated then gossiped.
        tx: Arc<RoutableTransaction>,
    },

    /// Raw gossip-delivered transaction. `IoLoop` queues it for async
    /// validation; the validated form is surfaced as
    /// `ProtocolEvent::TransactionValidated`.
    TransactionGossipReceived {
        /// The transaction.
        tx: Arc<RoutableTransaction>,
    },

    /// Sync block response received from network callback. Carries the
    /// elided wire shape; the `IoLoop` rehydrates to a full `CertifiedBlock`
    /// by looking up omitted bodies in the local mempool / cert cache /
    /// provision store before handing off to the sync state machine.
    BlockSyncResponseReceived {
        /// Height of the block being synced.
        height: BlockHeight,
        /// Elided block payload, or `None` if the peer couldn't serve this height.
        block: Option<Box<hyperscale_messages::response::ElidedCertifiedBlock>>,
    },

    /// Sync block fetch failed from network callback.
    BlockSyncFetchFailed {
        /// Height that failed to fetch.
        height: BlockHeight,
    },

    /// Sync block passed structural validation off-thread (Merkle roots,
    /// QC binding, per-wave shape). The pinned-thread `IoLoop` re-enters
    /// the post-validation delivery path on receipt.
    SyncBlockValidated {
        /// Height of the validated block.
        height: BlockHeight,
        /// Rehydrated, structurally-valid certified block ready for BFT.
        certified: Box<CertifiedBlock>,
    },

    /// Sync block failed structural validation off-thread. The pinned
    /// thread re-queues the height for retry.
    SyncBlockValidationFailed {
        /// Height that failed to validate.
        height: BlockHeight,
        /// Static reason tag — used for both metrics labels and warn logs.
        reason: &'static str,
    },

    /// Range response from a remote-header sync fetch. Headers are in
    /// ascending height order starting at `from_height`; missing tail
    /// heights (responder short-capped) get re-deferred by the FSM.
    RemoteHeadersResponseReceived {
        /// Source shard the fetch targeted.
        source_shard: hyperscale_types::ShardGroupId,
        /// First height of the requested range.
        from_height: BlockHeight,
        /// Number of heights the request covered.
        count: u64,
        /// Headers the responder returned.
        headers: Vec<hyperscale_types::CommittedBlockHeader>,
    },

    /// Remote-header range fetch failed (transport error / no peer).
    RemoteHeadersFetchFailed {
        /// Source shard the fetch targeted.
        source_shard: hyperscale_types::ShardGroupId,
        /// First height of the requested range.
        from_height: BlockHeight,
        /// Number of heights the request covered.
        count: u64,
    },

    /// Periodic tick for the fetch protocol to retry pending operations.
    FetchTick,

    /// A transaction fetch request failed (network error or peer returned None).
    TransactionsFetchFailed {
        /// Transaction hashes that failed to fetch.
        hashes: Vec<TxHash>,
    },

    /// Local provision fetch failed.
    LocalProvisionsFetchFailed {
        /// Provision hashes that failed to fetch.
        hashes: Vec<ProvisionHash>,
    },

    /// A finalized-wave fetch request failed.
    FinalizedWavesFetchFailed {
        /// Wave-id hashes that weren't returned.
        hashes: Vec<WaveIdHash>,
    },

    /// Transaction validated by the validation pipeline. The `IoLoop`
    /// resolves `submitted_locally` from its `locally_submitted` set
    /// before forwarding as `ProtocolEvent::TransactionValidated`.
    TransactionValidated {
        /// Validated transaction ready for the mempool.
        tx: Arc<RoutableTransaction>,
    },

    /// Transactions that failed validation — sent back so the `IoLoop` can
    /// remove their hashes from `pending_validation` and `locally_submitted`.
    TransactionValidationsFailed {
        /// Hashes of transactions that failed validation.
        hashes: Vec<TxHash>,
    },

    /// A committed block header gossip that has passed pre-filtering
    /// (sender committee check + public key resolution) but still needs
    /// batched BLS signature verification.
    CommittedBlockGossipReceived {
        /// Header carried in the gossip envelope. Boxed so the variant
        /// stays small — `CommittedBlockHeader` is the bulky field; the
        /// BLS pubkey/sig stay inline since boxing them adds an
        /// allocation per gossip without crossing a meaningful threshold.
        committed_header: Box<CommittedBlockHeader>,
        /// Sender validator id.
        sender: ValidatorId,
        /// Sender's public key, resolved from topology.
        public_key: Bls12381G1PublicKey,
        /// Sender's signature over the gossip payload, awaiting batch verify.
        sender_signature: Bls12381G2Signature,
    },

    /// A provision fetch request failed (network error or peer returned None).
    ProvisionsFetchFailed {
        /// Source shard whose provisions were being fetched.
        source_shard: ShardGroupId,
        /// Source-shard block height the provisions were anchored to.
        block_height: BlockHeight,
    },

    /// An execution certificate fetch request failed.
    ExecCertFetchFailed {
        /// Wave ids that weren't returned.
        hashes: Vec<WaveId>,
    },
}

impl NodeInput {
    /// Get the priority for this input type.
    ///
    /// Events at the same timestamp are processed in priority order,
    /// ensuring causality is preserved.
    #[must_use]
    #[allow(clippy::match_same_arms)] // explicit per-variant arms document intent
    pub fn priority(&self) -> EventPriority {
        match self {
            // Priority is a scheduling concern, not a protocol concern.
            // Timers and network-received messages are classified explicitly;
            // everything else (callbacks, continuations, completions) defaults to Internal.
            Self::Protocol(pe) => match pe.as_ref() {
                ProtocolEvent::ViewChangeTimer | ProtocolEvent::CleanupTimer => {
                    EventPriority::Timer
                }

                ProtocolEvent::BlockHeaderReceived { .. }
                | ProtocolEvent::RemoteHeaderReceived { .. }
                | ProtocolEvent::BlockVoteReceived { .. }
                | ProtocolEvent::ProvisionsReceived { .. }
                | ProtocolEvent::ExecutionCertificatesReceived { .. }
                | ProtocolEvent::FinalizedWavesReceived { .. }
                | ProtocolEvent::TransactionsReceived { .. } => EventPriority::Network,

                // Fetch delivery events are processed callbacks from the fetch
                // protocol, not raw network messages. They fall through to
                // Internal.
                _ => EventPriority::Internal,
            },
            Self::SubmitTransaction { .. } => EventPriority::Client,
            Self::TransactionGossipReceived { .. } => EventPriority::Network,
            Self::BlockSyncResponseReceived { .. } => EventPriority::Internal,
            Self::BlockSyncFetchFailed { .. } => EventPriority::Internal,
            Self::SyncBlockValidated { .. } => EventPriority::Internal,
            Self::SyncBlockValidationFailed { .. } => EventPriority::Internal,
            Self::RemoteHeadersResponseReceived { .. } => EventPriority::Internal,
            Self::RemoteHeadersFetchFailed { .. } => EventPriority::Internal,
            Self::FetchTick => EventPriority::Timer,
            Self::TransactionsFetchFailed { .. } => EventPriority::Internal,
            Self::TransactionValidated { .. } => EventPriority::Internal,
            Self::TransactionValidationsFailed { .. } => EventPriority::Internal,
            Self::CommittedBlockGossipReceived { .. } => EventPriority::Network,
            Self::ProvisionsFetchFailed { .. } => EventPriority::Internal,
            Self::ExecCertFetchFailed { .. } => EventPriority::Internal,
            Self::LocalProvisionsFetchFailed { .. } => EventPriority::Internal,
            Self::FinalizedWavesFetchFailed { .. } => EventPriority::Internal,
        }
    }

    /// Check if this is an internal event (consequence of prior processing).
    #[must_use]
    pub fn is_internal(&self) -> bool {
        self.priority() == EventPriority::Internal
    }

    /// Check if this is a network event (from another node).
    #[must_use]
    pub fn is_network(&self) -> bool {
        self.priority() == EventPriority::Network
    }

    /// Check if this is a client event (from a user).
    #[must_use]
    pub fn is_client(&self) -> bool {
        self.priority() == EventPriority::Client
    }

    /// Get the event type name for telemetry.
    ///
    /// Variant names come from the `IntoStaticStr` derive; `Protocol` delegates
    /// to the inner `ProtocolEvent::type_name` so protocol telemetry is
    /// attributable per inner variant.
    #[must_use]
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Protocol(pe) => pe.type_name(),
            other => other.into(),
        }
    }
}

impl From<ProtocolEvent> for NodeInput {
    fn from(event: ProtocolEvent) -> Self {
        Self::Protocol(Box::new(event))
    }
}
