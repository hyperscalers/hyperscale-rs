//! Event types for the deterministic state machine.

use crate::ProtocolEvent;
use hyperscale_types::{
    BlockHash, BlockHeight, Bls12381G1PublicKey, Bls12381G2Signature, CommittedBlockHeader,
    ExecutionCertificate, FinalizedWave, ProvisionHash, Provisions, RoutableTransaction,
    ShardGroupId, TxHash, ValidatorId, WaveIdHash,
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
#[allow(clippy::large_enum_variant)] // TODO: Box ProtocolEvent
#[derive(Debug, Clone)]
pub enum NodeInput {
    /// Pass-through to state machine. `IoLoop` extracts the `ProtocolEvent` and
    /// passes it to `state.handle()` directly.
    Protocol(ProtocolEvent),

    /// Client submitted a transaction.
    SubmitTransaction {
        /// Transaction submitted by the local client; will be validated then gossiped.
        tx: Arc<RoutableTransaction>,
    },

    /// Sync block response received from network callback. Carries the
    /// elided wire shape; the `IoLoop` rehydrates to a full `CertifiedBlock`
    /// by looking up omitted bodies in the local mempool / cert cache /
    /// provision store before handing off to the sync state machine.
    SyncBlockResponseReceived {
        /// Height of the block being synced.
        height: BlockHeight,
        /// Elided block payload, or `None` if the peer couldn't serve this height.
        block: Option<Box<hyperscale_messages::response::ElidedCertifiedBlock>>,
    },

    /// Sync block fetch failed from network callback.
    SyncBlockFetchFailed {
        /// Height that failed to fetch.
        height: BlockHeight,
    },

    /// Top-up response received from network callback after a rehydration
    /// miss. `response = None` signals the peer couldn't serve any of the
    /// requested bodies (empty-response short-circuit on the wire).
    SyncBlockTopUpReceived {
        /// Height the top-up belongs to.
        height: BlockHeight,
        /// Body bodies the peer returned, or `None` for empty-response short-circuit.
        response: Option<Box<hyperscale_messages::response::GetBlockTopUpResponse>>,
    },

    /// Top-up request failed (timeout / transport error). The `IoLoop`
    /// drops the buffered elided block and refetches the whole thing.
    SyncBlockTopUpFailed {
        /// Height whose top-up request failed.
        height: BlockHeight,
    },

    /// Periodic tick for the fetch protocol to retry pending operations.
    FetchTick,

    /// Fetch transactions failed from network callback.
    FetchTransactionsFailed {
        /// Block whose transactions were being fetched.
        block_hash: BlockHash,
        /// Transaction hashes that failed to fetch.
        hashes: Vec<TxHash>,
    },

    /// Received transactions from a fetch request (raw, before protocol processing).
    TransactionReceived {
        /// Block these transactions complete.
        block_hash: BlockHash,
        /// Transactions returned by the peer.
        transactions: Vec<Arc<RoutableTransaction>>,
    },

    /// Local provisions received from a fetch request.
    ///
    /// `missing_hashes` lists requested hashes the peer did not have
    /// (evicted or never seen). Together with `batches` it fully partitions
    /// the request, so the fetch protocol can reclaim missing hashes for
    /// retry without relying on a per-peer heuristic.
    LocalProvisionReceived {
        /// Block whose provisions were fetched.
        block_hash: BlockHash,
        /// Provision batches the peer returned.
        batches: Vec<Arc<Provisions>>,
        /// Hashes the peer didn't have — caller retries these elsewhere.
        missing_hashes: Vec<ProvisionHash>,
    },

    /// Local provision fetch failed.
    LocalProvisionFetchFailed {
        /// Block whose provision fetch failed.
        block_hash: BlockHash,
        /// Provision hashes that failed to fetch.
        hashes: Vec<ProvisionHash>,
    },

    /// Finalized waves received from a peer in response to a fetch request.
    FinalizedWaveReceived {
        /// Block these finalized waves complete.
        block_hash: BlockHash,
        /// Peer that served the response.
        peer: ValidatorId,
        /// Finalized waves returned by the peer.
        waves: Vec<Arc<FinalizedWave>>,
    },

    /// A finalized wave fetch request failed.
    FinalizedWaveFetchFailed {
        /// Block whose finalized-wave fetch failed.
        block_hash: BlockHash,
        /// Peer that failed to serve the request.
        peer: ValidatorId,
        /// Wave-id hashes that weren't returned.
        hashes: Vec<WaveIdHash>,
    },

    /// Transaction validated by the validation pipeline.
    TransactionValidated {
        /// Validated transaction ready for the mempool.
        tx: Arc<RoutableTransaction>,
        /// `true` if this validator submitted the tx (don't gossip back to client).
        submitted_locally: bool,
    },

    /// Transactions that failed validation — sent back so the `IoLoop` can
    /// remove their hashes from `pending_validation` and `locally_submitted`.
    TransactionValidationsFailed {
        /// Hashes of transactions that failed validation.
        hashes: Vec<TxHash>,
    },

    /// A committed block header from a remote shard whose sender signature
    /// has been verified by the `IoLoop` gossip gate.
    CommittedHeaderValidated {
        /// Verified committed block header from a remote shard.
        committed_header: CommittedBlockHeader,
        /// Validator that signed the gossip envelope.
        sender: ValidatorId,
    },

    /// A committed block header gossip that has passed pre-filtering
    /// (sender committee check + public key resolution) but still needs
    /// batched BLS signature verification.
    CommittedBlockGossipReceived {
        /// Header carried in the gossip envelope.
        committed_header: CommittedBlockHeader,
        /// Sender validator id.
        sender: ValidatorId,
        /// Sender's public key, resolved from topology.
        public_key: Bls12381G1PublicKey,
        /// Sender's signature over the gossip payload, awaiting batch verify.
        sender_signature: Bls12381G2Signature,
    },

    /// Provision built by the execution pool, ready for network broadcast.
    ///
    /// Returned from delegated `FetchAndBroadcastProvision` action.
    /// The I/O loop sends one `StateProvisionNotification` per target shard,
    /// targeted to the specific recipients embedded in each batch tuple.
    ProvisionReady {
        /// (`target_shard`, provisions, recipients) per target shard.
        batches: Vec<(ShardGroupId, Provisions, Vec<ValidatorId>)>,
    },

    /// Provision successfully received from a provision fetch request.
    ProvisionFetchReceived {
        /// Provision batch returned by the peer.
        provisions: Provisions,
    },

    /// A provision fetch request failed (network error or peer returned None).
    ProvisionFetchFailed {
        /// Source shard whose provisions were being fetched.
        source_shard: ShardGroupId,
        /// Source-shard block height the provisions were anchored to.
        block_height: BlockHeight,
    },

    /// Execution certificates successfully fetched from a source shard.
    ExecCertFetchReceived {
        /// Source shard the certs were fetched from.
        source_shard: ShardGroupId,
        /// Block height the certs are anchored to.
        block_height: BlockHeight,
        /// Execution certificates returned.
        certificates: Vec<ExecutionCertificate>,
    },

    /// An execution certificate fetch request failed.
    ExecCertFetchFailed {
        /// Source shard the fetch targeted.
        source_shard: ShardGroupId,
        /// Block height that failed to return certs.
        block_height: BlockHeight,
    },

    /// Committed block header successfully fetched from a source shard.
    HeaderFetchReceived {
        /// Source shard the header was fetched from.
        source_shard: ShardGroupId,
        /// Starting height of the requested header range.
        from_height: BlockHeight,
        /// Committed block header returned.
        header: CommittedBlockHeader,
    },

    /// A committed block header fetch request failed.
    HeaderFetchFailed {
        /// Source shard the fetch targeted.
        source_shard: ShardGroupId,
        /// Starting height that failed to return.
        from_height: BlockHeight,
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
            NodeInput::Protocol(pe) => match pe {
                ProtocolEvent::ViewChangeTimer
                | ProtocolEvent::CleanupTimer
                | ProtocolEvent::GlobalConsensusTimer => EventPriority::Timer,

                // ContentAvailable is an internal signal (from continuations
                // or rate-limit retry timers), not a network or timer event.
                ProtocolEvent::ContentAvailable => EventPriority::Internal,

                ProtocolEvent::BlockHeaderReceived { .. }
                | ProtocolEvent::RemoteBlockCommitted { .. }
                | ProtocolEvent::BlockVoteReceived { .. }
                | ProtocolEvent::TransactionGossipReceived { .. }
                | ProtocolEvent::GlobalBlockReceived { .. }
                | ProtocolEvent::GlobalBlockVoteReceived { .. }
                | ProtocolEvent::StateProvisionsReceived { .. } => EventPriority::Network,

                // Fetch delivery events are processed callbacks from the fetch
                // protocol, not raw network messages (analogous to
                // CommittedHeaderValidated). They fall through to Internal.
                _ => EventPriority::Internal,
            },
            NodeInput::SubmitTransaction { .. } => EventPriority::Client,
            NodeInput::SyncBlockResponseReceived { .. } => EventPriority::Internal,
            NodeInput::SyncBlockFetchFailed { .. } => EventPriority::Internal,
            NodeInput::SyncBlockTopUpReceived { .. } => EventPriority::Internal,
            NodeInput::SyncBlockTopUpFailed { .. } => EventPriority::Internal,
            NodeInput::FetchTick => EventPriority::Timer,
            NodeInput::FetchTransactionsFailed { .. } => EventPriority::Internal,
            NodeInput::TransactionReceived { .. } => EventPriority::Network,
            NodeInput::TransactionValidated { .. } => EventPriority::Internal,
            NodeInput::TransactionValidationsFailed { .. } => EventPriority::Internal,
            NodeInput::CommittedHeaderValidated { .. } => EventPriority::Internal,
            NodeInput::CommittedBlockGossipReceived { .. } => EventPriority::Network,
            NodeInput::ProvisionReady { .. } => EventPriority::Internal,
            NodeInput::ProvisionFetchReceived { .. } => EventPriority::Internal,
            NodeInput::ProvisionFetchFailed { .. } => EventPriority::Internal,
            NodeInput::ExecCertFetchReceived { .. } => EventPriority::Internal,
            NodeInput::ExecCertFetchFailed { .. } => EventPriority::Internal,
            NodeInput::HeaderFetchReceived { .. } => EventPriority::Internal,
            NodeInput::HeaderFetchFailed { .. } => EventPriority::Internal,
            NodeInput::LocalProvisionReceived { .. } => EventPriority::Internal,
            NodeInput::LocalProvisionFetchFailed { .. } => EventPriority::Internal,
            NodeInput::FinalizedWaveReceived { .. } => EventPriority::Internal,
            NodeInput::FinalizedWaveFetchFailed { .. } => EventPriority::Internal,
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
    #[must_use]
    pub fn type_name(&self) -> &'static str {
        match self {
            NodeInput::Protocol(pe) => pe.type_name(),
            NodeInput::SubmitTransaction { .. } => "SubmitTransaction",
            NodeInput::SyncBlockResponseReceived { .. } => "SyncBlockResponseReceived",
            NodeInput::SyncBlockFetchFailed { .. } => "SyncBlockFetchFailed",
            NodeInput::SyncBlockTopUpReceived { .. } => "SyncBlockTopUpReceived",
            NodeInput::SyncBlockTopUpFailed { .. } => "SyncBlockTopUpFailed",
            NodeInput::FetchTick => "FetchTick",
            NodeInput::FetchTransactionsFailed { .. } => "FetchTransactionsFailed",
            NodeInput::TransactionReceived { .. } => "TransactionReceived",
            NodeInput::TransactionValidated { .. } => "TransactionValidated",
            NodeInput::TransactionValidationsFailed { .. } => "TransactionValidationsFailed",
            NodeInput::CommittedHeaderValidated { .. } => "CommittedHeaderValidated",
            NodeInput::CommittedBlockGossipReceived { .. } => "CommittedBlockGossipReceived",
            NodeInput::ProvisionReady { .. } => "ProvisionReady",
            NodeInput::ProvisionFetchReceived { .. } => "ProvisionFetchReceived",
            NodeInput::ProvisionFetchFailed { .. } => "ProvisionFetchFailed",
            NodeInput::ExecCertFetchReceived { .. } => "ExecCertFetchReceived",
            NodeInput::ExecCertFetchFailed { .. } => "ExecCertFetchFailed",
            NodeInput::HeaderFetchReceived { .. } => "HeaderFetchReceived",
            NodeInput::HeaderFetchFailed { .. } => "HeaderFetchFailed",
            NodeInput::LocalProvisionReceived { .. } => "LocalProvisionReceived",
            NodeInput::LocalProvisionFetchFailed { .. } => "LocalProvisionFetchFailed",
            NodeInput::FinalizedWaveReceived { .. } => "FinalizedWaveReceived",
            NodeInput::FinalizedWaveFetchFailed { .. } => "FinalizedWaveFetchFailed",
        }
    }
}

impl From<ProtocolEvent> for NodeInput {
    fn from(event: ProtocolEvent) -> Self {
        NodeInput::Protocol(event)
    }
}
