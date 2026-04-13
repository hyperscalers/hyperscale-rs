//! Event types for the deterministic state machine.

use crate::ProtocolEvent;
use hyperscale_types::{
    Block, BlockHeight, Bls12381G1PublicKey, Bls12381G2Signature, CommittedBlockHeader,
    ExecutionCertificate, FinalizedWave, Hash, LocalReceiptEntry, Provision, QuorumCertificate,
    RoutableTransaction, ShardGroupId, ValidatorId,
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
/// - `Protocol(ProtocolEvent)`: pass-through events that IoLoop extracts and
///   passes to the state machine's `handle()` method directly.
/// - NodeInput-specific variants: events that IoLoop handles internally
///   (sync, fetch, validation pipeline) before potentially converting them
///   into `ProtocolEvent`s.
#[allow(clippy::large_enum_variant)] // TODO: Box ProtocolEvent
#[derive(Debug, Clone)]
pub enum NodeInput {
    /// Pass-through to state machine. IoLoop extracts the ProtocolEvent and
    /// passes it to state.handle() directly.
    Protocol(ProtocolEvent),

    /// Client submitted a transaction.
    SubmitTransaction { tx: Arc<RoutableTransaction> },

    /// Sync block response received from network callback.
    SyncBlockResponseReceived {
        height: u64,
        block: Box<Option<(Block, QuorumCertificate)>>,
        /// Local receipts for the block's certificates (from sync peer).
        local_receipts: Vec<LocalReceiptEntry>,
        /// Execution certificates produced by the serving shard.
        execution_certificates: Vec<ExecutionCertificate>,
    },

    /// Sync block fetch failed from network callback.
    SyncBlockFetchFailed { height: u64 },

    /// Periodic tick for the fetch protocol to retry pending operations.
    FetchTick,

    /// Fetch transactions failed from network callback.
    FetchTransactionsFailed { block_hash: Hash, hashes: Vec<Hash> },

    /// Received transactions from a fetch request (raw, before protocol processing).
    TransactionReceived {
        block_hash: Hash,
        transactions: Vec<Arc<RoutableTransaction>>,
    },

    /// Local provision batches received from a fetch request.
    LocalProvisionReceived {
        block_hash: Hash,
        batches: Vec<Arc<Provision>>,
    },

    /// Local provision fetch failed.
    LocalProvisionFetchFailed { block_hash: Hash, hashes: Vec<Hash> },

    /// Finalized waves received from a peer in response to a fetch request.
    FinalizedWaveReceived {
        block_hash: Hash,
        waves: Vec<Arc<FinalizedWave>>,
    },

    /// A finalized wave fetch request failed.
    FinalizedWaveFetchFailed { block_hash: Hash, hashes: Vec<Hash> },

    /// Transaction validated by the validation pipeline.
    TransactionValidated {
        tx: Arc<RoutableTransaction>,
        submitted_locally: bool,
    },

    /// Transactions that failed validation — sent back so the IoLoop can
    /// remove their hashes from `pending_validation` and `locally_submitted`.
    TransactionValidationsFailed { hashes: Vec<Hash> },

    /// A committed block header from a remote shard whose sender signature
    /// has been verified by the IoLoop gossip gate.
    CommittedHeaderValidated {
        committed_header: CommittedBlockHeader,
        sender: ValidatorId,
    },

    /// A committed block header gossip that has passed pre-filtering
    /// (sender committee check + public key resolution) but still needs
    /// batched BLS signature verification.
    CommittedBlockGossipReceived {
        committed_header: CommittedBlockHeader,
        sender: ValidatorId,
        public_key: Bls12381G1PublicKey,
        sender_signature: Bls12381G2Signature,
    },

    /// Provision built by the execution pool, ready for network broadcast.
    ///
    /// Returned from delegated `FetchAndBroadcastProvision` action.
    /// The I/O loop sends one `StateProvisionNotification` per target shard,
    /// targeted to the specific recipients embedded in each batch tuple.
    ProvisionReady {
        /// (target_shard, provision_batch, recipients) per target shard.
        batches: Vec<(ShardGroupId, Provision, Vec<ValidatorId>)>,
        /// Block timestamp from the source block (for wire format).
        block_timestamp: u64,
    },

    /// Provision successfully received from a provision fetch request.
    ProvisionFetchReceived { batch: Provision },

    /// A provision fetch request failed (network error or peer returned None).
    ProvisionFetchFailed {
        source_shard: ShardGroupId,
        block_height: BlockHeight,
    },

    /// Execution certificates successfully fetched from a source shard.
    ExecCertFetchReceived {
        source_shard: ShardGroupId,
        block_height: u64,
        certificates: Vec<ExecutionCertificate>,
    },

    /// An execution certificate fetch request failed.
    ExecCertFetchFailed {
        source_shard: ShardGroupId,
        block_height: u64,
    },

    /// Committed block header successfully fetched from a source shard.
    HeaderFetchReceived {
        source_shard: ShardGroupId,
        from_height: BlockHeight,
        header: CommittedBlockHeader,
    },

    /// A committed block header fetch request failed.
    HeaderFetchFailed {
        source_shard: ShardGroupId,
        from_height: BlockHeight,
    },
}

impl NodeInput {
    /// Get the priority for this input type.
    ///
    /// Events at the same timestamp are processed in priority order,
    /// ensuring causality is preserved.
    pub fn priority(&self) -> EventPriority {
        match self {
            // Priority is a scheduling concern, not a protocol concern.
            // Timers and network-received messages are classified explicitly;
            // everything else (callbacks, continuations, completions) defaults to Internal.
            NodeInput::Protocol(pe) => match pe {
                ProtocolEvent::ProposalTimer
                | ProtocolEvent::CleanupTimer
                | ProtocolEvent::GlobalConsensusTimer => EventPriority::Timer,

                ProtocolEvent::BlockHeaderReceived { .. }
                | ProtocolEvent::RemoteBlockCommitted { .. }
                | ProtocolEvent::BlockVoteReceived { .. }
                | ProtocolEvent::TransactionGossipReceived { .. }
                | ProtocolEvent::GlobalBlockReceived { .. }
                | ProtocolEvent::GlobalBlockVoteReceived { .. }
                | ProtocolEvent::StateProvisionReceived { .. } => EventPriority::Network,

                // Fetch delivery events are processed callbacks from the fetch
                // protocol, not raw network messages (analogous to
                // CommittedHeaderValidated). They fall through to Internal.
                _ => EventPriority::Internal,
            },
            NodeInput::SubmitTransaction { .. } => EventPriority::Client,
            NodeInput::SyncBlockResponseReceived { .. } => EventPriority::Internal,
            NodeInput::SyncBlockFetchFailed { .. } => EventPriority::Internal,
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
    pub fn is_internal(&self) -> bool {
        self.priority() == EventPriority::Internal
    }

    /// Check if this is a network event (from another node).
    pub fn is_network(&self) -> bool {
        self.priority() == EventPriority::Network
    }

    /// Check if this is a client event (from a user).
    pub fn is_client(&self) -> bool {
        self.priority() == EventPriority::Client
    }

    /// Get the event type name for telemetry.
    pub fn type_name(&self) -> &'static str {
        match self {
            NodeInput::Protocol(pe) => pe.type_name(),
            NodeInput::SubmitTransaction { .. } => "SubmitTransaction",
            NodeInput::SyncBlockResponseReceived { .. } => "SyncBlockResponseReceived",
            NodeInput::SyncBlockFetchFailed { .. } => "SyncBlockFetchFailed",
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
