//! Event types for the deterministic state machine.

use crate::ProtocolEvent;
use hyperscale_types::{
    BlockHeight, Bls12381G1PublicKey, Bls12381G2Signature, CommittedBlockHeader, FinalizedWave,
    ProvisionHash, Provisions, RoutableTransaction, ShardGroupId, TxHash, ValidatorId, WaveId,
    WaveIdHash,
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

    /// Fetch transactions failed from network callback.
    FetchTransactionsFailed {
        /// Transaction hashes that failed to fetch.
        hashes: Vec<TxHash>,
    },

    /// Received transactions from a fetch request (raw, before protocol processing).
    ///
    /// Routed to `NodeStateMachine::on_transactions_fetched`, which funnels
    /// them through mempool admission. The block-hash association is reported
    /// at admission time via the `Continuation(TransactionsAdmitted)` event;
    /// `io_loop`'s drain doesn't need it here.
    ///
    /// `missing_hashes` lists requested hashes the peer did not return
    /// (computed client-side as `requested - delivered`). The fetch FSM
    /// feeds them as `Failed` so `in_flight` is cleared and the next tick
    /// retries them; without this, partial responses would pin entries
    /// in the in-flight set forever.
    TransactionReceived {
        /// Transactions returned by the peer.
        transactions: Vec<Arc<RoutableTransaction>>,
        /// Requested hashes the peer did not return.
        missing_hashes: Vec<TxHash>,
    },

    /// Local provisions received from a fetch request.
    ///
    /// `missing_hashes` lists requested hashes the peer did not have
    /// (evicted or never seen). Together with `batches` it fully partitions
    /// the request, so the fetch protocol can reclaim missing hashes for
    /// retry without relying on a per-peer heuristic.
    LocalProvisionReceived {
        /// Provision batches the peer returned.
        batches: Vec<Arc<Provisions>>,
        /// Hashes the peer didn't have — caller retries these elsewhere.
        missing_hashes: Vec<ProvisionHash>,
    },

    /// Local provision fetch failed.
    LocalProvisionsFetchFailed {
        /// Provision hashes that failed to fetch.
        hashes: Vec<ProvisionHash>,
    },

    /// Finalized waves received from a peer in response to a fetch request.
    ///
    /// Routed to `ExecutionCoordinator::admit_finalized_wave`. `io_loop`'s
    /// `Continuation(FinalizedWavesAdmitted)` interception drains the matching
    /// fetch protocol — the block-hash association and serving peer aren't
    /// needed at `io_loop`'s level once the cert is in the wave's EC.
    ///
    /// `missing_hashes` lists requested wave-id hashes the peer did not
    /// return (computed client-side as `requested - delivered`); the fetch
    /// FSM feeds them as `Failed` so partial responses don't pin entries
    /// in the in-flight set.
    FinalizedWaveReceived {
        /// Finalized waves returned by the peer.
        waves: Vec<Arc<FinalizedWave>>,
        /// Requested wave-id hashes the peer did not return.
        missing_hashes: Vec<WaveIdHash>,
    },

    /// A finalized wave fetch request failed.
    FinalizedWaveFetchFailed {
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
                ProtocolEvent::ViewChangeTimer
                | ProtocolEvent::CleanupTimer
                | ProtocolEvent::GlobalConsensusTimer => EventPriority::Timer,

                ProtocolEvent::BlockHeaderReceived { .. }
                | ProtocolEvent::RemoteHeaderReceived { .. }
                | ProtocolEvent::BlockVoteReceived { .. }
                | ProtocolEvent::TransactionGossipReceived { .. }
                | ProtocolEvent::GlobalBlockReceived { .. }
                | ProtocolEvent::GlobalBlockVoteReceived { .. }
                | ProtocolEvent::ProvisionsReceived { .. }
                | ProtocolEvent::ExecutionCertificatesReceived { .. } => EventPriority::Network,

                // Fetch delivery events are processed callbacks from the fetch
                // protocol, not raw network messages (analogous to
                // CommittedHeaderValidated). They fall through to Internal.
                _ => EventPriority::Internal,
            },
            Self::SubmitTransaction { .. } => EventPriority::Client,
            Self::BlockSyncResponseReceived { .. } => EventPriority::Internal,
            Self::BlockSyncFetchFailed { .. } => EventPriority::Internal,
            Self::RemoteHeadersResponseReceived { .. } => EventPriority::Internal,
            Self::RemoteHeadersFetchFailed { .. } => EventPriority::Internal,
            Self::FetchTick => EventPriority::Timer,
            Self::FetchTransactionsFailed { .. } => EventPriority::Internal,
            Self::TransactionReceived { .. } => EventPriority::Network,
            Self::TransactionValidated { .. } => EventPriority::Internal,
            Self::TransactionValidationsFailed { .. } => EventPriority::Internal,
            Self::CommittedHeaderValidated { .. } => EventPriority::Internal,
            Self::CommittedBlockGossipReceived { .. } => EventPriority::Network,
            Self::ProvisionsFetchFailed { .. } => EventPriority::Internal,
            Self::ExecCertFetchFailed { .. } => EventPriority::Internal,
            Self::LocalProvisionReceived { .. } => EventPriority::Internal,
            Self::LocalProvisionsFetchFailed { .. } => EventPriority::Internal,
            Self::FinalizedWaveReceived { .. } => EventPriority::Internal,
            Self::FinalizedWaveFetchFailed { .. } => EventPriority::Internal,
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
