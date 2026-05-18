//! Event types for the deterministic state machine.

use std::sync::Arc;

use hyperscale_types::{
    BlockHeight, Bls12381G1PublicKey, Bls12381G2Signature, CertifiedBlock, CommittedBlockHeader,
    ElidedCertifiedBlock, HeaderFetchCount, ProvisionHash, RoutableTransaction, ShardGroupId,
    TxHash, ValidatorId, WaveId,
};

use crate::ProtocolEvent;

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
/// `NodeInput` is the top-level input type for `IoLoop`. It contains:
/// - `Protocol(ProtocolEvent)`: pass-through events that `IoLoop` extracts and
///   passes to the state machine's `handle()` method directly.
/// - `NodeInput`-specific variants: events that `IoLoop` handles internally
///   (sync, fetch, validation pipeline) before potentially converting them
///   into `ProtocolEvent`s.
#[derive(Debug, Clone, strum::IntoStaticStr)]
pub enum NodeInput {
    /// Pass-through to state machine. `IoLoop` extracts the `ProtocolEvent`
    /// and passes it to `state.handle()` directly on every vnode hosted in
    /// `shard`. Boxed because `ProtocolEvent` dwarfs every other variant
    /// and would inflate the event queue otherwise.
    ///
    /// `shard` is supplied at emission time so cross-shard hosting can
    /// fan the event out to the right vnodes — the prior single-shard
    /// design fell back to `vnodes[0].shard` and broke quietly when the
    /// host carried vnodes across multiple shards. Off-thread emission
    /// sites (BLS verify, sync rehydrate, fetch response callbacks)
    /// capture the shard at their dispatch point.
    Protocol {
        /// Hosted shard this event applies to. Used by `IoLoop::step()`
        /// to select which vnodes receive the event.
        shard: ShardGroupId,
        /// Boxed protocol event payload.
        event: Box<ProtocolEvent>,
    },

    /// Client submitted a transaction.
    SubmitTransaction {
        /// Transaction submitted by the local client; will be validated then gossiped.
        tx: Arc<RoutableTransaction>,
    },

    /// Raw gossip-delivered transaction. `IoLoop` queues it for async
    /// validation; the validated form is surfaced as
    /// `ProtocolEvent::TransactionValidated`.
    TransactionGossipReceived {
        /// Hosted shard the gossip arrived on. Cross-shard hosting
        /// keys mempool/validation pipeline state by this shard rather
        /// than `vnodes[0].shard`.
        local_shard: ShardGroupId,
        /// The transaction.
        tx: Arc<RoutableTransaction>,
    },

    /// Sync block response received from network callback. Carries the
    /// elided wire shape; the `IoLoop` rehydrates to a full `CertifiedBlock`
    /// by looking up omitted bodies in the local mempool / cert cache /
    /// provision store before handing off to the sync state machine.
    BlockSyncResponseReceived {
        /// Hosted shard whose sync FSM dispatched the fetch and now
        /// admits the response.
        local_shard: ShardGroupId,
        /// Height of the block being synced.
        height: BlockHeight,
        /// Elided block payload, or `None` if the peer couldn't serve this height.
        block: Option<Box<ElidedCertifiedBlock>>,
    },

    /// Sync block fetch failed from network callback.
    BlockSyncFetchFailed {
        /// Hosted shard whose sync FSM dispatched the fetch.
        local_shard: ShardGroupId,
        /// Height that failed to fetch.
        height: BlockHeight,
        /// Why the fetch failed — drives whether the sync FSM re-queues
        /// immediately or applies exponential deferral.
        kind: FetchFailureKind,
    },

    /// Sync block passed structural validation off-thread (Merkle roots,
    /// QC binding, per-wave shape). The pinned-thread `IoLoop` re-enters
    /// the post-validation delivery path on receipt.
    SyncBlockValidated {
        /// Hosted shard the block belongs to.
        local_shard: ShardGroupId,
        /// Height of the validated block.
        height: BlockHeight,
        /// Rehydrated, structurally-valid certified block ready for BFT.
        certified: Box<CertifiedBlock>,
    },

    /// Sync block failed structural validation off-thread. The pinned
    /// thread re-queues the height for retry.
    SyncBlockValidationFailed {
        /// Hosted shard whose sync FSM re-queues the height.
        local_shard: ShardGroupId,
        /// Height that failed to validate.
        height: BlockHeight,
        /// Static reason tag — used for both metrics labels and warn logs.
        reason: &'static str,
    },

    /// Range response from a remote-header sync fetch. Headers are in
    /// ascending height order starting at `from_height`; missing tail
    /// heights (responder short-capped) get re-deferred by the FSM.
    RemoteHeadersResponseReceived {
        /// Hosted shard whose `RemoteHeaderCoordinator` admits these
        /// headers (the "consumer" side; distinct from `source_shard`).
        local_shard: ShardGroupId,
        /// Source shard the fetch targeted.
        source_shard: ShardGroupId,
        /// First height of the requested range.
        from_height: BlockHeight,
        /// Number of heights the request covered.
        count: HeaderFetchCount,
        /// Headers the responder returned.
        headers: Vec<CommittedBlockHeader>,
    },

    /// Remote-header range fetch failed (transport error / no peer).
    RemoteHeadersFetchFailed {
        /// Hosted shard whose `RemoteHeaderCoordinator` re-queues.
        local_shard: ShardGroupId,
        /// Source shard the fetch targeted.
        source_shard: ShardGroupId,
        /// First height of the requested range.
        from_height: BlockHeight,
        /// Number of heights the request covered.
        count: HeaderFetchCount,
        /// Why the fetch failed — drives whether the sync FSM re-queues
        /// immediately or applies exponential deferral.
        kind: FetchFailureKind,
    },

    /// Periodic tick for the fetch protocol to retry pending operations.
    FetchTick,

    /// A transaction fetch request failed (network error or peer returned None).
    TransactionsFetchFailed {
        /// Hosted shard whose `FetchHost` owns the in-flight tracking
        /// for these ids.
        local_shard: ShardGroupId,
        /// Transaction hashes that failed to fetch.
        hashes: Vec<TxHash>,
    },

    /// Local provision fetch failed.
    LocalProvisionsFetchFailed {
        /// Hosted shard whose `FetchHost` owns the in-flight tracking.
        local_shard: ShardGroupId,
        /// Provision hashes that failed to fetch.
        hashes: Vec<ProvisionHash>,
    },

    /// A finalized-wave fetch request failed.
    FinalizedWavesFetchFailed {
        /// Hosted shard whose `FetchHost` owns the in-flight tracking.
        local_shard: ShardGroupId,
        /// Wave ids that weren't returned.
        ids: Vec<WaveId>,
    },

    /// Transaction validated by the validation pipeline. The `IoLoop`
    /// resolves `submitted_locally` from its `locally_submitted` set
    /// before forwarding as `ProtocolEvent::TransactionValidated`.
    TransactionValidated {
        /// Hosted shard whose `ShardIo` owns the validation tracking
        /// sets for this batch. Captured at `flush_validation_batch`
        /// dispatch so the result routes to the right hosted shard
        /// under cross-shard hosting.
        local_shard: ShardGroupId,
        /// Validated transaction ready for the mempool.
        tx: Arc<RoutableTransaction>,
    },

    /// Transactions that failed validation — sent back so the `IoLoop` can
    /// remove their hashes from `pending_validation` and `locally_submitted`.
    TransactionValidationsFailed {
        /// Hosted shard whose tracking sets to clean up.
        local_shard: ShardGroupId,
        /// Hashes of transactions that failed validation.
        hashes: Vec<TxHash>,
    },

    /// A committed block header gossip that has passed pre-filtering
    /// (sender committee check + public key resolution) but still needs
    /// batched BLS signature verification.
    CommittedBlockGossipReceived {
        /// Hosted shard this gossip is consumed by — derived from the
        /// receiving vnode's `local_shard`, not from the header's shard
        /// (the header is from a remote shard).
        local_shard: ShardGroupId,
        /// Header carried in the gossip envelope. `Arc`-shared so local
        /// publishers and the BLS-verify batch all hold the same
        /// allocation — `RemoteHeaderReceived` downstream takes
        /// `Arc<CommittedBlockHeader>` and the wire type's
        /// `SborArc<CommittedBlockHeader>` exposes the same inner.
        committed_header: Arc<CommittedBlockHeader>,
        /// Sender validator id.
        sender: ValidatorId,
        /// Sender's public key, resolved from topology.
        public_key: Bls12381G1PublicKey,
        /// Sender's signature over the gossip payload, awaiting batch verify.
        sender_signature: Bls12381G2Signature,
    },

    /// A provision fetch request failed (network error or peer returned None).
    ProvisionsFetchFailed {
        /// Hosted shard whose `FetchHost` owns the in-flight tracking
        /// (the "target" shard from the perspective of the provision
        /// flow; distinct from `source_shard`).
        local_shard: ShardGroupId,
        /// Source shard whose provisions were being fetched.
        source_shard: ShardGroupId,
        /// Source-shard block height the provisions were anchored to.
        block_height: BlockHeight,
    },

    /// An execution certificate fetch request failed.
    ExecCertFetchFailed {
        /// Hosted shard whose `FetchHost` owns the in-flight tracking.
        local_shard: ShardGroupId,
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
            Self::Protocol { event, .. } => match event.as_ref() {
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
            Self::Protocol { event, .. } => event.type_name(),
            other => other.into(),
        }
    }
}

impl NodeInput {
    /// Construct a `NodeInput::Protocol` for `shard` from `event`.
    /// Convenience for the common case where the caller has both
    /// `shard` and `event` in scope and doesn't want to spell out the
    /// boxing + struct construction.
    #[must_use]
    pub fn protocol(shard: ShardGroupId, event: ProtocolEvent) -> Self {
        Self::Protocol {
            shard,
            event: Box::new(event),
        }
    }
}

/// Why a sync fetch failed, picked by the I/O glue when translating a
/// network-layer `RequestError` into a [`NodeInput::BlockSyncFetchFailed`]
/// or [`NodeInput::RemoteHeadersFetchFailed`].
///
/// The sync FSM uses this to decide whether to apply exponential deferral.
/// `Exhausted` only arrives after the request manager has already retried
/// against rotated peers — the network layer absorbed seconds of waiting,
/// so the FSM re-queues immediately. Other kinds reflect transport
/// conditions where a brief deferral is appropriate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchFailureKind {
    /// Request manager retried against rotated peers and gave up. The
    /// network layer already absorbed the wait — re-queue immediately.
    Exhausted,
    /// No peers available to send to (empty topology committee). Defer
    /// with backoff so we don't spin until the committee populates.
    NoPeers,
    /// Transport-level error (connection issue, network shutdown). Rare;
    /// defer with backoff.
    Transport,
}
