//! Inputs to the I/O loop, partitioned by routing scope.
//!
//! [`ShardEvent`] is the envelope the runner pushes into the event
//! channel. It is a typed sum over the two routing scopes:
//!
//! - [`ShardEvent::Shard`] carries a [`ShardScopedInput`] tagged with
//!   the hosted-shard id it routes to. Every shard-coherent input
//!   (gossip, sync, fetch results, BLS-verified headers, protocol
//!   events) lives here.
//! - [`ShardEvent::Process`] carries a [`ProcessScopedInput`] with no
//!   shard tag — currently `FetchTick` and `SubmitTransaction`, both
//!   of which fan out across every hosted shard.
//!
//! The type-level partition replaces the previous `Option<ShardGroupId>`
//! envelope: shard-scoped inputs always carry a shard, process-scoped
//! inputs never need one, and the I/O loop's `step()` dispatch is an
//! exhaustive match instead of a runtime panic if the shard tag is
//! missing.

use std::sync::Arc;

use hyperscale_core::ProtocolEvent;
use hyperscale_types::{
    BlockHeight, Bls12381G1PublicKey, Bls12381G2Signature, CertifiedBlock, CommittedBlockHeader,
    ElidedCertifiedBlock, HeaderFetchCount, ProvisionHash, RoutableTransaction, ShardGroupId,
    TxHash, ValidatorId, WaveId,
};

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

/// Why a sync fetch failed, picked by the I/O glue when translating a
/// network-layer `RequestError` into a [`ShardScopedInput::BlockSyncFetchFailed`]
/// or [`ShardScopedInput::RemoteHeadersFetchFailed`].
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

/// Inputs whose dispatch is anchored to a specific hosted shard.
///
/// Every variant either targets the consensus of one shard (the
/// `Protocol(_)` passthrough, gossip arrivals, sync callbacks) or is
/// a tracking-set fixup for that shard's pipeline (`*FetchFailed`,
/// `TransactionValidated`, …). The [`ShardEvent::Shard`] envelope
/// carries the routing tag alongside; downstream callbacks capture
/// the shard at dispatch time and stamp every result.
#[derive(Debug, Clone, strum::IntoStaticStr)]
pub enum ShardScopedInput {
    /// Pass-through to state machine. `IoLoop` extracts the `ProtocolEvent`
    /// and feeds it to every vnode hosted in the envelope's shard. Boxed
    /// because `ProtocolEvent` dwarfs every other variant and would inflate
    /// the event queue otherwise.
    Protocol(Box<ProtocolEvent>),

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
        block: Option<Box<ElidedCertifiedBlock>>,
    },

    /// Sync block fetch failed from network callback.
    BlockSyncFetchFailed {
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
        /// Wave ids that weren't returned.
        ids: Vec<WaveId>,
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
    /// The envelope shard is the consumer (target) shard whose `FetchHost`
    /// owns the in-flight tracking; `source_shard` here is the originating
    /// shard whose provisions were being fetched.
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

impl ShardScopedInput {
    /// Priority for ordering events at the same simulation timestamp.
    #[must_use]
    #[allow(clippy::match_same_arms)] // explicit per-variant arms document intent
    pub fn priority(&self) -> EventPriority {
        match self {
            Self::Protocol(event) => match event.as_ref() {
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
                // Fetch delivery events are processed callbacks from the
                // fetch protocol, not raw network messages. They fall
                // through to Internal.
                _ => EventPriority::Internal,
            },
            Self::TransactionGossipReceived { .. } => EventPriority::Network,
            Self::CommittedBlockGossipReceived { .. } => EventPriority::Network,
            Self::BlockSyncResponseReceived { .. }
            | Self::BlockSyncFetchFailed { .. }
            | Self::SyncBlockValidated { .. }
            | Self::SyncBlockValidationFailed { .. }
            | Self::RemoteHeadersResponseReceived { .. }
            | Self::RemoteHeadersFetchFailed { .. }
            | Self::TransactionsFetchFailed { .. }
            | Self::TransactionValidated { .. }
            | Self::TransactionValidationsFailed { .. }
            | Self::ProvisionsFetchFailed { .. }
            | Self::ExecCertFetchFailed { .. }
            | Self::LocalProvisionsFetchFailed { .. }
            | Self::FinalizedWavesFetchFailed { .. } => EventPriority::Internal,
        }
    }

    /// Telemetry label. Variant names come from the `IntoStaticStr`
    /// derive; `Protocol` delegates to the inner `ProtocolEvent::type_name`
    /// so protocol telemetry is attributable per inner variant.
    #[must_use]
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Protocol(event) => event.type_name(),
            other => other.into(),
        }
    }
}

/// Inputs that aren't anchored to a particular hosted shard.
///
/// Fan out across every hosted shard the runner deems relevant — e.g.
/// `SubmitTransaction` admits to every hosted shard the tx touches;
/// `FetchTick` ticks every shard's fetch host.
#[derive(Debug, Clone, strum::IntoStaticStr)]
pub enum ProcessScopedInput {
    /// Client submitted a transaction.
    SubmitTransaction {
        /// Transaction submitted by the local client; will be validated then gossiped.
        tx: Arc<RoutableTransaction>,
    },

    /// Periodic tick for the fetch protocol to retry pending operations.
    FetchTick,
}

impl ProcessScopedInput {
    /// Priority for ordering events at the same simulation timestamp.
    #[must_use]
    pub const fn priority(&self) -> EventPriority {
        match self {
            Self::SubmitTransaction { .. } => EventPriority::Client,
            Self::FetchTick => EventPriority::Timer,
        }
    }

    /// Telemetry label.
    #[must_use]
    pub fn type_name(&self) -> &'static str {
        self.into()
    }
}

/// An input plus the routing scope the I/O loop's `step()` uses to
/// dispatch it.
///
/// The shard variant carries the hosted-shard tag inline; the process
/// variant has no tag because it isn't anchored to one shard. Earlier
/// revisions modelled this as `{ shard: Option<ShardGroupId>, input:
/// NodeInput }` and asserted at runtime that shard-scoped inputs
/// carried a `Some(_)` — the typed sum lifts that assertion to the
/// type level.
#[derive(Debug, Clone)]
pub enum ShardEvent {
    /// Routed to the hosted shard identified by [`ShardGroupId`]. Fans
    /// to every vnode in that shard for state-machine events; handled
    /// once for shard-scoped pipeline fixups.
    Shard(ShardGroupId, ShardScopedInput),
    /// Process-scoped — not anchored to a single shard.
    Process(ProcessScopedInput),
}

impl ShardEvent {
    /// Construct a shard-scoped envelope.
    #[must_use]
    pub const fn shard(shard: ShardGroupId, input: ShardScopedInput) -> Self {
        Self::Shard(shard, input)
    }

    /// Construct a process-scoped envelope.
    #[must_use]
    pub const fn process(input: ProcessScopedInput) -> Self {
        Self::Process(input)
    }

    /// Construct a shard-scoped `Protocol` envelope for `event`.
    #[must_use]
    pub fn protocol(shard: ShardGroupId, event: ProtocolEvent) -> Self {
        Self::Shard(shard, ShardScopedInput::Protocol(Box::new(event)))
    }

    /// Priority for ordering events at the same simulation timestamp.
    #[must_use]
    pub fn priority(&self) -> EventPriority {
        match self {
            Self::Shard(_, input) => input.priority(),
            Self::Process(input) => input.priority(),
        }
    }

    /// Telemetry label.
    #[must_use]
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Shard(_, input) => input.type_name(),
            Self::Process(input) => input.type_name(),
        }
    }
}
