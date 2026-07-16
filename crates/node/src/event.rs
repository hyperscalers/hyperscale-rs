//! Inputs to the I/O loop, partitioned by routing scope.
//!
//! [`HostEvent`] is the envelope the runner pushes into the event
//! channel. It is a typed sum over the three drivers a
//! [`NodeHost`](crate::host::NodeHost) routes to:
//!
//! - [`HostEvent::Beacon`] carries a [`PoolScopedInput`] routed to the
//!   host's pool of shard-less followers.
//! - [`HostEvent::Process`] carries a [`ProcessScopedInput`] with no
//!   shard tag — inputs that fan out across every hosted shard.
//! - [`HostEvent::Shard`] carries a [`ShardScopedInput`] tagged with
//!   the hosted-shard id it routes to. Every shard-coherent input
//!   (gossip, sync, fetch results, BLS-verified headers, protocol
//!   events) lives here.
//!
//! The typed sum lets `step()` dispatch via exhaustive match without a
//! runtime scope check.

use std::sync::Arc;

use hyperscale_core::{CommitSource, ProtocolEvent};
use hyperscale_network::RequestError;
use hyperscale_types::{
    BeaconWitnessCommit, BlockHash, BlockHeight, Bls12381G1PublicKey, Bls12381G2Signature,
    BoundedVec, CertifiedBeaconBlock, CertifiedBlock, CertifiedBlockHeader, ElidedCertifiedBlock,
    Epoch, HeaderFetchCount, LeafIndex, MAX_FINALIZED_TX_PER_BLOCK, ProvisionHash,
    RoutableTransaction, ShardId, TxHash, ValidatorId, Verifiable, Verified, WaveId,
};

use crate::shard::commit::QcOnlyDivergence;

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
    /// The peer answered, but doesn't have the requested height/epoch.
    /// Defers with backoff: a sustained not-found (e.g. a beacon sync
    /// target set from an unverified block beyond the chain's real tip)
    /// must not busy-loop the network re-requesting an epoch nobody has
    /// yet. Distinct from `Exhausted`, which re-queues immediately for a
    /// height that's known to exist.
    NotFound,
}

/// Classify a transport-level request error for the sync/fetch FSMs.
///
/// `Exhausted` already absorbed retries against rotated peers — re-queue
/// immediately; other variants reflect transport conditions where a brief
/// deferral is appropriate.
#[must_use]
pub const fn classify_fetch_error(err: &RequestError) -> FetchFailureKind {
    match err {
        RequestError::Exhausted { .. } => FetchFailureKind::Exhausted,
        RequestError::NoPeers => FetchFailureKind::NoPeers,
        RequestError::Timeout
        | RequestError::PeerUnreachable(_)
        | RequestError::PeerError(_)
        | RequestError::Shutdown => FetchFailureKind::Transport,
    }
}

/// Inputs whose dispatch is anchored to a specific hosted shard.
///
/// Every variant either targets the consensus of one shard (the
/// `Protocol(_)` passthrough, gossip arrivals, sync callbacks) or is
/// a tracking-set fixup for that shard's pipeline (`*FetchFailed`,
/// `TransactionValidated`, …). The [`HostEvent::Shard`] envelope
/// carries the routing tag alongside; downstream callbacks capture
/// the shard at dispatch time and stamp every result.
#[derive(Debug, Clone, strum::IntoStaticStr)]
pub enum ShardScopedInput {
    /// Pass-through to state machine. `NodeHost` extracts the `ProtocolEvent`
    /// and feeds it to every vnode hosted in the envelope's shard. Boxed
    /// because `ProtocolEvent` dwarfs every other variant and would inflate
    /// the event queue otherwise.
    Protocol(Box<ProtocolEvent>),

    /// Periodic tick for this shard's fetch / sync state machines to retry
    /// pending operations. Scheduled by the shard's own
    /// `update_fetch_tick_timer` via [`TimerOp::Set`] / [`TimerOp::Cancel`]
    /// on `TimerId::FetchTick`; the runner's timer driver fires the timer
    /// into this shard's input channel.
    ///
    /// [`TimerOp::Set`]: crate::shard::TimerOp::Set
    /// [`TimerOp::Cancel`]: crate::shard::TimerOp::Cancel
    FetchTick,

    /// Raw gossip-delivered transaction. `NodeHost` queues it for async
    /// validation; the validated form is surfaced as
    /// `ProtocolEvent::TransactionValidated`.
    TransactionGossipReceived {
        /// The transaction.
        tx: Arc<RoutableTransaction>,
    },

    /// Raw batch delivered by the transaction fetch protocol's response
    /// callback. `NodeHost` drives the fetch-FSM drain for every
    /// delivered hash (so invalid-signature payloads don't pin
    /// in-flight slots) and dispatches the batch for async validation;
    /// the validated subset surfaces as
    /// `ProtocolEvent::TransactionsReceived`.
    TransactionsFetched {
        /// Transactions returned by the peer.
        batch: Vec<Arc<RoutableTransaction>>,
    },

    /// Locally-submitted tx delivered to a passive co-host: a hosted
    /// shard that touches the tx but isn't the source. Admits to the
    /// shard's validation pipeline if not already pending / cached;
    /// does NOT enqueue outbound gossip and does NOT mark
    /// `locally_submitted` — that's the source shard's role.
    AdmitTransaction {
        /// The locally-submitted transaction.
        tx: Arc<RoutableTransaction>,
    },

    /// Locally-submitted tx delivered to the source shard (first hosted
    /// touched shard). Admits to the shard's validation pipeline, marks
    /// the tx as `locally_submitted` so finalization metrics fire once
    /// per node, AND enqueues outbound gossip for every destination in
    /// `touched_shards`. The source shard's `outbound_gossip_batches`
    /// accumulates one batch per destination shard — `touched_shards`
    /// may include destinations this node doesn't host.
    AdmitAndGossipTransaction {
        /// The locally-submitted transaction.
        tx: Arc<RoutableTransaction>,
        /// Every shard the tx touches (declared reads ∪ writes). Gossip
        /// goes to each — even non-hosted ones — over the destination
        /// shard's topic.
        touched_shards: Vec<ShardId>,
    },

    /// Locally-submitted tx whose touched shards are all non-hosted on
    /// this node. The receiving shard flushes outbound gossip for every
    /// destination in `touched_shards` but performs no admission and
    /// takes no `locally_submitted` ownership.
    GossipTransaction {
        /// The locally-submitted transaction.
        tx: Arc<RoutableTransaction>,
        /// Every shard the tx touches (declared reads ∪ writes). Gossip
        /// goes to each over the destination shard's topic.
        touched_shards: Vec<ShardId>,
    },

    /// Sync block response received from network callback. Carries the
    /// elided wire shape; the `NodeHost` rehydrates to a full `CertifiedBlock`
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

    /// Beacon-block sync response received from a network callback.
    /// `block` is `None` when the peer couldn't serve the epoch. The
    /// `NodeHost` hands the block to the beacon coordinator (cert
    /// verification + adoption) and feeds the beacon `Sync` machine.
    BeaconBlockSyncResponseReceived {
        /// Epoch of the block being synced.
        epoch: Epoch,
        /// The fetched block, or `None` if the peer didn't have it.
        block: Option<Arc<Verifiable<CertifiedBeaconBlock>>>,
    },

    /// Beacon-block sync fetch failed from a network callback.
    BeaconBlockSyncFetchFailed {
        /// Epoch that failed to fetch.
        epoch: Epoch,
        /// Why the fetch failed — drives the beacon `Sync` machine's
        /// re-queue vs. deferral decision.
        kind: FetchFailureKind,
    },

    /// Sync block passed structural validation off-thread (Merkle roots,
    /// QC binding, per-wave shape). The pinned-thread `NodeHost` re-enters
    /// the post-validation delivery path on receipt.
    SyncBlockValidated {
        /// Height of the validated block.
        height: BlockHeight,
        /// Rehydrated, structurally-valid certified block ready for shard consensus.
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
        source_shard: ShardId,
        /// First height of the requested range.
        from_height: BlockHeight,
        /// Number of heights the request covered.
        count: HeaderFetchCount,
        /// Headers the responder returned.
        headers: Vec<CertifiedBlockHeader>,
    },

    /// Remote-header range fetch failed (transport error / no peer).
    RemoteHeadersFetchFailed {
        /// Source shard the fetch targeted.
        source_shard: ShardId,
        /// First height of the requested range.
        from_height: BlockHeight,
        /// Number of heights the request covered.
        count: HeaderFetchCount,
        /// Why the fetch failed — drives whether the sync FSM re-queues
        /// immediately or applies exponential deferral.
        kind: FetchFailureKind,
    },

    /// A past-terminal shard's complete settled-wave window list, `None`
    /// when the peer didn't hold the terminal block. The acquisition host
    /// verifies it against the beacon-attested root before recording.
    SettledWavesResponseReceived {
        /// The terminated shard being acquired.
        source_shard: ShardId,
        /// The shard's complete settled-wave window list, or `None` for
        /// `not_found`.
        waves: Option<BoundedVec<WaveId, MAX_FINALIZED_TX_PER_BLOCK>>,
    },

    /// Settled-waves fetch failed at the transport level. The driver
    /// re-arms and the next `FetchTick` retries against a rotated peer.
    SettledWavesFetchFailed {
        /// The terminated shard being acquired.
        source_shard: ShardId,
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

    /// Transaction validated by the validation pipeline. The `NodeHost`
    /// resolves `submitted_locally` from its `locally_submitted` set
    /// before forwarding as `ProtocolEvent::TransactionValidated`.
    TransactionValidated {
        /// Validated transaction ready for the mempool.
        tx: Arc<Verified<RoutableTransaction>>,
    },

    /// Transactions that failed validation — sent back so the `NodeHost` can
    /// remove their hashes from `pending_validation` and `locally_submitted`.
    TransactionValidationsFailed {
        /// Hashes of transactions that failed validation.
        hashes: Vec<TxHash>,
    },

    /// A committed block header gossip that has passed pre-filtering
    /// (sender committee check + public key resolution) but still needs
    /// batched BLS signature verification.
    CommittedBlockGossipReceived {
        /// Header carried in the gossip envelope. Wrapped as `Verifiable`
        /// so a colocated proposer's local-dispatched broadcast can ride
        /// `Verifiable::Verified` through to the flush step, which then
        /// fast-paths the verified arm past the sender-signature batch.
        certified_header: Arc<Verifiable<CertifiedBlockHeader>>,
        /// Sender validator id.
        sender: ValidatorId,
        /// Sender's public key, resolved from topology.
        public_key: Bls12381G1PublicKey,
        /// Sender's signature over the gossip payload, awaiting batch verify.
        sender_signature: Bls12381G2Signature,
    },

    /// A provision fetch request failed (network error or peer returned None).
    /// The envelope shard is the consumer (target) shard whose cross-shard
    /// fetch owns the in-flight tracking; `source_shard` here is the
    /// originating shard whose provisions were being fetched.
    ProvisionsFetchFailed {
        /// Source shard whose provisions were being fetched.
        source_shard: ShardId,
        /// Source-shard block height the provisions were anchored to.
        block_height: BlockHeight,
    },

    /// An execution certificate fetch request failed.
    ExecCertFetchFailed {
        /// Wave ids that weren't returned.
        hashes: Vec<WaveId>,
    },

    /// A shard-witness fetch failed (network error, empty response, or
    /// peer reported the witness as pruned). Per-id so multiple
    /// in-flight leaves can fail independently.
    ShardWitnessesFetchFailed {
        /// Per-leaf identities that failed to fetch.
        ids: Vec<(ShardId, BlockHeight, BlockHash, LeafIndex)>,
    },

    /// A shard-witness fetch response delivered its payload: release the
    /// fetch slot so the next queued leaf can dispatch. Keyed by the
    /// *request* ids, not the response contents, so a peer's payload can't
    /// leave the slot pinned; if the delivered witness fails admission,
    /// the beacon coordinator's chunk re-drive re-requests the leaf. The
    /// payload itself rides the accompanying
    /// `ProtocolEvent::ShardWitnessesReceived`.
    ShardWitnessesFetchFulfilled {
        /// Per-leaf identities the response fulfilled.
        ids: Vec<(ShardId, BlockHeight, BlockHash, LeafIndex)>,
    },

    /// A beacon-proposal fetch failed (network error, or the peer
    /// didn't have the proposal pooled). Per-id so multiple parallel
    /// missing-proposal fetches can fail independently.
    BeaconProposalFetchFailed {
        /// `(epoch, validator)` pairs whose fetch failed.
        ids: Vec<(Epoch, ValidatorId)>,
    },

    /// A beacon-proposal fetch response delivered a proposal: release the
    /// fetch slot. Keyed by the request ids — same contract as
    /// [`Self::ShardWitnessesFetchFulfilled`]. The payload rides the
    /// accompanying `ProtocolEvent::BeaconProposalFetched`.
    BeaconProposalFetchFulfilled {
        /// `(epoch, validator)` pairs the response fulfilled.
        ids: Vec<(Epoch, ValidatorId)>,
    },

    /// JMT prep for a QC-only commit completed off-thread; the block's
    /// `PreparedCommit` and `PendingChain` entry have been inserted by
    /// the worker, so the shard can hand the commit straight into the
    /// standard accumulate / flush pipeline.
    ///
    /// One in-flight prep at a time per shard — see
    /// `BlockCommitCoordinator::try_acquire_qc_only_slot`. On receipt
    /// the shard runs `accept_block_commit` for the just-prepared
    /// entry, then dispatches the next queued entry if any.
    QcOnlyCommitPrepared {
        /// Block + certifying QC bundled as the verified handle the
        /// downstream `accept_block_commit` consumes directly.
        certified: Arc<Verified<CertifiedBlock>>,
        /// How this node learned the certifying QC. Threaded through to
        /// `accept_block_commit` for metrics labelling.
        source: CommitSource,
        /// Beacon-witness leaves to fold into the eventual block-flush
        /// `WriteBatch`. Originates from the `QcOnlyPending` entry the
        /// shard handed the prep slot; rides back through this event so
        /// the resulting `PendingCommit` can be persisted atomically.
        witness: BeaconWitnessCommit,
    },

    /// JMT prep for a QC-only commit computed a state root that doesn't
    /// match the QC-attested root. Operator-fatal: the local parent
    /// state diverged from canonical and block-by-block recovery can't
    /// repair it. The shard logs the diagnostic and panics on the
    /// pinned thread — rayon workers swallow panics by default, so the
    /// worker reports the divergence through this input rather than
    /// panicking itself. Boxed because the variant is rare and would
    /// otherwise inflate every other `HostEvent` in the queue.
    QcOnlyCommitDiverged(Box<QcOnlyDivergence>),
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
                | ProtocolEvent::VerifiedRemoteHeaderReceived { .. }
                | ProtocolEvent::UnverifiedRemoteHeaderReceived { .. }
                | ProtocolEvent::VerifiedBlockVoteReceived { .. }
                | ProtocolEvent::UnverifiedBlockVoteReceived { .. }
                | ProtocolEvent::VerifiedProvisionsReceived { .. }
                | ProtocolEvent::UnverifiedProvisionsReceived { .. }
                | ProtocolEvent::ExecutionCertificatesReceived { .. }
                | ProtocolEvent::FinalizedWavesReceived { .. }
                | ProtocolEvent::TransactionsReceived { .. }
                | ProtocolEvent::ReadySignalReceived { .. } => EventPriority::Network,
                // Fetch delivery events are processed callbacks from the
                // fetch protocol, not raw network messages. They fall
                // through to Internal.
                _ => EventPriority::Internal,
            },
            Self::TransactionGossipReceived { .. } | Self::TransactionsFetched { .. } => {
                EventPriority::Network
            }
            Self::CommittedBlockGossipReceived { .. } => EventPriority::Network,
            Self::AdmitTransaction { .. }
            | Self::AdmitAndGossipTransaction { .. }
            | Self::GossipTransaction { .. } => EventPriority::Client,
            Self::FetchTick => EventPriority::Timer,
            Self::BlockSyncResponseReceived { .. }
            | Self::BlockSyncFetchFailed { .. }
            | Self::BeaconBlockSyncResponseReceived { .. }
            | Self::BeaconBlockSyncFetchFailed { .. }
            | Self::SyncBlockValidated { .. }
            | Self::SyncBlockValidationFailed { .. }
            | Self::RemoteHeadersResponseReceived { .. }
            | Self::RemoteHeadersFetchFailed { .. }
            | Self::SettledWavesResponseReceived { .. }
            | Self::SettledWavesFetchFailed { .. }
            | Self::TransactionsFetchFailed { .. }
            | Self::TransactionValidated { .. }
            | Self::TransactionValidationsFailed { .. }
            | Self::ProvisionsFetchFailed { .. }
            | Self::ExecCertFetchFailed { .. }
            | Self::LocalProvisionsFetchFailed { .. }
            | Self::FinalizedWavesFetchFailed { .. }
            | Self::ShardWitnessesFetchFailed { .. }
            | Self::ShardWitnessesFetchFulfilled { .. }
            | Self::BeaconProposalFetchFailed { .. }
            | Self::BeaconProposalFetchFulfilled { .. }
            | Self::QcOnlyCommitPrepared { .. }
            | Self::QcOnlyCommitDiverged { .. } => EventPriority::Internal,
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
/// `SubmitTransaction` is the only entry — the runner fans it across
/// every hosted shard the transaction touches.
#[derive(Debug, Clone, strum::IntoStaticStr)]
pub enum ProcessScopedInput {
    /// Client submitted a transaction.
    SubmitTransaction {
        /// Transaction submitted by the local client; will be validated then gossiped.
        tx: Arc<RoutableTransaction>,
    },
}

impl ProcessScopedInput {
    /// Priority for ordering events at the same simulation timestamp.
    #[must_use]
    pub const fn priority(&self) -> EventPriority {
        match self {
            Self::SubmitTransaction { .. } => EventPriority::Client,
        }
    }

    /// Telemetry label.
    #[must_use]
    pub fn type_name(&self) -> &'static str {
        self.into()
    }
}

/// Inputs routed to the host's shard-less beacon-follower pool
/// ([`PoolLoop`](crate::pool_loop::PoolLoop)).
///
/// A follower folds the beacon and tracks topology but runs no shard
/// consensus, so its input set is small: gossiped beacon blocks — and the
/// self-driven verify/adopt continuations they spawn — arrive as
/// [`Self::Protocol`], and the catch-up sync the pool drives when a follower
/// falls behind delivers its fetch results through the remaining variants.
#[derive(Debug, Clone, strum::IntoStaticStr)]
pub enum PoolScopedInput {
    /// Pass-through to every pooled vnode's state machine. Boxed because
    /// `ProtocolEvent` dwarfs every other variant and would inflate the
    /// event queue otherwise.
    Protocol(Box<ProtocolEvent>),

    /// A beacon-block sync response landed for the pool's catch-up fetch.
    /// `block` is `None` when the peer couldn't serve the epoch. The pool
    /// delivers the block to every follower and advances its sync FSM.
    BeaconBlockSyncResponseReceived {
        /// Epoch of the block being synced.
        epoch: Epoch,
        /// The fetched block, or `None` if the peer didn't have it.
        block: Option<Arc<Verifiable<CertifiedBeaconBlock>>>,
    },

    /// A beacon-block sync fetch failed at the transport layer.
    BeaconBlockSyncFetchFailed {
        /// Epoch that failed to fetch.
        epoch: Epoch,
        /// Why the fetch failed — drives the sync FSM's re-queue vs. deferral.
        kind: FetchFailureKind,
    },

    /// Periodic tick driving the catch-up sync FSM's deferred-fetch retries.
    /// The pool driver fires it while a sync is in flight.
    FetchTick,
}

impl PoolScopedInput {
    /// Priority for ordering events at the same simulation timestamp.
    #[must_use]
    pub fn priority(&self) -> EventPriority {
        match self {
            // Inbound beacon gossip is a network input; the verify/adopt
            // continuations it spawns are internal consequences.
            Self::Protocol(event) => match event.as_ref() {
                ProtocolEvent::BeaconBlockReceived { .. } => EventPriority::Network,
                _ => EventPriority::Internal,
            },
            // Sync-fetch callbacks are processed consequences, not raw inputs.
            Self::BeaconBlockSyncResponseReceived { .. }
            | Self::BeaconBlockSyncFetchFailed { .. } => EventPriority::Internal,
            Self::FetchTick => EventPriority::Timer,
        }
    }

    /// Telemetry label. `Protocol` delegates to the inner
    /// [`ProtocolEvent::type_name`]; the rest use their variant names.
    #[must_use]
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Protocol(event) => event.type_name(),
            other => other.into(),
        }
    }
}

/// An input plus the driver the I/O loop's `step()` routes it to.
///
/// The shard variant carries the hosted-shard tag inline; the process and
/// beacon variants have no tag — the process fan is host-wide, and a host runs
/// at most one follower pool.
#[derive(Debug, Clone)]
pub enum HostEvent {
    /// Routed to the hosted shard identified by [`ShardId`]. Fans
    /// to every vnode in that shard for state-machine events; handled
    /// once for shard-scoped pipeline fixups.
    Shard(ShardId, ShardScopedInput),
    /// Process-scoped — not anchored to a single shard.
    Process(ProcessScopedInput),
    /// Beacon-scoped — routed to the host's pool of shard-less
    /// followers (the [`PoolLoop`](crate::pool_loop::PoolLoop)). Carries
    /// a [`PoolScopedInput`] the pool folds; shard hosts receive beacon
    /// events through their per-shard channels instead.
    Beacon(PoolScopedInput),
}

impl HostEvent {
    /// Construct a shard-scoped envelope.
    #[must_use]
    pub const fn shard(shard: ShardId, input: ShardScopedInput) -> Self {
        Self::Shard(shard, input)
    }

    /// Construct a process-scoped envelope.
    #[must_use]
    pub const fn process(input: ProcessScopedInput) -> Self {
        Self::Process(input)
    }

    /// Construct a shard-scoped `Protocol` envelope for `event`.
    #[must_use]
    pub fn protocol(shard: ShardId, event: ProtocolEvent) -> Self {
        Self::Shard(shard, ShardScopedInput::Protocol(Box::new(event)))
    }

    /// Construct a beacon-scoped envelope carrying a protocol event for the
    /// host's pool.
    #[must_use]
    pub fn beacon(event: ProtocolEvent) -> Self {
        Self::Beacon(PoolScopedInput::Protocol(Box::new(event)))
    }

    /// Construct the pool's catch-up sync retry tick.
    #[must_use]
    pub const fn beacon_fetch_tick() -> Self {
        Self::Beacon(PoolScopedInput::FetchTick)
    }

    /// Whether this is the pool's catch-up sync retry tick. The simulation
    /// harness uses it to re-arm the next tick while a pool sync is in flight.
    #[must_use]
    pub const fn is_pool_fetch_tick(&self) -> bool {
        matches!(self, Self::Beacon(PoolScopedInput::FetchTick))
    }

    /// Priority for ordering events at the same simulation timestamp.
    #[must_use]
    pub fn priority(&self) -> EventPriority {
        match self {
            Self::Shard(_, input) => input.priority(),
            Self::Process(input) => input.priority(),
            Self::Beacon(input) => input.priority(),
        }
    }

    /// Telemetry label.
    #[must_use]
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Shard(_, input) => input.type_name(),
            Self::Process(input) => input.type_name(),
            Self::Beacon(input) => input.type_name(),
        }
    }
}
