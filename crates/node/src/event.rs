//! Inputs to a host's loops, partitioned by routing scope, and what a step
//! hands back to the runner: its timer operations and output.
//!
//! [`HostEvent`] is the envelope the runner pushes into the event
//! channel. It is a typed sum over the two drivers a
//! [`NodeHost`](crate::host::NodeHost) routes to:
//!
//! - [`HostEvent::Beacon`] carries a [`BeaconScopedInput`] routed to the
//!   host's beacon loop.
//! - [`HostEvent::Shard`] carries a [`ShardScopedInput`] tagged with
//!   the hosted-shard id it routes to. Every shard-coherent input
//!   (gossip, sync, fetch results, signature-verified headers, protocol
//!   events) lives here.
//!
//! The typed sum lets `step()` dispatch via exhaustive match without a
//! runtime scope check.

use std::sync::Arc;
use std::time::Duration;

use crossbeam::channel::Sender;
use hyperscale_beacon::ChainRegistration;
use hyperscale_beacon::coordinator::LocalChainAnchors;
use hyperscale_core::{
    BeaconFetchIds, CommitSource, FetchIds, ParticipationChange, ProtocolEvent, TimerId,
};
use hyperscale_network::{PeerId, RequestError};
use hyperscale_types::network::gossip::MAX_GOSSIP_TX_BATCH;
use hyperscale_types::network::notification::BlockHeaderNotification;
use hyperscale_types::{
    Address, BeaconChainConfig, BeaconWitnessCommit, BlockHash, BlockHeight, CertifiedBeaconBlock,
    CertifiedBlock, CertifiedBlockHeader, ConsensusPublicKey, ConsensusSignature,
    ElidedCertifiedBlock, Epoch, Hash, HeaderFetchCount, MAX_UNSETTLED_PER_BLOCK,
    MAX_UNSETTLED_TXS, ShardForkProof, ShardId, ShardVoteEquivocation, Signer, TopologySchedule,
    Transaction, TransactionStatus, TxHash, ValidatorId, Verifiable, Verified, WeightedTimestamp,
};

pub use crate::network_lane::{
    NetworkInput, NetworkLane, NetworkLaneReceiver, Offer, network_lane,
};
use crate::shard::commit::QcOnlyDivergence;
use crate::shard::mempool::DeferredTransaction;

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
    /// Every peer's stream is backing off after a recent failure, and the
    /// soonest reopens after `retry_in`. Wait exactly that, then retry: the
    /// committee is there, so the FSM's own backoff has nothing to add.
    BackingOff {
        /// Until the soonest peer's stream reopens.
        retry_in: Duration,
    },
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
pub(crate) const fn classify_fetch_error(err: &RequestError) -> FetchFailureKind {
    match err {
        RequestError::Exhausted { .. } => FetchFailureKind::Exhausted,
        RequestError::NoPeers => FetchFailureKind::NoPeers,
        RequestError::BackingOff { retry_in } => FetchFailureKind::BackingOff {
            retry_in: *retry_in,
        },
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
    /// Pass-through to state machine. The shard's loop extracts the `ProtocolEvent`
    /// and feeds it to the envelope's shard's replica. Boxed because
    /// `ProtocolEvent` dwarfs every other variant and would inflate the
    /// event queue otherwise.
    Protocol(Box<ProtocolEvent>),

    /// A block proposal off the wire, its proposer's signature checked at
    /// intake. The loop feeds its header to the replica and holds it for
    /// serving once the replica admits it.
    ProposalReceived {
        /// The proposal as its proposer signed it.
        proposal: Box<BlockHeaderNotification>,
    },

    /// A block proposal fetched by hash, its proposer's signature not yet
    /// checked. The loop checks it, then takes it as
    /// [`Self::ProposalReceived`].
    ProposalFetched {
        /// The proposal the peer answered with.
        proposal: Box<BlockHeaderNotification>,
    },

    /// Periodic tick for this shard's fetch / sync state machines to retry
    /// pending operations. Scheduled by the shard's own
    /// `update_fetch_tick_timer` via [`TimerOp::Set`] / [`TimerOp::Cancel`]
    /// on `TimerId::FetchTick`; the runner's timer driver fires the timer
    /// into this shard's input channel.
    ///
    /// [`TimerOp::Set`]: crate::event::TimerOp::Set
    /// [`TimerOp::Cancel`]: crate::event::TimerOp::Cancel
    FetchTick,

    /// Raw gossip-delivered transaction. The loop queues it for async
    /// validation; the validated form is surfaced as
    /// `ProtocolEvent::TransactionValidated`.
    TransactionGossipReceived {
        /// The transaction.
        tx: Transaction,
    },

    /// Raw batch delivered by the transaction fetch protocol's response
    /// callback. The loop drives the fetch-FSM drain for every
    /// delivered hash (so invalid-signature payloads don't pin
    /// in-flight slots) and dispatches the batch for async validation;
    /// the validated subset surfaces as
    /// `ProtocolEvent::TransactionsReceived`.
    TransactionsFetched {
        /// Transactions returned by the peer.
        batch: Vec<Transaction>,
    },

    /// Envelopes a derivation could not resolve, each beside what it
    /// wanted — component records, package artifacts, or both — so the
    /// fetch can ask the shards owning them and the envelopes can wait
    /// for the answer.
    RecordsWanted {
        /// What is waiting, and what each is waiting for.
        wanted: Vec<DeferredTransaction>,
    },

    /// Records and code this loop asked the host's beacon loop for are
    /// now what derivation reads, so the envelopes waiting on them can be
    /// offered again.
    RecordsArrived {
        /// What arrived, each as the address a wait is indexed by: a
        /// component by its own, a package by the one its content
        /// address derives.
        arrived: Vec<Address>,
    },

    /// Locally-submitted tx delivered to a passive co-host: a hosted
    /// shard that touches the tx but isn't the source. Admits to the
    /// shard's validation pipeline if not already pending / cached;
    /// does NOT enqueue outbound gossip and does NOT mark
    /// `locally_submitted` — that's the source shard's role.
    AdmitTransaction {
        /// The locally-submitted transaction.
        tx: Transaction,
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
        tx: Transaction,
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
        tx: Transaction,
        /// Every shard the tx touches (declared reads ∪ writes). Gossip
        /// goes to each over the destination shard's topic.
        touched_shards: Vec<ShardId>,
    },

    /// Sync block response received from network callback. Carries the
    /// elided wire shape; the loop rehydrates to a full `CertifiedBlock`
    /// by looking up omitted bodies in the local mempool / cert cache /
    /// provision store before handing off to the sync state machine.
    BlockSyncResponseReceived {
        /// Height of the block being synced.
        height: BlockHeight,
        /// Elided block payload, or `None` if the peer couldn't serve this height.
        block: Option<Box<ElidedCertifiedBlock>>,
    },

    /// Every peer a sync block fetch reached keeps no block at `height`:
    /// it lies beneath their chain floor.
    BlockSyncBelowFloor {
        /// Height that was asked for.
        height: BlockHeight,
        /// The floor the answering peer named, above `height`.
        floor: BlockHeight,
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
    /// QC binding, per-tick shape). The loop's pinned thread re-enters
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
        /// The responder's chain floor, when the range starts beneath it.
        floor: Option<BlockHeight>,
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

    /// Response to a one-shot commit-proof fetch: the certified-header run
    /// starting at the wanted height, screened against the range asked.
    /// Headers feed the same QC-verification path gossip-arrived headers
    /// take; the commit-proof walk does the rest. Transport failures push
    /// nothing — the coordinator's commit sweep re-issues the fetch.
    CommitProofResponseReceived {
        /// Headers the responder returned.
        headers: Vec<CertifiedBlockHeader>,
    },

    /// A fetch went unanswered for these ids — a transport failure, a
    /// peer that did not hold them, or an answer this node could not
    /// use. The binding's state machine releases their in-flight slots
    /// so the next tick retries against another peer.
    FetchFailed(FetchIds),

    /// A fetch that never reached a peer — no committee resolves the
    /// shard, or none of its members is up. Released like
    /// [`Self::FetchFailed`], but the retry waits for the tick rather
    /// than leaving at once into the same wall.
    FetchUnroutable(FetchIds),

    /// A fetch was answered and verified for these ids: release their
    /// slots. Keyed by the *request* ids, not the response's contents,
    /// so a peer's payload cannot leave a slot pinned. The payload
    /// itself rides the accompanying `ProtocolEvent`.
    FetchFulfilled(FetchIds),

    /// Transaction validated by the validation pipeline. The loop
    /// resolves `submitted_locally` from its `locally_submitted` set
    /// before forwarding as `ProtocolEvent::TransactionValidated`.
    TransactionValidated {
        /// Validated transaction ready for the mempool.
        tx: Verified<Transaction>,
    },

    /// Transactions that failed validation — sent back so the loop can
    /// remove their hashes from `pending_validation` and `locally_submitted`.
    TransactionValidationsFailed {
        /// Hashes of transactions that failed validation.
        hashes: Vec<TxHash>,
    },

    /// A committed block header gossip that has passed pre-filtering
    /// (sender committee check + public key resolution) but still needs
    /// batched signature verification.
    CommittedBlockGossipReceived {
        /// Header carried in a peer's gossip envelope.
        certified_header: Verifiable<CertifiedBlockHeader>,
        /// Sender validator id.
        sender: ValidatorId,
        /// Sender's public key, resolved from topology.
        public_key: ConsensusPublicKey,
        /// Sender's signature over the gossip payload, awaiting batch verify.
        sender_signature: ConsensusSignature,
    },

    /// A self-authenticating shard fork proof arrived over global gossip.
    /// No sender trust to resolve — the state machine re-verifies the proof
    /// against its own topology.
    ShardForkProofGossipReceived {
        /// The fork evidence off the wire.
        proof: Arc<ShardForkProof>,
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
        /// `WriteBatch`. Originates from the `QcOnlyCommit` entry the
        /// shard handed the prep slot; rides back through this event so
        /// the resulting `PendingCommit` can be persisted atomically.
        witness: BeaconWitnessCommit,
        /// The committed block's committee anchor — its parent's own
        /// anchor — which classifies its content downstream. Carried from the
        /// commit rather than read at fan-out, because a buffered run commits
        /// in one step and a scalar read afterwards names only its last block.
        committee_anchor: WeightedTimestamp,
    },

    /// JMT prep for a QC-only commit computed a state root that doesn't
    /// match the QC-attested root. Operator-fatal: the local parent
    /// state diverged from canonical and block-by-block recovery can't
    /// repair it. The shard logs the diagnostic and panics on the
    /// pinned thread — rayon workers swallow panics by default, so the
    /// worker reports the divergence through this input rather than
    /// panicking itself. A block the store's write frontier reached while
    /// its prep ran is the exception: the shard drops it and moves on.
    /// Boxed because the variant is rare and would otherwise inflate
    /// every other `HostEvent` in the queue.
    QcOnlyCommitDiverged(Box<QcOnlyDivergence>),

    /// JMT prep for a QC-only commit found the store persisted past the
    /// block's parent before it could walk the block's sweep: the block
    /// is already written, so the shard drops it and moves on.
    QcOnlyCommitWrittenPast {
        /// Height being committed.
        block_height: BlockHeight,
        /// Hash of the committing block.
        block_hash: BlockHash,
    },

    /// A commit flush on the I/O pool wrote every block through
    /// `height`. The loop advances its commit pipeline and reads what
    /// the replica's `ProtocolEvent::BlockPersisted` carries off the
    /// store, so only the loop builds that event.
    BlockFlushed {
        /// The highest height the flush wrote.
        height: BlockHeight,
    },
}

impl ShardScopedInput {
    /// Priority for ordering events at the same simulation timestamp.
    #[must_use]
    pub(crate) fn priority(&self) -> EventPriority {
        match self {
            Self::Protocol(event) => match event.as_ref() {
                ProtocolEvent::ViewChangeTimer
                | ProtocolEvent::CleanupTimer
                | ProtocolEvent::ProposalPaceTimer
                | ProtocolEvent::ProposalFetchTimer => EventPriority::Timer,
                ProtocolEvent::BlockHeaderReceived { .. }
                | ProtocolEvent::VerifiedRemoteHeaderReceived { .. }
                | ProtocolEvent::UnverifiedRemoteHeaderReceived { .. }
                | ProtocolEvent::RemoteHeadersBelowFloor { .. }
                | ProtocolEvent::VerifiedBlockVoteReceived { .. }
                | ProtocolEvent::UnverifiedBlockVoteReceived { .. }
                | ProtocolEvent::VerifiedProvisionsReceived { .. }
                | ProtocolEvent::UnverifiedProvisionsReceived { .. }
                | ProtocolEvent::CrossingReadingsReceived { .. }
                | ProtocolEvent::ExecutionCertificatesReceived { .. }
                | ProtocolEvent::FinalizationsReceived { .. }
                | ProtocolEvent::TransactionsReceived { .. }
                | ProtocolEvent::ReadySignalReceived { .. } => EventPriority::Network,
                // Fetch delivery events are processed callbacks from the
                // fetch protocol, not raw network messages. They fall
                // through to Internal.
                _ => EventPriority::Internal,
            },
            Self::ProposalReceived { .. }
            | Self::TransactionGossipReceived { .. }
            | Self::TransactionsFetched { .. }
            | Self::RecordsArrived { .. }
            | Self::RecordsWanted { .. }
            | Self::CommittedBlockGossipReceived { .. }
            | Self::ShardForkProofGossipReceived { .. } => EventPriority::Network,
            Self::AdmitTransaction { .. }
            | Self::AdmitAndGossipTransaction { .. }
            | Self::GossipTransaction { .. } => EventPriority::Client,
            Self::FetchTick => EventPriority::Timer,
            Self::BlockSyncResponseReceived { .. }
            | Self::FetchUnroutable(..)
            | Self::BlockSyncFetchFailed { .. }
            | Self::BlockSyncBelowFloor { .. }
            | Self::SyncBlockValidated { .. }
            | Self::SyncBlockValidationFailed { .. }
            | Self::RemoteHeadersResponseReceived { .. }
            | Self::RemoteHeadersFetchFailed { .. }
            | Self::CommitProofResponseReceived { .. }
            | Self::FetchFailed(_)
            | Self::FetchFulfilled(_)
            | Self::ProposalFetched { .. }
            | Self::TransactionValidated { .. }
            | Self::TransactionValidationsFailed { .. }
            | Self::QcOnlyCommitPrepared { .. }
            | Self::QcOnlyCommitDiverged { .. }
            | Self::QcOnlyCommitWrittenPast { .. }
            | Self::BlockFlushed { .. } => EventPriority::Internal,
        }
    }

    /// Telemetry label. Variant names come from the `IntoStaticStr`
    /// derive; `Protocol` delegates to the inner `ProtocolEvent::type_name`
    /// so protocol telemetry is attributable per inner variant.
    #[must_use]
    pub(crate) fn type_name(&self) -> &'static str {
        match self {
            Self::Protocol(event) => event.type_name(),
            other => other.into(),
        }
    }
}

/// One attachment of a validator identity to the host's beacon loop.
///
/// Every attach takes a fresh serial from the host's process, so an
/// identity removed and attached again is a different attachment, and
/// what the earlier one left in flight never reaches the later one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Attachment {
    /// The attached identity.
    pub(crate) validator: ValidatorId,
    serial: u64,
}

impl Attachment {
    pub(crate) const fn new(validator: ValidatorId, serial: u64) -> Self {
        Self { validator, serial }
    }
}

/// Whose beacon work an input continues.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BeaconOwner {
    /// The host's fold: its block checks and witness fetches.
    Fold,
    /// One attached identity's beacon participation.
    Participant(Attachment),
    /// A registered chain's loop, asking for the records and code its
    /// envelopes and commits name.
    Chain(ChainRegistration),
    /// The host's own submissions, waiting on the beacon loop for the
    /// records they name.
    Submissions,
}

/// What a chain's loop reports to the host's beacon loop: what its
/// replica saw, and what the loop wants the host to fetch.
#[derive(Debug, Clone)]
pub enum BeaconInput {
    /// The replica committed the block this certified header heads.
    LocalCommit {
        /// The committed block's certified header.
        header: Verified<CertifiedBlockHeader>,
    },
    /// The replica certified this header, ahead of its commit.
    CertifiedHeader {
        /// The replica's own certified header.
        header: Verified<CertifiedBlockHeader>,
    },
    /// The replica admitted a remote source header.
    SourceHeader {
        /// The admitted header.
        header: Verified<CertifiedBlockHeader>,
    },
    /// The replica proved a remote source header's commit.
    CommitProven {
        /// The proven header.
        header: Verified<CertifiedBlockHeader>,
    },
    /// A shard fork is proven, for the next beacon proposal.
    ForkProof(Box<ShardForkProof>),
    /// A shard double-vote pair is proven, for the next beacon proposal.
    VoteEquivocation {
        /// The proven pair.
        evidence: Box<ShardVoteEquivocation>,
    },
    /// The loop wants these records and this code, which derivation does
    /// not read on this host yet.
    RecordsWanted {
        /// Component records, by address.
        instances: Vec<Address>,
        /// Package artifacts, by content address.
        packages: Vec<Hash>,
    },
    /// Nothing on the loop waits on these any more.
    RecordsAbandoned {
        /// Component records, by address.
        instances: Vec<Address>,
        /// Package artifacts, by content address.
        packages: Vec<Hash>,
    },
}

/// What a registration hands the loop that registered: its token, the
/// schedule its replica starts from, and the chain config the fold runs.
#[derive(Debug, Clone)]
pub struct Registration {
    /// The token every later input from the loop carries.
    pub token: ChainRegistration,
    /// The fold's schedule, widened for the chain.
    pub(crate) schedule: Arc<TopologySchedule>,
    /// The epoch the fold folded the schedule at.
    pub(crate) epoch: Epoch,
    /// The beacon chain's config.
    pub(crate) chain_config: BeaconChainConfig,
}

/// Where a runtime registration's [`Registration`] goes.
#[derive(Clone)]
pub struct RegistrationReply(pub Arc<dyn Fn(Registration) + Send + Sync>);

impl std::fmt::Debug for RegistrationReply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RegistrationReply")
    }
}

/// Inputs routed to the host's beacon loop
/// ([`BeaconLoop`](crate::beacon::BeaconLoop)).
///
/// Gossiped beacon blocks and votes arrive as [`Self::Protocol`]; the
/// outcomes of the loop's own dispatched actions return as
/// [`Self::Continuation`], and its fetches and catch-up sync deliver their
/// results through the remaining variants.
#[derive(Debug, Clone, strum::IntoStaticStr)]
pub enum BeaconScopedInput {
    /// Pass-through to every participant's state machine. Boxed because
    /// `ProtocolEvent` dwarfs every other variant and would inflate the
    /// event queue otherwise.
    Protocol(Box<ProtocolEvent>),

    /// The outcome of an action `owner` emitted, run on the dispatch pool:
    /// fed to that owner alone, and dropped once that attachment has left
    /// the loop, even when its identity has been attached again.
    Continuation {
        /// Who emitted the action.
        owner: BeaconOwner,
        /// The handler's outcome.
        event: Box<ProtocolEvent>,
    },

    /// A timer one participant armed, fired: fed to that participant
    /// alone, and dropped once that attachment has left the loop.
    ParticipantTimer {
        /// The participant that armed the timer.
        participant: Attachment,
        /// The timer's protocol event.
        event: Box<ProtocolEvent>,
    },

    /// A beacon-block sync response landed for the loop's catch-up fetch.
    /// `block` is `None` when the peer couldn't serve the epoch. The loop
    /// hands the block to its fold and advances its sync FSM.
    BeaconBlockSyncResponseReceived {
        /// Epoch of the block being synced.
        epoch: Epoch,
        /// The fetched block, or `None` if the peer didn't have it.
        block: Option<Verifiable<CertifiedBeaconBlock>>,
    },

    /// A beacon-block sync fetch failed at the transport layer.
    BeaconBlockSyncFetchFailed {
        /// Epoch that failed to fetch.
        epoch: Epoch,
        /// Why the fetch failed — drives the sync FSM's re-queue vs. deferral.
        kind: FetchFailureKind,
    },

    /// A fetch attempt for these ids failed or was refused; retry at
    /// once the first time since the tick, and on the tick after that.
    FetchFailed(BeaconFetchIds),
    /// A fetch request for these ids never reached a peer; retry on the
    /// tick.
    FetchUnroutable(BeaconFetchIds),
    /// A fetch for these ids was answered whole at its response boundary;
    /// they retire.
    FetchFulfilled(BeaconFetchIds),
    /// A fetch for `ids` was answered with `event`. The ids retire once
    /// the loop takes what the answer carries, and are released as
    /// failed when its fold refuses a witness run.
    Answered {
        /// The ids the answered request asked for.
        ids: BeaconFetchIds,
        /// What the answer carries. Boxed for the reason
        /// [`Self::Protocol`] is.
        event: Box<ProtocolEvent>,
    },

    /// The loop's fetch tick: retries its held fetches and its catch-up
    /// sync's deferred epochs.
    FetchTick,

    /// Instance records a fetch delivered, each already re-derived to the
    /// address it was asked for at the response boundary, so the loop
    /// never pays for the hash.
    InstanceRecordsFetched {
        /// The verified records, each beside the address it derives.
        records: Vec<(Address, Vec<u8>)>,
    },

    /// Package artifacts a fetch delivered, each already hashed to the
    /// content address it was asked for at the response boundary.
    PackageArtifactsFetched {
        /// The verified artifacts, each beside its content address.
        artifacts: Vec<(Hash, Vec<u8>)>,
    },

    /// A submission this host could not derive, to hold until the records
    /// it names arrive and then route through the fan-out it never got.
    SubmissionWantsRecords {
        /// What is waiting, and what it waits for.
        deferred: DeferredTransaction,
    },

    /// Package artifacts the loop's off-thread install has seated, so the
    /// metadata derivation reads is there to be read. Reported from
    /// inside the install, after the cache holds it.
    PackagesInstalled {
        /// The installed packages, by content address.
        packages: Vec<Hash>,
        /// The packages the install was to read from a store this host
        /// serves and found in none, to be asked of a peer.
        unheld: Vec<Hash>,
    },

    /// What the replica of the chain `chain` names reported.
    Shard {
        /// The reporting loop's registration.
        chain: ChainRegistration,
        /// The report.
        input: BeaconInput,
    },

    /// Register a chain a loop is about to run, from its recovered
    /// committed height and the anchors its tip carries. Beacon events
    /// for the chain go to `sender` from then on.
    Register {
        /// The chain's shard.
        shard: ShardId,
        /// The anchors the chain's committed tip carries.
        anchors: LocalChainAnchors,
        /// The chain's recovered committed height.
        height: BlockHeight,
        /// The loop's channel.
        sender: Sender<HostEvent>,
        /// Where the registration goes.
        reply: RegistrationReply,
    },

    /// Stop tracking a chain whose loop has closed.
    Deregister(ChainRegistration),

    /// Run another validator's beacon participation on this host from now
    /// on.
    AddParticipant {
        /// The validator.
        validator: ValidatorId,
        /// Its signing key.
        signer: Arc<dyn Signer>,
    },
}

impl BeaconScopedInput {
    /// Priority for ordering events at the same simulation timestamp.
    #[must_use]
    pub(crate) fn priority(&self) -> EventPriority {
        match self {
            // Inbound beacon gossip is a network input, whether pushed or
            // answering a fetch; the verify/adopt continuations it spawns
            // are internal consequences.
            Self::Protocol(event) | Self::Answered { event, .. } => match event.as_ref() {
                ProtocolEvent::BeaconBlockReceived { .. } => EventPriority::Network,
                _ => EventPriority::Internal,
            },
            // A participant's timers order as its beacon continuations do;
            // fetch callbacks are processed consequences, not raw inputs.
            Self::Continuation { .. }
            | Self::ParticipantTimer { .. }
            | Self::BeaconBlockSyncResponseReceived { .. }
            | Self::BeaconBlockSyncFetchFailed { .. }
            | Self::FetchFailed(_)
            | Self::FetchUnroutable(_)
            | Self::FetchFulfilled(_)
            | Self::InstanceRecordsFetched { .. }
            | Self::PackageArtifactsFetched { .. }
            | Self::PackagesInstalled { .. }
            | Self::SubmissionWantsRecords { .. }
            | Self::Shard { .. }
            | Self::Register { .. }
            | Self::Deregister(_)
            | Self::AddParticipant { .. } => EventPriority::Internal,
            Self::FetchTick => EventPriority::Timer,
        }
    }

    /// Telemetry label. `Protocol` delegates to the inner
    /// [`ProtocolEvent::type_name`]; the rest use their variant names.
    #[must_use]
    pub(crate) fn type_name(&self) -> &'static str {
        match self {
            Self::Protocol(event)
            | Self::Continuation { event, .. }
            | Self::ParticipantTimer { event, .. }
            | Self::Answered { event, .. } => event.type_name(),
            other => other.into(),
        }
    }
}

/// Inbound network inputs one hosted shard's network lane holds before it
/// refuses more.
///
/// Per-transaction gossip is the lane's most numerous item, and a chain
/// holds at most [`MAX_UNSETTLED_TXS`] transactions in flight: a backlog
/// deeper than that is more than the replica could take in before it
/// drains. Several full gossip batches fit.
pub const NETWORK_LANE_CAPACITY: usize = MAX_UNSETTLED_PER_BLOCK;

const _: () = assert!(NETWORK_LANE_CAPACITY as u64 == MAX_UNSETTLED_TXS);

const _: () = assert!(NETWORK_LANE_CAPACITY >= 4 * MAX_GOSSIP_TX_BATCH);

/// The two lanes into one hosted shard's driver.
///
/// The network lane takes what peers send unbidden (gossip and
/// notifications) and is bounded: a push that finds it full, or that
/// would take its peer past its share of it, is refused, never queued, so
/// a stalled driver cannot make peer traffic pile up without bound and
/// no one peer can keep it full. `internal` takes everything the host
/// itself produced (the loop's own continuations, off-thread results, the
/// answers to its own fetches, the beacon loop's reports, RPC
/// submissions) and is never bounded: each item there is owed to a state
/// machine that is waiting on it. The driver drains both, keeping each
/// lane's own order.
#[derive(Debug, Clone)]
pub struct ShardInbox {
    internal: Sender<HostEvent>,
    /// `None` when peers' inputs share the internal lane's channel.
    network: Option<NetworkLane>,
}

impl ShardInbox {
    /// An inbox over its two lanes.
    #[must_use]
    pub const fn new(internal: Sender<HostEvent>, network: NetworkLane) -> Self {
        Self {
            internal,
            network: Some(network),
        }
    }

    /// The lane for the host's own continuations and answers.
    #[must_use]
    pub const fn internal(&self) -> &Sender<HostEvent> {
        &self.internal
    }

    /// Offer `event`, sent by `peer`, to the lane for inputs peers send
    /// unbidden. An inbox whose lanes share one channel takes it there.
    #[must_use]
    pub fn offer(&self, event: HostEvent, peer: PeerId) -> Offer {
        if let Some(lane) = &self.network {
            return lane.offer(event, peer);
        }
        let _ = self.internal.send(event);
        Offer::Taken
    }
}

/// Both lanes on one channel: one driver draining a single receiver in
/// the order it was pushed, as the simulation harness does. An unbounded
/// channel never refuses a push, so neither the lane's bound nor any
/// peer's share of it applies.
impl From<Sender<HostEvent>> for ShardInbox {
    fn from(sender: Sender<HostEvent>) -> Self {
        Self {
            internal: sender,
            network: None,
        }
    }
}

/// An input plus the driver the host's `step()` routes it to.
///
/// The shard variant carries the hosted-shard tag inline; the beacon variant
/// has none, since a host runs one beacon loop.
#[derive(Debug, Clone)]
pub enum HostEvent {
    /// Routed to the hosted shard identified by [`ShardId`]: its replica
    /// for state-machine events, its loop for shard-scoped pipeline
    /// fixups.
    Shard(ShardId, ShardScopedInput),
    /// Beacon-scoped — routed to the host's
    /// [`BeaconLoop`](crate::beacon::BeaconLoop). Carries a
    /// [`BeaconScopedInput`]: beacon traffic, what the replicas report,
    /// and the loop's own continuations and fetch answers.
    Beacon(BeaconScopedInput),
}

impl HostEvent {
    /// Construct a shard-scoped envelope.
    #[must_use]
    pub const fn shard(shard: ShardId, input: ShardScopedInput) -> Self {
        Self::Shard(shard, input)
    }

    /// Construct a shard-scoped `Protocol` envelope for `event`.
    #[must_use]
    pub fn protocol(shard: ShardId, event: ProtocolEvent) -> Self {
        Self::Shard(shard, ShardScopedInput::Protocol(Box::new(event)))
    }

    /// Construct a beacon-scoped envelope carrying a protocol event for the
    /// host's beacon loop.
    #[must_use]
    pub fn beacon(event: ProtocolEvent) -> Self {
        Self::Beacon(BeaconScopedInput::Protocol(Box::new(event)))
    }

    /// Construct the beacon loop's fetch tick.
    #[must_use]
    pub(crate) const fn beacon_fetch_tick() -> Self {
        Self::Beacon(BeaconScopedInput::FetchTick)
    }

    /// Priority for ordering events at the same simulation timestamp.
    #[must_use]
    pub fn priority(&self) -> EventPriority {
        match self {
            Self::Shard(_, input) => input.priority(),
            Self::Beacon(input) => input.priority(),
        }
    }

    /// Telemetry label.
    #[must_use]
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Shard(_, input) => input.type_name(),
            Self::Beacon(input) => input.type_name(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// TimerOp — buffered timer operations for the runner
// ═══════════════════════════════════════════════════════════════════════

/// Whose timer a [`TimerOp`] names, and so whom its fire reaches.
///
/// Each beacon participant arms the same [`TimerId`]s against its own
/// deadlines, so a participant's timer is its own and its fire reaches it
/// alone. A shard loop's timers, its replica's and its fetch tick, are the
/// loop's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TimerOwner {
    /// A hosted shard's loop: its replica's timers and its fetch tick.
    Loop(ShardId),
    /// One attached identity's beacon participation on the host's beacon
    /// loop.
    Participant(Attachment),
    /// The host's beacon loop itself: its fetch tick.
    Beacon,
}

/// A timer operation buffered by a loop driver for the runner to process.
///
/// The runner's timer driver keys handles by `(TimerOwner, TimerId)`, and
/// the firing path ([`timer_event`]) addresses the envelope to the owner.
#[derive(Debug, Clone)]
pub enum TimerOp {
    /// Set a timer to fire after `duration`.
    Set {
        /// Whose timer this is.
        owner: TimerOwner,
        /// Logical timer identifier (state-machine-side).
        id: TimerId,
        /// How long until the timer should fire.
        duration: Duration,
    },
    /// Cancel a previously set timer.
    Cancel {
        /// Whose timer this is.
        owner: TimerOwner,
        /// Logical timer identifier to cancel.
        id: TimerId,
    },
}

/// Translate a fired [`TimerId`] back into the [`HostEvent`] the runner
/// pushes onto its event channel.
///
/// The envelope is addressed to the timer's owner: a loop's timer to its
/// shard, a participant's to that participant alone, and the beacon loop's
/// fetch tick to the beacon loop.
#[must_use]
pub fn timer_event(id: &TimerId, owner: TimerOwner) -> HostEvent {
    let event = match id {
        TimerId::ViewChange => ProtocolEvent::ViewChangeTimer,
        TimerId::Cleanup => ProtocolEvent::CleanupTimer,
        TimerId::ProposalPace => ProtocolEvent::ProposalPaceTimer,
        TimerId::ProposalFetch => ProtocolEvent::ProposalFetchTimer,
        TimerId::FetchTick => {
            return match owner {
                TimerOwner::Loop(shard) => HostEvent::shard(shard, ShardScopedInput::FetchTick),
                TimerOwner::Participant(_) | TimerOwner::Beacon => HostEvent::beacon_fetch_tick(),
            };
        }
        TimerId::BeaconCommitteeStart => ProtocolEvent::BeaconCommitteeStartTimer,
        TimerId::BeaconRatifyTrigger => ProtocolEvent::BeaconRatifyTimer,
        TimerId::BeaconSpcView => ProtocolEvent::BeaconSpcViewTimer,
        TimerId::BeaconSpcInputDwell => ProtocolEvent::BeaconSpcInputDwellTimer,
    };
    match owner {
        TimerOwner::Loop(shard) => HostEvent::protocol(shard, event),
        TimerOwner::Participant(participant) => {
            HostEvent::Beacon(BeaconScopedInput::ParticipantTimer {
                participant,
                event: Box::new(event),
            })
        }
        TimerOwner::Beacon => HostEvent::beacon(event),
    }
}

// ═══════════════════════════════════════════════════════════════════════
// StepOutput — returned to the caller after processing an event
// ═══════════════════════════════════════════════════════════════════════

/// Output from processing a single event via `NodeHost::step()`.
///
/// Aggregates the per-step scratch from every hosted shard touched by
/// the event: emitted transaction statuses, timer operations, action
/// counts. Sync/fetch I/O and block-commit dispatch happen internally
/// via the `Network` and `Dispatch` traits — the runner only processes
/// emitted transaction statuses and timer operations.
#[derive(Default)]
pub struct StepOutput {
    /// Transaction status notifications emitted during this step.
    pub(crate) emitted_statuses: Vec<(TxHash, TransactionStatus)>,
    /// Number of actions generated by the state machine during this step.
    pub actions_generated: usize,
    /// Timer operations (set/cancel) to be processed by the runner.
    pub timer_ops: Vec<TimerOp>,
    /// Placement deltas emitted via [`BeaconAction::ReconfigureParticipation`](hyperscale_core::BeaconAction::ReconfigureParticipation)
    /// during this step. The runner reconfigures physical shard
    /// membership from these — they are requests to the process layer,
    /// not state-machine state.
    pub participation_changes: Vec<ParticipationChange>,
    /// Validators the loop attached to its replica during this step.
    pub attached: Vec<ValidatorId>,
    /// Shards whose store needs a height beneath every serving peer's
    /// chain floor. Block sync can never carry such a store forward; the
    /// runner rebuilds it at the shard's attested anchor.
    pub reseats: Vec<ShardId>,
}

impl StepOutput {
    /// Fold another step's output into this one. The whole-host driver
    /// ([`NodeHost::step`](crate::host::NodeHost::step)) uses this to
    /// aggregate the per-driver outputs of every shard and the beacon loop a
    /// single event touched.
    pub(crate) fn merge(&mut self, other: Self) {
        self.emitted_statuses.extend(other.emitted_statuses);
        self.actions_generated += other.actions_generated;
        self.timer_ops.extend(other.timer_ops);
        self.participation_changes
            .extend(other.participation_changes);
        self.attached.extend(other.attached);
        self.reseats.extend(other.reseats);
    }
}
