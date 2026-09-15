//! Protocol events for the deterministic state machine.
//!
//! [`ProtocolEvent`] contains only the events that [`NodeStateMachine`] actually
//! processes. I/O callbacks (sync, fetch, validation) are handled by [`IoLoop`]
//! and never reach the state machine. This provides type-level enforcement of the
//! boundary between protocol logic and I/O orchestration.

use std::collections::BTreeSet;
use std::sync::Arc;

use hyperscale_engine::TickEnvironment;
use hyperscale_types::{
    Anchor, BeaconBlockHash, BeaconProposal, Block, BlockHash, BlockHeader, BlockHeight,
    BlockManifest, BlockVote, CandidateBeaconBlock, CandidateBeaconBlockVerifyError,
    CertifiedBeaconBlock, CertifiedBeaconBlockVerifyError, CertifiedBlock, CertifiedBlockHeader,
    CertifiedHeaderVerifyError, CheckOutcome, Epoch, ExecutionCertificate,
    ExecutionCertificateVerifyError, ExecutionVote, Finalization, FinalizationVerifyError, Hash,
    LeafIndex, MerkleInclusionProof, PcVote1, PcVote1VerifyError, PcVote2, PcVote2VerifyError,
    PcVote3, PcVote3VerifyError, Provisions, ProvisionsVerifyError, QcVerifyError,
    QuorumCertificate, RatifyPhase, RatifyRound, RatifyVote, RatifyVoteVerifyError, ReadySignal,
    Round, ShardForkProof, ShardId, ShardVoteEquivocation, ShardWitnessPayload, SpcEmptyViewMsg,
    SpcEmptyViewMsgVerifyError, SpcNewCommitMsg, SpcNewCommitMsgVerifyError, SpcProposalObject,
    SpcProposalObjectVerifyError, SpcView, StoredReceipt, SubstateKey, TickId, Timeout,
    Transaction, TxHash, TxOutcome, TxResolution, ValidatorId, Verifiable, VerificationKind,
    Verified, WeightedTimestamp,
};

use crate::action::CrossShardExecutionRequest;

/// What one tick's batch produced.
#[derive(Debug, Clone)]
pub struct TickBatchOutcome {
    /// The tick whose execution produced these results.
    pub tick_id: TickId,
    /// Per-member stored receipts (consensus portion + metadata) ready to
    /// be persisted alongside the settling block.
    pub results: Vec<StoredReceipt>,
    /// Per-member outcomes extracted on the handler thread for vote
    /// signing.
    pub tx_outcomes: Vec<TxOutcome>,
    /// Fee receipts built beside the execution receipts, for the
    /// transactions this shard pays for and a counterpart can still
    /// refuse. Held in reserve: an abort settles one of these in place of
    /// the discarded execution receipt.
    pub fee_receipts: Vec<StoredReceipt>,
}

/// How a node learned about the certifying QC that commits a given block.
///
/// Under the 2-chain rule, block N commits when the node observes QC_{N+1}.
/// A validator either aggregates that QC locally (if it was a vote recipient
/// for N+1) or learns it from block N+2's `parent_qc`. These two paths have
/// distinct latency characteristics, so tagging commits with their source
/// lets dashboards separate the modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitSource {
    /// Certifying QC was aggregated on this node.
    Aggregator,
    /// Certifying QC was learned from a subsequent block's `parent_qc`.
    Header,
    /// Block was applied via the sync protocol (historical catch-up).
    Sync,
}

impl CommitSource {
    /// Telemetry-friendly tag identifying how the certifying QC was learned.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Aggregator => "aggregator",
            Self::Header => "header",
            Self::Sync => "sync",
        }
    }
}

/// Events that the state machine processes.
///
/// These are the typed protocol events that `NodeStateMachine::handle()`
/// receives. No I/O callbacks, no intercepted events, no dead arms.
///
/// `IoLoop` translates each `HostEvent` into a `ProtocolEvent` before
/// passing it to the state machine.
#[derive(Debug, Clone, strum::IntoStaticStr)]
pub enum ProtocolEvent {
    // ═══════════════════════════════════════════════════════════════════════
    // Timers
    // ═══════════════════════════════════════════════════════════════════════
    /// View change timeout fired — check if the leader has timed out.
    ViewChangeTimer,

    /// Periodic cleanup of stale state.
    CleanupTimer,

    // ═══════════════════════════════════════════════════════════════════════
    // Shard Consensus
    // ═══════════════════════════════════════════════════════════════════════
    /// Received a block header from another node.
    BlockHeaderReceived {
        /// Block header received over gossip.
        header: Arc<BlockHeader>,
        /// Manifest listing the block's tx / cert / provision hashes.
        manifest: BlockManifest,
    },

    /// Received a committed block header from a remote shard whose QC
    /// still needs to be checked. Produced by gossip and sync paths —
    /// wire decode always lands the wrapper in `Verifiable::Unverified`.
    ///
    /// The `sender` field is the authenticated sender identity — `IoLoop`
    /// verified the sender's signature before admitting this event.
    UnverifiedRemoteHeaderReceived {
        /// Header + QC bundle from the remote shard.
        certified_header: Arc<CertifiedBlockHeader>,
        /// Authenticated sender identity (signature-verified by `IoLoop`).
        sender: ValidatorId,
    },

    /// Received a committed block header whose composite predicate already
    /// holds — produced only by the local-dispatch fast path when a
    /// colocated proposer's broadcast carries `Verifiable::Verified`.
    /// The recipient skips both the envelope signature check and
    /// `Action::VerifyRemoteHeaderQc`, admitting the header directly.
    VerifiedRemoteHeaderReceived {
        /// Header + QC bundle, sealed via
        /// [`Verified::<CertifiedBlockHeader>::from_qc_attestation`].
        certified_header: Arc<Verified<CertifiedBlockHeader>>,
        /// Authenticated sender identity (the local proposer).
        sender: ValidatorId,
    },

    /// Received a block vote whose signature has already been
    /// established at emit time.
    ///
    /// Produced only by the local sign-and-send handler, which routes
    /// our own signed vote back to the state machine for `VoteSet`
    /// tracking. Wire-arrived votes — even when the sender claims our
    /// validator id — take the [`Self::UnverifiedBlockVoteReceived`]
    /// path.
    VerifiedBlockVoteReceived {
        /// Our locally-signed vote, sealed via
        /// [`Verified::<BlockVote>::sign_local`].
        vote: Verified<BlockVote>,
    },

    /// Received a block vote whose signature still needs to be
    /// checked. Produced by the gossip handler after sender-batch
    /// authentication.
    UnverifiedBlockVoteReceived {
        /// Raw block vote off the wire.
        vote: BlockVote,
    },

    /// Our own locally-signed timeout, routed back to the state machine for
    /// the local `TimeoutKeeper`. Produced only by the sign-and-broadcast
    /// handler; wire-arrived timeouts take the
    /// [`Self::UnverifiedTimeoutReceived`] path.
    VerifiedTimeoutReceived {
        /// Our locally-signed timeout, sealed via
        /// [`Verified::<Timeout>::sign_local`].
        timeout: Verified<Timeout>,
    },

    /// Received a timeout whose signature share still needs to be checked. Produced
    /// by the gossip handler. The carried `high_qc` is verified separately
    /// (as a QC) only if it would advance the local `high_qc`.
    UnverifiedTimeoutReceived {
        /// Raw timeout off the wire.
        timeout: Timeout,
    },

    /// Received a validator's "ready on shard" signal.
    ///
    /// The sender's signature over the signal has already been
    /// verified by `IoLoop` against their pubkey before this event is
    /// pushed. Admission to the shard coordinator's `ReadySignalPool`
    /// is a pure local-state update; the next proposer drains
    /// dwell-eligible signals into the block's
    /// [`WitnessSources`](hyperscale_types::WitnessSources).
    ReadySignalReceived {
        /// The signal received from `sender`.
        signal: ReadySignal,
    },

    /// A quorum certificate was formed for a block.
    QuorumCertificateFormed {
        /// Block the QC certifies.
        block_hash: BlockHash,
        /// The newly formed QC. Verified by construction — built from
        /// pre-verified votes whose combined power cleared the quorum
        /// threshold in `verify_and_build_qc`.
        qc: Verified<QuorumCertificate>,
    },

    /// A block is ready to be committed.
    BlockReadyToCommit {
        /// Block + certifying QC, with the full
        /// [`Verified<CertifiedBlock>`] predicate established upstream
        /// — either by local per-root assembly (consensus path) or
        /// BFT-transitive trust in the source committee (sync path).
        certified: Arc<Verified<CertifiedBlock>>,
        /// How this node learned the certifying QC.
        source: CommitSource,
    },

    /// A block has been committed by consensus (QC formed, 2f+1 agreement).
    ///
    /// Fired immediately when the `CommitBlock` action arrives — before
    /// durable `RocksDB` persistence. All event data is carried in-memory
    /// from the action payload. Delegated actions that read substates use
    /// `PendingChain::view_at` to see unpersisted state.
    BlockCommitted {
        /// The committed block + its certifying QC. Wrapped as
        /// [`Verified<CertifiedBlock>`] so consumers see the typestate
        /// claim that the block, the QC, and the linkage are all
        /// verified — header verified, every applicable per-root
        /// verifier succeeded, QC's signature aggregate cleared the quorum
        /// threshold, and `qc.block_hash == block.hash()`. State-root
        /// verification rides the parallel pipeline path (see the doc
        /// on [`Verified<Block>`](hyperscale_types::Verified)).
        certified: Arc<Verified<CertifiedBlock>>,
    },

    /// A block has been durably persisted to `RocksDB`.
    ///
    /// Fires after the async `RocksDB` write completes. Used for
    /// persistence-lag bookkeeping, and to reconcile the coordinator's
    /// substate-byte frontier from storage — the path that keeps the
    /// frontier fresh through sync, where blocks commit QC-trusted with
    /// no per-block verification delta.
    /// The `height` is the highest block height in the persistence batch.
    BlockPersisted {
        /// Highest block height in the persistence batch that just completed.
        height: BlockHeight,
        /// Committed substate byte total at `height`, read back from
        /// storage. Authoritative when the event reaches the state
        /// machine — the shard loop fills it from storage while
        /// re-dispatching; the io worker's raw emission carries zero.
        substate_bytes: u64,
    },

    /// Quorum Certificate verification and building result.
    QuorumCertificateResult {
        /// Block hash the QC was assembled for.
        block_hash: BlockHash,
        /// The verified QC if quorum was reached, or `None` if not.
        qc: Option<Verified<QuorumCertificate>>,
        /// Verified votes, returned for accumulation when no QC was built.
        verified_votes: Vec<(usize, Verified<BlockVote>)>,
    },

    /// QC signature verification completed. The payload carries the
    /// verified QC directly so the consumer doesn't need a separate
    /// cache lookup after a positive result.
    QcSignatureVerified {
        /// Block whose parent-QC signature was verified.
        block_hash: BlockHash,
        /// Verified QC on success; the reason it failed otherwise.
        result: Result<Verified<QuorumCertificate>, QcVerifyError>,
    },

    /// Remote header QC verification completed.
    RemoteHeaderQcVerified {
        /// Remote shard that produced the header.
        shard: ShardId,
        /// Remote block height (for correlation).
        height: BlockHeight,
        /// Sender of the candidate header — needed by the coordinator to
        /// remove the failed candidate from its pending map on error.
        sender: ValidatorId,
        /// Verified composite on success (full predicate: QC verified +
        /// linkage check, BFT-transitive header trust via the source
        /// committee — see
        /// [`Verified::<CertifiedBlockHeader>::from_qc_attestation`]).
        /// QC-level signature/quorum failure or QC↔header linkage
        /// mismatch on error.
        result: Box<Result<Verified<CertifiedBlockHeader>, CertifiedHeaderVerifyError>>,
    },

    /// A remote committed block header has been fully verified (QC + structural checks).
    ///
    /// Emitted by `RemoteHeaderCoordinator` as a continuation after QC verification.
    /// Downstream consumers (shard consensus, Provision, Execution) use this as their single
    /// source of verified remote headers.
    RemoteHeaderAdmitted {
        /// The fully-verified certified header — predicate established by
        /// [`Verified::<CertifiedBlockHeader>::from_qc_attestation`].
        certified_header: Arc<Verified<CertifiedBlockHeader>>,
    },

    /// A remote header's commit proof is held: the `RemoteHeaderCoordinator`
    /// also holds the header's committing structure — a round-contiguous
    /// certified child, or a parent-hash link under a proven descendant for
    /// a block committed as the prefix of a later two-chain.
    ///
    /// Emitted at most once per `(shard, height)`, always after that
    /// header's `RemoteHeaderAdmitted`. Cross-shard consumption of the
    /// block's exports — provisions and execution certificates — gates on
    /// this event, not on admission: a bare QC certifies availability, and
    /// an f+1..2f corrupt committee can certify a sibling that never
    /// commits.
    RemoteHeaderCommitted {
        /// The commit-proven certified header.
        certified_header: Arc<Verified<CertifiedBlockHeader>>,
    },

    /// A shard committee's fork was assembled locally from two
    /// commit-proven conflicting headers at one `(shard, height)`. The
    /// proof is built from already-verified headers, so it needs no
    /// re-verification on this path; downstream buffers, re-gossips, and
    /// fences on it.
    ShardForkDetected {
        /// The self-proving fork evidence.
        proof: Box<ShardForkProof>,
    },

    /// A shard fork proof finished off-thread verification (the receive
    /// path for a gossiped or beacon-carried proof). `verified` is the
    /// verdict against the local schedule's committees.
    ShardForkProofVerified {
        /// The proof that was checked.
        proof: Box<ShardForkProof>,
        /// Whether it verified against the local topology.
        verified: bool,
    },

    /// A shard fork proof arrived over global gossip and still needs
    /// verification. The proof self-authenticates, so the receive path
    /// carries no sender trust — the state machine resolves committees
    /// from its own schedule and dispatches `VerifyShardForkProof`.
    UnverifiedShardForkProofReceived {
        /// The fork evidence off the wire.
        proof: Box<ShardForkProof>,
    },

    /// The local vote keeper caught a double-vote and built the pair.
    /// Already verified (both votes passed signature verification on
    /// receipt); downstream buffers it for the beacon and re-gossips.
    ShardVoteEquivocationDetected {
        /// The self-proving double-vote pair.
        evidence: Box<ShardVoteEquivocation>,
    },

    /// A gossiped double-vote pair finished off-thread verification.
    ShardVoteEquivocationVerified {
        /// The pair that was checked.
        evidence: Box<ShardVoteEquivocation>,
        /// Whether both signatures verify under the accused key.
        verified: bool,
    },

    /// A shard double-vote pair arrived over global gossip and still
    /// needs verification. Self-authenticating — no sender trust; the
    /// state machine resolves the accused pubkey from its topology and
    /// dispatches `VerifyShardVoteEquivocation`.
    UnverifiedShardVoteEquivocationReceived {
        /// The pair off the wire.
        evidence: Box<ShardVoteEquivocation>,
    },

    /// One check on a pending block completed: a root over one of its
    /// sections, its state root, its payers' reservations, the
    /// resolutions it names, or the state proofs it carries.
    ///
    /// The state root's replay also side-channels its `PreparedCommit`
    /// byproduct to the commit pipeline via `ActionContext::commit_prepared`
    /// — vnode-private `IoLoop` data that doesn't belong on this fan-out
    /// channel — and reports the net substate byte change it measured
    /// in the outcome.
    BlockCheckCompleted {
        /// Block the check ran on.
        block_hash: BlockHash,
        /// Which check.
        kind: VerificationKind,
        /// How it ended.
        outcome: CheckOutcome,
    },

    /// Proposal block built by the runner.
    ProposalBuilt {
        /// Height of the new block.
        height: BlockHeight,
        /// Round at which the proposal was built.
        round: Round,
        /// The constructed block.
        block: Arc<Block>,
        /// Hash of the constructed block, cached for callers.
        block_hash: BlockHash,
        /// Finalizations included in the block (carry certs + receipts + ECs).
        finalizations: Vec<Arc<Verifiable<Finalization>>>,
        /// Net substate byte total change from the build's JMT
        /// computation. Feeds the coordinator's count frontier for
        /// reshape-trigger derivation.
        bytes_delta: i64,
        /// Provisions included in the block.
        provisions: Vec<Arc<Verifiable<Provisions>>>,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Provision
    // ═══════════════════════════════════════════════════════════════════════
    /// Received provisions from a source shard whose merkle proof still
    /// needs to be checked. Produced by the gossip handler (wire decode
    /// always lands in `Verifiable::Unverified`) and by fetch-response
    /// drains.
    ///
    /// All transactions share the same `(source_shard, block_height)`
    /// because they originate from a single `FetchAndBroadcastProvisions` action.
    UnverifiedProvisionsReceived {
        /// Provisions batch received from a source shard.
        provisions: Arc<Provisions>,
    },

    /// Received provisions whose merkle proof predicate already holds —
    /// produced only by the local-dispatch fast path when a colocated
    /// source-shard vnode emits a notification carrying
    /// `Verifiable::Verified`. The recipient skips
    /// [`Action::VerifyProvisions`] and admits directly.
    ///
    /// [`Action::VerifyProvisions`]: crate::Action::VerifyProvisions
    VerifiedProvisionsReceived {
        /// Verified provisions batch sealed via
        /// [`Verified::<Provisions>::from_local`].
        provisions: Arc<Verified<Provisions>>,
    },

    /// Batch-level provision verification completed.
    ///
    /// The QC was verified upstream as part of promoting the source
    /// header to [`Verified<CertifiedBlockHeader>`]; merkle proofs are
    /// checked against the verified state root. The certified header is
    /// returned so the state machine can promote it without re-lookup.
    StateProvisionsVerified {
        /// Verified provisions on success; the raw bundle paired with
        /// its error on failure.
        result: Result<Arc<Verified<Provisions>>, (Arc<Provisions>, ProvisionsVerifyError)>,
        /// The certified header whose `state_root` the merkle proof was
        /// checked against.
        certified_header: Arc<Verified<CertifiedBlockHeader>>,
    },

    /// A provisions has been verified — ready for downstream consumption.
    ///
    /// `source_block_ts` is the shard consensus-authenticated weighted timestamp of the
    /// source shard's committing QC. Downstream consumers (notably the
    /// io-loop provision cache) anchor retention on this so eviction is
    /// deterministic across validators.
    ProvisionsAdmitted {
        /// Verified provisions batch.
        provisions: Arc<Verifiable<Provisions>>,
        /// BFT-authenticated weighted timestamp of the source shard's committing QC.
        source_block_ts: WeightedTimestamp,
    },

    /// Provisions our proposer generated were broadcast to a target shard.
    /// Routed to the `OutboundProvisionTracker` so they can be retained
    /// (and served from cache) until the target shard's execution
    /// certificates acknowledge every transaction in them.
    OutboundProvisionBroadcast {
        /// Provisions batch we just broadcast. Wrapped as `Verified` —
        /// the emitter built the bundle from a local JMT view so the
        /// merkle-proof predicate holds by construction.
        provisions: Arc<Verified<Provisions>>,
        /// Shard the batch was broadcast to.
        target_shard: ShardId,
    },

    /// An execution certificate from a remote shard — for a tick that
    /// depended on state provisions from *this* shard — has been verified.
    /// The tracker uses `tx_outcomes` to drain pending transactions from
    /// outbound batches; `Executed` and `Aborted` are both terminal.
    OutboundEcObserved {
        /// Shard whose EC was observed.
        target_shard: ShardId,
        /// Per-tx outcomes from the EC, used to drain matching outbound entries.
        tx_outcomes: Vec<TxOutcome>,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Execution
    // ═══════════════════════════════════════════════════════════════════════
    /// One tick's execution results from an `ExecuteTransactions`
    /// dispatch.
    ///
    /// Results carry the full execution output (writes, receipts) — stays
    /// local. A tick's batch completes once and no further results ever
    /// arrive for it. Its output has been appended to the tick chain
    /// before this event reaches the state machine, so the coordinator may
    /// dispatch the next tick on it.
    ExecutionBatchCompleted {
        /// The tick whose batch completed: the composing block's height.
        tick: BlockHeight,
        /// What the batch produced, fanned back to the tick that ran it.
        outcome: TickBatchOutcome,
    },

    /// A dispatched tick found this node unable to run a package one of
    /// its members names, so it produced nothing and comes back whole.
    ///
    /// Machine-local: the batch attested nothing, and the tick is still
    /// the one its committee composed. It returns to the dispatch head
    /// and waits there, the same wait a tick composed for code this node
    /// has not fetched already takes.
    ExecutionBatchUnavailable {
        /// The tick that came back unrun.
        tick: BlockHeight,
        /// Its anchor, carried back so the retry runs the same tick.
        tick_ts: WeightedTimestamp,
        /// Its environment, likewise.
        env: TickEnvironment,
        /// Its members, likewise.
        requests: Vec<CrossShardExecutionRequest>,
        /// The package this node could not run.
        package: Hash,
    },

    /// Received an execution vote. The tick leader's own sign-and-send
    /// feeds a sealed vote straight into the verified tally; a wire
    /// decode lands one unverified, and a colocated voter's batch keeps
    /// its marker. The early-arrivals buffer holds either taxonomy under
    /// one shape, so the marker rides on the payload rather than the arm.
    ExecutionVoteReceived {
        /// The vote, sealed via [`Verified::<ExecutionVote>::sign_local`]
        /// when its producer held the signing key.
        vote: Verifiable<ExecutionVote>,
    },

    /// Batch execution vote verification completed.
    ExecutionVotesVerifiedAndAggregated {
        /// Tick whose votes were verified.
        tick_id: TickId,
        /// Source block hash for correlation.
        block_hash: BlockHash,
        /// Verified votes.
        verified_votes: Vec<Verified<ExecutionVote>>,
    },

    /// Execution certificate aggregation completed.
    ExecutionCertificateAggregated {
        /// Tick whose EC was aggregated.
        tick_id: TickId,
        /// The newly aggregated execution certificate.
        certificate: Arc<Verified<ExecutionCertificate>>,
    },

    /// Execution certificates delivered from any source — fetch response or
    /// peer broadcast (post sender-sig check). Each cert carries its own
    /// `(shard_id, block_height, tick_id)`. The state machine iterates
    /// the batch and routes each cert to `ExecutionCoordinator::on_execution_certificate`,
    /// which dispatches signature verification. The fetch protocol drain
    /// hooks this event by `tick_id`.
    ExecutionCertificatesReceived {
        /// Execution certificates to admit. Wire-decoded entries land
        /// `Unverified`; a `Verifiable::Verified` entry short-circuits
        /// verify dispatch at the coordinator.
        certificates: Vec<Verifiable<ExecutionCertificate>>,
    },

    /// Execution certificate signature verification completed.
    ExecutionCertificateSignatureVerified {
        /// Verified certificate on success; the raw certificate plus
        /// the reason it failed otherwise.
        result: Result<
            Arc<Verified<ExecutionCertificate>>,
            (Arc<ExecutionCertificate>, ExecutionCertificateVerifyError),
        >,
    },

    /// All signature verifications for a fetched [`Finalization`] completed.
    ///
    /// Routed to `ExecutionCoordinator::on_finalization_verified`, which
    /// emits the matching `Continuation(FinalizationsAdmitted)` only when
    /// every contained EC's signature passed.
    FinalizationVerified {
        /// Verified tick on success; the raw tick plus the reason it
        /// failed otherwise.
        result: Result<Arc<Verified<Finalization>>, (Arc<Finalization>, FinalizationVerifyError)>,
    },

    /// An execution certificate was just admitted to the canonical EC store.
    ///
    /// Emitted by `ExecutionCoordinator::on_certificate_verified` only when
    /// the aggregated signature passes verification. Drives state-machine
    /// fan-out (cross-shard ACK observation, vote-action re-scan).
    ExecutionCertificateAdmitted {
        /// The admitted execution certificate.
        certificate: Arc<Verified<ExecutionCertificate>>,
    },

    /// Finalizations delivered from a peer in response to a fetch request.
    ///
    /// Routed to `ExecutionCoordinator::admit_finalization`, one at a time.
    /// The fetch protocol drain hooks the subsequent `FinalizationsAdmitted`
    /// continuation, not this event.
    FinalizationsReceived {
        /// Finalizations returned by the peer. Wire-decoded entries
        /// land `Unverified`; a `Verifiable::Verified` entry
        /// short-circuits verify dispatch at the coordinator.
        finalizations: Vec<Arc<Verifiable<Finalization>>>,
    },

    /// Finalizations were just admitted to the canonical execution store.
    ///
    /// Emitted by `ExecutionCoordinator` (wrapped in `Action::Continuation`)
    /// for both locally produced finalizations and fetch-delivered ones. Drives
    /// two consumers:
    ///
    /// - `io_loop` intercepts the matching `Continuation` arm and drains the
    ///   finalization fetch protocol's in-flight tracking.
    /// - state.rs forwards the event to `shard.on_finalizations_admitted`,
    ///   which validates each finalization's receipts against its EC and populates
    ///   any pending block waiting on its hash.
    FinalizationsAdmitted {
        /// Finalizations newly admitted on this admission call. Carried
        /// in the `Block::Live.certificates` transport shape — every
        /// entry is in the `Verifiable::Verified` variant by virtue of
        /// the typed gates the emitter went through (`finalize`'s
        /// `seal`, or `admit_finalization`'s `Verify::verify`).
        finalizations: Vec<Arc<Verifiable<Finalization>>>,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Mempool / Transactions
    // ═══════════════════════════════════════════════════════════════════════
    /// Transaction passed async validation. Routed to the state machine for
    /// mempool admission. Mempool emits `Continuation(TransactionsAdmitted)`
    /// for whatever it admits.
    TransactionValidated {
        /// The validated transaction.
        tx: Arc<Verified<Transaction>>,
        /// `true` if this validator submitted the tx (don't gossip back to client).
        submitted_locally: bool,
    },

    /// Transactions delivered from a fetch request, post-validation.
    ///
    /// Routed to `NodeStateMachine::on_transactions_fetched`, which funnels
    /// the batch through mempool admission. The fetch-FSM drain runs
    /// upstream on the raw delivery (`ShardScopedInput::TransactionsFetched`)
    /// so invalid-signature payloads don't pin in-flight slots; only
    /// signature-valid txs reach this event.
    TransactionsReceived {
        /// Transactions returned by the peer.
        transactions: Vec<Arc<Verified<Transaction>>>,
    },

    /// One or more transactions were just admitted to the canonical mempool.
    ///
    /// Emitted by `MempoolCoordinator` (wrapped in `Action::Continuation`) for
    /// every newly admitted batch, regardless of source (RPC, gossip, fetch,
    /// local production). Drives two downstream consumers:
    ///
    /// - `io_loop` intercepts the matching `Continuation` arm and drains the
    ///   transaction-fetch protocol's in-flight tracking.
    /// - state.rs forwards the event to `shard.on_transactions_admitted`, which
    ///   populates any pending block waiting on these hashes.
    ///
    /// Same shape as `RemoteHeaderAdmitted` / `ProvisionsAdmitted` —
    /// the canonical-store admission story is uniform across payloads.
    TransactionsAdmitted {
        /// Transactions newly admitted to mempool on this admission call.
        txs: Vec<Arc<Verified<Transaction>>>,
    },

    /// The execution coordinator settled what a core's certificates
    /// mean for transactions legs here issued for — refused, or accepted
    /// by every core shard — which its ledger alone can say. The mempool
    /// applies each to its entry's status.
    TransactionsResolved {
        /// Each transaction with what was settled about it.
        resolutions: Vec<(TxHash, TxResolution)>,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Storage Callbacks
    // ═══════════════════════════════════════════════════════════════════════
    /// Chain metadata fetched from storage.
    CommittedStateRestored {
        /// Highest committed height found in storage (`0` for fresh start).
        height: BlockHeight,
        /// Hash of the highest committed block, if present.
        hash: Option<BlockHash>,
        /// Latest QC found in storage, if present. Carried as
        /// `Verified<QuorumCertificate>` because storage holds only
        /// already-verified QCs.
        qc: Option<Verified<QuorumCertificate>>,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Sync Delivery (from IoLoop after sync protocol processing)
    // ═══════════════════════════════════════════════════════════════════════
    /// A synced block is ready to be applied to local state.
    BlockSyncReadyToApply {
        /// The synced block + its certifying QC, ready to apply.
        certified: Arc<CertifiedBlock>,
    },

    /// The `io_loop`'s [`BlockSync`] state machine has finished fetching all
    /// blocks up to the sync target. `ShardCoordinator` should exit sync mode
    /// so it can re-enter if still behind, or resume normal consensus.
    ///
    /// [`BlockSync`]: ../../node/io_loop/sync/block/type.BlockSync.html
    BlockSyncComplete {
        /// Height the sync caught up to.
        height: BlockHeight,
    },

    /// A synced beacon block is ready to apply. The runner's beacon
    /// `Sync` machine fetched it from a peer; `BeaconCoordinator` runs it
    /// through the same cert verification + adoption path as a gossiped
    /// block. Serial delivery guarantees `block.epoch() == tip + 1`.
    BeaconBlockSyncReadyToApply {
        /// The fetched block, wrapped `Unverified` — the coordinator
        /// dispatches cert verification before adopting.
        block: Arc<Verifiable<CertifiedBeaconBlock>>,
    },

    /// The `io_loop`'s [`RemoteHeaderSync`] state machine caught
    /// `source_shard`'s certified header chain up to `height`.
    /// `RemoteHeaderCoordinator` uses this to clear any "syncing" flag for
    /// that shard and resume normal per-gap behaviour.
    ///
    /// [`RemoteHeaderSync`]: ../../node/io_loop/sync/remote_header/type.RemoteHeaderSync.html
    RemoteHeaderSyncComplete {
        /// Source shard whose chain caught up.
        source_shard: ShardId,
        /// Height the sync caught up to.
        height: BlockHeight,
    },

    /// A cross-shard consumer is parked on a source block whose height sits
    /// at or below the shard's beacon-attested boundary — below the
    /// remote-header sync anchor, where forward sync never delivers the
    /// commit proof. `RemoteHeaderCoordinator` answers with a targeted
    /// [`Action::FetchCommitProof`](crate::Action::FetchCommitProof),
    /// retried until the height proves or ages out.
    CommitProofNeeded {
        /// Remote shard whose block needs commit-proving.
        source_shard: ShardId,
        /// The parked source height.
        block_height: BlockHeight,
    },

    /// A state proof fetched against a commit-proven remote header
    /// verified: it reconstructs the anchor's root and claims every key
    /// asked. The execution coordinator keeps the bytes to offer in a
    /// block it proposes; nothing reads an answer off a fetch, since
    /// the answer is the chain's once a block carries the proof.
    FetchedStateProofVerified {
        /// The state the proof was checked against.
        anchor: Anchor,
        /// The keys the proof was asked about.
        keys: Vec<SubstateKey>,
        /// The proof as fetched.
        proof: MerkleInclusionProof,
    },

    /// A settled-set fetch verified a past-terminal shard's complete
    /// settled-transaction set against its beacon-attested root. The
    /// execution coordinator records it for the split-boundary fence and
    /// releases what waited on it.
    SettledTxsReconstructed {
        /// The terminated shard whose settled set this is.
        shard: ShardId,
        /// Transactions that shard settled at or before its terminal block.
        txs: BTreeSet<TxHash>,
        /// The terminated shard's terminal weighted timestamp — bounds
        /// the fence's retention cutoff.
        terminal_wt: WeightedTimestamp,
    },

    /// A predecessor's committee answered which of the queried
    /// transactions it committed before terminating. Every `absent`
    /// answer here arrives already checked against that predecessor's
    /// `committed_txs_root`; a `committed` answer needs no proof, since
    /// it leaves the successor's standing refusal in place.
    ///
    /// `ShardCoordinator` records them and re-drives any vote that
    /// deferred for want of one.
    PrecutResolutionsReceived {
        /// The terminated chain that answered.
        predecessor: ShardId,
        /// One `(transaction, absent)` pair per answered query.
        answers: Vec<(TxHash, bool)>,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Beacon consensus
    // ═══════════════════════════════════════════════════════════════════════
    /// Round-1 PC vote received whose signature still needs to be
    /// checked. Produced by the gossip handler — wire decode lands the
    /// wrapper as `Verifiable::Unverified`.
    UnverifiedPcVote1Received {
        /// SPC view this vote belongs to.
        view: SpcView,
        /// The vote. Self-identifying via `vote.validator()`.
        vote: PcVote1,
    },

    /// Round-2 PC vote received whose signature still needs to be
    /// checked.
    UnverifiedPcVote2Received {
        /// SPC view this vote belongs to.
        view: SpcView,
        /// The vote. Self-identifying via `vote.validator()`.
        vote: Box<PcVote2>,
    },

    /// Round-3 PC vote received whose signature still needs to be
    /// checked.
    UnverifiedPcVote3Received {
        /// SPC view this vote belongs to.
        view: SpcView,
        /// The vote. Self-identifying via `vote.validator()`.
        vote: Box<PcVote3>,
    },

    /// Round-1 PC vote received whose verification predicate already
    /// holds — produced only by the local sign-and-emit handler (or by
    /// a colocated peer's local-dispatch fast path). The recipient
    /// skips [`Action::VerifyPcVote1`] and feeds the typed handle
    /// straight into the SPC sub-machine.
    ///
    /// [`Action::VerifyPcVote1`]: crate::Action::VerifyPcVote1
    VerifiedPcVote1Received {
        /// SPC view this vote belongs to.
        view: SpcView,
        /// Verified vote, sealed via [`Verified::<PcVote1>::sign_local`].
        /// Self-identifying via `vote.validator()`.
        vote: Verified<PcVote1>,
    },

    /// Round-2 PC vote received whose verification predicate already
    /// holds. Skips [`Action::VerifyPcVote2`].
    ///
    /// [`Action::VerifyPcVote2`]: crate::Action::VerifyPcVote2
    VerifiedPcVote2Received {
        /// SPC view this vote belongs to.
        view: SpcView,
        /// Verified vote, sealed via [`Verified::<PcVote2>::sign_local`].
        /// Self-identifying via `vote.validator()`.
        vote: Box<Verified<PcVote2>>,
    },

    /// Round-3 PC vote received whose verification predicate already
    /// holds. Skips [`Action::VerifyPcVote3`].
    ///
    /// [`Action::VerifyPcVote3`]: crate::Action::VerifyPcVote3
    VerifiedPcVote3Received {
        /// SPC view this vote belongs to.
        view: SpcView,
        /// Verified vote, sealed via [`Verified::<PcVote3>::sign_local`].
        /// Self-identifying via `vote.validator()`.
        vote: Box<Verified<PcVote3>>,
    },

    /// SPC `new-view` notification received from a peer. The proposal
    /// is self-authenticating; `from` only determines which validator's
    /// proposal-object slot the coordinator fills on admission. Wire
    /// decode lands the wrapper as `Unverified`; locally-relayed
    /// notifications preserve the `Verified` marker.
    SpcNewViewReceived {
        /// Sender id (transport-level).
        from: ValidatorId,
        /// Proposal object backing the entry.
        proposal: Arc<Verifiable<SpcProposalObject>>,
    },

    /// SPC `new-commit` notification received from a peer.
    /// Self-authenticating via the embedded `proof`; the sender label
    /// is carried for verification-pipeline bookkeeping only.
    SpcNewCommitReceived {
        /// Sender id (transport-level).
        from: ValidatorId,
        /// Committed-low message.
        msg: Arc<Verifiable<SpcNewCommitMsg>>,
    },

    /// SPC `empty-view` attestation received from a peer over the wire.
    /// The signer is carried inside `msg`; no separate transport-level
    /// sender id is needed.
    UnverifiedSpcEmptyViewReceived {
        /// The empty-view attestation.
        msg: Arc<Verifiable<SpcEmptyViewMsg>>,
    },

    /// SPC `empty-view` attestation whose verification predicate
    /// already holds — produced only by the local sign-and-emit
    /// handler. The coordinator skips [`Action::VerifySpcEmptyView`]
    /// and feeds the typed handle straight into the SPC sub-machine.
    ///
    /// [`Action::VerifySpcEmptyView`]: crate::Action::VerifySpcEmptyView
    VerifiedSpcEmptyViewReceived {
        /// Verified empty-view attestation, sealed via
        /// [`Verified::<SpcEmptyViewMsg>::sign_local`].
        msg: Box<Verified<SpcEmptyViewMsg>>,
    },

    /// A beacon block arrived via gossip. Wire decode lands the
    /// wrapper as `Unverified`; locally-relayed broadcasts preserve
    /// the `Verified` marker.
    BeaconBlockReceived {
        /// Received certified block.
        block: Arc<Verifiable<CertifiedBeaconBlock>>,
    },

    /// A peer committee member's `BeaconProposal` arrived over the
    /// wire. `IoLoop` has already authenticated the sender; the
    /// coordinator dispatches the VRF reveal check before admission.
    UnverifiedBeaconProposalReceived {
        /// Authenticated sender id.
        from: ValidatorId,
        /// Epoch the proposal targets — bound by the VRF reveal
        /// inside `proposal`.
        epoch: Epoch,
        /// Received proposal.
        proposal: Arc<Verifiable<BeaconProposal>>,
    },

    /// A locally-signed `BeaconProposal` arrived via the
    /// `Action::BuildAndBroadcastBeaconProposal` self-loopback path.
    /// The signing-key holder produced the VRF reveal, so the proposal
    /// is verified by construction — coordinator skips the VRF check
    /// and admits directly.
    VerifiedBeaconProposalReceived {
        /// Local validator id (the loopback sender).
        from: ValidatorId,
        /// Epoch the proposal targets.
        epoch: Epoch,
        /// Verified proposal, sealed via
        /// [`Verified::<BeaconProposal>::sign_local`].
        proposal: Arc<Verified<BeaconProposal>>,
    },

    /// A [`RatifyVote`] arrived over the wire. Wire decode lands the
    /// wrapper as `Unverified`; locally-relayed broadcasts preserve
    /// the marker.
    UnverifiedRatifyVoteReceived {
        /// Received vote.
        vote: Arc<Verifiable<RatifyVote>>,
    },

    /// A locally-signed [`RatifyVote`] arrived via the
    /// [`Action::SignAndBroadcastRatifyVote`] self-loopback path. The
    /// signing validator produced the signature, so the vote is verified
    /// by construction — coordinator skips
    /// [`Action::VerifyRatifyVote`] and pools it directly.
    ///
    /// [`Action::SignAndBroadcastRatifyVote`]: crate::Action::SignAndBroadcastRatifyVote
    /// [`Action::VerifyRatifyVote`]: crate::Action::VerifyRatifyVote
    VerifiedRatifyVoteReceived {
        /// Verified vote, sealed via
        /// [`Verified::<RatifyVote>::sign_local`].
        vote: Arc<Verified<RatifyVote>>,
    },

    /// A [`CandidateBeaconBlock`] arrived over the wire — an SPC output
    /// awaiting ratification. Wire decode lands the wrapper as
    /// `Unverified`; the locally-assembled candidate reaches the
    /// tracker directly and never takes this path.
    BeaconCandidateReceived {
        /// Received candidate.
        candidate: Arc<Verifiable<CandidateBeaconBlock>>,
    },

    /// Result of an [`Action::VerifyBeaconCandidate`] dispatch. The
    /// verified handle rides back on success so the coordinator can
    /// route it into the ratification tracker without stashing during
    /// the verify round-trip.
    ///
    /// [`Action::VerifyBeaconCandidate`]: crate::Action::VerifyBeaconCandidate
    BeaconCandidateVerified {
        /// Verified candidate on success; the typed error otherwise.
        result: Result<Arc<Verified<CandidateBeaconBlock>>, CandidateBeaconBlockVerifyError>,
    },

    /// A shard-witness chunk landed. `BeaconCoordinator` recomputes the
    /// anchor block's witness-window root from the payloads plus the range
    /// proof and admits the run whole.
    ShardWitnessesReceived {
        /// Source shard that served the response.
        shard_id: ShardId,
        /// Anchor block the run proves against.
        committed_block_hash: BlockHash,
        /// First leaf of the returned run.
        lo: LeafIndex,
        /// Payloads in leaf-index order, starting at `lo`.
        payloads: Vec<ShardWitnessPayload>,
        /// Flanking nodes lifting `payloads` to the anchor's witness root.
        range_proof: Vec<Hash>,
    },

    /// Result of a beacon-proposal fetch dispatch — carries a
    /// proposal the peer returned. A responder that didn't hold the
    /// proposal yields no event: the fetch binding releases the slot for
    /// retry against another peer instead. Wire decode lands the wrapper
    /// as `Verifiable::Unverified`; locally-dispatched serves preserve the
    /// `Verified` marker.
    ///
    BeaconProposalFetched {
        /// Epoch the fetched proposal targets.
        epoch: Epoch,
        /// Validator whose proposal was requested.
        validator: ValidatorId,
        /// The returned proposal.
        proposal: Arc<Verifiable<BeaconProposal>>,
    },

    /// Result of an [`Action::VerifyBeaconBlock`](crate::Action::VerifyBeaconBlock) dispatch. The
    /// verified handle rides back on success so the coordinator can
    /// route it into adoption without stashing during the verify
    /// round-trip.
    BeaconBlockVerified {
        /// Verified block on success; the typed error otherwise.
        result: Result<Arc<Verified<CertifiedBeaconBlock>>, CertifiedBeaconBlockVerifyError>,
    },

    /// Result of an [`Action::VerifyRatifyVote`] dispatch.
    ///
    /// [`Action::VerifyRatifyVote`]: crate::Action::VerifyRatifyVote
    RatifyVoteVerified {
        /// Vote anchor, extracted from the unverified payload at
        /// dispatch time. Carried with the epoch, round, phase, and
        /// signer in both result arms so the coordinator can clear the
        /// per-signer pipeline slot regardless of the verify outcome.
        anchor: BeaconBlockHash,
        /// Epoch the vote ratifies.
        epoch: Epoch,
        /// Round the vote was cast in.
        round: RatifyRound,
        /// Prevote or precommit.
        phase: RatifyPhase,
        /// Claimed signer; keys the verification slot alongside the
        /// anchor and epoch.
        signer: ValidatorId,
        /// Verified vote on success; the typed error otherwise.
        result: Result<Verified<RatifyVote>, RatifyVoteVerifyError>,
    },

    /// Result of an [`Action::VerifyPcVote1`](crate::Action::VerifyPcVote1) dispatch. The verified
    /// handle rides back so the coordinator can route it into the right
    /// view's inner PC sub-machine without stashing.
    PcVote1Verified {
        /// Epoch the inner PC instance belongs to.
        epoch: Epoch,
        /// SPC view whose inner PC produced this vote.
        view: SpcView,
        /// Vote signer, extracted from the unverified payload at
        /// dispatch time. Carried in both result arms so the coordinator
        /// can clear the per-`(epoch, view, signer, round)` pipeline
        /// slot regardless of the verify outcome.
        signer: ValidatorId,
        /// Verified vote on success; the typed error otherwise.
        result: Result<Verified<PcVote1>, PcVote1VerifyError>,
    },

    /// Result of an [`Action::VerifyPcVote2`](crate::Action::VerifyPcVote2) dispatch.
    PcVote2Verified {
        /// Epoch the inner PC instance belongs to.
        epoch: Epoch,
        /// SPC view whose inner PC produced this vote.
        view: SpcView,
        /// Vote signer; see [`Self::PcVote1Verified::signer`].
        signer: ValidatorId,
        /// Verified vote on success; the typed error otherwise.
        result: Result<Verified<PcVote2>, PcVote2VerifyError>,
    },

    /// Result of an [`Action::VerifyPcVote3`](crate::Action::VerifyPcVote3) dispatch.
    PcVote3Verified {
        /// Epoch the inner PC instance belongs to.
        epoch: Epoch,
        /// SPC view whose inner PC produced this vote.
        view: SpcView,
        /// Vote signer; see [`Self::PcVote1Verified::signer`].
        signer: ValidatorId,
        /// Verified vote on success; the typed error otherwise.
        result: Result<Verified<PcVote3>, PcVote3VerifyError>,
    },

    /// Result of an [`Action::VerifySpcNewView`](crate::Action::VerifySpcNewView) dispatch.
    SpcNewViewVerified {
        /// Epoch the SPC instance belongs to.
        epoch: Epoch,
        /// Sender of the `NewView`.
        from: ValidatorId,
        /// View this `NewView` advances into, extracted from the
        /// unverified payload at dispatch time. Carried in both result
        /// arms so the coordinator can clear the
        /// per-`(epoch, view, sender, kind)` pipeline slot regardless
        /// of the verify outcome.
        view: SpcView,
        /// Verified proposal on success; the typed error otherwise.
        result: Result<Verified<SpcProposalObject>, SpcProposalObjectVerifyError>,
    },

    /// Result of an [`Action::VerifySpcNewCommit`](crate::Action::VerifySpcNewCommit) dispatch.
    SpcNewCommitVerified {
        /// Epoch the SPC instance belongs to.
        epoch: Epoch,
        /// Wire-level sender — used by the coordinator to clear its
        /// per-`(epoch, view, sender)` pipeline slot.
        from: ValidatorId,
        /// View this commit was produced in; see
        /// [`Self::SpcNewViewVerified::view`].
        view: SpcView,
        /// Verified new-commit message on success; the typed error
        /// otherwise.
        result: Result<Verified<SpcNewCommitMsg>, SpcNewCommitMsgVerifyError>,
    },

    /// Result of an [`Action::VerifySpcEmptyView`](crate::Action::VerifySpcEmptyView) dispatch.
    SpcEmptyViewVerified {
        /// Epoch the SPC instance belongs to.
        epoch: Epoch,
        /// Empty-view signer, extracted from the unverified payload at
        /// dispatch time; see [`Self::SpcNewViewVerified::view`].
        from: ValidatorId,
        /// View this empty-view attestation skips; see
        /// [`Self::SpcNewViewVerified::view`].
        view: SpcView,
        /// Verified attestation on success; the typed error otherwise.
        result: Result<Verified<SpcEmptyViewMsg>, SpcEmptyViewMsgVerifyError>,
    },

    /// Beacon committee-start timer fired — the upcoming epoch's
    /// wall-clock boundary has been reached.
    BeaconCommitteeStartTimer,

    /// Beacon ratify timer fired. The first fire past the pending
    /// epoch's deadline makes the canonical skip hash prevotable;
    /// each subsequent fire is a ratify round timeout. If the local
    /// node is in the active pool, the coordinator drives its
    /// prevote/precommit effects and re-arms the timer at
    /// `RATIFY_ROUND_TIMEOUT` while the epoch is undecided.
    BeaconRatifyTimer,

    /// Beacon SPC view-timeout timer fired. The coordinator routes
    /// `SpcEvent::TimerExpired { view: spc.current_view() }` into
    /// the FSM — the inner PC instance fires its input even if the
    /// view's leader hasn't surfaced one.
    BeaconSpcViewTimer,

    /// `TimerId::BeaconSpcInputDwell` fired: the proposal-collection
    /// dwell after SPC bootstrap elapsed — feed the view-1 PC input
    /// from the pool if the fast path hasn't already.
    BeaconSpcInputDwellTimer,

    /// A committed beacon block + its state have been persisted to
    /// `BeaconStorage`. `BeaconCoordinator` can now drop in-memory
    /// state tied to the pre-commit world.
    BeaconBlockPersisted {
        /// Epoch that was persisted.
        epoch: Epoch,
    },
}

impl ProtocolEvent {
    /// Get the event type name for telemetry. Falls through to the
    /// `IntoStaticStr` derive.
    #[must_use]
    pub fn type_name(&self) -> &'static str {
        self.into()
    }
}
