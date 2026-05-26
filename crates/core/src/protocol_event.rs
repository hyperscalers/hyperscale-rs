//! Protocol events for the deterministic state machine.
//!
//! [`ProtocolEvent`] contains only the events that [`NodeStateMachine`] actually
//! processes. I/O callbacks (sync, fetch, validation) are handled by [`IoLoop`]
//! and never reach the state machine. This provides type-level enforcement of the
//! boundary between protocol logic and I/O orchestration.

use std::sync::Arc;

use hyperscale_types::{
    BeaconProposal, Block, BlockHash, BlockHeader, BlockHeight, BlockManifest, BlockVote,
    CertifiedBeaconBlock, CertifiedBlock, CommittedBlockHeader, Epoch, ExecutionCertificate,
    ExecutionVote, FinalizedWave, Provisions, QuorumCertificate, ReadySignal, Round,
    RoutableTransaction, ShardGroupId, ShardWitness, SkipEpochCert, SkipRequest, StoredReceipt,
    TxOutcome, ValidatorId, VotePower, WaveId, WeightedTimestamp,
};

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

/// Which block root verification completed.
///
/// Used with `ProtocolEvent::BlockRootVerified` to identify which
/// verification finished. The actions that produce these results
/// remain separate (they have different input types), but the
/// callback event is unified because the handler logic is identical:
/// record result → check if all verifications complete → vote.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerificationKind {
    /// State root computed by replaying the block's database updates against the JMT.
    StateRoot,
    /// Merkle root over the block's transactions plus per-tx validity-window check.
    TransactionRoot,
    /// Merkle root over included wave certificates' receipt hashes.
    CertificateRoot,
    /// Merkle root over the block's local receipts.
    LocalReceiptRoot,
    /// Merkle root over the block's provision-batch hashes.
    ProvisionRoot,
    /// Per-target-shard provision-tx merkle roots map.
    ProvisionTxRoots,
    /// Merkle root over the per-shard beacon-witness accumulator after this
    /// block's appended leaves.
    BeaconWitnessRoot,
}

/// Events that the state machine processes.
///
/// These are the typed protocol events that `NodeStateMachine::handle()`
/// receives. No I/O callbacks, no intercepted events, no dead arms.
///
/// `IoLoop` translates each `ShardEvent` into a `ProtocolEvent` before
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

    /// Received a committed block header from a remote shard (global broadcast).
    ///
    /// Used for the light-client provisions pattern: remote shards broadcast
    /// committed headers so we can verify state roots via merkle inclusion proofs.
    ///
    /// The `sender` field is the authenticated sender identity — `IoLoop`
    /// verified the sender's BLS signature before admitting this event.
    RemoteHeaderReceived {
        /// Header + QC bundle from the remote shard.
        committed_header: Arc<CommittedBlockHeader>,
        /// Authenticated sender identity (BLS-verified by `IoLoop`).
        sender: ValidatorId,
    },

    /// Received a vote on a block header.
    BlockVoteReceived {
        /// Block vote received from a peer.
        vote: BlockVote,
    },

    /// Received a validator's "ready on shard" signal.
    ///
    /// The sender's BLS signature over the signal has already been
    /// verified by `IoLoop` against their pubkey before this event is
    /// pushed. Admission to the shard coordinator's `ReadySignalPool`
    /// is a pure local-state update; the next proposer drains
    /// dwell-eligible signals into the block's
    /// [`BlockManifest::ready_signals`](hyperscale_types::BlockManifest::ready_signals).
    ReadySignalReceived {
        /// The signal received from `sender`.
        signal: ReadySignal,
    },

    /// A quorum certificate was formed for a block.
    QuorumCertificateFormed {
        /// Block the QC certifies.
        block_hash: BlockHash,
        /// The newly formed QC.
        qc: QuorumCertificate,
    },

    /// A block is ready to be committed.
    BlockReadyToCommit {
        /// Block being committed.
        block_hash: BlockHash,
        /// QC that triggers this commit (the next block's `parent_qc` under 2-chain).
        qc: QuorumCertificate,
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
        /// The committed block + its certifying QC.
        certified: Arc<CertifiedBlock>,
    },

    /// A block has been durably persisted to `RocksDB`.
    ///
    /// Fires after the async `RocksDB` write completes. Used for bookkeeping
    /// (persistence lag tracking) — not consensus-critical.
    /// The `height` is the highest block height in the persistence batch.
    BlockPersisted {
        /// Highest block height in the persistence batch that just completed.
        height: BlockHeight,
    },

    /// Quorum Certificate verification and building result.
    QuorumCertificateResult {
        /// Block hash the QC was assembled for.
        block_hash: BlockHash,
        /// The QC if quorum was reached, or `None` if not.
        qc: Option<QuorumCertificate>,
        /// Verified votes, returned for accumulation when no QC was built.
        verified_votes: Vec<(usize, BlockVote, VotePower)>,
    },

    /// QC signature verification completed.
    QcSignatureVerified {
        /// Block whose parent-QC signature was verified.
        block_hash: BlockHash,
        /// `true` when the aggregated signature passed verification.
        valid: bool,
    },

    /// Remote header QC verification completed.
    RemoteHeaderQcVerified {
        /// Remote shard that produced the header.
        shard: ShardGroupId,
        /// Remote block height (for correlation).
        height: BlockHeight,
        /// The verified committed header.
        committed_header: Arc<CommittedBlockHeader>,
        /// `true` when the QC passed verification.
        valid: bool,
    },

    /// A remote committed block header has been fully verified (QC + structural checks).
    ///
    /// Emitted by `RemoteHeaderCoordinator` as a continuation after QC verification.
    /// Downstream consumers (shard consensus, Provision, Execution) use this as their single
    /// source of verified remote headers.
    RemoteHeaderAdmitted {
        /// The fully-verified committed header.
        committed_header: Arc<CommittedBlockHeader>,
    },

    /// A block root verification completed (state, transaction, certificate,
    /// local receipt, or abort intent proofs).
    ///
    /// The handler logic is identical for all kinds: record the result in the
    /// verification pipeline, check if all verifications are complete, and
    /// vote if so. The `kind` field distinguishes which verification finished.
    BlockRootVerified {
        /// Which root verification just completed.
        kind: VerificationKind,
        /// Block whose root was verified.
        block_hash: BlockHash,
        /// `true` when the computed root matched the header's claim.
        valid: bool,
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
        /// Manifest carrying the proposer's drained `ready_signals`
        /// alongside the standard hash lists. Threaded back from
        /// `build_proposal` because `BlockManifest::from_block` can't
        /// recover `ready_signals` from a `Block` alone.
        manifest: BlockManifest,
        /// Finalized waves included in the block (carry certs + receipts + ECs).
        finalized_waves: Vec<Arc<FinalizedWave>>,
        /// Provisions included in the block.
        provisions: Vec<Arc<Provisions>>,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Provision
    // ═══════════════════════════════════════════════════════════════════════
    /// Received provisions from a source shard (light-client path).
    ///
    /// All transactions share the same `(source_shard, block_height)`
    /// because they originate from a single `FetchAndBroadcastProvisions` action.
    ProvisionsReceived {
        /// Provisions batch received from a source shard.
        provisions: Arc<Provisions>,
    },

    /// Batch-level provision verification completed.
    ///
    /// The QC is verified once for the source block's attestation; merkle
    /// proofs are checked against the verified state root. The committed
    /// header is returned so the state machine can promote it without
    /// re-lookup.
    StateProvisionsVerified {
        /// The verified provisions.
        provisions: Arc<Provisions>,
        /// The committed header whose QC passed verification.
        /// `None` if no candidate header passed QC verification.
        committed_header: Option<Arc<CommittedBlockHeader>>,
        /// Whether the batch passed verification.
        valid: bool,
    },

    /// A provisions has been verified — ready for downstream consumption.
    ///
    /// `source_block_ts` is the shard consensus-authenticated weighted timestamp of the
    /// source shard's committing QC. Downstream consumers (notably the
    /// io-loop provision cache) anchor retention on this so eviction is
    /// deterministic across validators.
    ProvisionsAdmitted {
        /// Verified provisions batch.
        provisions: Arc<Provisions>,
        /// BFT-authenticated weighted timestamp of the source shard's committing QC.
        source_block_ts: WeightedTimestamp,
    },

    /// Provisions our proposer generated were broadcast to a target shard.
    /// Routed to the `OutboundProvisionTracker` so they can be retained
    /// (and served from cache) until the target shard's execution
    /// certificates acknowledge every transaction in them.
    OutboundProvisionBroadcast {
        /// Provisions batch we just broadcast.
        provisions: Arc<Provisions>,
        /// Shard the batch was broadcast to.
        target_shard: ShardGroupId,
    },

    /// An execution certificate from a remote shard — for a wave that
    /// depended on state provisions from *this* shard — has been verified.
    /// The tracker uses `tx_outcomes` to drain pending transactions from
    /// outbound batches; `Executed` and `Aborted` are both terminal.
    OutboundEcObserved {
        /// Shard whose EC was observed.
        target_shard: ShardGroupId,
        /// Per-tx outcomes from the EC, used to drain matching outbound entries.
        tx_outcomes: Vec<TxOutcome>,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Execution
    // ═══════════════════════════════════════════════════════════════════════
    /// Batch of execution results from an `ExecuteTransactions` / `ExecuteCrossShardTransactions` dispatch.
    ///
    /// Results carry the full execution output (`DatabaseUpdates`, receipts) — stays local.
    /// Every result in this batch belongs to `wave_id`; the wave gets exactly
    /// one `ExecutionBatchCompleted` and no further results arrive for it.
    ///
    /// The state machine uses results to:
    /// 1. Store pending execution updates (co-located with TC at finalization)
    /// 2. Store receipts on the `WaveState` for later finalized wave assembly
    ExecutionBatchCompleted {
        /// The wave whose execution produced these results.
        wave_id: WaveId,
        /// Per-tx stored receipts (consensus portion + metadata) ready
        /// to be persisted alongside the wave's commit.
        results: Vec<StoredReceipt>,
        /// Per-tx outcomes extracted on the handler thread for vote signing.
        tx_outcomes: Vec<TxOutcome>,
    },

    /// Received an execution vote from another validator.
    ExecutionVoteReceived {
        /// Execution vote received from a peer.
        vote: ExecutionVote,
    },

    /// Batch execution vote verification completed.
    ExecutionVotesVerifiedAndAggregated {
        /// Wave whose votes were verified.
        wave_id: WaveId,
        /// Source block hash for correlation.
        block_hash: BlockHash,
        /// Verified votes paired with their voting power.
        verified_votes: Vec<(ExecutionVote, VotePower)>,
    },

    /// Execution certificate aggregation completed.
    ExecutionCertificateAggregated {
        /// Wave whose EC was aggregated.
        wave_id: WaveId,
        /// The newly aggregated execution certificate.
        certificate: Arc<ExecutionCertificate>,
    },

    /// Execution certificates delivered from any source — fetch response or
    /// peer broadcast (post sender-sig check). Each cert carries its own
    /// `(shard_group_id, block_height, wave_id)`. The state machine iterates
    /// the batch and routes each cert to `ExecutionCoordinator::on_wave_certificate`,
    /// which dispatches signature verification. The fetch protocol drain
    /// hooks this event by `wave_id`.
    ExecutionCertificatesReceived {
        /// Execution certificates to admit.
        certificates: Vec<ExecutionCertificate>,
    },

    /// Execution certificate signature verification completed.
    ExecutionCertificateSignatureVerified {
        /// The certificate whose signature was verified.
        certificate: Arc<ExecutionCertificate>,
        /// `true` when the aggregated signature passed verification.
        valid: bool,
    },

    /// All BLS verifications for a fetched [`FinalizedWave`] completed.
    ///
    /// Routed to `ExecutionCoordinator::on_finalized_wave_verified`, which
    /// emits the matching `Continuation(FinalizedWavesAdmitted)` only when
    /// every contained EC's signature passed.
    FinalizedWaveVerified {
        /// The wave whose ECs were verified.
        wave: Arc<FinalizedWave>,
        /// `true` when every contained EC's signature passed verification.
        valid: bool,
    },

    /// An execution certificate was just admitted to the canonical EC store.
    ///
    /// Emitted by `ExecutionCoordinator::on_certificate_verified` only when
    /// the aggregated BLS signature passes verification. Drives state-machine
    /// fan-out (cross-shard ACK observation, vote-action re-scan).
    ExecutionCertificateAdmitted {
        /// The verified certificate.
        certificate: Arc<ExecutionCertificate>,
    },

    /// Finalized waves delivered from a peer in response to a fetch request.
    ///
    /// Routed to `ExecutionCoordinator::admit_finalized_wave` per wave.
    /// The fetch protocol drain hooks the subsequent `FinalizedWavesAdmitted`
    /// continuation, not this event.
    FinalizedWavesReceived {
        /// Finalized waves returned by the peer.
        waves: Vec<Arc<FinalizedWave>>,
    },

    /// Finalized waves were just admitted to the canonical execution store.
    ///
    /// Emitted by `ExecutionCoordinator` (wrapped in `Action::Continuation`)
    /// for both locally finalized waves and fetch-delivered waves. Drives
    /// two consumers:
    ///
    /// - `io_loop` intercepts the matching `Continuation` arm and drains the
    ///   finalized-wave fetch protocol's in-flight tracking.
    /// - state.rs forwards the event to `shard.on_finalized_waves_admitted`,
    ///   which validates each wave's receipts against its EC and populates
    ///   any pending block waiting on its hash.
    FinalizedWavesAdmitted {
        /// Finalized waves newly admitted on this admission call.
        waves: Vec<Arc<FinalizedWave>>,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Mempool / Transactions
    // ═══════════════════════════════════════════════════════════════════════
    /// Transaction passed async validation. Routed to the state machine for
    /// mempool admission. Mempool emits `Continuation(TransactionsAdmitted)`
    /// for whatever it admits.
    TransactionValidated {
        /// The validated transaction.
        tx: Arc<RoutableTransaction>,
        /// `true` if this validator submitted the tx (don't gossip back to client).
        submitted_locally: bool,
    },

    /// Transactions delivered from a fetch request (raw, before mempool admission).
    ///
    /// Routed to `NodeStateMachine::on_transactions_fetched`, which funnels
    /// them through mempool admission. The fetch protocol drain hooks this
    /// event directly to drop every delivered hash from `in_flight`,
    /// including duplicates / tombstoned / validity-expired txs that won't
    /// surface via `TransactionsAdmitted`.
    TransactionsReceived {
        /// Transactions returned by the peer.
        transactions: Vec<Arc<RoutableTransaction>>,
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
        txs: Vec<Arc<RoutableTransaction>>,
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
        /// Latest QC found in storage, if present.
        qc: Option<QuorumCertificate>,
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

    /// The `io_loop`'s [`RemoteHeaderSync`] state machine caught
    /// `source_shard`'s committed-header chain up to `height`.
    /// `RemoteHeaderCoordinator` uses this to clear any "syncing" flag for
    /// that shard and resume normal per-gap behaviour.
    ///
    /// [`RemoteHeaderSync`]: ../../node/io_loop/sync/remote_header/type.RemoteHeaderSync.html
    RemoteHeaderSyncComplete {
        /// Source shard whose chain caught up.
        source_shard: ShardGroupId,
        /// Height the sync caught up to.
        height: BlockHeight,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Beacon consensus
    // ═══════════════════════════════════════════════════════════════════════
    /// PC inner-consensus vote received from a peer. Payload is the
    /// wire-form `PcVote` SBOR-encoded by the gossip decoder;
    /// `BeaconCoordinator` decodes and routes into the per-epoch
    /// `SpcInstance`.
    PcVoteReceived {
        /// Sender id (transport-level).
        from: ValidatorId,
        /// SBOR-encoded `VpcMsgPayload`.
        payload: Vec<u8>,
    },

    /// SPC-level message received from a peer.
    SpcMessageReceived {
        /// Sender id (transport-level).
        from: ValidatorId,
        /// SBOR-encoded `SpcMessage`.
        payload: Vec<u8>,
    },

    /// A beacon block arrived via gossip.
    BeaconBlockReceived {
        /// Received certified block.
        block: Arc<CertifiedBeaconBlock>,
    },

    /// A peer committee member's `BeaconProposal` arrived via gossip.
    /// `IoLoop` has already authenticated the sender and verified the
    /// proposal's VRF reveal against `(network.id, epoch)` — the
    /// coordinator gates admission on committee membership at the
    /// `epoch` and stores the proposal in its pool.
    BeaconProposalReceived {
        /// Authenticated sender id.
        from: ValidatorId,
        /// Epoch the proposal targets — bound by the verified VRF
        /// reveal inside `proposal`.
        epoch: Epoch,
        /// Received proposal.
        proposal: Arc<BeaconProposal>,
    },

    /// A `SkipRequest` arrived via gossip.
    SkipRequestReceived {
        /// Received request.
        request: Arc<SkipRequest>,
    },

    /// A standalone `SkipEpochCert` arrived via gossip. Useful for
    /// late-joining or syncing nodes that didn't observe the requests
    /// directly.
    SkipCertReceived {
        /// Received cert.
        cert: Arc<SkipEpochCert>,
    },

    /// A shard-witness fetch response landed. `BeaconCoordinator`
    /// validates the per-leaf Merkle proofs against the relevant
    /// `shard_header_records` entry and admits to the witness pool.
    ShardWitnessesReceived {
        /// Source shard that served the response.
        shard_id: ShardGroupId,
        /// Witnesses returned by the peer.
        witnesses: Vec<Arc<ShardWitness>>,
    },

    /// Result of an [`Action::VerifyBeaconBlock`] dispatch. The block
    /// rides back so the coordinator doesn't have to stash it during
    /// the verify round-trip.
    BeaconBlockVerified {
        /// The block whose cert was verified.
        block: Arc<CertifiedBeaconBlock>,
        /// Whether the cert check passed.
        valid: bool,
    },

    /// Result of an [`Action::VerifySkipRequest`] dispatch.
    SkipRequestVerified {
        /// The request whose BLS sig was verified.
        request: Box<SkipRequest>,
        /// Whether the sig check passed.
        valid: bool,
    },

    /// Beacon committee-start timer fired — the upcoming epoch's
    /// wall-clock boundary has been reached.
    BeaconCommitteeStartTimer,

    /// Beacon skip-trigger timer fired — the local vnode hasn't
    /// observed the expected commit within `SKIP_TIMEOUT` of its
    /// expected block time. If the local node is in the active pool,
    /// the coordinator emits a [`Action::BroadcastSkipRequest`]
    /// proposing to abandon the next epoch.
    BeaconSkipTimer,

    /// Beacon SPC view-timeout timer fired. The coordinator routes
    /// `SpcEvent::TimerExpired { view: spc.current_view() }` into
    /// the FSM — the inner PC instance fires its input even if the
    /// view's leader hasn't surfaced one.
    BeaconSpcViewTimer,

    /// A committed beacon block + its state have been persisted to
    /// `BeaconStorage`. `BeaconCoordinator` can now drop in-memory
    /// state tied to the pre-commit world.
    BeaconBlockPersisted {
        /// Epoch that was persisted.
        epoch: Epoch,
    },
}

impl ProtocolEvent {
    /// Get the event type name for telemetry.
    ///
    /// Variant names come from the `IntoStaticStr` derive; `BlockRootVerified`
    /// is sub-discriminated by `VerificationKind` so root-verification telemetry
    /// is attributable per root.
    #[must_use]
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::BlockRootVerified { kind, .. } => match kind {
                VerificationKind::StateRoot => "BlockRootVerified::StateRoot",
                VerificationKind::TransactionRoot => "BlockRootVerified::TransactionRoot",
                VerificationKind::CertificateRoot => "BlockRootVerified::CertificateRoot",
                VerificationKind::LocalReceiptRoot => "BlockRootVerified::LocalReceiptRoot",
                VerificationKind::ProvisionRoot => "BlockRootVerified::ProvisionRoot",
                VerificationKind::ProvisionTxRoots => "BlockRootVerified::ProvisionTxRoots",
                VerificationKind::BeaconWitnessRoot => "BlockRootVerified::BeaconWitnessRoot",
            },
            other => other.into(),
        }
    }
}
