//! Protocol events for the deterministic state machine.
//!
//! [`ProtocolEvent`] contains only the events that [`NodeStateMachine`] actually
//! processes. I/O callbacks (sync, fetch, validation) are handled by [`IoLoop`]
//! and never reach the state machine. This provides type-level enforcement of the
//! boundary between protocol logic and I/O orchestration.

use hyperscale_types::{
    Block, BlockHash, BlockHeader, BlockHeight, BlockManifest, BlockVote, CertifiedBlock,
    CommittedBlockHeader, EpochConfig, EpochId, ExecutionCertificate, ExecutionVote, FinalizedWave,
    Provisions, QuorumCertificate, Round, RoutableTransaction, ShardGroupId, TxHash, TxOutcome,
    ValidatorId, WaveCertificate, WaveId, WeightedTimestamp,
};
use std::sync::Arc;

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
}

/// Events that the state machine processes.
///
/// These are the typed protocol events that [`NodeStateMachine::handle()`]
/// receives. No I/O callbacks, no intercepted events, no dead arms.
///
/// [`IoLoop`] translates [`NodeInput`] into `ProtocolEvent` before passing
/// to the state machine.
#[derive(Debug, Clone, strum::IntoStaticStr)]
pub enum ProtocolEvent {
    // ═══════════════════════════════════════════════════════════════════════
    // Timers
    // ═══════════════════════════════════════════════════════════════════════
    /// View change timeout fired — check if the leader has timed out.
    ViewChangeTimer,

    /// New proposable content is available (transactions, finalized waves, or provisions).
    /// Triggers event-driven proposal building.
    ContentAvailable,

    /// Periodic cleanup of stale state.
    CleanupTimer,

    /// Timer for global consensus operations.
    GlobalConsensusTimer,

    // ═══════════════════════════════════════════════════════════════════════
    // BFT Consensus
    // ═══════════════════════════════════════════════════════════════════════
    /// Received a block header from another node.
    BlockHeaderReceived {
        /// Block header received over gossip.
        header: BlockHeader,
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
    RemoteBlockCommitted {
        /// Header + QC bundle from the remote shard.
        committed_header: CommittedBlockHeader,
        /// Authenticated sender identity (BLS-verified by `IoLoop`).
        sender: ValidatorId,
    },

    /// Received a vote on a block header.
    BlockVoteReceived {
        /// Block vote received from a peer.
        vote: BlockVote,
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
        certified: CertifiedBlock,
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
        verified_votes: Vec<(usize, BlockVote, u64)>,
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
        /// The verified header.
        header: Arc<CommittedBlockHeader>,
        /// `true` when the QC passed verification.
        valid: bool,
    },

    /// A remote committed block header has been fully verified (QC + structural checks).
    ///
    /// Emitted by `RemoteHeaderCoordinator` as a continuation after QC verification.
    /// Downstream consumers (BFT, Provision, Execution) use this as their single
    /// source of verified remote headers.
    RemoteHeaderVerified {
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
        /// Finalized waves included in the block (carry certs + receipts + ECs).
        finalized_waves: Vec<Arc<FinalizedWave>>,
        /// Provisions included in the block.
        provisions: Vec<Arc<Provisions>>,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Provision
    // ═══════════════════════════════════════════════════════════════════════
    /// A provisions has been verified — ready for downstream consumption.
    ///
    /// `source_block_ts` is the BFT-authenticated weighted timestamp of the
    /// source shard's committing QC. Downstream consumers (notably the
    /// io-loop provision cache) anchor retention on this so eviction is
    /// deterministic across validators.
    ProvisionsVerified {
        /// Verified provisions batch.
        provisions: Arc<Provisions>,
        /// BFT-authenticated weighted timestamp of the source shard's committing QC.
        source_block_ts: WeightedTimestamp,
    },

    /// Received provisions from a source shard (light-client path).
    ///
    /// All transactions share the same `(source_shard, block_height)`
    /// because they originate from a single `FetchAndBroadcastProvisions` action.
    ProvisionsReceived {
        /// Provisions batch received from a source shard.
        provisions: Provisions,
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

    /// Batch-level provision verification completed.
    ///
    /// The QC is verified once for the source block's attestation; merkle
    /// proofs are checked against the verified state root. The committed
    /// header is returned so the state machine can promote it without
    /// re-lookup.
    StateProvisionsVerified {
        /// The verified provisions.
        provisions: Provisions,
        /// The committed header whose QC passed verification.
        /// `None` if no candidate header passed QC verification.
        committed_header: Option<Arc<CommittedBlockHeader>>,
        /// Whether the batch passed verification.
        valid: bool,
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
        /// Per-tx local execution entries (database updates + receipt).
        results: Vec<hyperscale_types::LocalExecutionEntry>,
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
        verified_votes: Vec<(ExecutionVote, u64)>,
    },

    /// Execution certificate aggregation completed.
    ExecutionCertificateAggregated {
        /// Wave whose EC was aggregated.
        wave_id: WaveId,
        /// The newly aggregated execution certificate.
        certificate: ExecutionCertificate,
    },

    /// Received an execution certificate from a remote shard.
    ExecutionCertificateReceived {
        /// Execution certificate received from a remote shard.
        cert: ExecutionCertificate,
    },

    /// Execution certificate signature verification completed.
    ExecutionCertificateSignatureVerified {
        /// The certificate whose signature was verified.
        certificate: ExecutionCertificate,
        /// `true` when the aggregated signature passed verification.
        valid: bool,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Mempool / Transactions
    // ═══════════════════════════════════════════════════════════════════════
    /// Received a transaction via gossip (or validated RPC submission).
    TransactionGossipReceived {
        /// The transaction.
        tx: Arc<RoutableTransaction>,
        /// `true` if this validator submitted the tx (don't gossip back to client).
        submitted_locally: bool,
    },

    /// An execution certificate was just admitted to the canonical EC store.
    ///
    /// Emitted by `ExecutionCoordinator::on_wave_certificate` for both
    /// broadcast-delivered and fetch-delivered certs. `io_loop` intercepts
    /// the matching `Continuation` arm and drains the exec-cert fetch
    /// protocol's in-flight tracking by `wave_id`.
    ExecutionCertificateAdmitted {
        /// Wave the certificate covers.
        wave_id: WaveId,
    },

    /// Finalized waves were just admitted to the canonical execution store.
    ///
    /// Emitted by `ExecutionCoordinator` (wrapped in `Action::Continuation`)
    /// for both locally finalized waves and fetch-delivered waves. Drives
    /// two consumers:
    ///
    /// - `io_loop` intercepts the matching `Continuation` arm and drains the
    ///   finalized-wave fetch protocol's in-flight tracking.
    /// - state.rs forwards the event to `bft.on_finalized_waves_admitted`,
    ///   which validates each wave's receipts against its EC and populates
    ///   any pending block waiting on its hash.
    FinalizedWavesAdmitted {
        /// Finalized waves newly admitted on this admission call.
        waves: Vec<Arc<FinalizedWave>>,
    },

    /// Transactions delivered by a fetch response. Routed straight to
    /// `MempoolCoordinator::on_fetched_transactions` for admission; the
    /// fetch-protocol drain happens via the resulting
    /// `Continuation(TransactionsAdmitted)` so all paths converge.
    TransactionsFetched {
        /// Block whose transactions were fetched (informational; not used by
        /// the admission path).
        block_hash: BlockHash,
        /// Fetched transactions to admit.
        txs: Vec<Arc<RoutableTransaction>>,
    },

    /// One or more transactions were just admitted to the canonical mempool.
    ///
    /// Emitted by `MempoolCoordinator` (wrapped in `Action::Continuation`) for
    /// every newly admitted batch, regardless of source (RPC, gossip, fetch,
    /// local production). Drives two downstream consumers:
    ///
    /// - `io_loop` intercepts the matching `Continuation` arm and drains the
    ///   transaction-fetch protocol's in-flight tracking.
    /// - state.rs forwards the event to `bft.on_transactions_admitted`, which
    ///   populates any pending block waiting on these hashes.
    ///
    /// Same shape as `RemoteHeaderVerified` / `ProvisionsVerified` —
    /// the canonical-store admission story is uniform across payloads.
    TransactionsAdmitted {
        /// Transactions newly admitted to mempool on this admission call.
        txs: Vec<Arc<RoutableTransaction>>,
    },

    /// A transaction's execution outcome has been resolved and certificate finalized.
    /// Used for per-tx mempool status updates.
    TransactionExecuted {
        /// Transaction whose execution outcome resolved.
        tx_hash: TxHash,
        /// `true` if the tx was accepted (state-changing) vs rejected.
        accepted: bool,
    },

    /// Local execution certificate created for a wave (local votes aggregated).
    ExecutionCertificateCreated {
        /// Transaction hashes covered by the newly-created EC.
        tx_hashes: Vec<TxHash>,
    },

    /// A wave's execution has been finalized (all shards reported).
    /// Carries the wave cert (which contains the ECs) and per-tx hashes.
    WaveCompleted {
        /// Finalized wave certificate (carries per-shard ECs).
        wave_cert: Arc<WaveCertificate>,
        /// Transaction hashes covered by the wave.
        tx_hashes: Vec<TxHash>,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Storage Callbacks
    // ═══════════════════════════════════════════════════════════════════════
    /// Chain metadata fetched from storage.
    ChainMetadataFetched {
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
    SyncBlockReadyToApply {
        /// The synced block + its certifying QC, ready to apply.
        certified: CertifiedBlock,
    },

    /// Sync EC BLS verification completed (async callback from crypto pool).
    SyncEcVerificationComplete {
        /// Height whose synced ECs were verified.
        height: BlockHeight,
        /// `true` when all ECs at this height passed verification.
        valid: bool,
    },

    /// The `io_loop`'s `SyncProtocol` has finished fetching all blocks up to
    /// the sync target. `BftCoordinator` should exit sync mode so it can re-enter
    /// if still behind, or resume normal consensus.
    SyncProtocolComplete {
        /// Height the sync protocol caught up to.
        height: BlockHeight,
    },

    /// Sync recovery complete — validator has caught up and is resuming consensus.
    /// Triggers immediate provision and remote header fetching so the validator
    /// can participate in execution for recent blocks within the timeout window.
    SyncResumed,

    // ═══════════════════════════════════════════════════════════════════════
    // Global Consensus / Epoch
    // ═══════════════════════════════════════════════════════════════════════
    /// Received a global block proposal from another validator.
    GlobalBlockReceived {
        /// Current epoch.
        epoch: EpochId,
        /// Height within the global chain.
        height: BlockHeight,
        /// Validator that proposed the block.
        proposer: ValidatorId,
        /// Hash of the proposed global block.
        block_hash: BlockHash,
        /// Next epoch configuration carried by this block, if it finalizes the epoch.
        next_epoch_config: Option<Box<EpochConfig>>,
    },

    /// Received a vote on a global block.
    GlobalBlockVoteReceived {
        /// Block being voted on.
        block_hash: BlockHash,
        /// Shard the vote came from.
        shard: ShardGroupId,
        /// Aggregated BLS signature from the shard's local quorum.
        shard_signature: hyperscale_types::Bls12381G2Signature,
        /// Bitfield of validators in the shard who signed.
        signers: hyperscale_types::SignerBitfield,
        /// Total voting power covered by the shard signature.
        voting_power: hyperscale_types::VotePower,
    },

    /// Global quorum certificate formed.
    GlobalQcFormed {
        /// Block the global QC certifies.
        block_hash: BlockHash,
        /// Epoch in which the QC was formed.
        epoch: EpochId,
    },

    /// Epoch transition is imminent.
    EpochEndApproaching {
        /// Epoch that's about to end.
        current_epoch: EpochId,
        /// Height at which the current epoch ends.
        end_height: BlockHeight,
    },

    /// Ready to transition to next epoch.
    EpochTransitionReady {
        /// Epoch we're transitioning from.
        from_epoch: EpochId,
        /// Epoch we're transitioning to.
        to_epoch: EpochId,
        /// Finalized configuration for the new epoch.
        next_config: Box<EpochConfig>,
    },

    /// Epoch transition completed.
    EpochTransitionComplete {
        /// The new epoch.
        new_epoch: EpochId,
        /// This validator's shard in the new epoch.
        new_shard: ShardGroupId,
        /// `true` if this validator is still syncing to the new shard before resuming consensus.
        is_waiting: bool,
    },

    /// Validator finished syncing to new shard after shuffle.
    ValidatorSyncComplete {
        /// Epoch this validator finished syncing for.
        epoch: EpochId,
        /// Shard this validator now serves.
        shard: ShardGroupId,
    },

    /// Shard split initiated.
    ShardSplitInitiated {
        /// Shard being split.
        source_shard: ShardGroupId,
        /// New shard ID being created from the split.
        new_shard: ShardGroupId,
        /// Hash range split point — accounts above go to `new_shard`.
        split_point: u64,
    },

    /// Shard split completed.
    ShardSplitComplete {
        /// Original shard whose split is complete.
        source_shard: ShardGroupId,
        /// Newly created shard now serving its range.
        new_shard: ShardGroupId,
    },

    /// Shard merge initiated.
    ShardMergeInitiated {
        /// First shard being merged.
        shard_a: ShardGroupId,
        /// Second shard being merged.
        shard_b: ShardGroupId,
        /// Resulting shard ID after merge.
        merged_shard: ShardGroupId,
    },

    /// Shard merge completed.
    ShardMergeComplete {
        /// The merged shard now serving the combined range.
        merged_shard: ShardGroupId,
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
            },
            other => other.into(),
        }
    }
}
