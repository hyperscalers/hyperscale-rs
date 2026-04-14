//! Protocol events for the deterministic state machine.
//!
//! [`ProtocolEvent`] contains only the events that [`NodeStateMachine`] actually
//! processes. I/O callbacks (sync, fetch, validation) are handled by [`IoLoop`]
//! and never reach the state machine. This provides type-level enforcement of the
//! boundary between protocol logic and I/O orchestration.

use hyperscale_types::{
    Block, BlockHeader, BlockHeight, BlockManifest, BlockVote, CommittedBlockHeader, EpochConfig,
    EpochId, ExecutionCertificate, ExecutionVote, FinalizedWave, Hash, Provision,
    QuorumCertificate, RoutableTransaction, ShardGroupId, TxOutcome, ValidatorId, WaveCertificate,
    WaveId,
};
use std::sync::Arc;

/// Which block root verification completed.
///
/// Used with `ProtocolEvent::BlockRootVerified` to identify which
/// verification finished. The actions that produce these results
/// remain separate (they have different input types), but the
/// callback event is unified because the handler logic is identical:
/// record result → check if all verifications complete → vote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationKind {
    StateRoot,
    TransactionRoot,
    CertificateRoot,
    LocalReceiptRoot,
    ProvisionRoot,
}

/// Events that the state machine processes.
///
/// These are the typed protocol events that [`NodeStateMachine::handle()`]
/// receives. No I/O callbacks, no intercepted events, no dead arms.
///
/// [`IoLoop`] translates [`NodeInput`] into `ProtocolEvent` before passing
/// to the state machine.
#[derive(Debug, Clone)]
pub enum ProtocolEvent {
    // ═══════════════════════════════════════════════════════════════════════
    // Timers
    // ═══════════════════════════════════════════════════════════════════════
    /// Time to propose a new block (if this node is the proposer).
    /// Also used for implicit round advancement when no QC is formed.
    ProposalTimer,

    /// Periodic cleanup of stale state.
    CleanupTimer,

    /// Timer for global consensus operations.
    GlobalConsensusTimer,

    // ═══════════════════════════════════════════════════════════════════════
    // BFT Consensus
    // ═══════════════════════════════════════════════════════════════════════
    /// Received a block header from another node.
    BlockHeaderReceived {
        header: BlockHeader,
        manifest: BlockManifest,
    },

    /// Received a committed block header from a remote shard (global broadcast).
    ///
    /// Used for the light-client provisions pattern: remote shards broadcast
    /// committed headers so we can verify state roots via merkle inclusion proofs.
    ///
    /// The `sender` field is the authenticated sender identity — IoLoop
    /// verified the sender's BLS signature before admitting this event.
    RemoteBlockCommitted {
        committed_header: CommittedBlockHeader,
        sender: ValidatorId,
    },

    /// Received a vote on a block header.
    BlockVoteReceived { vote: BlockVote },

    /// A quorum certificate was formed for a block.
    QuorumCertificateFormed {
        block_hash: Hash,
        qc: QuorumCertificate,
    },

    /// A block is ready to be committed.
    BlockReadyToCommit {
        block_hash: Hash,
        qc: QuorumCertificate,
    },

    /// A block was committed to storage (state + block data atomically).
    ///
    /// The handler calls JVT unblocking first (via state_root),
    /// then subsystem notifications.
    BlockCommitted {
        block_hash: Hash,
        height: u64,
        block: Block,
        /// JVT state root after committing this block's state changes.
        state_root: Hash,
        /// Provision batch hashes from the block manifest. Resolved to actual
        /// batch data by the consumer via the ProvisionCoordinator.
        provision_hashes: Vec<Hash>,
    },

    /// Quorum Certificate verification and building result.
    QuorumCertificateResult {
        block_hash: Hash,
        qc: Option<QuorumCertificate>,
        verified_votes: Vec<(usize, BlockVote, u64)>,
    },

    /// QC signature verification completed.
    QcSignatureVerified { block_hash: Hash, valid: bool },

    /// Remote header QC verification completed.
    RemoteHeaderQcVerified {
        shard: ShardGroupId,
        height: BlockHeight,
        header: Arc<CommittedBlockHeader>,
        valid: bool,
    },

    /// A remote committed block header has been fully verified (QC + structural checks).
    ///
    /// Emitted by `RemoteHeaderCoordinator` as a continuation after QC verification.
    /// Downstream consumers (BFT, Provision, Execution) use this as their single
    /// source of verified remote headers.
    RemoteHeaderVerified {
        committed_header: Arc<CommittedBlockHeader>,
    },

    /// A block root verification completed (state, transaction, certificate,
    /// local receipt, or abort intent proofs).
    ///
    /// The handler logic is identical for all kinds: record the result in the
    /// verification pipeline, check if all verifications are complete, and
    /// vote if so. The `kind` field distinguishes which verification finished.
    BlockRootVerified {
        kind: VerificationKind,
        block_hash: Hash,
        valid: bool,
    },

    /// Proposal block built by the runner.
    ProposalBuilt {
        height: BlockHeight,
        round: u64,
        block: Arc<Block>,
        block_hash: Hash,
        /// Finalized waves included in this block (carries receipts for atomic commit).
        finalized_waves: Vec<Arc<FinalizedWave>>,
        /// Provision batch hashes included in this block (for PendingBlock DA tracking).
        provision_hashes: Vec<Hash>,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Provision
    // ═══════════════════════════════════════════════════════════════════════
    /// A provision batch has been verified — ready for downstream consumption.
    ProvisionVerified { batch: Arc<Provision> },

    /// Received a provision batch from a source shard (light-client path).
    ///
    /// All provisions in a batch share the same `(source_shard, block_height)`
    /// because they originate from a single `FetchAndBroadcastProvision` action.
    StateProvisionReceived { batch: Provision },

    /// Batch-level provision verification completed.
    ///
    /// The QC is verified once for the batch's attestation; verkle proofs are
    /// checked against the verified state root. The committed header is returned
    /// so the state machine can promote it without re-lookup.
    StateProvisionVerified {
        /// The verified provision batch.
        batch: Provision,
        /// The committed header whose QC passed verification.
        /// `None` if no candidate header passed QC verification.
        committed_header: Option<Arc<CommittedBlockHeader>>,
        /// Whether the batch passed verification.
        valid: bool,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Execution
    // ═══════════════════════════════════════════════════════════════════════
    /// Batch of execution results from an ExecuteTransactions dispatch.
    ///
    /// Results carry the full execution output (DatabaseUpdates, receipts) — stays local.
    ///
    /// The state machine uses results to:
    /// 1. Store pending execution updates (co-located with TC at finalization)
    /// 2. Store receipts in receipt_cache for later finalized wave assembly
    ExecutionBatchCompleted {
        results: Vec<hyperscale_types::LocalExecutionEntry>,
        /// Per-tx outcomes extracted on the handler thread for vote signing.
        tx_outcomes: Vec<TxOutcome>,
    },

    /// Received an execution vote from another validator.
    ExecutionVoteReceived { vote: ExecutionVote },

    /// Batch execution vote verification completed.
    ExecutionVotesVerifiedAndAggregated {
        wave_id: WaveId,
        block_hash: Hash,
        verified_votes: Vec<(ExecutionVote, u64)>,
    },

    /// Execution certificate aggregation completed.
    ExecutionCertificateAggregated {
        wave_id: WaveId,
        certificate: ExecutionCertificate,
    },

    /// Received an execution certificate from a remote shard.
    ExecutionCertificateReceived { cert: ExecutionCertificate },

    /// Execution certificate signature verification completed.
    ExecutionCertificateSignatureVerified {
        certificate: ExecutionCertificate,
        valid: bool,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Mempool / Transactions
    // ═══════════════════════════════════════════════════════════════════════
    /// Received a transaction via gossip (or validated RPC submission).
    TransactionGossipReceived {
        tx: Arc<RoutableTransaction>,
        submitted_locally: bool,
    },

    /// A transaction's execution outcome has been resolved and certificate finalized.
    /// Used for per-tx mempool status updates.
    TransactionExecuted { tx_hash: Hash, accepted: bool },

    /// A cross-shard transaction's provisions have arrived.
    TransactionProvisioned { tx_hash: Hash },

    /// All transactions in a wave are ready (all provisioned or timed out).
    WaveReady { tx_hashes: Vec<Hash> },

    /// Local execution certificate created for a wave (local votes aggregated).
    ExecutionCertificateCreated { tx_hashes: Vec<Hash> },

    /// A wave's execution has been finalized (all shards reported).
    /// Carries the wave cert (which contains the ECs) and per-tx hashes.
    WaveCompleted {
        wave_cert: Arc<WaveCertificate>,
        tx_hashes: Vec<Hash>,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Fetch Delivery (from IoLoop after fetch protocol processing)
    // ═══════════════════════════════════════════════════════════════════════
    /// Fetched transactions delivered to state machine.
    TransactionFetchDelivered {
        block_hash: Hash,
        transactions: Vec<Arc<RoutableTransaction>>,
    },

    /// Fetched finalized wave delivered to state machine for pending block completion.
    FinalizedWaveFetchDelivered { wave: Arc<FinalizedWave> },

    // ═══════════════════════════════════════════════════════════════════════
    // Storage Callbacks
    // ═══════════════════════════════════════════════════════════════════════
    /// Chain metadata fetched from storage.
    ChainMetadataFetched {
        height: BlockHeight,
        hash: Option<Hash>,
        qc: Option<QuorumCertificate>,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Sync Delivery (from IoLoop after sync protocol processing)
    // ═══════════════════════════════════════════════════════════════════════
    /// A synced block is ready to be applied to local state.
    SyncBlockReadyToApply { block: Block, qc: QuorumCertificate },

    /// Sync EC BLS verification completed (async callback from crypto pool).
    SyncEcVerificationComplete { height: u64, valid: bool },

    /// Sync completed successfully.
    SyncComplete { height: u64 },

    // ═══════════════════════════════════════════════════════════════════════
    // Global Consensus / Epoch
    // ═══════════════════════════════════════════════════════════════════════
    /// Received a global block proposal from another validator.
    GlobalBlockReceived {
        epoch: EpochId,
        height: BlockHeight,
        proposer: ValidatorId,
        block_hash: Hash,
        next_epoch_config: Option<Box<EpochConfig>>,
    },

    /// Received a vote on a global block.
    GlobalBlockVoteReceived {
        block_hash: Hash,
        shard: ShardGroupId,
        shard_signature: hyperscale_types::Bls12381G2Signature,
        signers: hyperscale_types::SignerBitfield,
        voting_power: hyperscale_types::VotePower,
    },

    /// Global quorum certificate formed.
    GlobalQcFormed { block_hash: Hash, epoch: EpochId },

    /// Epoch transition is imminent.
    EpochEndApproaching {
        current_epoch: EpochId,
        end_height: BlockHeight,
    },

    /// Ready to transition to next epoch.
    EpochTransitionReady {
        from_epoch: EpochId,
        to_epoch: EpochId,
        next_config: Box<EpochConfig>,
    },

    /// Epoch transition completed.
    EpochTransitionComplete {
        new_epoch: EpochId,
        new_shard: ShardGroupId,
        is_waiting: bool,
    },

    /// Validator finished syncing to new shard after shuffle.
    ValidatorSyncComplete { epoch: EpochId, shard: ShardGroupId },

    /// Shard split initiated.
    ShardSplitInitiated {
        source_shard: ShardGroupId,
        new_shard: ShardGroupId,
        split_point: u64,
    },

    /// Shard split completed.
    ShardSplitComplete {
        source_shard: ShardGroupId,
        new_shard: ShardGroupId,
    },

    /// Shard merge initiated.
    ShardMergeInitiated {
        shard_a: ShardGroupId,
        shard_b: ShardGroupId,
        merged_shard: ShardGroupId,
    },

    /// Shard merge completed.
    ShardMergeComplete { merged_shard: ShardGroupId },
}

impl ProtocolEvent {
    /// Get the event type name for telemetry.
    pub fn type_name(&self) -> &'static str {
        match self {
            // Timers
            ProtocolEvent::ProposalTimer => "ProposalTimer",
            ProtocolEvent::CleanupTimer => "CleanupTimer",
            ProtocolEvent::GlobalConsensusTimer => "GlobalConsensusTimer",

            // BFT Consensus
            ProtocolEvent::BlockHeaderReceived { .. } => "BlockHeaderReceived",
            ProtocolEvent::RemoteBlockCommitted { .. } => "RemoteBlockCommitted",
            ProtocolEvent::BlockVoteReceived { .. } => "BlockVoteReceived",
            ProtocolEvent::QuorumCertificateFormed { .. } => "QuorumCertificateFormed",
            ProtocolEvent::BlockReadyToCommit { .. } => "BlockReadyToCommit",
            ProtocolEvent::BlockCommitted { .. } => "BlockCommitted",
            ProtocolEvent::QuorumCertificateResult { .. } => "QuorumCertificateResult",
            ProtocolEvent::QcSignatureVerified { .. } => "QcSignatureVerified",
            ProtocolEvent::RemoteHeaderQcVerified { .. } => "RemoteHeaderQcVerified",
            ProtocolEvent::RemoteHeaderVerified { .. } => "RemoteHeaderVerified",
            ProtocolEvent::BlockRootVerified { kind, .. } => match kind {
                VerificationKind::StateRoot => "BlockRootVerified::StateRoot",
                VerificationKind::TransactionRoot => "BlockRootVerified::TransactionRoot",
                VerificationKind::CertificateRoot => "BlockRootVerified::CertificateRoot",
                VerificationKind::LocalReceiptRoot => "BlockRootVerified::LocalReceiptRoot",
                VerificationKind::ProvisionRoot => "BlockRootVerified::ProvisionRoot",
            },
            ProtocolEvent::ProposalBuilt { .. } => "ProposalBuilt",

            // Provision
            ProtocolEvent::ProvisionVerified { .. } => "ProvisionVerified",
            ProtocolEvent::StateProvisionReceived { .. } => "StateProvisionReceived",
            ProtocolEvent::StateProvisionVerified { .. } => "StateProvisionVerified",

            // Execution
            ProtocolEvent::ExecutionBatchCompleted { .. } => "ExecutionBatchCompleted",
            ProtocolEvent::ExecutionVoteReceived { .. } => "ExecutionVoteReceived",
            ProtocolEvent::ExecutionVotesVerifiedAndAggregated { .. } => {
                "ExecutionVotesVerifiedAndAggregated"
            }
            ProtocolEvent::ExecutionCertificateAggregated { .. } => {
                "ExecutionCertificateAggregated"
            }
            ProtocolEvent::ExecutionCertificateReceived { .. } => "ExecutionCertificateReceived",
            ProtocolEvent::ExecutionCertificateSignatureVerified { .. } => {
                "ExecutionCertificateSignatureVerified"
            }

            // Mempool / Transactions
            ProtocolEvent::TransactionGossipReceived { .. } => "TransactionGossipReceived",
            ProtocolEvent::TransactionExecuted { .. } => "TransactionExecuted",
            ProtocolEvent::TransactionProvisioned { .. } => "TransactionProvisioned",
            ProtocolEvent::WaveReady { .. } => "WaveReady",
            ProtocolEvent::ExecutionCertificateCreated { .. } => "ExecutionCertificateCreated",
            ProtocolEvent::WaveCompleted { .. } => "WaveCompleted",

            // Fetch Delivery
            ProtocolEvent::TransactionFetchDelivered { .. } => "TransactionFetchDelivered",
            ProtocolEvent::FinalizedWaveFetchDelivered { .. } => "FinalizedWaveFetchDelivered",
            // Storage Callbacks
            ProtocolEvent::ChainMetadataFetched { .. } => "ChainMetadataFetched",

            // Sync Delivery
            ProtocolEvent::SyncEcVerificationComplete { .. } => "SyncEcVerificationComplete",
            ProtocolEvent::SyncBlockReadyToApply { .. } => "SyncBlockReadyToApply",
            ProtocolEvent::SyncComplete { .. } => "SyncComplete",

            // Global Consensus / Epoch
            ProtocolEvent::GlobalBlockReceived { .. } => "GlobalBlockReceived",
            ProtocolEvent::GlobalBlockVoteReceived { .. } => "GlobalBlockVoteReceived",
            ProtocolEvent::GlobalQcFormed { .. } => "GlobalQcFormed",
            ProtocolEvent::EpochEndApproaching { .. } => "EpochEndApproaching",
            ProtocolEvent::EpochTransitionReady { .. } => "EpochTransitionReady",
            ProtocolEvent::EpochTransitionComplete { .. } => "EpochTransitionComplete",
            ProtocolEvent::ValidatorSyncComplete { .. } => "ValidatorSyncComplete",
            ProtocolEvent::ShardSplitInitiated { .. } => "ShardSplitInitiated",
            ProtocolEvent::ShardSplitComplete { .. } => "ShardSplitComplete",
            ProtocolEvent::ShardMergeInitiated { .. } => "ShardMergeInitiated",
            ProtocolEvent::ShardMergeComplete { .. } => "ShardMergeComplete",
        }
    }
}
