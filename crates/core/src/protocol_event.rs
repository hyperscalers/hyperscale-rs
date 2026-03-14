//! Protocol events for the deterministic state machine.
//!
//! [`ProtocolEvent`] contains only the events that [`NodeStateMachine`] actually
//! processes. I/O callbacks (sync, fetch, validation) are handled by [`IoLoop`]
//! and never reach the state machine. This provides type-level enforcement of the
//! boundary between protocol logic and I/O orchestration.

use hyperscale_types::{
    Block, BlockHeader, BlockHeight, BlockManifest, BlockVote, CommitmentProof,
    CommittedBlockHeader, EpochConfig, EpochId, ExecutionCertificate, ExecutionVote, Hash,
    QuorumCertificate, RoutableTransaction, ShardGroupId, StateProvision, TransactionCertificate,
    ValidatorId,
};
use std::sync::Arc;

/// Result of verifying a single provision within a batch.
#[derive(Debug, Clone)]
pub struct ProvisionVerificationResult {
    /// Transaction hash for correlation.
    pub tx_hash: Hash,
    /// Source shard the provision is from.
    pub source_shard: ShardGroupId,
    /// Whether the merkle inclusion proof verified against the committed state root.
    pub valid: bool,
    /// The provision that was verified.
    pub provision: StateProvision,
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

    /// A block was committed to storage.
    BlockCommitted {
        block_hash: Hash,
        height: u64,
        block: Block,
    },

    /// Quorum Certificate verification and building result.
    QuorumCertificateResult {
        block_hash: Hash,
        qc: Option<QuorumCertificate>,
        verified_votes: Vec<(usize, BlockVote, u64)>,
    },

    /// QC signature verification completed.
    QcSignatureVerified { block_hash: Hash, valid: bool },

    /// CommitmentProof signature verification completed.
    CommitmentProofVerified {
        block_hash: Hash,
        deferral_index: usize,
        valid: bool,
    },

    /// State root verification completed.
    StateRootVerified { block_hash: Hash, valid: bool },

    /// Transaction root verification completed.
    TransactionRootVerified { block_hash: Hash, valid: bool },

    /// Receipt root verification completed.
    ReceiptRootVerified { block_hash: Hash, valid: bool },

    /// Proposal block built by the runner.
    ProposalBuilt {
        height: BlockHeight,
        round: u64,
        block: Arc<Block>,
        block_hash: Hash,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // State Commit
    // ═══════════════════════════════════════════════════════════════════════
    /// JMT state commit completed for a block.
    /// The JMT version always equals the block height.
    StateCommitComplete { height: u64, state_root: Hash },

    // ═══════════════════════════════════════════════════════════════════════
    // Provisions
    // ═══════════════════════════════════════════════════════════════════════
    /// Cross-shard transaction registered for provision tracking.
    CrossShardTxRegistered {
        tx_hash: Hash,
        required_shards: std::collections::BTreeSet<ShardGroupId>,
        committed_height: BlockHeight,
    },

    /// A provision from a source shard has been verified and accepted.
    ProvisionAccepted {
        tx_hash: Hash,
        source_shard: ShardGroupId,
        commitment_proof: CommitmentProof,
    },

    /// All required shards have reached provision quorum - ready for execution.
    ProvisioningComplete {
        tx_hash: Hash,
        provisions: Vec<StateProvision>,
    },

    /// Received a batch of state provisions from a source shard (light-client path).
    ///
    /// All provisions in a batch share the same `(source_shard, block_height)`
    /// because they originate from a single `FetchAndBroadcastProvisions` action.
    StateProvisionsReceived { provisions: Vec<StateProvision> },

    /// Batch state provision QC + merkle proof verification completed.
    ///
    /// The QC is verified once across all candidates; merkle proofs are checked
    /// per provision. The verified header is returned so the state machine can
    /// promote it without re-lookup.
    StateProvisionsVerified {
        results: Vec<ProvisionVerificationResult>,
        /// The committed header whose QC passed verification.
        /// `None` if no candidate header passed QC verification.
        committed_header: Option<CommittedBlockHeader>,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Execution
    // ═══════════════════════════════════════════════════════════════════════
    /// Received an execution vote for cross-shard execution.
    ExecutionVoteReceived { vote: ExecutionVote },

    /// Batch of execution results from a single ExecuteTransactions or SpeculativeExecute dispatch.
    ///
    /// Votes are lightweight (receipt_hash + write_nodes) — suitable for network gossip.
    /// Results carry the full execution output (DatabaseUpdates, receipts) — stays local.
    ///
    /// The state machine uses results to:
    /// 1. Populate ExecutionCache (in-memory, for block commit fast path)
    /// 2. Dispatch StoreReceiptBundles action (for canonical execution only)
    ExecutionBatchCompleted {
        votes: Vec<ExecutionVote>,
        results: Vec<hyperscale_types::ExecutionResult>,
        /// True when this batch came from speculative execution.
        /// Receipt bundles are only persisted for canonical (non-speculative) execution.
        speculative: bool,
    },

    /// Received an execution certificate for cross-shard execution.
    ExecutionCertificateReceived { cert: ExecutionCertificate },

    /// Batch execution vote verification completed.
    ExecutionVotesVerifiedAndAggregated {
        tx_hash: Hash,
        verified_votes: Vec<(ExecutionVote, u64)>,
    },

    /// Execution certificate signature verification completed.
    ExecutionCertificateSignatureVerified {
        certificate: ExecutionCertificate,
        valid: bool,
    },

    /// Execution certificate aggregation completed.
    ExecutionCertificateAggregated {
        tx_hash: Hash,
        certificate: ExecutionCertificate,
    },

    /// Speculative execution of single-shard transactions completed.
    SpeculativeExecutionComplete {
        block_hash: Hash,
        tx_hashes: Vec<Hash>,
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
    TransactionExecuted { tx_hash: Hash, accepted: bool },

    // ═══════════════════════════════════════════════════════════════════════
    // Fetch Delivery (from IoLoop after fetch protocol processing)
    // ═══════════════════════════════════════════════════════════════════════
    /// Fetched transactions delivered to state machine.
    TransactionFetchDelivered {
        block_hash: Hash,
        transactions: Vec<Arc<RoutableTransaction>>,
    },

    /// Fetched certificates delivered to state machine.
    CertificateFetchDelivered {
        block_hash: Hash,
        certificates: Vec<TransactionCertificate>,
    },

    /// A fetched certificate has been verified.
    FetchedCertificateVerified {
        block_hash: Hash,
        certificate: TransactionCertificate,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Storage Callbacks
    // ═══════════════════════════════════════════════════════════════════════
    /// Block fetched from storage.
    BlockFetched {
        height: BlockHeight,
        block: Option<Block>,
    },

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
            ProtocolEvent::CommitmentProofVerified { .. } => "CommitmentProofVerified",
            ProtocolEvent::StateRootVerified { .. } => "StateRootVerified",
            ProtocolEvent::TransactionRootVerified { .. } => "TransactionRootVerified",
            ProtocolEvent::ReceiptRootVerified { .. } => "ReceiptRootVerified",
            ProtocolEvent::ProposalBuilt { .. } => "ProposalBuilt",

            // State Commit
            ProtocolEvent::StateCommitComplete { .. } => "StateCommitComplete",

            // Provisions
            ProtocolEvent::CrossShardTxRegistered { .. } => "CrossShardTxRegistered",
            ProtocolEvent::ProvisionAccepted { .. } => "ProvisionAccepted",
            ProtocolEvent::ProvisioningComplete { .. } => "ProvisioningComplete",
            ProtocolEvent::StateProvisionsReceived { .. } => "StateProvisionsReceived",
            ProtocolEvent::StateProvisionsVerified { .. } => "StateProvisionsVerified",

            // Execution
            ProtocolEvent::ExecutionVoteReceived { .. } => "ExecutionVoteReceived",
            ProtocolEvent::ExecutionBatchCompleted { .. } => "ExecutionBatchCompleted",
            ProtocolEvent::ExecutionCertificateReceived { .. } => "ExecutionCertificateReceived",
            ProtocolEvent::ExecutionVotesVerifiedAndAggregated { .. } => {
                "ExecutionVotesVerifiedAndAggregated"
            }
            ProtocolEvent::ExecutionCertificateSignatureVerified { .. } => {
                "ExecutionCertificateSignatureVerified"
            }
            ProtocolEvent::ExecutionCertificateAggregated { .. } => {
                "ExecutionCertificateAggregated"
            }
            ProtocolEvent::SpeculativeExecutionComplete { .. } => "SpeculativeExecutionComplete",

            // Mempool / Transactions
            ProtocolEvent::TransactionGossipReceived { .. } => "TransactionGossipReceived",
            ProtocolEvent::TransactionExecuted { .. } => "TransactionExecuted",

            // Fetch Delivery
            ProtocolEvent::TransactionFetchDelivered { .. } => "TransactionFetchDelivered",
            ProtocolEvent::CertificateFetchDelivered { .. } => "CertificateFetchDelivered",
            ProtocolEvent::FetchedCertificateVerified { .. } => "FetchedCertificateVerified",

            // Storage Callbacks
            ProtocolEvent::BlockFetched { .. } => "BlockFetched",
            ProtocolEvent::ChainMetadataFetched { .. } => "ChainMetadataFetched",

            // Sync Delivery
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
