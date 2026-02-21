//! Protocol events for the deterministic state machine.
//!
//! [`ProtocolEvent`] contains only the events that [`NodeStateMachine`] actually
//! processes. I/O callbacks (sync, fetch, validation) are handled by [`NodeLoop`]
//! and never reach the state machine. This provides type-level enforcement of the
//! boundary between protocol logic and I/O orchestration.

use hyperscale_types::{
    Block, BlockHeader, BlockHeight, BlockVote, CommitmentProof, EpochConfig, EpochId, Hash,
    QuorumCertificate, RoutableTransaction, ShardGroupId, StateCertificate, StateEntry,
    StateProvision, StateVoteBlock, TransactionAbort, TransactionCertificate, TransactionDefer,
    ValidatorId,
};
use std::sync::Arc;

/// Events that the state machine processes.
///
/// These are the typed protocol events that [`NodeStateMachine::handle()`]
/// receives. No I/O callbacks, no intercepted events, no dead arms.
///
/// [`NodeLoop`] translates [`NodeInput`] into `ProtocolEvent` before passing
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
        retry_hashes: Vec<Hash>,
        priority_hashes: Vec<Hash>,
        tx_hashes: Vec<Hash>,
        cert_hashes: Vec<Hash>,
        deferred: Vec<TransactionDefer>,
        aborted: Vec<TransactionAbort>,
        commitment_proofs: std::collections::HashMap<Hash, CommitmentProof>,
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

    /// CycleProof signature verification completed.
    CycleProofVerified {
        block_hash: Hash,
        deferral_index: usize,
        valid: bool,
    },

    /// State root verification completed.
    StateRootVerified { block_hash: Hash, valid: bool },

    /// Transaction root verification completed.
    TransactionRootVerified { block_hash: Hash, valid: bool },

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
    /// JMT state commit completed for a block's certificates.
    StateCommitComplete {
        height: u64,
        state_version: u64,
        state_root: Hash,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Provisions
    // ═══════════════════════════════════════════════════════════════════════
    /// Received state provision for cross-shard execution.
    StateProvisionReceived { provision: StateProvision },

    /// Batch provision verification and aggregation completed.
    ProvisionsVerifiedAndAggregated {
        tx_hash: Hash,
        source_shard: ShardGroupId,
        verified_provisions: Vec<StateProvision>,
        commitment_proof: Option<CommitmentProof>,
    },

    /// Cross-shard transaction registered for provision tracking.
    CrossShardTxRegistered {
        tx_hash: Hash,
        required_shards: std::collections::BTreeSet<ShardGroupId>,
        quorum_thresholds: std::collections::HashMap<ShardGroupId, usize>,
        committed_height: BlockHeight,
    },

    /// Cross-shard transaction completed successfully.
    CrossShardTxCompleted { tx_hash: Hash },

    /// Cross-shard transaction aborted.
    CrossShardTxAborted { tx_hash: Hash },

    /// Quorum of provisions reached for a source shard.
    ProvisionQuorumReached {
        tx_hash: Hash,
        source_shard: ShardGroupId,
        commitment_proof: CommitmentProof,
    },

    /// All required shards have reached provision quorum - ready for execution.
    ProvisioningComplete {
        tx_hash: Hash,
        provisions: Vec<StateProvision>,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Execution
    // ═══════════════════════════════════════════════════════════════════════
    /// Received a state vote for cross-shard execution.
    StateVoteReceived { vote: StateVoteBlock },

    /// Received a state certificate for cross-shard execution.
    StateCertificateReceived { cert: StateCertificate },

    /// Batch state vote verification completed.
    StateVotesVerifiedAndAggregated {
        tx_hash: Hash,
        verified_votes: Vec<(StateVoteBlock, u64)>,
    },

    /// State certificate signature verification completed.
    StateCertificateSignatureVerified {
        certificate: StateCertificate,
        valid: bool,
    },

    /// State certificate aggregation completed.
    StateCertificateAggregated {
        tx_hash: Hash,
        certificate: StateCertificate,
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

    /// Transaction execution completed.
    TransactionExecuted { tx_hash: Hash, accepted: bool },

    /// A transaction's status has changed.
    TransactionStatusChanged {
        tx_hash: Hash,
        status: hyperscale_types::TransactionStatus,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Fetch Delivery (from NodeLoop after fetch protocol processing)
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
    // Gossiped Certificate (verified by NodeLoop)
    // ═══════════════════════════════════════════════════════════════════════
    /// A gossiped TransactionCertificate has been fully verified.
    GossipedCertificateVerified { certificate: TransactionCertificate },

    // ═══════════════════════════════════════════════════════════════════════
    // Storage Callbacks
    // ═══════════════════════════════════════════════════════════════════════
    /// State entries fetched for cross-shard provisioning.
    StateEntriesFetched {
        tx_hash: Hash,
        entries: Vec<StateEntry>,
    },

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
    // Sync Delivery (from NodeLoop after sync protocol processing)
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
            ProtocolEvent::BlockVoteReceived { .. } => "BlockVoteReceived",
            ProtocolEvent::QuorumCertificateFormed { .. } => "QuorumCertificateFormed",
            ProtocolEvent::BlockReadyToCommit { .. } => "BlockReadyToCommit",
            ProtocolEvent::BlockCommitted { .. } => "BlockCommitted",
            ProtocolEvent::QuorumCertificateResult { .. } => "QuorumCertificateResult",
            ProtocolEvent::QcSignatureVerified { .. } => "QcSignatureVerified",
            ProtocolEvent::CycleProofVerified { .. } => "CycleProofVerified",
            ProtocolEvent::StateRootVerified { .. } => "StateRootVerified",
            ProtocolEvent::TransactionRootVerified { .. } => "TransactionRootVerified",
            ProtocolEvent::ProposalBuilt { .. } => "ProposalBuilt",

            // State Commit
            ProtocolEvent::StateCommitComplete { .. } => "StateCommitComplete",

            // Provisions
            ProtocolEvent::StateProvisionReceived { .. } => "StateProvisionReceived",
            ProtocolEvent::ProvisionsVerifiedAndAggregated { .. } => {
                "ProvisionsVerifiedAndAggregated"
            }
            ProtocolEvent::CrossShardTxRegistered { .. } => "CrossShardTxRegistered",
            ProtocolEvent::CrossShardTxCompleted { .. } => "CrossShardTxCompleted",
            ProtocolEvent::CrossShardTxAborted { .. } => "CrossShardTxAborted",
            ProtocolEvent::ProvisionQuorumReached { .. } => "ProvisionQuorumReached",
            ProtocolEvent::ProvisioningComplete { .. } => "ProvisioningComplete",

            // Execution
            ProtocolEvent::StateVoteReceived { .. } => "StateVoteReceived",
            ProtocolEvent::StateCertificateReceived { .. } => "StateCertificateReceived",
            ProtocolEvent::StateVotesVerifiedAndAggregated { .. } => {
                "StateVotesVerifiedAndAggregated"
            }
            ProtocolEvent::StateCertificateSignatureVerified { .. } => {
                "StateCertificateSignatureVerified"
            }
            ProtocolEvent::StateCertificateAggregated { .. } => "StateCertificateAggregated",
            ProtocolEvent::SpeculativeExecutionComplete { .. } => "SpeculativeExecutionComplete",

            // Mempool / Transactions
            ProtocolEvent::TransactionGossipReceived { .. } => "TransactionGossipReceived",
            ProtocolEvent::TransactionExecuted { .. } => "TransactionExecuted",
            ProtocolEvent::TransactionStatusChanged { .. } => "TransactionStatusChanged",

            // Fetch Delivery
            ProtocolEvent::TransactionFetchDelivered { .. } => "TransactionFetchDelivered",
            ProtocolEvent::CertificateFetchDelivered { .. } => "CertificateFetchDelivered",
            ProtocolEvent::FetchedCertificateVerified { .. } => "FetchedCertificateVerified",

            // Gossiped Certificate
            ProtocolEvent::GossipedCertificateVerified { .. } => "GossipedCertificateVerified",

            // Storage Callbacks
            ProtocolEvent::StateEntriesFetched { .. } => "StateEntriesFetched",
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
