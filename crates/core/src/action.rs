//! Action types for the deterministic state machine.

use crate::{message::OutboundMessage, Event, TimerId};
use hyperscale_types::{
    Block, BlockHeight, BlockVote, EpochConfig, EpochId, ExecutionResult, Hash, NodeId, PublicKey,
    QuorumCertificate, RoutableTransaction, ShardGroupId, Signature, SignerBitfield,
    StateCertificate, StateEntry, StateProvision, StateVoteBlock, TransactionCertificate,
    ValidatorId, VotePower,
};
use std::sync::Arc;
use std::time::Duration;

/// A request to execute a cross-shard transaction with its provisions.
#[derive(Debug, Clone)]
pub struct CrossShardExecutionRequest {
    /// Transaction hash (for correlation).
    pub tx_hash: Hash,
    /// The transaction to execute.
    pub transaction: Arc<RoutableTransaction>,
    /// State provisions from other shards.
    pub provisions: Vec<StateProvision>,
}

/// Actions the state machine wants to perform.
///
/// Actions are **commands** - they describe something to do.
/// The runner executes actions and may convert results back into events.
#[derive(Debug, Clone)]
pub enum Action {
    // ═══════════════════════════════════════════════════════════════════════
    // Network: Generic (for BFT consensus and mempool)
    // ═══════════════════════════════════════════════════════════════════════
    /// Broadcast a message to all nodes in a shard.
    ///
    /// Production uses gossipsub with topic-based routing.
    /// Simulation routes to all nodes in the shard.
    ///
    /// Used for BFT consensus messages (BlockHeader, BlockVote) and mempool
    /// (TransactionGossip). Execution messages use domain-specific actions below.
    BroadcastToShard {
        shard: ShardGroupId,
        message: OutboundMessage,
    },

    /// Broadcast a message to all nodes in the network.
    BroadcastGlobal { message: OutboundMessage },

    // ═══════════════════════════════════════════════════════════════════════
    // Network: Execution Layer (domain-specific, batchable by runner)
    // ═══════════════════════════════════════════════════════════════════════
    /// Broadcast a state vote to the local shard.
    ///
    /// The runner may batch multiple votes into a single network message
    /// for efficiency. State machines emit individual votes.
    BroadcastStateVote {
        shard: ShardGroupId,
        vote: StateVoteBlock,
    },

    /// Broadcast a state certificate to participating shards.
    ///
    /// The runner may batch multiple certificates into a single network message
    /// for efficiency. State machines emit individual certificates.
    BroadcastStateCertificate {
        shard: ShardGroupId,
        certificate: StateCertificate,
    },

    /// Broadcast a state provision to a target shard.
    ///
    /// The runner may batch multiple provisions into a single network message
    /// for efficiency. State machines emit individual provisions.
    BroadcastStateProvision {
        shard: ShardGroupId,
        provision: StateProvision,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Timers
    // ═══════════════════════════════════════════════════════════════════════
    /// Set a timer to fire after a duration.
    SetTimer { id: TimerId, duration: Duration },

    /// Cancel a previously set timer.
    CancelTimer { id: TimerId },

    // ═══════════════════════════════════════════════════════════════════════
    // Internal (fed back as events with Internal priority)
    // ═══════════════════════════════════════════════════════════════════════
    /// Enqueue an internal event for immediate processing.
    ///
    /// Internal events are processed at the same timestamp with higher
    /// priority than external events, preserving causality.
    EnqueueInternal { event: Event },

    // ═══════════════════════════════════════════════════════════════════════
    // Delegated Work (async, returns callback event)
    // ═══════════════════════════════════════════════════════════════════════
    /// Verify block votes and build a Quorum Certificate if quorum is reached.
    ///
    /// This combines vote verification and QC building into a single operation:
    /// 1. Batch-verifies all vote signatures using `batch_verify_bls_same_message`
    /// 2. If enough valid votes for quorum: aggregates signatures into a QC
    /// 3. If not enough valid votes: returns the verified votes so state machine
    ///    can wait for more votes
    ///
    /// This avoids wasting CPU on votes that will never be used (e.g., when a
    /// block never reaches quorum due to view change or leader failure).
    ///
    /// Delegated to a thread pool in production, instant in simulation.
    /// Returns `Event::QuorumCertificateResult` when complete.
    VerifyAndBuildQuorumCertificate {
        /// Block hash the QC would be for.
        block_hash: Hash,
        /// Block height.
        height: BlockHeight,
        /// Round number.
        round: u64,
        /// Parent block hash (from the block's header).
        parent_block_hash: Hash,
        /// The signing message (domain_tag || shard_group || height || round || block_hash).
        /// Pre-computed by state machine since it has the shard_group context.
        signing_message: Vec<u8>,
        /// Votes to verify and potentially aggregate.
        /// Each tuple is (committee_index, vote, public_key, voting_power).
        votes_to_verify: Vec<(usize, BlockVote, PublicKey, u64)>,
        /// Already-verified votes (e.g., our own vote).
        /// Each tuple is (committee_index, vote, voting_power).
        verified_votes: Vec<(usize, BlockVote, u64)>,
        /// Total voting power in the committee (for quorum calculation).
        total_voting_power: u64,
    },

    /// Batch verify and aggregate provisions (cross-shard Phase 2).
    ///
    /// Verifies all provision signatures and aggregates valid ones into a CommitmentProof.
    /// This combines verification and aggregation into a single operation, avoiding
    /// wasted work on provisions that might never reach quorum.
    ///
    /// Delegated to a thread pool in production, instant in simulation.
    /// Returns `Event::ProvisionsVerifiedAndAggregated` when complete.
    VerifyAndAggregateProvisions {
        /// Transaction hash for correlation.
        tx_hash: Hash,
        /// Source shard the provisions are from.
        source_shard: ShardGroupId,
        /// Block height when provisions were created.
        block_height: BlockHeight,
        /// State entries (from first provision - all should match).
        entries: Vec<StateEntry>,
        /// Provisions to verify and aggregate.
        provisions: Vec<StateProvision>,
        /// Public keys for each provision (same order as provisions).
        public_keys: Vec<PublicKey>,
        /// Committee size (for SignerBitfield capacity).
        committee_size: usize,
    },

    /// Aggregate state votes into a StateCertificate (vote quorum reached).
    ///
    /// Performs BLS signature aggregation which is compute-intensive.
    /// Delegated to a thread pool in production, instant in simulation.
    /// Returns `Event::StateCertificateAggregated` when complete.
    AggregateStateCertificate {
        /// Transaction hash for correlation.
        tx_hash: Hash,
        /// Shard group that executed.
        shard: ShardGroupId,
        /// Merkle root of the execution outputs.
        merkle_root: Hash,
        /// Votes to aggregate (with quorum).
        votes: Vec<StateVoteBlock>,
        /// Read nodes (for certificate).
        read_nodes: Vec<NodeId>,
        /// Total voting power of the votes.
        voting_power: VotePower,
        /// Committee size (for SignerBitfield capacity).
        committee_size: usize,
    },

    /// Batch verify state votes and aggregate valid ones (cross-shard Phase 4).
    ///
    /// Similar to `VerifyAndAggregateProvisions`, this defers verification until
    /// we have enough votes to possibly reach quorum. This avoids wasting CPU on
    /// votes that will never be used.
    ///
    /// The runner:
    /// 1. Batch-verifies all vote signatures (faster than individual verification)
    /// 2. Reports which votes passed verification with their voting power
    ///
    /// Delegated to a thread pool in production, instant in simulation.
    /// Returns `Event::StateVotesVerifiedAndAggregated` when complete.
    VerifyAndAggregateStateVotes {
        /// Transaction hash for correlation.
        tx_hash: Hash,
        /// Votes to verify with their public keys and voting power.
        /// Each tuple is (vote, public_key, voting_power).
        votes: Vec<(StateVoteBlock, PublicKey, u64)>,
    },

    /// Verify a state certificate's aggregated signature (cross-shard Phase 5).
    ///
    /// Delegated to a thread pool in production, instant in simulation.
    /// Returns `Event::StateCertificateSignatureVerified` when complete.
    VerifyStateCertificateSignature {
        /// The certificate to verify.
        certificate: StateCertificate,
        /// Public keys of the signers (in committee order, pre-resolved by state machine).
        public_keys: Vec<PublicKey>,
    },

    /// Verify a Quorum Certificate's aggregated BLS signature.
    ///
    /// This is CRITICAL for BFT safety: we must verify that the QC's aggregated signature
    /// was actually produced by the claimed signers. Without this check, a Byzantine proposer
    /// could include a fake QC with invalid signatures.
    ///
    /// Delegated to a thread pool in production, instant in simulation.
    /// Returns `Event::QcSignatureVerified` when complete.
    VerifyQcSignature {
        /// The QC to verify.
        qc: QuorumCertificate,
        /// Public keys of the signers (pre-resolved by state machine from QC's signer bitfield).
        public_keys: Vec<PublicKey>,
        /// The block hash this QC verification is associated with (for correlation).
        /// This is the hash of the block whose header contains this QC as parent_qc.
        block_hash: Hash,
        /// The signing message (domain_tag || shard_group || height || round || qc.block_hash).
        /// Pre-computed by state machine since it has the shard_group context.
        signing_message: Vec<u8>,
    },

    /// Execute a batch of single-shard transactions.
    ///
    /// Delegated to the engine thread pool in production, instant in simulation.
    /// Returns `Event::TransactionsExecuted` when complete.
    ExecuteTransactions {
        block_hash: Hash,
        transactions: Vec<Arc<RoutableTransaction>>,
        state_root: Hash,
    },

    /// Speculatively execute single-shard transactions before block commit.
    ///
    /// Triggered when a block header is received, before the block commits via
    /// the 2-chain rule. This hides execution latency behind consensus latency.
    ///
    /// Results are cached and used when the block commits, if no conflicting
    /// writes have occurred. If a speculative result is invalidated (due to
    /// committed writes to the read set), the transaction falls back to normal
    /// execution on commit.
    ///
    /// Returns `Event::SpeculativeExecutionComplete` when complete.
    SpeculativeExecute {
        /// Block hash where these transactions appear.
        block_hash: Hash,
        /// Single-shard transactions to execute speculatively.
        transactions: Vec<Arc<RoutableTransaction>>,
    },

    /// Execute a cross-shard transaction with provisioned state.
    ///
    /// Used after 2PC provisioning completes. The runner accumulates these actions
    /// and executes them in parallel batches for efficiency.
    /// Returns `Event::CrossShardTransactionsExecuted` when the batch completes.
    ExecuteCrossShardTransaction {
        /// Transaction hash (for correlation).
        tx_hash: Hash,
        /// The transaction to execute.
        transaction: Arc<RoutableTransaction>,
        /// State provisions from other shards.
        provisions: Vec<StateProvision>,
    },

    /// Sign execution results and broadcast votes.
    ///
    /// Used when execution results are already available (e.g., speculative execution cache hits).
    /// The runner signs each result, broadcasts the vote, and sends `StateVoteReceived`
    /// for local handling.
    SignExecutionResults {
        /// Execution results to sign and broadcast.
        results: Vec<ExecutionResult>,
    },

    /// Compute a merkle root from state changes.
    ///
    /// Delegated to a thread pool in production, instant in simulation.
    /// Returns `Event::MerkleRootComputed` when complete.
    ComputeMerkleRoot {
        tx_hash: Hash,
        writes: Vec<(NodeId, Vec<u8>)>,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // External Notifications
    // ═══════════════════════════════════════════════════════════════════════
    /// Emit a committed block for external observers.
    EmitCommittedBlock { block: Block },

    /// Emit transaction status update for RPC status cache.
    ///
    /// Emitted by the mempool whenever a transaction's status changes:
    /// - Pending: Transaction accepted into mempool
    /// - Committed: Transaction included in a committed block
    /// - Executed: Transaction execution complete (accept/reject decision made)
    /// - Completed: Transaction certificate committed, can be evicted
    /// - Blocked: Transaction deferred due to cross-shard livelock
    /// - Retried: Transaction superseded by retry transaction
    ///
    /// The production runner updates the RPC status cache when processing
    /// this action, allowing clients to query transaction status via the
    /// `GET /api/v1/transactions/{hash}` endpoint.
    ///
    /// The `added_at` field tracks when the transaction was first added to the
    /// mempool, enabling end-to-end latency metrics for finalized transactions.
    EmitTransactionStatus {
        tx_hash: Hash,
        status: TransactionStatus,
        /// When the transaction was added to the mempool (for latency tracking).
        added_at: Duration,
        /// Whether this is a cross-shard transaction (for metrics labeling).
        cross_shard: bool,
        /// Whether this transaction was submitted locally (via RPC) vs received via gossip/fetch.
        /// Only locally-submitted transactions should contribute to latency metrics.
        submitted_locally: bool,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Storage: Consensus
    // ═══════════════════════════════════════════════════════════════════════
    /// Persist a committed block to storage.
    ///
    /// This stores the block itself and updates chain metadata:
    /// - Block bytes at `block:{height}`
    /// - Latest committed height
    /// - Latest block hash
    PersistBlock {
        block: Block,
        /// The QC that certified this block (stored for recovery).
        qc: QuorumCertificate,
    },

    /// Persist a vote and broadcast it as a single atomic action.
    ///
    /// **BFT Safety Critical**: The runner MUST persist the vote before broadcasting.
    /// This action combines `PersistOwnVote` and `BroadcastToShard` into a single
    /// action, allowing the runner to:
    /// 1. Start persistence (potentially async with fsync)
    /// 2. Wait for persistence to complete
    /// 3. Then broadcast the vote
    PersistAndBroadcastVote {
        height: BlockHeight,
        round: u64,
        block_hash: Hash,
        shard: ShardGroupId,
        message: OutboundMessage,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Storage: Execution
    // ═══════════════════════════════════════════════════════════════════════
    /// Persist a finalized transaction certificate with its state writes.
    ///
    /// This is the deferred commit operation - state writes are only applied when
    /// a `TransactionCertificate` is included in a committed block. The runner
    /// extracts writes from `certificate.shard_proofs[local_shard]` and commits
    /// them atomically with the certificate.
    ///
    /// Stored so we don't re-execute if we crash and recover.
    PersistTransactionCertificate { certificate: TransactionCertificate },

    // ═══════════════════════════════════════════════════════════════════════
    // Global Consensus / Epoch Management
    // ═══════════════════════════════════════════════════════════════════════
    /// Propose a global block for epoch management.
    ///
    /// Only the designated global proposer (rotating based on epoch height) calls this.
    ProposeGlobalBlock {
        /// Current epoch.
        epoch: EpochId,
        /// Height within the global chain.
        height: BlockHeight,
        /// The proposed next epoch configuration (if this finalizes an epoch).
        next_epoch_config: Option<Box<EpochConfig>>,
    },

    /// Broadcast a shard vote for a global block.
    ///
    /// This is the "shard-level vote" - sent after 2f+1 local validators agree.
    BroadcastGlobalBlockVote {
        /// The block being voted on.
        block_hash: Hash,
        /// This shard's ID.
        shard: ShardGroupId,
        /// Aggregated BLS signature from 2f+1 local validators.
        shard_signature: Signature,
        /// Which validators in this shard signed.
        signers: SignerBitfield,
        /// Total voting power in the shard signature.
        voting_power: VotePower,
    },

    /// Initiate epoch transition.
    ///
    /// Called when EpochTransitionReady event is received.
    /// Updates the DynamicTopology and notifies subsystems.
    TransitionEpoch {
        /// The epoch we're transitioning from.
        from_epoch: EpochId,
        /// The epoch we're transitioning to.
        to_epoch: EpochId,
        /// The finalized configuration for the new epoch.
        next_config: Box<EpochConfig>,
    },

    /// Mark this validator as ready for the new epoch.
    ///
    /// Called after sync completes when validator was in Waiting state.
    MarkValidatorReady {
        /// The epoch.
        epoch: EpochId,
        /// The shard.
        shard: ShardGroupId,
    },

    /// Initiate a shard split.
    ///
    /// Marks the shard as splitting in the topology, triggering transaction rejection.
    InitiateShardSplit {
        /// The shard being split.
        source_shard: ShardGroupId,
        /// The new shard ID.
        new_shard: ShardGroupId,
        /// The hash range split point.
        split_point: u64,
    },

    /// Complete a shard split.
    ///
    /// Called after state migration is complete.
    CompleteShardSplit {
        /// The original shard.
        source_shard: ShardGroupId,
        /// The new shard.
        new_shard: ShardGroupId,
    },

    /// Initiate a shard merge.
    InitiateShardMerge {
        /// First shard.
        shard_a: ShardGroupId,
        /// Second shard.
        shard_b: ShardGroupId,
        /// Resulting shard ID.
        merged_shard: ShardGroupId,
    },

    /// Complete a shard merge.
    CompleteShardMerge {
        /// The merged shard.
        merged_shard: ShardGroupId,
    },

    /// Persist epoch configuration to storage.
    PersistEpochConfig {
        /// The epoch configuration to persist.
        config: Box<EpochConfig>,
    },

    /// Fetch the latest epoch configuration from storage.
    ///
    /// Returns via Event (to be added) when complete.
    FetchEpochConfig {
        /// Optional epoch ID to fetch (None = latest).
        epoch: Option<EpochId>,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Storage: Read Requests (returns callback Event)
    // ═══════════════════════════════════════════════════════════════════════
    /// Fetch state entries for nodes (for cross-shard provisioning).
    ///
    /// Returns `Event::StateEntriesFetched { tx_hash, entries }`.
    FetchStateEntries {
        /// Transaction hash (for correlation in callback).
        tx_hash: Hash,
        /// Nodes to fetch all substates for.
        nodes: Vec<NodeId>,
    },

    /// Fetch a block by height.
    ///
    /// Returns `Event::BlockFetched { height, block }`.
    FetchBlock { height: BlockHeight },

    /// Fetch chain metadata (latest height, hash, QC).
    ///
    /// Returns `Event::ChainMetadataFetched { height, hash, qc }`.
    FetchChainMetadata,

    // ═══════════════════════════════════════════════════════════════════════
    // Runner I/O Requests (network fetches handled by the runner)
    // These request the runner to perform network I/O and deliver results
    // back as Events (TransactionReceived, CertificateReceived, SyncBlockReadyToApply)
    // ═══════════════════════════════════════════════════════════════════════
    /// Request the runner to start syncing to a target height.
    ///
    /// Emitted when the state machine detects it's behind (e.g., receives a
    /// block header or QC ahead of committed height). The runner handles
    /// peer selection, fetching, validation, and delivers blocks via
    /// `Event::SyncBlockReadyToApply`.
    StartSync {
        /// The height we need to sync to.
        target_height: u64,
        /// The hash of the target block (for verification).
        target_hash: Hash,
    },

    /// Request the runner to fetch missing transactions for a pending block.
    ///
    /// Emitted when a block header arrives but transactions are missing from
    /// mempool. The runner fetches from the proposer or peers and delivers
    /// results via `Event::TransactionReceived`.
    FetchTransactions {
        /// Hash of the block that needs these transactions.
        block_hash: Hash,
        /// The proposer of the block (preferred fetch target).
        proposer: ValidatorId,
        /// Hashes of the missing transactions.
        tx_hashes: Vec<Hash>,
    },

    /// Request the runner to fetch missing certificates for a pending block.
    ///
    /// Emitted when a block header arrives but certificates are missing locally.
    /// The runner fetches from the proposer or peers and delivers results via
    /// `Event::CertificateReceived`.
    FetchCertificates {
        /// Hash of the block that needs these certificates.
        block_hash: Hash,
        /// The proposer of the block (preferred fetch target).
        proposer: ValidatorId,
        /// Hashes of the missing certificates (transaction hashes).
        cert_hashes: Vec<Hash>,
    },
}

impl Action {
    /// Check if this action requires async I/O (network or storage writes).
    pub fn is_async(&self) -> bool {
        matches!(
            self,
            Action::BroadcastToShard { .. }
                | Action::BroadcastGlobal { .. }
                | Action::BroadcastStateVote { .. }
                | Action::BroadcastStateCertificate { .. }
                | Action::BroadcastStateProvision { .. }
                | Action::PersistBlock { .. }
                | Action::PersistAndBroadcastVote { .. }
                | Action::PersistTransactionCertificate { .. }
        )
    }

    /// Check if this action is delegated work (runs on thread pool, returns callback).
    pub fn is_delegated(&self) -> bool {
        matches!(
            self,
            Action::VerifyAndBuildQuorumCertificate { .. }
                | Action::VerifyAndAggregateProvisions { .. }
                | Action::AggregateStateCertificate { .. }
                | Action::VerifyAndAggregateStateVotes { .. }
                | Action::VerifyStateCertificateSignature { .. }
                | Action::VerifyQcSignature { .. }
                | Action::ExecuteTransactions { .. }
                | Action::SpeculativeExecute { .. }
                | Action::ExecuteCrossShardTransaction { .. }
                | Action::SignExecutionResults { .. }
                | Action::ComputeMerkleRoot { .. }
                | Action::FetchStateEntries { .. }
                | Action::FetchBlock { .. }
                | Action::FetchChainMetadata
        )
    }

    /// Check if this is an internal event action.
    pub fn is_internal(&self) -> bool {
        matches!(self, Action::EnqueueInternal { .. })
    }

    /// Check if this is a storage write action.
    pub fn is_storage_write(&self) -> bool {
        matches!(
            self,
            Action::PersistBlock { .. }
                | Action::PersistAndBroadcastVote { .. }
                | Action::PersistTransactionCertificate { .. }
        )
    }

    /// Check if this is a storage read action (delegated, returns event).
    pub fn is_storage_read(&self) -> bool {
        matches!(
            self,
            Action::FetchStateEntries { .. }
                | Action::FetchBlock { .. }
                | Action::FetchChainMetadata
        )
    }

    /// Get the action type name for telemetry.
    pub fn type_name(&self) -> &'static str {
        match self {
            // Network - Generic
            Action::BroadcastToShard { .. } => "BroadcastToShard",
            Action::BroadcastGlobal { .. } => "BroadcastGlobal",

            // Network - Execution Layer (batchable)
            Action::BroadcastStateVote { .. } => "BroadcastStateVote",
            Action::BroadcastStateCertificate { .. } => "BroadcastStateCertificate",
            Action::BroadcastStateProvision { .. } => "BroadcastStateProvision",

            // Timers
            Action::SetTimer { .. } => "SetTimer",
            Action::CancelTimer { .. } => "CancelTimer",

            // Internal
            Action::EnqueueInternal { .. } => "EnqueueInternal",

            // Delegated Work - Crypto Verification
            Action::VerifyAndBuildQuorumCertificate { .. } => "VerifyAndBuildQuorumCertificate",
            Action::VerifyAndAggregateProvisions { .. } => "VerifyAndAggregateProvisions",
            Action::AggregateStateCertificate { .. } => "AggregateStateCertificate",
            Action::VerifyAndAggregateStateVotes { .. } => "VerifyAndAggregateStateVotes",
            Action::VerifyStateCertificateSignature { .. } => "VerifyStateCertificateSignature",
            Action::VerifyQcSignature { .. } => "VerifyQcSignature",

            // Delegated Work - Execution
            Action::ExecuteTransactions { .. } => "ExecuteTransactions",
            Action::SpeculativeExecute { .. } => "SpeculativeExecute",
            Action::ExecuteCrossShardTransaction { .. } => "ExecuteCrossShardTransaction",
            Action::SignExecutionResults { .. } => "SignExecutionResults",
            Action::ComputeMerkleRoot { .. } => "ComputeMerkleRoot",

            // External Notifications
            Action::EmitCommittedBlock { .. } => "EmitCommittedBlock",
            Action::EmitTransactionStatus { .. } => "EmitTransactionStatus",

            // Storage - Consensus
            Action::PersistBlock { .. } => "PersistBlock",
            Action::PersistAndBroadcastVote { .. } => "PersistAndBroadcastVote",

            // Storage - Execution
            Action::PersistTransactionCertificate { .. } => "PersistTransactionCertificate",

            // Storage - Read Requests
            Action::FetchStateEntries { .. } => "FetchStateEntries",
            Action::FetchBlock { .. } => "FetchBlock",
            Action::FetchChainMetadata => "FetchChainMetadata",

            // Global Consensus / Epoch Management
            Action::ProposeGlobalBlock { .. } => "ProposeGlobalBlock",
            Action::BroadcastGlobalBlockVote { .. } => "BroadcastGlobalBlockVote",
            Action::TransitionEpoch { .. } => "TransitionEpoch",
            Action::MarkValidatorReady { .. } => "MarkValidatorReady",
            Action::InitiateShardSplit { .. } => "InitiateShardSplit",
            Action::CompleteShardSplit { .. } => "CompleteShardSplit",
            Action::InitiateShardMerge { .. } => "InitiateShardMerge",
            Action::CompleteShardMerge { .. } => "CompleteShardMerge",
            Action::PersistEpochConfig { .. } => "PersistEpochConfig",
            Action::FetchEpochConfig { .. } => "FetchEpochConfig",

            // Runner I/O Requests
            Action::StartSync { .. } => "StartSync",
            Action::FetchTransactions { .. } => "FetchTransactions",
            Action::FetchCertificates { .. } => "FetchCertificates",
        }
    }
}

// Re-export TransactionStatus from types crate
pub use hyperscale_types::TransactionStatus;
