//! Event types for the deterministic state machine.

use hyperscale_types::{
    Block, BlockHeader, BlockHeight, BlockVote, EpochConfig, EpochId, ExecutionResult, Hash,
    QuorumCertificate, RoutableTransaction, ShardGroupId, StateCertificate, StateEntry,
    StateProvision, StateVoteBlock, TransactionAbort, TransactionCertificate, TransactionDefer,
    ValidatorId,
};
use std::sync::Arc;

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

/// All possible events a node can receive.
///
/// Events are **passive data** - they describe something that happened.
/// The state machine processes events and returns actions.
#[derive(Debug, Clone)]
pub enum Event {
    // ═══════════════════════════════════════════════════════════════════════
    // Timers (priority: Timer)
    // ═══════════════════════════════════════════════════════════════════════
    /// Time to propose a new block (if this node is the proposer).
    /// Also used for implicit round advancement when no QC is formed.
    ProposalTimer,

    /// Periodic cleanup of stale state.
    CleanupTimer,

    // ═══════════════════════════════════════════════════════════════════════
    // Network Messages - BFT (priority: Network)
    // ═══════════════════════════════════════════════════════════════════════
    /// Received a block header from another node.
    ///
    /// Note: Sender identity comes from message signatures (ValidatorId),
    /// not from a `from` field. Production uses gossipsub with signed messages.
    BlockHeaderReceived {
        header: BlockHeader,
        tx_hashes: Vec<Hash>,
        cert_hashes: Vec<Hash>,
        /// Deferred transactions in this block (livelock prevention).
        deferred: Vec<TransactionDefer>,
        /// Aborted transactions in this block.
        aborted: Vec<TransactionAbort>,
    },

    /// Received a vote on a block header.
    ///
    /// Sender identity comes from vote.voter (ValidatorId).
    BlockVoteReceived { vote: BlockVote },

    // ═══════════════════════════════════════════════════════════════════════
    // Network Messages - Execution (priority: Network)
    // ═══════════════════════════════════════════════════════════════════════
    /// Received state provision for cross-shard execution.
    ///
    /// Sender identity comes from provision.validator_id.
    StateProvisionReceived { provision: StateProvision },

    /// Received a state vote for cross-shard execution.
    ///
    /// Sender identity comes from vote.validator_id.
    StateVoteReceived { vote: StateVoteBlock },

    /// Received a state certificate for cross-shard execution.
    StateCertificateReceived { cert: StateCertificate },

    // ═══════════════════════════════════════════════════════════════════════
    // Network Messages - Mempool (priority: Network)
    // ═══════════════════════════════════════════════════════════════════════
    /// Received a transaction via gossip.
    TransactionGossipReceived { tx: Arc<RoutableTransaction> },

    // ═══════════════════════════════════════════════════════════════════════
    // Internal Events (priority: Internal)
    // These replace channel sends between async tasks
    // ═══════════════════════════════════════════════════════════════════════
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
    ///
    /// The full block is included so subsystems can process:
    /// - Transactions (execution, mempool status updates)
    /// - Certificates (finalization)
    /// - Deferrals (livelock prevention - release locks, queue retries)
    /// - Aborts (livelock prevention - release locks, mark as failed)
    BlockCommitted {
        /// Hash of the committed block.
        block_hash: Hash,
        /// Height of the committed block.
        height: u64,
        /// The full committed block (includes transactions, certificates, deferrals, aborts).
        block: Block,
    },

    /// Transaction execution completed.
    ///
    /// Emitted by the execution state machine when a TransactionCertificate
    /// is created (either single-shard or cross-shard 2PC completion).
    /// This notifies mempool to update transaction status to Executed.
    ///
    /// Note: State is NOT yet updated at this point. The certificate must be
    /// included in a block (triggering Completed status) before state changes
    /// are applied.
    TransactionExecuted {
        tx_hash: Hash,
        /// Whether the transaction was accepted or rejected.
        accepted: bool,
    },

    /// A transaction's status has changed.
    ///
    /// Emitted by the execution state machine when a transaction transitions
    /// through its lifecycle states (Committed, Executed, etc.).
    /// This allows mempool to track the detailed status of transactions
    /// and ensure proper state lock management.
    TransactionStatusChanged {
        tx_hash: Hash,
        /// The new status of the transaction.
        status: hyperscale_types::TransactionStatus,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Async Callbacks (priority: Internal)
    // Results from delegated work (crypto, execution)
    // ═══════════════════════════════════════════════════════════════════════
    /// Vote signature verification completed.
    ///
    /// Callback from `Action::VerifyVoteSignature`.
    VoteSignatureVerified {
        /// The vote that was verified.
        vote: BlockVote,
        /// Whether the signature is valid.
        valid: bool,
    },

    /// State provision signature verification completed.
    ///
    /// Callback from `Action::VerifyProvisionSignature`.
    ProvisionSignatureVerified {
        /// The provision that was verified.
        provision: StateProvision,
        /// Whether the signature is valid.
        valid: bool,
    },

    /// State vote signature verification completed.
    ///
    /// Callback from `Action::VerifyStateVoteSignature`.
    StateVoteSignatureVerified {
        /// The state vote that was verified.
        vote: StateVoteBlock,
        /// Whether the signature is valid.
        valid: bool,
    },

    /// State certificate signature verification completed.
    ///
    /// Callback from `Action::VerifyStateCertificateSignature`.
    StateCertificateSignatureVerified {
        /// The certificate that was verified.
        certificate: StateCertificate,
        /// Whether the aggregated signature is valid.
        valid: bool,
    },

    /// Quorum Certificate signature verification completed.
    ///
    /// Callback from `Action::VerifyQcSignature`.
    QcSignatureVerified {
        /// The block hash this QC verification is associated with.
        /// This is the hash of the block whose header contains this QC as parent_qc.
        block_hash: Hash,
        /// Whether the aggregated signature is valid.
        valid: bool,
    },

    /// Single-shard transaction execution completed.
    TransactionsExecuted {
        block_hash: Hash,
        results: Vec<ExecutionResult>,
    },

    /// Cross-shard transaction execution completed.
    ///
    /// Callback from `Action::ExecuteCrossShardTransaction`.
    CrossShardTransactionExecuted {
        tx_hash: Hash,
        result: ExecutionResult,
    },

    /// Merkle root computation completed.
    MerkleRootComputed { tx_hash: Hash, root: Hash },

    // ═══════════════════════════════════════════════════════════════════════
    // Storage Callbacks (priority: Internal)
    // Results from storage read operations
    // ═══════════════════════════════════════════════════════════════════════
    /// State entries fetched for cross-shard provisioning.
    ///
    /// Callback from `Action::FetchStateEntries`.
    StateEntriesFetched {
        tx_hash: Hash,
        entries: Vec<StateEntry>,
    },

    /// Block fetched from storage.
    ///
    /// Callback from `Action::FetchBlock`.
    BlockFetched {
        height: BlockHeight,
        block: Option<Block>,
    },

    /// Chain metadata fetched from storage.
    ///
    /// Callback from `Action::FetchChainMetadata`.
    ChainMetadataFetched {
        /// Latest committed height (0 if no blocks committed).
        height: BlockHeight,
        /// Latest block hash (None if no blocks committed).
        hash: Option<Hash>,
        /// Latest QC (None if no blocks committed).
        qc: Option<QuorumCertificate>,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Client Requests (priority: Client)
    // ═══════════════════════════════════════════════════════════════════════
    /// Client submitted a transaction.
    SubmitTransaction { tx: Arc<RoutableTransaction> },

    // ═══════════════════════════════════════════════════════════════════════
    // Global Consensus / Epoch Events (priority varies by type)
    // ═══════════════════════════════════════════════════════════════════════
    /// Timer for global consensus operations (priority: Timer).
    GlobalConsensusTimer,

    /// Received a global block proposal from another validator (priority: Network).
    ///
    /// Global blocks contain epoch transition decisions: shuffles, splits, merges.
    GlobalBlockReceived {
        /// Epoch this block belongs to.
        epoch: EpochId,
        /// Block height within the global chain.
        height: BlockHeight,
        /// Proposer of this global block.
        proposer: ValidatorId,
        /// Hash of the proposed block.
        block_hash: Hash,
        /// The next epoch configuration (if this block finalizes an epoch transition).
        next_epoch_config: Option<Box<EpochConfig>>,
    },

    /// Received a vote on a global block (priority: Network).
    ///
    /// This is a "shard vote" - represents 2f+1 agreement within a shard.
    GlobalBlockVoteReceived {
        /// The block being voted on.
        block_hash: Hash,
        /// The shard casting this vote.
        shard: ShardGroupId,
        /// Aggregated signature from 2f+1 validators in the shard.
        shard_signature: hyperscale_types::Signature,
        /// Which validators in the shard signed.
        signers: hyperscale_types::SignerBitfield,
        /// Total voting power represented.
        voting_power: hyperscale_types::VotePower,
    },

    /// Global quorum certificate formed (priority: Internal).
    ///
    /// 2/3 of shards have voted, epoch transition can proceed.
    GlobalQcFormed {
        /// The block that achieved global quorum.
        block_hash: Hash,
        /// The epoch being finalized.
        epoch: EpochId,
    },

    /// Epoch transition is imminent (priority: Internal).
    ///
    /// Emitted when the local shard reaches epoch_end_height.
    /// Triggers: stop accepting new transactions, drain in-flight ones.
    EpochEndApproaching {
        /// Current epoch that is ending.
        current_epoch: EpochId,
        /// Height at which epoch ends.
        end_height: BlockHeight,
    },

    /// Ready to transition to next epoch (priority: Internal).
    ///
    /// Emitted when:
    /// 1. All in-flight transactions have completed/aborted
    /// 2. Global consensus has finalized the next epoch config
    /// 3. Validator has synced to new shard (if shuffled)
    EpochTransitionReady {
        /// The epoch we're transitioning from.
        from_epoch: EpochId,
        /// The epoch we're transitioning to.
        to_epoch: EpochId,
        /// The finalized configuration for the new epoch.
        next_config: Box<EpochConfig>,
    },

    /// Epoch transition completed (priority: Internal).
    ///
    /// The DynamicTopology has been updated, new epoch is now active.
    EpochTransitionComplete {
        /// The new active epoch.
        new_epoch: EpochId,
        /// This validator's new shard (may have changed due to shuffle).
        new_shard: ShardGroupId,
        /// Whether this validator is in Waiting state (needs to sync).
        is_waiting: bool,
    },

    /// Validator finished syncing to new shard after shuffle (priority: Internal).
    ///
    /// Transitions validator from Waiting to Active state.
    ValidatorSyncComplete {
        /// The epoch in which sync completed.
        epoch: EpochId,
        /// The shard that was synced to.
        shard: ShardGroupId,
    },

    /// Shard split initiated (priority: Internal).
    ///
    /// Emitted when global consensus decides to split a shard.
    /// Triggers: reject new transactions for affected NodeIds, drain in-flight.
    ShardSplitInitiated {
        /// The shard being split.
        source_shard: ShardGroupId,
        /// The new shard that will receive half the state.
        new_shard: ShardGroupId,
        /// The hash range boundary for the split.
        split_point: u64,
    },

    /// Shard split completed (priority: Internal).
    ///
    /// State has been migrated, both shards are now operational.
    ShardSplitComplete {
        /// The original shard (now smaller hash range).
        source_shard: ShardGroupId,
        /// The new shard (other half of hash range).
        new_shard: ShardGroupId,
    },

    /// Shard merge initiated (priority: Internal).
    ShardMergeInitiated {
        /// First shard being merged.
        shard_a: ShardGroupId,
        /// Second shard being merged.
        shard_b: ShardGroupId,
        /// The resulting merged shard ID.
        merged_shard: ShardGroupId,
    },

    /// Shard merge completed (priority: Internal).
    ShardMergeComplete {
        /// The resulting merged shard.
        merged_shard: ShardGroupId,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Sync Protocol Events (priority varies by type)
    // Note: SyncNeeded is now Action::StartSync (runner I/O request)
    // ═══════════════════════════════════════════════════════════════════════
    /// Received a block from sync (priority: Network).
    ///
    /// Delivered by the runner after fetching from a peer.
    /// The runner handles peer selection and retry logic.
    SyncBlockReceived {
        /// The requested block.
        block: Block,
        /// The QC that certified this block.
        qc: QuorumCertificate,
    },

    /// A synced block is ready to be applied to local state (priority: Internal).
    ///
    /// This is different from BlockReadyToCommit - it's for blocks we fetched
    /// from peers, not blocks we participated in consensus for.
    SyncBlockReadyToApply { block: Block, qc: QuorumCertificate },

    /// Sync completed successfully (priority: Internal).
    SyncComplete {
        /// The height we synced to.
        height: u64,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Transaction Fetch Protocol (priority: Network)
    // Used when block header arrives but transactions are missing from mempool
    // BFT emits Action::FetchTransactions; runner handles retries and delivers results.
    // ═══════════════════════════════════════════════════════════════════════
    /// Received transactions from a fetch request (priority: Network).
    ///
    /// Delivered by the runner after fetching from a peer.
    TransactionReceived {
        /// Hash of the block these transactions are for.
        block_hash: Hash,
        /// The fetched transactions.
        transactions: Vec<Arc<RoutableTransaction>>,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Certificate Fetch Protocol (priority: Network)
    // Used when block header arrives but certificates are missing locally
    // BFT emits Action::FetchCertificates; runner handles retries and delivers results.
    // ═══════════════════════════════════════════════════════════════════════
    /// Received certificates from a fetch request (priority: Network).
    ///
    /// Delivered by the runner after fetching from a peer.
    /// Each certificate must be verified before use.
    CertificateReceived {
        /// Hash of the block these certificates are for.
        block_hash: Hash,
        /// The fetched certificates.
        certificates: Vec<TransactionCertificate>,
    },

    /// A fetched certificate has been verified (priority: Internal).
    ///
    /// Emitted after all embedded StateCertificate signatures in a
    /// TransactionCertificate have been verified against topology.
    FetchedCertificateVerified {
        /// Hash of the block this certificate is for.
        block_hash: Hash,
        /// The verified certificate.
        certificate: TransactionCertificate,
    },
}

impl Event {
    /// Get the priority for this event type.
    ///
    /// Events at the same timestamp are processed in priority order,
    /// ensuring causality is preserved.
    pub fn priority(&self) -> EventPriority {
        match self {
            // Internal events (processed first at same time)
            Event::QuorumCertificateFormed { .. }
            | Event::BlockReadyToCommit { .. }
            | Event::BlockCommitted { .. }
            | Event::TransactionExecuted { .. }
            | Event::TransactionStatusChanged { .. }
            | Event::VoteSignatureVerified { .. }
            | Event::ProvisionSignatureVerified { .. }
            | Event::StateVoteSignatureVerified { .. }
            | Event::StateCertificateSignatureVerified { .. }
            | Event::QcSignatureVerified { .. }
            | Event::TransactionsExecuted { .. }
            | Event::CrossShardTransactionExecuted { .. }
            | Event::MerkleRootComputed { .. }
            | Event::StateEntriesFetched { .. }
            | Event::BlockFetched { .. }
            | Event::ChainMetadataFetched { .. } => EventPriority::Internal,

            // Timer events
            Event::ProposalTimer | Event::CleanupTimer | Event::GlobalConsensusTimer => {
                EventPriority::Timer
            }

            // Network events
            Event::BlockHeaderReceived { .. }
            | Event::BlockVoteReceived { .. }
            | Event::StateProvisionReceived { .. }
            | Event::StateVoteReceived { .. }
            | Event::StateCertificateReceived { .. }
            | Event::TransactionGossipReceived { .. }
            | Event::GlobalBlockReceived { .. }
            | Event::GlobalBlockVoteReceived { .. } => EventPriority::Network,

            // Client events (processed last at same time)
            Event::SubmitTransaction { .. } => EventPriority::Client,

            // Global consensus internal events
            Event::GlobalQcFormed { .. }
            | Event::EpochEndApproaching { .. }
            | Event::EpochTransitionReady { .. }
            | Event::EpochTransitionComplete { .. }
            | Event::ValidatorSyncComplete { .. }
            | Event::ShardSplitInitiated { .. }
            | Event::ShardSplitComplete { .. }
            | Event::ShardMergeInitiated { .. }
            | Event::ShardMergeComplete { .. } => EventPriority::Internal,

            // Sync events have varying priorities
            // Note: SyncNeeded is now Action::StartSync
            Event::SyncBlockReadyToApply { .. } | Event::SyncComplete { .. } => {
                EventPriority::Internal
            }

            Event::SyncBlockReceived { .. } => EventPriority::Network,

            // Transaction fetch events (runner handles retries)
            Event::TransactionReceived { .. } => EventPriority::Network,

            // Certificate fetch events (runner handles retries)
            Event::CertificateReceived { .. } => EventPriority::Network,
            Event::FetchedCertificateVerified { .. } => EventPriority::Internal,
        }
    }

    /// Check if this is an internal event (consequence of prior processing).
    pub fn is_internal(&self) -> bool {
        self.priority() == EventPriority::Internal
    }

    /// Check if this is a network event (from another node).
    pub fn is_network(&self) -> bool {
        self.priority() == EventPriority::Network
    }

    /// Check if this is a client event (from a user).
    pub fn is_client(&self) -> bool {
        self.priority() == EventPriority::Client
    }

    /// Get the event type name for telemetry.
    pub fn type_name(&self) -> &'static str {
        match self {
            // Timers
            Event::ProposalTimer => "ProposalTimer",
            Event::CleanupTimer => "CleanupTimer",

            // Network - BFT
            Event::BlockHeaderReceived { .. } => "BlockHeaderReceived",
            Event::BlockVoteReceived { .. } => "BlockVoteReceived",

            // Network - Execution
            Event::StateProvisionReceived { .. } => "StateProvisionReceived",
            Event::StateVoteReceived { .. } => "StateVoteReceived",
            Event::StateCertificateReceived { .. } => "StateCertificateReceived",

            // Network - Mempool
            Event::TransactionGossipReceived { .. } => "TransactionGossipReceived",

            // Internal Events
            Event::QuorumCertificateFormed { .. } => "QuorumCertificateFormed",
            Event::BlockReadyToCommit { .. } => "BlockReadyToCommit",
            Event::BlockCommitted { .. } => "BlockCommitted",
            Event::TransactionExecuted { .. } => "TransactionExecuted",
            Event::TransactionStatusChanged { .. } => "TransactionStatusChanged",

            // Async Callbacks - Crypto Verification
            Event::VoteSignatureVerified { .. } => "VoteSignatureVerified",
            Event::ProvisionSignatureVerified { .. } => "ProvisionSignatureVerified",
            Event::StateVoteSignatureVerified { .. } => "StateVoteSignatureVerified",
            Event::StateCertificateSignatureVerified { .. } => "StateCertificateSignatureVerified",
            Event::QcSignatureVerified { .. } => "QcSignatureVerified",

            // Async Callbacks - Execution
            Event::TransactionsExecuted { .. } => "TransactionsExecuted",
            Event::CrossShardTransactionExecuted { .. } => "CrossShardTransactionExecuted",
            Event::MerkleRootComputed { .. } => "MerkleRootComputed",

            // Storage Callbacks
            Event::StateEntriesFetched { .. } => "StateEntriesFetched",
            Event::BlockFetched { .. } => "BlockFetched",
            Event::ChainMetadataFetched { .. } => "ChainMetadataFetched",

            // Client Requests
            Event::SubmitTransaction { .. } => "SubmitTransaction",

            // Global Consensus / Epoch
            Event::GlobalConsensusTimer => "GlobalConsensusTimer",
            Event::GlobalBlockReceived { .. } => "GlobalBlockReceived",
            Event::GlobalBlockVoteReceived { .. } => "GlobalBlockVoteReceived",
            Event::GlobalQcFormed { .. } => "GlobalQcFormed",
            Event::EpochEndApproaching { .. } => "EpochEndApproaching",
            Event::EpochTransitionReady { .. } => "EpochTransitionReady",
            Event::EpochTransitionComplete { .. } => "EpochTransitionComplete",
            Event::ValidatorSyncComplete { .. } => "ValidatorSyncComplete",
            Event::ShardSplitInitiated { .. } => "ShardSplitInitiated",
            Event::ShardSplitComplete { .. } => "ShardSplitComplete",
            Event::ShardMergeInitiated { .. } => "ShardMergeInitiated",
            Event::ShardMergeComplete { .. } => "ShardMergeComplete",

            // Sync Protocol (SyncNeeded is now Action::StartSync)
            Event::SyncBlockReceived { .. } => "SyncBlockReceived",
            Event::SyncBlockReadyToApply { .. } => "SyncBlockReadyToApply",
            Event::SyncComplete { .. } => "SyncComplete",

            // Transaction Fetch Protocol (runner handles retries)
            Event::TransactionReceived { .. } => "TransactionReceived",

            // Certificate Fetch Protocol (runner handles retries)
            Event::CertificateReceived { .. } => "CertificateReceived",
            Event::FetchedCertificateVerified { .. } => "FetchedCertificateVerified",
        }
    }
}
