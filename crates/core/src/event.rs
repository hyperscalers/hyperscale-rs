//! Event types for the deterministic state machine.

use crate::RequestId;
use hyperscale_types::{
    Block, BlockHeader, BlockHeight, BlockVote, ExecutionResult, Hash, QuorumCertificate,
    RoutableTransaction, StateCertificate, StateEntry, StateProvision, StateVoteBlock,
    TransactionAbort, TransactionDefer, ViewChangeCertificate, ViewChangeVote,
};

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
    ProposalTimer,

    /// View change timeout expired.
    ViewChangeTimer,

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

    /// Received a view change vote.
    ///
    /// Sender identity comes from vote.voter (ValidatorId).
    ViewChangeVoteReceived { vote: ViewChangeVote },

    /// Received a view change certificate.
    ViewChangeCertificateReceived { cert: ViewChangeCertificate },

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
    TransactionGossipReceived { tx: RoutableTransaction },

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

    /// A transaction was accepted into the mempool.
    TransactionAccepted { tx_hash: Hash },

    /// View change completed (round increment).
    ViewChangeCompleted { height: u64, new_round: u64 },

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

    /// View change vote signature verification completed.
    ///
    /// Callback from `Action::VerifyViewChangeVoteSignature`.
    ViewChangeVoteSignatureVerified {
        /// The view change vote that was verified.
        vote: ViewChangeVote,
        /// Whether the signature is valid.
        valid: bool,
    },

    /// View change highest QC verification completed.
    ///
    /// Callback from `Action::VerifyViewChangeHighestQc`.
    ViewChangeHighestQcVerified {
        /// The view change vote whose highest_qc was verified.
        vote: ViewChangeVote,
        /// Whether the highest_qc's aggregated signature is valid.
        valid: bool,
    },

    /// View change certificate signature verification completed.
    ///
    /// Callback from `Action::VerifyViewChangeCertificateSignature`.
    ViewChangeCertificateSignatureVerified {
        /// The certificate that was verified.
        certificate: ViewChangeCertificate,
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
    SubmitTransaction {
        tx: RoutableTransaction,
        request_id: RequestId,
    },

    /// Client requested transaction status.
    QueryTransactionStatus {
        tx_hash: Hash,
        request_id: RequestId,
    },

    // ═══════════════════════════════════════════════════════════════════════
    // Sync Protocol Events (priority varies by type)
    // ═══════════════════════════════════════════════════════════════════════
    /// Detected that we're behind and need to sync (priority: Internal).
    ///
    /// Triggered when we receive a block header or QC ahead of our committed height.
    /// The runner handles all sync I/O (peer selection, retries, timeouts).
    SyncNeeded {
        /// The height we need to sync to.
        target_height: u64,
        /// The hash of the target block (for verification).
        target_hash: Hash,
    },

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
            | Event::TransactionAccepted { .. }
            | Event::ViewChangeCompleted { .. }
            | Event::TransactionExecuted { .. }
            | Event::TransactionStatusChanged { .. }
            | Event::VoteSignatureVerified { .. }
            | Event::ProvisionSignatureVerified { .. }
            | Event::StateVoteSignatureVerified { .. }
            | Event::StateCertificateSignatureVerified { .. }
            | Event::QcSignatureVerified { .. }
            | Event::ViewChangeVoteSignatureVerified { .. }
            | Event::ViewChangeHighestQcVerified { .. }
            | Event::ViewChangeCertificateSignatureVerified { .. }
            | Event::TransactionsExecuted { .. }
            | Event::CrossShardTransactionExecuted { .. }
            | Event::MerkleRootComputed { .. }
            | Event::StateEntriesFetched { .. }
            | Event::BlockFetched { .. }
            | Event::ChainMetadataFetched { .. } => EventPriority::Internal,

            // Timer events
            Event::ProposalTimer | Event::ViewChangeTimer | Event::CleanupTimer => {
                EventPriority::Timer
            }

            // Network events
            Event::BlockHeaderReceived { .. }
            | Event::BlockVoteReceived { .. }
            | Event::ViewChangeVoteReceived { .. }
            | Event::ViewChangeCertificateReceived { .. }
            | Event::StateProvisionReceived { .. }
            | Event::StateVoteReceived { .. }
            | Event::StateCertificateReceived { .. }
            | Event::TransactionGossipReceived { .. } => EventPriority::Network,

            // Client events (processed last at same time)
            Event::SubmitTransaction { .. } | Event::QueryTransactionStatus { .. } => {
                EventPriority::Client
            }

            // Sync events have varying priorities
            Event::SyncNeeded { .. }
            | Event::SyncBlockReadyToApply { .. }
            | Event::SyncComplete { .. } => EventPriority::Internal,

            Event::SyncBlockReceived { .. } => EventPriority::Network,
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
            Event::ViewChangeTimer => "ViewChangeTimer",
            Event::CleanupTimer => "CleanupTimer",

            // Network - BFT
            Event::BlockHeaderReceived { .. } => "BlockHeaderReceived",
            Event::BlockVoteReceived { .. } => "BlockVoteReceived",
            Event::ViewChangeVoteReceived { .. } => "ViewChangeVoteReceived",
            Event::ViewChangeCertificateReceived { .. } => "ViewChangeCertificateReceived",

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
            Event::TransactionAccepted { .. } => "TransactionAccepted",
            Event::ViewChangeCompleted { .. } => "ViewChangeCompleted",
            Event::TransactionExecuted { .. } => "TransactionExecuted",
            Event::TransactionStatusChanged { .. } => "TransactionStatusChanged",

            // Async Callbacks - Crypto Verification
            Event::VoteSignatureVerified { .. } => "VoteSignatureVerified",
            Event::ProvisionSignatureVerified { .. } => "ProvisionSignatureVerified",
            Event::StateVoteSignatureVerified { .. } => "StateVoteSignatureVerified",
            Event::StateCertificateSignatureVerified { .. } => "StateCertificateSignatureVerified",
            Event::QcSignatureVerified { .. } => "QcSignatureVerified",
            Event::ViewChangeVoteSignatureVerified { .. } => "ViewChangeVoteSignatureVerified",
            Event::ViewChangeHighestQcVerified { .. } => "ViewChangeHighestQcVerified",
            Event::ViewChangeCertificateSignatureVerified { .. } => {
                "ViewChangeCertificateSignatureVerified"
            }

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
            Event::QueryTransactionStatus { .. } => "QueryTransactionStatus",

            // Sync Protocol
            Event::SyncNeeded { .. } => "SyncNeeded",
            Event::SyncBlockReceived { .. } => "SyncBlockReceived",
            Event::SyncBlockReadyToApply { .. } => "SyncBlockReadyToApply",
            Event::SyncComplete { .. } => "SyncComplete",
        }
    }
}
