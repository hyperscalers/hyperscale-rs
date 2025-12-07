//! Action types for the deterministic state machine.

use crate::{message::OutboundMessage, Event, RequestId, TimerId};
use hyperscale_types::{
    Block, BlockHeight, BlockVote, Hash, NodeId, PublicKey, QuorumCertificate, RoutableTransaction,
    ShardGroupId, StateCertificate, StateProvision, StateVoteBlock, SubstateWrite,
    TransactionCertificate, TransactionDecision, ViewChangeVote,
};
use std::time::Duration;

/// Actions the state machine wants to perform.
///
/// Actions are **commands** - they describe something to do.
/// The runner executes actions and may convert results back into events.
#[derive(Debug, Clone)]
pub enum Action {
    // ═══════════════════════════════════════════════════════════════════════
    // Network
    // ═══════════════════════════════════════════════════════════════════════
    /// Broadcast a message to all nodes in a shard.
    ///
    /// Production uses gossipsub with topic-based routing.
    /// Simulation routes to all nodes in the shard.
    BroadcastToShard {
        shard: ShardGroupId,
        message: OutboundMessage,
    },

    /// Broadcast a message to all nodes in the network.
    BroadcastGlobal { message: OutboundMessage },

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
    /// Verify a block vote's signature.
    ///
    /// Delegated to a thread pool in production, instant in simulation.
    /// Returns `Event::VoteSignatureVerified` when complete.
    VerifyVoteSignature {
        /// The vote to verify.
        vote: BlockVote,
        /// Public key of the voter (pre-resolved by state machine).
        public_key: PublicKey,
        /// The signing message (domain_tag || shard_group || height || round || block_hash).
        /// Pre-computed by state machine since it has the shard_group context.
        signing_message: Vec<u8>,
    },

    /// Verify a state provision's signature (cross-shard Phase 2).
    ///
    /// Delegated to a thread pool in production, instant in simulation.
    /// Returns `Event::ProvisionSignatureVerified` when complete.
    VerifyProvisionSignature {
        /// The provision to verify.
        provision: StateProvision,
        /// Public key of the sending validator (pre-resolved by state machine).
        public_key: PublicKey,
    },

    /// Verify a state vote's signature (cross-shard Phase 4).
    ///
    /// Delegated to a thread pool in production, instant in simulation.
    /// Returns `Event::StateVoteSignatureVerified` when complete.
    VerifyStateVoteSignature {
        /// The state vote to verify.
        vote: StateVoteBlock,
        /// Public key of the voter (pre-resolved by state machine).
        public_key: PublicKey,
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

    /// Verify a view change vote's signature.
    ///
    /// View change votes must be verified before being counted toward quorum.
    /// The signature is over (shard_group, height, new_round).
    ///
    /// Delegated to a thread pool in production, instant in simulation.
    /// Returns `Event::ViewChangeVoteSignatureVerified` when complete.
    VerifyViewChangeVoteSignature {
        /// The view change vote to verify.
        vote: ViewChangeVote,
        /// Public key of the voter (pre-resolved by state machine).
        public_key: PublicKey,
        /// The signing message (shard_group || height || new_round).
        /// Pre-computed by state machine since it has the shard_group context.
        signing_message: Vec<u8>,
    },

    /// Verify the highest QC attached to a view change vote.
    ///
    /// View change votes include the voter's highest QC. This QC must be verified
    /// before being used to determine the new proposer's starting point.
    ///
    /// Delegated to a thread pool in production, instant in simulation.
    /// Returns `Event::ViewChangeHighestQcVerified` when complete.
    VerifyViewChangeHighestQc {
        /// The view change vote containing the highest_qc.
        vote: ViewChangeVote,
        /// Public keys of the QC signers (pre-resolved from highest_qc.signers bitfield).
        public_keys: Vec<PublicKey>,
        /// The signing message for the QC (domain_tag || shard_group || height || round || block_hash).
        /// Pre-computed by state machine since it has the shard_group context.
        signing_message: Vec<u8>,
    },

    /// Execute a batch of single-shard transactions.
    ///
    /// Delegated to the engine thread pool in production, instant in simulation.
    /// Returns `Event::TransactionsExecuted` when complete.
    ExecuteTransactions {
        block_hash: Hash,
        transactions: Vec<RoutableTransaction>,
        state_root: Hash,
    },

    /// Execute a cross-shard transaction with provisioned state.
    ///
    /// Used after 2PC provisioning completes. The runner executes the transaction
    /// using the provided provisions and returns the result.
    /// Returns `Event::CrossShardTransactionExecuted` when complete.
    ExecuteCrossShardTransaction {
        /// Transaction hash (for correlation).
        tx_hash: Hash,
        /// The transaction to execute.
        transaction: RoutableTransaction,
        /// State provisions from other shards.
        provisions: Vec<StateProvision>,
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

    /// Emit a transaction result to the client.
    EmitTransactionResult {
        request_id: RequestId,
        result: TransactionDecision,
    },

    /// Emit transaction status to the client.
    EmitTransactionStatus {
        request_id: RequestId,
        tx_hash: Hash,
        status: TransactionStatus,
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

    // ═══════════════════════════════════════════════════════════════════════
    // Storage: Execution
    // ═══════════════════════════════════════════════════════════════════════
    /// Persist a finalized transaction certificate.
    ///
    /// Stored so we don't re-execute if we crash and recover.
    PersistTransactionCertificate { certificate: TransactionCertificate },

    /// Persist substate writes from transaction execution.
    ///
    /// These are the actual state changes to be applied to the ledger.
    /// Key format: `radix:` + node_key + partition + sort_key → value
    PersistSubstateWrites {
        tx_hash: Hash,
        writes: Vec<SubstateWrite>,
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
}

impl Action {
    /// Check if this action requires async I/O (network or storage writes).
    pub fn is_async(&self) -> bool {
        matches!(
            self,
            Action::BroadcastToShard { .. }
                | Action::BroadcastGlobal { .. }
                | Action::PersistBlock { .. }
                | Action::PersistTransactionCertificate { .. }
                | Action::PersistSubstateWrites { .. }
        )
    }

    /// Check if this action is delegated work (runs on thread pool, returns callback).
    pub fn is_delegated(&self) -> bool {
        matches!(
            self,
            Action::VerifyVoteSignature { .. }
                | Action::VerifyProvisionSignature { .. }
                | Action::VerifyStateVoteSignature { .. }
                | Action::VerifyStateCertificateSignature { .. }
                | Action::VerifyQcSignature { .. }
                | Action::VerifyViewChangeVoteSignature { .. }
                | Action::VerifyViewChangeHighestQc { .. }
                | Action::ExecuteTransactions { .. }
                | Action::ExecuteCrossShardTransaction { .. }
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
                | Action::PersistTransactionCertificate { .. }
                | Action::PersistSubstateWrites { .. }
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
}

// Re-export TransactionStatus from types crate
pub use hyperscale_types::TransactionStatus;
