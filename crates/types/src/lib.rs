//! Core types for Hyperscale consensus.
//!
//! This crate provides the foundational types used throughout the consensus
//! implementation:
//!
//! - **Primitives**: Hash, cryptographic keys and signatures
//! - **Identifiers**: ValidatorId, ShardGroupId, BlockHeight, etc.
//! - **Consensus types**: Block, BlockHeader, QuorumCertificate, etc.
//! - **Network traits**: Message markers for serialization
//!
//! # Design Philosophy
//!
//! This crate is self-contained with minimal dependencies. It does not depend on
//! any other workspace crates, making it the foundation layer.

pub mod bls;
mod crypto;
mod hash;
mod identifiers;
mod network;
mod proofs;
mod signing;
mod type_config;

// Consensus types
mod block;
mod epoch;
mod quorum_certificate;
mod receipt;
mod signer_bitfield;
mod state;
mod topology;
mod transaction;
mod validator;

// Re-export crypto types and helpers (BLS only — Ed25519 moved to radix-types)
pub use crypto::{
    // Helper functions
    batch_verify_bls_different_messages,
    batch_verify_bls_different_messages_all_or_nothing,
    batch_verify_bls_same_message,
    bls_keypair_from_seed,
    generate_bls_keypair,
    verify_bls12381_v1,
    zero_bls_signature,
    // BLS types (framework-owned)
    Bls12381G1PrivateKey,
    Bls12381G1PublicKey,
    Bls12381G2Signature,
    BlsError,
};
pub use epoch::{
    EpochConfig, EpochId, GlobalConsensusConfig, GlobalValidatorInfo, ShardCommitteeConfig,
    ValidatorRating, ValidatorShardState, DEFAULT_EPOCH_LENGTH,
};
pub use hash::{compute_merkle_root, Hash};
pub use identifiers::{BlockHeight, NodeId, PartitionNumber, ShardGroupId, ValidatorId, VotePower};
pub use network::{MessagePriority, NetworkMessage, Request, ShardMessage};
pub use proofs::{CommitmentProof, MerkleInclusionProof, SubstateInclusionProof};
pub use signing::{
    block_header_message, block_vote_message, committed_block_header_message,
    exec_cert_batch_message, exec_vote_batch_message, exec_vote_message,
    state_provision_batch_message, validator_bind_message, DOMAIN_BLOCK_HEADER, DOMAIN_BLOCK_VOTE,
    DOMAIN_COMMITTED_BLOCK_HEADER, DOMAIN_EXEC_CERT_BATCH, DOMAIN_EXEC_VOTE,
    DOMAIN_EXEC_VOTE_BATCH, DOMAIN_STATE_PROVISION_BATCH, DOMAIN_VALIDATOR_BIND,
};

pub use block::{
    compute_receipt_root, compute_transaction_root, Block, BlockHeader, BlockManifest,
    BlockMetadata, CommittedBlockHeader,
};
pub use quorum_certificate::QuorumCertificate;
pub use receipt::{
    ApplicationEvent, ConsensusReceipt, ExecutionResult, FeeSummary, LedgerReceiptEntry,
    LedgerTransactionOutcome, LedgerTransactionReceipt, LocalTransactionExecution, LogLevel,
    ReceiptBundle, SubstateChange, SubstateChangeAction, SubstateRef,
};
pub use signer_bitfield::SignerBitfield;
pub use state::{ExecutionCertificate, ExecutionVote, StateEntry, StateProvision};
pub use topology::{node_id_hash_u64, shard_for_node, TopologySnapshot, TopologySnapshotError};
pub use transaction::{
    AbortReason, DeferReason, ReadyTransactions, RetryDetails, TransactionAbort,
    TransactionCertificate, TransactionDecision, TransactionDefer, TransactionError,
    TransactionStatus, TransactionStatusParseError,
};
pub use type_config::{ConsensusExecutionReceipt, ConsensusTransaction, TypeConfig};
pub use validator::{ValidatorInfo, ValidatorSet};

use hyperscale_codec as sbor;

/// Block vote for BFT consensus.
#[derive(Debug, Clone, PartialEq, Eq, sbor::prelude::BasicSbor)]
pub struct BlockVote {
    /// Hash of the block being voted on.
    pub block_hash: Hash,
    /// Shard group this vote belongs to (prevents cross-shard replay).
    pub shard_group_id: ShardGroupId,
    /// Height of the block.
    pub height: BlockHeight,
    /// Round number (for view change).
    pub round: u64,
    /// Validator who cast this vote.
    pub voter: ValidatorId,
    /// BLS signature over the domain-separated signing message.
    pub signature: Bls12381G2Signature,
    /// Timestamp when this vote was created (milliseconds since epoch).
    pub timestamp: u64,
}

impl BlockVote {
    /// Create a new block vote with domain-separated signing.
    pub fn new(
        block_hash: Hash,
        shard_group_id: ShardGroupId,
        height: BlockHeight,
        round: u64,
        voter: ValidatorId,
        signing_key: &Bls12381G1PrivateKey,
        timestamp: u64,
    ) -> Self {
        let message = block_vote_message(shard_group_id, height.0, round, &block_hash);
        let signature = signing_key.sign_v1(&message);
        Self {
            block_hash,
            shard_group_id,
            height,
            round,
            voter,
            signature,
            timestamp,
        }
    }

    /// Build the canonical signing message for this vote.
    ///
    /// Uses `DOMAIN_BLOCK_VOTE` tag for domain separation.
    /// This is the same message used for QC aggregated signature verification.
    pub fn signing_message(&self) -> Vec<u8> {
        block_vote_message(
            self.shard_group_id,
            self.height.0,
            self.round,
            &self.block_hash,
        )
    }
}
