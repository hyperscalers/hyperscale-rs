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

mod crypto;
mod hash;
mod identifiers;
mod network;
mod proofs;
mod signing;

// Consensus types
mod block;
mod epoch;
mod quorum_certificate;
mod signer_bitfield;
mod state;
mod topology;
mod transaction;
mod validator;

// Re-export crypto types and helpers
pub use crypto::{
    // Helper functions
    batch_verify_bls_different_messages,
    batch_verify_bls_different_messages_all_or_nothing,
    batch_verify_bls_same_message,
    batch_verify_ed25519,
    bls_keypair_from_seed,
    ed25519_keypair_from_seed,
    generate_bls_keypair,
    generate_ed25519_keypair,
    verify_bls12381_v1,
    verify_ed25519,
    zero_bls_signature,
    zero_ed25519_signature,
    // Vendor types
    Bls12381G1PrivateKey,
    Bls12381G1PublicKey,
    Bls12381G2Signature,
    Ed25519PrivateKey,
    Ed25519PublicKey,
    Ed25519Signature,
};
pub use epoch::{
    EpochConfig, EpochId, GlobalConsensusConfig, GlobalValidatorInfo, ShardCommitteeConfig,
    ShardHashRange, ValidatorRating, ValidatorShardState, DEFAULT_EPOCH_LENGTH,
};
pub use hash::{compute_merkle_root, Hash};
pub use identifiers::{BlockHeight, NodeId, PartitionNumber, ShardGroupId, ValidatorId, VotePower};
pub use network::{MessagePriority, NetworkMessage, Request, ShardMessage};
pub use proofs::{commitment_proof_message, CommitmentProof, CycleProof};
pub use signing::{
    block_vote_message, exec_vote_message, state_provision_message, DOMAIN_BLOCK_VOTE,
    DOMAIN_EXEC_VOTE, DOMAIN_STATE_PROVISION,
};

pub use block::{compute_transaction_root, Block, BlockHeader, BlockMetadata};
pub use quorum_certificate::QuorumCertificate;
pub use signer_bitfield::SignerBitfield;
pub use state::{
    ExecutionResult, StateCertificate, StateEntry, StateProvision, StateVoteBlock, SubstateWrite,
};
pub use topology::{
    shard_for_node, DynamicTopology, DynamicTopologyError, StaticTopology, Topology, TopologyError,
};
pub use transaction::{
    sign_and_notarize, sign_and_notarize_with_options, AbortReason, DeferReason, ReadyTransactions,
    RetryDetails, RoutableTransaction, TransactionAbort, TransactionCertificate,
    TransactionDecision, TransactionDefer, TransactionError, TransactionStatus,
    TransactionStatusParseError,
};
pub use validator::{ValidatorInfo, ValidatorSet};

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

/// Test utilities.
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils {
    use super::*;
    use radix_common::crypto::{Ed25519PublicKey, Ed25519Signature, PublicKey as RadixPublicKey};
    use radix_common::prelude::Epoch;
    use radix_transactions::model::{
        BlobsV1, InstructionsV1, IntentSignaturesV1, IntentV1, MessageV1, NotarizedTransactionV1,
        NotarySignatureV1, SignatureV1, SignedIntentV1, TransactionHeaderV1, UserTransaction,
    };

    /// Create a test NodeId from a seed byte.
    pub fn test_node(seed: u8) -> NodeId {
        NodeId([seed; 30])
    }

    /// Create a minimal test NotarizedTransactionV1 from seed bytes.
    ///
    /// This creates a valid but minimal transaction structure for testing.
    /// The transaction won't execute successfully but is structurally valid.
    pub fn test_notarized_transaction_v1(seed_bytes: &[u8]) -> NotarizedTransactionV1 {
        // Create minimal header with unique nonce from seed
        let header = TransactionHeaderV1 {
            network_id: 0xf2, // Simulator network
            start_epoch_inclusive: Epoch::of(0),
            end_epoch_exclusive: Epoch::of(100),
            nonce: {
                let mut nonce_bytes = [0u8; 4];
                for (i, &b) in seed_bytes.iter().take(4).enumerate() {
                    nonce_bytes[i] = b;
                }
                u32::from_le_bytes(nonce_bytes)
            },
            notary_public_key: RadixPublicKey::Ed25519(Ed25519PublicKey([0u8; 32])),
            notary_is_signatory: false,
            tip_percentage: 0,
        };

        // Create a minimal intent
        let intent = IntentV1 {
            header,
            instructions: InstructionsV1(vec![]),
            blobs: BlobsV1 { blobs: vec![] },
            message: MessageV1::None,
        };

        // Create signed intent with no signatures
        let signed_intent = SignedIntentV1 {
            intent,
            intent_signatures: IntentSignaturesV1 { signatures: vec![] },
        };

        // Create notarized transaction with a zero signature
        NotarizedTransactionV1 {
            signed_intent,
            notary_signature: NotarySignatureV1(SignatureV1::Ed25519(Ed25519Signature([0u8; 64]))),
        }
    }

    /// Create a test transaction with specific read/write nodes.
    pub fn test_transaction_with_nodes(
        seed_bytes: &[u8],
        read_nodes: Vec<NodeId>,
        write_nodes: Vec<NodeId>,
    ) -> RoutableTransaction {
        let tx = test_notarized_transaction_v1(seed_bytes);
        RoutableTransaction::new(UserTransaction::V1(tx), read_nodes, write_nodes)
    }

    /// Create a simple test transaction.
    pub fn test_transaction(seed: u8) -> RoutableTransaction {
        test_transaction_with_nodes(
            &[seed, seed + 1, seed + 2],
            vec![test_node(seed)],
            vec![test_node(seed + 10)],
        )
    }
}
