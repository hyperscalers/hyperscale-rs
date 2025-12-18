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

pub use crypto::{AggregateError, KeyPair, KeyType, PublicKey, Signature};
pub use epoch::{
    EpochConfig, EpochId, GlobalConsensusConfig, GlobalValidatorInfo, ShardCommitteeConfig,
    ShardHashRange, ValidatorRating, ValidatorShardState, DEFAULT_EPOCH_LENGTH,
};
pub use hash::{Hash, HexError};
pub use identifiers::{BlockHeight, NodeId, PartitionNumber, ShardGroupId, ValidatorId, VotePower};
pub use network::{GlobalMessage, NetworkMessage, Request, ShardMessage};
pub use signing::{
    block_vote_message, exec_vote_message, state_provision_message, DOMAIN_BLOCK_VOTE,
    DOMAIN_EXEC_VOTE, DOMAIN_STATE_PROVISION,
};

pub use block::{Block, BlockHeader};
pub use quorum_certificate::QuorumCertificate;
pub use signer_bitfield::SignerBitfield;
pub use state::{
    ExecutionResult, StateCertificate, StateEntry, StateProvision, StateVoteBlock, SubstateWrite,
};
pub use topology::{
    shard_for_node, DynamicTopology, DynamicTopologyError, StaticTopology, Topology, TopologyError,
};
pub use transaction::{
    sign_and_notarize, sign_and_notarize_with_options, AbortReason, DeferReason, RetryDetails,
    RoutableTransaction, TransactionAbort, TransactionCertificate, TransactionDecision,
    TransactionDefer, TransactionError, TransactionStatus, TransactionStatusParseError,
};
pub use validator::{ValidatorInfo, ValidatorSet};

// Re-export Radix transaction types for convenience
pub use radix_transactions::model::UserTransaction;

/// Block vote for BFT consensus.
#[derive(Debug, Clone, PartialEq, Eq, sbor::prelude::BasicSbor)]
pub struct BlockVote {
    /// Hash of the block being voted on
    pub block_hash: Hash,
    /// Height of the block
    pub height: BlockHeight,
    /// Round number (for view change)
    pub round: u64,
    /// Validator who cast this vote
    pub voter: ValidatorId,
    /// Signature on the block hash
    pub signature: Signature,
    /// Timestamp when this vote was created (milliseconds since epoch)
    pub timestamp: u64,
}

impl BlockVote {
    /// Create a new block vote.
    pub fn new(
        block_hash: Hash,
        height: BlockHeight,
        round: u64,
        voter: ValidatorId,
        signing_key: &KeyPair,
        timestamp: u64,
    ) -> Self {
        let signature = signing_key.sign(block_hash.as_bytes());
        Self {
            block_hash,
            height,
            round,
            voter,
            signature,
            timestamp,
        }
    }
}

/// Helper functions.
pub mod helpers {
    use super::Hash;

    /// Create a zero hash (all bytes 0x00).
    pub fn zero_hash() -> Hash {
        Hash::ZERO
    }
}

/// Test utilities.
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils {
    use super::*;
    use radix_common::crypto::{Ed25519PublicKey, Ed25519Signature, PublicKey as RadixPublicKey};
    use radix_common::prelude::Epoch;
    use radix_transactions::model::*;

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
