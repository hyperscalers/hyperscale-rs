//! Core types for Hyperscale consensus.
//!
//! This crate provides the foundational types used throughout the consensus
//! implementation:
//!
//! - **Primitives**: Hash, cryptographic keys and signatures
//! - **Identifiers**: ValidatorId, ShardGroupId, BlockHeight, etc.
//! - **Consensus types**: Block, BlockHeader, QuorumCertificate, etc.
//! - **Wave types**: WaveId, ExecutionVote, ExecutionCertificate, WaveCertificate, etc.
//! - **Network traits**: Message markers for serialization
//!
//! # Design Philosophy
//!
//! This crate is self-contained with minimal dependencies. It does not depend on
//! any other workspace crates, making it the foundation layer.

mod bloom;
mod crypto;
mod hash;
mod hash_kinds;
mod identifiers;
mod network;
mod proofs;
mod signing;
mod timeouts;
mod timestamp;

// Consensus types
mod block;
mod certified_block;
mod epoch;
mod quorum_certificate;
mod receipt;
mod signer_bitfield;
mod state;
mod topology;
mod transaction;
mod validator;
mod wave;

pub use bloom::{BloomFilter, DEFAULT_FPR, MAX_BITS};

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
    ValidatorRating, ValidatorShardState, DEFAULT_EPOCH_LENGTH,
};
pub use hash::{
    compute_merkle_root, compute_merkle_root_with_proof, compute_padded_merkle_root,
    verify_merkle_inclusion, Hash, TypedHash,
};
pub use hash_kinds::{
    BlockHash, CertificateRoot, EventRoot, ExecutionCertificateHash, GlobalReceiptHash,
    GlobalReceiptRoot, LocalReceiptRoot, ProvisionHash, ProvisionTxRoot, ProvisionsRoot, StateRoot,
    TransactionRoot, TxHash, WaveIdHash, WaveReceiptHash, WritesRoot,
};
pub use identifiers::{
    Attempt, BlockHeight, NodeId, PartitionNumber, Round, ShardGroupId, ValidatorId, VotePower,
};
pub use network::{MessagePriority, NetworkMessage, Request, ShardMessage};
pub use proofs::{MerkleInclusionProof, Provision, TxEntries};
pub use signing::{
    block_header_message, block_vote_message, committed_block_header_message,
    exec_cert_batch_message, exec_vote_batch_message, exec_vote_message,
    state_provision_batch_message, validator_bind_message, DOMAIN_BLOCK_HEADER, DOMAIN_BLOCK_VOTE,
    DOMAIN_COMMITTED_BLOCK_HEADER, DOMAIN_EXEC_CERT_BATCH, DOMAIN_EXEC_VOTE,
    DOMAIN_EXEC_VOTE_BATCH, DOMAIN_STATE_PROVISION_BATCH, DOMAIN_VALIDATOR_BIND,
};

pub use block::{
    compute_certificate_root, compute_local_receipt_root, compute_provision_root,
    compute_transaction_root, Block, BlockHeader, BlockManifest, BlockMetadata, BlockVote,
    CommittedBlockHeader,
};
pub use certified_block::{CertifiedBlock, CertifiedBlockHashMismatch};
pub use quorum_certificate::QuorumCertificate;
pub use receipt::{
    ApplicationEvent, ExecutionMetadata, FeeSummary, GlobalReceipt, LocalExecutionEntry,
    LocalReceipt, LogLevel, ReceiptBundle, TransactionOutcome,
};
pub use signer_bitfield::SignerBitfield;
pub use state::{StateEntry, StateProvision};
pub use timeouts::{REMOTE_HEADER_RETENTION, WAVE_TIMEOUT};
pub use timestamp::{ProposerTimestamp, WeightedTimestamp};
pub use topology::{node_id_hash_u64, shard_for_node, TopologySnapshot, TopologySnapshotError};
pub use transaction::{
    sign_and_notarize, sign_and_notarize_with_options, RoutableTransaction, TransactionDecision,
    TransactionError, TransactionStatus, TransactionStatusParseError,
};
pub use validator::{ValidatorInfo, ValidatorSet};
pub use wave::{
    compute_global_receipt_root_with_proof, compute_provision_tx_roots, compute_waves,
    decode_finalized_wave_vec, decode_wave_cert_vec, encode_finalized_wave_vec,
    encode_wave_cert_vec, tx_outcome_leaf, wave_leader, wave_leader_at, ExecutionCertificate,
    ExecutionOutcome, ExecutionVote, FinalizedWave, ReceiptValidationError, TxOutcome,
    WaveCertificate, WaveId,
};
// Re-export with legacy alias for cross-crate use
pub use wave::compute_global_receipt_root as compute_execution_receipt_root;

// Re-export DatabaseUpdates from radix for cross-crate use (execution cache, block commit)
pub use radix_substate_store_interface::interface::DatabaseUpdates;

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
