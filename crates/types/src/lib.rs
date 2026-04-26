//! Core types for Hyperscale consensus.
//!
//! This crate provides the foundational types used throughout the consensus
//! implementation:
//!
//! - **Primitives**: Hash, cryptographic keys and signatures
//! - **Identifiers**: `ValidatorId`, `ShardGroupId`, `BlockHeight`, etc.
//! - **Consensus types**: Block, `BlockHeader`, `QuorumCertificate`, etc.
//! - **Wave types**: `WaveId`, `ExecutionVote`, `ExecutionCertificate`, `WaveCertificate`, etc.
//! - **Network traits**: Message markers for serialization
//!
//! # Design Philosophy
//!
//! This crate is self-contained with minimal dependencies. It does not depend on
//! any other workspace crates, making it the foundation layer.

mod crypto;
mod network;
mod primitives;
mod provisioning;
mod signing;
mod time;

// Consensus types
mod block;
mod quorum_certificate;
mod receipt;
mod topology;
mod transaction;
mod wave;

pub use primitives::bloom::{BloomFilter, DEFAULT_FPR, MAX_BITS};

pub use crypto::batch_verify::{
    batch_verify_bls_different_messages, batch_verify_bls_different_messages_all_or_nothing,
    batch_verify_bls_same_message, batch_verify_ed25519,
};
pub use crypto::keys::{
    bls_keypair_from_seed, ed25519_keypair_from_seed, generate_bls_keypair,
    generate_ed25519_keypair, zero_bls_signature, zero_ed25519_signature,
};
pub use crypto::{
    Bls12381G1PrivateKey, Bls12381G1PublicKey, Bls12381G2Signature, Ed25519PrivateKey,
    Ed25519PublicKey, Ed25519Signature, verify_bls12381_v1, verify_ed25519,
};
pub use network::{MessagePriority, NetworkMessage, Request, ShardMessage};
pub use primitives::hash::{Hash, TypedHash};
pub use primitives::hash_kinds::{
    BlockHash, CertificateRoot, EventRoot, ExecutionCertificateHash, GlobalReceiptHash,
    GlobalReceiptRoot, LocalReceiptRoot, ProvisionHash, ProvisionTxRoot, ProvisionsRoot, StateRoot,
    TransactionRoot, TxHash, WaveIdHash, WaveReceiptHash, WritesRoot,
};
pub use primitives::identifiers::{
    Attempt, BlockHeight, NodeId, PartitionNumber, Round, ShardGroupId, ValidatorId, VotePower,
};
pub use primitives::merkle::{
    compute_merkle_root, compute_merkle_root_with_proof, compute_padded_merkle_root,
    verify_merkle_inclusion,
};
pub use provisioning::batch::Provisions;
pub use provisioning::proof::MerkleInclusionProof;
pub use provisioning::state_entry::{StateEntry, StateProvision};
pub use provisioning::tx_entries::TxEntries;
pub use signing::{
    DOMAIN_BLOCK_HEADER, DOMAIN_BLOCK_VOTE, DOMAIN_COMMITTED_BLOCK_HEADER, DOMAIN_EXEC_CERT_BATCH,
    DOMAIN_EXEC_VOTE, DOMAIN_EXEC_VOTE_BATCH, DOMAIN_STATE_PROVISION_BATCH, DOMAIN_VALIDATOR_BIND,
    block_header_message, block_vote_message, committed_block_header_message,
    exec_cert_batch_message, exec_vote_batch_message, exec_vote_message, state_provisions_message,
    validator_bind_message,
};
pub use topology::consensus_config::{
    GlobalConsensusConfig, GlobalValidatorInfo, ShardCommitteeConfig, ValidatorRating,
};
pub use topology::epoch::{DEFAULT_EPOCH_LENGTH, EpochConfig, EpochId, ValidatorShardState};

pub use block::Block;
pub use block::certified::{CertifiedBlock, CertifiedBlockHashMismatch};
pub use block::committed_header::CommittedBlockHeader;
pub use block::header::BlockHeader;
pub use block::manifest::{BlockManifest, BlockMetadata};
pub use block::roots::{
    compute_certificate_root, compute_local_receipt_root, compute_provision_root,
    compute_transaction_root,
};
pub use block::vote::BlockVote;
pub use primitives::signer_bitfield::SignerBitfield;
pub use quorum_certificate::QuorumCertificate;
pub use receipt::bundle::ReceiptBundle;
pub use receipt::global::GlobalReceipt;
pub use receipt::local::{LocalExecutionEntry, LocalReceipt};
pub use receipt::metadata::{ApplicationEvent, ExecutionMetadata, FeeSummary, LogLevel};
pub use receipt::outcome::TransactionOutcome;
pub use time::range::{MAX_VALIDITY_RANGE, TimestampRange};
pub use time::timeouts::{REMOTE_HEADER_RETENTION, RETENTION_HORIZON, WAVE_TIMEOUT};
pub use time::timestamp::{LocalTimestamp, ProposerTimestamp, WeightedTimestamp};
pub use topology::snapshot::{
    TopologySnapshot, TopologySnapshotError, node_id_hash_u64, shard_for_node,
};
pub use topology::validator::{ValidatorInfo, ValidatorSet};
pub use transaction::constructors::{
    routable_from_notarized_v1, routable_from_notarized_v2, routable_from_user_transaction,
};
pub use transaction::notarize::{sign_and_notarize, sign_and_notarize_with_options};
pub use transaction::routable::RoutableTransaction;
pub use transaction::status::{
    TransactionDecision, TransactionError, TransactionStatus, TransactionStatusParseError,
};
pub use wave::certificate::{WaveCertificate, decode_wave_cert_vec, encode_wave_cert_vec};
pub use wave::computation::{
    compute_provision_tx_roots, compute_waves, wave_leader, wave_leader_at,
};
pub use wave::execution_certificate::ExecutionCertificate;
pub use wave::finalized::{
    FinalizedWave, ReceiptValidationError, decode_finalized_wave_vec, encode_finalized_wave_vec,
};
pub use wave::id::WaveId;
pub use wave::outcome::{ExecutionOutcome, TxOutcome};
pub use wave::receipt_tree::{
    compute_global_receipt_root, compute_global_receipt_root_with_proof, tx_outcome_leaf,
};
pub use wave::vote::ExecutionVote;

// Re-export DatabaseUpdates from radix for cross-crate use (execution cache, block commit)
pub use radix_substate_store_interface::interface::DatabaseUpdates;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;
