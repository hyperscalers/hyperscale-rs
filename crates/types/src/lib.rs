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
pub mod network;
mod primitives;
mod provisioning;
mod sbor_codec;
mod signing;
mod time;

// Consensus types
mod beacon;
mod receipt;
mod shard;
mod topology;
mod transaction;
mod wave;

pub use beacon::{
    BeaconBlock, BeaconBlockHeader, BeaconProposal, BeaconState, BeaconWitness, BeaconWitnessEvent,
    CommitteeTransition, EquivocationEvidence, JailReason, MAX_BEACON_WITNESS_EVENTS_PER_TX,
    MAX_EXCLUDED_VALIDATORS, MAX_PREFIX_SIGS, MAX_READY_SIGNALS_PER_BLOCK, MAX_READY_WINDOW_BLOCKS,
    MAX_VOTE_VECTOR_LEN, MAX_WITNESS_PROOF_DEPTH, MAX_WITNESSES_PER_FETCH,
    MAX_WITNESSES_PER_PROPOSER, PC_VALUE_ELEMENT_BYTES, PcCompactVote, PcDivergingProof, PcQc1,
    PcQc2, PcQc3, PcSignerLengths, PcValueElement, PcVector, PcVote1, PcVote2, PcVote3,
    PcVoteEquivocation, PcVoteRound, PcXpProof, PendingWithdrawal, ReadySignal,
    RecoveryCertificate, RecoveryEquivocation, RecoveryRequest, SHARD_WITNESS_LEAF_DOMAIN_TAG,
    ShardCommittee, ShardWitness, ShardWitnessPayload, ShardWitnessProof, SkipReport, SlotEffects,
    SpcCert, SpcEmptyLowEvidence, SpcEmptyViewMsg, SpcHighTriple, SpcMessage, SpcProposalObject,
    StakePool, StateKey, StateProof, StateValue, SubtreePath, TransitionCause, ValidatorRecord,
    ValidatorStatus, VpcMsgPayload, Witness, compute_proposals_root, prove, recovery_cert_hash,
    state_root, verify,
};
pub use crypto::batch_verify::{
    aggregate_verify_bls_different_messages, batch_verify_bls_different_messages,
    batch_verify_bls_different_messages_all_or_nothing, batch_verify_bls_same_message,
    batch_verify_ed25519,
};
pub use crypto::keys::{
    bls_keypair_from_seed, ed25519_keypair_from_seed, generate_bls_keypair,
    generate_ed25519_keypair, zero_bls_signature, zero_ed25519_signature,
};
pub use crypto::vrf::{
    RANDOMNESS_BYTES, Randomness, VRF_OUTPUT_BYTES, VRF_PROOF_BYTES, VrfOutput, VrfProof,
};
pub use crypto::{
    Bls12381G1PrivateKey, Bls12381G1PublicKey, Bls12381G2Signature, Ed25519PrivateKey,
    Ed25519PublicKey, Ed25519Signature, verify_bls12381_v1, verify_ed25519,
};
pub use network::{GossipMessage, MessageClass, NetworkMessage, Request, TopicScope};
pub use primitives::bloom::{BloomFilter, BloomKey, DEFAULT_FPR, MAX_BITS};
pub use primitives::hash::{Hash, TypedHash};
pub use primitives::hash_kinds::{
    BeaconBlockHash, BeaconProposalsRoot, BeaconStateRoot, BeaconWitnessRoot, BlockHash,
    CertificateRoot, EventRoot, GlobalReceiptHash, GlobalReceiptRoot, LocalReceiptRoot,
    ProvisionHash, ProvisionTxRoot, ProvisionsRoot, RecoveryCertHash, StateRoot, TransactionRoot,
    TxHash, WaveReceiptHash, WritesRoot,
};
pub use primitives::identifiers::{
    Attempt, BeaconWitnessLeafCount, BlockHeight, Epoch, HeaderFetchCount, InFlightCount,
    LeafIndex, NodeId, PartitionNumber, RecoveryRound, Round, ShardGroupId, SpcView, Stake,
    StakePoolId, ValidatorId, VotePower,
};
pub use primitives::merkle::{
    compute_merkle_root, compute_merkle_root_with_proof, verify_merkle_inclusion,
};
pub use primitives::positional_bundle::PositionalBundle;
pub use primitives::signer_bitfield::SignerBitfield;
pub use provisioning::entry::ProvisionEntry;
pub use provisioning::limits::{
    MAX_MERKLE_PROOF_LEN, MAX_OWNED_NODES_PER_TX, MAX_STATE_ENTRIES_PER_TX,
    MAX_STATE_ENTRY_KEY_LEN, MAX_STATE_ENTRY_VALUE_LEN,
};
pub use provisioning::proof::MerkleInclusionProof;
pub use provisioning::provisions::Provisions;
pub use provisioning::substate::SubstateEntry;
pub use radix_common::network::NetworkDefinition;
pub use radix_substate_store_interface::interface::DatabaseUpdates;
pub use receipt::consensus::{ConsensusReceipt, FAILED_RECEIPT_HASH};
pub use receipt::global::GlobalReceipt;
pub use receipt::metadata::{ApplicationEvent, EventData, ExecutionMetadata, FeeSummary, LogLevel};
pub use receipt::stored::StoredReceipt;
pub use sbor_codec::{
    BoundedBTreeMap, BoundedBTreeSet, BoundedBytes, BoundedLengthError, BoundedString, BoundedVec,
};
pub use shard::certified::{CertifiedBlock, CertifiedBlockHashMismatch};
pub use shard::committed_header::CommittedBlockHeader;
pub use shard::header::BlockHeader;
pub use shard::inventory::{ElidedCertifiedBlock, Inventory, RehydrateError, RehydrationMiss};
pub use shard::limits::{
    MAX_FINALIZED_TX_PER_BLOCK, MAX_PROVISIONS_PER_BLOCK, MAX_TX_IN_FLIGHT, MAX_TXS_PER_BLOCK,
};
pub use shard::manifest::{BlockManifest, BlockMetadata};
pub use shard::quorum_certificate::QuorumCertificate;
pub use shard::roots::{
    compute_certificate_root, compute_local_receipt_root, compute_provision_root,
    compute_transaction_root,
};
pub use shard::vote::BlockVote;
pub use shard::{Block, SharedCertificates, SharedProvisions, SharedTransactions};
pub use signing::{
    DOMAIN_BEACON_BLOCK_HEADER, DOMAIN_BLOCK_HEADER, DOMAIN_BLOCK_VOTE,
    DOMAIN_COMMITTED_BLOCK_HEADER, DOMAIN_EXEC_CERT_BATCH, DOMAIN_EXEC_VOTE,
    DOMAIN_EXEC_VOTE_BATCH, DOMAIN_PC_EMPTY_VIEW, DOMAIN_PC_VOTE1, DOMAIN_PC_VOTE2,
    DOMAIN_PC_VOTE2_LENGTH, DOMAIN_PC_VOTE3, DOMAIN_PC_VRF, DOMAIN_READY_SIGNAL,
    DOMAIN_RECOVERY_REQUEST, DOMAIN_STATE_PROVISION_BATCH, DOMAIN_VALIDATOR_BIND,
    VALIDATOR_BIND_NONCE_LEN, beacon_block_header_message, block_header_message,
    block_vote_message, committed_block_header_message, exec_cert_batch_message,
    exec_vote_batch_message, exec_vote_message, pc_context, pc_vote_signing_message,
    ready_signal_message, recovery_request_message, spc_context, state_provisions_message,
    validator_bind_message, vrf_output_from_proof, vrf_reveal_message, vrf_sign, vrf_verify,
};
pub use time::limits::{MAX_TIMESTAMP_DELAY, MAX_TIMESTAMP_RUSH};
pub use time::range::{MAX_VALIDITY_RANGE, TimestampRange};
pub use time::timeouts::{
    EPOCH_DURATION, MAX_PROGRESS_WAIT, RECOVERY_TIMEOUT, REMOTE_HEADER_RETENTION,
    RETENTION_HORIZON, VIEW_CHANGE_TIMEOUT, VIEW_CHANGE_TIMEOUT_INCREMENT, VIEW_CHANGE_TIMEOUT_MAX,
    WAVE_TIMEOUT,
};
pub use time::timestamp::{LocalTimestamp, ProposerTimestamp, WeightedTimestamp};
pub use topology::snapshot::{TopologySnapshot, node_id_hash_u64, shard_for_node};
pub use topology::validator::{ValidatorInfo, ValidatorSet};
pub use transaction::constructors::{
    routable_from_notarized_v1, routable_from_notarized_v2, routable_from_user_transaction,
};
pub use transaction::limits::{MAX_DECLARED_NODES_PER_TX, MAX_TX_BYTES_LEN};
pub use transaction::notarize::{sign_and_notarize, sign_and_notarize_with_options};
pub use transaction::routable::RoutableTransaction;
pub use transaction::status::{
    TransactionDecision, TransactionError, TransactionStatus, TransactionStatusParseError,
};
pub use wave::certificate::WaveCertificate;
pub use wave::computation::{
    compute_provision_tx_roots, compute_waves, wave_leader, wave_leader_at,
};
pub use wave::execution_certificate::ExecutionCertificate;
pub use wave::finalized::{FinalizedWave, ReceiptValidationError};
pub use wave::id::{MAX_REMOTE_SHARDS_PER_WAVE, WaveId};
pub use wave::outcome::{ExecutionOutcome, TxOutcome};
pub use wave::receipt_tree::{
    compute_global_receipt_root, compute_global_receipt_root_with_proof, tx_outcome_leaf,
};
pub use wave::vote::ExecutionVote;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;
