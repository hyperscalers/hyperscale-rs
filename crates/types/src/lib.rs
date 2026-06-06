//! Core types for Hyperscale consensus.
//!
//! This crate provides the foundational types used throughout the consensus
//! implementation:
//!
//! - **Primitives**: Hash, cryptographic keys and signatures
//! - **Identifiers**: `ValidatorId`, `ShardId`, `BlockHeight`, etc.
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
pub mod state_key;
mod time;
mod verifiable;

// Consensus types
mod beacon;
mod receipt;
mod shard;
mod topology;
mod transaction;
mod wave;

pub use beacon::{
    BEACON_SIGNER_COUNT, BeaconBlock, BeaconCert, BeaconChainConfig, BeaconGenesisConfig,
    BeaconProposal, BeaconProposalVerifyContext, BeaconProposalVerifyError,
    BeaconProposalWitnessMismatch, BeaconState, BeaconWitnessEvent, CertifiedBeaconBlock,
    CertifiedBeaconBlockPairingError, CertifiedBeaconBlockVerifyContext,
    CertifiedBeaconBlockVerifyError, CommitteeTransition, EMISSIONS_PER_EPOCH, EPOCHS_PER_YEAR,
    GenesisPool, GenesisValidator, JAIL_COOLDOWN_EPOCHS, JailReason,
    MAX_BEACON_WITNESS_EVENTS_PER_TX, MAX_EQUIVOCATIONS_PER_PROPOSER, MAX_PREFIX_SIGS,
    MAX_READY_SIGNALS_PER_BLOCK, MAX_READY_WINDOW_BLOCKS, MAX_SHARD_WITNESSES_PER_PROPOSER,
    MAX_VOTE_VECTOR_LEN, MAX_WITNESS_PROOF_DEPTH, MAX_WITNESSES_PER_FETCH,
    MIN_BEACON_COMMITTEE_SIZE, MIN_STAKE_FLOOR, MISSED_PROPOSAL_JAIL_THRESHOLD,
    PC_VALUE_ELEMENT_BYTES, POOL_BUFFER_TARGET, PcCompactVote, PcDivergingProof, PcQc1,
    PcQc1VerifyError, PcQc2, PcQc2VerifyError, PcQc3, PcQc3VerifyError, PcSignerLengths,
    PcValueElement, PcVector, PcVote1, PcVote1VerifyError, PcVote2, PcVote2VerifyError, PcVote3,
    PcVote3VerifyError, PcVoteEquivocation, PcVoteEquivocationContext,
    PcVoteEquivocationVerifyError, PcVoteRound, PcVoteVerifyContext, PcXpProof, PendingWithdrawal,
    READY_TIMEOUT_EPOCHS, ReadySignal, SHARD_CAPACITY, SHARD_WITNESS_LEAF_DOMAIN_TAG,
    SHUFFLE_INTERVAL_EPOCHS, SPC_VIEW_TIMEOUT, ShardCommittee, ShardWitness, ShardWitnessPayload,
    ShardWitnessProof, ShardWitnessVerifyError, SkipEpochCert, SkipEpochCertVerifyError,
    SkipReport, SkipRequest, SkipRequestVerifyError, SkipVerifyContext, SlotEffects, SpcCert,
    SpcCertVerifyError, SpcEmptyViewMsg, SpcEmptyViewMsgVerifyError, SpcHighTriple,
    SpcHighTripleVerifyError, SpcNewCommitMsg, SpcNewCommitMsgVerifyError, SpcProposalObject,
    SpcProposalObjectVerifyError, SpcVerifyContext, StakePool, TOKENS_PER_YEAR_TARGET,
    TransitionCause, UNBONDING_WINDOW_EPOCHS, ValidatorRecord, ValidatorStatus,
    build_indirect_cert, build_qc1, build_qc2, build_qc3, build_skip_cert, genesis_config_hash,
    hash_high_value, mce, mcp, qc1_certify, sign_empty_view_msg, sign_skip_request, sign_vote1,
    sign_vote2, sign_vote3, skip_target, verify_block_cert, verify_block_equivocations,
    verify_cert, verify_certified, verify_empty_view_msg, verify_proposal_object, verify_qc1,
    verify_qc2, verify_qc3, verify_skip_cert, verify_skip_request, verify_vote_equivocation,
    verify_vote1, verify_vote2, verify_vote3,
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
pub use network::{
    GossipMessage, MessageClass, NetworkMessage, Request, Signed, SignedContext, SignedVerifyError,
    TopicScope,
};
pub use primitives::bloom::{BloomFilter, BloomKey, DEFAULT_FPR, MAX_BITS};
pub use primitives::hash::{Hash, TypedHash};
pub use primitives::hash_kinds::{
    BeaconBlockHash, BeaconWitnessRoot, BlockHash, CertificateRoot, EventRoot, GenesisConfigHash,
    GlobalReceiptHash, GlobalReceiptRoot, LocalReceiptRoot, ProvisionHash, ProvisionTxRoot,
    ProvisionsRoot, StateRoot, TransactionRoot, TxHash, WaveReceiptHash, WritesRoot,
};
pub use primitives::identifiers::{
    Attempt, BeaconWitnessLeafCount, BlockHeight, Epoch, HeaderFetchCount, InFlightCount,
    LeafIndex, NodeId, PartitionNumber, Round, ShardId, SpcView, Stake, StakePoolId, ValidatorId,
    VotePower,
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
pub use provisioning::provisions::{Provisions, ProvisionsContext, ProvisionsVerifyError};
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
pub use shard::certified::{CertifiedBlock, CertifiedBlockHashMismatch, LinkageError};
pub use shard::certified_header::{CertifiedBlockHeader, CertifiedHeaderVerifyError};
pub use shard::header::{BlockHeader, BlockHeaderParentQcMismatch, BlockHeaderVerifyError};
pub use shard::inventory::{ElidedCertifiedBlock, Inventory, RehydrateError, RehydrationMiss};
pub use shard::limits::{
    MAX_FINALIZED_TX_PER_BLOCK, MAX_PROVISIONS_PER_BLOCK, MAX_ROUND_GAP, MAX_TX_IN_FLIGHT,
    MAX_TXS_PER_BLOCK,
};
pub use shard::manifest::{BlockManifest, BlockMetadata};
pub use shard::quorum_certificate::{QcContext, QcVerifyError, QuorumCertificate};
pub use shard::roots::{
    BeaconWitnessRootContext, BeaconWitnessRootVerifyError, CertRootVerifyError,
    CertificateRootContext, LocalReceiptRootContext, LocalReceiptRootVerifyError,
    ProvisionRootVerifyError, ProvisionTxRootsContext, ProvisionTxRootsMap,
    ProvisionTxRootsVerifyError, ProvisionsRootContext, StateRootContext, StateRootVerifyError,
    TransactionRootContext, TxRootVerifyError, derive_leaves, missed_proposals_since_prev_commit,
};
pub use shard::storage_commit::{BeaconWitnessCommit, PreparedCommit, SyncHint};
pub use shard::timeout::{Timeout, TimeoutContext, TimeoutVerifyError};
pub use shard::vote::{BlockVote, BlockVoteContext, BlockVoteVerifyError};
pub use shard::{
    Block, SharedCertificates, SharedProvisions, SharedTransactions, VerifiedBlockAssembleError,
    shared_transactions_from_raw,
};
pub use signing::{
    DOMAIN_BLOCK_HEADER, DOMAIN_BLOCK_VOTE, DOMAIN_COMMITTED_BLOCK_HEADER, DOMAIN_EXEC_CERT_BATCH,
    DOMAIN_EXEC_VOTE, DOMAIN_EXEC_VOTE_BATCH, DOMAIN_PC_EMPTY_VIEW, DOMAIN_PC_VOTE1,
    DOMAIN_PC_VOTE2, DOMAIN_PC_VOTE2_LENGTH, DOMAIN_PC_VOTE3, DOMAIN_PC_VRF, DOMAIN_READY_SIGNAL,
    DOMAIN_SKIP_REQUEST, DOMAIN_SPC_NEW_COMMIT, DOMAIN_SPC_NEW_VIEW, DOMAIN_STATE_PROVISION_BATCH,
    DOMAIN_TIMEOUT, DOMAIN_VALIDATOR_BIND, PcContext, SpcContext, VALIDATOR_BIND_NONCE_LEN,
    block_header_message, block_vote_message, certified_block_header_message,
    exec_cert_batch_message, exec_vote_batch_message, exec_vote_message, pc_context,
    pc_vote_signing_message, ready_signal_message, skip_request_message, spc_context,
    spc_relay_signing_message, state_provisions_message, timeout_message, validator_bind_message,
    vrf_output_from_proof, vrf_reveal_message, vrf_sign, vrf_verify,
};
pub use time::limits::{MAX_TIMESTAMP_DELAY, MAX_TIMESTAMP_RUSH};
pub use time::range::{MAX_VALIDITY_RANGE, TimestampRange};
pub use time::timeouts::{
    EPOCH_DURATION, MAX_PROGRESS_WAIT, REMOTE_HEADER_RETENTION, RETENTION_HORIZON, SKIP_TIMEOUT,
    VIEW_CHANGE_TIMEOUT, VIEW_CHANGE_TIMEOUT_INCREMENT, VIEW_CHANGE_TIMEOUT_MAX, WAVE_TIMEOUT,
};
pub use time::timestamp::{LocalTimestamp, ProposerTimestamp, WeightedTimestamp};
pub use topology::awaiting::AwaitingTopologyBuffer;
pub use topology::schedule::TopologySchedule;
pub use topology::snapshot::{TopologySnapshot, node_id_hash_u64, shard_for_node};
pub use topology::trie::ShardTrie;
pub use topology::validator::{ValidatorInfo, ValidatorSet};
pub use transaction::constructors::{
    routable_from_notarized_v1, routable_from_notarized_v2, routable_from_user_transaction,
};
pub use transaction::limits::{MAX_DECLARED_NODES_PER_TX, MAX_TX_BYTES_LEN};
pub use transaction::notarize::{sign_and_notarize, sign_and_notarize_with_options};
pub use transaction::routable::{
    RoutableTransaction, RoutableTransactionContext, RoutableTransactionVerifyError,
};
pub use transaction::status::{
    TransactionDecision, TransactionError, TransactionStatus, TransactionStatusParseError,
};
pub use verifiable::{Verifiable, Verified, Verify};
pub use wave::certificate::WaveCertificate;
pub use wave::computation::{compute_waves, wave_leader, wave_leader_at};
pub use wave::execution_certificate::{
    ExecutionCertificate, ExecutionCertificateContext, ExecutionCertificateVerifyError,
};
pub use wave::finalized::{
    FinalizedWave, FinalizedWaveContext, FinalizedWaveVerifyError, ReceiptValidationError,
};
pub use wave::id::{MAX_REMOTE_SHARDS_PER_WAVE, WaveId};
pub use wave::outcome::{ExecutionOutcome, TxOutcome};
pub use wave::receipt_tree::{
    compute_global_receipt_root, compute_global_receipt_root_with_proof, tx_outcome_leaf,
};
pub use wave::vote::{ExecutionVote, ExecutionVoteContext, ExecutionVoteVerifyError};

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;
