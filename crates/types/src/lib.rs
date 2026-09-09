//! Core types for Hyperscale consensus.
//!
//! This crate provides the foundational types used throughout the consensus
//! implementation:
//!
//! - **Primitives**: hashes, merkle roots, signer bitfields, randomness
//! - **Identifiers**: `ValidatorId`, `ShardId`, `BlockHeight`, etc.
//! - **Consensus types**: Block, `BlockHeader`, `QuorumCertificate`, etc.
//! - **Tick types**: `TickId`, `ExecutionVote`, `ExecutionCertificate`, `Finalization`, etc.
//! - **Network traits**: Message markers for serialization
//!
//! # Design Philosophy
//!
//! The foundation layer: every wire struct and the [`Verify`] predicate that
//! admits it live here. Signature checks route through the injected
//! [`Verifier`], so no scheme is named anywhere in the crate — its only
//! workspace dependencies are that crypto interface and the JMT whose
//! inclusion proofs the provisioning types verify.

mod crypto;
mod hashing;
pub mod network;
mod primitives;
mod provisioning;
mod signing;
pub mod state_holds;
pub mod state_key;
mod time;
mod verifiable;

// Consensus types
mod beacon;
mod execution;
mod receipt;
mod shard;
mod topology;
mod transaction;

pub use beacon::{
    BEACON_SIGNER_COUNT, BeaconBlock, BeaconCert, BeaconChainConfig, BeaconGenesisConfig,
    BeaconProposal, BeaconProposalEquivocationMismatch, BeaconProposalVerifyContext,
    BeaconProposalVerifyError, BeaconState, BeaconWitnessEvent, CandidateBeaconBlock,
    CandidateBeaconBlockVerifyError, CandidateVerifyContext, CertifiedBeaconBlock,
    CertifiedBeaconBlockPairingError, CertifiedBeaconBlockVerifyContext,
    CertifiedBeaconBlockVerifyError, CohortSeat, CommitteeTransition, CompletedRecovery,
    EMISSION_PARTICIPATION_WEIGHT, EMISSION_STORAGE_WEIGHT, EMISSION_WORK_WEIGHT,
    EMISSIONS_PER_EPOCH, EPOCHS_PER_YEAR, GenesisPool, GenesisValidator, HALT_THRESHOLD_EPOCHS,
    IMPOUND_EPOCHS_DEFAULT, JAIL_COOLDOWN_EPOCHS, JailReason, KeeperSeat, KeptSeat,
    MAX_BEACON_COMMITTEE, MAX_BEACON_WITNESS_EVENTS_PER_TX, MAX_EQUIVOCATIONS_PER_PROPOSER,
    MAX_FORK_PROOFS_PER_PROPOSER, MAX_PREFIX_SIGS, MAX_RANGE_PROOF_NODES,
    MAX_READY_SIGNALS_PER_BLOCK, MAX_SHARDS, MAX_VOTE_VECTOR_LEN, MAX_WITNESS_PROOF_DEPTH,
    MAX_WITNESSES_PER_FETCH, MAX_WITNESSES_PER_SHARD, MIN_BEACON_COMMITTEE_SIZE, MIN_STAKE_FLOOR,
    MISSED_PROPOSAL_JAIL_THRESHOLD, NetworkParams, ObserverSeat, PACKAGE_MATURITY_EPOCHS,
    PC_VALUE_ELEMENT_BYTES, POOL_BUFFER_TARGET, PRODUCTION_BEACON_COMMITTEE_SIZE, PackageFact,
    ParamBoundsError, ParamProposal, ParamVote, PcCompactVote, PcDivergingProof, PcQc1,
    PcQc1VerifyError, PcQc2, PcQc2VerifyError, PcQc3, PcQc3VerifyError, PcSignerLengths,
    PcValueElement, PcVector, PcVote1, PcVote1VerifyError, PcVote2, PcVote2VerifyError, PcVote3,
    PcVote3VerifyError, PcVoteEquivocation, PcVoteEquivocationContext,
    PcVoteEquivocationVerifyError, PcVoteRound, PcVoteVerifyContext, PcXpProof, PendingReshape,
    PendingRotation, PendingWithdrawal, PoolConviction, RESHAPE_HANDOFF_TTL_EPOCHS,
    RESHAPE_READY_TTL_EPOCHS, RESHAPE_TRIGGER_TTL_EPOCHS, RatifyCert, RatifyCertVerifyError,
    RatifyPhase, RatifyVerifyContext, RatifyVote, RatifyVoteRecord, RatifyVoteVerifyError,
    ReadySignal, RecoveryCause, SHARD_CAPACITY, SHARD_WITNESS_LEAF_DOMAIN_TAG,
    SHUFFLE_SYNC_HEADROOM, SPC_INPUT_DWELL, SPC_VIEW_TIMEOUT, ScheduledSplit, ShardBoundary,
    ShardCommittee, ShardEpochContribution, ShardRecovery, ShardWitnessPayload, SkipReport,
    SlotEffects, SpcCert, SpcCertVerifyError, SpcEmptyViewMsg, SpcEmptyViewMsgVerifyError,
    SpcHighTriple, SpcHighTripleVerifyError, SpcNewCommitMsg, SpcNewCommitMsgVerifyError,
    SpcProposalObject, SpcProposalObjectVerifyError, SpcVerifyContext, StakePool,
    TERMINAL_EVIDENCE_EPOCHS, TOKENS_PER_YEAR_TARGET, TransitionCause, UNBONDING_WINDOW_EPOCHS,
    ValidatorRecord, ValidatorStatus, build_indirect_cert, build_qc1, build_qc2, build_qc3,
    build_ratify_cert, byzantine_threshold, genesis_config_hash, hash_high_value, mce, mcp,
    qc1_certify, ratify_quorum, ready_signal_window, sign_empty_view_msg, sign_ratify_vote,
    sign_vote1, sign_vote2, sign_vote3, skip_target, verify_block_cert, verify_block_equivocations,
    verify_cert, verify_certified, verify_empty_view_msg, verify_proposal_object, verify_qc1,
    verify_qc2, verify_qc3, verify_ratify_cert, verify_ratify_vote, verify_vote_equivocation,
    verify_vote1, verify_vote2, verify_vote3,
};
pub use crypto::keys::{ed25519_keypair_from_seed, generate_ed25519_keypair};
pub use crypto::{Ed25519PrivateKey, MlDsa65PrivateKey, Secp256k1PrivateKey};
pub use execution::computation::{tick_leader, tick_leader_at};
pub use execution::execution_certificate::{
    ExecutionCertificate, ExecutionCertificateContext, ExecutionCertificateVerifyError, Spoken,
};
pub use execution::finalization::{
    Finalization, FinalizationContext, FinalizationVerifyError,
    MAX_EXECUTION_CERTIFICATES_PER_TICK, ReceiptValidationError, Settles, TickHalf,
    refused_transactions, settles,
};
pub use execution::outcome::{EscrowedValue, ExecutionOutcome, Role, TxOutcome};
pub use execution::receipt_tree::{
    compute_global_receipt_root, compute_global_receipt_root_with_proof, tx_outcome_leaf,
};
pub use execution::tick_id::TickId;
pub use execution::vote::{ExecutionVote, ExecutionVoteContext, ExecutionVoteVerifyError};
pub use hashing::ProtocolHasher;
pub use hyperscale_crypto::{
    AggregateError, AggregateSignature, CONSENSUS_PUBLIC_KEY_BYTES, CONSENSUS_SIGNATURE_BYTES,
    ConsensusPublicKey, ConsensusSignature, SignError, Signer, VRF_PROOF_BYTES, Verifier,
    VrfOutput, VrfProof,
};
pub use hyperscale_hbor::HborSigned;
pub use hyperscale_vm_types::{
    AMOUNT_CELL_BYTES, AccountSigner, Address, AddressClass, CallTarget, CollectionId,
    ComponentAddr, Compose, EntryKey, EntryLeaf, InvalidAddress, LEAF_KEY_BYTES, LocalKey,
    MAX_CELL_VALUE_LEN, Mode, ModeKind, Movement, NativeAddr, NotCallable, OverDebit, PackageAddr,
    Presence, PrincipalAddr, ResourceAddr, SWEEP_BUCKET_BYTES, SWEEP_BUCKET_SHIFT, SchemeId,
    SettledCells, SettledEntries, SettledWrites, StateWrites, SubstateKey, SweepBucket, TX_UNITS,
    amount_cell, compatible, declared_work, encode_amount, entry_leaf_key, read_amount,
};
pub use network::{
    GossipMessage, MessageClass, NetworkMessage, Request, Signed, SignedContext, SignedVerifyError,
    TopicScope,
};
pub use primitives::bloom::{BloomFilter, BloomKey, DEFAULT_FPR, MAX_BITS};
pub use primitives::hash::{Hash, TypedHash};
pub use primitives::hash_kinds::{
    AbandonmentRoot, BeaconBlockHash, BeaconWitnessRoot, BlockHash, CertificateRoot,
    CommittedTxsRoot, EventRoot, FinalizationHash, GenesisConfigHash, GlobalReceiptHash,
    GlobalReceiptRoot, LocalReceiptRoot, ProvisionHash, ProvisionTxRoot, ProvisionsRoot,
    RevealChain, SettledTxsRoot, StateClaimsRoot, StateRoot, TransactionRoot, TxHash, WritesRoot,
};
pub use primitives::identifiers::{
    Attempt, BeaconWitnessLeafCount, BlockHeight, Epoch, HeaderFetchCount, LeafIndex, RatifyRound,
    Round, ShardId, SpcView, Stake, StakePoolId, StakePoolSeat, ValidatorId, VoteCount,
    WorkInFlight,
};
pub use primitives::merkle::{
    compute_merkle_root, compute_merkle_root_with_proof, compute_range_proof, compute_sparse_proof,
    verify_merkle_inclusion, verify_range_inclusion, verify_sparse_inclusion,
};
pub use primitives::positional_bundle::PositionalBundle;
pub use primitives::randomness::{RANDOMNESS_BYTES, Randomness};
pub use primitives::seeds::{EpochSeed, SEED_WINDOW_EPOCHS, SeedLookup, SeedRing, SeedSource};
pub use primitives::signer_bitfield::SignerBitfield;
pub use provisioning::entry::ProvisionEntry;
pub use provisioning::limits::{MAX_MERKLE_PROOF_LEN, MAX_STATE_ENTRIES_PER_TX};
pub use provisioning::proof::{Inclusion, MerkleInclusionProof, StateProofError};
pub use provisioning::provisions::{Provisions, ProvisionsContext, ProvisionsVerifyError};
pub use provisioning::substate::{SubstateEntry, SubstateLeaf};
pub use receipt::consensus::{ConsensusReceipt, FAILED_RECEIPT_HASH, absorb_committed_cells};
pub use receipt::event::{
    Event, EventExt, MAX_ERROR_CODES, MAX_EVENT_PAYLOAD_BYTES, MAX_EVENT_TYPES, MAX_EVENTS_PER_TX,
};
pub use receipt::global::GlobalReceipt;
pub use receipt::metadata::{ExecutionMetadata, FeeSummary, LogLevel};
pub use receipt::stored::StoredReceipt;
pub use shard::abandonment::{
    AbandonmentRecord, AbortCharge, CommittedAt, Resolutions, UnsettledTx,
};
pub use shard::anchor::Anchor;
pub use shard::certified::{CertifiedBlock, CertifiedBlockHashMismatch, LinkageError};
pub use shard::certified_header::{CertifiedBlockHeader, CertifiedHeaderVerifyError};
pub use shard::chain_origin::{ChainOrigin, PredecessorTerminal};
pub use shard::commit_proof::{
    CommitProof, CommitProofVerifyError, MAX_COMMIT_PROOF_ANCESTRY, ResolvedCommittee,
};
pub use shard::counterpart_mirror::CounterpartMirror;
pub use shard::demands::{CheckOutcome, DeferOn, Demands, VerificationKind};
pub use shard::evidence::{
    ShardForkProof, ShardForkProofVerifyError, ShardVoteEquivocation, ShardVoteEquivocationContext,
    ShardVoteEquivocationVerifyError, verify_shard_vote_equivocation,
};
pub use shard::fork_fence::ForkFence;
pub use shard::header::{
    BlockHeader, BlockHeaderParentQcMismatch, BlockHeaderParts, BlockHeaderVerifyError,
    CommittedTip,
};
pub use shard::inventory::{ElidedCertifiedBlock, Inventory, RehydrateError, RehydrationMiss};
pub use shard::limits::{
    ABANDONMENT_RECORD_BYTES, MAX_DRAIN_WORK, MAX_FINALIZED_TX_PER_BLOCK, MAX_GAS_LIMIT,
    MAX_PREFIXES_PER_TX, MAX_PROOFS_PER_QUERY, MAX_PROPOSAL_EVIDENCE_BYTES,
    MAX_PROVISION_TARGET_SHARDS, MAX_PROVISIONS_PER_BLOCK, MAX_ROUND_GAP,
    MAX_STATE_CLAIMS_PER_BLOCK, MAX_SWEEP_PER_BLOCK, MAX_SWEEPABLE_CREATED_PER_BLOCK,
    MAX_TXS_PER_BLOCK, MAX_UNSETTLED_PER_BLOCK, MAX_WIRE_MESSAGE_BYTES, ROUTE_PREFIX_BYTES,
    UNSETTLED_TX_BYTES, drain_admits_block, evidence_admits_block, sweep_admits_block,
};
pub use shard::load::ShardLoad;
pub use shard::manifest::{BlockManifest, BlockMetadata};
pub use shard::proven_anchors::ProvenAnchors;
pub use shard::proven_cells::ProvenCells;
pub use shard::quorum_certificate::{QcContext, QcVerifyError, QuorumCertificate};
pub use shard::reshape::{ReshapeThresholds, ReshapeTrigger};
pub use shard::roots::{
    BeaconWitnessRootContext, BeaconWitnessRootVerifyError, CommittedTxAbsence, LeafRoot,
    ProvisionTxRootsContext, ProvisionTxRootsMap, ProvisionTxRootsVerifyError,
    REVEAL_CHAIN_DOMAIN_TAG, RootMismatch, SplitChildRoots, StateRootContext, StateRootVerifyError,
    TerminalRoots, TransactionRootContext, TxRootVerifyError, commit_witness_window,
    committed_crossings, committed_tx_leaf, committed_txs_root_from_hashes, derive_leaves,
    derive_reshape_trigger, extend_reveal_chain, local_settled_tx_hashes,
    missed_proposals_since_prev_commit, next_reveal_chain, prove_committed_tx_absent,
    ready_leaf_payload, settled_txs_root_from_hashes,
};
pub use shard::state_claim::StateClaim;
pub use shard::storage_commit::{BeaconWitnessCommit, PreparedCommit, SyncHint};
pub use shard::sweep::{SWEEP_BUCKET_MS, SweepFrontier, expired_at};
pub use shard::timeout::{Timeout, TimeoutContext, TimeoutVerifyError};
pub use shard::vote::{BlockVote, BlockVoteContext, BlockVoteVerifyError};
pub use shard::vote_registers::{SafeVoteRegisters, VotePosition};
pub use shard::{
    Block, SharedCertificates, SharedProvisions, SharedTransactions, SharedWitnessSources,
    TerminalRef, VerifiedBlockAssembleError, WitnessSources, derive_block_transactions,
    work_over_certificates,
};
pub use signing::{
    BeaconRevealMessage, BlockProposalMessage, BlockVoteMessage, CertifiedBlockHeaderSenderMessage,
    ExecutionCertificatesSenderMessage, ExecutionVoteMessage, ExecutionVotesSenderMessage,
    NetworkId, PcRound, PcScope, PcVoteMessage, ProvisionsSenderMessage, RatifyVoteMessage,
    ShardRevealMessage, SpcEmptyViewMessage, SpcRelayKind, SpcRelayMessage,
    VALIDATOR_BIND_NONCE_LEN, ValidatorAddressMessage, ValidatorBindMessage,
    ValidatorPossessionProofMessage, beacon_reveal_sign, beacon_reveal_verify, shard_reveal_sign,
    shard_reveal_verify, signed_bytes, validator_possession_proof_sign,
    validator_possession_proof_verify, vrf_output_from_proof,
};
pub use state_holds::ProvisionalHolds;
pub use time::deadline::{CLAIM_WINDOW, Deadline, Probed, TRANSACTION_EVIDENCE_HORIZON, Window};
pub use time::epoch_windows::EpochWindows;
pub use time::limits::{MAX_TIMESTAMP_DELAY, MAX_TIMESTAMP_RUSH};
pub use time::range::{MAX_SUBINTENT_VALIDITY_RANGE, MAX_VALIDITY_RANGE, TimestampRange};
pub use time::stopwatch::Stopwatch;
pub use time::timeouts::{
    CLAIM_VISIBILITY_LAG, DEDUP_WINDOW, EPOCH_DURATION, MAX_FINALIZATION_DELAY, MAX_PROGRESS_WAIT,
    RATIFY_ROUND_TIMEOUT, REMOTE_HEADER_RETENTION, RETENTION_HORIZON, SKIP_TIMEOUT,
    VIEW_CHANGE_TIMEOUT, VIEW_CHANGE_TIMEOUT_INCREMENT, VIEW_CHANGE_TIMEOUT_MAX,
};
pub use time::timestamp::{LocalTimestamp, ProposerTimestamp, WeightedTimestamp};
pub use topology::genesis::GenesisValidators;
pub use topology::network::{NetworkDefinition, UnknownNetwork};
pub use topology::schedule::{
    RoutingCommittees, ScheduleLookup, SplitAtBoundary, TopologySchedule,
};
pub use topology::settled_set::{
    SettledSetVerdict, SettledTxSet, TerminalEvidence, TxClaim, settled_set_verdict,
};
pub use topology::shard_prefix::shard_prefix_path;
pub use topology::snapshot::{ReshapeSeat, ShardAnchor, TopologySnapshot};
pub use topology::trie::{RoutePrefix, ShardTrie};
pub use topology::validator::{ValidatorInfo, ValidatorSet};
pub use transaction::declared_key::{DeclaredKey, DeclaredRange};
pub use transaction::limits::MAX_TX_BYTES_LEN;
pub use transaction::status::{
    TransactionDecision, TransactionError, TransactionStatus, TransactionStatusParseError,
    TxResolution,
};
pub use transaction::vm::{
    Derivation, DerivationError, Derived, EnvelopeExt, MAX_MESSAGE_LEN, MAX_SUBINTENTS,
    ProtocolStatics, ProtocolVerifier, Routing, SchemeVerifier, SubintentSig, TransactionBody,
    TransactionEnvelope, install_protocol_statics, protocol_statics, protocol_statics_installed,
};
pub use transaction::wire::{Transaction, TransactionContext, TransactionVerifyError};
pub use verifiable::{Verifiable, Verified, Verify};

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;
