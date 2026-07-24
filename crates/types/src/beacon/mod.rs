//! Beacon-chain consensus types.
//!
//! - [`block`]: [`BeaconBlock`] (epoch + parent linkage + committed
//!   proposals). The authenticating cert lives outside the block hash
//!   on a wrapper.
//! - [`cert`]: [`BeaconCert`] discriminator (Genesis / Normal / Skip).
//! - [`certified`]: [`CertifiedBeaconBlock`] — block + cert pair with
//!   decode-checked pairing invariant; mirrors shard
//!   [`CertifiedBlock`](crate::CertifiedBlock).
//! - [`genesis`]: [`BeaconGenesisConfig`] and the chain-identity hash
//!   embedded in [`BeaconCert::Genesis`](crate::BeaconCert::Genesis).
//! - [`limits`]: protocol-level caps on per-proposal payload sizes.
//! - [`params`]: [`NetworkParams`] — the governable subset of chain
//!   parameters, seeded from genesis and mutated only by the fold.
//! - [`pc`]: Prefix Consensus vote / QC wire types, verify / sign /
//!   build helpers.
//! - [`prefix_ops`]: prefix algebra ([`mcp`], [`mce`], [`qc1_certify`])
//!   the PC build path consumes.
//! - [`proposal`]: [`BeaconProposal`] (one committee member's slot
//!   submission: per-shard boundary QCs, equivocations, and a VRF reveal).
//! - [`ratify`]: [`RatifyVote`] / [`RatifyCert`] (the pool-quorum
//!   commit path for every non-genesis block) and
//!   [`CandidateBeaconBlock`] (the SPC output awaiting ratification).
//! - [`spc`]: Strong Prefix Consensus wire types, verify / sign /
//!   build helpers.
//! - [`ready_signal`]: [`ReadySignal`] validator-emitted "ready on shard"
//!   attestation that proposers pull into the block manifest.
//! - [`state`]: [`BeaconState`] and its components (validator records,
//!   pool aggregates, committee tables, the epoch-effect bundle). Pure
//!   data shapes — the application logic that mutates these lives in
//!   `hyperscale_beacon::state`.
//! - [`witness`]: [`Witness`] / [`ShardWitness`] / [`ShardWitnessPayload`] /
//!   [`ShardWitnessProof`] / [`BeaconWitnessEvent`] (observations the
//!   beacon applies per slot).

pub mod block;
pub mod cert;
pub mod certified;
pub mod constants;
pub mod genesis;
pub mod limits;
pub mod params;
pub mod pc;
pub mod prefix_ops;
pub mod proposal;
pub mod ratify;
pub mod ready_signal;
pub mod spc;
pub mod state;
pub mod witness;

pub use block::{BeaconBlock, ShardEpochContribution};
pub use cert::BeaconCert;
pub use certified::{
    CertifiedBeaconBlock, CertifiedBeaconBlockPairingError, CertifiedBeaconBlockVerifyContext,
    CertifiedBeaconBlockVerifyError, verify_block_equivocations, verify_certified,
};
pub use constants::{
    BEACON_SIGNER_COUNT, EMISSIONS_PER_EPOCH, EPOCHS_PER_YEAR, HALT_THRESHOLD_EPOCHS,
    IMPOUND_EPOCHS_DEFAULT, JAIL_COOLDOWN_EPOCHS, MIN_BEACON_COMMITTEE_SIZE, MIN_STAKE_FLOOR,
    MISSED_PROPOSAL_JAIL_THRESHOLD, POOL_BUFFER_TARGET, PRODUCTION_BEACON_COMMITTEE_SIZE,
    RESHAPE_HANDOFF_TTL_EPOCHS, RESHAPE_READY_TTL_EPOCHS, RESHAPE_TRIGGER_TTL_EPOCHS,
    SHARD_CAPACITY, SHUFFLE_SYNC_HEADROOM, SPC_INPUT_DWELL, SPC_VIEW_TIMEOUT,
    TOKENS_PER_YEAR_TARGET, UNBONDING_WINDOW_EPOCHS, byzantine_threshold,
};
pub use genesis::{
    BeaconChainConfig, BeaconGenesisConfig, GenesisPool, GenesisValidator, genesis_config_hash,
};
pub use limits::{
    MAX_BEACON_COMMITTEE, MAX_BEACON_WITNESS_EVENTS_PER_TX, MAX_EQUIVOCATIONS_PER_BLOCK,
    MAX_EQUIVOCATIONS_PER_PROPOSER, MAX_PREFIX_SIGS, MAX_READY_SIGNALS_PER_BLOCK, MAX_SHARDS,
    MAX_VOTE_VECTOR_LEN, MAX_WITNESS_PROOF_DEPTH, MAX_WITNESSES_PER_FETCH, MAX_WITNESSES_PER_SHARD,
};
pub use params::{NetworkParams, ParamBoundsError, ParamProposal, ParamVote};
pub use pc::{
    PC_VALUE_ELEMENT_BYTES, PcCompactVote, PcDivergingProof, PcQc1, PcQc1VerifyError, PcQc2,
    PcQc2VerifyError, PcQc3, PcQc3VerifyError, PcSignerLengths, PcValueElement, PcVector, PcVote1,
    PcVote1VerifyError, PcVote2, PcVote2VerifyError, PcVote3, PcVote3VerifyError,
    PcVoteEquivocation, PcVoteEquivocationContext, PcVoteEquivocationVerifyError, PcVoteRound,
    PcVoteVerifyContext, PcXpProof, build_qc1, build_qc2, build_qc3, sign_vote1, sign_vote2,
    sign_vote3, verify_qc1, verify_qc2, verify_qc3, verify_vote_equivocation, verify_vote1,
    verify_vote2, verify_vote3,
};
pub use prefix_ops::{mce, mcp, qc1_certify};
pub use proposal::{
    BeaconProposal, BeaconProposalEquivocationMismatch, BeaconProposalVerifyContext,
    BeaconProposalVerifyError,
};
pub use ratify::{
    CandidateBeaconBlock, CandidateBeaconBlockVerifyError, CandidateVerifyContext, RatifyCert,
    RatifyCertVerifyError, RatifyPhase, RatifyVerifyContext, RatifyVote, RatifyVoteRecord,
    RatifyVoteVerifyError, build_ratify_cert, ratify_quorum, sign_ratify_vote, verify_ratify_cert,
    verify_ratify_vote,
};
pub use ready_signal::{ReadySignal, ready_signal_window};
pub use spc::{
    SkipReport, SpcCert, SpcCertVerifyError, SpcEmptyViewMsg, SpcEmptyViewMsgVerifyError,
    SpcHighTriple, SpcHighTripleVerifyError, SpcNewCommitMsg, SpcNewCommitMsgVerifyError,
    SpcProposalObject, SpcProposalObjectVerifyError, SpcVerifyContext, build_indirect_cert,
    hash_high_value, sign_empty_view_msg, skip_target, verify_block_cert, verify_cert,
    verify_empty_view_msg, verify_proposal_object,
};
pub use state::{
    BeaconState, CohortSeat, CommitteeTransition, CompletedRecovery, JailReason, KeeperSeat,
    KeptSeat, ObserverSeat, PendingReshape, PendingWithdrawal, PoolConviction, RecoveryCause,
    ShardBoundary, ShardCommittee, ShardRecovery, SlotEffects, StakePool, TransitionCause,
    ValidatorRecord, ValidatorStatus,
};
pub use witness::{
    BeaconWitnessEvent, SHARD_WITNESS_LEAF_DOMAIN_TAG, ShardWitness, ShardWitnessPayload,
    ShardWitnessProof, ShardWitnessVerifyError,
};
