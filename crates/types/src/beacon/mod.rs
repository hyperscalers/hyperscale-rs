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
//! - [`pc`]: Prefix Consensus vote / QC wire types, verify / sign /
//!   build helpers.
//! - [`prefix_ops`]: prefix algebra ([`mcp`], [`mce`], [`qc1_certify`])
//!   the PC build path consumes.
//! - [`proposal`]: [`BeaconProposal`] (one committee member's slot
//!   submission: witnesses + VRF reveal).
//! - [`skip`]: [`SkipRequest`] and [`SkipEpochCert`] (pool-quorum
//!   abandonment of a stalled epoch).
//! - [`spc`]: Strong Prefix Consensus wire types (high triples, empty-view
//!   messages, view-entry certificates).
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
pub mod genesis;
pub mod limits;
pub mod pc;
pub mod prefix_ops;
pub mod proposal;
pub mod ready_signal;
pub mod skip;
pub mod spc;
pub mod state;
pub mod witness;

pub use block::BeaconBlock;
pub use cert::BeaconCert;
pub use certified::{CertifiedBeaconBlock, CertifiedBeaconBlockPairingError};
pub use genesis::{BeaconGenesisConfig, GenesisPool, GenesisValidator, genesis_config_hash};
pub use limits::{
    MAX_BEACON_WITNESS_EVENTS_PER_TX, MAX_PREFIX_SIGS, MAX_READY_SIGNALS_PER_BLOCK,
    MAX_READY_WINDOW_BLOCKS, MAX_VOTE_VECTOR_LEN, MAX_WITNESS_PROOF_DEPTH, MAX_WITNESSES_PER_FETCH,
    MAX_WITNESSES_PER_PROPOSER,
};
pub use pc::{
    PC_VALUE_ELEMENT_BYTES, PcCompactVote, PcDivergingProof, PcQc1, PcQc1VerifyError, PcQc2,
    PcQc2VerifyError, PcQc3, PcQc3VerifyError, PcSignerLengths, PcValueElement, PcVector, PcVote1,
    PcVote1VerifyError, PcVote2, PcVote2VerifyError, PcVote3, PcVote3VerifyError,
    PcVoteEquivocation, PcVoteEquivocationContext, PcVoteEquivocationVerifyError, PcVoteMessage,
    PcVoteMessageVerifyError, PcVoteRound, PcVoteVerifyContext, PcXpProof, build_qc1, build_qc2,
    build_qc3, sign_vote1, sign_vote2, sign_vote3, verify_qc1, verify_qc2, verify_qc3,
    verify_vote_equivocation, verify_vote1, verify_vote2, verify_vote3,
};
pub use prefix_ops::{mce, mcp, qc1_certify};
pub use proposal::BeaconProposal;
pub use ready_signal::ReadySignal;
pub use skip::{SkipEpochCert, SkipRequest};
pub use spc::{SkipReport, SpcCert, SpcEmptyViewMsg, SpcHighTriple, SpcProposalObject};
pub use state::{
    BeaconState, CommitteeTransition, JailReason, PendingWithdrawal, ShardCommittee, SlotEffects,
    StakePool, TransitionCause, ValidatorRecord, ValidatorStatus,
};
pub use witness::{
    BeaconWitnessEvent, SHARD_WITNESS_LEAF_DOMAIN_TAG, ShardWitness, ShardWitnessPayload,
    ShardWitnessProof, Witness,
};
