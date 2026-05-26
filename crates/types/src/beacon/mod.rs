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
//! - [`pc`]: Prefix Consensus vote / QC wire types.
//! - [`proposal`]: [`BeaconProposal`] (one committee member's slot
//!   submission: witnesses + VRF reveal).
//! - [`recovery`]: [`RecoveryRequest`] and [`RecoveryCertificate`] (committee
//!   replacement after stall) — being phased out; see
//!   `.plans/beacon-recovery-to-skip.md`.
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
pub mod proposal;
pub mod ready_signal;
pub mod recovery;
pub mod skip;
pub mod spc;
pub mod state;
pub mod witness;

pub use block::BeaconBlock;
pub use cert::BeaconCert;
pub use certified::{CertifiedBeaconBlock, CertifiedBeaconBlockPairingError};
pub use genesis::{BeaconGenesisConfig, GenesisPool, GenesisValidator, genesis_config_hash};
pub use limits::{
    MAX_BEACON_WITNESS_EVENTS_PER_TX, MAX_EXCLUDED_VALIDATORS, MAX_PREFIX_SIGS,
    MAX_READY_SIGNALS_PER_BLOCK, MAX_READY_WINDOW_BLOCKS, MAX_VOTE_VECTOR_LEN,
    MAX_WITNESS_PROOF_DEPTH, MAX_WITNESSES_PER_FETCH, MAX_WITNESSES_PER_PROPOSER,
};
pub use pc::{
    PC_VALUE_ELEMENT_BYTES, PcCompactVote, PcDivergingProof, PcQc1, PcQc2, PcQc3, PcSignerLengths,
    PcValueElement, PcVector, PcVote1, PcVote2, PcVote3, PcVoteEquivocation, PcVoteRound,
    PcXpProof,
};
pub use proposal::BeaconProposal;
pub use ready_signal::ReadySignal;
pub use recovery::{RecoveryCertificate, RecoveryEquivocation, RecoveryRequest};
pub use skip::{SkipEpochCert, SkipRequest};
pub use spc::{
    SkipReport, SpcCert, SpcEmptyViewMsg, SpcHighTriple, SpcMessage, SpcProposalObject,
    VpcMsgPayload,
};
pub use state::{
    BeaconState, CommitteeTransition, JailReason, PendingWithdrawal, ShardCommittee, SlotEffects,
    StakePool, TransitionCause, ValidatorRecord, ValidatorStatus,
};
pub use witness::{
    BeaconWitness, BeaconWitnessEvent, EquivocationEvidence, SHARD_WITNESS_LEAF_DOMAIN_TAG,
    ShardWitness, ShardWitnessPayload, ShardWitnessProof, Witness,
};
