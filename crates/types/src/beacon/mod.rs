//! Beacon-chain consensus types.
//!
//! - [`block`]: [`BeaconBlock`] (header + committee aggregate + optional
//!   recovery cert).
//! - [`header`]: [`BeaconBlockHeader`] (committee-signed chain link).
//! - [`limits`]: protocol-level caps on per-proposal payload sizes.
//! - [`msc`]: Multi-Slot Consensus wire types (slot proposals + empty-low
//!   accusations).
//! - [`pc`]: Prefix Consensus vote / QC wire types.
//! - [`proposal`]: [`BeaconProposal`] (one committee member's slot
//!   submission: witnesses + VRF reveal).
//! - [`recovery`]: [`RecoveryRequest`] and [`RecoveryCertificate`] (committee
//!   replacement after stall).
//! - [`spc`]: Strong Prefix Consensus wire types (high triples, empty-view
//!   messages, view-entry certificates).
//! - [`witness`]: [`Witness`] / [`ShardWitness`] / [`ShardWitnessPayload`] /
//!   [`ShardWitnessProof`] / [`JailReason`] (observations the beacon
//!   applies per slot).

pub mod block;
pub mod header;
pub mod limits;
pub mod msc;
pub mod pc;
pub mod proposal;
pub mod recovery;
pub mod spc;
pub mod witness;

pub use block::BeaconBlock;
pub use header::BeaconBlockHeader;
pub use limits::{MAX_PREFIX_SIGS, MAX_SKIP_SIGS, MAX_VOTE_VECTOR_LEN, MAX_WITNESSES_PER_PROPOSER};
pub use msc::{MscEmptyLowAccusation, MscSlotProposal};
pub use pc::{
    PC_VALUE_ELEMENT_BYTES, PcCompactLenSigner, PcCompactVote, PcDivergingProof, PcQc1, PcQc2,
    PcQc3, PcValueElement, PcVector, PcVote1, PcVote2, PcVote3, PcVoteEquivocation, PcVoteRound,
    PcXpProof,
};
pub use proposal::BeaconProposal;
pub use recovery::{
    RecoveryCertificate, RecoveryEquivocation, RecoveryRequest, recovery_cert_hash,
};
pub use spc::{
    SpcCert, SpcEmptyLowEvidence, SpcEmptyViewMsg, SpcHighTriple, SpcProposalObject, SpcSkipSig,
};
pub use witness::{
    BeaconWitness, EquivocationEvidence, JailReason, ShardWitness, ShardWitnessPayload,
    ShardWitnessProof, Witness,
};
