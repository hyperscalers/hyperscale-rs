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
//! - [`ready_signal`]: [`ReadySignal`] validator-emitted "ready on shard"
//!   attestation that proposers pull into the block manifest.
//! - [`witness`]: [`Witness`] / [`ShardWitness`] / [`ShardWitnessPayload`] /
//!   [`ShardWitnessProof`] / [`BeaconWitnessEvent`] (observations the
//!   beacon applies per slot).

pub mod block;
pub mod header;
pub mod limits;
pub mod msc;
pub mod pc;
pub mod proposal;
pub mod ready_signal;
pub mod recovery;
pub mod spc;
pub mod witness;

pub use block::BeaconBlock;
pub use header::BeaconBlockHeader;
pub use limits::{
    MAX_ACCUSATIONS_PER_PROPOSAL, MAX_BEACON_WITNESS_EVENTS_PER_TX, MAX_PREFIX_SIGS,
    MAX_READY_SIGNALS_PER_BLOCK, MAX_READY_WINDOW_BLOCKS, MAX_SKIP_SIGS, MAX_VOTE_VECTOR_LEN,
    MAX_WITNESS_PROOF_DEPTH, MAX_WITNESSES_PER_FETCH, MAX_WITNESSES_PER_PROPOSER,
};
pub use msc::{MscEmptyLowAccusation, MscSlotProposal};
pub use pc::{
    PC_VALUE_ELEMENT_BYTES, PcCompactLenSigner, PcCompactVote, PcDivergingProof, PcQc1, PcQc2,
    PcQc3, PcValueElement, PcVector, PcVote1, PcVote2, PcVote3, PcVoteEquivocation, PcVoteRound,
    PcXpProof,
};
pub use proposal::BeaconProposal;
pub use ready_signal::ReadySignal;
pub use recovery::{
    RecoveryCertificate, RecoveryEquivocation, RecoveryRequest, recovery_cert_hash,
};
pub use spc::{
    SpcCert, SpcEmptyLowEvidence, SpcEmptyViewMsg, SpcHighTriple, SpcProposalObject, SpcSkipSig,
};
pub use witness::{
    BeaconWitness, BeaconWitnessEvent, EquivocationEvidence, ShardWitness, ShardWitnessPayload,
    ShardWitnessProof, Witness,
};
