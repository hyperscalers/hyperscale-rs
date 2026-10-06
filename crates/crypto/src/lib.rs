//! Consensus crypto interface.
//!
//! Role newtypes for the key and signature material carried by consensus
//! wire structs, and the [`Signer`] / [`Verifier`] traits every scheme
//! implements. Scheme crates (`hyperscale-crypto-bls`, `hyperscale-crypto-mock`)
//! are the only code that interprets the newtypes' bytes; everything else
//! treats them as opaque containers.
//!
//! The trait ops sit at certificate altitude — "these signers signed this
//! message" — not at the level of any scheme's internal primitives.
//! Threshold and voting-power checks are committee policy and stay at call
//! sites.

mod role;
mod traits;
mod vrf;

pub use role::{
    AGGREGATE_SIGNATURE_BYTES, AggregateSignature, CONSENSUS_PUBLIC_KEY_BYTES,
    CONSENSUS_SIGNATURE_BYTES, ConsensusPublicKey, ConsensusSignature, VerifiedSignature,
};
pub use traits::{AggregateError, SignError, Signer, Verifier};
pub use vrf::{VRF_OUTPUT_BYTES, VRF_PROOF_BYTES, VrfOutput, VrfProof, vrf_output_from_proof};

#[cfg(any(test, feature = "test-utils"))]
mod conformance;

#[cfg(any(test, feature = "test-utils"))]
pub use conformance::run_conformance_suite;
