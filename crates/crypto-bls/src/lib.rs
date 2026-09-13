//! BLS12-381 (min-pk) implementation of the consensus crypto interface.
//!
//! The only crate that interprets the role newtypes' bytes as curve
//! points: public keys are compressed G1, signatures and VRF proofs
//! compressed G2, aggregates the G2 sum of their inputs. Rogue-key
//! safety for the unvalidated pubkey aggregation in
//! [`Verifier::verify_aggregate_same_message`][agg] rests on validator
//! registration proving possession of every key (genesis keys are
//! operator-trusted config).
//!
//! [agg]: hyperscale_crypto::Verifier::verify_aggregate_same_message

pub mod bls12381;
mod keys;
mod signer;
mod verifier;

pub use keys::{bls_keypair_from_seed, generate_bls_keypair};
#[cfg(any(test, feature = "test-utils"))]
pub use keys::{public_key_from_u64_seed, signer_from_u64_seed};
pub use signer::BlsSigner;
pub use verifier::BlsVerifier;
