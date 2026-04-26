//! Cryptographic types and helpers.
//!
//! Re-exports vendor crypto types from `radix_common::crypto` and adds
//! workspace-level helpers split across:
//!
//! - [`keys`]: random and seeded keypair generation, zero-signature placeholders.
//! - [`batch_verify`]: efficient batch verification for Ed25519 and BLS12-381.

pub mod batch_verify;
pub mod keys;

pub use radix_common::crypto::{
    Bls12381G1PrivateKey, Bls12381G1PublicKey, Bls12381G2Signature, Ed25519PrivateKey,
    Ed25519PublicKey, Ed25519Signature, verify_bls12381_v1, verify_ed25519,
};
