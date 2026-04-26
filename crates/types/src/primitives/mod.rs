//! Primitive value types shared across the crate.
//!
//! - [`hash`]: 32-byte Blake3 [`Hash`] type and the `hash_newtype!` macro.
//! - [`hash_kinds`]: domain-specific [`Hash`] newtypes (e.g. [`BlockHash`], [`TxHash`]).
//! - [`merkle`]: binary merkle root computation, proof construction, and verification.
//! - [`identifiers`]: thin newtypes for the various IDs ([`ValidatorId`], [`BlockHeight`], etc.).
//! - [`signer_bitfield`]: compact bitfield for tracking validator signatures.
//! - [`bloom`]: typed [`BloomFilter`] used for sync inventory negotiation.

pub mod bloom;
pub mod hash;
pub mod hash_kinds;
pub mod identifiers;
pub mod merkle;
pub mod signer_bitfield;
