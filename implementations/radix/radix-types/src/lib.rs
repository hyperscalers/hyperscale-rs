//! Radix-specific types for the Hyperscale consensus framework.
//!
//! This crate contains types that depend on the Radix ledger:
//! - `RoutableTransaction` — wraps a Radix `UserTransaction` with routing metadata
//! - Ed25519 cryptographic helpers (from `radix_common::crypto`)
//! - Transaction signing utilities (`sign_and_notarize`)
//! - Test utilities for creating mock Radix transactions

pub mod crypto;
mod transaction;

/// Test utilities for creating Radix-specific test fixtures.
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

// Re-export transaction types
pub use transaction::{sign_and_notarize, sign_and_notarize_with_options, RoutableTransaction};

// Re-export Ed25519 types and helpers
pub use crypto::{
    batch_verify_ed25519, ed25519_keypair_from_seed, generate_ed25519_keypair, verify_ed25519,
    zero_ed25519_signature, Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature,
};

// Re-export DatabaseUpdates for cross-crate use
pub use radix_substate_store_interface::interface::DatabaseUpdates;
