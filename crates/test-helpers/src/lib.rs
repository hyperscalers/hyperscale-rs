//! Test helpers for Hyperscale - provides properly-signed fixtures for crypto testing.
//!
//! This crate provides utilities for creating test fixtures with real BLS signatures,
//! enabling tests to exercise the actual cryptographic verification paths rather than
//! bypassing them with `zero_bls_signature()`.
//!
//! # Example
//!
//! ```rust
//! use hyperscale_test_helpers::{TestCommittee, fixtures};
//! use hyperscale_types::{Hash, BlockHeight, ShardGroupId, verify_bls12381_v1};
//!
//! // Create a committee of 4 validators with deterministic keys
//! let committee = TestCommittee::new(4, 42);
//!
//! // Create a properly-signed block vote
//! let block_hash = Hash::from_bytes(b"test_block");
//! let vote = fixtures::make_signed_block_vote(
//!     &committee,
//!     0, // voter index
//!     block_hash,
//!     BlockHeight(1),
//!     0, // round
//!     ShardGroupId(0),
//! );
//!
//! // The vote has a real BLS signature that can be verified
//! let pk = committee.public_key(0);
//! let msg = hyperscale_types::block_vote_message(ShardGroupId(0), 1, 0, &block_hash);
//! assert!(verify_bls12381_v1(&msg, pk, &vote.signature));
//! ```

pub mod byzantine;
pub mod fixtures;

use hyperscale_types::{
    bls_keypair_from_seed, Bls12381G1PrivateKey, Bls12381G1PublicKey, ValidatorId,
};

/// A test committee of validators with deterministic BLS keypairs.
///
/// Provides easy access to keypairs, public keys, and validator IDs
/// for creating signed test fixtures.
pub struct TestCommittee {
    keypairs: Vec<Bls12381G1PrivateKey>,
    public_keys: Vec<Bls12381G1PublicKey>,
    validator_ids: Vec<ValidatorId>,
}

impl std::fmt::Debug for TestCommittee {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestCommittee")
            .field("size", &self.keypairs.len())
            .field("validator_ids", &self.validator_ids)
            .finish()
    }
}

impl TestCommittee {
    /// Create a new test committee with the given size and seed.
    ///
    /// The seed ensures deterministic key generation for reproducible tests.
    /// Different seeds produce different committees.
    ///
    /// # Example
    ///
    /// ```rust
    /// use hyperscale_test_helpers::TestCommittee;
    ///
    /// let committee = TestCommittee::new(4, 42);
    /// assert_eq!(committee.size(), 4);
    /// ```
    pub fn new(size: usize, seed: u64) -> Self {
        let mut keypairs = Vec::with_capacity(size);
        let mut public_keys = Vec::with_capacity(size);
        let mut validator_ids = Vec::with_capacity(size);

        for i in 0..size {
            // Generate deterministic seed for this validator
            let mut seed_bytes = [0u8; 32];
            let key_seed = seed.wrapping_add(i as u64).wrapping_mul(0x517cc1b727220a95);
            seed_bytes[..8].copy_from_slice(&key_seed.to_le_bytes());
            seed_bytes[8..16].copy_from_slice(&(i as u64).to_le_bytes());
            seed_bytes[16..24].copy_from_slice(&seed.to_le_bytes());

            let kp = bls_keypair_from_seed(&seed_bytes);
            let pk = kp.public_key();

            keypairs.push(kp);
            public_keys.push(pk);
            validator_ids.push(ValidatorId(i as u64));
        }

        Self {
            keypairs,
            public_keys,
            validator_ids,
        }
    }

    /// Create a test committee for a specific shard with offset validator IDs.
    ///
    /// Useful for multi-shard tests where validator IDs need to be globally unique.
    ///
    /// # Example
    ///
    /// ```rust
    /// use hyperscale_test_helpers::TestCommittee;
    ///
    /// // Shard 0: validators 0, 1, 2, 3
    /// let shard0 = TestCommittee::for_shard(4, 42, 0);
    /// assert_eq!(shard0.validator_id(0).0, 0);
    ///
    /// // Shard 1: validators 4, 5, 6, 7
    /// let shard1 = TestCommittee::for_shard(4, 42, 1);
    /// assert_eq!(shard1.validator_id(0).0, 4);
    /// ```
    pub fn for_shard(size: usize, seed: u64, shard_index: u64) -> Self {
        let mut committee = Self::new(size, seed.wrapping_add(shard_index * 1000));

        // Offset validator IDs by shard
        let offset = shard_index * size as u64;
        for (i, vid) in committee.validator_ids.iter_mut().enumerate() {
            *vid = ValidatorId(offset + i as u64);
        }

        committee
    }

    /// Get the number of validators in the committee.
    pub fn size(&self) -> usize {
        self.keypairs.len()
    }

    /// Get a keypair by index.
    ///
    /// # Panics
    ///
    /// Panics if `idx >= size()`.
    pub fn keypair(&self, idx: usize) -> &Bls12381G1PrivateKey {
        &self.keypairs[idx]
    }

    /// Get a public key by index.
    ///
    /// # Panics
    ///
    /// Panics if `idx >= size()`.
    pub fn public_key(&self, idx: usize) -> &Bls12381G1PublicKey {
        &self.public_keys[idx]
    }

    /// Get a validator ID by index.
    ///
    /// # Panics
    ///
    /// Panics if `idx >= size()`.
    pub fn validator_id(&self, idx: usize) -> ValidatorId {
        self.validator_ids[idx]
    }

    /// Get all public keys.
    pub fn public_keys(&self) -> &[Bls12381G1PublicKey] {
        &self.public_keys
    }

    /// Get all validator IDs.
    pub fn validator_ids(&self) -> &[ValidatorId] {
        &self.validator_ids
    }

    /// Calculate quorum threshold (2f+1 where n = 3f+1).
    ///
    /// For a committee of size n, quorum is ceil(2n/3) + 1.
    pub fn quorum_threshold(&self) -> usize {
        (self.size() * 2 / 3) + 1
    }

    /// Get the indices needed for a minimal quorum.
    ///
    /// Returns the first `quorum_threshold()` indices.
    pub fn quorum_indices(&self) -> Vec<usize> {
        (0..self.quorum_threshold()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::verify_bls12381_v1;

    #[test]
    fn test_committee_creation() {
        let committee = TestCommittee::new(4, 42);

        assert_eq!(committee.size(), 4);
        assert_eq!(committee.validator_id(0), ValidatorId(0));
        assert_eq!(committee.validator_id(3), ValidatorId(3));
    }

    #[test]
    fn test_committee_deterministic() {
        let c1 = TestCommittee::new(4, 42);
        let c2 = TestCommittee::new(4, 42);

        // Same seed should produce same keys
        for i in 0..4 {
            assert_eq!(c1.public_key(i).0, c2.public_key(i).0);
        }
    }

    #[test]
    fn test_committee_different_seeds() {
        let c1 = TestCommittee::new(4, 42);
        let c2 = TestCommittee::new(4, 43);

        // Different seeds should produce different keys
        assert_ne!(c1.public_key(0).0, c2.public_key(0).0);
    }

    #[test]
    fn test_for_shard() {
        let shard0 = TestCommittee::for_shard(4, 42, 0);
        let shard1 = TestCommittee::for_shard(4, 42, 1);

        // Shard 0 has validators 0-3
        assert_eq!(shard0.validator_id(0), ValidatorId(0));
        assert_eq!(shard0.validator_id(3), ValidatorId(3));

        // Shard 1 has validators 4-7
        assert_eq!(shard1.validator_id(0), ValidatorId(4));
        assert_eq!(shard1.validator_id(3), ValidatorId(7));
    }

    #[test]
    fn test_quorum_threshold() {
        // n=4: f=1, quorum=3
        assert_eq!(TestCommittee::new(4, 0).quorum_threshold(), 3);

        // n=7: f=2, quorum=5
        assert_eq!(TestCommittee::new(7, 0).quorum_threshold(), 5);

        // n=10: f=3, quorum=7
        assert_eq!(TestCommittee::new(10, 0).quorum_threshold(), 7);
    }

    #[test]
    fn test_keypair_signing() {
        let committee = TestCommittee::new(4, 42);

        let message = b"test message";
        let signature = committee.keypair(0).sign_v1(message);

        // Verify with the corresponding public key
        assert!(verify_bls12381_v1(
            message,
            committee.public_key(0),
            &signature
        ));

        // Should not verify with different public key
        assert!(!verify_bls12381_v1(
            message,
            committee.public_key(1),
            &signature
        ));
    }
}
