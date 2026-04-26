//! Test helpers for Hyperscale — a deterministic BLS committee fixture.
//!
//! [`TestCommittee`] generates seeded BLS keypairs so tests can sign and
//! verify against real cryptographic paths rather than bypassing them with
//! zero signatures.
//!
//! # Example
//!
//! ```rust
//! use hyperscale_test_helpers::TestCommittee;
//! use hyperscale_types::verify_bls12381_v1;
//!
//! let committee = TestCommittee::new(4, 42);
//! let message = b"test message";
//! let signature = committee.keypair(0).sign_v1(message);
//! assert!(verify_bls12381_v1(message, committee.public_key(0), &signature));
//! ```

use hyperscale_types::{
    Block, BlockHash, BlockHeader, BlockHeight, Bls12381G1PrivateKey, Bls12381G1PublicKey,
    Bls12381G2Signature, CertificateRoot, CertifiedBlock, ExecutionCertificate, ExecutionOutcome,
    FinalizedWave, GlobalReceiptHash, GlobalReceiptRoot, LocalReceiptRoot, ProposerTimestamp,
    ProvisionsRoot, QuorumCertificate, Round, RoutableTransaction, ShardGroupId, SignerBitfield,
    StateRoot, TopologySnapshot, TransactionDecision, TransactionRoot, TxHash, TxOutcome,
    ValidatorId, ValidatorInfo, ValidatorSet, WaveCertificate, WaveId, WeightedTimestamp,
    bls_keypair_from_seed,
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

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
            .finish_non_exhaustive()
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
    #[must_use]
    pub fn new(size: usize, seed: u64) -> Self {
        let mut keypairs = Vec::with_capacity(size);
        let mut public_keys = Vec::with_capacity(size);
        let mut validator_ids = Vec::with_capacity(size);

        for i in 0..size {
            // Generate deterministic seed for this validator
            let mut seed_bytes = [0u8; 32];
            let key_seed = seed
                .wrapping_add(i as u64)
                .wrapping_mul(0x517c_c1b7_2722_0a95);
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
    #[must_use]
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
    #[must_use]
    pub const fn size(&self) -> usize {
        self.keypairs.len()
    }

    /// Get a keypair by index.
    ///
    /// # Panics
    ///
    /// Panics if `idx >= size()`.
    #[must_use]
    pub fn keypair(&self, idx: usize) -> &Bls12381G1PrivateKey {
        &self.keypairs[idx]
    }

    /// Get a public key by index.
    ///
    /// # Panics
    ///
    /// Panics if `idx >= size()`.
    #[must_use]
    pub fn public_key(&self, idx: usize) -> &Bls12381G1PublicKey {
        &self.public_keys[idx]
    }

    /// Get a validator ID by index.
    ///
    /// # Panics
    ///
    /// Panics if `idx >= size()`.
    #[must_use]
    pub fn validator_id(&self, idx: usize) -> ValidatorId {
        self.validator_ids[idx]
    }

    /// Get all public keys.
    #[must_use]
    pub fn public_keys(&self) -> &[Bls12381G1PublicKey] {
        &self.public_keys
    }

    /// Get all validator IDs.
    #[must_use]
    pub fn validator_ids(&self) -> &[ValidatorId] {
        &self.validator_ids
    }

    /// Calculate quorum threshold (2f+1 where n = 3f+1).
    ///
    /// For a committee of size n, quorum is ceil(2n/3) + 1.
    #[must_use]
    pub const fn quorum_threshold(&self) -> usize {
        (self.size() * 2 / 3) + 1
    }

    /// Get the indices needed for a minimal quorum.
    ///
    /// Returns the first `quorum_threshold()` indices.
    #[must_use]
    pub fn quorum_indices(&self) -> Vec<usize> {
        (0..self.quorum_threshold()).collect()
    }

    /// Build a [`TopologySnapshot`] from this committee with uniform voting
    /// power. `local_idx` picks which validator the snapshot represents;
    /// `num_shards` sets the shard count for tx routing.
    #[must_use]
    pub fn topology_snapshot(&self, local_idx: usize, num_shards: u64) -> TopologySnapshot {
        let validators: Vec<ValidatorInfo> = (0..self.size())
            .map(|i| ValidatorInfo {
                validator_id: self.validator_id(i),
                public_key: *self.public_key(i),
                voting_power: 1,
            })
            .collect();
        let validator_set = ValidatorSet::new(validators);
        TopologySnapshot::new(self.validator_id(local_idx), num_shards, validator_set)
    }
}

/// Build a minimal `Block::Live` fixture for driving state machines.
///
/// Every non-essential header field takes a zero default: all merkle roots
/// are `Hash::ZERO`, `parent_qc` is `QuorumCertificate::genesis()`, `round`
/// is `Round::INITIAL`, and there are no wave roots or provisions. Callers
/// pass only the bits that vary between tests.
#[must_use]
pub const fn make_live_block(
    shard_group_id: ShardGroupId,
    height: BlockHeight,
    timestamp_ms: u64,
    proposer: ValidatorId,
    transactions: Vec<Arc<RoutableTransaction>>,
    certificates: Vec<Arc<FinalizedWave>>,
) -> Block {
    let header = BlockHeader {
        shard_group_id,
        height,
        parent_hash: BlockHash::ZERO,
        parent_qc: QuorumCertificate::genesis(),
        proposer,
        timestamp: ProposerTimestamp(timestamp_ms),
        round: Round::INITIAL,
        is_fallback: false,
        state_root: StateRoot::ZERO,
        transaction_root: TransactionRoot::ZERO,
        certificate_root: CertificateRoot::ZERO,
        local_receipt_root: LocalReceiptRoot::ZERO,
        provision_root: ProvisionsRoot::ZERO,
        waves: vec![],
        provision_tx_roots: BTreeMap::new(),
        in_flight: 0,
    };
    Block::Live {
        header,
        transactions,
        certificates,
        provisions: vec![],
    }
}

/// Pair a block with a minimal valid `QuorumCertificate` so it satisfies
/// the `CertifiedBlock` pairing invariant.
///
/// `weighted_timestamp_ms` stamps the BFT-authenticated time anchor; pass
/// `0` when retention-window behavior doesn't matter.
#[must_use]
pub fn certify(block: Block, weighted_timestamp_ms: u64) -> CertifiedBlock {
    let qc = QuorumCertificate {
        block_hash: block.hash(),
        weighted_timestamp: WeightedTimestamp(weighted_timestamp_ms),
        ..QuorumCertificate::genesis()
    };
    CertifiedBlock::new_unchecked(block, qc)
}

/// Build a minimal `FinalizedWave` carrying a single tx decision.
///
/// The wave is anchored on `ShardGroupId(0)` with `block_height` as its
/// identity and no remote shard dependencies — sufficient for driving
/// `on_block_committed` when tests only care about tx-terminal-state side
/// effects. The inner EC carries a zeroed BLS signature and a 4-seat
/// signer bitfield, so callers should not feed the result through
/// verification paths.
#[must_use]
pub fn make_finalized_wave(
    block_height: BlockHeight,
    tx_hash: TxHash,
    decision: TransactionDecision,
) -> FinalizedWave {
    let outcome = match decision {
        TransactionDecision::Accept => ExecutionOutcome::Executed {
            receipt_hash: GlobalReceiptHash::ZERO,
            success: true,
        },
        TransactionDecision::Reject => ExecutionOutcome::Executed {
            receipt_hash: GlobalReceiptHash::ZERO,
            success: false,
        },
        TransactionDecision::Aborted => ExecutionOutcome::Aborted,
    };
    let wave_id = WaveId::new(ShardGroupId(0), block_height, BTreeSet::new());
    let ec = ExecutionCertificate::new(
        wave_id.clone(),
        WeightedTimestamp(block_height.0 + 1),
        GlobalReceiptRoot::ZERO,
        vec![TxOutcome { tx_hash, outcome }],
        Bls12381G2Signature([0u8; 96]),
        SignerBitfield::new(4),
    );
    FinalizedWave {
        certificate: Arc::new(WaveCertificate {
            wave_id,
            execution_certificates: vec![Arc::new(ec)],
        }),
        receipts: vec![],
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
