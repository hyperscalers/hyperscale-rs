//! Deterministic cluster test fixtures shared across the production runner,
//! libp2p transport, and scenario test suites.
//!
//! Generates seeded BLS (consensus) and Ed25519 (libp2p) keypairs plus a
//! topology snapshot from one seed, so every consumer derives byte-identical
//! identities.

use std::sync::Arc;

use hyperscale_network::ValidatorKeyMap;
use hyperscale_types::{
    Bls12381G1PrivateKey, Bls12381G1PublicKey, GenesisValidators, NetworkDefinition, ValidatorId,
    ValidatorInfo, ValidatorSet, bls_keypair_from_seed,
};
use libp2p::PeerId;
use libp2p::identity::Keypair;
use libp2p::identity::ed25519::{Keypair as Ed25519Keypair, SecretKey};

/// Generate `num_validators` deterministic BLS (consensus) and Ed25519
/// (libp2p) keypairs from `seed`, on independent derivation paths.
fn derive_keypairs(seed: u64, num_validators: u32) -> (Vec<Bls12381G1PrivateKey>, Vec<Keypair>) {
    let bls_keys = (0..num_validators)
        .map(|i| {
            let mut seed_bytes = [0u8; 32];
            let key_seed = seed
                .wrapping_add(u64::from(i))
                .wrapping_mul(0x517c_c1b7_2722_0a95);
            seed_bytes[..8].copy_from_slice(&key_seed.to_le_bytes());
            seed_bytes[8..16].copy_from_slice(&u64::from(i).to_le_bytes());
            bls_keypair_from_seed(&seed_bytes)
        })
        .collect();

    let ed25519_keys = (0..num_validators)
        .map(|i| {
            let mut seed_bytes = [0u8; 32];
            let key_seed = seed
                .wrapping_add(u64::from(i))
                .wrapping_mul(0x9e37_79b9_7f4a_7c15);
            seed_bytes[..8].copy_from_slice(&key_seed.to_le_bytes());
            seed_bytes[8..16].copy_from_slice(&u64::from(i).to_le_bytes());
            seed_bytes[16..24].copy_from_slice(b"ed25519k"); // Domain separation
            let secret = SecretKey::try_from_bytes(seed_bytes).expect("valid ed25519 seed");
            Keypair::from(Ed25519Keypair::from(secret))
        })
        .collect();

    (bls_keys, ed25519_keys)
}

/// Test fixtures for deterministic test setup.
///
/// Creates a set of validators with BLS keys for consensus and Ed25519 keys
/// for libp2p networking, all derived from a seed for reproducibility.
pub struct TestFixtures {
    /// BLS keypairs for consensus (one per validator).
    pub bls_keys: Vec<Bls12381G1PrivateKey>,

    /// Ed25519 keypairs for libp2p (one per validator).
    pub ed25519_keys: Vec<Keypair>,

    /// The genesis validators a runner projects its initial topology snapshot
    /// from.
    genesis: GenesisValidators,

    /// Number of validators (ROOT committee plus pooled surplus).
    pub num_validators: u32,
}

impl TestFixtures {
    /// Deterministic fixtures seating every validator in the single genesis
    /// ROOT committee. Derives both BLS and Ed25519 keys from `seed`.
    #[must_use]
    pub fn new(seed: u64, num_validators: u32) -> Self {
        Self::with_surplus(seed, num_validators, 0)
    }

    /// Deterministic fixtures seating `committee_size` validators in the genesis
    /// ROOT committee, plus `surplus` validators registered in the global set
    /// (and the beacon genesis pool) but seated nowhere — the production analog
    /// of the sim's `pool_surplus`, the pool a reshape draws a child
    /// cohort from. Validator ids `[0, committee_size)` seat the root; ids
    /// `[committee_size, committee_size + surplus)` are the surplus.
    #[must_use]
    pub fn with_surplus(seed: u64, committee_size: u32, surplus: u32) -> Self {
        let num_validators = committee_size + surplus;

        let (bls_keys, ed25519_keys) = derive_keypairs(seed, num_validators);

        let public_keys: Vec<Bls12381G1PublicKey> = bls_keys
            .iter()
            .map(Bls12381G1PrivateKey::public_key)
            .collect();

        let validators: Vec<ValidatorInfo> = (0..num_validators)
            .map(|i| ValidatorInfo {
                validator_id: ValidatorId::new(u64::from(i)),
                public_key: public_keys[i as usize],
            })
            .collect();
        let validator_set = ValidatorSet::new(validators);

        let committee: Vec<ValidatorId> = (0..committee_size)
            .map(|i| ValidatorId::new(u64::from(i)))
            .collect();
        let genesis =
            GenesisValidators::new(NetworkDefinition::simulator(), validator_set, committee);

        Self {
            bls_keys,
            ed25519_keys,
            genesis,
            num_validators,
        }
    }

    /// Get the genesis validators a runner projects its initial topology
    /// snapshot from.
    #[must_use]
    pub fn genesis_validators(&self) -> GenesisValidators {
        self.genesis.clone()
    }

    /// Extract a validator key map for network adapter construction.
    #[must_use]
    pub fn validator_key_map(&self) -> Arc<ValidatorKeyMap> {
        Arc::new(
            self.genesis
                .validators
                .validators
                .iter()
                .map(|v| (v.validator_id, v.public_key))
                .collect(),
        )
    }

    /// Get the BLS signing key for a validator.
    ///
    /// # Panics
    ///
    /// Panics if `index` is out of range.
    #[must_use]
    pub fn signing_key(&self, index: u32) -> Arc<Bls12381G1PrivateKey> {
        let key_bytes = self.bls_keys[index as usize].to_bytes();
        Arc::new(Bls12381G1PrivateKey::from_bytes(&key_bytes).expect("valid key bytes"))
    }

    /// Get the Ed25519 keypair for a validator.
    #[must_use]
    pub fn ed25519_keypair(&self, index: u32) -> Keypair {
        self.ed25519_keys[index as usize].clone()
    }

    /// Get the libp2p peer ID for a validator.
    #[must_use]
    pub fn peer_id(&self, index: u32) -> PeerId {
        PeerId::from(self.ed25519_keys[index as usize].public())
    }

    /// Alias of [`Self::signing_key`] reserved for bind-test call sites.
    #[must_use]
    pub fn bind_signing_key(&self, index: u32) -> Arc<Bls12381G1PrivateKey> {
        self.signing_key(index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixtures_creation() {
        let fixtures = TestFixtures::new(42, 4);

        assert_eq!(fixtures.num_validators, 4);
        assert_eq!(fixtures.bls_keys.len(), 4);
        assert_eq!(fixtures.ed25519_keys.len(), 4);
    }

    #[test]
    fn test_fixtures_deterministic() {
        let fixtures1 = TestFixtures::new(42, 4);
        let fixtures2 = TestFixtures::new(42, 4);

        // BLS keys should be identical
        for i in 0..4 {
            assert_eq!(
                fixtures1.bls_keys[i].public_key(),
                fixtures2.bls_keys[i].public_key()
            );
        }

        // Peer IDs should be identical
        for i in 0..4u32 {
            assert_eq!(fixtures1.peer_id(i), fixtures2.peer_id(i));
        }
    }

    #[test]
    fn test_genesis_seats_every_validator() {
        let fixtures = TestFixtures::new(42, 4);

        let genesis = fixtures.genesis_validators();
        assert_eq!(genesis.committee.len(), 4);
        assert!(genesis.committee.contains(&ValidatorId::new(0)));
    }

    #[test]
    fn test_fixtures_pool_surplus() {
        // 4 seated in the root committee, 2 surplus registered but seated nowhere.
        let fixtures = TestFixtures::with_surplus(42, 4, 2);

        assert_eq!(fixtures.num_validators, 6);
        assert_eq!(fixtures.bls_keys.len(), 6);

        let genesis = fixtures.genesis_validators();
        assert_eq!(
            genesis.committee.len(),
            4,
            "only the seated validators form the committee"
        );
        // Surplus ids 4 and 5 are in the global set but not the committee.
        assert!(
            genesis
                .validators
                .validators
                .iter()
                .any(|v| v.validator_id == ValidatorId::new(5)),
            "surplus validator is registered globally"
        );
        assert!(
            !genesis.committee.contains(&ValidatorId::new(4)),
            "surplus validator is seated in no committee"
        );
        assert!(!genesis.committee.contains(&ValidatorId::new(5)));
    }
}
