//! Deterministic cluster test fixtures.
//!
//! Generates seeded BLS (consensus) and Ed25519 (network) keys plus the
//! genesis validators from one seed, so every consumer derives
//! byte-identical identities.

use std::sync::Arc;

use hyperscale_crypto_bls::BlsSigner;
use hyperscale_network::ValidatorKeyMap;
use hyperscale_types::{
    ConsensusPublicKey, GenesisValidators, NetworkDefinition, Signer, ValidatorId, ValidatorInfo,
    ValidatorSet,
};
use iroh::{EndpointId, SecretKey};

/// Mixing constant for this fixture's key derivation.
///
/// Deliberately different from the one `hyperscale_types::TestCommittee`
/// uses: the two fixtures are independent families, and the same
/// `(seed, index)` must not name the same key in both.
const KEY_DERIVATION_MIX: u64 = 0x9e37_79b9_7f4a_7c15;

/// Seed bytes for key `index` of family `domain` under `seed`.
fn key_seed(seed: u64, index: u32, domain: [u8; 8]) -> [u8; 32] {
    let mut seed_bytes = [0u8; 32];
    let mixed = seed
        .wrapping_add(u64::from(index))
        .wrapping_mul(KEY_DERIVATION_MIX);
    seed_bytes[..8].copy_from_slice(&mixed.to_le_bytes());
    seed_bytes[8..16].copy_from_slice(&u64::from(index).to_le_bytes());
    seed_bytes[16..24].copy_from_slice(&domain);
    seed_bytes
}

/// Validators with BLS keys for consensus and Ed25519 keys for their hosts'
/// endpoints, all derived from a seed.
pub struct TestFixtures {
    /// BLS keypairs for consensus (one per validator).
    pub bls_signers: Vec<Arc<BlsSigner>>,

    /// Network keys (one per validator; a host uses its first validator's).
    pub network_keys: Vec<SecretKey>,

    /// The genesis validators a runner projects its initial topology
    /// snapshot from.
    genesis: GenesisValidators,

    /// Number of validators (ROOT committee plus pooled surplus).
    pub num_validators: u32,
}

impl TestFixtures {
    /// Fixtures seating every validator in the single genesis ROOT
    /// committee.
    #[must_use]
    pub fn new(seed: u64, num_validators: u32) -> Self {
        Self::with_surplus(seed, num_validators, 0)
    }

    /// Fixtures seating `committee_size` validators in the genesis ROOT
    /// committee, plus `surplus` validators registered in the global set
    /// but seated nowhere. Validator ids `[0, committee_size)` seat the
    /// root; ids `[committee_size, committee_size + surplus)` are the
    /// surplus.
    #[must_use]
    pub fn with_surplus(seed: u64, committee_size: u32, surplus: u32) -> Self {
        let num_validators = committee_size + surplus;

        let bls_signers: Vec<Arc<BlsSigner>> = (0..num_validators)
            .map(|i| Arc::new(BlsSigner::from_seed(&key_seed(seed, i, [0; 8]))))
            .collect();
        let network_keys = (0..num_validators)
            .map(|i| SecretKey::from_bytes(&key_seed(seed, i, *b"ed25519k")))
            .collect();

        let public_keys: Vec<ConsensusPublicKey> =
            bls_signers.iter().map(|s| s.public_key()).collect();
        let validators: Vec<ValidatorInfo> = (0..num_validators)
            .map(|i| ValidatorInfo {
                validator_id: ValidatorId::new(u64::from(i)),
                public_key: public_keys[i as usize],
            })
            .collect();
        let committee: Vec<ValidatorId> = (0..committee_size)
            .map(|i| ValidatorId::new(u64::from(i)))
            .collect();
        let genesis = GenesisValidators::new(
            NetworkDefinition::simulator(),
            ValidatorSet::new(validators),
            committee,
        );

        Self {
            bls_signers,
            network_keys,
            genesis,
            num_validators,
        }
    }

    /// The genesis validators a runner projects its initial topology
    /// snapshot from.
    #[must_use]
    pub fn genesis_validators(&self) -> GenesisValidators {
        self.genesis.clone()
    }

    /// The validator key map for network adapter construction.
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

    /// The consensus signer for a validator.
    ///
    /// # Panics
    ///
    /// Panics if `index` is out of range.
    #[must_use]
    pub fn signer(&self, index: u32) -> Arc<dyn Signer> {
        let signer: Arc<BlsSigner> = Arc::clone(&self.bls_signers[index as usize]);
        signer
    }

    /// The network key of the host whose first validator is `index`.
    #[must_use]
    pub fn network_key(&self, index: u32) -> SecretKey {
        self.network_keys[index as usize].clone()
    }

    /// The endpoint id of the host whose first validator is `index`.
    #[must_use]
    pub fn endpoint_id(&self, index: u32) -> EndpointId {
        self.network_keys[index as usize].public()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_seed_derives_the_same_identities() {
        let a = TestFixtures::new(42, 4);
        let b = TestFixtures::new(42, 4);
        for i in 0..4u32 {
            assert_eq!(
                a.bls_signers[i as usize].public_key(),
                b.bls_signers[i as usize].public_key()
            );
            assert_eq!(a.endpoint_id(i), b.endpoint_id(i));
        }
        assert_ne!(a.endpoint_id(0), a.endpoint_id(1));
    }

    #[test]
    fn surplus_validators_are_registered_and_seated_nowhere() {
        let fixtures = TestFixtures::with_surplus(42, 4, 2);
        assert_eq!(fixtures.num_validators, 6);

        let genesis = fixtures.genesis_validators();
        assert_eq!(genesis.committee.len(), 4);
        assert!(
            genesis
                .validators
                .validators
                .iter()
                .any(|v| v.validator_id == ValidatorId::new(5))
        );
        assert!(!genesis.committee.contains(&ValidatorId::new(5)));
    }
}
