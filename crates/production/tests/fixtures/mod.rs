//! Test fixtures for production e2e tests.
//!
//! Provides deterministic test setup including key generation and topology construction.

// Shared fixture surface consumed piecemeal across several test binaries
// (`e2e_tests`, `reshape_e2e`); each compiles its own copy and exercises a
// different subset, so unused helpers in any one binary aren't dead code.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;

use hyperscale_network::ValidatorKeyMap;
use hyperscale_types::{
    Bls12381G1PrivateKey, Bls12381G1PublicKey, NetworkDefinition, ShardId, TopologySnapshot,
    ValidatorId, ValidatorInfo, ValidatorSet, bls_keypair_from_seed,
};
use libp2p::identity::Keypair;
use libp2p::identity::ed25519::{Keypair as Ed25519Keypair, SecretKey};
use libp2p::{Multiaddr, PeerId};

/// Test fixtures for deterministic test setup.
///
/// Creates a set of validators with BLS keys for consensus and Ed25519 keys
/// for libp2p networking, all derived from a seed for reproducibility.
pub struct TestFixtures {
    /// BLS keypairs for consensus (one per validator).
    pub bls_keys: Vec<Bls12381G1PrivateKey>,

    /// Ed25519 keypairs for libp2p (one per validator).
    pub ed25519_keys: Vec<Keypair>,

    /// Identity-agnostic topology snapshot shared across every validator.
    topology: Arc<TopologySnapshot>,

    /// Number of validators.
    pub num_validators: u32,

    /// Number of shards.
    pub num_shards: u64,

    /// Validators per shard.
    pub validators_per_shard: u32,
}

impl TestFixtures {
    /// Create deterministic test fixtures from a seed.
    ///
    /// Derives both BLS and Ed25519 keys from seed for consistency.
    /// All validators are placed in a single shard.
    pub fn new(seed: u64, num_validators: u32) -> Self {
        Self::with_shards(seed, num_validators, 1)
    }

    /// Create test fixtures with multiple shards.
    pub fn with_shards(seed: u64, validators_per_shard: u32, num_shards: u64) -> Self {
        let num_validators = validators_per_shard
            * u32::try_from(num_shards).expect("num_shards fits in u32 for tests");

        // Generate BLS keys deterministically
        let bls_keys: Vec<Bls12381G1PrivateKey> = (0..num_validators)
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

        // Generate Ed25519 keys deterministically using a different derivation path
        // for independence from the BLS keys above.
        let ed25519_keys: Vec<Keypair> = (0..num_validators)
            .map(|i| {
                let mut seed_bytes = [0u8; 32];
                let key_seed = seed
                    .wrapping_add(u64::from(i))
                    .wrapping_mul(0x9e37_79b9_7f4a_7c15);
                seed_bytes[..8].copy_from_slice(&key_seed.to_le_bytes());
                seed_bytes[8..16].copy_from_slice(&u64::from(i).to_le_bytes());
                seed_bytes[16..24].copy_from_slice(b"ed25519k"); // Domain separation

                // libp2p's ed25519 key from seed
                let secret = SecretKey::try_from_bytes(seed_bytes).expect("valid ed25519 seed");
                Keypair::from(Ed25519Keypair::from(secret))
            })
            .collect();

        let public_keys: Vec<Bls12381G1PublicKey> = bls_keys
            .iter()
            .map(Bls12381G1PrivateKey::public_key)
            .collect();

        // Build global validator set
        let global_validators: Vec<ValidatorInfo> = (0..num_validators)
            .map(|i| ValidatorInfo {
                validator_id: ValidatorId::new(u64::from(i)),
                public_key: public_keys[i as usize],
            })
            .collect();
        let global_validator_set = ValidatorSet::new(global_validators);

        // Build per-shard committee mappings
        let mut shard_committees: HashMap<ShardId, Vec<ValidatorId>> = HashMap::new();
        let shard_depth = num_shards.trailing_zeros();
        for shard_id in 0..num_shards {
            let shard = ShardId::leaf(shard_depth, shard_id);
            let shard_start = u32::try_from(shard_id).expect("shard_id fits in u32 for tests")
                * validators_per_shard;
            let shard_end = shard_start + validators_per_shard;
            let committee: Vec<ValidatorId> = (shard_start..shard_end)
                .map(|i| ValidatorId::new(u64::from(i)))
                .collect();
            shard_committees.insert(shard, committee);
        }

        let topology = Arc::new(TopologySnapshot::with_shard_committees(
            NetworkDefinition::simulator(),
            num_shards,
            &global_validator_set,
            shard_committees,
        ));

        Self {
            bls_keys,
            ed25519_keys,
            topology,
            num_validators,
            num_shards,
            validators_per_shard,
        }
    }

    /// Get the identity-agnostic topology snapshot shared across every vnode.
    pub fn topology(&self) -> Arc<TopologySnapshot> {
        Arc::clone(&self.topology)
    }

    /// Extract a validator key map for network adapter construction.
    pub fn validator_key_map(&self) -> Arc<ValidatorKeyMap> {
        Arc::new(
            self.topology
                .global_validator_set()
                .validators
                .iter()
                .map(|v| (v.validator_id, v.public_key))
                .collect(),
        )
    }

    /// Get the BLS signing key for a validator.
    pub fn signing_key(&self, index: u32) -> Arc<Bls12381G1PrivateKey> {
        let key_bytes = self.bls_keys[index as usize].to_bytes();
        Arc::new(Bls12381G1PrivateKey::from_bytes(&key_bytes).expect("valid key bytes"))
    }

    /// Get the Ed25519 keypair for a validator.
    pub fn ed25519_keypair(&self, index: u32) -> Keypair {
        self.ed25519_keys[index as usize].clone()
    }

    /// Get the libp2p peer ID for a validator.
    pub fn peer_id(&self, index: u32) -> PeerId {
        PeerId::from(self.ed25519_keys[index as usize].public())
    }

    /// Get validators in a shard.
    pub fn validators_in_shard(&self, shard: ShardId) -> Vec<u32> {
        let start = u32::try_from(shard.path()).expect("shard fits in u32 for tests")
            * self.validators_per_shard;
        let end = start + self.validators_per_shard;
        (start..end).collect()
    }

    /// Alias of [`Self::signing_key`] reserved for bind-test call sites.
    pub fn bind_signing_key(&self, index: u32) -> Arc<Bls12381G1PrivateKey> {
        self.signing_key(index)
    }

    /// Create a listen address using port 0 (OS-assigned).
    pub fn listen_addr() -> Multiaddr {
        "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()
    }

    /// Create a listen address with a specific port.
    pub fn listen_addr_with_port(port: u16) -> Multiaddr {
        format!("/ip4/127.0.0.1/udp/{port}/quic-v1")
            .parse()
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixtures_creation() {
        let fixtures = TestFixtures::new(42, 4);

        assert_eq!(fixtures.num_validators, 4);
        assert_eq!(fixtures.num_shards, 1);
        assert_eq!(fixtures.validators_per_shard, 4);
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
    fn test_fixtures_multi_shard() {
        let fixtures = TestFixtures::with_shards(42, 3, 2);

        assert_eq!(fixtures.num_validators, 6);
        assert_eq!(fixtures.num_shards, 2);
        assert_eq!(fixtures.validators_per_shard, 3);

        // Check shard assignments
        let shard0_validators = fixtures.validators_in_shard(ShardId::leaf(1, 0));
        assert_eq!(shard0_validators, vec![0, 1, 2]);

        let shard1_validators = fixtures.validators_in_shard(ShardId::leaf(1, 1));
        assert_eq!(shard1_validators, vec![3, 4, 5]);
    }

    #[test]
    fn test_topology_lookup() {
        let fixtures = TestFixtures::new(42, 4);

        let topology = fixtures.topology();
        assert!(
            topology
                .committee_for_shard(ShardId::ROOT)
                .contains(&ValidatorId::new(0))
        );
        assert_eq!(topology.num_shards(), 1);
    }
}
