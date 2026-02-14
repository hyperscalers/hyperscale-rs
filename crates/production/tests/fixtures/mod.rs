//! Test fixtures for production e2e tests.
//!
//! Provides deterministic test setup including key generation and topology construction.

use hyperscale_types::{
    bls_keypair_from_seed, Bls12381G1PrivateKey, Bls12381G1PublicKey, ShardGroupId, StaticTopology,
    Topology, ValidatorId, ValidatorInfo, ValidatorSet,
};
use libp2p::{identity, Multiaddr};
use std::collections::HashMap;
use std::sync::Arc;

/// Test fixtures for deterministic test setup.
///
/// Creates a set of validators with BLS keys for consensus and Ed25519 keys
/// for libp2p networking, all derived from a seed for reproducibility.
pub struct TestFixtures {
    /// BLS keypairs for consensus (one per validator).
    pub bls_keys: Vec<Bls12381G1PrivateKey>,

    /// Ed25519 keypairs for libp2p (one per validator).
    pub ed25519_keys: Vec<identity::Keypair>,

    /// Per-validator topologies.
    topologies: Vec<Arc<dyn Topology>>,

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
        let num_validators = validators_per_shard * num_shards as u32;

        // Generate BLS keys deterministically
        let bls_keys: Vec<Bls12381G1PrivateKey> = (0..num_validators)
            .map(|i| {
                let mut seed_bytes = [0u8; 32];
                let key_seed = seed.wrapping_add(i as u64).wrapping_mul(0x517cc1b727220a95);
                seed_bytes[..8].copy_from_slice(&key_seed.to_le_bytes());
                seed_bytes[8..16].copy_from_slice(&(i as u64).to_le_bytes());
                bls_keypair_from_seed(&seed_bytes)
            })
            .collect();

        // Generate Ed25519 keys deterministically
        // We use a different derivation path to ensure independence
        let ed25519_keys: Vec<identity::Keypair> = (0..num_validators)
            .map(|i| {
                let mut seed_bytes = [0u8; 32];
                let key_seed = seed.wrapping_add(i as u64).wrapping_mul(0x9e3779b97f4a7c15); // Different constant
                seed_bytes[..8].copy_from_slice(&key_seed.to_le_bytes());
                seed_bytes[8..16].copy_from_slice(&(i as u64).to_le_bytes());
                seed_bytes[16..24].copy_from_slice(b"ed25519k"); // Domain separation

                // libp2p's ed25519 key from seed
                let secret = identity::ed25519::SecretKey::try_from_bytes(seed_bytes)
                    .expect("valid ed25519 seed");
                identity::Keypair::from(identity::ed25519::Keypair::from(secret))
            })
            .collect();

        let public_keys: Vec<Bls12381G1PublicKey> =
            bls_keys.iter().map(|k| k.public_key()).collect();

        // Build global validator set
        let global_validators: Vec<ValidatorInfo> = (0..num_validators)
            .map(|i| ValidatorInfo {
                validator_id: ValidatorId(i as u64),
                public_key: public_keys[i as usize],
                voting_power: 1,
            })
            .collect();
        let global_validator_set = ValidatorSet::new(global_validators);

        // Build per-shard committee mappings
        let mut shard_committees: HashMap<ShardGroupId, Vec<ValidatorId>> = HashMap::new();
        for shard_id in 0..num_shards {
            let shard = ShardGroupId(shard_id);
            let shard_start = shard_id as u32 * validators_per_shard;
            let shard_end = shard_start + validators_per_shard;
            let committee: Vec<ValidatorId> = (shard_start..shard_end)
                .map(|i| ValidatorId(i as u64))
                .collect();
            shard_committees.insert(shard, committee);
        }

        // Create per-validator topologies
        let topologies: Vec<Arc<dyn Topology>> = (0..num_validators)
            .map(|i| {
                let shard_id = i as u64 / validators_per_shard as u64;
                let shard = ShardGroupId(shard_id);
                let validator_id = ValidatorId(i as u64);

                Arc::new(StaticTopology::with_shard_committees(
                    validator_id,
                    shard,
                    num_shards,
                    &global_validator_set,
                    shard_committees.clone(),
                )) as Arc<dyn Topology>
            })
            .collect();

        Self {
            bls_keys,
            ed25519_keys,
            topologies,
            num_validators,
            num_shards,
            validators_per_shard,
        }
    }

    /// Get the topology for a validator by index.
    pub fn topology(&self, index: u32) -> Arc<dyn Topology> {
        self.topologies[index as usize].clone()
    }

    /// Get the BLS signing key for a validator.
    pub fn signing_key(&self, index: u32) -> Bls12381G1PrivateKey {
        let key_bytes = self.bls_keys[index as usize].to_bytes();
        Bls12381G1PrivateKey::from_bytes(&key_bytes).expect("valid key bytes")
    }

    /// Get the Ed25519 keypair for a validator.
    #[allow(dead_code)]
    pub fn ed25519_keypair(&self, index: u32) -> identity::Keypair {
        self.ed25519_keys[index as usize].clone()
    }

    /// Get the libp2p peer ID for a validator.
    pub fn peer_id(&self, index: u32) -> libp2p::PeerId {
        libp2p::PeerId::from(self.ed25519_keys[index as usize].public())
    }

    /// Get validators in a shard.
    pub fn validators_in_shard(&self, shard: ShardGroupId) -> Vec<u32> {
        let start = shard.0 as u32 * self.validators_per_shard;
        let end = start + self.validators_per_shard;
        (start..end).collect()
    }

    /// Create a listen address using port 0 (OS-assigned).
    #[allow(dead_code)]
    pub fn listen_addr() -> Multiaddr {
        "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()
    }

    /// Create a listen address with a specific port.
    #[allow(dead_code)]
    pub fn listen_addr_with_port(port: u16) -> Multiaddr {
        format!("/ip4/127.0.0.1/udp/{}/quic-v1", port)
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
        for i in 0..4 {
            assert_eq!(fixtures1.peer_id(i as u32), fixtures2.peer_id(i as u32));
        }
    }

    #[test]
    fn test_fixtures_multi_shard() {
        let fixtures = TestFixtures::with_shards(42, 3, 2);

        assert_eq!(fixtures.num_validators, 6);
        assert_eq!(fixtures.num_shards, 2);
        assert_eq!(fixtures.validators_per_shard, 3);

        // Check shard assignments
        let shard0_validators = fixtures.validators_in_shard(ShardGroupId(0));
        assert_eq!(shard0_validators, vec![0, 1, 2]);

        let shard1_validators = fixtures.validators_in_shard(ShardGroupId(1));
        assert_eq!(shard1_validators, vec![3, 4, 5]);
    }

    #[test]
    fn test_topology_lookup() {
        let fixtures = TestFixtures::new(42, 4);

        let topology = fixtures.topology(0);
        assert_eq!(topology.local_validator_id(), ValidatorId(0));
        assert_eq!(topology.local_shard(), ShardGroupId(0));

        let topology2 = fixtures.topology(2);
        assert_eq!(topology2.local_validator_id(), ValidatorId(2));
    }
}
