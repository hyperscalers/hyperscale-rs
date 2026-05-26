//! Genesis configuration for a beacon chain.
//!
//! Pure data shapes describing the operator-supplied bootstrap inputs
//! plus the canonical-hash function that pins the chain identity. The
//! builder that turns a [`BeaconGenesisConfig`] into a live
//! `BeaconState` lives in `hyperscale_beacon::genesis` — it needs
//! beacon-side protocol constants (committee sizes, stake floors) and
//! is not part of the consumer-facing type surface.

use std::collections::BTreeMap;

use sbor::prelude::*;

use crate::{
    Bls12381G1PublicKey, GenesisConfigHash, Hash, Randomness, ShardGroupId, Stake, StakePoolId,
    ValidatorId,
};

/// One validator as supplied at genesis.
///
/// Pool linkage lives on the validator (a validator belongs to exactly
/// one pool); the pool's validator set is derived by filtering
/// `initial_validators` on `pool == this_pool_id` during state
/// construction.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GenesisValidator {
    /// Validator id.
    pub id: ValidatorId,
    /// Pool this validator operates under.
    pub pool: StakePoolId,
    /// Compressed BLS pubkey.
    pub pubkey: Bls12381G1PublicKey,
}

/// One stake pool as supplied at genesis.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct GenesisPool {
    /// Pool id.
    pub id: StakePoolId,
    /// Total stake credited to this pool at genesis.
    pub total_stake: Stake,
}

/// Genesis configuration for a beacon chain.
///
/// Loaded from TOML at the validator binary's startup; consumed once by
/// the state builder. Every field is consensus-critical — two
/// validators with different `BeaconGenesisConfig`s produce divergent
/// `BeaconState`s at epoch 0 and never converge. The SBOR-canonical
/// hash of this struct is the [`GenesisConfigHash`] embedded in
/// [`SpcCert::Genesis`](crate::SpcCert), binding the chain identity to
/// operator-supplied TOML; see [`genesis_config_hash`].
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct BeaconGenesisConfig {
    /// Initial validator set.
    pub initial_validators: Vec<GenesisValidator>,
    /// Initial stake pools. Each pool's validator set is derived from
    /// `initial_validators` filtered on the pool id.
    pub initial_pools: Vec<GenesisPool>,
    /// Explicit initial beacon committee. Stored sorted in
    /// `BeaconState.committee`; the genesis builder sorts on the way
    /// in so the input order is incidental.
    pub initial_beacon_committee: Vec<ValidatorId>,
    /// Explicit initial per-shard committees. Members of each shard
    /// get `OnShard { ready: true, placed_at_epoch: GENESIS }` —
    /// presumed synced by construction at chain bootstrap.
    pub initial_shard_committees: BTreeMap<ShardGroupId, Vec<ValidatorId>>,
    /// Seed for the very first epoch's randomness. Mixed straight into
    /// `state.randomness`; subsequent slots roll it through accepted
    /// VRF outputs.
    pub initial_randomness: Randomness,
}

/// Hash a [`BeaconGenesisConfig`] into the [`GenesisConfigHash`] embedded
/// in [`SpcCert::Genesis`](crate::SpcCert).
///
/// Pure function over the SBOR-canonical encoding: two operators with
/// byte-identical TOML produce the same hash; any divergent field
/// (validator pubkey, pool stake, initial randomness, ...) yields a
/// different hash and therefore a different
/// [`BeaconBlockHash`](crate::BeaconBlockHash) at genesis, keeping
/// chains with mismatched bootstraps from accidentally merging.
///
/// # Panics
///
/// Never in practice: every field is `BasicSbor` and the struct is
/// closed, so encoding is total.
#[must_use]
pub fn genesis_config_hash(config: &BeaconGenesisConfig) -> GenesisConfigHash {
    let bytes = basic_encode(config).expect("BeaconGenesisConfig SBOR encode is infallible");
    GenesisConfigHash::from_raw(Hash::from_bytes(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls_keypair_from_seed;

    fn pubkey(seed: u64) -> Bls12381G1PublicKey {
        let mut s = [0u8; 32];
        s[..8].copy_from_slice(&seed.to_le_bytes());
        bls_keypair_from_seed(&s).public_key()
    }

    fn sample_config() -> BeaconGenesisConfig {
        let pool_id = StakePoolId::new(0);
        let shard = ShardGroupId::new(0);
        let validators = (0u64..4)
            .map(|i| GenesisValidator {
                id: ValidatorId::new(i),
                pool: pool_id,
                pubkey: pubkey(i),
            })
            .collect();
        let members: Vec<ValidatorId> = (0u64..4).map(ValidatorId::new).collect();
        BeaconGenesisConfig {
            initial_validators: validators,
            initial_pools: vec![GenesisPool {
                id: pool_id,
                total_stake: Stake::from_whole_tokens(1_000_000),
            }],
            initial_beacon_committee: members.clone(),
            initial_shard_committees: std::iter::once((shard, members)).collect(),
            initial_randomness: Randomness([0xAB; 32]),
        }
    }

    #[test]
    fn config_sbor_round_trip() {
        let original = sample_config();
        let bytes = basic_encode(&original).unwrap();
        let decoded: BeaconGenesisConfig = basic_decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn config_hash_is_deterministic() {
        let a = sample_config();
        assert_eq!(genesis_config_hash(&a), genesis_config_hash(&a));
    }

    #[test]
    fn config_hash_changes_on_any_field() {
        let base = sample_config();
        let base_hash = genesis_config_hash(&base);

        let mut diff_randomness = base.clone();
        diff_randomness.initial_randomness = Randomness([0xCD; 32]);
        assert_ne!(genesis_config_hash(&diff_randomness), base_hash);

        let mut diff_pool_stake = base.clone();
        diff_pool_stake.initial_pools[0].total_stake = Stake::from_whole_tokens(2_000_000);
        assert_ne!(genesis_config_hash(&diff_pool_stake), base_hash);

        let mut diff_pubkey = base;
        diff_pubkey.initial_validators[0].pubkey = pubkey(99);
        assert_ne!(genesis_config_hash(&diff_pubkey), base_hash);
    }
}
