//! Genesis bootstrap for [`BeaconState`].
//!
//! Genesis is the one place beacon committees and shard committees are
//! *supplied* rather than *derived*: there's no prior randomness to
//! seed sampling from, so the operator's TOML config carries explicit
//! initial committees. Every subsequent committee transition is
//! VRF-derived inside `apply_epoch`.
//!
//! [`build_genesis_beacon_state`] is the pure constructor — it takes a
//! validated [`BeaconGenesisConfig`] and produces the live
//! `BeaconState` for `Epoch::GENESIS`. The TOML-loading wrapper that
//! produces `BeaconGenesisConfig` from disk lives at the validator
//! binary layer (Phase B.10).

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_types::{
    BeaconGenesisConfig, BeaconState, Epoch, ShardCommittee, ShardGroupId, Stake, StakePool,
    StakePoolId, ValidatorId, ValidatorRecord, ValidatorStatus,
};

use crate::constants::{BEACON_SIGNER_COUNT, MIN_STAKE_FLOOR, SHARD_CAPACITY};

// ─── builder ───────────────────────────────────────────────────────────────

/// Construct the live genesis [`BeaconState`] from a
/// [`BeaconGenesisConfig`].
///
/// Pure deterministic function — every honest validator constructs the
/// same `BeaconState` for the same `config`.
///
/// # Panics
///
/// Panics on any genesis-config invariant violation (duplicate ids,
/// committee member outside the validator set, pool under-staked,
/// shard or beacon committee oversize, validator placed on two
/// shards). Genesis is a one-shot bootstrap whose inputs come from
/// operator-controlled config — any violation is a config bug to fix
/// before launch, not a runtime condition to recover from. The
/// TOML-loading wrapper layer can pre-validate if desired.
#[must_use]
pub fn build_genesis_beacon_state(config: &BeaconGenesisConfig) -> BeaconState {
    let placed = validate_config(config);

    // Validators in a shard committee start at `OnShard { ready: true }`
    // — genesis-placed validators are presumed synced by construction
    // (the operator has already coordinated key distribution and node
    // bootstrap before launch). Everyone else lands in `Pooled` ready
    // for the first natural pool draw.
    let mut validators: BTreeMap<ValidatorId, ValidatorRecord> = BTreeMap::new();
    for v in &config.initial_validators {
        let status =
            placed
                .get(&v.id)
                .map_or(ValidatorStatus::Pooled, |shard| ValidatorStatus::OnShard {
                    shard: *shard,
                    ready: true,
                    placed_at_epoch: Epoch::GENESIS,
                });
        validators.insert(
            v.id,
            ValidatorRecord {
                id: v.id,
                pool: v.pool,
                status,
                registered_at_epoch: Epoch::GENESIS,
                pubkey: v.pubkey,
            },
        );
    }

    // ─── build pools map ──────────────────────────────────────────────────
    let mut per_pool_validators: BTreeMap<StakePoolId, BTreeSet<ValidatorId>> = BTreeMap::new();
    for v in &config.initial_validators {
        per_pool_validators.entry(v.pool).or_default().insert(v.id);
    }
    let mut pools: BTreeMap<StakePoolId, StakePool> = BTreeMap::new();
    for p in &config.initial_pools {
        pools.insert(
            p.id,
            StakePool {
                id: p.id,
                total_stake: p.total_stake,
                validators: per_pool_validators.remove(&p.id).unwrap_or_default(),
                pending_withdrawals: Vec::new(),
            },
        );
    }

    // ─── build shard committees ───────────────────────────────────────────
    //
    // `ShardCommittee.members` order is incidental at runtime (status
    // is what gates signing, not list position), so the input order
    // carries through verbatim.
    let shard_committees: BTreeMap<ShardGroupId, ShardCommittee> = config
        .initial_shard_committees
        .iter()
        .map(|(shard, members)| {
            (
                *shard,
                ShardCommittee {
                    members: members.clone(),
                },
            )
        })
        .collect();

    // ─── beacon committee sorted ──────────────────────────────────────────
    //
    // Subsequent committees come from `sample_committee` which returns
    // sorted ids; matching that at genesis keeps the field's contract
    // uniform across the chain's lifetime.
    let mut committee = config.initial_beacon_committee.clone();
    committee.sort();

    BeaconState {
        current_epoch: Epoch::GENESIS,
        validators,
        pools,
        randomness: config.initial_randomness,
        committee,
        shard_committees,
        consumed_through: BTreeMap::new(),
        miss_counters: BTreeMap::new(),
    }
}

/// Walk every invariant the builder relies on, panicking on the first
/// violation. Returns the `validator_id → shard` placement map for the
/// builder to read on its second pass.
fn validate_config(config: &BeaconGenesisConfig) -> BTreeMap<ValidatorId, ShardGroupId> {
    // No duplicate validator or pool ids.
    let mut validator_ids: BTreeSet<ValidatorId> = BTreeSet::new();
    for v in &config.initial_validators {
        assert!(
            validator_ids.insert(v.id),
            "genesis declares validator {} twice",
            v.id,
        );
    }
    let mut pool_ids: BTreeSet<StakePoolId> = BTreeSet::new();
    for p in &config.initial_pools {
        assert!(
            pool_ids.insert(p.id),
            "genesis declares pool {} twice",
            p.id,
        );
    }

    // Every validator.pool resolves to a declared pool.
    for v in &config.initial_validators {
        assert!(
            pool_ids.contains(&v.pool),
            "genesis validator {} declares pool {} which is not in initial_pools",
            v.id,
            v.pool,
        );
    }

    // Each pool covers its declared member count at the floor — dynamic
    // `min_stake` only matters once the chain is running.
    let mut per_pool_count: BTreeMap<StakePoolId, u64> = BTreeMap::new();
    for v in &config.initial_validators {
        *per_pool_count.entry(v.pool).or_insert(0) += 1;
    }
    for pool in &config.initial_pools {
        let n = per_pool_count.get(&pool.id).copied().unwrap_or(0);
        let required = Stake::from_attos(u128::from(n) * MIN_STAKE_FLOOR.attos());
        assert!(
            pool.total_stake >= required,
            "genesis pool {} declares {n} validators but holds only {} stake; \
             MIN_STAKE_FLOOR is {} per validator",
            pool.id,
            pool.total_stake,
            MIN_STAKE_FLOOR,
        );
    }

    // Beacon committee members are declared and the committee fits.
    for id in &config.initial_beacon_committee {
        assert!(
            validator_ids.contains(id),
            "initial_beacon_committee references unknown validator {id}",
        );
    }
    assert!(
        config.initial_beacon_committee.len() <= BEACON_SIGNER_COUNT,
        "initial_beacon_committee ({} members) exceeds BEACON_SIGNER_COUNT ({})",
        config.initial_beacon_committee.len(),
        BEACON_SIGNER_COUNT,
    );

    // Shard committee members exist, each shard fits, no validator
    // sits on two shards.
    let mut placed: BTreeMap<ValidatorId, ShardGroupId> = BTreeMap::new();
    for (shard, members) in &config.initial_shard_committees {
        assert!(
            members.len() <= SHARD_CAPACITY,
            "initial shard committee {shard} has {} members; SHARD_CAPACITY is {SHARD_CAPACITY}",
            members.len(),
        );
        for id in members {
            assert!(
                validator_ids.contains(id),
                "shard {shard} committee references unknown validator {id}",
            );
            if let Some(prior) = placed.insert(*id, *shard) {
                panic!("validator {id} appears in shard {prior} and shard {shard}");
            }
        }
    }

    placed
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{
        Bls12381G1PublicKey, GenesisPool, GenesisValidator, Randomness, bls_keypair_from_seed,
    };

    use super::*;

    fn pubkey(seed: u64) -> Bls12381G1PublicKey {
        let mut s = [0u8; 32];
        s[..8].copy_from_slice(&seed.to_le_bytes());
        bls_keypair_from_seed(&s).public_key()
    }

    /// Build a single-pool, single-shard config with `n_validators`,
    /// the first `n_shard_members` placed on shard 0 and the first
    /// `n_beacon_members` on the beacon committee. The pool holds
    /// exactly enough stake for all validators at `MIN_STAKE_FLOOR`.
    fn sample_config(
        n_validators: u64,
        n_shard_members: u64,
        n_beacon_members: u64,
    ) -> BeaconGenesisConfig {
        let pool_id = StakePoolId::new(0);
        let shard = ShardGroupId::new(0);
        let validators: Vec<GenesisValidator> = (0..n_validators)
            .map(|i| GenesisValidator {
                id: ValidatorId::new(i),
                pool: pool_id,
                pubkey: pubkey(i),
            })
            .collect();
        let shard_members: Vec<ValidatorId> = (0..n_shard_members).map(ValidatorId::new).collect();
        let beacon_members: Vec<ValidatorId> =
            (0..n_beacon_members).map(ValidatorId::new).collect();
        BeaconGenesisConfig {
            initial_validators: validators,
            initial_pools: vec![GenesisPool {
                id: pool_id,
                total_stake: Stake::from_attos(u128::from(n_validators) * MIN_STAKE_FLOOR.attos()),
            }],
            initial_beacon_committee: beacon_members,
            initial_shard_committees: std::iter::once((shard, shard_members)).collect(),
            initial_randomness: Randomness::new([0xAB; 32]),
        }
    }

    // ─── happy path ──────────────────────────────────────────────────────

    #[test]
    fn builds_state_at_slot_genesis() {
        let cfg = sample_config(4, 4, 4);
        let state = build_genesis_beacon_state(&cfg);
        assert_eq!(state.current_epoch, Epoch::GENESIS);
        assert_eq!(state.current_epoch, Epoch::GENESIS);
        assert_eq!(state.randomness, cfg.initial_randomness);
        assert!(state.consumed_through.is_empty());
        assert!(state.miss_counters.is_empty());
    }

    #[test]
    fn validators_in_shard_committee_are_on_shard_ready() {
        let cfg = sample_config(4, 4, 4);
        let state = build_genesis_beacon_state(&cfg);
        for id in [0u64, 1, 2, 3].map(ValidatorId::new) {
            let status = state.validators.get(&id).unwrap().status;
            assert_eq!(
                status,
                ValidatorStatus::OnShard {
                    shard: ShardGroupId::new(0),
                    ready: true,
                    placed_at_epoch: Epoch::GENESIS,
                },
            );
        }
    }

    #[test]
    fn unplaced_validators_start_pooled() {
        // 6 validators, only 4 placed on shard 0 — remaining two land
        // in the global pool.
        let cfg = sample_config(6, 4, 4);
        let state = build_genesis_beacon_state(&cfg);
        for id in [4u64, 5].map(ValidatorId::new) {
            assert_eq!(
                state.validators.get(&id).unwrap().status,
                ValidatorStatus::Pooled,
            );
        }
    }

    #[test]
    fn pool_validators_set_includes_every_member() {
        let cfg = sample_config(6, 4, 4);
        let state = build_genesis_beacon_state(&cfg);
        let pool = state.pools.get(&StakePoolId::new(0)).unwrap();
        let expected: BTreeSet<ValidatorId> = (0u64..6).map(ValidatorId::new).collect();
        assert_eq!(pool.validators, expected);
    }

    #[test]
    fn beacon_committee_stored_sorted() {
        let pool_id = StakePoolId::new(0);
        let shard = ShardGroupId::new(0);
        let validators: Vec<GenesisValidator> = (0u64..4)
            .map(|i| GenesisValidator {
                id: ValidatorId::new(i),
                pool: pool_id,
                pubkey: pubkey(i),
            })
            .collect();
        // Beacon committee supplied OUT of id order — builder sorts it.
        let cfg = BeaconGenesisConfig {
            initial_validators: validators,
            initial_pools: vec![GenesisPool {
                id: pool_id,
                total_stake: Stake::from_attos(4 * MIN_STAKE_FLOOR.attos()),
            }],
            initial_beacon_committee: vec![
                ValidatorId::new(3),
                ValidatorId::new(0),
                ValidatorId::new(2),
                ValidatorId::new(1),
            ],
            initial_shard_committees: std::iter::once((shard, vec![])).collect(),
            initial_randomness: Randomness::ZERO,
        };
        let state = build_genesis_beacon_state(&cfg);
        assert_eq!(
            state.committee,
            vec![
                ValidatorId::new(0),
                ValidatorId::new(1),
                ValidatorId::new(2),
                ValidatorId::new(3),
            ]
        );
    }

    // ─── invariant violations panic ──────────────────────────────────────

    #[test]
    #[should_panic(expected = "validator Validator(2) twice")]
    fn rejects_duplicate_validator_id() {
        let pool_id = StakePoolId::new(0);
        let cfg = BeaconGenesisConfig {
            initial_validators: vec![
                GenesisValidator {
                    id: ValidatorId::new(2),
                    pool: pool_id,
                    pubkey: pubkey(2),
                },
                GenesisValidator {
                    id: ValidatorId::new(2),
                    pool: pool_id,
                    pubkey: pubkey(2),
                },
            ],
            initial_pools: vec![GenesisPool {
                id: pool_id,
                total_stake: Stake::from_attos(2 * MIN_STAKE_FLOOR.attos()),
            }],
            initial_beacon_committee: vec![],
            initial_shard_committees: BTreeMap::new(),
            initial_randomness: Randomness::ZERO,
        };
        let _ = build_genesis_beacon_state(&cfg);
    }

    #[test]
    #[should_panic(expected = "declares pool Pool(99) which is not in initial_pools")]
    fn rejects_validator_referencing_unknown_pool() {
        let cfg = BeaconGenesisConfig {
            initial_validators: vec![GenesisValidator {
                id: ValidatorId::new(0),
                pool: StakePoolId::new(99),
                pubkey: pubkey(0),
            }],
            initial_pools: vec![GenesisPool {
                id: StakePoolId::new(0),
                total_stake: Stake::from_whole_tokens(1_000_000),
            }],
            initial_beacon_committee: vec![],
            initial_shard_committees: BTreeMap::new(),
            initial_randomness: Randomness::ZERO,
        };
        let _ = build_genesis_beacon_state(&cfg);
    }

    #[test]
    #[should_panic(expected = "holds only")]
    fn rejects_pool_with_insufficient_stake() {
        let pool_id = StakePoolId::new(0);
        let cfg = BeaconGenesisConfig {
            initial_validators: (0u64..4)
                .map(|i| GenesisValidator {
                    id: ValidatorId::new(i),
                    pool: pool_id,
                    pubkey: pubkey(i),
                })
                .collect(),
            // 4 validators × MIN_STAKE_FLOOR each, but pool holds half.
            initial_pools: vec![GenesisPool {
                id: pool_id,
                total_stake: Stake::from_attos(2 * MIN_STAKE_FLOOR.attos()),
            }],
            initial_beacon_committee: vec![],
            initial_shard_committees: BTreeMap::new(),
            initial_randomness: Randomness::ZERO,
        };
        let _ = build_genesis_beacon_state(&cfg);
    }

    #[test]
    #[should_panic(expected = "shard Shard(0) and shard Shard(1)")]
    fn rejects_validator_in_two_shard_committees() {
        let pool_id = StakePoolId::new(0);
        let cfg = BeaconGenesisConfig {
            initial_validators: vec![GenesisValidator {
                id: ValidatorId::new(0),
                pool: pool_id,
                pubkey: pubkey(0),
            }],
            initial_pools: vec![GenesisPool {
                id: pool_id,
                total_stake: Stake::from_attos(MIN_STAKE_FLOOR.attos()),
            }],
            initial_beacon_committee: vec![],
            initial_shard_committees: [
                (ShardGroupId::new(0), vec![ValidatorId::new(0)]),
                (ShardGroupId::new(1), vec![ValidatorId::new(0)]),
            ]
            .into_iter()
            .collect(),
            initial_randomness: Randomness::ZERO,
        };
        let _ = build_genesis_beacon_state(&cfg);
    }

    #[test]
    #[should_panic(expected = "exceeds BEACON_SIGNER_COUNT")]
    fn rejects_beacon_committee_over_signer_count() {
        // BEACON_SIGNER_COUNT is 4 — pass 5 to overflow.
        let pool_id = StakePoolId::new(0);
        let cfg = BeaconGenesisConfig {
            initial_validators: (0u64..5)
                .map(|i| GenesisValidator {
                    id: ValidatorId::new(i),
                    pool: pool_id,
                    pubkey: pubkey(i),
                })
                .collect(),
            initial_pools: vec![GenesisPool {
                id: pool_id,
                total_stake: Stake::from_attos(5 * MIN_STAKE_FLOOR.attos()),
            }],
            initial_beacon_committee: (0u64..5).map(ValidatorId::new).collect(),
            initial_shard_committees: BTreeMap::new(),
            initial_randomness: Randomness::ZERO,
        };
        let _ = build_genesis_beacon_state(&cfg);
    }
}
