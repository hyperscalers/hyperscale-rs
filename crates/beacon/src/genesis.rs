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
//! binary layer.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use hyperscale_storage::BeaconStorage;
use hyperscale_types::{
    BeaconChainConfig, BeaconGenesisConfig, BeaconState, BeaconWitnessLeafCount, BlockHash,
    BlockHeight, CertifiedBeaconBlock, Epoch, GenesisConfigHash, GenesisPool, GenesisValidator,
    GenesisValidators, MAX_BEACON_COMMITTEE, MAX_VOTE_VECTOR_LEN, MIN_BEACON_COMMITTEE_SIZE,
    MIN_STAKE_FLOOR, NetworkParams, Randomness, ShardBoundary, ShardCommittee, ShardId, Stake,
    StakePool, StakePoolId, StateRoot, TopologySnapshot, ValidatorId, ValidatorRecord,
    ValidatorStatus, Verified, WeightedTimestamp, genesis_config_hash,
};

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
/// shard or beacon committee oversize, validator listed twice in the
/// committee). Genesis is a one-shot bootstrap whose inputs come from
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
        let status = if placed.contains(&v.id) {
            ValidatorStatus::OnShard {
                shard: ShardId::ROOT,
                ready: true,
                placed_at_epoch: Epoch::GENESIS,
            }
        } else {
            ValidatorStatus::Pooled
        };
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
                conviction: None,
            },
        );
    }

    // ─── build the genesis shard committee ────────────────────────────────
    //
    // A chain genesises with the single `ShardId::ROOT` shard.
    // `ShardCommittee.members` order is incidental at runtime (status
    // is what gates signing, not list position), so the input order
    // carries through verbatim.
    let next_shard_committees: BTreeMap<ShardId, ShardCommittee> = std::iter::once((
        ShardId::ROOT,
        ShardCommittee {
            members: config.initial_shard_committee.clone(),
        },
    ))
    .collect();

    // ─── beacon committee sorted ──────────────────────────────────────────
    //
    // Subsequent committees come from the recency-weighted resample, which
    // returns sorted ids; matching that at genesis keeps the field's
    // contract uniform across the chain's lifetime.
    let mut committee = config.initial_beacon_committee.clone();
    committee.sort();

    // Seed a boundary record for every genesis shard so `boundaries` is
    // never empty for an active shard. The `state_root` is a placeholder
    // until the shard's first observed crossing refreshes it in the fold
    // — genesis carries no per-shard root.
    let boundaries: BTreeMap<ShardId, ShardBoundary> = next_shard_committees
        .keys()
        .map(|shard| {
            (
                *shard,
                ShardBoundary {
                    state_root: StateRoot::ZERO,
                    block_hash: BlockHash::ZERO,
                    height: BlockHeight::GENESIS,
                    weighted_timestamp: WeightedTimestamp::ZERO,
                    witness_leaf_count: BeaconWitnessLeafCount::ZERO,
                    witness_base: BeaconWitnessLeafCount::ZERO,
                    last_live_epoch: Epoch::GENESIS,
                    consecutive_misses: 0,
                    terminal_epoch: None,
                    terminal_qc_wt: None,
                    settled_waves_root: None,
                    reshape_admitted_epoch: None,
                    reveals_fenced_below: None,
                },
            )
        })
        .collect();

    let mut state = BeaconState::empty(config.chain_config);
    state.params = NetworkParams::from_genesis(&state.chain_config);
    state.next_params = NetworkParams::from_genesis(&state.chain_config);
    state.validators = validators;
    state.pools = pools;
    state.randomness = config.initial_randomness;
    state.committee = committee;
    // Genesis fixes both windows to the configured committee: the
    // first apply_epoch promotes `next_shard_committees`, so epoch 0
    // and epoch 1 are both governed by the initial set until the
    // pipeline first rotates it.
    state.shard_committees = next_shard_committees.clone();
    state.next_shard_committees = next_shard_committees;
    state.boundaries = boundaries;
    // Genesis placements are `ready: true` by construction, so the frozen
    // consensus subset starts as full membership; the witness window
    // bases start at the zeroed genesis watermarks.
    state.shard_consensus_members = state.ready_consensus_members(&state.shard_committees);
    state.witness_window_bases = state.live_witness_bases();
    state
}

// ─── runner-shared genesis chain ─────────────────────────────────────────────

/// The genesis both runners boot from: the committed beacon chain — block,
/// folded state, config hash — plus the topology projected from that state.
pub struct GenesisBoot {
    /// Genesis [`CertifiedBeaconBlock`], verified for each per-vnode
    /// `BeaconCoordinator` to resume from.
    pub block: Arc<Verified<CertifiedBeaconBlock>>,
    /// Folded genesis [`BeaconState`].
    pub state: Arc<BeaconState>,
    /// Genesis config hash, bound into beacon signatures alongside the
    /// network.
    pub config_hash: GenesisConfigHash,
    /// Topology projected from `state`, identical in shape to the snapshot
    /// the runtime `ArcSwap` update derives on every epoch commit. `Arc`ed
    /// so a host shares one allocation across every vnode.
    pub topology_snapshot: Arc<TopologySnapshot>,
}

impl GenesisBoot {
    /// Commit the genesis (block, state) pair into `storage` if it holds no
    /// committed epoch yet, so fresh-start and warm-restart converge on the
    /// same resume load — the coordinator's resume epoch is whatever
    /// committed pair the store hands it. A store with history is left
    /// untouched.
    pub fn commit_if_empty(&self, storage: &dyn BeaconStorage) {
        if storage.latest_committed_epoch().is_none() {
            storage.commit_beacon_block(&self.block, &self.state);
        }
    }
}

/// Build the genesis beacon chain from `genesis` and project its topology
/// from the folded genesis state — the `inputs → BeaconState →
/// derive_topology_snapshot` direction the runtime follows.
///
/// Genesis is a single ROOT shard. The committee seats it; the committee
/// validators ordered by id form the beacon committee, capped at
/// [`BeaconChainConfig::beacon_committee_size`]. Every registered validator,
/// seated or pooled, joins the single genesis stake pool, so the projected
/// global set carries the pooled surplus a later reshape draws its child
/// cohort from.
#[must_use]
pub fn build_genesis(genesis: &GenesisValidators, chain_config: BeaconChainConfig) -> GenesisBoot {
    let pool_id = StakePoolId::new(0);
    let validators: Vec<GenesisValidator> = genesis
        .validators
        .validators
        .iter()
        .map(|v| GenesisValidator {
            id: v.validator_id,
            pool: pool_id,
            pubkey: v.public_key,
        })
        .collect();

    let seated: BTreeSet<ValidatorId> = genesis.committee.iter().copied().collect();
    let committee_len = seated
        .len()
        .min(chain_config.beacon_committee_size as usize);
    let beacon_committee: Vec<ValidatorId> = seated.into_iter().take(committee_len).collect();

    // One genesis pool holds every validator at the stake floor.
    let total_stake = Stake::from_attos(validators.len() as u128 * MIN_STAKE_FLOOR.attos());
    let config = BeaconGenesisConfig {
        chain_config,
        initial_validators: validators,
        initial_pools: vec![GenesisPool {
            id: pool_id,
            total_stake,
        }],
        initial_beacon_committee: beacon_committee,
        initial_shard_committee: genesis.committee.clone(),
        initial_randomness: Randomness::new([0x42; 32]),
    };
    let state = Arc::new(build_genesis_beacon_state(&config));
    let config_hash = genesis_config_hash(&config, &genesis.network);
    let block = Arc::new(Verified::<CertifiedBeaconBlock>::genesis(config_hash));
    let topology_snapshot = Arc::new(state.derive_topology_snapshot(genesis.network.clone()));
    GenesisBoot {
        block,
        state,
        config_hash,
        topology_snapshot,
    }
}

/// Walk every invariant the builder relies on, panicking on the first
/// violation. Returns the set of genesis-seated validators (all on
/// `ShardId::ROOT`) for the builder to read on its second pass.
fn validate_config(config: &BeaconGenesisConfig) -> BTreeSet<ValidatorId> {
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
        let Some(required_attos) = u128::from(n).checked_mul(MIN_STAKE_FLOOR.attos()) else {
            panic!(
                "genesis pool {} declares {n} validators, overflowing the stake floor",
                pool.id
            );
        };
        let required = Stake::from_attos(required_attos);
        assert!(
            pool.total_stake >= required,
            "genesis pool {} declares {n} validators but holds only {} stake; \
             MIN_STAKE_FLOOR is {} per validator",
            pool.id,
            pool.total_stake,
            MIN_STAKE_FLOOR,
        );
    }

    validate_beacon_committee(config, &validator_ids);

    // A zero shard size leaves no room to place a validator on any shard.
    assert!(
        config.chain_config.shard_size > 0,
        "chain_config.shard_size is zero; no validator can be placed on a shard",
    );

    // The genesis committee fits the shard, its members are declared, and
    // none is listed twice. Members seat on the sole genesis shard,
    // `ShardId::ROOT`.
    let shard_cap = config.chain_config.shard_size as usize;
    assert!(
        config.initial_shard_committee.len() <= shard_cap,
        "initial shard committee has {} members; chain_config.shard_size is {shard_cap}",
        config.initial_shard_committee.len(),
    );
    let mut placed: BTreeSet<ValidatorId> = BTreeSet::new();
    for id in &config.initial_shard_committee {
        assert!(
            validator_ids.contains(id),
            "genesis shard committee references unknown validator {id}",
        );
        assert!(
            placed.insert(*id),
            "validator {id} appears in the genesis shard committee twice",
        );
    }

    placed
}

/// Beacon committee members are declared and distinct, and the
/// configured size is BFT-viable and fits the SPC vote vector.
///
/// A duplicate member would inflate the committee size `n` that drives
/// the BFT quorum (`n - f`) while the vote pools — keyed by
/// `ValidatorId` — hold only distinct voters, so a pathological config
/// could leave quorum permanently unreachable.
fn validate_beacon_committee(config: &BeaconGenesisConfig, validator_ids: &BTreeSet<ValidatorId>) {
    let mut beacon_committee_ids: BTreeSet<ValidatorId> = BTreeSet::new();
    for id in &config.initial_beacon_committee {
        assert!(
            validator_ids.contains(id),
            "initial_beacon_committee references unknown validator {id}",
        );
        assert!(
            beacon_committee_ids.insert(*id),
            "initial_beacon_committee lists validator {id} twice",
        );
    }
    let beacon_committee_cap = config.chain_config.beacon_committee_size as usize;
    assert!(
        beacon_committee_cap >= MIN_BEACON_COMMITTEE_SIZE,
        "chain_config.beacon_committee_size ({beacon_committee_cap}) is below \
         MIN_BEACON_COMMITTEE_SIZE ({MIN_BEACON_COMMITTEE_SIZE}); PC needs n >= 3f + 1 \
         with f >= 1 to tolerate a fault",
    );
    assert!(
        beacon_committee_cap <= MAX_VOTE_VECTOR_LEN,
        "chain_config.beacon_committee_size ({beacon_committee_cap}) exceeds \
         MAX_VOTE_VECTOR_LEN ({MAX_VOTE_VECTOR_LEN}); SPC view-input vectors can't hold it",
    );
    assert!(
        beacon_committee_cap <= MAX_BEACON_COMMITTEE,
        "chain_config.beacon_committee_size ({beacon_committee_cap}) exceeds \
         MAX_BEACON_COMMITTEE ({MAX_BEACON_COMMITTEE}); a block's committed_proposals \
         wire cap can't hold it",
    );
    assert!(
        config.initial_beacon_committee.len() <= beacon_committee_cap,
        "initial_beacon_committee ({} members) exceeds chain_config.beacon_committee_size ({})",
        config.initial_beacon_committee.len(),
        beacon_committee_cap,
    );
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{
        BeaconChainConfig, Bls12381G1PublicKey, GenesisPool, GenesisValidator, MAX_VOTE_VECTOR_LEN,
        NetworkDefinition, PRODUCTION_BEACON_COMMITTEE_SIZE, Randomness, bls_keypair_from_seed,
    };

    use super::*;
    use crate::state::{ApplyEpochInput, apply_epoch};

    fn pubkey(seed: u64) -> Bls12381G1PublicKey {
        let mut s = [0u8; 32];
        s[..8].copy_from_slice(&seed.to_le_bytes());
        bls_keypair_from_seed(&s).public_key()
    }

    /// Build a single-pool, single-shard config with `n_validators`,
    /// the first `n_shard_members` placed on the ROOT genesis shard and
    /// the first `n_beacon_members` on the beacon committee. The pool
    /// holds exactly enough stake for all validators at `MIN_STAKE_FLOOR`.
    fn sample_config(
        n_validators: u64,
        n_shard_members: u64,
        n_beacon_members: u64,
    ) -> BeaconGenesisConfig {
        let pool_id = StakePoolId::new(0);
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
            chain_config: BeaconChainConfig::default(),
            initial_validators: validators,
            initial_pools: vec![GenesisPool {
                id: pool_id,
                total_stake: Stake::from_attos(u128::from(n_validators) * MIN_STAKE_FLOOR.attos()),
            }],
            initial_beacon_committee: beacon_members,
            initial_shard_committee: shard_members,
            initial_randomness: Randomness::new([0xAB; 32]),
        }
    }

    /// The production sizing seats its full beacon committee: a genesis
    /// with 16 eligible validators and the production chain config draws a
    /// 16-member beacon committee, confirming `build_genesis` is
    /// size-agnostic up to the production cap.
    #[test]
    fn production_config_seats_a_full_sixteen_member_committee() {
        let n = u64::try_from(PRODUCTION_BEACON_COMMITTEE_SIZE).unwrap();
        let mut cfg = sample_config(n, 4, n);
        cfg.chain_config = BeaconChainConfig::production();
        let state = build_genesis_beacon_state(&cfg);
        assert_eq!(state.committee.len(), PRODUCTION_BEACON_COMMITTEE_SIZE);
    }

    /// A network smaller than the cap runs a smaller committee — the cap
    /// is a ceiling, not a requirement, so `build_genesis` seats
    /// `min(eligible, b)`.
    #[test]
    fn production_config_seats_min_of_eligible_and_cap() {
        let mut cfg = sample_config(8, 4, 8);
        cfg.chain_config = BeaconChainConfig::production();
        let state = build_genesis_beacon_state(&cfg);
        assert_eq!(state.committee.len(), 8);
    }

    // ─── happy path ──────────────────────────────────────────────────────

    #[test]
    fn builds_state_at_slot_genesis() {
        let cfg = sample_config(4, 4, 4);
        let state = build_genesis_beacon_state(&cfg);
        assert_eq!(state.current_epoch, Epoch::GENESIS);
        assert_eq!(state.randomness, cfg.initial_randomness);
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
                    shard: ShardId::ROOT,
                    ready: true,
                    placed_at_epoch: Epoch::GENESIS,
                },
            );
        }
    }

    #[test]
    fn genesis_seeds_both_windows_then_apply_epoch_promotes_unchanged() {
        let cfg = sample_config(4, 4, 4);
        let shard = ShardId::ROOT;
        let configured: Vec<ValidatorId> = [0u64, 1, 2, 3].map(ValidatorId::new).to_vec();

        let mut state = build_genesis_beacon_state(&cfg);

        // Genesis fixes both windows to the configured committee: the active
        // set (epoch 0) and the lookahead (epoch 1) are the same set.
        assert_eq!(state.shard_committees[&shard].members, configured);
        assert_eq!(state.next_shard_committees[&shard].members, configured);
        assert_eq!(state.shard_committees, state.next_shard_committees);

        // The first `apply_epoch` promotes the genesis lookahead into the
        // active committee unchanged (epoch 1 is not a shuffle boundary), so
        // epoch 1 is governed by the same configured committee as epoch 0.
        let genesis_lookahead = state.next_shard_committees.clone();
        apply_epoch(
            &mut state,
            &NetworkDefinition::simulator(),
            Epoch::new(1),
            ApplyEpochInput::Normal {
                committed: &[],
                shard_contributions: &BTreeMap::new(),
            },
        );
        assert_eq!(state.current_epoch, Epoch::new(1));
        assert_eq!(
            state.shard_committees, genesis_lookahead,
            "epoch 1's active committee is the genesis lookahead, promoted unchanged",
        );
        assert_eq!(state.shard_committees[&shard].members, configured);
    }

    #[test]
    fn unplaced_validators_start_pooled() {
        // 6 validators, only 4 placed on the ROOT shard — remaining two
        // land in the global pool.
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
        let validators: Vec<GenesisValidator> = (0u64..4)
            .map(|i| GenesisValidator {
                id: ValidatorId::new(i),
                pool: pool_id,
                pubkey: pubkey(i),
            })
            .collect();
        // Beacon committee supplied OUT of id order — builder sorts it.
        let cfg = BeaconGenesisConfig {
            chain_config: BeaconChainConfig::default(),
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
            initial_shard_committee: vec![],
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
            chain_config: BeaconChainConfig::default(),
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
            initial_shard_committee: vec![],
            initial_randomness: Randomness::ZERO,
        };
        let _ = build_genesis_beacon_state(&cfg);
    }

    #[test]
    #[should_panic(expected = "declares pool Pool(99) which is not in initial_pools")]
    fn rejects_validator_referencing_unknown_pool() {
        let cfg = BeaconGenesisConfig {
            chain_config: BeaconChainConfig::default(),
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
            initial_shard_committee: vec![],
            initial_randomness: Randomness::ZERO,
        };
        let _ = build_genesis_beacon_state(&cfg);
    }

    #[test]
    #[should_panic(expected = "holds only")]
    fn rejects_pool_with_insufficient_stake() {
        let pool_id = StakePoolId::new(0);
        let cfg = BeaconGenesisConfig {
            chain_config: BeaconChainConfig::default(),
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
            initial_shard_committee: vec![],
            initial_randomness: Randomness::ZERO,
        };
        let _ = build_genesis_beacon_state(&cfg);
    }

    #[test]
    #[should_panic(expected = "genesis shard committee twice")]
    fn rejects_validator_listed_twice_in_shard_committee() {
        let pool_id = StakePoolId::new(0);
        let cfg = BeaconGenesisConfig {
            chain_config: BeaconChainConfig::default(),
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
            initial_shard_committee: vec![ValidatorId::new(0), ValidatorId::new(0)],
            initial_randomness: Randomness::ZERO,
        };
        let _ = build_genesis_beacon_state(&cfg);
    }

    #[test]
    #[should_panic(expected = "lists validator Validator(0) twice")]
    fn rejects_duplicate_beacon_committee_member() {
        // A validator listed twice in the beacon committee inflates the
        // nominal committee size used for the BFT quorum while the vote
        // pools hold only distinct voters. Length stays at the cap (4),
        // so the size gate passes and the dedup gate is what fires.
        let mut cfg = sample_config(4, 4, 4);
        cfg.initial_beacon_committee = vec![
            ValidatorId::new(0),
            ValidatorId::new(0),
            ValidatorId::new(1),
            ValidatorId::new(2),
        ];
        let _ = build_genesis_beacon_state(&cfg);
    }

    #[test]
    #[should_panic(expected = "exceeds chain_config.beacon_committee_size")]
    fn rejects_beacon_committee_over_signer_count() {
        // Default beacon_committee_size is 4 — pass 5 to overflow.
        let pool_id = StakePoolId::new(0);
        let cfg = BeaconGenesisConfig {
            chain_config: BeaconChainConfig::default(),
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
            initial_shard_committee: vec![],
            initial_randomness: Randomness::ZERO,
        };
        let _ = build_genesis_beacon_state(&cfg);
    }

    #[test]
    #[should_panic(expected = "exceeds MAX_VOTE_VECTOR_LEN")]
    fn rejects_beacon_committee_size_over_vote_vector_cap() {
        // A committee past the cap would overflow the `PcVector` that
        // every SPC view input fills; reject the config rather than let
        // `compute_view_input` panic at the first epoch rollover.
        let pool_id = StakePoolId::new(0);
        let cfg = BeaconGenesisConfig {
            chain_config: BeaconChainConfig {
                beacon_committee_size: u32::try_from(MAX_VOTE_VECTOR_LEN + 1)
                    .expect("cap + 1 fits in u32"),
                ..BeaconChainConfig::default()
            },
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
            initial_shard_committee: vec![],
            initial_randomness: Randomness::ZERO,
        };
        let _ = build_genesis_beacon_state(&cfg);
    }

    #[test]
    #[should_panic(expected = "below MIN_BEACON_COMMITTEE_SIZE")]
    fn rejects_beacon_committee_size_below_bft_floor() {
        // A committee that can't tolerate a single fault (n < 4) would
        // never form a normal-block quorum — reject the config typo
        // rather than ship a chain stuck on the skip path.
        let mut cfg = sample_config(4, 4, 4);
        cfg.chain_config.beacon_committee_size = 3;
        let _ = build_genesis_beacon_state(&cfg);
    }

    #[test]
    #[should_panic(expected = "shard_size is zero")]
    fn rejects_zero_shard_size() {
        let mut cfg = sample_config(4, 4, 4);
        cfg.chain_config.shard_size = 0;
        let _ = build_genesis_beacon_state(&cfg);
    }
}
