//! Multi-epoch determinism for [`apply_epoch`].
//!
//! Drives V parallel `BeaconState` instances starting from byte-identical
//! input through 50 epochs and asserts they stay byte-identical at every
//! epoch boundary.
//!
//! Determinism is load-bearing for the beacon coordinator: multi-vnode
//! processes share input streams but run independent `BeaconState`
//! instances, and a `HashMap`-iteration leak (or any non-deterministic
//! ordering source) would let derived `TopologySnapshot`s diverge
//! silently.
//!
//! Coverage at empty `committed`: `filter_and_roll_randomness` rolls
//! randomness via the chained BLAKE3 mix, `auto_*` stages re-evaluate
//! every epoch, the shuffle fires at epochs 16/32/48, `pool_draw`
//! refills against post-shuffle pool state, and the beacon committee
//! resamples every epoch from `randomness`-seeded Fisher–Yates.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_beacon::state::{ApplyEpochInput, apply_epoch};
use hyperscale_types::{
    BeaconChainConfig, BeaconState, Bls12381G1PublicKey, Epoch, MIN_STAKE_FLOOR, NetworkDefinition,
    NetworkParams, Randomness, SHUFFLE_INTERVAL_EPOCHS, ShardCommittee, ShardId, Stake, StakePool,
    StakePoolId, ValidatorId, ValidatorRecord, ValidatorStatus, bls_keypair_from_seed,
};

const V: usize = 3;
const EPOCHS: u64 = 50;

fn pubkey(seed: u64) -> Bls12381G1PublicKey {
    let mut s = [0u8; 32];
    s[..8].copy_from_slice(&seed.to_le_bytes());
    bls_keypair_from_seed(&s).public_key()
}

/// Initial state: 10 validators in one pool — 8 placed `OnShard` ready
/// across two shards of capacity 4, 2 sitting `Pooled` so the shuffle
/// has refill stock.
fn initial_state() -> BeaconState {
    let pool_id = StakePoolId::new(0);
    let shard_0 = ShardId::leaf(1, 0);
    let shard_1 = ShardId::leaf(1, 1);

    let mut validators = BTreeMap::new();
    let mut pool_validators = BTreeSet::new();
    let mut shard_0_members = Vec::new();
    let mut shard_1_members = Vec::new();

    for i in 0u64..10 {
        let id = ValidatorId::new(i);
        let status = if i < 4 {
            shard_0_members.push(id);
            ValidatorStatus::OnShard {
                shard: shard_0,
                ready: true,
                placed_at_epoch: Epoch::GENESIS,
            }
        } else if i < 8 {
            shard_1_members.push(id);
            ValidatorStatus::OnShard {
                shard: shard_1,
                ready: true,
                placed_at_epoch: Epoch::GENESIS,
            }
        } else {
            ValidatorStatus::Pooled
        };
        validators.insert(
            id,
            ValidatorRecord {
                id,
                pool: pool_id,
                status,
                registered_at_epoch: Epoch::GENESIS,
                pubkey: pubkey(i),
            },
        );
        pool_validators.insert(id);
    }

    let mut pools = BTreeMap::new();
    pools.insert(
        pool_id,
        StakePool {
            id: pool_id,
            // Generous so `min_stake` stays clamped at the floor and no
            // admission gates trip across 50 epochs.
            total_stake: Stake::from_attos(50 * MIN_STAKE_FLOOR.attos()),
            validators: pool_validators,
            pending_withdrawals: Vec::new(),
        },
    );

    let mut shard_committees = BTreeMap::new();
    shard_committees.insert(
        shard_0,
        ShardCommittee {
            members: shard_0_members,
        },
    );
    shard_committees.insert(
        shard_1,
        ShardCommittee {
            members: shard_1_members,
        },
    );

    let mut state = BeaconState {
        chain_config: BeaconChainConfig::default(),
        params: NetworkParams::default(),
        next_params: NetworkParams::default(),
        param_votes: BTreeMap::new(),
        current_epoch: Epoch::GENESIS,
        validators,
        pools,
        randomness: Randomness::new([0x42; 32]),
        committee: (0u64..4).map(ValidatorId::new).collect(),
        shard_committees: shard_committees.clone(),
        next_shard_committees: shard_committees,
        shard_consensus_members: BTreeMap::new(),
        witness_window_bases: BTreeMap::new(),
        split_pending_window: BTreeSet::new(),
        settled_window_floors: BTreeMap::new(),
        reshape_observers_window: BTreeMap::new(),
        reshape_keepers_window: BTreeMap::new(),
        reshape_parent_halves: BTreeMap::new(),
        boundaries: BTreeMap::new(),
        advanced: BTreeSet::new(),
        pending_reshapes: BTreeMap::new(),
        pending_recoveries: BTreeMap::new(),
        miss_counters: BTreeMap::new(),
    };
    state.shard_consensus_members = state.ready_consensus_members(&state.shard_committees);
    state
}

#[test]
fn fifty_epochs_byte_identical_across_replicas() {
    let network = NetworkDefinition::simulator();
    let mut replicas: Vec<BeaconState> = (0..V).map(|_| initial_state()).collect();

    for i in 1..V {
        assert_eq!(replicas[0], replicas[i], "replicas diverged at genesis");
    }

    for e in 1..=EPOCHS {
        let target = Epoch::new(e);
        for replica in &mut replicas {
            apply_epoch(
                replica,
                &network,
                target,
                ApplyEpochInput::Normal {
                    committed: &[],
                    shard_contributions: &BTreeMap::new(),
                },
            );
        }
        for i in 1..V {
            assert_eq!(replicas[0], replicas[i], "replicas diverged at epoch {e}");
        }
        assert_eq!(replicas[0].current_epoch, target);
    }

    // Sanity: 50 epochs of apply_epoch should have evolved state — at
    // minimum, randomness has been rolled 50 times and the shuffle has
    // fired at epochs 16, 32, 48.
    assert_ne!(
        replicas[0],
        initial_state(),
        "50 epochs of apply_epoch left state byte-identical to genesis",
    );
}

/// The committee governing epoch `N` is fixed a full epoch ahead: the
/// `next_shard_committees` written when `apply_epoch(N-1)` runs must equal the
/// `shard_committees` promoted active when `apply_epoch(N)` runs. Activation is
/// a pure promotion of the precomputed lookahead, never a recomputation, so
/// every node binds an epoch's committee to the same set the weighted timestamp
/// resolves. Pinned across a shuffle boundary, where the lookahead genuinely
/// diverges from the committee it supersedes, so the equality below proves
/// promotion rather than holding vacuously over constant committees.
#[test]
fn lookahead_committee_promotes_unchanged_to_active() {
    let network = NetworkDefinition::simulator();
    let mut state = initial_state();

    let last = SHUFFLE_INTERVAL_EPOCHS + 1;
    let mut lookahead_after: BTreeMap<u64, BTreeMap<ShardId, ShardCommittee>> = BTreeMap::new();
    let mut active_after: BTreeMap<u64, BTreeMap<ShardId, ShardCommittee>> = BTreeMap::new();

    for e in 1..=last {
        apply_epoch(
            &mut state,
            &network,
            Epoch::new(e),
            ApplyEpochInput::Normal {
                committed: &[],
                shard_contributions: &BTreeMap::new(),
            },
        );
        lookahead_after.insert(e, state.next_shard_committees.clone());
        active_after.insert(e, state.shard_committees.clone());
    }

    // Promotion invariant: active-at-N equals the lookahead fixed at N-1.
    for e in 2..=last {
        assert_eq!(
            active_after[&e],
            lookahead_after[&(e - 1)],
            "committee active at epoch {e} must equal the lookahead fixed at epoch {}",
            e - 1,
        );
    }

    // Non-triviality: the shuffle rotates the lookahead so it diverges from the
    // committee it supersedes, and that rotated set becomes active one epoch on.
    let boundary = SHUFFLE_INTERVAL_EPOCHS;
    assert_ne!(
        lookahead_after[&boundary], active_after[&boundary],
        "the shuffle at epoch {boundary} must rotate the lookahead committee",
    );
    assert_ne!(
        active_after[&(boundary + 1)],
        active_after[&boundary],
        "the rotated committee must become active the epoch after the shuffle",
    );
}
