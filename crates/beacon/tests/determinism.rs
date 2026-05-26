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

use hyperscale_beacon::constants::MIN_STAKE_FLOOR;
use hyperscale_beacon::state::{ApplyEpochInput, apply_epoch};
use hyperscale_types::{
    BeaconState, Bls12381G1PublicKey, Epoch, NetworkDefinition, Randomness, ShardCommittee,
    ShardGroupId, Stake, StakePool, StakePoolId, ValidatorId, ValidatorRecord, ValidatorStatus,
    bls_keypair_from_seed,
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
    let shard_0 = ShardGroupId::new(0);
    let shard_1 = ShardGroupId::new(1);

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

    BeaconState {
        current_epoch: Epoch::GENESIS,
        validators,
        pools,
        randomness: Randomness::new([0x42; 32]),
        committee: (0u64..4).map(ValidatorId::new).collect(),
        shard_committees,
        consumed_through: BTreeMap::new(),
        miss_counters: BTreeMap::new(),
    }
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
                ApplyEpochInput::Normal { committed: &[] },
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
