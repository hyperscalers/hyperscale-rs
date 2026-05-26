//! Shared test fixtures for state-module tests. Each submodule's
//! `#[cfg(test)] mod tests` pulls these in via
//! `use super::super::test_fixtures::*` so common scaffolding
//! (keypair derivation, VRF-signed proposals, single-pool state)
//! lives in one place.

#![cfg(test)]

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_types::{
    BeaconProposal, BeaconState, BlockHash, Bls12381G1PrivateKey, Bls12381G1PublicKey, BoundedVec,
    Epoch, LeafIndex, NetworkDefinition, PendingWithdrawal, Randomness, ShardCommittee,
    ShardGroupId, ShardWitness, ShardWitnessPayload, ShardWitnessProof, SlotEffects, Stake,
    StakePool, StakePoolId, ValidatorId, ValidatorRecord, ValidatorStatus, VrfProof, Witness,
    bls_keypair_from_seed, vrf_output_from_proof, vrf_sign,
};

use crate::constants::MIN_STAKE_FLOOR;
use crate::state::{ApplyEpochInput, apply_epoch};

pub fn keypair(seed: u64) -> Bls12381G1PrivateKey {
    let mut s = [0u8; 32];
    s[..8].copy_from_slice(&seed.to_le_bytes());
    bls_keypair_from_seed(&s)
}

pub fn pubkey(seed: u64) -> Bls12381G1PublicKey {
    keypair(seed).public_key()
}

pub fn net() -> NetworkDefinition {
    NetworkDefinition::simulator()
}

/// Build an honest VRF-signed empty `BeaconProposal` for validator
/// `id` at `epoch`. No witnesses (witness ingestion is a later
/// stage); just a deterministic VRF reveal.
pub fn vrf_proposal(id: u64, epoch: Epoch) -> BeaconProposal {
    let sk = keypair(id);
    let (output, proof) = vrf_sign(&sk, &net(), epoch);
    BeaconProposal::new(Vec::new(), output, proof)
}

/// Build a `BeaconProposal` whose VRF proof has been tampered with
/// so verification fails. The (output, proof) pair is internally
/// consistent by hash binding, but the BLS sig is broken.
pub fn malformed_vrf_proposal(id: u64, epoch: Epoch) -> BeaconProposal {
    let p = vrf_proposal(id, epoch);
    let mut bytes = *p.vrf_proof().as_bytes();
    bytes[0] ^= 1;
    let proof = VrfProof::new(bytes);
    // Output binding still matches the tampered proof (so we get
    // past the binding check); only the BLS verify fails.
    let output = vrf_output_from_proof(&proof);
    BeaconProposal::new(Vec::new(), output, proof)
}

pub fn validator_record(id: u64, pool: u32, status: ValidatorStatus) -> ValidatorRecord {
    ValidatorRecord {
        id: ValidatorId::new(id),
        pool: StakePoolId::new(pool),
        status,
        registered_at_epoch: Epoch::GENESIS,
        pubkey: pubkey(id),
    }
}

pub fn empty_state() -> BeaconState {
    BeaconState {
        current_epoch: Epoch::GENESIS,
        validators: BTreeMap::new(),
        pools: BTreeMap::new(),
        randomness: Randomness::ZERO,
        committee: Vec::new(),
        shard_committees: BTreeMap::new(),
        consumed_through: BTreeMap::new(),
        miss_counters: BTreeMap::new(),
    }
}

/// Build a state with one shard, one pool, and `n_active` validators
/// placed `OnShard { ready: true }`. The pool's `total_stake` is
/// `n_active * MIN_STAKE_FLOOR` — just enough to cover the active
/// set at the floor.
pub fn single_pool_state(n_active: u64) -> BeaconState {
    let mut state = empty_state();
    let pool_id = StakePoolId::new(0);
    let shard = ShardGroupId::new(0);

    let mut pool_validators = BTreeSet::new();
    let mut members = Vec::new();
    for i in 0..n_active {
        let id = ValidatorId::new(i);
        pool_validators.insert(id);
        members.push(id);
        state.validators.insert(
            id,
            validator_record(
                i,
                0,
                ValidatorStatus::OnShard {
                    shard,
                    ready: true,
                    placed_at_epoch: Epoch::GENESIS,
                },
            ),
        );
    }
    state.pools.insert(
        pool_id,
        StakePool {
            id: pool_id,
            total_stake: Stake::from_attos(u128::from(n_active) * MIN_STAKE_FLOOR.attos()),
            validators: pool_validators,
            pending_withdrawals: Vec::new(),
        },
    );
    state
        .shard_committees
        .insert(shard, ShardCommittee { members });
    state
}

/// Run one `apply_epoch` against `state.current_epoch.next()`. The
/// helper exists to dodge a `&mut` / `&` aliasing complaint when
/// callers want to thread the next-epoch number from inside the
/// borrow.
pub fn apply_next_epoch(
    state: &mut BeaconState,
    committed: &[(ValidatorId, BeaconProposal)],
) -> SlotEffects {
    let next = state.current_epoch.next();
    apply_epoch(state, &net(), next, ApplyEpochInput::Normal { committed })
}

/// Build a VRF-signed proposal for `id` at `epoch` carrying the given
/// witnesses. The `BoundedVec` inside `BeaconProposal` still caps
/// witness count at construction.
pub fn vrf_proposal_with_witnesses(
    id: u64,
    epoch: Epoch,
    witnesses: Vec<Witness>,
) -> BeaconProposal {
    let sk = keypair(id);
    let (output, proof) = vrf_sign(&sk, &net(), epoch);
    BeaconProposal::new(witnesses, output, proof)
}

/// Wrap a `ShardWitnessPayload` into a `Witness::Shard` with a
/// throwaway proof — the watermark gate is the only invariant the
/// tests exercise, and that only reads `(shard_id, leaf_index)`.
pub fn shard_witness(shard_id: u64, leaf_index: u64, payload: ShardWitnessPayload) -> Witness {
    Witness::Shard(ShardWitness {
        payload,
        proof: ShardWitnessProof {
            shard_id: ShardGroupId::new(shard_id),
            committed_block_hash: BlockHash::ZERO,
            leaf_index: LeafIndex::new(leaf_index),
            siblings: BoundedVec::new(),
        },
    })
}

/// Build a single-pool state with `n_actives` active validators
/// (placed `OnShard`) and one pre-loaded `PendingWithdrawal`. The
/// fixture parks `current_epoch` at a value past the unbonding
/// window so the test can run `apply_epoch` and watch the
/// withdrawal mature.
pub fn state_with_pending_withdrawal(
    n_actives: u64,
    total_stake: Stake,
    withdrawal_amount: Stake,
    initiated_at_epoch: Epoch,
    current_epoch: Epoch,
) -> BeaconState {
    let mut state = empty_state();
    state.current_epoch = current_epoch;
    let pool_id = StakePoolId::new(0);
    let shard = ShardGroupId::new(0);
    let mut pool_validators = BTreeSet::new();
    let mut members = Vec::new();
    for i in 0..n_actives {
        let id = ValidatorId::new(i);
        pool_validators.insert(id);
        members.push(id);
        state.validators.insert(
            id,
            validator_record(
                i,
                0,
                ValidatorStatus::OnShard {
                    shard,
                    ready: true,
                    placed_at_epoch: Epoch::GENESIS,
                },
            ),
        );
    }
    state.pools.insert(
        pool_id,
        StakePool {
            id: pool_id,
            total_stake,
            validators: pool_validators,
            pending_withdrawals: vec![PendingWithdrawal {
                amount: withdrawal_amount,
                initiated_at_epoch,
            }],
        },
    );
    state
        .shard_committees
        .insert(shard, ShardCommittee { members });
    state.committee = (0..n_actives).map(ValidatorId::new).collect();
    state
}
