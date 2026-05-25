//! Merkle-tree-shaped commitment over [`BeaconState`].
//!
//! Computes the 32-byte root carried in
//! [`BeaconBlockHeader::state_root`](hyperscale_types::BeaconBlockHeader::state_root)
//! and exposes [`prove`] / [`verify`] for inclusion proofs over individual
//! entries — a light client that has only verified the block header
//! (one aggregate BLS check) can accept a single validator record, the
//! current randomness, etc. without holding the full state.
//!
//! # Layout
//!
//! Binary tree of 9 live leaves padded to width 16, one leaf per
//! [`BeaconState`] field:
//!
//! | Index | Leaf                                                 |
//! |-------|------------------------------------------------------|
//! | 0     | `H(tag ‖ current_epoch)`                             |
//! | 1     | `H(tag ‖ randomness)`                                |
//! | 2     | `H(tag ‖ validators_root)`                           |
//! | 3     | `H(tag ‖ pools_root)`                                |
//! | 4     | `H(tag ‖ committee_root)`                            |
//! | 5     | `H(tag ‖ shard_committees_root)`                     |
//! | 6     | `H(tag ‖ consumed_through_root)`                     |
//! | 7     | `H(tag ‖ last_recovery_cert_hash)`                   |
//! | 8     | `H(tag ‖ miss_counters_root)`                        |
//! | 9..15 | `Hash::ZERO` (padding)                               |
//!
//! Aggregate fields commit to a sub-tree built from sorted entries:
//!
//! - `validators_root` — leaves sorted by [`ValidatorId`]
//! - `pools_root` — per-`StakePool` leaves sorted by `StakePoolId`,
//!   committing `(pool_id, total_stake, pending_withdrawals_root)`.
//!   `validators: BTreeSet<ValidatorId>` is *not* committed: pool
//!   membership is the inverse of `ValidatorRecord.pool` and is
//!   already covered by `validators_root`.
//! - `committee_root` — leaves in declared committee order
//! - `shard_committees_root` — flat list of
//!   `(shard_id, position, validator_id)` leaves sorted by
//!   `(shard_id, position)`. Lets shards prove membership and order
//!   of their own committee with a single Merkle path.
//! - `consumed_through_root` — leaves sorted by `ShardGroupId`
//! - `miss_counters_root` — leaves sorted by `ValidatorId`
//!
//! # Safety
//!
//! Every leaf is hashed through a tag-prefixed encoder before entering
//! the tree, so a raw application value can never collide with an
//! internal node and `Hash::ZERO` padding can never collide with a real
//! leaf. Tags follow the `polaris-state-*-v1` convention.

use std::collections::BTreeSet;

use hyperscale_types::{
    BeaconStateRoot, Bls12381G1PublicKey, Epoch, Hash, LeafIndex, Randomness, RecoveryCertificate,
    ShardGroupId, Stake, StakePoolId, ValidatorId, compute_merkle_root,
    compute_merkle_root_with_proof, recovery_cert_hash,
};

use crate::state::{
    BeaconState, JailReason, PendingWithdrawal, StakePool, ValidatorRecord, ValidatorStatus,
};

// ─── leaf-encoder domain tags ────────────────────────────────────────────────

const TAG_CONTAINER_EPOCH: &[u8] = b"polaris-state-container-epoch-v1";
const TAG_CONTAINER_RANDOMNESS: &[u8] = b"polaris-state-container-randomness-v1";
const TAG_CONTAINER_VALIDATORS: &[u8] = b"polaris-state-container-validators-v1";
const TAG_CONTAINER_POOLS: &[u8] = b"polaris-state-container-pools-v1";
const TAG_CONTAINER_COMMITTEE: &[u8] = b"polaris-state-container-committee-v1";
const TAG_CONTAINER_SHARD_COMMITTEES: &[u8] = b"polaris-state-container-shard-committees-v1";
const TAG_CONTAINER_CONSUMED_THROUGH: &[u8] = b"polaris-state-container-consumed-through-v1";
const TAG_CONTAINER_RECOVERY_CERT: &[u8] = b"polaris-state-container-recovery-cert-v1";
const TAG_CONTAINER_MISS_COUNTERS: &[u8] = b"polaris-state-container-miss-counters-v1";

const TAG_VALIDATOR_ENTRY: &[u8] = b"polaris-state-validator-entry-v1";
const TAG_POOL_ENTRY: &[u8] = b"polaris-state-pool-entry-v1";
const TAG_PENDING_WITHDRAWAL_ENTRY: &[u8] = b"polaris-state-pending-withdrawal-entry-v1";
const TAG_COMMITTEE_ENTRY: &[u8] = b"polaris-state-committee-entry-v1";
const TAG_SHARD_COMMITTEE_ENTRY: &[u8] = b"polaris-state-shard-committee-entry-v1";
const TAG_CONSUMED_THROUGH_ENTRY: &[u8] = b"polaris-state-consumed-through-entry-v1";
const TAG_MISS_COUNTER_ENTRY: &[u8] = b"polaris-state-miss-counter-entry-v1";

// ─── container leaf indices ──────────────────────────────────────────────────

const INDEX_EPOCH: u32 = 0;
const INDEX_RANDOMNESS: u32 = 1;
const INDEX_VALIDATORS: u32 = 2;
const INDEX_POOLS: u32 = 3;
const INDEX_COMMITTEE: u32 = 4;
const INDEX_SHARD_COMMITTEES: u32 = 5;
const INDEX_CONSUMED_THROUGH: u32 = 6;
const INDEX_RECOVERY_CERT: u32 = 7;
const INDEX_MISS_COUNTERS: u32 = 8;

/// Container width — padded to the next power of two so the tree shape
/// is fixed. Indices 9..16 are `Hash::ZERO` padding; live encoders
/// never produce `Hash::ZERO` (every leaf is tag-prefixed) so padding
/// can never collide with a real leaf.
const CONTAINER_WIDTH: usize = 16;

// ─── public proof API ────────────────────────────────────────────────────────

/// What a caller wants to prove about the state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateKey {
    /// The current epoch scalar.
    Epoch,
    /// The current beacon randomness scalar.
    Randomness,
    /// A specific validator record by id.
    Validator(ValidatorId),
    /// Per-pool aggregate state — `total_stake` and the ordered
    /// `pending_withdrawals`. Pool membership (which validator ids
    /// belong to this pool) is not committed here; it's derivable by
    /// filtering [`StateKey::Validator`] records on
    /// `record.pool == pool_id`. `None` from [`prove`] if the pool
    /// doesn't exist.
    Pool(StakePoolId),
    /// Position in the beacon-committee vector. Committee membership is
    /// queried positionally because the committee is declared as an
    /// ordered list; proving "X is at index i" composes with knowing
    /// the committee length to enumerate the full set.
    CommitteeMember(u32),
    /// Beacon's high-water mark over a specific shard's beacon-witness
    /// accumulator: the largest [`LeafIndex`] the beacon has lifted
    /// from `shard_id`. `None` from [`prove`] if the shard has never
    /// been lifted from.
    ConsumedThrough(ShardGroupId),
    /// The most recently applied recovery certificate (or its absence,
    /// encoded as [`RecoveryCertHash::ZERO`]).
    LastRecoveryCert,
    /// Membership and position of a single validator in a specific
    /// shard's committee — "validator V is at position `pos` of shard
    /// `shard_id`'s committee." `None` from [`prove`] if the shard has
    /// no committee yet or `pos` is out of range.
    ShardCommitteeMember {
        /// Shard whose committee is being inspected.
        shard_id: ShardGroupId,
        /// Position within `ShardCommittee.members`.
        position: u32,
    },
    /// `MissedProposal` counter for a specific validator. `None` from
    /// [`prove`] if the validator has no entry (which means a zero
    /// counter — entries are only inserted on the first miss).
    MissCounter(ValidatorId),
}

/// The value a proof attests to. Mirrors [`StateKey`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateValue {
    /// `current_epoch`.
    Epoch(Epoch),
    /// `randomness`.
    Randomness(Randomness),
    /// A full validator record.
    Validator(ValidatorRecord),
    /// Per-pool aggregates.
    Pool {
        /// Pool id matching `StateKey::Pool`.
        pool_id: StakePoolId,
        /// Total stake at this commitment.
        total_stake: Stake,
        /// Ordered pending withdrawals.
        pending_withdrawals: Vec<PendingWithdrawal>,
    },
    /// Validator id at the queried committee position.
    CommitteeMember(ValidatorId),
    /// High-water mark for the queried shard.
    ConsumedThrough {
        /// Shard id matching `StateKey::ConsumedThrough`.
        shard_id: ShardGroupId,
        /// The committed high-water mark.
        leaf_index: LeafIndex,
    },
    /// Recovery cert at the queried slot (or its absence).
    LastRecoveryCert(Option<RecoveryCertificate>),
    /// A single shard-committee position.
    ShardCommitteeMember {
        /// Shard id matching `StateKey::ShardCommitteeMember.shard_id`.
        shard_id: ShardGroupId,
        /// Position within that shard's committee.
        position: u32,
        /// Validator at that position.
        id: ValidatorId,
    },
    /// `MissedProposal` count for the queried validator.
    MissCounter {
        /// Validator id matching `StateKey::MissCounter`.
        validator_id: ValidatorId,
        /// Current count.
        count: u32,
    },
}

/// Path from a sub-tree leaf to its sub-root. Absent for keys that
/// hit a scalar container leaf directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubtreePath {
    /// Sibling hashes from leaf upward.
    pub siblings: Vec<Hash>,
    /// Leaf index within the sub-tree.
    pub index: u32,
}

/// Full inclusion proof: optional sub-tree path plus the container
/// path from the field's slot in the container up to the state root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateProof {
    /// Sub-tree path for aggregate fields; `None` for scalar keys.
    pub subtree: Option<SubtreePath>,
    /// Sibling hashes from the container leaf up to the root.
    pub container_siblings: Vec<Hash>,
    /// Container-level index of the field this proof targets.
    pub container_index: u32,
}

// ─── public commitment + proof functions ─────────────────────────────────────

/// 32-byte Merkle commitment to `state`. Output is carried in
/// [`BeaconBlockHeader::state_root`](hyperscale_types::BeaconBlockHeader::state_root).
#[must_use]
pub fn state_root(state: &BeaconState) -> BeaconStateRoot {
    BeaconStateRoot::from_raw(compute_merkle_root(&container_leaves(state)))
}

/// Build the value-and-proof pair for `key`, or `None` if the key
/// targets an entry that isn't present (e.g. a `ValidatorId` not in
/// the state's validators map).
///
/// # Panics
///
/// Panics if a committee position would not fit in `u32`. Beacon and
/// per-shard committees are bounded by
/// [`BEACON_SIGNER_COUNT`](crate::constants::BEACON_SIGNER_COUNT) and
/// [`SHARD_CAPACITY`](crate::constants::SHARD_CAPACITY) respectively,
/// both well below `u32::MAX`, so this is structurally unreachable.
#[allow(clippy::too_many_lines)] // single dispatch over StateKey variants
#[must_use]
pub fn prove(state: &BeaconState, key: &StateKey) -> Option<(StateValue, StateProof)> {
    let leaves = container_leaves(state);

    match key {
        StateKey::Epoch => Some((
            StateValue::Epoch(state.current_epoch),
            container_only_proof(&leaves, INDEX_EPOCH),
        )),
        StateKey::Randomness => Some((
            StateValue::Randomness(state.randomness),
            container_only_proof(&leaves, INDEX_RANDOMNESS),
        )),
        StateKey::Validator(id) => {
            let entries: Vec<&ValidatorRecord> = state.validators.values().collect();
            let idx = entries.iter().position(|r| r.id == *id)?;
            let sub_leaves: Vec<Hash> = entries.iter().map(|r| leaf_validator_entry(r)).collect();
            let (_, sub_sibs, sub_idx) = compute_merkle_root_with_proof(&sub_leaves, idx);
            Some((
                StateValue::Validator(entries[idx].clone()),
                aggregate_proof(&leaves, INDEX_VALIDATORS, sub_sibs, sub_idx),
            ))
        }
        StateKey::Pool(pool_id) => {
            let entries: Vec<&StakePool> = state.pools.values().collect();
            let idx = entries.iter().position(|p| p.id == *pool_id)?;
            let sub_leaves: Vec<Hash> = entries.iter().map(|p| leaf_pool_entry(p)).collect();
            let (_, sub_sibs, sub_idx) = compute_merkle_root_with_proof(&sub_leaves, idx);
            let p = entries[idx];
            Some((
                StateValue::Pool {
                    pool_id: p.id,
                    total_stake: p.total_stake,
                    pending_withdrawals: p.pending_withdrawals.clone(),
                },
                aggregate_proof(&leaves, INDEX_POOLS, sub_sibs, sub_idx),
            ))
        }
        StateKey::CommitteeMember(pos) => {
            let pos_usize = *pos as usize;
            let member = *state.committee.get(pos_usize)?;
            let sub_leaves: Vec<Hash> = state
                .committee
                .iter()
                .enumerate()
                .map(|(i, id)| {
                    leaf_committee_entry(
                        u32::try_from(i).expect("committee position fits in u32"),
                        *id,
                    )
                })
                .collect();
            let (_, sub_sibs, sub_idx) = compute_merkle_root_with_proof(&sub_leaves, pos_usize);
            Some((
                StateValue::CommitteeMember(member),
                aggregate_proof(&leaves, INDEX_COMMITTEE, sub_sibs, sub_idx),
            ))
        }
        StateKey::ConsumedThrough(shard_id) => {
            let entries: Vec<(ShardGroupId, LeafIndex)> = state
                .consumed_through
                .iter()
                .map(|(k, v)| (*k, *v))
                .collect();
            let idx = entries.iter().position(|(sid, _)| *sid == *shard_id)?;
            let sub_leaves: Vec<Hash> = entries
                .iter()
                .map(|(sid, li)| leaf_consumed_through_entry(*sid, *li))
                .collect();
            let (_, sub_sibs, sub_idx) = compute_merkle_root_with_proof(&sub_leaves, idx);
            let (sid, li) = entries[idx];
            Some((
                StateValue::ConsumedThrough {
                    shard_id: sid,
                    leaf_index: li,
                },
                aggregate_proof(&leaves, INDEX_CONSUMED_THROUGH, sub_sibs, sub_idx),
            ))
        }
        StateKey::LastRecoveryCert => Some((
            StateValue::LastRecoveryCert(state.last_recovery_cert.clone()),
            container_only_proof(&leaves, INDEX_RECOVERY_CERT),
        )),
        StateKey::ShardCommitteeMember { shard_id, position } => {
            let entries = shard_committee_leaves(state);
            let idx = entries
                .iter()
                .position(|(s, p, _)| *s == *shard_id && *p == *position)?;
            let sub_leaves: Vec<Hash> = entries
                .iter()
                .map(|(s, p, id)| leaf_shard_committee_entry(*s, *p, *id))
                .collect();
            let (_, sub_sibs, sub_idx) = compute_merkle_root_with_proof(&sub_leaves, idx);
            let (s, p, id) = entries[idx];
            Some((
                StateValue::ShardCommitteeMember {
                    shard_id: s,
                    position: p,
                    id,
                },
                aggregate_proof(&leaves, INDEX_SHARD_COMMITTEES, sub_sibs, sub_idx),
            ))
        }
        StateKey::MissCounter(validator_id) => {
            let entries: Vec<(ValidatorId, u32)> =
                state.miss_counters.iter().map(|(k, v)| (*k, *v)).collect();
            let idx = entries.iter().position(|(id, _)| *id == *validator_id)?;
            let sub_leaves: Vec<Hash> = entries
                .iter()
                .map(|(id, c)| leaf_miss_counter_entry(*id, *c))
                .collect();
            let (_, sub_sibs, sub_idx) = compute_merkle_root_with_proof(&sub_leaves, idx);
            let (vid, count) = entries[idx];
            Some((
                StateValue::MissCounter {
                    validator_id: vid,
                    count,
                },
                aggregate_proof(&leaves, INDEX_MISS_COUNTERS, sub_sibs, sub_idx),
            ))
        }
    }
}

/// Check that `value` is committed under `root` for `key` via `proof`.
///
/// Returns `false` for any structural mismatch (wrong sub-tree shape
/// for the key, wrong container index) before doing the cryptographic
/// check.
#[must_use]
pub fn verify(
    root: BeaconStateRoot,
    key: &StateKey,
    value: &StateValue,
    proof: &StateProof,
) -> bool {
    let Some(container_leaf) = compute_container_leaf(key, value, proof.subtree.as_ref()) else {
        return false;
    };
    if proof.container_index != container_index_for(key) {
        return false;
    }
    walk_path(
        container_leaf,
        &proof.container_siblings,
        proof.container_index,
    )
    .as_bytes()
        == root.as_bytes()
}

// ─── leaf encoders ───────────────────────────────────────────────────────────
//
// All leaves are `H(tag ‖ payload)`. Tags prevent inter-field
// collisions and rule out the `Hash::ZERO` padding ambiguity.

fn tagged_hash(tag: &[u8], payload: &[u8]) -> Hash {
    Hash::from_parts(&[tag, payload])
}

fn leaf_epoch(epoch: Epoch) -> Hash {
    tagged_hash(TAG_CONTAINER_EPOCH, &epoch.to_le_bytes())
}

fn leaf_randomness(r: &Randomness) -> Hash {
    tagged_hash(TAG_CONTAINER_RANDOMNESS, r.as_bytes())
}

fn leaf_recovery_cert(cert: Option<&RecoveryCertificate>) -> Hash {
    tagged_hash(
        TAG_CONTAINER_RECOVERY_CERT,
        recovery_cert_hash(cert).as_bytes(),
    )
}

fn leaf_validator_entry(r: &ValidatorRecord) -> Hash {
    let mut payload = Vec::with_capacity(8 + 4 + 1 + 32 + 8 + 48);
    payload.extend_from_slice(&r.id.to_le_bytes());
    payload.extend_from_slice(&r.pool.inner().to_le_bytes());
    encode_validator_status(&r.status, &mut payload);
    payload.extend_from_slice(&r.registered_at_epoch.to_le_bytes());
    payload.extend_from_slice(&r.pubkey.0);
    tagged_hash(TAG_VALIDATOR_ENTRY, &payload)
}

fn encode_validator_status(s: &ValidatorStatus, out: &mut Vec<u8>) {
    match s {
        ValidatorStatus::Pooled => out.push(0),
        ValidatorStatus::OnShard {
            shard,
            ready,
            placed_at_epoch,
        } => {
            out.push(1);
            out.extend_from_slice(&shard.to_le_bytes());
            out.push(u8::from(*ready));
            out.extend_from_slice(&placed_at_epoch.to_le_bytes());
        }
        ValidatorStatus::Jailed {
            since_epoch,
            reason,
        } => {
            out.push(2);
            out.extend_from_slice(&since_epoch.to_le_bytes());
            out.push(match reason {
                JailReason::Performance => 0,
                JailReason::Recovery => 1,
                JailReason::Equivocation => 2,
            });
        }
        ValidatorStatus::InsufficientStake => out.push(3),
    }
}

fn leaf_pool_entry(pool: &StakePool) -> Hash {
    // Commits per-pool aggregates only: `pool_id`, `total_stake`, and
    // the root of the ordered `pending_withdrawals` list.
    // `pool.validators` is intentionally omitted — derivable from
    // `ValidatorRecord.pool == pool_id`, already covered by
    // `validators_root`.
    let pending_root = {
        let entries: Vec<Hash> = pool
            .pending_withdrawals
            .iter()
            .map(leaf_pending_withdrawal_entry)
            .collect();
        compute_merkle_root(&entries)
    };
    let mut payload = Vec::with_capacity(4 + 16 + 32);
    payload.extend_from_slice(&pool.id.inner().to_le_bytes());
    payload.extend_from_slice(&pool.total_stake.attos().to_le_bytes());
    payload.extend_from_slice(pending_root.as_bytes());
    tagged_hash(TAG_POOL_ENTRY, &payload)
}

fn leaf_pending_withdrawal_entry(w: &PendingWithdrawal) -> Hash {
    let mut payload = Vec::with_capacity(16 + 8);
    payload.extend_from_slice(&w.amount.attos().to_le_bytes());
    payload.extend_from_slice(&w.initiated_at_epoch.to_le_bytes());
    tagged_hash(TAG_PENDING_WITHDRAWAL_ENTRY, &payload)
}

fn leaf_committee_entry(position: u32, id: ValidatorId) -> Hash {
    let mut payload = Vec::with_capacity(4 + 8);
    payload.extend_from_slice(&position.to_le_bytes());
    payload.extend_from_slice(&id.to_le_bytes());
    tagged_hash(TAG_COMMITTEE_ENTRY, &payload)
}

fn leaf_consumed_through_entry(shard_id: ShardGroupId, leaf_index: LeafIndex) -> Hash {
    let mut payload = Vec::with_capacity(8 + 8);
    payload.extend_from_slice(&shard_id.to_le_bytes());
    payload.extend_from_slice(&leaf_index.inner().to_le_bytes());
    tagged_hash(TAG_CONSUMED_THROUGH_ENTRY, &payload)
}

fn leaf_shard_committee_entry(shard_id: ShardGroupId, position: u32, id: ValidatorId) -> Hash {
    let mut payload = Vec::with_capacity(8 + 4 + 8);
    payload.extend_from_slice(&shard_id.to_le_bytes());
    payload.extend_from_slice(&position.to_le_bytes());
    payload.extend_from_slice(&id.to_le_bytes());
    tagged_hash(TAG_SHARD_COMMITTEE_ENTRY, &payload)
}

fn leaf_miss_counter_entry(validator_id: ValidatorId, count: u32) -> Hash {
    let mut payload = Vec::with_capacity(8 + 4);
    payload.extend_from_slice(&validator_id.to_le_bytes());
    payload.extend_from_slice(&count.to_le_bytes());
    tagged_hash(TAG_MISS_COUNTER_ENTRY, &payload)
}

/// Flatten `state.shard_committees` into the canonical leaf order
/// `(shard_id, position) ascending`. Shared between `prove` and
/// `container_leaves` so both agree on indexing.
fn shard_committee_leaves(state: &BeaconState) -> Vec<(ShardGroupId, u32, ValidatorId)> {
    let mut out = Vec::new();
    for (shard_id, committee) in &state.shard_committees {
        for (position, id) in committee.members.iter().enumerate() {
            out.push((
                *shard_id,
                u32::try_from(position).expect("shard committee position fits in u32"),
                *id,
            ));
        }
    }
    out
}

// ─── container builder + proof helpers ───────────────────────────────────────

fn container_leaves(state: &BeaconState) -> [Hash; CONTAINER_WIDTH] {
    let validators_root = {
        let entries: Vec<Hash> = state
            .validators
            .values()
            .map(leaf_validator_entry)
            .collect();
        compute_merkle_root(&entries)
    };
    let pools_root = {
        let entries: Vec<Hash> = state.pools.values().map(leaf_pool_entry).collect();
        compute_merkle_root(&entries)
    };
    let committee_root = {
        let entries: Vec<Hash> = state
            .committee
            .iter()
            .enumerate()
            .map(|(i, id)| {
                leaf_committee_entry(
                    u32::try_from(i).expect("committee position fits in u32"),
                    *id,
                )
            })
            .collect();
        compute_merkle_root(&entries)
    };
    let shard_committees_root = {
        let entries: Vec<Hash> = shard_committee_leaves(state)
            .into_iter()
            .map(|(s, p, id)| leaf_shard_committee_entry(s, p, id))
            .collect();
        compute_merkle_root(&entries)
    };
    let consumed_through_root = {
        let entries: Vec<Hash> = state
            .consumed_through
            .iter()
            .map(|(sid, li)| leaf_consumed_through_entry(*sid, *li))
            .collect();
        compute_merkle_root(&entries)
    };
    let miss_counters_root = {
        let entries: Vec<Hash> = state
            .miss_counters
            .iter()
            .map(|(id, c)| leaf_miss_counter_entry(*id, *c))
            .collect();
        compute_merkle_root(&entries)
    };

    let mut out = [Hash::ZERO; CONTAINER_WIDTH];
    out[INDEX_EPOCH as usize] = leaf_epoch(state.current_epoch);
    out[INDEX_RANDOMNESS as usize] = leaf_randomness(&state.randomness);
    out[INDEX_VALIDATORS as usize] =
        tagged_hash(TAG_CONTAINER_VALIDATORS, validators_root.as_bytes());
    out[INDEX_POOLS as usize] = tagged_hash(TAG_CONTAINER_POOLS, pools_root.as_bytes());
    out[INDEX_COMMITTEE as usize] = tagged_hash(TAG_CONTAINER_COMMITTEE, committee_root.as_bytes());
    out[INDEX_SHARD_COMMITTEES as usize] = tagged_hash(
        TAG_CONTAINER_SHARD_COMMITTEES,
        shard_committees_root.as_bytes(),
    );
    out[INDEX_CONSUMED_THROUGH as usize] = tagged_hash(
        TAG_CONTAINER_CONSUMED_THROUGH,
        consumed_through_root.as_bytes(),
    );
    out[INDEX_RECOVERY_CERT as usize] = leaf_recovery_cert(state.last_recovery_cert.as_ref());
    out[INDEX_MISS_COUNTERS as usize] =
        tagged_hash(TAG_CONTAINER_MISS_COUNTERS, miss_counters_root.as_bytes());
    out
}

fn container_only_proof(leaves: &[Hash; CONTAINER_WIDTH], index: u32) -> StateProof {
    let (_, sibs, idx) = compute_merkle_root_with_proof(leaves, index as usize);
    StateProof {
        subtree: None,
        container_siblings: sibs,
        container_index: idx,
    }
}

fn aggregate_proof(
    leaves: &[Hash; CONTAINER_WIDTH],
    container_index: u32,
    subtree_siblings: Vec<Hash>,
    subtree_index: u32,
) -> StateProof {
    let (_, sibs, idx) = compute_merkle_root_with_proof(leaves, container_index as usize);
    StateProof {
        subtree: Some(SubtreePath {
            siblings: subtree_siblings,
            index: subtree_index,
        }),
        container_siblings: sibs,
        container_index: idx,
    }
}

const fn container_index_for(key: &StateKey) -> u32 {
    match key {
        StateKey::Epoch => INDEX_EPOCH,
        StateKey::Randomness => INDEX_RANDOMNESS,
        StateKey::Validator(_) => INDEX_VALIDATORS,
        StateKey::Pool(_) => INDEX_POOLS,
        StateKey::CommitteeMember(_) => INDEX_COMMITTEE,
        StateKey::ShardCommitteeMember { .. } => INDEX_SHARD_COMMITTEES,
        StateKey::ConsumedThrough(_) => INDEX_CONSUMED_THROUGH,
        StateKey::LastRecoveryCert => INDEX_RECOVERY_CERT,
        StateKey::MissCounter(_) => INDEX_MISS_COUNTERS,
    }
}

/// Reconstruct the container-level leaf for `key`/`value`, walking up
/// the sub-tree path first when the key targets an aggregate field.
/// Returns `None` if the key/value/subtree shape doesn't agree.
#[allow(clippy::too_many_lines)] // single dispatch over (StateKey, StateValue) variants
fn compute_container_leaf(
    key: &StateKey,
    value: &StateValue,
    subtree: Option<&SubtreePath>,
) -> Option<Hash> {
    match (key, value, subtree) {
        (StateKey::Epoch, StateValue::Epoch(e), None) => Some(leaf_epoch(*e)),
        (StateKey::Randomness, StateValue::Randomness(r), None) => Some(leaf_randomness(r)),
        (StateKey::LastRecoveryCert, StateValue::LastRecoveryCert(c), None) => {
            Some(leaf_recovery_cert(c.as_ref()))
        }
        (StateKey::Validator(id), StateValue::Validator(rec), Some(path)) => {
            if rec.id != *id {
                return None;
            }
            let entry_leaf = leaf_validator_entry(rec);
            let sub_root = walk_path(entry_leaf, &path.siblings, path.index);
            Some(tagged_hash(TAG_CONTAINER_VALIDATORS, sub_root.as_bytes()))
        }
        (
            StateKey::Pool(key_pool_id),
            StateValue::Pool {
                pool_id,
                total_stake,
                pending_withdrawals,
            },
            Some(path),
        ) => {
            if key_pool_id != pool_id {
                return None;
            }
            // Rebuild the pool's leaf hash from the claimed value.
            // `pool.validators` is omitted from the commitment (see
            // `leaf_pool_entry` doc), so the placeholder set here
            // can't change the result.
            let synthetic = StakePool {
                id: *pool_id,
                total_stake: *total_stake,
                validators: BTreeSet::new(),
                pending_withdrawals: pending_withdrawals.clone(),
            };
            let entry_leaf = leaf_pool_entry(&synthetic);
            let sub_root = walk_path(entry_leaf, &path.siblings, path.index);
            Some(tagged_hash(TAG_CONTAINER_POOLS, sub_root.as_bytes()))
        }
        (StateKey::CommitteeMember(pos), StateValue::CommitteeMember(id), Some(path)) => {
            if path.index != *pos {
                return None;
            }
            let entry_leaf = leaf_committee_entry(*pos, *id);
            let sub_root = walk_path(entry_leaf, &path.siblings, path.index);
            Some(tagged_hash(TAG_CONTAINER_COMMITTEE, sub_root.as_bytes()))
        }
        (
            StateKey::ConsumedThrough(key_shard),
            StateValue::ConsumedThrough {
                shard_id,
                leaf_index,
            },
            Some(path),
        ) => {
            if key_shard != shard_id {
                return None;
            }
            let entry_leaf = leaf_consumed_through_entry(*shard_id, *leaf_index);
            let sub_root = walk_path(entry_leaf, &path.siblings, path.index);
            Some(tagged_hash(
                TAG_CONTAINER_CONSUMED_THROUGH,
                sub_root.as_bytes(),
            ))
        }
        (
            StateKey::ShardCommitteeMember {
                shard_id: key_shard,
                position: key_pos,
            },
            StateValue::ShardCommitteeMember {
                shard_id,
                position,
                id,
            },
            Some(path),
        ) => {
            if key_shard != shard_id || key_pos != position {
                return None;
            }
            let entry_leaf = leaf_shard_committee_entry(*shard_id, *position, *id);
            let sub_root = walk_path(entry_leaf, &path.siblings, path.index);
            Some(tagged_hash(
                TAG_CONTAINER_SHARD_COMMITTEES,
                sub_root.as_bytes(),
            ))
        }
        (
            StateKey::MissCounter(key_validator),
            StateValue::MissCounter {
                validator_id,
                count,
            },
            Some(path),
        ) => {
            if key_validator != validator_id {
                return None;
            }
            let entry_leaf = leaf_miss_counter_entry(*validator_id, *count);
            let sub_root = walk_path(entry_leaf, &path.siblings, path.index);
            Some(tagged_hash(
                TAG_CONTAINER_MISS_COUNTERS,
                sub_root.as_bytes(),
            ))
        }
        _ => None,
    }
}

/// Reconstruct the root of a binary merkle tree from a single leaf and
/// the sibling path captured by [`compute_merkle_root_with_proof`].
/// Caller compares the result against the expected anchor.
fn walk_path(leaf: Hash, siblings: &[Hash], leaf_index: u32) -> Hash {
    let mut current = leaf;
    let mut index = leaf_index as usize;
    for sibling in siblings {
        if index.is_multiple_of(2) {
            current = Hash::from_parts(&[current.as_bytes(), sibling.as_bytes()]);
        } else {
            current = Hash::from_parts(&[sibling.as_bytes(), current.as_bytes()]);
        }
        index /= 2;
    }
    current
}

// Suppress unused-import warning on `Bls12381G1PublicKey`: it appears
// only as the field type of `ValidatorRecord.pubkey` reached through
// `leaf_validator_entry`. Keep the explicit import so the encoder's
// dependency on the 48-byte pubkey representation is obvious.
#[allow(dead_code)]
const _PUBKEY_DEP: Option<Bls12381G1PublicKey> = None;

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use hyperscale_types::{
        BeaconBlockHash, Bls12381G2Signature, RecoveryRound, SignerBitfield, bls_keypair_from_seed,
    };

    use super::*;
    use crate::state::ShardCommittee;

    fn pubkey(seed: u64) -> Bls12381G1PublicKey {
        let mut s = [0u8; 32];
        s[..8].copy_from_slice(&seed.to_le_bytes());
        bls_keypair_from_seed(&s).public_key()
    }

    fn sample_state() -> BeaconState {
        let mut validators = BTreeMap::new();
        for id in 0u64..5 {
            let vid = ValidatorId::new(id);
            let status = if id == 2 {
                ValidatorStatus::Jailed {
                    since_epoch: Epoch::new(3),
                    reason: JailReason::Performance,
                }
            } else {
                ValidatorStatus::OnShard {
                    shard: ShardGroupId::new(0),
                    ready: true,
                    placed_at_epoch: Epoch::GENESIS,
                }
            };
            validators.insert(
                vid,
                ValidatorRecord {
                    id: vid,
                    pool: StakePoolId::new(0),
                    status,
                    registered_at_epoch: Epoch::GENESIS,
                    pubkey: pubkey(id),
                },
            );
        }

        let mut pools = BTreeMap::new();
        let mut pool_validators: BTreeSet<ValidatorId> = BTreeSet::new();
        for id in 0u64..5 {
            pool_validators.insert(ValidatorId::new(id));
        }
        pools.insert(
            StakePoolId::new(0),
            StakePool {
                id: StakePoolId::new(0),
                total_stake: Stake::from_whole_tokens(500),
                validators: pool_validators,
                pending_withdrawals: vec![
                    PendingWithdrawal {
                        amount: Stake::from_whole_tokens(50),
                        initiated_at_epoch: Epoch::new(10),
                    },
                    PendingWithdrawal {
                        amount: Stake::from_whole_tokens(30),
                        initiated_at_epoch: Epoch::new(20),
                    },
                ],
            },
        );
        pools.insert(
            StakePoolId::new(1),
            StakePool {
                id: StakePoolId::new(1),
                total_stake: Stake::ZERO,
                validators: BTreeSet::new(),
                pending_withdrawals: vec![],
            },
        );

        let mut consumed_through = BTreeMap::new();
        consumed_through.insert(ShardGroupId::new(0), LeafIndex::new(7));
        consumed_through.insert(ShardGroupId::new(1), LeafIndex::new(3));

        let mut shard_committees = BTreeMap::new();
        shard_committees.insert(
            ShardGroupId::new(0),
            ShardCommittee {
                members: vec![
                    ValidatorId::new(0),
                    ValidatorId::new(1),
                    ValidatorId::new(3),
                ],
            },
        );
        shard_committees.insert(
            ShardGroupId::new(1),
            ShardCommittee {
                members: vec![ValidatorId::new(3), ValidatorId::new(4)],
            },
        );

        let mut miss_counters = BTreeMap::new();
        miss_counters.insert(ValidatorId::new(1), 2);
        miss_counters.insert(ValidatorId::new(4), 5);

        BeaconState {
            current_epoch: Epoch::new(7),
            validators,
            pools,
            randomness: Randomness([0xAB; 32]),
            committee: vec![
                ValidatorId::new(0),
                ValidatorId::new(1),
                ValidatorId::new(3),
                ValidatorId::new(4),
            ],
            shard_committees,
            consumed_through,
            last_recovery_cert: None,
            miss_counters,
        }
    }

    // ─── determinism + sensitivity ──────────────────────────────────────

    #[test]
    fn state_root_is_deterministic() {
        let s = sample_state();
        assert_eq!(state_root(&s), state_root(&s));
    }

    #[test]
    fn state_root_depends_on_epoch() {
        let a = sample_state();
        let mut b = a.clone();
        b.current_epoch = Epoch::new(b.current_epoch.inner() + 1);
        assert_ne!(state_root(&a), state_root(&b));
    }

    #[test]
    fn state_root_depends_on_randomness() {
        let a = sample_state();
        let mut b = a.clone();
        b.randomness = Randomness([0xCD; 32]);
        assert_ne!(state_root(&a), state_root(&b));
    }

    #[test]
    fn state_root_depends_on_committee_order() {
        let a = sample_state();
        let mut b = a.clone();
        b.committee.swap(0, 1);
        assert_ne!(state_root(&a), state_root(&b));
    }

    #[test]
    fn state_root_depends_on_consumed_through() {
        let a = sample_state();
        let mut b = a.clone();
        *b.consumed_through.get_mut(&ShardGroupId::new(0)).unwrap() = LeafIndex::new(8);
        assert_ne!(state_root(&a), state_root(&b));
    }

    #[test]
    fn state_root_depends_on_miss_counters() {
        let a = sample_state();
        let mut b = a.clone();
        *b.miss_counters.get_mut(&ValidatorId::new(1)).unwrap() = 3;
        assert_ne!(state_root(&a), state_root(&b));
    }

    #[test]
    fn state_root_depends_on_recovery_cert() {
        let a = sample_state();
        let mut b = a.clone();
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        b.last_recovery_cert = Some(RecoveryCertificate::new(
            BeaconBlockHash::ZERO,
            Epoch::new(5),
            RecoveryRound::new(1),
            Vec::new(),
            signers,
            Bls12381G2Signature([0x22; 96]),
        ));
        assert_ne!(state_root(&a), state_root(&b));
    }

    #[test]
    fn state_root_depends_on_pool_total_stake() {
        let a = sample_state();
        let mut b = sample_state();
        b.pools.get_mut(&StakePoolId::new(0)).unwrap().total_stake = Stake::from_whole_tokens(501);
        assert_ne!(state_root(&a), state_root(&b));
    }

    #[test]
    fn state_root_depends_on_pool_pending_withdrawals() {
        let a = sample_state();
        let mut b = sample_state();
        b.pools
            .get_mut(&StakePoolId::new(0))
            .unwrap()
            .pending_withdrawals
            .push(PendingWithdrawal {
                amount: Stake::from_whole_tokens(1),
                initiated_at_epoch: Epoch::new(99),
            });
        assert_ne!(state_root(&a), state_root(&b));
    }

    /// `pool.validators` is intentionally not committed in the pool leaf
    /// — membership is derivable from `validators_root`. Mutating only
    /// that field on a pool entry must NOT change the root.
    #[test]
    fn state_root_indifferent_to_pool_validators_set() {
        let a = sample_state();
        let mut b = sample_state();
        b.pools
            .get_mut(&StakePoolId::new(0))
            .unwrap()
            .validators
            .remove(&ValidatorId::new(3));
        assert_eq!(state_root(&a), state_root(&b));
    }

    // ─── proof roundtrips ───────────────────────────────────────────────

    #[test]
    fn scalar_proofs_roundtrip() {
        let s = sample_state();
        let root = state_root(&s);

        for key in [
            StateKey::Epoch,
            StateKey::Randomness,
            StateKey::LastRecoveryCert,
        ] {
            let (value, proof) = prove(&s, &key).expect("scalar key always present");
            assert!(
                verify(root, &key, &value, &proof),
                "verify failed for {key:?}"
            );
        }
    }

    #[test]
    fn validator_proof_roundtrips() {
        let s = sample_state();
        let root = state_root(&s);
        for id in 0u64..5 {
            let key = StateKey::Validator(ValidatorId::new(id));
            let (value, proof) = prove(&s, &key).expect("validator present");
            assert!(verify(root, &key, &value, &proof), "validator {id}");
        }
    }

    #[test]
    fn committee_proof_roundtrips() {
        let s = sample_state();
        let root = state_root(&s);
        for pos in 0u32..u32::try_from(s.committee.len()).unwrap() {
            let key = StateKey::CommitteeMember(pos);
            let (value, proof) = prove(&s, &key).expect("committee pos present");
            assert!(verify(root, &key, &value, &proof), "committee pos {pos}");
        }
    }

    #[test]
    fn shard_committee_proof_roundtrips() {
        let s = sample_state();
        let root = state_root(&s);
        for (shard_id, committee) in &s.shard_committees {
            for (pos, _) in committee.members.iter().enumerate() {
                let key = StateKey::ShardCommitteeMember {
                    shard_id: *shard_id,
                    position: u32::try_from(pos).unwrap(),
                };
                let (value, proof) = prove(&s, &key).expect("shard committee member present");
                assert!(
                    verify(root, &key, &value, &proof),
                    "shard {shard_id:?} pos {pos}",
                );
            }
        }
    }

    #[test]
    fn pool_proof_roundtrips() {
        let s = sample_state();
        let root = state_root(&s);
        for pool_id in s.pools.keys() {
            let key = StateKey::Pool(*pool_id);
            let (value, proof) = prove(&s, &key).expect("pool present");
            assert!(verify(root, &key, &value, &proof), "pool {pool_id}");
            let StateValue::Pool {
                pool_id: vid,
                total_stake,
                pending_withdrawals,
            } = value
            else {
                panic!("expected StateValue::Pool");
            };
            let pool = &s.pools[pool_id];
            assert_eq!(vid, pool.id);
            assert_eq!(total_stake, pool.total_stake);
            assert_eq!(pending_withdrawals, pool.pending_withdrawals);
        }
    }

    #[test]
    fn consumed_through_proof_roundtrips() {
        let s = sample_state();
        let root = state_root(&s);
        for shard_id in s.consumed_through.keys() {
            let key = StateKey::ConsumedThrough(*shard_id);
            let (value, proof) = prove(&s, &key).expect("entry present");
            assert!(verify(root, &key, &value, &proof), "shard {shard_id:?}");
        }
    }

    #[test]
    fn miss_counter_proof_roundtrips() {
        let s = sample_state();
        let root = state_root(&s);
        for validator_id in s.miss_counters.keys() {
            let key = StateKey::MissCounter(*validator_id);
            let (value, proof) = prove(&s, &key).expect("entry present");
            assert!(
                verify(root, &key, &value, &proof),
                "validator {validator_id:?}"
            );
        }
    }

    // ─── absence + rejection ────────────────────────────────────────────

    #[test]
    fn absent_pool_returns_none() {
        let s = sample_state();
        assert!(prove(&s, &StateKey::Pool(StakePoolId::new(999))).is_none());
    }

    #[test]
    fn absent_validator_returns_none() {
        let s = sample_state();
        assert!(prove(&s, &StateKey::Validator(ValidatorId::new(999))).is_none());
    }

    #[test]
    fn absent_shard_committee_position_returns_none() {
        let s = sample_state();
        assert!(
            prove(
                &s,
                &StateKey::ShardCommitteeMember {
                    shard_id: ShardGroupId::new(0),
                    position: 99,
                },
            )
            .is_none()
        );
        assert!(
            prove(
                &s,
                &StateKey::ShardCommitteeMember {
                    shard_id: ShardGroupId::new(999),
                    position: 0,
                },
            )
            .is_none()
        );
    }

    #[test]
    fn absent_miss_counter_returns_none() {
        let s = sample_state();
        // Validator 0 has no miss-counter entry in sample_state.
        assert!(prove(&s, &StateKey::MissCounter(ValidatorId::new(0))).is_none());
    }

    #[test]
    fn tampered_validator_value_rejected() {
        let s = sample_state();
        let root = state_root(&s);
        let key = StateKey::Validator(ValidatorId::new(0));
        let (value, proof) = prove(&s, &key).unwrap();
        let tampered = match value {
            StateValue::Validator(mut r) => {
                r.id = ValidatorId::new(1);
                StateValue::Validator(r)
            }
            _ => unreachable!(),
        };
        assert!(!verify(root, &key, &tampered, &proof));
    }

    #[test]
    fn wrong_container_index_rejected() {
        let s = sample_state();
        let root = state_root(&s);
        let key = StateKey::Epoch;
        let (value, mut proof) = prove(&s, &key).unwrap();
        proof.container_index = INDEX_RANDOMNESS;
        assert!(!verify(root, &key, &value, &proof));
    }

    #[test]
    fn missing_subtree_for_aggregate_key_rejected() {
        let s = sample_state();
        let root = state_root(&s);
        let key = StateKey::Validator(ValidatorId::new(0));
        let (value, mut proof) = prove(&s, &key).unwrap();
        proof.subtree = None;
        assert!(!verify(root, &key, &value, &proof));
    }
}
