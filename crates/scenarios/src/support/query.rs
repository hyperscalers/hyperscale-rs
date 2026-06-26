//! Derived read-only combinators over a [`Cluster`].
//!
//! Each is a projection of [`Cluster::beacon_state`], kept out of the trait so
//! both adaptors share one definition and cannot drift apart.

use std::collections::BTreeSet;

use hyperscale_types::{
    Bls12381G1PublicKey, Epoch, PendingReshape, ShardId, Stake, StakePool, StakePoolId, StateRoot,
    ValidatorId, ValidatorStatus,
};

use super::Cluster;

/// The latest committed beacon epoch, if the cluster has folded one.
#[must_use]
pub fn beacon_epoch<C: Cluster>(c: &C) -> Option<Epoch> {
    c.beacon_state().map(|state| state.current_epoch)
}

/// Whether the beacon has admitted a split for `parent` — a pending `Split`
/// record carrying the drawn observer cohort.
#[must_use]
pub fn split_admitted<C: Cluster>(c: &C, parent: ShardId) -> bool {
    c.beacon_state().is_some_and(|state| {
        matches!(
            state.pending_reshapes.get(&parent),
            Some(PendingReshape::Split { .. })
        )
    })
}

/// The beacon-composed anchor root for `shard` — the `boundaries` `state_root`
/// a flip must reproduce.
#[must_use]
pub fn anchor_root<C: Cluster>(c: &C, shard: ShardId) -> Option<StateRoot> {
    c.beacon_state()
        .and_then(|state| state.boundaries.get(&shard).map(|b| b.state_root))
}

/// The number of keepers drawn for a merge into `parent`, once paired (both
/// children hold a live half). `None` before pairing.
#[must_use]
pub fn merge_keeper_count<C: Cluster>(c: &C, parent: ShardId) -> Option<usize> {
    c.beacon_state()
        .and_then(|state| match state.pending_reshapes.get(&parent) {
            Some(PendingReshape::Merge {
                keepers,
                admitted_at: Some(_),
                ..
            }) => Some(keepers.len()),
            _ => None,
        })
}

/// The number of validators seated on `shard`'s current committee, or `None` if
/// the beacon seats no committee there (the shard is unborn or terminated).
#[must_use]
pub fn committee_size<C: Cluster>(c: &C, shard: ShardId) -> Option<usize> {
    c.beacon_state().and_then(|state| {
        state
            .shard_committees
            .get(&shard)
            .map(|cm| cm.members.len())
    })
}

/// The set of shards the beacon currently seats a committee for — the live leaf
/// partition.
#[must_use]
pub fn live_shards<C: Cluster>(c: &C) -> BTreeSet<ShardId> {
    c.beacon_state()
        .map(|state| state.shard_committees.keys().copied().collect())
        .unwrap_or_default()
}

/// The total stake folded into `pool`, or `None` if the beacon holds no record
/// of it — counting deposits whether or not they have unbonded.
#[must_use]
pub fn pool_total_stake<C: Cluster>(c: &C, pool: StakePoolId) -> Option<Stake> {
    c.beacon_state()
        .and_then(|state| state.pools.get(&pool).map(|p| p.total_stake))
}

/// The effective (bonded) stake of `pool` — total less any stake still inside
/// its unbonding window. A withdrawal drops this immediately while
/// [`pool_total_stake`] holds until the unbond matures.
#[must_use]
pub fn pool_effective_stake<C: Cluster>(c: &C, pool: StakePoolId) -> Option<Stake> {
    c.beacon_state()
        .and_then(|state| state.pools.get(&pool).map(StakePool::effective_stake))
}

/// The folded status of validator `id`, or `None` if the beacon holds no record
/// of it.
#[must_use]
pub fn validator_status<C: Cluster>(c: &C, id: ValidatorId) -> Option<ValidatorStatus> {
    c.beacon_state()
        .and_then(|state| state.validators.get(&id).map(|r| r.status))
}

/// The registered BLS public key of validator `id`, or `None` if unregistered.
#[must_use]
pub fn validator_pubkey<C: Cluster>(c: &C, id: ValidatorId) -> Option<Bls12381G1PublicKey> {
    c.beacon_state()
        .and_then(|state| state.validators.get(&id).map(|r| r.pubkey))
}
