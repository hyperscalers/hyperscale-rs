//! Derived read-only combinators over a [`Cluster`].
//!
//! Each is a projection of [`Cluster::beacon_state`], kept out of the trait so
//! both adaptors share one definition and cannot drift apart.

use hyperscale_types::{Epoch, PendingReshape, ShardId, StateRoot};

use crate::Cluster;

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
