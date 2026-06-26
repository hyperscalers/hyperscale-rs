//! Await combinators: drive a [`Cluster`] until a condition holds.
//!
//! Each wraps [`Cluster::run_until`] with a budget in epochs and a predicate
//! over the cluster's synchronous observations. The bool-returning waits report
//! whether the condition held within budget; a scenario asserts on that.

use hyperscale_types::{ShardId, TransactionStatus, TxHash};

use super::query::{anchor_root, beacon_epoch, merge_keeper_count, split_admitted};
use super::{Budget, Cluster};

/// Wait until the committed beacon epoch reaches `target`.
pub fn await_beacon_epoch<C: Cluster>(c: &mut C, target: u64, budget: Budget) -> bool {
    c.run_until(budget, |c| {
        beacon_epoch(c).is_some_and(|e| e.inner() >= target)
    })
}

/// Wait until `shard`'s committed height reaches `target`.
pub fn await_height<C: Cluster>(c: &mut C, shard: ShardId, target: u64, budget: Budget) -> bool {
    c.run_until(budget, |c| {
        c.committed_height(shard)
            .is_some_and(|h| h.inner() >= target)
    })
}

/// Wait until any host serves `shard`.
pub fn await_serves<C: Cluster>(c: &mut C, shard: ShardId, budget: Budget) -> bool {
    c.run_until(budget, |c| c.serves_shard(shard))
}

/// Wait until the beacon admits a split for `parent`.
pub fn await_split_admitted<C: Cluster>(c: &mut C, parent: ShardId, budget: Budget) -> bool {
    c.run_until(budget, |c| split_admitted(c, parent))
}

/// Wait until the beacon pairs a merge into `parent` with at least `min`
/// keepers drawn.
pub fn await_merge_keeper_count<C: Cluster>(
    c: &mut C,
    parent: ShardId,
    min: usize,
    budget: Budget,
) -> bool {
    c.run_until(budget, |c| {
        merge_keeper_count(c, parent).is_some_and(|count| count >= min)
    })
}

/// Wait until `shard`'s committed root matches the beacon-composed anchor — the
/// subtree-root-continuity check a flip must satisfy.
pub fn await_root_matches_anchor<C: Cluster>(c: &mut C, shard: ShardId, budget: Budget) -> bool {
    c.run_until(budget, |c| {
        matches!(
            (c.committed_state_root(shard), anchor_root(c, shard)),
            (Some(committed), Some(anchor)) if committed == anchor
        )
    })
}

/// Wait until `tx` reaches a terminal (`Completed`) status, returning the last
/// observed status.
///
/// A successful tx finalizes and may then be cleaned up (status returns to
/// `None`); the latching of the first terminal observation lives in the
/// submit/status path, not here.
pub fn await_tx_terminal<C: Cluster>(
    c: &mut C,
    tx: TxHash,
    budget: Budget,
) -> Option<TransactionStatus> {
    c.run_until(budget, |c| c.tx_status(tx).is_some_and(|s| s.is_final()));
    c.tx_status(tx)
}

/// Run `budget` epochs and assert `shard`'s committed height never advances.
///
/// The "this shard stopped" signal (a terminated split parent). A terminated
/// parent may drop to `None` as its store is dropped, so this asserts
/// non-increase rather than strict equality (`None < Some`).
///
/// # Panics
///
/// Panics if the height advances over the window.
pub fn assert_height_frozen<C: Cluster>(c: &mut C, shard: ShardId, budget: Budget) {
    let before = c.committed_height(shard);
    c.run_until(budget, |_| false);
    let after = c.committed_height(shard);
    assert!(
        after <= before,
        "{shard:?} advanced from {before:?} to {after:?} over {budget:?}; expected stopped"
    );
}
