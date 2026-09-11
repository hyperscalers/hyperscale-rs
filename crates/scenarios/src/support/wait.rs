//! Await combinators: drive a [`Cluster`] until a condition holds.
//!
//! Each wraps [`Cluster::run_until`] with a budget in epochs and a predicate
//! over the cluster's synchronous observations. The bool-returning waits report
//! whether the condition held within budget; a scenario asserts on that.

use std::cell::Cell;
use std::time::Duration;

use hyperscale_types::{BlockHeight, Epoch, ShardId, TransactionStatus, TxHash};

use super::query::{
    anchor_root, anchored_genesis_height, beacon_epoch, epoch_duration_ms, merge_keeper_count,
    split_admitted,
};
use super::{Budget, Cluster, epochs};

/// How long [`measure_blocks_per_epoch`] samples a shard's cadence for.
///
/// Block cadence is activity-driven and steady within an epoch, so a few
/// dozen blocks read the rate; the harness advances a second at a time,
/// so the sample is spelled in seconds rather than blocks.
const CADENCE_SAMPLE: Duration = Duration::from_secs(10);

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

/// Wait until `shard` commits `blocks` more blocks past its height now.
///
/// The hold behind a claim about what a chain does *not* do next. A
/// delivery, a reclaim or a credit rides a block, so "nothing more comes
/// back" is read over blocks: a shard commits many times a second
/// whatever the epoch length, and an epoch of that is thousands of
/// blocks for a question a handful decides.
pub fn await_blocks<C: Cluster>(c: &mut C, shard: ShardId, blocks: u64, budget: Budget) -> bool {
    let target = c
        .committed_height(shard)
        .map_or(0, BlockHeight::inner)
        .saturating_add(blocks);
    await_height(c, shard, target, budget)
}

/// Wait until the beacon commits `folds` more epochs past the one committed
/// now.
///
/// The hold behind a claim about a beacon record: a record moves only at a
/// fold, so "the record did not move" is read across folds.
pub fn await_folds<C: Cluster>(c: &mut C, folds: u64, budget: Budget) -> bool {
    let target = beacon_epoch(c)
        .map_or(0, Epoch::inner)
        .saturating_add(folds);
    await_beacon_epoch(c, target, budget)
}

/// How many blocks `shard` commits per epoch at its current cadence,
/// sampled over [`CADENCE_SAMPLE`] and scaled to the epoch.
///
/// Block cadence is activity-driven and scales with neither the epoch nor
/// the harness, so a train spaced in blocks measures the rate rather
/// than assuming it. Whatever activity the caller wants priced in has to
/// be in flight before the sample starts.
///
/// # Panics
///
/// Panics if no beacon epoch is committed, since the epoch length is what
/// the sample is scaled to.
pub fn measure_blocks_per_epoch<C: Cluster>(c: &mut C, shard: ShardId) -> u64 {
    let epoch_ms = epoch_duration_ms(c).expect("a committed beacon epoch");
    let height = |c: &C| c.committed_height(shard).map_or(0, BlockHeight::inner);
    let before = height(c);
    let until = c.now() + CADENCE_SAMPLE;
    let _ = c.run_until(epochs(1), |c| c.now() >= until);
    let sampled = height(c).saturating_sub(before);
    let sample_ms = u64::try_from(CADENCE_SAMPLE.as_millis()).expect("a short sample");
    sampled.saturating_mul(epoch_ms) / sample_ms
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

/// Wait until the beacon composes `shard`'s reshape anchor, replacing the
/// placeholder its cut installed.
pub fn await_anchor_seeded<C: Cluster>(c: &mut C, shard: ShardId, budget: Budget) -> bool {
    c.run_until(budget, |c| anchored_genesis_height(c, shard).is_some())
}

/// Wait until `shard` is served, reporting whether the beacon had yet to
/// compose its reshape anchor at that instant.
///
/// `Some(true)` is the cut-over: the successor seated from its
/// predecessor's terminal crossing, ahead of the fold that publishes its
/// anchor. `Some(false)` means it seated only once the anchor was already
/// available — the fallback path, correct but an epoch late. `None` means
/// it never served within budget.
///
/// The reading is taken inside the wait, at the first step the shard
/// serves, so it cannot drift as the beacon catches up afterwards.
pub fn await_serves_ahead_of_anchor<C: Cluster>(
    c: &mut C,
    shard: ShardId,
    budget: Budget,
) -> Option<bool> {
    let ahead = Cell::new(false);
    let served = c.run_until(budget, |c| {
        if !c.serves_shard(shard) {
            return false;
        }
        ahead.set(anchored_genesis_height(c, shard).is_none());
        true
    });
    served.then(|| ahead.get())
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
