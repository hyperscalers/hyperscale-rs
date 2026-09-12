//! What a tick's batch is executed against.
//!
//! The snapshot borrow, the per-tick context, and the cross-shard input
//! an [`Executor`](crate::Executor) reads besides the transactions
//! themselves.
//!
//! Storage is NOT owned by the executor — the runner provides it as a
//! method argument so the same executor can serve multiple snapshots
//! and so the runner can hoist a single snapshot across an entire
//! action batch.
//!
//! Execution is READ-ONLY: results are returned as `ExecutedTx` values
//! whose writes the state machine caches and applies later, when the
//! tick's certificate is included in a committed block.

use std::sync::Arc;

use hyperscale_types::{
    Epoch, EpochWindows, EscrowedValue, ProvisionalHolds, ShardId, ShardTrie, SubstateEntry,
    TopologySnapshot, Transaction, TxHash, Verified, WeightedTimestamp,
};
use hyperscale_vm_types::{PriceTable, SeedWindow};

use crate::legs::Runs;

/// What a block fixes about the environment its tick executes under.
///
/// Resolved from the snapshot governing the block rather than from a
/// node's own head: a node's head advances as it folds the beacon, and
/// two members fold at their own pace, so a window taken from one would
/// answer `Pending` on a laggard where it answers `Ready` on a leader —
/// two receipts for one tick. Carried from the commit that composed the
/// tick, on the same terms as the clock beside it.
#[derive(Clone, Debug)]
pub struct TickEnvironment {
    /// The epochs a sealed draw in this batch may settle on.
    ///
    /// Global rather than per transaction: the seeds are the beacon's,
    /// so every shard resolves the same value for the same epoch and
    /// nothing about which block executes a leg reaches the answer.
    pub seeds: SeedWindow,
    /// The grid that turns a member's clock into the epoch a seal it
    /// writes records — so the epoch rides the clock the transaction
    /// already carries rather than travelling beside it.
    ///
    /// Taken from the schedule, which is the object indexed by it, and
    /// not from the snapshot: a genesis-fixed window length carried on
    /// something derived per window would be a second answer to a
    /// question already settled, and a default on the copy would answer
    /// it wrongly where nobody set one. It is also the half of this pair
    /// that cannot skew — a seed ring is what one window retained, where
    /// the grid is the same under every window there has been.
    pub windows: EpochWindows,
}

impl TickEnvironment {
    /// The environment the block governed by `snapshot` executes under,
    /// on the grid `windows` lays down.
    ///
    /// Only the reveal-folded epochs cross into the seed window. A
    /// ceremony roll is a seed a beacon member could have withheld from,
    /// and a draw settled on one is settled on a value somebody had a
    /// lever over — so a seal maturing into such an epoch answers
    /// `Expired` and the round closes again.
    #[must_use]
    pub fn governing(snapshot: &TopologySnapshot, windows: EpochWindows) -> Self {
        let ring = snapshot.seeds();
        Self {
            seeds: SeedWindow::new(
                ring.folded()
                    .map(|(epoch, seed)| (epoch.inner(), *seed.as_bytes()))
                    .collect(),
                ring.newest().map(Epoch::inner),
            ),
            windows,
        }
    }

    /// An environment no seal can open, over the single-window grid.
    /// For callers with no committed block to take one from.
    #[must_use]
    pub const fn unfolded() -> Self {
        Self {
            seeds: SeedWindow::unfolded(),
            windows: EpochWindows::new(0),
        }
    }
}

/// Per-tick inputs an engine's batch execution reads besides the
/// transactions themselves.
pub struct TickBatchContext<'a> {
    /// The executing vnode's shard — the projection target.
    pub local_shard: ShardId,
    /// The active shard partition.
    pub shard_trie: &'a ShardTrie,
    /// What each dimension costs under the window the tick-starting
    /// block anchored to.
    ///
    /// Off the anchor like the trie beside it, and for the same reason:
    /// a fee read at the head would price a transaction straddling an
    /// epoch boundary differently on its two shards, and the receipt
    /// carrying it is one both derive.
    pub prices: PriceTable,
    /// The tick-starting block's parent-QC weighted timestamp. For a
    /// single-shard batch this is the transaction clock of every member;
    /// cross-shard batches carry per-transaction clocks on their inputs.
    pub tick_ts: WeightedTimestamp,
    /// What the tick-starting block fixed about the environment: the
    /// seeds a seal may settle on and the epoch grid a clock resolves
    /// against.
    pub env: TickEnvironment,
    /// Reservations still held by legs of ticks this batch's baseline
    /// cannot see, because nothing an unresolved tick wrote is readable.
    /// The kernel judges a reservation and a debit against committed
    /// balance less what is held, so these are what keep one vault from
    /// funding two withdrawals in successive ticks.
    pub holds: &'a ProvisionalHolds,
}

/// One member of a tick's batch.
///
/// A single-shard transaction or a cross-shard leg, each carrying the
/// environment its committing block fixed. The whole tick executes as
/// one batch, so the executor's canonical order and conflict groups
/// sequence members across ticks.
pub struct TickTxInput<'a> {
    /// What names the member, and what its receipt is keyed by. Carried
    /// rather than hashed off the body, because a housekeeping member
    /// has no body: the record cell names the transaction that issued
    /// the crossing, and that is the name its own receipt takes.
    pub tx_hash: TxHash,
    /// The transaction to execute, for a member that runs its shape.
    /// `None` for a housekeeping member, whose cells `runs` names.
    pub transaction: Option<&'a Arc<Verified<Transaction>>>,
    /// Verified provision entry lists, one per source shard contribution.
    /// Empty for a single-shard member.
    pub provisions: &'a [Arc<Vec<SubstateEntry>>],
    /// The transaction clock, identical on every participant: the
    /// tick anchor for a single-shard member, the payer-shard
    /// committing block's parent-QC weighted timestamp for a cross-shard
    /// leg.
    pub clock: WeightedTimestamp,
    /// What this member runs: the transaction as its block froze it —
    /// carried, never re-derived, since a reshape landing between
    /// composition and execution would otherwise leave one shard running
    /// a whole manifest while its counterpart waits to be sent half of
    /// it — or a settlement of what a leg here issued. What it says of
    /// the member decides the batch's write locality — a member
    /// declaring remote cells has its writes filtered to the subtree
    /// this shard owns — and the reserve fee receipt, which only a
    /// member a counterpart's verdict can still discard holds.
    pub runs: Runs,
    /// What committed bundles attested for the edges this shard's legs
    /// consume. Empty for a member that runs whole.
    pub arrivals: &'a [EscrowedValue],
}
