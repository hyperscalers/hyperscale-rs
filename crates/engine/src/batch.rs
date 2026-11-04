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

use hyperscale_storage::FeeHoldReading;
use hyperscale_types::{
    EpochWindows, EscrowedValue, ProvisionalHolds, SeedRing, ShardId, ShardTrie, SubstateEntry,
    TopologySnapshot, Transaction, TxHash, Verified, WeightedTimestamp,
};
use hyperscale_vm_types::{PriceTable, SeedWindow};

use crate::executor::PointReads;
use crate::legs::Member;

/// What a block fixes about the environment its tick executes under.
///
/// Carried from the commit that composed the tick, on the same terms as
/// the clock beside it.
#[derive(Clone, Debug)]
pub struct TickEnvironment {
    /// The seeds this tick's members draw on: the ring the window
    /// governing the block carried, and the ring of each member's own
    /// window where that one falls short. That window is fresher for a
    /// member clocked past the block's, and older for one a halt
    /// recovery's crossing block names under a committee epochs past its
    /// clock.
    ///
    /// Only a store. What a member draws on is
    /// [`Self::seed_window_for`] its own clock, which the ring answers
    /// alike whichever copy of a window it came from and however far
    /// this node had folded the beacon when it took it.
    pub seeds: SeedRing,
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
    #[must_use]
    pub fn governing(snapshot: &TopologySnapshot, windows: EpochWindows) -> Self {
        Self {
            seeds: snapshot.seeds().clone(),
            windows,
        }
    }

    /// An environment no seal can open, over the single-window grid.
    /// For callers with no committed block to take one from.
    #[must_use]
    pub fn unfolded() -> Self {
        Self {
            seeds: SeedRing::default(),
            windows: EpochWindows::new(0, 0),
        }
    }

    /// The seed window a member clocked at `clock` draws on: the
    /// [`SeedRing::window_for`] the epoch its clock falls in. One answer
    /// on every shard running the member, since the clock is the
    /// transaction's and the window is a function of its epoch alone.
    ///
    /// `None` while the ring lacks a seed of it, which the tick waits out
    /// before it dispatches.
    #[must_use]
    pub fn seed_window_for(&self, clock: WeightedTimestamp) -> Option<SeedWindow> {
        self.seeds.window_for(self.windows.epoch_for(clock))
    }
}

/// Per-tick inputs an engine's batch execution reads besides the
/// transactions themselves.
pub struct TickBatchContext<'a> {
    /// The executing vnode's shard — the projection target.
    pub local_shard: ShardId,
    /// The active shard partition.
    pub shard_trie: &'a ShardTrie,
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
    /// The fee holds standing for this tick on the vaults this shard
    /// charges: every ceiling a committed transaction holds until its
    /// price is burned. The kernel judges a debit and a reservation
    /// under them as well, so no body spends what a price yet to be
    /// burned was promised, and a member's own burn comes out of its
    /// own hold.
    pub fee_holds: &'a dyn FeeHoldReading,
    /// What answers an entry point of this shard's own owners that no
    /// declaration's pre-read named, read at the snapshot's version: the
    /// tick view's own reads. `None` answers every point from the
    /// pre-read alone.
    pub points: Option<Arc<dyn PointReads>>,
}

/// One member of a tick's batch.
///
/// A single-shard transaction or a cross-shard leg, each carrying the
/// environment its committing block fixed. The whole tick executes as
/// one batch, so the executor's canonical order and conflict groups
/// sequence members across ticks.
pub struct TickTxInput<'a> {
    /// What names the member, and what its receipt is keyed by.
    pub tx_hash: TxHash,
    /// The transaction to execute.
    pub transaction: &'a Verified<Transaction>,
    /// Verified provision entry lists, one per source shard contribution.
    /// Empty for a single-shard member.
    pub provisions: &'a [Arc<Vec<SubstateEntry>>],
    /// The transaction clock, identical on every shard running the same
    /// body: the tick anchor for a single-shard member, the payer-shard
    /// committing block's parent-QC weighted timestamp for a whole
    /// cross-shard member, the earliest of the core shards' committing
    /// clocks for a core member, and its own committing block's for a
    /// leg, which runs alone.
    pub clock: WeightedTimestamp,
    /// The price table the block that committed this member named.
    ///
    /// This chain's own, not the clock's: the burn it settles is taken
    /// by the shard holding the payer's vault and by no other, and that
    /// shard's admission judged the signed ceiling against this same
    /// table. A table read at the executing head instead would price one
    /// transaction two ways across an epoch fold.
    pub prices: PriceTable,
    /// The transaction as its block froze it — carried, never
    /// re-derived, since a reshape landing between composition and
    /// execution would otherwise leave one shard running a whole
    /// manifest while its counterpart waits to be sent half of it. What
    /// it says of the member decides the batch's write locality — a
    /// member declaring remote cells has its writes filtered to the
    /// subtree this shard owns — and the reserve refusal receipt, which
    /// only a member a counterpart's verdict can still discard holds.
    pub member: Member,
    /// What committed bundles attested for the edges this shard's legs
    /// consume. Empty for a member that runs whole.
    pub arrivals: &'a [EscrowedValue],
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{Epoch, EpochSeed, Randomness, SeedSource};
    use hyperscale_vm_types::Drawn;

    use super::*;

    const ED: u64 = 1_000;
    const WINDOWS: EpochWindows = EpochWindows::new(0, ED);

    /// A tick's environment whose ring the beacon folded through `newest`.
    fn folded_through(newest: u64) -> TickEnvironment {
        let mut seeds = SeedRing::default();
        for epoch in 1..=newest {
            seeds.record(
                Epoch::new(epoch),
                EpochSeed {
                    randomness: Randomness::new([u8::try_from(epoch % 251).unwrap(); 32]),
                    source: SeedSource::Reveals,
                },
                WINDOWS,
            );
        }
        TickEnvironment {
            seeds,
            windows: WINDOWS,
        }
    }

    /// Two shards of one divided core tick its member in different
    /// windows, under one clock: the earliest of their committing clocks,
    /// in epoch `E`. One ticks in `E` on the copy of it the fold of
    /// `E - 1` published; the other ticks in `E + 1` on the copy the fold
    /// of `E + 1` froze, two seeds further on. Each half of the core opens
    /// a seal alike, or the two halves apply different branches.
    #[test]
    fn core_members_ticking_in_different_windows_draw_alike() {
        const E: u64 = 90;
        let clock = WeightedTimestamp::from_millis(E * ED + 700);
        let early = folded_through(E - 1).seed_window_for(clock).expect("held");
        let late = folded_through(E + 1).seed_window_for(clock).expect("held");
        assert_eq!(early, late);
        assert_eq!(late.at(E), Drawn::Pending, "the clock's own epoch is ahead");
        assert_eq!(late.at(E + 1), Drawn::Pending);
        assert_eq!(late.at(E - 1), Drawn::Ready([89; 32]));
    }

    /// Members of one tick clocked in different epochs draw on different
    /// windows: the window is the member's, not the tick's.
    #[test]
    fn each_member_draws_on_its_own_clocks_window() {
        let env = folded_through(80);
        let at = |epoch: u64| {
            env.seed_window_for(WeightedTimestamp::from_millis(epoch * ED))
                .expect("held")
        };
        assert_eq!(at(78).at(78), Drawn::Pending);
        assert_eq!(at(79).at(78), Drawn::Ready([78; 32]));
    }
}
