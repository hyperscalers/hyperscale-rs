//! Weighted-time-indexed schedule of per-epoch committee snapshots.
//!
//! A [`TopologySnapshot`] is one committee's view; a [`TopologySchedule`] is
//! those views indexed by the epoch each governs. It is the interface the rest
//! of the system resolves committees through — consensus artifacts are signed
//! by the committee for `epoch_for(weighted_timestamp)`, which may differ from
//! the current one, so verification keys on [`TopologySchedule::at`] while
//! routing keys on [`TopologySchedule::head`].
//!
//! The schedule is pure topology: it carries no consensus state and depends on
//! nothing above `hyperscale-types`. The beacon coordinator owns one and
//! advances it on each commit; shard and execution verification borrow it.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::{Epoch, ReshapeThresholds, ShardId, TopologySnapshot, WeightedTimestamp};

/// Per-epoch committee snapshots keyed by the epoch each governs, plus the
/// active head used for routing.
///
/// `committee_N` governs the weighted-time window `[N·ED, (N+1)·ED)`;
/// [`at`](Self::at) floors a timestamp to its epoch and returns that
/// committee. The map spans `[floor, current + lookahead]`: the owner derives
/// `floor` from the oldest epoch any consumer can still legitimately query
/// and trims via [`evict_below`](Self::evict_below); the lookahead entry is
/// finalized an epoch before its window opens.
///
/// A schedule built with [`single`](Self::single) carries one committee for
/// all time (`epoch_duration_ms == 0` folds every timestamp to genesis) — the
/// pre-rotation / single-epoch case used by tests and within-epoch callers.
#[derive(Clone)]
pub struct TopologySchedule {
    /// Window length in milliseconds; `epoch = floor(wt / epoch_duration_ms)`.
    /// Zero means a single fixed committee (every timestamp maps to genesis).
    epoch_duration_ms: u64,
    /// Substate-count thresholds for automatic shard reshaping, sourced
    /// from the folded `BeaconState`'s chain config like
    /// `epoch_duration_ms`. Consensus-critical; `DISABLED` unless the
    /// network configured reshaping.
    reshape_thresholds: ReshapeThresholds,
    /// Active committee for routing / gossip ("who is in the committee now?").
    head: Arc<TopologySnapshot>,
    /// Committee snapshots keyed by the epoch each governs.
    by_epoch: BTreeMap<Epoch, Arc<TopologySnapshot>>,
}

/// Answer of [`TopologySchedule::split_at_next_boundary`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitAtBoundary {
    /// No split lands at the end of this window — definitive.
    No,
    /// The window has an admitted split pending and the next window's
    /// entry hasn't committed locally, so whether the split executes at
    /// this boundary is genuinely unknown yet. Transient: defer and
    /// retry once the local beacon catches up.
    Unresolved,
    /// The shard's final epoch: the trie replaces it with these children
    /// at the next boundary.
    Children(ShardId, ShardId),
}

/// Result of resolving a weighted timestamp against the retained window.
pub enum ScheduleLookup<'a> {
    /// The epoch's committee is retained.
    Committee(&'a Arc<TopologySnapshot>),
    /// The epoch is newer than every retained entry — this node's beacon
    /// hasn't committed it yet. Transient: buffer or defer and retry.
    NotYetCommitted,
    /// The epoch is older than every retained entry. Eviction only drops
    /// epochs every consumer frontier has passed, so no honest artifact can
    /// still be attested there — reject rather than defer.
    Evicted,
}

impl TopologySchedule {
    /// Build a schedule seeded with `head` as the committee governing
    /// `head_epoch`. The beacon coordinator inserts the lookahead and any
    /// retained past epochs afterward via [`insert`](Self::insert).
    #[must_use]
    pub fn new(epoch_duration_ms: u64, head_epoch: Epoch, head: Arc<TopologySnapshot>) -> Self {
        let mut by_epoch = BTreeMap::new();
        by_epoch.insert(head_epoch, Arc::clone(&head));
        Self {
            epoch_duration_ms,
            reshape_thresholds: ReshapeThresholds::DISABLED,
            head,
            by_epoch,
        }
    }

    /// Set the network's reshape thresholds (from the folded
    /// `BeaconState`'s chain config). Construction-time only — the
    /// thresholds are a chain constant, not per-epoch state.
    #[must_use]
    pub const fn with_reshape_thresholds(mut self, thresholds: ReshapeThresholds) -> Self {
        self.reshape_thresholds = thresholds;
        self
    }

    /// Substate-count thresholds for automatic shard reshaping.
    #[must_use]
    pub const fn reshape_thresholds(&self) -> ReshapeThresholds {
        self.reshape_thresholds
    }

    /// The chain's epoch window length in milliseconds — the constant the
    /// schedule's epoch resolution divides by, sourced from the folded
    /// `BeaconState`'s chain config. Zero for [`Self::single`], where no
    /// epoch boundaries exist.
    #[must_use]
    pub const fn epoch_duration_ms(&self) -> u64 {
        self.epoch_duration_ms
    }

    /// A schedule of one committee for all time: every weighted timestamp
    /// resolves to `snapshot`, and it is also the head. Used by tests and by
    /// within-epoch callers that hold a single committee.
    #[must_use]
    pub fn single(snapshot: Arc<TopologySnapshot>) -> Self {
        // `epoch_duration_ms == 0` makes `epoch_for` fold every timestamp to
        // genesis, where the sole entry lives — so `at` always answers.
        let mut by_epoch = BTreeMap::new();
        by_epoch.insert(Epoch::GENESIS, Arc::clone(&snapshot));
        Self {
            epoch_duration_ms: 0,
            reshape_thresholds: ReshapeThresholds::DISABLED,
            head: snapshot,
            by_epoch,
        }
    }

    /// Epoch whose window contains `wt` — `floor(wt / epoch_duration_ms)`,
    /// genesis-relative. A zero duration (single-committee schedule) folds
    /// every timestamp to genesis.
    #[must_use]
    pub const fn epoch_for(&self, wt: WeightedTimestamp) -> Epoch {
        match wt.as_millis().checked_div(self.epoch_duration_ms) {
            Some(epoch) => Epoch::new(epoch),
            None => Epoch::GENESIS,
        }
    }

    /// Committee that signed an artifact attested at `wt` — exact, for
    /// verification and quorum. `None` when that epoch is outside the retained
    /// window; callers that handle the two miss reasons differently use
    /// [`lookup`](Self::lookup). Hands out a shared handle: borrow it for
    /// verification, or clone it to move into an off-thread closure.
    #[must_use]
    pub fn at(&self, wt: WeightedTimestamp) -> Option<&Arc<TopologySnapshot>> {
        match self.lookup(wt) {
            ScheduleLookup::Committee(snapshot) => Some(snapshot),
            ScheduleLookup::NotYetCommitted | ScheduleLookup::Evicted => None,
        }
    }

    /// [`at`](Self::at) with the miss reason surfaced: an epoch above every
    /// retained entry is [`NotYetCommitted`](ScheduleLookup::NotYetCommitted)
    /// (defer and retry), anything else absent is
    /// [`Evicted`](ScheduleLookup::Evicted) (reject — no honest artifact is
    /// attested below the eviction floor).
    #[must_use]
    pub fn lookup(&self, wt: WeightedTimestamp) -> ScheduleLookup<'_> {
        let epoch = self.epoch_for(wt);
        if let Some(snapshot) = self.by_epoch.get(&epoch) {
            return ScheduleLookup::Committee(snapshot);
        }
        match self.by_epoch.last_key_value() {
            Some((newest, _)) if epoch > *newest => ScheduleLookup::NotYetCommitted,
            _ => ScheduleLookup::Evicted,
        }
    }

    /// Active head committee — for the chain's constant
    /// [`NetworkDefinition`](crate::NetworkDefinition) and self-healing routing
    /// (including the lock-free reads the `io_loop` serves through its
    /// `ArcSwap`). Never for committee-quorum verification, which must key on
    /// the artifact's own weighted timestamp via [`at`](Self::at).
    #[must_use]
    pub const fn head(&self) -> &Arc<TopologySnapshot> {
        &self.head
    }

    /// [`at`](Self::at) for a shard whose chain may terminate: resolve
    /// `wt`'s committee, clamping to `shard`'s **terminal window** when
    /// `wt` falls past it. A splitting shard's last blocks carry parent
    /// QC timestamps past the cut (the coast blocks certifying the
    /// crossing), which resolve to a window whose trie no longer carries
    /// the shard; those blocks are still proposed and signed by the
    /// shard's final-epoch committee, so resolution walks back to the
    /// newest retained window that carries the shard. The second value
    /// is the past-terminal signal: `true` exactly for those coast
    /// blocks, which must be empty and stop the chain once the crossing
    /// commits. For a shard alive in `wt`'s window this is exactly
    /// [`at`](Self::at) plus `false`.
    #[must_use]
    pub fn at_for_shard(
        &self,
        shard: ShardId,
        wt: WeightedTimestamp,
    ) -> Option<(&Arc<TopologySnapshot>, bool)> {
        match self.lookup_for_shard(shard, wt) {
            (ScheduleLookup::Committee(snapshot), past_terminal) => Some((snapshot, past_terminal)),
            _ => None,
        }
    }

    /// [`lookup`](Self::lookup) with the terminal clamp of
    /// [`at_for_shard`](Self::at_for_shard): a `wt` whose window no
    /// longer carries `shard` resolves the newest retained window that
    /// does, flagged `true`. A `wt` whose window carries no trace of the
    /// shard in any retained window resolves [`Evicted`](ScheduleLookup::Evicted)
    /// — it claims a committee no honest artifact can be attested by.
    #[must_use]
    pub fn lookup_for_shard(
        &self,
        shard: ShardId,
        wt: WeightedTimestamp,
    ) -> (ScheduleLookup<'_>, bool) {
        match self.lookup(wt) {
            ScheduleLookup::Committee(snapshot) if !snapshot.shard_trie().contains(shard) => self
                .by_epoch
                .range(..self.epoch_for(wt))
                .rev()
                .find(|(_, s)| s.shard_trie().contains(shard))
                .map_or((ScheduleLookup::Evicted, true), |(_, s)| {
                    (ScheduleLookup::Committee(s), true)
                }),
            other => (other, false),
        }
    }

    /// Whether `shard` splits into its two children at the end of `wt`'s
    /// epoch window — [`Children`](SplitAtBoundary::Children) exactly
    /// when `wt` falls in the splitting shard's final epoch, resolved by
    /// comparing the window's trie against the next window's.
    ///
    /// The next window's entry is written by the fold that *starts*
    /// `wt`'s window, so blocks early in the window can locally outrun
    /// it. When it is absent, the window's own frozen
    /// [`split_pending`](TopologySnapshot::split_pending) projection
    /// decides: no admitted split means the trie cannot drop the shard
    /// at this boundary ([`No`](SplitAtBoundary::No), definitive — the
    /// common case, so plain epoch crossings never wait on the local
    /// beacon), while a pending split leaves the answer genuinely
    /// unknown until the local beacon catches up
    /// ([`Unresolved`](SplitAtBoundary::Unresolved); callers defer).
    ///
    /// A [`single`](Self::single) schedule has no epoch boundaries, so
    /// no split can land at one — [`No`](SplitAtBoundary::No),
    /// definitive.
    #[must_use]
    pub fn split_at_next_boundary(&self, shard: ShardId, wt: WeightedTimestamp) -> SplitAtBoundary {
        if self.epoch_duration_ms == 0 {
            return SplitAtBoundary::No;
        }
        let epoch = self.epoch_for(wt);
        let Some(current) = self.by_epoch.get(&epoch) else {
            return SplitAtBoundary::Unresolved;
        };
        if !current.shard_trie().contains(shard) {
            return SplitAtBoundary::No;
        }
        let Some(next) = self.by_epoch.get(&epoch.next()) else {
            return if current.split_pending(shard) {
                SplitAtBoundary::Unresolved
            } else {
                SplitAtBoundary::No
            };
        };
        if next.shard_trie().contains(shard) {
            return SplitAtBoundary::No;
        }
        let (left, right) = shard.children();
        if next.shard_trie().contains(left) && next.shard_trie().contains(right) {
            SplitAtBoundary::Children(left, right)
        } else {
            SplitAtBoundary::No
        }
    }

    /// Record the committee governing `epoch`. The beacon coordinator inserts
    /// the just-applied epoch's active committee and the next epoch's
    /// lookahead on every commit.
    pub fn insert(&mut self, epoch: Epoch, snapshot: Arc<TopologySnapshot>) {
        self.by_epoch.insert(epoch, snapshot);
    }

    /// Replace the active head committee (routing view).
    pub fn set_head(&mut self, snapshot: Arc<TopologySnapshot>) {
        self.head = snapshot;
    }

    /// Drop entries below `floor`. The owner derives `floor` from the oldest
    /// epoch any consumer can still legitimately query, so everything below
    /// is unreachable by honest artifacts.
    pub fn evict_below(&mut self, floor: Epoch) {
        self.by_epoch.retain(|epoch, _| *epoch >= floor);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashMap};

    use super::*;
    use crate::{NetworkDefinition, ValidatorSet};

    fn snapshot() -> Arc<TopologySnapshot> {
        Arc::new(TopologySnapshot::new(
            NetworkDefinition::simulator(),
            1,
            ValidatorSet::new(Vec::new()),
        ))
    }

    #[test]
    fn epoch_for_floors_to_window() {
        let sched = TopologySchedule::new(1000, Epoch::new(5), snapshot());
        assert_eq!(
            sched.epoch_for(WeightedTimestamp::from_millis(0)),
            Epoch::new(0)
        );
        assert_eq!(
            sched.epoch_for(WeightedTimestamp::from_millis(999)),
            Epoch::new(0)
        );
        assert_eq!(
            sched.epoch_for(WeightedTimestamp::from_millis(1000)),
            Epoch::new(1)
        );
        assert_eq!(
            sched.epoch_for(WeightedTimestamp::from_millis(2500)),
            Epoch::new(2)
        );
    }

    #[test]
    fn single_resolves_every_timestamp_to_the_one_committee() {
        let sched = TopologySchedule::single(snapshot());
        assert!(sched.at(WeightedTimestamp::from_millis(0)).is_some());
        assert!(
            sched
                .at(WeightedTimestamp::from_millis(1_000_000_000))
                .is_some()
        );
        // Head and `at` agree — one committee for all time.
        assert!(Arc::ptr_eq(
            sched.head(),
            sched.at(WeightedTimestamp::from_millis(42)).unwrap()
        ));
    }

    #[test]
    fn at_returns_none_for_epochs_outside_the_window() {
        // The window holds the active epoch 5 and its lookahead 6.
        let mut sched = TopologySchedule::new(1000, Epoch::new(5), snapshot());
        sched.insert(Epoch::new(6), snapshot());
        assert!(sched.at(WeightedTimestamp::from_millis(5500)).is_some());
        assert!(sched.at(WeightedTimestamp::from_millis(6500)).is_some());
        // Below the window (too old to retain) and above the lookahead (the
        // beacon hasn't committed it yet) both resolve to `None`.
        assert!(sched.at(WeightedTimestamp::from_millis(3500)).is_none());
        assert!(sched.at(WeightedTimestamp::from_millis(7500)).is_none());
    }

    #[test]
    fn lookup_distinguishes_the_two_miss_reasons() {
        let mut sched = TopologySchedule::new(1000, Epoch::new(5), snapshot());
        sched.insert(Epoch::new(6), snapshot());
        assert!(matches!(
            sched.lookup(WeightedTimestamp::from_millis(5500)),
            ScheduleLookup::Committee(_)
        ));
        assert!(matches!(
            sched.lookup(WeightedTimestamp::from_millis(7500)),
            ScheduleLookup::NotYetCommitted
        ));
        assert!(matches!(
            sched.lookup(WeightedTimestamp::from_millis(3500)),
            ScheduleLookup::Evicted
        ));
    }

    #[test]
    fn evict_below_drops_only_epochs_below_the_floor() {
        let mut sched = TopologySchedule::new(1000, Epoch::new(4), snapshot());
        sched.insert(Epoch::new(5), snapshot());
        sched.insert(Epoch::new(6), snapshot());
        sched.evict_below(Epoch::new(5));
        assert!(sched.at(WeightedTimestamp::from_millis(4500)).is_none());
        assert!(sched.at(WeightedTimestamp::from_millis(5500)).is_some());
        assert!(sched.at(WeightedTimestamp::from_millis(6500)).is_some());
        // A floor below every retained entry evicts nothing.
        sched.evict_below(Epoch::new(0));
        assert!(sched.at(WeightedTimestamp::from_millis(5500)).is_some());
    }

    #[test]
    fn split_at_next_boundary_fires_only_in_the_final_window() {
        let p = ShardId::leaf(1, 0);
        let sibling = ShardId::leaf(1, 1);
        let (left, right) = p.children();
        let snap_with = |leaves: &[ShardId], pending: &[ShardId]| -> Arc<TopologySnapshot> {
            Arc::new(TopologySnapshot::from_explicit_committees(
                NetworkDefinition::simulator(),
                &ValidatorSet::new(Vec::new()),
                leaves.iter().map(|s| (*s, Vec::new())).collect(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                pending.iter().copied().collect(),
            ))
        };
        // Windows 5 and 6 carry the parent with p's split admitted; the
        // fold starting window 6 executed the split, so window 7's
        // lookahead carries the children.
        let mut sched = TopologySchedule::new(1000, Epoch::new(5), snap_with(&[p, sibling], &[p]));
        sched.insert(Epoch::new(6), snap_with(&[p, sibling], &[p]));
        sched.insert(Epoch::new(7), snap_with(&[left, right, sibling], &[]));

        // Window 5: the next window still carries p — not the final epoch.
        assert_eq!(
            sched.split_at_next_boundary(p, WeightedTimestamp::from_millis(5500)),
            SplitAtBoundary::No
        );
        // Window 6 is the final epoch: the children land at the next boundary.
        assert_eq!(
            sched.split_at_next_boundary(p, WeightedTimestamp::from_millis(6500)),
            SplitAtBoundary::Children(left, right)
        );
        // The sibling keeps its leaf across the same boundary.
        assert_eq!(
            sched.split_at_next_boundary(sibling, WeightedTimestamp::from_millis(6500)),
            SplitAtBoundary::No
        );
        // Window 7: p no longer exists — definitive without window 8.
        assert_eq!(
            sched.split_at_next_boundary(p, WeightedTimestamp::from_millis(7500)),
            SplitAtBoundary::No
        );
    }

    #[test]
    fn split_at_next_boundary_defers_only_pending_shards_without_the_next_window() {
        let p = ShardId::leaf(1, 0);
        let sibling = ShardId::leaf(1, 1);
        let snap_with = |leaves: &[ShardId], pending: &[ShardId]| -> Arc<TopologySnapshot> {
            Arc::new(TopologySnapshot::from_explicit_committees(
                NetworkDefinition::simulator(),
                &ValidatorSet::new(Vec::new()),
                leaves.iter().map(|s| (*s, Vec::new())).collect(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                pending.iter().copied().collect(),
            ))
        };
        // Window 6 is the newest committed entry; whether p's pending
        // split executes at the fold starting window 6 is locally
        // unknown until that fold's entry for window 7 arrives.
        let sched = TopologySchedule::new(1000, Epoch::new(6), snap_with(&[p, sibling], &[p]));

        assert_eq!(
            sched.split_at_next_boundary(p, WeightedTimestamp::from_millis(6500)),
            SplitAtBoundary::Unresolved
        );
        // No admitted split — definitive: a plain epoch crossing never
        // waits on the local beacon.
        assert_eq!(
            sched.split_at_next_boundary(sibling, WeightedTimestamp::from_millis(6500)),
            SplitAtBoundary::No
        );
    }

    #[test]
    fn at_for_shard_clamps_past_the_terminal_window() {
        let p = ShardId::leaf(1, 0);
        let sibling = ShardId::leaf(1, 1);
        let (left, right) = p.children();
        let snap_with = |leaves: &[ShardId]| -> Arc<TopologySnapshot> {
            Arc::new(TopologySnapshot::from_explicit_committees(
                NetworkDefinition::simulator(),
                &ValidatorSet::new(Vec::new()),
                leaves.iter().map(|s| (*s, Vec::new())).collect(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                BTreeSet::new(),
            ))
        };
        // p's final window is 6; window 7 carries its children.
        let mut sched = TopologySchedule::new(1000, Epoch::new(6), snap_with(&[p, sibling]));
        sched.insert(Epoch::new(7), snap_with(&[left, right, sibling]));

        // Alive in its window: plain `at` plus `false`.
        let (in_window, past) = sched
            .at_for_shard(p, WeightedTimestamp::from_millis(6500))
            .unwrap();
        assert!(!past);
        assert!(Arc::ptr_eq(
            in_window,
            sched.at(WeightedTimestamp::from_millis(6500)).unwrap()
        ));

        // Past the cut: clamps to the terminal window's snapshot and flags it.
        let (clamped, past) = sched
            .at_for_shard(p, WeightedTimestamp::from_millis(7500))
            .unwrap();
        assert!(past);
        assert!(Arc::ptr_eq(
            clamped,
            sched.at(WeightedTimestamp::from_millis(6500)).unwrap()
        ));

        // A shard alive in the same window is untouched by the clamp.
        let (alive, past) = sched
            .at_for_shard(sibling, WeightedTimestamp::from_millis(7500))
            .unwrap();
        assert!(!past);
        assert!(Arc::ptr_eq(
            alive,
            sched.at(WeightedTimestamp::from_millis(7500)).unwrap()
        ));

        // Outside the retained window resolution still stalls.
        assert!(
            sched
                .at_for_shard(p, WeightedTimestamp::from_millis(9500))
                .is_none()
        );
    }
}
