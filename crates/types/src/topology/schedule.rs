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

use crate::{Epoch, TopologySnapshot, WeightedTimestamp};

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
    /// Active committee for routing / gossip ("who is in the committee now?").
    head: Arc<TopologySnapshot>,
    /// Committee snapshots keyed by the epoch each governs.
    by_epoch: BTreeMap<Epoch, Arc<TopologySnapshot>>,
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
            head,
            by_epoch,
        }
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
}
