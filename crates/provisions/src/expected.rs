//! Expected-provisions tracker + fallback-fetch typed effects.
//!
//! Anchors all liveness-driven decisions on the shard consensus-authenticated
//! `weighted_timestamp` of locally committed blocks, not local wall-clock.
//!
//! An expectation is one commit-proven source block's parts for this
//! shard. It holds the leaf indices already held, the leaf count once a
//! checked part or a checked count witness teaches it, and a monotone set
//! of the indices it has asked a fetch for. It asks on exactly two edges:
//!
//! 1. **Turning requested**: an entry has been outstanding for longer than
//!    [`PROVISION_FALLBACK_TIMEOUT`] ([`Self::check_timeouts`]), or the
//!    coordinator decides urgency overrides patience ([`Self::flush_all`]).
//!    It asks for every index not held and not asked if the count is known,
//!    and otherwise for index 0, whose answer also brings the count witness.
//! 2. **Learning the count while requested**: it asks for every index not
//!    held and not asked.
//!
//! Gossip still arriving asks nothing, and every retry of an asked index
//! belongs to the fetch layer. The expectation completes when all of its
//! leaves are held, and every way it ends lets go of every index it asked
//! for, since the fetch layer keeps an id pending until it is admitted or
//! abandoned.
//!
//! The tracker also owns `local_committed_ts` because every other consumer
//! of that value reads it through here (deadline sweeps, receipt-time
//! stamping, etc.) — keeping it co-located with the timestamp-driven
//! sweeps that update it.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use hyperscale_core::{Action, FetchIds, FetchRequest};
use hyperscale_types::{
    BlockHeight, CommittedClock, ProvisionCount, ShardId, ValidatorId, WeightedTimestamp,
};
use tracing::warn;

/// How long to wait before falling back to peer-fetch for missing
/// provisions. Proposers include provisions inline in `Block::Live` during
/// assembly, so this timeout only triggers when gossip dropped them — in
/// which case we fetch from a shard peer. Measured against the shard consensus-
/// authenticated `weighted_timestamp_ms` of locally committed blocks.
const PROVISION_FALLBACK_TIMEOUT: Duration = Duration::from_secs(5);

type Key = (ShardId, BlockHeight);

/// Per-entry liveness state for a registered expected provisions value.
#[derive(Debug, Clone)]
struct ExpectedProvision {
    /// Local weighted timestamp when we first expected these provisions.
    /// Liveness baseline for the fallback-fetch timeout — how long *we've*
    /// been waiting. A catch-up jump in `local_committed_ts` can leave this
    /// far behind the source block, which only makes the fetch fire sooner.
    discovered_at: WeightedTimestamp,
    /// Authenticated weighted timestamp of the source block (its parent QC).
    /// Orphan eviction keys on this, not `discovered_at`: a freshly-arrived
    /// header whose source block is recent must survive the
    /// `RETENTION_HORIZON` sweep even when our local clock was lagging at
    /// registration (e.g. a split child still catching up).
    source_block_ts: WeightedTimestamp,
    requested: bool,
    proposer: ValidatorId,
    /// The leaf count the source header's root commits for this shard,
    /// once a checked part or a checked count witness has taught it.
    count: Option<u32>,
    /// The leaf indices held: admitted, or retired as already committed
    /// or already verified.
    held: BTreeSet<u32>,
    /// Every index a fetch was asked for. Only grows.
    asked: BTreeSet<u32>,
    /// A count witness that arrived before the header it is checked
    /// against was commit-proven, held for that check.
    parked_count: Option<ProvisionCount>,
}

impl ExpectedProvision {
    /// Learn `count`, returning whether it was not known before.
    const fn learn(&mut self, count: u32) -> bool {
        if self.count.is_some() {
            return false;
        }
        self.count = Some(count);
        true
    }

    /// Every index this entry still wants and has not asked for, marked
    /// asked: every unheld index once the count is known, and index 0
    /// before.
    fn ask_unasked(&mut self) -> Vec<u32> {
        let wanted: Vec<u32> = (0..self.count.unwrap_or(1))
            .filter(|index| !self.held.contains(index) && !self.asked.contains(index))
            .collect();
        self.asked.extend(wanted.iter().copied());
        wanted
    }

    fn is_complete(&self) -> bool {
        self.count
            .is_some_and(|count| self.held.len() >= count as usize)
    }
}

/// An ask for the indices of one expectation, lifted into an
/// `Action::Fetch` of remote provisions via [`Self::into_fetch_action`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeoutEffect {
    pub(crate) source_shard: ShardId,
    pub(crate) block_height: BlockHeight,
    pub(crate) proposer: ValidatorId,
    pub(crate) indices: Vec<u32>,
}

impl TimeoutEffect {
    /// Build the remote-provisions fetch action: the proposer is preferred,
    /// the rest of the source shard's committee is rotation fallback (picked
    /// by the network layer from the source shard's current committee).
    ///
    /// Each id names both ends — the shard the parts come from and the one
    /// they are owed to — so `for_shard` is this coordinator's own.
    pub(crate) fn into_fetch_action(self, for_shard: ShardId) -> Action {
        Action::Fetch(FetchRequest::Ask {
            ids: FetchIds::RemoteProvisions(
                self.indices
                    .into_iter()
                    .map(|index| (self.source_shard, for_shard, self.block_height, index))
                    .collect(),
            ),
            shard: self.source_shard,
            preferred: Some(self.proposer),
            class: None,
        })
    }
}

/// The indices an expectation asked for, let go of as it ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Released {
    pub(crate) source_shard: ShardId,
    pub(crate) block_height: BlockHeight,
    pub(crate) indices: Vec<u32>,
}

impl Released {
    /// The fetch ids the asks named, for `for_shard`, this coordinator's
    /// own shard.
    pub(crate) fn ids(
        &self,
        for_shard: ShardId,
    ) -> impl Iterator<Item = (ShardId, ShardId, BlockHeight, u32)> + '_ {
        self.indices
            .iter()
            .map(move |index| (self.source_shard, for_shard, self.block_height, *index))
    }
}

/// What holding one leaf did to its expectation.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Held {
    /// The expectation completed: what it asked for, let go of.
    pub(crate) completed: Option<Released>,
    /// The leaf taught the count while the entry was requested: the
    /// indices to ask for now.
    pub(crate) ask: Option<TimeoutEffect>,
}

/// Liveness tracker for cross-shard provisions we expect but haven't yet
/// verified.
pub struct ExpectedProvisionTracker {
    expected: BTreeMap<Key, ExpectedProvision>,
    /// The node's committed clock, seeded at the recovered tip, so every
    /// gate below reads a resumed chain's "now" before its next commit.
    clock: CommittedClock,
    /// Whether a block has committed through this tracker yet: the edge
    /// the pre-commit entries are retro-stamped on.
    committed_once: bool,
}

impl ExpectedProvisionTracker {
    pub(crate) const fn new(clock: CommittedClock) -> Self {
        Self {
            expected: BTreeMap::new(),
            clock,
            committed_once: false,
        }
    }

    /// The node's committed clock — the "now" reference for every
    /// liveness decision. Read by the coordinator when stamping receipts
    /// and deadline-sweeping other sub-machines.
    pub(crate) fn local_ts(&self) -> WeightedTimestamp {
        self.clock.now()
    }

    pub(crate) fn len(&self) -> usize {
        self.expected.len()
    }

    /// Register an expectation for provisions at `(source_shard, block_height)`.
    /// No-op if an expectation is already registered for the same key.
    ///
    /// `source_block_ts` is the source block's authenticated weighted
    /// timestamp (its parent QC), the age anchor for orphan eviction.
    pub(crate) fn register(
        &mut self,
        source_shard: ShardId,
        block_height: BlockHeight,
        proposer: ValidatorId,
        source_block_ts: WeightedTimestamp,
    ) {
        self.expected
            .entry((source_shard, block_height))
            .or_insert_with(|| ExpectedProvision {
                discovered_at: self.clock.now(),
                source_block_ts,
                requested: false,
                proposer,
                count: None,
                held: BTreeSet::new(),
                asked: BTreeSet::new(),
                parked_count: None,
            });
    }

    /// Record leaf `index` of `count` as held for `(source_shard,
    /// block_height)`, off a part that has walked its path to the
    /// header's root. Completes and clears the expectation once every
    /// committed leaf is held.
    pub(crate) fn on_part_held(
        &mut self,
        source_shard: ShardId,
        block_height: BlockHeight,
        index: u32,
        count: u32,
    ) -> Held {
        let key = (source_shard, block_height);
        let Some(expected) = self.expected.get_mut(&key) else {
            return Held::default();
        };
        let learned = expected.learn(count);
        if index < count {
            expected.held.insert(index);
        }
        if expected.is_complete() {
            let asked = expected.asked.iter().copied().collect();
            self.expected.remove(&key);
            return Held {
                completed: Some(Released {
                    source_shard,
                    block_height,
                    indices: asked,
                }),
                ask: None,
            };
        }
        Held {
            completed: None,
            ask: Self::ask_on_learning(key, expected, learned),
        }
    }

    /// Learn the count of `(source_shard, block_height)` off a count
    /// witness checked against the header's root, asking for the rest if
    /// the entry is requested.
    pub(crate) fn on_count_checked(
        &mut self,
        source_shard: ShardId,
        block_height: BlockHeight,
        count: u32,
    ) -> Option<TimeoutEffect> {
        let key = (source_shard, block_height);
        let expected = self.expected.get_mut(&key)?;
        let learned = expected.learn(count);
        Self::ask_on_learning(key, expected, learned)
    }

    /// The second edge: a count learned while requested asks for every
    /// index not held and not asked.
    fn ask_on_learning(
        (source_shard, block_height): Key,
        expected: &mut ExpectedProvision,
        learned: bool,
    ) -> Option<TimeoutEffect> {
        if !learned || !expected.requested {
            return None;
        }
        let indices = expected.ask_unasked();
        (!indices.is_empty()).then_some(TimeoutEffect {
            source_shard,
            block_height,
            proposer: expected.proposer,
            indices,
        })
    }

    /// Whether `(source_shard, block_height)` is expected and its count
    /// not yet known: the one case a count witness is worth checking.
    pub(crate) fn wants_count(&self, source_shard: ShardId, block_height: BlockHeight) -> bool {
        self.expected
            .get(&(source_shard, block_height))
            .is_some_and(|expected| expected.count.is_none())
    }

    /// Hold a count witness until the header it is checked against is
    /// commit-proven. Only an expectation still missing its count keeps
    /// one, and only the latest.
    pub(crate) fn park_count(
        &mut self,
        source_shard: ShardId,
        block_height: BlockHeight,
        count: ProvisionCount,
    ) {
        if let Some(expected) = self.expected.get_mut(&(source_shard, block_height))
            && expected.count.is_none()
        {
            expected.parked_count = Some(count);
        }
    }

    /// The count witness parked for `(source_shard, block_height)`, taken.
    pub(crate) fn take_parked_count(
        &mut self,
        source_shard: ShardId,
        block_height: BlockHeight,
    ) -> Option<ProvisionCount> {
        self.expected
            .get_mut(&(source_shard, block_height))?
            .parked_count
            .take()
    }

    /// Update the local committed anchor and retro-stamp pre-genesis
    /// entries so liveness decisions don't fire spuriously on the first
    /// commit.
    ///
    /// Remote headers can arrive (and register expectations) on a fresh
    /// chain while the clock still reads zero or the `genesis` instant;
    /// without retro-stamping, every such entry would report its age since
    /// then on the next commit and trigger a fallback fetch storm.
    pub(crate) fn record_block_committed(
        &mut self,
        ts: WeightedTimestamp,
        genesis: WeightedTimestamp,
    ) {
        let first_commit = !self.committed_once;
        self.committed_once = true;
        // The shard coordinator's commit has already advanced the shared
        // clock past this block; this is a no-op there, and is what moves
        // a tracker that runs without one.
        self.clock.advance(ts);

        if first_commit {
            for expected in self.expected.values_mut() {
                if expected.discovered_at <= genesis {
                    expected.discovered_at = ts;
                }
            }
        }
    }

    /// Drop expectations whose source block predates `cutoff` — past
    /// `RETENTION_HORIZON` every tx in that block has terminated, so its
    /// provisions can never be needed again. Returns what each asked for,
    /// so the coordinator can abandon it and clean the matching headers.
    ///
    /// Keyed on the source block's authenticated `source_block_ts`, not the
    /// local `discovered_at`: a node that registered while its committed
    /// clock lagged (a split child catching up) would otherwise evict a
    /// still-live expectation whose source block is recent.
    ///
    /// Under nominal operation a header is retained exactly while its
    /// provisions are outstanding; this catches entries that would
    /// otherwise leak indefinitely, an index nobody can build among them.
    pub(crate) fn cleanup_orphans(&mut self, cutoff: WeightedTimestamp) -> Vec<Released> {
        self.drop_where(|_, exp| exp.source_block_ts < cutoff)
    }

    /// Drop expectations keyed to `shard` strictly above a pending
    /// recovery's attested frontier, returning what each asked for so
    /// in-flight fallback fetches can be abandoned. Nothing can fulfil
    /// them: the source content is rejected network-wide.
    pub(crate) fn purge_fenced(&mut self, shard: ShardId, frontier: BlockHeight) -> Vec<Released> {
        self.drop_where(|&(s, h), _| s == shard && h > frontier)
    }

    fn drop_where(&mut self, drop: impl Fn(&Key, &ExpectedProvision) -> bool) -> Vec<Released> {
        let mut dropped = Vec::new();
        self.expected.retain(|key, exp| {
            if !drop(key, exp) {
                return true;
            }
            dropped.push(Released {
                source_shard: key.0,
                block_height: key.1,
                indices: exp.asked.iter().copied().collect(),
            });
            false
        });
        dropped
    }

    /// The first edge, for every timed-out expectation not yet requested:
    /// turn it requested and ask for what it wants.
    pub(crate) fn check_timeouts(&mut self, now: WeightedTimestamp) -> Vec<TimeoutEffect> {
        self.turn_requested(|expected| {
            now.elapsed_since(expected.discovered_at) >= PROVISION_FALLBACK_TIMEOUT
        })
    }

    /// The first edge for every outstanding expectation, bypassing the
    /// normal timeout. Called when urgency overrides patience — sync
    /// completion and the execution advance gate stalling on missing data.
    pub(crate) fn flush_all(&mut self) -> Vec<TimeoutEffect> {
        self.turn_requested(|_| true)
    }

    fn turn_requested(&mut self, due: impl Fn(&ExpectedProvision) -> bool) -> Vec<TimeoutEffect> {
        let now = self.clock.now();
        let mut effects = Vec::new();
        for (&(source_shard, block_height), expected) in &mut self.expected {
            if expected.requested || !due(expected) {
                continue;
            }
            warn!(
                source_shard = source_shard.inner(),
                block_height = block_height.inner(),
                age_ms = u64::try_from(now.elapsed_since(expected.discovered_at).as_millis())
                    .unwrap_or(u64::MAX),
                held = expected.held.len(),
                count = ?expected.count,
                "Requesting missing provisions via fallback"
            );
            expected.requested = true;
            let indices = expected.ask_unasked();
            if !indices.is_empty() {
                effects.push(TimeoutEffect {
                    source_shard,
                    block_height,
                    proposer: expected.proposer,
                    indices,
                });
            }
        }
        effects
    }
}

impl Default for ExpectedProvisionTracker {
    fn default() -> Self {
        Self::new(CommittedClock::default())
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{Hash, RETENTION_HORIZON};

    use super::*;

    fn ts(ms: u64) -> WeightedTimestamp {
        WeightedTimestamp::from_millis(ms)
    }

    const SOURCE: ShardId = ShardId::leaf(2, 1);
    const HEIGHT: BlockHeight = BlockHeight::new(10);

    /// A tracker with one expectation for [`SOURCE`] at [`HEIGHT`].
    fn one_expected() -> ExpectedProvisionTracker {
        let mut t = ExpectedProvisionTracker::new(CommittedClock::default());
        t.record_block_committed(ts(1_000), WeightedTimestamp::ZERO);
        t.register(SOURCE, HEIGHT, ValidatorId::new(3), ts(1_000));
        t
    }

    fn ask(indices: &[u32]) -> TimeoutEffect {
        TimeoutEffect {
            source_shard: SOURCE,
            block_height: HEIGHT,
            proposer: ValidatorId::new(3),
            indices: indices.to_vec(),
        }
    }

    #[test]
    fn fresh_tracker_is_empty() {
        let t = ExpectedProvisionTracker::new(CommittedClock::default());
        assert_eq!(t.len(), 0);
        assert_eq!(t.local_ts(), WeightedTimestamp::ZERO);
    }

    /// A block whose anchor sits below the one already committed does not
    /// move the tracker's clock backwards. The orphan cutoff and every
    /// receipt deadline are read against it, and a clock that runs
    /// backwards fires them twice.
    #[test]
    fn the_local_clock_does_not_run_backwards() {
        let mut t = ExpectedProvisionTracker::new(CommittedClock::default());
        t.record_block_committed(ts(9_000), WeightedTimestamp::ZERO);
        assert_eq!(t.local_ts(), ts(9_000));

        t.record_block_committed(ts(4_000), WeightedTimestamp::ZERO);
        assert_eq!(t.local_ts(), ts(9_000), "a regressed anchor holds it");

        t.record_block_committed(ts(11_000), WeightedTimestamp::ZERO);
        assert_eq!(t.local_ts(), ts(11_000), "and it still advances");
    }

    #[test]
    fn register_is_idempotent() {
        let mut t = one_expected();
        t.register(SOURCE, HEIGHT, ValidatorId::new(7), ts(1_000));
        assert_eq!(t.len(), 1);
    }

    /// The expectation completes on holding every committed leaf, not on
    /// the first part to verify, and a part held before any ask lets go
    /// of nothing.
    #[test]
    fn an_expectation_completes_on_holding_every_leaf() {
        let mut t = one_expected();
        assert_eq!(t.on_part_held(SOURCE, HEIGHT, 2, 3), Held::default());
        assert_eq!(
            t.on_part_held(SOURCE, HEIGHT, 2, 3),
            Held::default(),
            "a repeat adds nothing"
        );
        assert_eq!(t.on_part_held(SOURCE, HEIGHT, 0, 3), Held::default());
        assert_eq!(t.len(), 1);
        let held = t.on_part_held(SOURCE, HEIGHT, 1, 3);
        assert_eq!(
            held.completed,
            Some(Released {
                source_shard: SOURCE,
                block_height: HEIGHT,
                indices: Vec::new(),
            })
        );
        assert_eq!(t.len(), 0);
        assert_eq!(t.on_part_held(SOURCE, HEIGHT, 1, 3), Held::default());
    }

    /// Turning requested asks for index 0 alone while the count is
    /// unknown; learning it then asks for every index not held and not
    /// asked, once.
    #[test]
    fn a_requested_entry_asks_index_zero_then_the_rest_once_counted() {
        let mut t = one_expected();
        assert_eq!(t.flush_all(), vec![ask(&[0])]);
        assert!(
            t.flush_all().is_empty(),
            "a requested entry is not asked again"
        );

        // Index 3 of five arrives by gossip: the count is learned, and
        // the rest is asked, leaving out 0 (asked) and 3 (held).
        let held = t.on_part_held(SOURCE, HEIGHT, 3, 5);
        assert_eq!(held.ask, Some(ask(&[1, 2, 4])));
        assert_eq!(held.completed, None);

        // Another learning teaches nothing new and asks nothing.
        assert_eq!(t.on_count_checked(SOURCE, HEIGHT, 5), None);
        assert_eq!(t.on_part_held(SOURCE, HEIGHT, 1, 5), Held::default());

        // Completion lets go of every index it ever asked for.
        for index in [0, 2] {
            assert_eq!(t.on_part_held(SOURCE, HEIGHT, index, 5), Held::default());
        }
        let done = t.on_part_held(SOURCE, HEIGHT, 4, 5);
        assert_eq!(
            done.completed.map(|released| released.indices),
            Some(vec![0, 1, 2, 4])
        );
    }

    /// A count known before the entry turns requested asks every index
    /// not held at once.
    #[test]
    fn a_counted_entry_asks_what_it_lacks_when_it_turns_requested() {
        let mut t = one_expected();
        assert_eq!(
            t.on_count_checked(SOURCE, HEIGHT, 4),
            None,
            "not yet requested"
        );
        assert_eq!(t.on_part_held(SOURCE, HEIGHT, 2, 4), Held::default());
        assert_eq!(t.flush_all(), vec![ask(&[0, 1, 3])]);
    }

    /// A checked count witness teaches the count while index 0 itself is
    /// never held, and the asks go out for every other index.
    #[test]
    fn a_count_witness_asks_the_rest_without_index_zero() {
        let mut t = one_expected();
        assert_eq!(t.flush_all(), vec![ask(&[0])]);
        assert!(t.wants_count(SOURCE, HEIGHT));
        assert_eq!(t.on_count_checked(SOURCE, HEIGHT, 3), Some(ask(&[1, 2])));
        assert!(!t.wants_count(SOURCE, HEIGHT));
    }

    #[test]
    fn first_commit_retro_stamps_pregenesis_entries() {
        let mut t = ExpectedProvisionTracker::new(CommittedClock::default());
        t.register(SOURCE, HEIGHT, ValidatorId::new(3), ts(1_000));

        // Before any commit, an immediate timeout sweep at a non-zero `now`
        // would fire — the entry's discovered_at is still ZERO. The
        // record_block_committed retro-stamp closes that gap.
        t.record_block_committed(ts(1_000), WeightedTimestamp::ZERO);

        // Now sweep at the same instant: no firings (we just registered).
        let effects = t.check_timeouts(ts(1_000));
        assert!(effects.is_empty());
    }

    #[test]
    fn timeout_emits_effect_after_threshold() {
        let mut t = one_expected();
        let timeout = u64::try_from(PROVISION_FALLBACK_TIMEOUT.as_millis()).unwrap_or(u64::MAX);

        // Just under threshold: no firings.
        assert!(t.check_timeouts(ts(1_000 + timeout - 1)).is_empty());

        // At threshold: one ask, for index 0.
        let at = ts(1_000 + timeout);
        assert_eq!(t.check_timeouts(at), vec![ask(&[0])]);

        // Subsequent sweep doesn't re-fire (already requested).
        assert!(t.check_timeouts(at).is_empty());
    }

    #[test]
    fn verified_before_timeout_never_emits() {
        let mut t = one_expected();
        assert!(t.on_part_held(SOURCE, HEIGHT, 0, 1).completed.is_some());

        let well_past =
            ts(1_000
                + 10 * u64::try_from(PROVISION_FALLBACK_TIMEOUT.as_millis()).unwrap_or(u64::MAX));
        assert!(t.check_timeouts(well_past).is_empty());
    }

    #[test]
    fn flush_all_bypasses_timeout() {
        let mut t = one_expected();
        t.register(
            ShardId::leaf(2, 2),
            BlockHeight::new(5),
            ValidatorId::new(7),
            ts(1_000),
        );

        let effects = t.flush_all();
        assert_eq!(effects.len(), 2);

        // Subsequent flush_all is a no-op (all requested).
        assert!(t.flush_all().is_empty());
    }

    /// The orphan sweep lets go of every index the dropped entry asked
    /// for: an index nobody can build stays asked until here.
    #[test]
    fn cleanup_orphans_drops_aged_entries_and_releases_their_asks() {
        let mut t = one_expected();
        let _ = t.flush_all();
        let _ = t.on_part_held(SOURCE, HEIGHT, 1, 2);

        // Advance well past RETENTION_HORIZON.
        let far_future =
            ts(1_000 + 2 * u64::try_from(RETENTION_HORIZON.as_millis()).unwrap_or(u64::MAX));
        t.record_block_committed(far_future, WeightedTimestamp::ZERO);

        let cutoff = far_future.minus(RETENTION_HORIZON);
        let dropped = t.cleanup_orphans(cutoff);
        assert_eq!(
            dropped,
            vec![Released {
                source_shard: SOURCE,
                block_height: HEIGHT,
                indices: vec![0],
            }]
        );
        assert_eq!(t.len(), 0);
    }

    /// A node whose committed clock lagged at registration (a split child
    /// catching up) stamps a stale `discovered_at`, but the source block is
    /// recent. The orphan sweep must key on `source_block_ts` and retain it,
    /// or the fallback fetch is evicted before it can fire and the dependent
    /// cross-shard tick aborts.
    #[test]
    fn cleanup_orphans_keeps_recent_source_despite_stale_discovery() {
        let mut t = ExpectedProvisionTracker::new(CommittedClock::default());

        // Register while the local clock lags far behind the source block.
        t.record_block_committed(ts(1_000), WeightedTimestamp::ZERO);
        let recent_source =
            ts(1_000 + 2 * u64::try_from(RETENTION_HORIZON.as_millis()).unwrap_or(u64::MAX));
        t.register(SOURCE, HEIGHT, ValidatorId::new(3), recent_source);

        // Catch up: the cutoff now predates the stale `discovered_at` (1_000)
        // but not the recent source block.
        let now = ts(1_000 + 3 * u64::try_from(RETENTION_HORIZON.as_millis()).unwrap_or(u64::MAX));
        t.record_block_committed(now, WeightedTimestamp::ZERO);
        let cutoff = now.minus(RETENTION_HORIZON);
        assert!(
            cutoff > ts(1_000),
            "cutoff must postdate the stale discovered_at"
        );
        assert!(
            recent_source >= cutoff,
            "source block must postdate the cutoff"
        );

        let dropped = t.cleanup_orphans(cutoff);
        assert!(dropped.is_empty());
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn cleanup_orphans_no_op_when_cutoff_zero() {
        let mut t = ExpectedProvisionTracker::new(CommittedClock::default());
        t.register(SOURCE, HEIGHT, ValidatorId::new(3), ts(1_000));
        let dropped = t.cleanup_orphans(WeightedTimestamp::ZERO);
        assert!(dropped.is_empty());
        assert_eq!(t.len(), 1);
    }

    /// A fenced shard's expectations go, each releasing what it asked.
    #[test]
    fn purge_fenced_releases_every_asked_index() {
        let mut t = one_expected();
        let _ = t.flush_all();
        let _ = t.on_count_checked(SOURCE, HEIGHT, 3);
        let dropped = t.purge_fenced(SOURCE, BlockHeight::new(9));
        assert_eq!(
            dropped,
            vec![Released {
                source_shard: SOURCE,
                block_height: HEIGHT,
                indices: vec![0, 1, 2],
            }]
        );
        assert_eq!(t.len(), 0);
    }

    /// A witness parked before its header waits on the entry, the latest
    /// one only, and is gone once the count is known.
    #[test]
    fn a_parked_count_waits_for_its_header() {
        let mut t = one_expected();
        let witness = |count| ProvisionCount {
            count,
            merkle_root: Hash::ZERO,
        };
        t.park_count(SOURCE, HEIGHT, witness(2));
        t.park_count(SOURCE, HEIGHT, witness(3));
        assert_eq!(t.take_parked_count(SOURCE, HEIGHT), Some(witness(3)));
        assert_eq!(t.take_parked_count(SOURCE, HEIGHT), None);
        let _ = t.on_count_checked(SOURCE, HEIGHT, 3);
        t.park_count(SOURCE, HEIGHT, witness(3));
        assert_eq!(t.take_parked_count(SOURCE, HEIGHT), None);
    }
}
