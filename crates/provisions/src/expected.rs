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
//!    held and not asked, once every part of the batch that taught it is
//!    held.
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
    BlockHeight, CommittedClock, Provision, ProvisionCount, ShardId, ValidatorId, WeightedTimestamp,
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
    /// The distinct count witnesses that arrived before the header they
    /// are checked against was commit-proven, held for that check in
    /// arrival order, at most [`MAX_PARKED_COUNTS`].
    parked_counts: Vec<ProvisionCount>,
}

/// How many distinct count witnesses one expectation holds for its
/// header.
///
/// Nothing can tell a true witness from a false one before the header
/// commits, so none displaces another. Each arrives in an answer to this
/// node's own ask, and before the header commits only the index-0 ask
/// and its retries are out, each to a peer the fetch rotates to: the
/// first few distinct answers hold an honest one unless every one of
/// them lies. One past the bound is dropped: until a part teaches the
/// count, the ask is retried, and a retry answered after the header
/// commits is checked at once.
const MAX_PARKED_COUNTS: usize = 4;

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

/// What holding a batch of leaves did to their expectations.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Held {
    /// The expectations that completed: what each asked for, let go of.
    pub(crate) completed: Vec<Released>,
    /// For each expectation whose count the batch taught while it was
    /// requested, the indices to ask for now: neither held, by this batch
    /// or before it, nor asked.
    pub(crate) asks: Vec<TimeoutEffect>,
}

/// One part's leaf, counted as held toward its expectation.
#[derive(Debug, Clone, Copy)]
pub struct HeldLeaf {
    pub(crate) source_shard: ShardId,
    pub(crate) block_height: BlockHeight,
    pub(crate) index: u32,
    pub(crate) count: u32,
}

impl HeldLeaf {
    /// The leaf `part` places its transaction at.
    pub(crate) fn of(part: &Provision) -> Self {
        Self {
            source_shard: part.source_shard(),
            block_height: part.block_height(),
            index: part.leaf().index,
            count: part.leaf().count,
        }
    }
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
                parked_counts: Vec::new(),
            });
    }

    /// Record each of `leaves` as held: leaf `index` of `count` under the
    /// root `(source_shard, block_height)` owes this shard, off a part
    /// that has walked its path to the header's root. Every leaf is held
    /// before any expectation completes or asks, so a count one leaf
    /// teaches asks for none of the batch's others.
    pub(crate) fn on_parts_held(&mut self, leaves: impl IntoIterator<Item = HeldLeaf>) -> Held {
        let mut learned = BTreeSet::new();
        let mut touched = BTreeSet::new();
        for HeldLeaf {
            source_shard,
            block_height,
            index,
            count,
        } in leaves
        {
            let key = (source_shard, block_height);
            let Some(expected) = self.expected.get_mut(&key) else {
                continue;
            };
            if expected.learn(count) {
                learned.insert(key);
            }
            if index < count {
                expected.held.insert(index);
            }
            touched.insert(key);
        }
        let mut held = Held::default();
        for key in touched {
            let Some(expected) = self.expected.get_mut(&key) else {
                continue;
            };
            if expected.is_complete() {
                held.completed.push(Released {
                    source_shard: key.0,
                    block_height: key.1,
                    indices: expected.asked.iter().copied().collect(),
                });
                self.expected.remove(&key);
            } else if let Some(ask) = Self::ask_on_learning(key, expected, learned.contains(&key)) {
                held.asks.push(ask);
            }
        }
        held
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
    /// any, each distinct one beside those before it, up to
    /// [`MAX_PARKED_COUNTS`].
    pub(crate) fn park_count(
        &mut self,
        source_shard: ShardId,
        block_height: BlockHeight,
        count: ProvisionCount,
    ) {
        if let Some(expected) = self.expected.get_mut(&(source_shard, block_height))
            && expected.count.is_none()
            && expected.parked_counts.len() < MAX_PARKED_COUNTS
            && !expected.parked_counts.contains(&count)
        {
            expected.parked_counts.push(count);
        }
    }

    /// The count witnesses parked for `(source_shard, block_height)`, in
    /// arrival order, taken.
    pub(crate) fn take_parked_counts(
        &mut self,
        source_shard: ShardId,
        block_height: BlockHeight,
    ) -> Vec<ProvisionCount> {
        self.expected
            .get_mut(&(source_shard, block_height))
            .map_or_default(|expected| std::mem::take(&mut expected.parked_counts))
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

    /// Leaf `index` of `count` under the expected root.
    const fn leaf(index: u32, count: u32) -> HeldLeaf {
        HeldLeaf {
            source_shard: SOURCE,
            block_height: HEIGHT,
            index,
            count,
        }
    }

    /// Hold leaf `index` of `count` alone.
    fn hold(t: &mut ExpectedProvisionTracker, index: u32, count: u32) -> Held {
        t.on_parts_held([leaf(index, count)])
    }

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
        assert_eq!(hold(&mut t, 2, 3), Held::default());
        assert_eq!(hold(&mut t, 2, 3), Held::default(), "a repeat adds nothing");
        assert_eq!(hold(&mut t, 0, 3), Held::default());
        assert_eq!(t.len(), 1);
        let held = hold(&mut t, 1, 3);
        assert_eq!(
            held.completed,
            vec![Released {
                source_shard: SOURCE,
                block_height: HEIGHT,
                indices: Vec::new(),
            }]
        );
        assert_eq!(t.len(), 0);
        assert_eq!(hold(&mut t, 1, 3), Held::default());
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
        let held = hold(&mut t, 3, 5);
        assert_eq!(held.asks, vec![ask(&[1, 2, 4])]);
        assert!(held.completed.is_empty());

        // Another learning teaches nothing new and asks nothing.
        assert_eq!(t.on_count_checked(SOURCE, HEIGHT, 5), None);
        assert_eq!(hold(&mut t, 1, 5), Held::default());

        // Completion lets go of every index it ever asked for.
        for index in [0, 2] {
            assert_eq!(hold(&mut t, index, 5), Held::default());
        }
        let done = hold(&mut t, 4, 5);
        assert_eq!(
            done.completed
                .into_iter()
                .map(|released| released.indices)
                .collect::<Vec<_>>(),
            vec![vec![0, 1, 2, 4]]
        );
    }

    /// A batch that teaches the count asks for none of its own leaves:
    /// every one is held before the ask is drawn, and a batch holding
    /// every leaf completes without asking at all.
    #[test]
    fn a_batch_teaching_the_count_asks_for_none_of_its_own() {
        let mut t = one_expected();
        assert_eq!(t.flush_all(), vec![ask(&[0])]);
        let held = t.on_parts_held([leaf(3, 5), leaf(1, 5)]);
        assert_eq!(held.asks, vec![ask(&[2, 4])]);

        let mut t = one_expected();
        assert_eq!(t.flush_all(), vec![ask(&[0])]);
        let held = t.on_parts_held((0..3).map(|index| leaf(index, 3)));
        assert!(held.asks.is_empty());
        assert_eq!(held.completed.len(), 1);
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
        assert_eq!(hold(&mut t, 2, 4), Held::default());
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
        assert!(!hold(&mut t, 0, 1).completed.is_empty());

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
        let _ = hold(&mut t, 1, 2);

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

    /// Witnesses parked before their header wait on the entry, each
    /// distinct one beside those before it up to the bound, and none is
    /// kept once the count is known.
    #[test]
    fn a_parked_count_waits_for_its_header() {
        let mut t = one_expected();
        let witness = |count| ProvisionCount {
            count,
            merkle_root: Hash::ZERO,
        };
        for count in [2, 3, 2, 4, 5, 6, 7] {
            t.park_count(SOURCE, HEIGHT, witness(count));
        }
        assert_eq!(
            t.take_parked_counts(SOURCE, HEIGHT),
            [2, 3, 4, 5].map(witness),
            "first come, each once, to the bound"
        );
        assert!(t.take_parked_counts(SOURCE, HEIGHT).is_empty());
        let _ = t.on_count_checked(SOURCE, HEIGHT, 3);
        t.park_count(SOURCE, HEIGHT, witness(3));
        assert!(t.take_parked_counts(SOURCE, HEIGHT).is_empty());
    }
}
