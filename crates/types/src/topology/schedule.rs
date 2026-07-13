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

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::{
    Epoch, EpochWindows, ReshapeThresholds, ShardId, TopologySnapshot, ValidatorId,
    WeightedTimestamp,
};

/// Per-shard committees for request **routing**, terminal-clamped.
///
/// See [`TopologySchedule::routing_committees`]. Keyed by shard so a fetch
/// resolves the peers of any shard the schedule still retains, including a
/// split parent draining out of the head.
pub type RoutingCommittees = BTreeMap<ShardId, Vec<ValidatorId>>;

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

/// A reshape-boundary quiesce window for a shard in its final epoch.
///
/// `cut_wt` is the weighted timestamp at which the shard terminates — a
/// split or a merge — at the end of the current epoch window; `now_wt` is
/// the proposer's current chain anchor. A proposer stops selecting a
/// transaction once `now_wt + margin` reaches `cut_wt` — cross-shard work
/// needs a wider margin (a full 2PC round) than single-shard, so a
/// transaction selected before the cut can still settle on every shard by
/// the terminal block. Pure proposer policy: a non-compliant proposer's
/// late transactions simply land in the counterpart abort backstop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuiesceCut {
    /// The proposer's current chain anchor.
    pub now_wt: WeightedTimestamp,
    /// The weighted timestamp at which the shard splits.
    pub cut_wt: WeightedTimestamp,
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

    /// Substate-count thresholds for automatic shard reshaping, read off the
    /// head snapshot's [`params`](TopologySnapshot::params).
    ///
    /// A coarse "is reshaping enabled" head value for proposer-local
    /// heuristics — not the consensus predicate input. The reshape trigger
    /// a block commits is recomputed against the thresholds on the block's
    /// own weighted-time-resolved snapshot ([`at`](Self::at) /
    /// [`at_for_shard`](Self::at_for_shard)), so a governance change
    /// resolves identically on every member regardless of fold skew.
    #[must_use]
    pub fn reshape_thresholds(&self) -> ReshapeThresholds {
        self.head.reshape_thresholds()
    }

    /// The chain's epoch window length in milliseconds — the constant the
    /// schedule's epoch resolution divides by, sourced from the folded
    /// `BeaconState`'s chain config. Zero for [`Self::single`], where no
    /// epoch boundaries exist.
    #[must_use]
    pub const fn epoch_duration_ms(&self) -> u64 {
        self.epoch_duration_ms
    }

    /// The schedule's epoch-window grid — for callers that need
    /// [`window_of`](EpochWindows::window_of) or the crossing predicates, not
    /// just the [`epoch_for`](Self::epoch_for) lookup the schedule itself uses.
    #[must_use]
    pub const fn windows(&self) -> EpochWindows {
        EpochWindows::new(self.epoch_duration_ms)
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
        self.windows().epoch_for(wt)
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

    /// Whether `shard`'s reshape successor(s) are live in the committed head —
    /// the make-before-break cutover a terminating committee reads off its own
    /// beacon fold. Keys on the live head, not a weighted-time window, because
    /// it gates a runtime handoff (dissolve when the successors have taken over)
    /// rather than verifying an artifact against its window's committee.
    #[must_use]
    pub fn successors_live(&self, shard: ShardId) -> bool {
        self.head.successors_live(shard)
    }

    /// Per-shard committees for request **routing**, terminal-clamped.
    ///
    /// Every shard appearing in any retained window maps to the committee
    /// of the most recent window that carried it. A live shard resolves its
    /// head committee; a shard that has dissolved from the head — a split
    /// parent draining out — resolves its final committee, so fetches still
    /// reach the draining members that serve through the retention window.
    /// A drained shard drops from the map only when
    /// [`evict_below`](Self::evict_below) trims its last window, which the
    /// owner derives from the same drain horizon.
    #[must_use]
    pub fn routing_committees(&self) -> RoutingCommittees {
        let mut committees = RoutingCommittees::new();
        // Newest window first so the first committee seen for each shard —
        // its most recent — wins.
        for snapshot in self.by_epoch.values().rev() {
            for shard in snapshot.shard_trie().leaves() {
                committees
                    .entry(shard)
                    .or_insert_with(|| snapshot.committee_for_shard(shard).to_vec());
            }
        }
        // A recovering shard's routing entry unions the committee its halt
        // recovery replaced: the fresh members hold no chain state until
        // they finish syncing, and the replaced members hold the halted
        // tip — fetches must reach both, and the replaced members' hosts
        // must keep serving, until the shard commits again and the beacon
        // drops the retention.
        for (shard, recovery) in self.head.pending_recoveries() {
            let entry = committees.entry(*shard).or_default();
            for id in &recovery.retained {
                if !entry.contains(id) {
                    entry.push(*id);
                }
            }
        }
        committees
    }

    /// Every shard appearing in any retained window — the key set of
    /// [`routing_committees`](Self::routing_committees) without building the
    /// committees. Includes a drained reshape shard (a split parent draining
    /// out, a merge child) whose final window the schedule still retains, so a
    /// consumer that syncs from this set keeps following a departing shard's
    /// terminal crossing until [`evict_below`](Self::evict_below) trims its
    /// last window.
    #[must_use]
    pub fn routable_shards(&self) -> BTreeSet<ShardId> {
        self.by_epoch
            .values()
            .flat_map(|snapshot| snapshot.shard_trie().leaves())
            .collect()
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

    /// The first epoch whose committee bridges `shard`'s halt gap — the
    /// window after the head's pending recovery seated the fresh
    /// committee — or `None` when no recovery is in flight.
    ///
    /// A halted chain's tip anchor is many windows stale, and the anchor's
    /// window resolves the committee that halted. While a recovery is
    /// pending, work anchored below this epoch binds to the fresh
    /// committee instead (the recovery bridge); the record clears on the
    /// shard's first crossing under the fresh committee, after which
    /// anchors are current and resolution is ordinary again.
    #[must_use]
    pub fn recovery_bridge(&self, shard: ShardId) -> Option<Epoch> {
        self.head
            .pending_recoveries()
            .get(&shard)
            .map(|recovery| recovery.rotated_at.next())
    }

    /// The committee of the newest retained window that carries `shard` —
    /// for a live shard, the lookahead entry. What the recovery bridge
    /// resolves: the fresh committee is finalized into the lookahead at
    /// the fold that seats it, so every replica that has folded the
    /// recovery resolves the same snapshot.
    fn newest_for_shard(&self, shard: ShardId) -> ScheduleLookup<'_> {
        self.by_epoch
            .values()
            .rev()
            .find(|s| s.shard_trie().contains(shard))
            .map_or(ScheduleLookup::Evicted, ScheduleLookup::Committee)
    }

    /// [`lookup_for_shard`](Self::lookup_for_shard) for **live** consensus
    /// work — proposals, votes, and the tip committee. A recovering
    /// shard's stale anchor resolves the fresh committee via the recovery
    /// bridge (see [`recovery_bridge`](Self::recovery_bridge)); the old
    /// committee resolves itself out of authority at the same fold, which
    /// is what stops a halted cohort from certifying a competing chain
    /// once the recovery lands. Never used to verify certified history —
    /// the halted suffix still verifies against its own windows via
    /// [`lookup_for_shard_certified`](Self::lookup_for_shard_certified).
    #[must_use]
    pub fn lookup_for_shard_live(
        &self,
        shard: ShardId,
        wt: WeightedTimestamp,
    ) -> (ScheduleLookup<'_>, bool) {
        if let Some(bridge) = self.recovery_bridge(shard)
            && self.epoch_for(wt) < bridge
        {
            return (self.newest_for_shard(shard), false);
        }
        self.lookup_for_shard(shard, wt)
    }

    /// [`at_for_shard`](Self::at_for_shard) with the recovery bridge of
    /// [`lookup_for_shard_live`](Self::lookup_for_shard_live).
    #[must_use]
    pub fn at_for_shard_live(
        &self,
        shard: ShardId,
        wt: WeightedTimestamp,
    ) -> Option<(&Arc<TopologySnapshot>, bool)> {
        match self.lookup_for_shard_live(shard, wt) {
            (ScheduleLookup::Committee(snapshot), past_terminal) => Some((snapshot, past_terminal)),
            _ => None,
        }
    }

    /// [`lookup_for_shard`](Self::lookup_for_shard) for a **certified**
    /// artifact — a block or header carrying its own QC. A recovery
    /// bridge block is anchored below the bridge epoch but certified at
    /// or after it, and resolves the fresh committee; the halted suffix —
    /// certified while the old committee still governed, so its QC
    /// timestamps sit a full halt gap below the bridge — resolves by its
    /// anchor as ever. The QC bound tolerates one window below the
    /// bridge: the seating-window quiesce gates each vote by its voter's
    /// own clock, but a skewed or adversarial minority stamp can drag the
    /// aggregated QC timestamp marginally under the window it opened in,
    /// and the halt gap keeps the tolerance unambiguous. A replica that
    /// has not yet folded the recovery resolves a bridge block's anchor
    /// window instead and drops it as unverifiable; its fetch retries
    /// succeed once its beacon catches up, the same self-healing as any
    /// beacon lag.
    #[must_use]
    pub fn lookup_for_shard_certified(
        &self,
        shard: ShardId,
        anchor_wt: WeightedTimestamp,
        qc_wt: WeightedTimestamp,
    ) -> (ScheduleLookup<'_>, bool) {
        if let Some(bridge) = self.recovery_bridge(shard)
            && self.epoch_for(anchor_wt) < bridge
            && self.epoch_for(qc_wt).next() >= bridge
        {
            return (self.newest_for_shard(shard), false);
        }
        self.lookup_for_shard(shard, anchor_wt)
    }

    /// [`at_for_shard`](Self::at_for_shard) with the recovery bridge of
    /// [`lookup_for_shard_certified`](Self::lookup_for_shard_certified).
    #[must_use]
    pub fn at_for_shard_certified(
        &self,
        shard: ShardId,
        anchor_wt: WeightedTimestamp,
        qc_wt: WeightedTimestamp,
    ) -> Option<(&Arc<TopologySnapshot>, bool)> {
        match self.lookup_for_shard_certified(shard, anchor_wt, qc_wt) {
            (ScheduleLookup::Committee(snapshot), past_terminal) => Some((snapshot, past_terminal)),
            _ => None,
        }
    }

    /// The weighted timestamp at which `shard` terminated — the end of the
    /// newest retained window that still carried it — or `None` when the
    /// shard is live in the head or absent from every retained window.
    ///
    /// A terminated split parent leaves the head trie but lingers in recent
    /// windows until its drain horizon; this returns its terminal cut,
    /// which bounds the split-boundary fence's retention cutoff and the
    /// settled-waves acquisition's self-expiry.
    #[must_use]
    pub fn terminal_cut_wt(&self, shard: ShardId) -> Option<WeightedTimestamp> {
        if self.head.shard_trie().contains(shard) {
            return None;
        }
        let windows = self.windows();
        self.by_epoch
            .iter()
            .rev()
            .find(|(_, snapshot)| snapshot.shard_trie().contains(shard))
            .map(|(epoch, _)| windows.window_of(*epoch).end)
    }

    /// The epoch window a *parent-anchor* timestamp resolves: an anchor
    /// exactly on a window boundary belongs to the closing window,
    /// mirroring [`EpochWindows::is_crossing`]'s parent-inclusive cut
    /// (`parent ≤ cut < qc`). A block anchored exactly at the cut is a
    /// valid crossing of that cut, so the reshape verdicts stamped on it
    /// (and the committee that signs it) must read the closing window —
    /// the half-open `epoch_for` would resolve the window the shard has
    /// already left.
    fn anchor_epoch_for(&self, wt: WeightedTimestamp) -> Epoch {
        let epoch = self.epoch_for(wt);
        if epoch > Epoch::GENESIS && self.windows().window_of(epoch).start == wt {
            Epoch::new(epoch.inner() - 1)
        } else {
            epoch
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
        let epoch = self.anchor_epoch_for(wt);
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

    /// Whether `shard` leaves the trie at the end of `wt`'s epoch window —
    /// terminating into either its two children (a split) or its parent (a
    /// merge). `Some(true)` when the next window drops it, `Some(false)`
    /// when it persists, `None` when the next window hasn't committed
    /// locally and an admitted reshape leaves the outcome genuinely unknown
    /// (defer and retry once the local beacon catches up).
    ///
    /// Generalizes [`split_at_next_boundary`](Self::split_at_next_boundary)
    /// from its split-only `Children` answer to any terminating reshape:
    /// the terminal-coast boundary header of a split parent *or* a merge
    /// child carries the `settled_waves_root`, so its carry predicate keys
    /// on this. A [`single`](Self::single) schedule has no epoch
    /// boundaries, so nothing terminates at one.
    #[must_use]
    pub fn terminates_at_next_boundary(
        &self,
        shard: ShardId,
        wt: WeightedTimestamp,
    ) -> Option<bool> {
        if self.epoch_duration_ms == 0 {
            return Some(false);
        }
        let epoch = self.anchor_epoch_for(wt);
        let current = self.by_epoch.get(&epoch)?;
        if !current.shard_trie().contains(shard) {
            return Some(false);
        }
        match self.by_epoch.get(&epoch.next()) {
            Some(next) => Some(!next.shard_trie().contains(shard)),
            None if current.split_pending(shard) || current.merge_pending(shard) => None,
            None => Some(false),
        }
    }

    /// Whether `shard` is scheduled to terminate — leave the trie via a split
    /// or merge — at or after `wt`, as far as the schedule can see.
    ///
    /// Covers the whole terminating lifecycle: an admitted-but-unexecuted
    /// reshape shows in the active window's [`split_pending`] /
    /// [`merge_pending`] one epoch after admission, and in the lookahead
    /// window immediately (its projection is frozen from the live pending
    /// reshapes), so both are consulted; once the reshape executes the record
    /// clears but the shard coasts to its terminal block with its successors
    /// already in the lookahead, which [`terminates_at_next_boundary`] reads.
    /// A shard with no reshape returns `false` in every window, so a plain
    /// epoch crossing never trips this.
    ///
    /// Deterministic in `(schedule, wt)`, so the vote fence and the finalize
    /// gate agree. Used to fence a straddler naming a shard whose settled set
    /// cannot exist yet because it has not terminated.
    ///
    /// [`split_pending`]: TopologySnapshot::split_pending
    /// [`merge_pending`]: TopologySnapshot::merge_pending
    /// [`terminates_at_next_boundary`]: Self::terminates_at_next_boundary
    #[must_use]
    pub fn termination_scheduled(&self, shard: ShardId, wt: WeightedTimestamp) -> bool {
        let epoch = self.epoch_for(wt);
        let pending = [epoch, epoch.next()].iter().any(|e| {
            self.by_epoch
                .get(e)
                .is_some_and(|s| s.split_pending(shard) || s.merge_pending(shard))
        });
        pending || self.terminates_at_next_boundary(shard, wt) == Some(true)
    }

    /// The floor of `shard`'s attested settled-waves window at `wt`: the
    /// start of the epoch its terminating reshape was admitted, backed off
    /// by [`RETENTION_HORIZON`] to cover a wave that finalized against the
    /// fence just after it armed but executed up to a full wave lifetime
    /// earlier. Counterpart fences hold straddlers from admission, so the
    /// window a terminal's `settled_waves_root` commits must reach back to
    /// it — a fixed span behind the terminal misses settlements the fence
    /// is still holding against.
    ///
    /// Reads the floor off `wt`'s window or its lookahead (the same
    /// entries [`termination_scheduled`] consults, so any wave the fence
    /// can hold has a floor at or before its settlement). `None` when
    /// neither retained window records a floor for `shard` — callers then
    /// floor on the block anchor alone. Deterministic in `(schedule,
    /// wt)`: the proposer committing a coast block's root, every verifier
    /// recomputing it, and a former member serving the window list all
    /// derive the same floor.
    ///
    /// [`termination_scheduled`]: Self::termination_scheduled
    #[must_use]
    pub fn settled_window_floor(
        &self,
        shard: ShardId,
        wt: WeightedTimestamp,
    ) -> Option<WeightedTimestamp> {
        if self.epoch_duration_ms == 0 {
            return None;
        }
        let epoch = self.epoch_for(wt);
        [epoch, epoch.next()].iter().find_map(|e| {
            self.by_epoch
                .get(e)
                .and_then(|s| s.settled_window_floor(shard))
        })
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
    use crate::{HaltRecovery, NetworkDefinition, ValidatorSet};

    fn snapshot() -> Arc<TopologySnapshot> {
        Arc::new(TopologySnapshot::new(
            NetworkDefinition::simulator(),
            1,
            ValidatorSet::new(Vec::new()),
        ))
    }

    #[test]
    fn settled_window_floor_reads_the_window_and_its_lookahead() {
        use std::collections::BTreeMap;

        let floor = WeightedTimestamp::from_millis(4_000);
        let terminating = Arc::new(
            TopologySnapshot::new(
                NetworkDefinition::simulator(),
                1,
                ValidatorSet::new(Vec::new()),
            )
            .with_settled_window_floors(BTreeMap::from([(ShardId::ROOT, floor)])),
        );
        let mut sched = TopologySchedule::new(1000, Epoch::new(3), snapshot());
        sched.insert(Epoch::new(5), terminating);

        // The floor answers from the governing window and from the epoch
        // before it (the lookahead consult), and nowhere else.
        assert_eq!(
            sched.settled_window_floor(ShardId::ROOT, WeightedTimestamp::from_millis(5_500)),
            Some(floor),
        );
        assert_eq!(
            sched.settled_window_floor(ShardId::ROOT, WeightedTimestamp::from_millis(4_500)),
            Some(floor),
        );
        assert_eq!(
            sched.settled_window_floor(ShardId::ROOT, WeightedTimestamp::from_millis(3_500)),
            None,
        );
        assert_eq!(
            sched.settled_window_floor(ShardId::leaf(1, 1), WeightedTimestamp::from_millis(5_500)),
            None,
        );

        // A single-committee schedule has no epoch boundaries to floor at.
        assert_eq!(
            TopologySchedule::single(snapshot())
                .settled_window_floor(ShardId::ROOT, WeightedTimestamp::from_millis(5_500)),
            None,
        );
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
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeMap::new(),
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

    /// A parent anchor exactly on a window boundary belongs to the
    /// closing window — the crossing predicate is parent-inclusive at
    /// the cut, so a terminal crossing anchored exactly on its cut is
    /// still the splitting shard's final-epoch block and must carry the
    /// split verdicts. The half-open `epoch_for` resolution would read
    /// the post-split window (which no longer carries the parent) and
    /// strip the child roots from the one crossing that can seed them.
    #[test]
    fn boundary_instant_anchor_resolves_the_closing_window() {
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
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeMap::new(),
                pending.iter().copied().collect(),
            ))
        };
        let mut sched = TopologySchedule::new(1000, Epoch::new(5), snap_with(&[p, sibling], &[p]));
        sched.insert(Epoch::new(6), snap_with(&[p, sibling], &[p]));
        sched.insert(Epoch::new(7), snap_with(&[left, right, sibling], &[]));

        // Anchored exactly on the terminal cut (window 6's end): still
        // the final-epoch crossing — the children ride it.
        assert_eq!(
            sched.split_at_next_boundary(p, WeightedTimestamp::from_millis(7000)),
            SplitAtBoundary::Children(left, right)
        );
        assert_eq!(
            sched.terminates_at_next_boundary(p, WeightedTimestamp::from_millis(7000)),
            Some(true)
        );
        // Anchored exactly on the prior cut: the closing window is 5,
        // whose next window still carries p — not the final epoch.
        assert_eq!(
            sched.split_at_next_boundary(p, WeightedTimestamp::from_millis(6000)),
            SplitAtBoundary::No
        );
        assert_eq!(
            sched.terminates_at_next_boundary(p, WeightedTimestamp::from_millis(6000)),
            Some(false)
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
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeMap::new(),
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
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeMap::new(),
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

    #[test]
    fn routing_committees_retains_a_drained_parent() {
        use crate::{ValidatorInfo, generate_bls_keypair};

        let validators: Vec<ValidatorInfo> = (0..4)
            .map(|i| ValidatorInfo {
                validator_id: ValidatorId::new(i),
                public_key: generate_bls_keypair().public_key(),
            })
            .collect();
        let set = ValidatorSet::new(validators);
        // Epoch 0: ROOT is one shard (the parent that will split).
        let pre = Arc::new(TopologySnapshot::new(
            NetworkDefinition::simulator(),
            1,
            set.clone(),
        ));
        // Epoch 1 (head): ROOT split into its two children.
        let post = Arc::new(TopologySnapshot::new(
            NetworkDefinition::simulator(),
            2,
            set,
        ));
        let mut sched = TopologySchedule::new(1000, Epoch::new(0), Arc::clone(&pre));
        sched.insert(Epoch::new(1), Arc::clone(&post));
        sched.set_head(post);

        let routing = sched.routing_committees();
        // The split parent has drained from the head but is still routable,
        // carrying the committee of its final window.
        assert_eq!(
            routing.get(&ShardId::ROOT).map(Vec::len),
            Some(4),
            "the drained parent ROOT keeps its final committee for routing",
        );
        // The live children resolve their head committees.
        assert!(routing.contains_key(&ShardId::leaf(1, 0)));
        assert!(routing.contains_key(&ShardId::leaf(1, 1)));
    }

    /// A recovering shard's routing entry unions the committee its halt
    /// recovery replaced: the fresh members and the replaced members are
    /// both reachable until the shard commits again, and other shards'
    /// entries are untouched.
    #[test]
    fn routing_committees_unions_a_recovering_shards_retained_committee() {
        use crate::{ValidatorInfo, generate_bls_keypair};

        let validators: Vec<ValidatorInfo> = (0..12)
            .map(|i| ValidatorInfo {
                validator_id: ValidatorId::new(i),
                public_key: generate_bls_keypair().public_key(),
            })
            .collect();
        let set = ValidatorSet::new(validators);
        let recovering = ShardId::leaf(1, 0);
        let healthy = ShardId::leaf(1, 1);
        let fresh: Vec<ValidatorId> = (0..4).map(ValidatorId::new).collect();
        let retained: Vec<ValidatorId> = (4..8).map(ValidatorId::new).collect();
        let bystanders: Vec<ValidatorId> = (8..12).map(ValidatorId::new).collect();
        let head = Arc::new(
            TopologySnapshot::with_shard_committees(
                NetworkDefinition::simulator(),
                2,
                &set,
                [(recovering, fresh.clone()), (healthy, bystanders.clone())]
                    .into_iter()
                    .collect(),
            )
            .with_pending_recoveries(
                std::iter::once((
                    recovering,
                    HaltRecovery {
                        rotated_at: Epoch::new(2),
                        retained: retained.clone(),
                    },
                ))
                .collect(),
            ),
        );
        let sched = TopologySchedule::new(1000, Epoch::new(3), Arc::clone(&head));

        let routing = sched.routing_committees();
        let recovering_entry = routing.get(&recovering).expect("recovering shard routes");
        for id in fresh.iter().chain(&retained) {
            assert!(
                recovering_entry.contains(id),
                "{id:?} must stay routable through the recovery",
            );
        }
        assert_eq!(recovering_entry.len(), 8, "no duplicate entries");
        // The healthy shard's entry is exactly its head committee.
        assert_eq!(routing.get(&healthy), Some(&bystanders));
    }

    /// The recovery bridge: live work anchored below the bridge resolves
    /// the fresh committee (the halted one resolves itself out of
    /// authority), while certified artifacts bridge only when their QC
    /// lands at or past the bridge window — the halted suffix keeps
    /// verifying against the windows that produced it. Without a pending
    /// recovery both resolutions are the plain anchor lookup.
    #[test]
    fn recovery_bridge_splits_live_and_certified_resolution() {
        use crate::{ValidatorInfo, generate_bls_keypair};

        let validators: Vec<ValidatorInfo> = (0..8)
            .map(|i| ValidatorInfo {
                validator_id: ValidatorId::new(i),
                public_key: generate_bls_keypair().public_key(),
            })
            .collect();
        let set = ValidatorSet::new(validators);
        let shard = ShardId::leaf(1, 0);
        let old: Vec<ValidatorId> = (0..4).map(ValidatorId::new).collect();
        let fresh: Vec<ValidatorId> = (4..8).map(ValidatorId::new).collect();
        let snap = |committee: &[ValidatorId]| {
            Arc::new(TopologySnapshot::with_shard_committees(
                NetworkDefinition::simulator(),
                2,
                &set,
                std::iter::once((shard, committee.to_vec())).collect(),
            ))
        };
        // The chain halted with its tip anchored in window 2; the recovery
        // seated the fresh committee at epoch 20, so the bridge is 21.
        let old_snap = snap(&old);
        let fresh_snap = Arc::new(
            snap(&fresh).as_ref().clone().with_pending_recoveries(
                std::iter::once((
                    shard,
                    HaltRecovery {
                        rotated_at: Epoch::new(20),
                        retained: old.clone(),
                    },
                ))
                .collect(),
            ),
        );
        let mut sched = TopologySchedule::new(1000, Epoch::new(2), Arc::clone(&old_snap));
        sched.insert(Epoch::new(21), Arc::clone(&fresh_snap));
        sched.set_head(Arc::clone(&fresh_snap));

        let committee_of = |lookup: ScheduleLookup<'_>| match lookup {
            ScheduleLookup::Committee(snapshot) => snapshot.committee_for_shard(shard).to_vec(),
            _ => panic!("expected a resolved committee"),
        };
        let stale_anchor = WeightedTimestamp::from_millis(2_500);
        let suffix_qc = WeightedTimestamp::from_millis(2_900);
        let bridge_qc = WeightedTimestamp::from_millis(21_100);
        // The QC-bound tolerance: one window below the bridge still bridges.
        let edge_qc = WeightedTimestamp::from_millis(20_900);

        // Live work at the stale anchor binds to the fresh committee.
        assert_eq!(
            committee_of(sched.lookup_for_shard_live(shard, stale_anchor).0),
            fresh,
        );
        // The plain anchor lookup is untouched — historical resolution.
        assert_eq!(
            committee_of(sched.lookup_for_shard(shard, stale_anchor).0),
            old,
        );
        // A suffix block — certified while the old committee governed —
        // keeps verifying against it.
        assert_eq!(
            committee_of(
                sched
                    .lookup_for_shard_certified(shard, stale_anchor, suffix_qc)
                    .0
            ),
            old,
        );
        // A bridge block — certified at (or one skew window under) the
        // bridge — verifies against the fresh committee.
        for qc_wt in [bridge_qc, edge_qc] {
            assert_eq!(
                committee_of(
                    sched
                        .lookup_for_shard_certified(shard, stale_anchor, qc_wt)
                        .0
                ),
                fresh,
            );
        }
        // Current anchors resolve normally on both paths.
        assert_eq!(
            committee_of(sched.lookup_for_shard_live(shard, bridge_qc).0),
            fresh,
        );

        // Without the recovery record, the live path is the plain lookup.
        let mut plain = TopologySchedule::new(1000, Epoch::new(2), Arc::clone(&old_snap));
        plain.insert(Epoch::new(21), snap(&fresh));
        assert_eq!(
            committee_of(plain.lookup_for_shard_live(shard, stale_anchor).0),
            old,
        );
    }

    #[test]
    fn terminates_at_next_boundary_covers_splits_and_merges() {
        use std::collections::BTreeMap;

        let snap_with = |leaves: &[ShardId],
                         split_pending: &[ShardId],
                         merge_keeper_children: &[ShardId]|
         -> Arc<TopologySnapshot> {
            let reshape_keepers: BTreeMap<ShardId, BTreeMap<ValidatorId, ShardId>> =
                merge_keeper_children
                    .iter()
                    .map(|child| {
                        (
                            *child,
                            BTreeMap::from([(ValidatorId::new(0), ShardId::ROOT)]),
                        )
                    })
                    .collect();
            Arc::new(TopologySnapshot::from_explicit_committees(
                NetworkDefinition::simulator(),
                &ValidatorSet::new(Vec::new()),
                leaves.iter().map(|s| (*s, Vec::new())).collect(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                BTreeMap::new(),
                reshape_keepers,
                BTreeMap::new(),
                split_pending.iter().copied().collect(),
            ))
        };
        let (left, right) = ShardId::ROOT.children();

        // A split parent terminates: its window carries it, the next drops
        // it for its two children. `split_at_next_boundary` also fires.
        let mut split =
            TopologySchedule::new(1000, Epoch::new(5), snap_with(&[ShardId::ROOT], &[], &[]));
        split.insert(Epoch::new(6), snap_with(&[left, right], &[], &[]));
        let wt = WeightedTimestamp::from_millis(5500);
        assert_eq!(
            split.terminates_at_next_boundary(ShardId::ROOT, wt),
            Some(true)
        );
        assert_eq!(
            split.split_at_next_boundary(ShardId::ROOT, wt),
            SplitAtBoundary::Children(left, right)
        );

        // A merge child terminates: its window carries the two children,
        // the next drops them for their parent. `terminates` fires even
        // though `split_at_next_boundary` does not — the case the
        // split-only predicate missed.
        let mut merge =
            TopologySchedule::new(1000, Epoch::new(5), snap_with(&[left, right], &[], &[]));
        merge.insert(Epoch::new(6), snap_with(&[ShardId::ROOT], &[], &[]));
        assert_eq!(merge.terminates_at_next_boundary(left, wt), Some(true));
        assert_eq!(merge.split_at_next_boundary(left, wt), SplitAtBoundary::No);
        // The shard's counterpart in the same merge also terminates.
        assert_eq!(merge.terminates_at_next_boundary(right, wt), Some(true));

        // A shard present in both windows does not terminate.
        let mut steady =
            TopologySchedule::new(1000, Epoch::new(5), snap_with(&[left, right], &[], &[]));
        steady.insert(Epoch::new(6), snap_with(&[left, right], &[], &[]));
        assert_eq!(steady.terminates_at_next_boundary(left, wt), Some(false));

        // Next window not yet committed: an admitted merge (keepers drawn)
        // leaves the outcome unresolved, exactly as an admitted split does.
        let merge_pending = TopologySchedule::new(
            1000,
            Epoch::new(5),
            snap_with(&[left, right], &[], &[left, right]),
        );
        assert_eq!(merge_pending.terminates_at_next_boundary(left, wt), None);
        let split_pending = TopologySchedule::new(
            1000,
            Epoch::new(5),
            snap_with(&[ShardId::ROOT], &[ShardId::ROOT], &[]),
        );
        assert_eq!(
            split_pending.terminates_at_next_boundary(ShardId::ROOT, wt),
            None
        );
        // No admitted reshape and no next window: definitively no termination.
        let quiet = TopologySchedule::new(1000, Epoch::new(5), snap_with(&[left, right], &[], &[]));
        assert_eq!(quiet.terminates_at_next_boundary(left, wt), Some(false));
    }
}
