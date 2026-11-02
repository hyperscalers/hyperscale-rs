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
    Anchor, BlockHeader, BlockHeight, CertifiedBlockHeader, Epoch, EpochWindows, PriceTable,
    RecoveryBinding, ReshapeThresholds, ShardAnchor, ShardForkProof, ShardId, ShardTrie,
    TopologySnapshot, ValidatorId, WeightedTimestamp,
};

/// A window this schedule does not hold as the fold before it first
/// published it: one older than the states a resumed schedule was built
/// from, or one evicted. Nothing as-published can be read of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unpublished;

/// Where the chain a window runs, or last ran, under a shard id began:
/// the epoch its record names as its formation, and the start of that
/// epoch's window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Formed {
    /// The epoch whose window first runs the chain.
    pub epoch: Epoch,
    /// The start of `epoch`'s window.
    pub opens: WeightedTimestamp,
}

impl Formed {
    /// Whether a row committed at `committed` predates this chain: its
    /// window falls before the chain's first, so the chain it awaited
    /// under the same id is an earlier one.
    #[must_use]
    pub fn predates(self, committed: WeightedTimestamp) -> bool {
        committed < self.opens
    }
}

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
/// A window is written twice: the fold of `N` publishes its projection of
/// `N+1`, and the fold of `N+1` replaces it with the frozen window. A
/// question about the window ahead — whether a shard is leaving, where a
/// settled window floors — must not move between those two writes, or a
/// replica replaying a block classifies it against a different future
/// than the replicas that committed it did. So the projection is also
/// kept as it was first written, in [`lookahead`](Self::lookahead), and
/// every forward question reads that copy.
///
/// A schedule built with [`single`](Self::single) carries one committee for
/// all time (a zero window length folds every timestamp to genesis) — the
/// pre-rotation / single-epoch case used by tests and within-epoch callers.
#[derive(Clone, Debug)]
pub struct TopologySchedule {
    /// The chain's epoch-window grid. A zero window length means a single
    /// fixed committee (every timestamp maps to genesis).
    windows: EpochWindows,
    /// Active committee for routing / gossip ("who is in the committee now?").
    head: Arc<TopologySnapshot>,
    /// The epoch `head` governs: the beacon's current epoch as this
    /// schedule last folded it.
    head_epoch: Epoch,
    /// Committee snapshots keyed by the epoch each governs.
    by_epoch: BTreeMap<Epoch, Arc<TopologySnapshot>>,
    /// Each window's projection as the fold before it first published it,
    /// never rewritten by the fold that freezes the window.
    lookahead: BTreeMap<Epoch, Arc<TopologySnapshot>>,
}

/// Answer of [`TopologySchedule::attests_boundary`]: what this schedule
/// says of an anchor claimed to be a boundary the beacon recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundaryAttestation {
    /// A held window or the head records exactly this anchor for its
    /// shard: height, root and clock.
    Stands,
    /// No held record names the anchor's height for its shard, or the
    /// one that does is its shard's terminal. A schedule behind the
    /// beacon answers this of a boundary it has yet to fold, and one
    /// ahead of it of a boundary it has evicted.
    Unknown,
    /// A held record names the anchor's height for its shard with
    /// another root or clock.
    Contradicted,
}

/// Answer of [`TopologySchedule::split_at_next_boundary`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitAtBoundary {
    /// No split lands at the end of this window — definitive.
    No,
    /// The schedule doesn't hold the window the timestamp resolves —
    /// ahead of the newest entry, or evicted below the retention floor.
    /// An admitted reshape never lands here: its cut is scheduled a
    /// window ahead, so the window's own entry decides.
    ///
    /// Callers defer, which is right for the first case and inert for the
    /// second: a proposer keys on its own tip's QC and a voter on the
    /// block it is judging, so neither reaches back below a floor derived
    /// from that same chain. A caller that could ask about an arbitrarily
    /// old window would need its own answer rather than this one.
    Unresolved,
    /// The shard's final epoch: the trie replaces it with these children
    /// at the next boundary.
    Children(ShardId, ShardId),
}

/// The shards one window says leave the trie at its end: each one it
/// runs whose scheduled terminal is that window's epoch.
#[derive(Debug, Clone, Copy)]
pub struct Terminating<'a> {
    ending: Option<(Epoch, &'a TopologySnapshot)>,
}

impl Terminating<'_> {
    /// No shard terminates: a schedule with no epoch boundaries.
    pub const NONE: Self = Self { ending: None };

    /// Whether `shard` leaves the trie at the end of the window.
    #[must_use]
    pub fn contains(self, shard: ShardId) -> bool {
        self.ending.is_some_and(|(epoch, window)| {
            window.shard_trie().contains(shard) && window.scheduled_terminal(shard) == Some(epoch)
        })
    }
}

/// The shards an anchor's window says are reshaping.
///
/// Each one it names draining under a latched reshape, and each one whose
/// cut falls at the window's end. Every scheduled cut belongs to a
/// latched record, so this covers every cut.
///
/// Intake reads it: no core member toward or from a shard it contains is
/// admitted or run, so a shard that has said it is quiet stays quiet
/// until its cut. A record's latch shows in every window frozen after the
/// fold that set it until the record clears, so once an anchor reads a
/// shard reshaping, every later anchor does until the cut or the cancel.
///
/// The frozen window is read and not the projection of the one after
/// it: a replica holds an anchor's frozen window before the window opens,
/// while the projection after it lands only once the beacon has folded
/// the window's own epoch, which every block anchored early in the window
/// would otherwise wait on.
#[derive(Debug, Clone, Copy)]
pub struct Reshaping<'a> {
    reading: ReshapingReading<'a>,
}

#[derive(Debug, Clone, Copy)]
enum ReshapingReading<'a> {
    /// A schedule with no epoch boundaries, where nothing reshapes.
    Nothing,
    /// The anchor's window could not be read, and every shard counts.
    Everything,
    /// The anchor's frozen window, and what terminates at its end.
    Window {
        frozen: &'a TopologySnapshot,
        terminating: Terminating<'a>,
    },
}

impl Reshaping<'_> {
    /// No shard reshapes: a schedule with no epoch boundaries.
    pub const NONE: Self = Self {
        reading: ReshapingReading::Nothing,
    };

    /// Every shard reads as reshaping: what a reader whose window is not
    /// held takes, failing closed.
    pub const UNHELD: Self = Self {
        reading: ReshapingReading::Everything,
    };

    /// Whether `shard` is reshaping at the anchor.
    #[must_use]
    pub fn contains(self, shard: ShardId) -> bool {
        match self.reading {
            ReshapingReading::Nothing => false,
            ReshapingReading::Everything => true,
            ReshapingReading::Window {
                frozen,
                terminating,
            } => frozen.draining(shard) || terminating.contains(shard),
        }
    }
}

/// What a window fixes network-wide, with no committee on it.
///
/// Read off the snapshot governing an anchor: the shard trie content is
/// classified against, the price table it is weighed at, and the
/// boundary records of departed shards. Which committee governs a shard
/// at an anchor is a
/// shard-scoped question — it needs the recovery bridge, the attested
/// frontier and the terminal clamp — and only the shard-aware lookups
/// answer it, so a committee read off a bare anchor does not compile.
#[derive(Clone, Copy)]
pub struct WindowView<'a> {
    snapshot: &'a TopologySnapshot,
}

impl<'a> WindowView<'a> {
    /// The trie in force in this window.
    #[must_use]
    pub const fn shard_trie(self) -> &'a ShardTrie {
        self.snapshot.shard_trie()
    }

    /// The price table in force in this window.
    #[must_use]
    pub const fn prices(self) -> PriceTable {
        self.snapshot.prices()
    }

    /// The boundary record of a departed `shard`, as this window carries
    /// it.
    #[must_use]
    pub fn boundary(self, shard: ShardId) -> Option<ShardAnchor> {
        self.snapshot.boundary(shard)
    }

    /// Every shard whose terminal record this window carries and whose
    /// chain it no longer runs, each with the cut its chain ended at.
    ///
    /// Read off this window's own records, so two replicas answer alike
    /// however many older windows each still retains; a departure whose
    /// record has dropped is one this window no longer attests.
    pub fn departures(
        self,
        windows: EpochWindows,
    ) -> impl Iterator<Item = (ShardId, WeightedTimestamp)> + 'a {
        let trie = self.snapshot.shard_trie();
        self.snapshot
            .boundaries()
            .filter(move |(shard, _)| !trie.contains(*shard))
            .filter_map(move |(shard, anchor)| {
                Some((shard, windows.window_of(anchor.terminal_epoch?).end))
            })
    }

    /// Where departed `shard`'s chain ended, as this window's terminal
    /// record says: the end of its terminal epoch's window. `None` while
    /// `shard` runs in this window, or once its record has dropped.
    #[must_use]
    pub fn terminal_cut(self, shard: ShardId, windows: EpochWindows) -> Option<WeightedTimestamp> {
        if self.snapshot.shard_trie().contains(shard) {
            return None;
        }
        let epoch = self.snapshot.boundary(shard)?.terminal_epoch?;
        Some(windows.window_of(epoch).end)
    }

    /// The epoch `shard`'s chain formed at, as this window's record names
    /// it: the running chain's, or a departed chain's while its terminal
    /// record stands. `None` where the window carries no record.
    #[must_use]
    pub fn formed(self, shard: ShardId) -> Option<Epoch> {
        self.snapshot.formed(shard)
    }

    /// The epoch the chain this window runs under `shard` formed at, or
    /// `None` where the window does not run `shard`.
    #[must_use]
    pub fn life(self, shard: ShardId) -> Option<Epoch> {
        self.snapshot.life(shard)
    }

    /// Whether departed `shard`'s terminal evidence is still readable at
    /// `at`: this window carries its record, and the handoff-complete
    /// stamp, if the beacon has landed it, has not aged past the evidence
    /// window.
    #[must_use]
    pub fn evidence_readable(
        self,
        shard: ShardId,
        at: WeightedTimestamp,
        windows: EpochWindows,
    ) -> bool {
        self.snapshot.boundary(shard).is_some_and(|anchor| {
            anchor
                .handoff_complete
                .is_none_or(|done| at <= windows.handoff_evidence_expiry(done))
        })
    }
}

/// Result of resolving a weighted timestamp to its window.
pub enum WindowLookup<'a> {
    /// The window is retained.
    Window(WindowView<'a>),
    /// As [`ScheduleLookup::NotYetCommitted`].
    NotYetCommitted,
    /// As [`ScheduleLookup::Evicted`].
    Evicted,
}

/// The anchor that selects the committee which signed a header's QC,
/// by what named it: see [`TopologySchedule::signing_anchor`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningAnchor {
    /// The held parent's own `parent_qc` timestamp.
    Parent(WeightedTimestamp),
    /// The beacon's attested boundary, which names the parent.
    Boundary(WeightedTimestamp),
    /// The header's own `parent_qc` timestamp, which names a different
    /// window than the parent's across an epoch cut.
    OwnQc(WeightedTimestamp),
}

impl SigningAnchor {
    /// The weighted timestamp the committee lookup resolves.
    #[must_use]
    pub const fn weighted_timestamp(self) -> WeightedTimestamp {
        match self {
            Self::Parent(wt) | Self::Boundary(wt) | Self::OwnQc(wt) => wt,
        }
    }

    /// Whether the parent named the committee, held or attested by the
    /// beacon, rather than the header itself.
    #[must_use]
    pub const fn names_parent(self) -> bool {
        matches!(self, Self::Parent(_) | Self::Boundary(_))
    }
}

/// Result of resolving a shard's committee at a weighted timestamp
/// against the retained window.
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

/// The committee a block of one shard belongs to: the window that seats
/// it and the epoch that window is keyed by.
#[derive(Clone, Copy)]
pub struct BlockCommittee<'a> {
    /// The window resolved. Its trie and prices are the block's as well
    /// as its committee, so it answers more than who signs.
    pub snapshot: &'a Arc<TopologySnapshot>,
    /// The epoch of the window resolved, after the terminal clamp: the
    /// key [`TopologySchedule::signed_committee`] resolves back to this
    /// window.
    pub epoch: Epoch,
    /// Whether the anchor resolved lands past the shard's terminal
    /// window, as [`TopologySchedule::past_terminal`] reads it. Always
    /// false for [`TopologySchedule::signed_committee`], which resolves
    /// an epoch rather than an anchor.
    pub past_terminal: bool,
}

/// Result of resolving the committee a block of one shard belongs to,
/// with the miss reasons of [`ScheduleLookup`].
#[derive(Clone, Copy)]
pub enum BlockResolution<'a> {
    /// The committee's window is retained.
    Committee(BlockCommittee<'a>),
    /// As [`ScheduleLookup::NotYetCommitted`].
    NotYetCommitted,
    /// As [`ScheduleLookup::Evicted`].
    Evicted,
}

impl<'a> BlockResolution<'a> {
    /// The resolved committee, or `None` for either miss.
    #[must_use]
    pub const fn committee(self) -> Option<BlockCommittee<'a>> {
        match self {
            Self::Committee(committee) => Some(committee),
            Self::NotYetCommitted | Self::Evicted => None,
        }
    }
}

/// What a verifier makes of a QC's signed committee epoch
/// ([`TopologySchedule::admits`]).
#[derive(Clone, Copy)]
pub enum QcAdmission<'a> {
    /// The epoch is one honest voters can have signed for the block, and
    /// its window is held: verify the aggregate under its keys.
    Admit(BlockCommittee<'a>),
    /// Not decidable here yet: the epoch's window, or a recovery binding
    /// that would place it, is ahead of this schedule. Buffer and ask
    /// again once the beacon catches up.
    Wait,
    /// No candidate committee of the block resolves to the epoch at the
    /// QC's stamp. Read off the committee anchor the caller supplied, so a
    /// caller that guessed it asks again under the parent's.
    Refuse,
    /// The signed-epoch fence refused it
    /// ([`TopologySchedule::fence_admits`]): work a pending recovery
    /// replaced. Anchor-free, so no parent changes it.
    Fenced,
}

impl TopologySchedule {
    /// Build a schedule seeded with `head` as the committee governing
    /// `head_epoch`. The beacon coordinator inserts the lookahead and any
    /// retained past epochs afterward via [`insert`](Self::insert).
    #[must_use]
    pub fn new(windows: EpochWindows, head_epoch: Epoch, head: Arc<TopologySnapshot>) -> Self {
        let mut by_epoch = BTreeMap::new();
        by_epoch.insert(head_epoch, Arc::clone(&head));
        let lookahead = BTreeMap::new();
        Self {
            windows,
            head,
            head_epoch,
            by_epoch,
            lookahead,
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
        self.windows.epoch_duration_ms()
    }

    /// The schedule's epoch-window grid — for callers that need
    /// [`window_of`](EpochWindows::window_of) or the crossing predicates, not
    /// just the [`epoch_for`](Self::epoch_for) lookup the schedule itself uses.
    #[must_use]
    pub const fn windows(&self) -> EpochWindows {
        self.windows
    }

    /// A schedule of one committee for all time: every weighted timestamp
    /// resolves to `snapshot`, and it is also the head. Used by tests and by
    /// within-epoch callers that hold a single committee. Every timestamp
    /// falls in the genesis epoch, so a completed recovery binding whose
    /// bridge is past it discards every height above its frontier.
    #[must_use]
    pub fn single(snapshot: Arc<TopologySnapshot>) -> Self {
        // A zero window length makes `epoch_for` fold every timestamp to
        // genesis, where the sole entry lives — so `at` always answers.
        let mut by_epoch = BTreeMap::new();
        by_epoch.insert(Epoch::GENESIS, Arc::clone(&snapshot));
        let lookahead = BTreeMap::new();
        Self {
            windows: EpochWindows::new(0, 0),
            head: snapshot,
            head_epoch: Epoch::GENESIS,
            by_epoch,
            lookahead,
        }
    }

    /// Epoch whose window contains `wt` — `floor((wt − genesis) /
    /// epoch_duration_ms)`. A zero duration (single-committee schedule)
    /// folds every timestamp to genesis.
    #[must_use]
    pub const fn epoch_for(&self, wt: WeightedTimestamp) -> Epoch {
        self.windows().epoch_for(wt)
    }

    /// The window `wt` falls in — its trie, prices and boundary records —
    /// or `None` when that epoch is outside the retained window. Callers
    /// that handle the two miss reasons differently use
    /// [`lookup`](Self::lookup). Never a committee: see [`WindowView`].
    #[must_use]
    pub fn at(&self, wt: WeightedTimestamp) -> Option<WindowView<'_>> {
        match self.lookup(wt) {
            WindowLookup::Window(window) => Some(window),
            WindowLookup::NotYetCommitted | WindowLookup::Evicted => None,
        }
    }

    /// Whether `wt`'s epoch lies below every retained entry, so no later
    /// fold brings its committee back. Narrower than
    /// [`lookup`](Self::lookup)'s [`Evicted`](WindowLookup::Evicted),
    /// which also answers for an epoch missing between two retained ones.
    #[must_use]
    pub fn evicted(&self, wt: WeightedTimestamp) -> bool {
        self.by_epoch
            .first_key_value()
            .is_some_and(|(oldest, _)| self.epoch_for(wt) < *oldest)
    }

    /// The oldest and the newest epoch whose committee is retained, or
    /// `None` for an empty schedule.
    #[must_use]
    pub fn retained_epochs(&self) -> Option<(Epoch, Epoch)> {
        Some((
            *self.by_epoch.first_key_value()?.0,
            *self.by_epoch.last_key_value()?.0,
        ))
    }

    /// [`at`](Self::at) with the miss reason surfaced: an epoch above every
    /// retained entry is [`NotYetCommitted`](WindowLookup::NotYetCommitted)
    /// (defer and retry), anything else absent is
    /// [`Evicted`](WindowLookup::Evicted) (reject — no honest artifact is
    /// attested below the eviction floor).
    #[must_use]
    pub fn lookup(&self, wt: WeightedTimestamp) -> WindowLookup<'_> {
        match self.lookup_snapshot(wt) {
            ScheduleLookup::Committee(snapshot) => WindowLookup::Window(WindowView { snapshot }),
            ScheduleLookup::NotYetCommitted => WindowLookup::NotYetCommitted,
            ScheduleLookup::Evicted => WindowLookup::Evicted,
        }
    }

    /// The snapshot governing `wt`'s epoch, or `None` outside the
    /// retained window.
    #[cfg(test)]
    fn snapshot_at(&self, wt: WeightedTimestamp) -> Option<&Arc<TopologySnapshot>> {
        match self.lookup_snapshot(wt) {
            ScheduleLookup::Committee(snapshot) => Some(snapshot),
            ScheduleLookup::NotYetCommitted | ScheduleLookup::Evicted => None,
        }
    }

    /// The snapshot governing `wt`'s epoch with the miss reason: the one
    /// resolution every lookup here derives from. Private, because a bare
    /// anchor names a window and not a committee; the shard-aware lookups
    /// add the bridge, the frontier and the clamp that make its committee
    /// answerable.
    fn lookup_snapshot(&self, wt: WeightedTimestamp) -> ScheduleLookup<'_> {
        self.lookup_epoch(self.epoch_for(wt))
    }

    /// The snapshot keyed `epoch`, with the miss reason.
    fn lookup_epoch(&self, epoch: Epoch) -> ScheduleLookup<'_> {
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

    /// The newest window this schedule holds: the projection of the epoch
    /// after the head that the last fold published, or the head itself
    /// where nothing past it is held. The committees the beacon has drawn a
    /// full window ahead, for placement questions; never for
    /// committee-quorum verification.
    #[must_use]
    pub fn newest_window(&self) -> &Arc<TopologySnapshot> {
        self.by_epoch
            .last_key_value()
            .map_or(&self.head, |(_, snapshot)| snapshot)
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
    /// head committee, plus the committees of the windows its chain has not
    /// yet crossed out of; a shard that has dissolved from the head — a split
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
        // A live shard's entry unions every committee its chain may still
        // sign under: the windows after the last crossing the beacon folded,
        // up to the head. A chain that lags the beacon's epoch needs the
        // committee of the window it is in to certify the block that crosses
        // out of it, so that committee's members keep their seats until the
        // crossing folds. A shard with no folded crossing unions every
        // retained window that carries it.
        for shard in self.head.shard_trie().leaves() {
            let from = self.head.boundary(shard).map_or(Epoch::GENESIS, |anchor| {
                self.anchor_epoch_for(anchor.weighted_timestamp).next()
            });
            let entry = committees.entry(shard).or_default();
            for snapshot in self.by_epoch.range(from..).map(|(_, snapshot)| snapshot) {
                if !snapshot.shard_trie().contains(shard) {
                    continue;
                }
                for id in snapshot.committee_for_shard(shard) {
                    if !entry.contains(id) {
                        entry.push(*id);
                    }
                }
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
        self.resolve_for_shard(shard, wt)
            .committee()
            .map(|committee| (committee.snapshot, committee.past_terminal))
    }

    /// Whether `wt` lands past `shard`'s terminal window: the
    /// past-terminal half of [`at_for_shard`](Self::at_for_shard). A
    /// window this schedule has not committed or has evicted answers
    /// `false`, so a replica whose schedule lags reads the flip once it
    /// catches up.
    #[must_use]
    pub fn past_terminal(&self, shard: ShardId, wt: WeightedTimestamp) -> bool {
        self.at_for_shard(shard, wt)
            .is_some_and(|(_, past_terminal)| past_terminal)
    }

    /// The snapshot governing `wt` with the terminal clamp of
    /// [`at_for_shard`](Self::at_for_shard): a `wt` whose window no
    /// longer carries `shard` resolves the newest retained window that
    /// does, flagged `true`. A `wt` whose window carries no trace of the
    /// shard in any retained window resolves [`Evicted`](ScheduleLookup::Evicted)
    /// — it claims a committee no honest artifact can be attested by.
    ///
    /// A `wt` exactly on the shard's cut resolves the same final window
    /// but is not past it: an anchor on a boundary belongs to the window
    /// it closes ([`anchor_epoch_for`](Self::anchor_epoch_for)), which is
    /// how the terminal-carry predicates read it. Were it flagged past,
    /// the block anchored there would carry the final window's split
    /// roots while the block after it failed the terminal test, and no
    /// header of the chain would carry the terminal settled root.
    ///
    /// The second value is also `true` for an [`Evicted`](ScheduleLookup::Evicted)
    /// answer at a held window that carries no trace of the shard: the
    /// anchor is past a terminal no retained window still records.
    #[must_use]
    pub fn lookup_for_shard(
        &self,
        shard: ShardId,
        wt: WeightedTimestamp,
    ) -> (ScheduleLookup<'_>, bool) {
        match self.resolve_for_shard(shard, wt) {
            BlockResolution::Committee(committee) => (
                ScheduleLookup::Committee(committee.snapshot),
                committee.past_terminal,
            ),
            BlockResolution::NotYetCommitted => (ScheduleLookup::NotYetCommitted, false),
            BlockResolution::Evicted => (
                ScheduleLookup::Evicted,
                self.by_epoch.contains_key(&self.epoch_for(wt)),
            ),
        }
    }

    /// [`lookup_for_shard`](Self::lookup_for_shard) with the epoch of the
    /// window resolved: the anchor's window, or the shard's terminal
    /// window where the anchor's no longer carries it.
    #[must_use]
    pub fn resolve_for_shard(&self, shard: ShardId, wt: WeightedTimestamp) -> BlockResolution<'_> {
        match self.lookup_snapshot(wt) {
            ScheduleLookup::Committee(snapshot) if !snapshot.shard_trie().contains(shard) => self
                .terminal_window(shard, wt)
                .map_or(BlockResolution::Evicted, |(epoch, snapshot)| {
                    BlockResolution::Committee(BlockCommittee {
                        snapshot,
                        epoch,
                        past_terminal: epoch != self.anchor_epoch_for(wt),
                    })
                }),
            ScheduleLookup::Committee(snapshot) => BlockResolution::Committee(BlockCommittee {
                snapshot,
                epoch: self.epoch_for(wt),
                past_terminal: false,
            }),
            ScheduleLookup::NotYetCommitted => BlockResolution::NotYetCommitted,
            ScheduleLookup::Evicted => BlockResolution::Evicted,
        }
    }

    /// The newest retained window below `wt`'s that carries `shard` — the
    /// last one its chain ran under, for a `wt` whose own window has
    /// dropped it. `None` once no retained window carries it at all.
    fn terminal_window(
        &self,
        shard: ShardId,
        wt: WeightedTimestamp,
    ) -> Option<(Epoch, &Arc<TopologySnapshot>)> {
        self.by_epoch
            .range(..self.epoch_for(wt))
            .rev()
            .find(|(_, s)| s.shard_trie().contains(shard))
            .map(|(epoch, snapshot)| (*epoch, snapshot))
    }

    /// Every shard a retained window carries that the window governing
    /// `wt` does not, each with where its chain ended.
    ///
    /// The departures still provable from the schedule. A consumer that
    /// has to outlive the record — a straddler waits on its counterpart
    /// for as long as the counterpart takes — reads them here while it
    /// can and keeps what it reads.
    pub fn departures_at(
        &self,
        wt: WeightedTimestamp,
    ) -> impl Iterator<Item = (ShardId, WeightedTimestamp)> + '_ {
        self.routable_shards()
            .into_iter()
            .filter_map(move |shard| Some((shard, self.terminal_cut_for_shard(shard, wt)?)))
    }

    /// Where `shard`'s chain ended, as an upper bound: the end of the last
    /// window that carried it.
    ///
    /// The figure a consumer records when it needs the terminal to outlive
    /// the window that proves it. Read off the attested schedule and the
    /// epoch geometry alone, so two replicas that observe the departure on
    /// different blocks — a lagging beacon fold moves *when* this resolves,
    /// never *what* it resolves to — still record the same instant.
    ///
    /// `None` while `shard` is alive in `wt`'s window, and `None` once no
    /// retained window carries it: a terminal this cannot read is not one
    /// it invents.
    #[must_use]
    pub fn terminal_cut_for_shard(
        &self,
        shard: ShardId,
        wt: WeightedTimestamp,
    ) -> Option<WeightedTimestamp> {
        match self.lookup_snapshot(wt) {
            ScheduleLookup::Committee(snapshot) if !snapshot.shard_trie().contains(shard) => self
                .terminal_window(shard, wt)
                .map(|(epoch, _)| self.windows().window_of(epoch).end),
            _ => None,
        }
    }

    /// The evidence expiry for a departed `shard` at the head snapshot:
    /// `Some` once the beacon has stamped its handoff complete, `None`
    /// while the window is open or the boundary record is gone — pair
    /// with boundary presence, which callers of the `None` case already
    /// read.
    #[must_use]
    pub fn handoff_evidence_expiry(&self, shard: ShardId) -> Option<WeightedTimestamp> {
        let done = self.head.boundary(shard)?.handoff_complete?;
        Some(self.windows().handoff_evidence_expiry(done))
    }

    /// Whether a departed `shard`'s terminal evidence is still readable at
    /// `wt`: its boundary record survives on the snapshot resolved there,
    /// and the handoff-complete stamp — if the beacon has landed it — has
    /// not aged past the evidence window. An unstamped window is open and
    /// reads readable; so does a window whose snapshot hasn't folded yet,
    /// because a transient lag must hold rather than drop.
    ///
    /// The local-bookkeeping companion of the fence's own inline
    /// derivation:
    /// caches, prunes, and the settled sets still wanted all read this, so
    /// none of them stops asking while the fence still expects an answer.
    #[must_use]
    pub fn terminal_evidence_readable(&self, shard: ShardId, wt: WeightedTimestamp) -> bool {
        match self.lookup_snapshot(wt) {
            ScheduleLookup::Committee(snapshot) => snapshot.boundary(shard).is_some_and(|anchor| {
                anchor
                    .handoff_complete
                    .is_none_or(|done| wt <= self.windows().handoff_evidence_expiry(done))
            }),
            ScheduleLookup::NotYetCommitted => true,
            ScheduleLookup::Evicted => false,
        }
    }

    /// The bridge of the recovery in flight on `shard` — the window after
    /// the head's pending recovery seated the fresh committee — or `None`
    /// when none is. What a recovery in flight gates (the seating-window
    /// quiesce, the harvest) reads this; committee resolution reads the
    /// shard's bindings, which outlive it.
    #[must_use]
    pub fn recovery_bridge(&self, shard: ShardId) -> Option<Epoch> {
        self.head
            .pending_recoveries()
            .get(&shard)
            .map(|recovery| recovery.rotated_at.next())
    }

    /// `shard`'s recovery bindings as the head folds them, oldest first.
    /// Bridges increase along them and attested frontiers never decrease.
    fn bindings(&self, shard: ShardId) -> impl DoubleEndedIterator<Item = RecoveryBinding> + '_ {
        self.head.recovery_bindings(shard)
    }

    /// `shard`'s newest recovery, pending or not.
    #[must_use]
    pub fn newest_recovery(&self, shard: ShardId) -> Option<RecoveryBinding> {
        self.bindings(shard).next_back()
    }

    /// Whether live work anchored at `wt` rides `shard`'s newest recovery
    /// bridge: `wt`'s epoch sits below it, the band
    /// [`live_committee`](Self::live_committee) re-binds to the fresh
    /// committee. The one predicate every consumer reads (proposer gating,
    /// state-root deferral, the live lookup itself), so the bridge band
    /// cannot drift between them.
    ///
    /// A halted chain's tip anchor is many windows stale, and the anchor's
    /// window resolves the committee that halted, so such work binds to
    /// the fresh committee instead. The binding does not end when the
    /// recovery completes: a fresh member still a QC behind the first
    /// crossing holds a tip anchored before the halt, and resolving the
    /// replaced committee for it would drop the very timeouts that carry
    /// it forward. Anchors at or past the bridge resolve as ordinary.
    #[must_use]
    pub fn recovery_bridging(&self, shard: ShardId, wt: WeightedTimestamp) -> bool {
        self.newest_recovery(shard)
            .is_some_and(|newest| self.epoch_for(wt) < newest.bridge())
    }

    /// Whether a block of `shard` whose own parent QC is anchored at
    /// `own_anchor` only coasts: past its terminal cut, or across a halt
    /// recovery's bridge. A coasting block is empty and writes nothing of
    /// its own accord, so the state it carries is its parent's.
    #[must_use]
    pub fn coasting(&self, shard: ShardId, own_anchor: WeightedTimestamp) -> bool {
        self.past_terminal(shard, own_anchor) || self.recovery_bridging(shard, own_anchor)
    }

    /// Whether a tick of `shard` anchored at `anchor_wt` is one a halt
    /// recovery has replaced the committee of: anchored below some
    /// binding's bridge. No replica that has folded the recovery runs or
    /// signs it, and the shard's crossing block discards it.
    ///
    /// A shuffle does not answer true here and must not: rotating a
    /// validator into or out of a shard changes later windows and leaves
    /// the one an old anchor names exactly as it was seated. Only a
    /// recovery replaces a committee *retroactively*. Reads every binding
    /// the shard's history keeps, so the answer does not flip when a
    /// recovery completes or a later one is seated.
    #[must_use]
    pub fn committee_replaced_for_anchored(
        &self,
        shard: ShardId,
        anchor_wt: WeightedTimestamp,
    ) -> bool {
        let anchor = self.epoch_for(anchor_wt);
        self.bindings(shard)
            .any(|binding| anchor < binding.bridge())
    }

    /// Whether the block of `shard` anchored at `anchor_wt`, whose parent
    /// is anchored at `parent_anchor_wt`, is the shard's crossing block:
    /// the first anchored at or past the newest bridge `committee` records
    /// for it. Its parent, a coast block, is anchored below that bridge.
    ///
    /// `committee` is the block's own. The proposer and every voter pass
    /// the snapshot [`live_committee`](Self::live_committee) resolves at
    /// the parent's anchor, which is the block's committee anchor;
    /// execution passes the window the block's QC signed, which is that
    /// same snapshot because honest voters sign the epoch they validated
    /// the block under. Read off that snapshot rather than the head, so
    /// the proposer, every voter and execution ask this one question of
    /// one record, and the block whose
    /// manifest names the recovery's discard is the block whose commit
    /// raises the tick chain floor. Bridges increase along a shard's
    /// history, so a block past an older bridge and below a newer one
    /// crosses nothing: the newer recovery's crossing block discards what
    /// it would have.
    #[must_use]
    pub fn crossing_block(
        &self,
        committee: &TopologySnapshot,
        shard: ShardId,
        parent_anchor_wt: WeightedTimestamp,
        anchor_wt: WeightedTimestamp,
    ) -> bool {
        let (parent, anchor) = (self.epoch_for(parent_anchor_wt), self.epoch_for(anchor_wt));
        committee
            .recovery_bindings(shard)
            .next_back()
            .is_some_and(|newest| parent < newest.bridge() && newest.bridge() <= anchor)
    }

    /// The highest height at which no work of `shard` is
    /// [`recovery_orphaned`](Self::recovery_orphaned): the lowest frontier
    /// among its recovery bindings, or `None` where it has none and
    /// nothing of it is.
    #[must_use]
    pub fn recovery_orphan_floor(&self, shard: ShardId) -> Option<BlockHeight> {
        self.bindings(shard)
            .map(|binding| binding.attested_frontier)
            .min()
    }

    /// Whether work of `shard` at `height` anchored at `anchor_wt` is in
    /// the band of any recovery the head holds for it, pending or not
    /// ([`RecoveryBinding::orphans`]).
    ///
    /// The one refusal of a certificate of the shard that a recovery
    /// replaced the committee of, and of a claim at a block the recovered
    /// chain does not keep. A certificate anchored at or past a bridge
    /// resolves the fresh committee and verifies only under its keys,
    /// and one at or below a frontier is the replaced committee's own
    /// history. Reads every binding the history keeps, so what the band
    /// refuses during a recovery it refuses after it.
    #[must_use]
    pub fn recovery_orphaned(
        &self,
        shard: ShardId,
        anchor_wt: WeightedTimestamp,
        height: BlockHeight,
    ) -> bool {
        let windows = self.windows();
        self.bindings(shard)
            .any(|binding| binding.orphans(windows, height, anchor_wt))
    }

    /// Whether a cross-shard artifact from `shard` at `height` is fenced by
    /// an in-flight halt recovery: past the beacon-attested frontier the
    /// recovery froze, the retained (beyond-f) committee could only have
    /// produced it after the halt, so no consumer that has folded the
    /// recovery trusts it. False when no recovery is pending for the shard
    /// (the ordinary case) or when `height` is within the frontier
    /// (legitimate pre-halt history, still verifiable against the old
    /// committee). A replica whose beacon has not folded the recovery has
    /// no record here and does not fence — the residual bounded to freeze
    /// propagation.
    ///
    /// Read off the head, so the answer is this replica's current one
    /// rather than the one governing any particular anchor. Its callers
    /// are admission checks made once, where the reading is
    /// against the freshest record a node holds and an artifact refused
    /// here is refused for good. A block-validity input would need the
    /// snapshot governing the block's own anchor instead, so that every
    /// replica validating it reads the same records whenever it
    /// validates — this is not that, and nothing here is.
    #[must_use]
    pub fn recovery_fences(&self, shard: ShardId, height: BlockHeight) -> bool {
        self.head.recovery_fences(shard, height)
    }

    /// Every boundary record this schedule holds: each window's and the
    /// head's.
    fn boundary_records(&self) -> impl Iterator<Item = (ShardId, ShardAnchor)> + '_ {
        self.by_epoch
            .values()
            .chain(self.lookahead.values())
            .chain(std::iter::once(&self.head))
            .flat_map(|snapshot| snapshot.boundaries())
    }

    /// Whether `proof` proves nothing about the committee governing its
    /// shard: no recovery of the shard is pending, and a side is on a
    /// branch one of its recoveries discarded
    /// ([`ShardForkProof::on_a_discarded_branch`]). Read off the head, as
    /// [`recovery_fences`](Self::recovery_fences) is.
    #[must_use]
    pub fn fork_proof_discarded(&self, proof: &ShardForkProof) -> bool {
        let shard = proof.shard();
        self.recovery_bridge(shard).is_none() && proof.on_a_discarded_branch(self.bindings(shard))
    }

    /// Whether `certified`'s block has the shape
    /// [`RecoveryBinding::discards`] names under one of its shard's
    /// recoveries, the pending one included: above that recovery's
    /// frontier, certified by a committee it replaced. Such a block is a
    /// replaced committee's. It is off the recovered chain unless a
    /// fresh-certified block descends from it, as one does from the tail
    /// a halt recovery harvests.
    #[must_use]
    pub fn recovery_discard_shaped(&self, certified: &CertifiedBlockHeader) -> bool {
        let (shard, qc) = (certified.shard_id(), certified.qc());
        !qc.is_genesis()
            && self
                .bindings(shard)
                .any(|binding| binding.discards(certified.height(), qc.committee_epoch()))
    }

    /// Whether `anchor` is a boundary the beacon recorded for its shard,
    /// as far as this schedule holds the records.
    ///
    /// A boundary is the one state of a shard no recovery discards: a
    /// recovery stamps its frontier at the recorded boundary and the
    /// recovered chain extends that block, and a recorded boundary never
    /// falls. So an anchor that [`Stands`](BoundaryAttestation::Stands) is on every
    /// chain the shard will ever commit, whatever a later fold records,
    /// and the answer for it does not change across the shard's
    /// recovery.
    ///
    /// Compared field for field, so a reading taken on another branch at
    /// a boundary's height is [`Contradicted`](BoundaryAttestation::Contradicted).
    /// Read off every window held and the head: nothing here fetches a
    /// header, since the root a proof is checked against is the one the
    /// beacon recorded.
    ///
    /// The record of a shard's terminal block, the one carrying its
    /// terminal settled root, attests nothing. No chain of that shard
    /// extends it, and the chain succeeding it may start its clock below
    /// the terminal's: a merged parent starts at the cut, its children's
    /// terminals an instant past it. So what the terminal's clock says
    /// has ended has not ended for the successor, whose own boundaries
    /// are the ones a reading of that keyspace stands at.
    #[must_use]
    pub fn attests_boundary(&self, anchor: &Anchor) -> BoundaryAttestation {
        let mut attested = BoundaryAttestation::Unknown;
        for (shard, record) in self.boundary_records() {
            if shard != anchor.shard
                || record.height != anchor.height
                || record.terminal_settled_txs.is_some()
            {
                continue;
            }
            if record.anchor(shard) == *anchor {
                return BoundaryAttestation::Stands;
            }
            attested = BoundaryAttestation::Contradicted;
        }
        attested
    }

    /// Whether `anchor`'s height is above every boundary this schedule
    /// holds for its shard's lineage: the shard, its ancestors and its
    /// descendants.
    ///
    /// The one case in which a boundary this schedule does not hold can
    /// be one the beacon has recorded and this replica has yet to fold.
    /// Heights rise across every reshape, so a lineage's records order
    /// together.
    #[must_use]
    pub fn above_held_boundaries(&self, anchor: &Anchor) -> bool {
        self.boundary_records()
            .filter(|(shard, _)| {
                shard.is_ancestor_of(anchor.shard) || anchor.shard.is_ancestor_of(*shard)
            })
            .all(|(_, record)| anchor.height > record.height)
    }

    /// The signed-epoch fence: `false` for a QC of `shard` whose committee
    /// signed `epoch` while a recovery of the shard is pending and that
    /// recovery replaced the work ([`RecoveryBinding::replaced`]).
    ///
    /// For the sites that see only *new* production during a recovery:
    /// the beacon's boundary fold, remote headers, sync claims, the reshape
    /// view and the observer. The fresh committee's blocks sign the
    /// bridged window or a later one, so the only QC this refuses that an
    /// honest committee signed is the halted suffix, which has no new
    /// crossing to offer and which those sites refuse today. What it is
    /// for is the orphan: a retained committee beyond f, plus its honest
    /// members that have not folded the recovery, can certify a block
    /// extending the halted tip under the window it was seated in, stamp
    /// it anywhere, and verify under its own keys.
    ///
    /// Anchor-free, so a verifier that has not got the block's parent
    /// applies it, and the bridge's own window need not be held.
    #[must_use]
    pub fn fence_admits(&self, shard: ShardId, epoch: Epoch) -> bool {
        self.recovery_bridge(shard)
            .is_none_or(|bridge| epoch >= bridge)
    }

    /// Whether any recovery the shard's history keeps replaced work signed
    /// under `epoch` ([`RecoveryBinding::replaced`]): the committee that
    /// signed it is one a recovery took the shard from, so its block is
    /// the halted suffix, an orphan extending it, or history no later
    /// block reads as the recovered chain's own.
    #[must_use]
    pub fn replaced(&self, shard: ShardId, epoch: Epoch) -> bool {
        self.bindings(shard).any(|binding| binding.replaced(epoch))
    }

    /// The committee entry the recovery bridge resolves: the bridge
    /// epoch's own window, where the fold seated the fresh committee.
    /// Pinned to that entry — rather than the newest retained window —
    /// so the binding is one value for every replica at every later
    /// fold: a mid-recovery top-up or a post-recovery shuffle lands in
    /// later entries and never re-binds work anchored below the bridge.
    fn bridged_for_shard(&self, shard: ShardId, bridge: Epoch) -> BlockResolution<'_> {
        self.resolve_for_shard(shard, self.windows().window_of(bridge).start)
    }

    /// The committee an uncertified block of `shard` whose committee
    /// anchor is `committee_anchor` is built and voted under: the
    /// anchor's window, terminal-clamped as
    /// [`lookup_for_shard`](Self::lookup_for_shard) clamps it, and bridged
    /// while [`recovery_bridging`](Self::recovery_bridging). For **live**
    /// consensus work — proposals, votes, and the tip committee. A recovering
    /// shard's stale anchor resolves the fresh committee via the recovery
    /// bridge (see [`recovery_bridge`](Self::recovery_bridge)), so an
    /// honest folded member proposes and votes only on the fresh chain and
    /// never on a competing extension the retained cohort gossips. This
    /// binds the *honest* side; it does not disarm the retained committee,
    /// which is beyond f by construction (that is why the shard halted) and
    /// can still certify a competing chain from its own members plus any
    /// lagging honest one. That orphan is caught on the verifier side, not
    /// here — see [`fence_admits`](Self::fence_admits). Never used to
    /// verify certified history: a QC states the epoch its committee
    /// signed, which [`admits`](Self::admits) checks.
    #[must_use]
    pub fn live_committee(
        &self,
        shard: ShardId,
        committee_anchor: WeightedTimestamp,
    ) -> BlockResolution<'_> {
        match self.newest_recovery(shard) {
            Some(newest) if self.recovery_bridging(shard, committee_anchor) => {
                self.bridged_for_shard(shard, newest.bridge())
            }
            _ => self.resolve_for_shard(shard, committee_anchor),
        }
    }

    /// The committee of `shard` keyed `epoch`, the epoch a
    /// [`BlockCommittee`] names: the window resolved back from its key,
    /// with no anchor, bridge or clamp to apply.
    /// [`Evicted`](BlockResolution::Evicted) for a held window that does
    /// not carry the shard, since no resolution keys one.
    #[must_use]
    pub fn signed_committee(&self, shard: ShardId, epoch: Epoch) -> BlockResolution<'_> {
        match self.lookup_epoch(epoch) {
            ScheduleLookup::Committee(snapshot) if snapshot.shard_trie().contains(shard) => {
                BlockResolution::Committee(BlockCommittee {
                    snapshot,
                    epoch,
                    past_terminal: false,
                })
            }
            ScheduleLookup::NotYetCommitted => BlockResolution::NotYetCommitted,
            ScheduleLookup::Committee(_) | ScheduleLookup::Evicted => BlockResolution::Evicted,
        }
    }

    /// Whether a QC over a block of `shard`, whose committee anchor is
    /// `committee_anchor`, stamped `qc_wt` and signed under `epoch`, is one
    /// honest voters can have signed — and if so, the committee to verify
    /// its aggregate under.
    ///
    /// A block's candidate committees are its anchor's own window (raw)
    /// and the window each recovery bridging the anchor seated, `B_1 <
    /// … < B_n`, every binding whose bridge sits above the anchor's epoch.
    /// The stamp places the QC between them. With `e` the stamp's epoch
    /// and `r_k = B_k - 1` the epoch binding `k` was seated in:
    ///
    /// - raw is a candidate while no binding was seated before the QC's
    ///   epoch: `n == 0` or `e <= r_1`;
    /// - `bridged(B_k)` is a candidate from its seating until the next one:
    ///   `r_k <= e`, and `e <= r_{k+1}` where `k < n`.
    ///
    /// Honest raw votes are stamped before the first such recovery is
    /// seated; honest `bridged(B_k)` votes at or past the bridge window,
    /// which the seating quiesce holds them to, and before the voter folds
    /// the next re-draw. The windows overlap at each seating epoch, so a
    /// fresh committee that certified there before folding the next
    /// re-draw is still admitted after it.
    ///
    /// Admitted when some candidate resolves to `epoch`. Otherwise the QC
    /// waits where this schedule may yet learn
    /// what places it: a candidate window not committed here, or a head
    /// behind `e`, which may not have folded a binding seated by then. A
    /// binding this head has not folded was seated past it, so its bridge
    /// lies at least two windows past the head, and a QC naming an epoch
    /// below that is refused at once. A QC refused here was refused under
    /// `committee_anchor`, so a caller that guessed the anchor asks again
    /// under the parent's.
    ///
    /// The stamp chooses no committee: it bounds which candidates count.
    /// Callers skip the genesis QC, which no committee signed.
    #[must_use]
    pub fn admits(
        &self,
        shard: ShardId,
        committee_anchor: WeightedTimestamp,
        qc_wt: WeightedTimestamp,
        epoch: Epoch,
    ) -> QcAdmission<'_> {
        let anchor = self.epoch_for(committee_anchor);
        let stamped = self.epoch_for(qc_wt);
        let bridges: Vec<Epoch> = self
            .bindings(shard)
            .map(RecoveryBinding::bridge)
            .filter(|bridge| anchor < *bridge)
            .collect();
        let raw = bridges
            .first()
            .is_none_or(|first| stamped < *first)
            .then(|| self.resolve_for_shard(shard, committee_anchor));
        let seated_since = bridges.iter().enumerate().filter_map(|(k, bridge)| {
            let seated = *bridge <= stamped.next();
            let superseded = bridges.get(k + 1).is_some_and(|next| stamped >= *next);
            (seated && !superseded).then(|| self.bridged_for_shard(shard, *bridge))
        });
        let mut waiting = false;
        for candidate in raw.into_iter().chain(seated_since) {
            match candidate {
                BlockResolution::Committee(committee) if committee.epoch == epoch => {
                    return QcAdmission::Admit(committee);
                }
                BlockResolution::NotYetCommitted => waiting = true,
                BlockResolution::Committee(_) | BlockResolution::Evicted => {}
            }
        }
        if waiting || (self.head_epoch < stamped && epoch > self.head_epoch.next()) {
            QcAdmission::Wait
        } else {
            QcAdmission::Refuse
        }
    }

    /// [`Self::admits`] for the sites that see only new production during
    /// a recovery, behind the signed-epoch fence
    /// ([`Self::fence_admits`]): [`Fenced`](QcAdmission::Fenced) for a QC a
    /// pending recovery replaced, whatever its stamp.
    #[must_use]
    pub fn admits_fenced(
        &self,
        shard: ShardId,
        committee_anchor: WeightedTimestamp,
        qc_wt: WeightedTimestamp,
        epoch: Epoch,
    ) -> QcAdmission<'_> {
        if !self.fence_admits(shard, epoch) {
            return QcAdmission::Fenced;
        }
        self.admits(shard, committee_anchor, qc_wt, epoch)
    }

    /// The anchor that selects the committee which signed the QC over
    /// `header`'s block. A block's committee anchors on its parent, so the
    /// window that signed is the one the parent dates itself in:
    /// `parent_anchor`, the held parent's own `parent_qc` timestamp, when the
    /// caller holds the parent. Without it, the head's attested boundary
    /// stands in when it names the parent, and otherwise the header's own
    /// anchor does, the same window except across an epoch cut.
    #[must_use]
    pub fn signing_anchor(
        &self,
        shard: ShardId,
        header: &BlockHeader,
        parent_anchor: Option<WeightedTimestamp>,
    ) -> SigningAnchor {
        if let Some(parent_anchor) = parent_anchor {
            return SigningAnchor::Parent(parent_anchor);
        }
        self.head()
            .boundary(shard)
            .filter(|boundary| boundary.block_hash == header.parent_block_hash())
            .map_or_else(
                || SigningAnchor::OwnQc(header.parent_qc().weighted_timestamp()),
                |boundary| SigningAnchor::Boundary(boundary.weighted_timestamp),
            )
    }

    /// The weighted timestamp at which `shard` terminated — the end of the
    /// newest retained window that still carried it — or `None` when the
    /// shard is live in the head or absent from every retained window.
    ///
    /// A terminated split parent leaves the head trie but lingers in recent
    /// windows until its drain horizon; this returns its terminal cut,
    /// which bounds the split-boundary fence's retention cutoff and the
    /// settled-set acquisition's self-expiry.
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

    /// The chains `shard` succeeds, each as the terminal state its
    /// markers are proven against, read off the beacon's own boundary
    /// records — one terminal for a split child, two for a merged parent,
    /// none for a chain born at network genesis.
    ///
    /// The reshape flip hands these to a seat present at the cut. This is
    /// where every other seat gets them: a restart, a validator rotated on
    /// afterwards, a snap-synced joiner. Nothing here is fetched, so
    /// nothing here is trusted — the records are the node's own commit-
    /// proved fold.
    ///
    /// A candidate is a predecessor when its terminal cut is exactly
    /// `origin_wt`. That binding is what makes shard-id reuse harmless: a
    /// merge reclaims an id its own ancestor once held, and the reclaimed
    /// chain's origin is the merge cut, which only the two children
    /// terminated at. Structure alone would not separate them — the same
    /// id can be a split parent in one era and a merged parent in the
    /// next.
    ///
    /// All or nothing. A candidate whose boundary record is not yet
    /// folded, or carries no terminal settled root yet,
    /// takes the whole set with it, so a successor never judges which
    /// shape it was born by from part of the set. Holding none is the
    /// strict refusal the successor already runs under, so nothing is lost
    /// by waiting — and a caller only adopts while it holds nothing, so the
    /// next fold that completes the set is what it takes.
    ///
    /// The two children's terminals fold independently and need not land
    /// together, so a merged parent reading this mid-window sees exactly
    /// that partial state.
    #[must_use]
    pub fn predecessor_terminals(
        &self,
        shard: ShardId,
        origin_wt: WeightedTimestamp,
    ) -> Vec<Anchor> {
        if origin_wt <= self.windows.origin() {
            // The network's first chain. Nothing ran before it, so nothing
            // offered to it can open before it began.
            return Vec::new();
        }
        let (left, right) = shard.children();
        // A split child succeeds its parent; a merged parent succeeds its
        // two children. Both are offered because a chain does not record
        // which reshape produced it, and the cut binding admits at most
        // one of the two shapes: a shard born at a cut has no children
        // that could have terminated at it.
        let complete: Option<Vec<Anchor>> = [shard.parent(), Some(left), Some(right)]
            .into_iter()
            .flatten()
            .filter(|candidate| self.terminal_cut_wt(*candidate) == Some(origin_wt))
            .map(|candidate| {
                let record = self.head.boundary(candidate)?;
                record.terminal_settled_txs?;
                Some(Anchor {
                    shard: candidate,
                    height: record.height,
                    state_root: record.state_root,
                    ts: record.weighted_timestamp,
                })
            })
            .collect();
        complete.unwrap_or_default()
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
    /// when `wt` falls in the splitting shard's final epoch.
    ///
    /// Answered from `wt`'s own window: the frozen
    /// [`scheduled_terminal`](TopologySnapshot::scheduled_terminal)
    /// names the cut, and
    /// [`split_pending`](TopologySnapshot::split_pending) says the
    /// terminating reshape is a split rather than a merge. Definitive
    /// either way — no fold schedules a terminal for the window it
    /// opens, so a cut at this window's end was already scheduled by a
    /// fold every reader of this window's entry has seen, and a reader
    /// that is behind cannot be missing one.
    ///
    /// [`Unresolved`](SplitAtBoundary::Unresolved) survives only for a
    /// window the schedule doesn't hold at all — a beacon behind its own
    /// retention floor.
    ///
    /// A [`single`](Self::single) schedule has no epoch boundaries, so
    /// no split can land at one — [`No`](SplitAtBoundary::No),
    /// definitive.
    #[must_use]
    pub fn split_at_next_boundary(&self, shard: ShardId, wt: WeightedTimestamp) -> SplitAtBoundary {
        if self.windows.epoch_duration_ms() == 0 {
            return SplitAtBoundary::No;
        }
        let epoch = self.anchor_epoch_for(wt);
        let Some(current) = self.by_epoch.get(&epoch) else {
            return SplitAtBoundary::Unresolved;
        };
        if !current.shard_trie().contains(shard)
            || current.scheduled_terminal(shard) != Some(epoch)
            || !current.split_pending(shard)
        {
            return SplitAtBoundary::No;
        }
        let (left, right) = shard.children();
        SplitAtBoundary::Children(left, right)
    }

    /// Whether `shard` leaves the trie at the end of `wt`'s epoch window —
    /// terminating into either its two children (a split) or its parent (a
    /// merge). `Some(true)` when the window's frozen
    /// [`scheduled_terminal`](TopologySnapshot::scheduled_terminal) names
    /// that cut, `Some(false)` otherwise, `None` only when the schedule
    /// doesn't hold `wt`'s window at all.
    ///
    /// Generalizes [`split_at_next_boundary`](Self::split_at_next_boundary)
    /// from its split-only `Children` answer to any terminating reshape:
    /// the terminal-coast boundary header of a split parent *or* a merge
    /// child carries the `settled_txs_root`, so its carry predicate keys
    /// on this. A [`single`](Self::single) schedule has no epoch
    /// boundaries, so nothing terminates at one.
    #[must_use]
    pub fn terminates_at_next_boundary(
        &self,
        shard: ShardId,
        wt: WeightedTimestamp,
    ) -> Option<bool> {
        self.terminating_at(wt)
            .map(|terminating| terminating.contains(shard))
    }

    /// The shards leaving the trie at the end of the window a
    /// parent-anchor timestamp `wt` resolves, the one
    /// [`terminates_at_next_boundary`](Self::terminates_at_next_boundary)
    /// reads; `None` where the schedule does not hold that window.
    #[must_use]
    pub fn terminating_at(&self, wt: WeightedTimestamp) -> Option<Terminating<'_>> {
        if self.windows.epoch_duration_ms() == 0 {
            return Some(Terminating::NONE);
        }
        let epoch = self.anchor_epoch_for(wt);
        let window = self.by_epoch.get(&epoch)?;
        Some(Terminating {
            ending: Some((epoch, window)),
        })
    }

    /// The shards reshaping at a parent-anchor timestamp `wt`, read off
    /// the one window [`terminating_at`](Self::terminating_at) reads, the
    /// closing one for an anchor exactly on a boundary as a committee
    /// resolves it: each it names draining, and each whose cut falls at
    /// its end. `None` where the schedule does not hold that window; a
    /// reader that cannot defer takes that as reshaping.
    #[must_use]
    pub fn reshaping_at(&self, wt: WeightedTimestamp) -> Option<Reshaping<'_>> {
        if self.windows.epoch_duration_ms() == 0 {
            return Some(Reshaping::NONE);
        }
        let terminating = self.terminating_at(wt)?;
        let frozen = self.by_epoch.get(&self.anchor_epoch_for(wt))?;
        Some(Reshaping {
            reading: ReshapingReading::Window {
                frozen,
                terminating,
            },
        })
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
        let pending = self
            .forward_windows(wt)
            .into_iter()
            .flatten()
            .any(|s| s.split_pending(shard) || s.merge_pending(shard));
        pending || self.terminates_at_next_boundary(shard, wt) == Some(true)
    }

    /// The window `wt` falls in and the projection of the one after it,
    /// as first published: what every forward question reads.
    ///
    /// The first is the frozen window. The second is the lookahead copy
    /// rather than the by-epoch entry, which the next fold rewrites: two
    /// replicas at one committed frontier hold the same copy whether or
    /// not either has folded past it, which is what lets a classification
    /// taken at commit be re-derived identically on replay.
    fn forward_windows(&self, wt: WeightedTimestamp) -> [Option<&Arc<TopologySnapshot>>; 2] {
        let epoch = self.epoch_for(wt);
        [self.by_epoch.get(&epoch), self.lookahead.get(&epoch.next())]
    }

    /// The window `wt` falls in as the fold before it first published
    /// it, which no later fold rewrites.
    fn as_published(&self, wt: WeightedTimestamp) -> Result<&Arc<TopologySnapshot>, Unpublished> {
        self.lookahead.get(&self.epoch_for(wt)).ok_or(Unpublished)
    }

    /// `shard`'s newest recovery as the window `wt` falls in recorded it
    /// when first published, pending or not.
    ///
    /// # Errors
    ///
    /// [`Unpublished`] where this schedule does not hold that window as
    /// it was first published.
    pub fn recovery_as_published(
        &self,
        shard: ShardId,
        wt: WeightedTimestamp,
    ) -> Result<Option<RecoveryBinding>, Unpublished> {
        Ok(self.as_published(wt)?.recovery_bindings(shard).next_back())
    }

    /// Where the chain the window `wt` falls in names under `shard` was
    /// formed, read off the copy [`partner_evidence`](crate::partner_evidence)
    /// reads. `None` where that window is not held or carries no record of
    /// `shard`.
    #[must_use]
    pub fn formed(&self, shard: ShardId, wt: WeightedTimestamp) -> Option<Formed> {
        let epoch = self.at(wt)?.formed(shard)?;
        Some(self.formation(epoch))
    }

    /// [`formed`](Self::formed), reading a window no beacon state
    /// projected as [`WindowView::life`] does: every shard it runs formed
    /// at genesis. `None` where that window is not held or names no chain
    /// under `shard`.
    #[must_use]
    pub fn formation_at(&self, shard: ShardId, wt: WeightedTimestamp) -> Option<Formed> {
        let window = self.at(wt)?;
        let epoch = window.formed(shard).or_else(|| window.life(shard))?;
        Some(self.formation(epoch))
    }

    /// [`formed`](Self::formed) off the window `wt` falls in as it was
    /// first published, the copy
    /// [`recovery_as_published`](Self::recovery_as_published) reads.
    ///
    /// # Errors
    ///
    /// [`Unpublished`] where this schedule does not hold that window as
    /// it was first published.
    pub fn formed_as_published(
        &self,
        shard: ShardId,
        wt: WeightedTimestamp,
    ) -> Result<Option<Formed>, Unpublished> {
        Ok(self
            .as_published(wt)?
            .formed(shard)
            .map(|epoch| self.formation(epoch)))
    }

    /// A formation at `epoch`, opening where its window does.
    const fn formation(&self, epoch: Epoch) -> Formed {
        Formed {
            epoch,
            opens: self.windows().window_of(epoch).start,
        }
    }

    /// The floor of `shard`'s attested settled-transaction window at `wt`: the
    /// start of the epoch its terminating reshape was admitted, backed off
    /// by [`RETENTION_HORIZON`] to cover a tick that finalized against the
    /// fence just after it armed but executed up to a full tick lifetime
    /// earlier. Counterpart fences hold straddlers from admission, so the
    /// window a terminal's `settled_txs_root` commits must reach back to
    /// it — a fixed span behind the terminal misses settlements the fence
    /// is still holding against.
    ///
    /// Reads the floor off `wt`'s window or its lookahead (the same
    /// entries [`termination_scheduled`] consults, so any tick the fence
    /// can hold has a floor at or before its settlement). `None` when
    /// neither retained window records a floor for `shard` — callers then
    /// floor on the block anchor alone. Deterministic in `(schedule,
    /// wt)`: the proposer committing a coast block's root, every verifier
    /// recomputing it, and a former member serving the window list all
    /// derive the same floor.
    ///
    /// [`termination_scheduled`]: Self::termination_scheduled
    ///
    /// [`RETENTION_HORIZON`]: crate::RETENTION_HORIZON
    #[must_use]
    pub fn settled_window_floor(
        &self,
        shard: ShardId,
        wt: WeightedTimestamp,
    ) -> Option<WeightedTimestamp> {
        if self.windows.epoch_duration_ms() == 0 {
            return None;
        }
        self.forward_windows(wt)
            .into_iter()
            .flatten()
            .find_map(|s| s.settled_window_floor(shard))
    }

    /// Record the committee governing `epoch`: the frozen window the
    /// beacon coordinator inserts for the epoch it has just applied.
    pub fn insert(&mut self, epoch: Epoch, snapshot: Arc<TopologySnapshot>) {
        self.by_epoch.insert(epoch, snapshot);
    }

    /// Record the projection of `epoch` the fold before it publishes.
    ///
    /// Written to the by-epoch map, where the committee lookup wants it
    /// and where the fold of `epoch` will replace it, and kept as first
    /// written for the forward questions: a projection published once is
    /// never rewritten, so a later insert for the same epoch leaves the
    /// kept copy alone.
    pub fn insert_lookahead(&mut self, epoch: Epoch, snapshot: Arc<TopologySnapshot>) {
        self.by_epoch.insert(epoch, Arc::clone(&snapshot));
        self.lookahead.entry(epoch).or_insert(snapshot);
    }

    /// Replace the active head committee (routing view), the beacon's
    /// state as of `epoch`.
    pub fn set_head(&mut self, epoch: Epoch, snapshot: Arc<TopologySnapshot>) {
        self.head = snapshot;
        self.head_epoch = epoch;
    }

    /// Drop entries below `floor`. The owner derives `floor` from the oldest
    /// epoch any consumer can still legitimately query, so everything below
    /// is unreachable by honest artifacts.
    pub fn evict_below(&mut self, floor: Epoch) {
        self.by_epoch.retain(|epoch, _| *epoch >= floor);
        self.lookahead.retain(|epoch, _| *epoch >= floor);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet, HashMap};

    use hyperscale_crypto::Signer;
    use hyperscale_crypto_bls::{BlsSigner, BlsVerifier};

    use super::*;
    use crate::{
        BeaconWitnessLeafCount, BlockHash, BlockHeight, EPOCH_DURATION, Evidence, Hash,
        NetworkDefinition, RETENTION_HORIZON, RecoveryBinding, RecoveryCause, ReshapeSeat,
        SettledTxsRoot, ShardAnchor, ShardRecovery, StateRoot, ValidatorSet, partner_evidence,
    };

    fn snapshot() -> Arc<TopologySnapshot> {
        Arc::new(TopologySnapshot::new(
            NetworkDefinition::simulator(),
            1,
            ValidatorSet::new(Vec::new()),
        ))
    }

    /// The members `resolution` seats for `shard`, after checking that the
    /// epoch it names resolves back to the same window.
    fn members_of(
        schedule: &TopologySchedule,
        shard: ShardId,
        resolution: BlockResolution<'_>,
    ) -> Vec<ValidatorId> {
        let BlockResolution::Committee(committee) = resolution else {
            panic!("expected a resolved committee");
        };
        let Some(signed) = schedule
            .signed_committee(shard, committee.epoch)
            .committee()
        else {
            panic!("the epoch a committee names resolves back");
        };
        assert!(Arc::ptr_eq(signed.snapshot, committee.snapshot));
        committee.snapshot.committee_for_shard(shard).to_vec()
    }

    /// The members of the committee `admission` admits a QC under.
    fn admitted(
        schedule: &TopologySchedule,
        shard: ShardId,
        admission: QcAdmission<'_>,
    ) -> Vec<ValidatorId> {
        let QcAdmission::Admit(committee) = admission else {
            panic!("expected the QC admitted");
        };
        members_of(schedule, shard, BlockResolution::Committee(committee))
    }

    fn halt_recovery(rotated_at: u64, retained: &[ValidatorId]) -> ShardRecovery {
        halt_recovery_at(rotated_at, retained, BlockHeight::GENESIS)
    }

    fn halt_recovery_at(
        rotated_at: u64,
        retained: &[ValidatorId],
        attested_frontier: BlockHeight,
    ) -> ShardRecovery {
        ShardRecovery {
            cause: RecoveryCause::Halt,
            rotated_at: Epoch::new(rotated_at),
            retained: retained.to_vec(),
            attested_frontier,
        }
    }

    /// A snapshot whose head trie holds `live` and whose boundary map
    /// records `terminated` with the given committed-transaction root.
    /// The state root `shard`'s boundary record carries.
    fn terminal_root(shard: ShardId) -> StateRoot {
        StateRoot::from_raw(Hash::from_bytes(format!("root-{shard:?}").as_bytes()))
    }

    fn topology_with(
        live: &[ShardId],
        terminated: &[(ShardId, Option<SettledTxsRoot>)],
    ) -> Arc<TopologySnapshot> {
        let committees: HashMap<ShardId, Vec<ValidatorId>> =
            live.iter().map(|shard| (*shard, Vec::new())).collect();
        let boundaries: BTreeMap<ShardId, ShardAnchor> = terminated
            .iter()
            .map(|(shard, settled)| {
                (
                    *shard,
                    ShardAnchor {
                        state_root: terminal_root(*shard),
                        block_hash: BlockHash::from_raw(Hash::from_bytes(
                            format!("{shard:?}").as_bytes(),
                        )),
                        height: BlockHeight::new(41),
                        weighted_timestamp: WeightedTimestamp::ZERO,
                        witness_base: BeaconWitnessLeafCount::ZERO,
                        terminal_settled_txs: *settled,
                        handoff_complete: None,
                        terminal_epoch: None,
                    },
                )
            })
            .collect();
        Arc::new(TopologySnapshot::from_explicit_committees(
            NetworkDefinition::simulator(),
            &ValidatorSet::new(Vec::new()),
            committees,
            HashMap::new(),
            boundaries,
            HashMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
        ))
    }

    fn root_settled() -> SettledTxsRoot {
        SettledTxsRoot::from_raw(Hash::from_bytes(b"settled window"))
    }

    /// A two-window schedule cut at 1000ms: `before` governs epoch 0,
    /// `after` governs epoch 1 and is the head. The head is what
    /// `terminal_cut_wt` reads to decide a shard has left, so a fixture
    /// that only inserts the later window leaves every shard live and
    /// every assertion here vacuous.
    fn cut_at_1000(
        before: &[ShardId],
        after: &[ShardId],
        terminated: &[(ShardId, Option<SettledTxsRoot>)],
    ) -> TopologySchedule {
        let head = topology_with(after, terminated);
        let mut sched = TopologySchedule::new(
            EpochWindows::new(0, 1000),
            Epoch::new(0),
            topology_with(before, &[]),
        );
        sched.insert(Epoch::new(1), Arc::clone(&head));
        sched.set_head(Epoch::new(1), head);
        sched
    }

    /// A split child succeeds the parent that terminated at its origin,
    /// and reads the parent's terminal state off the boundary record.
    #[test]
    fn a_split_child_succeeds_the_parent_that_terminated_at_its_cut() {
        let (left, right) = ShardId::ROOT.children();
        // ROOT is live in epoch 0 and gone from epoch 1, so its terminal
        // cut is the end of epoch 0 — 1000ms.
        let sched = cut_at_1000(
            &[ShardId::ROOT],
            &[left, right],
            &[(ShardId::ROOT, Some(root_settled()))],
        );
        let cut = WeightedTimestamp::from_millis(1000);

        let predecessors = sched.predecessor_terminals(left, cut);
        assert_eq!(predecessors.len(), 1);
        assert_eq!(predecessors[0].shard, ShardId::ROOT);
        assert_eq!(predecessors[0].height, BlockHeight::new(41));
        assert_eq!(predecessors[0].state_root, terminal_root(ShardId::ROOT));
    }

    /// A merged parent succeeds both children, and both terminals are
    /// found.
    #[test]
    fn a_merged_parent_succeeds_both_children() {
        let (left, right) = ShardId::ROOT.children();
        let sched = cut_at_1000(
            &[left, right],
            &[ShardId::ROOT],
            &[(left, Some(root_settled())), (right, Some(root_settled()))],
        );

        let predecessors =
            sched.predecessor_terminals(ShardId::ROOT, WeightedTimestamp::from_millis(1000));
        assert_eq!(
            predecessors.iter().map(|p| p.shard).collect::<Vec<_>>(),
            vec![left, right],
        );
    }

    /// And both or neither. The two children's terminals fold
    /// independently and need not land together, so a merged parent
    /// reading this mid-window can see one with its roots and one
    /// without — the ordinary state, not a corrupt one. The partial set
    /// is refused entirely, and a caller adopts only while it holds
    /// nothing, so the fold that completes the pair is the one it takes.
    #[test]
    fn a_merged_parent_holds_both_children_or_neither() {
        let (left, right) = ShardId::ROOT.children();
        let cut = WeightedTimestamp::from_millis(1000);
        let succeeding = |terminated: &[(ShardId, Option<SettledTxsRoot>)]| {
            cut_at_1000(&[left, right], &[ShardId::ROOT], terminated)
                .predecessor_terminals(ShardId::ROOT, cut)
        };

        assert_eq!(
            succeeding(&[(left, Some(root_settled())), (right, Some(root_settled())),]).len(),
            2,
        );
        // The right child's terminal has folded, but without its roots.
        assert!(
            succeeding(&[(left, Some(root_settled())), (right, None)]).is_empty(),
            "one child's commitment is not the merged parent's answer",
        );
        // And the case where its boundary record has not folded at all.
        assert!(succeeding(&[(left, Some(root_settled()))]).is_empty());
    }

    /// The cut is what binds a terminal to a chain, not the shard tree. A
    /// candidate that terminated at some *other* instant is not this
    /// chain's predecessor, which is what keeps a reclaimed shard id from
    /// inheriting an ancestor's terminal.
    #[test]
    fn a_terminal_at_another_cut_is_not_a_predecessor() {
        let (left, right) = ShardId::ROOT.children();
        let sched = cut_at_1000(
            &[ShardId::ROOT],
            &[left, right],
            &[(ShardId::ROOT, Some(root_settled()))],
        );

        // The fixture is the one the positive case uses, so this asserts
        // the binding rather than a mis-built schedule.
        assert_eq!(
            sched
                .predecessor_terminals(left, WeightedTimestamp::from_millis(1000))
                .len(),
            1,
        );
        // ROOT's terminal cut is 1000ms; a chain claiming to have begun at
        // 2000ms did not succeed it.
        assert!(
            sched
                .predecessor_terminals(left, WeightedTimestamp::from_millis(2000))
                .is_empty()
        );
    }

    /// A candidate whose boundary record carries no terminal settled root
    /// is left out: the successor keeps refusing everything from before
    /// its origin until the record completes.
    #[test]
    fn a_terminal_without_roots_is_not_adopted() {
        let (left, right) = ShardId::ROOT.children();
        let cut = WeightedTimestamp::from_millis(1000);

        // Same cut, same structure — only the roots are missing, so this
        // isolates the one condition it is about.
        assert_eq!(
            cut_at_1000(
                &[ShardId::ROOT],
                &[left, right],
                &[(ShardId::ROOT, Some(root_settled()))],
            )
            .predecessor_terminals(left, cut)
            .len(),
            1,
        );
        assert!(
            cut_at_1000(&[ShardId::ROOT], &[left, right], &[(ShardId::ROOT, None)])
                .predecessor_terminals(left, cut)
                .is_empty()
        );
    }

    /// A chain born at network genesis anchors at zero and succeeds
    /// nothing, so it never asks.
    #[test]
    fn a_genesis_chain_has_no_predecessors() {
        let sched = TopologySchedule::single(topology_with(&[ShardId::ROOT], &[]));
        assert!(
            sched
                .predecessor_terminals(ShardId::ROOT, WeightedTimestamp::ZERO)
                .is_empty()
        );
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
        let mut sched =
            TopologySchedule::new(EpochWindows::new(0, 1000), Epoch::new(3), snapshot());
        sched.insert_lookahead(Epoch::new(5), terminating);

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

    /// A forward question does not move with the fold: a replica that has
    /// folded epoch `e + 1` and one that has not answer alike for a
    /// timestamp in `e`, though the fold rewrote what the by-epoch map
    /// holds for `e + 1`.
    #[test]
    fn a_forward_question_does_not_move_with_the_fold() {
        let projecting_a_split = |pending: &[ShardId]| {
            Arc::new(TopologySnapshot::from_explicit_committees(
                NetworkDefinition::simulator(),
                &ValidatorSet::new(Vec::new()),
                HashMap::from([(ShardId::ROOT, Vec::new())]),
                HashMap::new(),
                BTreeMap::new(),
                HashMap::new(),
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeMap::new(),
                pending.iter().copied().collect(),
            ))
        };
        let in_window_four = WeightedTimestamp::from_millis(4_500);

        // The fold of 4 publishes its projection of 5, with the root's
        // split pending.
        let mut behind =
            TopologySchedule::new(EpochWindows::new(0, 1000), Epoch::new(4), snapshot());
        behind.insert_lookahead(Epoch::new(5), projecting_a_split(&[ShardId::ROOT]));
        assert!(behind.termination_scheduled(ShardId::ROOT, in_window_four));

        // The fold of 5 freezes window 5 with the split already cleared.
        // The replica that folded it answers for window 4 exactly as the
        // one that has not.
        let mut ahead = behind.clone();
        ahead.insert(Epoch::new(5), projecting_a_split(&[]));
        assert_eq!(
            ahead.termination_scheduled(ShardId::ROOT, in_window_four),
            behind.termination_scheduled(ShardId::ROOT, in_window_four),
        );

        // A projection is kept as first published: publishing window 5
        // again leaves the copy the forward question reads alone.
        ahead.insert_lookahead(Epoch::new(5), projecting_a_split(&[]));
        assert!(ahead.termination_scheduled(ShardId::ROOT, in_window_four));

        // Eviction takes the kept copy with the window.
        ahead.evict_below(Epoch::new(6));
        assert!(!ahead.termination_scheduled(ShardId::ROOT, in_window_four));
    }

    #[test]
    fn epoch_for_floors_to_window() {
        let sched = TopologySchedule::new(EpochWindows::new(0, 1000), Epoch::new(5), snapshot());
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
            sched
                .snapshot_at(WeightedTimestamp::from_millis(42))
                .unwrap()
        ));
    }

    #[test]
    fn at_returns_none_for_epochs_outside_the_window() {
        // The window holds the active epoch 5 and its lookahead 6.
        let mut sched =
            TopologySchedule::new(EpochWindows::new(0, 1000), Epoch::new(5), snapshot());
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
        let mut sched =
            TopologySchedule::new(EpochWindows::new(0, 1000), Epoch::new(5), snapshot());
        sched.insert(Epoch::new(6), snapshot());
        assert!(matches!(
            sched.lookup(WeightedTimestamp::from_millis(5500)),
            WindowLookup::Window(_)
        ));
        assert!(matches!(
            sched.lookup(WeightedTimestamp::from_millis(7500)),
            WindowLookup::NotYetCommitted
        ));
        assert!(matches!(
            sched.lookup(WeightedTimestamp::from_millis(3500)),
            WindowLookup::Evicted
        ));
    }

    /// Only an epoch below every retained entry is evicted; one missing
    /// between two retained entries, or above them, is not.
    #[test]
    fn an_epoch_is_evicted_only_below_the_oldest_retained() {
        let mut sched =
            TopologySchedule::new(EpochWindows::new(0, 1000), Epoch::new(4), snapshot());
        sched.insert(Epoch::new(8), snapshot());
        assert!(sched.evicted(WeightedTimestamp::from_millis(3500)));
        assert!(!sched.evicted(WeightedTimestamp::from_millis(4500)));
        assert!(!sched.evicted(WeightedTimestamp::from_millis(6500)));
        assert!(!sched.evicted(WeightedTimestamp::from_millis(9500)));
    }

    #[test]
    fn evict_below_drops_only_epochs_below_the_floor() {
        let mut sched =
            TopologySchedule::new(EpochWindows::new(0, 1000), Epoch::new(4), snapshot());
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
        // Windows 5 and 6 carry the parent with p's split admitted. The
        // fold opening window 5 met the readiness gate and scheduled the
        // cut at 6, so window 6 is the first entry carrying it; the fold
        // at 6 applies the split and window 7 carries the children.
        let mut sched = TopologySchedule::new(
            EpochWindows::new(0, 1000),
            Epoch::new(5),
            reshape_snap(&[p, sibling], &[p], &[], &[]),
        );
        sched.insert(
            Epoch::new(6),
            reshape_snap(&[p, sibling], &[p], &[], &[(p, 6)]),
        );
        sched.insert(
            Epoch::new(7),
            reshape_snap(&[left, right, sibling], &[], &[], &[]),
        );

        // Window 5: no cut scheduled at its end — not the final epoch.
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
        // Window 6's answer never needed window 7. A schedule whose
        // newest entry *is* the final window — a proposer that has not
        // yet seen the fold opening window 7 — answers identically, so
        // it never waits on that fold.
        let truncated = TopologySchedule::new(
            EpochWindows::new(0, 1000),
            Epoch::new(6),
            reshape_snap(&[p, sibling], &[p], &[], &[(p, 6)]),
        );
        assert_eq!(
            truncated.split_at_next_boundary(p, WeightedTimestamp::from_millis(6500)),
            SplitAtBoundary::Children(left, right)
        );
        assert_eq!(
            truncated.terminates_at_next_boundary(p, WeightedTimestamp::from_millis(6500)),
            Some(true)
        );
        // And a shard with no scheduled cut is answered just as
        // definitively from the same truncated view.
        assert_eq!(
            truncated.split_at_next_boundary(sibling, WeightedTimestamp::from_millis(6500)),
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
        let mut sched = TopologySchedule::new(
            EpochWindows::new(0, 1000),
            Epoch::new(5),
            reshape_snap(&[p, sibling], &[p], &[], &[]),
        );
        sched.insert(
            Epoch::new(6),
            reshape_snap(&[p, sibling], &[p], &[], &[(p, 6)]),
        );
        sched.insert(
            Epoch::new(7),
            reshape_snap(&[left, right, sibling], &[], &[], &[]),
        );

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

    /// An anchor exactly on a boundary reads its draining shards off the
    /// closing window, the one its cut is read from, and an anchor past
    /// it reads them off the window it opens.
    #[test]
    fn a_boundary_instant_anchor_reads_reshaping_off_the_closing_window() {
        let p = ShardId::leaf(1, 0);
        let sibling = ShardId::leaf(1, 1);
        let mut sched = TopologySchedule::new(
            EpochWindows::new(0, 1000),
            Epoch::new(5),
            reshape_snap(&[p, sibling], &[p], &[], &[]),
        );
        sched.insert(
            Epoch::new(6),
            Arc::new(
                Arc::unwrap_or_clone(reshape_snap(&[p, sibling], &[p], &[], &[]))
                    .with_draining(BTreeMap::from([(p, Epoch::new(4))])),
            ),
        );

        let reshaping = |ms: u64| {
            sched
                .reshaping_at(WeightedTimestamp::from_millis(ms))
                .expect("both windows are held")
                .contains(p)
        };
        assert!(!reshaping(5_500), "window 5 shows no latch");
        assert!(
            !reshaping(6_000),
            "an anchor on window 6's opening instant reads window 5",
        );
        assert!(
            reshaping(6_001),
            "an anchor inside window 6 reads its latch"
        );
        assert!(
            !sched
                .reshaping_at(WeightedTimestamp::from_millis(6_001))
                .expect("window 6 is held")
                .contains(sibling)
        );
    }

    /// The past-terminal flag reads a boundary instant as the carry
    /// predicates do: an anchor exactly on the cut resolves the final
    /// window's committee and is not past it; anything later is.
    #[test]
    fn boundary_instant_anchor_is_not_past_the_terminal() {
        let p = ShardId::leaf(1, 0);
        let sibling = ShardId::leaf(1, 1);
        let (left, right) = p.children();
        let final_window = reshape_snap(&[p, sibling], &[p], &[], &[(p, 6)]);
        let mut sched = TopologySchedule::new(
            EpochWindows::new(0, 1000),
            Epoch::new(5),
            reshape_snap(&[p, sibling], &[p], &[], &[]),
        );
        sched.insert(Epoch::new(6), Arc::clone(&final_window));
        sched.insert(
            Epoch::new(7),
            reshape_snap(&[left, right, sibling], &[], &[], &[]),
        );

        let on_cut = sched
            .at_for_shard(p, WeightedTimestamp::from_millis(7000))
            .expect("the final window is retained");
        assert!(Arc::ptr_eq(on_cut.0, &final_window));
        assert!(!on_cut.1);
        assert!(!sched.past_terminal(p, WeightedTimestamp::from_millis(7000)));
        let past = sched
            .at_for_shard(p, WeightedTimestamp::from_millis(7001))
            .expect("the final window is retained");
        assert!(Arc::ptr_eq(past.0, &final_window));
        assert!(past.1);
        // A shard alive in the next window is never past a cut.
        assert!(!sched.past_terminal(sibling, WeightedTimestamp::from_millis(7000)));
    }

    /// A pending split with no cut scheduled at this window's end is
    /// answered `No`, definitively, without the next window — an
    /// admitted reshape no longer makes the boundary unknowable. Only a
    /// window the schedule doesn't hold at all defers.
    #[test]
    fn split_at_next_boundary_never_defers_on_a_pending_reshape() {
        let p = ShardId::leaf(1, 0);
        let sibling = ShardId::leaf(1, 1);
        // Window 6 is the newest committed entry and p's split is
        // admitted but unscheduled — the fold opening window 7 cannot
        // schedule a cut at 6's end, so its absence changes nothing.
        let sched = TopologySchedule::new(
            EpochWindows::new(0, 1000),
            Epoch::new(6),
            reshape_snap(&[p, sibling], &[p], &[], &[]),
        );

        assert_eq!(
            sched.split_at_next_boundary(p, WeightedTimestamp::from_millis(6500)),
            SplitAtBoundary::No
        );
        assert_eq!(
            sched.terminates_at_next_boundary(p, WeightedTimestamp::from_millis(6500)),
            Some(false)
        );
        assert_eq!(
            sched.split_at_next_boundary(sibling, WeightedTimestamp::from_millis(6500)),
            SplitAtBoundary::No
        );
        // A window the schedule doesn't hold is the one remaining defer.
        assert_eq!(
            sched.split_at_next_boundary(p, WeightedTimestamp::from_millis(2500)),
            SplitAtBoundary::Unresolved
        );
    }

    /// The cut a departed shard's chain ended at is the end of the last
    /// window that carried it, and it reads the same from anywhere past
    /// it — which is what lets a consumer record it once and stop
    /// depending on the window that proves it.
    #[test]
    fn terminal_cut_is_the_end_of_the_last_window_carrying_the_shard() {
        let p = ShardId::leaf(1, 0);
        let sibling = ShardId::leaf(1, 1);
        let (left, right) = p.children();
        let mut sched = TopologySchedule::new(
            EpochWindows::new(0, 1000),
            Epoch::new(6),
            reshape_snap(&[p, sibling], &[], &[], &[]),
        );
        sched.insert(
            Epoch::new(7),
            reshape_snap(&[left, right, sibling], &[], &[], &[]),
        );

        let cut = sched.windows().window_of(Epoch::new(6)).end;
        assert_eq!(
            sched.terminal_cut_for_shard(p, WeightedTimestamp::from_millis(7500)),
            Some(cut),
        );
        assert_eq!(
            sched.terminal_cut_for_shard(p, WeightedTimestamp::from_millis(7999)),
            Some(cut),
            "and does not move with where it is read from",
        );

        assert_eq!(
            sched.terminal_cut_for_shard(p, WeightedTimestamp::from_millis(6500)),
            None,
            "a shard still in its own window has no terminal to read",
        );
        assert_eq!(
            sched.terminal_cut_for_shard(sibling, WeightedTimestamp::from_millis(7500)),
            None,
            "nor does one that outlived the window under test",
        );
    }

    #[test]
    fn at_for_shard_clamps_past_the_terminal_window() {
        let p = ShardId::leaf(1, 0);
        let sibling = ShardId::leaf(1, 1);
        let (left, right) = p.children();
        // p's final window is 6; window 7 carries its children.
        let mut sched = TopologySchedule::new(
            EpochWindows::new(0, 1000),
            Epoch::new(6),
            reshape_snap(&[p, sibling], &[], &[], &[]),
        );
        sched.insert(
            Epoch::new(7),
            reshape_snap(&[left, right, sibling], &[], &[], &[]),
        );

        // Alive in its window: plain `at` plus `false`.
        let (in_window, past) = sched
            .at_for_shard(p, WeightedTimestamp::from_millis(6500))
            .unwrap();
        assert!(!past);
        assert!(Arc::ptr_eq(
            in_window,
            sched
                .snapshot_at(WeightedTimestamp::from_millis(6500))
                .unwrap()
        ));

        // Past the cut: clamps to the terminal window's snapshot and flags it.
        let (clamped, past) = sched
            .at_for_shard(p, WeightedTimestamp::from_millis(7500))
            .unwrap();
        assert!(past);
        assert!(Arc::ptr_eq(
            clamped,
            sched
                .snapshot_at(WeightedTimestamp::from_millis(6500))
                .unwrap()
        ));

        // The live resolution names the terminal window's epoch, and that
        // epoch resolves the same window back.
        let Some(live) = sched
            .live_committee(p, WeightedTimestamp::from_millis(7500))
            .committee()
        else {
            panic!("the terminal window resolves");
        };
        assert!(live.past_terminal);
        assert_eq!(live.epoch, Epoch::new(6));
        assert!(Arc::ptr_eq(
            live.snapshot,
            sched
                .signed_committee(p, Epoch::new(6))
                .committee()
                .unwrap()
                .snapshot
        ));
        // Window 7 no longer carries p, so no resolution keys p there.
        assert!(matches!(
            sched.signed_committee(p, Epoch::new(7)),
            BlockResolution::Evicted
        ));
        assert!(matches!(
            sched.signed_committee(p, Epoch::new(9)),
            BlockResolution::NotYetCommitted
        ));

        // A shard alive in the same window is untouched by the clamp.
        let (alive, past) = sched
            .at_for_shard(sibling, WeightedTimestamp::from_millis(7500))
            .unwrap();
        assert!(!past);
        assert!(Arc::ptr_eq(
            alive,
            sched
                .snapshot_at(WeightedTimestamp::from_millis(7500))
                .unwrap()
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
        use crate::ValidatorInfo;

        let validators: Vec<ValidatorInfo> = (0..4)
            .map(|i| ValidatorInfo {
                validator_id: ValidatorId::new(i),
                public_key: BlsSigner::generate().public_key(),
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
        let mut sched =
            TopologySchedule::new(EpochWindows::new(0, 1000), Epoch::new(0), Arc::clone(&pre));
        sched.insert(Epoch::new(1), Arc::clone(&post));
        sched.set_head(Epoch::new(1), post);

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
        use crate::ValidatorInfo;

        let validators: Vec<ValidatorInfo> = (0..12)
            .map(|i| ValidatorInfo {
                validator_id: ValidatorId::new(i),
                public_key: BlsSigner::generate().public_key(),
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
                std::iter::once((recovering, halt_recovery(2, &retained))).collect(),
            ),
        );
        let sched =
            TopologySchedule::new(EpochWindows::new(0, 1000), Epoch::new(3), Arc::clone(&head));

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

    /// A shard whose chain has not crossed out of a window keeps that
    /// window's committee routable after the head rotates past it: the
    /// departing member is still needed to certify the crossing block.
    /// Once the beacon folds the crossing, the entry is the head committee.
    #[test]
    fn routing_committees_keep_a_window_the_chain_has_not_crossed_out_of() {
        use crate::ValidatorInfo;

        let validators: Vec<ValidatorInfo> = (0..5)
            .map(|i| ValidatorInfo {
                validator_id: ValidatorId::new(i),
                public_key: BlsSigner::generate().public_key(),
            })
            .collect();
        let set = ValidatorSet::new(validators);
        let shard = ShardId::ROOT;
        let departing = ValidatorId::new(0);
        let outgoing: Vec<ValidatorId> = (0..4).map(ValidatorId::new).collect();
        let incoming: Vec<ValidatorId> = (1..5).map(ValidatorId::new).collect();
        let committee = |members: &[ValidatorId]| {
            TopologySnapshot::with_shard_committees(
                NetworkDefinition::simulator(),
                1,
                &set,
                std::iter::once((shard, members.to_vec())).collect(),
            )
        };
        let crossed_at = |wt: u64| {
            std::iter::once((
                shard,
                ShardAnchor {
                    state_root: terminal_root(shard),
                    block_hash: BlockHash::from_raw(Hash::from_bytes(b"crossing")),
                    height: BlockHeight::new(7),
                    weighted_timestamp: WeightedTimestamp::from_millis(wt),
                    witness_base: BeaconWitnessLeafCount::ZERO,
                    terminal_settled_txs: None,
                    handoff_complete: None,
                    terminal_epoch: None,
                },
            ))
            .collect()
        };
        let routing_with_crossing_at = |wt: u64| {
            let head = Arc::new(committee(&incoming).with_boundaries(crossed_at(wt)));
            let mut sched = TopologySchedule::new(EpochWindows::new(0, 1000), Epoch::new(4), head);
            sched.insert(Epoch::new(3), Arc::new(committee(&outgoing)));
            sched.routing_committees()
        };

        let lagging = routing_with_crossing_at(2500);
        let entry = lagging.get(&shard).expect("the shard routes");
        assert!(
            entry.contains(&departing),
            "a chain still in window 3 keeps window 3's committee",
        );
        assert_eq!(entry.len(), 5, "no duplicate entries");

        let crossed = routing_with_crossing_at(3500);
        assert_eq!(
            crossed.get(&shard),
            Some(&incoming),
            "a folded crossing out of window 3 leaves the head committee",
        );
    }

    /// The recovery bridge: live work anchored below the bridge resolves
    /// the fresh committee (the halted one resolves itself out of
    /// authority), while a QC is admitted under the epoch its signers
    /// signed — the halted suffix under the windows that produced it, a
    /// bridge block under the fresh committee's. Without a pending
    /// recovery both resolutions are the plain anchor lookup.
    #[test]
    fn recovery_bridge_splits_live_and_admitted_resolution() {
        use crate::ValidatorInfo;

        let validators: Vec<ValidatorInfo> = (0..8)
            .map(|i| ValidatorInfo {
                validator_id: ValidatorId::new(i),
                public_key: BlsSigner::generate().public_key(),
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
        let fresh_snap =
            Arc::new(snap(&fresh).as_ref().clone().with_pending_recoveries(
                std::iter::once((shard, halt_recovery(20, &old))).collect(),
            ));
        let mut sched = TopologySchedule::new(
            EpochWindows::new(0, 1000),
            Epoch::new(2),
            Arc::clone(&old_snap),
        );
        sched.insert(Epoch::new(21), Arc::clone(&fresh_snap));
        sched.set_head(Epoch::new(21), Arc::clone(&fresh_snap));

        let committee_of = |lookup: ScheduleLookup<'_>| match lookup {
            ScheduleLookup::Committee(snapshot) => snapshot.committee_for_shard(shard).to_vec(),
            _ => panic!("expected a resolved committee"),
        };
        let stale_anchor = WeightedTimestamp::from_millis(2_500);
        let suffix_qc = WeightedTimestamp::from_millis(2_900);
        let bridge_qc = WeightedTimestamp::from_millis(21_100);
        // Stamped in the seating epoch, where the windows overlap.
        let edge_qc = WeightedTimestamp::from_millis(20_900);
        let (raw, bridged) = (Epoch::new(2), Epoch::new(21));

        // Live work at the stale anchor binds to the fresh committee. Each
        // window is keyed once, so `members_of` resolving the epoch back
        // to the same window pins the epoch too.
        assert_eq!(
            members_of(&sched, shard, sched.live_committee(shard, stale_anchor)),
            fresh,
        );
        // The plain anchor lookup is untouched — historical resolution.
        assert_eq!(
            committee_of(sched.lookup_for_shard(shard, stale_anchor).0),
            old,
        );
        // A suffix block — signed while the old committee governed — keeps
        // verifying against it.
        assert_eq!(
            admitted(
                &sched,
                shard,
                sched.admits(shard, stale_anchor, suffix_qc, raw)
            ),
            old,
        );
        // A bridge block — signed under the bridge — verifies against the
        // fresh committee, stamped in the seating epoch or past it.
        for qc_wt in [bridge_qc, edge_qc] {
            assert_eq!(
                admitted(
                    &sched,
                    shard,
                    sched.admits(shard, stale_anchor, qc_wt, bridged)
                ),
                fresh,
            );
        }
        // Current anchors resolve normally on both paths.
        assert_eq!(
            members_of(&sched, shard, sched.live_committee(shard, bridge_qc)),
            fresh,
        );

        // The fence refuses what the pending recovery replaced, whatever
        // the stamp, and admits the fresh committee's epochs.
        assert!(!sched.fence_admits(shard, raw));
        assert!(sched.fence_admits(shard, bridged));
        assert!(sched.fence_admits(shard, Epoch::new(25)));
        assert!(matches!(
            sched.admits_fenced(shard, stale_anchor, suffix_qc, raw),
            QcAdmission::Fenced
        ));
        assert_eq!(
            admitted(
                &sched,
                shard,
                sched.admits_fenced(shard, stale_anchor, bridge_qc, bridged)
            ),
            fresh,
        );
        assert!(sched.replaced(shard, raw));

        // Without the recovery record, the live path is the plain lookup
        // and the fence is inert.
        let mut plain = TopologySchedule::new(
            EpochWindows::new(0, 1000),
            Epoch::new(2),
            Arc::clone(&old_snap),
        );
        plain.insert(Epoch::new(21), snap(&fresh));
        assert_eq!(
            members_of(&plain, shard, plain.live_committee(shard, stale_anchor)),
            old,
        );
        assert!(plain.fence_admits(shard, raw));
        assert!(!plain.replaced(shard, raw));
    }

    /// The seating-epoch forgery: a retained committee beyond f certifies
    /// an orphan extending the halted tip under the window it was seated
    /// in, and sets the stamp inside the epoch the recovery was seated, the
    /// one where the raw and bridged intervals meet. The interval admits
    /// it; the fence refuses it whatever the stamp. In the chained case the
    /// first fresh committee, retained by the second recovery, states the
    /// first bridge and stamps in the second seating epoch: refused
    /// against the pending second bridge.
    #[test]
    fn a_retained_quorum_stamped_in_the_seating_epoch_is_fenced() {
        let (set, old, fresh) = recovery_committees();
        let shard = BOUNDED;
        let snap =
            |committee: &[ValidatorId], history: Vec<RecoveryBinding>, pending: Option<u64>| {
                let mut snapshot = seating(&set, committee, None)
                    .with_recoveries(std::iter::once((shard, history)).collect());
                if let Some(rotated_at) = pending {
                    snapshot = snapshot.with_pending_recoveries(
                        std::iter::once((shard, halt_recovery(rotated_at, committee))).collect(),
                    );
                }
                Arc::new(snapshot)
            };
        let binding = |rotated_at: u64, completed: bool| RecoveryBinding {
            rotated_at: Epoch::new(rotated_at),
            attested_frontier: BlockHeight::GENESIS,
            completed,
        };
        let at = |ms: u64| WeightedTimestamp::from_millis(ms);
        let stale_anchor = at(2_500);

        // Single: seated at 20, bridge 21.
        let head = snap(&fresh, vec![binding(20, false)], Some(20));
        let mut single = TopologySchedule::new(
            EpochWindows::new(0, 1000),
            Epoch::new(2),
            snap(&old, vec![], None),
        );
        single.insert(Epoch::new(21), Arc::clone(&head));
        single.set_head(Epoch::new(20), head);
        for stamp in [at(20_100), at(20_900)] {
            assert_eq!(
                admitted(
                    &single,
                    shard,
                    single.admits(shard, stale_anchor, stamp, Epoch::new(2))
                ),
                old,
                "the interval admits a raw QC stamped in the seating epoch",
            );
            assert!(matches!(
                single.admits_fenced(shard, stale_anchor, stamp, Epoch::new(2)),
                QcAdmission::Fenced
            ));
        }

        // Chained: first seated at 20 (bridge 21), second at 40 (bridge
        // 41), pending. The first fresh committee states 21.
        let head = snap(&old, vec![binding(20, false), binding(40, false)], Some(40));
        let mut chained = TopologySchedule::new(
            EpochWindows::new(0, 1000),
            Epoch::new(2),
            snap(&old, vec![], None),
        );
        chained.insert(
            Epoch::new(21),
            snap(&fresh, vec![binding(20, false)], Some(20)),
        );
        chained.insert(Epoch::new(41), Arc::clone(&head));
        chained.set_head(Epoch::new(40), head);
        let seating_stamp = at(40_500);
        assert_eq!(
            admitted(
                &chained,
                shard,
                chained.admits(shard, stale_anchor, seating_stamp, Epoch::new(21))
            ),
            fresh,
            "the interval admits the first bridge at the second seating epoch",
        );
        assert!(matches!(
            chained.admits_fenced(shard, stale_anchor, seating_stamp, Epoch::new(21)),
            QcAdmission::Fenced
        ));
        // The second fresh committee, here the original one redrawn at
        // its own indexes, states the second bridge and passes.
        assert_eq!(
            admitted(
                &chained,
                shard,
                chained.admits_fenced(shard, stale_anchor, seating_stamp, Epoch::new(41))
            ),
            old,
        );
    }

    /// Every interval and boundary of the rule: no bindings, one, and two,
    /// with the second fresh committee the original one redrawn at the
    /// same indexes.
    #[test]
    fn admits_the_epoch_honest_voters_sign() {
        let (set, old, fresh) = recovery_committees();
        let shard = BOUNDED;
        let window = |committee: &[ValidatorId], history: &[u64]| {
            Arc::new(
                seating(&set, committee, None).with_recoveries(
                    std::iter::once((
                        shard,
                        history
                            .iter()
                            .map(|rotated_at| RecoveryBinding {
                                rotated_at: Epoch::new(*rotated_at),
                                attested_frontier: BlockHeight::GENESIS,
                                completed: true,
                            })
                            .collect(),
                    ))
                    .collect(),
                ),
            )
        };
        let at = |epoch: u64| WeightedTimestamp::from_millis(epoch * 1_000 + 500);
        let anchor = at(2);
        let schedule = |history: &[u64]| {
            let mut sched =
                TopologySchedule::new(EpochWindows::new(0, 1000), Epoch::new(2), window(&old, &[]));
            sched.insert(
                Epoch::new(21),
                window(&fresh, &history[..1.min(history.len())]),
            );
            sched.insert(Epoch::new(41), window(&old, history));
            sched.set_head(Epoch::new(50), window(&old, history));
            sched
        };
        let admits = |sched: &TopologySchedule, stamp: u64, epoch: u64| match sched.admits(
            shard,
            anchor,
            at(stamp),
            Epoch::new(epoch),
        ) {
            QcAdmission::Admit(committee) => Some(committee.epoch.inner()),
            QcAdmission::Refuse => None,
            QcAdmission::Wait | QcAdmission::Fenced => panic!("a head at 50 decides"),
        };

        // No bindings: only raw, at any stamp.
        let none = schedule(&[]);
        for stamp in [2, 20, 30] {
            assert_eq!(admits(&none, stamp, 2), Some(2));
            assert_eq!(admits(&none, stamp, 21), None);
        }

        // One binding seated at 20: raw through 20, bridged from 20.
        let one = schedule(&[20]);
        assert_eq!(admits(&one, 19, 2), Some(2));
        assert_eq!(admits(&one, 20, 2), Some(2));
        assert_eq!(admits(&one, 21, 2), None);
        assert_eq!(admits(&one, 19, 21), None);
        assert_eq!(admits(&one, 20, 21), Some(21));
        assert_eq!(admits(&one, 45, 21), Some(21));

        // Two bindings, seated at 20 and 40: raw through 20, the first
        // bridge 20 through 40, the second from 40. The second fresh
        // committee is the original at its own indexes, but its window is
        // keyed 41, so the epoch tells it from raw.
        let two = schedule(&[20, 40]);
        assert_eq!(admits(&two, 20, 2), Some(2));
        assert_eq!(admits(&two, 21, 2), None);
        assert_eq!(admits(&two, 20, 21), Some(21));
        assert_eq!(admits(&two, 40, 21), Some(21));
        assert_eq!(admits(&two, 41, 21), None);
        assert_eq!(admits(&two, 39, 41), None);
        assert_eq!(admits(&two, 40, 41), Some(41));
        assert_eq!(admits(&two, 45, 41), Some(41));
    }

    /// A verifier whose beacon has not reached a QC's stamp waits rather
    /// than refusing: a binding seated by then may be one it has yet to
    /// fold. Once its head reaches the stamp the same QC is decided.
    #[test]
    fn a_lagging_verifier_waits_for_the_binding() {
        let (set, old, fresh) = recovery_committees();
        let shard = BOUNDED;
        let anchor = WeightedTimestamp::from_millis(2_500);
        let stamp = WeightedTimestamp::from_millis(21_100);
        // A head at 5 that has folded no recovery.
        let mut lagging = TopologySchedule::new(
            EpochWindows::new(0, 1000),
            Epoch::new(5),
            Arc::new(seating(&set, &old, None)),
        );
        lagging.insert(Epoch::new(2), Arc::new(seating(&set, &old, None)));
        assert!(matches!(
            lagging.admits(shard, anchor, stamp, Epoch::new(21)),
            QcAdmission::Wait
        ));
        // Caught up, with the recovery folded: admitted.
        let head =
            Arc::new(seating(&set, &fresh, None).with_pending_recoveries(
                std::iter::once((shard, halt_recovery(20, &old))).collect(),
            ));
        let mut caught_up = lagging.clone();
        caught_up.insert(Epoch::new(21), Arc::clone(&head));
        caught_up.set_head(Epoch::new(21), head);
        assert_eq!(
            admitted(
                &caught_up,
                shard,
                caught_up.admits(shard, anchor, stamp, Epoch::new(21))
            ),
            fresh,
        );
        // A head past the stamp that holds no binding placing it refuses.
        let mut decided = lagging;
        decided.set_head(Epoch::new(30), Arc::new(seating(&set, &old, None)));
        assert!(matches!(
            decided.admits(shard, anchor, stamp, Epoch::new(21)),
            QcAdmission::Refuse
        ));
    }

    /// The window every role resolves for a block of `shard` whose
    /// committee anchor is `anchor`, certified with stamp `stamp`: built
    /// and voted under `live`, its QC verified and the block folded under
    /// `verifier`. Panics where two roles part.
    fn agree(
        live: &TopologySchedule,
        verifier: &TopologySchedule,
        shard: ShardId,
        anchor: WeightedTimestamp,
        stamp: WeightedTimestamp,
    ) -> (Epoch, Vec<ValidatorId>) {
        let members =
            |committee: BlockCommittee<'_>| committee.snapshot.committee_for_shard(shard).to_vec();
        let proposed = live
            .live_committee(shard, anchor)
            .committee()
            .expect("the proposer resolves its committee");
        let signed = proposed.epoch;
        let QcAdmission::Admit(checked) = verifier.admits(shard, anchor, stamp, signed) else {
            panic!("the verifier refuses {signed:?} at {anchor:?} stamped {stamp:?}");
        };
        let folded = verifier
            .signed_committee(shard, signed)
            .committee()
            .expect("the fold resolves the signed window");
        assert_eq!((checked.epoch, folded.epoch), (signed, signed));
        assert!(Arc::ptr_eq(checked.snapshot, folded.snapshot));
        assert_eq!(members(checked), members(proposed));
        (signed, members(folded))
    }

    /// [`proposer_voter_and_fold_resolve_one_committee`] across a reshape:
    /// a block whose cut lies between its anchors, and a split child's
    /// first block. Window 0 runs the root whole, window 1 its children.
    #[test]
    fn proposer_voter_and_fold_resolve_one_committee_across_a_reshape() {
        let (set, old, fresh) = recovery_committees();
        let at = |ms: u64| WeightedTimestamp::from_millis(ms);
        let (left, right) = ShardId::ROOT.children();
        let whole = Arc::new(TopologySnapshot::with_shard_committees(
            NetworkDefinition::simulator(),
            1,
            &set,
            std::iter::once((ShardId::ROOT, old.clone())).collect(),
        ));
        let split = Arc::new(TopologySnapshot::with_shard_committees(
            NetworkDefinition::simulator(),
            2,
            &set,
            [(left, fresh.clone()), (right, old.clone())]
                .into_iter()
                .collect(),
        ));
        let mut reshaped = TopologySchedule::new(EpochWindows::new(0, 1000), Epoch::new(0), whole);
        reshaped.insert(Epoch::new(1), Arc::clone(&split));
        reshaped.set_head(Epoch::new(1), split);
        assert_eq!(
            agree(&reshaped, &reshaped, ShardId::ROOT, at(900), at(1_100)),
            (Epoch::new(0), old),
            "a block whose own anchor lies past the cut",
        );
        assert_eq!(
            agree(&reshaped, &reshaped, left, at(1_100), at(1_200)),
            (Epoch::new(1), fresh),
            "the split child's first block",
        );
    }

    /// The committee a block's proposer builds under and its voters sign
    /// (the live committee at its committee anchor, whose epoch the votes
    /// carry), the one a verifier admits its QC under, and the one the
    /// commit fold classifies it under (the window that epoch keys) are
    /// one window, each read under the schedule that role holds when it
    /// runs: before a recovery folds, after, or lagging behind it.
    #[test]
    fn proposer_voter_and_fold_resolve_one_committee() {
        let (set, old, fresh) = recovery_committees();
        let shard = BOUNDED;
        let at = |ms: u64| WeightedTimestamp::from_millis(ms);
        let binding = |rotated_at: u64| RecoveryBinding {
            rotated_at: Epoch::new(rotated_at),
            attested_frontier: BlockHeight::GENESIS,
            completed: false,
        };
        let window = |committee: &[ValidatorId], history: Vec<RecoveryBinding>| {
            Arc::new(
                seating(&set, committee, None)
                    .with_recoveries(std::iter::once((shard, history)).collect()),
            )
        };

        // A halt recovery: T anchored in window 2 and certified there
        // before the recovery folds; X1 and X2, whose committee anchor is
        // T's own, built by the fresh committee seated at 20 (bridge 21).
        let mut halted = TopologySchedule::new(
            EpochWindows::new(0, 1000),
            Epoch::new(2),
            window(&old, vec![]),
        );
        halted.set_head(Epoch::new(3), window(&old, vec![]));
        let mut recovered = halted.clone();
        let seated = Arc::new(
            window(&fresh, vec![binding(20)])
                .as_ref()
                .clone()
                .with_pending_recoveries(
                    std::iter::once((shard, halt_recovery(20, &old))).collect(),
                ),
        );
        recovered.insert(Epoch::new(21), Arc::clone(&seated));
        recovered.set_head(Epoch::new(21), seated);
        let t = agree(&halted, &recovered, shard, at(2_400), at(2_900));
        assert_eq!(t, (Epoch::new(2), old.clone()), "T");
        for (block, stamp) in [("X1", at(20_500)), ("X2", at(21_100))] {
            assert_eq!(
                agree(&recovered, &recovered, shard, at(2_900), stamp),
                (Epoch::new(21), fresh.clone()),
                "{block}",
            );
        }

        // A chained recovery whose second draw seats the original
        // committee at its own indexes: the stalled chain's next block,
        // anchored in window 2, takes the second bridge's window, never
        // window 2, though both seat the same members.
        let mut first = TopologySchedule::new(
            EpochWindows::new(0, 1000),
            Epoch::new(2),
            window(&old, vec![]),
        );
        let first_fresh = window(&fresh, vec![binding(20)]);
        first.insert(Epoch::new(21), Arc::clone(&first_fresh));
        first.set_head(Epoch::new(21), first_fresh);
        let mut chained = first.clone();
        let redrawn = window(&old, vec![binding(20), binding(40)]);
        chained.insert(Epoch::new(41), Arc::clone(&redrawn));
        chained.set_head(Epoch::new(41), redrawn);
        assert_eq!(
            agree(&chained, &chained, shard, at(2_900), at(41_100)),
            (Epoch::new(41), old.clone()),
            "the redrawn committee",
        );
        assert_eq!(
            agree(&first, &chained, shard, at(21_500), at(21_900)),
            (Epoch::new(21), fresh.clone()),
            "the first fresh committee's own block, verified after the redraw",
        );

        // A verifier whose beacon lags the recovery waits, and once it
        // folds the recovery agrees with the fresh committee's voters.
        let mut lagging = halted;
        lagging.set_head(Epoch::new(5), window(&old, vec![]));
        assert!(matches!(
            lagging.admits(shard, at(2_900), at(21_100), Epoch::new(21)),
            QcAdmission::Wait
        ));
        let mut caught_up = lagging;
        let folded = recovered.head().clone();
        caught_up.insert(Epoch::new(21), Arc::clone(&folded));
        caught_up.set_head(Epoch::new(21), folded);
        assert_eq!(
            agree(&recovered, &caught_up, shard, at(2_900), at(21_100)),
            (Epoch::new(21), fresh),
        );
    }

    /// A fresh committee that certified in the epoch a re-draw was seated,
    /// before folding the re-draw, is still admitted once the verifier has
    /// folded it: the windows overlap at the seating epoch.
    #[test]
    fn a_qc_certified_in_the_redraw_epoch_is_admitted_after_the_fold() {
        let (set, old, fresh) = recovery_committees();
        let shard = BOUNDED;
        let binding = |rotated_at: u64| RecoveryBinding {
            rotated_at: Epoch::new(rotated_at),
            attested_frontier: BlockHeight::GENESIS,
            completed: true,
        };
        let window = |committee: &[ValidatorId], history: Vec<RecoveryBinding>| {
            Arc::new(
                seating(&set, committee, None)
                    .with_recoveries(std::iter::once((shard, history)).collect()),
            )
        };
        let mut sched = TopologySchedule::new(
            EpochWindows::new(0, 1000),
            Epoch::new(2),
            window(&old, vec![]),
        );
        sched.insert(Epoch::new(21), window(&fresh, vec![binding(20)]));
        let head = window(&old, vec![binding(20), binding(40)]);
        sched.insert(Epoch::new(41), Arc::clone(&head));
        sched.set_head(Epoch::new(41), head);
        assert_eq!(
            admitted(
                &sched,
                shard,
                sched.admits(
                    shard,
                    WeightedTimestamp::from_millis(2_500),
                    WeightedTimestamp::from_millis(40_700),
                    Epoch::new(21)
                )
            ),
            fresh,
        );
    }

    /// The replacement predicates: an anchor below the bridge is
    /// replaced, and a block is replaced-certified only when its QC's
    /// signers signed below the bridge — a bridge block, signed under the
    /// bridge, is the fresh committee's.
    #[test]
    fn committee_replacement_reads_the_signed_epoch() {
        use crate::ValidatorInfo;

        let validators: Vec<ValidatorInfo> = (0..8)
            .map(|i| ValidatorInfo {
                validator_id: ValidatorId::new(i),
                public_key: BlsSigner::generate().public_key(),
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
        let old_snap = snap(&old);
        let fresh_snap =
            Arc::new(snap(&fresh).as_ref().clone().with_pending_recoveries(
                std::iter::once((shard, halt_recovery(20, &old))).collect(),
            ));
        let mut sched = TopologySchedule::new(
            EpochWindows::new(0, 1000),
            Epoch::new(2),
            Arc::clone(&old_snap),
        );
        sched.insert(Epoch::new(21), Arc::clone(&fresh_snap));
        sched.set_head(Epoch::new(20), Arc::clone(&fresh_snap));

        let stale_anchor = WeightedTimestamp::from_millis(2_500);
        let bridge_qc = WeightedTimestamp::from_millis(21_100);

        // A tick anchored below the bridge is one the recovery replaced
        // the committee of, at any height; one anchored at it is not.
        assert!(sched.committee_replaced_for_anchored(shard, stale_anchor));
        assert!(!sched.committee_replaced_for_anchored(shard, bridge_qc));
        assert!(!sched.recovery_orphaned(shard, stale_anchor, BlockHeight::GENESIS));
        assert!(sched.recovery_orphaned(shard, stale_anchor, BlockHeight::new(1)));
        assert!(!sched.recovery_orphaned(shard, bridge_qc, BlockHeight::new(1)));

        assert!(
            sched.replaced(shard, Epoch::new(2)),
            "a suffix block is the replaced committee's"
        );
        assert!(
            sched.replaced(shard, Epoch::new(20)),
            "so is anything signed in the seating window"
        );
        for epoch in [21, 22] {
            assert!(
                !sched.replaced(shard, Epoch::new(epoch)),
                "a block signed under {epoch} is the fresh committee's",
            );
        }

        // Without a recovery nothing is replaced, whatever the anchor.
        let mut plain = TopologySchedule::new(
            EpochWindows::new(0, 1000),
            Epoch::new(2),
            Arc::clone(&old_snap),
        );
        plain.insert(Epoch::new(21), snap(&fresh));
        assert!(!plain.committee_replaced_for_anchored(shard, stale_anchor));
        assert!(!plain.recovery_orphaned(shard, stale_anchor, BlockHeight::new(1)));
        assert!(!plain.replaced(shard, Epoch::new(2)));
    }

    /// The epoch length the boundary fixtures below run at.
    fn boundary_epoch_ms() -> u64 {
        u64::try_from(EPOCH_DURATION.as_millis()).expect("fits")
    }

    /// The shard the boundary fixtures record a boundary for.
    const BOUNDED: ShardId = ShardId::leaf(1, 0);

    /// A boundary of [`BOUNDED`] at height 40, a second short of the
    /// close of epoch 4.
    fn recorded_boundary() -> ShardAnchor {
        ShardAnchor {
            state_root: StateRoot::from_raw(Hash::from_bytes(b"boundary")),
            block_hash: BlockHash::from_raw(Hash::from_bytes(b"boundary block")),
            height: BlockHeight::new(40),
            weighted_timestamp: WeightedTimestamp::from_millis(5 * boundary_epoch_ms() - 1_000),
            witness_base: BeaconWitnessLeafCount::ZERO,
            terminal_settled_txs: None,
            handoff_complete: None,
            terminal_epoch: None,
        }
    }

    /// A snapshot seating `committee` on [`BOUNDED`], recording
    /// `boundary` for it where one is given.
    fn seating(
        set: &ValidatorSet,
        committee: &[ValidatorId],
        boundary: Option<ShardAnchor>,
    ) -> TopologySnapshot {
        TopologySnapshot::with_shard_committees(
            NetworkDefinition::simulator(),
            2,
            set,
            std::iter::once((BOUNDED, committee.to_vec())).collect(),
        )
        .with_boundaries(
            boundary
                .map(|boundary| (BOUNDED, boundary))
                .into_iter()
                .collect(),
        )
    }

    /// Eight validators: the first four the committee a recovery
    /// replaces, the last four the one it seats.
    fn recovery_committees() -> (ValidatorSet, Vec<ValidatorId>, Vec<ValidatorId>) {
        use crate::ValidatorInfo;

        let validators: Vec<ValidatorInfo> = (0..8)
            .map(|i| ValidatorInfo {
                validator_id: ValidatorId::new(i),
                public_key: BlsSigner::generate().public_key(),
            })
            .collect();
        (
            ValidatorSet::new(validators),
            (0..4).map(ValidatorId::new).collect(),
            (4..8).map(ValidatorId::new).collect(),
        )
    }

    /// A recorded boundary is attested before its shard's recovery and
    /// after it alike, and the recovery fences nothing at its height: a
    /// reading taken there outlives the discard of everything above it.
    /// An anchor of the suffix the recovery discards is no boundary at
    /// any time, and another root at the boundary's height contradicts
    /// the record.
    #[test]
    fn a_boundary_anchor_stands_across_its_shards_recovery() {
        let (set, old, fresh) = recovery_committees();
        let epoch_ms = boundary_epoch_ms();
        let boundary = recorded_boundary();
        let at_boundary = boundary.anchor(BOUNDED);
        let suffix = Anchor {
            shard: BOUNDED,
            height: BlockHeight::new(41),
            state_root: StateRoot::from_raw(Hash::from_bytes(b"suffix")),
            ts: WeightedTimestamp::from_millis(5 * epoch_ms + 2_000),
        };
        let other_branch = Anchor {
            state_root: StateRoot::from_raw(Hash::from_bytes(b"other branch")),
            ..at_boundary
        };
        let redated = Anchor {
            ts: WeightedTimestamp::from_millis(5 * epoch_ms - 999),
            ..at_boundary
        };
        let below = Anchor {
            height: BlockHeight::new(39),
            ..suffix
        };

        let healthy = || Arc::new(seating(&set, &old, Some(boundary)));
        let mut before =
            TopologySchedule::new(EpochWindows::new(0, epoch_ms), Epoch::new(5), healthy());
        before.insert(Epoch::new(6), healthy());
        before.set_head(Epoch::new(6), healthy());

        let recovered = Arc::new(
            seating(&set, &fresh, Some(boundary)).with_pending_recoveries(
                std::iter::once((BOUNDED, halt_recovery_at(22, &old, boundary.height))).collect(),
            ),
        );
        let mut after = before.clone();
        after.insert(Epoch::new(23), Arc::clone(&recovered));
        after.set_head(Epoch::new(22), recovered);

        for (label, schedule) in [("before", &before), ("after", &after)] {
            assert_eq!(
                schedule.attests_boundary(&at_boundary),
                BoundaryAttestation::Stands,
                "{label}: the recorded boundary stands",
            );
            assert_eq!(
                schedule.attests_boundary(&suffix),
                BoundaryAttestation::Unknown,
                "{label}: an anchor above the boundary is none the beacon recorded",
            );
            assert!(
                schedule.above_held_boundaries(&suffix),
                "{label}: and could be one this schedule has yet to fold",
            );
            assert_eq!(
                schedule.attests_boundary(&below),
                BoundaryAttestation::Unknown
            );
            assert!(
                !schedule.above_held_boundaries(&below),
                "{label}: an anchor below a held boundary is one no fold will record",
            );
            for contradicting in [other_branch, redated] {
                assert_eq!(
                    schedule.attests_boundary(&contradicting),
                    BoundaryAttestation::Contradicted,
                    "{label}: another root or clock at the boundary's height",
                );
            }
        }
        assert!(!before.recovery_fences(BOUNDED, boundary.height));
        assert!(
            !after.recovery_fences(BOUNDED, boundary.height),
            "the recovery fences nothing at the boundary",
        );
        assert!(
            after.recovery_fences(BOUNDED, suffix.height),
            "and everything above it",
        );
    }

    /// A boundary is older than any fresh reading may be by the time a
    /// block can read it, and a schedule answers for it only while a
    /// window it holds records it.
    #[test]
    fn a_boundary_is_past_the_horizon_when_first_read_and_goes_with_its_window() {
        let (set, old, _) = recovery_committees();
        let epoch_ms = boundary_epoch_ms();
        let boundary = recorded_boundary();
        let at_boundary = boundary.anchor(BOUNDED);

        // The first block that can read the boundary is anchored in the
        // window after the one its crossing opened.
        let first_reader = WeightedTimestamp::from_millis(6 * epoch_ms);
        assert!(first_reader.elapsed_since(boundary.weighted_timestamp) > RETENTION_HORIZON);

        let recording = Arc::new(seating(&set, &old, Some(boundary)));
        let moved_on = Arc::new(seating(&set, &old, None));
        let mut schedule =
            TopologySchedule::new(EpochWindows::new(0, epoch_ms), Epoch::new(5), recording);
        schedule.insert(Epoch::new(6), Arc::clone(&moved_on));
        schedule.set_head(Epoch::new(6), moved_on);
        assert_eq!(
            schedule.attests_boundary(&at_boundary),
            BoundaryAttestation::Stands,
            "a window still held records it, though the head has moved on",
        );
        schedule.evict_below(Epoch::new(6));
        assert_eq!(
            schedule.attests_boundary(&at_boundary),
            BoundaryAttestation::Unknown,
        );
    }

    /// The record of a shard's terminal block is no boundary a claim
    /// stands at, in a window or at the head: no chain of that shard
    /// extends it, and the chain that succeeds it may start its clock
    /// below the terminal's. Its height is still one the schedule holds,
    /// so an anchor there is not one a fold to come could record. A
    /// boundary recorded for a shard scheduled to terminate, short of
    /// its terminal, stands as any other does.
    #[test]
    fn a_terminal_record_is_no_boundary_a_claim_stands_at() {
        let (set, old, _) = recovery_committees();
        let epoch_ms = boundary_epoch_ms();
        let scheduled = ShardAnchor {
            terminal_epoch: Some(Epoch::new(5)),
            ..recorded_boundary()
        };
        let terminal = ShardAnchor {
            state_root: StateRoot::from_raw(Hash::from_bytes(b"terminal")),
            block_hash: BlockHash::from_raw(Hash::from_bytes(b"terminal block")),
            height: BlockHeight::new(52),
            weighted_timestamp: WeightedTimestamp::from_millis(6 * epoch_ms + 100),
            terminal_settled_txs: Some(SettledTxsRoot::ZERO),
            ..scheduled
        };
        let last_window = Arc::new(seating(&set, &old, Some(scheduled)));
        let departed = Arc::new(seating(&set, &old, Some(terminal)));
        let mut schedule =
            TopologySchedule::new(EpochWindows::new(0, epoch_ms), Epoch::new(5), last_window);
        schedule.insert(Epoch::new(6), Arc::clone(&departed));
        schedule.set_head(Epoch::new(6), departed);

        assert_eq!(
            schedule.attests_boundary(&scheduled.anchor(BOUNDED)),
            BoundaryAttestation::Stands,
            "a boundary short of the terminal is one the chain extends",
        );
        let at_terminal = terminal.anchor(BOUNDED);
        assert_eq!(
            schedule.attests_boundary(&at_terminal),
            BoundaryAttestation::Unknown,
        );
        assert!(!schedule.above_held_boundaries(&at_terminal));
    }

    /// A tick resolves the committee its anchor names, before and after a
    /// recovery: one anchored below the bridge resolves the replaced
    /// committee at any height, and one anchored at or past it the fresh
    /// committee, the bridge window's own entry rather than the head.
    /// What the recovery replaced is told by the band alone: a tick
    /// anchored below the bridge is replaced whatever its height, and
    /// the band holds it above the frontier only. The answers read the
    /// same before and after the pending record clears, and are inert
    /// without a record.
    #[test]
    fn a_tick_anchored_below_a_bridge_resolves_the_committee_its_anchor_names() {
        use crate::ValidatorInfo;

        let validators: Vec<ValidatorInfo> = (0..12)
            .map(|i| ValidatorInfo {
                validator_id: ValidatorId::new(i),
                public_key: BlsSigner::generate().public_key(),
            })
            .collect();
        let set = ValidatorSet::new(validators);
        let shard = ShardId::leaf(1, 0);
        let old: Vec<ValidatorId> = (0..4).map(ValidatorId::new).collect();
        let fresh: Vec<ValidatorId> = (4..8).map(ValidatorId::new).collect();
        let shuffled: Vec<ValidatorId> = (8..12).map(ValidatorId::new).collect();
        let snap = |committee: &[ValidatorId]| {
            Arc::new(TopologySnapshot::with_shard_committees(
                NetworkDefinition::simulator(),
                2,
                &set,
                std::iter::once((shard, committee.to_vec())).collect(),
            ))
        };
        let frontier = BlockHeight::new(10);
        // The recovery seated the fresh committee at epoch 20 (bridge 21),
        // frozen at height 10.
        let pending = || {
            let fresh_snap = Arc::new(snap(&fresh).as_ref().clone().with_pending_recoveries(
                std::iter::once((shard, halt_recovery_at(20, &old, frontier))).collect(),
            ));
            let mut sched =
                TopologySchedule::new(EpochWindows::new(0, 1000), Epoch::new(2), snap(&old));
            sched.insert(Epoch::new(21), Arc::clone(&fresh_snap));
            sched.set_head(Epoch::new(20), fresh_snap);
            sched
        };
        // The same recovery once its first crossing cleared the pending
        // record, with a later shuffle in a newer entry.
        let completed = || {
            let completed = |committee: &[ValidatorId]| {
                Arc::new(
                    snap(committee).as_ref().clone().with_recoveries(
                        std::iter::once((
                            shard,
                            vec![RecoveryBinding {
                                rotated_at: Epoch::new(20),
                                attested_frontier: frontier,
                                completed: true,
                            }],
                        ))
                        .collect(),
                    ),
                )
            };
            let mut sched =
                TopologySchedule::new(EpochWindows::new(0, 1000), Epoch::new(2), snap(&old));
            sched.insert(Epoch::new(21), completed(&fresh));
            sched.insert(Epoch::new(23), completed(&shuffled));
            sched.set_head(Epoch::new(23), completed(&shuffled));
            sched
        };

        let committee_of = |lookup: (ScheduleLookup<'_>, bool)| match lookup {
            (ScheduleLookup::Committee(snapshot), false) => {
                snapshot.committee_for_shard(shard).to_vec()
            }
            _ => panic!("expected a resolved committee within the shard's windows"),
        };
        let stale_anchor = WeightedTimestamp::from_millis(2_500);
        let bridge_anchor = WeightedTimestamp::from_millis(21_100);
        let above = frontier.next();

        for (label, sched) in [("pending", pending()), ("completed", completed())] {
            for height in [frontier, above] {
                assert_eq!(
                    committee_of(sched.lookup_for_shard(shard, stale_anchor)),
                    old,
                    "{label}: a tick below the bridge resolves its anchor's committee",
                );
                assert!(
                    sched.committee_replaced_for_anchored(shard, stale_anchor),
                    "{label}: a tick below the bridge is replaced at any height",
                );
                assert_eq!(
                    sched.recovery_orphaned(shard, stale_anchor, height),
                    height > frontier,
                    "{label}: the band holds a tick below the bridge above the frontier",
                );
                assert_eq!(
                    committee_of(sched.lookup_for_shard(shard, bridge_anchor)),
                    fresh,
                    "{label}: a bridge-window anchor resolves its own committee",
                );
                assert!(!sched.committee_replaced_for_anchored(shard, bridge_anchor));
                assert!(!sched.recovery_orphaned(shard, bridge_anchor, height));
            }
        }

        // Without a record nothing is replaced or in a band.
        let mut plain =
            TopologySchedule::new(EpochWindows::new(0, 1000), Epoch::new(2), snap(&old));
        plain.insert(Epoch::new(21), snap(&fresh));
        for height in [frontier, above] {
            assert_eq!(
                committee_of(plain.lookup_for_shard(shard, stale_anchor)),
                old
            );
            assert!(!plain.committee_replaced_for_anchored(shard, stale_anchor));
            assert!(!plain.recovery_orphaned(shard, stale_anchor, height));
        }
    }

    /// The bridge binding outlives the pending record: once the recovery
    /// completes (pending record cleared, seating epoch in the completed
    /// map), a bridge block's QC is still admitted under the fresh
    /// committee — the bridge window's own entry, so a post-recovery
    /// shuffle landing in a later entry never re-binds it — while the
    /// suffix keeps its old committee, live work at a stale anchor keeps
    /// binding the fresh committee, and the pending-scoped fences go
    /// inert.
    #[test]
    fn recovery_bridge_binding_survives_the_pending_records_clear() {
        use crate::ValidatorInfo;

        let validators: Vec<ValidatorInfo> = (0..12)
            .map(|i| ValidatorInfo {
                validator_id: ValidatorId::new(i),
                public_key: BlsSigner::generate().public_key(),
            })
            .collect();
        let set = ValidatorSet::new(validators);
        let shard = ShardId::leaf(1, 0);
        let old: Vec<ValidatorId> = (0..4).map(ValidatorId::new).collect();
        let fresh: Vec<ValidatorId> = (4..8).map(ValidatorId::new).collect();
        let shuffled: Vec<ValidatorId> = (8..12).map(ValidatorId::new).collect();
        let snap = |committee: &[ValidatorId]| {
            Arc::new(TopologySnapshot::with_shard_committees(
                NetworkDefinition::simulator(),
                2,
                &set,
                std::iter::once((shard, committee.to_vec())).collect(),
            ))
        };
        let completed = |committee: &[ValidatorId]| {
            Arc::new(
                snap(committee).as_ref().clone().with_recoveries(
                    std::iter::once((
                        shard,
                        vec![RecoveryBinding {
                            rotated_at: Epoch::new(20),
                            attested_frontier: BlockHeight::GENESIS,
                            completed: true,
                        }],
                    ))
                    .collect(),
                ),
            )
        };

        // The recovery seated the fresh committee at epoch 20 (bridge 21);
        // its first crossing cleared the pending record, and a later fold
        // rotated the committee again in a newer entry.
        let mut sched =
            TopologySchedule::new(EpochWindows::new(0, 1000), Epoch::new(2), snap(&old));
        sched.insert(Epoch::new(21), completed(&fresh));
        sched.insert(Epoch::new(23), completed(&shuffled));
        sched.set_head(Epoch::new(23), completed(&shuffled));

        let stale_anchor = WeightedTimestamp::from_millis(2_500);
        let suffix_qc = WeightedTimestamp::from_millis(2_900);
        let bridge_qc = WeightedTimestamp::from_millis(21_100);

        // A bridge block is still admitted under the fresh committee — the
        // bridge window's own entry, not the shuffled head.
        assert_eq!(
            admitted(
                &sched,
                shard,
                sched.admits(shard, stale_anchor, bridge_qc, Epoch::new(21))
            ),
            fresh,
        );
        // The suffix keeps resolving the committee that produced it.
        assert_eq!(
            admitted(
                &sched,
                shard,
                sched.admits(shard, stale_anchor, suffix_qc, Epoch::new(2))
            ),
            old,
        );
        // A tip still anchored before the halt keeps binding the fresh
        // committee: a member one QC behind the first crossing must not
        // resolve the committee the recovery replaced.
        assert_eq!(
            members_of(&sched, shard, sched.live_committee(shard, stale_anchor)),
            fresh,
        );
        // Live work anchored at the bridge or past it resolves as ordinary.
        let current = WeightedTimestamp::from_millis(23_500);
        assert_eq!(
            members_of(&sched, shard, sched.live_committee(shard, current)),
            shuffled,
        );
        // The pending-scoped fences do not outlive the recovery.
        assert!(sched.fence_admits(shard, Epoch::new(2)));
        assert!(!sched.recovery_fences(shard, BlockHeight::new(1_000)));
        // What it replaced does outlive it: a sync-admitted suffix block
        // never gains an execution delta, however long ago the record
        // cleared, so the byte-walk suppression that reads this must not
        // lapse with the pending record.
        assert!(sched.replaced(shard, Epoch::new(2)));
        assert!(!sched.replaced(shard, Epoch::new(21)));
        // A shard with no recovery history has replaced nothing.
        assert!(!sched.replaced(ShardId::leaf(1, 1), Epoch::new(2)));
    }

    /// A fork proof with a side on a branch a recovery discarded is
    /// discarded only once no recovery of its shard is pending; a fork of
    /// the recovered chain's committee never is.
    #[test]
    fn a_fork_proof_on_a_discarded_branch_is_discarded_once_no_recovery_is_pending() {
        use crate::test_utils::{TestCommittee, shard_fork_proof_signed_by};

        let replaced = TestCommittee::new(4, 1);
        let fresh = TestCommittee::new(4, 2);
        let shard = ShardId::ROOT;
        let proof = |committee: &TestCommittee, ms: u64| {
            let keys: Vec<_> = (0..4).map(|i| committee.signer(i)).collect();
            shard_fork_proof_signed_by(
                &BlsVerifier,
                &keys,
                shard,
                BlockHeight::new(14),
                Epoch::new(ms / 1_000),
                WeightedTimestamp::from_millis(ms),
            )
        };
        let schedule = |pending: bool| {
            let binding = RecoveryBinding {
                rotated_at: Epoch::new(9),
                attested_frontier: BlockHeight::new(8),
                completed: !pending,
            };
            let mut head = fresh
                .topology_snapshot(1)
                .with_recoveries(std::iter::once((shard, vec![binding])).collect());
            if pending {
                head = head.with_pending_recoveries(
                    std::iter::once((shard, halt_recovery_at(9, &[], BlockHeight::new(8))))
                        .collect(),
                );
            }
            TopologySchedule::new(EpochWindows::new(0, 1_000), Epoch::new(11), Arc::new(head))
        };

        let discarded = proof(&replaced, 5_000);
        assert!(schedule(false).fork_proof_discarded(&discarded));
        assert!(!schedule(true).fork_proof_discarded(&discarded));
        assert!(!schedule(false).fork_proof_discarded(&proof(&fresh, 11_000)));
    }

    /// A recovery whose fresh committee stalls is followed by a second.
    /// The first recovery's bridge blocks keep resolving the committee it
    /// seated while the second is pending and after it completes; their
    /// committee is one the second recovery replaced; and live work at any
    /// stale anchor binds the newest fresh committee.
    #[test]
    fn a_chained_recovery_keeps_the_first_bridge_bound() {
        use crate::ValidatorInfo;

        let validators: Vec<ValidatorInfo> = (0..12)
            .map(|i| ValidatorInfo {
                validator_id: ValidatorId::new(i),
                public_key: BlsSigner::generate().public_key(),
            })
            .collect();
        let set = ValidatorSet::new(validators);
        let shard = ShardId::leaf(1, 0);
        let old: Vec<ValidatorId> = (0..4).map(ValidatorId::new).collect();
        let first: Vec<ValidatorId> = (4..8).map(ValidatorId::new).collect();
        let second: Vec<ValidatorId> = (8..12).map(ValidatorId::new).collect();
        let snap = |committee: &[ValidatorId], second_completed: Option<bool>| {
            let mut history = vec![RecoveryBinding {
                rotated_at: Epoch::new(20),
                attested_frontier: BlockHeight::new(10),
                completed: false,
            }];
            let mut snapshot = TopologySnapshot::with_shard_committees(
                NetworkDefinition::simulator(),
                2,
                &set,
                std::iter::once((shard, committee.to_vec())).collect(),
            );
            if let Some(completed) = second_completed {
                history.push(RecoveryBinding {
                    rotated_at: Epoch::new(40),
                    attested_frontier: BlockHeight::new(12),
                    completed,
                });
                if !completed {
                    snapshot = snapshot.with_pending_recoveries(
                        std::iter::once((
                            shard,
                            halt_recovery_at(40, &first, BlockHeight::new(12)),
                        ))
                        .collect(),
                    );
                }
            }
            Arc::new(snapshot.with_recoveries(std::iter::once((shard, history)).collect()))
        };
        let committee_of = |lookup: ScheduleLookup<'_>| match lookup {
            ScheduleLookup::Committee(snapshot) => snapshot.committee_for_shard(shard).to_vec(),
            _ => panic!("expected a resolved committee"),
        };
        let stale_anchor = WeightedTimestamp::from_millis(2_500);
        let first_bridge_qc = WeightedTimestamp::from_millis(21_100);
        let first_era_anchor = WeightedTimestamp::from_millis(21_500);
        let first_era_qc = WeightedTimestamp::from_millis(21_900);

        for second_completed in [false, true] {
            let mut sched =
                TopologySchedule::new(EpochWindows::new(0, 1000), Epoch::new(2), snap(&old, None));
            sched.insert(Epoch::new(21), snap(&first, None));
            let head = snap(&second, Some(second_completed));
            sched.insert(Epoch::new(41), Arc::clone(&head));
            sched.set_head(Epoch::new(41), head);

            // The first recovery's bridge block verifies against the
            // committee that certified it.
            assert_eq!(
                admitted(
                    &sched,
                    shard,
                    sched.admits(shard, stale_anchor, first_bridge_qc, Epoch::new(21))
                ),
                first,
            );
            // So does a block the first fresh committee certified in its
            // own windows.
            assert_eq!(
                admitted(
                    &sched,
                    shard,
                    sched.admits(shard, first_era_anchor, first_era_qc, Epoch::new(21))
                ),
                first,
            );
            // Both are the second recovery's suffix: the committee that
            // certified them has been replaced.
            assert!(sched.replaced(shard, Epoch::new(21)));
            assert!(!sched.replaced(shard, Epoch::new(41)));
            // A tick at the stale anchor resolves the committee its
            // anchor names, and is replaced; above the first frontier it
            // is in the band, as is one of the first fresh committee's
            // own era above the second frontier, which the second
            // recovery orphans.
            for height in [11, 13] {
                let height = BlockHeight::new(height);
                assert_eq!(
                    committee_of(sched.lookup_for_shard(shard, stale_anchor).0),
                    old,
                );
                assert!(sched.committee_replaced_for_anchored(shard, stale_anchor));
                assert!(sched.recovery_orphaned(shard, stale_anchor, height));
            }
            assert!(sched.committee_replaced_for_anchored(shard, first_era_anchor));
            assert!(sched.recovery_orphaned(shard, first_era_anchor, BlockHeight::new(13)));
            assert!(!sched.recovery_orphaned(shard, first_era_anchor, BlockHeight::new(12)));
            // Live work at either era's anchor binds the newest committee.
            for anchor in [stale_anchor, first_era_anchor] {
                assert_eq!(
                    members_of(&sched, shard, sched.live_committee(shard, anchor)),
                    second,
                );
            }
        }
    }

    /// A chained recovery crosses once, at its newest bridge. Of a chain
    /// whose anchors walk past both bridges, the one block whose parent
    /// is anchored below the second bridge and which is anchored at or
    /// past it is the crossing block, and a block past the first bridge
    /// alone crosses nothing. It is the first block that does not coast
    /// on its parent's anchor as the head reads it, so the block whose
    /// manifest the recovery's discard heads is the first one that names
    /// member lines.
    #[test]
    fn a_chained_recovery_crosses_once_at_its_newest_bridge() {
        let shard = ShardId::leaf(1, 0);
        let binding = |rotated_at| RecoveryBinding {
            rotated_at: Epoch::new(rotated_at),
            attested_frontier: BlockHeight::new(10),
            completed: false,
        };
        let head = Arc::new(
            TopologySnapshot::new(NetworkDefinition::simulator(), 2, ValidatorSet::new(vec![]))
                .with_recoveries(std::iter::once((shard, vec![binding(20), binding(40)])).collect())
                .with_pending_recoveries(
                    std::iter::once((shard, halt_recovery_at(40, &[], BlockHeight::new(10))))
                        .collect(),
                ),
        );
        let sched = TopologySchedule::new(
            EpochWindows::new(0, 1000),
            Epoch::new(41),
            Arc::clone(&head),
        );
        let at = |epoch: u64| WeightedTimestamp::from_millis(epoch * 1_000 + 100);
        let anchors = [19, 20, 21, 22, 39, 40, 41, 42];

        let crossings: Vec<(u64, u64)> = anchors
            .windows(2)
            .filter(|pair| sched.crossing_block(&head, shard, at(pair[0]), at(pair[1])))
            .map(|pair| (pair[0], pair[1]))
            .collect();
        assert_eq!(crossings, vec![(40, 41)]);
        for pair in anchors.windows(2) {
            assert_eq!(
                sched.crossing_block(&head, shard, at(pair[0]), at(pair[1])),
                sched.coasting(shard, at(pair[0])) && !sched.coasting(shard, at(pair[1])),
                "one block is the crossing and the first to name member lines: {pair:?}",
            );
        }
        // A shard with no recovery crosses nothing.
        let plain = Arc::new(TopologySnapshot::new(
            NetworkDefinition::simulator(),
            2,
            ValidatorSet::new(vec![]),
        ));
        assert!(!sched.crossing_block(&plain, shard, at(40), at(41)));
    }

    /// Only the crossing block crosses: a block past it, while the
    /// recovery is pending or once its record has cleared, discards
    /// nothing, and neither does a coast block below the bridge or a
    /// block whose parent is past it.
    #[test]
    fn a_block_past_the_crossing_discards_nothing() {
        let shard = ShardId::leaf(1, 0);
        let at = |epoch: u64| WeightedTimestamp::from_millis(epoch * 1_000 + 100);
        for pending in [true, false] {
            let mut head =
                TopologySnapshot::new(NetworkDefinition::simulator(), 2, ValidatorSet::new(vec![]))
                    .with_recoveries(
                        std::iter::once((
                            shard,
                            vec![RecoveryBinding {
                                rotated_at: Epoch::new(20),
                                attested_frontier: BlockHeight::new(10),
                                completed: !pending,
                            }],
                        ))
                        .collect(),
                    );
            if pending {
                head = head.with_pending_recoveries(
                    std::iter::once((shard, halt_recovery_at(20, &[], BlockHeight::new(10))))
                        .collect(),
                );
            }
            let head = Arc::new(head);
            let sched = TopologySchedule::new(
                EpochWindows::new(0, 1000),
                Epoch::new(21),
                Arc::clone(&head),
            );
            assert!(sched.crossing_block(&head, shard, at(20), at(21)));
            assert!(sched.crossing_block(&head, shard, at(3), at(25)));
            for (parent, block) in [(2, 3), (3, 20), (20, 20), (21, 21), (21, 22), (22, 40)] {
                assert!(
                    !sched.crossing_block(&head, shard, at(parent), at(block)),
                    "pending {pending}: a block anchored in {block} over one in {parent}",
                );
            }
        }
    }

    /// A window entry carrying an arbitrary reshape projection: which
    /// shards are leaves, which have a split admitted, which hold merge
    /// keepers, and each terminating leaf's scheduled cut.
    fn reshape_snap(
        leaves: &[ShardId],
        split_pending: &[ShardId],
        merge_keeper_children: &[ShardId],
        cut: &[(ShardId, u64)],
    ) -> Arc<TopologySnapshot> {
        let reshape_keepers: BTreeMap<ShardId, BTreeMap<ValidatorId, ReshapeSeat>> =
            merge_keeper_children
                .iter()
                .map(|child| {
                    (
                        *child,
                        BTreeMap::from([(
                            ValidatorId::new(0),
                            ReshapeSeat {
                                shard: ShardId::ROOT,
                                ready: false,
                            },
                        )]),
                    )
                })
                .collect();
        Arc::new(
            TopologySnapshot::from_explicit_committees(
                NetworkDefinition::simulator(),
                &ValidatorSet::new(Vec::new()),
                leaves.iter().map(|s| (*s, Vec::new())).collect(),
                HashMap::new(),
                BTreeMap::new(),
                HashMap::new(),
                BTreeMap::new(),
                reshape_keepers,
                BTreeMap::new(),
                split_pending.iter().copied().collect(),
            )
            .with_scheduled_terminals(cut.iter().map(|(s, e)| (*s, Epoch::new(*e))).collect()),
        )
    }

    /// The recovery is read off the window as it was first published: a
    /// later fold's rewrite of the window does not move it, and a window
    /// never published here answers nothing.
    #[test]
    fn the_published_window_answers_whatever_a_later_fold_rewrites() {
        let (left, right) = ShardId::ROOT.children();
        let wt = WeightedTimestamp::from_millis(6_500);
        let recovered = |rotated_at: u64| RecoveryBinding {
            rotated_at: Epoch::new(rotated_at),
            attested_frontier: BlockHeight::new(9),
            completed: false,
        };
        let children = |recoveries: Vec<RecoveryBinding>| {
            Arc::new(
                reshape_snap(&[left, right], &[], &[], &[])
                    .as_ref()
                    .clone()
                    .with_recoveries(BTreeMap::from([(left, recoveries)])),
            )
        };

        let mut schedule =
            TopologySchedule::new(EpochWindows::new(0, 1000), Epoch::new(5), snapshot());
        assert_eq!(schedule.recovery_as_published(left, wt), Err(Unpublished));
        // The frozen window alone is not the published one.
        schedule.insert(Epoch::new(6), children(vec![recovered(3)]));
        assert_eq!(schedule.recovery_as_published(left, wt), Err(Unpublished));

        schedule.insert_lookahead(Epoch::new(6), children(vec![recovered(3)]));
        assert_eq!(
            schedule.recovery_as_published(left, wt),
            Ok(Some(recovered(3)))
        );
        assert_eq!(schedule.recovery_as_published(right, wt), Ok(None));

        // The fold of 6 records a newer recovery in the frozen window
        // and at the head; the published window still says what it said.
        schedule.insert(Epoch::new(6), children(vec![recovered(3), recovered(5)]));
        schedule.set_head(Epoch::new(6), children(vec![recovered(3), recovered(5)]));
        assert_eq!(schedule.newest_recovery(left), Some(recovered(5)));
        assert_eq!(
            schedule.recovery_as_published(left, wt),
            Ok(Some(recovered(3)))
        );

        schedule.evict_below(Epoch::new(7));
        assert_eq!(schedule.recovery_as_published(left, wt), Err(Unpublished));
    }

    /// A window running `leaves`, carrying `records` and naming each of
    /// `formed` formed at its epoch.
    fn formed_window(
        leaves: &[ShardId],
        formed: &[(ShardId, u64)],
        records: &[(ShardId, ShardAnchor)],
    ) -> Arc<TopologySnapshot> {
        Arc::new(
            TopologySnapshot::from_explicit_committees(
                NetworkDefinition::simulator(),
                &ValidatorSet::new(Vec::new()),
                leaves.iter().map(|s| (*s, Vec::new())).collect(),
                HashMap::new(),
                records.iter().copied().collect(),
                HashMap::new(),
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeSet::new(),
            )
            .with_formed(formed.iter().map(|(s, e)| (*s, Epoch::new(*e))).collect()),
        )
    }

    /// The two writes of a window differ in formation only where neither
    /// reading moves. Fold 8 seats placeholders for the children of a
    /// split it applies, which its frozen write of window 8 carries and
    /// the lookahead fold 7 published does not; and it drops the record
    /// of the root, whose chain ended long before, which the lookahead
    /// still carries. Window 8 runs neither, and its evidence reads each
    /// unreadable, while every shard it runs reads one formation off
    /// both copies.
    #[test]
    fn both_writes_of_a_window_read_a_formation_alike() {
        let (left, right) = ShardId::ROOT.children();
        let (seated, sibling) = left.children();
        let wt = WeightedTimestamp::from_millis(8_500);
        let departed_root = ShardAnchor {
            state_root: StateRoot::ZERO,
            block_hash: BlockHash::from_raw(Hash::from_bytes(b"root terminal")),
            height: BlockHeight::new(9),
            weighted_timestamp: WeightedTimestamp::from_millis(900),
            witness_base: BeaconWitnessLeafCount::ZERO,
            terminal_settled_txs: Some(SettledTxsRoot::ZERO),
            handoff_complete: Some(Epoch::new(1)),
            terminal_epoch: Some(Epoch::GENESIS),
        };
        let published = formed_window(
            &[left, right],
            &[(ShardId::ROOT, 0), (left, 1), (right, 1)],
            &[(ShardId::ROOT, departed_root)],
        );
        let frozen = formed_window(
            &[left, right],
            &[(left, 1), (right, 1), (seated, 9), (sibling, 9)],
            &[],
        );
        let mut schedule =
            TopologySchedule::new(EpochWindows::new(0, 1000), Epoch::new(7), snapshot());
        schedule.insert_lookahead(Epoch::new(8), published);
        schedule.insert(Epoch::new(8), frozen);
        assert!(
            WeightedTimestamp::from_millis(8_000)
                > schedule.windows().handoff_evidence_expiry(Epoch::new(1)),
            "fold 8 is the one that drops the root's record"
        );

        for running in [left, right] {
            let formed = schedule.formed(running, wt);
            assert_eq!(
                formed,
                Some(Formed {
                    epoch: Epoch::new(1),
                    opens: WeightedTimestamp::from_millis(1_000),
                })
            );
            assert_eq!(schedule.formed_as_published(running, wt), Ok(formed));
        }

        assert_eq!(
            schedule.formed(seated, wt).map(|formed| formed.epoch),
            Some(Epoch::new(9))
        );
        assert_eq!(schedule.formed_as_published(seated, wt), Ok(None));
        assert_eq!(schedule.formed(ShardId::ROOT, wt), None);
        assert_eq!(
            schedule.formed_as_published(ShardId::ROOT, wt),
            Ok(Some(Formed {
                epoch: Epoch::GENESIS,
                opens: WeightedTimestamp::ZERO,
            }))
        );
        for unrun in [seated, sibling, ShardId::ROOT] {
            assert_eq!(partner_evidence(&schedule, unrun, wt), Evidence::Unreadable);
        }
    }

    /// The as-published formation is the window's first write: a window
    /// only frozen here, or evicted, answers nothing, and a later rewrite
    /// of the window moves the lookup's reading but not this one. A
    /// formation opens where its epoch's window does, and a row committed
    /// before that predates it.
    #[test]
    fn formed_as_published_reads_the_window_as_first_published() {
        let (left, right) = ShardId::ROOT.children();
        let wt = WeightedTimestamp::from_millis(6_500);
        let window =
            |formed: u64| formed_window(&[left, right], &[(left, formed), (right, 2)], &[]);

        let mut schedule =
            TopologySchedule::new(EpochWindows::new(0, 1000), Epoch::new(5), snapshot());
        assert_eq!(schedule.formed_as_published(left, wt), Err(Unpublished));
        schedule.insert(Epoch::new(6), window(3));
        assert_eq!(schedule.formed_as_published(left, wt), Err(Unpublished));

        schedule.insert_lookahead(Epoch::new(6), window(3));
        let first = Formed {
            epoch: Epoch::new(3),
            opens: WeightedTimestamp::from_millis(3_000),
        };
        assert_eq!(schedule.formed_as_published(left, wt), Ok(Some(first)));
        assert_eq!(schedule.formed(left, wt), Some(first));

        schedule.insert(Epoch::new(6), window(4));
        assert_eq!(
            schedule.formed(left, wt).map(|f| f.epoch),
            Some(Epoch::new(4))
        );
        assert_eq!(schedule.formed_as_published(left, wt), Ok(Some(first)));

        assert!(first.predates(WeightedTimestamp::from_millis(2_999)));
        assert!(!first.predates(first.opens));

        schedule.evict_below(Epoch::new(7));
        assert_eq!(schedule.formed_as_published(left, wt), Err(Unpublished));
        assert_eq!(schedule.formed(left, wt), None);
    }

    /// A snapshot no beacon state projected carries no formations, and
    /// every shard it runs lives from genesis; one it does not run has no
    /// life. A projected snapshot reads the record's.
    #[test]
    fn a_running_shard_without_a_record_lives_from_genesis() {
        let (left, right) = ShardId::ROOT.children();
        let wt = WeightedTimestamp::from_millis(6_500);
        let unprojected = TopologySchedule::single(topology_with(&[left, right], &[]));
        let window = unprojected.at(wt).expect("held");
        assert_eq!(window.life(left), Some(Epoch::GENESIS));
        assert_eq!(window.formed(left), None);
        assert_eq!(window.life(ShardId::ROOT), None);
        assert_eq!(unprojected.formed(left, wt), None);

        let projected =
            TopologySchedule::single(formed_window(&[left, right], &[(left, 4), (right, 4)], &[]));
        let window = projected.at(wt).expect("held");
        assert_eq!(window.life(left), Some(Epoch::new(4)));
        assert_eq!(window.life(ShardId::ROOT), None);
    }

    /// A shard reads as terminating through its final epoch and in no
    /// other: the window before it carries no cut, the final one names
    /// it from its first instant through the cut itself, which a
    /// parent anchor resolves to the window it closes, and the window
    /// after it no longer runs the shard. A window not held answers
    /// nothing, and the shards terminating in a window are read one at
    /// a time off the same answer.
    #[test]
    fn termination_is_published_for_the_final_epoch_only() {
        let (left, right) = ShardId::ROOT.children();
        let before = reshape_snap(&[ShardId::ROOT], &[ShardId::ROOT], &[], &[]);
        let last = reshape_snap(
            &[ShardId::ROOT],
            &[ShardId::ROOT],
            &[],
            &[(ShardId::ROOT, 5)],
        );
        let after = reshape_snap(&[left, right], &[], &[], &[]);
        let mut schedule = TopologySchedule::new(EpochWindows::new(0, 1000), Epoch::new(4), before);
        schedule.insert_lookahead(Epoch::new(5), last);
        schedule.insert_lookahead(Epoch::new(6), after);
        let at = WeightedTimestamp::from_millis;
        for (wt, root) in [
            (4_500, false),
            (5_000, false),
            (5_001, true),
            (5_999, true),
            (6_000, true),
            (6_001, false),
        ] {
            let terminating = schedule.terminating_at(at(wt)).expect("held");
            assert_eq!(terminating.contains(ShardId::ROOT), root, "at {wt}");
            assert_eq!(
                schedule.terminates_at_next_boundary(ShardId::ROOT, at(wt)),
                Some(root),
                "at {wt}",
            );
            for child in [left, right] {
                assert!(!terminating.contains(child), "{child:?} at {wt}");
            }
        }
        assert!(schedule.terminating_at(at(7_500)).is_none());
        let single = TopologySchedule::single(reshape_snap(
            &[ShardId::ROOT],
            &[ShardId::ROOT],
            &[],
            &[(ShardId::ROOT, 0)],
        ));
        assert!(
            !single
                .terminating_at(at(500))
                .expect("a single window spans every anchor")
                .contains(ShardId::ROOT),
            "a single window has no boundary to terminate at",
        );
    }

    #[test]
    fn terminates_at_next_boundary_covers_splits_and_merges() {
        let (left, right) = ShardId::ROOT.children();
        let wt = WeightedTimestamp::from_millis(5500);

        // A split parent terminates: window 5 carries it with the cut
        // scheduled at 5's end. `split_at_next_boundary` also fires — the
        // scheduled cut says *whether*, `split_pending` says *which
        // reshape*. Neither reads window 6, which isn't inserted at all.
        let split = TopologySchedule::new(
            EpochWindows::new(0, 1000),
            Epoch::new(5),
            reshape_snap(
                &[ShardId::ROOT],
                &[ShardId::ROOT],
                &[],
                &[(ShardId::ROOT, 5)],
            ),
        );
        assert_eq!(
            split.terminates_at_next_boundary(ShardId::ROOT, wt),
            Some(true)
        );
        assert_eq!(
            split.split_at_next_boundary(ShardId::ROOT, wt),
            SplitAtBoundary::Children(left, right)
        );

        // A merge child terminates: both children carry the same cut, and
        // `terminates` fires even though `split_at_next_boundary` does not
        // — the case the split-only predicate missed.
        let merge = TopologySchedule::new(
            EpochWindows::new(0, 1000),
            Epoch::new(5),
            reshape_snap(
                &[left, right],
                &[],
                &[left, right],
                &[(left, 5), (right, 5)],
            ),
        );
        assert_eq!(merge.terminates_at_next_boundary(left, wt), Some(true));
        assert_eq!(merge.split_at_next_boundary(left, wt), SplitAtBoundary::No);
        // The shard's counterpart in the same merge also terminates.
        assert_eq!(merge.terminates_at_next_boundary(right, wt), Some(true));

        // An admitted reshape carrying no cut does not terminate here —
        // definitive: the window's own entry carries the answer.
        let merge_pending = TopologySchedule::new(
            EpochWindows::new(0, 1000),
            Epoch::new(5),
            reshape_snap(&[left, right], &[], &[left, right], &[]),
        );
        assert_eq!(
            merge_pending.terminates_at_next_boundary(left, wt),
            Some(false)
        );
        let split_pending = TopologySchedule::new(
            EpochWindows::new(0, 1000),
            Epoch::new(5),
            reshape_snap(&[ShardId::ROOT], &[ShardId::ROOT], &[], &[]),
        );
        assert_eq!(
            split_pending.terminates_at_next_boundary(ShardId::ROOT, wt),
            Some(false)
        );
        // A cut scheduled for a *later* window is equally definitive here.
        let later = TopologySchedule::new(
            EpochWindows::new(0, 1000),
            Epoch::new(5),
            reshape_snap(
                &[ShardId::ROOT],
                &[ShardId::ROOT],
                &[],
                &[(ShardId::ROOT, 6)],
            ),
        );
        assert_eq!(
            later.terminates_at_next_boundary(ShardId::ROOT, wt),
            Some(false)
        );
        // No admitted reshape at all: definitively no termination.
        let quiet = TopologySchedule::new(
            EpochWindows::new(0, 1000),
            Epoch::new(5),
            reshape_snap(&[left, right], &[], &[], &[]),
        );
        assert_eq!(quiet.terminates_at_next_boundary(left, wt), Some(false));
    }
}
