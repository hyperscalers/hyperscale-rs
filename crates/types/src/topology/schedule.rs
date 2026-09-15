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
    BlockHeight, Epoch, EpochWindows, PredecessorTerminal, ReshapeThresholds, ShardId,
    TopologySnapshot, ValidatorId, WeightedTimestamp,
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
/// all time (`epoch_duration_ms == 0` folds every timestamp to genesis) — the
/// pre-rotation / single-epoch case used by tests and within-epoch callers.
#[derive(Clone, Debug)]
pub struct TopologySchedule {
    /// Window length in milliseconds; `epoch = floor(wt / epoch_duration_ms)`.
    /// Zero means a single fixed committee (every timestamp maps to genesis).
    epoch_duration_ms: u64,
    /// Active committee for routing / gossip ("who is in the committee now?").
    head: Arc<TopologySnapshot>,
    /// Committee snapshots keyed by the epoch each governs.
    by_epoch: BTreeMap<Epoch, Arc<TopologySnapshot>>,
    /// Each window's projection as the fold before it first published it,
    /// never rewritten by the fold that freezes the window.
    lookahead: BTreeMap<Epoch, Arc<TopologySnapshot>>,
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
        let lookahead = BTreeMap::new();
        Self {
            epoch_duration_ms,
            head,
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
        let lookahead = BTreeMap::new();
        Self {
            epoch_duration_ms: 0,
            head: snapshot,
            by_epoch,
            lookahead,
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
        Self::resolved(self.lookup_for_shard(shard, wt))
    }

    /// Collapse a lookup tuple to its resolved committee — `None` for
    /// [`NotYetCommitted`](ScheduleLookup::NotYetCommitted) and
    /// [`Evicted`](ScheduleLookup::Evicted) alike. The one adapter behind
    /// every `at_*` wrapper, so a new `ScheduleLookup` variant is handled
    /// in one place.
    ///
    /// Callers that must tell the two apart — a transient lag deserves a
    /// defer, an evicted window a reject — cannot use this and should read
    /// the `lookup_*` form directly.
    const fn resolved(
        (lookup, past_terminal): (ScheduleLookup<'_>, bool),
    ) -> Option<(&Arc<TopologySnapshot>, bool)> {
        match lookup {
            ScheduleLookup::Committee(snapshot) => Some((snapshot, past_terminal)),
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
                .terminal_window(shard, wt)
                .map_or((ScheduleLookup::Evicted, true), |(_, s)| {
                    (ScheduleLookup::Committee(s), true)
                }),
            other => (other, false),
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
        match self.lookup(wt) {
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
    /// derivation in [`settled_set_verdict`](crate::settled_set_verdict):
    /// caches, prunes, and the settled sets still wanted all read this, so
    /// none of them stops asking while the fence still expects an answer.
    #[must_use]
    pub fn terminal_evidence_readable(&self, shard: ShardId, wt: WeightedTimestamp) -> bool {
        match self.lookup(wt) {
            ScheduleLookup::Committee(snapshot) => snapshot.boundary(shard).is_some_and(|anchor| {
                anchor
                    .handoff_complete
                    .is_none_or(|done| wt <= self.windows().handoff_evidence_expiry(done))
            }),
            ScheduleLookup::NotYetCommitted => true,
            ScheduleLookup::Evicted => false,
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

    /// The bridge epoch when live work anchored at `wt` rides `shard`'s
    /// pending halt recovery: a recovery is in flight and `wt`'s epoch
    /// sits below the bridge.
    fn live_bridge(&self, shard: ShardId, wt: WeightedTimestamp) -> Option<Epoch> {
        self.recovery_bridge(shard)
            .filter(|&bridge| self.epoch_for(wt) < bridge)
    }

    /// Whether live work anchored at `wt` rides `shard`'s pending halt
    /// recovery bridge — the band
    /// [`lookup_for_shard_live`](Self::lookup_for_shard_live) re-binds to
    /// the fresh committee. The one predicate every consumer reads
    /// (proposer gating, state-root deferral, the live lookup itself), so
    /// the bridge band cannot drift between them.
    #[must_use]
    pub fn recovery_bridging(&self, shard: ShardId, wt: WeightedTimestamp) -> bool {
        self.live_bridge(shard, wt).is_some()
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
    /// are admission and gate checks made once, where the reading is
    /// against the freshest record a node holds and an artifact refused
    /// here is refused for good. A block-validity input would need the
    /// snapshot governing the block's own anchor instead, so that every
    /// replica validating it reads the same records whenever it
    /// validates — this is not that, and nothing here is.
    #[must_use]
    pub fn recovery_fences(&self, shard: ShardId, height: BlockHeight) -> bool {
        self.head.recovery_fences(shard, height)
    }

    /// During a pending recovery, whether a certified artifact resolves the
    /// **retained** (old) committee through the suffix band: a stale anchor
    /// (below the bridge) whose QC timestamp also sits below the bridge, so
    /// [`lookup_for_shard_certified`](Self::lookup_for_shard_certified) does
    /// not re-bind it to the fresh committee.
    ///
    /// The fresh committee's own artifacts either re-bind (a bridge block,
    /// anchored below the bridge but certified at or past it) or anchor at a
    /// current window (resolving the fresh committee directly), so both are
    /// false here. What is true here is exactly a stale-anchored,
    /// suffix-band-stamped artifact — the halted suffix, or an orphan the
    /// beyond-f retained committee forged extending the halted tip. Callers
    /// that only ever see *new* production during a recovery (the beacon's
    /// boundary fold — the suffix has no epoch crossing of its own) use this
    /// to reject the orphan, since the only legitimate new crossing is the
    /// fresh committee's. False when no recovery is pending for the shard.
    #[must_use]
    pub fn recovery_resolves_retained(
        &self,
        shard: ShardId,
        anchor_wt: WeightedTimestamp,
        qc_wt: WeightedTimestamp,
    ) -> bool {
        self.recovery_bridge(shard)
            .is_some_and(|bridge| self.below_bridge_band(bridge, anchor_wt, qc_wt))
    }

    /// Whether a certified block of `shard` sits inside a halt recovery's
    /// suffix band — anchored and certified below the bridge epoch — for a
    /// recovery pending **or** completed. The same banding as
    /// [`recovery_resolves_retained`](Self::recovery_resolves_retained),
    /// held permanently through the completed record: a suffix block is
    /// QC-attested but never locally executed on any replica that synced
    /// it, and that stays true after the pending record clears on the
    /// shard's first crossing.
    #[must_use]
    pub fn recovery_suffix_band(
        &self,
        shard: ShardId,
        anchor_wt: WeightedTimestamp,
        qc_wt: WeightedTimestamp,
    ) -> bool {
        self.certified_recovery_bridge(shard)
            .is_some_and(|bridge| self.below_bridge_band(bridge, anchor_wt, qc_wt))
    }

    /// The suffix-band test shared by the pending and certified recovery
    /// predicates: both the anchor and the QC stamp resolve below the
    /// bridge epoch. A bridge block fails it — anchored below but
    /// certified at or past the bridge.
    fn below_bridge_band(
        &self,
        bridge: Epoch,
        anchor_wt: WeightedTimestamp,
        qc_wt: WeightedTimestamp,
    ) -> bool {
        self.epoch_for(anchor_wt) < bridge && self.epoch_for(qc_wt).next() < bridge
    }

    /// The first epoch whose committee bridges `shard`'s halt gap —
    /// pending or completed. Certified resolution reads this rather than
    /// [`recovery_bridge`](Self::recovery_bridge): a bridge block's
    /// committee binding must not change when the pending record clears
    /// on the shard's first crossing, so the completed recovery keeps
    /// answering for the band below it, permanently.
    fn certified_recovery_bridge(&self, shard: ShardId) -> Option<Epoch> {
        self.recovery_bridge(shard).or_else(|| {
            self.head
                .completed_recoveries()
                .get(&shard)
                .map(|completed| completed.rotated_at.next())
        })
    }

    /// The committee entry the recovery bridge resolves: the bridge
    /// epoch's own window, where the fold seated the fresh committee.
    /// Pinned to that entry — rather than the newest retained window —
    /// so the binding is one value for every replica at every later
    /// fold: a mid-recovery top-up or a post-recovery shuffle lands in
    /// later entries and never re-binds work anchored below the bridge.
    fn bridged_for_shard(&self, shard: ShardId, bridge: Epoch) -> (ScheduleLookup<'_>, bool) {
        self.lookup_for_shard(shard, self.windows().window_of(bridge).start)
    }

    /// [`lookup_for_shard`](Self::lookup_for_shard) for **live** consensus
    /// work — proposals, votes, and the tip committee. A recovering
    /// shard's stale anchor resolves the fresh committee via the recovery
    /// bridge (see [`recovery_bridge`](Self::recovery_bridge)), so an
    /// honest folded member proposes and votes only on the fresh chain and
    /// never on a competing extension the retained cohort gossips. This
    /// binds the *honest* side; it does not disarm the retained committee,
    /// which is beyond f by construction (that is why the shard halted) and
    /// can still certify a competing chain from its own members plus any
    /// lagging honest one. That orphan is caught on the verifier side, not
    /// here — see [`lookup_for_shard_certified`](Self::lookup_for_shard_certified).
    /// Never used to verify certified history — the halted suffix verifies
    /// against its own windows via the certified path.
    #[must_use]
    pub fn lookup_for_shard_live(
        &self,
        shard: ShardId,
        wt: WeightedTimestamp,
    ) -> (ScheduleLookup<'_>, bool) {
        if let Some(bridge) = self.live_bridge(shard, wt) {
            return self.bridged_for_shard(shard, bridge);
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
        Self::resolved(self.lookup_for_shard_live(shard, wt))
    }

    /// [`lookup_for_shard`](Self::lookup_for_shard) for a **certified**
    /// artifact — a block or header carrying its own QC. A recovery
    /// bridge block is anchored below the bridge epoch but certified at
    /// or after it, and resolves the fresh committee; the halted suffix —
    /// certified while the old committee still governed, so its QC
    /// timestamps sit a full halt gap below the bridge — resolves by its
    /// anchor as ever. The bridge outlives the pending record: once the
    /// recovery completes, the completed-recovery epoch keeps the band
    /// re-binding, so a replica that verifies or commits a bridge block
    /// after the shard's first crossing binds it to the same committee as
    /// one that processed it during the recovery. The QC bound tolerates
    /// one window below the bridge because the seating-window quiesce
    /// holds each honest vote at or past the bridge window, so an
    /// honest-majority quorum's mean stamp cannot fall more than a skew
    /// window under it.
    ///
    /// That tolerance is calibrated for an adversarial *minority* in the
    /// quorum, and the retained committee is beyond f — an honest minority
    /// in its own quorum — so it can drag the aggregated (mean) timestamp
    /// arbitrarily below the bridge and land an orphan extending the
    /// halted tip back in the suffix band, where this resolves the old
    /// committee and its signatures verify. The re-bind narrows the local
    /// orphan but does not close it. The safety-critical leak — a forged
    /// finalization exporting cross-shard — is closed at the height
    /// gate [`recovery_fences`](Self::recovery_fences); a purely local
    /// orphan fork surfaces as a commit-linkage divergence and self-halts
    /// (a re-fired recovery, a liveness cost), rather than forking
    /// silently. A replica that has not yet folded the recovery
    /// resolves a bridge block's anchor window instead and drops it as
    /// unverifiable; its fetch retries succeed once its beacon catches up,
    /// the same self-healing as any beacon lag.
    #[must_use]
    pub fn lookup_for_shard_certified(
        &self,
        shard: ShardId,
        anchor_wt: WeightedTimestamp,
        qc_wt: WeightedTimestamp,
    ) -> (ScheduleLookup<'_>, bool) {
        if let Some(bridge) = self.certified_recovery_bridge(shard)
            && self.epoch_for(anchor_wt) < bridge
            && self.epoch_for(qc_wt).next() >= bridge
        {
            return self.bridged_for_shard(shard, bridge);
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
        Self::resolved(self.lookup_for_shard_certified(shard, anchor_wt, qc_wt))
    }

    /// [`lookup_for_shard_certified`](Self::lookup_for_shard_certified) for
    /// verifiers that must reject the pending-recovery orphan: `None` for a
    /// stale-anchored, suffix-band-stamped artifact — the shape only the
    /// retained (beyond-f) committee produces as *new* work during a halt
    /// recovery (see
    /// [`recovery_resolves_retained`](Self::recovery_resolves_retained)) —
    /// otherwise the certified resolution. The reject and the lookup are
    /// order-sensitive (the plain certified lookup would resolve the orphan
    /// to the old committee, whose signatures verify), so consumers that
    /// only ever see new production during a recovery call this instead of
    /// pairing the two by hand.
    #[must_use]
    pub fn lookup_for_shard_certified_fenced(
        &self,
        shard: ShardId,
        anchor_wt: WeightedTimestamp,
        qc_wt: WeightedTimestamp,
    ) -> Option<(ScheduleLookup<'_>, bool)> {
        if self.recovery_resolves_retained(shard, anchor_wt, qc_wt) {
            return None;
        }
        Some(self.lookup_for_shard_certified(shard, anchor_wt, qc_wt))
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

    /// The chains `shard` succeeds, read off the beacon's own boundary
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
    /// folded, or carries no [`TerminalRoots`](crate::TerminalRoots) yet, takes the whole set
    /// with it: a successor holding a *subset* of the chains it succeeds
    /// reads one predecessor's absence proof as the whole answer and
    /// admits what another predecessor committed, which is the replay
    /// this rule exists to refuse. Holding none is the strict refusal the
    /// successor already runs under, so nothing is lost by waiting — and
    /// a caller only adopts when it holds nothing, so the next fold that
    /// completes the set is what it takes.
    ///
    /// The two children's terminals fold independently and need not land
    /// together, so a merged parent reading this mid-window sees exactly
    /// that partial state.
    #[must_use]
    pub fn predecessor_terminals(
        &self,
        shard: ShardId,
        origin_wt: WeightedTimestamp,
    ) -> Vec<PredecessorTerminal> {
        if origin_wt == WeightedTimestamp::ZERO {
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
        let complete: Option<Vec<PredecessorTerminal>> = [shard.parent(), Some(left), Some(right)]
            .into_iter()
            .flatten()
            .filter(|candidate| self.terminal_cut_wt(*candidate) == Some(origin_wt))
            .map(|candidate| {
                let anchor = self.head.boundary(candidate)?;
                Some(PredecessorTerminal {
                    shard: candidate,
                    height: anchor.height,
                    block_hash: anchor.block_hash,
                    committed_txs_root: anchor.terminal_roots?.committed_txs,
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
        if self.epoch_duration_ms == 0 {
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
        if self.epoch_duration_ms == 0 {
            return Some(false);
        }
        self.terminates_at_end_of(shard, self.anchor_epoch_for(wt))
    }

    /// [`terminates_at_next_boundary`](Self::terminates_at_next_boundary)
    /// keyed on the window itself rather than on an instant inside it.
    ///
    /// Callers that already hold an epoch use this: naming the window by
    /// its opening instant would resolve the *previous* one, since
    /// [`anchor_epoch_for`](Self::anchor_epoch_for) treats a boundary
    /// instant as belonging to the window it closes.
    #[must_use]
    pub fn terminates_at_end_of(&self, shard: ShardId, epoch: Epoch) -> Option<bool> {
        if self.epoch_duration_ms == 0 {
            return Some(false);
        }
        let current = self.by_epoch.get(&epoch)?;
        Some(
            current.shard_trie().contains(shard)
                && current.scheduled_terminal(shard) == Some(epoch),
        )
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
        if self.epoch_duration_ms == 0 {
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

    /// Replace the active head committee (routing view).
    pub fn set_head(&mut self, snapshot: Arc<TopologySnapshot>) {
        self.head = snapshot;
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
    use hyperscale_crypto_bls::BlsSigner;

    use super::*;
    use crate::{
        BeaconWitnessLeafCount, BlockHash, BlockHeight, CommittedTxsRoot, CompletedRecovery, Hash,
        NetworkDefinition, RecoveryCause, ReshapeSeat, SettledTxsRoot, ShardAnchor, ShardRecovery,
        StateRoot, TerminalRoots, ValidatorSet,
    };

    fn snapshot() -> Arc<TopologySnapshot> {
        Arc::new(TopologySnapshot::new(
            NetworkDefinition::simulator(),
            1,
            ValidatorSet::new(Vec::new()),
        ))
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
    fn topology_with(
        live: &[ShardId],
        terminated: &[(ShardId, Option<CommittedTxsRoot>)],
    ) -> Arc<TopologySnapshot> {
        let committees: HashMap<ShardId, Vec<ValidatorId>> =
            live.iter().map(|shard| (*shard, Vec::new())).collect();
        let boundaries: HashMap<ShardId, ShardAnchor> = terminated
            .iter()
            .map(|(shard, committed)| {
                (
                    *shard,
                    ShardAnchor {
                        state_root: StateRoot::ZERO,
                        block_hash: BlockHash::from_raw(Hash::from_bytes(
                            format!("{shard:?}").as_bytes(),
                        )),
                        height: BlockHeight::new(41),
                        weighted_timestamp: WeightedTimestamp::ZERO,
                        witness_base: BeaconWitnessLeafCount::ZERO,
                        terminal_roots: committed.map(|committed_txs| TerminalRoots {
                            settled_txs: SettledTxsRoot::ZERO,
                            committed_txs,
                        }),
                        handoff_complete: None,
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

    fn root_committed() -> CommittedTxsRoot {
        CommittedTxsRoot::from_raw(Hash::from_bytes(b"committed window"))
    }

    /// A two-window schedule cut at 1000ms: `before` governs epoch 0,
    /// `after` governs epoch 1 and is the head. The head is what
    /// `terminal_cut_wt` reads to decide a shard has left, so a fixture
    /// that only inserts the later window leaves every shard live and
    /// every assertion here vacuous.
    fn cut_at_1000(
        before: &[ShardId],
        after: &[ShardId],
        terminated: &[(ShardId, Option<CommittedTxsRoot>)],
    ) -> TopologySchedule {
        let head = topology_with(after, terminated);
        let mut sched = TopologySchedule::new(1000, Epoch::new(0), topology_with(before, &[]));
        sched.insert(Epoch::new(1), Arc::clone(&head));
        sched.set_head(head);
        sched
    }

    /// A split child succeeds the parent that terminated at its origin,
    /// and reads the parent's commitment off the boundary record.
    #[test]
    fn a_split_child_succeeds_the_parent_that_terminated_at_its_cut() {
        let (left, right) = ShardId::ROOT.children();
        // ROOT is live in epoch 0 and gone from epoch 1, so its terminal
        // cut is the end of epoch 0 — 1000ms.
        let sched = cut_at_1000(
            &[ShardId::ROOT],
            &[left, right],
            &[(ShardId::ROOT, Some(root_committed()))],
        );
        let cut = WeightedTimestamp::from_millis(1000);

        let predecessors = sched.predecessor_terminals(left, cut);
        assert_eq!(predecessors.len(), 1);
        assert_eq!(predecessors[0].shard, ShardId::ROOT);
        assert_eq!(predecessors[0].height, BlockHeight::new(41));
        assert_eq!(predecessors[0].committed_txs_root, root_committed());
    }

    /// A merged parent succeeds both children — one absence proof settles
    /// nothing, so both terminals have to be found.
    #[test]
    fn a_merged_parent_succeeds_both_children() {
        let (left, right) = ShardId::ROOT.children();
        let sched = cut_at_1000(
            &[left, right],
            &[ShardId::ROOT],
            &[
                (left, Some(root_committed())),
                (right, Some(root_committed())),
            ],
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
    /// without — the ordinary state, not a corrupt one. Holding the one
    /// would read its absence proof as the whole answer and admit what
    /// the other child committed, so the partial set is refused entirely.
    /// A caller adopts only while it holds nothing, so the fold that
    /// completes the pair is the one it takes.
    #[test]
    fn a_merged_parent_holds_both_children_or_neither() {
        let (left, right) = ShardId::ROOT.children();
        let cut = WeightedTimestamp::from_millis(1000);
        let succeeding = |terminated: &[(ShardId, Option<CommittedTxsRoot>)]| {
            cut_at_1000(&[left, right], &[ShardId::ROOT], terminated)
                .predecessor_terminals(ShardId::ROOT, cut)
        };

        assert_eq!(
            succeeding(&[
                (left, Some(root_committed())),
                (right, Some(root_committed())),
            ])
            .len(),
            2,
        );
        // The right child's terminal has folded, but without its roots.
        assert!(
            succeeding(&[(left, Some(root_committed())), (right, None)]).is_empty(),
            "one child's commitment is not the merged parent's answer",
        );
        // And the case where its boundary record has not folded at all.
        assert!(succeeding(&[(left, Some(root_committed()))]).is_empty());
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
            &[(ShardId::ROOT, Some(root_committed()))],
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

    /// A candidate whose boundary record carries no terminal roots is left
    /// out: the successor keeps refusing everything from before its
    /// origin, which is the rule the roots would have relaxed.
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
                &[(ShardId::ROOT, Some(root_committed()))],
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
        let mut sched = TopologySchedule::new(1000, Epoch::new(3), snapshot());
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
                HashMap::new(),
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
        let mut behind = TopologySchedule::new(1000, Epoch::new(4), snapshot());
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
        // Windows 5 and 6 carry the parent with p's split admitted. The
        // fold opening window 5 met the readiness gate and scheduled the
        // cut at 6, so window 6 is the first entry carrying it; the fold
        // at 6 applies the split and window 7 carries the children.
        let mut sched = TopologySchedule::new(
            1000,
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
            1000,
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
            1000,
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
            1000,
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
            1000,
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
            1000,
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

        // `recovery_resolves_retained` isolates the orphan shape — a stale
        // anchor whose QC also sits in the suffix band, which the beacon
        // boundary fold and remote-header verify reject. A bridge block
        // (re-bound) and a current anchor are false.
        assert!(sched.recovery_resolves_retained(shard, stale_anchor, suffix_qc));
        assert!(!sched.recovery_resolves_retained(shard, stale_anchor, bridge_qc));
        assert!(!sched.recovery_resolves_retained(shard, stale_anchor, edge_qc));
        assert!(!sched.recovery_resolves_retained(shard, bridge_qc, bridge_qc));
        // While the recovery pends, the suffix band matches retained
        // resolution; the negatives are pinned in the completed-record test.
        assert!(sched.recovery_suffix_band(shard, stale_anchor, suffix_qc));

        // The fenced lookup folds the reject and the resolution into one
        // call: the orphan shape is `None`, everything else resolves.
        assert!(
            sched
                .lookup_for_shard_certified_fenced(shard, stale_anchor, suffix_qc)
                .is_none()
        );
        assert_eq!(
            committee_of(
                sched
                    .lookup_for_shard_certified_fenced(shard, stale_anchor, bridge_qc)
                    .expect("bridge block passes the fence")
                    .0
            ),
            fresh,
        );

        // Without the recovery record, the live path is the plain lookup
        // and the retained-resolution predicate is inert.
        let mut plain = TopologySchedule::new(1000, Epoch::new(2), Arc::clone(&old_snap));
        plain.insert(Epoch::new(21), snap(&fresh));
        assert_eq!(
            committee_of(plain.lookup_for_shard_live(shard, stale_anchor).0),
            old,
        );
        assert!(!plain.recovery_resolves_retained(shard, stale_anchor, suffix_qc));
    }

    /// The bridge binding outlives the pending record: once the recovery
    /// completes (pending record cleared, seating epoch in the completed
    /// map), certified resolution still re-binds the bridge band to the
    /// fresh committee — pinned to the bridge window's own entry, so a
    /// post-recovery shuffle landing in a later entry never re-binds it —
    /// while the suffix keeps its old committee, live resolution returns
    /// to the plain anchor lookup, and the pending-scoped fences go inert.
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
                snap(committee).as_ref().clone().with_completed_recoveries(
                    std::iter::once((
                        shard,
                        CompletedRecovery {
                            rotated_at: Epoch::new(20),
                            attested_frontier: BlockHeight::GENESIS,
                        },
                    ))
                    .collect(),
                ),
            )
        };

        // The recovery seated the fresh committee at epoch 20 (bridge 21);
        // its first crossing cleared the pending record, and a later fold
        // rotated the committee again in a newer entry.
        let mut sched = TopologySchedule::new(1000, Epoch::new(2), snap(&old));
        sched.insert(Epoch::new(21), completed(&fresh));
        sched.insert(Epoch::new(23), completed(&shuffled));
        sched.set_head(completed(&shuffled));

        let committee_of = |lookup: ScheduleLookup<'_>| match lookup {
            ScheduleLookup::Committee(snapshot) => snapshot.committee_for_shard(shard).to_vec(),
            _ => panic!("expected a resolved committee"),
        };
        let stale_anchor = WeightedTimestamp::from_millis(2_500);
        let suffix_qc = WeightedTimestamp::from_millis(2_900);
        let bridge_qc = WeightedTimestamp::from_millis(21_100);

        // The bridge band still re-binds to the fresh committee — the
        // bridge window's own entry, not the shuffled head.
        assert_eq!(
            committee_of(
                sched
                    .lookup_for_shard_certified(shard, stale_anchor, bridge_qc)
                    .0
            ),
            fresh,
        );
        // The suffix keeps resolving the committee that produced it.
        assert_eq!(
            committee_of(
                sched
                    .lookup_for_shard_certified(shard, stale_anchor, suffix_qc)
                    .0
            ),
            old,
        );
        // Live resolution is ordinary again once no recovery is pending.
        assert_eq!(
            committee_of(sched.lookup_for_shard_live(shard, stale_anchor).0),
            old,
        );
        // The pending-scoped fences do not outlive the recovery.
        assert!(!sched.recovery_resolves_retained(shard, stale_anchor, suffix_qc));
        assert!(!sched.recovery_fences(shard, BlockHeight::new(1_000)));
        // The suffix band does outlive it: a sync-admitted suffix block
        // never gains an execution delta, however long ago the record
        // cleared, so the byte-walk suppression that reads this must not
        // lapse with the pending record.
        assert!(sched.recovery_suffix_band(shard, stale_anchor, suffix_qc));
        assert!(!sched.recovery_suffix_band(shard, stale_anchor, bridge_qc));
        // A shard with no recovery history has no band.
        assert!(!sched.recovery_suffix_band(ShardId::leaf(1, 1), stale_anchor, suffix_qc));
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
                HashMap::new(),
                HashMap::new(),
                BTreeMap::new(),
                reshape_keepers,
                BTreeMap::new(),
                split_pending.iter().copied().collect(),
            )
            .with_scheduled_terminals(cut.iter().map(|(s, e)| (*s, Epoch::new(*e))).collect()),
        )
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
            1000,
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
            1000,
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
            1000,
            Epoch::new(5),
            reshape_snap(&[left, right], &[], &[left, right], &[]),
        );
        assert_eq!(
            merge_pending.terminates_at_next_boundary(left, wt),
            Some(false)
        );
        let split_pending = TopologySchedule::new(
            1000,
            Epoch::new(5),
            reshape_snap(&[ShardId::ROOT], &[ShardId::ROOT], &[], &[]),
        );
        assert_eq!(
            split_pending.terminates_at_next_boundary(ShardId::ROOT, wt),
            Some(false)
        );
        // A cut scheduled for a *later* window is equally definitive here.
        let later = TopologySchedule::new(
            1000,
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
            1000,
            Epoch::new(5),
            reshape_snap(&[left, right], &[], &[], &[]),
        );
        assert_eq!(quiet.terminates_at_next_boundary(left, wt), Some(false));
    }
}
