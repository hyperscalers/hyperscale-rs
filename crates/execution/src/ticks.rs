//! In-flight tick registry: owns [`TickState`], [`VoteTracker`], EC-dispatch
//! gating, vote-retry bookkeeping, and the `tx_hash → TickId` reverse index.
//!
//! The registry is the execution coordinator's "what's currently in flight"
//! sub-machine. Everything else is keyed against it:
//!
//! - Incoming votes look up ticks by `tick_id` to decide buffering vs
//!   tracker creation.
//! - Incoming cross-shard ECs route by `tx_hash → tick_id` via
//!   [`classify_attestation`](TickRegistry::classify_attestation).
//! - [`EarlyArrivalBuffer`](crate::early_arrivals) retention reads from the
//!   registry to tell "tick still active" from "tick long gone".
//! - [`FinalizationStore`](crate::finalizations::FinalizationStore)
//!   receives ticks handed off from the registry at finalization.
//!
//! ## Assignments as an inverted index
//!
//! `assignments[tx_hash] = tick_id` is the reverse of the tick's
//! `tx_hashes()` list. Pruning the two sides atomically is the registry's
//! job — see [`prune_resolved`](TickRegistry::prune_resolved), which drops
//! states whose keys no longer appear in `assignments.values()` and then
//! drops assignments whose `tick_ids` no longer appear in `states`.
//!
//! ## Typed effects
//!
//! - [`check_vote_retry_timeouts`](TickRegistry::check_vote_retry_timeouts)
//!   returns a `Vec<RetryEffect>` — the coordinator resolves the rotated
//!   leader via topology and wraps each as
//!   `Action::SignAndSendExecutionVote`.
//! - [`classify_attestation`](TickRegistry::classify_attestation) returns
//!   [`AttestationRouting`] — the coordinator fans out into
//!   `EarlyArrivalBuffer::buffer_ec` / `clear_routed` and walks the affected
//!   ticks.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;
use std::time::Duration;

use hyperscale_types::{
    Attempt, BlockHash, BlockHeight, ExecutionCertificate, GlobalReceiptRoot, TickId, TxHash,
    TxOutcome, VoteCount, WeightedTimestamp,
};

use crate::tick_state::TickState;
use crate::vote_tracker::VoteTracker;

/// How long to wait before retrying a vote with the next rotated tick
/// leader. Must exceed typical tick-leader aggregation latency so we don't
/// rotate past a leader that's about to succeed. Measured against the
/// BFT-authenticated `weighted_timestamp_ms` of locally committed blocks.
pub const VOTE_RETRY_TIMEOUT: Duration = Duration::from_secs(8);

/// Tracks a pending vote sent to a tick leader, for retry on timeout.
///
/// Retries are unbounded — the loop self-terminates when a working leader
/// aggregates the EC and broadcasts it back. Capping retries would stall
/// ticks that have not produced one yet.
#[derive(Debug, Clone)]
pub struct PendingVoteRetry {
    /// Local weighted timestamp when this vote was last dispatched.
    /// Compared against `committed_ts` to detect leader aggregation
    /// timeouts independently of block production rate.
    pub(crate) sent_at: WeightedTimestamp,
    pub(crate) attempt: Attempt,
    pub(crate) block_hash: BlockHash,
    pub(crate) block_height: BlockHeight,
    pub(crate) vote_anchor_ts: WeightedTimestamp,
    pub(crate) global_receipt_root: GlobalReceiptRoot,
    pub(crate) tx_outcomes: Arc<Vec<TxOutcome>>,
}

/// One retry the coordinator should lift to an
/// `Action::SignAndSendExecutionVote` by resolving the rotated leader via
/// topology.
#[derive(Debug, Clone)]
pub struct RetryEffect {
    pub(crate) tick_id: TickId,
    pub(crate) attempt: Attempt,
    pub(crate) block_hash: BlockHash,
    pub(crate) block_height: BlockHeight,
    pub(crate) vote_anchor_ts: WeightedTimestamp,
    pub(crate) global_receipt_root: GlobalReceiptRoot,
    pub(crate) tx_outcomes: Arc<Vec<TxOutcome>>,
}

/// Classification of an incoming cross-shard [`ExecutionCertificate`].
///
/// `routed_tx_hashes` are the `tx_hashes` covered by an existing local tick
/// — the coordinator feeds the certificate into each tick and clears them
/// from the early-arrival buffer. `unrouted_tx_hashes` have no local tick yet —
/// they're buffered for replay when their blocks commit.
#[derive(Debug, Default, Clone)]
pub struct AttestationRouting {
    pub(crate) affected_ticks: BTreeSet<TickId>,
    pub(crate) routed_tx_hashes: Vec<TxHash>,
    pub(crate) unrouted_tx_hashes: Vec<TxHash>,
}

/// Counts returned by [`TickRegistry::prune_resolved`] so the coordinator
/// can fold in its own early-vote pruning before the final log line.
#[derive(Debug, Default, Clone, Copy)]
pub struct PruneCounts {
    pub(crate) ticks: usize,
    pub(crate) trackers: usize,
    pub(crate) assignments: usize,
}

pub struct TickRegistry {
    /// Per-tick state. The authoritative "tick exists" signal; every other
    /// field is keyed off this presence.
    states: BTreeMap<TickId, TickState>,

    /// Per-tick vote trackers. Only populated at the tick leader (primary
    /// or fallback via rotation) to collect execution votes for EC
    /// aggregation.
    trackers: BTreeMap<TickId, VoteTracker>,

    /// Ticks whose local certificate aggregation has been dispatched OR whose local
    /// EC has already been received. Guards against creating a duplicate
    /// fallback tracker during the aggregation window — the
    /// `AggregateExecutionCertificate` action fires before
    /// `TickState::local_ec_emitted` flips on receipt.
    ec_dispatched: BTreeSet<TickId>,

    /// Pending vote retries for ticks whose leader hasn't produced a certificate.
    /// Populated by non-leaders at vote emission. Cleared on EC receipt or
    /// tick removal.
    retries: BTreeMap<TickId, PendingVoteRetry>,

    /// `tx_hash → tick_id` reverse index. The authoritative lookup for
    /// "what local tick does this transaction belong to" — drives certificate routing,
    /// certificate routing and proposal lookups.
    assignments: BTreeMap<TxHash, TickId>,
}

impl TickRegistry {
    pub(crate) const fn new() -> Self {
        Self {
            states: BTreeMap::new(),
            trackers: BTreeMap::new(),
            ec_dispatched: BTreeSet::new(),
            retries: BTreeMap::new(),
            assignments: BTreeMap::new(),
        }
    }

    // ─── Tick state ─────────────────────────────────────────────────────

    pub(crate) fn insert_tick(&mut self, tick_id: TickId, state: TickState) {
        self.states.insert(tick_id, state);
    }

    pub(crate) fn remove_tick(&mut self, tick_id: &TickId) -> Option<TickState> {
        self.states.remove(tick_id)
    }

    pub(crate) fn contains_tick(&self, tick_id: &TickId) -> bool {
        self.states.contains_key(tick_id)
    }

    pub(crate) fn get_tick(&self, tick_id: &TickId) -> Option<&TickState> {
        self.states.get(tick_id)
    }

    pub(crate) fn get_tick_mut(&mut self, tick_id: &TickId) -> Option<&mut TickState> {
        self.states.get_mut(tick_id)
    }

    pub(crate) fn ticks_iter(&self) -> impl Iterator<Item = (&TickId, &TickState)> {
        self.states.iter()
    }

    pub(crate) fn ticks_iter_mut(&mut self) -> impl Iterator<Item = (&TickId, &mut TickState)> {
        self.states.iter_mut()
    }

    // ─── Vote trackers ──────────────────────────────────────────────────

    pub(crate) fn insert_tracker(&mut self, tick_id: TickId, tracker: VoteTracker) {
        self.trackers.insert(tick_id, tracker);
    }

    pub(crate) fn remove_tracker(&mut self, tick_id: &TickId) -> Option<VoteTracker> {
        self.trackers.remove(tick_id)
    }

    pub(crate) fn contains_tracker(&self, tick_id: &TickId) -> bool {
        self.trackers.contains_key(tick_id)
    }

    pub(crate) fn get_tracker_mut(&mut self, tick_id: &TickId) -> Option<&mut VoteTracker> {
        self.trackers.get_mut(tick_id)
    }

    // ─── EC dispatch gate ───────────────────────────────────────────────

    pub(crate) fn mark_ec_dispatched(&mut self, tick_id: TickId) {
        self.ec_dispatched.insert(tick_id);
    }

    pub(crate) fn is_ec_dispatched(&self, tick_id: &TickId) -> bool {
        self.ec_dispatched.contains(tick_id)
    }

    // ─── Assignments ────────────────────────────────────────────────────

    pub(crate) fn assign_tx(&mut self, tx_hash: TxHash, tick_id: TickId) {
        self.assignments.insert(tx_hash, tick_id);
    }

    pub(crate) fn remove_assignment(&mut self, tx_hash: TxHash) {
        self.assignments.remove(&tx_hash);
    }

    pub(crate) fn tick_assignment(&self, tx_hash: TxHash) -> Option<TickId> {
        self.assignments.get(&tx_hash).copied()
    }

    // ─── Vote retries ───────────────────────────────────────────────────

    pub(crate) fn record_vote_retry(&mut self, tick_id: TickId, pending: PendingVoteRetry) {
        self.retries.insert(tick_id, pending);
    }

    pub(crate) fn clear_vote_retry(&mut self, tick_id: &TickId) {
        self.retries.remove(tick_id);
    }

    /// Advance every retry whose last dispatch is at least
    /// [`VOTE_RETRY_TIMEOUT`] behind `now_ts`. Returns one
    /// [`RetryEffect`] per fired retry; entries stay in the retry table
    /// with `attempt` incremented and `sent_at = now_ts` so the next
    /// tick runs the rotated-leader check again.
    pub(crate) fn check_vote_retry_timeouts(
        &mut self,
        now_ts: WeightedTimestamp,
    ) -> Vec<RetryEffect> {
        let fired: Vec<TickId> = self
            .retries
            .iter()
            .filter(|(_, p)| now_ts.elapsed_since(p.sent_at) >= VOTE_RETRY_TIMEOUT)
            .map(|(wid, _)| *wid)
            .collect();

        let mut effects = Vec::with_capacity(fired.len());
        for tick_id in fired {
            let pending = self
                .retries
                .get_mut(&tick_id)
                .expect("entry exists: we just collected its key");
            pending.attempt += 1;
            pending.sent_at = now_ts;
            effects.push(RetryEffect {
                tick_id,
                attempt: pending.attempt,
                block_hash: pending.block_hash,
                block_height: pending.block_height,
                vote_anchor_ts: pending.vote_anchor_ts,
                global_receipt_root: pending.global_receipt_root,
                tx_outcomes: Arc::clone(&pending.tx_outcomes),
            });
        }
        effects
    }

    // ─── Attestation routing ────────────────────────────────────────────

    /// Classify `ec`'s `tx_outcomes` by whether they have a local tick
    /// assignment. Read-only — mutation happens through the coordinator's
    /// follow-up calls to [`TickRegistry::get_tick_mut`] and to the
    /// early-arrival buffer.
    pub(crate) fn classify_attestation(&self, ec: &ExecutionCertificate) -> AttestationRouting {
        let mut routing = AttestationRouting::default();
        for outcome in ec.tx_outcomes() {
            match self.assignments.get(&outcome.tx_hash()) {
                Some(tick_id) => {
                    routing.affected_ticks.insert(*tick_id);
                    routing.routed_tx_hashes.push(outcome.tx_hash());
                }
                None => routing.unrouted_tx_hashes.push(outcome.tx_hash()),
            }
        }
        routing
    }

    // ─── Queries that span multiple fields ──────────────────────────────

    /// Count of unique transactions still awaiting a counterpart's
    /// outcome. Used by observability to gauge the outstanding cross-shard
    /// backlog.
    pub(crate) fn cross_shard_pending_count(&self) -> usize {
        let mut pending_txs: HashSet<TxHash> = HashSet::new();
        for tick in self.states.values() {
            for h in tick.awaiting_tx_hashes() {
                pending_txs.insert(h);
            }
        }
        pending_txs.len()
    }

    // ─── Pruning ────────────────────────────────────────────────────────

    /// Drop every tick and everything keyed against it, returning the
    /// counts. Used when the local chain terminates at a reshape
    /// boundary: finalization is a finalization in a later block,
    /// and a terminated chain commits no later block, so every pending
    /// tick here is permanently undecidable.
    pub(crate) fn drain_all(&mut self) -> PruneCounts {
        let counts = PruneCounts {
            ticks: self.states.len(),
            trackers: self.trackers.len(),
            assignments: self.assignments.len(),
        };
        self.states.clear();
        self.trackers.clear();
        self.ec_dispatched.clear();
        self.retries.clear();
        self.assignments.clear();
        counts
    }

    /// Drop one tick and everything keyed against it, including the
    /// assignments of every member it holds.
    ///
    /// The members are released rather than resolved: each is owed an
    /// outcome still, and with no tick holding it the deadline path is
    /// what reaches one.
    pub(crate) fn discard_tick(&mut self, tick_id: &TickId) -> PruneCounts {
        let ticks = usize::from(self.states.remove(tick_id).is_some());
        let trackers = usize::from(self.trackers.remove(tick_id).is_some());
        self.ec_dispatched.remove(tick_id);
        self.retries.remove(tick_id);

        let before_assignments = self.assignments.len();
        self.assignments.retain(|_, held_by| held_by != tick_id);
        PruneCounts {
            ticks,
            trackers,
            assignments: before_assignments - self.assignments.len(),
        }
    }

    /// Drop resolved ticks and everything keyed against them.
    ///
    /// Ticks whose `tick_id` no longer appears in `assignments.values()`
    /// are considered resolved — their txs reached terminal state and the
    /// assignments were cleared by finalization. Trackers, EC-dispatch
    /// marks, retries, and assignments pointing at now-gone ticks all
    /// cascade.
    ///
    /// Emits a warning for vote trackers pruned with non-zero verified
    /// power (never reached quorum) so the operator sees split-receipt
    /// cases. No-op if every field is already consistent.
    pub(crate) fn prune_resolved(&mut self) -> PruneCounts {
        let active_keys: HashSet<&TickId> = self.assignments.values().collect();

        let before_ticks = self.states.len();
        self.states.retain(|key, _| active_keys.contains(key));
        let ticks_pruned = before_ticks - self.states.len();

        let before_trackers = self.trackers.len();
        let states = &self.states;
        self.trackers.retain(|key, tracker| {
            if states.contains_key(key) {
                return true;
            }
            let root_count = tracker.distinct_global_receipt_root_count();
            if root_count > 1 {
                let summary = tracker.global_receipt_root_power_summary();
                tracing::warn!(
                    tick = %key,
                    global_receipt_root_split = ?summary,
                    "Pruning vote tracker that never reached quorum — global receipt roots were split"
                );
            } else if tracker.total_verified_power() > VoteCount::ZERO {
                tracing::warn!(
                    tick = %key,
                    verified_power = tracker.total_verified_power().inner(),
                    "Pruning vote tracker that never reached quorum — insufficient votes"
                );
            }
            false
        });
        let trackers_pruned = before_trackers - self.trackers.len();

        self.ec_dispatched.retain(|key| states.contains_key(key));
        self.retries.retain(|key, _| active_keys.contains(key));

        let before_assignments = self.assignments.len();
        self.assignments
            .retain(|_, tick_id| states.contains_key(tick_id));
        let assignments_pruned = before_assignments - self.assignments.len();

        PruneCounts {
            ticks: ticks_pruned,
            trackers: trackers_pruned,
            assignments: assignments_pruned,
        }
    }

    // ─── Stats ──────────────────────────────────────────────────────────

    pub(crate) fn ticks_len(&self) -> usize {
        self.states.len()
    }

    pub(crate) fn trackers_len(&self) -> usize {
        self.trackers.len()
    }

    pub(crate) fn ec_dispatched_len(&self) -> usize {
        self.ec_dispatched.len()
    }

    pub(crate) fn retries_len(&self) -> usize {
        self.retries.len()
    }

    pub(crate) fn assignments_len(&self) -> usize {
        self.assignments.len()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::test_utils::test_transaction;
    use hyperscale_types::{
        AggregateSignature, BlockHash, BlockHeight, ExecutionOutcome, GlobalReceiptHash, Hash,
        ShardId, SignerBitfield,
    };
    use proptest::collection::vec as prop_vec;

    use super::*;
    use crate::tick_state::{Admission, Membership};

    fn shard() -> ShardId {
        ShardId::ROOT
    }

    fn tick(height: u64) -> TickId {
        TickId::new(shard(), BlockHeight::new(height))
    }

    fn ms(value: u64) -> WeightedTimestamp {
        WeightedTimestamp::from_millis(value)
    }

    fn make_tick_state(tick_id: TickId, block_hash: BlockHash, tx_seed: u8) -> TickState {
        let mut state = TickState::new(tick_id, block_hash, ms(0));
        state.admit(
            test_transaction(tx_seed).hash(),
            Membership::whole(BTreeSet::from([shard()])),
            Some(1),
            Admission::Executes,
        );
        state
    }

    fn make_tracker(tick_id: TickId, block_hash: BlockHash) -> VoteTracker {
        VoteTracker::new(tick_id, block_hash, VoteCount::new(3))
    }

    fn make_outcome(tx_hash: TxHash) -> TxOutcome {
        TxOutcome::new(
            tx_hash,
            ExecutionOutcome::Succeeded {
                receipt_hash: GlobalReceiptHash::ZERO,
            },
        )
    }

    fn make_ec(tick_id: TickId, tx_hashes: &[TxHash]) -> ExecutionCertificate {
        ExecutionCertificate::new(
            tick_id,
            WeightedTimestamp::ZERO,
            GlobalReceiptRoot::ZERO,
            tx_hashes.iter().map(|h| make_outcome(*h)).collect(),
            AggregateSignature::ZERO,
            SignerBitfield::new(4),
        )
    }

    // ─── Basic insert / lookup ─────────────────────────────────────────

    #[test]
    fn fresh_registry_is_empty() {
        let r = TickRegistry::new();
        assert_eq!(r.ticks_len(), 0);
        assert_eq!(r.trackers_len(), 0);
        assert_eq!(r.ec_dispatched_len(), 0);
        assert_eq!(r.retries_len(), 0);
        assert_eq!(r.assignments_len(), 0);
    }

    #[test]
    fn insert_and_query_tick_state() {
        let mut r = TickRegistry::new();
        let wid = tick(1);
        r.insert_tick(wid, make_tick_state(wid, BlockHash::ZERO, 1));
        assert!(r.contains_tick(&wid));
        assert!(r.get_tick(&wid).is_some());
        assert_eq!(r.ticks_len(), 1);
    }

    #[test]
    fn insert_and_remove_tracker() {
        let mut r = TickRegistry::new();
        let wid = tick(1);
        r.insert_tracker(wid, make_tracker(wid, BlockHash::ZERO));
        assert!(r.contains_tracker(&wid));

        let removed = r.remove_tracker(&wid);
        assert!(removed.is_some());
        assert!(!r.contains_tracker(&wid));
    }

    #[test]
    fn ec_dispatched_is_idempotent() {
        let mut r = TickRegistry::new();
        let wid = tick(1);
        r.mark_ec_dispatched(wid);
        r.mark_ec_dispatched(wid);
        assert_eq!(r.ec_dispatched_len(), 1);
        assert!(r.is_ec_dispatched(&wid));
    }

    #[test]
    fn assign_and_lookup_tx() {
        let mut r = TickRegistry::new();
        let tx = TxHash::from(Hash::from_bytes(b"tx"));
        let wid = tick(1);
        r.assign_tx(tx, wid);
        assert_eq!(r.tick_assignment(tx), Some(wid));

        r.remove_assignment(tx);
        assert_eq!(r.tick_assignment(tx), None);
    }

    // ─── Vote-retry timeouts ───────────────────────────────────────────

    fn make_retry(sent_at: WeightedTimestamp) -> PendingVoteRetry {
        PendingVoteRetry {
            sent_at,
            attempt: Attempt::INITIAL,
            block_hash: BlockHash::ZERO,
            block_height: BlockHeight::new(1),
            vote_anchor_ts: ms(0),
            global_receipt_root: GlobalReceiptRoot::ZERO,
            tx_outcomes: Arc::new(vec![]),
        }
    }

    #[test]
    fn check_vote_retry_timeouts_fires_after_window_and_bumps_attempt() {
        let mut r = TickRegistry::new();
        let wid = tick(1);
        r.record_vote_retry(wid, make_retry(ms(0)));

        let timeout_ms = u64::try_from(VOTE_RETRY_TIMEOUT.as_millis()).unwrap_or(u64::MAX);
        // Before the window: no effect.
        let effects = r.check_vote_retry_timeouts(ms(timeout_ms - 1));
        assert!(effects.is_empty());

        // At the window: one effect, attempt bumped.
        let effects = r.check_vote_retry_timeouts(ms(timeout_ms));
        assert_eq!(effects.len(), 1);
        assert_eq!(effects[0].attempt, Attempt::new(1));

        // Retry cooldown restarts from the new sent_at.
        let effects = r.check_vote_retry_timeouts(ms(timeout_ms + 1));
        assert!(effects.is_empty());
    }

    #[test]
    fn clear_vote_retry_stops_further_effects() {
        let mut r = TickRegistry::new();
        let wid = tick(1);
        r.record_vote_retry(wid, make_retry(ms(0)));
        r.clear_vote_retry(&wid);

        let effects = r.check_vote_retry_timeouts(ms(100_000));
        assert!(effects.is_empty());
    }

    // ─── Attestation routing ───────────────────────────────────────────

    #[test]
    fn classify_attestation_splits_routed_and_unrouted() {
        let mut r = TickRegistry::new();
        let tx_known = TxHash::from(Hash::from_bytes(b"known"));
        let tx_unknown = TxHash::from(Hash::from_bytes(b"unknown"));
        let wid = tick(1);

        r.assign_tx(tx_known, wid);

        let ec = make_ec(wid, &[tx_known, tx_unknown]);
        let routing = r.classify_attestation(&ec);

        assert_eq!(routing.routed_tx_hashes, vec![tx_known]);
        assert_eq!(routing.unrouted_tx_hashes, vec![tx_unknown]);
        assert!(routing.affected_ticks.contains(&wid));
    }

    // ─── Pruning ───────────────────────────────────────────────────────

    #[test]
    fn drain_all_empties_every_table() {
        let mut r = TickRegistry::new();
        let wid1 = tick(1);
        let wid2 = tick(2);
        let ws1 = make_tick_state(wid1, BlockHash::ZERO, 1);
        let tx1 = ws1.tx_hashes()[0];
        r.insert_tick(wid1, ws1);
        r.assign_tx(tx1, wid1);
        r.insert_tick(wid2, make_tick_state(wid2, BlockHash::ZERO, 2));
        r.mark_ec_dispatched(wid2);

        let counts = r.drain_all();
        assert_eq!(counts.ticks, 2);
        assert_eq!(counts.assignments, 1);
        assert!(!r.contains_tick(&wid1));
        assert!(!r.contains_tick(&wid2));
        assert!(!r.is_ec_dispatched(&wid2));
        assert!(r.tick_assignment(tx1).is_none());
    }

    #[test]
    fn prune_resolved_drops_ticks_without_active_assignments() {
        let mut r = TickRegistry::new();
        let wid1 = tick(1);
        let wid2 = tick(2);
        r.insert_tick(wid1, make_tick_state(wid1, BlockHash::ZERO, 1));
        r.insert_tick(wid2, make_tick_state(wid2, BlockHash::ZERO, 2));
        r.assign_tx(TxHash::from(Hash::from_bytes(b"a")), wid1);
        // wid2 has no assignment — it's resolved.

        let counts = r.prune_resolved();
        assert_eq!(counts.ticks, 1);
        assert!(r.contains_tick(&wid1));
        assert!(!r.contains_tick(&wid2));
    }

    /// Discarding a tick releases every member it held, leaving each owed
    /// an outcome with nothing holding it — and touches no other tick.
    #[test]
    fn discard_tick_releases_every_member_it_held() {
        let mut r = TickRegistry::new();
        let discarded = tick(1);
        let survivor = tick(2);
        let held = TxHash::from(Hash::from_bytes(b"held"));
        let sibling = TxHash::from(Hash::from_bytes(b"sibling"));
        let elsewhere = TxHash::from(Hash::from_bytes(b"elsewhere"));
        r.insert_tick(discarded, make_tick_state(discarded, BlockHash::ZERO, 1));
        r.insert_tick(survivor, make_tick_state(survivor, BlockHash::ZERO, 2));
        r.mark_ec_dispatched(discarded);
        r.assign_tx(held, discarded);
        r.assign_tx(sibling, discarded);
        r.assign_tx(elsewhere, survivor);

        let counts = r.discard_tick(&discarded);
        assert_eq!(counts.ticks, 1);
        assert_eq!(counts.assignments, 2);
        assert!(!r.contains_tick(&discarded));
        assert!(!r.is_ec_dispatched(&discarded));
        assert!(r.tick_assignment(held).is_none());
        assert!(r.tick_assignment(sibling).is_none());
        assert_eq!(r.tick_assignment(elsewhere), Some(survivor));
        assert!(r.contains_tick(&survivor));
    }

    #[test]
    fn prune_resolved_drops_assignments_whose_ticks_are_gone() {
        let mut r = TickRegistry::new();
        let wid1 = tick(1);
        let wid_gone = tick(99);
        r.insert_tick(wid1, make_tick_state(wid1, BlockHash::ZERO, 1));
        r.assign_tx(TxHash::from(Hash::from_bytes(b"a")), wid1);
        r.assign_tx(TxHash::from(Hash::from_bytes(b"dangling")), wid_gone);

        let counts = r.prune_resolved();
        assert_eq!(counts.assignments, 1);
        assert_eq!(r.assignments_len(), 1);
    }

    // ─── Property test: cleanup atomicity ──────────────────────────────

    use proptest::prelude::*;

    // After prune_resolved, every surviving assignment points to a
    // surviving tick, and every surviving tick's key appears in the
    // assignments values. Trackers, EC-dispatch marks, and retries for
    // removed ticks are all dropped.
    proptest! {
        #[test]
        fn prune_resolved_leaves_registry_consistent(
            tick_heights in prop_vec(0u64..10, 1..10),
            assignment_indices in prop_vec(0usize..20, 0..20),
        ) {
            let mut r = TickRegistry::new();
            let tick_ids: Vec<TickId> = tick_heights.iter().map(|h| tick(*h)).collect();
            for wid in &tick_ids {
                r.insert_tick(*wid, make_tick_state(*wid, BlockHash::ZERO, 1));
                r.insert_tracker(*wid, make_tracker(*wid, BlockHash::ZERO));
                r.mark_ec_dispatched(*wid);
                r.record_vote_retry(*wid, make_retry(ms(0)));
            }
            // Assign some subset of txs to some subset of ticks.
            for (i, idx) in assignment_indices.iter().enumerate() {
                let tx = TxHash::from(Hash::from_bytes(&[u8::try_from(i).unwrap_or(u8::MAX); 32]));
                let wid = &tick_ids[idx % tick_ids.len()];
                r.assign_tx(tx, *wid);
            }

            let _ = r.prune_resolved();

            // Invariant 1: every assignment points to a live tick.
            for wid in (0_u8..20).filter_map(|i| {
                r.tick_assignment(TxHash::from(Hash::from_bytes(&[i; 32])))
            }) {
                prop_assert!(r.contains_tick(&wid));
            }
            // Invariant 2: every tracker / ec_dispatched / retry key has a live tick
            // (tracker may exceptionally be retained if its key points to a tick,
            // which is the same invariant).
            for (wid, _) in r.ticks_iter() {
                // Surviving ticks must have at least one assignment.
                let referenced = (0_u8..20).any(|i| {
                    r.tick_assignment(TxHash::from(Hash::from_bytes(&[i; 32])))
                        .as_ref()
                        == Some(wid)
                });
                prop_assert!(referenced, "surviving tick {wid:?} not referenced by any assignment");
            }
        }
    }
}
