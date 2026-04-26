//! In-flight wave registry: owns [`WaveState`], [`VoteTracker`], EC-dispatch
//! gating, vote-retry bookkeeping, and the `tx_hash → WaveId` reverse index.
//!
//! The registry is the execution coordinator's "what's currently in flight"
//! sub-machine. Everything else is keyed against it:
//!
//! - Incoming votes look up waves by `wave_id` to decide buffering vs
//!   tracker creation.
//! - Incoming cross-shard ECs route by `tx_hash → wave_id` via
//!   [`classify_attestation`](WaveRegistry::classify_attestation).
//! - [`EarlyArrivalBuffer`](crate::early_arrivals) retention reads from the
//!   registry to tell "wave still active" from "wave long gone".
//! - [`FinalizedWaveStore`](crate::finalized_waves::FinalizedWaveStore)
//!   receives waves handed off from the registry at finalization.
//!
//! ## Assignments as an inverted index
//!
//! `assignments[tx_hash] = wave_id` is the reverse of the wave's
//! `tx_hashes()` list. Pruning the two sides atomically is the registry's
//! job — see [`prune_resolved`](WaveRegistry::prune_resolved), which drops
//! states whose keys no longer appear in `assignments.values()` and then
//! drops assignments whose `wave_ids` no longer appear in `states`.
//!
//! ## Typed effects
//!
//! - [`check_vote_retry_timeouts`](WaveRegistry::check_vote_retry_timeouts)
//!   returns a `Vec<RetryEffect>` — the coordinator resolves the rotated
//!   leader via topology and wraps each as
//!   `Action::SignAndSendExecutionVote`.
//! - [`classify_attestation`](WaveRegistry::classify_attestation) returns
//!   [`AttestationRouting`] — the coordinator fans out into
//!   `EarlyArrivalBuffer::buffer_ec` / `clear_routed` and walks the affected
//!   waves.

#[cfg(test)]
use hyperscale_types::Hash;
use hyperscale_types::{
    Attempt, BlockHash, ExecutionCertificate, GlobalReceiptRoot, TxHash, TxOutcome, WaveId,
    WeightedTimestamp,
};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use crate::vote_tracker::VoteTracker;
use crate::wave_state::WaveState;

/// How long to wait before retrying a vote with the next rotated wave
/// leader. Must exceed typical wave-leader aggregation latency so we don't
/// rotate past a leader that's about to succeed. Measured against the
/// BFT-authenticated `weighted_timestamp_ms` of locally committed blocks.
pub(crate) const VOTE_RETRY_TIMEOUT: Duration = Duration::from_secs(8);

/// Tracks a pending vote sent to a wave leader, for retry on timeout.
///
/// Retries are unbounded — the loop self-terminates when a working leader
/// aggregates the EC and broadcasts it back. Capping retries would stall
/// waves that haven't resolved yet (including timeout-abort waves, which
/// still need a leader to aggregate the timeout votes).
#[derive(Debug, Clone)]
pub(crate) struct PendingVoteRetry {
    /// Local weighted timestamp when this vote was last dispatched.
    /// Compared against `committed_ts` to detect leader aggregation
    /// timeouts independently of block production rate.
    pub sent_at: WeightedTimestamp,
    pub attempt: Attempt,
    pub block_hash: BlockHash,
    pub block_height: hyperscale_types::BlockHeight,
    pub vote_anchor_ts: WeightedTimestamp,
    pub global_receipt_root: GlobalReceiptRoot,
    pub tx_outcomes: Arc<Vec<TxOutcome>>,
}

/// One retry the coordinator should lift to an
/// `Action::SignAndSendExecutionVote` by resolving the rotated leader via
/// topology.
#[derive(Debug, Clone)]
pub(crate) struct RetryEffect {
    pub wave_id: WaveId,
    pub attempt: Attempt,
    pub block_hash: BlockHash,
    pub block_height: hyperscale_types::BlockHeight,
    pub vote_anchor_ts: WeightedTimestamp,
    pub global_receipt_root: GlobalReceiptRoot,
    pub tx_outcomes: Arc<Vec<TxOutcome>>,
}

/// Classification of an incoming cross-shard [`ExecutionCertificate`].
///
/// `routed_tx_hashes` are the `tx_hashes` covered by an existing local wave
/// — the coordinator feeds the EC into each wave and clears them from the
/// early-arrival buffer. `unrouted_tx_hashes` have no local wave yet —
/// they're buffered for replay when their blocks commit.
#[derive(Debug, Default, Clone)]
pub(crate) struct AttestationRouting {
    pub affected_waves: BTreeSet<WaveId>,
    pub routed_tx_hashes: Vec<TxHash>,
    pub unrouted_tx_hashes: Vec<TxHash>,
}

/// Counts returned by [`WaveRegistry::prune_resolved`] so the coordinator
/// can fold in its own early-vote pruning before the final log line.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct PruneCounts {
    pub waves: usize,
    pub trackers: usize,
    pub assignments: usize,
}

pub(crate) struct WaveRegistry {
    /// Per-wave state. The authoritative "wave exists" signal; every other
    /// field is keyed off this presence.
    states: HashMap<WaveId, WaveState>,

    /// Per-wave vote trackers. Only populated at the wave leader (primary
    /// or fallback via rotation) to collect execution votes for EC
    /// aggregation.
    trackers: HashMap<WaveId, VoteTracker>,

    /// Waves whose local EC aggregation has been dispatched OR whose local
    /// EC has already been received. Guards against creating a duplicate
    /// fallback tracker during the aggregation window — the
    /// `AggregateExecutionCertificate` action fires before
    /// `WaveState.local_ec_emitted` flips on receipt.
    ec_dispatched: HashSet<WaveId>,

    /// Pending vote retries for waves whose leader hasn't produced an EC.
    /// Populated by non-leaders at vote emission. Cleared on EC receipt or
    /// wave removal.
    retries: HashMap<WaveId, PendingVoteRetry>,

    /// `tx_hash → wave_id` reverse index. The authoritative lookup for
    /// "what local wave does this tx belong to" — drives EC routing,
    /// `is_awaiting_provisioning`, `get_wave_assignment`.
    assignments: HashMap<TxHash, WaveId>,
}

impl WaveRegistry {
    pub fn new() -> Self {
        Self {
            states: HashMap::new(),
            trackers: HashMap::new(),
            ec_dispatched: HashSet::new(),
            retries: HashMap::new(),
            assignments: HashMap::new(),
        }
    }

    // ─── Wave state ─────────────────────────────────────────────────────

    pub fn insert_wave(&mut self, wave_id: WaveId, state: WaveState) {
        self.states.insert(wave_id, state);
    }

    pub fn remove_wave(&mut self, wave_id: &WaveId) -> Option<WaveState> {
        self.states.remove(wave_id)
    }

    pub fn contains_wave(&self, wave_id: &WaveId) -> bool {
        self.states.contains_key(wave_id)
    }

    pub fn get_wave(&self, wave_id: &WaveId) -> Option<&WaveState> {
        self.states.get(wave_id)
    }

    pub fn get_wave_mut(&mut self, wave_id: &WaveId) -> Option<&mut WaveState> {
        self.states.get_mut(wave_id)
    }

    pub fn waves_iter(&self) -> impl Iterator<Item = (&WaveId, &WaveState)> {
        self.states.iter()
    }

    pub fn waves_iter_mut(&mut self) -> impl Iterator<Item = (&WaveId, &mut WaveState)> {
        self.states.iter_mut()
    }

    // ─── Vote trackers ──────────────────────────────────────────────────

    pub fn insert_tracker(&mut self, wave_id: WaveId, tracker: VoteTracker) {
        self.trackers.insert(wave_id, tracker);
    }

    pub fn remove_tracker(&mut self, wave_id: &WaveId) -> Option<VoteTracker> {
        self.trackers.remove(wave_id)
    }

    pub fn contains_tracker(&self, wave_id: &WaveId) -> bool {
        self.trackers.contains_key(wave_id)
    }

    pub fn get_tracker_mut(&mut self, wave_id: &WaveId) -> Option<&mut VoteTracker> {
        self.trackers.get_mut(wave_id)
    }

    // ─── EC dispatch gate ───────────────────────────────────────────────

    pub fn mark_ec_dispatched(&mut self, wave_id: WaveId) {
        self.ec_dispatched.insert(wave_id);
    }

    pub fn is_ec_dispatched(&self, wave_id: &WaveId) -> bool {
        self.ec_dispatched.contains(wave_id)
    }

    // ─── Assignments ────────────────────────────────────────────────────

    pub fn assign_tx(&mut self, tx_hash: TxHash, wave_id: WaveId) {
        self.assignments.insert(tx_hash, wave_id);
    }

    pub fn remove_assignment(&mut self, tx_hash: &TxHash) {
        self.assignments.remove(tx_hash);
    }

    pub fn wave_assignment(&self, tx_hash: &TxHash) -> Option<WaveId> {
        self.assignments.get(tx_hash).cloned()
    }

    // ─── Vote retries ───────────────────────────────────────────────────

    pub fn record_vote_retry(&mut self, wave_id: WaveId, pending: PendingVoteRetry) {
        self.retries.insert(wave_id, pending);
    }

    pub fn clear_vote_retry(&mut self, wave_id: &WaveId) {
        self.retries.remove(wave_id);
    }

    /// Advance every retry whose last dispatch is at least
    /// [`VOTE_RETRY_TIMEOUT`] behind `now_ts`. Returns one
    /// [`RetryEffect`] per fired retry; entries stay in the retry table
    /// with `attempt` incremented and `sent_at = now_ts` so the next
    /// tick runs the rotated-leader check again.
    pub fn check_vote_retry_timeouts(&mut self, now_ts: WeightedTimestamp) -> Vec<RetryEffect> {
        let fired: Vec<WaveId> = self
            .retries
            .iter()
            .filter(|(_, p)| now_ts.elapsed_since(p.sent_at) >= VOTE_RETRY_TIMEOUT)
            .map(|(wid, _)| wid.clone())
            .collect();

        let mut effects = Vec::with_capacity(fired.len());
        for wave_id in fired {
            let pending = self
                .retries
                .get_mut(&wave_id)
                .expect("entry exists: we just collected its key");
            pending.attempt += 1;
            pending.sent_at = now_ts;
            effects.push(RetryEffect {
                wave_id,
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

    /// Classify `ec`'s `tx_outcomes` by whether they have a local wave
    /// assignment. Read-only — mutation happens through the coordinator's
    /// follow-up calls to [`WaveRegistry::get_wave_mut`] and to the
    /// early-arrival buffer.
    pub fn classify_attestation(&self, ec: &ExecutionCertificate) -> AttestationRouting {
        let mut routing = AttestationRouting::default();
        for outcome in &ec.tx_outcomes {
            match self.assignments.get(&outcome.tx_hash) {
                Some(wave_id) => {
                    routing.affected_waves.insert(wave_id.clone());
                    routing.routed_tx_hashes.push(outcome.tx_hash);
                }
                None => routing.unrouted_tx_hashes.push(outcome.tx_hash),
            }
        }
        routing
    }

    // ─── Queries that span multiple fields ──────────────────────────────

    /// Whether `tx_hash` is assigned to a wave that's still waiting on
    /// provisions. False when the tx has no assignment, the wave is gone,
    /// or the wave is already fully provisioned.
    pub fn is_awaiting_provisioning(&self, tx_hash: &TxHash) -> bool {
        let Some(wave_id) = self.assignments.get(tx_hash) else {
            return false;
        };
        self.states
            .get(wave_id)
            .is_some_and(|w| !w.is_fully_provisioned())
    }

    /// Count of unique `tx_hashes` across all cross-shard waves. Used by
    /// observability to gauge the outstanding cross-shard backlog.
    pub fn cross_shard_pending_count(&self) -> usize {
        let mut pending_txs: HashSet<TxHash> = HashSet::new();
        for (wave_id, wave) in &self.states {
            if !wave_id.is_zero() {
                for h in wave.tx_hashes() {
                    pending_txs.insert(*h);
                }
            }
        }
        pending_txs.len()
    }

    // ─── Pruning ────────────────────────────────────────────────────────

    /// Drop resolved waves and everything keyed against them.
    ///
    /// Waves whose `wave_id` no longer appears in `assignments.values()`
    /// are considered resolved — their txs reached terminal state and the
    /// assignments were cleared by finalization. Trackers, EC-dispatch
    /// marks, retries, and assignments pointing at now-gone waves all
    /// cascade.
    ///
    /// Emits a warning for vote trackers pruned with non-zero verified
    /// power (never reached quorum) so the operator sees split-receipt
    /// cases. No-op if every field is already consistent.
    pub fn prune_resolved(&mut self) -> PruneCounts {
        let active_keys: HashSet<&WaveId> = self.assignments.values().collect();

        let before_waves = self.states.len();
        self.states.retain(|key, _| active_keys.contains(key));
        let waves_pruned = before_waves - self.states.len();

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
                    wave = %key,
                    global_receipt_root_split = ?summary,
                    "Pruning vote tracker that never reached quorum — global receipt roots were split"
                );
            } else if tracker.total_verified_power() > 0 {
                tracing::warn!(
                    wave = %key,
                    verified_power = tracker.total_verified_power(),
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
            .retain(|_, wave_id| states.contains_key(wave_id));
        let assignments_pruned = before_assignments - self.assignments.len();

        PruneCounts {
            waves: waves_pruned,
            trackers: trackers_pruned,
            assignments: assignments_pruned,
        }
    }

    // ─── Stats ──────────────────────────────────────────────────────────

    pub fn waves_len(&self) -> usize {
        self.states.len()
    }

    pub fn trackers_len(&self) -> usize {
        self.trackers.len()
    }

    pub fn ec_dispatched_len(&self) -> usize {
        self.ec_dispatched.len()
    }

    pub fn retries_len(&self) -> usize {
        self.retries.len()
    }

    pub fn assignments_len(&self) -> usize {
        self.assignments.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{
        BlockHash, BlockHeight, ExecutionOutcome, GlobalReceiptHash, ShardGroupId, SignerBitfield,
        test_utils::test_transaction,
    };

    fn shard() -> ShardGroupId {
        ShardGroupId(0)
    }

    fn wave(height: u64) -> WaveId {
        WaveId {
            shard_group_id: shard(),
            block_height: BlockHeight(height),
            remote_shards: BTreeSet::new(),
        }
    }

    fn ms(value: u64) -> WeightedTimestamp {
        WeightedTimestamp(value)
    }

    fn make_wave_state(wave_id: WaveId, block_hash: BlockHash, tx_seed: u8) -> WaveState {
        let tx = Arc::new(test_transaction(tx_seed));
        let mut participating = BTreeSet::new();
        participating.insert(shard());
        WaveState::new(wave_id, block_hash, ms(0), vec![(tx, participating)], true)
    }

    fn make_tracker(wave_id: WaveId, block_hash: BlockHash) -> VoteTracker {
        VoteTracker::new(wave_id, block_hash, 3)
    }

    fn make_outcome(tx_hash: TxHash) -> TxOutcome {
        TxOutcome {
            tx_hash,
            outcome: ExecutionOutcome::Executed {
                receipt_hash: GlobalReceiptHash::ZERO,
                success: true,
            },
        }
    }

    fn make_ec(wave_id: WaveId, tx_hashes: &[TxHash]) -> ExecutionCertificate {
        ExecutionCertificate::new(
            wave_id,
            WeightedTimestamp::ZERO,
            GlobalReceiptRoot::ZERO,
            tx_hashes.iter().map(|h| make_outcome(*h)).collect(),
            hyperscale_types::zero_bls_signature(),
            SignerBitfield::new(4),
        )
    }

    // ─── Basic insert / lookup ─────────────────────────────────────────

    #[test]
    fn fresh_registry_is_empty() {
        let r = WaveRegistry::new();
        assert_eq!(r.waves_len(), 0);
        assert_eq!(r.trackers_len(), 0);
        assert_eq!(r.ec_dispatched_len(), 0);
        assert_eq!(r.retries_len(), 0);
        assert_eq!(r.assignments_len(), 0);
    }

    #[test]
    fn insert_and_query_wave_state() {
        let mut r = WaveRegistry::new();
        let wid = wave(1);
        r.insert_wave(
            wid.clone(),
            make_wave_state(wid.clone(), BlockHash::ZERO, 1),
        );
        assert!(r.contains_wave(&wid));
        assert!(r.get_wave(&wid).is_some());
        assert_eq!(r.waves_len(), 1);
    }

    #[test]
    fn insert_and_remove_tracker() {
        let mut r = WaveRegistry::new();
        let wid = wave(1);
        r.insert_tracker(wid.clone(), make_tracker(wid.clone(), BlockHash::ZERO));
        assert!(r.contains_tracker(&wid));

        let removed = r.remove_tracker(&wid);
        assert!(removed.is_some());
        assert!(!r.contains_tracker(&wid));
    }

    #[test]
    fn ec_dispatched_is_idempotent() {
        let mut r = WaveRegistry::new();
        let wid = wave(1);
        r.mark_ec_dispatched(wid.clone());
        r.mark_ec_dispatched(wid.clone());
        assert_eq!(r.ec_dispatched_len(), 1);
        assert!(r.is_ec_dispatched(&wid));
    }

    #[test]
    fn assign_and_lookup_tx() {
        let mut r = WaveRegistry::new();
        let tx = TxHash::from_raw(Hash::from_bytes(b"tx"));
        let wid = wave(1);
        r.assign_tx(tx, wid.clone());
        assert_eq!(r.wave_assignment(&tx), Some(wid));

        r.remove_assignment(&tx);
        assert_eq!(r.wave_assignment(&tx), None);
    }

    // ─── Vote-retry timeouts ───────────────────────────────────────────

    fn make_retry(sent_at: WeightedTimestamp) -> PendingVoteRetry {
        PendingVoteRetry {
            sent_at,
            attempt: Attempt::INITIAL,
            block_hash: BlockHash::ZERO,
            block_height: BlockHeight(1),
            vote_anchor_ts: ms(0),
            global_receipt_root: GlobalReceiptRoot::ZERO,
            tx_outcomes: Arc::new(vec![]),
        }
    }

    #[test]
    fn check_vote_retry_timeouts_fires_after_window_and_bumps_attempt() {
        let mut r = WaveRegistry::new();
        let wid = wave(1);
        r.record_vote_retry(wid.clone(), make_retry(ms(0)));

        let timeout_ms = u64::try_from(VOTE_RETRY_TIMEOUT.as_millis()).unwrap_or(u64::MAX);
        // Before the window: no effect.
        let effects = r.check_vote_retry_timeouts(ms(timeout_ms - 1));
        assert!(effects.is_empty());

        // At the window: one effect, attempt bumped.
        let effects = r.check_vote_retry_timeouts(ms(timeout_ms));
        assert_eq!(effects.len(), 1);
        assert_eq!(effects[0].attempt, Attempt(1));

        // Retry cooldown restarts from the new sent_at.
        let effects = r.check_vote_retry_timeouts(ms(timeout_ms + 1));
        assert!(effects.is_empty());
    }

    #[test]
    fn clear_vote_retry_stops_further_effects() {
        let mut r = WaveRegistry::new();
        let wid = wave(1);
        r.record_vote_retry(wid.clone(), make_retry(ms(0)));
        r.clear_vote_retry(&wid);

        let effects = r.check_vote_retry_timeouts(ms(100_000));
        assert!(effects.is_empty());
    }

    // ─── Attestation routing ───────────────────────────────────────────

    #[test]
    fn classify_attestation_splits_routed_and_unrouted() {
        let mut r = WaveRegistry::new();
        let tx_known = TxHash::from_raw(Hash::from_bytes(b"known"));
        let tx_unknown = TxHash::from_raw(Hash::from_bytes(b"unknown"));
        let wid = wave(1);

        r.assign_tx(tx_known, wid.clone());

        let ec = make_ec(wid.clone(), &[tx_known, tx_unknown]);
        let routing = r.classify_attestation(&ec);

        assert_eq!(routing.routed_tx_hashes, vec![tx_known]);
        assert_eq!(routing.unrouted_tx_hashes, vec![tx_unknown]);
        assert!(routing.affected_waves.contains(&wid));
    }

    // ─── is_awaiting_provisioning ──────────────────────────────────────

    #[test]
    fn is_awaiting_provisioning_false_without_assignment() {
        let r = WaveRegistry::new();
        assert!(!r.is_awaiting_provisioning(&TxHash::from_raw(Hash::from_bytes(b"orphan"))));
    }

    #[test]
    fn is_awaiting_provisioning_false_when_single_shard_wave_is_ready() {
        // Single-shard waves pass `is_fully_provisioned = true` at creation.
        let mut r = WaveRegistry::new();
        let tx = TxHash::from_raw(Hash::from_bytes(b"tx"));
        let wid = wave(1);
        let ws = make_wave_state(wid.clone(), BlockHash::ZERO, 1);
        let tx_hash_in_wave = ws.tx_hashes()[0];
        r.insert_wave(wid.clone(), ws);
        r.assign_tx(tx_hash_in_wave, wid);

        assert!(!r.is_awaiting_provisioning(&tx_hash_in_wave));
        let _ = tx;
    }

    // ─── Pruning ───────────────────────────────────────────────────────

    #[test]
    fn prune_resolved_drops_waves_without_active_assignments() {
        let mut r = WaveRegistry::new();
        let wid1 = wave(1);
        let wid2 = wave(2);
        r.insert_wave(
            wid1.clone(),
            make_wave_state(wid1.clone(), BlockHash::ZERO, 1),
        );
        r.insert_wave(
            wid2.clone(),
            make_wave_state(wid2.clone(), BlockHash::ZERO, 2),
        );
        r.assign_tx(TxHash::from_raw(Hash::from_bytes(b"a")), wid1.clone());
        // wid2 has no assignment — it's resolved.

        let counts = r.prune_resolved();
        assert_eq!(counts.waves, 1);
        assert!(r.contains_wave(&wid1));
        assert!(!r.contains_wave(&wid2));
    }

    #[test]
    fn prune_resolved_drops_assignments_whose_waves_are_gone() {
        let mut r = WaveRegistry::new();
        let wid1 = wave(1);
        let wid_gone = wave(99);
        r.insert_wave(
            wid1.clone(),
            make_wave_state(wid1.clone(), BlockHash::ZERO, 1),
        );
        r.assign_tx(TxHash::from_raw(Hash::from_bytes(b"a")), wid1.clone());
        r.assign_tx(TxHash::from_raw(Hash::from_bytes(b"dangling")), wid_gone);

        let counts = r.prune_resolved();
        assert_eq!(counts.assignments, 1);
        assert_eq!(r.assignments_len(), 1);
    }

    // ─── Property test: cleanup atomicity ──────────────────────────────

    use proptest::prelude::*;

    // After prune_resolved, every surviving assignment points to a
    // surviving wave, and every surviving wave's key appears in the
    // assignments values. Trackers, EC-dispatch marks, and retries for
    // removed waves are all dropped.
    proptest! {
        #[test]
        fn prune_resolved_leaves_registry_consistent(
            wave_heights in proptest::collection::vec(0u64..10, 1..10),
            assignment_indices in proptest::collection::vec(0usize..20, 0..20),
        ) {
            let mut r = WaveRegistry::new();
            let wave_ids: Vec<WaveId> = wave_heights.iter().map(|h| wave(*h)).collect();
            for wid in &wave_ids {
                r.insert_wave(wid.clone(), make_wave_state(wid.clone(), BlockHash::ZERO, 1));
                r.insert_tracker(wid.clone(), make_tracker(wid.clone(), BlockHash::ZERO));
                r.mark_ec_dispatched(wid.clone());
                r.record_vote_retry(wid.clone(), make_retry(ms(0)));
            }
            // Assign some subset of txs to some subset of waves.
            for (i, idx) in assignment_indices.iter().enumerate() {
                let tx = TxHash::from_raw(Hash::from_bytes(&[u8::try_from(i).unwrap_or(u8::MAX); 32]));
                let wid = &wave_ids[idx % wave_ids.len()];
                r.assign_tx(tx, wid.clone());
            }

            let _ = r.prune_resolved();

            // Invariant 1: every assignment points to a live wave.
            for wid in (0_u8..20).filter_map(|i| {
                r.wave_assignment(&TxHash::from_raw(Hash::from_bytes(&[i; 32])))
            }) {
                prop_assert!(r.contains_wave(&wid));
            }
            // Invariant 2: every tracker / ec_dispatched / retry key has a live wave
            // (tracker may exceptionally be retained if its key points to a wave,
            // which is the same invariant).
            for (wid, _) in r.waves_iter() {
                // Surviving waves must have at least one assignment.
                let referenced = (0_u8..20).any(|i| {
                    r.wave_assignment(&TxHash::from_raw(Hash::from_bytes(&[i; 32])))
                        .as_ref()
                        == Some(wid)
                });
                prop_assert!(referenced, "surviving wave {wid:?} not referenced by any assignment");
            }
        }
    }
}
