//! Pending [`ReadySignal`] pool — local-only state owned by the shard
//! coordinator.
//!
//! Validators broadcast `ReadySignalNotification` to every member of
//! their shard committee; each member admits the signal into this pool.
//! At proposal time the local proposer drains dwell-eligible signals
//! into the next block's
//! [`BlockManifest::ready_signals`](hyperscale_types::BlockManifest::ready_signals);
//! beacon's `Ready` witness derives one entry per included signal.
//!
//! The pool is keyed by `validator_id` so a re-emission from the same
//! sender overwrites their previous pending entry — keeps the freshest
//! `received_at` and tracks the latest valid window. Window expiry,
//! dwell, and an externally-supplied "already ready" predicate drive
//! eviction.

use std::collections::BTreeMap;
use std::time::Duration;

use hyperscale_types::{LocalTimestamp, ReadySignal, ValidatorId, WeightedTimestamp};

/// Minimum dwell time before a [`ReadySignal`] is eligible to be
/// drained into a block.
///
/// Matches the mempool's `DEFAULT_MIN_DWELL_TIME` — admission and drain
/// both honour this so a signal has had time to propagate to other
/// committee members before it gets committed.
pub const MIN_READY_SIGNAL_DWELL: Duration = Duration::from_millis(150);

/// Locally-pooled `ReadySignal` paired with the time we received it.
///
/// `received_at` drives the dwell-eligibility check (callers compare
/// against `now - MIN_READY_SIGNAL_DWELL`); honouring a minimum dwell
/// gives the gossip fan-out time to converge across honest committee
/// members before the signal is binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingReadySignal {
    /// The signal itself — carries validator id, height window, BLS sig.
    pub signal: ReadySignal,
    /// When this node accepted the signal into the pool.
    pub received_at: LocalTimestamp,
}

/// Pool of [`PendingReadySignal`]s the local node is holding for the
/// next proposal.
///
/// Stored as a `BTreeMap` keyed by `ValidatorId` so drained signals
/// come out in deterministic ascending order — matches the canonical
/// ordering the leaf-derivation rule expects (see
/// [`crate::beacon_witnesses::derive_leaves`]).
#[derive(Debug, Default)]
pub struct ReadySignalPool {
    pending: BTreeMap<ValidatorId, PendingReadySignal>,
}

impl ReadySignalPool {
    /// Construct an empty pool.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            pending: BTreeMap::new(),
        }
    }

    /// Number of pending signals currently held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// `true` when the pool holds no pending signals.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Admit `signal` into the pool with `received_at` as its arrival
    /// stamp. A re-emission carrying a *new* window supersedes the older
    /// entry and resets the dwell clock; a re-emission of the window
    /// already held keeps the earlier `received_at`, so the dwell accrues.
    ///
    /// The keep-on-repeat rule is load-bearing: a reshape observer
    /// re-asserts its ready signal every reshape pump — far more often
    /// than [`MIN_READY_SIGNAL_DWELL`] — against the same anchor window
    /// until the split executes. Overwriting `received_at` on each repeat
    /// would pin the dwell below the threshold forever, so
    /// [`Self::drain_eligible`] would never collect the signal and the
    /// cohort's `ReshapeReady` would never commit.
    ///
    /// Caller is responsible for any cryptographic verification (BLS
    /// sig over [`crate::signing::ready_signal_message`]) before
    /// calling — the pool trusts what it's given and only enforces
    /// pool-shape invariants.
    pub fn admit(&mut self, signal: ReadySignal, received_at: LocalTimestamp) {
        if let Some(existing) = self.pending.get(&signal.validator_id())
            && existing.signal.wt_window_start() == signal.wt_window_start()
            && existing.signal.wt_window_end() == signal.wt_window_end()
        {
            return;
        }
        self.pending.insert(
            signal.validator_id(),
            PendingReadySignal {
                signal,
                received_at,
            },
        );
    }

    /// Drop entries whose window-end has passed `committed_wt`.
    ///
    /// Run on every block commit to keep the pool bounded by window
    /// length. A validator whose signal expires uncollected re-emits
    /// with a fresh window.
    pub fn evict_expired(&mut self, committed_wt: WeightedTimestamp) {
        self.pending
            .retain(|_, entry| entry.signal.wt_window_end() >= committed_wt);
    }

    /// Drop entries whose `validator_id` satisfies `is_already_ready`.
    ///
    /// Called after applying a `Ready` witness — once beacon state
    /// reflects the readiness transition, holding the signal is
    /// redundant and another proposer could re-include it. The
    /// predicate stays caller-supplied so this module doesn't have to
    /// reach into beacon state directly.
    pub fn evict_ready(&mut self, is_already_ready: impl Fn(ValidatorId) -> bool) {
        self.pending.retain(|id, _| !is_already_ready(*id));
    }

    /// Drain dwell-eligible signals up to `max` entries.
    ///
    /// A signal is dwell-eligible when `now - received_at >=
    /// min_dwell`. Drained entries are removed from the pool. Signals
    /// whose `[start, end]` window does not cover `proposal_wt` (the
    /// proposal's parent-QC weighted timestamp) stay in the pool
    /// unchanged — a not-yet-open window may still be drained at a later
    /// proposal, and an expired one is reaped by [`Self::evict_expired`]
    /// on the next commit rather than being dropped mid-drain. Returns
    /// signals in ascending `validator_id` order — matching the canonical
    /// leaf-derivation order downstream.
    pub fn drain_eligible(
        &mut self,
        proposal_wt: WeightedTimestamp,
        now: LocalTimestamp,
        min_dwell: Duration,
        max: usize,
    ) -> Vec<ReadySignal> {
        let mut drained = Vec::new();
        let mut keys_to_remove = Vec::new();
        for (id, entry) in &self.pending {
            if drained.len() >= max {
                break;
            }
            let dwell = now.saturating_sub(entry.received_at);
            if dwell < min_dwell {
                continue;
            }
            if proposal_wt < entry.signal.wt_window_start()
                || proposal_wt > entry.signal.wt_window_end()
            {
                continue;
            }
            drained.push(entry.signal.clone());
            keys_to_remove.push(*id);
        }
        for id in keys_to_remove {
            self.pending.remove(&id);
        }
        drained
    }

    /// Read-only iterator over the pool's current entries. Order is
    /// ascending by `validator_id` (the `BTreeMap` storage order).
    pub fn iter(&self) -> impl Iterator<Item = (&ValidatorId, &PendingReadySignal)> {
        self.pending.iter()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::Bls12381G2Signature;

    use super::*;

    fn signal(validator: u64, start: u64, end: u64) -> ReadySignal {
        ReadySignal::new(
            ValidatorId::new(validator),
            WeightedTimestamp::from_millis(start),
            WeightedTimestamp::from_millis(end),
            Bls12381G2Signature([0xAB; 96]),
        )
    }

    fn wt(ms: u64) -> WeightedTimestamp {
        WeightedTimestamp::from_millis(ms)
    }

    fn ts(ms: u64) -> LocalTimestamp {
        LocalTimestamp::from_millis(ms)
    }

    const DWELL: Duration = Duration::from_millis(100);

    #[test]
    fn new_pool_is_empty() {
        let pool = ReadySignalPool::new();
        assert!(pool.is_empty());
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn admit_inserts_keyed_by_validator() {
        let mut pool = ReadySignalPool::new();
        pool.admit(signal(7, 0, 100), ts(0));
        assert_eq!(pool.len(), 1);
        assert!(pool.iter().any(|(id, _)| id.inner() == 7));
    }

    #[test]
    fn admit_overwrites_same_validator() {
        let mut pool = ReadySignalPool::new();
        pool.admit(signal(3, 0, 10), ts(0));
        pool.admit(signal(3, 50, 200), ts(500));
        assert_eq!(pool.len(), 1);
        let (_, entry) = pool.iter().next().unwrap();
        assert_eq!(entry.signal.wt_window_end(), wt(200));
        assert_eq!(entry.received_at, ts(500));
    }

    #[test]
    fn admit_keeps_received_at_for_repeated_window() {
        // A reshape observer re-asserts the same-window signal every pump.
        // The first arrival's stamp must survive so the dwell accrues.
        let mut pool = ReadySignalPool::new();
        pool.admit(signal(3, 0, 100), ts(0));
        pool.admit(signal(3, 0, 100), ts(500));
        let (_, entry) = pool.iter().next().unwrap();
        assert_eq!(
            entry.received_at,
            ts(0),
            "an identical re-emission must not reset the dwell clock",
        );
    }

    #[test]
    fn admit_resets_received_at_for_a_fresh_window() {
        // A genuinely new window (fresh anchor epoch) supersedes and
        // restarts the dwell — it is a distinct signal to converge on.
        let mut pool = ReadySignalPool::new();
        pool.admit(signal(3, 0, 100), ts(0));
        pool.admit(signal(3, 50, 200), ts(500));
        let (_, entry) = pool.iter().next().unwrap();
        assert_eq!(entry.received_at, ts(500));
        assert_eq!(entry.signal.wt_window_end(), wt(200));
    }

    #[test]
    fn evict_expired_drops_past_window_end() {
        let mut pool = ReadySignalPool::new();
        pool.admit(signal(1, 0, 10), ts(0));
        pool.admit(signal(2, 0, 100), ts(0));
        pool.evict_expired(wt(50));
        assert_eq!(pool.len(), 1);
        assert!(pool.iter().any(|(id, _)| id.inner() == 2));
    }

    #[test]
    fn evict_expired_keeps_window_end_equal_to_committed() {
        // A signal whose window-end == committed_height is still
        // eligible — only strict expiry drops it.
        let mut pool = ReadySignalPool::new();
        pool.admit(signal(1, 0, 50), ts(0));
        pool.evict_expired(wt(50));
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn evict_ready_drops_matching_validators() {
        let mut pool = ReadySignalPool::new();
        pool.admit(signal(1, 0, 100), ts(0));
        pool.admit(signal(2, 0, 100), ts(0));
        pool.admit(signal(3, 0, 100), ts(0));
        pool.evict_ready(|id| id.inner() == 2);
        assert_eq!(pool.len(), 2);
        let ids: Vec<u64> = pool.iter().map(|(id, _)| id.inner()).collect();
        assert_eq!(ids, vec![1, 3]);
    }

    #[test]
    fn drain_skips_signals_under_dwell() {
        let mut pool = ReadySignalPool::new();
        pool.admit(signal(1, 0, 100), ts(0));
        let drained = pool.drain_eligible(wt(10), ts(50), DWELL, 32);
        assert!(drained.is_empty());
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn drain_returns_dwell_eligible_signals() {
        let mut pool = ReadySignalPool::new();
        pool.admit(signal(1, 0, 100), ts(0));
        pool.admit(signal(2, 0, 100), ts(0));
        let drained = pool.drain_eligible(wt(10), ts(150), DWELL, 32);
        assert_eq!(drained.len(), 2);
        assert!(pool.is_empty());
    }

    #[test]
    fn drain_orders_by_validator_ascending() {
        let mut pool = ReadySignalPool::new();
        pool.admit(signal(3, 0, 100), ts(0));
        pool.admit(signal(1, 0, 100), ts(0));
        pool.admit(signal(2, 0, 100), ts(0));
        let drained = pool.drain_eligible(wt(10), ts(200), DWELL, 32);
        let ids: Vec<u64> = drained.iter().map(|s| s.validator_id().inner()).collect();
        assert_eq!(ids, vec![1, 2, 3]);
    }

    #[test]
    fn drain_skips_signals_outside_window() {
        let mut pool = ReadySignalPool::new();
        pool.admit(signal(1, 100, 200), ts(0));
        let drained = pool.drain_eligible(wt(50), ts(500), DWELL, 32);
        assert!(drained.is_empty());
        assert_eq!(pool.len(), 1, "signal stays pending for a future proposal");
    }

    #[test]
    fn drain_respects_max_cap() {
        let mut pool = ReadySignalPool::new();
        for i in 1..=5 {
            pool.admit(signal(i, 0, 100), ts(0));
        }
        let drained = pool.drain_eligible(wt(10), ts(500), DWELL, 3);
        assert_eq!(drained.len(), 3);
        assert_eq!(pool.len(), 2, "remainder stays for a future proposal");
    }
}
