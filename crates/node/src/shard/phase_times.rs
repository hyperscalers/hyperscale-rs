//! Per-transaction phase-time tracking for the slow-tx finalization log.
//!
//! Stamps wall-clock at each lifecycle transition that the `io_loop` observes
//! via `Action::EmitTransactionStatus` and `Action::RecordTxEcCreated`. The
//! map is purely a diagnostic aid: it drives the
//! `"Transaction finalization exceeded 10s"` warning's phase breakdown and is
//! never exposed beyond logs. Lives entirely on the `io_loop` so the mempool
//! state machine stays free of telemetry plumbing.
//!
//! An entry opens on a `Pending` status — the one a submission to this
//! node reports — and closes on `Completed`. Later stamps land only on an
//! open entry, so nothing is tracked that never reported `Pending` here.
//! Not every entry closes: the mempool drops a transaction whose window
//! lapsed without reporting a terminal status, and one handed to a
//! successor completes there. So the cache is bounded, at the mempool's
//! own limit on pending submissions, and a full cache forgets its oldest
//! entry first.
//!
//! Stamps are ms-since-Unix-epoch (`LocalTimestamp`), the same unit the
//! `io_loop`'s clock origin is minted in. They're never compared across
//! validators; each node logs its own observed latency only.
use std::collections::{BTreeSet, HashMap};
use std::fmt;

use hyperscale_mempool::DEFAULT_MAX_PENDING;
use hyperscale_types::{LocalTimestamp, TransactionStatus, TxHash};

/// How many transactions the cache tracks at once.
const MAX_TRACKED: usize = DEFAULT_MAX_PENDING;

/// Phase-time stamps for a single transaction's mempool → terminal flow.
#[derive(Debug, Clone, Copy)]
#[allow(clippy::struct_field_names)] // every field is a timestamp; suffix carries the role
pub struct TxPhaseTimes {
    /// First time this validator saw the tx (RPC submit or gossip arrival).
    added_at: LocalTimestamp,
    committed_at: Option<LocalTimestamp>,
    ec_created_at: Option<LocalTimestamp>,
}

impl TxPhaseTimes {
    const fn new(added_at: LocalTimestamp) -> Self {
        Self {
            added_at,
            committed_at: None,
            ec_created_at: None,
        }
    }

    pub(crate) const fn added_at(&self) -> LocalTimestamp {
        self.added_at
    }

    /// Renders the phase breakdown for the slow-tx log, formatting the
    /// completed-at duration relative to `completed_at` (the terminal stamp
    /// the `io_loop` computed when it observed the `Completed` status).
    pub(crate) fn display_at(&self, completed_at: LocalTimestamp) -> impl fmt::Display + '_ {
        TxPhaseTimesDisplay {
            phases: self,
            completed_at,
        }
    }
}

/// Per-tx side cache. Keys are `TxHash`, values are stamps the `io_loop`
/// records as `EmitTransactionStatus` / `RecordTxEcCreated` actions arrive.
#[derive(Default)]
pub struct TxPhaseTimesCache {
    entries: HashMap<TxHash, TxPhaseTimes>,
    /// Every entry by when it opened, so the bound evicts the oldest.
    by_age: BTreeSet<(LocalTimestamp, TxHash)>,
}

impl TxPhaseTimesCache {
    /// Update phase-time stamps for one observed status transition. Returns
    /// the populated entry on terminal statuses (so the caller can render
    /// the slow-tx log) and removes it from the cache. Returns `None` for
    /// non-terminal statuses or a transaction with no open entry.
    pub(crate) fn observe_status(
        &mut self,
        tx_hash: TxHash,
        status: &TransactionStatus,
        now: LocalTimestamp,
    ) -> Option<TxPhaseTimes> {
        match status {
            TransactionStatus::Pending => {
                self.open(tx_hash, now);
                None
            }
            TransactionStatus::Committed(_) => {
                if let Some(entry) = self.entries.get_mut(&tx_hash) {
                    entry.committed_at.get_or_insert(now);
                }
                None
            }
            // A leg's own finalization: the terminal is still to come.
            TransactionStatus::LegFinalized => None,
            TransactionStatus::Completed(_) => {
                let entry = self.entries.remove(&tx_hash)?;
                self.by_age.remove(&(entry.added_at, tx_hash));
                Some(entry)
            }
        }
    }

    /// Stamp `ec_created_at` for each open tx hash. Pure stamp — no
    /// terminal status flows through here.
    pub(crate) fn record_ec_created(&mut self, tx_hashes: &[TxHash], now: LocalTimestamp) {
        for hash in tx_hashes {
            if let Some(entry) = self.entries.get_mut(hash) {
                entry.ec_created_at.get_or_insert(now);
            }
        }
    }

    /// Open an entry for `tx_hash` at `now` unless one is open, evicting
    /// the oldest where the bound leaves no room.
    fn open(&mut self, tx_hash: TxHash, now: LocalTimestamp) {
        if self.entries.contains_key(&tx_hash) {
            return;
        }
        if self.entries.len() >= MAX_TRACKED
            && let Some((_, oldest)) = self.by_age.pop_first()
        {
            self.entries.remove(&oldest);
        }
        self.entries.insert(tx_hash, TxPhaseTimes::new(now));
        self.by_age.insert((now, tx_hash));
    }
}

struct TxPhaseTimesDisplay<'a> {
    phases: &'a TxPhaseTimes,
    completed_at: LocalTimestamp,
}

impl fmt::Display for TxPhaseTimesDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let p = self.phases;
        let dur = |start: LocalTimestamp, end: LocalTimestamp| -> f64 {
            end.saturating_sub(start).as_secs_f64()
        };
        let total = dur(p.added_at, self.completed_at);
        write!(f, "total={total:.3}s")?;
        if let Some(c) = p.committed_at {
            write!(f, " mempool={:.3}s", dur(p.added_at, c))?;
            write!(f, " commit_to_complete={:.3}s", dur(c, self.completed_at))?;
        }
        if let Some(e) = p.ec_created_at {
            write!(f, " ec_to_complete={:.3}s", dur(e, self.completed_at))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{BlockHeight, Hash, TransactionDecision};

    use super::*;

    fn hash(n: u64) -> TxHash {
        TxHash::from(Hash::from_bytes(&n.to_le_bytes()))
    }

    /// A commit or a certificate for a transaction that never reported
    /// `Pending` here opens nothing.
    #[test]
    fn only_a_pending_status_opens_an_entry() {
        let mut cache = TxPhaseTimesCache::default();
        let now = LocalTimestamp::from_millis(1);
        cache.observe_status(
            hash(1),
            &TransactionStatus::Committed(BlockHeight::new(1)),
            now,
        );
        cache.record_ec_created(&[hash(2)], now);
        assert!(cache.entries.is_empty());
        assert!(cache.by_age.is_empty());
    }

    /// Entries that never reach a terminal status stop at the bound, and
    /// the oldest goes first.
    #[test]
    fn unfinished_entries_stop_at_the_bound() {
        let mut cache = TxPhaseTimesCache::default();
        let extra = 3u64;
        for n in 0..MAX_TRACKED as u64 + extra {
            cache.observe_status(
                hash(n),
                &TransactionStatus::Pending,
                LocalTimestamp::from_millis(n),
            );
        }
        assert_eq!(cache.entries.len(), MAX_TRACKED);
        assert_eq!(cache.by_age.len(), MAX_TRACKED);
        assert!(!cache.entries.contains_key(&hash(0)));
        assert!(cache.entries.contains_key(&hash(extra)));

        let done = cache.observe_status(
            hash(extra),
            &TransactionStatus::Completed(TransactionDecision::Accept),
            LocalTimestamp::from_millis(u64::MAX / 2),
        );
        assert!(done.is_some());
        assert_eq!(cache.by_age.len(), MAX_TRACKED - 1);
    }
}
