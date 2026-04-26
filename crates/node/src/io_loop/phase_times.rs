//! Per-transaction phase-time tracking for the slow-tx finalization log.
//!
//! Stamps wall-clock at each lifecycle transition that the `io_loop` observes
//! via `Action::EmitTransactionStatus` and `Action::RecordTxEcCreated`. The
//! map is purely a diagnostic aid: it drives the
//! `"Transaction finalization exceeded 10s"` warning's phase breakdown and is
//! never exposed beyond logs. Lives entirely on the `io_loop` so the mempool
//! state machine stays free of telemetry plumbing.
//!
//! Entries are created on the first `Pending` status, stamped through the
//! lifecycle, and dropped on terminal status. A bounded-cleanup pass isn't
//! needed: every entry created here is always followed by a terminal status
//! (Completed / Aborted) under all execution paths the rest of the system
//! supports — see `process_certificate_committed` in the mempool.
//!
//! Stamps are ms-since-Unix-epoch (`LocalTimestamp`), the same unit the
//! `io_loop`'s clock origin is minted in. They're never compared across
//! validators; each node logs its own observed latency only.
use hyperscale_types::{LocalTimestamp, TransactionStatus, TxHash};
use std::collections::HashMap;
use std::fmt;

/// Phase-time stamps for a single transaction's mempool → terminal flow.
#[derive(Debug, Clone, Copy)]
#[allow(clippy::struct_field_names)] // every field is a timestamp; suffix carries the role
pub(super) struct TxPhaseTimes {
    /// First time this validator saw the tx (RPC submit or gossip arrival).
    added_at: LocalTimestamp,
    committed_at: Option<LocalTimestamp>,
    ec_created_at: Option<LocalTimestamp>,
    executed_at: Option<LocalTimestamp>,
}

impl TxPhaseTimes {
    fn new(added_at: LocalTimestamp) -> Self {
        Self {
            added_at,
            committed_at: None,
            ec_created_at: None,
            executed_at: None,
        }
    }

    pub(super) fn added_at(&self) -> LocalTimestamp {
        self.added_at
    }

    /// Renders the phase breakdown for the slow-tx log, formatting the
    /// completed-at duration relative to `completed_at` (the terminal stamp
    /// the `io_loop` computed when it observed the `Completed` status).
    pub(super) fn display_at(&self, completed_at: LocalTimestamp) -> impl fmt::Display + '_ {
        TxPhaseTimesDisplay {
            phases: self,
            completed_at,
        }
    }
}

/// Per-tx side cache. Keys are `TxHash`, values are stamps the `io_loop`
/// records as `EmitTransactionStatus` / `RecordTxEcCreated` actions arrive.
#[derive(Default)]
pub(super) struct TxPhaseTimesCache {
    entries: HashMap<TxHash, TxPhaseTimes>,
}

impl TxPhaseTimesCache {
    /// Update phase-time stamps for one observed status transition. Returns
    /// the populated entry on terminal statuses (so the caller can render
    /// the slow-tx log) and removes it from the cache. Returns `None` for
    /// non-terminal statuses or unknown transitions.
    pub(super) fn observe_status(
        &mut self,
        tx_hash: TxHash,
        status: &TransactionStatus,
        now: LocalTimestamp,
    ) -> Option<TxPhaseTimes> {
        match status {
            TransactionStatus::Pending => {
                self.entries
                    .entry(tx_hash)
                    .or_insert_with(|| TxPhaseTimes::new(now));
                None
            }
            TransactionStatus::Committed(_) => {
                let entry = self
                    .entries
                    .entry(tx_hash)
                    .or_insert_with(|| TxPhaseTimes::new(now));
                entry.committed_at.get_or_insert(now);
                None
            }
            TransactionStatus::Executed { .. } => {
                let entry = self
                    .entries
                    .entry(tx_hash)
                    .or_insert_with(|| TxPhaseTimes::new(now));
                entry.executed_at.get_or_insert(now);
                None
            }
            TransactionStatus::Completed(_) => {
                // Terminal — pull the entry so the caller can log.
                self.entries.remove(&tx_hash)
            }
        }
    }

    /// Stamp `ec_created_at` for each tx hash. Pure stamp — no terminal
    /// status flows through here.
    pub(super) fn record_ec_created(&mut self, tx_hashes: &[TxHash], now: LocalTimestamp) {
        for hash in tx_hashes {
            let entry = self
                .entries
                .entry(*hash)
                .or_insert_with(|| TxPhaseTimes::new(now));
            entry.ec_created_at.get_or_insert(now);
        }
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
        }
        match (p.committed_at, p.executed_at) {
            (Some(c), Some(x)) => {
                write!(f, " execution={:.3}s", dur(c, x))?;
            }
            (Some(c), None) => {
                write!(f, " commit_to_complete={:.3}s", dur(c, self.completed_at))?;
            }
            _ => {}
        }
        if let (Some(e), Some(x)) = (p.ec_created_at, p.executed_at) {
            write!(f, " ec_collection={:.3}s", dur(e, x))?;
        }
        if let Some(x) = p.executed_at {
            write!(f, " tc_inclusion={:.3}s", dur(x, self.completed_at))?;
        }
        Ok(())
    }
}
