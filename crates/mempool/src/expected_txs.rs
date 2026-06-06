//! Tracking for cross-shard txs the mempool has been told to expect.
//!
//! When a committed block carries verified provisions referencing a tx that
//! is not yet in our pool, we record `(tx_hash, source_shard, first_seen_ts)`
//! here. The happy path is gossip arrival, which calls `forget`. Block-
//! include race and retention-horizon orphan sweep also remove entries; the
//! coordinator turns those drops into `Action::AbandonFetch` so any in-flight
//! transaction fetch is cancelled rather than retried indefinitely. On miss
//! callers consult the index to drive fetch fallback and horizon-bounded
//! eviction.
//!
//! First sighting wins: only the earliest `(source_shard, first_seen_ts)` is
//! retained. Subsequent records for the same `tx_hash` (from any source) are
//! dropped — the grace clock is anchored on first signal, not refreshed by
//! re-signal, and a single source per tx avoids duplicate fetch traffic.
//! Time is BFT-anchored (`WeightedTimestamp`), consistent with every other
//! retention/deadline knob in the mempool.

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use hyperscale_types::{ShardId, TxHash, WeightedTimestamp};

/// Grace before mempool emits a fetch for an expected tx.
///
/// Long enough for typical gossip arrival (cross-shard hop is ~tens of ms);
/// short enough that wave timeout (~24s) doesn't fire in practice if gossip
/// drops and fetch is needed.
pub const EXPECTED_TX_GRACE: Duration = Duration::from_secs(2);

/// One source-shard's claim that a tx will be available.
#[derive(Debug, Clone, Copy)]
struct ExpectedTx {
    first_seen_ts: WeightedTimestamp,
    source_shard: ShardId,
}

/// Per-tx index of first-sighting `(source_shard, first_seen_ts)`.
#[derive(Debug, Default)]
pub struct ExpectedTxs {
    entries: HashMap<TxHash, ExpectedTx>,
}

impl ExpectedTxs {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `(tx_hash, source_shard, first_seen_ts)` as expected. No-op if
    /// `tx_hash` is already tracked (first sighting wins regardless of
    /// source).
    pub fn record(
        &mut self,
        tx_hash: TxHash,
        source_shard: ShardId,
        first_seen_ts: WeightedTimestamp,
    ) {
        self.entries.entry(tx_hash).or_insert(ExpectedTx {
            first_seen_ts,
            source_shard,
        });
    }

    /// Drop the expectation for `tx_hash`. Called from admission paths once
    /// the tx is in pool. Returns `true` if an entry was removed — the
    /// caller uses that to emit `Action::AbandonFetch` so any in-flight
    /// fetch is cancelled.
    pub fn forget(&mut self, tx_hash: &TxHash) -> bool {
        self.entries.remove(tx_hash).is_some()
    }

    /// Number of distinct tx hashes currently expected.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Timestamp of the first (and only retained) sighting for `tx_hash`.
    pub fn first_seen_ts(&self, tx_hash: &TxHash) -> Option<WeightedTimestamp> {
        self.entries.get(tx_hash).map(|e| e.first_seen_ts)
    }

    /// Source shard recorded for `tx_hash`, if any.
    pub fn source(&self, tx_hash: &TxHash) -> Option<ShardId> {
        self.entries.get(tx_hash).map(|e| e.source_shard)
    }

    /// Drain entries whose first sighting is older than `horizon` at `now`.
    /// Returned in `(tx_hash, source_shard)` form so callers can warn/metric
    /// per-entry; the entries themselves are removed from the index.
    pub fn drop_past_horizon(
        &mut self,
        now: WeightedTimestamp,
        horizon: Duration,
    ) -> Vec<(TxHash, ShardId)> {
        let mut dropped = Vec::new();
        self.entries.retain(|tx_hash, entry| {
            if now.elapsed_since(entry.first_seen_ts) >= horizon {
                dropped.push((*tx_hash, entry.source_shard));
                false
            } else {
                true
            }
        });
        dropped
    }

    /// Tx hashes whose grace window has elapsed at `now`, grouped by the
    /// source shard whose committee should serve the fetch.
    ///
    /// Returns groups in `ShardId` order; ids within each group sorted
    /// by `TxHash` — `HashMap` iteration is otherwise random.
    pub fn due_for_fetch(
        &self,
        now: WeightedTimestamp,
        grace: Duration,
    ) -> Vec<(ShardId, Vec<TxHash>)> {
        let mut by_source: BTreeMap<ShardId, Vec<TxHash>> = BTreeMap::new();
        for (tx_hash, entry) in &self.entries {
            if now.elapsed_since(entry.first_seen_ts) >= grace {
                by_source
                    .entry(entry.source_shard)
                    .or_default()
                    .push(*tx_hash);
            }
        }
        for ids in by_source.values_mut() {
            ids.sort();
        }
        by_source.into_iter().collect()
    }
}
