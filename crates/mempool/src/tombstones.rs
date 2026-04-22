//! Terminal-state deduplication + evicted-transaction cache.
//!
//! Two concerns sharing a lifecycle:
//!
//! - **Tombstones** (`tx_hash → insertion_ts_ms`) stop gossip from re-adding
//!   transactions that have already reached a terminal state (Completed,
//!   Aborted).
//! - **Recently-evicted bodies** (`tx_hash → (tx, eviction_ts_ms)`) retain
//!   the transaction payload after eviction so slow peers can still fetch it.
//!
//! Retention windows are anchored on the BFT-authenticated weighted timestamp
//! of the last committed block, so behavior is deterministic across validators
//! regardless of block cadence.

use hyperscale_types::{Hash, RoutableTransaction};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// How long to retain evicted transactions for peer fetch requests. Allows
/// slow validators to catch up and fetch transactions from peers even after
/// the transaction has reached a terminal state.
pub(crate) const TRANSACTION_RETENTION: Duration = Duration::from_secs(30);

/// How long to retain tombstones. Paired with BFT's `COMMITTED_TX_RETENTION`
/// — both must cover the longest plausible late-gossip window so stale
/// transactions don't get re-accepted.
pub(crate) const TOMBSTONE_RETENTION: Duration = Duration::from_secs(300);

pub(crate) struct TombstoneStore {
    tombstones: HashMap<Hash, u64>,
    recently_evicted: HashMap<Hash, (Arc<RoutableTransaction>, u64)>,
}

impl TombstoneStore {
    pub fn new() -> Self {
        Self {
            tombstones: HashMap::new(),
            recently_evicted: HashMap::new(),
        }
    }

    /// Record `tx_hash` as tombstoned at `now_ms`.
    pub fn tombstone(&mut self, tx_hash: Hash, now_ms: u64) {
        self.tombstones.insert(tx_hash, now_ms);
    }

    /// Whether `tx_hash` has been tombstoned.
    pub fn is_tombstoned(&self, tx_hash: &Hash) -> bool {
        self.tombstones.contains_key(tx_hash)
    }

    /// Move a transaction body into the evicted cache under its own hash.
    /// Callers typically pair this with [`tombstone`](Self::tombstone).
    pub fn evict(&mut self, tx: Arc<RoutableTransaction>, now_ms: u64) {
        let hash = tx.hash();
        self.recently_evicted.insert(hash, (tx, now_ms));
    }

    /// Look up an evicted transaction body by hash.
    pub fn get_evicted(&self, tx_hash: &Hash) -> Option<Arc<RoutableTransaction>> {
        self.recently_evicted
            .get(tx_hash)
            .map(|(tx, _)| Arc::clone(tx))
    }

    /// Drop tombstones older than `retention`, anchored on `now_ms`. Returns
    /// the number of entries removed.
    pub fn prune_tombstones(&mut self, retention: Duration, now_ms: u64) -> usize {
        let retention_ms = retention.as_millis() as u64;
        let cutoff_ms = now_ms.saturating_sub(retention_ms);
        let before = self.tombstones.len();
        self.tombstones.retain(|_, ts_ms| *ts_ms > cutoff_ms);
        before - self.tombstones.len()
    }

    /// Drop evicted entries older than `retention`, anchored on `now_ms`.
    pub fn prune_evicted(&mut self, retention: Duration, now_ms: u64) {
        let retention_ms = retention.as_millis() as u64;
        let cutoff_ms = now_ms.saturating_sub(retention_ms);
        self.recently_evicted
            .retain(|_, (_, ts_ms)| *ts_ms > cutoff_ms);
    }

    pub fn len_tombstones(&self) -> usize {
        self.tombstones.len()
    }

    pub fn len_evicted(&self) -> usize {
        self.recently_evicted.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::test_utils::test_transaction;

    fn tx_arc(seed: u8) -> Arc<RoutableTransaction> {
        Arc::new(test_transaction(seed))
    }

    #[test]
    fn fresh_store_is_empty() {
        let store = TombstoneStore::new();
        assert_eq!(store.len_tombstones(), 0);
        assert_eq!(store.len_evicted(), 0);
        assert!(!store.is_tombstoned(&Hash::ZERO));
        assert!(store.get_evicted(&Hash::ZERO).is_none());
    }

    #[test]
    fn tombstone_is_observable_via_is_tombstoned() {
        let mut store = TombstoneStore::new();
        let hash = Hash::from_bytes(b"tx1");
        store.tombstone(hash, 1_000);
        assert!(store.is_tombstoned(&hash));
        assert!(!store.is_tombstoned(&Hash::from_bytes(b"other")));
    }

    #[test]
    fn evict_then_get_evicted_round_trips_the_body() {
        let mut store = TombstoneStore::new();
        let tx = tx_arc(1);
        let hash = tx.hash();
        store.evict(Arc::clone(&tx), 500);

        let got = store.get_evicted(&hash).expect("body present");
        assert_eq!(got.hash(), hash);
        assert_eq!(store.len_evicted(), 1);
    }

    #[test]
    fn tombstone_and_evict_are_independent() {
        // Evicting does not tombstone, and vice versa. The coordinator pairs
        // them deliberately; the store does not.
        let mut store = TombstoneStore::new();
        let tx = tx_arc(2);
        let hash = tx.hash();

        store.evict(Arc::clone(&tx), 100);
        assert!(!store.is_tombstoned(&hash));
        assert_eq!(store.len_tombstones(), 0);

        store.tombstone(hash, 100);
        assert!(store.is_tombstoned(&hash));
        assert_eq!(store.len_tombstones(), 1);
        assert_eq!(store.len_evicted(), 1);
    }

    #[test]
    fn prune_tombstones_drops_entries_older_than_retention() {
        let mut store = TombstoneStore::new();
        store.tombstone(Hash::from_bytes(b"old"), 100);
        store.tombstone(Hash::from_bytes(b"recent"), 900);

        // At now=1000 with retention=500ms: cutoff=500, "old" (100) dropped,
        // "recent" (900) kept.
        let removed = store.prune_tombstones(Duration::from_millis(500), 1_000);
        assert_eq!(removed, 1);
        assert!(!store.is_tombstoned(&Hash::from_bytes(b"old")));
        assert!(store.is_tombstoned(&Hash::from_bytes(b"recent")));
    }

    #[test]
    fn prune_tombstones_with_zero_retention_clears_everything() {
        let mut store = TombstoneStore::new();
        store.tombstone(Hash::from_bytes(b"a"), 100);
        store.tombstone(Hash::from_bytes(b"b"), 200);

        let removed = store.prune_tombstones(Duration::ZERO, 1_000);
        assert_eq!(removed, 2);
        assert_eq!(store.len_tombstones(), 0);
    }

    #[test]
    fn prune_evicted_drops_old_bodies() {
        let mut store = TombstoneStore::new();
        let old_tx = tx_arc(10);
        let recent_tx = tx_arc(11);
        let old_hash = old_tx.hash();
        let recent_hash = recent_tx.hash();

        store.evict(old_tx, 100);
        store.evict(recent_tx, 900);

        store.prune_evicted(Duration::from_millis(500), 1_000);
        assert!(store.get_evicted(&old_hash).is_none());
        assert!(store.get_evicted(&recent_hash).is_some());
    }

    #[test]
    fn prune_respects_strict_greater_than_cutoff() {
        // Entries whose ts equals the cutoff are dropped (retain keeps
        // `ts > cutoff`). Documents the boundary so tests elsewhere don't
        // silently depend on the opposite.
        let mut store = TombstoneStore::new();
        store.tombstone(Hash::from_bytes(b"at_cutoff"), 500);
        // now=1000, retention=500ms → cutoff=500 → entry at 500 is dropped.
        let removed = store.prune_tombstones(Duration::from_millis(500), 1_000);
        assert_eq!(removed, 1);
    }
}
