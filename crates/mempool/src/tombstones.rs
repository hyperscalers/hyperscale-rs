//! Terminal-state deduplication for transaction admission.
//!
//! `tx_hash → end_timestamp_exclusive`. Tombstones stop gossip from re-adding
//! transactions that have already reached a terminal state (Completed,
//! Aborted) and bound the lifetime of their body in [`crate::TxStore`] —
//! when a tombstone is pruned, the coordinator drops the matching body from
//! the store.
//!
//! Retention is `end_timestamp_exclusive`-derived: an entry is dropped once
//! the latest committed [`WeightedTimestamp`] reaches the tx's
//! `end_timestamp_exclusive`. Past that point, even a re-submission would be
//! rejected by block validity (validator-side check on `validity_range`),
//! so the tombstone is no longer needed for correctness — it becomes a pure
//! perf optimisation. The maximum age of any entry is bounded by
//! `MAX_VALIDITY_RANGE` because admission requires
//! `end_timestamp_exclusive <= anchor + MAX_VALIDITY_RANGE`.
//!
//! Anchored on the shard consensus-authenticated weighted timestamp of the last committed
//! block, so behavior is deterministic across validators regardless of block
//! cadence.

use std::collections::HashMap;

use hyperscale_types::{TxHash, WeightedTimestamp};

pub struct TombstoneStore {
    /// `tx_hash → end_timestamp_exclusive`. Pruned when
    /// `end_timestamp_exclusive <= current_committed_ts`.
    tombstones: HashMap<TxHash, WeightedTimestamp>,
}

impl TombstoneStore {
    pub fn new() -> Self {
        Self {
            tombstones: HashMap::new(),
        }
    }

    /// Record `tx_hash` as tombstoned. `end_timestamp_exclusive` comes from
    /// the tx's `validity_range` and bounds the entry's lifetime.
    pub fn tombstone(&mut self, tx_hash: TxHash, end_timestamp_exclusive: WeightedTimestamp) {
        self.tombstones.insert(tx_hash, end_timestamp_exclusive);
    }

    /// Whether `tx_hash` has been tombstoned.
    pub fn is_tombstoned(&self, tx_hash: &TxHash) -> bool {
        self.tombstones.contains_key(tx_hash)
    }

    /// Drop tombstones whose `end_timestamp_exclusive <= now`. Returns the
    /// hashes that were removed so the caller can drop matching bodies from
    /// [`crate::TxStore`]. Past expiry, the validator-side validity check
    /// rejects any re-submission, so the tombstone is no longer load-bearing
    /// for correctness.
    pub fn prune_tombstones(&mut self, now: WeightedTimestamp) -> Vec<TxHash> {
        let mut removed = Vec::new();
        self.tombstones.retain(|hash, end| {
            if *end > now {
                true
            } else {
                removed.push(*hash);
                false
            }
        });
        removed
    }

    pub fn len_tombstones(&self) -> usize {
        self.tombstones.len()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::Hash;

    use super::*;

    #[test]
    fn fresh_store_is_empty() {
        let store = TombstoneStore::new();
        assert_eq!(store.len_tombstones(), 0);
        assert!(!store.is_tombstoned(&TxHash::ZERO));
    }

    #[test]
    fn tombstone_is_observable_via_is_tombstoned() {
        let mut store = TombstoneStore::new();
        let hash = TxHash::from_raw(Hash::from_bytes(b"tx1"));
        store.tombstone(hash, WeightedTimestamp::from_millis(1_000));
        assert!(store.is_tombstoned(&hash));
        assert!(!store.is_tombstoned(&TxHash::from_raw(Hash::from_bytes(b"other"))));
    }

    #[test]
    fn prune_tombstones_drops_entries_past_their_end_exclusive() {
        let mut store = TombstoneStore::new();
        let old = TxHash::from_raw(Hash::from_bytes(b"old"));
        let future = TxHash::from_raw(Hash::from_bytes(b"future"));
        store.tombstone(old, WeightedTimestamp::from_millis(100));
        store.tombstone(future, WeightedTimestamp::from_millis(900));

        // At now=500: "old" (end=100) is past expiry, "future" (end=900) survives.
        let removed = store.prune_tombstones(WeightedTimestamp::from_millis(500));
        assert_eq!(removed, vec![old]);
        assert!(!store.is_tombstoned(&old));
        assert!(store.is_tombstoned(&future));
    }

    #[test]
    fn prune_tombstones_far_in_future_clears_everything() {
        let mut store = TombstoneStore::new();
        store.tombstone(
            TxHash::from_raw(Hash::from_bytes(b"a")),
            WeightedTimestamp::from_millis(100),
        );
        store.tombstone(
            TxHash::from_raw(Hash::from_bytes(b"b")),
            WeightedTimestamp::from_millis(200),
        );

        let removed = store.prune_tombstones(WeightedTimestamp::from_millis(1_000));
        assert_eq!(removed.len(), 2);
        assert_eq!(store.len_tombstones(), 0);
    }

    #[test]
    fn prune_drops_entries_at_exact_end_exclusive() {
        // Half-open semantics: end_timestamp_exclusive == now means past
        // expiry. retain keeps `end > now`.
        let mut store = TombstoneStore::new();
        let at_end = TxHash::from_raw(Hash::from_bytes(b"at_end"));
        store.tombstone(at_end, WeightedTimestamp::from_millis(500));
        let removed = store.prune_tombstones(WeightedTimestamp::from_millis(500));
        assert_eq!(removed, vec![at_end]);
    }
}
