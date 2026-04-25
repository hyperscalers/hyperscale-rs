//! Terminal-state deduplication + evicted-transaction cache.
//!
//! Two concerns sharing a lifecycle:
//!
//! - **Tombstones** (`tx_hash → end_timestamp_exclusive`) stop gossip from
//!   re-adding transactions that have already reached a terminal state
//!   (Completed, Aborted).
//! - **Recently-evicted bodies** (`tx_hash → (tx, end_timestamp_exclusive)`)
//!   retain the transaction payload after eviction so slow peers can still
//!   fetch it.
//!
//! Retention is `end_timestamp_exclusive`-derived: an entry is dropped once
//! the latest committed `WeightedTimestamp` reaches the tx's
//! `end_timestamp_exclusive`. Past that point, even a re-submission would be
//! rejected by block validity (validator-side check on `validity_range`),
//! so the tombstone is no longer needed for correctness — it becomes a pure
//! perf optimisation. The maximum age of any entry is bounded by
//! `MAX_VALIDITY_RANGE` because admission requires
//! `end_timestamp_exclusive <= anchor + MAX_VALIDITY_RANGE`.
//!
//! Anchored on the BFT-authenticated weighted timestamp of the last committed
//! block, so behavior is deterministic across validators regardless of block
//! cadence.

#[cfg(test)]
use hyperscale_types::Hash;
use hyperscale_types::{RoutableTransaction, TxHash, WeightedTimestamp};
use std::collections::HashMap;
use std::sync::Arc;

pub(crate) struct TombstoneStore {
    /// `tx_hash → end_timestamp_exclusive`. Pruned when
    /// `end_timestamp_exclusive <= current_committed_ts`.
    tombstones: HashMap<TxHash, WeightedTimestamp>,
    /// `tx_hash → (body, end_timestamp_exclusive)`. Same lifetime as the
    /// matching tombstone so peer fetches and dedup expire together.
    recently_evicted: HashMap<TxHash, (Arc<RoutableTransaction>, WeightedTimestamp)>,
}

impl TombstoneStore {
    pub fn new() -> Self {
        Self {
            tombstones: HashMap::new(),
            recently_evicted: HashMap::new(),
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

    /// Move a transaction body into the evicted cache under its own hash.
    /// Reads `validity_range.end_timestamp_exclusive` from the tx so the
    /// entry expires alongside its tombstone.
    pub fn evict(&mut self, tx: Arc<RoutableTransaction>) {
        let hash = tx.hash();
        let end = tx.validity_range.end_timestamp_exclusive;
        self.recently_evicted.insert(hash, (tx, end));
    }

    /// Look up an evicted transaction body by hash.
    pub fn get_evicted(&self, tx_hash: &TxHash) -> Option<Arc<RoutableTransaction>> {
        self.recently_evicted
            .get(tx_hash)
            .map(|(tx, _)| Arc::clone(tx))
    }

    /// Drop tombstones whose `end_timestamp_exclusive <= now`. Returns the
    /// number of entries removed. Past expiry, the validator-side validity
    /// check rejects any re-submission, so the tombstone is no longer
    /// load-bearing for correctness.
    pub fn prune_tombstones(&mut self, now: WeightedTimestamp) -> usize {
        let before = self.tombstones.len();
        self.tombstones.retain(|_, end| *end > now);
        before - self.tombstones.len()
    }

    /// Drop evicted entries whose `end_timestamp_exclusive <= now`. Symmetric
    /// to `prune_tombstones` — peers cannot include the tx anywhere past
    /// expiry, so retaining the body is wasted memory.
    pub fn prune_evicted(&mut self, now: WeightedTimestamp) {
        self.recently_evicted.retain(|_, (_, end)| *end > now);
    }

    pub fn len_tombstones(&self) -> usize {
        self.tombstones.len()
    }

    pub fn len_evicted(&self) -> usize {
        self.recently_evicted.len()
    }

    /// Iterate the hashes of every cached evicted-body entry. Sync inventory
    /// needs these: tombstoned transactions whose bodies we still hold must
    /// not be re-requested during block catchup.
    pub fn recently_evicted_hashes(&self) -> impl Iterator<Item = &TxHash> {
        self.recently_evicted.keys()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::test_utils::test_notarized_transaction_v1;
    use hyperscale_types::{routable_from_notarized_v1, TimestampRange};

    /// Build a test tx whose `validity_range.end_timestamp_exclusive == end`.
    fn tx_with_end(seed: u8, end_ms: u64) -> Arc<RoutableTransaction> {
        let notarized = test_notarized_transaction_v1(&[seed]);
        let range = TimestampRange::new(WeightedTimestamp::ZERO, WeightedTimestamp(end_ms));
        Arc::new(routable_from_notarized_v1(notarized, range).expect("valid notarized fixture"))
    }

    #[test]
    fn fresh_store_is_empty() {
        let store = TombstoneStore::new();
        assert_eq!(store.len_tombstones(), 0);
        assert_eq!(store.len_evicted(), 0);
        assert!(!store.is_tombstoned(&TxHash::ZERO));
        assert!(store.get_evicted(&TxHash::ZERO).is_none());
    }

    #[test]
    fn tombstone_is_observable_via_is_tombstoned() {
        let mut store = TombstoneStore::new();
        let hash = TxHash::from_raw(Hash::from_bytes(b"tx1"));
        store.tombstone(hash, WeightedTimestamp(1_000));
        assert!(store.is_tombstoned(&hash));
        assert!(!store.is_tombstoned(&TxHash::from_raw(Hash::from_bytes(b"other"))));
    }

    #[test]
    fn evict_then_get_evicted_round_trips_the_body() {
        let mut store = TombstoneStore::new();
        let tx = tx_with_end(1, 60_000);
        let hash = tx.hash();
        store.evict(Arc::clone(&tx));

        let got = store.get_evicted(&hash).expect("body present");
        assert_eq!(got.hash(), hash);
        assert_eq!(store.len_evicted(), 1);
    }

    #[test]
    fn tombstone_and_evict_are_independent() {
        // Evicting does not tombstone, and vice versa. The coordinator pairs
        // them deliberately; the store does not.
        let mut store = TombstoneStore::new();
        let tx = tx_with_end(2, 60_000);
        let hash = tx.hash();
        let end = tx.validity_range.end_timestamp_exclusive;

        store.evict(Arc::clone(&tx));
        assert!(!store.is_tombstoned(&hash));
        assert_eq!(store.len_tombstones(), 0);

        store.tombstone(hash, end);
        assert!(store.is_tombstoned(&hash));
        assert_eq!(store.len_tombstones(), 1);
        assert_eq!(store.len_evicted(), 1);
    }

    #[test]
    fn prune_tombstones_drops_entries_past_their_end_exclusive() {
        let mut store = TombstoneStore::new();
        store.tombstone(
            TxHash::from_raw(Hash::from_bytes(b"old")),
            WeightedTimestamp(100),
        );
        store.tombstone(
            TxHash::from_raw(Hash::from_bytes(b"future")),
            WeightedTimestamp(900),
        );

        // At now=500: "old" (end=100) is past expiry, "future" (end=900) survives.
        let removed = store.prune_tombstones(WeightedTimestamp(500));
        assert_eq!(removed, 1);
        assert!(!store.is_tombstoned(&TxHash::from_raw(Hash::from_bytes(b"old"))));
        assert!(store.is_tombstoned(&TxHash::from_raw(Hash::from_bytes(b"future"))));
    }

    #[test]
    fn prune_tombstones_far_in_future_clears_everything() {
        let mut store = TombstoneStore::new();
        store.tombstone(
            TxHash::from_raw(Hash::from_bytes(b"a")),
            WeightedTimestamp(100),
        );
        store.tombstone(
            TxHash::from_raw(Hash::from_bytes(b"b")),
            WeightedTimestamp(200),
        );

        let removed = store.prune_tombstones(WeightedTimestamp(1_000));
        assert_eq!(removed, 2);
        assert_eq!(store.len_tombstones(), 0);
    }

    #[test]
    fn prune_evicted_drops_bodies_past_their_end_exclusive() {
        let mut store = TombstoneStore::new();
        let early_tx = tx_with_end(10, 100);
        let later_tx = tx_with_end(11, 900);
        let early_hash = early_tx.hash();
        let later_hash = later_tx.hash();

        store.evict(early_tx);
        store.evict(later_tx);

        // At now=500: early (end=100) is past expiry, later (end=900) survives.
        store.prune_evicted(WeightedTimestamp(500));
        assert!(store.get_evicted(&early_hash).is_none());
        assert!(store.get_evicted(&later_hash).is_some());
    }

    #[test]
    fn prune_drops_entries_at_exact_end_exclusive() {
        // Half-open semantics: end_timestamp_exclusive == now means past
        // expiry. retain keeps `end > now`.
        let mut store = TombstoneStore::new();
        store.tombstone(
            TxHash::from_raw(Hash::from_bytes(b"at_end")),
            WeightedTimestamp(500),
        );
        let removed = store.prune_tombstones(WeightedTimestamp(500));
        assert_eq!(removed, 1);
    }
}
