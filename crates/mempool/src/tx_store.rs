//! Shared transaction body store.
//!
//! Single source of truth for transaction bodies, keyed by [`TxHash`].
//! Held behind an `Arc` so both the single-threaded mempool state machine
//! and network-thread request handlers can read/write through the same
//! map without channel-bouncing or contending on the mempool's admission
//! mutex.
//!
//! Two writers drive this store:
//!
//! - **Validation pipeline** inserts bodies on successful validation, before
//!   the gossip-admission path hands them to the mempool.
//! - **Mempool eviction** ages bodies out via [`Self::evict`] once the
//!   tombstone retention window elapses, so peers fetching by hash during
//!   the window still get a body.
//!
//! Mirrors [`hyperscale_provisions::store::ProvisionStore`] in shape and
//! intent, minus the secondary `(height, target_shard)` index that
//! provisions need but transactions don't (tx fetches are hash-keyed).
//!
//! The mempool's [`PoolEntry`](crate::coordinator) holds metadata only;
//! body lookups go through this store.
//!
//! Backed by [`papaya::HashMap`] — a lock-free concurrent map. Reads from
//! the network worker thread are wait-free in the common case and never
//! contend with the single state-machine writer.

use std::sync::Arc;

use hyperscale_types::{BloomFilter, DEFAULT_FPR, RoutableTransaction, TxHash, Verified};
use papaya::HashMap;

/// Shared content-addressed store of [`RoutableTransaction`] bodies.
///
/// Bodies are stored as `Arc<Verified<RoutableTransaction>>`; admission to
/// the store is gated by the standard `Verify` predicate (gossip / RPC /
/// fetch all run through the validation pipeline), and re-population from
/// committed blocks goes through
/// [`Verified::<RoutableTransaction>::from_persisted`] under BFT-transitive
/// trust. The store's type expresses that invariant directly.
///
/// Read-heavy: every mempool iteration and every inbound fetch serve
/// reads bodies; writes (insert on validation, evict on retention sweep)
/// are infrequent and single-threaded (state machine).
pub struct TxStore {
    inner: HashMap<TxHash, Arc<Verified<RoutableTransaction>>>,
}

impl TxStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    /// Insert a transaction body. Idempotent: re-inserting the same hash is
    /// a no-op (the existing `Arc` is preserved so callers holding clones
    /// keep pointing at the same allocation).
    pub fn insert(&self, tx: Arc<Verified<RoutableTransaction>>) {
        let hash = tx.hash();
        self.inner.pin().get_or_insert_with(hash, || tx);
    }

    /// Look up a transaction body by hash.
    #[must_use]
    pub fn get(&self, hash: &TxHash) -> Option<Arc<Verified<RoutableTransaction>>> {
        self.inner.pin().get(hash).cloned()
    }

    /// Bulk lookup. Returns `(hash, body)` pairs for those found; missing
    /// hashes are skipped (caller decides fallback policy).
    #[must_use]
    pub fn get_batch(
        &self,
        hashes: &[TxHash],
    ) -> Vec<(TxHash, Arc<Verified<RoutableTransaction>>)> {
        let g = self.inner.pin();
        hashes
            .iter()
            .filter_map(|h| g.get(h).map(|tx| (*h, Arc::clone(tx))))
            .collect()
    }

    /// True if the store currently holds a body for `hash`.
    #[must_use]
    pub fn contains(&self, hash: &TxHash) -> bool {
        self.inner.pin().contains_key(hash)
    }

    /// Drop bodies for the given hashes. Returns the number actually
    /// removed.
    pub fn evict(&self, hashes: impl IntoIterator<Item = TxHash>) -> usize {
        let g = self.inner.pin();
        hashes.into_iter().filter(|h| g.remove(h).is_some()).count()
    }

    /// Number of bodies currently held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// True when the store holds no bodies.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Build a bloom filter over every cached transaction hash. Sync
    /// inventory attaches this to `GetBlockRequest` so the responder can
    /// elide tx bodies the requester already holds.
    ///
    /// Returns `None` if the set is too large to size a filter within the
    /// [`MAX_BITS`](hyperscale_types::MAX_BITS) cap; callers treat this as
    /// "send no inventory, accept the full response."
    ///
    /// Iteration is concurrent-safe: keys inserted or removed during the
    /// snapshot may or may not appear. Bloom filters are an inclusion hint,
    /// not a manifest — false positives waste a fetch attempt, false
    /// negatives just mean the responder sends extras. Both are fine.
    #[must_use]
    pub fn tx_bloom_snapshot(&self) -> Option<BloomFilter<TxHash>> {
        let g = self.inner.pin();
        let mut bf = BloomFilter::with_capacity(g.len(), DEFAULT_FPR)?;
        for (hash, _) in &g {
            bf.insert(hash);
        }
        Some(bf)
    }
}

impl Default for TxStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::test_utils::verified_test_transaction;

    use super::*;

    fn tx(seed: u8) -> Arc<Verified<RoutableTransaction>> {
        Arc::new(verified_test_transaction(seed))
    }

    #[test]
    fn insert_then_get_round_trips() {
        let store = TxStore::new();
        let t = tx(1);
        let hash = t.hash();
        store.insert(Arc::clone(&t));
        assert_eq!(store.get(&hash).map(|a| a.hash()), Some(hash));
    }

    #[test]
    fn insert_is_idempotent() {
        let store = TxStore::new();
        let t = tx(1);
        store.insert(Arc::clone(&t));
        store.insert(Arc::clone(&t));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn get_batch_skips_missing_hashes() {
        let store = TxStore::new();
        let a = tx(1);
        let b = tx(2);
        let missing = tx(99).hash();
        store.insert(Arc::clone(&a));
        store.insert(Arc::clone(&b));
        let got = store.get_batch(&[a.hash(), missing, b.hash()]);
        assert_eq!(got.len(), 2);
    }

    #[test]
    fn evict_removes_only_listed_hashes() {
        let store = TxStore::new();
        let a = tx(1);
        let b = tx(2);
        store.insert(Arc::clone(&a));
        store.insert(Arc::clone(&b));
        let removed = store.evict([a.hash()]);
        assert_eq!(removed, 1);
        assert!(!store.contains(&a.hash()));
        assert!(store.contains(&b.hash()));
    }

    #[test]
    fn bloom_snapshot_contains_every_inserted_hash() {
        let store = TxStore::new();
        let txs: Vec<_> = (0..10).map(tx).collect();
        for t in &txs {
            store.insert(Arc::clone(t));
        }
        let bf = store.tx_bloom_snapshot().unwrap();
        for t in &txs {
            assert!(bf.contains(&t.hash()));
        }
    }
}
