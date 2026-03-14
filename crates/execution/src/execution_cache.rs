//! In-memory cache of execution write sets, keyed by transaction hash.
//!
//! Used as the fast path during block commit: if this validator executed the
//! transaction, the writes are available in memory without disk or network I/O.
//!
//! # Ownership
//!
//! The `ExecutionCache` is a plain `HashMap` — no locks needed.
//! It is owned by the single-threaded state machine and accessed only from
//! its thread (insert on execution completion, read on block commit, remove
//! after commit).

use hyperscale_storage::DatabaseUpdates;
use hyperscale_types::Hash;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

/// Default maximum number of cached entries before LRU eviction.
pub const DEFAULT_MAX_ENTRIES: usize = 10_000;

/// Cached execution output for a single transaction.
struct CachedExecution {
    /// Raw write set from execution (Arc-wrapped for cheap clones across threads).
    database_updates: Arc<DatabaseUpdates>,
    /// Hash of the ConsensusReceipt (outcome + event_root).
    /// Used for debug_assert cross-checks at block commit time.
    receipt_hash: Hash,
}

/// In-memory cache of execution write sets, keyed by transaction hash.
///
/// Entries are evicted when:
/// - The transaction is committed in a block (writes applied to JMT)
/// - The transaction times out / is rejected
/// - The cache exceeds a size limit (LRU eviction)
///
/// This cache does NOT persist across restarts. After restart, the node
/// syncs (fetches receipts from peers) to rebuild state.
pub struct ExecutionCache {
    entries: HashMap<Hash, CachedExecution>,
    /// Insertion-order tracking for LRU eviction (VecDeque for O(1) pop_front).
    insertion_order: VecDeque<Hash>,
    /// Maximum number of entries before LRU eviction.
    max_entries: usize,
}

impl ExecutionCache {
    /// Create a new cache with the given maximum entry count.
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::with_capacity(max_entries.min(1024)),
            insertion_order: VecDeque::with_capacity(max_entries.min(1024)),
            max_entries,
        }
    }

    /// Insert execution results. If the cache is full, evict oldest entries.
    pub fn insert(&mut self, tx_hash: Hash, updates: Arc<DatabaseUpdates>, receipt_hash: Hash) {
        let entry = CachedExecution {
            database_updates: updates,
            receipt_hash,
        };

        // If already present, update in-place without changing insertion order
        if let std::collections::hash_map::Entry::Occupied(mut e) = self.entries.entry(tx_hash) {
            e.insert(entry);
            return;
        }

        // Evict oldest entries if at capacity
        while self.entries.len() >= self.max_entries {
            if let Some(oldest) = self.insertion_order.pop_front() {
                self.entries.remove(&oldest);
            } else {
                break;
            }
        }

        self.entries.insert(tx_hash, entry);
        self.insertion_order.push_back(tx_hash);
    }

    /// Look up cached writes for a transaction. Returns `None` if not cached.
    pub fn get(&self, tx_hash: &Hash) -> Option<&Arc<DatabaseUpdates>> {
        self.entries.get(tx_hash).map(|e| &e.database_updates)
    }

    /// Look up the cached receipt_hash for a transaction. Returns `None` if not cached.
    pub fn get_receipt_hash(&self, tx_hash: &Hash) -> Option<Hash> {
        self.entries.get(tx_hash).map(|e| e.receipt_hash)
    }

    /// Remove an entry (called after block commit or transaction rejection).
    pub fn remove(&mut self, tx_hash: &Hash) -> Option<Arc<DatabaseUpdates>> {
        if let Some(entry) = self.entries.remove(tx_hash) {
            self.insertion_order.retain(|h| h != tx_hash);
            Some(entry.database_updates)
        } else {
            None
        }
    }

    /// Remove multiple entries (called after block commit with all cert tx_hashes).
    pub fn remove_batch(&mut self, tx_hashes: &[Hash]) {
        for hash in tx_hashes {
            self.entries.remove(hash);
        }
        let set: std::collections::HashSet<&Hash> = tx_hashes.iter().collect();
        self.insertion_order.retain(|h| !set.contains(h));
    }

    /// Check if all given transaction hashes have cached writes.
    pub fn has_all(&self, tx_hashes: &[Hash]) -> bool {
        tx_hashes.iter().all(|h| self.entries.contains_key(h))
    }

    /// Return which of the given tx_hashes are missing from the cache.
    pub fn missing(&self, tx_hashes: &[Hash]) -> Vec<Hash> {
        tx_hashes
            .iter()
            .filter(|h| !self.entries.contains_key(h))
            .copied()
            .collect()
    }

    /// Number of cached entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_updates() -> Arc<DatabaseUpdates> {
        // Empty updates are sufficient for cache tests — we're testing
        // the cache mechanics, not the content of the updates.
        Arc::new(DatabaseUpdates::default())
    }

    fn hash(seed: u8) -> Hash {
        Hash::from_bytes(&[seed; 32])
    }

    #[test]
    fn test_insert_and_get() {
        let mut cache = ExecutionCache::new(100);
        let h = hash(1);
        let updates = make_updates();

        assert!(cache.get(&h).is_none());
        cache.insert(h, updates, Hash::ZERO);
        assert!(cache.get(&h).is_some());
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_remove() {
        let mut cache = ExecutionCache::new(100);
        let h = hash(1);
        cache.insert(h, make_updates(), Hash::ZERO);

        let removed = cache.remove(&h);
        assert!(removed.is_some());
        assert!(cache.get(&h).is_none());
        assert!(cache.is_empty());
    }

    #[test]
    fn test_remove_nonexistent() {
        let mut cache = ExecutionCache::new(100);
        assert!(cache.remove(&hash(99)).is_none());
    }

    #[test]
    fn test_remove_batch() {
        let mut cache = ExecutionCache::new(100);
        for i in 0..5 {
            cache.insert(hash(i), make_updates(), Hash::ZERO);
        }
        assert_eq!(cache.len(), 5);

        cache.remove_batch(&[hash(1), hash(3)]);
        assert_eq!(cache.len(), 3);
        assert!(cache.get(&hash(0)).is_some());
        assert!(cache.get(&hash(1)).is_none());
        assert!(cache.get(&hash(2)).is_some());
        assert!(cache.get(&hash(3)).is_none());
        assert!(cache.get(&hash(4)).is_some());
    }

    #[test]
    fn test_lru_eviction() {
        let mut cache = ExecutionCache::new(3);
        cache.insert(hash(1), make_updates(), Hash::ZERO);
        cache.insert(hash(2), make_updates(), Hash::ZERO);
        cache.insert(hash(3), make_updates(), Hash::ZERO);
        assert_eq!(cache.len(), 3);

        // Inserting a 4th should evict hash(1) (oldest)
        cache.insert(hash(4), make_updates(), Hash::ZERO);
        assert_eq!(cache.len(), 3);
        assert!(cache.get(&hash(1)).is_none(), "oldest should be evicted");
        assert!(cache.get(&hash(2)).is_some());
        assert!(cache.get(&hash(3)).is_some());
        assert!(cache.get(&hash(4)).is_some());
    }

    #[test]
    fn test_insert_duplicate_does_not_evict() {
        let mut cache = ExecutionCache::new(3);
        cache.insert(hash(1), make_updates(), Hash::ZERO);
        cache.insert(hash(2), make_updates(), Hash::ZERO);
        cache.insert(hash(3), make_updates(), Hash::ZERO);

        // Re-inserting hash(1) should NOT evict anything
        cache.insert(hash(1), make_updates(), Hash::ZERO);
        assert_eq!(cache.len(), 3);
        assert!(cache.get(&hash(1)).is_some());
        assert!(cache.get(&hash(2)).is_some());
        assert!(cache.get(&hash(3)).is_some());
    }

    #[test]
    fn test_has_all() {
        let mut cache = ExecutionCache::new(100);
        cache.insert(hash(1), make_updates(), Hash::ZERO);
        cache.insert(hash(2), make_updates(), Hash::ZERO);

        assert!(cache.has_all(&[hash(1), hash(2)]));
        assert!(!cache.has_all(&[hash(1), hash(3)]));
        assert!(cache.has_all(&[]));
    }

    #[test]
    fn test_missing() {
        let mut cache = ExecutionCache::new(100);
        cache.insert(hash(1), make_updates(), Hash::ZERO);
        cache.insert(hash(2), make_updates(), Hash::ZERO);

        let missing = cache.missing(&[hash(1), hash(2), hash(3)]);
        assert_eq!(missing, vec![hash(3)]);

        let none_missing = cache.missing(&[hash(1), hash(2)]);
        assert!(none_missing.is_empty());
    }
}
