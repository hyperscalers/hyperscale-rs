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

use hyperscale_types::{ConcreteConfig, Hash, TypeConfig};
use std::collections::HashMap;
use std::sync::Arc;

/// Cached execution output for a single transaction.
struct CachedExecution<C: TypeConfig> {
    /// Raw write set from execution (Arc-wrapped for cheap clones across threads).
    database_updates: Arc<C::StateUpdate>,
    /// Hash of the ConsensusReceipt (outcome + event_root).
    /// Used for debug_assert cross-checks at block commit time.
    receipt_hash: Hash,
}

/// In-memory cache of execution write sets, keyed by transaction hash.
///
/// Entries are explicitly evicted when:
/// - The transaction is committed in a block (writes applied to JMT)
/// - The transaction times out / is rejected
///
/// This cache does NOT persist across restarts. After restart, the node
/// syncs (fetches receipts from peers) to rebuild state.
pub struct ExecutionCache<C: TypeConfig = ConcreteConfig> {
    entries: HashMap<Hash, CachedExecution<C>>,
}

impl<C: TypeConfig> ExecutionCache<C> {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Insert execution results.
    pub fn insert(&mut self, tx_hash: Hash, updates: Arc<C::StateUpdate>, receipt_hash: Hash) {
        self.entries.insert(
            tx_hash,
            CachedExecution {
                database_updates: updates,
                receipt_hash,
            },
        );
    }

    /// Look up cached writes for a transaction. Returns `None` if not cached.
    pub fn get(&self, tx_hash: &Hash) -> Option<&Arc<C::StateUpdate>> {
        self.entries.get(tx_hash).map(|e| &e.database_updates)
    }

    /// Look up the cached receipt_hash for a transaction. Returns `None` if not cached.
    pub fn get_receipt_hash(&self, tx_hash: &Hash) -> Option<Hash> {
        self.entries.get(tx_hash).map(|e| e.receipt_hash)
    }

    /// Remove an entry (called after block commit or transaction rejection).
    pub fn remove(&mut self, tx_hash: &Hash) -> Option<Arc<C::StateUpdate>> {
        self.entries.remove(tx_hash).map(|e| e.database_updates)
    }

    /// Remove multiple entries (called after block commit with all cert tx_hashes).
    pub fn remove_batch(&mut self, tx_hashes: &[Hash]) {
        for hash in tx_hashes {
            self.entries.remove(hash);
        }
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

impl<C: TypeConfig> Default for ExecutionCache<C> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_storage::DatabaseUpdates;

    fn make_updates() -> Arc<DatabaseUpdates> {
        Arc::new(DatabaseUpdates::default())
    }

    fn hash(seed: u8) -> Hash {
        Hash::from_bytes(&[seed; 32])
    }

    #[test]
    fn test_insert_and_get() {
        let mut cache: ExecutionCache = ExecutionCache::new();
        let h = hash(1);
        let updates = make_updates();

        assert!(cache.get(&h).is_none());
        cache.insert(h, updates, Hash::ZERO);
        assert!(cache.get(&h).is_some());
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_remove() {
        let mut cache: ExecutionCache = ExecutionCache::new();
        let h = hash(1);
        cache.insert(h, make_updates(), Hash::ZERO);

        let removed = cache.remove(&h);
        assert!(removed.is_some());
        assert!(cache.get(&h).is_none());
        assert!(cache.is_empty());
    }

    #[test]
    fn test_remove_nonexistent() {
        let mut cache: ExecutionCache = ExecutionCache::new();
        assert!(cache.remove(&hash(99)).is_none());
    }

    #[test]
    fn test_remove_batch() {
        let mut cache: ExecutionCache = ExecutionCache::new();
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
    fn test_insert_duplicate_replaces() {
        let mut cache: ExecutionCache = ExecutionCache::new();
        cache.insert(hash(1), make_updates(), Hash::ZERO);
        cache.insert(hash(2), make_updates(), Hash::ZERO);

        // Re-inserting hash(1) should replace in-place
        cache.insert(hash(1), make_updates(), Hash::ZERO);
        assert_eq!(cache.len(), 2);
        assert!(cache.get(&hash(1)).is_some());
        assert!(cache.get(&hash(2)).is_some());
    }

    #[test]
    fn test_has_all() {
        let mut cache: ExecutionCache = ExecutionCache::new();
        cache.insert(hash(1), make_updates(), Hash::ZERO);
        cache.insert(hash(2), make_updates(), Hash::ZERO);

        assert!(cache.has_all(&[hash(1), hash(2)]));
        assert!(!cache.has_all(&[hash(1), hash(3)]));
        assert!(cache.has_all(&[]));
    }

    #[test]
    fn test_missing() {
        let mut cache: ExecutionCache = ExecutionCache::new();
        cache.insert(hash(1), make_updates(), Hash::ZERO);
        cache.insert(hash(2), make_updates(), Hash::ZERO);

        let missing = cache.missing(&[hash(1), hash(2), hash(3)]);
        assert_eq!(missing, vec![hash(3)]);

        let none_missing = cache.missing(&[hash(1), hash(2)]);
        assert!(none_missing.is_empty());
    }
}
