//! Shared provision store.
//!
//! Single source of truth for provision bodies, keyed by content hash.
//! Held behind an `Arc` so both the single-threaded provisions state
//! machine and network-thread request handlers can read/write through
//! the same map.
//!
//! Two writers drive this store:
//!
//! - Inbound path ([`crate::coordinator::ProvisionCoordinator`]) inserts
//!   provisions received from remote shards via [`Self::insert`] and
//!   evicts them via the post-commit retention sweep.
//! - Outbound path ([`crate::outbound::OutboundProvisionTracker`]) inserts
//!   provisions our proposer generated via [`Self::insert_outbound`],
//!   which also populates a `(source_block_height, target_shard)` index
//!   used by the cross-shard `provision.request` fast path. Eviction is
//!   gated on terminal execution certificates from the target shard.

use hyperscale_types::{
    BlockHeight, BloomFilter, DEFAULT_FPR, ProvisionHash, Provisions, ShardGroupId,
};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

/// Shared content-addressed store of `Provisions` bodies.
pub struct ProvisionStore {
    inner: Mutex<HashMap<ProvisionHash, Arc<Provisions>>>,
    outbound_index: Mutex<HashMap<(BlockHeight, ShardGroupId), HashSet<ProvisionHash>>>,
}

impl ProvisionStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            outbound_index: Mutex::new(HashMap::new()),
        }
    }

    /// Insert provisions. Idempotent: re-inserting the same hash is a no-op.
    ///
    /// Inbound callers use this; the secondary outbound index is not
    /// touched.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned by a previously panicking writer.
    pub fn insert(&self, provisions: Arc<Provisions>) {
        let hash = provisions.hash();
        let mut g = self.inner.lock().unwrap();
        g.entry(hash).or_insert(provisions);
    }

    /// Insert provisions our proposer generated for `target_shard`.
    /// Populates the `(source_block_height, target_shard)` index so
    /// cross-shard `provision.request` handlers can serve from the cache
    /// before regenerating from `RocksDB`. Idempotent.
    ///
    /// # Panics
    ///
    /// Panics if either internal mutex is poisoned.
    pub fn insert_outbound(&self, provisions: Arc<Provisions>, target_shard: ShardGroupId) {
        let hash = provisions.hash();
        let block_height = provisions.block_height;
        {
            let mut g = self.inner.lock().unwrap();
            g.entry(hash).or_insert(provisions);
        }
        let mut idx = self.outbound_index.lock().unwrap();
        idx.entry((block_height, target_shard))
            .or_default()
            .insert(hash);
    }

    /// Look up provisions by content hash.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn get(&self, hash: &ProvisionHash) -> Option<Arc<Provisions>> {
        self.inner.lock().unwrap().get(hash).cloned()
    }

    /// Fetch every outbound provisions entry registered for
    /// `(block_height, target_shard)`. Returns an empty vec if nothing is
    /// cached — the caller should fall through to `RocksDB` regeneration.
    ///
    /// # Panics
    ///
    /// Panics if either internal mutex is poisoned.
    pub fn get_outbound(
        &self,
        block_height: BlockHeight,
        target_shard: ShardGroupId,
    ) -> Vec<Arc<Provisions>> {
        let idx = self.outbound_index.lock().unwrap();
        let Some(hashes) = idx.get(&(block_height, target_shard)) else {
            return Vec::new();
        };
        let hashes: Vec<ProvisionHash> = hashes.iter().copied().collect();
        drop(idx);
        let inner = self.inner.lock().unwrap();
        hashes
            .iter()
            .filter_map(|h| inner.get(h).cloned())
            .collect()
    }

    /// Evict provisions whose retention window has elapsed. Returns the
    /// number of entries actually removed from the primary map. Also
    /// scrubs the outbound secondary index for the evicted hashes.
    ///
    /// # Panics
    ///
    /// Panics if either internal mutex is poisoned.
    pub fn evict(&self, hashes: impl IntoIterator<Item = ProvisionHash>) -> usize {
        let hashes: Vec<ProvisionHash> = hashes.into_iter().collect();
        let removed = {
            let mut g = self.inner.lock().unwrap();
            hashes.iter().filter(|h| g.remove(h).is_some()).count()
        };
        if !hashes.is_empty() {
            let mut idx = self.outbound_index.lock().unwrap();
            idx.retain(|_, set| {
                for h in &hashes {
                    set.remove(h);
                }
                !set.is_empty()
            });
        }
        removed
    }

    /// Number of provisions currently held in the primary map.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    /// True when the primary map holds no provisions.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn is_empty(&self) -> bool {
        self.inner.lock().unwrap().is_empty()
    }

    /// Build a bloom filter over every cached provision hash. Sync
    /// inventory attaches this to `GetBlockRequest` so the responder can
    /// elide provisions the requester already holds.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn provision_bloom_snapshot(&self) -> Option<BloomFilter<ProvisionHash>> {
        let inner = self.inner.lock().unwrap();
        let mut bf = BloomFilter::with_capacity(inner.len(), DEFAULT_FPR)?;
        for hash in inner.keys() {
            bf.insert(hash);
        }
        Some(bf)
    }
}

impl Default for ProvisionStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{MerkleInclusionProof, TxEntries, TxHash};

    fn make_provisions(tx_seed: u8, height: u64) -> Arc<Provisions> {
        Arc::new(Provisions::new(
            ShardGroupId(1),
            BlockHeight(height),
            MerkleInclusionProof::dummy(),
            vec![TxEntries {
                tx_hash: TxHash::from_raw(hyperscale_types::Hash::from_bytes(&[tx_seed])),
                entries: vec![],
                target_nodes: vec![],
            }],
        ))
    }

    #[test]
    fn empty_store_yields_filter_that_matches_nothing() {
        let store = ProvisionStore::new();
        let bf = store.provision_bloom_snapshot().expect("empty sizing ok");
        let absent = make_provisions(99, 1);
        assert!(!bf.contains(&absent.hash()));
    }

    #[test]
    fn snapshot_contains_every_cached_hash() {
        let store = ProvisionStore::new();
        let entries: Vec<_> = (0u8..20)
            .map(|i| make_provisions(i, 1 + u64::from(i)))
            .collect();
        for p in &entries {
            store.insert(p.clone());
        }
        let bf = store.provision_bloom_snapshot().unwrap();
        for p in &entries {
            assert!(bf.contains(&p.hash()), "missing cached provisions");
        }
    }
}
