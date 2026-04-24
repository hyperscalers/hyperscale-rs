//! Shared provision-batch store.
//!
//! Single source of truth for provision bodies, keyed by content hash.
//! Held behind an `Arc` so both the single-threaded provisions state
//! machine and network-thread request handlers can read/write through
//! the same map.
//!
//! Two writers drive this store:
//!
//! - Inbound path ([`crate::state::ProvisionCoordinator`]) inserts batches
//!   received from remote shards via [`Self::insert`] and evicts them via
//!   the post-commit retention sweep.
//! - Outbound path ([`crate::outbound::OutboundProvisionTracker`]) inserts
//!   batches our proposer generated via [`Self::insert_outbound`], which
//!   also populates a `(source_block_height, target_shard)` index used by
//!   the cross-shard `provision.request` fast path. Eviction is gated on
//!   terminal execution certificates from the target shard.

use hyperscale_types::{
    BlockHeight, BloomFilter, Provision, ProvisionHash, ShardGroupId, DEFAULT_FPR,
};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

pub struct ProvisionStore {
    inner: Mutex<HashMap<ProvisionHash, Arc<Provision>>>,
    outbound_index: Mutex<HashMap<(BlockHeight, ShardGroupId), HashSet<ProvisionHash>>>,
}

impl ProvisionStore {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            outbound_index: Mutex::new(HashMap::new()),
        }
    }

    /// Insert a batch. Idempotent: re-inserting the same hash is a no-op.
    ///
    /// Inbound callers use this; the secondary outbound index is not
    /// touched.
    pub fn insert(&self, batch: Arc<Provision>) {
        let hash = batch.hash();
        let mut g = self.inner.lock().unwrap();
        g.entry(hash).or_insert(batch);
    }

    /// Insert a batch our proposer generated for `target_shard`. Populates
    /// the `(source_block_height, target_shard)` index so cross-shard
    /// `provision.request` handlers can serve from the cache before
    /// regenerating from RocksDB. Idempotent.
    pub fn insert_outbound(&self, batch: Arc<Provision>, target_shard: ShardGroupId) {
        let hash = batch.hash();
        let block_height = batch.block_height;
        {
            let mut g = self.inner.lock().unwrap();
            g.entry(hash).or_insert(batch);
        }
        let mut idx = self.outbound_index.lock().unwrap();
        idx.entry((block_height, target_shard))
            .or_default()
            .insert(hash);
    }

    /// Look up a batch by content hash.
    pub fn get(&self, hash: &ProvisionHash) -> Option<Arc<Provision>> {
        self.inner.lock().unwrap().get(hash).cloned()
    }

    /// Fetch every outbound batch registered for `(block_height, target_shard)`.
    /// Returns an empty vec if nothing is cached — the caller should fall
    /// through to RocksDB regeneration.
    pub fn get_outbound(
        &self,
        block_height: BlockHeight,
        target_shard: ShardGroupId,
    ) -> Vec<Arc<Provision>> {
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

    /// Evict batches whose retention window has elapsed. Returns the number
    /// of entries actually removed from the primary map. Also scrubs the
    /// outbound secondary index for the evicted hashes.
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

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.lock().unwrap().is_empty()
    }

    /// Build a bloom filter over every cached provision hash. Sync
    /// inventory attaches this to `GetBlockRequest` so the responder can
    /// elide provisions the requester already holds.
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

    fn make_batch(tx_seed: u8, height: u64) -> Arc<Provision> {
        Arc::new(Provision::new(
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
        let absent = make_batch(99, 1);
        assert!(!bf.contains(&absent.hash()));
    }

    #[test]
    fn snapshot_contains_every_cached_hash() {
        let store = ProvisionStore::new();
        let batches: Vec<_> = (0u8..20).map(|i| make_batch(i, 1 + i as u64)).collect();
        for b in &batches {
            store.insert(b.clone());
        }
        let bf = store.provision_bloom_snapshot().unwrap();
        for b in &batches {
            assert!(bf.contains(&b.hash()), "missing cached batch");
        }
    }
}
