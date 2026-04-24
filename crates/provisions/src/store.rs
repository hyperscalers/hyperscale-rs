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

use hyperscale_types::{BlockHeight, Provision, ProvisionHash, ShardGroupId};
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
}

impl Default for ProvisionStore {
    fn default() -> Self {
        Self::new()
    }
}
