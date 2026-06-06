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
//!
//! Both maps are backed by [`papaya::HashMap`] — lock-free concurrent
//! maps so the network worker thread can read provisions wait-free in
//! the common case without contending with the single state-machine
//! writer.
//!
//! The outbound index is single-slot per `(source_block_height,
//! target_shard)`: the protocol guarantees exactly one [`Provisions`]
//! batch per such key (the proposer commits to one set at the source
//! block, attested in the source block header). Repeated inserts for
//! the same key are idempotent.

use std::collections::HashSet;
use std::sync::Arc;

use hyperscale_types::{BlockHeight, BloomFilter, DEFAULT_FPR, ProvisionHash, Provisions, ShardId};
use papaya::HashMap;

/// Shared content-addressed store of `Provisions` bodies.
pub struct ProvisionStore {
    inner: HashMap<ProvisionHash, Arc<Provisions>>,
    outbound_index: HashMap<(BlockHeight, ShardId), Arc<Provisions>>,
}

impl ProvisionStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
            outbound_index: HashMap::new(),
        }
    }

    /// Insert provisions. Idempotent: re-inserting the same hash is a no-op.
    ///
    /// Inbound callers use this; the secondary outbound index is not
    /// touched.
    pub fn insert(&self, provisions: Arc<Provisions>) {
        let hash = provisions.hash();
        self.inner.pin().get_or_insert_with(hash, || provisions);
    }

    /// Insert provisions our proposer generated for `target_shard`.
    /// Populates the `(source_block_height, target_shard)` slot so
    /// cross-shard `provision.request` handlers can serve from the cache
    /// before regenerating from `RocksDB`. Idempotent on the
    /// `(height, shard)` slot — first writer wins, repeated inserts of
    /// the same content are no-ops.
    pub fn insert_outbound(&self, provisions: Arc<Provisions>, target_shard: ShardId) {
        let hash = provisions.hash();
        let block_height = provisions.block_height();
        self.inner
            .pin()
            .get_or_insert_with(hash, || Arc::clone(&provisions));
        self.outbound_index
            .pin()
            .get_or_insert_with((block_height, target_shard), || provisions);
    }

    /// Look up provisions by content hash.
    pub fn get(&self, hash: ProvisionHash) -> Option<Arc<Provisions>> {
        self.inner.pin().get(&hash).cloned()
    }

    /// Fetch the outbound provisions registered for
    /// `(block_height, target_shard)`, if any. Returns `None` if nothing
    /// is cached — the caller should fall through to `RocksDB`
    /// regeneration.
    pub fn get_outbound(
        &self,
        block_height: BlockHeight,
        target_shard: ShardId,
    ) -> Option<Arc<Provisions>> {
        self.outbound_index
            .pin()
            .get(&(block_height, target_shard))
            .cloned()
    }

    /// Evict provisions whose retention window has elapsed. Returns the
    /// number of entries actually removed from the primary map. Also
    /// scrubs the outbound secondary index for the evicted hashes.
    pub fn evict(&self, hashes: impl IntoIterator<Item = ProvisionHash>) -> usize {
        let hashes: HashSet<ProvisionHash> = hashes.into_iter().collect();
        if hashes.is_empty() {
            return 0;
        }
        let removed = {
            let g = self.inner.pin();
            hashes.iter().filter(|h| g.remove(*h).is_some()).count()
        };
        let idx = self.outbound_index.pin();
        idx.retain(|_, provisions| !hashes.contains(&provisions.hash()));
        removed
    }

    /// Number of provisions currently held in the primary map.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// True when the primary map holds no provisions.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Build a bloom filter over every cached provision hash. Sync
    /// inventory attaches this to `GetBlockRequest` so the responder can
    /// elide provisions the requester already holds.
    ///
    /// Iteration is concurrent-safe: keys inserted or removed during the
    /// snapshot may or may not appear. Bloom filters are an inclusion hint,
    /// not a manifest — false positives waste a fetch attempt, false
    /// negatives just mean the responder sends extras.
    pub fn provision_bloom_snapshot(&self) -> Option<BloomFilter<ProvisionHash>> {
        let g = self.inner.pin();
        let mut bf = BloomFilter::with_capacity(g.len(), DEFAULT_FPR)?;
        for (hash, _) in &g {
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
    use hyperscale_types::{Hash, MerkleInclusionProof, ProvisionEntry, TxHash};

    use super::*;

    fn make_provisions(tx_seed: u8, height: u64) -> Arc<Provisions> {
        Arc::new(Provisions::new(
            ShardId::leaf(1, 1),
            ShardId::leaf(1, 0),
            BlockHeight::new(height),
            MerkleInclusionProof::dummy(),
            vec![ProvisionEntry::new(
                TxHash::from_raw(Hash::from_bytes(&[tx_seed])),
                vec![],
                vec![],
                vec![],
            )],
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
