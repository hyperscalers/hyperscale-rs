//! Time-bounded cache for provision batches.
//!
//! Entries are retained until `source_block_ts + RETENTION_WINDOW`. The
//! window is anchored on the BFT-authenticated weighted timestamp of the
//! source block, so all validators evict the same entries at the same
//! logical moment. Sized to match the cross-shard execution window plus
//! a rotation tail, so late-syncing peers can still fetch provisions in
//! time to execute and vote before the wave aborts.
//!
//! Eviction is opportunistic: `insert` sweeps expired entries at most
//! once per second. The secondary `by_expiry` index makes sweeps O(log n)
//! in the number of expiring buckets.
use hyperscale_types::{Provision, ProvisionHash, WeightedTimestamp, WAVE_TIMEOUT};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Retention margin beyond `WAVE_TIMEOUT`. Sized to cover one vote-retry
/// rotation (8s) plus slack for a late-syncing peer to fetch, execute,
/// and vote before the next rotation deadline.
pub const RETENTION_MARGIN: Duration = Duration::from_secs(12);

/// Total retention window: waves remain live for `WAVE_TIMEOUT`, and we
/// hold provisions long enough for laggards to catch up within their
/// rotation budget.
pub const RETENTION_WINDOW: Duration =
    Duration::from_secs(WAVE_TIMEOUT.as_secs() + RETENTION_MARGIN.as_secs());

/// Minimum interval between opportunistic sweeps.
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

struct Entry {
    batch: Arc<Provision>,
    expires_at: WeightedTimestamp,
}

struct Inner {
    by_hash: HashMap<ProvisionHash, Entry>,
    by_expiry: BTreeMap<WeightedTimestamp, Vec<ProvisionHash>>,
    last_sweep_ts: WeightedTimestamp,
    last_observed_ts: WeightedTimestamp,
}

/// Time-bounded provision cache. Thread-safe via interior mutability.
pub struct ProvisionCache {
    inner: Mutex<Inner>,
}

impl ProvisionCache {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                by_hash: HashMap::new(),
                by_expiry: BTreeMap::new(),
                last_sweep_ts: WeightedTimestamp::ZERO,
                last_observed_ts: WeightedTimestamp::ZERO,
            }),
        }
    }

    /// Insert a provision. `source_block_ts` is the BFT-authenticated
    /// weighted timestamp of the block that emitted it; retention is
    /// anchored there so eviction is deterministic across validators.
    pub fn insert(&self, batch: Arc<Provision>, source_block_ts: WeightedTimestamp) {
        let hash = batch.hash();
        let expires_at = source_block_ts.plus(RETENTION_WINDOW);
        let mut g = self.inner.lock().unwrap();

        if source_block_ts > g.last_observed_ts {
            g.last_observed_ts = source_block_ts;
        }

        if let Some(prev) = g.by_hash.insert(hash, Entry { batch, expires_at }) {
            if let Some(bucket) = g.by_expiry.get_mut(&prev.expires_at) {
                bucket.retain(|h| *h != hash);
                if bucket.is_empty() {
                    g.by_expiry.remove(&prev.expires_at);
                }
            }
        }
        g.by_expiry.entry(expires_at).or_default().push(hash);

        let now = g.last_observed_ts;
        if now.elapsed_since(g.last_sweep_ts) >= SWEEP_INTERVAL {
            Self::sweep_locked(&mut g, now);
        }
    }

    /// Lookup a provision by its batch hash. Returns the provision if
    /// present, regardless of expiry — stale entries are filtered out by
    /// the periodic sweep, and a brief window of stale reads is harmless
    /// (the serve path's Live/Sealed decision uses block age, not cache
    /// entry age).
    pub fn get(&self, hash: &ProvisionHash) -> Option<Arc<Provision>> {
        self.inner
            .lock()
            .unwrap()
            .by_hash
            .get(hash)
            .map(|e| Arc::clone(&e.batch))
    }

    /// Force an eviction sweep. Useful from a periodic tick; also runs
    /// inline from `insert` at most once per `SWEEP_INTERVAL`.
    pub fn sweep_expired(&self, now_ts: WeightedTimestamp) {
        let mut g = self.inner.lock().unwrap();
        if now_ts > g.last_observed_ts {
            g.last_observed_ts = now_ts;
        }
        Self::sweep_locked(&mut g, now_ts);
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().by_hash.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn sweep_locked(g: &mut Inner, now_ts: WeightedTimestamp) {
        g.last_sweep_ts = now_ts;
        let expired_keys: Vec<WeightedTimestamp> =
            g.by_expiry.range(..=now_ts).map(|(k, _)| *k).collect();
        for key in expired_keys {
            if let Some(hashes) = g.by_expiry.remove(&key) {
                for h in hashes {
                    g.by_hash.remove(&h);
                }
            }
        }
    }
}

impl Default for ProvisionCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{BlockHeight, MerkleInclusionProof, ShardGroupId};

    fn make_batch(source: ShardGroupId, height: BlockHeight) -> Arc<Provision> {
        Arc::new(Provision::new(
            source,
            height,
            MerkleInclusionProof(vec![]),
            vec![],
        ))
    }

    #[test]
    fn insert_then_get_returns_same_arc() {
        let cache = ProvisionCache::new();
        let batch = make_batch(ShardGroupId(1), BlockHeight(42));
        let hash = batch.hash();

        cache.insert(Arc::clone(&batch), WeightedTimestamp(1_000));

        let got = cache.get(&hash).expect("entry present");
        assert_eq!(got.hash(), hash);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn sweep_drops_entries_past_retention() {
        let cache = ProvisionCache::new();
        let old = make_batch(ShardGroupId(1), BlockHeight(1));
        let fresh = make_batch(ShardGroupId(1), BlockHeight(2));
        let old_ts = WeightedTimestamp(1_000);
        let fresh_ts = old_ts.plus(RETENTION_WINDOW).plus(Duration::from_secs(10));

        cache.insert(Arc::clone(&old), old_ts);
        cache.insert(Arc::clone(&fresh), fresh_ts);

        // Force a sweep at fresh_ts — old entry should be gone.
        cache.sweep_expired(fresh_ts);

        assert!(cache.get(&old.hash()).is_none());
        assert!(cache.get(&fresh.hash()).is_some());
    }

    #[test]
    fn reinsert_updates_expiry_bucket() {
        let cache = ProvisionCache::new();
        let batch = make_batch(ShardGroupId(1), BlockHeight(1));
        let ts1 = WeightedTimestamp(1_000);
        let ts2 = ts1.plus(Duration::from_secs(10));

        cache.insert(Arc::clone(&batch), ts1);
        cache.insert(Arc::clone(&batch), ts2);

        // Sweep right after ts1+RETENTION — entry should survive because
        // its expiry was updated to ts2+RETENTION.
        let probe = ts1.plus(RETENTION_WINDOW).plus(Duration::from_secs(1));
        cache.sweep_expired(probe);

        assert!(cache.get(&batch.hash()).is_some());
    }

    #[test]
    fn opportunistic_sweep_bounds_memory() {
        let cache = ProvisionCache::new();
        let base = WeightedTimestamp(1_000);

        // Insert 10 old batches.
        for i in 0..10u32 {
            let b = make_batch(ShardGroupId(1), BlockHeight(i as u64));
            cache.insert(b, base);
        }
        assert_eq!(cache.len(), 10);

        // A much later insert advances last_observed_ts and triggers the
        // opportunistic sweep, dropping the old entries.
        let fresh = make_batch(ShardGroupId(1), BlockHeight(100));
        let fresh_ts = base.plus(RETENTION_WINDOW).plus(Duration::from_secs(5));
        cache.insert(Arc::clone(&fresh), fresh_ts);

        assert_eq!(cache.len(), 1);
        assert!(cache.get(&fresh.hash()).is_some());
    }
}
