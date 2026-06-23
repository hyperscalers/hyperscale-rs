//! Process-wide canonical transaction instances.

use std::convert::Infallible;
use std::sync::Arc;

use hyperscale_types::{RoutableTransaction, TxHash};
use quick_cache::sync::Cache as QuickCache;

/// Capacity of the canonical-instance cache. Sized to bridge the
/// cross-shard validation window, not to store history; entries age
/// out by LRU.
const CANONICAL_TX_CACHE_SIZE: usize = 10_000;

/// Canonical `RoutableTransaction` instance per tx hash.
///
/// A cross-shard transaction reaches a multi-shard host once per
/// hosted shard (per-shard gossip topics, per-shard fetch responses),
/// and every arrival decodes a fresh allocation with an empty
/// `validated` cache — left alone, each shard re-runs the full
/// signature/SBOR validation. Mapping every ingress onto one canonical
/// `Arc` shares the instance's `OnceLock` validation verdict instead:
/// the first shard to validate populates it, concurrent shards block
/// on the in-flight init rather than racing, and failed verdicts
/// dedupe the same way. Per-shard admission (pending-validation
/// tracking, mempool, tombstones) is untouched.
///
/// Identity here is the body hash — the same identity every per-shard
/// dedup (tx store, pending-validation set) already keys by.
pub struct CanonicalTxs {
    cache: QuickCache<TxHash, Arc<RoutableTransaction>>,
}

impl CanonicalTxs {
    pub fn new() -> Self {
        Self {
            cache: QuickCache::new(CANONICAL_TX_CACHE_SIZE),
        }
    }

    /// Map `tx` onto the process-wide canonical instance for its hash.
    /// The first arrival's instance wins; later arrivals get it back.
    pub fn canonicalize(&self, tx: &Arc<RoutableTransaction>) -> Arc<RoutableTransaction> {
        let hash = tx.hash();
        self.cache
            .get_or_insert_with(&hash, || Ok::<_, Infallible>(Arc::clone(tx)))
            .expect("get_or_insert_with closure is infallible")
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::test_utils::test_transaction;

    use super::*;

    #[test]
    fn later_arrivals_map_onto_the_first_instance() {
        let canon = CanonicalTxs::new();
        let first = Arc::new(test_transaction(1));
        let second = Arc::new(first.as_ref().clone());
        assert!(!Arc::ptr_eq(&first, &second));

        let a = canon.canonicalize(&first);
        let b = canon.canonicalize(&second);
        assert!(Arc::ptr_eq(&a, &first));
        assert!(Arc::ptr_eq(&b, &first));
    }

    #[test]
    fn distinct_transactions_keep_distinct_instances() {
        let canon = CanonicalTxs::new();
        let one = canon.canonicalize(&Arc::new(test_transaction(1)));
        let two = canon.canonicalize(&Arc::new(test_transaction(2)));
        assert!(!Arc::ptr_eq(&one, &two));
        assert_ne!(one.hash(), two.hash());
    }
}
