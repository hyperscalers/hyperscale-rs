//! Process-wide canonical transaction instances.

use std::convert::Infallible;

use hyperscale_types::cache::{BoundedCache, bounded_cache};
use hyperscale_types::{Transaction, TxHash};

/// Capacity of the canonical-instance cache. Sized to bridge the
/// cross-shard validation window, not to store history; entries age
/// out by LRU.
const CANONICAL_TX_CACHE_SIZE: usize = 10_000;

/// Canonical `Transaction` instance per tx hash.
///
/// A cross-shard transaction reaches a multi-shard host once per
/// hosted shard (per-shard gossip topics, per-shard fetch responses),
/// and every arrival decodes a fresh allocation with an empty
/// `validated` cache — left alone, each shard re-runs the full
/// signature/decode validation. Mapping every ingress onto one canonical
/// body shares the instance's `OnceLock` validation verdict instead:
/// the first shard to validate populates it, concurrent shards block
/// on the in-flight init rather than racing, and failed verdicts
/// dedupe the same way. Per-shard admission (pending-validation
/// tracking, mempool, tombstones) is untouched.
///
/// Identity here is the body hash — the same identity every per-shard
/// dedup (tx store, pending-validation set) already keys by.
pub struct CanonicalTxs {
    cache: BoundedCache<TxHash, Transaction>,
}

impl CanonicalTxs {
    pub(crate) fn new() -> Self {
        Self {
            cache: bounded_cache(CANONICAL_TX_CACHE_SIZE),
        }
    }

    /// Map `tx` onto the process-wide canonical instance for its hash.
    /// The first arrival's instance wins; later arrivals get it back.
    pub(crate) fn canonicalize(&self, tx: &Transaction) -> Transaction {
        let hash = tx.hash();
        self.cache
            .get_or_insert_with(&hash, || Ok::<_, Infallible>(tx.clone()))
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
        let first = test_transaction(1);
        let second = test_transaction(1);
        assert_eq!(first.hash(), second.hash());
        assert!(!first.same_body(&second));

        let a = canon.canonicalize(&first);
        let b = canon.canonicalize(&second);
        assert!(a.same_body(&first));
        assert!(b.same_body(&first));
    }

    #[test]
    fn distinct_transactions_keep_distinct_instances() {
        let canon = CanonicalTxs::new();
        let one = canon.canonicalize(&test_transaction(1));
        let two = canon.canonicalize(&test_transaction(2));
        assert!(!one.same_body(&two));
        assert_ne!(one.hash(), two.hash());
    }
}
