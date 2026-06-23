//! Process-wide transaction status view.

use hyperscale_types::{ShardId, TransactionStatus, TxHash};
use quick_cache::sync::Cache as QuickCache;

/// Capacity of the process-wide status cache.
const TX_STATUS_CACHE_SIZE: usize = 100_000;

/// Latest emitted status per transaction across every hosted shard.
///
/// One process-wide cache: every shard thread writes through
/// [`Self::record`]'s monotonic merge, external RPC consumers read
/// lock-free. A cross-shard transaction gets statuses emitted by every
/// hosted shard that touches it; the merge keeps the client-visible
/// answer from regressing when a lagging shard reports an earlier
/// phase after another shard already advanced. Entries outlive shard
/// departure (they age out by LRU) and survive mempool eviction, so
/// lookups can answer for finalized/expired transactions.
pub struct TxStatusCache {
    cache: QuickCache<TxHash, (TransactionStatus, ShardId)>,
}

/// Merge rank: statuses only advance `Pending → Committed → Completed`.
/// Committed heights from different shards are incomparable, so equal
/// ranks resolve by last write.
const fn rank(status: &TransactionStatus) -> u8 {
    match status {
        TransactionStatus::Pending => 0,
        TransactionStatus::Committed(_) => 1,
        TransactionStatus::Completed(_) => 2,
    }
}

impl TxStatusCache {
    /// Construct an empty cache at the default capacity.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cache: QuickCache::new(TX_STATUS_CACHE_SIZE),
        }
    }

    /// Merge a status emitted by `shard`: a write ranked below the
    /// current entry is dropped, equal or higher ranks win (see
    /// [`rank`]). The recording shard is kept as provenance for
    /// debugging.
    ///
    /// The check-then-insert pair is not atomic — two shards racing on
    /// the same transaction can transiently regress a just-advanced
    /// status until the lagging shard's next emission. Cross-shard
    /// decisions agree, so the entry always reconverges to the same
    /// final status.
    pub fn record(&self, tx_hash: TxHash, status: TransactionStatus, shard: ShardId) {
        if let Some((existing, _)) = self.cache.get(&tx_hash)
            && rank(&status) < rank(&existing)
        {
            return;
        }
        self.cache.insert(tx_hash, (status, shard));
    }

    /// Latest merged status for `tx_hash`, with the shard that emitted
    /// it.
    #[must_use]
    pub fn get(&self, tx_hash: &TxHash) -> Option<(TransactionStatus, ShardId)> {
        self.cache.get(tx_hash)
    }

    /// Number of cached entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Whether the cache holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
}

impl Default for TxStatusCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{BlockHeight, Hash, TransactionDecision};

    use super::*;

    fn tx(bytes: &[u8]) -> TxHash {
        TxHash::from_raw(Hash::from_bytes(bytes))
    }

    const SHARD_A: ShardId = ShardId::leaf(1, 0);
    const SHARD_B: ShardId = ShardId::leaf(1, 1);

    #[test]
    fn get_unknown_is_none() {
        let cache = TxStatusCache::new();
        assert!(cache.get(&tx(&[1u8; 32])).is_none());
    }

    #[test]
    fn statuses_never_regress() {
        let cache = TxStatusCache::new();
        let tx_hash = tx(&[2u8; 32]);

        cache.record(tx_hash, TransactionStatus::Pending, SHARD_A);
        cache.record(
            tx_hash,
            TransactionStatus::Committed(BlockHeight::new(10)),
            SHARD_A,
        );
        // A lagging shard's Pending must not regress a Committed entry.
        cache.record(tx_hash, TransactionStatus::Pending, SHARD_B);
        let (status, shard) = cache.get(&tx_hash).unwrap();
        assert!(matches!(status, TransactionStatus::Committed(h) if h == BlockHeight::new(10)));
        assert_eq!(shard, SHARD_A);

        cache.record(
            tx_hash,
            TransactionStatus::Completed(TransactionDecision::Accept),
            SHARD_A,
        );
        // Nor must any non-final write regress a Completed entry.
        cache.record(tx_hash, TransactionStatus::Pending, SHARD_B);
        cache.record(
            tx_hash,
            TransactionStatus::Committed(BlockHeight::new(7)),
            SHARD_B,
        );
        let (status, shard) = cache.get(&tx_hash).unwrap();
        assert!(matches!(
            status,
            TransactionStatus::Completed(TransactionDecision::Accept)
        ));
        assert_eq!(shard, SHARD_A);
    }

    #[test]
    fn equal_ranks_resolve_by_last_write() {
        let cache = TxStatusCache::new();
        let tx_hash = tx(&[3u8; 32]);

        cache.record(
            tx_hash,
            TransactionStatus::Committed(BlockHeight::new(5)),
            SHARD_A,
        );
        cache.record(
            tx_hash,
            TransactionStatus::Committed(BlockHeight::new(9)),
            SHARD_B,
        );

        let (status, shard) = cache.get(&tx_hash).unwrap();
        assert!(matches!(status, TransactionStatus::Committed(h) if h == BlockHeight::new(9)));
        assert_eq!(shard, SHARD_B);
    }
}
