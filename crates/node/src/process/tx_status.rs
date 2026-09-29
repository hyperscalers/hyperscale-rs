//! Process-wide transaction status view.

use hyperscale_types::cache::{BoundedCache, EntryAction, EntryResult, bounded_cache};
use hyperscale_types::{ShardId, TransactionStatus, TxHash};

/// Capacity of the process-wide status cache.
const TX_STATUS_CACHE_SIZE: usize = 100_000;

/// Latest status per transaction that a hosted shard emitted, with the
/// shard that emitted it.
///
/// Each shard decides its own leg of a cross-shard transaction, so two
/// shards can hold different decisions about the same transaction. The
/// cache reports the status a hosted shard emitted for its own leg (see
/// [`TransactionStatus`] for what each shard's statuses mean): a process
/// hosting one shard of a transaction reports that shard's decision, and
/// a process hosting several reports the decision of whichever hosted
/// shard decided first. The shard beside each status names whose leg it
/// is.
///
/// One process-wide cache: every shard thread writes through
/// [`Self::record`]'s monotonic merge, external RPC consumers read
/// lock-free. The merge keeps the client-visible answer from regressing
/// when a lagging hosted shard reports an earlier phase after another
/// already advanced. Entries outlive shard departure (they age out by
/// LRU) and survive mempool eviction, so lookups can answer for
/// finalized/expired transactions.
pub struct TxStatusCache {
    cache: BoundedCache<TxHash, (TransactionStatus, ShardId)>,
}

/// Merge rank: statuses only advance `Pending → Committed →
/// LegFinalized → Completed`. Committed heights from different shards
/// are incomparable, so equal non-final ranks resolve by last write.
const fn rank(status: &TransactionStatus) -> u8 {
    match status {
        TransactionStatus::Pending => 0,
        TransactionStatus::Committed(_) => 1,
        TransactionStatus::LegFinalized => 2,
        TransactionStatus::Completed(_) => 3,
    }
}

/// Whether `incoming` replaces `existing`: a lower rank never does, and
/// nothing replaces a decision, so a second hosted shard's decision
/// cannot overwrite the first.
const fn supersedes(incoming: &TransactionStatus, existing: &TransactionStatus) -> bool {
    !existing.is_final() && rank(incoming) >= rank(existing)
}

impl TxStatusCache {
    /// Construct an empty cache at the default capacity.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cache: bounded_cache(TX_STATUS_CACHE_SIZE),
        }
    }

    /// Merge a status emitted by `shard` for its own leg. A write ranked
    /// below the current entry is dropped, and a decided entry keeps its
    /// decision; otherwise the write wins (see [`rank`]). The merge runs
    /// under the entry's lock, so racing shard threads cannot regress it.
    pub fn record(&self, tx_hash: TxHash, status: TransactionStatus, shard: ShardId) {
        let incoming = (status, shard);
        let result = self.cache.entry(&tx_hash, None, |_, existing| {
            if supersedes(&incoming.0, &existing.0) {
                *existing = incoming.clone();
            }
            EntryAction::Retain(())
        });
        match result {
            EntryResult::Vacant(guard) => {
                // A placeholder removed before this insert lands leaves the
                // entry absent; the shard's next emission records it.
                let _ = guard.insert(incoming);
            }
            EntryResult::Retained(()) => {}
            EntryResult::Removed(..) | EntryResult::Replaced(..) | EntryResult::Timeout => {
                unreachable!("the merge only retains, and waits without a timeout")
            }
        }
    }

    /// Latest merged status for `tx_hash`, with the hosted shard whose
    /// leg it is.
    #[must_use]
    pub fn get(&self, tx_hash: &TxHash) -> Option<(TransactionStatus, ShardId)> {
        self.cache.get(tx_hash)
    }

    /// Number of cached entries.
    #[must_use]
    pub(crate) fn len(&self) -> usize {
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
        TxHash::from(Hash::from_bytes(bytes))
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

    /// A leg finalizing ranks past its commit and short of the verdict:
    /// the issuer's leg neither regresses a core's decision nor is
    /// regressed by a lagging shard's commit.
    #[test]
    fn a_finalized_leg_sits_between_committed_and_completed() {
        let cache = TxStatusCache::new();
        let tx_hash = tx(&[4u8; 32]);

        cache.record(tx_hash, TransactionStatus::LegFinalized, SHARD_A);
        cache.record(
            tx_hash,
            TransactionStatus::Committed(BlockHeight::new(3)),
            SHARD_B,
        );
        let (status, _) = cache.get(&tx_hash).unwrap();
        assert_eq!(status, TransactionStatus::LegFinalized);

        cache.record(
            tx_hash,
            TransactionStatus::Completed(TransactionDecision::Accept),
            SHARD_B,
        );
        cache.record(tx_hash, TransactionStatus::LegFinalized, SHARD_A);
        let (status, _) = cache.get(&tx_hash).unwrap();
        assert_eq!(
            status,
            TransactionStatus::Completed(TransactionDecision::Accept)
        );
    }

    /// Two hosted shards can decide their legs differently; the entry
    /// keeps the first decision and the shard that made it, so a later
    /// shard's decision never relabels it.
    #[test]
    fn a_decision_is_not_replaced_by_another_shards() {
        let cache = TxStatusCache::new();
        let tx_hash = tx(&[5u8; 32]);

        cache.record(
            tx_hash,
            TransactionStatus::Completed(TransactionDecision::Reject),
            SHARD_A,
        );
        cache.record(
            tx_hash,
            TransactionStatus::Completed(TransactionDecision::Accept),
            SHARD_B,
        );

        assert_eq!(
            cache.get(&tx_hash),
            Some((
                TransactionStatus::Completed(TransactionDecision::Reject),
                SHARD_A
            ))
        );
    }

    #[test]
    fn equal_undecided_ranks_resolve_by_last_write() {
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
