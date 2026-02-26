//! Shared state types for RPC handlers.

use crate::status::SyncStatus;
use arc_swap::ArcSwap;
use hyperscale_core::{NodeInput, TransactionStatus};
use hyperscale_types::Hash;
use quick_cache::sync::Cache as QuickCache;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

/// Type alias for the transaction submission channel.
///
/// RPC handlers send `Event::SubmitTransaction` directly to the NodeLoop's
/// crossbeam event channel, bypassing tokio mpsc bridges entirely.
pub type TxSubmissionSender = crossbeam::channel::Sender<NodeInput>;

/// Shared state for RPC handlers.
#[derive(Clone)]
pub struct RpcState {
    /// Ready flag for readiness probe.
    pub ready: Arc<AtomicBool>,
    /// Sync status provider.
    pub sync_status: Arc<ArcSwap<SyncStatus>>,
    /// Node status provider.
    pub node_status: Arc<RwLock<NodeStatusState>>,
    /// Channel to submit transactions to the NodeLoop.
    ///
    /// RPC-submitted transactions are sent as `Event::SubmitTransaction` directly
    /// to the NodeLoop's crossbeam event channel, which:
    /// 1. Gossips to all relevant shards
    /// 2. Queues for batch validation (via Dispatch)
    /// 3. Dispatches to the mempool after validation
    pub tx_submission_tx: TxSubmissionSender,
    /// Server start time for uptime calculation.
    pub start_time: Instant,
    /// Transaction status cache for querying transaction state.
    ///
    /// Shared directly from NodeLoop's internal QuickCache — writes happen on
    /// the pinned thread, reads happen here on the RPC thread, no locking needed.
    pub tx_status_cache: Arc<QuickCache<Hash, TransactionStatus>>,
    /// Mempool snapshot for querying mempool stats.
    pub mempool_snapshot: Arc<RwLock<MempoolSnapshot>>,
    /// Number of blocks behind before rejecting transaction submissions.
    ///
    /// When set and the node is this many blocks behind, new transaction
    /// submissions are rejected to allow the node to catch up.
    pub sync_backpressure_threshold: Option<u64>,
}

/// Snapshot of mempool state for RPC queries.
///
/// Updated periodically by the runner from the mempool state.
#[derive(Debug, Clone)]
pub struct MempoolSnapshot {
    /// Number of pending transactions (waiting to be included in a block).
    pub pending_count: usize,
    /// Number of transactions in Committed status (block committed, being executed).
    pub committed_count: usize,
    /// Number of transactions in Executed status (execution done, awaiting certificate).
    pub executed_count: usize,
    /// Total number of transactions in the mempool.
    pub total_count: usize,
    /// Number of transactions deferred waiting for a winner.
    pub deferred_count: usize,
    /// When this snapshot was taken.
    pub updated_at: Option<Instant>,
    /// Whether the mempool is accepting new RPC transactions.
    ///
    /// When `false`, the cross-shard hard limit has been reached and new RPC
    /// submissions should be rejected with a backpressure response.
    ///
    /// Defaults to `true` so that transactions can be accepted before the first
    /// snapshot update from the runner.
    pub accepting_rpc_transactions: bool,
    /// Whether the pending transaction limit has been reached.
    ///
    /// When `true`, the pending transaction count exceeds the configured limit
    /// and new RPC submissions should be rejected with a backpressure response.
    ///
    /// Defaults to `false` so transactions can be accepted before the first
    /// snapshot update from the runner.
    pub at_pending_limit: bool,
}

impl Default for MempoolSnapshot {
    fn default() -> Self {
        Self {
            pending_count: 0,
            committed_count: 0,
            executed_count: 0,
            total_count: 0,
            deferred_count: 0,
            updated_at: None,
            accepting_rpc_transactions: true, // Default to accepting until we know otherwise
            at_pending_limit: false,          // Default to not at limit until we know otherwise
        }
    }
}

/// Mutable node status state updated by the runner.
#[derive(Debug, Clone, Default)]
pub struct NodeStatusState {
    pub validator_id: u64,
    pub shard: u64,
    pub num_shards: u64,
    pub block_height: u64,
    pub view: u64,
    pub connected_peers: usize,
    /// Current JMT state version (increments with each committed certificate).
    pub state_version: u64,
    /// Current JMT state root hash (hex-encoded).
    pub state_root_hash: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{BlockHeight, TransactionDecision};

    fn new_cache() -> QuickCache<Hash, TransactionStatus> {
        QuickCache::new(100)
    }

    #[test]
    fn test_cache_new() {
        let cache = new_cache();
        let tx_hash = Hash::from_bytes(&[1u8; 32]);
        assert!(cache.get(&tx_hash).is_none());
    }

    #[test]
    fn test_cache_update_and_get() {
        let cache = new_cache();
        let tx_hash = Hash::from_bytes(&[1u8; 32]);

        cache.insert(tx_hash, TransactionStatus::Pending);

        let status = cache.get(&tx_hash).unwrap();
        assert!(matches!(status, TransactionStatus::Pending));
    }

    #[test]
    fn test_cache_status_transitions() {
        let cache = new_cache();
        let tx_hash = Hash::from_bytes(&[2u8; 32]);

        // Pending -> Committed
        cache.insert(tx_hash, TransactionStatus::Pending);
        cache.insert(tx_hash, TransactionStatus::Committed(BlockHeight(10)));

        let status = cache.get(&tx_hash).unwrap();
        assert!(matches!(status, TransactionStatus::Committed(h) if h.0 == 10));

        // Committed -> Executed
        cache.insert(
            tx_hash,
            TransactionStatus::Executed {
                decision: TransactionDecision::Accept,
                committed_at: BlockHeight(1),
            },
        );
        let status = cache.get(&tx_hash).unwrap();
        assert!(matches!(
            status,
            TransactionStatus::Executed {
                decision: TransactionDecision::Accept,
                ..
            }
        ));

        // Executed -> Completed
        cache.insert(
            tx_hash,
            TransactionStatus::Completed(TransactionDecision::Accept),
        );
        let status = cache.get(&tx_hash).unwrap();
        assert!(matches!(
            status,
            TransactionStatus::Completed(TransactionDecision::Accept)
        ));
    }

    #[test]
    fn test_cache_blocked_status() {
        let cache = new_cache();
        let tx_hash = Hash::from_bytes(&[3u8; 32]);
        let blocker_hash = Hash::from_bytes(&[4u8; 32]);

        cache.insert(tx_hash, TransactionStatus::Deferred { by: blocker_hash });

        let status = cache.get(&tx_hash).unwrap();
        if let TransactionStatus::Deferred { by } = &status {
            assert_eq!(*by, blocker_hash);
        } else {
            panic!("Expected Deferred status");
        }
    }

    #[test]
    fn test_cache_retried_status() {
        let cache = new_cache();
        let tx_hash = Hash::from_bytes(&[5u8; 32]);
        let retry_hash = Hash::from_bytes(&[6u8; 32]);

        cache.insert(tx_hash, TransactionStatus::Retried { new_tx: retry_hash });

        let status = cache.get(&tx_hash).unwrap();
        if let TransactionStatus::Retried { new_tx } = &status {
            assert_eq!(*new_tx, retry_hash);
        } else {
            panic!("Expected Retried status");
        }
    }

    #[test]
    fn test_cache_get_unknown() {
        let cache = new_cache();
        let tx_hash = Hash::from_bytes(&[7u8; 32]);
        assert!(cache.get(&tx_hash).is_none());
    }
}
