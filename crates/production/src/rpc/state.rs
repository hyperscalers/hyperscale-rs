//! Shared state types for RPC handlers.

use crate::sync::SyncStatus;
use hyperscale_core::TransactionStatus;
use hyperscale_types::{Hash, RoutableTransaction};
use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};

/// Shared state for RPC handlers.
#[derive(Clone)]
pub struct RpcState {
    /// Ready flag for readiness probe.
    pub ready: Arc<AtomicBool>,
    /// Sync status provider.
    pub sync_status: Arc<RwLock<SyncStatus>>,
    /// Node status provider.
    pub node_status: Arc<RwLock<NodeStatusState>>,
    /// Channel to submit transactions to the node.
    pub tx_sender: mpsc::Sender<RoutableTransaction>,
    /// Server start time for uptime calculation.
    pub start_time: Instant,
    /// Transaction status cache for querying transaction state.
    pub tx_status_cache: Arc<RwLock<TransactionStatusCache>>,
    /// Mempool snapshot for querying mempool stats.
    pub mempool_snapshot: Arc<RwLock<MempoolSnapshot>>,
}

/// Cached transaction status entry.
#[derive(Debug, Clone)]
pub struct CachedTransactionStatus {
    /// Current status of the transaction.
    pub status: TransactionStatus,
    /// When this entry was last updated.
    pub updated_at: Instant,
}

impl CachedTransactionStatus {
    /// Create a new cached status entry.
    pub fn new(status: TransactionStatus) -> Self {
        Self {
            status,
            updated_at: Instant::now(),
        }
    }
}

/// Cache of transaction statuses for RPC queries.
///
/// This cache is updated by the runner when processing `EmitTransactionStatus` actions.
/// Entries are kept for a configurable TTL to allow status queries after completion.
#[derive(Debug, Default)]
pub struct TransactionStatusCache {
    /// Map of transaction hash to cached status.
    entries: HashMap<Hash, CachedTransactionStatus>,
    /// Maximum number of entries to keep (prevents unbounded growth).
    max_entries: usize,
    /// TTL for completed transaction entries.
    completed_ttl: Duration,
}

impl TransactionStatusCache {
    /// Create a new cache with default settings.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            max_entries: 100_000,
            completed_ttl: Duration::from_secs(300), // 5 minutes
        }
    }

    /// Create a new cache with custom settings.
    pub fn with_config(max_entries: usize, completed_ttl: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries,
            completed_ttl,
        }
    }

    /// Update or insert a transaction status.
    pub fn update(&mut self, tx_hash: Hash, status: TransactionStatus) {
        // If at capacity and this is a new entry, evict old completed entries first
        if self.entries.len() >= self.max_entries && !self.entries.contains_key(&tx_hash) {
            self.evict_old_entries();
        }

        self.entries
            .insert(tx_hash, CachedTransactionStatus::new(status));
    }

    /// Get the status of a transaction.
    pub fn get(&self, tx_hash: &Hash) -> Option<&CachedTransactionStatus> {
        self.entries.get(tx_hash)
    }

    /// Evict old completed entries to make room for new ones.
    fn evict_old_entries(&mut self) {
        let now = Instant::now();
        let ttl = self.completed_ttl;

        // Remove entries that are completed/retried and older than TTL
        self.entries.retain(|_, entry| {
            let is_terminal = entry.status.is_final();
            let is_old = now.duration_since(entry.updated_at) > ttl;
            !(is_terminal && is_old)
        });

        // If still at capacity, remove oldest terminal entries
        if self.entries.len() >= self.max_entries {
            let mut terminal_entries: Vec<_> = self
                .entries
                .iter()
                .filter(|(_, e)| e.status.is_final())
                .map(|(h, e)| (*h, e.updated_at))
                .collect();

            terminal_entries.sort_by_key(|(_, t)| *t);

            // Remove oldest 10% of terminal entries
            let to_remove = terminal_entries.len() / 10 + 1;
            for (hash, _) in terminal_entries.into_iter().take(to_remove) {
                self.entries.remove(&hash);
            }
        }
    }

    /// Get the number of cached entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Snapshot of mempool state for RPC queries.
///
/// Updated periodically by the runner from the mempool state.
#[derive(Debug, Clone, Default)]
pub struct MempoolSnapshot {
    /// Number of pending transactions (waiting to be included in a block).
    pub pending_count: usize,
    /// Number of transactions currently being executed (holding locks).
    pub executing_count: usize,
    /// Total number of transactions in the mempool.
    pub total_count: usize,
    /// Number of transactions blocked waiting for a winner.
    pub blocked_count: usize,
    /// When this snapshot was taken.
    pub updated_at: Option<Instant>,
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{BlockHeight, TransactionDecision};

    #[test]
    fn test_cache_new() {
        let cache = TransactionStatusCache::new();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_cache_update_and_get() {
        let mut cache = TransactionStatusCache::new();
        let tx_hash = Hash::from_bytes(&[1u8; 32]);

        cache.update(tx_hash, TransactionStatus::Pending);
        assert_eq!(cache.len(), 1);

        let cached = cache.get(&tx_hash).unwrap();
        assert!(matches!(cached.status, TransactionStatus::Pending));
    }

    #[test]
    fn test_cache_status_transitions() {
        let mut cache = TransactionStatusCache::new();
        let tx_hash = Hash::from_bytes(&[2u8; 32]);

        // Pending -> Committed
        cache.update(tx_hash, TransactionStatus::Pending);
        cache.update(tx_hash, TransactionStatus::Committed(BlockHeight(10)));

        let cached = cache.get(&tx_hash).unwrap();
        assert!(matches!(cached.status, TransactionStatus::Committed(h) if h.0 == 10));

        // Committed -> Executed
        cache.update(
            tx_hash,
            TransactionStatus::Executed(TransactionDecision::Accept),
        );
        let cached = cache.get(&tx_hash).unwrap();
        assert!(matches!(
            cached.status,
            TransactionStatus::Executed(TransactionDecision::Accept)
        ));

        // Executed -> Completed
        cache.update(tx_hash, TransactionStatus::Completed);
        let cached = cache.get(&tx_hash).unwrap();
        assert!(matches!(cached.status, TransactionStatus::Completed));
    }

    #[test]
    fn test_cache_blocked_status() {
        let mut cache = TransactionStatusCache::new();
        let tx_hash = Hash::from_bytes(&[3u8; 32]);
        let blocker_hash = Hash::from_bytes(&[4u8; 32]);

        cache.update(tx_hash, TransactionStatus::Blocked { by: blocker_hash });

        let cached = cache.get(&tx_hash).unwrap();
        if let TransactionStatus::Blocked { by } = &cached.status {
            assert_eq!(*by, blocker_hash);
        } else {
            panic!("Expected Blocked status");
        }
    }

    #[test]
    fn test_cache_retried_status() {
        let mut cache = TransactionStatusCache::new();
        let tx_hash = Hash::from_bytes(&[5u8; 32]);
        let retry_hash = Hash::from_bytes(&[6u8; 32]);

        cache.update(tx_hash, TransactionStatus::Retried { new_tx: retry_hash });

        let cached = cache.get(&tx_hash).unwrap();
        if let TransactionStatus::Retried { new_tx } = &cached.status {
            assert_eq!(*new_tx, retry_hash);
        } else {
            panic!("Expected Retried status");
        }
    }

    #[test]
    fn test_cache_get_unknown() {
        let cache = TransactionStatusCache::new();
        let tx_hash = Hash::from_bytes(&[7u8; 32]);
        assert!(cache.get(&tx_hash).is_none());
    }

    #[test]
    fn test_cache_with_config() {
        let cache = TransactionStatusCache::with_config(10, Duration::from_secs(60));
        assert!(cache.is_empty());
    }
}
