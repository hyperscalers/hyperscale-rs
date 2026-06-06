//! Shared state types for RPC handlers.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use arc_swap::ArcSwap;
use hyperscale_types::{InFlightCount, RoutableTransaction, ShardId, TransactionStatus, TxHash};
use quick_cache::sync::Cache as QuickCache;
use serde::{Deserialize, Serialize};

use crate::status::SyncStatus;

/// Submit a locally-issued transaction to the runner.
///
/// Returns `true` if the runner accepted the tx; `false` only when the
/// runner is shutting down (every per-shard channel send failed). The
/// closure is shared (`Fn`) and called concurrently from tokio worker
/// threads — internally it computes the touched-shard fanout from a
/// lock-free topology snapshot and pushes admit/admit-and-gossip
/// envelopes onto the relevant per-shard event channels.
pub type TxSubmissionSender = Arc<dyn Fn(Arc<RoutableTransaction>) -> bool + Send + Sync + 'static>;

/// Shared state for RPC handlers.
#[derive(Clone)]
pub struct RpcState {
    /// Ready flag for readiness probe.
    pub ready: Arc<AtomicBool>,
    /// Sync status provider.
    pub sync_status: Arc<ArcSwap<SyncStatus>>,
    /// Node status provider.
    pub node_status: Arc<ArcSwap<NodeStatusState>>,
    /// Channel to submit transactions to the `IoLoop`.
    ///
    /// RPC-submitted transactions are sent as `Event::SubmitTransaction` directly
    /// to the `IoLoop`'s crossbeam event channel, which:
    /// 1. Gossips to all relevant shards
    /// 2. Queues for batch validation (via Dispatch)
    /// 3. Dispatches to the mempool after validation
    pub tx_submission_tx: TxSubmissionSender,
    /// Server start time for uptime calculation.
    pub start_time: Instant,
    /// Per-shard transaction status caches for querying transaction state.
    ///
    /// One entry per hosted shard, shared directly from `IoLoop`'s
    /// internal `QuickCache` instances — writes happen on the pinned
    /// thread, reads happen here on the RPC thread, no locking needed.
    /// Status lookup probes every entry: a tx may have landed on any
    /// hosted shard, and under cross-shard packed a single primary
    /// entry would hide half the txs.
    pub tx_status_caches: HashMap<ShardId, Arc<QuickCache<TxHash, TransactionStatus>>>,
    /// Mempool snapshot for querying mempool stats.
    pub mempool_snapshot: Arc<ArcSwap<MempoolSnapshot>>,
    /// Number of blocks behind before rejecting transaction submissions.
    ///
    /// When set and the node is this many blocks behind, new transaction
    /// submissions are rejected to allow the node to catch up.
    pub sync_backpressure_threshold: Option<u64>,
}

impl RpcState {
    /// Look up `hash` in every hosted shard's status cache. Returns the
    /// first match. A given tx hash lives in at most one shard's cache,
    /// so iteration order doesn't matter.
    #[must_use]
    pub fn lookup_tx_status(&self, hash: &TxHash) -> Option<TransactionStatus> {
        self.tx_status_caches.values().find_map(|c| c.get(hash))
    }
}

/// Snapshot of mempool state for RPC queries.
///
/// One [`VnodeMempoolSnapshot`] per hosted vnode, keyed by validator
/// id. Each vnode owns its own [`hyperscale_mempool::MempoolCoordinator`];
/// same-shard vnodes converge by determinism but their instantaneous
/// counts diverge, so the backpressure check must inspect every entry
/// individually (not pick a shard-level "representative"). Used only
/// by RPC submission backpressure — per-vnode counts shown to clients
/// live in [`NodeStatusState::vnodes`].
#[derive(Debug, Clone, Default)]
pub struct MempoolSnapshot {
    /// Per-hosted-vnode mempool readouts, keyed by validator id.
    pub vnodes: HashMap<u64, VnodeMempoolSnapshot>,
}

/// One hosted vnode's mempool readout.
#[derive(Debug, Clone)]
pub struct VnodeMempoolSnapshot {
    /// Number of pending transactions (waiting to be included in a block).
    pub pending_count: usize,
    /// Number of transactions holding state locks (Committed status).
    pub in_flight_count: usize,
    /// Total number of transactions in the mempool.
    pub total_count: usize,
    /// When this snapshot was taken.
    pub updated_at: Option<Instant>,
    /// Whether the mempool is accepting new RPC transactions.
    ///
    /// When `false`, the cross-shard hard limit has been reached and new RPC
    /// submissions should be rejected with a backpressure response.
    pub accepting_rpc_transactions: bool,
    /// Whether the pending transaction limit has been reached.
    ///
    /// When `true`, the pending transaction count exceeds the configured limit
    /// and new RPC submissions should be rejected with a backpressure response.
    pub at_pending_limit: bool,
    /// Per-remote-shard in-flight counts from latest verified block headers.
    /// Used for cross-shard backpressure: reject transactions targeting congested shards.
    pub remote_shard_in_flight: HashMap<ShardId, InFlightCount>,
    /// Threshold for rejecting transactions due to remote shard congestion
    /// (80% of [`hyperscale_types::MAX_TX_IN_FLIGHT`]).
    pub remote_congestion_threshold: InFlightCount,
}

impl Default for VnodeMempoolSnapshot {
    fn default() -> Self {
        Self {
            pending_count: 0,
            in_flight_count: 0,
            total_count: 0,
            updated_at: None,
            accepting_rpc_transactions: true,
            at_pending_limit: false,
            remote_shard_in_flight: HashMap::new(),
            remote_congestion_threshold: InFlightCount::ZERO,
        }
    }
}

/// Mutable node status state updated by the runner.
///
/// Process-level fields (`num_shards`, `connected_peers`) sit at the top;
/// per-vnode readouts live in `vnodes`, sorted by `validator_id` for stable
/// output. Multi-vnode hosts surface every hosted vnode; single-vnode hosts
/// produce a one-element `vnodes` vec.
#[allow(missing_docs)] // flat readouts; field names are the documentation
#[derive(Debug, Clone, Default)]
pub struct NodeStatusState {
    pub num_shards: u64,
    pub connected_peers: usize,
    pub vnodes: Vec<VnodeStatusEntry>,
}

/// Per-hosted-vnode status entry. Mirrors the wire shape exposed under
/// `vnodes[]` in the `/api/v1/status` response.
#[allow(missing_docs)] // flat readouts; field names are the documentation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VnodeStatusEntry {
    pub validator_id: u64,
    pub shard: u64,
    pub block_height: u64,
    pub view: u64,
    /// Current JMT state root hash (hex-encoded).
    pub state_root_hash: String,
    pub mempool: VnodeMempoolStats,
}

/// Per-vnode mempool counts, embedded in each [`VnodeStatusEntry`].
#[allow(missing_docs)] // flat readouts; field names are the documentation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VnodeMempoolStats {
    pub pending_count: usize,
    pub in_flight_count: usize,
    pub total_count: usize,
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{BlockHeight, Hash, TransactionDecision};

    use super::*;

    fn new_cache() -> QuickCache<TxHash, TransactionStatus> {
        QuickCache::new(100)
    }

    fn tx(bytes: &[u8]) -> TxHash {
        TxHash::from_raw(Hash::from_bytes(bytes))
    }

    #[test]
    fn test_cache_new() {
        let cache = new_cache();
        let tx_hash = tx(&[1u8; 32]);
        assert!(cache.get(&tx_hash).is_none());
    }

    #[test]
    fn test_cache_update_and_get() {
        let cache = new_cache();
        let tx_hash = tx(&[1u8; 32]);

        cache.insert(tx_hash, TransactionStatus::Pending);

        let status = cache.get(&tx_hash).unwrap();
        assert!(matches!(status, TransactionStatus::Pending));
    }

    #[test]
    fn test_cache_status_transitions() {
        let cache = new_cache();
        let tx_hash = tx(&[2u8; 32]);

        // Pending -> Committed
        cache.insert(tx_hash, TransactionStatus::Pending);
        cache.insert(tx_hash, TransactionStatus::Committed(BlockHeight::new(10)));

        let status = cache.get(&tx_hash).unwrap();
        assert!(matches!(status, TransactionStatus::Committed(h) if h == BlockHeight::new(10)));

        // Committed -> Completed
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
    fn test_cache_get_unknown() {
        let cache = new_cache();
        let tx_hash = tx(&[7u8; 32]);
        assert!(cache.get(&tx_hash).is_none());
    }
}
