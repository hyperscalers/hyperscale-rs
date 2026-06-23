//! Shared state types for RPC handlers.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use arc_swap::ArcSwap;
use hyperscale_node::TxStatusCache;
use hyperscale_types::{InFlightCount, RoutableTransaction, ShardId, TransactionStatus, TxHash};
use serde::{Deserialize, Serialize};

use crate::status::SyncStatus;

/// Shared RPC state publishers — whole-value `ArcSwap`s the runner and
/// shard threads store into and the HTTP handlers load lock-free. A
/// `None` slot means no RPC server is attached (tests, tooling).
#[derive(Clone, Default)]
pub struct RpcPublishers {
    /// `/status` per-vnode readouts.
    pub node_status: Option<Arc<ArcSwap<NodeStatusState>>>,
    /// `/sync` per-shard block-sync state.
    pub sync_status: Option<Arc<ArcSwap<SyncStatus>>>,
    /// Per-vnode mempool snapshots feeding RPC submission backpressure.
    pub mempool: Option<Arc<ArcSwap<MempoolSnapshot>>>,
}

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
    /// Process-wide transaction status cache for querying transaction
    /// state. Every shard thread writes through its monotonic merge;
    /// reads here on the RPC threads are lock-free. Shard membership
    /// changes don't touch it — a departed shard's entries age out by
    /// LRU.
    pub tx_status: Arc<TxStatusCache>,
    /// Mempool snapshot for querying mempool stats.
    pub mempool_snapshot: Arc<ArcSwap<MempoolSnapshot>>,
    /// Number of blocks behind before rejecting transaction submissions.
    ///
    /// When set and the node is this many blocks behind, new transaction
    /// submissions are rejected to allow the node to catch up.
    pub sync_backpressure_threshold: Option<u64>,
}

impl RpcState {
    /// Look up the latest merged status for `hash`.
    #[must_use]
    pub fn lookup_tx_status(&self, hash: &TxHash) -> Option<TransactionStatus> {
        self.tx_status.get(hash).map(|(status, _)| status)
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
/// output. `num_shards` is the network's current shard count, published from
/// the host's live [`TopologySnapshot`] each tick — it tracks the topology as
/// the network splits and merges, not a frozen genesis value. Multi-vnode
/// hosts surface every hosted vnode; single-vnode hosts produce a one-element
/// `vnodes` vec.
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
