//! Shared state types for RPC handlers.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use arc_swap::ArcSwap;
use hyperscale_engine::PreviewReport;
use hyperscale_node::TxStatusCache;
use hyperscale_types::{ShardId, Transaction, TransactionStatus, TxHash, TxsInFlight};
use serde::{Deserialize, Serialize};

use crate::observe::{HeaderRing, Importing, Observations};
use crate::status::SyncStatus;

/// Shared RPC state publishers — whole-value `ArcSwap`s the runner and
/// shard threads store into and the HTTP handlers load lock-free. A
/// `None` slot means no RPC server is attached (tests, tooling).
#[derive(Clone, Default)]
pub struct RpcPublishers {
    /// `/status` per-signer readouts.
    pub node_status: Option<Arc<ArcSwap<NodeStatusState>>>,
    /// `/sync` per-shard block-sync state.
    pub sync_status: Option<Arc<ArcSwap<SyncStatus>>>,
    /// Per-signer mempool snapshots feeding RPC submission backpressure.
    pub mempool: Option<Arc<ArcSwap<MempoolSnapshot>>>,
    /// The last hour of certified headers per shard, kept by the beacon
    /// thread.
    pub headers: Arc<HeaderRing>,
    /// What the beacon thread has seen, published after each step that
    /// changed it.
    pub observations: Observations,
    /// Bytes staged by each snap-sync import in progress.
    pub importing: Arc<Importing>,
}

/// Submit a locally-issued transaction to the runner.
///
/// Returns `true` if the runner accepted the tx; `false` only when the
/// runner is shutting down (every per-shard channel send failed). The
/// closure is shared (`Fn`) and called concurrently from tokio worker
/// threads — internally it computes the touched-shard fanout from a
/// lock-free topology snapshot and pushes admit/admit-and-gossip
/// envelopes onto the relevant per-shard event channels.
pub type TxSubmissionSender = Arc<dyn Fn(Arc<Transaction>) -> bool + Send + Sync + 'static>;

/// Ask the runner what a transaction would do, without submitting it.
///
/// `None` when no hosted shard could answer or the driver did not answer in
/// time. Blocking on a crossbeam reply, so handlers call it inside
/// `spawn_blocking` rather than on a tokio worker.
pub type PreviewSender =
    Arc<dyn Fn(&Transaction) -> Option<Box<PreviewReport>> + Send + Sync + 'static>;

/// Shared state for RPC handlers.
#[derive(Clone)]
pub struct RpcState {
    /// Ready flag for readiness probe.
    pub ready: Arc<AtomicBool>,
    /// Sync status provider.
    pub sync_status: Arc<ArcSwap<SyncStatus>>,
    /// Node status provider.
    pub node_status: Arc<ArcSwap<NodeStatusState>>,
    /// Ask a hosted shard what a transaction would do. Reads committed
    /// state and commits nothing, so it neither admits the transaction
    /// nor gossips it.
    pub preview_tx: PreviewSender,
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
    /// Look up the latest merged status for `hash`: a hosted shard's own
    /// leg of it (see [`TxStatusCache`]).
    #[must_use]
    pub fn lookup_tx_status(&self, hash: &TxHash) -> Option<TransactionStatus> {
        self.tx_status.get(hash).map(|(status, _)| status)
    }
}

/// Snapshot of mempool state for RPC queries.
///
/// One [`VnodeMempoolSnapshot`] per attached signer, keyed by validator
/// id. Signers on one shard read that shard replica's
/// [`hyperscale_mempool::MempoolCoordinator`], so their entries repeat
/// its counts. Used only by RPC submission backpressure — the counts
/// shown to clients live in [`NodeStatusState::vnodes`].
#[derive(Debug, Clone, Default)]
pub struct MempoolSnapshot {
    /// Per-signer mempool readouts, keyed by validator id.
    pub vnodes: BTreeMap<u64, VnodeMempoolSnapshot>,
}

/// One attached signer's mempool readout: its shard replica's counts.
#[derive(Debug, Clone)]
pub struct VnodeMempoolSnapshot {
    /// Number of pending transactions (waiting to be included in a block).
    pub pending_count: usize,
    /// Number of transactions holding state locks (Committed status).
    pub in_flight_count: u64,
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
    /// Per-remote-shard transactions in flight, from the latest verified
    /// block headers. Used for cross-shard backpressure: reject
    /// transactions targeting congested shards.
    pub remote_shard_in_flight: BTreeMap<ShardId, TxsInFlight>,
    /// Threshold for rejecting transactions due to remote shard congestion
    /// (80% of [`hyperscale_types::MAX_UNSETTLED_TXS`]).
    pub remote_congestion_threshold: TxsInFlight,
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
            remote_shard_in_flight: BTreeMap::new(),
            remote_congestion_threshold: TxsInFlight::ZERO,
        }
    }
}

/// Mutable node status state updated by the runner.
///
/// Process-level fields (`num_shards`, `connected_peers`) sit at the top;
/// per-signer readouts live in `vnodes`, sorted by `validator_id` for stable
/// output. `num_shards` is the network's current shard count, published from
/// the host's live [`TopologySnapshot`] each tick — it tracks the topology as
/// the network splits and merges, not a frozen genesis value. A host
/// surfaces every attached signer; a single-validator host produces a
/// one-element `vnodes` vec.
///
/// [`TopologySnapshot`]: hyperscale_types::TopologySnapshot
#[allow(missing_docs)] // flat readouts; field names are the documentation
#[derive(Debug, Clone, Default)]
pub struct NodeStatusState {
    pub num_shards: u64,
    pub connected_peers: usize,
    pub vnodes: Vec<VnodeStatusEntry>,
}

/// Per-signer status entry. Mirrors the wire shape exposed under
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

/// Per-signer mempool counts, embedded in each [`VnodeStatusEntry`].
#[allow(missing_docs)] // flat readouts; field names are the documentation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VnodeMempoolStats {
    pub pending_count: usize,
    pub in_flight_count: u64,
    pub total_count: usize,
}
