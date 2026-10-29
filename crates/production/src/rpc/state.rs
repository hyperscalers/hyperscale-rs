//! Shared state types for RPC handlers.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use arc_swap::ArcSwap;
use hyperscale_engine::PreviewReport;
use hyperscale_types::{ShardId, Transaction, TxsInFlight};
use serde::{Deserialize, Serialize};

use crate::handle::NodeHandle;
use crate::observe::{HeaderRing, Importing, Observations};
use crate::status::SyncStatus;

/// The host's published state: whole-value `ArcSwap`s the runner and shard
/// threads store into and readers load lock-free, and the beacon thread's
/// observations.
#[derive(Clone, Default)]
pub struct RpcPublishers {
    /// `/status` per-signer readouts.
    pub node_status: Arc<ArcSwap<NodeStatusState>>,
    /// `/sync` per-shard block-sync state.
    pub sync_status: Arc<ArcSwap<SyncStatus>>,
    /// Per-signer mempool snapshots feeding RPC submission backpressure.
    pub mempool: Arc<ArcSwap<MempoolSnapshot>>,
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
/// time. Blocking on a crossbeam reply, so callers run it on a blocking
/// worker rather than on a tokio worker.
pub type PreviewSender =
    Arc<dyn Fn(&Transaction) -> Option<Box<PreviewReport>> + Send + Sync + 'static>;

/// Shared state for RPC handlers: the host, read through its handle, and
/// the server's own readiness and start time.
#[derive(Clone)]
pub struct RpcState {
    /// Ready flag for readiness probe.
    pub ready: Arc<AtomicBool>,
    /// The host the server answers for.
    pub node: NodeHandle,
    /// Server start time for uptime calculation.
    pub start_time: Instant,
    /// Number of blocks behind before rejecting transaction submissions.
    ///
    /// When set and the node is this many blocks behind, new transaction
    /// submissions are rejected to allow the node to catch up.
    pub sync_backpressure_threshold: Option<u64>,
}

/// Snapshot of mempool state for RPC queries.
///
/// One [`VnodeMempoolSnapshot`] per attached signer, keyed by validator
/// id. Signers on one shard read that shard replica's
/// [`hyperscale_mempool::MempoolCoordinator`], so their entries repeat
/// its limits. Used only by RPC submission backpressure — the counts
/// shown to clients live in [`NodeStatusState::vnodes`].
#[derive(Debug, Clone, Default)]
pub struct MempoolSnapshot {
    /// Per-signer mempool readouts, keyed by validator id.
    pub vnodes: BTreeMap<u64, VnodeMempoolSnapshot>,
}

/// One attached signer's mempool readout: whether its shard replica takes
/// more submissions.
#[derive(Debug, Clone)]
pub struct VnodeMempoolSnapshot {
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
