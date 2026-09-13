//! Request and response types for the RPC API.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

pub use super::state::VnodeStatusEntry;

// ═══════════════════════════════════════════════════════════════════════════
// Health & Readiness
// ═══════════════════════════════════════════════════════════════════════════

/// Response for `/health` endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Always `"ok"` when the server is running.
    pub status: String,
}

impl Default for HealthResponse {
    fn default() -> Self {
        Self {
            status: "ok".to_string(),
        }
    }
}

/// Response for `/ready` endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadyResponse {
    /// `"ready"` when the node has finished startup, otherwise `"not_ready"`.
    pub status: String,
    /// True once the node has completed initial sync and can serve traffic.
    pub ready: bool,
}

// ═══════════════════════════════════════════════════════════════════════════
// Node Status
// ═══════════════════════════════════════════════════════════════════════════

/// Response for `/api/v1/status` endpoint.
///
/// Process-level fields sit at the top; one [`VnodeStatusEntry`] per hosted
/// vnode lives in `vnodes`, sorted by `validator_id` for stable output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeStatusResponse {
    /// The network's current shard count, from the host's live topology.
    pub num_shards: u64,
    /// Number of connected peers.
    pub connected_peers: usize,
    /// Node uptime in seconds.
    pub uptime_secs: u64,
    /// Version string.
    pub version: String,
    /// Per-hosted-vnode status entries.
    pub vnodes: Vec<VnodeStatusEntry>,
}

/// Response for `/api/v1/sync` endpoint.
///
/// Each hosted shard runs its own block-sync FSM, so the response is
/// keyed by shard id. `sync_peers` is process-level (one libp2p
/// adapter across hosted shards) and lives at the top level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStatusResponse {
    /// Per-hosted-shard sync status, keyed by shard id.
    pub shards: HashMap<u64, ShardSyncStatus>,
    /// Number of connected peers capable of sync.
    pub sync_peers: usize,
}

/// One hosted shard's view of its block-sync FSM, embedded in
/// [`SyncStatusResponse::shards`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardSyncStatus {
    /// Current sync state.
    pub state: String,
    /// Current block height.
    pub current_height: u64,
    /// Target height (if syncing).
    pub target_height: Option<u64>,
    /// Number of blocks behind.
    pub blocks_behind: u64,
    /// Number of pending block fetches.
    pub pending_fetches: usize,
    /// Number of heights queued for fetch.
    pub queued_heights: usize,
}

// ═══════════════════════════════════════════════════════════════════════════
// Transactions
// ═══════════════════════════════════════════════════════════════════════════

/// Request body for `POST /api/v1/transactions`.
///
/// Accepts a transaction in hex-encoded HBOR format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitTransactionRequest {
    /// Hex-encoded HBOR-serialized `Transaction`.
    pub transaction_hex: String,
}

/// Response for `POST /api/v1/transactions`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitTransactionResponse {
    /// Whether the transaction was accepted into the mempool.
    pub accepted: bool,
    /// Transaction hash (hex-encoded).
    pub hash: String,
    /// Error message if not accepted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Response for `GET /api/v1/transactions/:hash`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionStatusResponse {
    /// Transaction hash (hex-encoded).
    pub hash: String,
    /// Current status of the transaction.
    /// Possible values: "pending", "committed", "executed", "completed", "aborted", "unknown", "error"
    pub status: String,
    /// Block height where committed (if committed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub committed_height: Option<u64>,
    /// Final decision (if executed): "accept", "reject", or "aborted".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    /// Error message if status lookup failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ═══════════════════════════════════════════════════════════════════════════
// Error Response
// ═══════════════════════════════════════════════════════════════════════════

/// What a wallet asks before it signs.
#[derive(Debug, Deserialize)]
pub struct PreviewTransactionRequest {
    /// The candidate envelope, hex-encoded, exactly as it would be
    /// submitted.
    pub transaction_hex: String,
}

/// What the run would do, and what to sign so it can.
#[derive(Debug, Serialize)]
pub struct PreviewTransactionResponse {
    /// `completed`, `aborted` or `refused`.
    pub outcome: String,
    /// Why, when the outcome carries a reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// What the payer would burn, as a decimal string: a `u128` does not
    /// survive a JSON number.
    pub fee: String,
    /// Fuel the run consumed, which the ceilings are the margin over.
    pub fuel: u64,
    /// The ceiling each node's run asks for, in node order — the vector
    /// a composer signs into `gas_limits`, and the reason to ask at all.
    pub ceilings: Vec<u64>,
}

/// Generic error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// Short error category (e.g. `"invalid_request"`).
    pub error: String,
    /// Optional human-readable explanation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

impl ErrorResponse {
    /// Build an error response with no extra details.
    pub fn new(error: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            details: None,
        }
    }

    /// Build an error response with both a category and a detailed message.
    pub fn with_details(error: impl Into<String>, details: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            details: Some(details.into()),
        }
    }
}
