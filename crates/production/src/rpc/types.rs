//! Request and response types for the RPC API.

use serde::{Deserialize, Serialize};

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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeStatusResponse {
    /// Validator ID of this node.
    pub validator_id: u64,
    /// Shard group this node belongs to.
    pub shard: u64,
    /// Total number of shards in the network.
    pub num_shards: u64,
    /// Current block height.
    pub block_height: u64,
    /// Current view number.
    pub view: u64,
    /// Number of connected peers.
    pub connected_peers: usize,
    /// Node uptime in seconds.
    pub uptime_secs: u64,
    /// Version string.
    pub version: String,
    /// Current JMT state root hash (hex-encoded).
    pub state_root_hash: String,
    /// Mempool statistics.
    pub mempool: MempoolStatusResponse,
}

/// Response for `/api/v1/sync` endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStatusResponse {
    /// Current sync state.
    pub state: String,
    /// Current block height.
    pub current_height: u64,
    /// Target height (if syncing).
    pub target_height: Option<u64>,
    /// Number of blocks behind.
    pub blocks_behind: u64,
    /// Number of sync peers.
    pub sync_peers: usize,
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
/// Accepts a transaction in hex-encoded SBOR format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitTransactionRequest {
    /// Hex-encoded SBOR-serialized `RoutableTransaction`.
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
// Mempool
// ═══════════════════════════════════════════════════════════════════════════

/// Response for `GET /api/v1/mempool`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolStatusResponse {
    /// Number of pending transactions (waiting to be included in a block).
    pub pending_count: usize,
    /// Number of transactions in Committed status (block committed, being executed).
    pub committed_count: usize,
    /// Number of transactions in Executed status (execution done, awaiting certificate).
    pub executed_count: usize,
    /// Total transactions in mempool.
    pub total_count: usize,
}

// ═══════════════════════════════════════════════════════════════════════════
// Error Response
// ═══════════════════════════════════════════════════════════════════════════

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
