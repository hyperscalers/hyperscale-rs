//! Request and response types for the RPC API.

use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════════════════════════════
// Health & Readiness
// ═══════════════════════════════════════════════════════════════════════════

/// Response for `/health` endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
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
    pub status: String,
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
    /// Current JMT state version (increments with each committed certificate).
    pub state_version: u64,
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
    /// Hex-encoded SBOR-serialized RoutableTransaction.
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
    /// Possible values: "pending", "committed", "executed", "completed", "deferred", "retried", "unknown", "error"
    pub status: String,
    /// Block height where committed (if committed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub committed_height: Option<u64>,
    /// Final decision (if executed): "accept" or "reject".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    /// Hash of the transaction deferreding this one (if deferred).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deferred_by: Option<String>,
    /// Hash of the retry transaction (if retried).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_tx: Option<String>,
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
    /// Number of transactions deferred waiting for a winner to complete.
    pub deferred_count: usize,
}

// ═══════════════════════════════════════════════════════════════════════════
// Error Response
// ═══════════════════════════════════════════════════════════════════════════

/// Generic error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

impl ErrorResponse {
    pub fn new(error: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            details: None,
        }
    }

    pub fn with_details(error: impl Into<String>, details: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            details: Some(details.into()),
        }
    }
}
