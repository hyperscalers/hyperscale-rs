//! Types for RPC client communication.

use hyperscale_types::{BlockHeight, TransactionDecision, TransactionStatus};
use serde::{Deserialize, Serialize};

/// Request to submit a transaction.
#[derive(Debug, Serialize)]
pub struct SubmitTransactionRequest {
    /// Hex-encoded SBOR-serialized `RoutableTransaction`.
    pub transaction_hex: String,
}

/// Response from transaction submission.
#[derive(Debug, Deserialize)]
pub struct SubmitTransactionResponse {
    /// True if the node accepted the transaction into its mempool.
    pub accepted: bool,
    /// Hex-encoded transaction hash returned by the node.
    pub hash: String,
    /// Error message when `accepted == false`.
    pub error: Option<String>,
}

/// Result of a transaction submission.
#[derive(Debug)]
pub struct SubmissionResult {
    /// Whether the transaction was accepted.
    pub accepted: bool,
    /// The transaction hash.
    pub hash: String,
    /// Error message if rejected.
    pub error: Option<String>,
    /// HTTP status code.
    pub status_code: u16,
}

impl SubmissionResult {
    /// Check if the submission was successful.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.accepted && self.status_code >= 200 && self.status_code < 300
    }
}

/// Response from node status endpoint.
#[allow(missing_docs)] // flat status readouts; field names are the documentation
#[derive(Debug, Deserialize)]
pub struct NodeStatusResponse {
    pub validator_id: u32,
    pub shard: u64,
    #[serde(default)]
    pub num_shards: u64,
    #[serde(default)]
    pub block_height: u64,
    #[serde(default)]
    pub view: u64,
    #[serde(default)]
    pub connected_peers: usize,
    #[serde(default)]
    pub uptime_secs: u64,
    #[serde(default)]
    pub version: String,
}

/// Simplified node status.
#[allow(missing_docs)] // flat status readouts; field names are the documentation
#[derive(Debug)]
pub struct NodeStatus {
    pub validator_id: u32,
    pub shard: u64,
    pub block_height: u64,
    pub connected_peers: usize,
}

/// Response from transaction status endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct TransactionStatusResponse {
    /// Transaction hash (hex-encoded).
    pub hash: String,
    /// Current status of the transaction.
    /// Possible values: "pending", "committed", "executed", "completed", "aborted", "unknown", "error"
    pub status: String,
    /// Block height where committed (if committed).
    #[serde(default)]
    pub committed_height: Option<u64>,
    /// Final decision (if executed): "accept" or "reject".
    #[serde(default)]
    pub decision: Option<String>,
    /// Error message if status lookup failed.
    #[serde(default)]
    pub error: Option<String>,
}

impl TransactionStatusResponse {
    /// Convert to a typed `TransactionStatus` if possible.
    ///
    /// Returns None for unknown statuses or parse errors.
    #[must_use]
    pub fn to_status(&self) -> Option<TransactionStatus> {
        let decision = || -> Option<TransactionDecision> {
            match self.decision.as_deref()? {
                "accept" => Some(TransactionDecision::Accept),
                "reject" => Some(TransactionDecision::Reject),
                _ => None,
            }
        };

        match self.status.as_str() {
            "pending" => Some(TransactionStatus::Pending),
            "committed" => Some(TransactionStatus::Committed(BlockHeight(
                self.committed_height.unwrap_or(0),
            ))),
            "completed" => Some(TransactionStatus::Completed(decision()?)),
            _ => None,
        }
    }

    /// Check if the transaction has reached a terminal state.
    ///
    /// Uses the typed `TransactionStatus.is_final()` when possible,
    /// falls back to string matching for unknown statuses.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        // Fallback for unknown statuses like "error".
        self.to_status()
            .map_or_else(|| self.status == "error", |s| s.is_final())
    }

    /// Check if the transaction completed successfully.
    ///
    /// A transaction is successful when it reaches `completed` status with
    /// an `accept` decision.
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(
            self.to_status(),
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        )
    }
}
