//! Types for RPC client communication.

use hyperscale_types::{AbortReason, BlockHeight, Hash, TransactionDecision, TransactionStatus};
use serde::{Deserialize, Serialize};

/// Request to submit a transaction.
#[derive(Debug, Serialize)]
pub struct SubmitTransactionRequest {
    pub transaction_hex: String,
}

/// Response from transaction submission.
#[derive(Debug, Deserialize)]
pub struct SubmitTransactionResponse {
    pub accepted: bool,
    pub hash: String,
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
    pub fn is_success(&self) -> bool {
        self.accepted && self.status_code >= 200 && self.status_code < 300
    }
}

/// Response from node status endpoint.
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
    /// Possible values: "pending", "committed", "executed", "completed", "blocked", "retried", "unknown", "error"
    pub status: String,
    /// Block height where committed (if committed).
    #[serde(default)]
    pub committed_height: Option<u64>,
    /// Final decision (if executed): "accept" or "reject".
    #[serde(default)]
    pub decision: Option<String>,
    /// Hash of the transaction blocking this one (if blocked).
    #[serde(default)]
    pub blocked_by: Option<String>,
    /// Hash of the retry transaction (if retried).
    #[serde(default)]
    pub retry_tx: Option<String>,
    /// Error message if status lookup failed.
    #[serde(default)]
    pub error: Option<String>,
}

impl TransactionStatusResponse {
    /// Convert to a typed TransactionStatus if possible.
    ///
    /// Returns None for unknown statuses or parse errors.
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
            "executed" => Some(TransactionStatus::Executed(decision()?)),
            "completed" => Some(TransactionStatus::Completed(decision()?)),
            "blocked" => {
                let hash = Hash::from_hex(self.blocked_by.as_deref()?).ok()?;
                Some(TransactionStatus::Blocked { by: hash })
            }
            "retried" => {
                let hash = Hash::from_hex(self.retry_tx.as_deref()?).ok()?;
                Some(TransactionStatus::Retried { new_tx: hash })
            }
            "aborted" => {
                // For aborted, we store the reason in error field as a string
                // Parse it back if possible, otherwise use a generic rejected reason
                let reason = self
                    .error
                    .as_deref()
                    .and_then(|s| s.parse::<AbortReason>().ok())
                    .unwrap_or(AbortReason::ExecutionRejected {
                        reason: self.error.clone().unwrap_or_default(),
                    });
                Some(TransactionStatus::Aborted { reason })
            }
            _ => None,
        }
    }

    /// Check if the transaction has reached a terminal state.
    ///
    /// Uses the typed TransactionStatus.is_final() when possible,
    /// falls back to string matching for unknown statuses.
    pub fn is_terminal(&self) -> bool {
        if let Some(status) = self.to_status() {
            status.is_final()
        } else {
            // Fallback for unknown statuses like "error"
            self.status == "error"
        }
    }

    /// Check if the transaction completed successfully.
    ///
    /// A transaction is successful when it reaches `completed` status with
    /// an `accept` decision.
    pub fn is_success(&self) -> bool {
        matches!(
            self.to_status(),
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        )
    }
}
