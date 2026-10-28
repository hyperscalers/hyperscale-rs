//! Types for RPC client communication.

use hyperscale_types::{BlockHeight, TransactionDecision, TransactionStatus};
use serde::{Deserialize, Serialize};

/// Request to submit a transaction.
#[derive(Debug, Serialize)]
pub struct SubmitTransactionRequest {
    /// Hex-encoded HBOR-serialized `Transaction`.
    pub(crate) transaction_hex: String,
}

/// Response from transaction submission.
#[derive(Debug, Deserialize)]
pub struct SubmitTransactionResponse {
    /// True if the node accepted the transaction into its mempool.
    pub(crate) accepted: bool,
    /// Hex-encoded transaction hash returned by the node.
    pub hash: String,
    /// Error message when `accepted == false`.
    pub(crate) error: Option<String>,
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

/// Response from node status endpoint. Process-level fields plus a list of
/// per-hosted-vnode entries.
#[allow(missing_docs)] // flat status readouts; field names are the documentation
#[derive(Debug, Deserialize)]
pub struct NodeStatusResponse {
    #[serde(default)]
    pub num_shards: u64,
    #[serde(default)]
    pub connected_peers: usize,
    #[serde(default)]
    pub uptime_secs: u64,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub(crate) vnodes: Vec<VnodeStatusEntry>,
}

/// Per-vnode status entry inside [`NodeStatusResponse::vnodes`].
#[allow(missing_docs)] // flat status readouts; field names are the documentation
#[derive(Debug, Deserialize)]
pub struct VnodeStatusEntry {
    pub validator_id: u32,
    pub shard: u64,
    #[serde(default)]
    pub(crate) block_height: u64,
    #[serde(default)]
    pub view: u64,
}

/// Simplified node status — process summary collapsed over every hosted vnode.
///
/// `min_block_height` is the slowest hosted vnode's committed height — the
/// relevant signal for "have all of this host's vnodes made progress?".
#[allow(missing_docs)] // flat status readouts; field names are the documentation
#[derive(Debug)]
pub struct NodeStatus {
    pub connected_peers: usize,
    pub vnode_count: usize,
    pub min_block_height: u64,
}

/// Response from transaction status endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct TransactionStatusResponse {
    /// Transaction hash (hex-encoded).
    pub hash: String,
    /// Current status of the transaction. Possible values: `pending`,
    /// `committed`, `leg_finalized`, `completed`, plus `unknown` when the
    /// server holds no record and `error` when the lookup itself failed.
    pub status: String,
    /// Block height where committed (if committed).
    #[serde(default)]
    pub(crate) committed_height: Option<u64>,
    /// Final decision (when completed): `accept`, `reject` or `aborted`.
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
    pub(crate) fn to_status(&self) -> Option<TransactionStatus> {
        let decision = || -> Option<TransactionDecision> {
            match self.decision.as_deref()? {
                "accept" => Some(TransactionDecision::Accept),
                "reject" => Some(TransactionDecision::Reject),
                "aborted" => Some(TransactionDecision::Aborted),
                _ => None,
            }
        };

        match self.status.as_str() {
            "pending" => Some(TransactionStatus::Pending),
            "committed" => Some(TransactionStatus::Committed(BlockHeight::new(
                self.committed_height.unwrap_or(0),
            ))),
            "leg_finalized" => Some(TransactionStatus::LegFinalized),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn completed(decision: &str) -> TransactionStatusResponse {
        TransactionStatusResponse {
            hash: String::new(),
            status: "completed".to_string(),
            committed_height: None,
            decision: Some(decision.to_string()),
            error: None,
        }
    }

    #[test]
    fn every_decision_the_server_emits_decodes_and_terminates() {
        for decision in ["accept", "reject", "aborted"] {
            let response = completed(decision);
            assert!(
                response.to_status().is_some(),
                "decision {decision} failed to decode"
            );
            assert!(
                response.is_terminal(),
                "decision {decision} never terminates"
            );
        }
        assert!(completed("accept").is_success());
        assert!(!completed("reject").is_success());
        assert!(!completed("aborted").is_success());
    }
}
