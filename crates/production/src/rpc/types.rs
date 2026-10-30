//! Request and response types for the RPC API.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::state::VnodeStatusEntry;

// ═══════════════════════════════════════════════════════════════════════════
// Health & Readiness
// ═══════════════════════════════════════════════════════════════════════════

/// Response for `/health` endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Always `"ok"` when the server is running.
    pub(crate) status: String,
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
    pub(crate) status: String,
    /// True once the node has completed initial sync and can serve traffic.
    pub(crate) ready: bool,
}

// ═══════════════════════════════════════════════════════════════════════════
// Node Status
// ═══════════════════════════════════════════════════════════════════════════

/// Response for `/api/v1/status` endpoint.
///
/// Process-level fields sit at the top; one [`VnodeStatusEntry`] per
/// attached signer lives in `vnodes`, sorted by `validator_id` for stable
/// output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeStatusResponse {
    /// The network's current shard count, from the host's live topology.
    pub(crate) num_shards: u64,
    /// Number of connected peers.
    pub connected_peers: usize,
    /// Node uptime in seconds.
    pub(crate) uptime_secs: u64,
    /// Version string.
    pub(crate) version: String,
    /// Per-signer status entries.
    pub(crate) vnodes: Vec<VnodeStatusEntry>,
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
    pub(crate) transaction_hex: String,
}

/// Response for `POST /api/v1/transactions`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitTransactionResponse {
    /// Whether the transaction was accepted into the mempool.
    pub(crate) accepted: bool,
    /// Transaction hash (hex-encoded).
    pub hash: String,
    /// Error message if not accepted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
}

/// Response for `GET /api/v1/transactions/:hash`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionStatusResponse {
    /// Transaction hash (hex-encoded).
    pub hash: String,
    /// Current status of the transaction.
    /// Possible values: "pending", "committed", "executed", "completed", "aborted", "unknown", "error"
    pub(crate) status: String,
    /// Block height where committed (if committed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) committed_height: Option<u64>,
    /// Final decision (if executed): "accept", "reject", or "aborted".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) decision: Option<String>,
    /// Error message if status lookup failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
}

// ═══════════════════════════════════════════════════════════════════════════
// Error Response
// ═══════════════════════════════════════════════════════════════════════════

/// What a wallet asks before it signs.
#[derive(Debug, Deserialize)]
pub struct PreviewTransactionRequest {
    /// The candidate envelope, hex-encoded, exactly as it would be
    /// submitted.
    pub(crate) transaction_hex: String,
}

/// What the run would do, and what to sign so it can.
#[derive(Debug, Serialize)]
pub struct PreviewTransactionResponse {
    /// `completed`, `aborted` or `refused`.
    pub(crate) outcome: String,
    /// Why, when the outcome carries a reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) reason: Option<String>,
    /// What the payer would burn, as a decimal string: a `u128` does not
    /// survive a JSON number.
    pub(crate) fee: String,
    /// Fuel the run consumed, which the ceilings are the margin over.
    pub(crate) fuel: u64,
    /// The ceiling each node's run asks for, in node order — the vector
    /// a composer signs into `gas_limits`, and the reason to ask at all.
    pub(crate) ceilings: Vec<u64>,
    /// The committed height each answering shard read at, keyed by the
    /// shard's `Shard(dNpM)` spelling.
    ///
    /// What the ceilings above were measured against. A server picks its
    /// own height, so a report is a run over snapshots that were never
    /// simultaneous and may sit well behind the tip — and a ceiling
    /// measured over stale state is one a real run can trip, burning the
    /// fee on the trap. A composer that watches these can tell a fresh
    /// answer from an old one; without them it cannot.
    pub(crate) anchors: BTreeMap<String, u64>,
    /// The collection intervals the run read on another node's word that
    /// they leave nothing out.
    ///
    /// Each entry such an interval returned is proven, but not that the
    /// interval is whole: a server can omit entries and the run reads
    /// the gap as empty. A composer that will not rest a signature on a
    /// server's completeness asks another node for these, or does not
    /// sign. Empty when every read was proven.
    pub(crate) unproven_intervals: Vec<UnprovenIntervalJson>,
}

/// One declared interval whose answer is not proven whole.
#[derive(Debug, Serialize)]
pub struct UnprovenIntervalJson {
    /// The collection's owner, hex-encoded.
    pub(crate) owner: String,
    /// The collection, hex-encoded.
    pub(crate) collection: String,
    /// The first order, inclusive, as a decimal string: a `u128` does not
    /// survive a JSON number.
    pub(crate) lo: String,
    /// The last order, inclusive, as a decimal string.
    pub(crate) hi: String,
}

/// Generic error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// Short error category (e.g. `"invalid_request"`).
    pub(crate) error: String,
    /// Optional human-readable explanation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) details: Option<String>,
}
