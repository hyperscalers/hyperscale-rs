//! HTTP request handlers for the validator RPC API.
//!
//! Endpoints split into three categories:
//! - **Liveness/readiness**: `/health`, `/ready` — used by orchestrators
//!   to decide whether to route traffic.
//! - **Status**: `/status`, `/sync`, `/metrics` — read-only snapshots
//!   maintained by the running node, exposed via `ArcSwap` handles so
//!   handlers never block on the consensus thread. Per-vnode mempool
//!   counts ride on `/status.vnodes[].mempool` — there's no separate
//!   `/mempool` endpoint because mempools are per-vnode, not per-host.
//! - **Submission**: `POST /transactions`, `GET /transactions/:hash` —
//!   transaction ingress and lookup.
//!
//! # Ingress backpressure
//!
//! The submission handler rejects with HTTP 503 when any hosted shard
//! is syncing (it cannot validly admit new transactions) or when any
//! hosted vnode's mempool has signalled an in-flight or pending limit
//! breach. Each rejection reason emits a Prometheus counter so
//! operators can distinguish capacity from sync-state stalls.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::http::header::CONTENT_TYPE;
use axum::response::IntoResponse;
use hex::{decode as hex_decode, encode as hex_encode};
use hyperscale_metrics::{
    record_transaction_rejected, record_tx_ingress_rejected_pending_limit,
    record_tx_ingress_rejected_syncing,
};
use hyperscale_metrics_prometheus::encode_metrics;
use hyperscale_types::{
    Hash, InFlightCount, RoutableTransaction, TransactionDecision, TransactionStatus, TxHash,
};
use sbor::prelude::basic_decode;

use super::state::RpcState;
use super::types::{
    HealthResponse, NodeStatusResponse, ReadyResponse, ShardSyncStatus, SubmitTransactionRequest,
    SubmitTransactionResponse, SyncStatusResponse, TransactionStatusResponse,
};

// ═══════════════════════════════════════════════════════════════════════════
// Health & Readiness Handlers
// ═══════════════════════════════════════════════════════════════════════════

/// Handler for `GET /health` - liveness probe.
pub async fn health_handler() -> impl IntoResponse {
    Json(HealthResponse::default())
}

/// Handler for `GET /ready` - readiness probe.
pub async fn ready_handler(State(state): State<RpcState>) -> impl IntoResponse {
    if state.ready.load(Ordering::SeqCst) {
        (
            StatusCode::OK,
            Json(ReadyResponse {
                status: "ready".to_string(),
                ready: true,
            }),
        )
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ReadyResponse {
                status: "not_ready".to_string(),
                ready: false,
            }),
        )
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Metrics Handler
// ═══════════════════════════════════════════════════════════════════════════

/// Handler for `GET /metrics` - Prometheus metrics.
pub async fn metrics_handler() -> impl IntoResponse {
    match encode_metrics() {
        Ok((content_type, buffer)) => ([(CONTENT_TYPE, content_type)], buffer).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to encode metrics");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to encode metrics".to_string(),
            )
                .into_response()
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Status Handlers
// ═══════════════════════════════════════════════════════════════════════════

/// Handler for `GET /api/v1/status` - node status.
pub async fn status_handler(State(state): State<RpcState>) -> impl IntoResponse {
    let node_status = state.node_status.load();
    let uptime = state.start_time.elapsed().as_secs();

    Json(NodeStatusResponse {
        num_shards: node_status.num_shards,
        connected_peers: node_status.connected_peers,
        uptime_secs: uptime,
        version: option_env!("HYPERSCALE_VERSION")
            .unwrap_or("localdev")
            .to_string(),
        vnodes: node_status.vnodes.clone(),
    })
}

/// Handler for `GET /api/v1/sync` - sync status.
pub async fn sync_handler(State(state): State<RpcState>) -> impl IntoResponse {
    let sync_status = state.sync_status.load();

    let shards = sync_status
        .shards
        .iter()
        .map(|(shard, s)| {
            (
                *shard,
                ShardSyncStatus {
                    state: format!("{:?}", s.state).to_lowercase(),
                    current_height: s.current_height,
                    target_height: s.target_height,
                    blocks_behind: s.blocks_behind,
                    pending_fetches: s.pending_fetches,
                    queued_heights: s.queued_heights,
                },
            )
        })
        .collect();

    Json(SyncStatusResponse {
        shards,
        sync_peers: sync_status.sync_peers,
    })
}

// ═══════════════════════════════════════════════════════════════════════════
// Transaction Handlers
// ═══════════════════════════════════════════════════════════════════════════

/// Handler for `POST /api/v1/transactions` - submit transaction.
///
/// Performs quick structural validation (hex decode, SBOR decode) and submits
/// to the runner for validation and gossip.
///
/// Returns 202 Accepted immediately with transaction hash. Clients should poll
/// `GET /api/v1/transactions/{hash}` to check the result.
///
/// This matches Ethereum behavior where `eth_sendRawTransaction` returns the
/// transaction hash immediately, and invalid transactions simply never get mined.
///
/// Returns 503 Service Unavailable if the mempool is full (backpressure) or
/// if the node is syncing and too far behind.
pub async fn submit_transaction_handler(
    State(state): State<RpcState>,
    Json(request): Json<SubmitTransactionRequest>,
) -> impl IntoResponse {
    if let Some(rejection) = check_backpressure(&state) {
        return rejection;
    }

    let transaction = match decode_transaction(&request.transaction_hex) {
        Ok(tx) => tx,
        Err(rejection) => return rejection,
    };

    let hash = hex_encode(transaction.hash().as_bytes());
    let tx_arc = Arc::new(transaction);

    // Compute the touched-shard fanout on this tokio worker and push
    // admit envelopes directly onto each touched shard's event channel.
    // The closure captures `Arc<ProcessIo>` (for the lock-free topology
    // read) plus the per-shard senders.
    if !(state.tx_submission_tx)(tx_arc) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(SubmitTransactionResponse {
                accepted: false,
                hash,
                error: Some("Node is shutting down".to_string()),
            }),
        );
    }

    // Return immediately - validation and gossip happen async
    // Client should poll GET /api/v1/transactions/{hash} to check result
    (
        StatusCode::ACCEPTED,
        Json(SubmitTransactionResponse {
            accepted: true,
            hash,
            error: None,
        }),
    )
}

/// Handler for `GET /api/v1/transactions/:hash` - get transaction status.
pub async fn get_transaction_handler(
    State(state): State<RpcState>,
    Path(hash_hex): Path<String>,
) -> impl IntoResponse {
    // Parse the hash from hex (expects the raw hash bytes, not data to hash)
    let tx_hash = match Hash::from_hex(&hash_hex) {
        Ok(hash) => TxHash::from_raw(hash),
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(TransactionStatusResponse {
                    hash: hash_hex,
                    status: "error".to_string(),
                    committed_height: None,
                    decision: None,
                    error: Some("Invalid transaction hash: must be 64 hex characters".to_string()),
                }),
            );
        }
    };

    // Look up in caches (QuickCache is lock-free, no await needed).
    // Probe every hosted shard's cache — a tx can live in any of them.
    match state.lookup_tx_status(&tx_hash) {
        Some(status) => {
            let (status_str, committed_height, decision, error) =
                format_transaction_status(&status);

            (
                StatusCode::OK,
                Json(TransactionStatusResponse {
                    hash: hash_hex,
                    status: status_str,
                    committed_height,
                    decision,
                    error,
                }),
            )
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(TransactionStatusResponse {
                hash: hash_hex,
                status: "unknown".to_string(),
                committed_height: None,
                decision: None,
                error: Some("Transaction not found in cache".to_string()),
            }),
        ),
    }
}

/// Reject the request if any sync or mempool backpressure condition is
/// active on any hosted shard. A locally-submitted transaction fans
/// out to every touched shard, so the safe envelope is "if any hosted
/// shard would refuse, refuse the whole request."
fn check_backpressure(state: &RpcState) -> Option<(StatusCode, Json<SubmitTransactionResponse>)> {
    if let Some(threshold) = state.sync_backpressure_threshold {
        let sync_status = state.sync_status.load();
        if let Some(behind) = sync_status.shards.values().map(|s| s.blocks_behind).max()
            && behind > threshold
        {
            record_tx_ingress_rejected_syncing();
            return Some((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(SubmitTransactionResponse {
                    accepted: false,
                    hash: String::new(),
                    error: Some(format!(
                        "Node is syncing ({behind} blocks behind). Try again later.",
                    )),
                }),
            ));
        }
    }

    let snapshot = state.mempool_snapshot.load();

    if snapshot
        .vnodes
        .values()
        .any(|v| !v.accepting_rpc_transactions)
    {
        record_transaction_rejected("in_flight_limit");
        return Some((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(SubmitTransactionResponse {
                accepted: false,
                hash: String::new(),
                error: Some("Cross-shard transaction limit reached. Try again later.".to_string()),
            }),
        ));
    }

    if snapshot.vnodes.values().any(|v| v.at_pending_limit) {
        record_tx_ingress_rejected_pending_limit();
        return Some((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(SubmitTransactionResponse {
                accepted: false,
                hash: String::new(),
                error: Some("Too many pending transactions. Try again later.".to_string()),
            }),
        ));
    }

    // Threshold is 80% of `MAX_TX_IN_FLIGHT` (block/limits.rs). Each
    // hosted vnode tracks its own remote-shard in-flight counts via
    // verified block headers; reject if any of them flags a congested
    // remote shard.
    for v in snapshot.vnodes.values() {
        let threshold = v.remote_congestion_threshold;
        if threshold <= InFlightCount::ZERO {
            continue;
        }
        if let Some((&congested_shard, &count)) = v
            .remote_shard_in_flight
            .iter()
            .find(|&(_, &count)| count >= threshold)
        {
            record_transaction_rejected("remote_shard_congestion");
            return Some((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(SubmitTransactionResponse {
                    accepted: false,
                    hash: String::new(),
                    error: Some(format!(
                        "Remote shard {} is congested ({} in-flight). Try again later.",
                        congested_shard.inner(),
                        count.inner(),
                    )),
                }),
            ));
        }
    }

    None
}

/// Hex- and SBOR-decode a submitted transaction, recording metrics on failure.
fn decode_transaction(
    transaction_hex: &str,
) -> Result<RoutableTransaction, (StatusCode, Json<SubmitTransactionResponse>)> {
    let tx_bytes = hex_decode(transaction_hex).map_err(|e| {
        record_transaction_rejected("invalid_hex");
        (
            StatusCode::BAD_REQUEST,
            Json(SubmitTransactionResponse {
                accepted: false,
                hash: String::new(),
                error: Some(format!("Invalid hex encoding: {e}")),
            }),
        )
    })?;

    basic_decode(&tx_bytes).map_err(|e| {
        record_transaction_rejected("invalid_format");
        (
            StatusCode::BAD_REQUEST,
            Json(SubmitTransactionResponse {
                accepted: false,
                hash: String::new(),
                error: Some(format!("Invalid transaction format: {e:?}")),
            }),
        )
    })
}

/// Format a `TransactionStatus` into RPC response fields.
/// Formatted status fields: (status, `committed_height`, decision, error).
fn format_transaction_status(
    status: &TransactionStatus,
) -> (String, Option<u64>, Option<String>, Option<String>) {
    match status {
        TransactionStatus::Pending => ("pending".to_string(), None, None, None),
        TransactionStatus::Committed(height) => {
            ("committed".to_string(), Some(height.inner()), None, None)
        }
        TransactionStatus::Completed(decision) => {
            let decision_str = match decision {
                TransactionDecision::Accept => "accept",
                TransactionDecision::Reject => "reject",
                TransactionDecision::Aborted => "aborted",
            };
            (
                "completed".to_string(),
                None,
                Some(decision_str.to_string()),
                None,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::time::Instant;

    use arc_swap::ArcSwap;
    use axum::Router;
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use axum::routing::{get, post};
    use hyperscale_node::BlockSyncStateKind;
    use hyperscale_types::test_utils::test_transaction;
    use hyperscale_types::{BlockHeight, ShardId, TransactionDecision};
    use quick_cache::sync::Cache;
    use sbor::prelude::basic_encode;
    use serde_json::{from_slice, to_string};
    use tower::ServiceExt;

    use super::super::state::TxSubmissionSender;
    use super::*;
    use crate::rpc::state::{MempoolSnapshot, NodeStatusState};
    use crate::status::{ShardSyncState, SyncStatus};

    fn create_test_state() -> RpcState {
        let tx_submission_tx: TxSubmissionSender = Arc::new(|_tx| true);
        RpcState {
            ready: Arc::new(AtomicBool::new(false)),
            sync_status: Arc::new(ArcSwap::new(Arc::new(SyncStatus::default()))),
            node_status: Arc::new(ArcSwap::new(Arc::new(NodeStatusState::default()))),
            tx_submission_tx,
            start_time: Instant::now(),
            tx_status_caches: std::iter::once((ShardId::ROOT, Arc::new(Cache::new(1000))))
                .collect(),
            mempool_snapshot: Arc::new(ArcSwap::new(Arc::new(MempoolSnapshot::default()))),
            sync_backpressure_threshold: Some(10),
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Health & Readiness Handler Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_health_handler() {
        let app = Router::new()
            .route("/health", get(health_handler))
            .with_state(create_test_state());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_ready_handler_not_ready() {
        let state = create_test_state();
        let app = Router::new()
            .route("/ready", get(ready_handler))
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn test_ready_handler_ready() {
        let state = create_test_state();
        state.ready.store(true, Ordering::SeqCst);
        let app = Router::new()
            .route("/ready", get(ready_handler))
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // format_transaction_status Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_format_pending() {
        let (status, height, decision, error) =
            format_transaction_status(&TransactionStatus::Pending);
        assert_eq!(status, "pending");
        assert!(height.is_none());
        assert!(decision.is_none());
        assert!(error.is_none());
    }

    #[test]
    fn test_format_committed() {
        let (status, height, decision, error) =
            format_transaction_status(&TransactionStatus::Committed(BlockHeight::new(42)));
        assert_eq!(status, "committed");
        assert_eq!(height, Some(42));
        assert!(decision.is_none());
        assert!(error.is_none());
    }

    #[test]
    fn test_format_completed_accept() {
        let (status, height, decision, error) =
            format_transaction_status(&TransactionStatus::Completed(TransactionDecision::Accept));
        assert_eq!(status, "completed");
        assert!(height.is_none());
        assert_eq!(decision, Some("accept".to_string()));
        assert!(error.is_none());
    }

    #[test]
    fn test_format_completed_reject() {
        let (status, height, decision, error) =
            format_transaction_status(&TransactionStatus::Completed(TransactionDecision::Reject));
        assert_eq!(status, "completed");
        assert!(height.is_none());
        assert_eq!(decision, Some("reject".to_string()));
        assert!(error.is_none());
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Transaction Status Handler Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_get_transaction_not_found() {
        let state = create_test_state();
        let app = Router::new()
            .route("/tx/{hash}", get(get_transaction_handler))
            .with_state(state);

        let tx_hash = hex_encode([0u8; 32]);
        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/tx/{tx_hash}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_get_transaction_invalid_hex() {
        let state = create_test_state();
        let app = Router::new()
            .route("/tx/{hash}", get(get_transaction_handler))
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/tx/not_valid_hex!")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_get_transaction_found() {
        let state = create_test_state();
        // Create a hash from some input bytes
        let tx_hash = TxHash::from_raw(Hash::from_bytes(&[0x12; 32]));
        let tx_hash_hex = hex_encode(tx_hash.as_raw().as_bytes());

        // Insert a transaction into the (single hosted shard's) cache.
        state
            .tx_status_caches
            .values()
            .next()
            .expect("test fixture inserts a shard 0 cache")
            .insert(tx_hash, TransactionStatus::Pending);

        let app = Router::new()
            .route("/tx/{hash}", get(get_transaction_handler))
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/tx/{tx_hash_hex}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Parse response and verify status
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        let resp: TransactionStatusResponse = from_slice(&body).unwrap();
        assert_eq!(resp.status, "pending");
        assert_eq!(resp.hash, tx_hash_hex);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Sync Backpressure Tests
    // ═══════════════════════════════════════════════════════════════════════════

    fn sync_status_with(blocks_behind: u64) -> SyncStatus {
        let mut shards = std::collections::HashMap::new();
        shards.insert(
            0,
            ShardSyncState {
                state: BlockSyncStateKind::Syncing,
                current_height: 100u64.saturating_sub(blocks_behind),
                target_height: Some(100),
                blocks_behind,
                pending_fetches: 1,
                queued_heights: 2,
            },
        );
        SyncStatus {
            shards,
            sync_peers: 3,
        }
    }

    #[tokio::test]
    async fn test_submit_rejected_when_syncing() {
        let tx_submission_tx: TxSubmissionSender = Arc::new(|_tx| true);

        // Create state with node that is 20 blocks behind (threshold is 10)
        let sync_status = sync_status_with(20);

        let state = RpcState {
            ready: Arc::new(AtomicBool::new(true)),
            sync_status: Arc::new(ArcSwap::new(Arc::new(sync_status))),
            node_status: Arc::new(ArcSwap::new(Arc::new(NodeStatusState::default()))),
            tx_submission_tx,
            start_time: Instant::now(),
            tx_status_caches: std::iter::once((ShardId::ROOT, Arc::new(Cache::new(1000))))
                .collect(),
            mempool_snapshot: Arc::new(ArcSwap::new(Arc::new(MempoolSnapshot::default()))),
            sync_backpressure_threshold: Some(10),
        };

        let app = Router::new()
            .route("/tx", post(submit_transaction_handler))
            .with_state(state);

        // Submit a valid transaction (we expect it to be rejected due to sync)
        let tx = test_transaction(1);
        let tx_hex = hex_encode(basic_encode(&tx).unwrap());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/tx")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        to_string(&SubmitTransactionRequest {
                            transaction_hex: tx_hex,
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should get 503 Service Unavailable
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        // Parse response and check error message
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        let resp: SubmitTransactionResponse = from_slice(&body).unwrap();
        assert!(!resp.accepted);
        assert!(resp.error.unwrap().contains("syncing"));
    }

    #[tokio::test]
    async fn test_submit_accepted_when_caught_up() {
        let tx_submission_tx: TxSubmissionSender = Arc::new(|_tx| true);

        // Create state with node that is only 5 blocks behind (under threshold of 10)
        let sync_status = sync_status_with(5);

        let state = RpcState {
            ready: Arc::new(AtomicBool::new(true)),
            sync_status: Arc::new(ArcSwap::new(Arc::new(sync_status))),
            node_status: Arc::new(ArcSwap::new(Arc::new(NodeStatusState::default()))),
            tx_submission_tx,
            start_time: Instant::now(),
            tx_status_caches: std::iter::once((ShardId::ROOT, Arc::new(Cache::new(1000))))
                .collect(),
            mempool_snapshot: Arc::new(ArcSwap::new(Arc::new(MempoolSnapshot::default()))),
            sync_backpressure_threshold: Some(10),
        };

        let app = Router::new()
            .route("/tx", post(submit_transaction_handler))
            .with_state(state);

        // Submit a valid transaction
        let tx = test_transaction(1);
        let tx_hex = hex_encode(basic_encode(&tx).unwrap());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/tx")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        to_string(&SubmitTransactionRequest {
                            transaction_hex: tx_hex,
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should be accepted (202)
        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }
}
