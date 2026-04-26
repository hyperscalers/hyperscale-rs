//! HTTP request handlers for the RPC API.

use super::state::RpcState;
use super::types::{
    HealthResponse, MempoolStatusResponse, NodeStatusResponse, ReadyResponse,
    SubmitTransactionRequest, SubmitTransactionResponse, SyncStatusResponse,
    TransactionStatusResponse,
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use hyperscale_core::{NodeInput, TransactionStatus};
use hyperscale_metrics as metrics;
use hyperscale_types::{Hash, RoutableTransaction, TransactionDecision, TxHash};
use std::sync::atomic::Ordering;
use std::sync::Arc;

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
    match hyperscale_metrics_prometheus::encode_metrics() {
        Ok((content_type, buffer)) => {
            ([(axum::http::header::CONTENT_TYPE, content_type)], buffer).into_response()
        }
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
    let mempool_snapshot = state.mempool_snapshot.load();
    let uptime = state.start_time.elapsed().as_secs();

    Json(NodeStatusResponse {
        validator_id: node_status.validator_id,
        shard: node_status.shard,
        num_shards: node_status.num_shards,
        block_height: node_status.block_height,
        view: node_status.view,
        connected_peers: node_status.connected_peers,
        uptime_secs: uptime,
        version: option_env!("HYPERSCALE_VERSION")
            .unwrap_or("localdev")
            .to_string(),
        state_root_hash: node_status.state_root_hash.clone(),
        mempool: MempoolStatusResponse {
            pending_count: mempool_snapshot.pending_count,
            committed_count: mempool_snapshot.committed_count,
            executed_count: mempool_snapshot.executed_count,
            total_count: mempool_snapshot.total_count,
        },
    })
}

/// Handler for `GET /api/v1/sync` - sync status.
pub async fn sync_handler(State(state): State<RpcState>) -> impl IntoResponse {
    let sync_status = state.sync_status.load();

    Json(SyncStatusResponse {
        state: format!("{:?}", sync_status.state).to_lowercase(),
        current_height: sync_status.current_height,
        target_height: sync_status.target_height,
        blocks_behind: sync_status.blocks_behind,
        sync_peers: sync_status.sync_peers,
        pending_fetches: sync_status.pending_fetches,
        queued_heights: sync_status.queued_heights,
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

    let hash = hex::encode(transaction.hash().as_bytes());
    let tx_arc = Arc::new(transaction);

    // Submit directly to IoLoop via crossbeam channel.
    // IoLoop will:
    // 1. Gossip to all relevant shards
    // 2. Queue for batch validation (via Dispatch)
    // 3. Dispatch to mempool after validation
    if state
        .tx_submission_tx
        .send(NodeInput::SubmitTransaction { tx: tx_arc })
        .is_err()
    {
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

    // Look up in cache (QuickCache is lock-free, no await needed)
    match state.tx_status_cache.get(&tx_hash) {
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

/// Reject the request if any sync or mempool backpressure condition is active.
fn check_backpressure(state: &RpcState) -> Option<(StatusCode, Json<SubmitTransactionResponse>)> {
    if let Some(threshold) = state.sync_backpressure_threshold {
        let sync_status = state.sync_status.load();
        if sync_status.blocks_behind > threshold {
            metrics::record_tx_ingress_rejected_syncing();
            return Some((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(SubmitTransactionResponse {
                    accepted: false,
                    hash: String::new(),
                    error: Some(format!(
                        "Node is syncing ({} blocks behind). Try again later.",
                        sync_status.blocks_behind
                    )),
                }),
            ));
        }
    }

    let snapshot = state.mempool_snapshot.load();

    if !snapshot.accepting_rpc_transactions {
        metrics::record_transaction_rejected("in_flight_limit");
        return Some((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(SubmitTransactionResponse {
                accepted: false,
                hash: String::new(),
                error: Some("Cross-shard transaction limit reached. Try again later.".to_string()),
            }),
        ));
    }

    if snapshot.at_pending_limit {
        metrics::record_tx_ingress_rejected_pending_limit();
        return Some((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(SubmitTransactionResponse {
                accepted: false,
                hash: String::new(),
                error: Some("Too many pending transactions. Try again later.".to_string()),
            }),
        ));
    }

    // Threshold is 80% of `max_in_flight`, derived from mempool config.
    let threshold = snapshot.remote_congestion_threshold;
    if let Some((&congested_shard, &count)) = snapshot
        .remote_shard_in_flight
        .iter()
        .find(|(_, &count)| threshold > 0 && count >= threshold)
    {
        metrics::record_transaction_rejected("remote_shard_congestion");
        return Some((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(SubmitTransactionResponse {
                accepted: false,
                hash: String::new(),
                error: Some(format!(
                    "Remote shard {} is congested ({count} in-flight). Try again later.",
                    congested_shard.0
                )),
            }),
        ));
    }

    None
}

/// Hex- and SBOR-decode a submitted transaction, recording metrics on failure.
fn decode_transaction(
    transaction_hex: &str,
) -> Result<RoutableTransaction, (StatusCode, Json<SubmitTransactionResponse>)> {
    let tx_bytes = hex::decode(transaction_hex).map_err(|e| {
        metrics::record_transaction_rejected("invalid_hex");
        (
            StatusCode::BAD_REQUEST,
            Json(SubmitTransactionResponse {
                accepted: false,
                hash: String::new(),
                error: Some(format!("Invalid hex encoding: {e}")),
            }),
        )
    })?;

    sbor::prelude::basic_decode(&tx_bytes).map_err(|e| {
        metrics::record_transaction_rejected("invalid_format");
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
            ("committed".to_string(), Some(height.0), None, None)
        }
        TransactionStatus::Executed {
            decision,
            committed_at,
        } => {
            let decision_str = match decision {
                TransactionDecision::Accept => "accept",
                TransactionDecision::Reject => "reject",
                TransactionDecision::Aborted => "aborted",
            };
            (
                "executed".to_string(),
                Some(committed_at.0),
                Some(decision_str.to_string()),
                None,
            )
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

// ═══════════════════════════════════════════════════════════════════════════
// Mempool Handler
// ═══════════════════════════════════════════════════════════════════════════

/// Handler for `GET /api/v1/mempool` - mempool status.
pub async fn mempool_handler(State(state): State<RpcState>) -> impl IntoResponse {
    let snapshot = state.mempool_snapshot.load();
    Json(MempoolStatusResponse {
        pending_count: snapshot.pending_count,
        committed_count: snapshot.committed_count,
        executed_count: snapshot.executed_count,
        total_count: snapshot.total_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::state::{MempoolSnapshot, NodeStatusState};
    use crate::status::SyncStatus;
    use arc_swap::ArcSwap;
    use axum::{body::Body, http::Request, Router};
    use hyperscale_types::{BlockHeight, TransactionDecision};
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    use std::time::Instant;
    use tower::ServiceExt;

    fn create_test_state() -> RpcState {
        let (tx_submission_tx, _rx) = crossbeam::channel::unbounded();
        RpcState {
            ready: Arc::new(AtomicBool::new(false)),
            sync_status: Arc::new(ArcSwap::new(Arc::new(SyncStatus::default()))),
            node_status: Arc::new(ArcSwap::new(Arc::new(NodeStatusState::default()))),
            tx_submission_tx,
            start_time: Instant::now(),
            tx_status_cache: Arc::new(quick_cache::sync::Cache::new(1000)),
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
            .route("/health", axum::routing::get(health_handler))
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
            .route("/ready", axum::routing::get(ready_handler))
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
            .route("/ready", axum::routing::get(ready_handler))
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
            format_transaction_status(&TransactionStatus::Committed(BlockHeight(42)));
        assert_eq!(status, "committed");
        assert_eq!(height, Some(42));
        assert!(decision.is_none());
        assert!(error.is_none());
    }

    #[test]
    fn test_format_executed_accept() {
        let (status, height, decision, error) =
            format_transaction_status(&TransactionStatus::Executed {
                decision: TransactionDecision::Accept,
                committed_at: BlockHeight(5),
            });
        assert_eq!(status, "executed");
        assert_eq!(height, Some(5));
        assert_eq!(decision, Some("accept".to_string()));
        assert!(error.is_none());
    }

    #[test]
    fn test_format_executed_reject() {
        let (status, height, decision, error) =
            format_transaction_status(&TransactionStatus::Executed {
                decision: TransactionDecision::Reject,
                committed_at: BlockHeight(10),
            });
        assert_eq!(status, "executed");
        assert_eq!(height, Some(10));
        assert_eq!(decision, Some("reject".to_string()));
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
            .route("/tx/{hash}", axum::routing::get(get_transaction_handler))
            .with_state(state);

        let tx_hash = hex::encode([0u8; 32]);
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
            .route("/tx/{hash}", axum::routing::get(get_transaction_handler))
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
        let tx_hash_hex = hex::encode(tx_hash.as_raw().as_bytes());

        // Insert a transaction into the cache
        state
            .tx_status_cache
            .insert(tx_hash, TransactionStatus::Pending);

        let app = Router::new()
            .route("/tx/{hash}", axum::routing::get(get_transaction_handler))
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
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let resp: TransactionStatusResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(resp.status, "pending");
        assert_eq!(resp.hash, tx_hash_hex);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Mempool Handler Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_mempool_handler_default() {
        let state = create_test_state();
        let app = Router::new()
            .route("/mempool", axum::routing::get(mempool_handler))
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/mempool")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_mempool_handler_with_data() {
        let state = create_test_state();

        // Update the mempool snapshot
        state.mempool_snapshot.store(Arc::new(MempoolSnapshot {
            pending_count: 10,
            committed_count: 3,
            executed_count: 2,
            total_count: 17,
            ..MempoolSnapshot::default()
        }));

        let app = Router::new()
            .route("/mempool", axum::routing::get(mempool_handler))
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/mempool")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Parse response body
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let resp: MempoolStatusResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(resp.pending_count, 10);
        assert_eq!(resp.committed_count, 3);
        assert_eq!(resp.executed_count, 2);
        assert_eq!(resp.total_count, 17);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Sync Backpressure Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_submit_rejected_when_syncing() {
        let (tx_submission_tx, _rx) = crossbeam::channel::unbounded();

        // Create state with node that is 20 blocks behind (threshold is 10)
        let sync_status = crate::status::SyncStatus {
            state: crate::status::SyncStateKind::Syncing,
            current_height: 80,
            target_height: Some(100),
            blocks_behind: 20,
            sync_peers: 3,
            pending_fetches: 2,
            queued_heights: 5,
        };

        let state = RpcState {
            ready: Arc::new(AtomicBool::new(true)),
            sync_status: Arc::new(ArcSwap::new(Arc::new(sync_status))),
            node_status: Arc::new(ArcSwap::new(Arc::new(NodeStatusState::default()))),
            tx_submission_tx,
            start_time: Instant::now(),
            tx_status_cache: Arc::new(quick_cache::sync::Cache::new(1000)),
            mempool_snapshot: Arc::new(ArcSwap::new(Arc::new(MempoolSnapshot::default()))),
            sync_backpressure_threshold: Some(10),
        };

        let app = Router::new()
            .route("/tx", axum::routing::post(submit_transaction_handler))
            .with_state(state);

        // Submit a valid transaction (we expect it to be rejected due to sync)
        let tx = hyperscale_types::test_utils::test_transaction(1);
        let tx_hex = hex::encode(sbor::prelude::basic_encode(&tx).unwrap());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/tx")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_string(&SubmitTransactionRequest {
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
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let resp: SubmitTransactionResponse = serde_json::from_slice(&body).unwrap();
        assert!(!resp.accepted);
        assert!(resp.error.unwrap().contains("syncing"));
    }

    #[tokio::test]
    async fn test_submit_accepted_when_caught_up() {
        let (tx_submission_tx, _rx) = crossbeam::channel::unbounded();

        // Create state with node that is only 5 blocks behind (under threshold of 10)
        let sync_status = crate::status::SyncStatus {
            state: crate::status::SyncStateKind::Syncing,
            current_height: 95,
            target_height: Some(100),
            blocks_behind: 5,
            sync_peers: 3,
            pending_fetches: 1,
            queued_heights: 2,
        };

        let state = RpcState {
            ready: Arc::new(AtomicBool::new(true)),
            sync_status: Arc::new(ArcSwap::new(Arc::new(sync_status))),
            node_status: Arc::new(ArcSwap::new(Arc::new(NodeStatusState::default()))),
            tx_submission_tx,
            start_time: Instant::now(),
            tx_status_cache: Arc::new(quick_cache::sync::Cache::new(1000)),
            mempool_snapshot: Arc::new(ArcSwap::new(Arc::new(MempoolSnapshot::default()))),
            sync_backpressure_threshold: Some(10),
        };

        let app = Router::new()
            .route("/tx", axum::routing::post(submit_transaction_handler))
            .with_state(state);

        // Submit a valid transaction
        let tx = hyperscale_types::test_utils::test_transaction(1);
        let tx_hex = hex::encode(sbor::prelude::basic_encode(&tx).unwrap());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/tx")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_string(&SubmitTransactionRequest {
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
