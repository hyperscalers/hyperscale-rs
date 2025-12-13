//! HTTP request handlers for the RPC API.

use super::state::RpcState;
use super::types::*;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use hyperscale_core::TransactionStatus;
use hyperscale_types::{Hash, RoutableTransaction, TransactionDecision};
use prometheus::{Encoder, TextEncoder};
use std::sync::atomic::Ordering;
use tokio::sync::mpsc;

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
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();

    let mut buffer = Vec::new();
    if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
        tracing::error!(error = ?e, "Failed to encode metrics");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to encode metrics".to_string(),
        )
            .into_response();
    }

    (
        [(
            axum::http::header::CONTENT_TYPE,
            encoder.format_type().to_string(),
        )],
        buffer,
    )
        .into_response()
}

// ═══════════════════════════════════════════════════════════════════════════
// Status Handlers
// ═══════════════════════════════════════════════════════════════════════════

/// Handler for `GET /api/v1/status` - node status.
pub async fn status_handler(State(state): State<RpcState>) -> impl IntoResponse {
    let node_status = state.node_status.read().await;
    let mempool_snapshot = state.mempool_snapshot.read().await;
    let uptime = state.start_time.elapsed().as_secs();

    Json(NodeStatusResponse {
        validator_id: node_status.validator_id,
        shard: node_status.shard,
        num_shards: node_status.num_shards,
        block_height: node_status.block_height,
        view: node_status.view,
        connected_peers: node_status.connected_peers,
        uptime_secs: uptime,
        version: env!("CARGO_PKG_VERSION").to_string(),
        mempool: MempoolStatusResponse {
            pending_count: mempool_snapshot.pending_count,
            executing_count: mempool_snapshot.executing_count,
            total_count: mempool_snapshot.total_count,
            blocked_count: mempool_snapshot.blocked_count,
        },
    })
}

/// Handler for `GET /api/v1/sync` - sync status.
pub async fn sync_handler(State(state): State<RpcState>) -> impl IntoResponse {
    let sync_status = state.sync_status.read().await;

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
/// Performs signature validation before accepting the transaction into the
/// mempool. Invalid transactions are rejected with a 400 Bad Request response.
pub async fn submit_transaction_handler(
    State(state): State<RpcState>,
    Json(request): Json<SubmitTransactionRequest>,
) -> impl IntoResponse {
    // Decode hex
    let tx_bytes = match hex::decode(&request.transaction_hex) {
        Ok(bytes) => bytes,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(SubmitTransactionResponse {
                    accepted: false,
                    hash: String::new(),
                    error: Some(format!("Invalid hex encoding: {}", e)),
                }),
            );
        }
    };

    // Decode SBOR
    let transaction: RoutableTransaction = match sbor::prelude::basic_decode(&tx_bytes) {
        Ok(tx) => tx,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(SubmitTransactionResponse {
                    accepted: false,
                    hash: String::new(),
                    error: Some(format!("Invalid transaction format: {:?}", e)),
                }),
            );
        }
    };

    let hash = hex::encode(transaction.hash().as_bytes());

    // Validate transaction signatures before accepting into mempool
    {
        let validator = state.tx_validator.clone();
        let tx_for_validation = transaction.clone();

        // Run validation on blocking thread pool to avoid blocking async runtime
        // Signature verification is CPU-intensive
        let validation_result =
            tokio::task::spawn_blocking(move || validator.validate_transaction(&tx_for_validation))
                .await;

        match validation_result {
            Ok(Ok(())) => {
                // Validation passed, continue to send
            }
            Ok(Err(e)) => {
                // Validation failed - reject transaction
                tracing::debug!(
                    tx_hash = %hash,
                    error = %e,
                    "Transaction validation failed"
                );
                return (
                    StatusCode::BAD_REQUEST,
                    Json(SubmitTransactionResponse {
                        accepted: false,
                        hash,
                        error: Some(format!("Transaction validation failed: {}", e)),
                    }),
                );
            }
            Err(e) => {
                // spawn_blocking task panicked - shouldn't happen
                tracing::error!(error = ?e, "Validation task panicked");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(SubmitTransactionResponse {
                        accepted: false,
                        hash,
                        error: Some("Internal validation error".to_string()),
                    }),
                );
            }
        }
    }

    // Send to node
    match state.tx_sender.try_send(transaction) {
        Ok(()) => (
            StatusCode::ACCEPTED,
            Json(SubmitTransactionResponse {
                accepted: true,
                hash,
                error: None,
            }),
        ),
        Err(mpsc::error::TrySendError::Full(_)) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(SubmitTransactionResponse {
                accepted: false,
                hash,
                error: Some("Transaction queue full, try again later".to_string()),
            }),
        ),
        Err(mpsc::error::TrySendError::Closed(_)) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(SubmitTransactionResponse {
                accepted: false,
                hash,
                error: Some("Node is shutting down".to_string()),
            }),
        ),
    }
}

/// Handler for `GET /api/v1/transactions/:hash` - get transaction status.
pub async fn get_transaction_handler(
    State(state): State<RpcState>,
    Path(hash_hex): Path<String>,
) -> impl IntoResponse {
    // Parse the hash from hex (expects the raw hash bytes, not data to hash)
    let tx_hash = match Hash::from_hex(&hash_hex) {
        Ok(hash) => hash,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(TransactionStatusResponse {
                    hash: hash_hex,
                    status: "error".to_string(),
                    committed_height: None,
                    decision: None,
                    blocked_by: None,
                    retry_tx: None,
                    error: Some("Invalid transaction hash: must be 64 hex characters".to_string()),
                }),
            );
        }
    };

    // Look up in cache
    let cache = state.tx_status_cache.read().await;
    match cache.get(&tx_hash) {
        Some(cached) => {
            let (status_str, committed_height, decision, blocked_by, retry_tx) =
                format_transaction_status(&cached.status);

            (
                StatusCode::OK,
                Json(TransactionStatusResponse {
                    hash: hash_hex,
                    status: status_str,
                    committed_height,
                    decision,
                    blocked_by,
                    retry_tx,
                    error: None,
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
                blocked_by: None,
                retry_tx: None,
                error: Some("Transaction not found in cache".to_string()),
            }),
        ),
    }
}

/// Format a TransactionStatus into RPC response fields.
fn format_transaction_status(
    status: &TransactionStatus,
) -> (
    String,
    Option<u64>,
    Option<String>,
    Option<String>,
    Option<String>,
) {
    match status {
        TransactionStatus::Pending => ("pending".to_string(), None, None, None, None),
        TransactionStatus::Committed(height) => {
            ("committed".to_string(), Some(height.0), None, None, None)
        }
        TransactionStatus::Executed(decision) => {
            let decision_str = match decision {
                TransactionDecision::Accept => "accept",
                TransactionDecision::Reject => "reject",
            };
            (
                "executed".to_string(),
                None,
                Some(decision_str.to_string()),
                None,
                None,
            )
        }
        TransactionStatus::Completed(decision) => {
            let decision_str = match decision {
                TransactionDecision::Accept => "accept",
                TransactionDecision::Reject => "reject",
            };
            (
                "completed".to_string(),
                None,
                Some(decision_str.to_string()),
                None,
                None,
            )
        }
        TransactionStatus::Blocked { by } => (
            "blocked".to_string(),
            None,
            None,
            Some(hex::encode(by.as_bytes())),
            None,
        ),
        TransactionStatus::Retried { new_tx } => (
            "retried".to_string(),
            None,
            None,
            None,
            Some(hex::encode(new_tx.as_bytes())),
        ),
        TransactionStatus::Aborted { reason } => (
            "aborted".to_string(),
            None,
            None,
            None,
            Some(reason.to_string()),
        ),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Mempool Handler
// ═══════════════════════════════════════════════════════════════════════════

/// Handler for `GET /api/v1/mempool` - mempool status.
pub async fn mempool_handler(State(state): State<RpcState>) -> impl IntoResponse {
    let snapshot = state.mempool_snapshot.read().await;
    Json(MempoolStatusResponse {
        pending_count: snapshot.pending_count,
        executing_count: snapshot.executing_count,
        total_count: snapshot.total_count,
        blocked_count: snapshot.blocked_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::state::{MempoolSnapshot, NodeStatusState, TransactionStatusCache};
    use crate::sync::SyncStatus;
    use axum::{body::Body, http::Request, Router};
    use hyperscale_engine::TransactionValidation;
    use hyperscale_types::{BlockHeight, TransactionDecision};
    use radix_common::network::NetworkDefinition;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    use std::time::Instant;
    use tokio::sync::RwLock;
    use tower::ServiceExt;

    fn create_test_state() -> RpcState {
        let (tx_sender, _rx) = tokio::sync::mpsc::channel(100);
        RpcState {
            ready: Arc::new(AtomicBool::new(false)),
            sync_status: Arc::new(RwLock::new(SyncStatus::default())),
            node_status: Arc::new(RwLock::new(NodeStatusState::default())),
            tx_sender,
            start_time: Instant::now(),
            tx_status_cache: Arc::new(RwLock::new(TransactionStatusCache::new())),
            mempool_snapshot: Arc::new(RwLock::new(MempoolSnapshot::default())),
            tx_validator: Arc::new(TransactionValidation::new(NetworkDefinition::simulator())),
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
        let (status, height, decision, blocked_by, retry_tx) =
            format_transaction_status(&TransactionStatus::Pending);
        assert_eq!(status, "pending");
        assert!(height.is_none());
        assert!(decision.is_none());
        assert!(blocked_by.is_none());
        assert!(retry_tx.is_none());
    }

    #[test]
    fn test_format_committed() {
        let (status, height, decision, blocked_by, retry_tx) =
            format_transaction_status(&TransactionStatus::Committed(BlockHeight(42)));
        assert_eq!(status, "committed");
        assert_eq!(height, Some(42));
        assert!(decision.is_none());
        assert!(blocked_by.is_none());
        assert!(retry_tx.is_none());
    }

    #[test]
    fn test_format_executed_accept() {
        let (status, height, decision, blocked_by, retry_tx) =
            format_transaction_status(&TransactionStatus::Executed(TransactionDecision::Accept));
        assert_eq!(status, "executed");
        assert!(height.is_none());
        assert_eq!(decision, Some("accept".to_string()));
        assert!(blocked_by.is_none());
        assert!(retry_tx.is_none());
    }

    #[test]
    fn test_format_executed_reject() {
        let (status, height, decision, blocked_by, retry_tx) =
            format_transaction_status(&TransactionStatus::Executed(TransactionDecision::Reject));
        assert_eq!(status, "executed");
        assert!(height.is_none());
        assert_eq!(decision, Some("reject".to_string()));
        assert!(blocked_by.is_none());
        assert!(retry_tx.is_none());
    }

    #[test]
    fn test_format_completed_accept() {
        let (status, height, decision, blocked_by, retry_tx) =
            format_transaction_status(&TransactionStatus::Completed(TransactionDecision::Accept));
        assert_eq!(status, "completed");
        assert!(height.is_none());
        assert_eq!(decision, Some("accept".to_string()));
        assert!(blocked_by.is_none());
        assert!(retry_tx.is_none());
    }

    #[test]
    fn test_format_completed_reject() {
        let (status, height, decision, blocked_by, retry_tx) =
            format_transaction_status(&TransactionStatus::Completed(TransactionDecision::Reject));
        assert_eq!(status, "completed");
        assert!(height.is_none());
        assert_eq!(decision, Some("reject".to_string()));
        assert!(blocked_by.is_none());
        assert!(retry_tx.is_none());
    }

    #[test]
    fn test_format_blocked() {
        let blocker = Hash::from_bytes(&[0xab; 32]);
        let (status, height, decision, blocked_by, retry_tx) =
            format_transaction_status(&TransactionStatus::Blocked { by: blocker });
        assert_eq!(status, "blocked");
        assert!(height.is_none());
        assert!(decision.is_none());
        assert_eq!(blocked_by, Some(hex::encode(blocker.as_bytes())));
        assert!(retry_tx.is_none());
    }

    #[test]
    fn test_format_retried() {
        let new_tx = Hash::from_bytes(&[0xcd; 32]);
        let (status, height, decision, blocked_by, retry_tx) =
            format_transaction_status(&TransactionStatus::Retried { new_tx });
        assert_eq!(status, "retried");
        assert!(height.is_none());
        assert!(decision.is_none());
        assert!(blocked_by.is_none());
        assert_eq!(retry_tx, Some(hex::encode(new_tx.as_bytes())));
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
                    .uri(format!("/tx/{}", tx_hash))
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
        let tx_hash = Hash::from_bytes(&[0x12; 32]);
        let tx_hash_hex = hex::encode(tx_hash.as_bytes());

        // Insert a transaction into the cache
        {
            let mut cache = state.tx_status_cache.write().await;
            cache.update(tx_hash, TransactionStatus::Pending);
        }

        let app = Router::new()
            .route("/tx/{hash}", axum::routing::get(get_transaction_handler))
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/tx/{}", tx_hash_hex))
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
        {
            let mut snapshot = state.mempool_snapshot.write().await;
            snapshot.pending_count = 10;
            snapshot.executing_count = 5;
            snapshot.blocked_count = 2;
            snapshot.total_count = 17;
        }

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
        assert_eq!(resp.executing_count, 5);
        assert_eq!(resp.blocked_count, 2);
        assert_eq!(resp.total_count, 17);
    }
}
