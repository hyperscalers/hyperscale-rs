//! Route configuration for the RPC API.

use super::handlers::*;
use super::state::RpcState;
use axum::{
    routing::{get, post},
    Router,
};

/// Create the full router with all RPC routes.
pub fn create_router(state: RpcState) -> Router {
    Router::new()
        // Health & readiness probes (no prefix)
        .route("/health", get(health_handler))
        .route("/ready", get(ready_handler))
        // Metrics (no prefix, for Prometheus scraping)
        .route("/metrics", get(metrics_handler))
        // API v1 routes
        .nest("/api/v1", api_v1_routes())
        .with_state(state)
}

/// Create the `/api/v1` router.
fn api_v1_routes() -> Router<RpcState> {
    Router::new()
        // Status endpoints
        .route("/status", get(status_handler))
        .route("/sync", get(sync_handler))
        // Transaction endpoints
        .route("/transactions", post(submit_transaction_handler))
        .route("/transactions/{hash}", get(get_transaction_handler))
        // Mempool endpoint
        .route("/mempool", get(mempool_handler))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::{
        MempoolSnapshot, NodeStatusResponse, NodeStatusState, TransactionStatusCache,
    };
    use arc_swap::ArcSwap;
    use axum::{body::Body, http::Request};
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    use std::time::Instant;
    use tokio::sync::{mpsc, RwLock};
    use tower::ServiceExt;

    fn create_test_state() -> RpcState {
        let (tx_submission_tx, _rx) = mpsc::unbounded_channel();
        RpcState {
            ready: Arc::new(AtomicBool::new(true)),
            sync_status: Arc::new(ArcSwap::new(Arc::new(crate::sync::SyncStatus::default()))),
            node_status: Arc::new(RwLock::new(NodeStatusState {
                validator_id: 1,
                shard: 0,
                num_shards: 2,
                block_height: 100,
                view: 100,
                connected_peers: 5,
            })),
            tx_submission_tx,
            start_time: Instant::now(),
            tx_status_cache: Arc::new(RwLock::new(TransactionStatusCache::new())),
            mempool_snapshot: Arc::new(RwLock::new(MempoolSnapshot::default())),
            tx_ingress: None, // Tests use legacy path
        }
    }

    #[tokio::test]
    async fn test_router_health() {
        let app = create_router(create_test_state());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn test_router_status() {
        let app = create_router(create_test_state());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let status: NodeStatusResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(status.version, "localdev");
    }

    #[tokio::test]
    async fn test_router_metrics() {
        let app = create_router(create_test_state());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }
}
