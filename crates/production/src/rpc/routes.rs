//! Route configuration for the RPC API.

use axum::Router;
use axum::routing::{get, post};

use super::handlers::{
    get_transaction_handler, health_handler, metrics_handler, preview_transaction_handler,
    ready_handler, status_handler, submit_transaction_handler, sync_handler,
};
use super::state::RpcState;

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
        .route("/transactions/preview", post(preview_transaction_handler))
        .route("/transactions/{hash}", get(get_transaction_handler))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::time::Instant;

    use arc_swap::ArcSwap;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use hyperscale_node::TxStatusCache;
    use serde_json::from_slice;
    use tower::ServiceExt;

    use super::*;
    use crate::rpc::state::TxSubmissionSender;
    use crate::rpc::{
        MempoolSnapshot, NodeStatusResponse, NodeStatusState, VnodeMempoolStats, VnodeStatusEntry,
    };
    use crate::status::SyncStatus;

    fn create_test_state() -> RpcState {
        let tx_submission_tx: TxSubmissionSender = Arc::new(|_tx| true);
        RpcState {
            ready: Arc::new(AtomicBool::new(true)),
            sync_status: Arc::new(ArcSwap::new(Arc::new(SyncStatus::default()))),
            node_status: Arc::new(ArcSwap::new(Arc::new(NodeStatusState {
                num_shards: 2,
                connected_peers: 5,
                vnodes: vec![VnodeStatusEntry {
                    validator_id: 1,
                    shard: 0,
                    block_height: 100,
                    view: 100,
                    state_root_hash: "0".repeat(64),
                    mempool: VnodeMempoolStats {
                        pending_count: 0,
                        in_flight_count: 0,
                        total_count: 0,
                    },
                }],
            }))),
            tx_submission_tx,
            preview_tx: Arc::new(|_tx| None),
            start_time: Instant::now(),
            tx_status: Arc::new(TxStatusCache::new()),
            mempool_snapshot: Arc::new(ArcSwap::new(Arc::new(MempoolSnapshot::default()))),
            sync_backpressure_threshold: Some(10),
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

        assert_eq!(response.status(), StatusCode::OK);
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

        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        let status: NodeStatusResponse = from_slice(&body).unwrap();
        assert_eq!(status.version, "localdev");
    }

    /// A node whose shards cannot answer says so, rather than
    /// answering with an empty preview.
    ///
    /// The stub state's sender returns nothing, which is what a host
    /// with no shard able to run the transaction produces — and the
    /// difference between "this node cannot tell you" and "the
    /// transaction does nothing" is the whole reason the endpoint
    /// refuses instead of rendering a default.
    #[tokio::test]
    async fn a_preview_no_shard_answers_is_unavailable() {
        let app = create_router(create_test_state());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/transactions/preview")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"transaction_hex":"00"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "a node that cannot run the preview says so, rather than rendering a default"
        );
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

        assert_eq!(response.status(), StatusCode::OK);
    }
}
