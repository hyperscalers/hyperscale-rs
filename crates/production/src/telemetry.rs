//! OpenTelemetry initialization and configuration.
//!
//! This module provides telemetry setup for distributed tracing and metrics.
//! The architecture instruments the production runner while preserving
//! state machine determinism.

use crate::sync::SyncStatus;
use arc_swap::ArcSwap;
use axum::{response::IntoResponse, routing::get, Router};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    trace::{RandomIdGenerator, Sampler, SdkTracerProvider},
    Resource,
};
use opentelemetry_semantic_conventions::resource::{SERVICE_NAME, SERVICE_VERSION};
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::{layer::SubscriberExt, EnvFilter, Layer, Registry};

/// Provider for sync status, used by the telemetry HTTP server.
pub type SyncStatusProvider = Arc<ArcSwap<SyncStatus>>;

#[derive(Debug, Error)]
pub enum TelemetryError {
    #[error("Failed to build OTLP exporter: {0}")]
    ExporterBuild(#[from] opentelemetry_otlp::ExporterBuildError),

    #[error("OpenTelemetry SDK error: {0}")]
    OtelSdk(#[from] opentelemetry_sdk::error::OTelSdkError),

    #[error("Failed to set global subscriber: {0}")]
    SetSubscriber(#[from] tracing::subscriber::SetGlobalDefaultError),

    #[error("Failed to bind metrics port: {0}")]
    MetricsPort(#[from] std::io::Error),
}

/// Configuration for telemetry.
#[derive(Debug, Clone)]
pub struct TelemetryConfig {
    /// Service name for OTEL resource attributes.
    pub service_name: String,
    /// OTLP endpoint (e.g., "http://localhost:4317").
    pub otlp_endpoint: Option<String>,
    /// Sampling ratio (0.0 to 1.0). Default: 1.0 (sample everything).
    pub sampling_ratio: f64,
    /// Enable Prometheus metrics endpoint.
    pub prometheus_enabled: bool,
    /// Prometheus metrics port.
    pub prometheus_port: u16,
    /// Additional resource attributes.
    pub resource_attributes: Vec<(String, String)>,
    /// Optional log file path. If provided, logs are written to this file instead of stdout.
    pub log_file: Option<std::path::PathBuf>,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            service_name: "hyperscale-node".to_string(),
            otlp_endpoint: None,
            sampling_ratio: 1.0,
            prometheus_enabled: false,
            prometheus_port: 9090,
            resource_attributes: vec![],
            log_file: None,
        }
    }
}

/// Initialize telemetry with the given configuration.
///
/// If `otlp_endpoint` is None, falls back to console/env-filter logging only.
/// This allows graceful degradation when no collector is available.
///
/// **Resilience**: The OTLP exporter uses a batch processor with retry logic.
/// If the collector is temporarily unavailable:
/// - Spans are buffered in memory (up to batch size limit)
/// - The node continues running normally
/// - Spans are exported when the collector becomes available
/// - If the buffer fills, oldest spans are dropped (not the node)
///
/// The `build()` call validates the endpoint URL format but does NOT
/// establish a connection - that happens lazily on first export.
pub fn init_telemetry(config: &TelemetryConfig) -> Result<TelemetryGuard, TelemetryError> {
    // Build resource attributes
    let mut resource_attrs = vec![
        opentelemetry::KeyValue::new(SERVICE_NAME, config.service_name.clone()),
        opentelemetry::KeyValue::new(SERVICE_VERSION, env!("CARGO_PKG_VERSION")),
    ];

    for (key, value) in &config.resource_attributes {
        resource_attrs.push(opentelemetry::KeyValue::new(key.clone(), value.clone()));
    }

    let resource = Resource::builder().with_attributes(resource_attrs).build();

    // Build the subscriber layers
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,hyperscale=debug"));

    // Optional OTLP tracing layer
    let (otel_layer, tracer_provider) = if let Some(endpoint) = &config.otlp_endpoint {
        // Note: build() validates URL format but connection is lazy
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .build()?;

        let tracer_provider = SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .with_sampler(Sampler::TraceIdRatioBased(config.sampling_ratio))
            .with_id_generator(RandomIdGenerator::default())
            .with_resource(resource.clone())
            .build();

        let tracer = tracer_provider.tracer("hyperscale");

        (
            Some(OpenTelemetryLayer::new(tracer).boxed()),
            Some(tracer_provider),
        )
    } else {
        (None, None)
    };

    // Initialize formatting layer (file or stdout)
    let (fmt_layer, _appender_guard) = if let Some(log_file) = &config.log_file {
        if let Some(parent) = log_file.parent() {
            std::fs::create_dir_all(parent).map_err(TelemetryError::MetricsPort)?;
        }
        let file_name = log_file
            .file_name()
            .ok_or_else(|| {
                TelemetryError::MetricsPort(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Invalid log file name",
                ))
            })?
            .to_string_lossy()
            .to_string();
        let directory = log_file
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .to_path_buf();

        let file_appender = tracing_appender::rolling::never(directory, file_name);
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

        let layer = tracing_subscriber::fmt::layer()
            .with_writer(non_blocking)
            .with_ansi(false) // Disable ANSI colors in file logs
            .with_target(true)
            .with_thread_ids(true);

        (layer.boxed(), Some(guard))
    } else {
        let layer = tracing_subscriber::fmt::layer()
            .with_target(true)
            .with_thread_ids(true);
        (layer.boxed(), None)
    };

    // Initialize the subscriber
    let subscriber = Registry::default()
        .with(env_filter)
        .with(fmt_layer)
        .with(otel_layer);

    tracing::subscriber::set_global_default(subscriber)?;

    // Start Prometheus metrics endpoint if enabled
    let (prometheus_handle, ready_flag, sync_status) = if config.prometheus_enabled {
        let ready_flag = Arc::new(AtomicBool::new(false));
        let sync_status = Arc::new(ArcSwap::new(Arc::new(SyncStatus::default())));
        let handle = start_metrics_server(
            config.prometheus_port,
            ready_flag.clone(),
            sync_status.clone(),
        );
        (Some(handle), Some(ready_flag), Some(sync_status))
    } else {
        (None, None, None)
    };

    Ok(TelemetryGuard {
        tracer_provider,
        prometheus_handle,
        ready_flag,
        sync_status,
        _appender_guard,
    })
}

/// Guard that shuts down telemetry on drop.
///
/// For graceful shutdown with span flushing, call `shutdown().await` explicitly
/// before dropping. The `Drop` impl provides a fallback but cannot flush async.
pub struct TelemetryGuard {
    tracer_provider: Option<SdkTracerProvider>,
    prometheus_handle: Option<tokio::task::JoinHandle<()>>,
    ready_flag: Option<Arc<AtomicBool>>,
    sync_status: Option<SyncStatusProvider>,
    _appender_guard: Option<tracing_appender::non_blocking::WorkerGuard>,
}

impl TelemetryGuard {
    /// Gracefully shutdown telemetry, flushing pending spans to the collector.
    ///
    /// Call this before dropping the guard for clean shutdown. Waits up to 5 seconds
    /// for pending spans to be exported before forcing shutdown.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let guard = init_telemetry(&config)?;
    /// // ... run application ...
    /// guard.shutdown().await; // Flushes spans before exit
    /// ```
    pub async fn shutdown(mut self) {
        use std::time::Duration;

        // Flush pending spans with timeout
        if let Some(provider) = self.tracer_provider.take() {
            let _ = tokio::time::timeout(
                Duration::from_secs(5),
                tokio::task::spawn_blocking(move || {
                    let _ = provider.shutdown();
                }),
            )
            .await;
        }

        // Stop Prometheus server
        if let Some(handle) = self.prometheus_handle.take() {
            handle.abort();
        }
    }

    /// Set the Prometheus server handle (called internally).
    #[allow(dead_code)]
    pub(crate) fn set_prometheus_handle(&mut self, handle: tokio::task::JoinHandle<()>) {
        self.prometheus_handle = Some(handle);
    }

    /// Mark the node as ready (for readiness probe).
    ///
    /// Call this after the node has completed initialization and is ready
    /// to participate in consensus.
    pub fn set_ready(&self, ready: bool) {
        if let Some(flag) = &self.ready_flag {
            flag.store(ready, Ordering::SeqCst);
        }
    }

    /// Get the sync status provider for updating sync status.
    ///
    /// Returns `None` if Prometheus metrics are disabled.
    /// The runner should call this to get a handle for updating sync status.
    pub fn sync_status_provider(&self) -> Option<SyncStatusProvider> {
        self.sync_status.clone()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Prometheus HTTP Server
// ═══════════════════════════════════════════════════════════════════════════

/// Start the metrics HTTP server.
///
/// Exposes:
/// - `GET /metrics` - Prometheus metrics in text format
/// - `GET /health` - Liveness probe (always returns 200 if server is running)
/// - `GET /ready` - Readiness probe (returns 200 if node is ready, 503 otherwise)
/// - `GET /system/sync-status` - Sync status for operational visibility
fn start_metrics_server(
    port: u16,
    ready_flag: Arc<AtomicBool>,
    sync_status: SyncStatusProvider,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let ready_flag_clone = ready_flag.clone();
        let sync_status_clone = sync_status.clone();

        let app = Router::new()
            .route("/metrics", get(metrics_handler))
            .route("/health", get(health_handler))
            .route(
                "/ready",
                get(move || ready_handler(ready_flag_clone.clone())),
            )
            .route(
                "/system/sync-status",
                get(move || sync_status_handler(sync_status_clone.clone())),
            );

        let addr = SocketAddr::from(([0, 0, 0, 0], port));
        tracing::info!(port, "Starting metrics server on http://{}", addr);

        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(error = ?e, port, "Failed to bind metrics server");
                return;
            }
        };

        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!(error = ?e, "Metrics server error");
        }
    })
}

/// Handler for `/metrics` - returns Prometheus metrics.
async fn metrics_handler() -> impl axum::response::IntoResponse {
    match hyperscale_metrics_prometheus::encode_metrics() {
        Ok((content_type, buffer)) => {
            ([(axum::http::header::CONTENT_TYPE, content_type)], buffer).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to encode metrics");
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to encode metrics",
            )
                .into_response()
        }
    }
}

/// Handler for `/health` - liveness probe.
///
/// Returns 200 OK if the server is running. This indicates the process is alive
/// but not necessarily ready to serve traffic.
async fn health_handler() -> impl axum::response::IntoResponse {
    axum::Json(HealthResponse { status: "ok" })
}

/// Handler for `/ready` - readiness probe.
///
/// Returns 200 OK if the node is ready to participate in consensus.
/// Returns 503 Service Unavailable if still initializing.
async fn ready_handler(ready_flag: Arc<AtomicBool>) -> impl axum::response::IntoResponse {
    if ready_flag.load(Ordering::SeqCst) {
        (
            axum::http::StatusCode::OK,
            axum::Json(ReadyResponse {
                status: "ready",
                ready: true,
            }),
        )
    } else {
        (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(ReadyResponse {
                status: "not_ready",
                ready: false,
            }),
        )
    }
}

/// Handler for `/system/sync-status` - sync status endpoint.
///
/// Returns the current sync status as JSON.
async fn sync_status_handler(sync_status: SyncStatusProvider) -> impl axum::response::IntoResponse {
    let status = sync_status.load();
    axum::Json((**status).clone())
}

/// Response for health endpoint.
#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}

/// Response for readiness endpoint.
#[derive(Serialize)]
struct ReadyResponse {
    status: &'static str,
    ready: bool,
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        // Fallback shutdown - may lose pending spans if shutdown() wasn't called
        if let Some(provider) = self.tracer_provider.take() {
            let _ = provider.shutdown();
        }
        if let Some(handle) = self.prometheus_handle.take() {
            handle.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;

    #[test]
    fn test_default_config() {
        let config = TelemetryConfig::default();
        assert_eq!(config.service_name, "hyperscale-node");
        assert!(config.otlp_endpoint.is_none());
        assert_eq!(config.sampling_ratio, 1.0);
        assert!(!config.prometheus_enabled);
        assert_eq!(config.prometheus_port, 9090);
    }

    #[test]
    fn test_telemetry_disabled_by_default() {
        // Verify config defaults to no OTLP endpoint
        let config = TelemetryConfig::default();
        assert!(config.otlp_endpoint.is_none());
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let ready_flag = Arc::new(AtomicBool::new(false));
        let app = Router::new().route("/health", get(health_handler));

        let response = axum::http::Request::builder()
            .uri("/health")
            .body(axum::body::Body::empty())
            .unwrap();

        let response = app.oneshot(response).await.unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "ok");

        // Suppress unused variable warning
        let _ = ready_flag;
    }

    #[tokio::test]
    async fn test_ready_endpoint_not_ready() {
        let ready_flag = Arc::new(AtomicBool::new(false));
        let flag_clone = ready_flag.clone();

        let app = Router::new().route("/ready", get(move || ready_handler(flag_clone.clone())));

        let response = axum::http::Request::builder()
            .uri("/ready")
            .body(axum::body::Body::empty())
            .unwrap();

        let response = app.oneshot(response).await.unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );

        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "not_ready");
        assert_eq!(json["ready"], false);
    }

    #[tokio::test]
    async fn test_ready_endpoint_ready() {
        let ready_flag = Arc::new(AtomicBool::new(true));
        let flag_clone = ready_flag.clone();

        let app = Router::new().route("/ready", get(move || ready_handler(flag_clone.clone())));

        let response = axum::http::Request::builder()
            .uri("/ready")
            .body(axum::body::Body::empty())
            .unwrap();

        let response = app.oneshot(response).await.unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "ready");
        assert_eq!(json["ready"], true);
    }

    #[tokio::test]
    async fn test_metrics_endpoint() {
        let app = Router::new().route("/metrics", get(metrics_handler));

        let response = axum::http::Request::builder()
            .uri("/metrics")
            .body(axum::body::Body::empty())
            .unwrap();

        let response = app.oneshot(response).await.unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        // Check content type is Prometheus text format
        let content_type = response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(content_type.contains("text/plain"));

        // Body should be valid (even if empty metrics)
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        // Prometheus format is text-based, should be valid UTF-8
        let _text = std::str::from_utf8(&body).expect("Metrics should be valid UTF-8");
    }

    #[tokio::test]
    async fn test_set_ready_flag() {
        let ready_flag = Arc::new(AtomicBool::new(false));

        // Create a mock guard with the ready flag
        let guard = TelemetryGuard {
            tracer_provider: None,
            prometheus_handle: None,
            ready_flag: Some(ready_flag.clone()),
            sync_status: None,
            _appender_guard: None,
        };

        // Initially not ready
        assert!(!ready_flag.load(Ordering::SeqCst));

        // Set ready
        guard.set_ready(true);
        assert!(ready_flag.load(Ordering::SeqCst));

        // Set not ready
        guard.set_ready(false);
        assert!(!ready_flag.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_sync_status_endpoint() {
        use crate::sync::{SyncStateKind, SyncStatus};

        let sync_status = Arc::new(ArcSwap::new(Arc::new(SyncStatus {
            state: SyncStateKind::Syncing,
            current_height: 100,
            target_height: Some(200),
            blocks_behind: 100,
            sync_peers: 3,
            pending_fetches: 2,
            queued_heights: 98,
        })));

        let status_clone = sync_status.clone();
        let app = Router::new().route(
            "/system/sync-status",
            get(move || sync_status_handler(status_clone.clone())),
        );

        let response = axum::http::Request::builder()
            .uri("/system/sync-status")
            .body(axum::body::Body::empty())
            .unwrap();

        let response = app.oneshot(response).await.unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["state"], "syncing");
        assert_eq!(json["current_height"], 100);
        assert_eq!(json["target_height"], 200);
        assert_eq!(json["blocks_behind"], 100);
        assert_eq!(json["sync_peers"], 3);
    }
}
