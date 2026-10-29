//! OpenTelemetry initialization and configuration.
//!
//! This module provides telemetry setup for distributed tracing and metrics.
//! The architecture instruments the production runner while preserving
//! state machine determinism.

use std::path::{Path, PathBuf};

use opentelemetry::KeyValue;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::{ExporterBuildError, SpanExporter, WithExportConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::error::OTelSdkError;
use opentelemetry_sdk::trace::{RandomIdGenerator, Sampler, SdkTracerProvider};
use opentelemetry_semantic_conventions::resource::{SERVICE_NAME, SERVICE_VERSION};
use thiserror::Error;
use tokio::task::spawn_blocking;
use tokio::time::timeout;
use tracing::subscriber::{SetGlobalDefaultError, set_global_default};
use tracing_appender::non_blocking as wrap_non_blocking;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::never;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::fmt::layer as fmt_layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{EnvFilter, Layer, Registry};

/// Errors that can occur while initialising telemetry.
#[derive(Debug, Error)]
pub enum TelemetryError {
    /// The OTLP exporter could not be constructed (e.g. invalid endpoint URL).
    #[error("Failed to build OTLP exporter: {0}")]
    ExporterBuild(#[from] ExporterBuildError),

    /// The `OpenTelemetry` SDK reported an internal error.
    #[error("OpenTelemetry SDK error: {0}")]
    OtelSdk(#[from] OTelSdkError),

    /// The global tracing subscriber was already set by another component.
    #[error("Failed to set global subscriber: {0}")]
    SetSubscriber(#[from] SetGlobalDefaultError),

    /// I/O error while preparing the log file.
    #[error("Failed to prepare the log file: {0}")]
    LogFile(#[from] std::io::Error),
}

/// Configuration for telemetry.
#[derive(Debug, Clone)]
pub struct TelemetryConfig {
    /// Service name for OTEL resource attributes.
    pub service_name: String,
    /// OTLP endpoint (e.g., <http://localhost:4317>).
    pub otlp_endpoint: Option<String>,
    /// Sampling ratio (0.0 to 1.0). Default: 1.0 (sample everything).
    pub sampling_ratio: f64,
    /// The log filter directives used when `RUST_LOG` is unset.
    pub default_filter: String,
    /// Additional resource attributes.
    pub resource_attributes: Vec<(String, String)>,
    /// Optional log file path. If provided, logs are written to this file instead of stdout.
    pub log_file: Option<PathBuf>,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            service_name: "hyperscale-node".to_string(),
            otlp_endpoint: None,
            sampling_ratio: 1.0,
            default_filter: "info,hyperscale=debug".to_string(),
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
///
/// # Errors
///
/// Returns [`TelemetryError`] if the OTLP exporter or tracer provider cannot be
/// constructed, the global tracing subscriber cannot be installed, or the log
/// directory cannot be created.
pub fn init_telemetry(config: &TelemetryConfig) -> Result<TelemetryGuard, TelemetryError> {
    // Build resource attributes
    let mut resource_attrs = vec![
        KeyValue::new(SERVICE_NAME, config.service_name.clone()),
        KeyValue::new(SERVICE_VERSION, env!("CARGO_PKG_VERSION")),
    ];

    for (key, value) in &config.resource_attributes {
        resource_attrs.push(KeyValue::new(key.clone(), value.clone()));
    }

    let resource = Resource::builder().with_attributes(resource_attrs).build();

    // Build the subscriber layers
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&config.default_filter));

    // Optional OTLP tracing layer
    let (otel_layer, tracer_provider) = if let Some(endpoint) = &config.otlp_endpoint {
        // Note: build() validates URL format but connection is lazy
        let exporter = SpanExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .build()?;

        let tracer_provider = SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .with_sampler(Sampler::TraceIdRatioBased(config.sampling_ratio))
            .with_id_generator(RandomIdGenerator::default())
            .with_resource(resource)
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
    let (fmt_layer, appender_guard) = if let Some(log_file) = &config.log_file {
        if let Some(parent) = log_file.parent() {
            std::fs::create_dir_all(parent).map_err(TelemetryError::LogFile)?;
        }
        let file_name = log_file
            .file_name()
            .ok_or_else(|| {
                TelemetryError::LogFile(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Invalid log file name",
                ))
            })?
            .to_string_lossy()
            .to_string();
        let directory = log_file
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();

        let file_appender = never(directory, file_name);
        let (non_blocking_writer, guard) = wrap_non_blocking(file_appender);

        let layer = fmt_layer()
            .with_writer(non_blocking_writer)
            .with_ansi(false) // Disable ANSI colors in file logs
            .with_target(true)
            .with_thread_ids(true);

        (layer.boxed(), Some(guard))
    } else {
        let layer = fmt_layer().with_target(true).with_thread_ids(true);
        (layer.boxed(), None)
    };

    // Initialize the subscriber
    let subscriber = Registry::default()
        .with(env_filter)
        .with(fmt_layer)
        .with(otel_layer);

    set_global_default(subscriber)?;

    Ok(TelemetryGuard {
        tracer_provider,
        _appender_guard: appender_guard,
    })
}

/// Guard that shuts down telemetry on drop.
///
/// For graceful shutdown with span flushing, call `shutdown().await` explicitly
/// before dropping. The `Drop` impl provides a fallback but cannot flush async.
pub struct TelemetryGuard {
    tracer_provider: Option<SdkTracerProvider>,
    /// Keeps the non-blocking log appender's worker running.
    _appender_guard: Option<WorkerGuard>,
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
            let _ = timeout(
                Duration::from_secs(5),
                spawn_blocking(move || {
                    let _ = provider.shutdown();
                }),
            )
            .await;
        }
    }
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        // Fallback shutdown - may lose pending spans if shutdown() wasn't called
        if let Some(provider) = self.tracer_provider.take() {
            let _ = provider.shutdown();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = TelemetryConfig::default();
        assert_eq!(config.service_name, "hyperscale-node");
        assert!(config.otlp_endpoint.is_none());
        assert!((config.sampling_ratio - 1.0).abs() < f64::EPSILON);
        assert_eq!(config.default_filter, "info,hyperscale=debug");
    }
}
