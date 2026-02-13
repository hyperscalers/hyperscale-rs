//! No-op metrics recorder.
//!
//! Installs a recorder that silently discards all metrics.
//! This is the default behavior when no recorder is installed,
//! but can be explicitly installed for clarity.

/// A metrics recorder that does nothing.
pub struct NoopRecorder;

impl hyperscale_metrics::MetricsRecorder for NoopRecorder {}

/// Install the no-op recorder as the global metrics backend.
pub fn install() {
    hyperscale_metrics::set_global_recorder(Box::new(NoopRecorder));
}
