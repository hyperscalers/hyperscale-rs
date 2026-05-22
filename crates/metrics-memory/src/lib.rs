//! In-memory metrics backend for Hyperscale.
//!
//! Implements [`hyperscale_metrics::MetricsRecorder`] backed by an
//! `Arc<Mutex<_>>` map so tests and simulation harnesses can read recorded
//! values back. Counters, gauges, and histogram count/sum are stored per
//! `(metric_name, label)` key.
//!
//! # Usage
//!
//! ```ignore
//! let recorder = hyperscale_metrics_memory::MemoryRecorder::new();
//! hyperscale_metrics::set_global_recorder(Box::new(recorder.clone()));
//!
//! // ... run simulation ...
//!
//! assert!(recorder.counter("fetch_started", Some("transaction")) >= 1);
//! ```
//!
//! Methods that aren't currently overridden inherit the trait's no-op
//! defaults; add overrides as new test assertions need them.

#![allow(clippy::cast_precision_loss)]

use std::collections::BTreeMap;
use std::sync::Arc;

use hyperscale_metrics::MetricsRecorder;
use parking_lot::Mutex;

/// Metric storage key: `(name, optional single label value)`.
///
/// Hyperscale's metrics either have no labels or a single label (`kind`,
/// `source`, `reason`, etc.), so a single optional label is sufficient.
type Key = (&'static str, Option<String>);

#[derive(Default, Debug)]
struct Inner {
    counters: BTreeMap<Key, u64>,
    gauges: BTreeMap<Key, f64>,
    histogram_count: BTreeMap<Key, u64>,
    histogram_sum: BTreeMap<Key, f64>,
}

/// In-memory metrics recorder. Cheaply cloneable; clones share state.
#[derive(Clone, Default)]
pub struct MemoryRecorder {
    inner: Arc<Mutex<Inner>>,
}

impl MemoryRecorder {
    /// Create a new recorder with empty state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Read a counter value. Returns 0 if the metric has not been recorded.
    #[must_use]
    pub fn counter(&self, name: &'static str, label: Option<&str>) -> u64 {
        let key = (name, label.map(str::to_owned));
        self.inner.lock().counters.get(&key).copied().unwrap_or(0)
    }

    /// Read a gauge value. Returns 0.0 if the metric has not been recorded.
    #[must_use]
    pub fn gauge(&self, name: &'static str, label: Option<&str>) -> f64 {
        let key = (name, label.map(str::to_owned));
        self.inner.lock().gauges.get(&key).copied().unwrap_or(0.0)
    }

    /// Read a histogram observation count.
    #[must_use]
    pub fn histogram_count(&self, name: &'static str, label: Option<&str>) -> u64 {
        let key = (name, label.map(str::to_owned));
        self.inner
            .lock()
            .histogram_count
            .get(&key)
            .copied()
            .unwrap_or(0)
    }

    /// Read a histogram observation sum.
    #[must_use]
    pub fn histogram_sum(&self, name: &'static str, label: Option<&str>) -> f64 {
        let key = (name, label.map(str::to_owned));
        self.inner
            .lock()
            .histogram_sum
            .get(&key)
            .copied()
            .unwrap_or(0.0)
    }

    /// Drop all recorded values.
    pub fn reset(&self) {
        let mut inner = self.inner.lock();
        inner.counters.clear();
        inner.gauges.clear();
        inner.histogram_count.clear();
        inner.histogram_sum.clear();
    }

    /// Snapshot all recorded values for debugging or golden-file output.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        let inner = self.inner.lock();
        Snapshot {
            counters: inner.counters.clone(),
            gauges: inner.gauges.clone(),
            histogram_count: inner.histogram_count.clone(),
            histogram_sum: inner.histogram_sum.clone(),
        }
    }

    fn inc(&self, name: &'static str, label: Option<&str>, by: u64) {
        let key = (name, label.map(str::to_owned));
        *self.inner.lock().counters.entry(key).or_insert(0) += by;
    }

    fn set(&self, name: &'static str, label: Option<&str>, value: f64) {
        let key = (name, label.map(str::to_owned));
        self.inner.lock().gauges.insert(key, value);
    }

    fn observe(&self, name: &'static str, label: Option<&str>, value: f64) {
        let key = (name, label.map(str::to_owned));
        let mut inner = self.inner.lock();
        *inner.histogram_count.entry(key.clone()).or_insert(0) += 1;
        *inner.histogram_sum.entry(key).or_insert(0.0) += value;
    }
}

/// Read-only snapshot of all recorded metrics.
#[derive(Debug, Clone, Default)]
#[allow(missing_docs)] // each map's name is its documentation
pub struct Snapshot {
    pub counters: BTreeMap<Key, u64>,
    pub gauges: BTreeMap<Key, f64>,
    pub histogram_count: BTreeMap<Key, u64>,
    pub histogram_sum: BTreeMap<Key, f64>,
}

impl MetricsRecorder for MemoryRecorder {
    // ── Storage ──────────────────────────────────────────────────────

    fn record_storage_read(&self, latency_secs: f64) {
        self.observe("storage_read_latency", None, latency_secs);
    }

    fn record_storage_write(&self, latency_secs: f64) {
        self.observe("storage_write_latency", None, latency_secs);
    }

    fn record_storage_operation(&self, operation: &str, latency_secs: f64) {
        self.observe("storage_operation_latency", Some(operation), latency_secs);
    }

    fn record_block_persisted(&self) {
        self.inc("blocks_persisted", None, 1);
    }

    fn record_certificate_persisted(&self) {
        self.inc("certificates_persisted", None, 1);
    }

    fn record_transactions_persisted(&self, count: usize) {
        self.inc("transactions_persisted", None, count as u64);
    }

    // ── Consensus ────────────────────────────────────────────────────

    fn record_block_committed(&self, shard: u64, commit_latency_secs: f64, source: &str) {
        self.inc("blocks_committed", Some(&shard.to_string()), 1);
        self.observe("block_commit_latency", Some(source), commit_latency_secs);
    }

    fn record_transaction_finalized(&self, latency_secs: f64, cross_shard: bool) {
        let label = if cross_shard { "true" } else { "false" };
        self.observe("transaction_latency", Some(label), latency_secs);
    }

    fn set_block_height(&self, shard: u64, height: u64) {
        self.set("block_height", Some(&shard.to_string()), height as f64);
    }

    fn set_shard_round(&self, shard: u64, validator_id: u64, round: u64) {
        self.set(
            "shard_round",
            Some(&format!("{shard}:{validator_id}")),
            round as f64,
        );
    }

    fn set_view_changes(&self, shard: u64, validator_id: u64, count: u64) {
        self.set(
            "view_changes",
            Some(&format!("{shard}:{validator_id}")),
            count as f64,
        );
    }

    fn set_view_syncs(&self, shard: u64, validator_id: u64, count: u64) {
        self.set(
            "view_syncs",
            Some(&format!("{shard}:{validator_id}")),
            count as f64,
        );
    }

    fn set_mempool_size(&self, shard: u64, validator_id: u64, size: usize) {
        self.set(
            "mempool_size",
            Some(&format!("{shard}:{validator_id}")),
            size as f64,
        );
    }

    // ── Network ──────────────────────────────────────────────────────

    fn record_network_message_sent(&self) {
        self.inc("network_messages_sent", None, 1);
    }

    fn record_network_message_received(&self) {
        self.inc("network_messages_received", None, 1);
    }

    fn record_request_retry(&self, request_type: &str) {
        self.inc("network_request_retries", Some(request_type), 1);
    }

    fn increment_dispatch_failures(&self, message_type: &str) {
        self.inc("dispatch_failures", Some(message_type), 1);
    }

    fn record_broadcast_failure(&self) {
        self.inc("broadcast_failures", None, 1);
    }

    fn record_broadcast_retry_success(&self) {
        self.inc("broadcast_retry_successes", None, 1);
    }

    fn record_broadcast_message_dropped(&self) {
        self.inc("broadcast_messages_dropped", None, 1);
    }

    fn record_early_arrival_eviction(&self) {
        self.inc("early_arrival_evictions", None, 1);
    }

    // ── Sync ─────────────────────────────────────────────────────────

    fn set_sync_blocks_behind(&self, kind: &str, shard: u64, blocks_behind: u64) {
        self.set(
            "sync_blocks_behind",
            Some(&format!("{kind}:{shard}")),
            blocks_behind as f64,
        );
    }

    fn set_sync_in_progress(&self, kind: &str, shard: u64, in_progress: bool) {
        self.set(
            "sync_in_progress",
            Some(&format!("{kind}:{shard}")),
            if in_progress { 1.0 } else { 0.0 },
        );
    }

    fn record_sync_block_filtered(&self, kind: &str, reason: &str) {
        // Memory backend stores a single string label; concatenate.
        self.inc("sync_blocks_filtered", Some(&format!("{kind}:{reason}")), 1);
    }

    fn record_sync_response_error(&self, kind: &str, error_type: &str) {
        self.inc(
            "sync_response_errors",
            Some(&format!("{kind}:{error_type}")),
            1,
        );
    }

    fn record_sync_round_started(&self, kind: &str) {
        self.inc("sync_round_started", Some(kind), 1);
    }

    fn record_sync_round_completed(&self, kind: &str) {
        self.inc("sync_round_completed", Some(kind), 1);
    }

    fn record_sync_round_retried(&self, kind: &str) {
        self.inc("sync_round_retried", Some(kind), 1);
    }

    fn set_sync_round_in_flight(&self, kind: &str, shard: u64, count: usize) {
        self.set(
            "sync_round_in_flight",
            Some(&format!("{kind}:{shard}")),
            count as f64,
        );
    }

    // ── Fetch ────────────────────────────────────────────────────────

    fn record_fetch_started(&self, kind: &str) {
        self.inc("fetch_started", Some(kind), 1);
    }

    fn record_fetch_completed(&self, kind: &str) {
        self.inc("fetch_completed", Some(kind), 1);
    }

    fn record_fetch_abandoned(&self, kind: &str) {
        self.inc("fetch_abandoned", Some(kind), 1);
    }

    fn record_fetch_retried(&self, kind: &str) {
        self.inc("fetch_retried", Some(kind), 1);
    }

    fn record_fetch_items_received(&self, kind: &str, count: usize) {
        self.inc("fetch_items_received", Some(kind), count as u64);
    }

    fn record_fetch_latency(&self, kind: &str, latency_secs: f64) {
        self.observe("fetch_latency", Some(kind), latency_secs);
    }

    fn set_fetch_in_flight(&self, kind: &str, shard: u64, count: usize) {
        self.set(
            "fetch_in_flight",
            Some(&format!("{kind}:{shard}")),
            count as f64,
        );
    }

    fn record_fetch_response_sent(&self, kind: &str, count: usize) {
        self.inc("fetch_items_sent", Some(kind), count as u64);
    }

    // ── Transaction Ingress ──────────────────────────────────────────

    fn record_tx_ingress_rejected_syncing(&self) {
        self.inc("tx_ingress_rejected_syncing", None, 1);
    }

    fn record_tx_ingress_rejected_pending_limit(&self) {
        self.inc("tx_ingress_rejected_pending_limit", None, 1);
    }

    fn record_transaction_rejected(&self, reason: &str) {
        self.inc("transactions_rejected", Some(reason), 1);
    }

    fn record_invalid_message(&self) {
        self.inc("invalid_messages", None, 1);
    }

    // ── Aborted Transactions ─────────────────────────────────────────

    fn record_transaction_aborted(&self) {
        self.inc("transactions_aborted", None, 1);
    }

    fn record_expected_tx_dropped(&self) {
        self.inc("expected_tx_dropped", None, 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_starts_at_zero_and_increments() {
        let r = MemoryRecorder::new();
        assert_eq!(r.counter("fetch_started", Some("transaction")), 0);
        r.record_fetch_started("transaction");
        r.record_fetch_started("transaction");
        r.record_fetch_started("provision");
        assert_eq!(r.counter("fetch_started", Some("transaction")), 2);
        assert_eq!(r.counter("fetch_started", Some("provision")), 1);
    }

    #[test]
    fn gauge_overwrites() {
        let r = MemoryRecorder::new();
        r.set_block_height(0, 5);
        r.set_block_height(0, 10);
        assert!((r.gauge("block_height", Some("0")) - 10.0).abs() < f64::EPSILON);
    }

    #[test]
    fn histogram_accumulates_count_and_sum() {
        let r = MemoryRecorder::new();
        r.record_fetch_latency("transaction", 0.1);
        r.record_fetch_latency("transaction", 0.3);
        assert_eq!(r.histogram_count("fetch_latency", Some("transaction")), 2);
        assert!((r.histogram_sum("fetch_latency", Some("transaction")) - 0.4).abs() < 1e-9);
    }

    #[test]
    fn block_committed_updates_counter_and_histogram() {
        let r = MemoryRecorder::new();
        r.record_block_committed(0, 0.05, "qc");
        assert_eq!(r.counter("blocks_committed", Some("0")), 1);
        assert_eq!(r.histogram_count("block_commit_latency", Some("qc")), 1);
    }

    #[test]
    fn reset_clears_state() {
        let r = MemoryRecorder::new();
        r.record_fetch_started("transaction");
        r.set_block_height(0, 7);
        r.reset();
        assert_eq!(r.counter("fetch_started", Some("transaction")), 0);
        assert!((r.gauge("block_height", Some("0")) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn clones_share_state() {
        let r = MemoryRecorder::new();
        let r2 = r.clone();
        r.record_fetch_started("transaction");
        assert_eq!(r2.counter("fetch_started", Some("transaction")), 1);
    }
}
