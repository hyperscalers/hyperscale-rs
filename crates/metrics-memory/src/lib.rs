//! In-memory metrics backend for Hyperscale.
//!
//! Implements [`hyperscale_metrics::MetricsRecorder`] backed by an
//! `Arc<Mutex<_>>` map so tests and simulation harnesses can read recorded
//! values back. Counters, gauges, and histogram count/sum are stored per
//! `(metric_name, label)` key, and each histogram's observations in
//! log-linear buckets, so a quantile reads within an eighth of its value
//! in memory bounded by the value range rather than the run's length.
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
    histogram_buckets: BTreeMap<Key, BTreeMap<u16, u64>>,
}

/// The bucket a histogram observation falls in: a positive value's
/// exponent and top three mantissa bits, so buckets order as the values
/// do and each spans an eighth of its lower edge. Zero and below share
/// the lowest.
fn bucket_of(value: f64) -> u16 {
    if value > 0.0 {
        u16::try_from(value.to_bits() >> 49).expect("a positive double's top fifteen bits")
    } else {
        0
    }
}

/// The lower edge of `bucket`; the lowest, which holds zero and below,
/// reaches down to the least double.
fn bucket_floor(bucket: u16) -> f64 {
    if bucket == 0 {
        f64::MIN
    } else {
        f64::from_bits(u64::from(bucket) << 49)
    }
}

/// The upper edge of `bucket`; zero for the lowest, which holds zero.
fn bucket_ceiling(bucket: u16) -> f64 {
    if bucket == 0 {
        0.0
    } else {
        f64::from_bits((u64::from(bucket) + 1) << 49)
    }
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

    /// Read a counter value. An unlabelled read of a labelled counter is
    /// the sum over its labels, the reading a `CounterVec` gives with no
    /// selector. Returns 0 if nothing has been recorded under `name`.
    #[must_use]
    pub fn counter(&self, name: &'static str, label: Option<&str>) -> u64 {
        let inner = self.inner.lock();
        label.map_or_else(
            || {
                inner
                    .counters
                    .range((name, None)..)
                    .take_while(|((entry, _), _)| *entry == name)
                    .map(|(_, count)| count)
                    .sum()
            },
            |label| {
                inner
                    .counters
                    .get(&(name, Some(label.to_owned())))
                    .copied()
                    .unwrap_or(0)
            },
        )
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

    /// The `q` quantile of a histogram's observations, as the upper edge
    /// of the bucket it falls in: never below the true quantile and at
    /// most an eighth above it. `None` if nothing has been observed.
    ///
    /// # Panics
    ///
    /// If `q` is outside `[0, 1]`.
    #[must_use]
    pub fn histogram_quantile(
        &self,
        name: &'static str,
        label: Option<&str>,
        q: f64,
    ) -> Option<f64> {
        self.histogram_quantile_above(name, label, q, f64::NEG_INFINITY)
    }

    /// [`Self::histogram_quantile`] over the observations whose bucket
    /// lies wholly above `floor`, so a floor of zero drops the zeros: the
    /// quantile of a histogram that records
    /// zero for most events among the events it measures.
    ///
    /// # Panics
    ///
    /// If `q` is outside `[0, 1]`.
    #[must_use]
    pub fn histogram_quantile_above(
        &self,
        name: &'static str,
        label: Option<&str>,
        q: f64,
        floor: f64,
    ) -> Option<f64> {
        assert!((0.0..=1.0).contains(&q), "a quantile lies in [0, 1]: {q}");
        let key = (name, label.map(str::to_owned));
        let mut buckets = self.inner.lock().histogram_buckets.get(&key)?.clone();
        buckets.retain(|bucket, _| bucket_floor(*bucket) > floor);
        if buckets.is_empty() {
            return None;
        }
        let rank = q * buckets.values().sum::<u64>() as f64;
        let mut seen = 0;
        buckets.iter().find_map(|(bucket, count)| {
            seen += count;
            (seen as f64 >= rank).then(|| bucket_ceiling(*bucket))
        })
    }

    /// Drop all recorded values.
    pub fn reset(&self) {
        let mut inner = self.inner.lock();
        inner.counters.clear();
        inner.gauges.clear();
        inner.histogram_count.clear();
        inner.histogram_sum.clear();
        inner.histogram_buckets.clear();
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
        *inner.histogram_sum.entry(key.clone()).or_insert(0.0) += value;
        *inner
            .histogram_buckets
            .entry(key)
            .or_default()
            .entry(bucket_of(value))
            .or_insert(0) += 1;
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

    fn record_transaction_executed(&self) {
        self.inc("transactions_executed", None, 1);
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

    fn record_unresolvable_tx(&self, cause: &str) {
        self.inc("unresolvable_txs", Some(cause), 1);
    }

    fn record_rebuilt_record_entry(&self) {
        self.inc("rebuilt_record_entries", None, 1);
    }

    fn record_reclaim_probe_answered(&self, present: bool) {
        let label = if present { "present" } else { "absent" };
        self.inc("reclaim_probes_answered", Some(label), 1);
    }

    fn record_reclaim_admitted(&self, from_leaf: bool) {
        let label = if from_leaf { "leaf" } else { "entry" };
        self.inc("reclaims_admitted", Some(label), 1);
    }

    fn record_reclaim_probe_pending(&self) {
        self.inc("reclaim_probes_pending", None, 1);
    }

    fn record_hold_contentions(&self, pairs: usize) {
        self.inc("hold_contentions", None, pairs as u64);
    }

    fn record_hold_inversions_proven(&self, victims: usize) {
        self.inc("hold_inversions_proven", None, victims as u64);
    }

    fn record_state_claims_weight(&self, bytes: usize) {
        self.observe("state_claims_weight", None, bytes as f64);
    }

    fn record_record_ask(&self) {
        self.inc("record_asks", None, 1);
    }

    fn record_crossing_fallback_ask(&self, asker: &str) {
        self.inc("crossing_fallback_asks", Some(asker), 1);
    }

    fn record_fenced_claim(&self, reading: &str, carried: bool) {
        let name = if carried {
            "fenced_claims_carried"
        } else {
            "fenced_claims_refused"
        };
        self.inc(name, Some(reading), 1);
    }

    fn record_crossing_push_dropped(&self, reason: &str) {
        self.inc("crossing_pushes_dropped", None, 1);
        self.inc("crossing_pushes_dropped", Some(reason), 1);
    }

    fn record_fetch_response_refused(&self, kind: &str, reason: &str) {
        self.inc("fetch_responses_refused", Some(kind), 1);
        self.inc(
            "fetch_responses_refused",
            Some(&format!("{kind}:{reason}")),
            1,
        );
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

    fn record_halt_recovery_offer_refused(&self) {
        self.inc("halt_recovery_offers_refused", None, 1);
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
    /// A quantile reads the upper edge of its bucket: at or above the
    /// true value and within an eighth of it, the maximum at `1.0`, and
    /// nothing before any observation. Above a floor of zero the zeros
    /// drop out.
    #[test]
    fn a_histogram_quantile_reads_within_an_eighth() {
        let recorder = MemoryRecorder::new();
        assert_eq!(recorder.histogram_quantile("weight", None, 0.99), None);
        for value in 1..=1_000 {
            recorder.observe("weight", None, f64::from(value));
        }
        for (q, truth) in [(0.5, 500.0), (0.99, 990.0), (1.0, 1_000.0)] {
            let read = recorder
                .histogram_quantile("weight", None, q)
                .expect("observed");
            assert!(
                read >= truth && read <= truth * 1.125,
                "q {q}: read {read} against {truth}",
            );
        }
        assert_eq!(
            recorder.histogram_quantile("weight", Some("other"), 0.5),
            None
        );

        for _ in 0..1_000 {
            recorder.observe("weight", None, 0.0);
        }
        assert_eq!(recorder.histogram_quantile("weight", None, 0.5), Some(0.0));
        let above = recorder
            .histogram_quantile_above("weight", None, 0.5, 0.0)
            .expect("observed above zero");
        assert!(
            (500.0..=562.5).contains(&above),
            "the zeros are not counted above the floor: {above}",
        );
        recorder.observe("empty", None, 0.0);
        assert_eq!(
            recorder.histogram_quantile_above("empty", None, 0.5, 0.0),
            None
        );
    }

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
    fn an_unlabelled_read_sums_a_labelled_counter() {
        let r = MemoryRecorder::new();
        r.record_reclaim_admitted(true);
        r.record_reclaim_admitted(false);
        assert_eq!(r.counter("reclaims_admitted", None), 2);
        assert_eq!(r.counter("reclaims_admitted", Some("leaf")), 1);
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
