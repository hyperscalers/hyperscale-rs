//! Metrics facade for Hyperscale.
//!
//! Provides a [`MetricsRecorder`] trait with domain-specific methods and default
//! no-op implementations. A global singleton recorder is accessed via [`recorder()`],
//! and convenience free functions delegate to it.
//!
//! # Usage
//!
//! Callers record metrics via free functions:
//! ```ignore
//! hyperscale_metrics::record_storage_read(latency_secs);
//! hyperscale_metrics::record_block_committed(height, latency_secs);
//! ```
//!
//! At startup, install a backend:
//! ```ignore
//! // Production:
//! hyperscale_metrics_prometheus::install();
//!
//! // Simulation (optional — defaults to no-op):
//! hyperscale_metrics_noop::install();
//! ```

use std::sync::OnceLock;

// ═══════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════

/// Channel depth statistics for the event loop.
#[derive(Debug, Default, Clone)]
pub struct ChannelDepths {
    /// Callback channel (crypto/execution results).
    pub callback: usize,
    /// Consensus channel (BFT network messages).
    pub consensus: usize,
    /// Validated transactions channel.
    pub validated_tx: usize,
    /// RPC transaction submissions channel.
    pub rpc_tx: usize,
    /// Status updates channel.
    pub status: usize,
    /// Inbound sync request channel.
    pub sync_request: usize,
    /// Inbound transaction fetch request channel.
    pub tx_request: usize,
    /// Inbound certificate fetch request channel.
    pub cert_request: usize,
}

// ═══════════════════════════════════════════════════════════════════════
// Trait
// ═══════════════════════════════════════════════════════════════════════

/// Domain-specific metrics recording trait.
///
/// All methods have default no-op implementations so backends only need
/// to override the metrics they care about.
#[allow(unused_variables)]
pub trait MetricsRecorder: Send + Sync + 'static {
    // ── Storage ──────────────────────────────────────────────────────

    /// Record a storage read latency.
    fn record_storage_read(&self, latency_secs: f64) {}

    /// Record a storage write latency.
    fn record_storage_write(&self, latency_secs: f64) {}

    /// Record a named storage operation latency.
    fn record_storage_operation(&self, operation: &str, latency_secs: f64) {}

    /// Record the size of an atomic write batch.
    fn record_storage_batch_size(&self, size: usize) {}

    /// Record a block persisted to storage.
    fn record_block_persisted(&self) {}

    /// Record a certificate persisted to storage.
    fn record_certificate_persisted(&self) {}

    /// Record a vote persisted to storage.
    fn record_vote_persisted(&self) {}

    /// Record transactions persisted to storage.
    fn record_transactions_persisted(&self, count: usize) {}

    // ── Consensus ────────────────────────────────────────────────────

    /// Record a block committed.
    fn record_block_committed(&self, height: u64, commit_latency_secs: f64) {}

    /// Record a transaction finalized.
    fn record_transaction_finalized(&self, latency_secs: f64, cross_shard: bool) {}

    /// Set the current block height gauge.
    fn set_block_height(&self, height: u64) {}

    /// Set the current BFT round gauge.
    fn set_bft_round(&self, round: u64) {}

    /// Set the view changes gauge.
    fn set_view_changes(&self, count: u64) {}

    /// Set the mempool size gauge.
    fn set_mempool_size(&self, size: usize) {}

    /// Set the in-flight transaction count gauge.
    fn set_in_flight(&self, count: usize) {}

    /// Set whether backpressure is active.
    fn set_backpressure_active(&self, active: bool) {}

    /// Set count of TXs with commitment proofs.
    fn set_txs_with_commitment_proof(&self, count: usize) {}

    // ── Infrastructure ───────────────────────────────────────────────

    /// Set thread pool queue depths.
    fn set_pool_queue_depths(
        &self,
        consensus_crypto: usize,
        crypto: usize,
        tx_validation: usize,
        execution: usize,
    ) {
    }

    /// Set event channel depths.
    fn set_channel_depths(&self, depths: &ChannelDepths) {}

    /// Record execution latency.
    fn record_execution_latency(&self, latency_secs: f64) {}

    /// Record speculative execution latency.
    fn record_speculative_execution_latency(&self, latency_secs: f64) {}

    /// Record speculative executions started.
    fn record_speculative_execution_started(&self, count: u64) {}

    /// Record speculative execution cache hits.
    fn record_speculative_execution_cache_hit(&self, count: u64) {}

    /// Record speculative execution late hits.
    fn record_speculative_execution_late_hit(&self, count: u64) {}

    /// Record speculative execution cache misses.
    fn record_speculative_execution_cache_miss(&self, count: u64) {}

    /// Record speculative executions invalidated.
    fn record_speculative_execution_invalidated(&self, count: u64) {}

    /// Record signature verification latency by type.
    fn record_signature_verification_latency(&self, sig_type: &str, latency_secs: f64) {}

    /// Record a signature verification failure.
    fn record_signature_verification_failure(&self) {}

    // ── Network ──────────────────────────────────────────────────────

    /// Record a network message sent.
    fn record_network_message_sent(&self) {}

    /// Record a network message received.
    fn record_network_message_received(&self) {}

    /// Set the libp2p peer count gauge.
    fn set_libp2p_peers(&self, count: usize) {}

    /// Record libp2p bandwidth.
    fn record_libp2p_bandwidth(&self, bytes_in: u64, bytes_out: u64) {}

    /// Record pending response channels count.
    fn record_pending_response_channels(&self, count: usize) {}

    /// Record a network event loop panic.
    fn record_network_event_loop_panic(&self) {}

    /// Record a gossipsub publish failure.
    fn record_gossipsub_publish_failure(&self, topic: &str) {}

    /// Record a network request retry.
    fn record_request_retry(&self, request_type: &str) {}

    /// Increment dispatch failure counter.
    fn increment_dispatch_failures(&self, message_type: &str) {}

    /// Record a broadcast failure.
    fn record_broadcast_failure(&self) {}

    /// Record a broadcast retry success.
    fn record_broadcast_retry_success(&self) {}

    /// Record a broadcast message dropped.
    fn record_broadcast_message_dropped(&self) {}

    /// Set the broadcast retry queue size gauge.
    fn set_broadcast_retry_queue_size(&self, size: usize) {}

    /// Record a backpressure event.
    fn record_backpressure_event(&self, source: &str) {}

    /// Set pending gossiped cert batch size gauge.
    fn set_pending_gossiped_cert_batch_size(&self, size: usize) {}

    /// Record an early arrival eviction.
    fn record_early_arrival_eviction(&self) {}

    // ── Sync ─────────────────────────────────────────────────────────

    /// Set sync status gauges.
    fn set_sync_status(&self, blocks_behind: u64, in_progress: bool) {}

    /// Record a sync block downloaded.
    fn record_sync_block_downloaded(&self) {}

    /// Record a sync block received by BFT.
    fn record_sync_block_received_by_bft(&self) {}

    /// Record a sync block submitted for verification.
    fn record_sync_block_submitted_for_verification(&self) {}

    /// Record a sync block buffered.
    fn record_sync_block_buffered(&self) {}

    /// Record a sync block filtered out.
    fn record_sync_block_filtered(&self, reason: &str) {}

    /// Record a sync block verified.
    fn record_sync_block_verified(&self) {}

    /// Record a sync block applied.
    fn record_sync_block_applied(&self) {}

    /// Record a sync response error.
    fn record_sync_response_error(&self, error_type: &str) {}

    /// Record a sync peer banned.
    fn record_sync_peer_banned(&self) {}

    // ── Fetch ────────────────────────────────────────────────────────

    /// Record a fetch operation started.
    fn record_fetch_started(&self, kind: &str) {}

    /// Record a fetch operation completed.
    fn record_fetch_completed(&self, kind: &str) {}

    /// Record a fetch operation failed.
    fn record_fetch_failed(&self, kind: &str) {}

    /// Record items received via fetch.
    fn record_fetch_items_received(&self, kind: &str, count: usize) {}

    /// Record fetch operation latency.
    fn record_fetch_latency(&self, kind: &str, latency_secs: f64) {}

    /// Set the fetch in-flight gauge.
    fn set_fetch_in_flight(&self, count: usize) {}

    /// Record items sent in response to a fetch request.
    fn record_fetch_response_sent(&self, kind: &str, count: usize) {}

    // ── Transaction Ingress ──────────────────────────────────────────

    /// Record a transaction rejected because node is syncing.
    fn record_tx_ingress_rejected_syncing(&self) {}

    /// Record a transaction rejected because pending count is too high.
    fn record_tx_ingress_rejected_pending_limit(&self) {}

    /// Record a transaction rejected with reason.
    fn record_transaction_rejected(&self, reason: &str) {}

    /// Record an invalid message received.
    fn record_invalid_message(&self) {}

    // ── Livelock ─────────────────────────────────────────────────────

    /// Record a livelock cycle detected.
    fn record_livelock_cycle_detected(&self) {}

    /// Record a livelock deferral.
    fn record_livelock_deferral(&self) {}

    /// Set the livelock deferred count gauge.
    fn set_livelock_deferred_count(&self, count: usize) {}

    // ── Lock Contention ──────────────────────────────────────────────

    /// Set lock contention metrics.
    fn set_lock_contention(&self, deferred: u64, ratio: f64) {}
}

// ═══════════════════════════════════════════════════════════════════════
// Global singleton
// ═══════════════════════════════════════════════════════════════════════

struct NoopRecorder;
impl MetricsRecorder for NoopRecorder {}

static RECORDER: OnceLock<Box<dyn MetricsRecorder>> = OnceLock::new();

/// Install a global metrics recorder.
///
/// Can only be called once. Subsequent calls are silently ignored.
pub fn set_global_recorder(recorder: Box<dyn MetricsRecorder>) {
    let _ = RECORDER.set(recorder);
}

/// Get the global metrics recorder.
///
/// Returns a no-op recorder if none has been installed.
#[inline]
fn recorder() -> &'static dyn MetricsRecorder {
    RECORDER.get().map(|r| r.as_ref()).unwrap_or(&NoopRecorder)
}

// ═══════════════════════════════════════════════════════════════════════
// Convenience free functions
// ═══════════════════════════════════════════════════════════════════════

// ── Storage ──────────────────────────────────────────────────────────

/// Record a storage read latency.
#[inline]
pub fn record_storage_read(latency_secs: f64) {
    recorder().record_storage_read(latency_secs);
}

/// Record a storage write latency.
#[inline]
pub fn record_storage_write(latency_secs: f64) {
    recorder().record_storage_write(latency_secs);
}

/// Record a named storage operation latency.
#[inline]
pub fn record_storage_operation(operation: &str, latency_secs: f64) {
    recorder().record_storage_operation(operation, latency_secs);
}

/// Record the size of an atomic write batch.
#[inline]
pub fn record_storage_batch_size(size: usize) {
    recorder().record_storage_batch_size(size);
}

/// Record a block persisted to storage.
#[inline]
pub fn record_block_persisted() {
    recorder().record_block_persisted();
}

/// Record a certificate persisted to storage.
#[inline]
pub fn record_certificate_persisted() {
    recorder().record_certificate_persisted();
}

/// Record a vote persisted to storage.
#[inline]
pub fn record_vote_persisted() {
    recorder().record_vote_persisted();
}

/// Record transactions persisted to storage.
#[inline]
pub fn record_transactions_persisted(count: usize) {
    recorder().record_transactions_persisted(count);
}

// ── Consensus ────────────────────────────────────────────────────────

/// Record a block committed.
#[inline]
pub fn record_block_committed(height: u64, commit_latency_secs: f64) {
    recorder().record_block_committed(height, commit_latency_secs);
}

/// Record a transaction finalized.
#[inline]
pub fn record_transaction_finalized(latency_secs: f64, cross_shard: bool) {
    recorder().record_transaction_finalized(latency_secs, cross_shard);
}

/// Set the current block height gauge.
#[inline]
pub fn set_block_height(height: u64) {
    recorder().set_block_height(height);
}

/// Set the current BFT round gauge.
#[inline]
pub fn set_bft_round(round: u64) {
    recorder().set_bft_round(round);
}

/// Set the view changes gauge.
#[inline]
pub fn set_view_changes(count: u64) {
    recorder().set_view_changes(count);
}

/// Set the mempool size gauge.
#[inline]
pub fn set_mempool_size(size: usize) {
    recorder().set_mempool_size(size);
}

/// Set the in-flight transaction count gauge.
#[inline]
pub fn set_in_flight(count: usize) {
    recorder().set_in_flight(count);
}

/// Set whether backpressure is active.
#[inline]
pub fn set_backpressure_active(active: bool) {
    recorder().set_backpressure_active(active);
}

/// Set count of TXs with commitment proofs.
#[inline]
pub fn set_txs_with_commitment_proof(count: usize) {
    recorder().set_txs_with_commitment_proof(count);
}

// ── Infrastructure ───────────────────────────────────────────────────

/// Set thread pool queue depths.
#[inline]
pub fn set_pool_queue_depths(
    consensus_crypto: usize,
    crypto: usize,
    tx_validation: usize,
    execution: usize,
) {
    recorder().set_pool_queue_depths(consensus_crypto, crypto, tx_validation, execution);
}

/// Set event channel depths.
#[inline]
pub fn set_channel_depths(depths: &ChannelDepths) {
    recorder().set_channel_depths(depths);
}

/// Record execution latency.
#[inline]
pub fn record_execution_latency(latency_secs: f64) {
    recorder().record_execution_latency(latency_secs);
}

/// Record speculative execution latency.
#[inline]
pub fn record_speculative_execution_latency(latency_secs: f64) {
    recorder().record_speculative_execution_latency(latency_secs);
}

/// Record speculative executions started.
#[inline]
pub fn record_speculative_execution_started(count: u64) {
    recorder().record_speculative_execution_started(count);
}

/// Record speculative execution cache hits.
#[inline]
pub fn record_speculative_execution_cache_hit(count: u64) {
    recorder().record_speculative_execution_cache_hit(count);
}

/// Record speculative execution late hits.
#[inline]
pub fn record_speculative_execution_late_hit(count: u64) {
    recorder().record_speculative_execution_late_hit(count);
}

/// Record speculative execution cache misses.
#[inline]
pub fn record_speculative_execution_cache_miss(count: u64) {
    recorder().record_speculative_execution_cache_miss(count);
}

/// Record speculative executions invalidated.
#[inline]
pub fn record_speculative_execution_invalidated(count: u64) {
    recorder().record_speculative_execution_invalidated(count);
}

/// Record signature verification latency by type.
#[inline]
pub fn record_signature_verification_latency(sig_type: &str, latency_secs: f64) {
    recorder().record_signature_verification_latency(sig_type, latency_secs);
}

/// Record a signature verification failure.
#[inline]
pub fn record_signature_verification_failure() {
    recorder().record_signature_verification_failure();
}

// ── Network ──────────────────────────────────────────────────────────

/// Record a network message sent.
#[inline]
pub fn record_network_message_sent() {
    recorder().record_network_message_sent();
}

/// Record a network message received.
#[inline]
pub fn record_network_message_received() {
    recorder().record_network_message_received();
}

/// Set the libp2p peer count gauge.
#[inline]
pub fn set_libp2p_peers(count: usize) {
    recorder().set_libp2p_peers(count);
}

/// Record libp2p bandwidth.
#[inline]
pub fn record_libp2p_bandwidth(bytes_in: u64, bytes_out: u64) {
    recorder().record_libp2p_bandwidth(bytes_in, bytes_out);
}

/// Record pending response channels count.
#[inline]
pub fn record_pending_response_channels(count: usize) {
    recorder().record_pending_response_channels(count);
}

/// Record a network event loop panic.
#[inline]
pub fn record_network_event_loop_panic() {
    recorder().record_network_event_loop_panic();
}

/// Record a gossipsub publish failure.
#[inline]
pub fn record_gossipsub_publish_failure(topic: &str) {
    recorder().record_gossipsub_publish_failure(topic);
}

/// Record a network request retry.
#[inline]
pub fn record_request_retry(request_type: &str) {
    recorder().record_request_retry(request_type);
}

/// Increment dispatch failure counter.
#[inline]
pub fn increment_dispatch_failures(message_type: &str) {
    recorder().increment_dispatch_failures(message_type);
}

/// Record a broadcast failure.
#[inline]
pub fn record_broadcast_failure() {
    recorder().record_broadcast_failure();
}

/// Record a broadcast retry success.
#[inline]
pub fn record_broadcast_retry_success() {
    recorder().record_broadcast_retry_success();
}

/// Record a broadcast message dropped.
#[inline]
pub fn record_broadcast_message_dropped() {
    recorder().record_broadcast_message_dropped();
}

/// Set the broadcast retry queue size gauge.
#[inline]
pub fn set_broadcast_retry_queue_size(size: usize) {
    recorder().set_broadcast_retry_queue_size(size);
}

/// Record a backpressure event.
#[inline]
pub fn record_backpressure_event(source: &str) {
    recorder().record_backpressure_event(source);
}

/// Set pending gossiped cert batch size gauge.
#[inline]
pub fn set_pending_gossiped_cert_batch_size(size: usize) {
    recorder().set_pending_gossiped_cert_batch_size(size);
}

/// Record an early arrival eviction.
#[inline]
pub fn record_early_arrival_eviction() {
    recorder().record_early_arrival_eviction();
}

// ── Sync ─────────────────────────────────────────────────────────────

/// Set sync status gauges.
#[inline]
pub fn set_sync_status(blocks_behind: u64, in_progress: bool) {
    recorder().set_sync_status(blocks_behind, in_progress);
}

/// Record a sync block downloaded.
#[inline]
pub fn record_sync_block_downloaded() {
    recorder().record_sync_block_downloaded();
}

/// Record a sync block received by BFT.
#[inline]
pub fn record_sync_block_received_by_bft() {
    recorder().record_sync_block_received_by_bft();
}

/// Record a sync block submitted for verification.
#[inline]
pub fn record_sync_block_submitted_for_verification() {
    recorder().record_sync_block_submitted_for_verification();
}

/// Record a sync block buffered.
#[inline]
pub fn record_sync_block_buffered() {
    recorder().record_sync_block_buffered();
}

/// Record a sync block filtered out.
#[inline]
pub fn record_sync_block_filtered(reason: &str) {
    recorder().record_sync_block_filtered(reason);
}

/// Record a sync block verified.
#[inline]
pub fn record_sync_block_verified() {
    recorder().record_sync_block_verified();
}

/// Record a sync block applied.
#[inline]
pub fn record_sync_block_applied() {
    recorder().record_sync_block_applied();
}

/// Record a sync response error.
#[inline]
pub fn record_sync_response_error(error_type: &str) {
    recorder().record_sync_response_error(error_type);
}

/// Record a sync peer banned.
#[inline]
pub fn record_sync_peer_banned() {
    recorder().record_sync_peer_banned();
}

// ── Fetch ────────────────────────────────────────────────────────────

/// Record a fetch operation started.
#[inline]
pub fn record_fetch_started(kind: &str) {
    recorder().record_fetch_started(kind);
}

/// Record a fetch operation completed.
#[inline]
pub fn record_fetch_completed(kind: &str) {
    recorder().record_fetch_completed(kind);
}

/// Record a fetch operation failed.
#[inline]
pub fn record_fetch_failed(kind: &str) {
    recorder().record_fetch_failed(kind);
}

/// Record items received via fetch.
#[inline]
pub fn record_fetch_items_received(kind: &str, count: usize) {
    recorder().record_fetch_items_received(kind, count);
}

/// Record fetch operation latency.
#[inline]
pub fn record_fetch_latency(kind: &str, latency_secs: f64) {
    recorder().record_fetch_latency(kind, latency_secs);
}

/// Set the fetch in-flight gauge.
#[inline]
pub fn set_fetch_in_flight(count: usize) {
    recorder().set_fetch_in_flight(count);
}

/// Record items sent in response to a fetch request.
#[inline]
pub fn record_fetch_response_sent(kind: &str, count: usize) {
    recorder().record_fetch_response_sent(kind, count);
}

// ── Transaction Ingress ──────────────────────────────────────────────

/// Record a transaction rejected because node is syncing.
#[inline]
pub fn record_tx_ingress_rejected_syncing() {
    recorder().record_tx_ingress_rejected_syncing();
}

/// Record a transaction rejected because pending count is too high.
#[inline]
pub fn record_tx_ingress_rejected_pending_limit() {
    recorder().record_tx_ingress_rejected_pending_limit();
}

/// Record a transaction rejected with reason.
#[inline]
pub fn record_transaction_rejected(reason: &str) {
    recorder().record_transaction_rejected(reason);
}

/// Record an invalid message received.
#[inline]
pub fn record_invalid_message() {
    recorder().record_invalid_message();
}

// ── Livelock ─────────────────────────────────────────────────────────

/// Record a livelock cycle detected.
#[inline]
pub fn record_livelock_cycle_detected() {
    recorder().record_livelock_cycle_detected();
}

/// Record a livelock deferral.
#[inline]
pub fn record_livelock_deferral() {
    recorder().record_livelock_deferral();
}

/// Set the livelock deferred count gauge.
#[inline]
pub fn set_livelock_deferred_count(count: usize) {
    recorder().set_livelock_deferred_count(count);
}

// ── Lock Contention ──────────────────────────────────────────────────

/// Set lock contention metrics.
#[inline]
pub fn set_lock_contention(deferred: u64, ratio: f64) {
    recorder().set_lock_contention(deferred, ratio);
}
