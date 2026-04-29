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

use std::cell::RefCell;
use std::sync::{Arc, OnceLock};

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

/// Memory usage statistics for monitoring state machine growth.
///
/// All values are collection lengths (entry counts), not byte sizes,
/// unless the field name explicitly says `_bytes`.
#[derive(Debug, Default, Clone)]
pub struct MemoryMetrics {
    // ── BFT ──
    /// Blocks being assembled from headers + transactions.
    pub bft_pending_blocks: usize,
    /// Vote sets per block (unverified + verified votes).
    pub bft_vote_sets: usize,
    /// Blocks with QC but not yet committed.
    pub bft_certified_blocks: usize,
    /// Out-of-order commits buffered.
    pub bft_pending_commits: usize,
    /// Commits waiting for block data (header/txs).
    pub bft_pending_commits_awaiting_data: usize,
    /// Heights we have voted on (equivocation guard).
    pub bft_voted_heights: usize,
    /// Votes received per (height, validator) pair.
    pub bft_received_votes_by_height: usize,
    /// Committed transaction hash lookup.
    pub bft_committed_tx_lookup: usize,
    /// Recently committed transaction hashes (dedup window).
    pub bft_recently_committed_txs: usize,
    /// Recently committed certificate hashes (dedup window).
    pub bft_recently_committed_certs: usize,
    /// Block headers pending QC verification.
    pub bft_pending_qc_verifications: usize,
    /// Cache of verified QC signatures.
    pub bft_verified_qcs: usize,
    /// Blocks waiting for JMT to reach parent state.
    pub bft_pending_state_root_verifications: usize,
    /// Out-of-order synced blocks.
    pub bft_buffered_synced_blocks: usize,
    /// Synced blocks pending QC verification.
    pub bft_pending_synced_block_verifications: usize,

    // ── Execution ──
    /// In-memory write sets per transaction.
    pub exec_cache_entries: usize,
    /// Wave certificates ready for block inclusion.
    pub exec_finalized_wave_certificates: usize,
    /// Active wave states (per-wave execution + finalization tracking).
    pub exec_waves: usize,
    /// Execution votes collection per wave.
    pub exec_vote_trackers: usize,
    /// Votes that arrived before tracking started.
    pub exec_early_votes: usize,
    /// Expected execution certificates from remote shards.
    pub exec_expected_exec_certs: usize,
    /// Verified state provisions per transaction.
    pub exec_verified_provisions: usize,
    /// Required provision shards per transaction.
    pub exec_required_provision_shards: usize,
    /// Received provision shards per transaction.
    pub exec_received_provision_shards: usize,
    /// Waves that have produced an execution certificate.
    pub exec_waves_with_ec: usize,
    /// Waves with pending vote retries.
    pub exec_pending_vote_retries: usize,
    /// Transaction to wave assignment mapping.
    pub exec_wave_assignments: usize,
    /// Wave attestations that arrived before tracking.
    pub exec_early_wave_attestations: usize,
    /// Buffered ECs awaiting full routing to local wave trackers.
    pub exec_pending_routing: usize,
    /// Fulfilled execution certificates from remote shards.
    pub exec_fulfilled_exec_certs: usize,
    /// Outbound ECs awaiting wave finalization (re-broadcast tracker).
    pub exec_outbound_certs: usize,

    // ── Mempool ──
    /// All transactions in the pool.
    pub mempool_pool: usize,
    /// Ready transactions (no node conflicts).
    pub mempool_ready: usize,
    /// Terminal state transactions (for dedup).
    pub mempool_tombstones: usize,
    /// Evicted transactions (for peer fetch).
    pub mempool_recently_evicted: usize,
    /// Cached set of locked nodes.
    pub mempool_locked_nodes: usize,
    /// Transactions deferred due to node conflicts.
    pub mempool_deferred_by_nodes: usize,
    /// Reverse index: node -> deferred transactions.
    pub mempool_txs_deferred_by_node: usize,
    /// Reverse index: node -> ready transactions.
    pub mempool_ready_txs_by_node: usize,

    // ── Remote Headers ──
    /// Remote headers pending QC verification.
    pub rh_pending_headers: usize,
    /// Verified remote shard headers.
    pub rh_verified_headers: usize,
    /// Remote shards being tracked for liveness.
    pub rh_expected_headers: usize,

    // ── Provision ──
    /// Verified remote shard headers (provisions local cache).
    pub prov_verified_remote_headers: usize,
    /// Provisions waiting for corresponding header.
    pub prov_pending_provisions: usize,
    /// Verified provisions.
    pub prov_verified_provisions: usize,
    /// Expected provisions that haven't arrived yet.
    pub prov_expected_provisions: usize,
    /// Content-addressed lookup count.
    pub prov_provisions_by_hash: usize,
    /// Provisions queued for processing.
    pub prov_queued_provisions: usize,
    /// Tombstones for committed provisions.
    pub prov_committed_tombstones: usize,

    // ── Node (io_loop) ──
    /// LRU cache of transaction bodies (fixed capacity, ~50k).
    pub node_tx_cache: usize,
    /// LRU cache of transaction statuses (fixed capacity, ~100k).
    pub node_tx_status_cache: usize,
    /// LRU cache of finalized wave certificates (fixed capacity, ~10k).
    pub node_finalized_wave_cache: usize,
    /// Time-bounded cache of provision bodies for cross-shard fetch service.
    pub node_provision_cache: usize,
    /// Fallback execution certificate cache keyed by (`wave_id_hash`, `wave_id`).
    pub node_exec_cert_cache: usize,
    /// Blocks with prepared JMT state awaiting flush.
    pub node_prepared_commits: usize,
    /// Transactions awaiting validation.
    pub node_pending_validation: usize,
    /// Locally-submitted transactions awaiting finalization (latency tracking).
    pub node_locally_submitted: usize,
    /// Block commits queued for batched flushing.
    pub node_pending_block_commits: usize,
    /// Transactions queued in the validation batch.
    pub node_validation_batch: usize,
    /// Committed headers queued in the verification batch.
    pub node_committed_header_batch: usize,
    /// Block heights queued for sync fetch.
    pub node_block_sync_queued_heights: usize,
    /// In-flight sync fetches.
    pub node_block_sync_in_flight_fetches: usize,
    /// Blocks with pending transaction fetches.
    pub node_tx_fetch_blocks: usize,
    /// Blocks with pending local provision fetches.
    pub node_local_provision_fetch_pending: usize,
    /// Blocks with pending finalized-wave fetches.
    pub node_finalized_wave_fetch_pending: usize,
    /// (shard, height) keys with pending cross-shard provision fetches.
    pub node_provision_fetch_pending: usize,
    /// (shard, height) keys with pending cross-shard execution-cert fetches.
    pub node_exec_cert_fetch_pending: usize,
    /// In-flight cross-shard remote-header range fetches across all shards.
    pub node_remote_header_fetch_pending: usize,

    // ── Storage (byte-level where available) ──
    /// `RocksDB` block cache usage in bytes.
    pub rocksdb_block_cache_usage_bytes: u64,
    /// `RocksDB` memtable usage in bytes.
    pub rocksdb_memtable_usage_bytes: u64,
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

    /// Record transactions persisted to storage.
    fn record_transactions_persisted(&self, count: usize) {}

    // ── Consensus ────────────────────────────────────────────────────

    /// Record a block committed.
    fn record_block_committed(&self, height: u64, commit_latency_secs: f64, source: &str) {}

    /// Record a transaction finalized.
    fn record_transaction_finalized(&self, latency_secs: f64, cross_shard: bool) {}

    /// Set the current block height gauge.
    fn set_block_height(&self, height: u64) {}

    /// Set the current BFT round gauge.
    fn set_bft_round(&self, round: u64) {}

    /// Set the view changes gauge (self-originated round advances).
    fn set_view_changes(&self, count: u64) {}

    /// Set the view syncs gauge (rounds we caught up to from peers).
    fn set_view_syncs(&self, count: u64) {}

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

    /// Record a completed pool task with its duration.
    ///
    /// The histogram's `_count` gives throughput (tasks/sec via `rate()`),
    /// and `_sum / threads` gives utilization per pool.
    fn record_pool_task_completed(&self, pool: &str, latency_secs: f64) {}

    /// Set event channel depths.
    fn set_channel_depths(&self, depths: &ChannelDepths) {}

    /// Record execution latency.
    fn record_execution_latency(&self, latency_secs: f64) {}

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

    /// Record an early arrival eviction.
    fn record_early_arrival_eviction(&self) {}

    // ── Sync ─────────────────────────────────────────────────────────
    //
    // Two scopes share these metrics: `kind="block"` for block-sync and
    // `kind="remote_header"` for remote-header sync. Both run as
    // `Sync<Binding>` FSMs that fetch *ranges* of contiguous heights, not
    // individual ids — keep their counters separate from the per-id Fetch
    // family below so dashboards aren't comparing range-rate to id-rate
    // under one chart.

    /// Set the per-scope `blocks_behind` gauge.
    fn set_sync_blocks_behind(&self, kind: &str, blocks_behind: u64) {}

    /// Set the per-scope `in_progress` gauge (0/1).
    fn set_sync_in_progress(&self, kind: &str, in_progress: bool) {}

    /// Record a sync response that was filtered out before delivery
    /// (height mismatch, QC mismatch, certificate-root mismatch, etc.).
    fn record_sync_block_filtered(&self, kind: &str, reason: &str) {}

    /// Record a sync response error (rehydration miss, `fetch_failed`, etc.).
    fn record_sync_response_error(&self, kind: &str, error_type: &str) {}

    /// Record a sync range round-trip started (network request emitted).
    fn record_sync_round_started(&self, kind: &str) {}

    /// Record a sync range round-trip that completed successfully.
    fn record_sync_round_completed(&self, kind: &str) {}

    /// Record a sync range round-trip released for retry. Increments per
    /// release-for-retry, not per unrecoverable failure.
    fn record_sync_round_retried(&self, kind: &str) {}

    /// Set the per-scope in-flight range gauge.
    fn set_sync_round_in_flight(&self, kind: &str, count: usize) {}

    // ── Fetch ────────────────────────────────────────────────────────
    //
    // Per-`kind` counters and gauge for outbound per-id fetches. Always
    // counted in *ids*. Range round-trips driven by sync FSMs use the
    // `sync_round_*` family above, not these.

    /// Record a fetch operation started.
    fn record_fetch_started(&self, kind: &str) {}

    /// Record a fetch operation completed.
    fn record_fetch_completed(&self, kind: &str) {}

    /// Record a fetch operation released for retry. Increments per release-
    /// for-retry, not per unrecoverable failure — the retry budget is owned
    /// by the network layer, so this is genuinely a retry counter.
    fn record_fetch_retried(&self, kind: &str) {}

    /// Record items received via fetch.
    fn record_fetch_items_received(&self, kind: &str, count: usize) {}

    /// Record fetch operation latency.
    fn record_fetch_latency(&self, kind: &str, latency_secs: f64) {}

    /// Set the fetch in-flight gauge (per kind).
    fn set_fetch_in_flight(&self, kind: &str, count: usize) {}

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

    /// Record a cross-shard transaction abort (timeout or conflict).
    fn record_transaction_aborted(&self) {}

    /// Record an expected cross-shard tx dropped past `RETENTION_HORIZON`
    /// without arriving via gossip, submit, fetch, or block inclusion. A
    /// non-zero rate here means cross-shard data availability has failed for
    /// some payload (bug, attack, or partition past every other timeout).
    fn record_expected_tx_dropped(&self) {}

    // ── Lock Contention ──────────────────────────────────────────────

    /// Set lock contention metrics.
    fn set_lock_contention(&self, ratio: f64) {}

    // ── Memory ────────────────────────────────────────────────────────

    /// Set memory usage metrics for all sub-state machines and storage.
    fn set_memory_metrics(&self, metrics: &MemoryMetrics) {}
}

// ═══════════════════════════════════════════════════════════════════════
// Global singleton
// ═══════════════════════════════════════════════════════════════════════

struct NoopRecorder;
impl MetricsRecorder for NoopRecorder {}

static RECORDER: OnceLock<Box<dyn MetricsRecorder>> = OnceLock::new();
static NOOP: NoopRecorder = NoopRecorder;

thread_local! {
    static SCOPED_RECORDER: RefCell<Option<Arc<dyn MetricsRecorder>>> =
        const { RefCell::new(None) };
}

/// Install a global metrics recorder.
///
/// Can only be called once. Subsequent calls are silently ignored.
pub fn set_global_recorder(recorder: Box<dyn MetricsRecorder>) {
    let _ = RECORDER.set(recorder);
}

/// Run `f` with `recorder` installed as the thread-local metrics recorder.
///
/// All emissions on this thread for the duration of `f` route to `recorder`
/// instead of the global. Used in tests so concurrent simulations (cargo
/// runs each test on its own thread) don't share counters. Thread-local
/// scoping does not propagate across `spawn_blocking` / rayon workers.
pub fn with_scoped_recorder<R>(recorder: Arc<dyn MetricsRecorder>, f: impl FnOnce() -> R) -> R {
    struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) {
            SCOPED_RECORDER.with(|cell| cell.borrow_mut().take());
        }
    }
    SCOPED_RECORDER.with(|cell| *cell.borrow_mut() = Some(recorder));
    let _guard = Guard;
    f()
}

/// Handle to the active metrics recorder. Holds either a thread-local `Arc`
/// (when a scoped recorder is installed) or a static reference to the global.
enum RecorderHandle {
    Scoped(Arc<dyn MetricsRecorder>),
    Static(&'static dyn MetricsRecorder),
}

impl std::ops::Deref for RecorderHandle {
    type Target = dyn MetricsRecorder;
    #[inline]
    fn deref(&self) -> &(dyn MetricsRecorder + 'static) {
        match self {
            Self::Scoped(arc) => &**arc,
            Self::Static(r) => *r,
        }
    }
}

/// Get the active metrics recorder.
///
/// Prefers the thread-local scoped recorder if set; otherwise falls back to
/// the global recorder, or a no-op if none has been installed.
#[inline]
fn recorder() -> RecorderHandle {
    if let Some(scoped) = SCOPED_RECORDER.with(|cell| cell.borrow().clone()) {
        return RecorderHandle::Scoped(scoped);
    }
    RecorderHandle::Static(
        RECORDER
            .get()
            .map_or(&NOOP as &dyn MetricsRecorder, AsRef::as_ref),
    )
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

/// Record transactions persisted to storage.
#[inline]
pub fn record_transactions_persisted(count: usize) {
    recorder().record_transactions_persisted(count);
}

// ── Consensus ────────────────────────────────────────────────────────

/// Record a block committed.
#[inline]
pub fn record_block_committed(height: u64, commit_latency_secs: f64, source: &str) {
    recorder().record_block_committed(height, commit_latency_secs, source);
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

/// Set the view syncs gauge.
#[inline]
pub fn set_view_syncs(count: u64) {
    recorder().set_view_syncs(count);
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

/// Record a completed pool task with its duration.
#[inline]
pub fn record_pool_task_completed(pool: &str, latency_secs: f64) {
    recorder().record_pool_task_completed(pool, latency_secs);
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

/// Record an early arrival eviction.
#[inline]
pub fn record_early_arrival_eviction() {
    recorder().record_early_arrival_eviction();
}

// ── Sync ─────────────────────────────────────────────────────────────

/// Set the per-scope `blocks_behind` gauge.
#[inline]
pub fn set_sync_blocks_behind(kind: &str, blocks_behind: u64) {
    recorder().set_sync_blocks_behind(kind, blocks_behind);
}

/// Set the per-scope `in_progress` gauge (0/1).
#[inline]
pub fn set_sync_in_progress(kind: &str, in_progress: bool) {
    recorder().set_sync_in_progress(kind, in_progress);
}

/// Record a sync response filtered out before delivery.
#[inline]
pub fn record_sync_block_filtered(kind: &str, reason: &str) {
    recorder().record_sync_block_filtered(kind, reason);
}

/// Record a sync response error.
#[inline]
pub fn record_sync_response_error(kind: &str, error_type: &str) {
    recorder().record_sync_response_error(kind, error_type);
}

/// Record a sync range round-trip started.
#[inline]
pub fn record_sync_round_started(kind: &str) {
    recorder().record_sync_round_started(kind);
}

/// Record a sync range round-trip completed successfully.
#[inline]
pub fn record_sync_round_completed(kind: &str) {
    recorder().record_sync_round_completed(kind);
}

/// Record a sync range round-trip released for retry.
#[inline]
pub fn record_sync_round_retried(kind: &str) {
    recorder().record_sync_round_retried(kind);
}

/// Set the per-scope in-flight range gauge.
#[inline]
pub fn set_sync_round_in_flight(kind: &str, count: usize) {
    recorder().set_sync_round_in_flight(kind, count);
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

/// Record a fetch operation released for retry.
#[inline]
pub fn record_fetch_retried(kind: &str) {
    recorder().record_fetch_retried(kind);
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

/// Set the fetch in-flight gauge (per kind).
#[inline]
pub fn set_fetch_in_flight(kind: &str, count: usize) {
    recorder().set_fetch_in_flight(kind, count);
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

// ── Aborted Transactions ─────────────────────────────────────────────

/// Record a cross-shard transaction abort (timeout or conflict).
#[inline]
pub fn record_transaction_aborted() {
    recorder().record_transaction_aborted();
}

/// Record an expected cross-shard tx dropped past `RETENTION_HORIZON`.
#[inline]
pub fn record_expected_tx_dropped() {
    recorder().record_expected_tx_dropped();
}

// ── Lock Contention ──────────────────────────────────────────────────

/// Set lock contention metrics.
#[inline]
pub fn set_lock_contention(ratio: f64) {
    recorder().set_lock_contention(ratio);
}

// ── Memory ────────────────────────────────────────────────────────

/// Set memory usage metrics for all sub-state machines and storage.
#[inline]
pub fn set_memory_metrics(metrics: &MemoryMetrics) {
    recorder().set_memory_metrics(metrics);
}
