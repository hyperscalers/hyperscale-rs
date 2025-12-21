//! Production metrics using native Prometheus client.
//!
//! Metrics are domain-specific rather than generic event counters.
//! Use traces for event-level granularity during investigations.

use prometheus::{
    register_counter, register_counter_vec, register_gauge, register_histogram,
    register_histogram_vec, Counter, CounterVec, Gauge, Histogram, HistogramVec,
};
use std::sync::OnceLock;

static METRICS: OnceLock<Metrics> = OnceLock::new();

/// Domain-specific metrics for production monitoring.
pub struct Metrics {
    // === Consensus ===
    pub blocks_committed: Counter,
    pub block_commit_latency: Histogram,
    pub block_height: Gauge,
    /// Current BFT round number within the current height.
    pub round: Gauge,
    /// Total number of view changes (round advances due to timeout).
    pub view_changes: Gauge,

    // === Transactions ===
    pub transactions_finalized: HistogramVec,
    pub mempool_size: Gauge,

    // === Backpressure ===
    /// Number of transactions currently holding state locks (Committed or Executed status).
    pub in_flight: Gauge,
    /// Deprecated: alias for in_flight. Use in_flight instead.
    pub provisions_registered: Gauge,
    /// Whether backpressure limit is currently active (0 or 1).
    pub backpressure_active: Gauge,
    /// Number of TXs with commitment proofs attached in last proposal.
    pub txs_with_commitment_proof: Gauge,

    // === Infrastructure ===
    pub network_messages_sent: Counter,
    pub network_messages_received: Counter,
    pub signature_verification_latency: HistogramVec,
    pub execution_latency: Histogram,
    pub speculative_execution_latency: Histogram,

    // === Speculative Execution ===
    pub speculative_execution_started: Counter,
    pub speculative_execution_cache_hit: Counter,
    pub speculative_execution_late_hit: Counter,
    pub speculative_execution_cache_miss: Counter,
    pub speculative_execution_invalidated: Counter,

    // === Thread Pools ===
    /// Queue depth of the consensus crypto pool (block votes, QC verification).
    /// This pool is liveness-critical and should remain near zero under load.
    pub consensus_crypto_pool_queue_depth: Gauge,
    /// Queue depth of the general crypto pool (provisions, state votes, tx validation).
    pub crypto_pool_queue_depth: Gauge,
    pub execution_pool_queue_depth: Gauge,

    // === Event Channel Depths ===
    /// Depth of the callback channel (crypto/execution results).
    pub callback_channel_depth: Gauge,
    /// Depth of the consensus channel (BFT network messages).
    pub consensus_channel_depth: Gauge,
    /// Depth of the validated transactions channel.
    pub validated_tx_channel_depth: Gauge,
    /// Depth of the RPC transaction submission channel.
    pub rpc_tx_channel_depth: Gauge,
    /// Depth of the status channel (transaction status updates).
    pub status_channel_depth: Gauge,
    /// Depth of the inbound sync request channel.
    pub sync_request_channel_depth: Gauge,
    /// Depth of the inbound transaction fetch request channel.
    pub tx_request_channel_depth: Gauge,
    /// Depth of the inbound certificate fetch request channel.
    pub cert_request_channel_depth: Gauge,

    // === Transaction Ingress ===
    /// Available permits in the transaction ingress semaphore.
    pub tx_ingress_available_permits: Gauge,
    /// Total transactions submitted through ingress.
    pub tx_ingress_submitted: Counter,
    /// Total transactions rejected due to backpressure.
    pub tx_ingress_rejected: Counter,

    // === Storage ===
    pub rocksdb_read_latency: Histogram,
    pub rocksdb_write_latency: Histogram,
    pub storage_operation_latency: HistogramVec,
    pub storage_batch_size: Histogram,
    pub storage_votes_persisted: Counter,
    pub storage_certificates_persisted: Counter,
    pub storage_blocks_persisted: Counter,

    // === Network ===
    pub libp2p_peers_connected: Gauge,
    pub libp2p_bandwidth_in_bytes: Counter,
    pub libp2p_bandwidth_out_bytes: Counter,

    // === Sync ===
    pub sync_blocks_behind: Gauge,
    pub sync_blocks_downloaded: Counter,
    pub sync_in_progress: Gauge,
    pub sync_response_errors: CounterVec,
    pub sync_peers_banned: Counter,

    // === Fetch (transactions/certificates) ===
    pub fetch_started: CounterVec,
    pub fetch_completed: CounterVec,
    pub fetch_failed: CounterVec,
    pub fetch_items_received: CounterVec,
    pub fetch_items_sent: CounterVec,
    pub fetch_latency: HistogramVec,
    pub fetch_in_flight: Gauge,

    // === Livelock ===
    pub livelock_cycles_detected: Counter,
    pub livelock_deferrals: Counter,
    pub livelock_deferred_transactions: Gauge,

    // === Lock Contention ===
    pub lock_contention_blocked: Gauge,
    pub lock_contention_ratio: Gauge,

    // === Errors ===
    pub signature_verification_failures: Counter,
    pub invalid_messages_received: Counter,
    pub transactions_rejected: CounterVec,
}

impl Metrics {
    fn new() -> Self {
        // Latency buckets: 1ms to 60s
        let latency_buckets = vec![
            0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0,
        ];

        Self {
            // Consensus
            blocks_committed: register_counter!(
                "hyperscale_blocks_committed_total",
                "Total number of blocks committed"
            )
            .unwrap(),

            block_commit_latency: register_histogram!(
                "hyperscale_block_commit_latency_seconds",
                "Time from proposal to commit",
                latency_buckets.clone()
            )
            .unwrap(),

            block_height: register_gauge!("hyperscale_block_height", "Current block height")
                .unwrap(),

            round: register_gauge!(
                "hyperscale_round",
                "Current BFT round within current height"
            )
            .unwrap(),

            view_changes: register_gauge!(
                "hyperscale_view_changes",
                "Total number of view changes (round advances due to timeout)"
            )
            .unwrap(),

            // Transactions
            transactions_finalized: register_histogram_vec!(
                "hyperscale_transaction_latency_seconds",
                "Transaction end-to-end latency",
                &["cross_shard"],
                latency_buckets.clone()
            )
            .unwrap(),

            mempool_size: register_gauge!(
                "hyperscale_mempool_size",
                "Number of pending transactions in mempool"
            )
            .unwrap(),

            // Backpressure
            in_flight: register_gauge!(
                "hyperscale_in_flight",
                "Number of transactions holding state locks (Committed or Executed)"
            )
            .unwrap(),
            provisions_registered: register_gauge!(
                "hyperscale_provisions_registered",
                "Deprecated: same as in_flight"
            )
            .unwrap(),
            backpressure_active: register_gauge!(
                "hyperscale_backpressure_active",
                "Whether backpressure limit is currently active (1) or not (0)"
            )
            .unwrap(),
            txs_with_commitment_proof: register_gauge!(
                "hyperscale_txs_with_commitment_proof",
                "Number of TXs with commitment proofs in last proposal"
            )
            .unwrap(),

            // Infrastructure
            network_messages_sent: register_counter!(
                "hyperscale_network_messages_sent_total",
                "Total network messages sent"
            )
            .unwrap(),

            network_messages_received: register_counter!(
                "hyperscale_network_messages_received_total",
                "Total network messages received"
            )
            .unwrap(),

            signature_verification_latency: register_histogram_vec!(
                "hyperscale_signature_verification_latency_seconds",
                "Signature verification latency by type",
                &["type"],
                vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5]
            )
            .unwrap(),

            execution_latency: register_histogram!(
                "hyperscale_execution_latency_seconds",
                "Transaction execution latency",
                vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]
            )
            .unwrap(),

            speculative_execution_latency: register_histogram!(
                "hyperscale_speculative_execution_latency_seconds",
                "Speculative transaction execution latency (before block commit)",
                vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]
            )
            .unwrap(),

            // Speculative Execution Counters
            speculative_execution_started: register_counter!(
                "hyperscale_speculative_execution_started_total",
                "Total speculative executions triggered"
            )
            .unwrap(),

            speculative_execution_cache_hit: register_counter!(
                "hyperscale_speculative_execution_cache_hit_total",
                "Speculative execution results used on block commit"
            )
            .unwrap(),

            speculative_execution_late_hit: register_counter!(
                "hyperscale_speculative_execution_late_hit_total",
                "Speculative results used after commit (dedup optimization)"
            )
            .unwrap(),

            speculative_execution_cache_miss: register_counter!(
                "hyperscale_speculative_execution_cache_miss_total",
                "Block commits requiring re-execution (no cached result)"
            )
            .unwrap(),

            speculative_execution_invalidated: register_counter!(
                "hyperscale_speculative_execution_invalidated_total",
                "Speculative results invalidated due to state conflicts"
            )
            .unwrap(),

            // Thread Pools
            consensus_crypto_pool_queue_depth: register_gauge!(
                "hyperscale_consensus_crypto_pool_queue_depth",
                "Number of pending tasks in consensus crypto pool (block votes, QC verification)"
            )
            .unwrap(),

            crypto_pool_queue_depth: register_gauge!(
                "hyperscale_crypto_pool_queue_depth",
                "Number of pending tasks in general crypto pool (provisions, state votes)"
            )
            .unwrap(),

            execution_pool_queue_depth: register_gauge!(
                "hyperscale_execution_pool_queue_depth",
                "Number of pending tasks in execution pool"
            )
            .unwrap(),

            // Event Channel Depths
            callback_channel_depth: register_gauge!(
                "hyperscale_callback_channel_depth",
                "Depth of callback channel (crypto/execution results)"
            )
            .unwrap(),

            consensus_channel_depth: register_gauge!(
                "hyperscale_consensus_channel_depth",
                "Depth of consensus channel (BFT network messages)"
            )
            .unwrap(),

            validated_tx_channel_depth: register_gauge!(
                "hyperscale_validated_tx_channel_depth",
                "Depth of validated transactions channel"
            )
            .unwrap(),

            rpc_tx_channel_depth: register_gauge!(
                "hyperscale_rpc_tx_channel_depth",
                "Depth of RPC transaction submission channel"
            )
            .unwrap(),

            status_channel_depth: register_gauge!(
                "hyperscale_status_channel_depth",
                "Depth of status channel (transaction status updates)"
            )
            .unwrap(),

            sync_request_channel_depth: register_gauge!(
                "hyperscale_sync_request_channel_depth",
                "Depth of inbound sync request channel"
            )
            .unwrap(),

            tx_request_channel_depth: register_gauge!(
                "hyperscale_tx_request_channel_depth",
                "Depth of inbound transaction fetch request channel"
            )
            .unwrap(),

            cert_request_channel_depth: register_gauge!(
                "hyperscale_cert_request_channel_depth",
                "Depth of inbound certificate fetch request channel"
            )
            .unwrap(),

            // Transaction Ingress
            tx_ingress_available_permits: register_gauge!(
                "hyperscale_tx_ingress_available_permits",
                "Available permits in transaction ingress semaphore"
            )
            .unwrap(),

            tx_ingress_submitted: register_counter!(
                "hyperscale_tx_ingress_submitted_total",
                "Total transactions submitted through ingress"
            )
            .unwrap(),

            tx_ingress_rejected: register_counter!(
                "hyperscale_tx_ingress_rejected_total",
                "Total transactions rejected due to backpressure"
            )
            .unwrap(),

            // Storage
            rocksdb_read_latency: register_histogram!(
                "hyperscale_rocksdb_read_latency_seconds",
                "RocksDB read operation latency",
                vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5]
            )
            .unwrap(),

            rocksdb_write_latency: register_histogram!(
                "hyperscale_rocksdb_write_latency_seconds",
                "RocksDB write operation latency",
                vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5]
            )
            .unwrap(),

            storage_operation_latency: register_histogram_vec!(
                "hyperscale_storage_operation_latency_seconds",
                "Storage operation latency by type",
                &["operation"],
                vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]
            )
            .unwrap(),

            storage_batch_size: register_histogram!(
                "hyperscale_storage_batch_size",
                "Number of writes in atomic batches",
                vec![1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0]
            )
            .unwrap(),

            storage_votes_persisted: register_counter!(
                "hyperscale_storage_votes_persisted_total",
                "Total number of votes persisted to storage"
            )
            .unwrap(),

            storage_certificates_persisted: register_counter!(
                "hyperscale_storage_certificates_persisted_total",
                "Total number of transaction certificates persisted"
            )
            .unwrap(),

            storage_blocks_persisted: register_counter!(
                "hyperscale_storage_blocks_persisted_total",
                "Total number of blocks persisted to storage"
            )
            .unwrap(),

            // Network
            libp2p_peers_connected: register_gauge!(
                "hyperscale_libp2p_peers_connected",
                "Number of connected libp2p peers"
            )
            .unwrap(),

            libp2p_bandwidth_in_bytes: register_counter!(
                "hyperscale_libp2p_bandwidth_in_bytes_total",
                "Total bytes received via libp2p"
            )
            .unwrap(),

            libp2p_bandwidth_out_bytes: register_counter!(
                "hyperscale_libp2p_bandwidth_out_bytes_total",
                "Total bytes sent via libp2p"
            )
            .unwrap(),

            // Sync
            sync_blocks_behind: register_gauge!(
                "hyperscale_sync_blocks_behind",
                "Number of blocks behind the network head"
            )
            .unwrap(),

            sync_blocks_downloaded: register_counter!(
                "hyperscale_sync_blocks_downloaded_total",
                "Total blocks downloaded during sync"
            )
            .unwrap(),

            sync_in_progress: register_gauge!(
                "hyperscale_sync_in_progress",
                "Whether sync is currently active (0 or 1)"
            )
            .unwrap(),

            sync_response_errors: register_counter_vec!(
                "hyperscale_sync_response_errors_total",
                "Total sync response errors by type",
                &["error_type"]
            )
            .unwrap(),

            sync_peers_banned: register_counter!(
                "hyperscale_sync_peers_banned_total",
                "Total peers banned for malicious sync responses"
            )
            .unwrap(),

            // Fetch (transactions/certificates)
            fetch_started: register_counter_vec!(
                "hyperscale_fetch_started_total",
                "Total fetch operations started",
                &["kind"]
            )
            .unwrap(),

            fetch_completed: register_counter_vec!(
                "hyperscale_fetch_completed_total",
                "Total fetch operations completed successfully",
                &["kind"]
            )
            .unwrap(),

            fetch_failed: register_counter_vec!(
                "hyperscale_fetch_failed_total",
                "Total fetch operations failed",
                &["kind"]
            )
            .unwrap(),

            fetch_items_received: register_counter_vec!(
                "hyperscale_fetch_items_received_total",
                "Total items (transactions/certificates) received via fetch",
                &["kind"]
            )
            .unwrap(),

            fetch_items_sent: register_counter_vec!(
                "hyperscale_fetch_items_sent_total",
                "Total items (transactions/certificates) sent in response to fetch requests",
                &["kind"]
            )
            .unwrap(),

            fetch_latency: register_histogram_vec!(
                "hyperscale_fetch_latency_seconds",
                "Fetch operation latency",
                &["kind"],
                vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
            )
            .unwrap(),

            fetch_in_flight: register_gauge!(
                "hyperscale_fetch_in_flight",
                "Number of fetch requests currently in flight"
            )
            .unwrap(),

            // Livelock
            livelock_cycles_detected: register_counter!(
                "hyperscale_livelock_cycles_detected_total",
                "Total number of cross-shard cycles detected"
            )
            .unwrap(),

            livelock_deferrals: register_counter!(
                "hyperscale_livelock_deferrals_total",
                "Total number of transaction deferrals due to cycle detection"
            )
            .unwrap(),

            livelock_deferred_transactions: register_gauge!(
                "hyperscale_livelock_deferred_transactions",
                "Current number of deferred transactions awaiting retry"
            )
            .unwrap(),

            // Lock Contention
            lock_contention_blocked: register_gauge!(
                "hyperscale_lock_contention_blocked",
                "Number of transactions currently blocked by lock contention"
            )
            .unwrap(),

            lock_contention_ratio: register_gauge!(
                "hyperscale_lock_contention_ratio",
                "Ratio of blocked transactions to total (0.0 to 1.0)"
            )
            .unwrap(),

            // Errors
            signature_verification_failures: register_counter!(
                "hyperscale_signature_verification_failures_total",
                "Total signature verification failures"
            )
            .unwrap(),

            invalid_messages_received: register_counter!(
                "hyperscale_invalid_messages_received_total",
                "Total invalid/malformed messages received"
            )
            .unwrap(),

            transactions_rejected: register_counter_vec!(
                "hyperscale_transactions_rejected_total",
                "Total transactions rejected",
                &["reason"]
            )
            .unwrap(),
        }
    }
}

/// Get or initialize the global metrics instance.
pub fn metrics() -> &'static Metrics {
    METRICS.get_or_init(Metrics::new)
}

/// Record a block committed.
pub fn record_block_committed(height: u64, commit_latency_secs: f64) {
    let m = metrics();
    m.blocks_committed.inc();
    m.block_commit_latency.observe(commit_latency_secs);
    m.block_height.set(height as f64);
}

/// Record a transaction finalized.
pub fn record_transaction_finalized(latency_secs: f64, cross_shard: bool) {
    let label = if cross_shard { "true" } else { "false" };
    metrics()
        .transactions_finalized
        .with_label_values(&[label])
        .observe(latency_secs);
}

/// Update BFT metrics from BftStats.
pub fn set_bft_stats(stats: &hyperscale_bft::BftStats) {
    let m = metrics();
    m.round.set(stats.current_round as f64);
    m.view_changes.set(stats.view_changes as f64);
}

/// Update mempool size.
pub fn set_mempool_size(size: usize) {
    metrics().mempool_size.set(size as f64);
}

/// Update in-flight transaction count (transactions holding state locks).
pub fn set_in_flight(count: usize) {
    metrics().in_flight.set(count as f64);
    // Also update deprecated metric for backwards compatibility
    metrics().provisions_registered.set(count as f64);
}

/// Update backpressure active status.
pub fn set_backpressure_active(active: bool) {
    metrics()
        .backpressure_active
        .set(if active { 1.0 } else { 0.0 });
}

/// Update count of TXs with commitment proofs.
pub fn set_txs_with_commitment_proof(count: usize) {
    metrics().txs_with_commitment_proof.set(count as f64);
}

/// Update thread pool queue depths.
pub fn set_pool_queue_depths(consensus_crypto: usize, crypto: usize, execution: usize) {
    let m = metrics();
    m.consensus_crypto_pool_queue_depth
        .set(consensus_crypto as f64);
    m.crypto_pool_queue_depth.set(crypto as f64);
    m.execution_pool_queue_depth.set(execution as f64);
}

/// Channel depth statistics for the event loop.
#[derive(Debug, Default)]
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

/// Update event channel depths.
pub fn set_channel_depths(depths: &ChannelDepths) {
    let m = metrics();
    m.callback_channel_depth.set(depths.callback as f64);
    m.consensus_channel_depth.set(depths.consensus as f64);
    m.validated_tx_channel_depth.set(depths.validated_tx as f64);
    m.rpc_tx_channel_depth.set(depths.rpc_tx as f64);
    m.status_channel_depth.set(depths.status as f64);
    m.sync_request_channel_depth.set(depths.sync_request as f64);
    m.tx_request_channel_depth.set(depths.tx_request as f64);
    m.cert_request_channel_depth.set(depths.cert_request as f64);
}

/// Update transaction ingress metrics.
pub fn set_tx_ingress_available_permits(count: usize) {
    metrics().tx_ingress_available_permits.set(count as f64);
}

/// Record a successful transaction ingress submission.
pub fn record_tx_ingress_submitted() {
    metrics().tx_ingress_submitted.inc();
}

/// Record a rejected transaction due to backpressure.
pub fn record_tx_ingress_rejected() {
    metrics().tx_ingress_rejected.inc();
}

/// Record RocksDB read latency.
pub fn record_rocksdb_read(latency_secs: f64) {
    metrics().rocksdb_read_latency.observe(latency_secs);
}

/// Record RocksDB write latency.
pub fn record_rocksdb_write(latency_secs: f64) {
    metrics().rocksdb_write_latency.observe(latency_secs);
}

/// Record storage operation latency by type.
///
/// **Cardinality control**: Use only these predefined operation types:
/// - `"put_block"` - persisting a committed block
/// - `"put_vote"` - persisting own vote (BFT safety critical)
/// - `"put_certificate"` - persisting a transaction certificate
/// - `"commit_cert_writes"` - atomic certificate + state writes
/// - `"get_block"` - fetching a block by height
/// - `"get_certificate"` - fetching a certificate by hash
/// - `"get_chain_metadata"` - fetching chain height/hash/qc
/// - `"get_state_entries"` - fetching state for provisioning
/// - `"load_recovered_state"` - crash recovery state load
pub fn record_storage_operation(operation: &str, latency_secs: f64) {
    metrics()
        .storage_operation_latency
        .with_label_values(&[operation])
        .observe(latency_secs);
}

/// Record the size of an atomic write batch.
pub fn record_storage_batch_size(size: usize) {
    metrics().storage_batch_size.observe(size as f64);
}

/// Record a vote persisted.
pub fn record_vote_persisted() {
    metrics().storage_votes_persisted.inc();
}

/// Record a certificate persisted.
pub fn record_certificate_persisted() {
    metrics().storage_certificates_persisted.inc();
}

/// Record a block persisted.
pub fn record_block_persisted() {
    metrics().storage_blocks_persisted.inc();
}

/// Update libp2p peer count.
pub fn set_libp2p_peers(count: usize) {
    metrics().libp2p_peers_connected.set(count as f64);
}

/// Record libp2p bandwidth.
pub fn record_libp2p_bandwidth(bytes_in: u64, bytes_out: u64) {
    let m = metrics();
    m.libp2p_bandwidth_in_bytes.inc_by(bytes_in as f64);
    m.libp2p_bandwidth_out_bytes.inc_by(bytes_out as f64);
}

/// Update sync status.
pub fn set_sync_status(blocks_behind: u64, in_progress: bool) {
    let m = metrics();
    m.sync_blocks_behind.set(blocks_behind as f64);
    m.sync_in_progress.set(if in_progress { 1.0 } else { 0.0 });
}

/// Record a block downloaded during sync.
pub fn record_sync_block_downloaded() {
    metrics().sync_blocks_downloaded.inc();
}

/// Record a sync response error by type.
///
/// **Cardinality control**: Use only these predefined error types (from `SyncResponseError::metric_label()`):
///
/// Non-malicious (retry with different peer):
/// - `"no_request"` - response when no request pending
/// - `"peer_mismatch"` - response from unexpected peer
/// - `"request_id_mismatch"` - wrong request ID
/// - `"state_mismatch"` - block doesn't extend current state
/// - `"timeout"` - request timed out
/// - `"network_error"` - network-level failure
/// - `"empty_response"` - peer doesn't have the block (may have pruned it)
///
/// Malicious (results in peer ban):
/// - `"qc_hash_mismatch"` - QC doesn't match block
/// - `"qc_height_mismatch"` - QC height wrong
/// - `"qc_sig_invalid"` - QC signature invalid
/// - `"qc_no_quorum"` - QC lacks quorum
/// - `"block_hash_mismatch"` - block hash mismatch
/// - `"block_parent_mismatch"` - block parent mismatch
pub fn record_sync_response_error(error_type: &str) {
    metrics()
        .sync_response_errors
        .with_label_values(&[error_type])
        .inc();
}

/// Record a peer banned for malicious sync behavior.
pub fn record_sync_peer_banned() {
    metrics().sync_peers_banned.inc();
}

/// Record a livelock cycle detection event.
pub fn record_livelock_cycle_detected() {
    metrics().livelock_cycles_detected.inc();
}

/// Record a transaction deferral due to cycle detection.
pub fn record_livelock_deferral() {
    metrics().livelock_deferrals.inc();
}

/// Update the count of currently deferred transactions.
pub fn set_livelock_deferred_count(count: usize) {
    metrics().livelock_deferred_transactions.set(count as f64);
}

/// Record a signature verification failure.
pub fn record_signature_verification_failure() {
    metrics().signature_verification_failures.inc();
}

/// Record an invalid message received.
pub fn record_invalid_message() {
    metrics().invalid_messages_received.inc();
}

/// Record a transaction rejection with reason.
///
/// **Cardinality control**: Use only these predefined reasons to avoid
/// label explosion in Prometheus:
/// - `"duplicate"` - transaction already in mempool
/// - `"invalid_signature"` - signature verification failed
/// - `"invalid_format"` - malformed transaction
/// - `"wrong_shard"` - transaction routed to wrong shard
/// - `"mempool_full"` - mempool capacity exceeded
/// - `"nonce_too_low"` - nonce already used
/// - `"insufficient_balance"` - sender has insufficient funds
/// - `"execution_failed"` - transaction execution rejected
///
/// Do NOT use dynamic strings (e.g., error messages) as reasons.
pub fn record_transaction_rejected(reason: &str) {
    debug_assert!(
        matches!(
            reason,
            "duplicate"
                | "invalid_signature"
                | "invalid_format"
                | "wrong_shard"
                | "mempool_full"
                | "nonce_too_low"
                | "insufficient_balance"
                | "execution_failed"
        ),
        "Unknown rejection reason: {} - add to allowed list or use existing",
        reason
    );
    metrics()
        .transactions_rejected
        .with_label_values(&[reason])
        .inc();
}

/// Record network message sent.
pub fn record_network_message_sent() {
    metrics().network_messages_sent.inc();
}

/// Record network message received.
pub fn record_network_message_received() {
    metrics().network_messages_received.inc();
}

/// Record signature verification latency by type.
///
/// Types:
/// - "vote": Individual vote signature (BLS or Ed25519)
/// - "qc": Aggregated QC signature (BLS aggregate)
/// - "state_vote": State vote signature (execution layer)
/// - "state_cert": State certificate aggregated signature
/// - "provision": Provision signature
pub fn record_signature_verification_latency(sig_type: &str, latency_secs: f64) {
    metrics()
        .signature_verification_latency
        .with_label_values(&[sig_type])
        .observe(latency_secs);
}

/// Record execution latency.
pub fn record_execution_latency(latency_secs: f64) {
    metrics().execution_latency.observe(latency_secs);
}

/// Record speculative execution latency.
pub fn record_speculative_execution_latency(latency_secs: f64) {
    metrics()
        .speculative_execution_latency
        .observe(latency_secs);
}

/// Record speculative execution started.
pub fn record_speculative_execution_started(count: u64) {
    metrics().speculative_execution_started.inc_by(count as f64);
}

/// Record speculative execution cache hit.
pub fn record_speculative_execution_cache_hit() {
    metrics().speculative_execution_cache_hit.inc();
}

/// Record speculative execution late hit (commit before speculation complete).
/// These are also counted as cache hits - this metric tracks the dedup optimization.
pub fn record_speculative_execution_late_hit() {
    metrics().speculative_execution_late_hit.inc();
}

/// Record speculative execution cache miss.
pub fn record_speculative_execution_cache_miss() {
    metrics().speculative_execution_cache_miss.inc();
}

/// Record speculative execution invalidated.
pub fn record_speculative_execution_invalidated() {
    metrics().speculative_execution_invalidated.inc();
}

/// Update lock contention metrics.
pub fn set_lock_contention(blocked: u64, ratio: f64) {
    let m = metrics();
    m.lock_contention_blocked.set(blocked as f64);
    m.lock_contention_ratio.set(ratio);
}

/// Update lock contention metrics from LockContentionStats.
///
/// This is a convenience wrapper that extracts the relevant fields
/// from the mempool's LockContentionStats struct.
pub fn set_lock_contention_from_stats(stats: &hyperscale_mempool::LockContentionStats) {
    set_lock_contention(stats.blocked_count, stats.contention_ratio());
}

// ═══════════════════════════════════════════════════════════════════════════
// Fetch Metrics (transactions/certificates)
// ═══════════════════════════════════════════════════════════════════════════

/// Record a fetch operation started.
///
/// **Cardinality control**: `kind` must be one of:
/// - `"transaction"` - fetching transactions for a pending block
/// - `"certificate"` - fetching certificates for a pending block
pub fn record_fetch_started(kind: crate::fetch::FetchKind) {
    metrics()
        .fetch_started
        .with_label_values(&[kind.as_str()])
        .inc();
}

/// Record a fetch operation completed successfully.
pub fn record_fetch_completed(kind: crate::fetch::FetchKind) {
    metrics()
        .fetch_completed
        .with_label_values(&[kind.as_str()])
        .inc();
}

/// Record a fetch operation failed.
pub fn record_fetch_failed(kind: crate::fetch::FetchKind) {
    metrics()
        .fetch_failed
        .with_label_values(&[kind.as_str()])
        .inc();
}

/// Record items received via fetch.
pub fn record_fetch_items_received(kind: crate::fetch::FetchKind, count: usize) {
    metrics()
        .fetch_items_received
        .with_label_values(&[kind.as_str()])
        .inc_by(count as f64);
}

/// Record fetch operation latency.
pub fn record_fetch_latency(kind: crate::fetch::FetchKind, latency: std::time::Duration) {
    metrics()
        .fetch_latency
        .with_label_values(&[kind.as_str()])
        .observe(latency.as_secs_f64());
}

/// Update the number of in-flight fetch requests.
pub fn set_fetch_in_flight(count: usize) {
    metrics().fetch_in_flight.set(count as f64);
}

/// Record items sent in response to a fetch request.
///
/// Called by the fetch handler when responding to inbound fetch requests.
pub fn record_fetch_response_sent(kind: &str, count: usize) {
    metrics()
        .fetch_items_sent
        .with_label_values(&[kind])
        .inc_by(count as f64);
}
