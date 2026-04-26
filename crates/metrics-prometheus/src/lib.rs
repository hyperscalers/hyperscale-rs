//! Prometheus metrics backend for Hyperscale.
//!
//! Implements [`hyperscale_metrics::MetricsRecorder`] using native Prometheus
//! counters, gauges, and histograms.
//!
//! # Usage
//!
//! Call [`install()`] once at startup before any metrics are recorded:
//! ```ignore
//! hyperscale_metrics_prometheus::install();
//! ```
#![allow(dead_code)]

use hyperscale_metrics::{ChannelDepths, MemoryMetrics, MetricsRecorder};
use prometheus::{
    register_counter, register_counter_vec, register_gauge, register_gauge_vec, register_histogram,
    register_histogram_vec, Counter, CounterVec, Gauge, GaugeVec, Histogram, HistogramVec,
};

/// Domain-specific Prometheus metrics for production monitoring.
pub struct Metrics {
    // === Consensus ===
    pub blocks_committed: Counter,
    pub block_commit_latency: HistogramVec,
    pub block_height: Gauge,
    pub round: Gauge,
    pub view_changes: Gauge,
    pub view_syncs: Gauge,
    pub build_info: GaugeVec,

    // === Transactions ===
    pub transactions_finalized: HistogramVec,
    pub mempool_size: Gauge,

    // === Backpressure ===
    pub in_flight: Gauge,
    pub backpressure_active: Gauge,
    pub txs_with_commitment_proof: Gauge,

    // === Infrastructure ===
    pub network_messages_sent: Counter,
    pub network_messages_received: Counter,
    pub signature_verification_latency: HistogramVec,
    pub execution_latency: Histogram,
    // === Thread Pools ===
    pub consensus_crypto_pool_queue_depth: Gauge,
    pub crypto_pool_queue_depth: Gauge,
    pub tx_validation_pool_queue_depth: Gauge,
    pub execution_pool_queue_depth: Gauge,
    pub pool_task_duration: HistogramVec,

    // === Event Channel Depths ===
    pub callback_channel_depth: Gauge,
    pub consensus_channel_depth: Gauge,
    pub validated_tx_channel_depth: Gauge,
    pub rpc_tx_channel_depth: Gauge,
    pub status_channel_depth: Gauge,
    pub sync_request_channel_depth: Gauge,
    pub tx_request_channel_depth: Gauge,
    pub cert_request_channel_depth: Gauge,

    // === Transaction Ingress ===
    pub tx_ingress_rejected_syncing: Counter,
    pub tx_ingress_rejected_pending_limit: Counter,

    // === Storage ===
    pub rocksdb_read_latency: Histogram,
    pub rocksdb_write_latency: Histogram,
    pub storage_operation_latency: HistogramVec,
    pub storage_batch_size: Histogram,
    pub storage_certificates_persisted: Counter,
    pub storage_blocks_persisted: Counter,
    pub storage_transactions_persisted: Counter,

    // === Network ===
    pub libp2p_peers_connected: Gauge,
    pub libp2p_bandwidth_in_bytes: Counter,
    pub libp2p_bandwidth_out_bytes: Counter,
    pub libp2p_pending_response_channels: Gauge,
    pub libp2p_event_loop_panics: Counter,

    // === Sync ===
    pub sync_blocks_behind: Gauge,
    pub sync_blocks_downloaded: Counter,
    pub sync_blocks_received_by_bft: Counter,
    pub sync_blocks_submitted_for_verification: Counter,
    pub sync_blocks_buffered: Counter,
    pub sync_blocks_filtered: CounterVec,
    pub sync_blocks_verified: Counter,
    pub sync_blocks_applied: Counter,
    pub sync_in_progress: Gauge,
    pub sync_response_errors: CounterVec,
    pub sync_peers_banned: Counter,

    // === Fetch ===
    pub fetch_started: CounterVec,
    pub fetch_completed: CounterVec,
    pub fetch_failed: CounterVec,
    pub fetch_items_received: CounterVec,
    pub fetch_items_sent: CounterVec,
    pub fetch_latency: HistogramVec,
    pub fetch_in_flight: GaugeVec,

    // === Aborted Transactions ===
    pub transactions_aborted: Counter,

    // === Lock Contention ===
    pub lock_contention_ratio: Gauge,

    // === Errors ===
    pub signature_verification_failures: Counter,
    pub invalid_messages_received: Counter,
    pub transactions_rejected: CounterVec,

    // === Memory ===
    pub memory_bft: GaugeVec,
    pub memory_exec: GaugeVec,
    pub memory_mempool: GaugeVec,
    pub memory_remote_headers: GaugeVec,
    pub memory_provisions: GaugeVec,
    pub memory_node: GaugeVec,
    pub memory_storage: GaugeVec,

    // === Cross-Shard Message Delivery ===
    pub dispatch_failures: CounterVec,
    pub broadcast_failures: Counter,
    pub broadcast_retry_successes: Counter,
    pub broadcast_messages_dropped: Counter,
    pub broadcast_retry_queue_size: Gauge,
    pub gossipsub_publish_failures: CounterVec,
    pub network_request_retries: CounterVec,
    pub early_arrival_evictions: Counter,
    pub backpressure_events: CounterVec,
}

impl Metrics {
    fn new() -> Self {
        let latency_buckets = vec![
            0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 0.75, 1.0, 1.25, 1.5, 1.75, 2.0, 2.5,
            3.0, 5.0, 10.0, 30.0, 60.0, 120.0,
        ];

        let build_info = register_gauge_vec!(
            "hyperscale_build_info",
            "Node build information",
            &["version"]
        )
        .unwrap();

        let version = option_env!("HYPERSCALE_VERSION").unwrap_or("localdev");
        build_info.with_label_values(&[version]).set(1.0);

        Self {
            build_info,

            // Consensus
            blocks_committed: register_counter!(
                "hyperscale_blocks_committed_total",
                "Total number of blocks committed"
            )
            .unwrap(),

            block_commit_latency: register_histogram_vec!(
                "hyperscale_block_commit_latency_seconds",
                "Time from proposal to commit, split by how this node learned the certifying QC",
                &["source"],
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
                "Self-originated view changes (this validator's leader-activity timer fired)"
            )
            .unwrap(),

            view_syncs: register_gauge!(
                "hyperscale_view_syncs",
                "Rounds advanced via sync_to_qc_round (caught up to higher round seen on peers)"
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
                vec![
                    0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
                    30.0
                ]
            )
            .unwrap(),

            execution_latency: register_histogram!(
                "hyperscale_execution_latency_seconds",
                "Transaction execution latency",
                vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 2.5, 5.0, 10.0]
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
                "Number of pending tasks in general crypto pool (provisions, execution votes)"
            )
            .unwrap(),

            tx_validation_pool_queue_depth: register_gauge!(
                "hyperscale_tx_validation_pool_queue_depth",
                "Number of pending tasks in tx validation pool (transaction signature verification)"
            )
            .unwrap(),

            execution_pool_queue_depth: register_gauge!(
                "hyperscale_execution_pool_queue_depth",
                "Number of pending tasks in execution pool"
            )
            .unwrap(),

            pool_task_duration: register_histogram_vec!(
                "hyperscale_pool_task_duration_seconds",
                "Time spent executing tasks in each dispatch pool",
                &["pool"],
                vec![
                    0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
                    30.0
                ]
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
            tx_ingress_rejected_syncing: register_counter!(
                "hyperscale_tx_ingress_rejected_syncing_total",
                "Total transactions rejected because node is syncing"
            )
            .unwrap(),

            tx_ingress_rejected_pending_limit: register_counter!(
                "hyperscale_tx_ingress_rejected_pending_limit_total",
                "Total transactions rejected because pending count is too high"
            )
            .unwrap(),

            // Storage
            rocksdb_read_latency: register_histogram!(
                "hyperscale_rocksdb_read_latency_seconds",
                "RocksDB read operation latency",
                vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 2.0]
            )
            .unwrap(),

            rocksdb_write_latency: register_histogram!(
                "hyperscale_rocksdb_write_latency_seconds",
                "RocksDB write operation latency",
                vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 2.0]
            )
            .unwrap(),

            storage_operation_latency: register_histogram_vec!(
                "hyperscale_storage_operation_latency_seconds",
                "Storage operation latency by type",
                &["operation"],
                vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 2.5, 5.0, 10.0]
            )
            .unwrap(),

            storage_batch_size: register_histogram!(
                "hyperscale_storage_batch_size",
                "Number of writes in atomic batches",
                vec![
                    1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0,
                    10000.0
                ]
            )
            .unwrap(),

            storage_certificates_persisted: register_counter!(
                "hyperscale_storage_certificates_persisted_total",
                "Total number of wave certificates persisted"
            )
            .unwrap(),

            storage_blocks_persisted: register_counter!(
                "hyperscale_storage_blocks_persisted_total",
                "Total number of blocks persisted to storage"
            )
            .unwrap(),

            storage_transactions_persisted: register_counter!(
                "hyperscale_storage_transactions_persisted_total",
                "Total number of transactions persisted to storage"
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

            libp2p_pending_response_channels: register_gauge!(
                "hyperscale_libp2p_pending_response_channels",
                "Number of pending response channels (potential memory leak if growing)"
            )
            .unwrap(),

            libp2p_event_loop_panics: register_counter!(
                "hyperscale_libp2p_event_loop_panics_total",
                "Network event loop panics (critical - requires node restart)"
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

            sync_blocks_received_by_bft: register_counter!(
                "hyperscale_sync_blocks_received_by_bft_total",
                "Total sync blocks received by BFT state machine"
            )
            .unwrap(),

            sync_blocks_submitted_for_verification: register_counter!(
                "hyperscale_sync_blocks_submitted_for_verification_total",
                "Total sync blocks submitted for QC verification"
            )
            .unwrap(),

            sync_blocks_buffered: register_counter!(
                "hyperscale_sync_blocks_buffered_total",
                "Total sync blocks buffered (out of order)"
            )
            .unwrap(),

            sync_blocks_filtered: register_counter_vec!(
                "hyperscale_sync_blocks_filtered_total",
                "Total sync blocks filtered out by reason",
                &["reason"]
            )
            .unwrap(),

            sync_blocks_verified: register_counter!(
                "hyperscale_sync_blocks_verified_total",
                "Total sync blocks with verified QC signatures"
            )
            .unwrap(),

            sync_blocks_applied: register_counter!(
                "hyperscale_sync_blocks_applied_total",
                "Total sync blocks applied (committed)"
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

            // Fetch
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
                vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0]
            )
            .unwrap(),

            fetch_in_flight: register_gauge_vec!(
                "hyperscale_fetch_in_flight",
                "Number of fetch requests currently in flight",
                &["kind"]
            )
            .unwrap(),

            // Aborted Transactions
            transactions_aborted: register_counter!(
                "hyperscale_transactions_aborted_total",
                "Total cross-shard transactions aborted (timeout or node-ID conflict)"
            )
            .unwrap(),

            // Lock Contention
            lock_contention_ratio: register_gauge!(
                "hyperscale_lock_contention_ratio",
                "Ratio of deferred transactions to total (0.0 to 1.0)"
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

            // Memory
            memory_bft: register_gauge_vec!(
                "hyperscale_memory_bft_collections",
                "BFT state machine collection sizes (entry count)",
                &["collection"]
            )
            .unwrap(),

            memory_exec: register_gauge_vec!(
                "hyperscale_memory_exec_collections",
                "Execution state machine collection sizes (entry count)",
                &["collection"]
            )
            .unwrap(),

            memory_mempool: register_gauge_vec!(
                "hyperscale_memory_mempool_collections",
                "Mempool collection sizes (entry count)",
                &["collection"]
            )
            .unwrap(),

            memory_remote_headers: register_gauge_vec!(
                "hyperscale_memory_remote_headers_collections",
                "Remote header coordinator collection sizes (entry count)",
                &["collection"]
            )
            .unwrap(),

            memory_provisions: register_gauge_vec!(
                "hyperscale_memory_provisions_collections",
                "Provision coordinator collection sizes (entry count)",
                &["collection"]
            )
            .unwrap(),

            memory_node: register_gauge_vec!(
                "hyperscale_memory_node_collections",
                "Node io_loop collection sizes (entry count)",
                &["collection"]
            )
            .unwrap(),

            memory_storage: register_gauge_vec!(
                "hyperscale_memory_storage",
                "Storage cache memory usage",
                &["cache"]
            )
            .unwrap(),

            // Cross-Shard Message Delivery
            dispatch_failures: register_counter_vec!(
                "hyperscale_dispatch_failures_total",
                "Failures to dispatch cross-shard messages (channel closed)",
                &["message_type"]
            )
            .unwrap(),

            broadcast_failures: register_counter!(
                "hyperscale_broadcast_failures_total",
                "Cross-shard message batches that failed initial broadcast"
            )
            .unwrap(),

            broadcast_retry_successes: register_counter!(
                "hyperscale_broadcast_retry_successes_total",
                "Cross-shard message batches successfully delivered after retry"
            )
            .unwrap(),

            broadcast_messages_dropped: register_counter!(
                "hyperscale_broadcast_messages_dropped_total",
                "Cross-shard message batches dropped after max retries (CRITICAL)"
            )
            .unwrap(),

            broadcast_retry_queue_size: register_gauge!(
                "hyperscale_broadcast_retry_queue_size",
                "Current size of the broadcast retry queue"
            )
            .unwrap(),

            gossipsub_publish_failures: register_counter_vec!(
                "hyperscale_gossipsub_publish_failures_total",
                "Gossipsub publish failures by topic type",
                &["topic_type"]
            )
            .unwrap(),

            network_request_retries: register_counter_vec!(
                "hyperscale_network_request_retries_total",
                "Network request retries due to timeout (likely packet loss)",
                &["request_type"]
            )
            .unwrap(),

            early_arrival_evictions: register_counter!(
                "hyperscale_early_arrival_evictions_total",
                "Early arrival buffer entries evicted due to size limit"
            )
            .unwrap(),

            backpressure_events: register_counter_vec!(
                "hyperscale_backpressure_events_total",
                "Backpressure events by source",
                &["source"]
            )
            .unwrap(),
        }
    }
}

/// Prometheus-backed metrics recorder.
pub struct PrometheusRecorder {
    metrics: Metrics,
}

impl PrometheusRecorder {
    fn new() -> Self {
        Self {
            metrics: Metrics::new(),
        }
    }
}

impl MetricsRecorder for PrometheusRecorder {
    // ── Storage ──────────────────────────────────────────────────────

    fn record_storage_read(&self, latency_secs: f64) {
        self.metrics.rocksdb_read_latency.observe(latency_secs);
    }

    fn record_storage_write(&self, latency_secs: f64) {
        self.metrics.rocksdb_write_latency.observe(latency_secs);
    }

    fn record_storage_operation(&self, operation: &str, latency_secs: f64) {
        self.metrics
            .storage_operation_latency
            .with_label_values(&[operation])
            .observe(latency_secs);
    }

    fn record_storage_batch_size(&self, size: usize) {
        self.metrics.storage_batch_size.observe(size as f64);
    }

    fn record_block_persisted(&self) {
        self.metrics.storage_blocks_persisted.inc();
    }

    fn record_certificate_persisted(&self) {
        self.metrics.storage_certificates_persisted.inc();
    }

    fn record_transactions_persisted(&self, count: usize) {
        self.metrics
            .storage_transactions_persisted
            .inc_by(count as f64);
    }

    // ── Consensus ────────────────────────────────────────────────────

    fn record_block_committed(&self, height: u64, commit_latency_secs: f64, source: &str) {
        self.metrics.blocks_committed.inc();
        self.metrics
            .block_commit_latency
            .with_label_values(&[source])
            .observe(commit_latency_secs);
        self.metrics.block_height.set(height as f64);
    }

    fn record_transaction_finalized(&self, latency_secs: f64, cross_shard: bool) {
        let label = if cross_shard { "true" } else { "false" };
        self.metrics
            .transactions_finalized
            .with_label_values(&[label])
            .observe(latency_secs);
    }

    fn set_block_height(&self, height: u64) {
        self.metrics.block_height.set(height as f64);
    }

    fn set_bft_round(&self, round: u64) {
        self.metrics.round.set(round as f64);
    }

    fn set_view_changes(&self, count: u64) {
        self.metrics.view_changes.set(count as f64);
    }

    fn set_view_syncs(&self, count: u64) {
        self.metrics.view_syncs.set(count as f64);
    }

    fn set_mempool_size(&self, size: usize) {
        self.metrics.mempool_size.set(size as f64);
    }

    fn set_in_flight(&self, count: usize) {
        self.metrics.in_flight.set(count as f64);
    }

    fn set_backpressure_active(&self, active: bool) {
        self.metrics
            .backpressure_active
            .set(if active { 1.0 } else { 0.0 });
    }

    fn set_txs_with_commitment_proof(&self, count: usize) {
        self.metrics.txs_with_commitment_proof.set(count as f64);
    }

    // ── Infrastructure ───────────────────────────────────────────────

    fn set_pool_queue_depths(
        &self,
        consensus_crypto: usize,
        crypto: usize,
        tx_validation: usize,
        execution: usize,
    ) {
        self.metrics
            .consensus_crypto_pool_queue_depth
            .set(consensus_crypto as f64);
        self.metrics.crypto_pool_queue_depth.set(crypto as f64);
        self.metrics
            .tx_validation_pool_queue_depth
            .set(tx_validation as f64);
        self.metrics
            .execution_pool_queue_depth
            .set(execution as f64);
    }

    fn record_pool_task_completed(&self, pool: &str, latency_secs: f64) {
        self.metrics
            .pool_task_duration
            .with_label_values(&[pool])
            .observe(latency_secs);
    }

    fn set_channel_depths(&self, depths: &ChannelDepths) {
        self.metrics
            .callback_channel_depth
            .set(depths.callback as f64);
        self.metrics
            .consensus_channel_depth
            .set(depths.consensus as f64);
        self.metrics
            .validated_tx_channel_depth
            .set(depths.validated_tx as f64);
        self.metrics.rpc_tx_channel_depth.set(depths.rpc_tx as f64);
        self.metrics.status_channel_depth.set(depths.status as f64);
        self.metrics
            .sync_request_channel_depth
            .set(depths.sync_request as f64);
        self.metrics
            .tx_request_channel_depth
            .set(depths.tx_request as f64);
        self.metrics
            .cert_request_channel_depth
            .set(depths.cert_request as f64);
    }

    fn record_execution_latency(&self, latency_secs: f64) {
        self.metrics.execution_latency.observe(latency_secs);
    }

    fn record_signature_verification_latency(&self, sig_type: &str, latency_secs: f64) {
        self.metrics
            .signature_verification_latency
            .with_label_values(&[sig_type])
            .observe(latency_secs);
    }

    fn record_signature_verification_failure(&self) {
        self.metrics.signature_verification_failures.inc();
    }

    // ── Network ──────────────────────────────────────────────────────

    fn record_network_message_sent(&self) {
        self.metrics.network_messages_sent.inc();
    }

    fn record_network_message_received(&self) {
        self.metrics.network_messages_received.inc();
    }

    fn set_libp2p_peers(&self, count: usize) {
        self.metrics.libp2p_peers_connected.set(count as f64);
    }

    fn record_libp2p_bandwidth(&self, bytes_in: u64, bytes_out: u64) {
        self.metrics
            .libp2p_bandwidth_in_bytes
            .inc_by(bytes_in as f64);
        self.metrics
            .libp2p_bandwidth_out_bytes
            .inc_by(bytes_out as f64);
    }

    fn record_pending_response_channels(&self, count: usize) {
        self.metrics
            .libp2p_pending_response_channels
            .set(count as f64);
    }

    fn record_network_event_loop_panic(&self) {
        self.metrics.libp2p_event_loop_panics.inc();
    }

    fn record_gossipsub_publish_failure(&self, topic: &str) {
        let topic_type = topic.rsplit('/').next().unwrap_or("unknown");
        self.metrics
            .gossipsub_publish_failures
            .with_label_values(&[topic_type])
            .inc();
    }

    fn record_request_retry(&self, request_type: &str) {
        self.metrics
            .network_request_retries
            .with_label_values(&[request_type])
            .inc();
    }

    fn increment_dispatch_failures(&self, message_type: &str) {
        self.metrics
            .dispatch_failures
            .with_label_values(&[message_type])
            .inc();
    }

    fn record_broadcast_failure(&self) {
        self.metrics.broadcast_failures.inc();
    }

    fn record_broadcast_retry_success(&self) {
        self.metrics.broadcast_retry_successes.inc();
    }

    fn record_broadcast_message_dropped(&self) {
        self.metrics.broadcast_messages_dropped.inc();
    }

    fn set_broadcast_retry_queue_size(&self, size: usize) {
        self.metrics.broadcast_retry_queue_size.set(size as f64);
    }

    fn record_backpressure_event(&self, source: &str) {
        self.metrics
            .backpressure_events
            .with_label_values(&[source])
            .inc();
    }

    fn record_early_arrival_eviction(&self) {
        self.metrics.early_arrival_evictions.inc();
    }

    // ── Sync ─────────────────────────────────────────────────────────

    fn set_sync_status(&self, blocks_behind: u64, in_progress: bool) {
        self.metrics.sync_blocks_behind.set(blocks_behind as f64);
        self.metrics
            .sync_in_progress
            .set(if in_progress { 1.0 } else { 0.0 });
    }

    fn record_sync_block_downloaded(&self) {
        self.metrics.sync_blocks_downloaded.inc();
    }

    fn record_sync_block_received_by_bft(&self) {
        self.metrics.sync_blocks_received_by_bft.inc();
    }

    fn record_sync_block_submitted_for_verification(&self) {
        self.metrics.sync_blocks_submitted_for_verification.inc();
    }

    fn record_sync_block_buffered(&self) {
        self.metrics.sync_blocks_buffered.inc();
    }

    fn record_sync_block_filtered(&self, reason: &str) {
        self.metrics
            .sync_blocks_filtered
            .with_label_values(&[reason])
            .inc();
    }

    fn record_sync_block_verified(&self) {
        self.metrics.sync_blocks_verified.inc();
    }

    fn record_sync_block_applied(&self) {
        self.metrics.sync_blocks_applied.inc();
    }

    fn record_sync_response_error(&self, error_type: &str) {
        self.metrics
            .sync_response_errors
            .with_label_values(&[error_type])
            .inc();
    }

    fn record_sync_peer_banned(&self) {
        self.metrics.sync_peers_banned.inc();
    }

    // ── Fetch ────────────────────────────────────────────────────────

    fn record_fetch_started(&self, kind: &str) {
        self.metrics.fetch_started.with_label_values(&[kind]).inc();
    }

    fn record_fetch_completed(&self, kind: &str) {
        self.metrics
            .fetch_completed
            .with_label_values(&[kind])
            .inc();
    }

    fn record_fetch_failed(&self, kind: &str) {
        self.metrics.fetch_failed.with_label_values(&[kind]).inc();
    }

    fn record_fetch_items_received(&self, kind: &str, count: usize) {
        self.metrics
            .fetch_items_received
            .with_label_values(&[kind])
            .inc_by(count as f64);
    }

    fn record_fetch_latency(&self, kind: &str, latency_secs: f64) {
        self.metrics
            .fetch_latency
            .with_label_values(&[kind])
            .observe(latency_secs);
    }

    fn set_fetch_in_flight(&self, kind: &str, count: usize) {
        self.metrics
            .fetch_in_flight
            .with_label_values(&[kind])
            .set(count as f64);
    }

    fn record_fetch_response_sent(&self, kind: &str, count: usize) {
        self.metrics
            .fetch_items_sent
            .with_label_values(&[kind])
            .inc_by(count as f64);
    }

    // ── Transaction Ingress ──────────────────────────────────────────

    fn record_tx_ingress_rejected_syncing(&self) {
        self.metrics.tx_ingress_rejected_syncing.inc();
    }

    fn record_tx_ingress_rejected_pending_limit(&self) {
        self.metrics.tx_ingress_rejected_pending_limit.inc();
    }

    fn record_transaction_rejected(&self, reason: &str) {
        self.metrics
            .transactions_rejected
            .with_label_values(&[reason])
            .inc();
    }

    fn record_invalid_message(&self) {
        self.metrics.invalid_messages_received.inc();
    }

    // ── Aborted Transactions ─────────────────────────────────────────

    fn record_transaction_aborted(&self) {
        self.metrics.transactions_aborted.inc();
    }

    // ── Lock Contention ──────────────────────────────────────────────

    fn set_lock_contention(&self, ratio: f64) {
        self.metrics.lock_contention_ratio.set(ratio);
    }

    // ── Memory ──────────────────────────────────────────────────────

    fn set_memory_metrics(&self, m: &MemoryMetrics) {
        // BFT
        self.metrics
            .memory_bft
            .with_label_values(&["pending_blocks"])
            .set(m.bft_pending_blocks as f64);
        self.metrics
            .memory_bft
            .with_label_values(&["vote_sets"])
            .set(m.bft_vote_sets as f64);
        self.metrics
            .memory_bft
            .with_label_values(&["certified_blocks"])
            .set(m.bft_certified_blocks as f64);
        self.metrics
            .memory_bft
            .with_label_values(&["pending_commits"])
            .set(m.bft_pending_commits as f64);
        self.metrics
            .memory_bft
            .with_label_values(&["pending_commits_awaiting_data"])
            .set(m.bft_pending_commits_awaiting_data as f64);
        self.metrics
            .memory_bft
            .with_label_values(&["voted_heights"])
            .set(m.bft_voted_heights as f64);
        self.metrics
            .memory_bft
            .with_label_values(&["received_votes_by_height"])
            .set(m.bft_received_votes_by_height as f64);
        self.metrics
            .memory_bft
            .with_label_values(&["committed_tx_lookup"])
            .set(m.bft_committed_tx_lookup as f64);
        self.metrics
            .memory_bft
            .with_label_values(&["recently_committed_txs"])
            .set(m.bft_recently_committed_txs as f64);
        self.metrics
            .memory_bft
            .with_label_values(&["recently_committed_certs"])
            .set(m.bft_recently_committed_certs as f64);
        self.metrics
            .memory_bft
            .with_label_values(&["pending_qc_verifications"])
            .set(m.bft_pending_qc_verifications as f64);
        self.metrics
            .memory_bft
            .with_label_values(&["verified_qcs"])
            .set(m.bft_verified_qcs as f64);
        self.metrics
            .memory_bft
            .with_label_values(&["pending_state_root_verifications"])
            .set(m.bft_pending_state_root_verifications as f64);
        self.metrics
            .memory_bft
            .with_label_values(&["buffered_synced_blocks"])
            .set(m.bft_buffered_synced_blocks as f64);
        self.metrics
            .memory_bft
            .with_label_values(&["pending_synced_block_verifications"])
            .set(m.bft_pending_synced_block_verifications as f64);

        // Execution
        self.metrics
            .memory_exec
            .with_label_values(&["cache_entries"])
            .set(m.exec_cache_entries as f64);
        self.metrics
            .memory_exec
            .with_label_values(&["finalized_wave_certificates"])
            .set(m.exec_finalized_wave_certificates as f64);
        self.metrics
            .memory_exec
            .with_label_values(&["waves"])
            .set(m.exec_waves as f64);
        self.metrics
            .memory_exec
            .with_label_values(&["vote_trackers"])
            .set(m.exec_vote_trackers as f64);
        self.metrics
            .memory_exec
            .with_label_values(&["early_votes"])
            .set(m.exec_early_votes as f64);
        self.metrics
            .memory_exec
            .with_label_values(&["expected_exec_certs"])
            .set(m.exec_expected_exec_certs as f64);
        self.metrics
            .memory_exec
            .with_label_values(&["verified_provisions"])
            .set(m.exec_verified_provisions as f64);
        self.metrics
            .memory_exec
            .with_label_values(&["required_provision_shards"])
            .set(m.exec_required_provision_shards as f64);
        self.metrics
            .memory_exec
            .with_label_values(&["received_provision_shards"])
            .set(m.exec_received_provision_shards as f64);
        self.metrics
            .memory_exec
            .with_label_values(&["waves_with_ec"])
            .set(m.exec_waves_with_ec as f64);
        self.metrics
            .memory_exec
            .with_label_values(&["pending_vote_retries"])
            .set(m.exec_pending_vote_retries as f64);
        self.metrics
            .memory_exec
            .with_label_values(&["wave_assignments"])
            .set(m.exec_wave_assignments as f64);
        self.metrics
            .memory_exec
            .with_label_values(&["early_wave_attestations"])
            .set(m.exec_early_wave_attestations as f64);
        self.metrics
            .memory_exec
            .with_label_values(&["pending_routing"])
            .set(m.exec_pending_routing as f64);
        self.metrics
            .memory_exec
            .with_label_values(&["fulfilled_exec_certs"])
            .set(m.exec_fulfilled_exec_certs as f64);
        self.metrics
            .memory_exec
            .with_label_values(&["outbound_certs"])
            .set(m.exec_outbound_certs as f64);

        // Mempool
        self.metrics
            .memory_mempool
            .with_label_values(&["pool"])
            .set(m.mempool_pool as f64);
        self.metrics
            .memory_mempool
            .with_label_values(&["ready"])
            .set(m.mempool_ready as f64);
        self.metrics
            .memory_mempool
            .with_label_values(&["tombstones"])
            .set(m.mempool_tombstones as f64);
        self.metrics
            .memory_mempool
            .with_label_values(&["recently_evicted"])
            .set(m.mempool_recently_evicted as f64);
        self.metrics
            .memory_mempool
            .with_label_values(&["locked_nodes"])
            .set(m.mempool_locked_nodes as f64);
        self.metrics
            .memory_mempool
            .with_label_values(&["deferred_by_nodes"])
            .set(m.mempool_deferred_by_nodes as f64);
        self.metrics
            .memory_mempool
            .with_label_values(&["txs_deferred_by_node"])
            .set(m.mempool_txs_deferred_by_node as f64);
        self.metrics
            .memory_mempool
            .with_label_values(&["ready_txs_by_node"])
            .set(m.mempool_ready_txs_by_node as f64);

        // Remote Headers
        self.metrics
            .memory_remote_headers
            .with_label_values(&["pending_headers"])
            .set(m.rh_pending_headers as f64);
        self.metrics
            .memory_remote_headers
            .with_label_values(&["verified_headers"])
            .set(m.rh_verified_headers as f64);
        self.metrics
            .memory_remote_headers
            .with_label_values(&["expected_headers"])
            .set(m.rh_expected_headers as f64);

        // Provision
        self.metrics
            .memory_provisions
            .with_label_values(&["verified_remote_headers"])
            .set(m.prov_verified_remote_headers as f64);
        self.metrics
            .memory_provisions
            .with_label_values(&["pending_provisions"])
            .set(m.prov_pending_provisions as f64);
        self.metrics
            .memory_provisions
            .with_label_values(&["verified_provisions"])
            .set(m.prov_verified_provisions as f64);
        self.metrics
            .memory_provisions
            .with_label_values(&["expected_provisions"])
            .set(m.prov_expected_provisions as f64);
        self.metrics
            .memory_provisions
            .with_label_values(&["provisions_by_hash"])
            .set(m.prov_provisions_by_hash as f64);
        self.metrics
            .memory_provisions
            .with_label_values(&["queued_provisions"])
            .set(m.prov_queued_provisions as f64);
        self.metrics
            .memory_provisions
            .with_label_values(&["committed_tombstones"])
            .set(m.prov_committed_tombstones as f64);

        // Node (io_loop)
        self.metrics
            .memory_node
            .with_label_values(&["tx_cache"])
            .set(m.node_tx_cache as f64);
        self.metrics
            .memory_node
            .with_label_values(&["tx_status_cache"])
            .set(m.node_tx_status_cache as f64);
        self.metrics
            .memory_node
            .with_label_values(&["finalized_wave_cache"])
            .set(m.node_finalized_wave_cache as f64);
        self.metrics
            .memory_node
            .with_label_values(&["provision_cache"])
            .set(m.node_provision_cache as f64);
        self.metrics
            .memory_node
            .with_label_values(&["exec_cert_cache"])
            .set(m.node_exec_cert_cache as f64);
        self.metrics
            .memory_node
            .with_label_values(&["prepared_commits"])
            .set(m.node_prepared_commits as f64);
        self.metrics
            .memory_node
            .with_label_values(&["pending_validation"])
            .set(m.node_pending_validation as f64);
        self.metrics
            .memory_node
            .with_label_values(&["locally_submitted"])
            .set(m.node_locally_submitted as f64);
        self.metrics
            .memory_node
            .with_label_values(&["pending_block_commits"])
            .set(m.node_pending_block_commits as f64);
        self.metrics
            .memory_node
            .with_label_values(&["validation_batch"])
            .set(m.node_validation_batch as f64);
        self.metrics
            .memory_node
            .with_label_values(&["committed_header_batch"])
            .set(m.node_committed_header_batch as f64);
        self.metrics
            .memory_node
            .with_label_values(&["sync_queued_heights"])
            .set(m.node_sync_queued_heights as f64);
        self.metrics
            .memory_node
            .with_label_values(&["sync_in_flight_fetches"])
            .set(m.node_sync_in_flight_fetches as f64);
        self.metrics
            .memory_node
            .with_label_values(&["tx_fetch_blocks"])
            .set(m.node_tx_fetch_blocks as f64);
        self.metrics
            .memory_node
            .with_label_values(&["local_provision_fetch_pending"])
            .set(m.node_local_provision_fetch_pending as f64);
        self.metrics
            .memory_node
            .with_label_values(&["finalized_wave_fetch_pending"])
            .set(m.node_finalized_wave_fetch_pending as f64);
        self.metrics
            .memory_node
            .with_label_values(&["provision_fetch_pending"])
            .set(m.node_provision_fetch_pending as f64);
        self.metrics
            .memory_node
            .with_label_values(&["exec_cert_fetch_pending"])
            .set(m.node_exec_cert_fetch_pending as f64);
        self.metrics
            .memory_node
            .with_label_values(&["header_fetch_pending"])
            .set(m.node_header_fetch_pending as f64);

        // Storage
        self.metrics
            .memory_storage
            .with_label_values(&["rocksdb_block_cache_bytes"])
            .set(m.rocksdb_block_cache_usage_bytes as f64);
        self.metrics
            .memory_storage
            .with_label_values(&["rocksdb_memtable_bytes"])
            .set(m.rocksdb_memtable_usage_bytes as f64);
    }
}

/// Install the Prometheus metrics recorder as the global backend.
///
/// Idempotent — safe to call multiple times (e.g., in tests). Only the
/// first call creates and registers the Prometheus metrics.
pub fn install() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        hyperscale_metrics::set_global_recorder(Box::new(PrometheusRecorder::new()));
    });
}

/// Gather and encode all registered Prometheus metrics as text format.
///
/// Returns `(content_type, encoded_body)` suitable for an HTTP response.
pub fn encode_metrics() -> Result<(String, Vec<u8>), String> {
    use prometheus::{Encoder, TextEncoder};
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let content_type = encoder.format_type().to_string();
    let mut buffer = Vec::new();
    encoder
        .encode(&metric_families, &mut buffer)
        .map_err(|e| format!("{e}"))?;
    Ok((content_type, buffer))
}
