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
// Metrics values are display readouts; precision loss on usize/u64 → f64 is irrelevant.
#![allow(clippy::cast_precision_loss)]

use hyperscale_metrics::{MemoryFamily, MetricsRecorder, set_global_recorder};
use prometheus::{
    Counter, CounterVec, Gauge, GaugeVec, Histogram, HistogramVec, gather, register_counter,
    register_counter_vec, register_gauge, register_gauge_vec, register_histogram,
    register_histogram_vec,
};

/// Domain-specific Prometheus metrics for production monitoring.
// Field names like `blocks_committed` and section comments serve as docs;
// individual field doc-comments would just restate the names.
#[allow(missing_docs)]
pub struct Metrics {
    // === Consensus ===
    /// Per-shard count of blocks committed.
    pub blocks_committed: CounterVec,
    pub block_commit_latency: HistogramVec,
    /// Per-shard chain height. Each hosted shard maintains its own height.
    pub block_height: GaugeVec,
    /// Per-vnode current shard round.
    pub round: GaugeVec,
    /// Per-vnode self-originated view changes (leader-activity timer fired).
    pub view_changes: GaugeVec,
    /// Per-vnode view syncs (rounds caught up to from peers).
    pub view_syncs: GaugeVec,
    pub build_info: GaugeVec,

    // === Transactions ===
    pub transactions_finalized: HistogramVec,
    pub transactions_executed: Counter,
    /// Per-vnode mempool size.
    pub mempool_size: GaugeVec,

    // === Backpressure ===
    /// Per-vnode drain the committed tip records.
    pub in_flight: GaugeVec,
    /// Per-vnode flag (0 or 1): the drain is at its budget.
    pub backpressure_active: GaugeVec,

    // === Infrastructure ===
    pub network_messages_sent: Counter,
    pub network_messages_received: Counter,
    pub signature_verification_latency: HistogramVec,
    pub execution_latency: Histogram,
    // === Thread Pools ===
    pub consensus_pool_queue_depth: Gauge,
    pub throughput_pool_queue_depth: Gauge,
    pub pool_task_duration: HistogramVec,

    // === Shard Loop Channel Depths ===
    pub callback_channel_depth: GaugeVec,
    pub timer_channel_depth: GaugeVec,

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
    pub block_commit_deferred: Counter,
    pub storage_transactions_persisted: Counter,

    // === Network ===
    pub libp2p_peers_connected: Gauge,
    pub libp2p_bandwidth_in_bytes: Counter,
    pub libp2p_bandwidth_out_bytes: Counter,

    // === Sync ===
    //
    // Per-scope status keyed by (`kind`, `shard`). `kind` is `block` or
    // `remote_header`; `shard` is the hosted shard's id. Filtering /
    // response-error dimensions remain because they don't collapse into
    // the per-`kind` fetch counters below.
    pub sync_blocks_behind: GaugeVec,
    pub sync_in_progress: GaugeVec,
    pub sync_blocks_filtered: CounterVec,
    pub sync_response_errors: CounterVec,
    pub sync_round_started: CounterVec,
    pub halt_recovery_offers_refused: Counter,
    pub sync_round_completed: CounterVec,
    pub sync_round_retried: CounterVec,
    pub sync_round_in_flight: GaugeVec,

    // === Fetch ===
    pub fetch_started: CounterVec,
    pub fetch_completed: CounterVec,
    pub fetch_abandoned: CounterVec,
    pub fetch_retried: CounterVec,
    pub fetch_items_sent: CounterVec,
    pub fetch_latency: HistogramVec,
    pub fetch_in_flight: GaugeVec,
    pub fetch_oldest_in_flight_age_ms: GaugeVec,

    // === Aborted Transactions ===
    pub transactions_aborted: Counter,
    pub expected_tx_dropped: Counter,

    // === Errors ===
    pub signature_verification_failures: CounterVec,
    pub invalid_messages_received: Counter,
    pub transactions_rejected: CounterVec,

    // === Memory ===
    pub memory_shard: GaugeVec,
    pub memory_exec: GaugeVec,
    pub memory_mempool: GaugeVec,
    pub memory_remote_headers: GaugeVec,
    pub memory_provisions: GaugeVec,
    pub memory_node: GaugeVec,

    // === Cross-Shard Message Delivery ===
    pub dispatch_failures: CounterVec,
    pub gossipsub_publish_failures: CounterVec,
    pub network_request_retries: CounterVec,
    pub early_votes_refused: Counter,
    pub backpressure_events: CounterVec,
    /// Committed transactions whose outcome the shard can no longer
    /// produce, by cause — their drain reservations never return.
    pub unresolvable_txs: CounterVec,
    /// Ledger entries rebuilt from a committed boundary record. Read
    /// across a shard's replicas: an outlier is one whose rebuild missed
    /// the transaction's own block.
    pub rebuilt_record_entries: Counter,
    /// Counterpart cells a committed proof answered for, by whether the
    /// cell was present. An absent answer is what licenses a reclaim.
    pub reclaim_probes_answered: CounterVec,
    /// Settlements of escrowed value admitted into a tick, by what
    /// composed each: an entry, or the record leaf alone.
    pub reclaims_admitted: CounterVec,
    pub reclaim_probes_pending: Counter,
    /// Dispatched ticks a node could not run for want of a package's
    /// code; any rate is a stalled replica.
    pub batches_unavailable: Counter,
    pub hold_contentions: Counter,
    pub hold_inversions_proven: Counter,
    /// The bytes a committed block's state claims weigh, proofs
    /// included.
    pub state_claims_weight: Histogram,
    /// Consumers' asks for crossing records: the fallback reads.
    pub record_asks: Counter,
    /// Fenced claims committed blocks carried, by what they read.
    pub fenced_claims_carried: CounterVec,
    /// Fenced claims the read frontier refused from what a validator
    /// held to offer, by what they read.
    pub fenced_claims_refused: CounterVec,
    pub crossing_fallback_asks: CounterVec,
    /// Pushed crossing readings the consumer dropped, by reason.
    pub crossing_pushes_dropped: CounterVec,
    /// Fetch responses a requester's own check refused, by fetch kind and
    /// the check that refused them.
    pub fetch_responses_refused: CounterVec,

    // === Network class accounting ===
    /// Per-class in-flight request slot count.
    pub request_slots_in_flight: GaugeVec,
    /// `acquire_slot` wait time histogram, per class.
    pub request_slot_wait: HistogramVec,
    /// Gossipsub validation outcomes (accept / reject / ignore).
    pub gossipsub_validations: CounterVec,
    /// Inbound serving stream count, per protocol.
    pub inbound_streams_in_use: GaugeVec,
}

impl Metrics {
    #[allow(clippy::too_many_lines)] // single registration table for every Prometheus metric
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
            blocks_committed: register_counter_vec!(
                "hyperscale_blocks_committed_total",
                "Total number of blocks committed, per shard",
                &["shard"]
            )
            .unwrap(),

            block_commit_latency: register_histogram_vec!(
                "hyperscale_block_commit_latency_seconds",
                "Time from proposal to commit, split by how this node learned the certifying QC",
                &["source"],
                latency_buckets.clone()
            )
            .unwrap(),

            block_height: register_gauge_vec!(
                "hyperscale_block_height",
                "Current block height, per shard",
                &["shard"]
            )
            .unwrap(),

            round: register_gauge_vec!(
                "hyperscale_round",
                "Current shard round within current height, per (shard, validator_id)",
                &["shard", "validator_id"]
            )
            .unwrap(),

            view_changes: register_gauge_vec!(
                "hyperscale_view_changes",
                "Self-originated view changes (this validator's leader-activity timer fired)",
                &["shard", "validator_id"]
            )
            .unwrap(),

            view_syncs: register_gauge_vec!(
                "hyperscale_view_syncs",
                "Rounds advanced via sync_to_qc_round (caught up to higher round seen on peers)",
                &["shard", "validator_id"]
            )
            .unwrap(),

            // Transactions
            transactions_finalized: register_histogram_vec!(
                "hyperscale_transaction_latency_seconds",
                "Transaction end-to-end latency",
                &["cross_shard"],
                latency_buckets
            )
            .unwrap(),

            transactions_executed: register_counter!(
                "hyperscale_transactions_executed_total",
                "Engine executions of a transaction; against finalized transactions, the replicated-execution factor"
            )
            .unwrap(),

            mempool_size: register_gauge_vec!(
                "hyperscale_mempool_size",
                "Number of pending transactions in mempool, per (shard, validator_id)",
                &["shard", "validator_id"]
            )
            .unwrap(),

            // Backpressure
            in_flight: register_gauge_vec!(
                "hyperscale_in_flight",
                "Drain the committed tip records: what committed transactions reserved and their ticks have not yet returned",
                &["shard", "validator_id"]
            )
            .unwrap(),
            backpressure_active: register_gauge_vec!(
                "hyperscale_backpressure_active",
                "Whether the drain is at MAX_UNSETTLED_TXS (1), refusing RPC submissions and new proposed transactions, or not (0)",
                &["shard", "validator_id"]
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
                vec![
                    0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 2.5, 5.0, 10.0
                ]
            )
            .unwrap(),

            // Thread Pools
            consensus_pool_queue_depth: register_gauge!(
                "hyperscale_consensus_pool_queue_depth",
                "Number of pending tasks in the consensus pool (votes, QCs, state root, proposals)"
            )
            .unwrap(),

            throughput_pool_queue_depth: register_gauge!(
                "hyperscale_throughput_pool_queue_depth",
                "Number of pending tasks in the throughput pool (crypto verify, tx validation, execution)"
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

            // Shard Loop Channel Depths
            callback_channel_depth: register_gauge_vec!(
                "hyperscale_callback_channel_depth",
                "Events queued on a shard loop's callback channel (off-thread results, inbound network deliveries, RPC fanout)",
                &["shard"]
            )
            .unwrap(),

            timer_channel_depth: register_gauge_vec!(
                "hyperscale_timer_channel_depth",
                "Timer fires queued on a shard loop's timer channel",
                &["shard"]
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
                vec![
                    0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 2.5, 5.0, 10.0
                ]
            )
            .unwrap(),

            storage_batch_size: register_histogram!(
                "hyperscale_storage_batch_size",
                "Number of writes in a block's atomic commit batch",
                vec![
                    1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0,
                    10000.0
                ]
            )
            .unwrap(),

            storage_certificates_persisted: register_counter!(
                "hyperscale_storage_certificates_persisted_total",
                "Total finalizations (certificates) carried by persisted blocks"
            )
            .unwrap(),

            storage_blocks_persisted: register_counter!(
                "hyperscale_storage_blocks_persisted_total",
                "Total committed blocks written to storage"
            )
            .unwrap(),

            block_commit_deferred: register_counter!(
                "hyperscale_block_commit_deferred_total",
                "Total number of commits whose BlockCommitted waited for persistence"
            )
            .unwrap(),

            storage_transactions_persisted: register_counter!(
                "hyperscale_storage_transactions_persisted_total",
                "Total transactions carried by persisted blocks"
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

            // Sync — per-scope status (`kind` = "block" or "remote_header"), per-shard.
            sync_blocks_behind: register_gauge_vec!(
                "hyperscale_sync_blocks_behind",
                "Per-(scope, shard) blocks behind the latest known target",
                &["kind", "shard"]
            )
            .unwrap(),

            sync_in_progress: register_gauge_vec!(
                "hyperscale_sync_in_progress",
                "Per-(scope, shard) sync activity (0 or 1)",
                &["kind", "shard"]
            )
            .unwrap(),

            sync_blocks_filtered: register_counter_vec!(
                "hyperscale_sync_blocks_filtered_total",
                "Sync responses filtered out before delivery, by scope and reason",
                &["kind", "reason"]
            )
            .unwrap(),

            sync_response_errors: register_counter_vec!(
                "hyperscale_sync_response_errors_total",
                "Sync response errors by scope and type",
                &["kind", "error_type"]
            )
            .unwrap(),

            sync_round_started: register_counter_vec!(
                "hyperscale_sync_round_started_total",
                "Sync range round-trips started (one per network request emitted by a sync FSM)",
                &["kind"]
            )
            .unwrap(),
            halt_recovery_offers_refused: register_counter!(
                "hyperscale_halt_recovery_offers_refused_total",
                "Retained tip offers refused by a halt recovery's fresh committee after its chain certified past the anchor"
            )
            .unwrap(),

            sync_round_completed: register_counter_vec!(
                "hyperscale_sync_round_completed_total",
                "Sync range round-trips completed successfully",
                &["kind"]
            )
            .unwrap(),

            sync_round_retried: register_counter_vec!(
                "hyperscale_sync_round_retried_total",
                "Sync range round-trips released for retry — increments per release-for-retry, not per unrecoverable failure",
                &["kind"]
            )
            .unwrap(),

            sync_round_in_flight: register_gauge_vec!(
                "hyperscale_sync_round_in_flight",
                "Per-(scope, shard) in-flight sync range fetches",
                &["kind", "shard"]
            )
            .unwrap(),

            // Fetch — per-`kind` counters. Per-id bindings count in *ids*;
            // range bindings (`block`, `remote_header`) count in *ranges*.
            fetch_started: register_counter_vec!(
                "hyperscale_fetch_started_total",
                "Total fetch operations started (ids for per-id bindings, ranges for sync)",
                &["kind"]
            )
            .unwrap(),

            fetch_completed: register_counter_vec!(
                "hyperscale_fetch_completed_total",
                "Total fetch operations completed successfully (payload landed and drained the entry)",
                &["kind"]
            )
            .unwrap(),

            fetch_abandoned: register_counter_vec!(
                "hyperscale_fetch_abandoned_total",
                "Total fetch operations cancelled by Action::AbandonFetch (consumer gave up before admission)",
                &["kind"]
            )
            .unwrap(),

            fetch_retried: register_counter_vec!(
                "hyperscale_fetch_retried_total",
                "Total fetch operations released for retry — increments per release-for-retry, not per unrecoverable failure",
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
                "Time from an admitted fetch's latest dispatch to its admission",
                &["kind"],
                vec![
                    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0
                ]
            )
            .unwrap(),

            fetch_in_flight: register_gauge_vec!(
                "hyperscale_fetch_in_flight",
                "Number of fetch requests currently in flight, per (kind, shard)",
                &["kind", "shard"]
            )
            .unwrap(),

            fetch_oldest_in_flight_age_ms: register_gauge_vec!(
                "hyperscale_fetch_oldest_in_flight_age_ms",
                "Age in ms of the longest-running in-flight fetch entry, per (kind, shard); 0 when no entry is in flight. Alert on rising past tens of seconds — admission silently dropped a response.",
                &["kind", "shard"]
            )
            .unwrap(),

            // Aborted Transactions
            transactions_aborted: register_counter!(
                "hyperscale_transactions_aborted_total",
                "Total cross-shard transactions aborted (timeout or node-ID conflict)"
            )
            .unwrap(),

            expected_tx_dropped: register_counter!(
                "hyperscale_mempool_expected_tx_dropped_total",
                "Expected cross-shard txs dropped past RETENTION_HORIZON without DA fulfilment"
            )
            .unwrap(),

            // Errors
            signature_verification_failures: register_counter_vec!(
                "hyperscale_signature_verification_failures_total",
                "Signature verifications that failed, by type",
                &["type"]
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
            memory_shard: register_gauge_vec!(
                "hyperscale_memory_shard_collections",
                "shard consensus state machine collection sizes (entry count)",
                &["collection", "shard", "validator_id"]
            )
            .unwrap(),

            memory_exec: register_gauge_vec!(
                "hyperscale_memory_exec_collections",
                "Execution state machine collection sizes (entry count)",
                &["collection", "shard", "validator_id"]
            )
            .unwrap(),

            memory_mempool: register_gauge_vec!(
                "hyperscale_memory_mempool_collections",
                "Mempool collection sizes (entry count)",
                &["collection", "shard", "validator_id"]
            )
            .unwrap(),

            memory_remote_headers: register_gauge_vec!(
                "hyperscale_memory_remote_headers_collections",
                "Remote header coordinator collection sizes (entry count)",
                &["collection", "shard", "validator_id"]
            )
            .unwrap(),

            memory_provisions: register_gauge_vec!(
                "hyperscale_memory_provisions_collections",
                "Provision coordinator collection sizes (entry count)",
                &["collection", "shard", "validator_id"]
            )
            .unwrap(),

            memory_node: register_gauge_vec!(
                "hyperscale_memory_node_collections",
                "Node io_loop collection sizes (entry count)",
                &["collection", "shard"]
            )
            .unwrap(),

            // Cross-Shard Message Delivery
            dispatch_failures: register_counter_vec!(
                "hyperscale_dispatch_failures_total",
                "Failures to dispatch cross-shard messages (channel closed)",
                &["message_type"]
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

            early_votes_refused: register_counter!(
                "hyperscale_early_votes_refused_total",
                "Execution votes for a tick not yet committed that the early-arrival buffer refused at capacity"
            )
            .unwrap(),

            backpressure_events: register_counter_vec!(
                "hyperscale_backpressure_events_total",
                "Backpressure events by source",
                &["source"]
            )
            .unwrap(),

            unresolvable_txs: register_counter_vec!(
                "hyperscale_unresolvable_txs_total",
                "Committed transactions the shard can no longer produce an outcome for, \
                 by cause; their drain reservations never return",
                &["cause"]
            )
            .unwrap(),

            rebuilt_record_entries: register_counter!(
                "hyperscale_rebuilt_record_entries_total",
                "Ledger entries rebuilt from a committed abandonment record"
            )
            .unwrap(),

            reclaim_probes_answered: register_counter_vec!(
                "hyperscale_reclaim_probes_answered_total",
                "Counterpart cells a committed state proof answered for, by presence",
                &["presence"]
            )
            .unwrap(),

            reclaims_admitted: register_counter_vec!(
                "hyperscale_reclaims_admitted_total",
                "Settlements of escrowed value admitted into a tick, by what composed each",
                &["composer"]
            )
            .unwrap(),

            reclaim_probes_pending: register_counter!(
                "hyperscale_reclaim_probes_pending_total",
                "Counterpart cells a fetch read as answering nothing yet, asked again at a newer header"
            )
            .unwrap(),

            batches_unavailable: register_counter!(
                "hyperscale_batches_unavailable_total",
                "Dispatched ticks this node could not run for want of a package's code; any rate is a stalled replica"
            )
            .unwrap(),

            hold_contentions: register_counter!(
                "hyperscale_hold_contentions_total",
                "Pending core members proposed blocks left out behind a core member's holds, one per pair per block"
            )
            .unwrap(),

            hold_inversions_proven: register_counter!(
                "hyperscale_hold_inversions_proven_total",
                "Pending core members proposed blocks aborted as the proven victims of a hold cycle"
            )
            .unwrap(),

            record_asks: register_counter!(
                "hyperscale_record_asks_total",
                "Asks a consumer put to a producer's chain for a crossing record it waits on"
            )
            .unwrap(),

            fenced_claims_carried: register_counter_vec!(
                "hyperscale_fenced_claims_carried_total",
                "Fenced claims committed blocks carried, by what they read",
                &["reading"]
            )
            .unwrap(),

            fenced_claims_refused: register_counter_vec!(
                "hyperscale_fenced_claims_refused_total",
                "Fenced claims the read frontier refused from what a validator held to offer",
                &["reading"]
            )
            .unwrap(),

            crossing_fallback_asks: register_counter_vec!(
                "hyperscale_crossing_fallback_asks_total",
                "Crossing questions asked past their deadline, where no push answered them",
                &["asker"]
            )
            .unwrap(),

            crossing_pushes_dropped: register_counter_vec!(
                "hyperscale_crossing_pushes_dropped_total",
                "Pushed crossing readings the consumer dropped, by reason",
                &["reason"]
            )
            .unwrap(),

            state_claims_weight: register_histogram!(
                "hyperscale_state_claims_weight_bytes",
                "Bytes a committed block's state claims weigh, proofs included",
                vec![
                    0.0, 512.0, 1024.0, 4096.0, 16384.0, 65536.0, 131_072.0, 262_144.0,
                    1_048_576.0,
                ]
            )
            .unwrap(),

            fetch_responses_refused: register_counter_vec!(
                "hyperscale_fetch_responses_refused_total",
                "Fetch responses refused by the requester's own check",
                &["kind", "reason"]
            )
            .unwrap(),

            request_slots_in_flight: register_gauge_vec!(
                "hyperscale_request_slots_in_flight",
                "In-flight request slots, broken down by message class",
                &["class"]
            )
            .unwrap(),

            request_slot_wait: register_histogram_vec!(
                "hyperscale_request_slot_wait_seconds",
                "Time spent inside acquire_slot before admission",
                &["class"],
                vec![
                    0.000_1, 0.000_5, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5,
                    5.0, 10.0,
                ]
            )
            .unwrap(),

            gossipsub_validations: register_counter_vec!(
                "hyperscale_gossipsub_validations_total",
                "Gossipsub validation outcomes (accept / reject / ignore)",
                &["outcome"]
            )
            .unwrap(),

            inbound_streams_in_use: register_gauge_vec!(
                "hyperscale_inbound_streams_in_use",
                "Inbound serving streams in flight, per protocol",
                &["protocol"]
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

    fn record_block_commit_deferred(&self) {
        self.metrics.block_commit_deferred.inc();
    }

    fn record_certificates_persisted(&self, count: usize) {
        self.metrics
            .storage_certificates_persisted
            .inc_by(count as f64);
    }

    fn record_transactions_persisted(&self, count: usize) {
        self.metrics
            .storage_transactions_persisted
            .inc_by(count as f64);
    }

    // ── Consensus ────────────────────────────────────────────────────

    fn record_block_committed(&self, shard: u64, commit_latency_secs: f64, source: &str) {
        self.metrics
            .blocks_committed
            .with_label_values(&[&shard.to_string()])
            .inc();
        self.metrics
            .block_commit_latency
            .with_label_values(&[source])
            .observe(commit_latency_secs);
        // `block_height` is set via the explicit per-shard `set_block_height`
        // setter at the same call site.
    }

    fn record_transaction_finalized(&self, latency_secs: f64, cross_shard: bool) {
        let label = if cross_shard { "true" } else { "false" };
        self.metrics
            .transactions_finalized
            .with_label_values(&[label])
            .observe(latency_secs);
    }

    fn record_transaction_executed(&self) {
        self.metrics.transactions_executed.inc();
    }

    fn set_block_height(&self, shard: u64, height: u64) {
        self.metrics
            .block_height
            .with_label_values(&[&shard.to_string()])
            .set(height as f64);
    }

    fn set_shard_round(&self, shard: u64, validator_id: u64, round: u64) {
        self.metrics
            .round
            .with_label_values(&[&shard.to_string(), &validator_id.to_string()])
            .set(round as f64);
    }

    fn set_view_changes(&self, shard: u64, validator_id: u64, count: u64) {
        self.metrics
            .view_changes
            .with_label_values(&[&shard.to_string(), &validator_id.to_string()])
            .set(count as f64);
    }

    fn set_view_syncs(&self, shard: u64, validator_id: u64, count: u64) {
        self.metrics
            .view_syncs
            .with_label_values(&[&shard.to_string(), &validator_id.to_string()])
            .set(count as f64);
    }

    fn set_mempool_size(&self, shard: u64, validator_id: u64, size: usize) {
        self.metrics
            .mempool_size
            .with_label_values(&[&shard.to_string(), &validator_id.to_string()])
            .set(size as f64);
    }

    fn set_in_flight(&self, shard: u64, validator_id: u64, drain: u64) {
        self.metrics
            .in_flight
            .with_label_values(&[&shard.to_string(), &validator_id.to_string()])
            .set(drain as f64);
    }

    fn set_backpressure_active(&self, shard: u64, validator_id: u64, active: bool) {
        self.metrics
            .backpressure_active
            .with_label_values(&[&shard.to_string(), &validator_id.to_string()])
            .set(if active { 1.0 } else { 0.0 });
    }

    // ── Infrastructure ───────────────────────────────────────────────

    fn set_pool_queue_depths(&self, consensus: usize, throughput: usize) {
        self.metrics
            .consensus_pool_queue_depth
            .set(consensus as f64);
        self.metrics
            .throughput_pool_queue_depth
            .set(throughput as f64);
    }

    fn record_pool_task_completed(&self, pool: &str, latency_secs: f64) {
        self.metrics
            .pool_task_duration
            .with_label_values(&[pool])
            .observe(latency_secs);
    }

    fn set_shard_channel_depths(&self, shard: u64, callback: usize, timer: usize) {
        let shard = shard.to_string();
        self.metrics
            .callback_channel_depth
            .with_label_values(&[&shard])
            .set(callback as f64);
        self.metrics
            .timer_channel_depth
            .with_label_values(&[&shard])
            .set(timer as f64);
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

    fn record_signature_verification_failure(&self, sig_type: &str) {
        self.metrics
            .signature_verification_failures
            .with_label_values(&[sig_type])
            .inc();
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

    fn record_backpressure_event(&self, source: &str) {
        self.metrics
            .backpressure_events
            .with_label_values(&[source])
            .inc();
    }

    fn record_early_vote_refused(&self) {
        self.metrics.early_votes_refused.inc();
    }

    fn record_unresolvable_tx(&self, cause: &str) {
        self.metrics
            .unresolvable_txs
            .with_label_values(&[cause])
            .inc();
    }

    fn record_rebuilt_record_entry(&self) {
        self.metrics.rebuilt_record_entries.inc();
    }

    fn record_batch_unavailable(&self) {
        self.metrics.batches_unavailable.inc();
    }

    fn record_reclaim_probe_answered(&self, present: bool) {
        let label = if present { "present" } else { "absent" };
        self.metrics
            .reclaim_probes_answered
            .with_label_values(&[label])
            .inc();
    }

    fn record_reclaim_admitted(&self, from_leaf: bool) {
        let label = if from_leaf { "leaf" } else { "entry" };
        self.metrics
            .reclaims_admitted
            .with_label_values(&[label])
            .inc();
    }

    fn record_reclaim_probe_pending(&self) {
        self.metrics.reclaim_probes_pending.inc();
    }

    fn record_hold_contentions(&self, pairs: usize) {
        self.metrics.hold_contentions.inc_by(pairs as f64);
    }

    fn record_hold_inversions_proven(&self, victims: usize) {
        self.metrics.hold_inversions_proven.inc_by(victims as f64);
    }

    fn record_state_claims_weight(&self, bytes: usize) {
        self.metrics.state_claims_weight.observe(bytes as f64);
    }

    fn record_record_ask(&self) {
        self.metrics.record_asks.inc();
    }

    fn record_crossing_fallback_ask(&self, asker: &str) {
        self.metrics
            .crossing_fallback_asks
            .with_label_values(&[asker])
            .inc();
    }

    fn record_fenced_claim(&self, reading: &str, carried: bool) {
        let counter = if carried {
            &self.metrics.fenced_claims_carried
        } else {
            &self.metrics.fenced_claims_refused
        };
        counter.with_label_values(&[reading]).inc();
    }

    fn record_crossing_push_dropped(&self, reason: &str) {
        self.metrics
            .crossing_pushes_dropped
            .with_label_values(&[reason])
            .inc();
    }

    fn record_fetch_response_refused(&self, kind: &str, reason: &str) {
        self.metrics
            .fetch_responses_refused
            .with_label_values(&[kind, reason])
            .inc();
    }

    fn set_request_slots_in_flight(&self, class: &str, count: usize) {
        #[allow(clippy::cast_precision_loss)]
        // count is bounded by RequestManagerConfig::max_concurrent (≤ 64)
        self.metrics
            .request_slots_in_flight
            .with_label_values(&[class])
            .set(count as f64);
    }

    fn record_request_slot_wait(&self, class: &str, wait_secs: f64) {
        self.metrics
            .request_slot_wait
            .with_label_values(&[class])
            .observe(wait_secs);
    }

    fn record_gossipsub_validation(&self, outcome: &str) {
        self.metrics
            .gossipsub_validations
            .with_label_values(&[outcome])
            .inc();
    }

    fn set_inbound_streams_in_use(&self, protocol: &str, count: usize) {
        #[allow(clippy::cast_precision_loss)]
        // count is bounded by MAX_INBOUND_CONCURRENT (= 128)
        self.metrics
            .inbound_streams_in_use
            .with_label_values(&[protocol])
            .set(count as f64);
    }

    // ── Sync ─────────────────────────────────────────────────────────

    fn set_sync_blocks_behind(&self, kind: &str, shard: u64, blocks_behind: u64) {
        self.metrics
            .sync_blocks_behind
            .with_label_values(&[kind, &shard.to_string()])
            .set(blocks_behind as f64);
    }

    fn set_sync_in_progress(&self, kind: &str, shard: u64, in_progress: bool) {
        self.metrics
            .sync_in_progress
            .with_label_values(&[kind, &shard.to_string()])
            .set(if in_progress { 1.0 } else { 0.0 });
    }

    fn record_sync_block_filtered(&self, kind: &str, reason: &str) {
        self.metrics
            .sync_blocks_filtered
            .with_label_values(&[kind, reason])
            .inc();
    }

    fn record_sync_response_error(&self, kind: &str, error_type: &str) {
        self.metrics
            .sync_response_errors
            .with_label_values(&[kind, error_type])
            .inc();
    }

    fn record_sync_round_started(&self, kind: &str) {
        self.metrics
            .sync_round_started
            .with_label_values(&[kind])
            .inc();
    }

    fn record_halt_recovery_offer_refused(&self) {
        self.metrics.halt_recovery_offers_refused.inc();
    }

    fn record_sync_round_completed(&self, kind: &str) {
        self.metrics
            .sync_round_completed
            .with_label_values(&[kind])
            .inc();
    }

    fn record_sync_round_retried(&self, kind: &str) {
        self.metrics
            .sync_round_retried
            .with_label_values(&[kind])
            .inc();
    }

    fn set_sync_round_in_flight(&self, kind: &str, shard: u64, count: usize) {
        self.metrics
            .sync_round_in_flight
            .with_label_values(&[kind, &shard.to_string()])
            .set(count as f64);
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

    fn record_fetch_abandoned(&self, kind: &str) {
        self.metrics
            .fetch_abandoned
            .with_label_values(&[kind])
            .inc();
    }

    fn record_fetch_retried(&self, kind: &str) {
        self.metrics.fetch_retried.with_label_values(&[kind]).inc();
    }

    fn record_fetch_latency(&self, kind: &str, latency_secs: f64) {
        self.metrics
            .fetch_latency
            .with_label_values(&[kind])
            .observe(latency_secs);
    }

    fn set_fetch_in_flight(&self, kind: &str, shard: u64, count: usize) {
        self.metrics
            .fetch_in_flight
            .with_label_values(&[kind, &shard.to_string()])
            .set(count as f64);
    }

    fn set_fetch_oldest_in_flight_age_ms(&self, kind: &str, shard: u64, age_ms: u64) {
        self.metrics
            .fetch_oldest_in_flight_age_ms
            .with_label_values(&[kind, &shard.to_string()])
            .set(age_ms as f64);
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

    fn record_expected_tx_dropped(&self) {
        self.metrics.expected_tx_dropped.inc();
    }

    // ── Memory ──────────────────────────────────────────────────────

    fn set_vnode_memory_gauge(
        &self,
        family: MemoryFamily,
        field: &str,
        shard: u64,
        validator_id: u64,
        value: usize,
    ) {
        let gauge = match family {
            MemoryFamily::Shard => &self.metrics.memory_shard,
            MemoryFamily::Execution => &self.metrics.memory_exec,
            MemoryFamily::Mempool => &self.metrics.memory_mempool,
            MemoryFamily::RemoteHeaders => &self.metrics.memory_remote_headers,
            MemoryFamily::Provisions => &self.metrics.memory_provisions,
        };
        gauge
            .with_label_values(&[field, &shard.to_string(), &validator_id.to_string()])
            .set(value as f64);
    }

    fn set_shard_memory_gauge(&self, field: &str, shard: u64, value: usize) {
        self.metrics
            .memory_node
            .with_label_values(&[field, &shard.to_string()])
            .set(value as f64);
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
        set_global_recorder(Box::new(PrometheusRecorder::new()));
    });
}

/// Gather and encode all registered Prometheus metrics as text format.
///
/// Returns `(content_type, encoded_body)` suitable for an HTTP response.
///
/// # Errors
///
/// Returns the underlying Prometheus encoding error rendered as a string
/// if `prometheus::Encoder::encode` fails.
pub fn encode_metrics() -> Result<(String, Vec<u8>), String> {
    use prometheus::{Encoder, TextEncoder};
    let encoder = TextEncoder::new();
    let metric_families = gather();
    let content_type = encoder.format_type().to_string();
    let mut buffer = Vec::new();
    encoder
        .encode(&metric_families, &mut buffer)
        .map_err(|e| format!("{e}"))?;
    Ok((content_type, buffer))
}
